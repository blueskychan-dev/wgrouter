package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migration is one numbered, forward-only schema step. There is deliberately no
// "down" direction: rolling a schema backwards on a live router is more likely
// to destroy state than to rescue it, and every step here is written to be
// safe to apply to the previous version's data.
type migration struct {
	version int
	name    string
	sql     string
}

// Migrate applies every migration newer than the recorded schema version.
//
// Each migration runs in its own transaction together with the version bump, so
// a failure part-way through leaves the database on the last complete version
// rather than in a half-migrated state.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT    NOT NULL,
			applied_at INTEGER NOT NULL
		)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	var current int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}

	all, err := loadMigrations()
	if err != nil {
		return err
	}

	for _, m := range all {
		if m.version <= current {
			continue
		}
		err := s.Tx(ctx, func(tx *sql.Tx) error {
			// Re-check inside the transaction. The version read above was taken
			// in autocommit, so another process starting at the same moment
			// could have applied this migration in between; without this the
			// second one would run CREATE TABLE against tables that now exist
			// and fail the whole startup.
			var applied int
			if err := tx.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&applied); err != nil {
				return fmt.Errorf("store: re-check migration %04d_%s: %w", m.version, m.name, err)
			}
			if applied > 0 {
				return nil
			}
			if _, err := tx.ExecContext(ctx, m.sql); err != nil {
				return fmt.Errorf("store: apply migration %04d_%s: %w", m.version, m.name, err)
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
				m.version, m.name, time.Now().Unix()); err != nil {
				return fmt.Errorf("store: record migration %04d_%s: %w", m.version, m.name, err)
			}
			return nil
		})
		if err != nil {
			return err
		}
		slog.Info("applied schema migration", "version", m.version, "name", m.name)
	}
	return nil
}

// SchemaVersion reports the highest applied migration version.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	return v, nil
}

// loadMigrations reads and validates the embedded migration set. Filenames must
// be NNNN_name.sql; versions must be unique and are applied in numeric order.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}

	out := make([]migration, 0, len(entries))
	seen := make(map[int]string, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".sql")
		num, name, ok := strings.Cut(base, "_")
		if !ok {
			return nil, fmt.Errorf("store: migration %q: want NNNN_name.sql", e.Name())
		}
		version, err := strconv.Atoi(num)
		if err != nil {
			return nil, fmt.Errorf("store: migration %q: bad version prefix: %w", e.Name(), err)
		}
		if version <= 0 {
			return nil, fmt.Errorf("store: migration %q: version must be positive", e.Name())
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("store: migrations %q and %q share version %d", prev, e.Name(), version)
		}
		seen[version] = e.Name()

		body, err := fs.ReadFile(migrationFS, "migrations/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("store: read migration %q: %w", e.Name(), err)
		}
		out = append(out, migration{version: version, name: name, sql: string(body)})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}
