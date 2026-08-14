// Package store owns wgrouter's SQLite database: connection setup, schema
// migration, and the small typed accessors the rest of the program uses.
//
// The database is the source of truth for everything wgrouter decides (peers,
// address allocations, port forwards). Kernel state -- WireGuard peers and
// nftables rules -- is derived from it and rebuilt on startup, because none of
// that state survives a reboot.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"

	_ "modernc.org/sqlite" // pure-Go driver: no cgo, so the binary stays static
)

// ErrNotFound is returned by accessors that look up a single row.
var ErrNotFound = errors.New("not found")

// Store wraps the database handle.
type Store struct {
	db *sql.DB
}

// Open connects to the SQLite database at path, creating the file and its
// parent directory if needed, and applies any outstanding migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: empty database path")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("store: create database directory %s: %w", dir, err)
		}
	}

	// Create the file ourselves with restrictive permissions before the driver
	// does. The database holds password hashes, preshared keys and the server
	// private key; left to the driver it would be created 0644 minus umask.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: create database file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("store: create database file %s: %w", path, err)
	}

	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}

	// SQLite serialises writers regardless of pool size. Capping the pool keeps
	// lock contention predictable and makes busy_timeout the only thing we rely
	// on for concurrent writers; under WAL, readers do not block behind them.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: connect %s: %w", path, err)
	}

	s := &Store{db: db}
	if err := s.Migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// memorySeq gives each in-memory database a distinct name.
var memorySeq atomic.Int64

// OpenMemory opens a private in-memory database, migrated and ready. Used by
// tests so they need neither root nor a temp file.
//
// The name must be unique per call. "file::memory:?cache=shared" is a single
// process-global database, so two Stores opened that way would silently share
// rows -- one test's admin account would appear in the next test's fresh
// router. A named database with mode=memory keeps the shared cache (needed so
// the pooled connections see the same data) while staying private to this
// Store.
func OpenMemory(ctx context.Context) (*Store, error) {
	name := fmt.Sprintf("wgrouter-mem-%d", memorySeq.Add(1))
	db, err := sql.Open("sqlite",
		"file:"+name+"?mode=memory&cache=shared&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("store: open memory: %w", err)
	}
	// At least one connection must stay open or the database is destroyed; the
	// pool is capped so an idle connection is always retained.
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(0)

	s := &Store{db: db}
	if err := s.Migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// dsn builds the driver connection string. The parameters matter:
//
//	journal_mode=WAL    readers do not block the writer, which keeps the SSE
//	                    status stream from stalling behind a peer creation.
//	busy_timeout=5000   wait rather than failing instantly on a locked database.
//	foreign_keys=1      SQLite disables FK enforcement by default; forwards
//	                    reference peers and we rely on ON DELETE CASCADE.
//	synchronous=NORMAL  the documented safe pairing with WAL: durable across
//	                    process crashes, and only at risk in a power loss that
//	                    would also lose the kernel state we rebuild anyway.
//	_txlock=immediate   take the write lock when a transaction begins rather
//	                    than on its first write. Deferred transactions can fail
//	                    the upgrade with SQLITE_BUSY after already reading --
//	                    the lost-update shape that would let two concurrent
//	                    address allocations both observe the same free address.
func dsn(path string) string {
	q := url.Values{}
	for _, p := range []string{
		"journal_mode(WAL)",
		"busy_timeout(5000)",
		"foreign_keys(1)",
		"synchronous(NORMAL)",
	} {
		q.Add("_pragma", p)
	}
	q.Set("_txlock", "immediate")

	// Percent-encode the path. This is a URI, so an unescaped '?' or '#' in a
	// directory name would be read as the start of the query or fragment and
	// the driver would open a different file -- or accept injected URI
	// parameters from whatever created that directory.
	escaped := (&url.URL{Path: path}).EscapedPath()
	return "file:" + escaped + "?" + q.Encode()
}

// DB exposes the underlying handle for packages that need to drive their own
// transactions.
func (s *Store) DB() *sql.DB { return s.db }

// Close releases the database handle.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Tx runs fn inside a transaction, rolling back if it returns an error.
//
// Transactions are IMMEDIATE (see dsn), so the write lock is held for the whole
// of fn. Read-modify-write sequences are therefore serialised against each
// other, which is what makes the database -- not a process-local mutex -- the
// arbiter for address allocation.
func (s *Store) Tx(ctx context.Context, fn func(*sql.Tx) error) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			// Roll back before re-panicking so the connection is not left in a
			// transaction and returned to the pool that way.
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
				err = errors.Join(err, fmt.Errorf("store: rollback: %w", rbErr))
			}
		}
	}()

	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}
