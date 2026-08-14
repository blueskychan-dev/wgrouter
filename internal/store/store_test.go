package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := OpenMemory(context.Background())
	if err != nil {
		t.Fatalf("OpenMemory: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return st
}

func TestMigrateCreatesSchema(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	v, err := st.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v < 1 {
		t.Fatalf("SchemaVersion = %d, want at least 1", v)
	}

	for _, table := range []string{"users", "settings", "peers", "forwards", "audit_log"} {
		var name string
		err := st.DB().QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Errorf("table %q missing after migration: %v", table, err)
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	before, err := st.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	// Running again must be a no-op, not an error and not a re-application.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	after, err := st.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if before != after {
		t.Errorf("schema version changed on re-migration: %d -> %d", before, after)
	}

	var n int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if n != after {
		t.Errorf("schema_migrations has %d rows for version %d", n, after)
	}
}

func TestMigrationFilesAreWellFormed(t *testing.T) {
	all, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("no migrations were embedded")
	}
	for i, m := range all {
		if m.version <= 0 {
			t.Errorf("migration %d has non-positive version %d", i, m.version)
		}
		if m.sql == "" {
			t.Errorf("migration %04d_%s is empty", m.version, m.name)
		}
		if i > 0 && all[i-1].version >= m.version {
			t.Errorf("migrations are not in ascending order at index %d", i)
		}
	}
}

func TestOpenCreatesParentDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "deeper")
	path := filepath.Join(dir, "wgrouter.db")

	st, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	if v, err := st.SchemaVersion(context.Background()); err != nil || v < 1 {
		t.Errorf("SchemaVersion = %d, %v; want a migrated database", v, err)
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	if _, err := Open(context.Background(), ""); err == nil {
		t.Error("Open with an empty path succeeded, want error")
	}
}

// The database holds password hashes, preshared keys and the server private
// key. It must not be created world-readable.
func TestDatabaseFileIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgrouter.db")
	st, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("database file mode = %04o, want no group or other access", perm)
	}
}

// A path containing URI syntax must open the file that was asked for, not a
// different one, and must not let the surrounding directory name inject
// connection parameters.
func TestOpenHandlesPathsWithURISyntax(t *testing.T) {
	for _, name := range []string{"odd?name.db", "odd#name.db", "odd%name.db", "odd&name.db"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			st, err := Open(context.Background(), path)
			if err != nil {
				t.Fatalf("Open(%q): %v", path, err)
			}
			defer st.Close()

			if _, err := st.CreateFirstUser(context.Background(), "admin", "hash"); err != nil {
				t.Fatalf("CreateFirstUser: %v", err)
			}
			// The file the caller named must be the file that now exists.
			if _, err := os.Stat(path); err != nil {
				t.Errorf("database was not created at the requested path: %v", err)
			}
		})
	}
}

// Two in-memory stores must be independent. When they shared one process-global
// database, one test's admin account showed up in the next test's "fresh"
// router.
func TestOpenMemoryStoresAreIndependent(t *testing.T) {
	ctx := context.Background()

	a, err := OpenMemory(ctx)
	if err != nil {
		t.Fatalf("OpenMemory(a): %v", err)
	}
	defer a.Close()

	b, err := OpenMemory(ctx)
	if err != nil {
		t.Fatalf("OpenMemory(b): %v", err)
	}
	defer b.Close()

	if _, err := a.CreateFirstUser(ctx, "admin", "hash"); err != nil {
		t.Fatalf("CreateFirstUser on a: %v", err)
	}

	n, err := b.UserCount(ctx)
	if err != nil {
		t.Fatalf("UserCount on b: %v", err)
	}
	if n != 0 {
		t.Errorf("second in-memory store sees %d users from the first; they share a database", n)
	}
}

// --- Users -----------------------------------------------------------------

func TestUserLifecycle(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if n, err := st.UserCount(ctx); err != nil || n != 0 {
		t.Fatalf("UserCount on a fresh database = %d, %v; want 0", n, err)
	}
	if _, err := st.UserByName(ctx, "admin"); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserByName on a fresh database = %v, want ErrNotFound", err)
	}

	created, err := st.CreateFirstUser(ctx, "admin", "hash-1")
	if err != nil {
		t.Fatalf("CreateFirstUser: %v", err)
	}
	if created.ID == 0 || created.Username != "admin" {
		t.Errorf("CreateFirstUser returned %+v", created)
	}

	got, err := st.UserByName(ctx, "admin")
	if err != nil {
		t.Fatalf("UserByName: %v", err)
	}
	if got.PasswordHash != "hash-1" {
		t.Errorf("PasswordHash = %q, want hash-1", got.PasswordHash)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt was not populated")
	}

	if err := st.SetPassword(ctx, got.ID, "hash-2"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	got, err = st.UserByName(ctx, "admin")
	if err != nil {
		t.Fatalf("UserByName after SetPassword: %v", err)
	}
	if got.PasswordHash != "hash-2" {
		t.Errorf("PasswordHash = %q, want hash-2", got.PasswordHash)
	}

	if err := st.SetPassword(ctx, 9999, "hash-3"); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetPassword for a missing user = %v, want ErrNotFound", err)
	}
}

// TestCreateFirstUserIsOnlyEverFirst guards the setup wizard: once an account
// exists, a second attempt must be refused rather than silently adding one.
func TestCreateFirstUserIsOnlyEverFirst(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.CreateFirstUser(ctx, "admin", "hash-1"); err != nil {
		t.Fatalf("first CreateFirstUser: %v", err)
	}
	_, err := st.CreateFirstUser(ctx, "intruder", "hash-2")
	if !errors.Is(err, ErrSetupComplete) {
		t.Fatalf("second CreateFirstUser = %v, want ErrSetupComplete", err)
	}

	if n, err := st.UserCount(ctx); err != nil || n != 1 {
		t.Errorf("UserCount = %d, %v; want exactly 1", n, err)
	}
}

// --- Settings --------------------------------------------------------------

func TestSettings(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.Setting(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Setting for an unset key = %v, want ErrNotFound", err)
	}
	if v, err := st.SettingOr(ctx, "missing", "fallback"); err != nil || v != "fallback" {
		t.Errorf("SettingOr = %q, %v; want the fallback", v, err)
	}

	if err := st.SetSetting(ctx, SettingServerPublicKey, "pubkey-1"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if v, err := st.Setting(ctx, SettingServerPublicKey); err != nil || v != "pubkey-1" {
		t.Errorf("Setting = %q, %v; want pubkey-1", v, err)
	}

	// Writing again must replace, not conflict.
	if err := st.SetSetting(ctx, SettingServerPublicKey, "pubkey-2"); err != nil {
		t.Fatalf("SetSetting (update): %v", err)
	}
	if v, _ := st.Setting(ctx, SettingServerPublicKey); v != "pubkey-2" {
		t.Errorf("Setting after update = %q, want pubkey-2", v)
	}
}

// --- Audit -----------------------------------------------------------------

func TestAuditLog(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if entries, err := st.RecentAudit(ctx, 10); err != nil || len(entries) != 0 {
		t.Fatalf("RecentAudit on a fresh database = %d entries, %v", len(entries), err)
	}

	for _, a := range []struct{ actor, action, detail string }{
		{"admin", ActionLogin, "signed in"},
		{"admin", ActionPeerCreate, "created peer laptop"},
		{"", ActionReconcile, "periodic"},
	} {
		if err := st.Audit(ctx, a.actor, a.action, a.detail, "10.10.0.2"); err != nil {
			t.Fatalf("Audit: %v", err)
		}
	}

	entries, err := st.RecentAudit(ctx, 10)
	if err != nil {
		t.Fatalf("RecentAudit: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("RecentAudit returned %d entries, want 3", len(entries))
	}
	// Newest first.
	if entries[0].Action != ActionReconcile {
		t.Errorf("first entry action = %q, want the most recent (%q)", entries[0].Action, ActionReconcile)
	}
	// An empty actor is recorded as the system actor, not as "".
	if entries[0].Actor != ActorSystem {
		t.Errorf("empty actor stored as %q, want %q", entries[0].Actor, ActorSystem)
	}
	if entries[0].At.IsZero() {
		t.Error("audit timestamp was not populated")
	}
	if entries[0].RemoteAddr != "10.10.0.2" {
		t.Errorf("RemoteAddr = %q, want 10.10.0.2", entries[0].RemoteAddr)
	}
}

func TestRecentAuditClampsLimit(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.Audit(ctx, "admin", ActionLogin, "", ""); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	for _, limit := range []int{0, -1, 100000} {
		if _, err := st.RecentAudit(ctx, limit); err != nil {
			t.Errorf("RecentAudit(%d): %v", limit, err)
		}
	}
}

// --- Transactions ----------------------------------------------------------

func TestTxRollsBackOnError(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	sentinel := errors.New("deliberate failure")
	err := st.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO settings (key, value, updated_at) VALUES ('k', 'v', 0)`); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Tx returned %v, want the sentinel error", err)
	}

	if _, err := st.Setting(ctx, "k"); !errors.Is(err, ErrNotFound) {
		t.Error("the row written inside a failed transaction was committed")
	}
}

func TestTxCommitsOnSuccess(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	err := st.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO settings (key, value, updated_at) VALUES ('committed', 'yes', 0)`)
		return err
	})
	if err != nil {
		t.Fatalf("Tx: %v", err)
	}
	if v, err := st.Setting(ctx, "committed"); err != nil || v != "yes" {
		t.Errorf("Setting = %q, %v; want the committed value", v, err)
	}
}

// --- Schema constraints ----------------------------------------------------

// The peers.tunnel_ip UNIQUE constraint is what makes the database, rather than
// a process-local mutex, the arbiter for address allocation. If this ever stops
// holding, concurrent provisioning can hand the same address to two peers.
func TestTunnelIPIsUnique(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	insert := func(pubkey, ip string) error {
		_, err := st.DB().ExecContext(ctx,
			`INSERT INTO peers (name, public_key, preshared_key, tunnel_ip, created_at)
			 VALUES (?, ?, 'psk', ?, 0)`, "peer-"+pubkey, pubkey, ip)
		return err
	}

	if err := insert("key-a", "10.10.0.2"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := insert("key-b", "10.10.0.2"); err == nil {
		t.Fatal("a second peer was allowed to claim the same tunnel address")
	}
	if err := insert("key-a", "10.10.0.3"); err == nil {
		t.Fatal("a second peer was allowed to reuse a public key")
	}
}

func TestForwardConstraints(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO peers (name, public_key, preshared_key, tunnel_ip, created_at)
		 VALUES ('peer', 'pubkey', 'psk', '10.10.0.2', 0)`); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	insert := func(proto string, port int, mode string, peer string) error {
		_, err := st.DB().ExecContext(ctx,
			`INSERT INTO forwards (label, proto, listen_port, target_peer, target_ip, target_port, preserve_src, created_at)
			 VALUES ('l', ?, ?, ?, '10.10.0.2', 80, ?, 0)`, proto, port, peer, mode)
		return err
	}

	if err := insert("tcp", 443, "masquerade", "pubkey"); err != nil {
		t.Fatalf("valid forward rejected: %v", err)
	}
	if err := insert("sctp", 8443, "masquerade", "pubkey"); err == nil {
		t.Error("an invalid protocol was accepted")
	}
	if err := insert("tcp", 0, "masquerade", "pubkey"); err == nil {
		t.Error("port 0 was accepted")
	}
	if err := insert("tcp", 70000, "masquerade", "pubkey"); err == nil {
		t.Error("a port above 65535 was accepted")
	}
	if err := insert("tcp", 8443, "sorcery", "pubkey"); err == nil {
		t.Error("an invalid source mode was accepted")
	}
	if err := insert("tcp", 8443, "masquerade", "no-such-peer"); err == nil {
		t.Error("a forward referencing an unknown peer was accepted")
	}
	// Two enabled forwards must not claim the same proto and port.
	if err := insert("tcp", 443, "direct", "pubkey"); err == nil {
		t.Error("a duplicate enabled proto/port pair was accepted")
	}
}

// Deleting a peer must take its forwards with it, or the reconciler would try
// to program rules pointing at an address nobody holds.
func TestDeletingPeerCascadesToForwards(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO peers (name, public_key, preshared_key, tunnel_ip, created_at)
		 VALUES ('peer', 'pubkey', 'psk', '10.10.0.2', 0)`); err != nil {
		t.Fatalf("seed peer: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO forwards (label, proto, listen_port, target_peer, target_ip, target_port, preserve_src, created_at)
		 VALUES ('l', 'tcp', 443, 'pubkey', '10.10.0.2', 80, 'masquerade', 0)`); err != nil {
		t.Fatalf("seed forward: %v", err)
	}

	if _, err := st.DB().ExecContext(ctx, `DELETE FROM peers WHERE public_key = 'pubkey'`); err != nil {
		t.Fatalf("delete peer: %v", err)
	}

	var n int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM forwards`).Scan(&n); err != nil {
		t.Fatalf("count forwards: %v", err)
	}
	if n != 0 {
		t.Errorf("%d forwards survived deletion of their peer; foreign keys are not being enforced", n)
	}
}
