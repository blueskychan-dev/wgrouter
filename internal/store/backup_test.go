package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"wgrouter/internal/forward"
)

func seedForBackup(t *testing.T, st *Store) {
	t.Helper()
	ctx := context.Background()
	key, ip := seedPeer(t, st)
	if _, err := st.CreateForward(ctx, newForward(key, ip, forward.ProtoTCP, 443)); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, SettingServerPrivateKey, "a-server-key"); err != nil {
		t.Fatal(err)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	src := testStore(t)
	ctx := context.Background()
	seedForBackup(t, src)

	data, err := src.ExportConfig(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}

	// Restore into a different, non-empty store to prove it replaces rather
	// than merges.
	dst := testStore(t)
	seedForBackup(t, dst)
	if _, err := dst.CreateForward(ctx, newForward(mustPeerKey(t, dst), netip.MustParseAddr("10.10.0.2"), forward.ProtoTCP, 9999)); err != nil {
		t.Fatal(err)
	}

	b, err := dst.ImportConfig(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Peers) != 1 || len(b.Forwards) != 1 {
		t.Fatalf("backup reported %d peers, %d forwards", len(b.Peers), len(b.Forwards))
	}

	peers, _ := dst.Peers(ctx)
	fwds, _ := dst.Forwards(ctx)
	if len(peers) != 1 || len(fwds) != 1 {
		t.Errorf("after restore: %d peers, %d forwards — the import merged instead of replacing", len(peers), len(fwds))
	}
	if fwds[0].Listen.Start != 443 {
		t.Errorf("restored forward listens on %s, want 443", fwds[0].Listen)
	}

	// The server key has to survive, or every issued client config breaks.
	if v, err := dst.Setting(ctx, SettingServerPrivateKey); err != nil || v != "a-server-key" {
		t.Errorf("server key after restore = %q, err = %v", v, err)
	}
}

// A restore must not be a way to replace who can sign in.
func TestImportDoesNotTouchUsers(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if _, err := st.CreateFirstUser(ctx, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	seedForBackup(t, st)

	data, err := st.ExportConfig(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "hash") {
		t.Error("the export contains a password hash")
	}
	if _, err := st.ImportConfig(ctx, data); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.UserCount(ctx); n != 1 {
		t.Errorf("UserCount = %d after a restore, want the account untouched", n)
	}
}

// Logs and statistics are history, not configuration.
func TestExportExcludesLogs(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	seedForBackup(t, st)
	if err := st.Audit(ctx, "admin", ActionLogin, "signed in", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}

	data, err := st.ExportConfig(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "signed in") {
		t.Error("the export contains audit log entries")
	}
}

func TestImportRejectsGarbage(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	for _, in := range []string{"", "not json", "{}", `{"version":0}`} {
		if _, err := st.ImportConfig(ctx, []byte(in)); err == nil {
			t.Errorf("ImportConfig(%q) was accepted", in)
		}
	}
}

// A file from a newer build may contain settings this one would silently drop,
// which on a firewall means rules the operator believes are in place.
func TestImportRejectsNewerVersion(t *testing.T) {
	st := testStore(t)
	future, _ := json.Marshal(Backup{Version: BackupVersion + 1})
	if _, err := st.ImportConfig(context.Background(), future); err == nil {
		t.Error("a newer backup version was accepted")
	}
}

func TestResetToFactoryKeepsUsers(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if _, err := st.CreateFirstUser(ctx, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	seedForBackup(t, st)

	if err := st.ResetToFactory(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.UserCount(ctx); n != 1 {
		t.Errorf("UserCount = %d after a factory reset; the operator would be locked out", n)
	}
	if peers, _ := st.Peers(ctx); len(peers) != 0 {
		t.Error("peers survived a factory reset")
	}
	if fwds, _ := st.Forwards(ctx); len(fwds) != 0 {
		t.Error("forwards survived a factory reset")
	}
}

func mustPeerKey(t *testing.T, st *Store) string {
	t.Helper()
	peers, err := st.Peers(context.Background())
	if err != nil || len(peers) == 0 {
		t.Fatalf("no peers: %v", err)
	}
	return peers[0].PublicKey
}
