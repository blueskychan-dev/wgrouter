package wg

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"wgrouter/internal/ipam"
	"wgrouter/internal/store"
)

func testManager(t *testing.T) (*Manager, *FakeKernel, *store.Store) {
	t.Helper()
	st, err := store.OpenMemory(context.Background())
	if err != nil {
		t.Fatalf("OpenMemory: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	plan, err := ipam.NewPlan(netip.MustParsePrefix("10.10.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	k := NewFakeKernel()
	return NewManager(k, st, plan, "wg0", 51820, DefaultMTU), k, st
}

func TestPresenceIsDerivedFromHandshake(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		handshake time.Time
		want      Presence
		wantLabel string
	}{
		{"never handshaked", time.Time{}, PresenceNever, "Never connected"},
		{"just now", now, PresenceOnline, "Online"},
		{"one second inside the window", now.Add(-HandshakeTimeout + time.Second), PresenceOnline, "Online"},
		{"exactly at the window", now.Add(-HandshakeTimeout), PresenceIdle, "Idle"},
		{"long ago", now.Add(-24 * time.Hour), PresenceIdle, "Idle"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PresenceOf(tt.handshake, now)
			if got != tt.want {
				t.Errorf("PresenceOf = %q, want %q", got, tt.want)
			}
			if got.Label() != tt.wantLabel {
				t.Errorf("Label = %q, want %q", got.Label(), tt.wantLabel)
			}
		})
	}
}

// The brief is explicit that no peer is ever labelled "disconnected".
func TestNoPresenceIsLabelledDisconnected(t *testing.T) {
	for _, p := range []Presence{PresenceOnline, PresenceIdle, PresenceNever, Presence("bogus")} {
		if got := p.Label(); got == "Disconnected" || got == "disconnected" {
			t.Errorf("Presence(%q).Label() = %q; peers are never 'disconnected'", p, got)
		}
	}
}

func TestEnsureServerKeyGeneratesOnceAndPersists(t *testing.T) {
	m, _, st := testManager(t)
	ctx := context.Background()

	first, err := m.EnsureServerKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.EnsureServerKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Error("EnsureServerKey generated a second key on the same manager")
	}

	// A fresh manager over the same database must load the same key, not make
	// a new one -- otherwise every restart invalidates every client config.
	plan, _ := ipam.NewPlan(netip.MustParsePrefix("10.10.0.0/24"))
	m2 := NewManager(NewFakeKernel(), st, plan, "wg0", 51820, DefaultMTU)
	reloaded, err := m2.EnsureServerKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded != first {
		t.Error("a restart generated a new server key instead of loading the stored one")
	}

	pub, err := st.Setting(ctx, store.SettingServerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if pub != first.PublicKey().String() {
		t.Errorf("cached public key = %q, want %q", pub, first.PublicKey())
	}
}

// A key we cannot parse must stop the program, not be silently replaced.
func TestCorruptServerKeyIsAnError(t *testing.T) {
	m, _, st := testManager(t)
	ctx := context.Background()

	if err := st.SetSetting(ctx, store.SettingServerPrivateKey, "not-a-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.EnsureServerKey(ctx); err == nil {
		t.Fatal("a corrupt stored key was accepted")
	}
}

func TestSyncPushesEnabledPeersOnly(t *testing.T) {
	m, k, st := testManager(t)
	ctx := context.Background()
	plan, _ := ipam.NewPlan(netip.MustParsePrefix("10.10.0.0/24"))

	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	psk, _ := GeneratePresharedKey()

	p1, err := st.CreatePeer(ctx, plan, store.Peer{
		Name: "laptop", PublicKey: key1.PublicKey().String(), PresharedKey: psk.String(), Enabled: true,
	}, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePeer(ctx, plan, store.Peer{
		Name: "old-phone", PublicKey: key2.PublicKey().String(), PresharedKey: psk.String(), Enabled: false,
	}, netip.Addr{}); err != nil {
		t.Fatal(err)
	}

	if err := m.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	cfg, ok := k.LastConfig("wg0")
	if !ok {
		t.Fatal("no configuration was applied")
	}
	if len(cfg.Upsert) != 1 {
		t.Fatalf("pushed %d peers, want only the enabled one", len(cfg.Upsert))
	}
	if cfg.Upsert[0].PublicKey != key1.PublicKey() {
		t.Error("the wrong peer was pushed")
	}
	if cfg.Upsert[0].PresharedKey != psk {
		t.Error("the preshared key was not pushed")
	}
	if cfg.ListenPort == nil || *cfg.ListenPort != 51820 {
		t.Errorf("listen port = %v, want 51820", cfg.ListenPort)
	}

	// AllowedIPs must be exactly the peer's own address as a /32. Anything
	// wider would let one client claim another's address.
	want := ipam.HostPrefix(p1.TunnelIP)
	if len(cfg.Upsert[0].AllowedIPs) != 1 || cfg.Upsert[0].AllowedIPs[0] != want {
		t.Errorf("AllowedIPs = %v, want [%s]", cfg.Upsert[0].AllowedIPs, want)
	}

	// The link must have the router's address, with the pool's prefix length.
	if got := k.Links["wg0"]; got.String() != "10.10.0.1/24" {
		t.Errorf("link address = %s, want 10.10.0.1/24", got)
	}
}

func TestSyncRemovesDisabledPeerFromKernel(t *testing.T) {
	m, k, st := testManager(t)
	ctx := context.Background()
	plan, _ := ipam.NewPlan(netip.MustParsePrefix("10.10.0.0/24"))

	key, _ := GenerateKey()
	p, err := st.CreatePeer(ctx, plan, store.Peer{
		Name: "phone", PublicKey: key.PublicKey().String(), Enabled: true,
	}, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := k.LastConfig("wg0"); len(cfg.Upsert) != 1 {
		t.Fatalf("setup: expected 1 peer, got %d", len(cfg.Upsert))
	}

	if err := st.SetPeerEnabled(ctx, p.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// The peer must be explicitly removed, and the kernel must no longer list it.
	cfg, _ := k.LastConfig("wg0")
	if len(cfg.Remove) != 1 {
		t.Errorf("disabling a peer produced %d removals, want 1", len(cfg.Remove))
	}
	dev, err := k.Device(ctx, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if len(dev.Peers) != 0 {
		t.Error("disabling a peer did not remove it from the kernel; the toggle would be decorative")
	}
}

// One unparseable row must not stop every other peer being configured.
func TestSyncSkipsUnreadablePeer(t *testing.T) {
	m, k, st := testManager(t)
	ctx := context.Background()
	plan, _ := ipam.NewPlan(netip.MustParsePrefix("10.10.0.0/24"))

	good, _ := GenerateKey()
	if _, err := st.CreatePeer(ctx, plan, store.Peer{
		Name: "broken", PublicKey: "this-is-not-a-valid-key", Enabled: true,
	}, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePeer(ctx, plan, store.Peer{
		Name: "good", PublicKey: good.PublicKey().String(), Enabled: true,
	}, netip.Addr{}); err != nil {
		t.Fatal(err)
	}

	if err := m.Sync(ctx); err != nil {
		t.Fatalf("Sync failed because of one bad row: %v", err)
	}
	cfg, _ := k.LastConfig("wg0")
	if len(cfg.Upsert) != 1 || cfg.Upsert[0].PublicKey != good.PublicKey() {
		t.Errorf("expected only the good peer to be configured, got %d peers", len(cfg.Upsert))
	}
}

func TestSnapshotJoinsKernelStateWithDatabase(t *testing.T) {
	m, k, st := testManager(t)
	ctx := context.Background()
	plan, _ := ipam.NewPlan(netip.MustParsePrefix("10.10.0.0/24"))
	now := time.Now()

	key, _ := GenerateKey()
	if _, err := st.CreatePeer(ctx, plan, store.Peer{
		Name: "laptop", PublicKey: key.PublicKey().String(), Enabled: true,
	}, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}

	k.SetPeerState("wg0", PeerState{
		PublicKey:     key.PublicKey().String(),
		Endpoint:      "203.0.113.9:1234",
		LastHandshake: now.Add(-10 * time.Second),
		RxBytes:       4096,
		TxBytes:       2048,
	})

	snap, err := m.Snapshot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Up {
		t.Error("snapshot reports the interface down after a successful sync")
	}
	if len(snap.Peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(snap.Peers))
	}
	p := snap.Peers[0]
	if p.Name != "laptop" {
		t.Errorf("name = %q, want laptop (the database half of the join)", p.Name)
	}
	if p.Endpoint != "203.0.113.9:1234" || p.RxBytes != 4096 {
		t.Error("live kernel state was not joined onto the stored peer")
	}
	if p.Presence != PresenceOnline {
		t.Errorf("presence = %q, want online", p.Presence)
	}
	if !p.InKernel {
		t.Error("InKernel = false for a peer the kernel knows about")
	}
}

// Before the first sync there is no device; that is a state, not an error.
func TestSnapshotWithNoDeviceStillListsStoredPeers(t *testing.T) {
	m, _, st := testManager(t)
	ctx := context.Background()
	plan, _ := ipam.NewPlan(netip.MustParsePrefix("10.10.0.0/24"))

	key, _ := GenerateKey()
	if _, err := st.CreatePeer(ctx, plan, store.Peer{
		Name: "laptop", PublicKey: key.PublicKey().String(), Enabled: true,
	}, netip.Addr{}); err != nil {
		t.Fatal(err)
	}

	snap, err := m.Snapshot(ctx, time.Now())
	if err != nil {
		t.Fatalf("Snapshot returned an error for a missing device: %v", err)
	}
	if snap.Up {
		t.Error("Up = true with no device")
	}
	if len(snap.Peers) != 1 {
		t.Fatalf("got %d peers, want the stored one listed anyway", len(snap.Peers))
	}
	if snap.Peers[0].InKernel {
		t.Error("InKernel = true with no device")
	}
	if snap.Peers[0].Presence != PresenceNever {
		t.Errorf("presence = %q, want never", snap.Peers[0].Presence)
	}
}

// A kernel read failure must surface, not render as an empty device list.
func TestSnapshotSurfacesKernelError(t *testing.T) {
	m, k, st := testManager(t)
	ctx := context.Background()
	plan, _ := ipam.NewPlan(netip.MustParsePrefix("10.10.0.0/24"))

	key, _ := GenerateKey()
	if _, err := st.CreatePeer(ctx, plan, store.Peer{
		Name: "laptop", PublicKey: key.PublicKey().String(), Enabled: true,
	}, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	k.DeviceErr = errors.New("netlink is on fire")

	snap, err := m.Snapshot(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Err == nil {
		t.Error("a kernel read failure was swallowed")
	}
	if len(snap.Peers) != 1 {
		t.Error("stored peers should still be listed when the kernel cannot be read")
	}
}

// --- reconcile must not disturb live sessions -------------------------------

// The bug this guards against: Sync used ReplacePeers, which tells the kernel
// to remove every peer before re-adding the list. Removal destroys the peer's
// session -- negotiated keys, learned endpoint, byte counters -- so an
// unchanged peer was torn down and forced to re-handshake on every 60s tick.
// It presents as a VPN that randomly drops and reconnects, with nothing in the
// logs, and it is invisible unless a test asserts on session survival.
func TestReconcileDoesNotDisturbAnEstablishedPeer(t *testing.T) {
	m, k, st := testManager(t)
	ctx := context.Background()
	plan, _ := ipam.NewPlan(netip.MustParsePrefix("10.10.0.0/24"))

	key, _ := GenerateKey()
	if _, err := st.CreatePeer(ctx, plan, store.Peer{
		Name: "phone", PublicKey: key.PublicKey().String(), Enabled: true,
	}, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}

	// Simulate the peer connecting: it now has an endpoint, a handshake and
	// traffic counters.
	established := PeerState{
		PublicKey:     key.PublicKey().String(),
		Endpoint:      "203.0.113.9:51820",
		AllowedIPs:    []string{"10.10.0.2/32"},
		LastHandshake: time.Now(),
		RxBytes:       4096,
		TxBytes:       2048,
	}
	k.SetPeerState("wg0", established)

	// Reconcile repeatedly, as the 60s timer does.
	before := k.ConfigureCalls
	for i := 0; i < 5; i++ {
		if err := m.Sync(ctx); err != nil {
			t.Fatalf("sync %d: %v", i, err)
		}
	}

	// Nothing changed, so nothing should have been written to the kernel.
	if k.ConfigureCalls != before {
		t.Errorf("%d kernel writes for a no-op reconcile, want 0", k.ConfigureCalls-before)
	}

	dev, err := k.Device(ctx, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if len(dev.Peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(dev.Peers))
	}
	got := dev.Peers[0]
	if got.Endpoint != established.Endpoint {
		t.Errorf("endpoint = %q after reconcile, want %q preserved", got.Endpoint, established.Endpoint)
	}
	if got.LastHandshake.IsZero() {
		t.Error("the handshake was reset; the peer will have to renegotiate")
	}
	if got.RxBytes != 4096 || got.TxBytes != 2048 {
		t.Errorf("counters reset to rx=%d tx=%d; the peer object was destroyed and recreated",
			got.RxBytes, got.TxBytes)
	}

	// And the peer must still be reported online, not bounced back to "never".
	snap, err := m.Snapshot(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Peers[0].Presence != PresenceOnline {
		t.Errorf("presence = %q after reconcile, want online", snap.Peers[0].Presence)
	}
}

func TestDiffPeers(t *testing.T) {
	keyA, _ := GenerateKey()
	keyB, _ := GenerateKey()
	psk, _ := GeneratePresharedKey()

	specA := PeerSpec{PublicKey: keyA.PublicKey(), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.10.0.2/32")}}
	stateA := PeerState{PublicKey: keyA.PublicKey().String(), AllowedIPs: []string{"10.10.0.2/32"}}

	tests := []struct {
		name       string
		desired    map[wgtypes.Key]PeerSpec
		actual     map[wgtypes.Key]PeerState
		wantUpsert int
		wantRemove int
	}{
		{
			name:    "identical is a no-op",
			desired: map[wgtypes.Key]PeerSpec{keyA.PublicKey(): specA},
			actual:  map[wgtypes.Key]PeerState{keyA.PublicKey(): stateA},
		},
		{
			name:       "new peer is added",
			desired:    map[wgtypes.Key]PeerSpec{keyA.PublicKey(): specA},
			actual:     map[wgtypes.Key]PeerState{},
			wantUpsert: 1,
		},
		{
			name:       "unknown peer is removed",
			desired:    map[wgtypes.Key]PeerSpec{},
			actual:     map[wgtypes.Key]PeerState{keyB.PublicKey(): {PublicKey: keyB.PublicKey().String()}},
			wantRemove: 1,
		},
		{
			name:       "changed allowed ips is an update, not a remove",
			desired:    map[wgtypes.Key]PeerSpec{keyA.PublicKey(): specA},
			actual:     map[wgtypes.Key]PeerState{keyA.PublicKey(): {PublicKey: keyA.PublicKey().String(), AllowedIPs: []string{"10.10.0.9/32"}}},
			wantUpsert: 1,
		},
		{
			name:       "changed preshared key is an update",
			desired:    map[wgtypes.Key]PeerSpec{keyA.PublicKey(): {PublicKey: keyA.PublicKey(), PresharedKey: psk, AllowedIPs: specA.AllowedIPs}},
			actual:     map[wgtypes.Key]PeerState{keyA.PublicKey(): stateA},
			wantUpsert: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := diffPeers(tt.desired, tt.actual)
			if len(cfg.Upsert) != tt.wantUpsert {
				t.Errorf("upsert = %d, want %d", len(cfg.Upsert), tt.wantUpsert)
			}
			if len(cfg.Remove) != tt.wantRemove {
				t.Errorf("remove = %d, want %d", len(cfg.Remove), tt.wantRemove)
			}
			if tt.wantUpsert == 0 && tt.wantRemove == 0 && !cfg.Empty() {
				t.Error("a no-change diff did not report Empty()")
			}
		})
	}
}
