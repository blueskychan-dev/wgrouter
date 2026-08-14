package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"wgrouter/internal/ipam"
)

// testFileStore opens a real on-disk store, matching how wgrouter runs.
func testFileStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(context.Background(), filepath.Join(t.TempDir(), "wgrouter.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return st
}

func testPlan(t *testing.T, pool string) ipam.Plan {
	t.Helper()
	p, err := ipam.NewPlan(netip.MustParsePrefix(pool))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	return p
}

// newPeer builds a peer with a distinct public key.
func newPeer(i int) Peer {
	return Peer{
		Name:         fmt.Sprintf("device-%d", i),
		PublicKey:    fmt.Sprintf("pubkey-%040d", i),
		PresharedKey: fmt.Sprintf("psk-%040d", i),
		Enabled:      true,
	}
}

func TestCreatePeerAllocatesSequentially(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	plan := testPlan(t, "10.10.0.0/24")

	var got []string
	for i := 0; i < 3; i++ {
		p, err := st.CreatePeer(ctx, plan, newPeer(i), netip.Addr{})
		if err != nil {
			t.Fatalf("CreatePeer %d: %v", i, err)
		}
		got = append(got, p.TunnelIP.String())
	}

	want := []string{"10.10.0.2", "10.10.0.3", "10.10.0.4"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("peer %d got %s, want %s", i, got[i], want[i])
		}
	}
}

// The brief's core IPAM requirement: concurrent allocations must never collide,
// and the arbiter must be the database rather than a mutex.
//
// This one test uses a file-backed store rather than the shared in-memory one.
// `cache=shared` makes SQLite take table-level locks and return SQLITE_LOCKED,
// which -- unlike SQLITE_BUSY -- does not invoke the busy handler, so
// busy_timeout cannot wait it out. That is a property of the test harness, not
// of wgrouter: the real database is always file-backed WAL. Testing concurrency
// against in-memory shared cache would measure locking semantics the running
// program never uses.
func TestCreatePeerIsSafeUnderConcurrency(t *testing.T) {
	st := testFileStore(t)
	ctx := context.Background()
	plan := testPlan(t, "10.10.0.0/24")

	const n = 40
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		addr = make(map[string]int)
		errs []error
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, err := st.CreatePeer(ctx, plan, newPeer(i), netip.Addr{})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			addr[p.TunnelIP.String()]++
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		t.Errorf("concurrent CreatePeer failed: %v", err)
	}
	if len(addr) != n {
		t.Errorf("got %d distinct addresses for %d peers", len(addr), n)
	}
	for a, count := range addr {
		if count > 1 {
			t.Errorf("address %s was handed out %d times", a, count)
		}
	}
}

func TestCreatePeerExhaustsThePool(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	plan := testPlan(t, "10.10.0.0/29") // 5 usable

	for i := 0; i < plan.Capacity(); i++ {
		if _, err := st.CreatePeer(ctx, plan, newPeer(i), netip.Addr{}); err != nil {
			t.Fatalf("CreatePeer %d: %v", i, err)
		}
	}
	_, err := st.CreatePeer(ctx, plan, newPeer(99), netip.Addr{})
	if !errors.Is(err, ipam.ErrPoolExhausted) {
		t.Errorf("err = %v, want ErrPoolExhausted", err)
	}
}

// A deleted peer's address must return to the pool.
func TestDeletedAddressIsReused(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	plan := testPlan(t, "10.10.0.0/24")

	first, err := st.CreatePeer(ctx, plan, newPeer(0), netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePeer(ctx, plan, newPeer(1), netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePeer(ctx, first.ID); err != nil {
		t.Fatal(err)
	}

	reused, err := st.CreatePeer(ctx, plan, newPeer(2), netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if reused.TunnelIP != first.TunnelIP {
		t.Errorf("reused address = %s, want the freed %s", reused.TunnelIP, first.TunnelIP)
	}
}

// A disabled peer keeps its address. Moving a device's IP when it is re-enabled
// would silently break every port forward pointing at it.
func TestDisabledPeerKeepsItsAddress(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	plan := testPlan(t, "10.10.0.0/24")

	p, err := st.CreatePeer(ctx, plan, newPeer(0), netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetPeerEnabled(ctx, p.ID, false); err != nil {
		t.Fatal(err)
	}
	next, err := st.CreatePeer(ctx, plan, newPeer(1), netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if next.TunnelIP == p.TunnelIP {
		t.Errorf("a disabled peer's address %s was handed to another device", p.TunnelIP)
	}
}

func TestCreatePeerRejectsDuplicatePublicKey(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	plan := testPlan(t, "10.10.0.0/24")

	if _, err := st.CreatePeer(ctx, plan, newPeer(0), netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	_, err := st.CreatePeer(ctx, plan, newPeer(0), netip.Addr{})
	if !errors.Is(err, ErrDuplicateKey) {
		t.Errorf("err = %v, want ErrDuplicateKey", err)
	}
}

func TestCreatePeerWithPinnedAddress(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	plan := testPlan(t, "10.10.0.0/24")

	pin := netip.MustParseAddr("10.10.0.50")
	p, err := st.CreatePeer(ctx, plan, newPeer(0), pin)
	if err != nil {
		t.Fatal(err)
	}
	if p.TunnelIP != pin {
		t.Errorf("address = %s, want the pinned %s", p.TunnelIP, pin)
	}

	_, err = st.CreatePeer(ctx, plan, newPeer(1), pin)
	if !errors.Is(err, ErrAddressTaken) {
		t.Errorf("err = %v, want ErrAddressTaken", err)
	}
}

func TestPeersAreSortedNumerically(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	plan := testPlan(t, "10.10.0.0/24")

	// .10 sorts before .2 as text, so this ordering only comes out right if the
	// sort is numeric.
	for i, s := range []string{"10.10.0.10", "10.10.0.2", "10.10.0.30"} {
		if _, err := st.CreatePeer(ctx, plan, newPeer(i), netip.MustParseAddr(s)); err != nil {
			t.Fatal(err)
		}
	}
	peers, err := st.Peers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.10.0.2", "10.10.0.10", "10.10.0.30"}
	for i := range want {
		if peers[i].TunnelIP.String() != want[i] {
			t.Errorf("position %d = %s, want %s", i, peers[i].TunnelIP, want[i])
		}
	}
}

func TestPeerLifecycle(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	plan := testPlan(t, "10.10.0.0/24")

	p, err := st.CreatePeer(ctx, plan, newPeer(0), netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}

	if err := st.RenamePeer(ctx, p.ID, "renamed", "a note"); err != nil {
		t.Fatal(err)
	}
	got, err := st.PeerByID(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "renamed" || got.Notes != "a note" {
		t.Errorf("after rename: name=%q notes=%q", got.Name, got.Notes)
	}
	if !got.Enabled {
		t.Error("peer should still be enabled")
	}

	if err := st.SetPeerEnabled(ctx, p.ID, false); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.PeerByID(ctx, p.ID); got.Enabled {
		t.Error("peer should be disabled")
	}

	if err := st.DeletePeer(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PeerByID(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: err = %v, want ErrNotFound", err)
	}
}

func TestMutatingAMissingPeerReportsNotFound(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if err := st.DeletePeer(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeletePeer: err = %v, want ErrNotFound", err)
	}
	if err := st.SetPeerEnabled(ctx, 999, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetPeerEnabled: err = %v, want ErrNotFound", err)
	}
	if err := st.RenamePeer(ctx, 999, "x", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("RenamePeer: err = %v, want ErrNotFound", err)
	}
}
