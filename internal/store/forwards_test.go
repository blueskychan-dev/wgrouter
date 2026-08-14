package store

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"wgrouter/internal/forward"
)

// seedPeer creates a peer to hang forwards off, returning its public key.
func seedPeer(t *testing.T, st *Store) (string, netip.Addr) {
	t.Helper()
	ctx := context.Background()
	p, err := st.CreatePeer(ctx, testPlan(t, "10.10.0.0/24"), newPeer(0), netip.Addr{})
	if err != nil {
		t.Fatalf("seed peer: %v", err)
	}
	return p.PublicKey, p.TunnelIP
}

func newForward(key string, ip netip.Addr, proto forward.Proto, listen uint16) Forward {
	return Forward{
		Label:      "test forward",
		Proto:      proto,
		Listen:     forward.PortRange{Start: listen, End: listen},
		RateLimit:  true,
		SrcPolicy:  forward.SrcPolicyAny,
		TargetPeer: key,
		TargetIP:   ip,
		TargetPort: 8080,
		SrcMode:    forward.SrcModeMasquerade,
		Enabled:    true,
	}
}

func TestForwardRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	key, ip := seedPeer(t, st)

	created, err := st.CreateForward(ctx, newForward(key, ip, forward.ProtoTCP, 443))
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 {
		t.Error("no ID was assigned")
	}

	got, err := st.ForwardByID(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Listen.Start != 443 || got.TargetIP != ip || got.Proto != forward.ProtoTCP {
		t.Errorf("round trip lost data: %+v", got)
	}
	if got.PeerName == "" {
		t.Error("the peer name was not joined onto the forward")
	}
	if got.SrcMode != forward.SrcModeMasquerade {
		t.Errorf("source mode = %q, want masquerade", got.SrcMode)
	}
}

// The overlap case SQLite's index cannot catch, checked through the store.
func TestCreateForwardRejectsProtocolOverlap(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	key, ip := seedPeer(t, st)

	if _, err := st.CreateForward(ctx, newForward(key, ip, forward.ProtoBoth, 443)); err != nil {
		t.Fatal(err)
	}
	_, err := st.CreateForward(ctx, newForward(key, ip, forward.ProtoTCP, 443))

	var conflict forward.Conflict
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want a forward.Conflict for tcp/443 against both/443", err)
	}
}

func TestCreateForwardAllowsDifferentProtocolOnSamePort(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	key, ip := seedPeer(t, st)

	if _, err := st.CreateForward(ctx, newForward(key, ip, forward.ProtoTCP, 5000)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateForward(ctx, newForward(key, ip, forward.ProtoUDP, 5000)); err != nil {
		t.Errorf("tcp and udp on the same port should coexist: %v", err)
	}
}

// A disabled forward does not hold the port; enabling it must re-check.
func TestDisabledForwardDoesNotHoldThePort(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	key, ip := seedPeer(t, st)

	disabled := newForward(key, ip, forward.ProtoTCP, 443)
	disabled.Enabled = false
	created, err := st.CreateForward(ctx, disabled)
	if err != nil {
		t.Fatal(err)
	}

	// A second, enabled forward may take the port.
	if _, err := st.CreateForward(ctx, newForward(key, ip, forward.ProtoTCP, 443)); err != nil {
		t.Fatalf("an enabled forward could not take a port held only by a disabled one: %v", err)
	}

	// Enabling the first must now be refused.
	err = st.SetForwardEnabled(ctx, created.ID, true)
	var conflict forward.Conflict
	if !errors.As(err, &conflict) {
		t.Errorf("enabling a conflicting forward: err = %v, want a Conflict", err)
	}
}

func TestEnabledForwardRulesOnlyReturnsEnabled(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	key, ip := seedPeer(t, st)

	if _, err := st.CreateForward(ctx, newForward(key, ip, forward.ProtoTCP, 443)); err != nil {
		t.Fatal(err)
	}
	off := newForward(key, ip, forward.ProtoTCP, 444)
	off.Enabled = false
	if _, err := st.CreateForward(ctx, off); err != nil {
		t.Fatal(err)
	}

	rules, err := st.EnabledForwardRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Listen.Start != 443 {
		t.Errorf("rules = %+v, want only the enabled forward on 443", rules)
	}
}

// Deleting a peer must take its forwards with it: a forward pointing at an
// address nobody owns would send WAN traffic into a black hole.
func TestDeletingAPeerCascadesToItsForwards(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	key, ip := seedPeer(t, st)

	if _, err := st.CreateForward(ctx, newForward(key, ip, forward.ProtoTCP, 443)); err != nil {
		t.Fatal(err)
	}
	peers, err := st.Peers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePeer(ctx, peers[0].ID); err != nil {
		t.Fatal(err)
	}

	rest, err := st.Forwards(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Errorf("%d forwards survived the peer they pointed at", len(rest))
	}
}

func TestForwardsAreOrderedByListenPort(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	key, ip := seedPeer(t, st)

	for _, port := range []uint16{8080, 443, 22} {
		if _, err := st.CreateForward(ctx, newForward(key, ip, forward.ProtoTCP, port)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.Forwards(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{22, 443, 8080}
	for i := range want {
		if got[i].Listen.Start != want[i] {
			t.Errorf("position %d = %d, want %d", i, got[i].Listen.Start, want[i])
		}
	}
}

func TestDeleteAndToggleMissingForward(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if err := st.DeleteForward(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteForward: err = %v, want ErrNotFound", err)
	}
	if err := st.SetForwardEnabled(ctx, 999, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetForwardEnabled: err = %v, want ErrNotFound", err)
	}
}

// A port-range forward has no single target port: every port passes straight
// through. The schema has to permit that, not force a placeholder value.
func TestPortRangeForwardStoresWithoutTargetPort(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	key, ip := seedPeer(t, st)

	f := newForward(key, ip, forward.ProtoTCP, 8080)
	f.Listen = forward.PortRange{Start: 8080, End: 8090}
	f.TargetPort = 0

	created, err := st.CreateForward(ctx, f)
	if err != nil {
		t.Fatalf("a port range could not be stored: %v", err)
	}

	got, err := st.ForwardByID(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Listen.Start != 8080 || got.Listen.End != 8090 {
		t.Errorf("range round-tripped as %s", got.Listen)
	}
	if !got.Listen.IsRange() {
		t.Error("the stored forward is not reported as a range")
	}
}

// Overlapping ranges must be refused by the store, not just by the pure check.
func TestCreateForwardRejectsOverlappingRange(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	key, ip := seedPeer(t, st)

	first := newForward(key, ip, forward.ProtoTCP, 8080)
	first.Listen = forward.PortRange{Start: 8080, End: 8090}
	first.TargetPort = 0
	if _, err := st.CreateForward(ctx, first); err != nil {
		t.Fatal(err)
	}

	// A single port inside the range.
	inside := newForward(key, ip, forward.ProtoTCP, 8085)
	_, err := st.CreateForward(ctx, inside)
	var conflict forward.Conflict
	if !errors.As(err, &conflict) {
		t.Errorf("a port inside an existing range was accepted: err = %v", err)
	}
}

// The ACL and the rate-limit toggle must survive a round trip.
func TestForwardACLRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	key, ip := seedPeer(t, st)

	f := newForward(key, ip, forward.ProtoTCP, 3389)
	f.RateLimit = false
	f.SrcPolicy = forward.SrcPolicyAllow
	f.Sources = []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("198.51.100.7/32"),
	}
	created, err := st.CreateForward(ctx, f)
	if err != nil {
		t.Fatal(err)
	}

	got, err := st.ForwardByID(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RateLimit {
		t.Error("the rate-limit toggle was not persisted")
	}
	if got.SrcPolicy != forward.SrcPolicyAllow {
		t.Errorf("policy = %q, want allow", got.SrcPolicy)
	}
	if len(got.Sources) != 2 {
		t.Fatalf("got %d sources, want 2", len(got.Sources))
	}
	if got.Sources[0].String() != "203.0.113.0/24" {
		t.Errorf("source[0] = %s", got.Sources[0])
	}

	// And the kernel-facing rule must carry them.
	rules, err := st.EnabledForwardRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || len(rules[0].Sources) != 2 || rules[0].RateLimit {
		t.Errorf("rule = %+v, want the ACL and the disabled rate limit", rules[0])
	}
}
