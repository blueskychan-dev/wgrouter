package ipam

import (
	"errors"
	"net/netip"
	"testing"
)

func mustPlan(t *testing.T, s string) Plan {
	t.Helper()
	p, err := NewPlan(netip.MustParsePrefix(s))
	if err != nil {
		t.Fatalf("NewPlan(%q): %v", s, err)
	}
	return p
}

func TestNewPlanDerivesServerAddress(t *testing.T) {
	tests := []struct {
		pool       string
		wantServer string
		wantCap    int
	}{
		{"10.10.0.0/24", "10.10.0.1", 253},
		{"192.168.9.0/28", "192.168.9.1", 13},
		{"172.16.0.0/30", "172.16.0.1", 1},
	}
	for _, tt := range tests {
		p := mustPlan(t, tt.pool)
		if got := p.ServerIP.String(); got != tt.wantServer {
			t.Errorf("%s: server = %s, want %s", tt.pool, got, tt.wantServer)
		}
		if got := p.Capacity(); got != tt.wantCap {
			t.Errorf("%s: capacity = %d, want %d", tt.pool, got, tt.wantCap)
		}
	}
}

func TestNewPlanRejectsUnusablePools(t *testing.T) {
	for _, s := range []string{"10.0.0.0/31", "10.0.0.1/32", "fd00::/64"} {
		if _, err := NewPlan(netip.MustParsePrefix(s)); err == nil {
			t.Errorf("NewPlan(%q) succeeded, want an error", s)
		}
	}
}

// An unmasked pool must be normalised, or every containment check below it is
// computed against the wrong network.
func TestNewPlanMasksThePool(t *testing.T) {
	p, err := NewPlan(netip.MustParsePrefix("10.10.0.37/24"))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Pool.String(); got != "10.10.0.0/24" {
		t.Errorf("pool = %s, want 10.10.0.0/24", got)
	}
	if got := p.ServerIP.String(); got != "10.10.0.1" {
		t.Errorf("server = %s, want 10.10.0.1", got)
	}
}

func TestNextSkipsReservedAndUsed(t *testing.T) {
	p := mustPlan(t, "10.10.0.0/24")

	addr, err := p.Next(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := addr.String(); got != "10.10.0.2" {
		t.Errorf("first allocation = %s, want 10.10.0.2 (.0 network, .1 router)", got)
	}

	used := map[netip.Addr]bool{
		netip.MustParseAddr("10.10.0.2"): true,
		netip.MustParseAddr("10.10.0.3"): true,
	}
	addr, err = p.Next(used)
	if err != nil {
		t.Fatal(err)
	}
	if got := addr.String(); got != "10.10.0.4" {
		t.Errorf("next allocation = %s, want 10.10.0.4", got)
	}
}

// Freed addresses are reused rather than the counter marching upward.
func TestNextReusesTheLowestFreeAddress(t *testing.T) {
	p := mustPlan(t, "10.10.0.0/24")
	used := map[netip.Addr]bool{
		netip.MustParseAddr("10.10.0.2"): true,
		netip.MustParseAddr("10.10.0.4"): true,
	}
	addr, err := p.Next(used)
	if err != nil {
		t.Fatal(err)
	}
	if got := addr.String(); got != "10.10.0.3" {
		t.Errorf("allocation = %s, want the gap at 10.10.0.3", got)
	}
}

func TestNextExhaustsCleanly(t *testing.T) {
	p := mustPlan(t, "10.10.0.0/29") // .0 network, .1 router, .7 broadcast => 5 usable

	used := map[netip.Addr]bool{}
	var got []string
	for {
		addr, err := p.Next(used)
		if errors.Is(err, ErrPoolExhausted) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		used[addr] = true
		got = append(got, addr.String())
		if len(got) > 16 {
			t.Fatal("Next never exhausted; it is handing out addresses outside the pool")
		}
	}

	want := []string{"10.10.0.2", "10.10.0.3", "10.10.0.4", "10.10.0.5", "10.10.0.6"}
	if len(got) != len(want) {
		t.Fatalf("allocated %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("allocation %d = %s, want %s", i, got[i], want[i])
		}
	}
	if p.Capacity() != len(want) {
		t.Errorf("Capacity() = %d but %d addresses were allocated", p.Capacity(), len(want))
	}
}

// The broadcast address must never be handed out, at any prefix length.
func TestBroadcastIsNeverAllocated(t *testing.T) {
	for _, pool := range []string{"10.10.0.0/24", "10.10.0.0/28", "10.10.0.0/30", "172.20.5.0/22"} {
		p := mustPlan(t, pool)
		used := map[netip.Addr]bool{}
		for {
			addr, err := p.Next(used)
			if err != nil {
				break
			}
			if addr == p.broadcast() {
				t.Errorf("%s: allocated the broadcast address %s", pool, addr)
			}
			if addr == p.ServerIP {
				t.Errorf("%s: allocated the router's own address %s", pool, addr)
			}
			used[addr] = true
		}
	}
}

func TestParseRejectsOutsideAndReserved(t *testing.T) {
	p := mustPlan(t, "10.10.0.0/24")

	if _, err := p.Parse("10.10.0.9"); err != nil {
		t.Errorf("Parse of a valid in-pool address failed: %v", err)
	}
	if _, err := p.Parse("192.168.1.5"); !errors.Is(err, ErrOutsidePool) {
		t.Errorf("Parse outside the pool: err = %v, want ErrOutsidePool", err)
	}
	for _, s := range []string{"10.10.0.0", "10.10.0.1", "10.10.0.255"} {
		if _, err := p.Parse(s); err == nil {
			t.Errorf("Parse(%q) succeeded; it is reserved", s)
		}
	}
	if _, err := p.Parse("not-an-ip"); err == nil {
		t.Error("Parse of a malformed address succeeded")
	}
}

func TestHostPrefixIsASingleHost(t *testing.T) {
	got := HostPrefix(netip.MustParseAddr("10.10.0.7"))
	if got.String() != "10.10.0.7/32" {
		t.Errorf("HostPrefix = %s, want 10.10.0.7/32", got)
	}
}

func TestContains(t *testing.T) {
	p := mustPlan(t, "10.10.0.0/24")
	tests := []struct {
		addr string
		want bool
	}{
		{"10.10.0.2", true},
		{"10.10.0.254", true},
		{"10.10.0.0", false},   // network
		{"10.10.0.1", false},   // router
		{"10.10.0.255", false}, // broadcast
		{"10.10.1.2", false},   // outside
	}
	for _, tt := range tests {
		if got := p.Contains(netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("Contains(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}
