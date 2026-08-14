// Package ipam allocates tunnel addresses out of the peer pool.
//
// The allocation policy lives here as pure functions over a set of addresses
// already in use. Deciding *which* address is free is separable from making
// that decision stick, and the two have very different testing needs: this half
// is exhaustively testable in memory, while the half that matters for
// correctness under concurrency is a database transaction (see store.CreatePeer).
//
// Note what is deliberately not here: a mutex. A mutex would serialise
// allocations within one process and prove nothing -- it would still be
// possible for two allocations to observe the same free address if anything
// else ever wrote to the table. The UNIQUE constraint on peers.tunnel_ip is the
// arbiter, and a caller that loses the race retries against fresh state.
package ipam

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrPoolExhausted is returned when every usable address in the pool is taken.
var ErrPoolExhausted = errors.New("ipam: address pool exhausted")

// ErrOutsidePool is returned for an address that is not in the pool at all.
var ErrOutsidePool = errors.New("ipam: address is outside the tunnel pool")

// Plan describes the pool and the addresses within it that are not available
// to peers.
type Plan struct {
	Pool     netip.Prefix
	ServerIP netip.Addr
}

// NewPlan validates a pool and derives the server's own address: the first
// usable address in the range.
func NewPlan(pool netip.Prefix) (Plan, error) {
	pool = pool.Masked()
	if !pool.Addr().Is4() {
		return Plan{}, fmt.Errorf("ipam: pool %s: only IPv4 pools are supported", pool)
	}
	// A /31 has no usable host addresses under the convention below, and a /32
	// is a single address with nothing left over for peers.
	if pool.Bits() > 30 {
		return Plan{}, fmt.Errorf("ipam: pool %s is too small; use /30 or larger", pool)
	}
	server := pool.Addr().Next()
	return Plan{Pool: pool, ServerIP: server}, nil
}

// Capacity is how many addresses the pool can hand out to peers.
//
// The network address, the broadcast address and the server's own address are
// all excluded. Strictly, a routed point-to-point tunnel does not need a
// broadcast address reserved -- but client operating systems and their users
// both expect a /24 to behave like a LAN, and handing out .255 invites a class
// of bug that is tedious to diagnose for the sake of one extra address.
func (p Plan) Capacity() int {
	hostBits := 32 - p.Pool.Bits()
	total := 1 << hostBits
	return total - 3
}

// Contains reports whether addr is a valid peer address in this pool.
func (p Plan) Contains(addr netip.Addr) bool {
	if !p.Pool.Contains(addr) {
		return false
	}
	return !p.reserved(addr)
}

// reserved reports whether addr is in the pool but not assignable to a peer.
func (p Plan) reserved(addr netip.Addr) bool {
	return addr == p.Pool.Addr() || addr == p.ServerIP || addr == p.broadcast()
}

// broadcast returns the last address in the pool.
func (p Plan) broadcast() netip.Addr {
	addr := p.Pool.Addr().As4()
	hostBits := 32 - p.Pool.Bits()
	// Set every host bit.
	var mask uint32
	if hostBits >= 32 {
		mask = ^uint32(0)
	} else {
		mask = (uint32(1) << hostBits) - 1
	}
	v := uint32(addr[0])<<24 | uint32(addr[1])<<16 | uint32(addr[2])<<8 | uint32(addr[3])
	v |= mask
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Next returns the lowest address in the pool that is not already used and not
// reserved.
//
// Lowest-free rather than sequential-next: addresses are reused after a peer is
// deleted, which keeps a long-lived router's addresses dense and readable
// instead of drifting upward forever. The tradeoff is that a deleted peer's
// address can be handed to a different device later, so the audit log records
// both the name and the address at creation time.
func (p Plan) Next(used map[netip.Addr]bool) (netip.Addr, error) {
	for addr := p.ServerIP.Next(); p.Pool.Contains(addr); addr = addr.Next() {
		if p.reserved(addr) {
			continue
		}
		if !used[addr] {
			return addr, nil
		}
	}
	return netip.Addr{}, ErrPoolExhausted
}

// Parse validates a caller-supplied address against the pool, for the case
// where an administrator pins a specific address rather than taking the next
// free one.
func (p Plan) Parse(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ipam: parse address %q: %w", s, err)
	}
	addr = addr.Unmap()
	if !p.Pool.Contains(addr) {
		return netip.Addr{}, fmt.Errorf("%w: %s is not in %s", ErrOutsidePool, addr, p.Pool)
	}
	if p.reserved(addr) {
		return netip.Addr{}, fmt.Errorf("ipam: %s is reserved (network, broadcast or the router itself)", addr)
	}
	return addr, nil
}

// HostPrefix returns addr as a single-host prefix, which is what a peer's
// AllowedIPs must be.
func HostPrefix(addr netip.Addr) netip.Prefix {
	return netip.PrefixFrom(addr, addr.BitLen())
}
