// Package forward programs the kernel's NAT rules from the forwards stored in
// the database.
//
// The database is the source of truth and nftables is derived state. The
// reconciler flushes wgrouter's own table and rebuilds it from the database:
// on startup, after every mutation, and on a timer. That makes drift
// self-correcting and means there is exactly one code path that writes rules.
//
// wgrouter owns exactly one table, `inet wgrouter`, and touches nothing else.
// Other tables belong to other software -- Docker, firewalld, an
// administrator's own ruleset -- and flushing or reordering them would break
// things wgrouter has no business breaking.
package forward

import (
	"fmt"
	"net/netip"
	"strings"
)

// TableName is the single nftables table wgrouter owns.
const TableName = "wgrouter"

// LogPrefix marks our own lines in the kernel log stream.
//
// It lives here rather than in the Linux-only rule builder so that the reader
// which parses those lines can assert against the same constant. The two
// drifting apart would leave the firewall log silently empty: rules emitting
// one prefix, a reader looking for another, and no error anywhere.
const LogPrefix = "wgrouter-drop "

// Proto is the transport protocol a forward matches.
type Proto string

const (
	ProtoTCP  Proto = "tcp"
	ProtoUDP  Proto = "udp"
	ProtoBoth Proto = "both"
)

// Valid reports whether p is a protocol we understand.
func (p Proto) Valid() bool {
	switch p {
	case ProtoTCP, ProtoUDP, ProtoBoth:
		return true
	}
	return false
}

// Covers reports whether p includes the transport protocol other.
func (p Proto) Covers(other Proto) bool {
	if p == ProtoBoth || other == ProtoBoth {
		return true
	}
	return p == other
}

// SrcMode is how the client's source address is handled. This is the choice
// with real consequences for the peer, so it is explicit per forward rather
// than a global setting.
type SrcMode string

const (
	// SrcModeMasquerade rewrites the source to the router's tunnel address.
	// Always works, and the peer never learns who connected -- so wgrouter
	// records the origin in its own connection log as compensation.
	SrcModeMasquerade SrcMode = "masquerade"

	// SrcModeDirect leaves the source address alone. The peer sees the real
	// client, but only works if the peer routes its replies back through the
	// tunnel; otherwise replies leave by the wrong path and the connection
	// hangs in a way that looks exactly like a firewall drop.
	SrcModeDirect SrcMode = "direct"
)

// Valid reports whether m is a mode we understand.
func (m SrcMode) Valid() bool {
	switch m {
	case SrcModeMasquerade, SrcModeDirect:
		return true
	}
	return false
}

// Label renders a mode for the UI.
func (m SrcMode) Label() string {
	switch m {
	case SrcModeMasquerade:
		return "Masquerade"
	case SrcModeDirect:
		return "Direct"
	default:
		return string(m)
	}
}

// Rule is one forward, as the kernel should implement it.
type Rule struct {
	ID    int64
	Label string
	Proto Proto

	// Listen is the WAN port or range. A range forwards each port straight
	// through to the same port on the peer -- see TargetPort.
	Listen PortRange

	TargetIP netip.Addr

	// TargetPort applies only to a single-port forward. A range cannot
	// meaningfully be remapped onto one port, and mapping it onto another range
	// relies on netfilter picking the matching offset, which is not something to
	// build a firewall on. So a range preserves the port and this is ignored.
	TargetPort uint16

	SrcMode SrcMode

	// RateLimit enables per-forward flood protection.
	RateLimit bool

	// SrcPolicy and Sources are the access control list.
	SrcPolicy SrcPolicy
	Sources   []netip.Prefix
}

// Equal reports whether two rules would produce the same kernel state.
//
// slices.Equal cannot be used on Rule directly once it contains a slice field,
// and the reconciler depends on this comparison to decide whether to rebuild --
// getting it wrong either rebuilds constantly (resetting counters) or never
// (ignoring edits).
func (r Rule) Equal(o Rule) bool {
	if r.ID != o.ID || r.Label != o.Label || r.Proto != o.Proto ||
		r.Listen != o.Listen || r.TargetIP != o.TargetIP ||
		r.TargetPort != o.TargetPort || r.SrcMode != o.SrcMode ||
		r.RateLimit != o.RateLimit || r.SrcPolicy != o.SrcPolicy ||
		len(r.Sources) != len(o.Sources) {
		return false
	}
	for i := range r.Sources {
		if r.Sources[i] != o.Sources[i] {
			return false
		}
	}
	return true
}

// EffectiveTargetPort is the port traffic arrives on at the peer.
func (r Rule) EffectiveTargetPort(listenPort uint16) uint16 {
	if r.Listen.IsRange() {
		return listenPort
	}
	return r.TargetPort
}

// Transports expands Proto into the concrete protocols to program. A rule with
// ProtoBoth becomes one TCP rule and one UDP rule, because nftables matches on
// a concrete transport header.
func (r Rule) Transports() []Proto {
	if r.Proto == ProtoBoth {
		return []Proto{ProtoTCP, ProtoUDP}
	}
	return []Proto{r.Proto}
}

// Validate checks a rule is programmable.
//
// This runs before anything reaches the kernel. Port numbers arrive as text
// from an HTTP form, and a value that is merely stored wrong is a bug, while a
// value that reaches a rule builder wrong is a firewall that does not do what
// the administrator was shown.
func (r Rule) Validate(pool netip.Prefix) error {
	if strings.TrimSpace(r.Label) == "" {
		return fmt.Errorf("forward: label is required")
	}
	if !r.Proto.Valid() {
		return fmt.Errorf("forward: unknown protocol %q", r.Proto)
	}
	if !r.SrcMode.Valid() {
		return fmt.Errorf("forward: unknown source mode %q", r.SrcMode)
	}
	if !r.Listen.Valid() {
		return fmt.Errorf("forward: listen port must be between 1 and 65535")
	}
	if !r.Listen.IsRange() && r.TargetPort == 0 {
		return fmt.Errorf("forward: target port must be between 1 and 65535")
	}
	// A range costs one kernel rule set per transport regardless of width, but
	// an enormous range is far more often a typo than an intent.
	if r.Listen.Count() > 4096 {
		return fmt.Errorf("forward: port range %s covers %d ports; at most 4096 are allowed",
			r.Listen, r.Listen.Count())
	}
	if !r.SrcPolicy.Valid() {
		return fmt.Errorf("forward: unknown source policy %q", r.SrcPolicy)
	}
	if r.SrcPolicy != SrcPolicyAny && len(r.Sources) == 0 {
		return fmt.Errorf("forward: the %q source policy needs at least one address or range", r.SrcPolicy)
	}
	if len(r.Sources) > MaxSourceEntries {
		return fmt.Errorf("forward: at most %d source entries are allowed", MaxSourceEntries)
	}
	if !r.TargetIP.IsValid() || !r.TargetIP.Is4() {
		return fmt.Errorf("forward: target address %q is not a valid IPv4 address", r.TargetIP)
	}
	// The target must be inside the tunnel. Forwarding a WAN port to an
	// arbitrary address would turn the router into an open relay into whatever
	// network it can reach.
	if !pool.Contains(r.TargetIP) {
		return fmt.Errorf("forward: target %s is outside the tunnel pool %s", r.TargetIP, pool)
	}
	return nil
}

// Conflict describes two rules that cannot both be active.
type Conflict struct {
	Existing Rule
	Incoming Rule
}

func (c Conflict) Error() string {
	return fmt.Sprintf("port %s/%s overlaps %s/%s, already forwarded by %q",
		c.Incoming.Listen, c.Incoming.Proto,
		c.Existing.Listen, c.Existing.Proto, c.Existing.Label)
}

// CheckOverlap reports whether incoming claims a listen port already claimed by
// one of existing.
//
// The database has a partial unique index on (proto, listen_port), but SQLite
// cannot express that 'both' overlaps 'tcp' -- they are different values in the
// same column. So the real check lives here, and the index is a backstop
// against a bug in this function rather than the other way round.
func CheckOverlap(existing []Rule, incoming Rule) error {
	for _, e := range existing {
		if e.ID == incoming.ID {
			continue // updating a rule does not conflict with itself
		}
		if !e.Listen.Normalised().Overlaps(incoming.Listen.Normalised()) {
			continue
		}
		if e.Proto.Covers(incoming.Proto) {
			return Conflict{Existing: e, Incoming: incoming}
		}
	}
	return nil
}
