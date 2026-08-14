package forward

import (
	"fmt"
	"net/netip"
	"strings"
)

// SrcPolicy is how a forward treats the client's source address.
type SrcPolicy string

const (
	// SrcPolicyAny accepts every source. The default, and what a forward with
	// no ACL has always done.
	SrcPolicyAny SrcPolicy = "any"

	// SrcPolicyAllow accepts only the listed sources and drops everything else.
	// This is the safe direction for an administrative service: a source you
	// forgot to list is refused rather than admitted.
	SrcPolicyAllow SrcPolicy = "allow"

	// SrcPolicyDeny drops the listed sources and accepts everything else. Useful
	// for banning a scanner, but it fails open -- anything not listed gets in.
	SrcPolicyDeny SrcPolicy = "deny"
)

// Valid reports whether p is a policy we understand.
func (p SrcPolicy) Valid() bool {
	switch p {
	case SrcPolicyAny, SrcPolicyAllow, SrcPolicyDeny:
		return true
	}
	return false
}

// Label renders a policy for the UI.
func (p SrcPolicy) Label() string {
	switch p {
	case SrcPolicyAny:
		return "Any source"
	case SrcPolicyAllow:
		return "Allow listed only"
	case SrcPolicyDeny:
		return "Deny listed"
	default:
		return string(p)
	}
}

// MaxSourceEntries bounds an ACL.
//
// Each entry becomes its own kernel rule, so an unbounded list would let one
// forward fill the ruleset. Anything approaching this many entries wants a
// named set, which is a different feature.
const MaxSourceEntries = 32

// ParseSources turns the ACL text field into prefixes.
//
// Entries are separated by comma, newline or whitespace so an administrator can
// paste a list in whatever shape they already have it. A bare address is
// accepted and becomes a /32, because typing "203.0.113.9" and meaning "that
// one host" is overwhelmingly the common case.
func ParseSources(s string) ([]netip.Prefix, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ';'
	})
	if len(fields) == 0 {
		return nil, nil
	}
	if len(fields) > MaxSourceEntries {
		return nil, fmt.Errorf("at most %d source entries are allowed, got %d", MaxSourceEntries, len(fields))
	}

	out := make([]netip.Prefix, 0, len(fields))
	seen := map[netip.Prefix]bool{}
	for _, f := range fields {
		p, err := parseSource(f)
		if err != nil {
			return nil, err
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

func parseSource(f string) (netip.Prefix, error) {
	if strings.Contains(f, "/") {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a valid CIDR range", f)
		}
		if !p.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("%q is IPv6; only IPv4 sources are supported", f)
		}
		// Masked so 203.0.113.9/24 is stored as the network it actually means,
		// rather than silently matching something different from what is shown.
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(f)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a valid IP address or CIDR range", f)
	}
	a = a.Unmap()
	if !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("%q is IPv6; only IPv4 sources are supported", f)
	}
	return netip.PrefixFrom(a, 32), nil
}

// FormatSources renders prefixes back into the text field's format.
func FormatSources(ps []netip.Prefix) string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		// A /32 is shown as a bare address: that is how it was almost certainly
		// typed, and round-tripping it as "x/32" looks like the router changed
		// what the operator wrote.
		if p.Bits() == 32 {
			parts = append(parts, p.Addr().String())
			continue
		}
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ", ")
}
