package forward

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseSources(t *testing.T) {
	tests := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{in: "", want: nil},
		{in: "203.0.113.9", want: []string{"203.0.113.9/32"}},
		{in: "203.0.113.0/24", want: []string{"203.0.113.0/24"}},
		// Separators an operator might paste.
		{in: "203.0.113.9, 198.51.100.7", want: []string{"203.0.113.9/32", "198.51.100.7/32"}},
		{in: "203.0.113.9\n198.51.100.7", want: []string{"203.0.113.9/32", "198.51.100.7/32"}},
		{in: "203.0.113.9 198.51.100.7", want: []string{"203.0.113.9/32", "198.51.100.7/32"}},
		// A host address with a prefix is masked to the network it really means.
		{in: "203.0.113.9/24", want: []string{"203.0.113.0/24"}},
		// Duplicates collapse.
		{in: "1.1.1.1, 1.1.1.1", want: []string{"1.1.1.1/32"}},

		{in: "not-an-ip", wantErr: true},
		{in: "203.0.113.9/33", wantErr: true},
		{in: "2001:db8::1", wantErr: true},
		{in: "2001:db8::/32", wantErr: true},
		{in: strings.Repeat("1.1.1.1,", MaxSourceEntries+1), wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseSources(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseSources(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("ParseSources(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i].String() != tt.want[i] {
				t.Errorf("ParseSources(%q)[%d] = %s, want %s", tt.in, i, got[i], tt.want[i])
			}
		}
	}
}

// A /32 round-trips as a bare address, because that is how it was typed.
func TestFormatSourcesRoundTrip(t *testing.T) {
	in := "203.0.113.9, 198.51.100.0/24"
	parsed, err := ParseSources(in)
	if err != nil {
		t.Fatal(err)
	}
	got := FormatSources(parsed)
	if got != in {
		t.Errorf("round trip = %q, want %q", got, in)
	}
}

func TestSrcPolicyValidity(t *testing.T) {
	for _, p := range []SrcPolicy{SrcPolicyAny, SrcPolicyAllow, SrcPolicyDeny} {
		if !p.Valid() || p.Label() == "" {
			t.Errorf("%q should be a valid, labelled policy", p)
		}
	}
	for _, p := range []SrcPolicy{"", "block", "permit"} {
		if p.Valid() {
			t.Errorf("%q should not be valid", p)
		}
	}
}

// A restricting policy with no sources would either drop everything (allow) or
// nothing (deny). Both are almost certainly a mistake, so it is refused.
func TestValidateRejectsEmptyACL(t *testing.T) {
	for _, policy := range []SrcPolicy{SrcPolicyAllow, SrcPolicyDeny} {
		r := rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade)
		r.SrcPolicy = policy
		r.Sources = nil
		if err := r.Validate(testPool); err == nil {
			t.Errorf("policy %q with no sources was accepted", policy)
		}
	}
}

func TestValidateAcceptsACL(t *testing.T) {
	r := rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade)
	r.SrcPolicy = SrcPolicyAllow
	r.Sources = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	if err := r.Validate(testPool); err != nil {
		t.Errorf("a valid ACL was refused: %v", err)
	}
}

// The reconciler decides whether to rebuild by comparing rules, so an edited
// ACL has to register as a change -- otherwise the kernel keeps enforcing the
// old list while the UI shows the new one.
func TestRuleEqualNoticesACLChange(t *testing.T) {
	a := rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade)
	a.SrcPolicy = SrcPolicyAllow
	a.Sources = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}

	b := a
	b.Sources = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	if a.Equal(b) {
		t.Error("a changed source list compared equal")
	}

	c := a
	c.SrcPolicy = SrcPolicyDeny
	if a.Equal(c) {
		t.Error("a changed policy compared equal")
	}

	d := a
	d.RateLimit = !a.RateLimit
	if a.Equal(d) {
		t.Error("a changed rate-limit toggle compared equal")
	}

	same := a
	same.Sources = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	if !a.Equal(same) {
		t.Error("identical rules compared unequal; the ruleset would rebuild every tick")
	}
}
