package forward

import "testing"

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		in         string
		start, end uint16
		isRange    bool
		wantErr    bool
	}{
		{in: "8080", start: 8080, end: 8080},
		{in: " 443 ", start: 443, end: 443},
		{in: "8080-8090", start: 8080, end: 8090, isRange: true},
		{in: "1-65535", start: 1, end: 65535, isRange: true},
		{in: "8080 - 8090", start: 8080, end: 8090, isRange: true},
		// A single-port "range" is not a range.
		{in: "8080-8080", start: 8080, end: 8080},

		{in: "", wantErr: true},
		{in: "-1", wantErr: true},
		{in: "0", wantErr: true},
		{in: "65536", wantErr: true},
		{in: "8090-8080", wantErr: true}, // backwards
		{in: "8080-", wantErr: true},
		{in: "-8080", wantErr: true},
		{in: "http", wantErr: true},
		{in: "80,443", wantErr: true},
		{in: "8080-8090-9000", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParsePortRange(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParsePortRange(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			continue
		}
		if got.Start != tt.start || got.End != tt.end {
			t.Errorf("ParsePortRange(%q) = %d-%d, want %d-%d", tt.in, got.Start, got.End, tt.start, tt.end)
		}
		if got.IsRange() != tt.isRange {
			t.Errorf("ParsePortRange(%q).IsRange() = %v, want %v", tt.in, got.IsRange(), tt.isRange)
		}
	}
}

func TestPortRangeString(t *testing.T) {
	if got := (PortRange{Start: 80, End: 80}).String(); got != "80" {
		t.Errorf("single port rendered as %q", got)
	}
	if got := (PortRange{Start: 80, End: 90}).String(); got != "80-90" {
		t.Errorf("range rendered as %q", got)
	}
	// A zero End is a single port that has not been normalised.
	if got := (PortRange{Start: 80}).String(); got != "80" {
		t.Errorf("unnormalised range rendered as %q", got)
	}
}

func TestPortRangeOverlaps(t *testing.T) {
	tests := []struct {
		a, b PortRange
		want bool
	}{
		{PortRange{80, 80}, PortRange{80, 80}, true},
		{PortRange{80, 80}, PortRange{81, 81}, false},
		{PortRange{8080, 8090}, PortRange{8085, 8095}, true},
		{PortRange{8080, 8090}, PortRange{8091, 9000}, false},
		{PortRange{8080, 8090}, PortRange{8085, 8085}, true}, // single inside a range
		{PortRange{8085, 8085}, PortRange{8080, 8090}, true}, // and the reverse
		{PortRange{1, 65535}, PortRange{443, 443}, true},
		{PortRange{8080, 8090}, PortRange{7000, 8079}, false}, // adjacent, not overlapping
	}
	for _, tt := range tests {
		if got := tt.a.Overlaps(tt.b); got != tt.want {
			t.Errorf("%s overlaps %s = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestPortRangeCount(t *testing.T) {
	if got := (PortRange{8080, 8090}).Count(); got != 11 {
		t.Errorf("Count = %d, want 11 (inclusive)", got)
	}
	if got := (PortRange{80, 80}).Count(); got != 1 {
		t.Errorf("Count = %d, want 1", got)
	}
}

// Overlap detection must work across ranges, which is the whole reason the
// database's unique index on a single port is not sufficient.
func TestCheckOverlapWithRanges(t *testing.T) {
	base := rule(1, ProtoTCP, 0, "10.10.0.2", 80, SrcModeMasquerade)
	base.Listen = PortRange{8080, 8090}

	overlapping := rule(2, ProtoTCP, 0, "10.10.0.3", 80, SrcModeMasquerade)
	overlapping.Listen = PortRange{8085, 8095}
	if err := CheckOverlap([]Rule{base}, overlapping); err == nil {
		t.Error("overlapping ranges were accepted")
	}

	inside := rule(3, ProtoTCP, 0, "10.10.0.3", 80, SrcModeMasquerade)
	inside.Listen = PortRange{8085, 8085}
	if err := CheckOverlap([]Rule{base}, inside); err == nil {
		t.Error("a single port inside an existing range was accepted")
	}

	clear := rule(4, ProtoTCP, 0, "10.10.0.3", 80, SrcModeMasquerade)
	clear.Listen = PortRange{9000, 9010}
	if err := CheckOverlap([]Rule{base}, clear); err != nil {
		t.Errorf("a non-overlapping range was refused: %v", err)
	}
}

func TestValidateRejectsHugeRange(t *testing.T) {
	r := rule(1, ProtoTCP, 0, "10.10.0.2", 80, SrcModeMasquerade)
	r.Listen = PortRange{1, 65535}
	if err := r.Validate(testPool); err == nil {
		t.Error("a 65535-port range was accepted")
	}
}

// A range preserves the port; a single forward uses the configured target.
func TestEffectiveTargetPort(t *testing.T) {
	single := rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade)
	if got := single.EffectiveTargetPort(443); got != 8443 {
		t.Errorf("single forward maps 443 to %d, want 8443", got)
	}

	ranged := single
	ranged.Listen = PortRange{8080, 8090}
	if got := ranged.EffectiveTargetPort(8085); got != 8085 {
		t.Errorf("range maps 8085 to %d, want it preserved", got)
	}
}
