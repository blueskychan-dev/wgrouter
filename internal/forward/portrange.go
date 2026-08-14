package forward

import (
	"fmt"
	"strconv"
	"strings"
)

// PortRange is an inclusive range of listen ports. A range whose End is zero or
// equal to Start is a single port.
type PortRange struct {
	Start uint16
	End   uint16
}

// ParsePortRange accepts "8080" or "8080-8090".
//
// Both forms come from the same form field, so the parser has to be strict:
// silently treating "8080-" as 8080 would open a port the administrator did not
// ask for, and treating "8090-8080" as valid would produce a range the kernel
// rejects at reconcile time, long after the mistake was made.
func ParsePortRange(s string) (PortRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return PortRange{}, fmt.Errorf("a port or range is required")
	}

	// A leading dash is a negative number, not an open-ended range. Cutting on
	// the dash first would turn "-1" into an empty low bound and report a
	// confusing "both sides of the dash" error for what is really an
	// out-of-range port.
	if strings.HasPrefix(s, "-") {
		return PortRange{}, fmt.Errorf("must be between 1 and 65535")
	}

	lo, hi, isRange := strings.Cut(s, "-")
	start, err := parsePortText(lo)
	if err != nil {
		return PortRange{}, err
	}
	if !isRange {
		return PortRange{Start: start, End: start}, nil
	}

	end, err := parsePortText(hi)
	if err != nil {
		return PortRange{}, err
	}
	if end < start {
		return PortRange{}, fmt.Errorf("range %d-%d is backwards; the first port must be the lower one", start, end)
	}
	return PortRange{Start: start, End: end}, nil
}

func parsePortText(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("a port number is required on both sides of the dash")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("must be a number, or a range like 8080-8090")
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("must be between 1 and 65535")
	}
	return uint16(n), nil
}

// IsRange reports whether this covers more than one port.
func (r PortRange) IsRange() bool { return r.End > r.Start }

// Count is how many ports the range covers.
func (r PortRange) Count() int {
	if r.End < r.Start {
		return 0
	}
	return int(r.End) - int(r.Start) + 1
}

// Overlaps reports whether two ranges share any port.
func (r PortRange) Overlaps(o PortRange) bool {
	return r.Start <= o.End && o.Start <= r.End
}

// String renders the range the way it is typed.
func (r PortRange) String() string {
	if r.IsRange() {
		return fmt.Sprintf("%d-%d", r.Start, r.End)
	}
	return strconv.Itoa(int(r.Start))
}

// Normalised returns the range with End filled in for a single port, so callers
// never have to special-case a zero End.
func (r PortRange) Normalised() PortRange {
	if r.End < r.Start {
		r.End = r.Start
	}
	return r
}

// Valid reports whether the range is usable.
func (r PortRange) Valid() bool {
	return r.Start >= 1 && r.End >= r.Start
}
