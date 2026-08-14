package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// procNetRoute is overridable so the parser can be tested without root or a
// particular host routing table.
var procNetRoute = "/proc/net/route"

// DetectWANInterface returns the interface holding the default IPv4 route.
//
// This reads procfs rather than talking to netlink or shelling out to `ip`:
// the information is a single well-defined file, and the format below has been
// stable for the entire lifetime of the interface.
//
// Note what this deliberately does NOT do: it does not attempt to discover the
// public address. On a 1:1-NAT'd cloud instance the public address is not
// present on any local interface, so anything derived from the routing table
// would be the private address wearing a misleading label.
func DetectWANInterface() (string, error) {
	f, err := os.Open(procNetRoute)
	if err != nil {
		return "", fmt.Errorf("detect WAN interface: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return "", fmt.Errorf("detect WAN interface: %s is empty", procNetRoute)
	}
	// Header row: Iface Destination Gateway Flags RefCnt Use Metric Mask ...

	best := ""
	bestMetric := -1
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		// The default route is the one with both destination and mask all-zero.
		// Values are little-endian hex, but zero reads the same either way.
		if fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil {
			continue
		}
		// Lowest metric wins, matching the kernel's own preference.
		if bestMetric == -1 || metric < bestMetric {
			best, bestMetric = fields[0], metric
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("detect WAN interface: read %s: %w", procNetRoute, err)
	}
	if best == "" {
		return "", fmt.Errorf("detect WAN interface: no default route in %s", procNetRoute)
	}
	return best, nil
}
