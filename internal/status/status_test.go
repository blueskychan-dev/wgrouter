package status

import (
	"os"
	"path/filepath"
	"testing"
)

// fixture writes a procfs file and points the package at it.
func fixture(t *testing.T, target *string, name, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := *target
	*target = path
	t.Cleanup(func() { *target = orig })
}

// CPU utilisation is a rate, so the first reading has no value to report.
// Showing 0% there would claim an idle router rather than admit it does not
// know yet.
func TestCPUPercentNeedsTwoSamples(t *testing.T) {
	fixture(t, &procStat, "stat", "cpu  100 0 100 800 0 0 0 0 0 0\n")
	c := NewCollector()

	pct, ok, err := c.cpuPercent()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("first sample reported a value (%.1f%%); a rate needs two", pct)
	}

	// 200 more busy jiffies, 800 more idle => 20% busy.
	fixture(t, &procStat, "stat2", "cpu  200 0 200 1600 0 0 0 0 0 0\n")
	pct, ok, err = c.cpuPercent()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("second sample reported no value")
	}
	if pct < 19.9 || pct > 20.1 {
		t.Errorf("cpu = %.2f%%, want 20%%", pct)
	}
}

// A reboot resets the counters. Subtracting would underflow, so the collector
// must report "no value" rather than a nonsense rate.
func TestCPUPercentHandlesCounterReset(t *testing.T) {
	fixture(t, &procStat, "stat", "cpu  1000 0 1000 8000 0 0 0 0 0 0\n")
	c := NewCollector()
	if _, _, err := c.cpuPercent(); err != nil {
		t.Fatal(err)
	}

	fixture(t, &procStat, "stat2", "cpu  10 0 10 80 0 0 0 0 0 0\n")
	pct, ok, err := c.cpuPercent()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("reported %.1f%% after a counter reset, want no value", pct)
	}
}

// guest and guest_nice are already inside user and nice; counting them again
// would inflate the total and understate utilisation.
func TestCPUIgnoresGuestFields(t *testing.T) {
	fixture(t, &procStat, "stat", "cpu  100 0 100 800 0 0 0 0 5000 5000\n")
	c := NewCollector()
	if _, _, err := c.cpuPercent(); err != nil {
		t.Fatal(err)
	}
	fixture(t, &procStat, "stat2", "cpu  200 0 200 1600 0 0 0 0 9000 9000\n")
	pct, ok, _ := c.cpuPercent()
	if !ok {
		t.Fatal("no value")
	}
	if pct < 19.9 || pct > 20.1 {
		t.Errorf("cpu = %.2f%%, want 20%% — guest time was counted twice", pct)
	}
}

// Used memory must come from MemAvailable, not MemFree: a warm page cache
// would otherwise make a healthy router look nearly out of memory.
func TestMemoryUsesAvailableNotFree(t *testing.T) {
	fixture(t, &procMeminfo, "meminfo", `MemTotal:       1000000 kB
MemFree:          50000 kB
MemAvailable:    800000 kB
Buffers:         100000 kB
SwapTotal:       200000 kB
SwapFree:        150000 kB
`)
	var s System
	if err := readMeminfo(&s); err != nil {
		t.Fatal(err)
	}
	if s.MemTotalBytes != 1000000*1024 {
		t.Errorf("total = %d", s.MemTotalBytes)
	}
	// 1000000 - 800000 = 200000 kB used, i.e. 20%.
	if s.MemUsedBytes != 200000*1024 {
		t.Errorf("used = %d bytes, want it derived from MemAvailable", s.MemUsedBytes)
	}
	if s.MemUsedPercent < 19.9 || s.MemUsedPercent > 20.1 {
		t.Errorf("used = %.1f%%, want 20%%", s.MemUsedPercent)
	}
	if s.SwapUsedBytes != 50000*1024 {
		t.Errorf("swap used = %d", s.SwapUsedBytes)
	}
}

func TestLoadAndUptime(t *testing.T) {
	fixture(t, &procLoadavg, "loadavg", "0.52 0.31 0.11 1/416 1601149\n")
	fixture(t, &procUptime, "uptime", "2150713.92 8576750.60\n")

	var s System
	if err := readLoadavg(&s); err != nil {
		t.Fatal(err)
	}
	if s.Load1 != 0.52 || s.Load5 != 0.31 || s.Load15 != 0.11 {
		t.Errorf("load = %v %v %v", s.Load1, s.Load5, s.Load15)
	}
	if err := readUptime(&s); err != nil {
		t.Fatal(err)
	}
	if s.UptimeSeconds != 2150713 {
		t.Errorf("uptime = %d", s.UptimeSeconds)
	}
	if got := s.UptimeString(); got != "24day:21h:25m" {
		t.Errorf("UptimeString = %q", got)
	}
}

// A missing or malformed source must be an error, not a confident zero.
func TestMissingSourcesReportErrors(t *testing.T) {
	fixture(t, &procStat, "stat", "no cpu line here\n")
	if _, err := readCPUTimes(); err == nil {
		t.Error("a /proc/stat with no cpu line was accepted")
	}

	var s System
	procLoadavgOrig := procLoadavg
	procLoadavg = filepath.Join(t.TempDir(), "absent")
	defer func() { procLoadavg = procLoadavgOrig }()
	if err := readLoadavg(&s); err == nil {
		t.Error("a missing loadavg was accepted")
	}
}

// Read must populate what it can even when one source fails, rather than
// returning nothing.
func TestReadIsPartialOnFailure(t *testing.T) {
	fixture(t, &procMeminfo, "meminfo", "garbage\n")
	c := NewCollector()
	s, _ := c.Read()
	if s.GoVersion == "" || s.NumCPU == 0 {
		t.Error("runtime facts were dropped because another source failed")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1024 * 1024, "1.0 MiB"},
		{3 * 1024 * 1024 * 1024, "3.0 GiB"},
	}
	for _, tt := range tests {
		if got := FormatBytes(tt.in); got != tt.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
