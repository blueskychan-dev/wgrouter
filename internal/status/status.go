// Package status reads the router's own health: processor load, memory, uptime
// and the versions of the things it is running on.
//
// Everything comes from procfs and the Go runtime. Nothing here shells out to
// `top`, `free` or `uname` -- the same rule the rest of wgrouter follows, and
// for the same reason: those tools' output formats differ between distributions
// and change between releases, so a parser built on them breaks silently on a
// host you did not test.
package status

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Paths are variables so tests can point them at fixtures.
var (
	procStat      = "/proc/stat"
	procMeminfo   = "/proc/meminfo"
	procLoadavg   = "/proc/loadavg"
	procUptime    = "/proc/uptime"
	procOSRelease = "/proc/sys/kernel/osrelease"
)

// System is a point-in-time view of the router.
type System struct {
	// CPUPercent is utilisation since the previous reading, 0-100. It is zero
	// on the first call, because a rate needs two samples.
	CPUPercent  float64
	CPUHasValue bool
	NumCPU      int
	CPUModel    string

	MemTotalBytes     uint64
	MemAvailableBytes uint64
	MemUsedBytes      uint64
	MemUsedPercent    float64

	SwapTotalBytes uint64
	SwapUsedBytes  uint64

	Load1, Load5, Load15 float64

	UptimeSeconds uint64

	KernelVersion string
	GoVersion     string
	Arch          string
	OS            string
}

// UptimeString renders host uptime the way a router panel does.
func (s System) UptimeString() string {
	d := time.Duration(s.UptimeSeconds) * time.Second
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	return fmt.Sprintf("%dday:%dh:%dm", days, h, m)
}

// cpuTimes is one sample of the aggregate CPU line in /proc/stat.
type cpuTimes struct {
	total uint64
	idle  uint64
}

// Collector reads system metrics. CPU utilisation is a rate, so the collector
// keeps the previous sample; it is safe for concurrent use.
type Collector struct {
	mu   sync.Mutex
	prev cpuTimes
	have bool
}

// NewCollector returns a Collector.
func NewCollector() *Collector { return &Collector{} }

// Read gathers everything.
//
// A failure in one source does not fail the whole read: a router panel that
// shows nothing because /proc/meminfo moved is less useful than one that shows
// the processor figures and leaves memory blank. Errors are returned so the
// caller can log them, but the System value is still populated as far as it got.
func (c *Collector) Read() (System, error) {
	s := System{
		NumCPU:    runtime.NumCPU(),
		GoVersion: runtime.Version(),
		Arch:      runtime.GOARCH,
		OS:        runtime.GOOS,
	}
	var errs []string

	if pct, ok, err := c.cpuPercent(); err != nil {
		errs = append(errs, err.Error())
	} else {
		s.CPUPercent, s.CPUHasValue = pct, ok
	}

	if model, err := readCPUModel(); err != nil {
		errs = append(errs, err.Error())
	} else {
		s.CPUModel = model
	}

	if err := readMeminfo(&s); err != nil {
		errs = append(errs, err.Error())
	}
	if err := readLoadavg(&s); err != nil {
		errs = append(errs, err.Error())
	}
	if err := readUptime(&s); err != nil {
		errs = append(errs, err.Error())
	}
	if v, err := readKernelVersion(); err != nil {
		errs = append(errs, err.Error())
	} else {
		s.KernelVersion = v
	}

	if len(errs) > 0 {
		return s, fmt.Errorf("status: %s", strings.Join(errs, "; "))
	}
	return s, nil
}

// cpuPercent computes utilisation since the previous call.
func (c *Collector) cpuPercent() (float64, bool, error) {
	now, err := readCPUTimes()
	if err != nil {
		return 0, false, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	prev, have := c.prev, c.have
	c.prev, c.have = now, true
	if !have {
		// First reading: there is no interval to measure over yet. Reporting 0
		// would be a lie, so the caller is told there is no value.
		return 0, false, nil
	}

	dTotal := now.total - prev.total
	dIdle := now.idle - prev.idle
	if dTotal == 0 || now.total < prev.total {
		// No elapsed jiffies, or the counters went backwards (a reboot, or a
		// wrapped counter). Neither yields a meaningful rate.
		return 0, false, nil
	}
	busy := float64(dTotal-dIdle) / float64(dTotal) * 100
	if busy < 0 {
		busy = 0
	}
	if busy > 100 {
		busy = 100
	}
	return busy, true, nil
}

// readCPUTimes parses the aggregate "cpu" line of /proc/stat.
//
// Fields are: user nice system idle iowait irq softirq steal guest guest_nice.
// Idle time is idle+iowait: a processor waiting on disk is not doing work, and
// counting iowait as busy makes an idle router look loaded during log writes.
func readCPUTimes() (cpuTimes, error) {
	f, err := os.Open(procStat)
	if err != nil {
		return cpuTimes{}, fmt.Errorf("read %s: %w", procStat, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var total, idle uint64
		for i, raw := range fields[1:] {
			v, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return cpuTimes{}, fmt.Errorf("parse %s field %d: %w", procStat, i, err)
			}
			// guest and guest_nice (indices 8 and 9) are already counted inside
			// user and nice; adding them again would inflate the total.
			if i >= 8 {
				continue
			}
			total += v
			if i == 3 || i == 4 { // idle, iowait
				idle += v
			}
		}
		return cpuTimes{total: total, idle: idle}, nil
	}
	if err := sc.Err(); err != nil {
		return cpuTimes{}, fmt.Errorf("read %s: %w", procStat, err)
	}
	return cpuTimes{}, fmt.Errorf("no aggregate cpu line in %s", procStat)
}

// readMeminfo fills in the memory fields.
//
// "Used" is derived from MemAvailable rather than MemFree. MemFree excludes the
// page cache, which the kernel will hand back under pressure, so a healthy
// router with a warm cache would otherwise report itself nearly out of memory.
func readMeminfo(s *System) error {
	f, err := os.Open(procMeminfo)
	if err != nil {
		return fmt.Errorf("read %s: %w", procMeminfo, err)
	}
	defer f.Close()

	var swapFree uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		b := kb * 1024
		switch key {
		case "MemTotal":
			s.MemTotalBytes = b
		case "MemAvailable":
			s.MemAvailableBytes = b
		case "SwapTotal":
			s.SwapTotalBytes = b
		case "SwapFree":
			swapFree = b
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read %s: %w", procMeminfo, err)
	}

	if s.MemTotalBytes > 0 && s.MemAvailableBytes <= s.MemTotalBytes {
		s.MemUsedBytes = s.MemTotalBytes - s.MemAvailableBytes
		s.MemUsedPercent = float64(s.MemUsedBytes) / float64(s.MemTotalBytes) * 100
	}
	if s.SwapTotalBytes >= swapFree {
		s.SwapUsedBytes = s.SwapTotalBytes - swapFree
	}
	return nil
}

func readLoadavg(s *System) error {
	b, err := os.ReadFile(procLoadavg)
	if err != nil {
		return fmt.Errorf("read %s: %w", procLoadavg, err)
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return fmt.Errorf("unexpected %s format", procLoadavg)
	}
	s.Load1, _ = strconv.ParseFloat(fields[0], 64)
	s.Load5, _ = strconv.ParseFloat(fields[1], 64)
	s.Load15, _ = strconv.ParseFloat(fields[2], 64)
	return nil
}

func readUptime(s *System) error {
	b, err := os.ReadFile(procUptime)
	if err != nil {
		return fmt.Errorf("read %s: %w", procUptime, err)
	}
	fields := strings.Fields(string(b))
	if len(fields) < 1 {
		return fmt.Errorf("unexpected %s format", procUptime)
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return fmt.Errorf("parse %s: %w", procUptime, err)
	}
	s.UptimeSeconds = uint64(secs)
	return nil
}

func readKernelVersion() (string, error) {
	b, err := os.ReadFile(procOSRelease)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", procOSRelease, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// FormatBytes renders a byte count for the UI.
func FormatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
