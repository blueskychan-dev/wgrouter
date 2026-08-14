package server

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"wgrouter/internal/diag"
	"wgrouter/internal/status"
	"wgrouter/internal/store"
)

// diagSlots bounds concurrent diagnostic probes.
//
// Each one holds a goroutine and a socket for up to diag.TotalTimeout, and the
// console is a button an administrator can hold down. Two at a time is plenty
// for one operator and stops the page becoming a way to generate traffic.
const diagSlots = 2

// loadSystem fills in the router's own health figures.
func (s *Server) loadSystem(d *pageData) {
	sys, err := s.sys.Read()
	if err != nil {
		// Partial data is still useful, so this is recorded rather than fatal.
		slog.Warn("read system status", "error", err)
		d.SystemError = err.Error()
	}
	d.System = systemView{
		CPUPercent:     sys.CPUPercent,
		CPUHasValue:    sys.CPUHasValue,
		NumCPU:         sys.NumCPU,
		CPUModel:       sys.CPUModel,
		MemUsed:        status.FormatBytes(sys.MemUsedBytes),
		MemTotal:       status.FormatBytes(sys.MemTotalBytes),
		MemPercent:     sys.MemUsedPercent,
		SwapUsed:       status.FormatBytes(sys.SwapUsedBytes),
		SwapTotal:      status.FormatBytes(sys.SwapTotalBytes),
		HasSwap:        sys.SwapTotalBytes > 0,
		Load1:          sys.Load1,
		Load5:          sys.Load5,
		Load15:         sys.Load15,
		HostUptime:     sys.UptimeString(),
		KernelVersion:  sys.KernelVersion,
		GoVersion:      sys.GoVersion,
		Arch:           sys.Arch,
		OS:             sys.OS,
		RouterVersion:  s.version,
		ServiceUptime:  uptime(s.started),
		FirmwareStatus: "Up to date — automatic updates are not implemented yet.",
	}
}

// loadConnStats fills in the windowed connection figures.
func (s *Server) loadConnStats(r *http.Request, d *pageData) {
	w, err := s.store.ForwardStats(r.Context(), 0, time.Now())
	if err != nil {
		slog.ErrorContext(r.Context(), "read connection statistics", "error", err)
		d.StatsError = "Connection statistics could not be read from the database."
		return
	}
	d.Stats = statsView{
		Day7:    connWindow(w.Day7),
		Day30:   connWindow(w.Day30),
		AllTime: connWindow(w.AllTime),
	}
	d.HasStats = w.AllTime.Total() > 0
}

func connWindow(c store.ConnStats) connStatsView {
	return connStatsView{
		Total:    c.Total(),
		Accepted: c.Accepted,
		Dropped:  c.Dropped,
		DropRate: c.DropRate(),
		Bytes:    status.FormatBytes(c.Bytes),
	}
}

// --- diagnostics -----------------------------------------------------------

func (s *Server) handleDiagnosticsRun(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())

	tool := diag.Tool(strings.TrimSpace(r.PostFormValue("tool")))
	target := r.PostFormValue("target")

	d := s.newPageData(r, "/system")
	s.loadSystem(&d)
	d.DiagTools = diagToolOptions(string(tool))
	d.DiagTarget = strings.TrimSpace(target)
	d.DiagTool = string(tool)

	fail := func(msg string) {
		d.Flash = &flash{Kind: "error", Message: msg}
		s.render(w, r, http.StatusBadRequest, "system", d)
	}

	if !tool.Valid() {
		fail("Choose a diagnostic tool.")
		return
	}
	if _, err := diag.ValidateTarget(target); err != nil {
		fail(err.Error())
		return
	}

	req := diag.Request{Tool: tool, Target: target, Count: diag.DefaultCount}

	// The TCP check needs a port, and it arrives as text from a form, so it is
	// validated at this boundary like every other integer.
	if tool == diag.ToolTCP {
		port, err := parsePort(r.PostFormValue("port"))
		if err != nil {
			fail("Port: " + err.Error())
			return
		}
		req.Port = port
		d.DiagPort = strconv.Itoa(int(port))
	}

	// Bound concurrency: probes are cheap to start and slow to finish.
	select {
	case s.diagSem <- struct{}{}:
		defer func() { <-s.diagSem }()
	default:
		fail("Another diagnostic is already running. Wait for it to finish.")
		return
	}

	res, err := diag.Run(r.Context(), req)
	if err != nil {
		slog.WarnContext(r.Context(), "diagnostic failed", "tool", tool, "error", err)
		fail(strings.TrimPrefix(err.Error(), "diag: "))
		return
	}

	// The target is attacker-influenced only in the sense that an authenticated
	// administrator typed it, but it is still recorded so the audit log shows
	// what the router was pointed at and by whom.
	s.audit(r, actorOf(sess), store.ActionDiagnostic,
		string(tool)+" "+d.DiagTarget+" — "+res.Summary)

	d.DiagResult = &diagResultView{
		Tool:    tool.Label(),
		Target:  d.DiagTarget,
		Lines:   res.Lines,
		Summary: res.Summary,
		OK:      res.OK,
	}
	s.render(w, r, http.StatusOK, "system", d)
}

// diagToolOptions lists the console's closed command set.
func diagToolOptions(selected string) []diagToolView {
	tools := []struct {
		tool diag.Tool
		help string
	}{
		{diag.ToolPing, "Send ICMP echo requests and report round-trip time."},
		{diag.ToolTraceroute, "Show the path packets take, hop by hop."},
		{diag.ToolDNS, "Resolve a name to addresses, and back again."},
		{diag.ToolTCP, "Open a TCP connection to a port and report whether it answers."},
	}
	out := make([]diagToolView, 0, len(tools))
	for _, t := range tools {
		out = append(out, diagToolView{
			Value:    string(t.tool),
			Label:    t.tool.Label(),
			Help:     t.help,
			NeedPort: t.tool == diag.ToolTCP,
			Selected: string(t.tool) == selected,
		})
	}
	if selected == "" && len(out) > 0 {
		out[0].Selected = true
	}
	return out
}
