package server

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"wgrouter/internal/store"
)

// maxBackupBytes bounds an uploaded configuration file.
//
// A backup of a full router is a few hundred kilobytes; anything approaching
// this is either corrupt or an attempt to make the parser allocate. The limit
// is applied before the body is read, not after.
const maxBackupBytes = 4 << 20 // 4 MiB

// --- Configuration file management -----------------------------------------

func (s *Server) handleConfigPage(w http.ResponseWriter, r *http.Request) {
	d := s.newPageData(r, "/admin/config")
	d.Flash = s.takeFlash(w, r)
	s.loadAdminCounts(r, &d)
	s.render(w, r, http.StatusOK, "config", d)
}

// handleConfigExport streams the configuration as a download.
func (s *Server) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())

	data, err := s.store.ExportConfig(r.Context(), s.version)
	if err != nil {
		slog.ErrorContext(r.Context(), "export configuration", "error", err)
		s.setFlash(w, "error", "The configuration could not be exported.")
		http.Redirect(w, r, "/admin/config", http.StatusSeeOther)
		return
	}

	s.audit(r, actorOf(sess), store.ActionConfigExport,
		fmt.Sprintf("exported configuration (%d bytes)", len(data)))

	name := fmt.Sprintf("wgrouter-config-%s.json", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		slog.DebugContext(r.Context(), "write export", "error", err)
	}
}

// handleConfigImport restores a configuration file.
func (s *Server) handleConfigImport(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	fail := func(msg string) {
		s.setFlash(w, "error", msg)
		http.Redirect(w, r, "/admin/config", http.StatusSeeOther)
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBackupBytes)
	if err := r.ParseMultipartForm(maxBackupBytes); err != nil {
		fail("The uploaded file was too large or could not be read.")
		return
	}
	file, _, err := r.FormFile("backup")
	if err != nil {
		fail("Choose a configuration file to restore.")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxBackupBytes))
	if err != nil {
		fail("The uploaded file could not be read.")
		return
	}

	b, err := s.store.ImportConfig(r.Context(), data)
	if err != nil {
		slog.WarnContext(r.Context(), "import configuration", "error", err)
		fail(strings.TrimPrefix(err.Error(), "store: "))
		return
	}

	s.audit(r, actorOf(sess), store.ActionConfigImport,
		fmt.Sprintf("restored configuration: %d devices, %d forwards", len(b.Peers), len(b.Forwards)))

	// The kernel is derived state, so both subsystems have to be rebuilt from
	// what was just restored -- otherwise the panel shows the new configuration
	// while the kernel still enforces the old one.
	s.syncKernel(r, "import configuration")
	s.reconcileForwards(r, "import configuration")

	s.setFlash(w, "ok", fmt.Sprintf(
		"Configuration restored: %d devices and %d forwards. Existing client configs keep working.",
		len(b.Peers), len(b.Forwards)))
	http.Redirect(w, r, "/admin/config", http.StatusSeeOther)
}

// --- Maintenance ------------------------------------------------------------

func (s *Server) handleMaintenancePage(w http.ResponseWriter, r *http.Request) {
	d := s.newPageData(r, "/admin/maintenance")
	d.Flash = s.takeFlash(w, r)
	s.loadSystem(&d)
	s.loadAdminCounts(r, &d)
	s.render(w, r, http.StatusOK, "maintenance", d)
}

// handleMaintenanceRun performs one maintenance action.
func (s *Server) handleMaintenanceRun(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	action := r.PostFormValue("action")

	done := func(kind, msg string) {
		s.setFlash(w, kind, msg)
		http.Redirect(w, r, "/admin/maintenance", http.StatusSeeOther)
	}

	switch action {
	case "vacuum":
		if err := s.store.Vacuum(r.Context()); err != nil {
			slog.ErrorContext(r.Context(), "vacuum", "error", err)
			done("error", "The database could not be compacted.")
			return
		}
		s.audit(r, actorOf(sess), store.ActionMaintenance, "compacted the database")
		done("ok", "The database was compacted.")

	case "reconcile":
		s.syncKernel(r, "manual reconcile")
		s.reconcileForwards(r, "manual reconcile")
		s.audit(r, actorOf(sess), store.ActionMaintenance, "forced a kernel reconcile")
		done("ok", "The kernel was re-synchronised from the database.")

	case "factory-reset":
		// Typing the phrase is the confirmation. A button alone is too easy to
		// hit on a page full of other buttons, and this one destroys every
		// device and forward on the router.
		if strings.TrimSpace(r.PostFormValue("confirm")) != "RESET" {
			done("error", "Type RESET in the confirmation box to reset the router.")
			return
		}
		if err := s.store.ResetToFactory(r.Context()); err != nil {
			slog.ErrorContext(r.Context(), "factory reset", "error", err)
			done("error", "The reset did not complete.")
			return
		}
		s.audit(r, actorOf(sess), store.ActionMaintenance, "performed a factory reset")
		s.syncKernel(r, "factory reset")
		s.reconcileForwards(r, "factory reset")
		done("ok", "The router was reset. Devices, forwards, logs and settings are gone; your account was kept.")

	default:
		done("error", "Unknown maintenance action.")
	}
}

// --- Log settings -----------------------------------------------------------

func (s *Server) handleUserLogPage(w http.ResponseWriter, r *http.Request) {
	d := s.newPageData(r, "/admin/userlog")
	d.Flash = s.takeFlash(w, r)
	s.loadLogSettings(r, &d)

	entries, err := s.store.RecentAudit(r.Context(), 200)
	if err != nil {
		slog.ErrorContext(r.Context(), "read audit log", "error", err)
		d.AuditFailed = true
		if d.Flash == nil {
			d.Flash = &flash{Kind: "error", Message: "The user log could not be read. This is a database error, not an empty log."}
		}
	} else {
		d.Audit = entries
	}
	s.render(w, r, http.StatusOK, "userlog", d)
}

func (s *Server) handleFirewallLogPage(w http.ResponseWriter, r *http.Request) {
	d := s.newPageData(r, "/admin/firewalllog")
	d.Flash = s.takeFlash(w, r)
	s.loadLogSettings(r, &d)

	events, err := s.store.FirewallLog(r.Context(), 200)
	if err != nil {
		slog.ErrorContext(r.Context(), "read firewall log", "error", err)
		d.FirewallFailed = true
		if d.Flash == nil {
			d.Flash = &flash{Kind: "error", Message: "The firewall log could not be read."}
		}
	} else {
		for _, e := range events {
			d.Firewall = append(d.Firewall, firewallRow{
				At:      e.At.Format("2006-01-02 15:04:05"),
				Reason:  e.Reason,
				Source:  joinHostPort(e.SrcIP, e.SrcPort),
				Dest:    joinHostPort(e.DstIP, e.DstPort),
				Proto:   e.Proto,
				Forward: e.ForwardID,
			})
		}
	}
	s.render(w, r, http.StatusOK, "firewalllog", d)
}

// handleLogSettings saves the enable/disable and filter choices.
func (s *Server) handleLogSettings(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	which := r.PostFormValue("which")
	back := "/admin/userlog"
	if which == "firewall" {
		back = "/admin/firewalllog"
	}

	ls, err := s.store.LoadLogSettings(r.Context())
	if err != nil {
		slog.ErrorContext(r.Context(), "load log settings", "error", err)
		s.setFlash(w, "error", "The current log settings could not be read.")
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}

	switch which {
	case "user":
		ls.UserEnabled = r.PostFormValue("enabled") == "1"
		ls.UserActions = filterKnownActions(r.PostForm["actions"])
	case "firewall":
		ls.FirewallEnabled = r.PostFormValue("enabled") == "1"
	default:
		s.setFlash(w, "error", "Unknown log.")
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}

	if err := s.store.SaveLogSettings(r.Context(), ls); err != nil {
		slog.ErrorContext(r.Context(), "save log settings", "error", err)
		s.setFlash(w, "error", "The settings could not be saved.")
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	s.setLogSettings(ls)

	// Firewall logging lives in the nftables rules themselves, so turning it on
	// or off has to rebuild them.
	if which == "firewall" && s.rec != nil {
		if err := s.rec.SetLogDrops(r.Context(), ls.FirewallEnabled); err != nil {
			slog.ErrorContext(r.Context(), "apply firewall logging", "error", err)
			s.setFlash(w, "error", "Saved, but the firewall rules could not be rebuilt to match.")
			http.Redirect(w, r, back, http.StatusSeeOther)
			return
		}
	}

	s.audit(r, actorOf(sess), store.ActionLogSettings,
		fmt.Sprintf("updated %s log settings", which))
	s.setFlash(w, "ok", "Log settings saved.")
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// handleLogClear empties one of the logs.
func (s *Server) handleLogClear(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	which := r.PostFormValue("which")
	back := "/admin/userlog"

	var (
		n   int64
		err error
	)
	switch which {
	case "user":
		n, err = s.store.ClearAuditLog(r.Context())
	case "firewall":
		back = "/admin/firewalllog"
		n, err = s.store.ClearFirewallLog(r.Context())
	default:
		s.setFlash(w, "error", "Unknown log.")
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "clear log", "which", which, "error", err)
		s.setFlash(w, "error", "The log could not be cleared.")
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}

	// Recorded after the clear, so the audit trail always shows that it
	// happened and who did it -- an operator cannot erase their own tracks by
	// wiping the log, because this line is written immediately afterwards.
	s.audit(r, actorOf(sess), store.ActionLogCleared,
		fmt.Sprintf("cleared the %s log (%d entries removed)", which, n))
	s.setFlash(w, "ok", fmt.Sprintf("%d entries removed.", n))
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// handleLogExport streams a log as CSV.
func (s *Server) handleLogExport(w http.ResponseWriter, r *http.Request) {
	which := r.URL.Query().Get("which")

	var (
		name string
		rows [][]string
	)
	switch which {
	case "user":
		entries, err := s.store.RecentAudit(r.Context(), 1000)
		if err != nil {
			s.setFlash(w, "error", "The log could not be read.")
			http.Redirect(w, r, "/admin/userlog", http.StatusSeeOther)
			return
		}
		name = "wgrouter-user-log"
		rows = append(rows, []string{"time", "actor", "action", "detail", "remote"})
		for _, e := range entries {
			rows = append(rows, []string{
				e.At.UTC().Format(time.RFC3339), e.Actor, e.Action, e.Detail, e.RemoteAddr,
			})
		}
	case "firewall":
		events, err := s.store.FirewallLog(r.Context(), 1000)
		if err != nil {
			s.setFlash(w, "error", "The log could not be read.")
			http.Redirect(w, r, "/admin/firewalllog", http.StatusSeeOther)
			return
		}
		name = "wgrouter-firewall-log"
		rows = append(rows, []string{"time", "reason", "forward", "source", "destination", "proto"})
		for _, e := range events {
			rows = append(rows, []string{
				e.At.UTC().Format(time.RFC3339), e.Reason, fmt.Sprint(e.ForwardID),
				joinHostPort(e.SrcIP, e.SrcPort), joinHostPort(e.DstIP, e.DstPort), e.Proto,
			})
		}
	default:
		http.Error(w, "unknown log", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.csv"`,
		name, time.Now().UTC().Format("20060102-150405")))
	w.Header().Set("Cache-Control", "no-store")
	writeCSV(w, rows)
}

// writeCSV emits rows, quoting every field.
//
// Quoting unconditionally rather than only when needed avoids the classic CSV
// injection footgun: a log detail beginning with '=' is data, and a spreadsheet
// must not evaluate it as a formula.
func writeCSV(w io.Writer, rows [][]string) {
	var b strings.Builder
	for _, row := range rows {
		for i, f := range row {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteByte('"')
			b.WriteString(strings.ReplaceAll(f, `"`, `""`))
			b.WriteByte('"')
		}
		b.WriteString("\r\n")
	}
	_, _ = io.WriteString(w, b.String())
}

// --- helpers ---------------------------------------------------------------

func (s *Server) loadLogSettings(r *http.Request, d *pageData) {
	ls, err := s.store.LoadLogSettings(r.Context())
	if err != nil {
		slog.ErrorContext(r.Context(), "load log settings", "error", err)
		return
	}
	d.LogUserEnabled = ls.UserEnabled
	d.LogFirewallEnabled = ls.FirewallEnabled

	selected := map[string]bool{}
	for _, a := range ls.UserActions {
		selected[a] = true
	}
	all := len(ls.UserActions) == 0
	for _, f := range store.UserActionFilters {
		d.LogActionFilters = append(d.LogActionFilters, logFilterView{
			Value:    f.Value,
			Label:    f.Label,
			Selected: all || selected[f.Value],
		})
	}
}

func (s *Server) loadAdminCounts(r *http.Request, d *pageData) {
	for _, t := range []struct {
		table string
		into  *int64
	}{
		{"peers", &d.CountPeers},
		{"forwards", &d.CountForwards},
		{"audit_log", &d.CountAudit},
		{"firewall_log", &d.CountFirewall},
	} {
		if n, err := s.store.CountRows(r.Context(), t.table); err == nil {
			*t.into = n
		}
	}
}

// filterKnownActions keeps only actions we actually offer, so a hand-crafted
// form cannot store junk that would later be compared against every audit write.
func filterKnownActions(in []string) []string {
	known := map[string]bool{}
	for _, f := range store.UserActionFilters {
		known[f.Value] = true
	}
	var out []string
	for _, a := range in {
		if known[a] {
			out = append(out, a)
		}
	}
	return out
}

func joinHostPort(host string, port int) string {
	if host == "" {
		return ""
	}
	if port == 0 {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}
