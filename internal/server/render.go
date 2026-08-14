package server

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"wgrouter/internal/auth"
	"wgrouter/internal/store"
	"wgrouter/internal/wg"
	"wgrouter/web"
)

// pages maps a template name to its file. Each page defines "content" (and
// optionally "title", "heading" and "desc") and is combined with the shared
// layout at startup.
var pages = []string{
	"status",
	"devices",
	"forwards",
	"system",
	"login",
	"setup",
	"config",
	"maintenance",
	"userlog",
	"firewalllog",
}

var templateFuncs = template.FuncMap{
	"add": func(a, b int) int { return a + b },
	// int64 gives templates a typed zero for comparisons against an ID, since
	// a bare 0 literal is an int and eq refuses to compare mismatched types.
	"int64": func(v int) int64 { return int64(v) },
}

// parseTemplates builds one template set per page. Parsing happens once at
// startup so a broken template is a startup failure rather than a 500 in front
// of the user.
func parseTemplates() (map[string]*template.Template, error) {
	out := make(map[string]*template.Template, len(pages))
	for _, name := range pages {
		t, err := template.New(name).Funcs(templateFuncs).ParseFS(web.Templates,
			"templates/layout.html",
			"templates/partials/*.html",
			"templates/pages/"+name+".html",
		)
		if err != nil {
			return nil, fmt.Errorf("server: parse template %q: %w", name, err)
		}
		out[name] = t
	}
	return out, nil
}

// navItem is one sidebar entry. An entry with Children renders as a group that
// expands when one of its pages is open.
type navItem struct {
	Label    string
	Href     string
	Glyph    string
	Active   bool
	Children []navItem
	Open     bool
}

// navSpec is the sidebar in display order. The original panel's sidebar was a
// flat list of eight; ours is five, with sub-pages living inside each section.
var navSpec = []navItem{
	{Label: "Status", Href: "/", Glyph: "◆"},
	{Label: "WireGuard", Href: "/devices", Glyph: "▤"},
	{Label: "Port Forwarding", Href: "/forwards", Glyph: "⇄"},
	{Label: "System", Href: "/system", Glyph: "⚙"},
	{Label: "Administration", Glyph: "▣", Children: []navItem{
		{Label: "Configuration File", Href: "/admin/config"},
		{Label: "Maintenance", Href: "/admin/maintenance"},
		{Label: "User Log", Href: "/admin/userlog"},
		{Label: "Firewall Log", Href: "/admin/firewalllog"},
	}},
}

// flash is a one-shot message carried across a redirect.
type flash struct {
	Kind    string // ok | error | info
	Message string
}

// pageData is the single data type handed to every template. One struct rather
// than per-page types keeps the layout's contract explicit and lets the
// compiler catch a field rename.
type pageData struct {
	// Shell
	User      string
	CSRFToken string
	Nav       []navItem
	Flash     *flash
	Version   string

	// Configuration echoes, shown across several screens
	WGInterface      string
	WGListenPort     int
	TunnelPool       string
	ServerIP         string
	PublicEndpoint   string
	ClientAllowedIPs string
	ClientDNS        string
	WANInterface     string
	ListenAddr       string
	DBPath           string
	TLSEnabled       bool

	MinPasswordLength int
	HandshakeWindow   int

	// Page-specific
	SchemaVersion   int
	Uptime          string
	PeerCount       int
	ForwardCount    int
	OnlineCount     int
	ServerPublicKey string
	Audit           []store.AuditEntry

	// AuditFailed distinguishes "the log is empty" from "the log could not be
	// read", so the empty state is not shown for a database error.
	AuditFailed bool

	// WireGuard
	Devices     []deviceRow
	WGUp        bool
	KernelError string

	// NewDevice is set only on the response that creates a device: it carries
	// the one and only rendering of that device's private key.
	NewDevice *newDevice

	// EditDevice and EditForward are set when ?edit=<id> names a row, turning
	// the create form on that page into an edit form.
	EditDevice  *deviceRow
	EditForward *forwardRow

	// Router health and diagnostics
	System      systemView
	SystemError string

	Stats      statsView
	HasStats   bool
	StatsError string

	DiagTools  []diagToolView
	DiagTool   string
	DiagTarget string
	DiagPort   string
	DiagResult *diagResultView

	// Administration
	LogUserEnabled     bool
	LogFirewallEnabled bool
	LogActionFilters   []logFilterView
	Firewall           []firewallRow
	FirewallFailed     bool
	CountPeers         int64
	CountForwards      int64
	CountAudit         int64
	CountFirewall      int64

	// Forwarding
	Forwards        []forwardRow
	ForwardModes    []modeOption
	ReconcileAt     string
	ReconcileErr    string
	IPForwardingOn  bool
	NoDevicesForFwd bool
}

// deviceRow is one row of the device list: the stored peer joined with live
// kernel state.
type deviceRow struct {
	ID            int64
	Name          string
	TunnelIP      string
	PublicKey     string
	Notes         string
	Enabled       bool
	Presence      string
	PresenceLabel string
	Endpoint      string
	LastHandshake string
	Rx            string
	Tx            string
	InKernel      bool
}

// newDevice is the once-only provisioning result.
//
// The two data: URIs are template.URL rather than string because
// html/template's URL sanitiser rewrites any scheme outside its allowlist to
// "#ZgotmplZ" -- which would silently break both the QR image and the download
// link. Marking them trusted is safe here and nowhere else: both are built by
// this program from base64, whose alphabet ([A-Za-z0-9+/=]) cannot carry a
// quote, an angle bracket or a scheme change. No user input reaches them
// unencoded.
type newDevice struct {
	Direct        bool
	AllowedIPs    string
	Name          string
	TunnelIP      string
	Config        string
	Filename      string
	ConfigDataURI template.URL
	QRDataURI     template.URL
}

// forwardRow is one row of the forwarding table.
type forwardRow struct {
	ID         int64
	Label      string
	Proto      string
	Listen     string
	IsRange    bool
	PeerID     int64
	PeerName   string
	TargetIP   string
	TargetPort uint16
	SrcMode    string
	ModeLabel  string
	RateLimit  bool
	SrcPolicy  string
	PolicyLbl  string
	Sources    string
	Enabled    bool
	InKernel   bool

	// Connection figures for this forward.
	Accepted7d  uint64
	Dropped7d   uint64
	AcceptedAll uint64
	DroppedAll  uint64

	// Warn carries the caveat for this row's source mode, if any.
	Warn string
}

// logFilterView is one selectable audit action.
type logFilterView struct {
	Value    string
	Label    string
	Selected bool
}

// firewallRow is one dropped-packet record.
type firewallRow struct {
	At      string
	Reason  string
	Source  string
	Dest    string
	Proto   string
	Forward int64
}

// systemView is the router's own health, formatted for display.
type systemView struct {
	CPUPercent  float64
	CPUHasValue bool
	NumCPU      int
	CPUModel    string

	MemUsed    string
	MemTotal   string
	MemPercent float64

	SwapUsed  string
	SwapTotal string
	HasSwap   bool

	Load1, Load5, Load15 float64

	HostUptime    string
	ServiceUptime string

	KernelVersion  string
	GoVersion      string
	Arch           string
	OS             string
	RouterVersion  string
	FirmwareStatus string
}

// connStatsView is one window of connection figures.
type connStatsView struct {
	Total    uint64
	Accepted uint64
	Dropped  uint64
	DropRate float64
	Bytes    string
}

// statsView holds the three windows shown side by side.
type statsView struct {
	Day7    connStatsView
	Day30   connStatsView
	AllTime connStatsView
}

// diagToolView is one entry in the diagnostics tool list.
type diagToolView struct {
	Value    string
	Label    string
	Help     string
	NeedPort bool
	Selected bool
}

// diagResultView is the output of one probe.
type diagResultView struct {
	Tool    string
	Target  string
	Lines   []string
	Summary string
	OK      bool
}

// modeOption is a source-preservation choice offered in the create form.
type modeOption struct {
	Value    string
	Label    string
	Help     string
	Selected bool
}

// newPageData builds the shell fields common to every page.
func (s *Server) newPageData(r *http.Request, activeHref string) pageData {
	d := pageData{
		Version:           s.version,
		WGInterface:       s.cfg.WGInterface,
		WGListenPort:      s.cfg.WGListenPort,
		TunnelPool:        s.cfg.TunnelPool.String(),
		ServerIP:          s.cfg.ServerIP.String(),
		PublicEndpoint:    s.cfg.PublicEndpoint,
		ClientAllowedIPs:  s.cfg.ClientAllowedIPs,
		ClientDNS:         s.cfg.ClientDNS,
		WANInterface:      s.cfg.WANInterface,
		ListenAddr:        s.cfg.ListenAddr,
		DBPath:            s.cfg.DBPath,
		TLSEnabled:        s.cfg.TLSEnabled(),
		MinPasswordLength: auth.MinPasswordLength,
		HandshakeWindow:   int(wg.HandshakeTimeout.Seconds()),
	}

	if sess := sessionFrom(r.Context()); sess != nil {
		d.User = sess.Username
		d.CSRFToken = sess.CSRFToken
		// The sidebar is only meaningful once signed in; the login and setup
		// screens deliberately render without it.
		nav := make([]navItem, len(navSpec))
		copy(nav, navSpec)
		for i := range nav {
			nav[i].Active = nav[i].Href != "" && nav[i].Href == activeHref
			if len(nav[i].Children) == 0 {
				continue
			}
			// Copy the children too: marking the active one on the shared
			// navSpec would leak that state into every other request.
			kids := make([]navItem, len(nav[i].Children))
			copy(kids, nav[i].Children)
			for j := range kids {
				kids[j].Active = kids[j].Href == activeHref
				if kids[j].Active {
					nav[i].Open = true
				}
			}
			nav[i].Children = kids
		}
		d.Nav = nav
	} else {
		d.CSRFToken = csrfTokenFrom(r.Context())
	}
	return d
}

// render executes a page template. It buffers first so that a template error
// produces a clean 500 rather than a half-written page with a 200 already
// committed.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, data pageData) {
	t, ok := s.tmpl[name]
	if !ok {
		slog.ErrorContext(r.Context(), "unknown template", "template", name)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		slog.ErrorContext(r.Context(), "render template", "template", name, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Every rendered page is either behind a session or is a login form. None
	// of it should sit in a shared or on-disk cache: without this the audit log
	// and admin forms stay readable via the back button after signing out.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	if _, err := buf.WriteTo(w); err != nil {
		slog.DebugContext(r.Context(), "write response", "error", err)
	}
}

// uptime renders the process uptime the way a router panel does.
func uptime(since time.Time) string {
	d := time.Since(since).Truncate(time.Second)
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	sec := int(d.Seconds()) % 60
	return fmt.Sprintf("%dday:%dh:%dm:%ds", days, h, m, sec)
}
