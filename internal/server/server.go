// Package server implements wgrouter's admin HTTP interface: routing,
// session authentication, CSRF protection and the HUMAX-styled screens.
package server

import (
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"sync"
	"time"

	"wgrouter/internal/auth"
	"wgrouter/internal/config"
	"wgrouter/internal/forward"
	"wgrouter/internal/ipam"
	"wgrouter/internal/status"
	"wgrouter/internal/store"
	"wgrouter/internal/wg"
	"wgrouter/web"
)

// Server holds everything the HTTP handlers need.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	sessions *auth.SessionStore
	tmpl     map[string]*template.Template
	mux      *http.ServeMux
	handler  http.Handler
	started  time.Time
	version  string

	// wgm and rec are the two kernel-facing subsystems. Handlers mutate the
	// database and then ask these to make the kernel agree; they never write
	// kernel state directly.
	wgm  *wg.Manager
	rec  *forward.Reconciler
	plan ipam.Plan

	// sys reads the router's own health. It holds the previous CPU sample, so
	// there is one collector for the process rather than one per request.
	sys *status.Collector

	// hashSem bounds concurrent password hashing; loginThrottle bounds repeated
	// failures from one source. See throttle.go for why both are needed.
	// diagSem bounds concurrent diagnostic probes for the same reason.
	hashSem       chan struct{}
	diagSem       chan struct{}
	loginThrottle *throttle

	// logMu guards the cached logging configuration. It is cached rather than
	// read per audit write: audit() runs on the tail of every mutation, and a
	// database round trip there would double the cost of every change.
	logMu       sync.RWMutex
	logSettings store.LogSettings
}

// setLogSettings updates the cached logging configuration.
func (s *Server) setLogSettings(ls store.LogSettings) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	s.logSettings = ls
}

// LoadLogSettings primes the cache from the database. Called at startup.
func (s *Server) LoadLogSettings(ctx context.Context) error {
	ls, err := s.store.LoadLogSettings(ctx)
	if err != nil {
		return err
	}
	s.setLogSettings(ls)
	return nil
}

// shouldAudit reports whether an action passes the operator's filter.
func (s *Server) shouldAudit(action string) bool {
	s.logMu.RLock()
	defer s.logMu.RUnlock()
	return s.logSettings.ShouldAudit(action)
}

// Deps are the collaborators a Server needs beyond its configuration.
type Deps struct {
	Store      *store.Store
	Sessions   *auth.SessionStore
	WG         *wg.Manager
	Reconciler *forward.Reconciler
	Plan       ipam.Plan
	Version    string
}

// New builds a Server. It parses templates eagerly so that a malformed
// template fails at startup rather than in front of a user.
func New(cfg *config.Config, d Deps) (*Server, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:           cfg,
		store:         d.Store,
		sessions:      d.Sessions,
		wgm:           d.WG,
		rec:           d.Reconciler,
		plan:          d.Plan,
		tmpl:          tmpl,
		started:       time.Now(),
		version:       d.Version,
		sys:           status.NewCollector(),
		hashSem:       make(chan struct{}, hashSlots()),
		diagSem:       make(chan struct{}, diagSlots),
		loginThrottle: newThrottle(),
		// Default until the database is read: recording everything is the safe
		// starting point for an audit log.
		logSettings: store.LogSettings{UserEnabled: true},
	}
	s.mux = s.routes()

	// Build the middleware chain once. logRequests is outermost so that a
	// panicked request still produces an access-log line: recoverPanic writes
	// its 500 through the status recorder rather than past it.
	s.handler = s.logRequests(s.recoverPanic(s.securityHeaders(s.mux)))
	return s, nil
}

// ServeHTTP dispatches through the middleware chain.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// StartBackground launches the server's housekeeping goroutines, stopping them
// when done is closed.
func (s *Server) StartBackground(done <-chan struct{}) {
	s.loginThrottle.StartSweeper(done)
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	// Static assets are public and unauthenticated: they leak nothing, and
	// gating them would break the login page's own styling.
	static, err := fs.Sub(web.Static, "static")
	if err != nil {
		// Only possible if the embed directive and this path disagree, which is
		// a build-time mistake, not a runtime condition.
		panic(fmt.Sprintf("server: embedded static assets missing: %v", err))
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", s.cacheStatic(http.FileServerFS(static))))

	// First-run setup. Reachable only while no account exists; setupOnly
	// enforces that in both directions.
	mux.Handle("GET /setup", s.setupOnly(http.HandlerFunc(s.handleSetupForm)))
	mux.Handle("POST /setup", s.setupOnly(s.requireCSRF(http.HandlerFunc(s.handleSetupSubmit))))

	// Authentication.
	mux.Handle("GET /login", s.requireSetup(http.HandlerFunc(s.handleLoginForm)))
	mux.Handle("POST /login", s.requireSetup(s.requireCSRF(http.HandlerFunc(s.handleLoginSubmit))))
	mux.Handle("POST /logout", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleLogout))))

	// Screens. "GET /{$}" matches only the exact root, leaving "GET /" free to
	// act as the catch-all 404 below.
	mux.Handle("GET /{$}", s.requireAuth(http.HandlerFunc(s.handleStatus)))
	mux.Handle("GET /devices", s.requireAuth(http.HandlerFunc(s.handleDevices)))
	mux.Handle("GET /forwards", s.requireAuth(http.HandlerFunc(s.handleForwards)))
	// /logs was the audit log before the Administration section existed. It is
	// kept as a redirect rather than deleted outright: a bookmark or a link in
	// someone's runbook should land on the page that replaced it, not a 404.
	mux.Handle("GET /logs", s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/userlog", http.StatusMovedPermanently)
	})))
	mux.Handle("GET /system", s.requireAuth(http.HandlerFunc(s.handleSystem)))
	mux.Handle("POST /system/password", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handlePasswordChange))))

	// Diagnostics console. A closed command set, so nothing arbitrary runs.
	mux.Handle("POST /system/diagnostics", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleDiagnosticsRun))))

	// Device provisioning. The generated config is rendered once, in the
	// response to the create request, and never stored -- so there is no
	// "download it again" route by design.
	mux.Handle("POST /devices", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleDeviceCreate))))
	mux.Handle("POST /devices/{id}/delete", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleDeviceDelete))))
	mux.Handle("POST /devices/{id}/toggle", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleDeviceToggle))))
	mux.Handle("POST /devices/{id}/update", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleDeviceUpdate))))

	// Port forwarding.
	mux.Handle("POST /forwards", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleForwardCreate))))
	mux.Handle("POST /forwards/{id}/delete", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleForwardDelete))))
	mux.Handle("POST /forwards/{id}/toggle", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleForwardToggle))))
	mux.Handle("POST /forwards/{id}/update", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleForwardUpdate))))

	// Administration: configuration files, maintenance and the two logs.
	mux.Handle("GET /admin/config", s.requireAuth(http.HandlerFunc(s.handleConfigPage)))
	mux.Handle("GET /admin/config/export", s.requireAuth(http.HandlerFunc(s.handleConfigExport)))
	mux.Handle("POST /admin/config/import", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleConfigImport))))
	mux.Handle("GET /admin/maintenance", s.requireAuth(http.HandlerFunc(s.handleMaintenancePage)))
	mux.Handle("POST /admin/maintenance", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleMaintenanceRun))))
	mux.Handle("GET /admin/userlog", s.requireAuth(http.HandlerFunc(s.handleUserLogPage)))
	mux.Handle("GET /admin/firewalllog", s.requireAuth(http.HandlerFunc(s.handleFirewallLogPage)))
	mux.Handle("POST /admin/logs/settings", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleLogSettings))))
	mux.Handle("POST /admin/logs/clear", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleLogClear))))
	mux.Handle("GET /admin/logs/export", s.requireAuth(http.HandlerFunc(s.handleLogExport)))

	// Live status stream for the device list.
	mux.Handle("GET /events", s.requireAuth(http.HandlerFunc(s.handleEvents)))

	// Liveness. Deliberately unauthenticated and contentless so it can be used
	// by a supervisor without handing out a credential.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/", s.handleNotFound)
	return mux
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not found", http.StatusNotFound)
}

// Handler returns the fully-wrapped handler, for use by httptest and main.
func (s *Server) Handler() http.Handler { return s }

// setupComplete reports whether an admin account exists.
func (s *Server) setupComplete(ctx context.Context) (bool, error) {
	n, err := s.store.UserCount(ctx)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
