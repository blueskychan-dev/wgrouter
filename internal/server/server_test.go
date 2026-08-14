package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"wgrouter/internal/auth"
	"wgrouter/internal/config"
	"wgrouter/internal/forward"
	"wgrouter/internal/ipam"
	"wgrouter/internal/store"
	"wgrouter/internal/wg"
)

const testPassword = "a sufficiently long password"

// TestMain silences the access log. These tests deliberately exercise failure
// paths, and their warnings would otherwise bury a real test failure.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

type harness struct {
	t        *testing.T
	srv      *Server
	store    *store.Store
	sessions *auth.SessionStore
	client   *http.Client
	base     string

	// The fakes behind the kernel-facing subsystems, for assertions.
	kernel *wg.FakeKernel
	fw     *forward.FakeFirewall
	plan   ipam.Plan
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	cfg, err := config.Load([]string{"-public-endpoint", "vpn.example.com"})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	st, err := store.OpenMemory(context.Background())
	if err != nil {
		t.Fatalf("store.OpenMemory: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	sessions := auth.NewSessionStore()

	// The kernel-facing halves run against fakes, so these tests exercise the
	// real handler logic without root, netlink or a network namespace.
	plan, err := ipam.NewPlan(cfg.TunnelPool)
	if err != nil {
		t.Fatalf("ipam.NewPlan: %v", err)
	}
	kernel := wg.NewFakeKernel()
	fw := forward.NewFakeFirewall()
	wgm := wg.NewManager(kernel, st, plan, cfg.WGInterface, cfg.WGListenPort, wg.DefaultMTU)
	rec := forward.NewReconciler(fw, st)

	srv, err := New(cfg, Deps{
		Store:      st,
		Sessions:   sessions,
		WG:         wgm,
		Reconciler: rec,
		Plan:       plan,
		Version:    "test",
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	jar := &cookieJar{cookies: map[string]*http.Cookie{}}
	return &harness{
		t:        t,
		srv:      srv,
		store:    st,
		sessions: sessions,
		base:     ts.URL,
		kernel:   kernel,
		fw:       fw,
		plan:     plan,
		client: &http.Client{
			Jar: jar,
			// Do not follow redirects: the redirect itself is what most of these
			// tests are asserting.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// cookieJar is a minimal jar: the standard one refuses to store cookies for
// 127.0.0.1 in some configurations, and we only ever talk to one host.
type cookieJar struct {
	cookies map[string]*http.Cookie
}

func (j *cookieJar) SetCookies(_ *url.URL, cs []*http.Cookie) {
	for _, c := range cs {
		if c.MaxAge < 0 || c.Value == "" {
			delete(j.cookies, c.Name)
			continue
		}
		j.cookies[c.Name] = c
	}
}

func (j *cookieJar) Cookies(*url.URL) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(j.cookies))
	for _, c := range j.cookies {
		out = append(out, c)
	}
	return out
}

func (h *harness) get(path string) *http.Response {
	h.t.Helper()
	resp, err := h.client.Get(h.base + path)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func (h *harness) post(path string, form url.Values) *http.Response {
	h.t.Helper()
	resp, err := h.client.PostForm(h.base+path, form)
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// csrfFrom fetches a page and extracts the CSRF token its form embeds.
func (h *harness) csrfFrom(path string) string {
	h.t.Helper()
	resp := h.get(path)
	b := body(h.t, resp)
	m := csrfRe.FindStringSubmatch(b)
	if m == nil {
		h.t.Fatalf("no csrf_token found on %s (status %d)", path, resp.StatusCode)
	}
	return m[1]
}

// completeSetup runs the first-run wizard.
func (h *harness) completeSetup() {
	h.t.Helper()
	token := h.csrfFrom("/setup")
	resp := h.post("/setup", url.Values{
		"csrf_token":       {token},
		"username":         {"admin"},
		"password":         {testPassword},
		"confirm_password": {testPassword},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("setup POST = %d, want 303", resp.StatusCode)
	}
}

// login signs in as the admin created by completeSetup.
func (h *harness) login() {
	h.t.Helper()
	token := h.csrfFrom("/login")
	resp := h.post("/login", url.Values{
		"csrf_token": {token},
		"username":   {"admin"},
		"password":   {testPassword},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("login POST = %d, want 303", resp.StatusCode)
	}
}

// --- Setup gate ------------------------------------------------------------

// Until an admin account exists the router must serve nothing but the wizard.
func TestBeforeSetupEverythingRedirectsToSetup(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/", "/devices", "/forwards", "/logs", "/system", "/login"} {
		resp := h.get(path)
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("GET %s before setup = %d, want 303", path, resp.StatusCode)
			continue
		}
		if loc := resp.Header.Get("Location"); loc != "/setup" {
			t.Errorf("GET %s before setup redirected to %q, want /setup", path, loc)
		}
	}
}

func TestSetupPageIsServedBeforeSetup(t *testing.T) {
	h := newHarness(t)
	resp := h.get("/setup")
	b := body(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /setup = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(b, "First-run setup") {
		t.Error("setup page did not render its heading")
	}
	// The sidebar must not appear before sign-in.
	if strings.Contains(b, `id="menuDiv"`) {
		t.Error("setup page rendered the navigation sidebar")
	}
}

// Once setup is complete the wizard must close behind itself, or anyone who can
// reach the port could create a second account.
func TestSetupIsClosedAfterCompletion(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()

	resp := h.get("/setup")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("GET /setup after completion = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("redirected to %q, want /login", loc)
	}

	// And the POST endpoint must be closed too, not just the form.
	token := h.csrfFrom("/login")
	resp = h.post("/setup", url.Values{
		"csrf_token":       {token},
		"username":         {"intruder"},
		"password":         {testPassword},
		"confirm_password": {testPassword},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("POST /setup after completion = %d, want a redirect away", resp.StatusCode)
	}
	if n, _ := h.store.UserCount(context.Background()); n != 1 {
		t.Errorf("UserCount = %d after a second setup attempt, want 1", n)
	}
}

func TestSetupValidation(t *testing.T) {
	tests := []struct {
		name string
		form url.Values
		want string
	}{
		{
			name: "mismatched passwords",
			form: url.Values{"username": {"admin"}, "password": {testPassword}, "confirm_password": {"something else entirely"}},
			want: "do not match",
		},
		{
			name: "short password",
			form: url.Values{"username": {"admin"}, "password": {"short"}, "confirm_password": {"short"}},
			want: "at least",
		},
		{
			name: "empty username",
			form: url.Values{"username": {""}, "password": {testPassword}, "confirm_password": {testPassword}},
			want: "username",
		},
		{
			name: "username with spaces",
			form: url.Values{"username": {"not valid"}, "password": {testPassword}, "confirm_password": {testPassword}},
			want: "username",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			form := url.Values{"csrf_token": {h.csrfFrom("/setup")}}
			for k, v := range tt.form {
				form[k] = v
			}
			resp := h.post("/setup", form)
			b := body(t, resp)

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if !strings.Contains(b, tt.want) {
				t.Errorf("response does not mention %q", tt.want)
			}
			if n, _ := h.store.UserCount(context.Background()); n != 0 {
				t.Errorf("UserCount = %d after a rejected setup, want 0", n)
			}
		})
	}
}

// --- CSRF ------------------------------------------------------------------

func TestCSRFIsRequired(t *testing.T) {
	h := newHarness(t)

	// Setup POST without a token.
	resp := h.post("/setup", url.Values{
		"username":         {"admin"},
		"password":         {testPassword},
		"confirm_password": {testPassword},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST /setup without a CSRF token = %d, want 403", resp.StatusCode)
	}
	if n, _ := h.store.UserCount(context.Background()); n != 0 {
		t.Error("an account was created by a request with no CSRF token")
	}

	// And with a wrong one.
	_ = h.csrfFrom("/setup") // establishes the cookie
	resp = h.post("/setup", url.Values{
		"csrf_token":       {"definitely-not-the-token"},
		"username":         {"admin"},
		"password":         {testPassword},
		"confirm_password": {testPassword},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST /setup with a wrong CSRF token = %d, want 403", resp.StatusCode)
	}
}

func TestCSRFRequiredOnAuthenticatedPost(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	resp := h.post("/system/password", url.Values{
		"current_password": {testPassword},
		"new_password":     {"another sufficiently long one"},
		"confirm_password": {"another sufficiently long one"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("password change without a CSRF token = %d, want 403", resp.StatusCode)
	}
}

// --- Authentication --------------------------------------------------------

func TestUnauthenticatedAccessRedirectsToLogin(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()

	for _, path := range []string{"/", "/devices", "/forwards", "/admin/userlog", "/admin/firewalllog", "/admin/config", "/admin/maintenance", "/system"} {
		resp := h.get(path)
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("GET %s unauthenticated = %d, want 303", path, resp.StatusCode)
			continue
		}
		if loc := resp.Header.Get("Location"); loc != "/login" {
			t.Errorf("GET %s redirected to %q, want /login", path, loc)
		}
	}
}

func TestLoginAndAccess(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	resp := h.get("/")
	b := body(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / after login = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(b, `id="menuDiv"`) {
		t.Error("the sidebar is missing from an authenticated page")
	}
	for _, want := range []string{"Status", "WireGuard", "Port Forwarding", "System",
		"Administration", "Configuration File", "Maintenance", "User Log", "Firewall Log"} {
		if !strings.Contains(b, want) {
			t.Errorf("navigation is missing %q", want)
		}
	}
	if !strings.Contains(b, "vpn.example.com") {
		t.Error("the status page does not show the configured endpoint")
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()

	for _, tc := range []struct{ name, user, pass string }{
		{"wrong password", "admin", "not the right password"},
		{"unknown user", "nobody", testPassword},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.post("/login", url.Values{
				"csrf_token": {h.csrfFrom("/login")},
				"username":   {tc.user},
				"password":   {tc.pass},
			})
			b := body(t, resp)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}
			// The same message for both, so login is not a user-enumeration oracle.
			if !strings.Contains(b, "Incorrect username or password") {
				t.Error("response did not show the generic failure message")
			}
		})
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()

	resp := h.post("/login", url.Values{
		"csrf_token": {h.csrfFrom("/login")},
		"username":   {"admin"},
		"password":   {testPassword},
	})
	defer resp.Body.Close()

	var sc *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			sc = c
		}
	}
	if sc == nil {
		t.Fatal("login did not set a session cookie")
	}
	if !sc.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}
	if sc.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie SameSite = %v, want Strict", sc.SameSite)
	}
	// Secure is conditional on TLS: setting it over plain HTTP would mean the
	// browser never sends the cookie back. This harness serves HTTP.
	if sc.Secure {
		t.Error("session cookie is marked Secure on a plain-HTTP listener, which would break login")
	}
}

func TestLogout(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	token := h.csrfFrom("/system")
	resp := h.post("/logout", url.Values{"csrf_token": {token}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout = %d, want 303", resp.StatusCode)
	}
	if h.sessions.Count() != 0 {
		t.Errorf("session count = %d after logout, want 0", h.sessions.Count())
	}

	resp = h.get("/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("GET / after logout = %d, want a redirect to login", resp.StatusCode)
	}
}

func TestStaleSessionCookieIsRejected(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	// Drop the session server-side, as a restart would.
	h.sessions.DestroyAllFor("admin")

	resp := h.get("/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("GET / with a stale cookie = %d, want a redirect", resp.StatusCode)
	}
}

// --- Password change -------------------------------------------------------

func TestPasswordChange(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	const newPassword = "an entirely different long password"
	resp := h.post("/system/password", url.Values{
		"csrf_token":       {h.csrfFrom("/system")},
		"current_password": {testPassword},
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("password change = %d, want 303", resp.StatusCode)
	}

	// The changing browser stays signed in.
	resp = h.get("/system")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /system after password change = %d, want 200", resp.StatusCode)
	}

	// The old password must no longer work.
	user, err := h.store.UserByName(context.Background(), "admin")
	if err != nil {
		t.Fatalf("UserByName: %v", err)
	}
	if err := auth.VerifyPassword(testPassword, user.PasswordHash); err == nil {
		t.Error("the old password still verifies after a change")
	}
	if err := auth.VerifyPassword(newPassword, user.PasswordHash); err != nil {
		t.Errorf("the new password does not verify: %v", err)
	}
}

func TestPasswordChangeRejectsWrongCurrent(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	resp := h.post("/system/password", url.Values{
		"csrf_token":       {h.csrfFrom("/system")},
		"current_password": {"not the current password"},
		"new_password":     {"a brand new long password"},
		"confirm_password": {"a brand new long password"},
	})
	resp.Body.Close()

	user, _ := h.store.UserByName(context.Background(), "admin")
	if err := auth.VerifyPassword(testPassword, user.PasswordHash); err != nil {
		t.Error("the password was changed despite a wrong current password")
	}
}

// A password change must end every other session, so a stolen cookie does not
// outlive the password it was captured under.
func TestPasswordChangeEndsOtherSessions(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	// A second browser, signed in independently.
	otherToken, _, err := h.sessions.Create("admin")
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	const newPassword = "yet another sufficiently long password"
	resp := h.post("/system/password", url.Values{
		"csrf_token":       {h.csrfFrom("/system")},
		"current_password": {testPassword},
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
	})
	resp.Body.Close()

	if _, ok := h.sessions.Get(otherToken); ok {
		t.Error("another session survived the password change")
	}
}

// --- Misc ------------------------------------------------------------------

func TestAuditTrailRecordsAuthEvents(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	entries, err := h.store.RecentAudit(context.Background(), 50)
	if err != nil {
		t.Fatalf("RecentAudit: %v", err)
	}

	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Action] = true
		if e.RemoteAddr == "" {
			t.Errorf("audit entry %q has no remote address", e.Action)
		}
	}
	for _, want := range []string{store.ActionSetupComplete, store.ActionLogin} {
		if !seen[want] {
			t.Errorf("audit log is missing a %q entry", want)
		}
	}
}

func TestStaticAssetsAreServed(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/static/css/tokens.css", "/static/css/humax.css"} {
		resp := h.get(path)
		b := body(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
		if len(b) == 0 {
			t.Errorf("GET %s returned an empty body", path)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	resp := h.get("/setup")
	resp.Body.Close()

	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "same-origin",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy = %q, missing frame-ancestors", csp)
	}
	// HSTS is meaningless without TLS and this listener is plain HTTP.
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS was set on a plain-HTTP listener")
	}
}

func TestHealthzIsUnauthenticated(t *testing.T) {
	h := newHarness(t)
	resp := h.get("/healthz")
	b := body(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(b, "ok") {
		t.Errorf("healthz body = %q", b)
	}
}

// Repeated failures from one source must start being refused before the
// argon2 work is done, or the login endpoint is an unthrottled guessing oracle.
func TestRepeatedFailedLoginsAreThrottled(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()

	var got429 bool
	for i := 0; i < throttleBurst+3; i++ {
		resp := h.post("/login", url.Values{
			"csrf_token": {h.csrfFrom("/login")},
			"username":   {"admin"},
			"password":   {"still the wrong password"},
		})
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			if resp.Header.Get("Retry-After") == "" {
				t.Error("a throttled response carries no Retry-After header")
			}
			break
		}
	}
	if !got429 {
		t.Errorf("no request was throttled after %d consecutive failures", throttleBurst+3)
	}
}

// A malformed username cannot match any account, so it must be rejected before
// a 64 MiB hash is spent on it and before it reaches the audit log.
func TestMalformedUsernameIsRejectedWithoutHashing(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()

	// Large, but inside the request body limit, so it reaches the handler's own
	// validation rather than being cut off by MaxBytesReader first.
	long := strings.Repeat("A", 10_000)
	resp := h.post("/login", url.Values{
		"csrf_token": {h.csrfFrom("/login")},
		"username":   {long},
		"password":   {"whatever this is"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}

	entries, err := h.store.RecentAudit(context.Background(), 50)
	if err != nil {
		t.Fatalf("RecentAudit: %v", err)
	}
	for _, e := range entries {
		if len(e.Actor) > 64 {
			t.Errorf("audit actor is %d bytes; attacker-controlled text reached the log unclamped", len(e.Actor))
		}
	}
}

// A body larger than the form limit must be refused outright, before any
// parsing or hashing.
func TestOversizedFormBodyIsRejected(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()

	resp := h.post("/login", url.Values{
		"csrf_token": {h.csrfFrom("/login")},
		"username":   {"admin"},
		"password":   {strings.Repeat("x", maxFormBytes+1024)},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d for an oversized body, want 400", resp.StatusCode)
	}
}

// A successful sign-in must not leave the browser's previous session valid.
func TestLoginInvalidatesThePreviousSession(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	first := h.sessions.Count()
	if first != 1 {
		t.Fatalf("session count after first login = %d, want 1", first)
	}

	h.login() // same browser, same cookie jar

	if n := h.sessions.Count(); n != 1 {
		t.Errorf("session count after a second login = %d, want 1; the old session was not dropped", n)
	}
}

// Signed-in pages must not be left in the browser cache after sign-out.
func TestAuthenticatedPagesAreNotCacheable(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	for _, path := range []string{"/", "/admin/userlog", "/system"} {
		resp := h.get(path)
		resp.Body.Close()
		cc := resp.Header.Get("Cache-Control")
		if !strings.Contains(cc, "no-store") {
			t.Errorf("GET %s Cache-Control = %q, want it to contain no-store", path, cc)
		}
	}
}

func TestUnknownPathIs404(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	resp := h.get("/no-such-page")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /no-such-page = %d, want 404", resp.StatusCode)
	}
}

func TestAllTemplatesRender(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	for _, path := range []string{"/", "/devices", "/forwards", "/admin/userlog", "/admin/firewalllog", "/admin/config", "/admin/maintenance", "/system"} {
		resp := h.get(path)
		b := body(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
		if !strings.Contains(b, "</html>") {
			t.Errorf("GET %s did not render a complete document", path)
		}
		// A template that references a missing field renders the literal
		// "<no value>"; catching it here beats finding it in a browser.
		if strings.Contains(b, "<no value>") {
			t.Errorf("GET %s rendered a missing template value", path)
		}
	}
}

// The audit log used to live at /logs, before the Administration section
// existed. A bookmark or a link in someone's runbook should land on the page
// that replaced it rather than a 404 -- and there must be exactly one page
// showing the audit log, not two that drift apart.
func TestOldLogsPathRedirects(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()
	h.login()

	resp := h.get("/logs")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("GET /logs = %d, want 301", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/admin/userlog" {
		t.Errorf("redirected to %q, want /admin/userlog", loc)
	}
}

// The sidebar must not offer two routes to the same screen.
func TestSidebarHasNoDuplicateDestinations(t *testing.T) {
	seen := map[string]string{}
	var walk func(items []navItem)
	walk = func(items []navItem) {
		for _, it := range items {
			if it.Href != "" {
				if prev, dup := seen[it.Href]; dup {
					t.Errorf("%q and %q both link to %s", prev, it.Label, it.Href)
				}
				seen[it.Href] = it.Label
			}
			walk(it.Children)
		}
	}
	walk(navSpec)
}
