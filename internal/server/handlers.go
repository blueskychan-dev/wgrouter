package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"wgrouter/internal/auth"
	"wgrouter/internal/store"
)

// sessionMaxAge mirrors the session store's lifetime for the cookie's MaxAge.
const sessionMaxAge = auth.SessionLifetime

// --- First-run setup -------------------------------------------------------

func (s *Server) handleSetupForm(w http.ResponseWriter, r *http.Request) {
	r = s.ensureCSRFCookie(w, r)
	d := s.newPageData(r, "")
	d.Flash = s.takeFlash(w, r)
	s.render(w, r, http.StatusOK, "setup", d)
}

func (s *Server) handleSetupSubmit(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm_password")

	fail := func(msg string) {
		r = s.ensureCSRFCookie(w, r)
		d := s.newPageData(r, "")
		d.Flash = &flash{Kind: "error", Message: msg}
		s.render(w, r, http.StatusBadRequest, "setup", d)
	}

	if err := validateUsername(username); err != nil {
		fail(err.Error())
		return
	}
	if password != confirm {
		fail("The two passwords do not match.")
		return
	}
	if err := auth.ValidatePassword(password); err != nil {
		fail(err.Error())
		return
	}

	// The wizard is unauthenticated while it is open, so its hashing is bounded
	// the same way login's is.
	if !s.acquireHashSlot(r.Context()) {
		fail("The router is busy. Try again in a moment.")
		return
	}
	hash, err := auth.HashPassword(password)
	s.releaseHashSlot()
	if err != nil {
		slog.ErrorContext(r.Context(), "hash password", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if _, err := s.store.CreateFirstUser(r.Context(), username, hash); err != nil {
		if errors.Is(err, store.ErrSetupComplete) {
			// Someone else completed setup between the GET and this POST.
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		slog.ErrorContext(r.Context(), "create first user", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	s.audit(r, username, store.ActionSetupComplete, "created initial administrator account")
	s.setFlash(w, "ok", "Administrator account created. Sign in to continue.")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- Authentication --------------------------------------------------------

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	r = s.ensureCSRFCookie(w, r)
	d := s.newPageData(r, "")
	d.Flash = s.takeFlash(w, r)
	s.render(w, r, http.StatusOK, "login", d)
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	source := remoteAddr(r)

	// Reject before hashing when this source has been failing repeatedly. Doing
	// this first is the point: the expensive work is what we are protecting.
	if delay, throttled := s.loginThrottle.Delay(source); throttled {
		slog.WarnContext(r.Context(), "login throttled", "remote", source, "delay", delay.String())
		w.Header().Set("Retry-After", strconv.Itoa(int(delay.Seconds())+1))
		s.renderLoginError(w, r, http.StatusTooManyRequests,
			"Too many failed sign-in attempts. Wait a moment and try again.")
		return
	}

	// A malformed username can never match a stored account, so reject it
	// before spending a hash on it -- and before it reaches the audit log,
	// where it would otherwise be attacker-controlled text.
	if err := validateUsername(username); err != nil {
		s.loginThrottle.Fail(source)
		s.audit(r, "", store.ActionLoginFailed, "rejected malformed username")
		s.renderLoginError(w, r, http.StatusUnauthorized, "Incorrect username or password.")
		return
	}

	user, err := s.store.UserByName(r.Context(), username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		slog.ErrorContext(r.Context(), "look up user", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Verify even when the user does not exist, against a hash that cannot
	// match. Skipping the work for unknown usernames makes login timing a user
	// enumeration oracle.
	stored := user.PasswordHash
	if errors.Is(err, store.ErrNotFound) {
		stored = dummyHash
	}

	// Bound concurrent hashing: each verification holds 64 MiB for its
	// duration, and this endpoint is unauthenticated.
	if !s.acquireHashSlot(r.Context()) {
		slog.WarnContext(r.Context(), "login shed: no hashing slot available", "remote", source)
		s.renderLoginError(w, r, http.StatusServiceUnavailable,
			"The router is busy. Try again in a moment.")
		return
	}
	verr := auth.VerifyPassword(password, stored)
	s.releaseHashSlot()

	if err != nil || verr != nil {
		s.loginThrottle.Fail(source)
		s.audit(r, username, store.ActionLoginFailed, "invalid credentials")
		s.renderLoginError(w, r, http.StatusUnauthorized, "Incorrect username or password.")
		return
	}
	s.loginThrottle.Succeed(source)

	// Transparently upgrade a hash produced with weaker parameters, now that we
	// hold the plaintext and know it is correct.
	if auth.NeedsRehash(stored) {
		if newHash, err := auth.HashPassword(password); err == nil {
			if err := s.store.SetPassword(r.Context(), user.ID, newHash); err != nil {
				slog.WarnContext(r.Context(), "rehash password", "error", err)
			}
		}
	}

	// Drop whatever session this browser was carrying before issuing a new one,
	// so a pre-login token can never be re-presented as an authenticated one
	// and stale sessions do not accumulate for the full lifetime.
	if c, cerr := r.Cookie(sessionCookie); cerr == nil {
		s.sessions.Destroy(c.Value)
	}

	token, _, err := s.sessions.Create(user.Username)
	if err != nil {
		slog.ErrorContext(r.Context(), "create session", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, token)
	s.audit(r, user.Username, store.ActionLogin, "signed in")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// renderLoginError re-renders the sign-in form with a message.
func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	r = s.ensureCSRFCookie(w, r)
	d := s.newPageData(r, "")
	d.Flash = &flash{Kind: "error", Message: msg}
	s.render(w, r, status, "login", d)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Destroy(c.Value)
	}
	if sess := sessionFrom(r.Context()); sess != nil {
		s.audit(r, sess.Username, store.ActionLogout, "signed out")
	}
	s.clearSessionCookie(w)
	s.setFlash(w, "ok", "You have been signed out.")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// dummyHash is an argon2id hash of a random value nobody knows, generated once
// at startup. Verifying against it makes an unknown username cost the same as a
// known one; a hard-coded constant risks silently decoding to something cheap.
var dummyHash = func() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// Startup-time and non-recoverable in any useful way, but this is a
		// library: degrade to a value that still fails every comparison.
		return "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	h, err := auth.HashPassword(base64.RawStdEncoding.EncodeToString(raw))
	if err != nil {
		return "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	return h
}()

// --- Screens ---------------------------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	d := s.newPageData(r, "/")
	d.Flash = s.takeFlash(w, r)
	d.Uptime = uptime(s.started)

	// A failed read here must not render as a confident zero. Log it and say so
	// on the page, rather than showing "0 peers" for a database that is simply
	// unreadable.
	var degraded bool
	v, err := s.store.SchemaVersion(r.Context())
	if err != nil {
		slog.ErrorContext(r.Context(), "read schema version", "error", err)
		degraded = true
	}
	d.SchemaVersion = v

	key, err := s.store.SettingOr(r.Context(), store.SettingServerPublicKey, "")
	if err != nil {
		slog.ErrorContext(r.Context(), "read server public key", "error", err)
		degraded = true
	}
	d.ServerPublicKey = key

	var ok bool
	if d.PeerCount, ok = s.countRows(r, "peers"); !ok {
		degraded = true
	}
	if d.ForwardCount, ok = s.countRows(r, "forwards"); !ok {
		degraded = true
	}

	// The online figure has to come from the kernel: it is derived from
	// handshake times, which the database does not hold.
	if err := s.loadDevices(r, &d); err != nil {
		slog.ErrorContext(r.Context(), "load devices for status", "error", err)
		degraded = true
	}
	d.OnlineCount = countOnline(d.Devices)

	s.loadSystem(&d)
	s.loadConnStats(r, &d)

	if degraded && d.Flash == nil {
		d.Flash = &flash{Kind: "error", Message: "Some values could not be read from the database; the figures below may be incomplete."}
	}
	s.render(w, r, http.StatusOK, "status", d)
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	d := s.newPageData(r, "/devices")
	d.Flash = s.takeFlash(w, r)

	if err := s.loadDevices(r, &d); err != nil {
		slog.ErrorContext(r.Context(), "load devices", "error", err)
		if d.Flash == nil {
			d.Flash = &flash{Kind: "error", Message: "The device list could not be read from the database."}
		}
	}
	if id := editID(r); id != 0 {
		for i := range d.Devices {
			if d.Devices[i].ID == id {
				d.EditDevice = &d.Devices[i]
				break
			}
		}
	}
	s.render(w, r, http.StatusOK, "devices", d)
}

func (s *Server) handleForwards(w http.ResponseWriter, r *http.Request) {
	d := s.newPageData(r, "/forwards")
	d.Flash = s.takeFlash(w, r)

	if err := s.loadForwards(r, &d); err != nil {
		slog.ErrorContext(r.Context(), "load forwards", "error", err)
		if d.Flash == nil {
			d.Flash = &flash{Kind: "error", Message: "The forwarding table could not be read from the database."}
		}
	}
	// The create form needs the device list to populate its target dropdown.
	if err := s.loadDevices(r, &d); err != nil {
		slog.ErrorContext(r.Context(), "load devices for forward form", "error", err)
	}
	d.NoDevicesForFwd = len(d.Devices) == 0

	if id := editID(r); id != 0 {
		for i := range d.Forwards {
			if d.Forwards[i].ID == id {
				d.EditForward = &d.Forwards[i]
				break
			}
		}
	}
	s.render(w, r, http.StatusOK, "forwards", d)
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	d := s.newPageData(r, "/system")
	d.Flash = s.takeFlash(w, r)
	v, err := s.store.SchemaVersion(r.Context())
	if err != nil {
		slog.ErrorContext(r.Context(), "read schema version", "error", err)
		if d.Flash == nil {
			d.Flash = &flash{Kind: "error", Message: "The schema version could not be read from the database."}
		}
	}
	d.SchemaVersion = v
	s.loadSystem(&d)
	d.DiagTools = diagToolOptions("")
	s.render(w, r, http.StatusOK, "system", d)
}

func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if sess == nil {
		s.redirectToLogin(w, r)
		return
	}

	current := r.PostFormValue("current_password")
	next := r.PostFormValue("new_password")
	confirm := r.PostFormValue("confirm_password")

	redirectErr := func(msg string) {
		s.setFlash(w, "error", msg)
		http.Redirect(w, r, "/system", http.StatusSeeOther)
	}

	user, err := s.store.UserByName(r.Context(), sess.Username)
	if err != nil {
		slog.ErrorContext(r.Context(), "look up user", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if err := auth.VerifyPassword(current, user.PasswordHash); err != nil {
		s.audit(r, sess.Username, store.ActionLoginFailed, "password change with wrong current password")
		redirectErr("The current password is incorrect.")
		return
	}
	if next != confirm {
		redirectErr("The two new passwords do not match.")
		return
	}
	if err := auth.ValidatePassword(next); err != nil {
		redirectErr(err.Error())
		return
	}

	hash, err := auth.HashPassword(next)
	if err != nil {
		slog.ErrorContext(r.Context(), "hash password", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if err := s.store.SetPassword(r.Context(), user.ID, hash); err != nil {
		slog.ErrorContext(r.Context(), "set password", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	s.audit(r, sess.Username, store.ActionPasswordChange, "changed the administrator password")

	// Invalidate every session for this user, then issue a fresh one so the
	// browser that made the change stays signed in. A stolen cookie must not
	// outlive the password it was captured under.
	s.sessions.DestroyAllFor(user.Username)
	token, _, err := s.sessions.Create(user.Username)
	if err != nil {
		slog.ErrorContext(r.Context(), "reissue session", "error", err)
		s.clearSessionCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, token)
	s.setFlash(w, "ok", "Password changed. Any other signed-in sessions have been ended.")
	http.Redirect(w, r, "/system", http.StatusSeeOther)
}

// --- Helpers ---------------------------------------------------------------

// countRows returns the row count for one of our own tables, and whether the
// read succeeded. The table name is never user-supplied; it is a compile-time
// constant at every call site.
func (s *Server) countRows(r *http.Request, table string) (int, bool) {
	var n int
	q := fmt.Sprintf("SELECT COUNT(*) FROM %s", table)
	if err := s.store.DB().QueryRowContext(r.Context(), q).Scan(&n); err != nil {
		slog.ErrorContext(r.Context(), "count rows", "table", table, "error", err)
		return 0, false
	}
	return n, true
}

// audit records a mutation, logging rather than failing the request if the
// write itself fails: losing an audit line is bad, but undoing a change that
// already happened because we could not log it is worse.
//
// The context is detached from the request. Audit entries are written after the
// mutation has already committed, and a client that disconnects at that moment
// -- closing the tab, a flaky tunnel -- would otherwise cancel the insert and
// leave a completed change with no record of who made it. That is precisely the
// case the audit trail exists for.
func (s *Server) audit(r *http.Request, actor, action, detail string) {
	// The operator's filter decides what is recorded, except for the actions
	// store.alwaysAudited protects -- a log that can be silently switched off
	// for failed sign-ins would still look authoritative while hiding exactly
	// what an audit exists to show.
	if !s.shouldAudit(action) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()

	if err := s.store.Audit(ctx, actor, action, detail, remoteAddr(r)); err != nil {
		slog.ErrorContext(ctx, "write audit entry", "action", action, "error", err)
	}
}

// validateUsername applies the username policy. Messages are lowercase and
// unpunctuated to match the convention for Go error strings; the templates
// present them as-is.
func validateUsername(u string) error {
	if len(u) < 1 || len(u) > 64 {
		return errors.New("username must be between 1 and 64 characters")
	}
	for _, c := range u {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return errors.New("username may contain only letters, digits, dot, dash and underscore")
		}
	}
	return nil
}
