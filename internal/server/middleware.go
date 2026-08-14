package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"wgrouter/internal/auth"
)

type ctxKey int

const (
	ctxKeySession ctxKey = iota
	ctxKeyCSRF
)

// sessionCookie is the session identifier; csrfCookie backs CSRF protection for
// forms submitted before a session exists (login and first-run setup).
const (
	sessionCookie = "wgrouter_session"
	csrfCookie    = "wgrouter_csrf"
	flashCookie   = "wgrouter_flash"
)

func sessionFrom(ctx context.Context) *auth.Session {
	sess, _ := ctx.Value(ctxKeySession).(*auth.Session)
	return sess
}

func csrfTokenFrom(ctx context.Context) string {
	tok, _ := ctx.Value(ctxKeyCSRF).(string)
	return tok
}

// recoverPanic turns a handler panic into a 500 instead of a dropped
// connection, and logs the stack. main is the only place allowed to die.
func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				// http.ErrAbortHandler is the documented way for a handler to
				// abandon a response; propagating it is correct.
				if p == http.ErrAbortHandler {
					panic(p)
				}
				slog.ErrorContext(r.Context(), "panic in handler",
					"panic", p, "path", r.URL.Path, "stack", string(debug.Stack()))
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the response code for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (rec *statusRecorder) WriteHeader(code int) {
	if !rec.wrote {
		rec.status = code
		rec.wrote = true
	}
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *statusRecorder) Write(b []byte) (int, error) {
	if !rec.wrote {
		rec.status = http.StatusOK
		rec.wrote = true
	}
	return rec.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer, which the
// SSE handler will need for flushing.
func (rec *statusRecorder) Unwrap() http.ResponseWriter { return rec.ResponseWriter }

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		level := slog.LevelInfo
		if rec.status >= 500 {
			level = slog.LevelError
		} else if rec.status >= 400 {
			level = slog.LevelWarn
		}
		slog.Log(r.Context(), level, "http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration", time.Since(start).Round(time.Millisecond).String(),
			"remote", remoteAddr(r),
		)
	})
}

// securityHeaders sets defensive headers on every response.
//
// The CSP is strict because the UI needs nothing exotic: styles come from our
// own origin, and there is no inline script anywhere in the templates.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		if s.cfg.TLSEnabled() {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// cacheStatic marks embedded assets cacheable. They are compiled into the
// binary, so they can only change when the binary does.
func (s *Server) cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}

// requireSetup redirects to the first-run wizard until an admin account exists.
// The brief is explicit: serve nothing else until the password is set.
func (s *Server) requireSetup(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done, err := s.setupComplete(r.Context())
		if err != nil {
			slog.ErrorContext(r.Context(), "check setup state", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !done {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// setupOnly is the mirror image: the wizard is unreachable once setup is done,
// so a completed router cannot have a second account created by anyone who can
// reach the port.
func (s *Server) setupOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done, err := s.setupComplete(r.Context())
		if err != nil {
			slog.ErrorContext(r.Context(), "check setup state", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if done {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuth gates a handler behind a valid session, redirecting to the setup
// wizard or the login form as appropriate.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return s.requireSetup(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			s.redirectToLogin(w, r)
			return
		}
		sess, ok := s.sessions.Get(c.Value)
		if !ok {
			s.clearSessionCookie(w)
			s.redirectToLogin(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeySession, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	}))
}

func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// remoteAddr extracts the client address for logging and the audit trail.
//
// We deliberately do NOT honour X-Forwarded-For: the admin listener binds the
// tunnel address and is not expected to sit behind a proxy, so trusting a
// client-supplied header would let anyone forge their own audit entries.
func remoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
