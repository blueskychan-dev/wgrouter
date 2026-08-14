package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// maxFormBytes caps request bodies parsed as forms. Every form we accept is a
// handful of short fields; without a cap an unauthenticated POST could ask the
// process to buffer an arbitrary amount.
const maxFormBytes = 64 << 10 // 64 KiB

// requireCSRF rejects a mutating request whose token does not match.
//
// Two token sources, because there are two situations:
//
//   - Signed in: the token is bound to the session. This is the strong form --
//     an attacker would need to read the user's session state to forge it.
//   - Not signed in (login, first-run setup): there is no session to bind to,
//     so we fall back to double-submit -- a random value held in a HttpOnly
//     cookie and echoed in the form. A cross-site attacker can cause a request
//     but cannot read the cookie to populate the field.
//
// SameSite=Strict on both cookies already blocks the classic cross-site POST;
// this is the second layer, and it is what protects against a same-site
// subdomain or a browser that does not enforce SameSite.
func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var expected string
		if sess := sessionFrom(r.Context()); sess != nil {
			expected = sess.CSRFToken
		} else if c, err := r.Cookie(csrfCookie); err == nil {
			expected = c.Value
		}

		got := r.PostFormValue("csrf_token")
		if expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(got)) != 1 {
			slog.WarnContext(r.Context(), "csrf token rejected",
				"path", r.URL.Path, "remote", remoteAddr(r))
			http.Error(w, "invalid or missing CSRF token — reload the page and try again", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ensureCSRFCookie issues a double-submit token for pre-session forms and puts
// it on the request context so the template can embed it.
func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) *http.Request {
	if c, err := r.Cookie(csrfCookie); err == nil && c.Value != "" {
		return r.WithContext(context.WithValue(r.Context(), ctxKeyCSRF, c.Value))
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// Failing closed here would make the login page unusable; log loudly and
		// continue with an empty token, which requireCSRF will then reject.
		slog.ErrorContext(r.Context(), "generate csrf token", "error", err)
		return r
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSEnabled(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
	})
	return r.WithContext(context.WithValue(r.Context(), ctxKeyCSRF, token))
}

// setSessionCookie issues the session cookie.
//
// Secure is set only when the listener actually serves HTTPS. Setting it
// unconditionally over plain HTTP would mean the browser never sends the cookie
// back and login would silently fail forever. The brief asks for Secure; the
// honest implementation is Secure whenever it can work, plus a startup warning
// when TLS is off. See README.
func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSEnabled(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionMaxAge.Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSEnabled(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// setFlash stores a one-shot message for the next request, so handlers can
// redirect after a successful POST instead of re-rendering.
func (s *Server) setFlash(w http.ResponseWriter, kind, msg string) {
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookie,
		Value:    url.QueryEscape(kind + "|" + msg),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSEnabled(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   60,
	})
}

// takeFlash reads and clears a pending flash message.
func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) *flash {
	c, err := r.Cookie(flashCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSEnabled(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	decoded, err := url.QueryUnescape(c.Value)
	if err != nil {
		return nil
	}
	kind, msg, ok := strings.Cut(decoded, "|")
	if !ok {
		return nil
	}
	switch kind {
	case "ok", "error", "info":
	default:
		kind = "info"
	}
	return &flash{Kind: kind, Message: msg}
}
