package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// Session lifetime and the sweep interval for expired entries.
const (
	SessionLifetime = 8 * time.Hour
	sweepInterval   = 10 * time.Minute

	tokenBytes = 32 // 256 bits of entropy; far beyond guessing range
)

// Session is one logged-in browser.
type Session struct {
	Username  string
	CSRFToken string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// SessionStore keeps sessions in memory.
//
// Sessions deliberately do not survive a restart: they are not in the schema,
// and a router that has just rebooted has also just dropped every WireGuard
// peer and nftables rule it had. Being asked to log in again after a restart is
// the correct signal that the box has been down.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session // keyed by SHA-256 of the token, never the token
	now      func() time.Time    // injectable for tests
}

// NewSessionStore returns an empty store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
		now:      time.Now,
	}
}

// Create issues a session for username and returns the opaque token to put in
// the cookie. The token is returned only here; the store keeps a hash of it.
//
// Hashing the key means a leak of process memory or a heap dump does not hand
// over usable session cookies, the same reason we never store password
// plaintext.
func (s *SessionStore) Create(username string) (token string, sess *Session, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("auth: generate session token: %w", err)
	}
	csrf := make([]byte, tokenBytes)
	if _, err := rand.Read(csrf); err != nil {
		return "", nil, fmt.Errorf("auth: generate csrf token: %w", err)
	}

	token = base64.RawURLEncoding.EncodeToString(raw)
	now := s.now()
	sess = &Session{
		Username:  username,
		CSRFToken: base64.RawURLEncoding.EncodeToString(csrf),
		IssuedAt:  now,
		ExpiresAt: now.Add(SessionLifetime),
	}

	s.mu.Lock()
	s.sessions[hashToken(token)] = sess
	s.mu.Unlock()
	return token, sess, nil
}

// Get returns the session for a token, or false if it is unknown or expired.
func (s *SessionStore) Get(token string) (*Session, bool) {
	if token == "" {
		return nil, false
	}
	key := hashToken(token)

	s.mu.RLock()
	sess, ok := s.sessions[key]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if s.now().After(sess.ExpiresAt) {
		s.Destroy(token)
		return nil, false
	}
	return sess, true
}

// Destroy invalidates a session.
func (s *SessionStore) Destroy(token string) {
	if token == "" {
		return
	}
	key := hashToken(token)
	s.mu.Lock()
	delete(s.sessions, key)
	s.mu.Unlock()
}

// DestroyAllFor invalidates every session belonging to a user. Used after a
// password change so that a stolen cookie does not outlive the password it was
// obtained with.
func (s *SessionStore) DestroyAllFor(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, sess := range s.sessions {
		if sess.Username == username {
			delete(s.sessions, key)
		}
	}
}

// ValidCSRF reports whether token matches the session's CSRF token.
func (sess *Session) ValidCSRF(token string) bool {
	if sess == nil || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sess.CSRFToken), []byte(token)) == 1
}

// Count returns the number of live sessions. Exposed for the system page and
// for tests.
func (s *SessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// StartSweeper runs a background loop that drops expired sessions until done is
// closed. Without it, sessions for browsers that never log out would be
// retained until the process exits.
func (s *SessionStore) StartSweeper(done <-chan struct{}) {
	go func() {
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				s.sweep()
			}
		}
	}()
}

func (s *SessionStore) sweep() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, key)
		}
	}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return string(sum[:])
}
