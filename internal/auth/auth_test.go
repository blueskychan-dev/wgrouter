package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const goodPassword = "correct horse battery staple"

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword(goodPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Errorf("hash %q is not a PHC argon2id string", hash)
	}
	if strings.Contains(hash, goodPassword) {
		t.Fatal("hash contains the plaintext password")
	}
	if err := VerifyPassword(goodPassword, hash); err != nil {
		t.Errorf("VerifyPassword with the right password: %v", err)
	}
	if err := VerifyPassword("wrong password entirely", hash); !errors.Is(err, ErrMismatch) {
		t.Errorf("VerifyPassword with a wrong password = %v, want ErrMismatch", err)
	}
}

func TestHashesAreSalted(t *testing.T) {
	a, err := HashPassword(goodPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	b, err := HashPassword(goodPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if a == b {
		t.Error("two hashes of the same password are identical; the salt is not random")
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"not phc", "just-a-string"},
		{"too few fields", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA"},
		{"wrong algorithm", "$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"},
		{"bad version", "$argon2id$v=99$m=65536,t=3,p=4$c2FsdA$aGFzaA"},
		{"bad params", "$argon2id$v=19$m=abc,t=3,p=4$c2FsdA$aGFzaA"},
		{"zero cost", "$argon2id$v=19$m=0,t=3,p=4$c2FsdA$aGFzaA"},
		{"bad base64 salt", "$argon2id$v=19$m=65536,t=3,p=4$!!!!$aGFzaA"},
		{"empty salt", "$argon2id$v=19$m=65536,t=3,p=4$$aGFzaA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPassword(goodPassword, tt.hash)
			if !errors.Is(err, ErrBadHash) {
				t.Errorf("VerifyPassword(%q) = %v, want ErrBadHash", tt.hash, err)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword(strings.Repeat("a", MinPasswordLength-1)); err == nil {
		t.Error("a too-short password was accepted")
	}
	if err := ValidatePassword(strings.Repeat("a", MinPasswordLength)); err != nil {
		t.Errorf("a minimum-length password was rejected: %v", err)
	}
	if err := ValidatePassword(strings.Repeat("a", 2000)); err == nil {
		t.Error("an oversized password was accepted")
	}
	// Length is counted in runes, so a short multi-byte password is still short.
	if err := ValidatePassword("héllo"); err == nil {
		t.Error("a short multi-byte password was accepted")
	}
}

func TestHashPasswordAppliesPolicy(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("HashPassword accepted a password that violates the policy")
	}
}

func TestNeedsRehash(t *testing.T) {
	current, err := HashPassword(goodPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if NeedsRehash(current) {
		t.Error("a freshly-generated hash reports NeedsRehash")
	}
	// A hash produced with weaker parameters should be upgraded on next login.
	if !NeedsRehash("$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA") {
		t.Error("a weak-parameter hash does not report NeedsRehash")
	}
	if !NeedsRehash("garbage") {
		t.Error("an unparseable hash should report NeedsRehash")
	}
}

// --- Sessions --------------------------------------------------------------

func TestSessionLifecycle(t *testing.T) {
	s := NewSessionStore()

	token, sess, err := s.Create("admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if token == "" || sess.CSRFToken == "" {
		t.Fatal("Create returned an empty token")
	}
	if token == sess.CSRFToken {
		t.Error("session token and CSRF token are the same value")
	}

	got, ok := s.Get(token)
	if !ok {
		t.Fatal("Get did not find the session just created")
	}
	if got.Username != "admin" {
		t.Errorf("Username = %q, want admin", got.Username)
	}

	if _, ok := s.Get("some-other-token"); ok {
		t.Error("Get accepted an unknown token")
	}
	if _, ok := s.Get(""); ok {
		t.Error("Get accepted an empty token")
	}

	s.Destroy(token)
	if _, ok := s.Get(token); ok {
		t.Error("session survived Destroy")
	}
}

func TestSessionExpiry(t *testing.T) {
	s := NewSessionStore()
	now := time.Now()
	s.now = func() time.Time { return now }

	token, _, err := s.Create("admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok := s.Get(token); !ok {
		t.Fatal("session not valid immediately after creation")
	}

	// Step past the lifetime.
	now = now.Add(SessionLifetime + time.Second)
	if _, ok := s.Get(token); ok {
		t.Error("expired session was still accepted")
	}
	// Get should also have dropped it.
	if s.Count() != 0 {
		t.Errorf("Count() = %d after expiry, want 0", s.Count())
	}
}

func TestSweepDropsExpiredOnly(t *testing.T) {
	s := NewSessionStore()
	now := time.Now()
	s.now = func() time.Time { return now }

	oldToken, _, _ := s.Create("old")
	now = now.Add(SessionLifetime - time.Minute)
	freshToken, _, _ := s.Create("fresh")

	// Now step just past the first session's expiry.
	now = now.Add(2 * time.Minute)
	s.sweep()

	if _, ok := s.Get(oldToken); ok {
		t.Error("expired session survived sweep")
	}
	if _, ok := s.Get(freshToken); !ok {
		t.Error("sweep dropped a session that had not expired")
	}
}

func TestDestroyAllFor(t *testing.T) {
	s := NewSessionStore()
	a1, _, _ := s.Create("admin")
	a2, _, _ := s.Create("admin")
	other, _, _ := s.Create("someone")

	s.DestroyAllFor("admin")

	if _, ok := s.Get(a1); ok {
		t.Error("first admin session survived DestroyAllFor")
	}
	if _, ok := s.Get(a2); ok {
		t.Error("second admin session survived DestroyAllFor")
	}
	if _, ok := s.Get(other); !ok {
		t.Error("DestroyAllFor removed another user's session")
	}
}

func TestValidCSRF(t *testing.T) {
	s := NewSessionStore()
	_, sess, err := s.Create("admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !sess.ValidCSRF(sess.CSRFToken) {
		t.Error("the session's own CSRF token was rejected")
	}
	if sess.ValidCSRF("") {
		t.Error("an empty CSRF token was accepted")
	}
	if sess.ValidCSRF("not-the-token") {
		t.Error("a wrong CSRF token was accepted")
	}

	var nilSess *Session
	if nilSess.ValidCSRF("anything") {
		t.Error("a nil session accepted a CSRF token")
	}
}

func TestConcurrentSessionAccess(t *testing.T) {
	// Exercises the mutex under -race.
	s := NewSessionStore()
	const n = 50

	tokens := make(chan string, n)
	done := make(chan struct{})

	for i := 0; i < n; i++ {
		go func() {
			token, _, err := s.Create("admin")
			if err != nil {
				t.Error(err)
			}
			tokens <- token
		}()
	}
	go func() {
		for i := 0; i < n; i++ {
			token := <-tokens
			s.Get(token)
			s.Destroy(token)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for concurrent session operations")
	}
	if s.Count() != 0 {
		t.Errorf("Count() = %d, want 0 after destroying every session", s.Count())
	}
}
