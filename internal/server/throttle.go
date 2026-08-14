package server

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// Password hashing is deliberately expensive: argon2id at m=64 MiB allocates a
// fresh 64 MiB buffer for the duration of every call. That cost is the point
// when an attacker is guessing, but it is a liability when the endpoint doing
// the hashing is unauthenticated -- a ~200 byte request turns into 64 MiB of
// live heap, an amplification of roughly 300,000x.
//
// Both defences below exist because they stop different things:
//
//   - The semaphore bounds MEMORY. Without it, N concurrent login attempts
//     allocate N x 64 MiB; sixteen of them reach a gigabyte, which is fatal on
//     the small instances and routers this is meant to run on.
//   - The failure throttle bounds ATTEMPTS from one source. The semaphore alone
//     would serialise a guessing attack, not stop it.
//
// CSRF is not a defence here. Double-submit only proves the request came from
// something that can read its own cookie, which an attacker talking directly to
// the port trivially can.

// hashSlots bounds concurrent password hashing.
//
// Sized against memory rather than CPU: each slot may hold 64 MiB, so four
// slots is a 256 MiB ceiling. On a single-core box we still allow two, because
// the limit exists to cap footprint, not to keep cores busy.
func hashSlots() int {
	n := runtime.NumCPU() / 2
	if n < 2 {
		n = 2
	}
	if n > 4 {
		n = 4
	}
	return n
}

// acquireHashSlot blocks until a hashing slot is free, the request is
// cancelled, or the wait becomes too long to be worth serving. It reports
// whether the caller may proceed.
func (s *Server) acquireHashSlot(ctx context.Context) bool {
	// A short deadline rather than an unbounded wait: under a flood we would
	// rather shed load with a 503 than accumulate goroutines that each hold a
	// request open for a minute.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	select {
	case s.hashSem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Server) releaseHashSlot() {
	select {
	case <-s.hashSem:
	default:
	}
}

// Failed-login throttling.
const (
	// Attempts allowed from one source before the backoff engages.
	throttleBurst = 5
	// How long a recorded failure counts against the source.
	throttleWindow = 15 * time.Minute
	// Longest delay the backoff will impose.
	throttleMaxDelay = 30 * time.Second
)

// throttle counts recent failures per key (a remote address) and converts them
// into a delay.
//
// It is deliberately in-memory and approximate. A persistent per-account
// lockout would let anyone who can reach the port lock the administrator out of
// their own router, which is a worse failure than a slow guessing attack.
type throttle struct {
	mu      sync.Mutex
	entries map[string]*throttleEntry
	now     func() time.Time
}

type throttleEntry struct {
	failures int
	last     time.Time
}

func newThrottle() *throttle {
	return &throttle{
		entries: make(map[string]*throttleEntry),
		now:     time.Now,
	}
}

// Delay returns how long this key should be made to wait before its next
// attempt is processed, and whether it should be refused outright.
func (t *throttle) Delay(key string) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[key]
	if !ok {
		return 0, false
	}
	if t.now().Sub(e.last) > throttleWindow {
		delete(t.entries, key)
		return 0, false
	}
	if e.failures <= throttleBurst {
		return 0, false
	}

	// Exponential in the number of failures past the burst, capped.
	d := time.Second << min(e.failures-throttleBurst-1, 8)
	if d > throttleMaxDelay {
		return throttleMaxDelay, true
	}
	return d, true
}

// Fail records a failed attempt.
func (t *throttle) Fail(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[key]
	if !ok || t.now().Sub(e.last) > throttleWindow {
		e = &throttleEntry{}
		t.entries[key] = e
	}
	e.failures++
	e.last = t.now()
}

// Succeed clears a key's history after a successful sign-in.
func (t *throttle) Succeed(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// sweep drops entries that have aged out, so a long-running process does not
// accumulate one map entry per address that ever mistyped a password.
func (t *throttle) sweep() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for k, e := range t.entries {
		if now.Sub(e.last) > throttleWindow {
			delete(t.entries, k)
		}
	}
}

// StartSweeper runs a background cleanup loop until done is closed.
func (t *throttle) StartSweeper(done <-chan struct{}) {
	go func() {
		tk := time.NewTicker(throttleWindow)
		defer tk.Stop()
		for {
			select {
			case <-done:
				return
			case <-tk.C:
				t.sweep()
			}
		}
	}()
}
