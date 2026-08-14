package server

import (
	"context"
	"testing"
	"time"
)

func TestThrottleAllowsTheBurst(t *testing.T) {
	th := newThrottle()

	for i := 0; i < throttleBurst; i++ {
		if _, blocked := th.Delay("10.10.0.2"); blocked {
			t.Fatalf("blocked after only %d failures, want the first %d allowed", i, throttleBurst)
		}
		th.Fail("10.10.0.2")
	}
	// One more failure pushes it past the burst.
	th.Fail("10.10.0.2")
	if _, blocked := th.Delay("10.10.0.2"); !blocked {
		t.Error("not blocked after exceeding the burst")
	}
}

func TestThrottleBacksOffAndCaps(t *testing.T) {
	th := newThrottle()
	for i := 0; i < throttleBurst+2; i++ {
		th.Fail("10.10.0.2")
	}
	first, blocked := th.Delay("10.10.0.2")
	if !blocked {
		t.Fatal("expected to be blocked")
	}

	for i := 0; i < 20; i++ {
		th.Fail("10.10.0.2")
	}
	later, _ := th.Delay("10.10.0.2")

	if later < first {
		t.Errorf("delay did not grow with failures: %v then %v", first, later)
	}
	if later > throttleMaxDelay {
		t.Errorf("delay %v exceeds the cap %v", later, throttleMaxDelay)
	}
}

func TestThrottleIsPerKey(t *testing.T) {
	th := newThrottle()
	for i := 0; i < throttleBurst+2; i++ {
		th.Fail("10.10.0.2")
	}
	if _, blocked := th.Delay("10.10.0.3"); blocked {
		t.Error("one source's failures blocked a different source")
	}
}

func TestThrottleSucceedClears(t *testing.T) {
	th := newThrottle()
	for i := 0; i < throttleBurst+2; i++ {
		th.Fail("10.10.0.2")
	}
	th.Succeed("10.10.0.2")
	if _, blocked := th.Delay("10.10.0.2"); blocked {
		t.Error("still blocked after a successful sign-in cleared the history")
	}
}

func TestThrottleForgetsAfterTheWindow(t *testing.T) {
	th := newThrottle()
	now := time.Now()
	th.now = func() time.Time { return now }

	for i := 0; i < throttleBurst+2; i++ {
		th.Fail("10.10.0.2")
	}
	if _, blocked := th.Delay("10.10.0.2"); !blocked {
		t.Fatal("expected to be blocked")
	}

	now = now.Add(throttleWindow + time.Minute)
	if _, blocked := th.Delay("10.10.0.2"); blocked {
		t.Error("still blocked after the window elapsed")
	}
}

func TestThrottleSweepDropsStaleEntries(t *testing.T) {
	th := newThrottle()
	now := time.Now()
	th.now = func() time.Time { return now }

	th.Fail("stale")
	now = now.Add(throttleWindow + time.Minute)
	th.Fail("fresh")
	th.sweep()

	th.mu.Lock()
	_, staleExists := th.entries["stale"]
	_, freshExists := th.entries["fresh"]
	th.mu.Unlock()

	if staleExists {
		t.Error("sweep kept an entry older than the window")
	}
	if !freshExists {
		t.Error("sweep dropped a current entry")
	}
}

// The semaphore is what bounds memory: each password hash holds 64 MiB, so an
// unbounded unauthenticated endpoint is a large amplification factor.
func TestHashSlotsAreBounded(t *testing.T) {
	s := &Server{hashSem: make(chan struct{}, 2)}
	ctx := context.Background()

	if !s.acquireHashSlot(ctx) {
		t.Fatal("first slot not acquired")
	}
	if !s.acquireHashSlot(ctx) {
		t.Fatal("second slot not acquired")
	}

	// The third must not be granted while the first two are held.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if s.acquireHashSlot(cancelled) {
		t.Error("a third slot was granted with a capacity of two")
	}

	s.releaseHashSlot()
	if !s.acquireHashSlot(ctx) {
		t.Error("a slot was not reusable after release")
	}
}

func TestReleaseHashSlotIsSafeWhenEmpty(t *testing.T) {
	s := &Server{hashSem: make(chan struct{}, 1)}
	// Must not block or panic when nothing is held.
	s.releaseHashSlot()
	if !s.acquireHashSlot(context.Background()) {
		t.Error("slot unavailable after a spurious release")
	}
}

func TestHashSlotsSizing(t *testing.T) {
	n := hashSlots()
	if n < 2 || n > 4 {
		t.Errorf("hashSlots() = %d, want between 2 and 4", n)
	}
}
