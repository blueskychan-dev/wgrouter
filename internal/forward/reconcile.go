package forward

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Counters is what the kernel reports for one forward.
//
// Accepted and Dropped count *connections*, not packets: both rules match only
// ct state new, so each increment is one connection attempt. Bytes counts every
// packet arriving on the forwarded port, which is traffic rather than
// connections -- the two answer different questions and are kept separate.
type Counters struct {
	Rules    int
	Accepted uint64
	Dropped  uint64
	Bytes    uint64
}

// Firewall is the kernel surface the reconciler needs. The nftables
// implementation is behind it so the reconciler's logic can be tested without
// root or a network namespace.
type Firewall interface {
	// Apply replaces our table's contents with rules for these forwards.
	Apply(ctx context.Context, rules []Rule) error

	// Verify reports the kernel's state and counters per forward ID.
	Verify(ctx context.Context) (map[int64]Counters, error)

	// Teardown removes our table.
	Teardown(ctx context.Context) error

	// SetLogDrops turns firewall logging on or off, applied on the next Apply.
	SetLogDrops(on bool)

	Close() error
}

// RuleSource supplies the desired state. The store implements it.
type RuleSource interface {
	EnabledForwardRules(ctx context.Context) ([]Rule, error)
}

// Reconciler keeps the kernel equal to the database.
type Reconciler struct {
	fw  Firewall
	src RuleSource

	// mu serialises Apply. Two concurrent rebuilds would each be internally
	// consistent but the later one might be built from an older read.
	mu sync.Mutex

	// applied is the ruleset last written to the kernel, used to decide whether
	// a rebuild is needed at all.
	applied []Rule

	// baseline is the previous cumulative counter reading. Guarded by mu, which
	// Reconcile holds for its whole duration.
	baseline map[int64]Counters

	// last records the outcome of the most recent reconcile, for the UI.
	lastMu  sync.RWMutex
	lastAt  time.Time
	lastErr error
	present map[int64]Counters

	// Sink receives per-forward counter deltas after each reconcile. Optional.
	sink Sink
}

// Sink records connection statistics. The store implements it.
type Sink interface {
	RecordForwardStats(ctx context.Context, at time.Time, deltas map[int64]Counters) error
}

// NewReconciler builds a Reconciler.
func NewReconciler(fw Firewall, src RuleSource) *Reconciler {
	return &Reconciler{fw: fw, src: src, present: map[int64]Counters{}}
}

// SetLogDrops turns firewall logging on or off and forces a rebuild, since the
// log statements live in the rules themselves.
func (r *Reconciler) SetLogDrops(ctx context.Context, on bool) error {
	r.mu.Lock()
	r.fw.SetLogDrops(on)
	// Drop the memo of what was applied so the next reconcile rebuilds.
	r.applied = nil
	r.mu.Unlock()
	return r.Reconcile(ctx)
}

// WithSink attaches a statistics sink.
func (r *Reconciler) WithSink(s Sink) *Reconciler {
	r.sink = s
	return r
}

// Reconcile rebuilds the kernel ruleset from the database.
//
// This is the only path that writes rules. Startup, every mutation and the
// periodic timer all call it, so there is one way for the kernel to be wrong
// and it corrects itself on the next tick.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	rules, err := r.src.EnabledForwardRules(ctx)
	if err != nil {
		r.record(nil, err)
		return err
	}

	// Read the kernel first. Applying rebuilds the table from scratch, which
	// resets every packet counter -- so an unconditional rebuild on the timer
	// would zero the connection statistics every tick and lose the numbers this
	// whole mechanism exists to collect.
	present, verr := r.fw.Verify(ctx)
	if verr != nil {
		r.record(nil, verr)
		return verr
	}

	if r.needsApply(rules, present) {
		if err := r.fw.Apply(ctx, rules); err != nil {
			r.record(nil, err)
			return err
		}
		r.applied = append([]Rule(nil), rules...)
		// Re-read so the recorded state reflects what is actually installed
		// rather than what was requested.
		if present, verr = r.fw.Verify(ctx); verr != nil {
			r.record(nil, verr)
			return verr
		}
		// A rebuild zeroed the counters, so the previous cumulative reading is
		// no longer a valid baseline.
		r.resetBaseline()
	}

	r.record(present, nil)
	r.emit(ctx, present)
	return nil
}

// needsApply reports whether the kernel ruleset must be rebuilt.
//
// It rebuilds when the desired rules differ from what was last written, or when
// the kernel does not hold a rule for every enabled forward -- which covers
// drift: someone flushing our table by hand, or a reboot.
func (r *Reconciler) needsApply(rules []Rule, present map[int64]Counters) bool {
	// Rule.Equal rather than slices.Equal: Rule holds a slice of source
	// prefixes, so it is not comparable and == would not compile -- and a
	// shallow comparison would miss an edited ACL entirely.
	if !slices.EqualFunc(rules, r.applied, func(a, b Rule) bool { return a.Equal(b) }) {
		return true
	}
	for _, rule := range rules {
		if present[rule.ID].Rules == 0 {
			return true
		}
	}
	// Rules in the kernel that no longer correspond to a desired forward.
	for id := range present {
		if !slices.ContainsFunc(rules, func(x Rule) bool { return x.ID == id }) {
			return true
		}
	}
	return false
}

// baseline is the previous cumulative counter reading, used to turn the
// kernel's monotonic counters into per-interval deltas.
//
// The counters restart at zero whenever the ruleset is rebuilt, so a naive
// subtraction would underflow into an enormous number. resetBaseline clears it
// after a rebuild, and emit treats any decrease as a reset as a second guard.
func (r *Reconciler) resetBaseline() {
	r.baseline = nil
}

// emit converts cumulative counters into deltas and hands them to the sink.
func (r *Reconciler) emit(ctx context.Context, present map[int64]Counters) {
	if r.sink == nil {
		return
	}
	deltas := make(map[int64]Counters, len(present))
	for id, now := range present {
		prev, had := r.baseline[id]
		d := Counters{Rules: now.Rules}
		switch {
		case !had || now.Accepted < prev.Accepted || now.Dropped < prev.Dropped || now.Bytes < prev.Bytes:
			// First reading, or the counters went backwards because the rules
			// were rebuilt. Take the current value as the interval's total
			// rather than a negative delta.
			d.Accepted, d.Dropped, d.Bytes = now.Accepted, now.Dropped, now.Bytes
		default:
			d.Accepted = now.Accepted - prev.Accepted
			d.Dropped = now.Dropped - prev.Dropped
			d.Bytes = now.Bytes - prev.Bytes
		}
		if d.Accepted > 0 || d.Dropped > 0 || d.Bytes > 0 {
			deltas[id] = d
		}
	}

	r.baseline = present
	if len(deltas) == 0 {
		return
	}
	if err := r.sink.RecordForwardStats(ctx, time.Now(), deltas); err != nil {
		slog.ErrorContext(ctx, "record forward statistics", "error", err)
	}
}

func (r *Reconciler) record(present map[int64]Counters, err error) {
	r.lastMu.Lock()
	defer r.lastMu.Unlock()
	r.lastAt = time.Now()
	r.lastErr = err
	if present != nil {
		r.present = present
	}
}

// Status is the reconciler's view of the kernel, for the UI.
type Status struct {
	At      time.Time
	Err     error
	Present map[int64]Counters
}

// Status returns the last reconcile outcome.
func (r *Reconciler) Status() Status {
	r.lastMu.RLock()
	defer r.lastMu.RUnlock()
	present := make(map[int64]Counters, len(r.present))
	for k, v := range r.present {
		present[k] = v
	}
	return Status{At: r.lastAt, Err: r.lastErr, Present: present}
}

// InKernel reports whether a forward has rules in the kernel.
func (s Status) InKernel(id int64) bool { return s.Present[id].Rules > 0 }

// Counters returns the kernel's figures for one forward.
func (s Status) Counters(id int64) Counters { return s.Present[id] }

// Start runs a reconcile immediately and then on a timer.
func (r *Reconciler) Start(ctx context.Context, every time.Duration, done <-chan struct{}) {
	if every <= 0 {
		every = 60 * time.Second
	}
	if err := r.Reconcile(ctx); err != nil {
		slog.ErrorContext(ctx, "initial nftables reconcile failed", "error", err)
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if err := r.Reconcile(ctx); err != nil {
					slog.ErrorContext(ctx, "periodic nftables reconcile failed", "error", err)
				}
			}
		}
	}()
}

// ipForwardPath is the sysctl that controls IPv4 forwarding. It is a variable
// so tests can point it at a temporary file.
var ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// EnableIPForwarding turns on IPv4 forwarding if it is off.
//
// Without this every NAT rule is programmed correctly and no packet is ever
// forwarded, which presents as "the port forward does nothing" with a
// completely healthy-looking ruleset. It is a sysctl rather than a netlink
// object, so it is a file write -- not a shell-out, and not a value that
// user input can influence.
func EnableIPForwarding() (changed bool, err error) {
	current, err := os.ReadFile(ipForwardPath)
	if err != nil {
		return false, fmt.Errorf("forward: read %s: %w", ipForwardPath, err)
	}
	if strings.TrimSpace(string(current)) == "1" {
		return false, nil
	}
	if err := os.WriteFile(ipForwardPath, []byte("1\n"), 0o644); err != nil {
		return false, fmt.Errorf("forward: enable IPv4 forwarding by writing %s "+
			"(needs CAP_NET_ADMIN and a writable /proc/sys): %w", ipForwardPath, err)
	}
	return true, nil
}
