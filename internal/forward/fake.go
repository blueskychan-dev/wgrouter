package forward

import (
	"context"
	"sync"
)

// FakeFirewall is an in-memory Firewall for tests.
type FakeFirewall struct {
	mu sync.Mutex

	// Applied is the most recent ruleset handed to Apply.
	Applied []Rule
	// ApplyCalls counts reconciles that reached the kernel layer.
	ApplyCalls int
	// TornDown records whether Teardown ran.
	TornDown bool
	Closed   bool

	ApplyErr  error
	VerifyErr error

	// DropFromKernel simulates rules that failed to install: IDs listed here
	// are omitted from Verify even though Apply accepted them.
	DropFromKernel map[int64]bool

	// SimCounters is the cumulative counter reading Verify reports per forward.
	SimCounters map[int64]Counters

	// LogDrops mirrors the firewall-logging switch.
	LogDrops bool
}

// NewFakeFirewall returns an initialised fake.
func NewFakeFirewall() *FakeFirewall {
	return &FakeFirewall{DropFromKernel: map[int64]bool{}, SimCounters: map[int64]Counters{}}
}

func (f *FakeFirewall) Apply(ctx context.Context, rules []Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ApplyCalls++
	if f.ApplyErr != nil {
		return f.ApplyErr
	}
	f.Applied = append([]Rule(nil), rules...)
	return nil
}

func (f *FakeFirewall) Verify(ctx context.Context) (map[int64]Counters, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.VerifyErr != nil {
		return nil, f.VerifyErr
	}
	out := map[int64]Counters{}
	for _, r := range f.Applied {
		if f.DropFromKernel[r.ID] {
			continue
		}
		// Mirror the real implementation's shape: one DNAT and one filter rule
		// per transport, plus a masquerade rule when that mode is selected.
		n := len(r.Transports()) * 2
		if r.SrcMode == SrcModeMasquerade {
			n += len(r.Transports())
		}
		c := Counters{Rules: n}
		if sim, ok := f.SimCounters[r.ID]; ok {
			c.Accepted, c.Dropped, c.Bytes = sim.Accepted, sim.Dropped, sim.Bytes
		}
		out[r.ID] = c
	}
	return out, nil
}

// SetCounters makes Verify report these cumulative figures for a forward, so a
// test can simulate traffic without a kernel.
func (f *FakeFirewall) SetCounters(id int64, c Counters) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.SimCounters == nil {
		f.SimCounters = map[int64]Counters{}
	}
	f.SimCounters[id] = c
}

// SetLogDrops records the requested logging state.
func (f *FakeFirewall) SetLogDrops(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.LogDrops = on
}

func (f *FakeFirewall) Teardown(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.TornDown = true
	f.Applied = nil
	return nil
}

func (f *FakeFirewall) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Closed = true
	return nil
}

// LastApplied returns a copy of the most recent ruleset.
func (f *FakeFirewall) LastApplied() []Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Rule(nil), f.Applied...)
}

// StaticRules is a RuleSource backed by a fixed slice.
type StaticRules struct {
	mu    sync.Mutex
	Rules []Rule
	Err   error
}

func (s *StaticRules) EnabledForwardRules(ctx context.Context) ([]Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Err != nil {
		return nil, s.Err
	}
	return append([]Rule(nil), s.Rules...), nil
}

// Set replaces the rule set.
func (s *StaticRules) Set(rules ...Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Rules = rules
}

var (
	_ Firewall   = (*FakeFirewall)(nil)
	_ RuleSource = (*StaticRules)(nil)
)
