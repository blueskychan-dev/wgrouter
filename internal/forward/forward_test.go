package forward

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var testPool = netip.MustParsePrefix("10.10.0.0/24")

func rule(id int64, proto Proto, listen uint16, target string, tport uint16, mode SrcMode) Rule {
	return Rule{
		ID:         id,
		Label:      "test",
		Proto:      proto,
		Listen:     PortRange{Start: listen, End: listen},
		RateLimit:  true,
		SrcPolicy:  SrcPolicyAny,
		TargetIP:   netip.MustParseAddr(target),
		TargetPort: tport,
		SrcMode:    mode,
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{"valid tcp masquerade", rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade), false},
		{"valid udp direct", rule(1, ProtoUDP, 5000, "10.10.0.2", 5000, SrcModeDirect), false},
		{"valid both", rule(1, ProtoBoth, 53, "10.10.0.2", 53, SrcModeMasquerade), false},
		{"zero listen port", rule(1, ProtoTCP, 0, "10.10.0.2", 80, SrcModeMasquerade), true},
		{"zero target port", rule(1, ProtoTCP, 80, "10.10.0.2", 0, SrcModeMasquerade), true},
		{"unknown protocol", rule(1, Proto("sctp"), 80, "10.10.0.2", 80, SrcModeMasquerade), true},
		{"unknown source mode", rule(1, ProtoTCP, 80, "10.10.0.2", 80, SrcMode("magic")), true},
		{"target outside the pool", rule(1, ProtoTCP, 80, "192.168.1.5", 80, SrcModeMasquerade), true},
		{"removed proxy mode is rejected", rule(1, ProtoTCP, 80, "10.10.0.2", 80, SrcMode("proxy")), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate(testPool)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRequiresLabel(t *testing.T) {
	r := rule(1, ProtoTCP, 80, "10.10.0.2", 80, SrcModeMasquerade)
	r.Label = "   "
	if err := r.Validate(testPool); err == nil {
		t.Error("a blank label was accepted")
	}
}

// The case SQLite's partial unique index cannot express.
func TestCheckOverlapAcrossProtocols(t *testing.T) {
	tests := []struct {
		name     string
		existing Rule
		incoming Rule
		conflict bool
	}{
		{"same port same proto", rule(1, ProtoTCP, 80, "10.10.0.2", 80, SrcModeMasquerade),
			rule(2, ProtoTCP, 80, "10.10.0.3", 80, SrcModeMasquerade), true},
		{"same port different proto", rule(1, ProtoTCP, 80, "10.10.0.2", 80, SrcModeMasquerade),
			rule(2, ProtoUDP, 80, "10.10.0.3", 80, SrcModeMasquerade), false},
		{"both overlaps tcp", rule(1, ProtoBoth, 80, "10.10.0.2", 80, SrcModeMasquerade),
			rule(2, ProtoTCP, 80, "10.10.0.3", 80, SrcModeMasquerade), true},
		{"tcp overlaps both", rule(1, ProtoTCP, 80, "10.10.0.2", 80, SrcModeMasquerade),
			rule(2, ProtoBoth, 80, "10.10.0.3", 80, SrcModeMasquerade), true},
		{"both overlaps udp", rule(1, ProtoBoth, 80, "10.10.0.2", 80, SrcModeMasquerade),
			rule(2, ProtoUDP, 80, "10.10.0.3", 80, SrcModeMasquerade), true},
		{"different port", rule(1, ProtoTCP, 80, "10.10.0.2", 80, SrcModeMasquerade),
			rule(2, ProtoTCP, 81, "10.10.0.3", 80, SrcModeMasquerade), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckOverlap([]Rule{tt.existing}, tt.incoming)
			if (err != nil) != tt.conflict {
				t.Errorf("CheckOverlap() = %v, want conflict = %v", err, tt.conflict)
			}
		})
	}
}

// Editing a rule must not conflict with the row it is replacing.
func TestCheckOverlapIgnoresItself(t *testing.T) {
	r := rule(7, ProtoTCP, 80, "10.10.0.2", 80, SrcModeMasquerade)
	updated := r
	updated.TargetPort = 8080
	if err := CheckOverlap([]Rule{r}, updated); err != nil {
		t.Errorf("a rule conflicted with itself: %v", err)
	}
}

func TestTransportsExpandsBoth(t *testing.T) {
	if got := rule(1, ProtoBoth, 80, "10.10.0.2", 80, SrcModeMasquerade).Transports(); len(got) != 2 {
		t.Errorf("both expanded to %v, want two transports", got)
	}
	if got := rule(1, ProtoTCP, 80, "10.10.0.2", 80, SrcModeMasquerade).Transports(); len(got) != 1 {
		t.Errorf("tcp expanded to %v, want one", got)
	}
}

// --- reconciler ------------------------------------------------------------

func TestReconcileAppliesAndVerifies(t *testing.T) {
	fw := NewFakeFirewall()
	src := &StaticRules{}
	src.Set(rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade))
	rec := NewReconciler(fw, src)

	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := fw.LastApplied(); len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("applied %v, want the single rule", got)
	}
	st := rec.Status()
	if st.Err != nil {
		t.Errorf("status carries an error: %v", st.Err)
	}
	if !st.InKernel(1) {
		t.Error("forward 1 not reported present in the kernel")
	}
	if st.At.IsZero() {
		t.Error("reconcile time was not recorded")
	}
}

// A rule that the kernel silently did not install must not be reported live.
func TestReconcileReportsMissingKernelRule(t *testing.T) {
	fw := NewFakeFirewall()
	src := &StaticRules{}
	src.Set(
		rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade),
		rule(2, ProtoTCP, 444, "10.10.0.3", 8444, SrcModeMasquerade),
	)
	fw.DropFromKernel[2] = true
	rec := NewReconciler(fw, src)

	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := rec.Status()
	if !st.InKernel(1) {
		t.Error("forward 1 should be present")
	}
	if st.InKernel(2) {
		t.Error("forward 2 is absent from the kernel but reported as present")
	}
}

func TestReconcileSurfacesApplyFailure(t *testing.T) {
	fw := NewFakeFirewall()
	fw.ApplyErr = errors.New("netlink refused")
	// A rule is needed for Apply to be attempted at all: an empty desired set
	// against an empty kernel is already reconciled, so nothing is written.
	src := &StaticRules{}
	src.Set(rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade))
	rec := NewReconciler(fw, src)

	if err := rec.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile swallowed an apply failure")
	}
	if rec.Status().Err == nil {
		t.Error("status does not carry the failure")
	}
}

func TestReconcileSurfacesSourceFailure(t *testing.T) {
	fw := NewFakeFirewall()
	src := &StaticRules{Err: errors.New("database is gone")}
	rec := NewReconciler(fw, src)

	if err := rec.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile swallowed a database failure")
	}
	if fw.ApplyCalls != 0 {
		t.Error("the kernel was written from a failed database read")
	}
}

// Status must hand out a copy; a caller mutating it must not corrupt the
// reconciler's own view.
func TestStatusIsACopy(t *testing.T) {
	fw := NewFakeFirewall()
	src := &StaticRules{}
	src.Set(rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade))
	rec := NewReconciler(fw, src)
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	st := rec.Status()
	delete(st.Present, 1)
	if !rec.Status().InKernel(1) {
		t.Error("mutating a returned Status changed the reconciler's state")
	}
}

// Disabling every forward must clear the kernel, not leave the last ruleset.
func TestReconcileWithNoRulesClearsKernel(t *testing.T) {
	fw := NewFakeFirewall()
	src := &StaticRules{}
	src.Set(rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade))
	rec := NewReconciler(fw, src)
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	src.Set()
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := fw.LastApplied(); len(got) != 0 {
		t.Errorf("kernel still holds %d rules after every forward was removed", len(got))
	}
	if rec.Status().InKernel(1) {
		t.Error("a removed forward is still reported as present")
	}
}

// --- ip forwarding ---------------------------------------------------------

func TestEnableIPForwarding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ip_forward")
	orig := ipForwardPath
	ipForwardPath = path
	t.Cleanup(func() { ipForwardPath = orig })

	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := EnableIPForwarding()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("changed = false when forwarding was off")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "1\n" {
		t.Errorf("wrote %q, want \"1\\n\"", got)
	}

	// Already on: no write, no change reported.
	changed, err = EnableIPForwarding()
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("changed = true when forwarding was already on")
	}
}

func TestEnableIPForwardingReportsMissingSysctl(t *testing.T) {
	orig := ipForwardPath
	ipForwardPath = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { ipForwardPath = orig })

	if _, err := EnableIPForwarding(); err == nil {
		t.Error("a missing sysctl was not reported")
	}
}

// --- counter preservation and statistics ------------------------------------

// The bug this guards against: Apply rebuilds the table from scratch, which
// resets every packet counter. An unconditional rebuild on the 60s timer would
// therefore zero the connection statistics on every tick, and the 7-day and
// all-time figures would never accumulate past one interval.
func TestReconcileDoesNotRebuildWhenNothingChanged(t *testing.T) {
	fw := NewFakeFirewall()
	src := &StaticRules{}
	src.Set(rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade))
	rec := NewReconciler(fw, src)

	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fw.ApplyCalls != 1 {
		t.Fatalf("first reconcile made %d applies, want 1", fw.ApplyCalls)
	}

	for i := 0; i < 5; i++ {
		if err := rec.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if fw.ApplyCalls != 1 {
		t.Errorf("%d applies after five no-op reconciles, want 1; counters would be reset each time",
			fw.ApplyCalls)
	}
}

// Drift must still be corrected: if our table is flushed by hand, the next
// reconcile has to rebuild it.
func TestReconcileRebuildsAfterDrift(t *testing.T) {
	fw := NewFakeFirewall()
	src := &StaticRules{}
	src.Set(rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade))
	rec := NewReconciler(fw, src)

	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fw.Teardown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fw.ApplyCalls != 2 {
		t.Errorf("applies = %d, want a rebuild after the table was flushed", fw.ApplyCalls)
	}
	if !rec.Status().InKernel(1) {
		t.Error("the forward was not restored")
	}
}

// A changed ruleset must rebuild.
func TestReconcileRebuildsWhenRulesChange(t *testing.T) {
	fw := NewFakeFirewall()
	src := &StaticRules{}
	src.Set(rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade))
	rec := NewReconciler(fw, src)
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	src.Set(rule(1, ProtoTCP, 443, "10.10.0.2", 9999, SrcModeMasquerade))
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fw.ApplyCalls != 2 {
		t.Errorf("applies = %d, want a rebuild after the target port changed", fw.ApplyCalls)
	}
}

// countingSink records what the reconciler emits.
type countingSink struct {
	calls  int
	deltas []map[int64]Counters
}

func (s *countingSink) RecordForwardStats(_ context.Context, _ time.Time, d map[int64]Counters) error {
	s.calls++
	copied := map[int64]Counters{}
	for k, v := range d {
		copied[k] = v
	}
	s.deltas = append(s.deltas, copied)
	return nil
}

// Counters are cumulative in the kernel; the sink must receive per-interval
// deltas, not the running totals.
func TestStatsAreEmittedAsDeltas(t *testing.T) {
	fw := NewFakeFirewall()
	src := &StaticRules{}
	src.Set(rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade))
	sink := &countingSink{}
	rec := NewReconciler(fw, src).WithSink(sink)

	fw.SetCounters(1, Counters{Accepted: 10, Dropped: 2, Bytes: 1000})
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fw.SetCounters(1, Counters{Accepted: 25, Dropped: 3, Bytes: 4000})
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	if sink.calls != 2 {
		t.Fatalf("sink called %d times, want 2", sink.calls)
	}
	first, second := sink.deltas[0][1], sink.deltas[1][1]
	if first.Accepted != 10 || first.Dropped != 2 {
		t.Errorf("first delta = %+v, want the initial reading", first)
	}
	if second.Accepted != 15 || second.Dropped != 1 || second.Bytes != 3000 {
		t.Errorf("second delta = %+v, want the difference (15 accepted, 1 dropped, 3000 bytes)", second)
	}
}

// When the ruleset is rebuilt the kernel counters restart at zero. Subtracting
// the old baseline would underflow to an astronomically large unsigned number,
// so a decrease has to be treated as a reset.
func TestCounterResetIsNotAnUnderflow(t *testing.T) {
	fw := NewFakeFirewall()
	src := &StaticRules{}
	src.Set(rule(1, ProtoTCP, 443, "10.10.0.2", 8443, SrcModeMasquerade))
	sink := &countingSink{}
	rec := NewReconciler(fw, src).WithSink(sink)

	fw.SetCounters(1, Counters{Accepted: 5000, Bytes: 900000})
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The rules are rebuilt and the counters restart low.
	fw.SetCounters(1, Counters{Accepted: 7, Bytes: 400})
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	last := sink.deltas[len(sink.deltas)-1][1]
	if last.Accepted != 7 || last.Bytes != 400 {
		t.Errorf("delta after a counter reset = %+v, want the post-reset values", last)
	}
	if last.Accepted > 1<<40 {
		t.Error("the delta underflowed")
	}
}
