package store

import (
	"context"
	"testing"
	"time"
)

func TestLogSettingsRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Defaults: the user log records everything, the firewall log is off.
	ls, err := st.LoadLogSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ls.UserEnabled {
		t.Error("the user log defaults to disabled; it should default to on")
	}
	if ls.FirewallEnabled {
		t.Error("the firewall log defaults to on; it should be opt-in")
	}
	if len(ls.UserActions) != 0 {
		t.Error("a filter is set by default")
	}

	ls.UserActions = []string{ActionLogin, ActionPeerCreate}
	ls.FirewallEnabled = true
	if err := st.SaveLogSettings(ctx, ls); err != nil {
		t.Fatal(err)
	}

	got, err := st.LoadLogSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !got.FirewallEnabled || len(got.UserActions) != 2 {
		t.Errorf("round trip lost settings: %+v", got)
	}
}

// The filter must never be able to hide a failed sign-in or a password change.
// A security log that can be quietly switched off for exactly those events is
// worse than none, because it still looks authoritative.
func TestSecurityEventsCannotBeFilteredOut(t *testing.T) {
	ls := LogSettings{UserEnabled: false, UserActions: nil}

	for _, action := range []string{ActionLoginFailed, ActionPasswordChange, ActionSetupComplete, ActionLogSettings} {
		if !ls.ShouldAudit(action) {
			t.Errorf("%q was suppressed with logging disabled", action)
		}
	}
	// Everything else honours the switch.
	for _, action := range []string{ActionLogin, ActionPeerCreate, ActionFwdDelete} {
		if ls.ShouldAudit(action) {
			t.Errorf("%q was recorded with logging disabled", action)
		}
	}
}

func TestShouldAuditHonoursFilter(t *testing.T) {
	ls := LogSettings{UserEnabled: true, UserActions: []string{ActionPeerCreate}}

	if !ls.ShouldAudit(ActionPeerCreate) {
		t.Error("a selected action was not recorded")
	}
	if ls.ShouldAudit(ActionPeerDelete) {
		t.Error("an unselected action was recorded")
	}

	// An empty filter means everything, not nothing -- the opposite reading
	// would silently stop recording the moment a filter was cleared.
	all := LogSettings{UserEnabled: true}
	if !all.ShouldAudit(ActionPeerDelete) {
		t.Error("an empty filter suppressed an action")
	}
}

func TestFirewallLogRoundTripAndClear(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	now := time.Now()
	events := []FirewallEvent{
		{At: now, Reason: "ratelimit", ForwardID: 1, SrcIP: "203.0.113.9", SrcPort: 5555, DstIP: "10.10.0.2", DstPort: 80, Proto: "tcp"},
		{At: now, Reason: "acl", ForwardID: 2, SrcIP: "198.51.100.7", DstIP: "10.10.0.3", DstPort: 443, Proto: "tcp"},
	}
	if err := st.RecordFirewallEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	got, err := st.FirewallLog(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
	if got[0].SrcIP == "" || got[0].Reason == "" {
		t.Errorf("event lost data: %+v", got[0])
	}

	n, err := st.ClearFirewallLog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("cleared %d rows, want 2", n)
	}
	if got, _ := st.FirewallLog(ctx, 100); len(got) != 0 {
		t.Error("the log was not emptied")
	}
}

// An empty batch must not open a transaction: the reader calls this on every
// tick whether or not anything was dropped.
func TestRecordFirewallEventsIgnoresEmpty(t *testing.T) {
	st := testStore(t)
	if err := st.RecordFirewallEvents(context.Background(), nil); err != nil {
		t.Errorf("an empty batch errored: %v", err)
	}
}
