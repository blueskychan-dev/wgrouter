package fwlog

import (
	"testing"
	"time"

	"wgrouter/internal/forward"
)

func TestParse(t *testing.T) {
	now := time.Now()

	line := `4,123,456789,-;wgrouter-drop 7:ratelimit IN=enp0s6 OUT=wg0 MAC=00:11 SRC=203.0.113.9 DST=10.10.0.2 LEN=60 PROTO=TCP SPT=54321 DPT=80 WINDOW=64240`
	ev, ok := Parse(line, now)
	if !ok {
		t.Fatal("a well-formed line was not matched")
	}
	if ev.SrcIP != "203.0.113.9" || ev.SrcPort != 54321 {
		t.Errorf("source = %s:%d", ev.SrcIP, ev.SrcPort)
	}
	if ev.DstIP != "10.10.0.2" || ev.DstPort != 80 {
		t.Errorf("destination = %s:%d", ev.DstIP, ev.DstPort)
	}
	if ev.Proto != "tcp" {
		t.Errorf("proto = %q, want lowercased tcp", ev.Proto)
	}
	if ev.ForwardID != 7 {
		t.Errorf("forward id = %d, want 7", ev.ForwardID)
	}
	if ev.Reason != "ratelimit" {
		t.Errorf("reason = %q", ev.Reason)
	}
}

func TestParseACLReason(t *testing.T) {
	line := `4,1,1,-;wgrouter-drop 3:acl IN=eth0 OUT=wg0 SRC=198.51.100.7 DST=10.10.0.3 PROTO=UDP SPT=1 DPT=53`
	ev, ok := Parse(line, time.Now())
	if !ok {
		t.Fatal("not matched")
	}
	if ev.Reason != "acl" || ev.ForwardID != 3 || ev.Proto != "udp" {
		t.Errorf("event = %+v", ev)
	}
}

// The kernel log carries everything on the system. Only our own lines are ours.
func TestParseIgnoresOtherKernelMessages(t *testing.T) {
	for _, line := range []string{
		`6,100,200,-;usb 1-1: new high-speed USB device`,
		`4,101,201,-;IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP`, // someone else's netfilter log
		`4,102,202,-;other-prefix SRC=1.2.3.4`,
		``,
		`malformed`,
	} {
		if _, ok := Parse(line, time.Now()); ok {
			t.Errorf("Parse(%q) claimed a line that is not ours", line)
		}
	}
}

// A line with our prefix but no source is a format change, not an event. Storing
// it would fill the log with blank rows that look like a firewall bug.
func TestParseRejectsLineWithoutSource(t *testing.T) {
	if _, ok := Parse(`4,1,1,-;wgrouter-drop 1:acl IN=eth0 OUT=wg0 PROTO=TCP`, time.Now()); ok {
		t.Error("a line with no SRC was accepted")
	}
}

// A record with no ";" separator still parses, since the format is not
// guaranteed across kernel versions.
func TestParseWithoutRecordHeader(t *testing.T) {
	if _, ok := Parse(`wgrouter-drop 1:acl SRC=203.0.113.9 DST=10.10.0.2 PROTO=TCP SPT=1 DPT=2`, time.Now()); !ok {
		t.Error("a bare message line was not matched")
	}
}

// The prefix here and the one the rule builder writes must agree, or nothing is
// ever matched and the firewall log stays silently empty.
func TestPrefixMatchesRuleBuilder(t *testing.T) {
	if Prefix != forward.LogPrefix {
		t.Errorf("Prefix = %q but the rule builder writes %q; the log would never match",
			Prefix, forward.LogPrefix)
	}
}
