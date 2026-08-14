package diag

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// The whole point of a closed command set is that a target field cannot become
// a command. Nothing here reaches a shell, but the validator is the layer that
// makes that obvious rather than incidental.
func TestValidateTargetRejectsShellish(t *testing.T) {
	bad := []string{
		"", "   ",
		"example.com; rm -rf /",
		"$(whoami)",
		"`id`",
		"example.com && curl evil",
		"a|b",
		"host name",
		"host\nname",
		".leading",
		"trailing.",
		"double..dot",
		strings.Repeat("a", 300),
	}
	for _, s := range bad {
		if _, err := ValidateTarget(s); err == nil {
			t.Errorf("ValidateTarget(%q) was accepted", s)
		} else if !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("ValidateTarget(%q) = %v, want ErrInvalidTarget", s, err)
		}
	}
}

func TestValidateTargetAcceptsRealTargets(t *testing.T) {
	good := []string{
		"10.10.0.3", "192.168.1.1", "1.1.1.1",
		"example.com", "sub.example.co.uk", "my-router", "host_name",
		"2606:4700:4700::1111",
	}
	for _, s := range good {
		if _, err := ValidateTarget(s); err != nil {
			t.Errorf("ValidateTarget(%q) = %v, want accepted", s, err)
		}
	}
}

func TestValidateTargetTrims(t *testing.T) {
	got, err := ValidateTarget("  10.10.0.3  ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.10.0.3" {
		t.Errorf("got %q, want the trimmed address", got)
	}
}

func TestToolValidity(t *testing.T) {
	for _, tool := range []Tool{ToolPing, ToolTraceroute, ToolDNS, ToolTCP} {
		if !tool.Valid() {
			t.Errorf("%q should be valid", tool)
		}
		if tool.Label() == "" {
			t.Errorf("%q has no label", tool)
		}
	}
	for _, tool := range []Tool{"", "shell", "bash", "exec"} {
		if Tool(tool).Valid() {
			t.Errorf("%q should not be a valid tool", tool)
		}
	}
}

func TestRunRejectsUnknownTool(t *testing.T) {
	_, err := Run(context.Background(), Request{Tool: "shell", Target: "127.0.0.1"})
	if err == nil {
		t.Fatal("an unknown tool was executed")
	}
}

func TestRunRejectsBadTargetBeforeAnyNetwork(t *testing.T) {
	_, err := Run(context.Background(), Request{Tool: ToolPing, Target: "; rm -rf /"})
	if !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("err = %v, want ErrInvalidTarget", err)
	}
}

// A TCP check against a port nothing is listening on must report "closed"
// distinctly from a filtered port: they mean very different things when
// debugging a port forward.
func TestTCPCheckReportsRefused(t *testing.T) {
	res, err := Run(context.Background(), Request{Tool: ToolTCP, Target: "127.0.0.1", Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Error("port 1 on localhost reported open")
	}
	if !strings.Contains(res.Summary, "closed") {
		t.Errorf("summary = %q, want it to say closed", res.Summary)
	}
}

func TestTCPCheckReportsOpen(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	res, err := Run(context.Background(), Request{Tool: ToolTCP, Target: "127.0.0.1", Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Summary != "open" {
		t.Errorf("res = %+v, want open", res)
	}
}

func TestTCPCheckRequiresPort(t *testing.T) {
	if _, err := Run(context.Background(), Request{Tool: ToolTCP, Target: "127.0.0.1"}); err == nil {
		t.Error("a TCP check without a port was accepted")
	}
}

// Ping against loopback needs no privilege on a host where unprivileged ICMP
// is permitted; where it is not, the error must say so rather than hang.
func TestPingLoopback(t *testing.T) {
	res, err := Run(context.Background(), Request{Tool: ToolPing, Target: "127.0.0.1", Count: 2})
	if err != nil {
		if strings.Contains(err.Error(), "ICMP socket") {
			t.Skipf("no ICMP socket available in this environment: %v", err)
		}
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("loopback ping failed: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Lines, "\n"), "ping statistics") {
		t.Error("no summary block in the output")
	}
}

// The count is clamped, so a hand-crafted request cannot turn one click into
// an unbounded packet stream.
func TestPingCountIsClamped(t *testing.T) {
	res, err := Run(context.Background(), Request{Tool: ToolPing, Target: "127.0.0.1", Count: 10000})
	if err != nil {
		if strings.Contains(err.Error(), "ICMP socket") {
			t.Skip("no ICMP socket available")
		}
		t.Fatal(err)
	}
	replies := 0
	for _, l := range res.Lines {
		if strings.Contains(l, "icmp_seq=") {
			replies++
		}
	}
	if replies > MaxCount {
		t.Errorf("%d probes sent, want at most %d", replies, MaxCount)
	}
}
