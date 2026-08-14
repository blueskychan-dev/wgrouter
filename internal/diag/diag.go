// Package diag implements the router's diagnostics console: a fixed set of
// network probes an administrator can run against a target they type in.
//
// The command set is closed and every tool is implemented in Go against
// sockets. Nothing here builds a command line, so a target field containing
// shell metacharacters is just a hostname that fails to resolve rather than a
// remote code execution. That is the entire reason this is a diagnostics
// console and not a terminal.
package diag

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Tool identifies a probe.
type Tool string

const (
	ToolPing       Tool = "ping"
	ToolTraceroute Tool = "traceroute"
	ToolDNS        Tool = "dns"
	ToolTCP        Tool = "tcp"
)

// Valid reports whether t is a tool we implement.
func (t Tool) Valid() bool {
	switch t {
	case ToolPing, ToolTraceroute, ToolDNS, ToolTCP:
		return true
	}
	return false
}

// Label renders a tool for the UI.
func (t Tool) Label() string {
	switch t {
	case ToolPing:
		return "Ping"
	case ToolTraceroute:
		return "Traceroute"
	case ToolDNS:
		return "DNS lookup"
	case ToolTCP:
		return "TCP port check"
	default:
		return string(t)
	}
}

// Bounds on every probe. These are not tuning knobs: they cap how long one
// admin request can hold a goroutine and how much traffic a single click can
// generate.
const (
	MaxCount     = 10
	DefaultCount = 4
	MaxHops      = 20
	DefaultHops  = 15
	probeTimeout = 2 * time.Second
	// TotalTimeout bounds a whole run, so a traceroute into a black hole
	// cannot pin a request open for hops * timeout.
	TotalTimeout = 30 * time.Second
)

// Request is a validated probe request.
type Request struct {
	Tool   Tool
	Target string
	Port   uint16 // ToolTCP only
	Count  int    // ToolPing only
}

// Result is what the console renders.
type Result struct {
	Lines   []string
	Summary string
	OK      bool
}

// ErrInvalidTarget is returned for a target that is neither an IP address nor a
// plausible hostname.
var ErrInvalidTarget = errors.New("target must be an IP address or hostname")

// ValidateTarget checks a user-supplied target.
//
// This is deliberately strict. The target never reaches a shell, but it does
// reach a resolver and a socket, and a tight character set means a typo fails
// here with a clear message rather than three seconds later in a DNS timeout.
func ValidateTarget(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ErrInvalidTarget
	}
	if len(s) > 253 {
		return "", fmt.Errorf("%w: too long", ErrInvalidTarget)
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return s, nil
	}
	// Hostname: letters, digits, dot and dash, with no empty labels.
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_'
		if !ok {
			return "", fmt.Errorf("%w: %q is not allowed in a hostname", ErrInvalidTarget, string(r))
		}
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return "", fmt.Errorf("%w: malformed hostname", ErrInvalidTarget)
	}
	return s, nil
}

// Run executes a probe.
func Run(ctx context.Context, req Request) (Result, error) {
	if !req.Tool.Valid() {
		return Result{}, fmt.Errorf("diag: unknown tool %q", req.Tool)
	}
	target, err := ValidateTarget(req.Target)
	if err != nil {
		return Result{}, err
	}
	req.Target = target

	ctx, cancel := context.WithTimeout(ctx, TotalTimeout)
	defer cancel()

	switch req.Tool {
	case ToolPing:
		return ping(ctx, req)
	case ToolTraceroute:
		return traceroute(ctx, req)
	case ToolDNS:
		return lookup(ctx, req)
	case ToolTCP:
		return tcpCheck(ctx, req)
	}
	return Result{}, fmt.Errorf("diag: unhandled tool %q", req.Tool)
}

// resolve4 resolves a target to a single IPv4 address.
func resolve4(ctx context.Context, target string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(target); err == nil {
		a = a.Unmap()
		if !a.Is4() {
			return netip.Addr{}, fmt.Errorf("diag: %s is IPv6; only IPv4 is supported", a)
		}
		return a, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", target)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("diag: resolve %s: %w", target, err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("diag: %s has no IPv4 address", target)
	}
	return addrs[0].Unmap(), nil
}

// listenICMP opens an ICMP socket.
//
// The unprivileged datagram socket is tried first: on Linux, when
// net/ipv4/ping_group_range covers our gid, this needs no capability at all.
// The raw socket is the fallback, and needs CAP_NET_RAW -- which wgrouter does
// not otherwise hold, so a system with a restrictive ping_group_range gets a
// clear error rather than a silent failure.
func listenICMP() (*icmp.PacketConn, error) {
	if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		return c, nil
	}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("diag: open ICMP socket (unprivileged ICMP is unavailable and a raw socket needs CAP_NET_RAW): %w", err)
	}
	return c, nil
}

func ping(ctx context.Context, req Request) (Result, error) {
	count := req.Count
	if count <= 0 {
		count = DefaultCount
	}
	if count > MaxCount {
		count = MaxCount
	}

	dst, err := resolve4(ctx, req.Target)
	if err != nil {
		return Result{}, err
	}

	conn, err := listenICMP()
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()

	res := Result{Lines: []string{fmt.Sprintf("PING %s (%s) 56 bytes of data.", req.Target, dst)}}
	id := os.Getpid() & 0xffff

	var sent, received int
	var totalRTT, minRTT, maxRTT time.Duration

	for seq := 1; seq <= count; seq++ {
		if ctx.Err() != nil {
			break
		}
		rtt, err := pingOnce(ctx, conn, dst, id, seq)
		sent++
		if err != nil {
			res.Lines = append(res.Lines, fmt.Sprintf("Request timeout for icmp_seq=%d", seq))
		} else {
			received++
			totalRTT += rtt
			if minRTT == 0 || rtt < minRTT {
				minRTT = rtt
			}
			if rtt > maxRTT {
				maxRTT = rtt
			}
			res.Lines = append(res.Lines,
				fmt.Sprintf("64 bytes from %s: icmp_seq=%d time=%.1f ms", dst, seq, float64(rtt.Microseconds())/1000))
		}
		// Space out probes the way ping does, but skip the wait after the last.
		if seq < count {
			select {
			case <-ctx.Done():
			case <-time.After(500 * time.Millisecond):
			}
		}
	}

	loss := 100.0
	if sent > 0 {
		loss = float64(sent-received) / float64(sent) * 100
	}
	res.Lines = append(res.Lines, "", fmt.Sprintf("--- %s ping statistics ---", req.Target))
	res.Lines = append(res.Lines,
		fmt.Sprintf("%d packets transmitted, %d received, %.0f%% packet loss", sent, received, loss))
	if received > 0 {
		avg := totalRTT / time.Duration(received)
		res.Lines = append(res.Lines, fmt.Sprintf("rtt min/avg/max = %.1f/%.1f/%.1f ms",
			float64(minRTT.Microseconds())/1000,
			float64(avg.Microseconds())/1000,
			float64(maxRTT.Microseconds())/1000))
		res.Summary = fmt.Sprintf("%d/%d replies, %.0f%% loss", received, sent, loss)
		res.OK = true
	} else {
		res.Summary = "no reply"
	}
	return res, nil
}

// pingOnce sends one echo request and waits for its reply.
func pingOnce(ctx context.Context, conn *icmp.PacketConn, dst netip.Addr, id, seq int) (time.Duration, error) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("wgrouter-diagnostics")},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}

	deadline := time.Now().Add(probeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, err
	}

	start := time.Now()
	if _, err := conn.WriteTo(wire, &net.UDPAddr{IP: dst.AsSlice()}); err != nil {
		return 0, err
	}

	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		parsed, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
		if err != nil {
			continue
		}
		echo, ok := parsed.Body.(*icmp.Echo)
		if !ok || parsed.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		// The kernel rewrites the ID on unprivileged sockets, so only the
		// sequence number is a reliable match.
		if echo.Seq != seq {
			continue
		}
		return time.Since(start), nil
	}
}

func traceroute(ctx context.Context, req Request) (Result, error) {
	maxHops := DefaultHops
	if maxHops > MaxHops {
		maxHops = MaxHops
	}

	dst, err := resolve4(ctx, req.Target)
	if err != nil {
		return Result{}, err
	}

	conn, err := listenICMP()
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()

	pc := conn.IPv4PacketConn()
	if pc == nil {
		return Result{}, fmt.Errorf("diag: traceroute needs an IPv4 packet connection")
	}

	res := Result{Lines: []string{
		fmt.Sprintf("traceroute to %s (%s), %d hops max", req.Target, dst, maxHops),
	}}

	for ttl := 1; ttl <= maxHops; ttl++ {
		if ctx.Err() != nil {
			res.Lines = append(res.Lines, "(timed out)")
			break
		}
		if err := pc.SetTTL(ttl); err != nil {
			return Result{}, fmt.Errorf("diag: set TTL: %w", err)
		}
		hop, rtt, done, err := traceOnce(ctx, conn, dst, ttl)
		switch {
		case err != nil:
			res.Lines = append(res.Lines, fmt.Sprintf("%2d  *", ttl))
		default:
			res.Lines = append(res.Lines,
				fmt.Sprintf("%2d  %-15s  %.1f ms", ttl, hop, float64(rtt.Microseconds())/1000))
		}
		if done {
			res.OK = true
			res.Summary = fmt.Sprintf("reached %s in %d hops", dst, ttl)
			return res, nil
		}
	}
	res.Summary = fmt.Sprintf("did not reach %s within %d hops", dst, maxHops)
	return res, nil
}

// traceOnce sends one TTL-limited probe and reports which router answered.
func traceOnce(ctx context.Context, conn *icmp.PacketConn, dst netip.Addr, seq int) (string, time.Duration, bool, error) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: seq, Data: []byte("wgrouter-traceroute")},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return "", 0, false, err
	}

	deadline := time.Now().Add(probeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return "", 0, false, err
	}

	start := time.Now()
	if _, err := conn.WriteTo(wire, &net.UDPAddr{IP: dst.AsSlice()}); err != nil {
		return "", 0, false, err
	}

	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return "", 0, false, err
		}
		parsed, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
		if err != nil {
			continue
		}
		from := peerAddr(peer)
		switch parsed.Type {
		case ipv4.ICMPTypeTimeExceeded:
			// An intermediate router. Its address is what we want; the body
			// carries our original packet, which we do not need to inspect
			// because the sequence is implied by which probe is outstanding.
			return from, time.Since(start), false, nil
		case ipv4.ICMPTypeEchoReply:
			return from, time.Since(start), true, nil
		}
	}
}

func peerAddr(a net.Addr) string {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP.String()
	case *net.IPAddr:
		return v.IP.String()
	default:
		return a.String()
	}
}

func lookup(ctx context.Context, req Request) (Result, error) {
	res := Result{Lines: []string{fmt.Sprintf("Resolving %s", req.Target)}}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", req.Target)
	if err != nil {
		res.Lines = append(res.Lines, err.Error())
		res.Summary = "lookup failed"
		return res, nil
	}
	for _, a := range addrs {
		kind := "A"
		if a.Is6() && !a.Is4In6() {
			kind = "AAAA"
		}
		res.Lines = append(res.Lines, fmt.Sprintf("  %-6s %s", kind, a.Unmap()))
	}

	// Reverse lookup for the first address is often the useful half.
	if len(addrs) > 0 {
		if names, err := net.DefaultResolver.LookupAddr(ctx, addrs[0].Unmap().String()); err == nil && len(names) > 0 {
			res.Lines = append(res.Lines, "", "Reverse:")
			for _, n := range names {
				res.Lines = append(res.Lines, "  "+strings.TrimSuffix(n, "."))
			}
		}
	}
	res.OK = true
	res.Summary = fmt.Sprintf("%d address(es)", len(addrs))
	return res, nil
}

func tcpCheck(ctx context.Context, req Request) (Result, error) {
	if req.Port == 0 {
		return Result{}, fmt.Errorf("diag: a port is required for a TCP check")
	}
	dst, err := resolve4(ctx, req.Target)
	if err != nil {
		return Result{}, err
	}
	addr := net.JoinHostPort(dst.String(), fmt.Sprint(req.Port))

	res := Result{Lines: []string{fmt.Sprintf("Connecting to %s", addr)}}
	start := time.Now()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		res.Lines = append(res.Lines, "  "+err.Error())
		// A refusal and a timeout mean very different things: refused proves
		// something answered and nothing is listening; a timeout usually means
		// a firewall silently dropped it.
		if strings.Contains(err.Error(), "refused") {
			res.Summary = "closed (connection refused)"
		} else {
			res.Summary = "filtered or unreachable (no response)"
		}
		return res, nil
	}
	_ = conn.Close()

	rtt := time.Since(start)
	res.Lines = append(res.Lines, fmt.Sprintf("  open — connected in %.1f ms", float64(rtt.Microseconds())/1000))
	res.OK = true
	res.Summary = "open"
	return res, nil
}
