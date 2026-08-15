// Package device turns a stored peer into something a client can import: a
// WireGuard configuration file and the QR code that encodes it.
//
// The client's private key never reaches this package's persistent side. It is
// generated, rendered into exactly one config, shown once, and discarded. A
// router that can hand out a working config on demand is a router where
// compromising the admin panel compromises every device that ever connected;
// wgrouter deliberately cannot do that.
package device

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"text/template"

	qrcode "github.com/skip2/go-qrcode"
)

// FullTunnel is the AllowedIPs value direct mode requires.
//
// It is a crypto filter here, not a routing instruction -- the direct-mode
// template sets Table = off precisely so wg-quick does not read it as one.
const FullTunnel = "0.0.0.0/0"

// KeepaliveSeconds is written into every generated config.
//
// Without it a peer behind NAT goes silent when idle, its NAT mapping expires,
// and the router can no longer reach it -- which is precisely the situation
// port forwarding exists to avoid. 25s is the standard value: comfortably under
// the ~30s mapping timeout of the most aggressive consumer NATs.
const KeepaliveSeconds = 25

// Routing selects how the client installs routes for the tunnel.
type Routing string

const (
	// RoutingTunnelOnly routes only the tunnel pool. Correct for a peer that is
	// reached through masquerade forwards, and the default.
	RoutingTunnelOnly Routing = "tunnel"

	// RoutingDirect supports direct-mode port forwards.
	//
	// Direct mode delivers packets carrying the client's real source address,
	// so the peer's AllowedIPs must be 0.0.0.0/0 -- AllowedIPs is both the
	// outbound route selector and the inbound cryptokey filter, and anything
	// narrower makes WireGuard silently drop those packets.
	//
	// But 0.0.0.0/0 under wg-quick's default (Table = auto) also becomes a
	// default route, pushing all of the device's internet traffic onto a tunnel
	// that has no internet egress -- wgrouter never masquerades a peer's
	// outbound traffic. So this mode sets Table = off and installs source-based
	// policy routing instead: replies from the tunnel address leave through the
	// tunnel, and the system default route is untouched.
	RoutingDirect Routing = "direct"
)

// Valid reports whether r is a routing mode we render.
func (r Routing) Valid() bool {
	switch r {
	case RoutingTunnelOnly, RoutingDirect:
		return true
	}
	return false
}

// Default table and rule-priority values for direct-mode policy routing.
//
// Both are deliberately away from 51820, which is wg-quick's own auto-table
// base: another interface running Table = auto on the same host would claim it.
const (
	DefaultRouteTable   = 200
	DefaultRulePriority = 100
)

// Params is everything needed to render one client configuration.
type Params struct {
	// ClientPrivateKey is shown once and never stored.
	ClientPrivateKey string
	ClientAddress    netip.Addr

	ServerPublicKey string
	PresharedKey    string
	Endpoint        string // host:port
	AllowedIPs      string
	DNS             string // omitted when empty

	// Routing selects the template. Empty means RoutingTunnelOnly.
	Routing Routing

	// TunnelSubnet is the peer pool, needed by direct mode to route the tunnel
	// itself once wg-quick has been told to install nothing.
	TunnelSubnet string

	// RouteTable and RulePriority are the policy-routing identifiers. Zero
	// selects the defaults above.
	RouteTable   int
	RulePriority int
}

// configTemplate is written to look like a hand-written wg-quick file, because
// that is what the people importing it will compare it against.
//
// The direct-mode branch is deliberately verbose. Every line in it exists to
// stop a specific failure, and someone reading the file six months later has no
// other way to know which.
var configTemplate = template.Must(template.New("wg").Parse(
	`{{- if .Direct}}# WireGuard client configuration -- direct source-address mode.
#
# AllowedIPs must be 0.0.0.0/0: it is both the outbound route selector and the
# inbound cryptokey filter, and this peer receives packets carrying the real
# address of whoever connected. Anything narrower is silently dropped.
#
# Table = off stops wg-quick turning that into a default route. Without it the
# device would send all its internet traffic down a tunnel that has no internet
# egress. The hooks below add only the routes that are actually wanted: the
# tunnel subnet, plus a source-based rule so replies from {{.ClientAddress}}
# leave through the tunnel while the system default route stays on the LAN.
{{end}}[Interface]
PrivateKey = {{.ClientPrivateKey}}
Address = {{.Address}}
{{- if .DNS}}
DNS = {{.DNS}}
{{- end}}
{{- if .Direct}}
Table = off

# Reach other hosts inside the tunnel pool.
PostUp = ip route replace {{.TunnelSubnet}} dev %i

# Anything sourced from the tunnel address leaves via the tunnel. An inbound
# connection to {{.ClientAddress}} leaves the socket bound to that address, so
# every reply matches this rule whatever the client's real address is. No
# conntrack involved, so UDP and stateless traffic work too.
PostUp = ip route replace default dev %i table {{.RouteTable}}
PostUp = ip rule del from {{.ClientAddress}} lookup {{.RouteTable}} priority {{.RulePriority}} 2>/dev/null || true
PostUp = ip rule add from {{.ClientAddress}} lookup {{.RouteTable}} priority {{.RulePriority}}

# No routing loop: the encrypted packets to the endpoint are sourced from the
# LAN address, not {{.ClientAddress}}, so they miss the rule above and take the
# main table as normal.

# ---------------------------------------------------------------------------
# IF THE TUNNEL HANDSHAKES AND THEN PASSES NOTHING, START HERE.
#
# Reverse-path filtering is the most likely cause, and it fails silently.
# Packets arrive on %i carrying arbitrary real internet source addresses. Under
# strict rp_filter the kernel asks "would I route back to this source via %i?".
# The policy rule above is meant to make that answer yes -- the reverse lookup
# is done with the addresses swapped, so "from {{.ClientAddress}}" matches and
# resolves through table {{.RouteTable}} to %i -- but whether the reverse check
# consults ip rules at all has varied across kernel versions. When it does not,
# the main table answers "out the LAN interface", the packet is dropped, and
# nothing is logged.
#
# Check the effective value. It is max(all, %i), so read both:
#   sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.%i.rp_filter
# 1 is strict, 2 is loose, 0 is off. Many distributions ship
# net.ipv4.conf.default.rp_filter=1, which a newly created %i inherits.
#
# To relax it, uncomment these. Loose mode still drops packets from sources
# that are unroutable by any path, so it is a far smaller change than turning
# source validation off entirely -- do not use 0.
#PostUp = sysctl -w net.ipv4.conf.all.rp_filter=2
#PostUp = sysctl -w net.ipv4.conf.%i.rp_filter=2
#
# They are commented out because loosening source validation is a security
# decision about your machine, not something a generated file should make on
# your behalf.
# ---------------------------------------------------------------------------

# The "|| true" guards are mandatory. wg-quick runs with "set -e" and runs
# PreDown BEFORE deleting the interface, so one failing line aborts the
# whole teardown: the interface stays up, stale rules survive, and every
# later restart dies on "RTNETLINK answers: File exists".
PreDown = ip rule del from {{.ClientAddress}} lookup {{.RouteTable}} priority {{.RulePriority}} || true
PreDown = ip route del default dev %i table {{.RouteTable}} || true
PreDown = ip route del {{.TunnelSubnet}} dev %i || true
{{- end}}

[Peer]
PublicKey = {{.ServerPublicKey}}
{{- if .PresharedKey}}
PresharedKey = {{.PresharedKey}}
{{- end}}
Endpoint = {{.Endpoint}}
AllowedIPs = {{.AllowedIPs}}
PersistentKeepalive = {{.Keepalive}}
{{- if .Direct}}

# Verify:
#   ip rule show                                  -> {{.RulePriority}}: from {{.ClientAddress}} lookup {{.RouteTable}}
#   ip route get 1.1.1.1                          -> your LAN interface, internet unaffected
#   ip route get 1.1.1.1 from {{.ClientAddress}}  -> dev %i, replies use the tunnel
#   sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.%i.rp_filter
#
# A real test needs an out-of-pool client. "ss -tn" on this host should show
# that client's ACTUAL address, and the session should complete rather than
# hang after the handshake.
#
# Only one peer per interface can hold 0.0.0.0/0, since AllowedIPs doubles as
# the outbound selector. A second direct-mode uplink needs its own interface,
# route table and rule priority.
{{- end}}
`))

// Render produces the client configuration file.
func Render(p Params) (string, error) {
	if p.ClientPrivateKey == "" {
		return "", fmt.Errorf("device: client private key is required")
	}
	if p.ServerPublicKey == "" {
		return "", fmt.Errorf("device: server public key is required")
	}
	if p.Endpoint == "" {
		return "", fmt.Errorf("device: endpoint is required")
	}
	if !p.ClientAddress.IsValid() {
		return "", fmt.Errorf("device: client address is required")
	}
	allowed := p.AllowedIPs
	if allowed == "" {
		return "", fmt.Errorf("device: allowed IPs are required")
	}

	if p.Routing == "" {
		p.Routing = RoutingTunnelOnly
	}
	if !p.Routing.Valid() {
		return "", fmt.Errorf("device: unknown routing mode %q", p.Routing)
	}

	direct := p.Routing == RoutingDirect
	if direct {
		// Direct mode's whole reason to exist is that AllowedIPs is 0.0.0.0/0.
		// Rendering the policy-routing hooks around anything narrower would
		// produce a config that looks carefully built and still drops the
		// packets it was made for.
		if strings.TrimSpace(allowed) != FullTunnel {
			return "", fmt.Errorf("device: direct-mode routing requires AllowedIPs %s, got %q",
				FullTunnel, allowed)
		}
		if p.TunnelSubnet == "" {
			return "", fmt.Errorf("device: direct-mode routing needs the tunnel subnet")
		}
		if p.RouteTable == 0 {
			p.RouteTable = DefaultRouteTable
		}
		if p.RulePriority == 0 {
			p.RulePriority = DefaultRulePriority
		}
	}

	// The client's own address is always a /32. Anything wider would make the
	// client believe it owns a range of the tunnel that the router has not
	// allocated to it.
	data := struct {
		Params
		Address   string
		Keepalive int
		Direct    bool
	}{
		Params:    p,
		Direct:    direct,
		Address:   netip.PrefixFrom(p.ClientAddress, p.ClientAddress.BitLen()).String(),
		Keepalive: KeepaliveSeconds,
	}

	var buf bytes.Buffer
	if err := configTemplate.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("device: render config: %w", err)
	}
	return buf.String(), nil
}

// QRCode encodes a rendered config as a PNG.
//
// Size is bounded because the config is user-influenced only in length, but a
// long AllowedIPs list can still push the QR version high enough that phones
// struggle to scan it; failing loudly beats emitting an image nobody can read.
func QRCode(config string, size int) ([]byte, error) {
	if size < 128 {
		size = 128
	}
	if size > 1024 {
		size = 1024
	}
	png, err := qrcode.Encode(config, qrcode.Medium, size)
	if err != nil {
		return nil, fmt.Errorf("device: encode QR code (config may be too long to encode): %w", err)
	}
	return png, nil
}

// Filename returns a safe download filename for a device's config.
//
// wg-quick takes the interface name from the filename, and it must be a valid
// interface name: at most 15 characters, no path separators, no spaces. A
// device called "Ana's iPhone (work)" has to become something the client will
// accept, so everything outside a conservative set is replaced.
func Filename(deviceName string) string {
	var b strings.Builder
	for _, r := range deviceName {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	// Collapse runs of dashes left by stripped characters.
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	if name == "" {
		name = "wg-client"
	}
	if len(name) > 15 {
		name = strings.Trim(name[:15], "-")
	}
	return name + ".conf"
}
