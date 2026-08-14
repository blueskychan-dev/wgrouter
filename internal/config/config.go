// Package config loads wgrouter's runtime configuration from environment
// variables and command-line flags. There is deliberately no config-file
// format: everything is a flag with a WGROUTER_-prefixed env fallback.
//
// Precedence is flag > environment > default.
package config

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"wgrouter/internal/device"
)

// Defaults that are referenced from more than one place.
const (
	DefaultWGInterface  = "wg0"
	DefaultWGListenPort = 51820

	// DefaultForwardRateLimit caps new connections per second on each port
	// forward. 50/s with a burst of 100 is generous for anything a home or
	// small-office service actually receives, while still bounding a flood: a
	// SYN flood arrives at tens of thousands per second, so the limit bites
	// long before the peer behind the tunnel is overwhelmed.
	//
	// It is deliberately per forward rather than global, so one noisy service
	// cannot starve the others.
	DefaultForwardRateLimit = 50
	DefaultForwardBurst     = 100
	DefaultTunnelPool       = "10.10.0.0/24"
	DefaultAdminPort        = 8080
	DefaultDBPath           = "/var/lib/wgrouter/wgrouter.db"

	// OnlineWindow is how long after a handshake a peer is still considered
	// online. WireGuard is connectionless and reports no link state, so
	// "online" is always a derivation from the last handshake timestamp.
	// 180s is three keepalive-ish intervals: long enough not to flap, short
	// enough to be useful.
	OnlineWindow = 180 * time.Second
)

// Config is the fully-resolved runtime configuration. It is immutable after
// Load returns.
type Config struct {
	// WireGuard
	WGInterface  string       // interface we create and own
	WGListenPort int          // UDP port WireGuard listens on
	TunnelPool   netip.Prefix // pool we allocate peer addresses from
	ServerIP     netip.Addr   // our address inside the pool (always the first usable)

	// Client config generation
	PublicEndpoint   string // hostname:port peers dial. Required; no default.
	ClientDNS        string // optional; omitted from generated configs when empty
	ClientAllowedIPs string // AllowedIPs written into generated client configs

	// ClientRouteTable and ClientRulePriority are the policy-routing
	// identifiers written into a direct-mode client configuration.
	ClientRouteTable   int
	ClientRulePriority int

	// NoBanner suppresses the startup banner. It is only ever printed to an
	// interactive terminal anyway; this is for someone who finds it noisy.
	NoBanner bool

	// ForwardRateLimit caps new connections per second on each port forward,
	// and ForwardBurst how many may arrive at once first. Zero disables it.
	ForwardRateLimit uint64
	ForwardBurst     uint32

	// Networking
	WANInterface string // interface holding the default route

	// Admin HTTP listener
	ListenAddr string // host:port
	TLSCert    string // optional; enables HTTPS when both cert and key are set
	TLSKey     string

	// Storage
	DBPath string

	// Logging
	LogLevel slog.Level
}

// TLSEnabled reports whether the admin listener will serve HTTPS.
func (c *Config) TLSEnabled() bool { return c.TLSCert != "" && c.TLSKey != "" }

// ServerPrefix returns the server's own address as a host route inside the
// tunnel, which is what we assign to the WireGuard interface.
func (c *Config) ServerPrefix() netip.Prefix {
	return netip.PrefixFrom(c.ServerIP, c.ServerIP.BitLen())
}

// Load parses configuration from args (usually os.Args[1:]) and the
// environment. It returns a usage error suitable for printing when the
// configuration is invalid.
func Load(args []string) (*Config, error) {
	fs := flag.NewFlagSet("wgrouter", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "wgrouter — WireGuard router control panel\n\nUsage:\n  wgrouter [flags]\n\nEvery flag may also be set via its WGROUTER_ environment variable.\n\nFlags:\n")
		fs.PrintDefaults()
	}

	// Resolve the one integer environment default up front: a malformed value
	// must be a startup error, not a silent fallback that leaves the router
	// listening on a port nobody configured.
	wgPortDefault, err := envInt("WG_LISTEN_PORT", DefaultWGListenPort)
	if err != nil {
		return nil, err
	}
	tableDefault, err := envInt("CLIENT_ROUTE_TABLE", device.DefaultRouteTable)
	if err != nil {
		return nil, err
	}
	prioDefault, err := envInt("CLIENT_RULE_PRIORITY", device.DefaultRulePriority)
	if err != nil {
		return nil, err
	}
	rateDefault, err := envInt("FORWARD_RATE_LIMIT", DefaultForwardRateLimit)
	if err != nil {
		return nil, err
	}
	burstDefault, err := envInt("FORWARD_BURST", DefaultForwardBurst)
	if err != nil {
		return nil, err
	}

	var (
		wgIface     = fs.String("wg-interface", env("WG_INTERFACE", DefaultWGInterface), "WireGuard interface to create and manage")
		wgPort      = fs.Int("wg-listen-port", wgPortDefault, "UDP port for WireGuard to listen on")
		pool        = fs.String("tunnel-pool", env("TUNNEL_POOL", DefaultTunnelPool), "CIDR to allocate peer tunnel addresses from")
		endpoint    = fs.String("public-endpoint", env("PUBLIC_ENDPOINT", ""), "public host peers dial, e.g. vpn.example.com (required)")
		clientDNS   = fs.String("client-dns", env("CLIENT_DNS", ""), "DNS server written into generated client configs (omitted if empty)")
		clientAllow = fs.String("client-allowed-ips", env("CLIENT_ALLOWED_IPS", ""), "AllowedIPs for generated client configs (default: the tunnel pool)")
		wanIface    = fs.String("wan-interface", env("WAN_INTERFACE", ""), "interface facing the internet (default: autodetected from the default route)")
		listen      = fs.String("listen", env("LISTEN", ""), "admin UI listen address (default: the WireGuard interface IP)")
		tlsCert     = fs.String("tls-cert", env("TLS_CERT", ""), "PEM certificate for the admin UI; enables HTTPS with -tls-key")
		tlsKey      = fs.String("tls-key", env("TLS_KEY", ""), "PEM private key for the admin UI")
		dbPath      = fs.String("db", env("DB", DefaultDBPath), "path to the SQLite database")
		logLevel    = fs.String("log-level", env("LOG_LEVEL", "info"), "log level: debug, info, warn, error")
		routeTable  = fs.Int("client-route-table", tableDefault, "routing table id used by direct-mode client configs")
		rulePrio    = fs.Int("client-rule-priority", prioDefault, "ip-rule priority used by direct-mode client configs")
		noBanner    = fs.Bool("no-banner", env("NO_BANNER", "") != "", "suppress the startup banner even on a terminal")
		fwdRate     = fs.Int("forward-rate-limit", rateDefault, "max new connections per second per port forward; 0 disables rate limiting")
		fwdBurst    = fs.Int("forward-burst", burstDefault, "how many new connections may arrive at once before the rate limit applies")
	)

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected positional argument %q", fs.Arg(0))
	}

	cfg := &Config{
		WGInterface:      *wgIface,
		WGListenPort:     *wgPort,
		PublicEndpoint:   strings.TrimSpace(*endpoint),
		ClientDNS:        strings.TrimSpace(*clientDNS),
		ClientAllowedIPs: strings.TrimSpace(*clientAllow),
		WANInterface:     strings.TrimSpace(*wanIface),
		TLSCert:          *tlsCert,
		TLSKey:           *tlsKey,
		DBPath:           *dbPath,
		NoBanner:         *noBanner,
	}

	// Basic flood protection for the forwarded ports. Validated here because
	// these values become nftables rate-limit expressions, and a nonsensical
	// one would either be rejected by the kernel at reconcile time -- long
	// after the operator typed it -- or silently block all traffic.
	if *fwdRate < 0 || *fwdRate > 1_000_000 {
		return nil, fmt.Errorf("-forward-rate-limit %d: must be between 0 and 1000000", *fwdRate)
	}
	if *fwdBurst < 0 || *fwdBurst > 1_000_000 {
		return nil, fmt.Errorf("-forward-burst %d: must be between 0 and 1000000", *fwdBurst)
	}
	cfg.ForwardRateLimit = uint64(*fwdRate)
	cfg.ForwardBurst = uint32(*fwdBurst)

	// 51820 is wg-quick's own auto-table base. A direct-mode config that used
	// it would collide with any other interface on the client running
	// Table = auto, and the symptom would be routes vanishing at random.
	if *routeTable < 1 || *routeTable > 252 {
		return nil, fmt.Errorf("-client-route-table %d: must be between 1 and 252", *routeTable)
	}
	if *rulePrio < 1 || *rulePrio > 32765 {
		return nil, fmt.Errorf("-client-rule-priority %d: must be between 1 and 32765", *rulePrio)
	}
	cfg.ClientRouteTable = *routeTable
	cfg.ClientRulePriority = *rulePrio

	if err := cfg.applyInterface(*wgIface); err != nil {
		return nil, err
	}
	if err := cfg.applyPool(*pool); err != nil {
		return nil, err
	}
	if err := cfg.applyPort(*wgPort); err != nil {
		return nil, err
	}
	if err := cfg.applyEndpoint(); err != nil {
		return nil, err
	}
	if err := cfg.applyListen(*listen); err != nil {
		return nil, err
	}
	if err := cfg.applyLogLevel(*logLevel); err != nil {
		return nil, err
	}
	if cfg.ClientAllowedIPs == "" {
		cfg.ClientAllowedIPs = cfg.TunnelPool.String()
	}
	if cfg.WANInterface == "" {
		// Best-effort: a missing default route is not fatal at startup, because
		// nothing in this milestone needs the WAN interface yet and the operator
		// can always set it explicitly.
		if iface, err := DetectWANInterface(); err == nil {
			cfg.WANInterface = iface
		} else {
			cfg.WANInterface = "unknown"
			slog.Warn("could not detect the WAN interface", "error", err,
				"advice", "set -wan-interface explicitly if port forwarding does not work")
		}
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return nil, errors.New("-tls-cert and -tls-key must be set together")
	}
	if cfg.DBPath == "" {
		return nil, errors.New("-db must not be empty")
	}
	return cfg, nil
}

func (c *Config) applyInterface(name string) error {
	name = strings.TrimSpace(name)
	// Linux caps interface names at IFNAMSIZ-1 = 15 bytes. Reject early with a
	// clear message rather than letting netlink fail cryptically later.
	if name == "" || len(name) > 15 {
		return fmt.Errorf("-wg-interface %q: must be 1..15 characters", name)
	}
	if strings.ContainsAny(name, " /\t\n") {
		return fmt.Errorf("-wg-interface %q: must not contain spaces or slashes", name)
	}
	c.WGInterface = name
	return nil
}

func (c *Config) applyPort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("-wg-listen-port %d: must be in 1..65535", p)
	}
	c.WGListenPort = p
	return nil
}

func (c *Config) applyPool(s string) error {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("-tunnel-pool %q: %w", s, err)
	}
	p = p.Masked()
	if !p.Addr().Is4() {
		// IPv6 pools need different IPAM and a different nftables family; we
		// reject rather than half-support them.
		return fmt.Errorf("-tunnel-pool %q: only IPv4 pools are supported", s)
	}
	// Need room for the server plus at least one peer.
	if p.Bits() > 30 {
		return fmt.Errorf("-tunnel-pool %q: prefix too small, need /30 or larger", s)
	}
	// Reject ranges that cannot carry tunnel traffic. Allocating peers out of
	// 127.0.0.0/8 or 224.0.0.0/4 produces addresses that are accepted here and
	// then fail far away -- at route installation, or silently at the peer.
	if a := p.Addr(); a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() || a.IsLinkLocalUnicast() {
		return fmt.Errorf("-tunnel-pool %q: must be a routable unicast range, not loopback, multicast, link-local or unspecified", s)
	}
	c.TunnelPool = p
	// The server always takes the first usable address in the pool (.1 for a
	// /24). Peers are allocated from the next address up.
	c.ServerIP = p.Addr().Next()
	return nil
}

func (c *Config) applyEndpoint() error {
	if c.PublicEndpoint == "" {
		// Deliberately fatal with no default. On a NAT'd cloud instance the
		// public address is not present on any local interface, so guessing it
		// from the routing table produces configs that silently never connect.
		return errors.New("-public-endpoint is required: the host peers dial, e.g. vpn.example.com (no default; it cannot be detected from a NAT'd instance)")
	}
	if strings.ContainsAny(c.PublicEndpoint, " \t\n/") {
		return fmt.Errorf("-public-endpoint %q: must be a bare host or host:port", c.PublicEndpoint)
	}
	return nil
}

func (c *Config) applyListen(s string) error {
	if s == "" {
		// Default to the WireGuard interface IP, never 0.0.0.0: the admin panel
		// should be reachable only from inside the tunnel unless the operator
		// deliberately says otherwise.
		c.ListenAddr = netip.AddrPortFrom(c.ServerIP, DefaultAdminPort).String()
		return nil
	}

	// net.SplitHostPort rather than a hand-rolled split: it understands the
	// bracketed IPv6 form, and rejects a bare "2001:db8::1" instead of silently
	// reading the last hextet as a port number.
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("-listen %q: %w", s, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("-listen %q: bad port %q", s, portStr)
	}
	// Port 0 would bind an ephemeral port: the process starts, reports success,
	// and is then reachable on an address nobody can predict.
	if port < 1 || port > 65535 {
		return fmt.Errorf("-listen %q: port must be in 1..65535", s)
	}
	// An empty host means "every interface" and is allowed, but PublicListen
	// reports it so the operator gets a warning.
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil && !validHostname(host) {
			return fmt.Errorf("-listen %q: %q is neither an IP address nor a hostname", s, host)
		}
	}
	c.ListenAddr = s
	return nil
}

// validHostname applies a deliberately loose check: enough to catch a typo or a
// pasted URL, not so strict that it rejects a name the resolver would accept.
func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func (c *Config) applyLogLevel(s string) error {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		c.LogLevel = slog.LevelDebug
	case "info", "":
		c.LogLevel = slog.LevelInfo
	case "warn", "warning":
		c.LogLevel = slog.LevelWarn
	case "error":
		c.LogLevel = slog.LevelError
	default:
		return fmt.Errorf("-log-level %q: must be one of debug, info, warn, error", s)
	}
	return nil
}

// PublicListen reports whether the admin listener is bound somewhere other than
// the tunnel, which warrants a loud warning at startup.
//
// When the bind address is a hostname we cannot resolve it here without doing
// DNS at config time, so we assume the worst and warn. A spurious warning costs
// a line of log; a missed one means an admin panel is quietly exposed.
func (c *Config) PublicListen() bool {
	host, _, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return false
	}
	if host == "" {
		return true // ":8080" binds every interface
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return !strings.EqualFold(host, "localhost")
	}
	// Compare unmapped, so ::ffff:10.10.0.1 is recognised as the tunnel address
	// rather than warned about as some unrelated interface.
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return true
	}
	return addr != c.ServerIP.Unmap() && !addr.IsLoopback()
}

func env(key, def string) string {
	if v, ok := os.LookupEnv("WGROUTER_" + key); ok {
		return v
	}
	return def
}

// envInt reads an integer environment override. A malformed value is an error
// rather than a silent fall back to the default: a typo in a unit file should
// stop the service, not start it with settings the operator did not choose.
func envInt(key string, def int) (int, error) {
	v, ok := os.LookupEnv("WGROUTER_" + key)
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("WGROUTER_%s=%q: not a number", key, v)
	}
	return n, nil
}
