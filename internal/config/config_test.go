package config

import (
	"log/slog"
	"strings"
	"testing"
)

// baseArgs supplies the one required flag so each test can vary only what it
// cares about.
func baseArgs(extra ...string) []string {
	return append([]string{"-public-endpoint", "vpn.example.com"}, extra...)
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(baseArgs())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.WGInterface != DefaultWGInterface {
		t.Errorf("WGInterface = %q, want %q", cfg.WGInterface, DefaultWGInterface)
	}
	if cfg.WGListenPort != DefaultWGListenPort {
		t.Errorf("WGListenPort = %d, want %d", cfg.WGListenPort, DefaultWGListenPort)
	}
	if got := cfg.TunnelPool.String(); got != DefaultTunnelPool {
		t.Errorf("TunnelPool = %q, want %q", got, DefaultTunnelPool)
	}
	// The server always takes the first usable address in the pool.
	if got := cfg.ServerIP.String(); got != "10.10.0.1" {
		t.Errorf("ServerIP = %q, want 10.10.0.1", got)
	}
	// The admin listener must default to the tunnel address, never 0.0.0.0.
	if want := "10.10.0.1:8080"; cfg.ListenAddr != want {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, want)
	}
	// AllowedIPs falls back to the pool when unset.
	if got := cfg.ClientAllowedIPs; got != DefaultTunnelPool {
		t.Errorf("ClientAllowedIPs = %q, want %q", got, DefaultTunnelPool)
	}
	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() = true with no cert or key")
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want info", cfg.LogLevel)
	}
}

func TestPublicEndpointIsRequired(t *testing.T) {
	_, err := Load(nil)
	if err == nil {
		t.Fatal("Load with no -public-endpoint succeeded, want error")
	}
	if !strings.Contains(err.Error(), "public-endpoint") {
		t.Errorf("error %q does not mention the missing flag", err)
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"port zero", baseArgs("-wg-listen-port", "0"), "1..65535"},
		{"port too high", baseArgs("-wg-listen-port", "65536"), "1..65535"},
		{"pool not a cidr", baseArgs("-tunnel-pool", "10.10.0.0"), "tunnel-pool"},
		{"pool too small", baseArgs("-tunnel-pool", "10.10.0.0/31"), "too small"},
		{"pool is ipv6", baseArgs("-tunnel-pool", "fd00::/64"), "IPv4"},
		{"interface too long", baseArgs("-wg-interface", "averyverylonginterfacename"), "1..15"},
		{"interface empty", baseArgs("-wg-interface", ""), "1..15"},
		{"interface with slash", baseArgs("-wg-interface", "wg/0"), "slashes"},
		{"endpoint with slash", []string{"-public-endpoint", "https://vpn.example.com"}, "bare host"},
		{"bad log level", baseArgs("-log-level", "chatty"), "log-level"},
		{"cert without key", baseArgs("-tls-cert", "/tmp/c.pem"), "must be set together"},
		{"positional argument", baseArgs("unexpected"), "positional"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.args)
			if err == nil {
				t.Fatalf("Load(%v) succeeded, want error", tt.args)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

// A malformed environment integer must stop startup rather than silently
// leaving the router on a port nobody configured.
func TestMalformedEnvIntIsFatal(t *testing.T) {
	t.Setenv("WGROUTER_WG_LISTEN_PORT", "fifty-one-eight-twenty")
	_, err := Load(baseArgs())
	if err == nil {
		t.Fatal("Load with a malformed WGROUTER_WG_LISTEN_PORT succeeded, want error")
	}
	if !strings.Contains(err.Error(), "WG_LISTEN_PORT") {
		t.Errorf("error %q does not name the offending variable", err)
	}
}

func TestListenValidation(t *testing.T) {
	tests := []struct {
		name    string
		listen  string
		wantErr bool
	}{
		{"tunnel address", "10.10.0.1:8080", false},
		{"bare port", ":8080", false},
		{"hostname", "router.local:8080", false},
		{"bracketed ipv6", "[::1]:8080", false},
		// Port 0 binds an ephemeral port: the service starts, claims success,
		// and is reachable on an address nobody can predict.
		{"port zero", "10.10.0.1:0", true},
		{"port out of range", "10.10.0.1:70000", true},
		{"no port", "10.10.0.1", true},
		{"bare ipv6 without brackets", "2001:db8::1", true},
		{"garbage host", "not a host:8080", true},
		{"pasted url", "http://10.10.0.1:8080", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(baseArgs("-listen", tt.listen))
			if tt.wantErr && err == nil {
				t.Errorf("Load(-listen %q) succeeded, want error", tt.listen)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Load(-listen %q): %v", tt.listen, err)
			}
		})
	}
}

// Pools that cannot carry tunnel traffic must be rejected at startup, not
// accepted and then failed far away at route installation.
func TestPoolRejectsUnusableRanges(t *testing.T) {
	for _, pool := range []string{
		"127.0.0.0/24",   // loopback
		"224.0.0.0/24",   // multicast
		"0.0.0.0/24",     // unspecified
		"169.254.0.0/24", // link-local
	} {
		if _, err := Load(baseArgs("-tunnel-pool", pool)); err == nil {
			t.Errorf("Load(-tunnel-pool %q) succeeded, want it rejected", pool)
		}
	}
}

func TestPoolIsMaskedAndServerIPDerived(t *testing.T) {
	// A pool given with host bits set should be normalised rather than rejected.
	cfg, err := Load(baseArgs("-tunnel-pool", "192.168.77.9/24"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := cfg.TunnelPool.String(), "192.168.77.0/24"; got != want {
		t.Errorf("TunnelPool = %q, want %q", got, want)
	}
	if got, want := cfg.ServerIP.String(), "192.168.77.1"; got != want {
		t.Errorf("ServerIP = %q, want %q", got, want)
	}
	if got, want := cfg.ServerPrefix().String(), "192.168.77.1/32"; got != want {
		t.Errorf("ServerPrefix() = %q, want %q", got, want)
	}
}

func TestPublicListen(t *testing.T) {
	tests := []struct {
		name   string
		listen string
		want   bool
	}{
		{"tunnel address", "10.10.0.1:8080", false},
		{"loopback", "127.0.0.1:8080", false},
		{"wildcard v4", "0.0.0.0:8080", true},
		{"bare port", ":8080", true},
		{"another interface", "10.0.0.161:8080", true},
		// A hostname cannot be resolved at config time, so we assume the worst.
		// A spurious warning costs a log line; a missed one leaves an admin
		// panel quietly exposed.
		{"unresolvable hostname warns", "router.local:8080", true},
		{"localhost does not warn", "localhost:8080", false},
		// The tunnel address written IPv4-mapped is still the tunnel address.
		{"ipv4-mapped tunnel address", "[::ffff:10.10.0.1]:8080", false},
		{"bracketed wildcard v6", "[::]:8080", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(baseArgs("-listen", tt.listen))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.PublicListen(); got != tt.want {
				t.Errorf("PublicListen() for %q = %v, want %v", tt.listen, got, tt.want)
			}
		})
	}
}

func TestEnvironmentFallback(t *testing.T) {
	t.Setenv("WGROUTER_PUBLIC_ENDPOINT", "env.example.com")
	t.Setenv("WGROUTER_WG_LISTEN_PORT", "51821")
	t.Setenv("WGROUTER_TUNNEL_POOL", "10.44.0.0/24")

	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PublicEndpoint != "env.example.com" {
		t.Errorf("PublicEndpoint = %q, want env.example.com", cfg.PublicEndpoint)
	}
	if cfg.WGListenPort != 51821 {
		t.Errorf("WGListenPort = %d, want 51821", cfg.WGListenPort)
	}
	if got := cfg.TunnelPool.String(); got != "10.44.0.0/24" {
		t.Errorf("TunnelPool = %q, want 10.44.0.0/24", got)
	}
}

func TestFlagsBeatEnvironment(t *testing.T) {
	t.Setenv("WGROUTER_PUBLIC_ENDPOINT", "env.example.com")
	cfg, err := Load([]string{"-public-endpoint", "flag.example.com"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PublicEndpoint != "flag.example.com" {
		t.Errorf("PublicEndpoint = %q, want the flag to win", cfg.PublicEndpoint)
	}
}

func TestLogLevels(t *testing.T) {
	for input, want := range map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
		"WARN":  slog.LevelWarn,
	} {
		cfg, err := Load(baseArgs("-log-level", input))
		if err != nil {
			t.Fatalf("Load(-log-level %q): %v", input, err)
		}
		if cfg.LogLevel != want {
			t.Errorf("LogLevel for %q = %v, want %v", input, cfg.LogLevel, want)
		}
	}
}
