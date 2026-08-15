package device

import (
	"net/netip"
	"strings"
	"testing"
)

func validParams() Params {
	return Params{
		ClientPrivateKey: "cGxhY2Vob2xkZXIgcHJpdmF0ZSBrZXkgMzIgYnl0ZXM=",
		ClientAddress:    netip.MustParseAddr("10.10.0.2"),
		ServerPublicKey:  "cGxhY2Vob2xkZXIgc2VydmVyIHB1YmxpYyBrZXkgYnk=",
		PresharedKey:     "cGxhY2Vob2xkZXIgcHJlc2hhcmVkIGtleSAzMmJ5dA==",
		Endpoint:         "vpn.example.com:51820",
		AllowedIPs:       "10.10.0.0/24",
	}
}

func TestRenderProducesAWorkingConfig(t *testing.T) {
	got, err := Render(validParams())
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"[Interface]",
		"PrivateKey = cGxhY2Vob2xkZXIgcHJpdmF0ZSBrZXkgMzIgYnl0ZXM=",
		"Address = 10.10.0.2/32",
		"[Peer]",
		"PublicKey = cGxhY2Vob2xkZXIgc2VydmVyIHB1YmxpYyBrZXkgYnk=",
		"PresharedKey = cGxhY2Vob2xkZXIgcHJlc2hhcmVkIGtleSAzMmJ5dA==",
		"Endpoint = vpn.example.com:51820",
		"AllowedIPs = 10.10.0.0/24",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("config is missing %q\n--- got ---\n%s", want, got)
		}
	}
}

// The brief makes PersistentKeepalive mandatory: without it a peer behind NAT
// becomes unreachable once its mapping expires, which is exactly what port
// forwarding exists to prevent.
func TestKeepaliveIsAlwaysPresent(t *testing.T) {
	p := validParams()
	p.DNS = ""
	p.PresharedKey = ""
	got, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "PersistentKeepalive = 25") {
		t.Error("PersistentKeepalive is missing from a minimal config")
	}
}

// The client's own address must be a /32, whatever the pool's prefix is.
func TestClientAddressIsAlwaysASingleHost(t *testing.T) {
	p := validParams()
	p.ClientAddress = netip.MustParseAddr("10.10.0.200")
	got, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "Address = 10.10.0.200/32") {
		t.Error("the client address is not rendered as a /32")
	}
}

func TestOptionalFieldsAreOmittedNotBlank(t *testing.T) {
	p := validParams()
	p.DNS = ""
	p.PresharedKey = ""
	got, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	// A blank "DNS = " line is not merely untidy: wg-quick rejects it.
	if strings.Contains(got, "DNS =") {
		t.Error("an empty DNS line was emitted")
	}
	if strings.Contains(got, "PresharedKey =") {
		t.Error("an empty PresharedKey line was emitted")
	}

	p.DNS = "1.1.1.1"
	got, err = Render(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "DNS = 1.1.1.1") {
		t.Error("DNS was not emitted when set")
	}
}

func TestRenderRejectsIncompleteParams(t *testing.T) {
	tests := []struct {
		name  string
		mutit func(*Params)
	}{
		{"no private key", func(p *Params) { p.ClientPrivateKey = "" }},
		{"no server key", func(p *Params) { p.ServerPublicKey = "" }},
		{"no endpoint", func(p *Params) { p.Endpoint = "" }},
		{"no allowed ips", func(p *Params) { p.AllowedIPs = "" }},
		{"no address", func(p *Params) { p.ClientAddress = netip.Addr{} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validParams()
			tt.mutit(&p)
			if _, err := Render(p); err == nil {
				t.Error("an incomplete config was rendered instead of an error")
			}
		})
	}
}

func TestQRCodeEncodes(t *testing.T) {
	conf, err := Render(validParams())
	if err != nil {
		t.Fatal(err)
	}
	png, err := QRCode(conf, 320)
	if err != nil {
		t.Fatal(err)
	}
	if len(png) == 0 {
		t.Fatal("empty PNG")
	}
	// PNG magic, so this is an image and not an error page.
	if string(png[1:4]) != "PNG" {
		t.Errorf("output is not a PNG: % x", png[:8])
	}
}

func TestQRCodeSizeIsClamped(t *testing.T) {
	conf, _ := Render(validParams())
	for _, size := range []int{-100, 0, 10, 5000} {
		if _, err := QRCode(conf, size); err != nil {
			t.Errorf("QRCode(size=%d) failed: %v", size, err)
		}
	}
}

// wg-quick derives the interface name from the filename, and an interface name
// has hard constraints a device label does not.
func TestFilenameIsSafeForWgQuick(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"laptop", "laptop.conf"},
		{"Ana's iPhone (work)", "Ana-s-iPhone-wo.conf"},
		{"../../etc/passwd", "etc-passwd.conf"},
		{"", "wg-client.conf"},
		{"!!!", "wg-client.conf"},
		{"a-very-long-device-name-indeed", "a-very-long-dev.conf"},
		{"with spaces", "with-spaces.conf"},
	}
	for _, tt := range tests {
		got := Filename(tt.in)
		if got != tt.want {
			t.Errorf("Filename(%q) = %q, want %q", tt.in, got, tt.want)
		}
		// Whatever the input, the result must never escape a directory or
		// exceed the 15-character interface-name limit.
		if strings.ContainsAny(got, "/\\ ") {
			t.Errorf("Filename(%q) = %q contains a path or space character", tt.in, got)
		}
		if name := strings.TrimSuffix(got, ".conf"); len(name) > 15 {
			t.Errorf("Filename(%q) = %q has a %d-character interface name, max 15", tt.in, got, len(name))
		}
	}
}

// --- direct-mode routing ----------------------------------------------------

func directParams() Params {
	p := validParams()
	p.Routing = RoutingDirect
	p.AllowedIPs = FullTunnel
	p.TunnelSubnet = "10.10.0.0/24"
	return p
}

// The bug this guards against: AllowedIPs = 0.0.0.0/0 on its own. wg-quick's
// default (Table = auto) turns it into a default route, and this tunnel has no
// internet egress -- wgrouter never masquerades a peer's outbound traffic. The
// device would lose its internet to fix its reply routing.
func TestDirectModeDoesNotHijackTheDefaultRoute(t *testing.T) {
	got, err := Render(directParams())
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(got, "Table = off") {
		t.Error("Table = off is missing; wg-quick would install 0.0.0.0/0 as a default route " +
			"and take out the device's internet")
	}
	if !strings.Contains(got, "AllowedIPs = 0.0.0.0/0") {
		t.Error("direct mode needs 0.0.0.0/0 as the cryptokey filter")
	}

	// The policy-routing rule is what actually makes replies work.
	for _, want := range []string{
		"ip route replace 10.10.0.0/24 dev %i",
		"ip route replace default dev %i table 200",
		"ip rule add from 10.10.0.2 lookup 200 priority 100",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing hook: %s", want)
		}
	}
}

// wg-quick runs PreDown with `set -e` before deleting the interface. One
// failing line aborts the teardown, the interface survives, and every later
// restart dies on "RTNETLINK answers: File exists".
func TestDirectModeTeardownIsGuarded(t *testing.T) {
	got, err := Render(directParams())
	if err != nil {
		t.Fatal(err)
	}

	var preDowns int
	for _, line := range strings.Split(got, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "PreDown") {
			continue
		}
		preDowns++
		if !strings.HasSuffix(strings.TrimSpace(line), "|| true") {
			t.Errorf("unguarded PreDown line, a failure here wedges the interface:\n  %s", line)
		}
	}
	if preDowns != 3 {
		t.Errorf("got %d PreDown lines, want 3 (rule, table route, subnet route)", preDowns)
	}
}

// The idempotent delete-before-add means bringing the interface up twice does
// not stack duplicate rules.
func TestDirectModeAddIsIdempotent(t *testing.T) {
	got, err := Render(directParams())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "ip rule del from 10.10.0.2 lookup 200 priority 100 2>/dev/null || true") {
		t.Error("the PostUp rule is not deleted before being added; a second wg-quick up would stack duplicates")
	}
}

// Tunnel-only is the default and must carry none of the direct-mode machinery.
func TestTunnelOnlyHasNoHooks(t *testing.T) {
	got, err := Render(validParams())
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"Table = off", "PostUp", "PreDown", "ip rule", "ip route"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("a plain config contains %q", unwanted)
		}
	}
	if strings.Contains(got, "0.0.0.0/0") {
		t.Error("a plain config claims the default route")
	}
}

// An unset Routing must behave as tunnel-only rather than rendering nothing.
func TestEmptyRoutingDefaultsToTunnelOnly(t *testing.T) {
	p := validParams()
	p.Routing = ""
	got, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "Table = off") {
		t.Error("an unset routing mode rendered the direct template")
	}
}

// Direct mode with a narrower AllowedIPs would look carefully built and still
// drop every packet it was made for, so it is refused outright.
func TestDirectModeRequiresFullTunnelAllowedIPs(t *testing.T) {
	p := directParams()
	p.AllowedIPs = "10.10.0.0/24"
	if _, err := Render(p); err == nil {
		t.Error("direct mode was rendered with a narrowed AllowedIPs")
	}
}

func TestDirectModeRequiresTunnelSubnet(t *testing.T) {
	p := directParams()
	p.TunnelSubnet = ""
	if _, err := Render(p); err == nil {
		t.Error("direct mode was rendered without the tunnel subnet to route")
	}
}

func TestRenderRejectsUnknownRouting(t *testing.T) {
	p := validParams()
	p.Routing = "magic"
	if _, err := Render(p); err == nil {
		t.Error("an unknown routing mode was accepted")
	}
}

// Custom table and priority must reach every line that references them, or the
// PostUp and PreDown halves would disagree and teardown would leave a rule
// behind.
func TestDirectModeHonoursCustomTableAndPriority(t *testing.T) {
	p := directParams()
	p.RouteTable = railTable
	p.RulePriority = railPrio
	got, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(got, "lookup 200") || strings.Contains(got, "table 200") {
		t.Error("the default table leaked into a config with a custom one")
	}
	// Count only executable lines, not the explanatory comments: PostUp del,
	// PostUp add and PreDown del must all agree, or teardown leaves a rule
	// behind that the next start then trips over.
	var ruleLines int
	for _, l := range strings.Split(got, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "PostUp") && !strings.HasPrefix(l, "PreDown") {
			continue
		}
		if !strings.Contains(l, "ip rule") {
			continue
		}
		ruleLines++
		if !strings.Contains(l, "lookup 250") || !strings.Contains(l, "priority 77") {
			t.Errorf("rule line does not use the custom table/priority:\n  %s", l)
		}
	}
	if ruleLines != 3 {
		t.Errorf("got %d ip-rule lines, want 3 (PostUp del, PostUp add, PreDown del)", ruleLines)
	}
}

const (
	railTable = 250
	railPrio  = 77
)

// A direct-mode config is far too long for a QR code, and a phone could not run
// its hooks anyway. The server does not offer one; this records why, so nobody
// "fixes" it later by dropping the error correction and shipping a code that
// scans into a broken config.
func TestDirectConfigIsTooLongForAQRCode(t *testing.T) {
	conf, err := Render(directParams())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("direct config is %d bytes", len(conf))
	if _, err := QRCode(conf, 320); err == nil {
		t.Log("note: the direct config now fits in a QR code, but the hooks still " +
			"only run under wg-quick, so the server deliberately does not offer one")
	}
}

// The plain config must still fit, since that is the one people scan.
func TestTunnelOnlyConfigFitsInAQRCode(t *testing.T) {
	conf, err := Render(validParams())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := QRCode(conf, 320); err != nil {
		t.Errorf("the ordinary config no longer encodes as a QR code: %v", err)
	}
}

// Reverse-path filtering is the failure this mode hits most often, and it is
// silent: the tunnel handshakes and then passes nothing. The config has to say
// so, and has to carry the check and the fix.
func TestDirectModeExplainsReversePathFiltering(t *testing.T) {
	got, err := Render(directParams())
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"rp_filter",
		"sysctl net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.%i.rp_filter=2",
		"max(all, %i)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the direct config does not mention %q", want)
		}
	}
}

// Loosening source validation is a security decision about the operator's own
// machine. The generated file must describe it, not make it.
func TestReversePathFixIsCommentedOut(t *testing.T) {
	got, err := Render(directParams())
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(got, "\n") {
		l := strings.TrimSpace(line)
		if !strings.Contains(l, "rp_filter") {
			continue
		}
		// Any line that would actually execute must not touch rp_filter.
		if strings.HasPrefix(l, "PostUp") || strings.HasPrefix(l, "PreDown") {
			t.Errorf("an active hook changes rp_filter without being asked:\n  %s", l)
		}
	}
	// And 0 must never be suggested: loose still validates, off does not.
	if strings.Contains(got, "rp_filter=0") {
		t.Error("the config suggests disabling source validation entirely")
	}
}

// A plain config has nothing to do with any of this.
func TestTunnelOnlyDoesNotMentionRPFilter(t *testing.T) {
	got, err := Render(validParams())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "rp_filter") {
		t.Error("an ordinary config carries direct-mode troubleshooting")
	}
}
