package server

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"wgrouter/internal/forward"
)

// signedIn returns a harness past setup and login.
func signedIn(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.completeSetup()
	h.login()
	return h
}

// addDevice creates a device through the UI and returns the response body.
func (h *harness) addDevice(name string, extra url.Values) *http.Response {
	h.t.Helper()
	form := url.Values{
		"csrf_token": {h.csrfFrom("/devices")},
		"name":       {name},
	}
	for k, v := range extra {
		form[k] = v
	}
	return h.post("/devices", form)
}

func TestCreateDeviceShowsConfigExactlyOnce(t *testing.T) {
	h := signedIn(t)

	resp := h.addDevice("ana-laptop", nil)
	page := body(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /devices = %d, want 200", resp.StatusCode)
	}

	// The config must be complete and importable.
	for _, want := range []string{
		"[Interface]", "PrivateKey =", "Address = 10.10.0.2/32",
		"[Peer]", "PublicKey =", "PresharedKey =",
		"Endpoint = vpn.example.com:51820", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("generated config is missing %q", want)
		}
	}
	// Both the QR image and the download link are data: URIs, which
	// html/template rewrites to "#ZgotmplZ" unless they are marked as trusted
	// URLs. Assert on both, and on the absence of that marker: the failure is
	// silent in the browser and easy to reintroduce.
	if !strings.Contains(page, "data:image/png;base64,") {
		t.Error("no QR code was rendered")
	}
	if !strings.Contains(page, "data:application/octet-stream;base64,") {
		t.Error("the config download link was not rendered")
	}
	if strings.Contains(page, "ZgotmplZ") {
		t.Error("a data: URI was stripped by html/template's URL sanitiser")
	}
	if !strings.Contains(page, "only time this configuration is shown") {
		t.Error("the one-time warning was not shown")
	}

	// Reloading the device list must not show the key again -- it was never
	// stored, so it cannot be.
	page2 := body(t, h.get("/devices"))
	if strings.Contains(page2, "PrivateKey") {
		t.Error("the private key reappeared on a later page load")
	}
	if !strings.Contains(page2, "ana-laptop") {
		t.Error("the device is missing from the list")
	}
}

// The brief's hardest requirement: the private key must never be persisted.
func TestPrivateKeyIsNeverStored(t *testing.T) {
	h := signedIn(t)
	page := body(t, h.addDevice("laptop", nil))

	// Pull the private key out of the rendered config.
	var priv string
	for _, line := range strings.Split(page, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "PrivateKey = ") {
			priv = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "PrivateKey = "))
			break
		}
	}
	if priv == "" {
		t.Fatal("could not find the generated private key in the response")
	}

	// Scan every text column of every table for it.
	ctx := context.Background()
	rows, err := h.store.DB().QueryContext(ctx, `
		SELECT name, public_key, preshared_key, notes FROM peers`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a, b, c, d string
		if err := rows.Scan(&a, &b, &c, &d); err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{a, b, c, d} {
			if v == priv {
				t.Fatal("the client private key was written to the peers table")
			}
		}
	}

	var settings int
	if err := h.store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM settings WHERE value = ?`, priv).Scan(&settings); err != nil {
		t.Fatal(err)
	}
	if settings != 0 {
		t.Fatal("the client private key was written to the settings table")
	}
}

func TestCreateDevicePushesToKernel(t *testing.T) {
	h := signedIn(t)
	body(t, h.addDevice("laptop", nil))

	if _, ok := h.kernel.LastConfig("wg0"); !ok {
		t.Fatal("no configuration reached the kernel")
	}
	dev, err := h.kernel.Device(context.Background(), "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if len(dev.Peers) != 1 {
		t.Fatalf("kernel has %d peers, want 1", len(dev.Peers))
	}
	if got := dev.Peers[0].AllowedIPs[0]; got != "10.10.0.2/32" {
		t.Errorf("AllowedIPs = %s, want the peer's own /32", got)
	}
}

func TestCreateDeviceValidation(t *testing.T) {
	tests := []struct {
		name string
		form url.Values
		want string
	}{
		{"blank name", url.Values{"name": {"  "}}, "device name is required"},
		{"name too long", url.Values{"name": {strings.Repeat("x", 65)}}, "64 characters or fewer"},
		{"address outside pool", url.Values{"name": {"a"}, "address": {"192.168.1.5"}}, "not in 10.10.0.0/24"},
		{"reserved address", url.Values{"name": {"a"}, "address": {"10.10.0.1"}}, "reserved"},
		{"malformed address", url.Values{"name": {"a"}, "address": {"not-an-ip"}}, "parse address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := signedIn(t)
			form := url.Values{"csrf_token": {h.csrfFrom("/devices")}}
			for k, v := range tt.form {
				form[k] = v
			}
			resp := h.post("/devices", form)
			resp.Body.Close()
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303 back to the form", resp.StatusCode)
			}
			page := body(t, h.get("/devices"))
			if !strings.Contains(page, tt.want) {
				t.Errorf("the flash message does not mention %q", tt.want)
			}
			if n, _ := h.store.Peers(context.Background()); len(n) != 0 {
				t.Error("an invalid device was created anyway")
			}
		})
	}
}

func TestPinnedAddressIsHonoured(t *testing.T) {
	h := signedIn(t)
	page := body(t, h.addDevice("pinned", url.Values{"address": {"10.10.0.77"}}))
	if !strings.Contains(page, "Address = 10.10.0.77/32") {
		t.Error("the pinned address was not used")
	}
}

func TestDeviceToggleAndDelete(t *testing.T) {
	h := signedIn(t)
	body(t, h.addDevice("laptop", nil))

	peers, err := h.store.Peers(context.Background())
	if err != nil || len(peers) != 1 {
		t.Fatalf("setup: peers = %v, err = %v", peers, err)
	}
	id := peers[0].ID

	// Disable: the peer must leave the kernel.
	resp := h.post("/devices/"+strconv.FormatInt(id, 10)+"/toggle", url.Values{
		"csrf_token": {h.csrfFrom("/devices")}, "enable": {"0"},
	})
	resp.Body.Close()
	if dev, _ := h.kernel.Device(context.Background(), "wg0"); len(dev.Peers) != 0 {
		t.Error("a disabled device is still configured in the kernel")
	}

	// Re-enable.
	resp = h.post("/devices/"+strconv.FormatInt(id, 10)+"/toggle", url.Values{
		"csrf_token": {h.csrfFrom("/devices")}, "enable": {"1"},
	})
	resp.Body.Close()
	if dev, _ := h.kernel.Device(context.Background(), "wg0"); len(dev.Peers) != 1 {
		t.Error("a re-enabled device did not return to the kernel")
	}

	// Delete.
	resp = h.post("/devices/"+strconv.FormatInt(id, 10)+"/delete", url.Values{
		"csrf_token": {h.csrfFrom("/devices")},
	})
	resp.Body.Close()
	if peers, _ := h.store.Peers(context.Background()); len(peers) != 0 {
		t.Error("the device was not deleted")
	}
	if dev, _ := h.kernel.Device(context.Background(), "wg0"); len(dev.Peers) != 0 {
		t.Error("a deleted device is still in the kernel")
	}
}

// --- forwards --------------------------------------------------------------

func (h *harness) addForward(form url.Values) *http.Response {
	h.t.Helper()
	full := url.Values{"csrf_token": {h.csrfFrom("/forwards")}}
	for k, v := range form {
		full[k] = v
	}
	return h.post("/forwards", full)
}

// seedDevice creates one device and returns its peer ID.
func (h *harness) seedDevice() int64 {
	h.t.Helper()
	body(h.t, h.addDevice("target", nil))
	peers, err := h.store.Peers(context.Background())
	if err != nil || len(peers) == 0 {
		h.t.Fatalf("seed device: %v", err)
	}
	return peers[0].ID
}

func TestCreateForwardProgramsKernel(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()

	resp := h.addForward(url.Values{
		"label":       {"web"},
		"listen_port": {"443"},
		"proto":       {"tcp"},
		"peer_id":     {strconv.FormatInt(id, 10)},
		"target_port": {"8443"},
		"src_mode":    {"masquerade"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}

	applied := h.fw.LastApplied()
	if len(applied) != 1 {
		t.Fatalf("kernel has %d rules, want 1", len(applied))
	}
	r := applied[0]
	if r.Listen.Start != 443 || r.TargetPort != 8443 || r.Proto != forward.ProtoTCP {
		t.Errorf("rule = %+v, not what was submitted", r)
	}
	if r.TargetIP.String() != "10.10.0.2" {
		t.Errorf("target = %s, want the peer's tunnel address", r.TargetIP)
	}

	// The list must report it as live, from the read-back rather than from
	// the fact that we asked for it.
	page := body(t, h.get("/forwards"))
	if !strings.Contains(page, "Live") {
		t.Error("the forward is not reported as live in the kernel")
	}
}

func TestForwardPortValidation(t *testing.T) {
	tests := []struct {
		name string
		port string
		want string
	}{
		{"zero", "0", "between 1 and 65535"},
		{"negative", "-1", "between 1 and 65535"},
		{"too large", "65536", "between 1 and 65535"},
		{"not a number", "http", "must be a number"},
		{"empty", "", "required"},
		{"overflowing int", "4294967296", "between 1 and 65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := signedIn(t)
			id := h.seedDevice()
			resp := h.addForward(url.Values{
				"label":       {"x"},
				"listen_port": {tt.port},
				"proto":       {"tcp"},
				"peer_id":     {strconv.FormatInt(id, 10)},
				"target_port": {"80"},
				"src_mode":    {"masquerade"},
			})
			resp.Body.Close()

			page := body(t, h.get("/forwards"))
			if !strings.Contains(page, tt.want) {
				t.Errorf("flash does not mention %q", tt.want)
			}
			if fs, _ := h.store.Forwards(context.Background()); len(fs) != 0 {
				t.Errorf("a forward with port %q was created", tt.port)
			}
		})
	}
}

// The PROXY-protocol mode was removed. A request naming it -- a stale
// bookmark, or a hand-crafted POST -- must be refused rather than stored as an
// unknown mode the reconciler would then have to interpret.
func TestForwardRejectsRemovedProxyMode(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()

	resp := h.addForward(url.Values{
		"label":       {"legacy"},
		"listen_port": {"443"},
		"proto":       {"tcp"},
		"peer_id":     {strconv.FormatInt(id, 10)},
		"target_port": {"443"},
		"src_mode":    {"proxy"},
	})
	resp.Body.Close()

	page := body(t, h.get("/forwards"))
	if !strings.Contains(page, "unknown source mode") {
		t.Error("the removed mode was not reported as unknown")
	}
	if fs, _ := h.store.Forwards(context.Background()); len(fs) != 0 {
		t.Error("a forward with the removed proxy mode was created")
	}
}

// And the UI must not offer it any more.
func TestForwardFormDoesNotOfferProxy(t *testing.T) {
	h := signedIn(t)
	h.seedDevice()
	page := body(t, h.get("/forwards"))
	if strings.Contains(page, `value="proxy"`) || strings.Contains(page, "PROXY") {
		t.Error("the forwarding page still offers PROXY protocol")
	}
}

func TestForwardRejectsUnknownPeer(t *testing.T) {
	h := signedIn(t)
	resp := h.addForward(url.Values{
		"label":       {"x"},
		"listen_port": {"443"},
		"proto":       {"tcp"},
		"peer_id":     {"9999"},
		"target_port": {"80"},
		"src_mode":    {"masquerade"},
	})
	resp.Body.Close()
	if fs, _ := h.store.Forwards(context.Background()); len(fs) != 0 {
		t.Error("a forward was created for a peer that does not exist")
	}
}

func TestForwardPortConflictIsExplained(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()
	base := url.Values{
		"label":       {"first"},
		"listen_port": {"443"},
		"proto":       {"both"},
		"peer_id":     {strconv.FormatInt(id, 10)},
		"target_port": {"8443"},
		"src_mode":    {"masquerade"},
	}
	h.addForward(base).Body.Close()

	second := url.Values{}
	for k, v := range base {
		second[k] = v
	}
	second["label"] = []string{"second"}
	second["proto"] = []string{"tcp"}
	h.addForward(second).Body.Close()

	page := body(t, h.get("/forwards"))
	if !strings.Contains(page, "already forwarded by") {
		t.Error("the port conflict was not explained to the user")
	}
	if fs, _ := h.store.Forwards(context.Background()); len(fs) != 1 {
		t.Errorf("%d forwards exist, want the conflicting one refused", len(fs))
	}
}

// Deleting a peer must remove the forwards pointing at it, from the kernel too.
func TestDeletingPeerClearsItsForwardsFromKernel(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()
	h.addForward(url.Values{
		"label":       {"web"},
		"listen_port": {"443"},
		"proto":       {"tcp"},
		"peer_id":     {strconv.FormatInt(id, 10)},
		"target_port": {"8443"},
		"src_mode":    {"masquerade"},
	}).Body.Close()
	if len(h.fw.LastApplied()) != 1 {
		t.Fatal("setup: the forward did not reach the kernel")
	}

	h.post("/devices/"+strconv.FormatInt(id, 10)+"/delete", url.Values{
		"csrf_token": {h.csrfFrom("/devices")},
	}).Body.Close()

	if got := h.fw.LastApplied(); len(got) != 0 {
		t.Errorf("%d nftables rules survive a deleted peer", len(got))
	}
}

// Mutating endpoints must all reject a missing CSRF token.
func TestMutatingEndpointsRequireCSRF(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()

	paths := []string{
		"/devices",
		"/devices/" + strconv.FormatInt(id, 10) + "/delete",
		"/devices/" + strconv.FormatInt(id, 10) + "/toggle",
		"/forwards",
		"/forwards/1/delete",
		"/forwards/1/toggle",
	}
	for _, p := range paths {
		resp := h.post(p, url.Values{"name": {"x"}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s without a CSRF token = %d, want 403", p, resp.StatusCode)
		}
	}
}

func TestEventsStreamRequiresAuth(t *testing.T) {
	h := newHarness(t)
	h.completeSetup()

	resp := h.get("/events")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("GET /events unauthenticated = %d, want a redirect to login", resp.StatusCode)
	}
}

// The SSE stream must survive the middleware chain. The access log wraps the
// ResponseWriter, and a wrapper does not satisfy http.Flusher just because
// what it wraps does -- a bare type assertion turns the live device list into
// a 500 that only shows up in a browser.
func TestEventsStreamsThroughMiddleware(t *testing.T) {
	h := signedIn(t)
	h.seedDevice()

	req, err := http.NewRequest("GET", h.base+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range h.client.Jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /events = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}

	// Read the first event, which is sent immediately rather than on the tick.
	buf := make([]byte, 512)
	n, err := resp.Body.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("no event was streamed: %v", err)
	}
	got := string(buf[:n])
	if !strings.HasPrefix(got, "event: peers\ndata: ") {
		t.Errorf("first frame = %q, want an SSE peers event", got)
	}
	if !strings.Contains(got, `"presence"`) {
		t.Errorf("event payload has no presence field: %q", got)
	}
}

// --- editing ----------------------------------------------------------------

func TestEditDeviceNameAndNote(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()

	// The edit form is reached with ?edit=<id> and must be pre-filled.
	page := body(t, h.get("/devices?edit="+strconv.FormatInt(id, 10)))
	if !strings.Contains(page, "Save changes") {
		t.Error("the edit form was not rendered")
	}
	if !strings.Contains(page, `value="target"`) {
		t.Error("the edit form was not pre-filled with the current name")
	}

	resp := h.post("/devices/"+strconv.FormatInt(id, 10)+"/update", url.Values{
		"csrf_token": {h.csrfFrom("/devices")},
		"name":       {"renamed-laptop"},
		"notes":      {"belongs to ana"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}

	p, err := h.store.PeerByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "renamed-laptop" || p.Notes != "belongs to ana" {
		t.Errorf("after edit: name=%q notes=%q", p.Name, p.Notes)
	}
}

// The address and public key are the device's identity and its issued config;
// neither may be changed by a hand-crafted POST.
func TestEditDeviceCannotChangeAddressOrKey(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()
	before, _ := h.store.PeerByID(context.Background(), id)

	h.post("/devices/"+strconv.FormatInt(id, 10)+"/update", url.Values{
		"csrf_token": {h.csrfFrom("/devices")},
		"name":       {"still-fine"},
		"address":    {"10.10.0.99"},
		"public_key": {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}).Body.Close()

	after, _ := h.store.PeerByID(context.Background(), id)
	if after.TunnelIP != before.TunnelIP {
		t.Errorf("tunnel address changed from %s to %s", before.TunnelIP, after.TunnelIP)
	}
	if after.PublicKey != before.PublicKey {
		t.Error("the public key was changed")
	}
}

func TestEditDeviceValidation(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()

	resp := h.post("/devices/"+strconv.FormatInt(id, 10)+"/update", url.Values{
		"csrf_token": {h.csrfFrom("/devices")},
		"name":       {"   "},
	})
	resp.Body.Close()
	page := body(t, h.get("/devices"))
	if !strings.Contains(page, "device name is required") {
		t.Error("a blank name was accepted on edit")
	}
	if p, _ := h.store.PeerByID(context.Background(), id); p.Name != "target" {
		t.Errorf("name became %q despite the failed edit", p.Name)
	}
}

func TestEditForward(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()
	h.addForward(url.Values{
		"label": {"web"}, "listen_port": {"443"}, "proto": {"tcp"},
		"peer_id": {strconv.FormatInt(id, 10)}, "target_port": {"8443"},
		"src_mode": {"masquerade"},
	}).Body.Close()

	fwds, _ := h.store.Forwards(context.Background())
	if len(fwds) != 1 {
		t.Fatalf("setup: %d forwards", len(fwds))
	}
	fid := fwds[0].ID

	page := body(t, h.get("/forwards?edit="+strconv.FormatInt(fid, 10)))
	if !strings.Contains(page, "Save changes") || !strings.Contains(page, `value="443"`) {
		t.Error("the edit form was not rendered pre-filled")
	}

	resp := h.post("/forwards/"+strconv.FormatInt(fid, 10)+"/update", url.Values{
		"csrf_token": {h.csrfFrom("/forwards")},
		"label":      {"web-renamed"}, "listen_port": {"8443"}, "proto": {"both"},
		"peer_id": {strconv.FormatInt(id, 10)}, "target_port": {"9000"},
		"src_mode": {"direct"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}

	got, err := h.store.ForwardByID(context.Background(), fid)
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "web-renamed" || got.Listen.Start != 8443 || got.TargetPort != 9000 {
		t.Errorf("after edit: %+v", got)
	}
	if got.Proto != "both" || got.SrcMode != "direct" {
		t.Errorf("proto/mode not updated: %q %q", got.Proto, got.SrcMode)
	}

	// The kernel must reflect the edit, not the old rule.
	applied := h.fw.LastApplied()
	if len(applied) != 1 || applied[0].Listen.Start != 8443 || applied[0].TargetPort != 9000 {
		t.Errorf("kernel holds %+v, want the edited rule", applied)
	}
}

// Editing a forward without moving its port must not conflict with itself.
func TestEditForwardDoesNotConflictWithItself(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()
	h.addForward(url.Values{
		"label": {"web"}, "listen_port": {"443"}, "proto": {"tcp"},
		"peer_id": {strconv.FormatInt(id, 10)}, "target_port": {"8443"},
		"src_mode": {"masquerade"},
	}).Body.Close()
	fwds, _ := h.store.Forwards(context.Background())
	fid := fwds[0].ID

	resp := h.post("/forwards/"+strconv.FormatInt(fid, 10)+"/update", url.Values{
		"csrf_token": {h.csrfFrom("/forwards")},
		"label":      {"web"}, "listen_port": {"443"}, "proto": {"tcp"},
		"peer_id": {strconv.FormatInt(id, 10)}, "target_port": {"9999"},
		"src_mode": {"masquerade"},
	})
	resp.Body.Close()

	got, _ := h.store.ForwardByID(context.Background(), fid)
	if got.TargetPort != 9999 {
		t.Errorf("target port = %d; the edit was refused as a self-conflict", got.TargetPort)
	}
}

// Editing onto a port another enabled forward holds must be refused.
func TestEditForwardRejectsPortConflict(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()
	for _, p := range []string{"443", "8080"} {
		h.addForward(url.Values{
			"label": {"f" + p}, "listen_port": {p}, "proto": {"tcp"},
			"peer_id": {strconv.FormatInt(id, 10)}, "target_port": {"80"},
			"src_mode": {"masquerade"},
		}).Body.Close()
	}
	fwds, _ := h.store.Forwards(context.Background())
	first := fwds[0].ID // 443

	h.post("/forwards/"+strconv.FormatInt(first, 10)+"/update", url.Values{
		"csrf_token": {h.csrfFrom("/forwards")},
		"label":      {"f443"}, "listen_port": {"8080"}, "proto": {"tcp"},
		"peer_id": {strconv.FormatInt(id, 10)}, "target_port": {"80"},
		"src_mode": {"masquerade"},
	}).Body.Close()

	got, _ := h.store.ForwardByID(context.Background(), first)
	if got.Listen.Start != 443 {
		t.Errorf("listen port became %d; the conflicting edit was allowed", got.Listen.Start)
	}
	page := body(t, h.get("/forwards"))
	if !strings.Contains(page, "already forwarded by") {
		t.Error("the conflict was not explained")
	}
}

// Editing must not silently flip a disabled forward on.
func TestEditForwardPreservesEnabledState(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()
	h.addForward(url.Values{
		"label": {"web"}, "listen_port": {"443"}, "proto": {"tcp"},
		"peer_id": {strconv.FormatInt(id, 10)}, "target_port": {"8443"},
		"src_mode": {"masquerade"},
	}).Body.Close()
	fwds, _ := h.store.Forwards(context.Background())
	fid := fwds[0].ID

	h.post("/forwards/"+strconv.FormatInt(fid, 10)+"/toggle", url.Values{
		"csrf_token": {h.csrfFrom("/forwards")}, "enable": {"0"},
	}).Body.Close()

	h.post("/forwards/"+strconv.FormatInt(fid, 10)+"/update", url.Values{
		"csrf_token": {h.csrfFrom("/forwards")},
		"label":      {"web2"}, "listen_port": {"443"}, "proto": {"tcp"},
		"peer_id": {strconv.FormatInt(id, 10)}, "target_port": {"8443"},
		"src_mode": {"masquerade"},
	}).Body.Close()

	got, _ := h.store.ForwardByID(context.Background(), fid)
	if got.Enabled {
		t.Error("editing a disabled forward re-enabled it")
	}
	if got.Label != "web2" {
		t.Error("the edit did not apply")
	}
}

func TestEditEndpointsRequireCSRF(t *testing.T) {
	h := signedIn(t)
	id := h.seedDevice()
	for _, p := range []string{
		"/devices/" + strconv.FormatInt(id, 10) + "/update",
		"/forwards/1/update",
	} {
		resp := h.post(p, url.Values{"name": {"x"}, "label": {"x"}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s without CSRF = %d, want 403", p, resp.StatusCode)
		}
	}
}

// --- direct-mode device provisioning ----------------------------------------

// The bug: AllowedIPs = 0.0.0.0/0 with nothing else. wg-quick's default turns
// it into a default route, and this tunnel has no internet egress, so the
// device would lose connectivity the moment it came up.
func TestDirectRoutingConfigDoesNotBreakClientInternet(t *testing.T) {
	h := signedIn(t)
	conf := configBlock(t, body(t, h.addDevice("srv", url.Values{"routing": {"direct"}})))

	if !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0") {
		t.Error("direct routing did not widen AllowedIPs to the cryptokey filter it needs")
	}
	if !strings.Contains(conf, "Table = off") {
		t.Fatal("Table = off is missing: wg-quick would install a default route through a " +
			"tunnel with no internet egress")
	}
	for _, want := range []string{
		"PostUp = ip route replace 10.10.0.0/24 dev %i",
		"ip rule add from 10.10.0.2 lookup 200 priority 100",
		"PreDown = ip rule del from 10.10.0.2 lookup 200 priority 100 || true",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("generated config is missing %q", want)
		}
	}
}

// configBlock extracts the generated config from the page.
//
// Assertions have to run against this, not the whole page: the form below it
// explains the routing modes and mentions 0.0.0.0/0 in its help text, so a
// naive strings.Contains over the response matches the documentation rather
// than the config.
func configBlock(t *testing.T, page string) string {
	t.Helper()
	const open = `<pre class="conf" id="newconf">`
	i := strings.Index(page, open)
	if i < 0 {
		t.Fatal("no generated config on the page")
	}
	rest := page[i+len(open):]
	j := strings.Index(rest, "</pre>")
	if j < 0 {
		t.Fatal("unterminated config block")
	}
	return rest[:j]
}

// The default must stay the safe one.
func TestDefaultRoutingIsTunnelOnly(t *testing.T) {
	h := signedIn(t)
	conf := configBlock(t, body(t, h.addDevice("laptop", nil)))

	if strings.Contains(conf, "0.0.0.0/0") {
		t.Error("a device created without choosing direct routing claimed the default route")
	}
	if strings.Contains(conf, "Table = off") || strings.Contains(conf, "PostUp") {
		t.Error("a plain device got the direct-mode hooks")
	}
	if !strings.Contains(conf, "AllowedIPs = 10.10.0.0/24") {
		t.Error("the tunnel-only config does not carry the pool as AllowedIPs")
	}
}

// A direct-mode config cannot be scanned: its hooks only run under wg-quick,
// and the file is past what a QR can hold anyway. Offering one would hand
// someone a config that silently does not work.
func TestDirectConfigOffersNoQRCode(t *testing.T) {
	h := signedIn(t)
	page := body(t, h.addDevice("srv", url.Values{"routing": {"direct"}}))

	if strings.Contains(page, "data:image/png;base64,") {
		t.Error("a QR code was offered for a config whose hooks a phone cannot run")
	}
	// The download link is the actual deliverable and must still be there.
	if !strings.Contains(page, "data:application/octet-stream;base64,") {
		t.Error("the config download link is missing")
	}
}

// An ordinary device still gets its QR.
func TestTunnelOnlyConfigKeepsItsQRCode(t *testing.T) {
	h := signedIn(t)
	page := body(t, h.addDevice("phone", nil))
	if !strings.Contains(page, "data:image/png;base64,") {
		t.Error("the QR code disappeared from an ordinary config")
	}
}
