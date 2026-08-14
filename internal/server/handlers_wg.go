package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"wgrouter/internal/auth"
	"wgrouter/internal/device"
	"wgrouter/internal/forward"
	"wgrouter/internal/ipam"
	"wgrouter/internal/store"
	"wgrouter/internal/wg"
)

// maxNameLength bounds the device label. It is not a security boundary -- the
// templates escape everything -- but an unbounded name would make the audit log
// and the device list unreadable.
const maxNameLength = 64

// --- devices ---------------------------------------------------------------

func (s *Server) handleDeviceCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	name := strings.TrimSpace(r.PostFormValue("name"))
	notes := strings.TrimSpace(r.PostFormValue("notes"))

	fail := func(msg string) {
		s.setFlash(w, "error", msg)
		http.Redirect(w, r, "/devices", http.StatusSeeOther)
	}

	if name == "" {
		fail("A device name is required.")
		return
	}
	if len(name) > maxNameLength {
		fail(fmt.Sprintf("The device name must be %d characters or fewer.", maxNameLength))
		return
	}
	if len(notes) > 256 {
		fail("The note must be 256 characters or fewer.")
		return
	}

	// An administrator may pin an address; anything they type is validated
	// against the pool before it can reach the allocator.
	var pinned netip.Addr
	if raw := strings.TrimSpace(r.PostFormValue("address")); raw != "" {
		addr, err := s.plan.Parse(raw)
		if err != nil {
			fail(err.Error())
			return
		}
		pinned = addr
	}

	// The client keypair is generated here and the private half is rendered
	// exactly once, into this response. It is never written to the database,
	// so a later compromise of the router cannot reconstruct a client's
	// identity -- and equally, a lost config cannot be re-downloaded.
	priv, err := wg.GenerateKey()
	if err != nil {
		slog.ErrorContext(r.Context(), "generate client key", "error", err)
		fail("The client key could not be generated.")
		return
	}
	psk, err := wg.GeneratePresharedKey()
	if err != nil {
		slog.ErrorContext(r.Context(), "generate preshared key", "error", err)
		fail("The preshared key could not be generated.")
		return
	}

	peer, err := s.store.CreatePeer(r.Context(), s.plan, store.Peer{
		Name:         name,
		PublicKey:    priv.PublicKey().String(),
		PresharedKey: psk.String(),
		Notes:        notes,
		Enabled:      true,
	}, pinned)
	switch {
	case errors.Is(err, ipam.ErrPoolExhausted):
		fail("The address pool is full. Delete a device or use a larger -tunnel-pool.")
		return
	case errors.Is(err, store.ErrAddressTaken):
		fail("That tunnel address is already in use.")
		return
	case err != nil:
		slog.ErrorContext(r.Context(), "create peer", "error", err)
		fail("The device could not be created.")
		return
	}

	s.audit(r, actorOf(sess), store.ActionPeerCreate,
		fmt.Sprintf("created device %q at %s", name, peer.TunnelIP))

	// Push it to the kernel before showing the config, so the config the user
	// is about to import actually works.
	if err := s.wgm.Sync(r.Context()); err != nil {
		slog.ErrorContext(r.Context(), "sync wireguard after peer create", "error", err)
		s.setFlash(w, "error", "The device was created but could not be applied to the kernel. It will be retried automatically.")
	}

	serverPub, err := s.wgm.PublicKey(r.Context())
	if err != nil {
		slog.ErrorContext(r.Context(), "read server public key", "error", err)
		fail("The device was created, but the server key could not be read to build its configuration.")
		return
	}

	// Direct-mode forwards need AllowedIPs = 0.0.0.0/0, because AllowedIPs is
	// the inbound cryptokey filter as well as the outbound route selector. On
	// its own that would also become the client's default route -- and wgrouter
	// never masquerades a peer's outbound traffic, so the tunnel has no
	// internet egress and the device would lose connectivity. The direct
	// template therefore also sets Table = off and installs source-based policy
	// routing; see internal/device.
	params := device.Params{
		ClientPrivateKey: priv.String(),
		ClientAddress:    peer.TunnelIP,
		ServerPublicKey:  serverPub,
		PresharedKey:     psk.String(),
		Endpoint:         fmt.Sprintf("%s:%d", s.cfg.PublicEndpoint, s.cfg.WGListenPort),
		AllowedIPs:       s.cfg.ClientAllowedIPs,
		DNS:              s.cfg.ClientDNS,
		Routing:          device.RoutingTunnelOnly,
	}
	if r.PostFormValue("routing") == string(device.RoutingDirect) {
		params.Routing = device.RoutingDirect
		params.AllowedIPs = device.FullTunnel
		params.TunnelSubnet = s.cfg.TunnelPool.String()
		params.RouteTable = s.cfg.ClientRouteTable
		params.RulePriority = s.cfg.ClientRulePriority
	}

	conf, err := device.Render(params)
	if err != nil {
		slog.ErrorContext(r.Context(), "render client config", "error", err)
		fail("The device was created, but its configuration could not be rendered.")
		return
	}

	// No QR for a direct-mode config, deliberately. It carries PostUp/PreDown
	// hooks that only wg-quick on Linux executes -- the mobile apps ignore
	// them -- so a scannable code would hand someone a config that silently
	// does not do the thing it was generated for. It is also past what a QR
	// can hold at this error-correction level, so the alternative was a
	// warning in the log and a blank space on the page.
	var png []byte
	if params.Routing != device.RoutingDirect {
		var qerr error
		png, qerr = device.QRCode(conf, 320)
		if qerr != nil {
			// Not fatal: the text config is the real deliverable and the QR is
			// a convenience.
			slog.WarnContext(r.Context(), "encode QR code", "error", qerr)
		}
	}

	d := s.newPageData(r, "/devices")
	d.NewDevice = &newDevice{
		Direct:     params.Routing == device.RoutingDirect,
		AllowedIPs: params.AllowedIPs,
		Name:       peer.Name,
		TunnelIP:   peer.TunnelIP.String(),
		Config:     conf,
		Filename:   device.Filename(peer.Name),
		// Both are data URIs so nothing has to be held server-side between
		// this response and the user's click.
		ConfigDataURI: template.URL("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString([]byte(conf))),
	}
	if png != nil {
		d.NewDevice.QRDataURI = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	}
	if err := s.loadDevices(r, &d); err != nil {
		slog.ErrorContext(r.Context(), "load devices", "error", err)
	}
	s.render(w, r, http.StatusOK, "devices", d)
}

func (s *Server) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := s.pathID(w, r, "/devices")
	if !ok {
		return
	}

	peer, err := s.store.PeerByID(r.Context(), id)
	if err != nil {
		s.setFlash(w, "error", "That device no longer exists.")
		http.Redirect(w, r, "/devices", http.StatusSeeOther)
		return
	}
	if err := s.store.DeletePeer(r.Context(), id); err != nil {
		slog.ErrorContext(r.Context(), "delete peer", "error", err, "id", id)
		s.setFlash(w, "error", "The device could not be deleted.")
		http.Redirect(w, r, "/devices", http.StatusSeeOther)
		return
	}

	s.audit(r, actorOf(sess), store.ActionPeerDelete,
		fmt.Sprintf("deleted device %q at %s", peer.Name, peer.TunnelIP))

	// Deleting a peer cascades to its forwards, so both subsystems have to be
	// re-synced or the kernel keeps DNAT rules pointing into a black hole --
	// a WAN port still open, now aimed at an address nobody owns.
	s.syncKernel(r, "delete device")
	s.reconcileForwards(r, "delete device")
	s.setFlash(w, "ok", fmt.Sprintf("Device %q was deleted.", peer.Name))
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

func (s *Server) handleDeviceToggle(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := s.pathID(w, r, "/devices")
	if !ok {
		return
	}
	enable := r.PostFormValue("enable") == "1"

	if err := s.store.SetPeerEnabled(r.Context(), id, enable); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.setFlash(w, "error", "That device no longer exists.")
		} else {
			slog.ErrorContext(r.Context(), "toggle peer", "error", err, "id", id)
			s.setFlash(w, "error", "The device could not be updated.")
		}
		http.Redirect(w, r, "/devices", http.StatusSeeOther)
		return
	}

	state := "disabled"
	if enable {
		state = "enabled"
	}
	s.audit(r, actorOf(sess), store.ActionPeerUpdate, fmt.Sprintf("%s device %d", state, id))
	s.syncKernel(r, "toggle device")
	s.setFlash(w, "ok", "The device was "+state+".")
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

// --- forwards --------------------------------------------------------------

func (s *Server) handleForwardCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())

	fail := func(msg string) {
		s.setFlash(w, "error", msg)
		http.Redirect(w, r, "/forwards", http.StatusSeeOther)
	}

	f, msg := s.forwardForm(r)
	if msg != "" {
		fail(msg)
		return
	}
	f.Enabled = true

	created, err := s.store.CreateForward(r.Context(), f)
	if err != nil {
		var conflict forward.Conflict
		if errors.As(err, &conflict) {
			fail(conflict.Error() + ".")
			return
		}
		slog.ErrorContext(r.Context(), "create forward", "error", err)
		fail("The forward could not be created.")
		return
	}

	s.audit(r, actorOf(sess), store.ActionFwdCreate,
		fmt.Sprintf("forward %s/%s to %s (%s, filter %s)",
			f.Listen, f.Proto, f.TargetIP, f.SrcMode, f.SrcPolicy))

	s.reconcileForwards(r, "create forward")
	s.setFlash(w, "ok", fmt.Sprintf("Forward %q created on port %s.", created.Label, created.Listen))
	http.Redirect(w, r, "/forwards", http.StatusSeeOther)
}

func (s *Server) handleForwardDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := s.pathID(w, r, "/forwards")
	if !ok {
		return
	}
	f, err := s.store.ForwardByID(r.Context(), id)
	if err != nil {
		s.setFlash(w, "error", "That forward no longer exists.")
		http.Redirect(w, r, "/forwards", http.StatusSeeOther)
		return
	}
	if err := s.store.DeleteForward(r.Context(), id); err != nil {
		slog.ErrorContext(r.Context(), "delete forward", "error", err, "id", id)
		s.setFlash(w, "error", "The forward could not be deleted.")
		http.Redirect(w, r, "/forwards", http.StatusSeeOther)
		return
	}
	s.audit(r, actorOf(sess), store.ActionFwdDelete,
		fmt.Sprintf("deleted forward %s/%s (%q)", f.Listen, f.Proto, f.Label))
	s.reconcileForwards(r, "delete forward")
	s.setFlash(w, "ok", "The forward was deleted.")
	http.Redirect(w, r, "/forwards", http.StatusSeeOther)
}

func (s *Server) handleForwardToggle(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := s.pathID(w, r, "/forwards")
	if !ok {
		return
	}
	enable := r.PostFormValue("enable") == "1"

	if err := s.store.SetForwardEnabled(r.Context(), id, enable); err != nil {
		var conflict forward.Conflict
		switch {
		case errors.As(err, &conflict):
			s.setFlash(w, "error", conflict.Error()+".")
		case errors.Is(err, store.ErrNotFound):
			s.setFlash(w, "error", "That forward no longer exists.")
		default:
			slog.ErrorContext(r.Context(), "toggle forward", "error", err, "id", id)
			s.setFlash(w, "error", "The forward could not be updated.")
		}
		http.Redirect(w, r, "/forwards", http.StatusSeeOther)
		return
	}

	state := "disabled"
	if enable {
		state = "enabled"
	}
	s.audit(r, actorOf(sess), store.ActionFwdToggle, fmt.Sprintf("%s forward %d", state, id))
	s.reconcileForwards(r, "toggle forward")
	s.setFlash(w, "ok", "The forward was "+state+".")
	http.Redirect(w, r, "/forwards", http.StatusSeeOther)
}

// --- helpers ---------------------------------------------------------------

// parsePort validates a port from form input.
//
// strconv.Atoi alone is not enough: a negative number, a value above 65535 or
// zero all parse fine and all produce a rule that does not mean what the
// administrator intended.
func parsePort(raw string) (uint16, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, errors.New("a port number is required")
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errors.New("must be a number")
	}
	if n < 1 || n > 65535 {
		return 0, errors.New("must be between 1 and 65535")
	}
	return uint16(n), nil
}

// pathID reads and validates the {id} path segment.
func (s *Server) pathID(w http.ResponseWriter, r *http.Request, redirectTo string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.setFlash(w, "error", "That request referred to an item that does not exist.")
		http.Redirect(w, r, redirectTo, http.StatusSeeOther)
		return 0, false
	}
	return id, true
}

// actorOf returns the username for the audit log, or empty for an unauthenticated
// request (which should not reach these handlers, but must not panic if it does).
func actorOf(sess *auth.Session) string {
	if sess == nil {
		return ""
	}
	return sess.Username
}

// syncKernel pushes the database's peers into the kernel, reporting failure to
// the operator rather than silently leaving the two disagreeing.
func (s *Server) syncKernel(r *http.Request, what string) {
	if s.wgm == nil {
		return
	}
	if err := s.wgm.Sync(r.Context()); err != nil {
		slog.ErrorContext(r.Context(), "sync wireguard", "after", what, "error", err)
	}
}

// reconcileForwards rebuilds the nftables ruleset.
func (s *Server) reconcileForwards(r *http.Request, what string) {
	if s.rec == nil {
		return
	}
	if err := s.rec.Reconcile(r.Context()); err != nil {
		slog.ErrorContext(r.Context(), "reconcile forwards", "after", what, "error", err)
	}
}

// loadDevices fills in the device list from the joined kernel/database view.
func (s *Server) loadDevices(r *http.Request, d *pageData) error {
	if s.wgm == nil {
		return nil
	}
	snap, err := s.wgm.Snapshot(r.Context(), time.Now())
	if err != nil {
		return err
	}
	d.WGUp = snap.Up
	d.ServerPublicKey = snap.PublicKey
	if snap.Err != nil {
		d.KernelError = snap.Err.Error()
	}
	for _, p := range snap.Peers {
		d.Devices = append(d.Devices, deviceRow{
			ID:            p.ID,
			Name:          p.Name,
			TunnelIP:      p.TunnelIP.String(),
			PublicKey:     p.PublicKey,
			Notes:         p.Notes,
			Enabled:       p.Enabled,
			Presence:      string(p.Presence),
			PresenceLabel: p.PresenceLabel,
			Endpoint:      p.Endpoint,
			LastHandshake: humanSince(p.LastHandshake),
			Rx:            humanBytes(p.RxBytes),
			Tx:            humanBytes(p.TxBytes),
			InKernel:      p.InKernel,
		})
	}
	return nil
}

// humanSince renders a handshake time the way a router panel does.
func humanSince(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t).Truncate(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours())/24)
	}
}

// humanBytes renders a byte counter compactly.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// forwardForm parses and validates the shared create/edit form.
//
// Create and edit accept exactly the same fields, so they parse through one
// function: two parsers drifting apart is how an edit form ends up accepting
// something the create form rejects.
// The second return is a message for the operator, empty when the form is
// valid. It is deliberately not an error: these are sentences shown in the UI,
// and Go's error convention (lowercase, unpunctuated) is the opposite of what
// reads well in a flash message.
func (s *Server) forwardForm(r *http.Request) (store.Forward, string) {
	var f store.Forward

	f.Label = strings.TrimSpace(r.PostFormValue("label"))
	if f.Label == "" {
		return f, "A label is required."
	}
	if len(f.Label) > maxNameLength {
		return f, fmt.Sprintf("The label must be %d characters or fewer.", maxNameLength)
	}

	listen, err := forward.ParsePortRange(r.PostFormValue("listen_port"))
	if err != nil {
		return f, "WAN port: " + err.Error()
	}
	f.Listen = listen

	// A range forwards every port straight through, so a target port would be
	// ignored -- asking for one and then discarding it would be a lie.
	if !listen.IsRange() {
		tp, err := parsePort(r.PostFormValue("target_port"))
		if err != nil {
			return f, "Target port: " + err.Error()
		}
		f.TargetPort = tp
	}

	peerID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("peer_id")), 10, 64)
	if err != nil || peerID <= 0 {
		return f, "Choose a device to forward to."
	}
	peer, err := s.store.PeerByID(r.Context(), peerID)
	if err != nil {
		return f, "That device no longer exists."
	}
	f.TargetPeer = peer.PublicKey
	f.TargetIP = peer.TunnelIP
	f.PeerID = peer.ID

	f.Proto = forward.Proto(r.PostFormValue("proto"))
	f.SrcMode = forward.SrcMode(r.PostFormValue("src_mode"))
	f.RateLimit = r.PostFormValue("rate_limit") == "1"

	f.SrcPolicy = forward.SrcPolicy(r.PostFormValue("src_policy"))
	if f.SrcPolicy == "" {
		f.SrcPolicy = forward.SrcPolicyAny
	}
	sources, err := forward.ParseSources(r.PostFormValue("src_list"))
	if err != nil {
		return f, "Source filter: " + err.Error()
	}
	f.Sources = sources

	if err := f.Rule().Validate(s.plan.Pool); err != nil {
		return f, strings.TrimPrefix(err.Error(), "forward: ")
	}
	return f, ""
}

// --- edit ------------------------------------------------------------------

// handleDeviceUpdate edits a device's name and note.
//
// Only those two fields are editable. The public key is the peer's identity and
// the tunnel address is baked into a client config that was shown once and
// cannot be reissued, so changing either here would silently break a device
// that is working.
func (s *Server) handleDeviceUpdate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := s.pathID(w, r, "/devices")
	if !ok {
		return
	}

	name := strings.TrimSpace(r.PostFormValue("name"))
	notes := strings.TrimSpace(r.PostFormValue("notes"))

	fail := func(msg string) {
		s.setFlash(w, "error", msg)
		http.Redirect(w, r, "/devices?edit="+strconv.FormatInt(id, 10), http.StatusSeeOther)
	}

	if name == "" {
		fail("A device name is required.")
		return
	}
	if len(name) > maxNameLength {
		fail(fmt.Sprintf("The device name must be %d characters or fewer.", maxNameLength))
		return
	}
	if len(notes) > 256 {
		fail("The note must be 256 characters or fewer.")
		return
	}

	if err := s.store.RenamePeer(r.Context(), id, name, notes); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.setFlash(w, "error", "That device no longer exists.")
			http.Redirect(w, r, "/devices", http.StatusSeeOther)
			return
		}
		slog.ErrorContext(r.Context(), "rename peer", "error", err, "id", id)
		fail("The device could not be updated.")
		return
	}

	s.audit(r, actorOf(sess), store.ActionPeerUpdate, fmt.Sprintf("renamed device %d to %q", id, name))
	// No kernel sync: neither field reaches the kernel, and a needless Sync
	// would be a write for nothing.
	s.setFlash(w, "ok", "The device was updated.")
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

// handleForwardUpdate edits a forward.
func (s *Server) handleForwardUpdate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := s.pathID(w, r, "/forwards")
	if !ok {
		return
	}

	editURL := "/forwards?edit=" + strconv.FormatInt(id, 10)
	fail := func(msg string) {
		s.setFlash(w, "error", msg)
		http.Redirect(w, r, editURL, http.StatusSeeOther)
	}

	current, err := s.store.ForwardByID(r.Context(), id)
	if err != nil {
		s.setFlash(w, "error", "That forward no longer exists.")
		http.Redirect(w, r, "/forwards", http.StatusSeeOther)
		return
	}

	updated, msg := s.forwardForm(r)
	if msg != "" {
		fail(msg)
		return
	}
	updated.ID = id
	// Editing does not change whether the forward is enabled; that is what the
	// toggle is for, and conflating them would surprise an operator who only
	// meant to correct a port.
	updated.Enabled = current.Enabled

	if err := s.store.UpdateForward(r.Context(), updated); err != nil {
		var conflict forward.Conflict
		switch {
		case errors.As(err, &conflict):
			fail(conflict.Error() + ".")
		case errors.Is(err, store.ErrNotFound):
			s.setFlash(w, "error", "That forward no longer exists.")
			http.Redirect(w, r, "/forwards", http.StatusSeeOther)
		default:
			slog.ErrorContext(r.Context(), "update forward", "error", err, "id", id)
			fail("The forward could not be updated.")
		}
		return
	}

	s.audit(r, actorOf(sess), store.ActionFwdUpdate,
		fmt.Sprintf("updated forward %d to %s/%s -> %s (%s, filter %s)",
			id, updated.Listen, updated.Proto, updated.TargetIP, updated.SrcMode, updated.SrcPolicy))

	s.reconcileForwards(r, "update forward")
	s.setFlash(w, "ok", fmt.Sprintf("Forward %q was updated.", updated.Label))
	http.Redirect(w, r, "/forwards", http.StatusSeeOther)
}

// editID reads the ?edit= query parameter, returning 0 when absent or invalid.
// An unparseable value simply means "no row is being edited" rather than an
// error page: it can only come from a hand-edited URL.
func editID(r *http.Request) int64 {
	raw := r.URL.Query().Get("edit")
	if raw == "" {
		return 0
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}
