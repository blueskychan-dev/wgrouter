package wg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"wgrouter/internal/ipam"
	"wgrouter/internal/store"
)

// Manager owns the WireGuard interface: it holds the server key, keeps the
// kernel's peer set equal to the database's, and answers questions about live
// state.
//
// The database is the source of truth and the kernel is derived from it. Sync
// is the one code path that writes peers -- startup, every mutation and the
// periodic timer all call it -- so there is exactly one way the kernel can come
// to disagree with the database, and it self-corrects within the reconcile
// interval. It converges by diffing rather than replacing, because replacing
// would destroy the live sessions of peers that had not changed.
type Manager struct {
	kernel Kernel
	store  *store.Store
	plan   ipam.Plan

	iface string
	port  int
	mtu   int

	// mu serialises Sync against itself. Two concurrent reconciles would each
	// read the kernel, compute a diff and apply it; the later one could be
	// built from an older read of the database and undo the newer.
	mu sync.Mutex

	privateKey wgtypes.Key
	haveKey    bool
}

// NewManager builds a Manager. It does not touch the kernel.
func NewManager(k Kernel, st *store.Store, plan ipam.Plan, iface string, port, mtu int) *Manager {
	return &Manager{kernel: k, store: st, plan: plan, iface: iface, port: port, mtu: mtu}
}

// EnsureServerKey loads the server private key, generating and persisting one
// on first run.
//
// Unlike a peer's key this one must be stored: the interface is rebuilt from it
// on every start, and regenerating it would invalidate every client config ever
// handed out -- silently, since clients would simply fail to handshake with no
// indication why.
func (m *Manager) EnsureServerKey(ctx context.Context) (wgtypes.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.haveKey {
		return m.privateKey, nil
	}

	stored, err := m.store.Setting(ctx, store.SettingServerPrivateKey)
	switch {
	case err == nil:
		key, perr := ParseKey(stored)
		if perr != nil {
			// Refuse to silently replace a key we cannot read. Generating a new
			// one here would look like a successful start while every existing
			// client stopped working.
			return wgtypes.Key{}, fmt.Errorf("wg: stored server private key is corrupt; "+
				"fix or clear %q in the settings table: %w", store.SettingServerPrivateKey, perr)
		}
		m.privateKey, m.haveKey = key, true
		return key, nil

	case errors.Is(err, store.ErrNotFound):
		key, gerr := GenerateKey()
		if gerr != nil {
			return wgtypes.Key{}, gerr
		}
		if err := m.store.SetSetting(ctx, store.SettingServerPrivateKey, key.String()); err != nil {
			return wgtypes.Key{}, err
		}
		if err := m.store.SetSetting(ctx, store.SettingServerPublicKey, key.PublicKey().String()); err != nil {
			return wgtypes.Key{}, err
		}
		slog.InfoContext(ctx, "generated WireGuard server key", "public_key", key.PublicKey().String())
		m.privateKey, m.haveKey = key, true
		return key, nil

	default:
		return wgtypes.Key{}, err
	}
}

// PublicKey returns the server's public key, loading the private key if needed.
func (m *Manager) PublicKey(ctx context.Context) (string, error) {
	k, err := m.EnsureServerKey(ctx)
	if err != nil {
		return "", err
	}
	return k.PublicKey().String(), nil
}

// Sync makes the kernel match the database: the link exists and is addressed
// and up, and its peer set is exactly the enabled peers we have stored.
//
// The peer set is reconciled as a diff, not a replace. Removing a peer destroys
// its kernel object -- session keys, learned endpoint, byte counters -- so
// re-adding an identical peer silently drops a working tunnel and forces a new
// handshake. Doing that on a 60-second timer would disconnect every client
// every minute, which presents as an unstable VPN with no obvious cause. So an
// unchanged peer is left strictly alone, and a reconcile that finds nothing to
// do performs no kernel write at all.
func (m *Manager) Sync(ctx context.Context) error {
	key, err := m.EnsureServerKey(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	serverPrefix := netip.PrefixFrom(m.plan.ServerIP, m.plan.Pool.Bits())
	if err := m.kernel.EnsureLink(ctx, m.iface, serverPrefix, m.mtu); err != nil {
		return err
	}

	peers, err := m.store.Peers(ctx)
	if err != nil {
		return err
	}
	desired := m.desiredPeers(ctx, peers)

	// Read what the kernel actually has, so the diff is against reality rather
	// than against what we last asked for.
	var actual map[wgtypes.Key]PeerState
	dev, err := m.kernel.Device(ctx, m.iface)
	switch {
	case err == nil:
		actual = make(map[wgtypes.Key]PeerState, len(dev.Peers))
		for _, p := range dev.Peers {
			pub, perr := ParseKey(p.PublicKey)
			if perr != nil {
				continue
			}
			actual[pub] = p
		}
	case errors.Is(err, ErrNoDevice):
		// EnsureLink just created it; treat as empty.
		actual = map[wgtypes.Key]PeerState{}
	default:
		return err
	}

	cfg := diffPeers(desired, actual)

	// The device key and port are set only when they differ, for the same
	// reason: rewriting the private key resets every session on the interface.
	if dev == nil || dev.PublicKey != key.PublicKey().String() {
		k := key
		cfg.PrivateKey = &k
	}
	if dev == nil || dev.ListenPort != m.port {
		p := m.port
		cfg.ListenPort = &p
	}

	if cfg.Empty() {
		return nil
	}
	slog.DebugContext(ctx, "reconciling wireguard peers",
		"upsert", len(cfg.Upsert), "remove", len(cfg.Remove))
	return m.kernel.ConfigureDevice(ctx, m.iface, cfg)
}

// desiredPeers converts stored peers into the specs the kernel should hold.
func (m *Manager) desiredPeers(ctx context.Context, peers []store.Peer) map[wgtypes.Key]PeerSpec {
	desired := make(map[wgtypes.Key]PeerSpec, len(peers))
	for _, p := range peers {
		if !p.Enabled {
			// A disabled peer is removed from the kernel but keeps its database
			// row and its address. Disabling has to actually stop the device
			// connecting, or the toggle is decorative.
			continue
		}
		pub, err := ParseKey(p.PublicKey)
		if err != nil {
			// One unreadable row must not stop every other peer being
			// configured; log it and carry on.
			slog.WarnContext(ctx, "skipping peer with unparseable public key",
				"peer", p.Name, "id", p.ID, "error", err)
			continue
		}
		spec := PeerSpec{
			PublicKey:  pub,
			AllowedIPs: []netip.Prefix{ipam.HostPrefix(p.TunnelIP)},
		}
		if p.PresharedKey != "" {
			psk, err := ParseKey(p.PresharedKey)
			if err != nil {
				slog.WarnContext(ctx, "peer has an unreadable preshared key; configuring without it",
					"peer", p.Name, "id", p.ID, "error", err)
			} else {
				spec.PresharedKey = psk
			}
		}
		desired[pub] = spec
	}
	return desired
}

// diffPeers computes the minimal change that makes actual equal desired.
func diffPeers(desired map[wgtypes.Key]PeerSpec, actual map[wgtypes.Key]PeerState) DeviceConfig {
	var cfg DeviceConfig

	for pub, spec := range desired {
		have, ok := actual[pub]
		if !ok {
			cfg.Upsert = append(cfg.Upsert, spec)
			continue
		}
		if !peerMatches(spec, have) {
			cfg.Upsert = append(cfg.Upsert, spec)
		}
	}
	for pub := range actual {
		if _, ok := desired[pub]; !ok {
			cfg.Remove = append(cfg.Remove, pub)
		}
	}

	// Deterministic order, so a reconcile is reproducible and testable.
	slices.SortFunc(cfg.Upsert, func(a, b PeerSpec) int {
		return strings.Compare(a.PublicKey.String(), b.PublicKey.String())
	})
	slices.SortFunc(cfg.Remove, func(a, b wgtypes.Key) int {
		return strings.Compare(a.String(), b.String())
	})
	return cfg
}

// peerMatches reports whether the kernel's peer already matches the spec.
func peerMatches(spec PeerSpec, have PeerState) bool {
	if spec.PresharedKey != have.PresharedKey {
		return false
	}
	if len(spec.AllowedIPs) != len(have.AllowedIPs) {
		return false
	}
	want := make([]string, 0, len(spec.AllowedIPs))
	for _, p := range spec.AllowedIPs {
		want = append(want, p.String())
	}
	got := append([]string(nil), have.AllowedIPs...)
	slices.Sort(want)
	slices.Sort(got)
	return slices.Equal(want, got)
}

// DevicePeer is a stored peer joined with its live kernel state.
type DevicePeer struct {
	store.Peer

	Presence      Presence
	PresenceLabel string
	Endpoint      string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64

	// InKernel reports whether the kernel actually knows about this peer. An
	// enabled peer that is missing from the kernel means the database and the
	// kernel have diverged, which the UI surfaces rather than hides.
	InKernel bool
}

// Snapshot is the joined view the UI renders.
type Snapshot struct {
	Interface  string
	PublicKey  string
	ListenPort int
	Peers      []DevicePeer

	// Up reports whether the interface exists in the kernel at all.
	Up bool

	// Err carries a kernel read failure. The UI shows stored peers with unknown
	// live state rather than an empty page, because "the database has three
	// devices but the kernel cannot be read" is far more useful than "no
	// devices".
	Err error
}

// Snapshot reads live kernel state and joins it with the database.
func (m *Manager) Snapshot(ctx context.Context, now time.Time) (Snapshot, error) {
	peers, err := m.store.Peers(ctx)
	if err != nil {
		return Snapshot{}, err
	}

	snap := Snapshot{Interface: m.iface, ListenPort: m.port}
	if pub, err := m.PublicKey(ctx); err == nil {
		snap.PublicKey = pub
	}

	live := map[string]PeerState{}
	dev, err := m.kernel.Device(ctx, m.iface)
	switch {
	case err == nil:
		snap.Up = true
		snap.PublicKey = dev.PublicKey
		snap.ListenPort = dev.ListenPort
		for _, p := range dev.Peers {
			live[p.PublicKey] = p
		}
	case errors.Is(err, ErrNoDevice):
		// Not an error worth failing the page for: before the first Sync, or
		// after someone removes the link by hand, this is simply the state.
		snap.Up = false
	default:
		snap.Err = err
	}

	for _, p := range peers {
		dp := DevicePeer{Peer: p, Presence: PresenceNever}
		if ls, ok := live[p.PublicKey]; ok {
			dp.InKernel = true
			dp.Endpoint = ls.Endpoint
			dp.LastHandshake = ls.LastHandshake
			dp.RxBytes = ls.RxBytes
			dp.TxBytes = ls.TxBytes
			dp.Presence = ls.Presence(now)
		}
		dp.PresenceLabel = dp.Presence.Label()
		snap.Peers = append(snap.Peers, dp)
	}
	return snap, nil
}

// StartReconciler re-syncs periodically, so that state drift -- someone running
// `wg set` by hand, a link removed and recreated -- converges without needing a
// restart.
func (m *Manager) StartReconciler(ctx context.Context, every time.Duration, done <-chan struct{}) {
	if every <= 0 {
		every = 60 * time.Second
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if err := m.Sync(ctx); err != nil {
					slog.ErrorContext(ctx, "periodic wireguard reconcile failed", "error", err)
				}
			}
		}
	}()
}
