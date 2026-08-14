// Package wg manages the WireGuard interface: creating the link, holding the
// server key, pushing peers into the kernel and reading live state back out.
//
// Everything here goes through netlink. wgrouter never shells out to `wg` or
// `ip`: passing user-supplied values to a shell running with CAP_NET_ADMIN is a
// remote code execution waiting to happen, and CLI output formats change
// between versions in ways that break parsers silently.
//
// The kernel-touching half sits behind the Kernel interface so the rest of the
// package -- and everything above it -- is testable without root or a real
// network namespace.
package wg

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// HandshakeTimeout is how long after its last handshake a peer is still
// considered online.
//
// WireGuard has no connection: there is nothing to be "disconnected" from. A
// peer that has traffic to send rekeys at least every 120s, and a peer with
// PersistentKeepalive set sends every 25s. 180s is comfortably past both, so a
// peer that has gone quiet for longer is genuinely not there -- while a peer
// that is simply idle between keepalives is not misreported as gone.
const HandshakeTimeout = 180 * time.Second

// Presence is a peer's derived connection state. It is derived from the last
// handshake time, never reported by the peer itself.
type Presence string

const (
	// PresenceOnline means a handshake happened within HandshakeTimeout.
	PresenceOnline Presence = "online"
	// PresenceIdle means the peer has handshaked at some point, but not
	// recently. It is not an error state: a phone with the tunnel up but the
	// screen off looks exactly like this.
	PresenceIdle Presence = "idle"
	// PresenceNever means the peer has never completed a handshake. Usually the
	// config has not been imported yet.
	PresenceNever Presence = "never"
)

// Label renders a Presence for the UI.
//
// Deliberately absent: "disconnected". A peer with no recent handshake has not
// dropped a connection, because there was never a connection to drop -- and
// telling an administrator their peer is "disconnected" when it is a laptop
// that is merely asleep sends them debugging a problem that does not exist.
func (p Presence) Label() string {
	switch p {
	case PresenceOnline:
		return "Online"
	case PresenceIdle:
		return "Idle"
	default:
		return "Never connected"
	}
}

// PresenceOf derives a peer's state from its last handshake.
func PresenceOf(lastHandshake time.Time, now time.Time) Presence {
	if lastHandshake.IsZero() {
		return PresenceNever
	}
	if now.Sub(lastHandshake) < HandshakeTimeout {
		return PresenceOnline
	}
	return PresenceIdle
}

// PeerSpec is a peer as we want it to exist in the kernel. It is built from
// the database, never from the kernel.
type PeerSpec struct {
	PublicKey    wgtypes.Key
	PresharedKey wgtypes.Key
	// AllowedIPs is what traffic the server will route to this peer. For a
	// client peer this is exactly its own tunnel address -- a /32. Anything
	// wider would let one client claim another's address, because WireGuard's
	// cryptokey routing treats AllowedIPs as authorisation, not just a route.
	AllowedIPs []netip.Prefix
}

// PeerState is live kernel state for one peer.
type PeerState struct {
	PublicKey     string
	Endpoint      string
	AllowedIPs    []string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64

	// PresharedKey is read back so the reconciler can tell an unchanged peer
	// from one that needs updating without touching its session.
	PresharedKey wgtypes.Key
}

// Presence derives this peer's state as of now.
func (p PeerState) Presence(now time.Time) Presence {
	return PresenceOf(p.LastHandshake, now)
}

// DeviceState is live kernel state for the interface.
type DeviceState struct {
	Name       string
	PublicKey  string
	ListenPort int
	Peers      []PeerState
}

// DeviceConfig is a set of changes to apply to the interface.
//
// It is deliberately NOT a full desired state. Removing a peer destroys its
// kernel object, and with it the live session: negotiated keys, the learned
// endpoint and the byte counters all go. Re-adding an identical peer therefore
// drops a working tunnel and forces a fresh handshake. A reconciler that
// replaced the whole peer set on a timer would disconnect every client on
// every tick, so Sync computes a diff and sends only what actually changed.
type DeviceConfig struct {
	// PrivateKey and ListenPort are applied only when non-nil, so an unchanged
	// reconcile does not rewrite them.
	PrivateKey *wgtypes.Key
	ListenPort *int

	// Upsert are peers to add or modify. Modifying an existing peer preserves
	// its session; only removal destroys it.
	Upsert []PeerSpec

	// Remove are the public keys of peers that should no longer exist.
	Remove []wgtypes.Key
}

// Empty reports whether applying this config would change nothing, so the
// caller can skip the netlink round trip entirely.
func (c DeviceConfig) Empty() bool {
	return c.PrivateKey == nil && c.ListenPort == nil && len(c.Upsert) == 0 && len(c.Remove) == 0
}

// Kernel is the netlink surface wgrouter needs. Implemented by linuxKernel
// against real netlink, and by a fake in tests.
type Kernel interface {
	// EnsureLink creates the WireGuard link if it does not exist, gives it the
	// supplied address, and brings it up. It is idempotent.
	EnsureLink(ctx context.Context, name string, addr netip.Prefix, mtu int) error

	// ConfigureDevice replaces the device's key, port and peer set.
	ConfigureDevice(ctx context.Context, name string, cfg DeviceConfig) error

	// Device reads live state. It returns ErrNoDevice if the link is absent.
	Device(ctx context.Context, name string) (*DeviceState, error)

	// Close releases the netlink sockets.
	Close() error
}

// ErrNoDevice is returned when the WireGuard interface does not exist.
var ErrNoDevice = fmt.Errorf("wg: device does not exist")

// GenerateKey returns a new WireGuard private key.
func GenerateKey() (wgtypes.Key, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("wg: generate private key: %w", err)
	}
	return k, nil
}

// GeneratePresharedKey returns a new symmetric preshared key.
//
// The preshared key is an optional extra layer mixed into the handshake. It
// guards against a future adversary who has recorded the traffic and later
// acquires a quantum computer capable of breaking Curve25519; without it, such
// an adversary could decrypt the recorded session retroactively.
func GeneratePresharedKey() (wgtypes.Key, error) {
	k, err := wgtypes.GenerateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("wg: generate preshared key: %w", err)
	}
	return k, nil
}

// ParseKey decodes a base64 WireGuard key.
func ParseKey(s string) (wgtypes.Key, error) {
	k, err := wgtypes.ParseKey(s)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("wg: parse key: %w", err)
	}
	return k, nil
}
