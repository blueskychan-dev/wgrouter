//go:build linux

package wg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DefaultMTU is the interface MTU for a WireGuard link.
//
// 1420 = 1500 (Ethernet) - 20 (outer IPv4) - 8 (UDP) - 32 (WireGuard header
// and Poly1305 tag). Getting this wrong does not fail loudly: the tunnel comes
// up, small packets work, and large ones silently vanish when something in the
// path refuses to fragment. That failure looks like "TLS handshakes hang" and
// costs hours to track down, which is why it is a named constant and not a
// value someone can tune casually.
const DefaultMTU = 1420

// linuxKernel implements Kernel against real netlink.
type linuxKernel struct {
	ctrl *wgctrl.Client
}

// NewKernel opens the netlink sockets. The caller must Close it.
func NewKernel() (Kernel, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wg: open wireguard netlink socket (is the wireguard module loaded, and do we hold CAP_NET_ADMIN?): %w", err)
	}
	return &linuxKernel{ctrl: c}, nil
}

func (k *linuxKernel) Close() error {
	if err := k.ctrl.Close(); err != nil {
		return fmt.Errorf("wg: close netlink socket: %w", err)
	}
	return nil
}

// EnsureLink creates the interface if needed, addresses it and brings it up.
//
// Every step is idempotent, because this runs on every startup and must
// converge whether the link is absent, half-configured, or already correct.
func (k *linuxKernel) EnsureLink(ctx context.Context, name string, addr netip.Prefix, mtu int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		var missing netlink.LinkNotFoundError
		if !errors.As(err, &missing) {
			return fmt.Errorf("wg: look up link %q: %w", name, err)
		}
		attrs := netlink.NewLinkAttrs()
		attrs.Name = name
		attrs.MTU = mtu
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
			if errors.Is(err, os.ErrPermission) {
				return fmt.Errorf("wg: create link %q: permission denied; wgrouter needs CAP_NET_ADMIN: %w", name, err)
			}
			return fmt.Errorf("wg: create link %q: %w", name, err)
		}
		if link, err = netlink.LinkByName(name); err != nil {
			return fmt.Errorf("wg: look up link %q after creating it: %w", name, err)
		}
	}

	// Refuse to touch a pre-existing interface of some other type. Taking over
	// an unrelated link and assigning it our tunnel address would be a
	// destructive surprise on a host where the name happens to collide.
	if got := link.Type(); got != "wireguard" {
		return fmt.Errorf("wg: link %q already exists and is a %q, not a wireguard interface; "+
			"choose a different -wg-interface name", name, got)
	}

	if link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("wg: set MTU on %q: %w", name, err)
		}
	}

	if err := k.ensureAddr(link, addr); err != nil {
		return err
	}

	if link.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("wg: bring up %q: %w", name, err)
		}
	}
	return nil
}

// ensureAddr gives the link exactly the address we want, removing any other
// address we previously put there.
//
// Replacing rather than merely adding matters when -tunnel-pool changes: the
// stale address would otherwise linger and keep attracting traffic for a subnet
// we no longer serve.
func (k *linuxKernel) ensureAddr(link netlink.Link, want netip.Prefix) error {
	name := link.Attrs().Name

	family := netlink.FAMILY_V4
	if want.Addr().Is6() {
		family = netlink.FAMILY_V6
	}
	existing, err := netlink.AddrList(link, family)
	if err != nil {
		return fmt.Errorf("wg: list addresses on %q: %w", name, err)
	}

	wantAddr, err := netlink.ParseAddr(want.String())
	if err != nil {
		return fmt.Errorf("wg: parse address %q: %w", want, err)
	}

	found := false
	for i := range existing {
		if existing[i].Equal(*wantAddr) {
			found = true
			continue
		}
		// Only remove addresses inside the link's own scope. A link-local
		// address is the kernel's business, not ours.
		if existing[i].IP.IsLinkLocalUnicast() {
			continue
		}
		if err := netlink.AddrDel(link, &existing[i]); err != nil {
			return fmt.Errorf("wg: remove stale address %s from %q: %w", existing[i].IPNet, name, err)
		}
	}
	if !found {
		if err := netlink.AddrAdd(link, wantAddr); err != nil {
			return fmt.Errorf("wg: add address %s to %q: %w", want, name, err)
		}
	}
	return nil
}

// ConfigureDevice applies a set of changes to the device.
//
// ReplacePeers is deliberately never set. It tells the kernel to remove every
// peer before adding the supplied list, which destroys the session state of
// peers that are merely unchanged -- dropping live tunnels on every reconcile.
// Removals are explicit instead, so only a peer that should genuinely go away
// loses its session.
func (k *linuxKernel) ConfigureDevice(ctx context.Context, name string, cfg DeviceConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	peers := make([]wgtypes.PeerConfig, 0, len(cfg.Upsert)+len(cfg.Remove))
	for _, p := range cfg.Upsert {
		allowed := make([]net.IPNet, 0, len(p.AllowedIPs))
		for _, a := range p.AllowedIPs {
			allowed = append(allowed, *netipToIPNet(a))
		}
		pc := wgtypes.PeerConfig{
			PublicKey: p.PublicKey,
			// Replace rather than merge. A peer's allowed IPs are its
			// authorisation to use an address; merging would let a stale entry
			// keep permission we have since revoked. This modifies the peer in
			// place and does not disturb its session.
			ReplaceAllowedIPs: true,
			AllowedIPs:        allowed,
		}
		if p.PresharedKey != (wgtypes.Key{}) {
			psk := p.PresharedKey
			pc.PresharedKey = &psk
		}
		peers = append(peers, pc)
	}
	for _, pub := range cfg.Remove {
		peers = append(peers, wgtypes.PeerConfig{PublicKey: pub, Remove: true})
	}

	wcfg := wgtypes.Config{
		PrivateKey: cfg.PrivateKey,
		ListenPort: cfg.ListenPort,
		Peers:      peers,
	}

	if err := k.ctrl.ConfigureDevice(name, wcfg); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("wg: configure %q: permission denied; wgrouter needs CAP_NET_ADMIN: %w", name, err)
		}
		return fmt.Errorf("wg: configure %q: %w", name, err)
	}
	return nil
}

// Device reads live kernel state.
func (k *linuxKernel) Device(ctx context.Context, name string) (*DeviceState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := k.ctrl.Device(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoDevice
		}
		return nil, fmt.Errorf("wg: read device %q: %w", name, err)
	}

	out := &DeviceState{
		Name:       d.Name,
		PublicKey:  d.PublicKey.String(),
		ListenPort: d.ListenPort,
		Peers:      make([]PeerState, 0, len(d.Peers)),
	}
	for _, p := range d.Peers {
		ps := PeerState{
			PublicKey:     p.PublicKey.String(),
			LastHandshake: p.LastHandshakeTime,
			RxBytes:       p.ReceiveBytes,
			TxBytes:       p.TransmitBytes,
			PresharedKey:  p.PresharedKey,
		}
		if p.Endpoint != nil {
			ps.Endpoint = p.Endpoint.String()
		}
		for _, a := range p.AllowedIPs {
			ps.AllowedIPs = append(ps.AllowedIPs, a.String())
		}
		out.Peers = append(out.Peers, ps)
	}
	return out, nil
}

// netipToIPNet converts a netip.Prefix to the net.IPNet wgctrl expects.
func netipToIPNet(p netip.Prefix) *net.IPNet {
	addr := p.Addr()
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return &net.IPNet{
		IP:   addr.AsSlice(),
		Mask: net.CIDRMask(p.Bits(), bits),
	}
}

var _ Kernel = (*linuxKernel)(nil)
