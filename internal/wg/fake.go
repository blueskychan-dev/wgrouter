package wg

import (
	"context"
	"net/netip"
	"sync"
)

// FakeKernel is an in-memory Kernel for tests. It records what was asked of it
// so assertions can be made about the calls, not just the outcome.
//
// It lives in the non-test build so that packages above this one can use it in
// their own tests without wgrouter exporting a test-only build tag.
type FakeKernel struct {
	mu sync.Mutex

	// Links maps interface name to the address it was given.
	Links map[string]netip.Prefix
	// Configs holds the last configuration applied to each interface.
	Configs map[string]DeviceConfig
	// Devices is what Device returns; absent means ErrNoDevice.
	Devices map[string]*DeviceState

	// EnsureLinkErr, ConfigureErr and DeviceErr force failures.
	EnsureLinkErr error
	ConfigureErr  error
	DeviceErr     error

	// Counters for assertions.
	EnsureLinkCalls int
	ConfigureCalls  int
	Closed          bool
}

// NewFakeKernel returns an initialised fake.
func NewFakeKernel() *FakeKernel {
	return &FakeKernel{
		Links:   map[string]netip.Prefix{},
		Configs: map[string]DeviceConfig{},
		Devices: map[string]*DeviceState{},
	}
}

func (f *FakeKernel) EnsureLink(ctx context.Context, name string, addr netip.Prefix, mtu int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.EnsureLinkCalls++
	if f.EnsureLinkErr != nil {
		return f.EnsureLinkErr
	}
	f.Links[name] = addr
	return nil
}

func (f *FakeKernel) ConfigureDevice(ctx context.Context, name string, cfg DeviceConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ConfigureCalls++
	if f.ConfigureErr != nil {
		return f.ConfigureErr
	}
	f.Configs[name] = cfg

	// Apply the change to readable device state the way the real kernel does:
	// upserts modify in place and preserve everything else about the peer,
	// removals destroy it. Getting this right in the fake is what lets a test
	// prove that an unchanged peer keeps its session.
	d, ok := f.Devices[name]
	if !ok {
		d = &DeviceState{Name: name}
		f.Devices[name] = d
	}
	if cfg.PrivateKey != nil {
		d.PublicKey = cfg.PrivateKey.PublicKey().String()
	}
	if cfg.ListenPort != nil {
		d.ListenPort = *cfg.ListenPort
	}

	for _, p := range cfg.Upsert {
		allowed := make([]string, 0, len(p.AllowedIPs))
		for _, a := range p.AllowedIPs {
			allowed = append(allowed, a.String())
		}
		idx := -1
		for i := range d.Peers {
			if d.Peers[i].PublicKey == p.PublicKey.String() {
				idx = i
				break
			}
		}
		if idx < 0 {
			d.Peers = append(d.Peers, PeerState{
				PublicKey:    p.PublicKey.String(),
				AllowedIPs:   allowed,
				PresharedKey: p.PresharedKey,
			})
			continue
		}
		// Modify in place: endpoint, handshake and counters survive.
		d.Peers[idx].AllowedIPs = allowed
		d.Peers[idx].PresharedKey = p.PresharedKey
	}

	for _, pub := range cfg.Remove {
		for i := range d.Peers {
			if d.Peers[i].PublicKey == pub.String() {
				d.Peers = append(d.Peers[:i], d.Peers[i+1:]...)
				break
			}
		}
	}
	return nil
}

func (f *FakeKernel) Device(ctx context.Context, name string) (*DeviceState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.DeviceErr != nil {
		return nil, f.DeviceErr
	}
	d, ok := f.Devices[name]
	if !ok {
		return nil, ErrNoDevice
	}
	return d, nil
}

func (f *FakeKernel) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Closed = true
	return nil
}

// LastConfig returns the most recent configuration applied to name.
func (f *FakeKernel) LastConfig(name string) (DeviceConfig, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.Configs[name]
	return c, ok
}

// SetPeerState overrides live state for one peer, for presence tests.
func (f *FakeKernel) SetPeerState(iface string, ps PeerState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.Devices[iface]
	if !ok {
		d = &DeviceState{Name: iface}
		f.Devices[iface] = d
	}
	for i := range d.Peers {
		if d.Peers[i].PublicKey == ps.PublicKey {
			d.Peers[i] = ps
			return
		}
	}
	d.Peers = append(d.Peers, ps)
}

var _ Kernel = (*FakeKernel)(nil)
