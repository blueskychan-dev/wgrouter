//go:build linux

package forward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Chain names inside our table.
const (
	chainPrerouting  = "prerouting"
	chainPostrouting = "postrouting"
	chainForward     = "forward"
)

// nftFirewall programs rules through netlink.
type nftFirewall struct {
	conn *nftables.Conn

	wanIface string
	wgIface  string

	rateLimit uint64 // new connections per second per forward; 0 disables
	burst     uint32

	// logDrops adds a rate-limited log statement to every drop, feeding the
	// firewall log. Off unless the operator turns it on.
	logDrops bool
}

// SetLogDrops turns firewall logging on or off. The change takes effect on the
// next Apply, which the caller triggers by reconciling.
func (f *nftFirewall) SetLogDrops(on bool) { f.logDrops = on }

// NewFirewall opens a netlink connection to nftables.
//
// rateLimit is the per-forward ceiling on new connections per second, and burst
// how many may arrive at once before it applies. Zero disables rate limiting.
func NewFirewall(wanIface, wgIface string, rateLimit uint64, burst uint32) (Firewall, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("forward: open nftables netlink socket (needs CAP_NET_ADMIN): %w", err)
	}
	return &nftFirewall{
		conn:      c,
		wanIface:  wanIface,
		wgIface:   wgIface,
		rateLimit: rateLimit,
		burst:     burst,
	}, nil
}

func (f *nftFirewall) Close() error {
	if err := f.conn.CloseLasting(); err != nil {
		return fmt.Errorf("forward: close nftables socket: %w", err)
	}
	return nil
}

// Apply replaces the contents of our table with rules for the supplied
// forwards.
//
// The whole thing is one netlink batch: the table is deleted and rebuilt, and
// the kernel applies the batch atomically. There is no window in which the
// router has half a ruleset -- which matters, because the half that exists
// might be the DNAT without the matching filter accept.
//
// Rebuilding resets the packet counters attached to each rule, which is why
// the reconciler only calls Apply when the desired ruleset has actually
// changed. Rebuilding on a timer would zero the connection statistics every
// tick.
func (f *nftFirewall) Apply(ctx context.Context, rules []Rule) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}

	// Delete then recreate. DelTable on a table that does not exist is not an
	// error we care about -- the batch simply recreates it -- and this is the
	// only way to guarantee no stale rule survives from a previous run.
	//
	// Only OUR table is touched. Every other table on the host, including
	// whatever Docker or firewalld has installed, is left exactly alone.
	f.conn.DelTable(table)
	f.conn.Flush() // best effort; a missing table makes this a no-op error we ignore

	table = f.conn.AddTable(table)

	pre := f.conn.AddChain(&nftables.Chain{
		Name:     chainPrerouting,
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		// No policy is set: a nat chain must not drop, and an empty base chain
		// with the default accept simply lets unmatched traffic continue to
		// whatever other tables exist.
	})
	post := f.conn.AddChain(&nftables.Chain{
		Name:     chainPostrouting,
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	fwd := f.conn.AddChain(&nftables.Chain{
		Name:     chainForward,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	// Return traffic first, so replies are not re-evaluated per forward and do
	// not count against any connection-rate limit.
	f.conn.AddRule(&nftables.Rule{
		Table: table, Chain: fwd,
		Exprs: append(ctStateEstablishedRelated(), &expr.Verdict{Kind: expr.VerdictAccept}),
	})

	for _, r := range rules {
		listen := r.Listen.Normalised()
		for _, proto := range r.Transports() {
			l4 := protoNumber(proto)

			// Destination NAT: WAN port(s) -> peer. A range preserves the port,
			// so no proto register is supplied and netfilter leaves it alone.
			dnat := dnatToAddr(r.TargetIP)
			if !listen.IsRange() {
				dnat = dnatTo(r.TargetIP, r.TargetPort)
			}
			f.conn.AddRule(&nftables.Rule{
				Table:    table,
				Chain:    pre,
				UserData: ruleTag(r.ID, roleDNAT),
				Exprs: concat(
					matchIPv4(),
					matchIifname(f.wanIface),
					matchL4Proto(l4),
					matchDportRange(listen),
					[]expr.Any{&expr.Counter{}},
					dnat,
				),
			})

			// Everything below matches post-DNAT, on the way out to the peer.
			match := concat(
				matchIPv4(),
				matchOifname(f.wgIface),
				matchDaddr(r.TargetIP),
				matchL4Proto(l4),
				matchDportRangeAfterDNAT(r, listen),
			)

			// Access control comes first: a source that is not permitted should
			// never reach the rate limiter, let alone the peer.
			f.addACLRules(table, fwd, r, match)

			// Flood protection, if this forward has it enabled. Matching only
			// ct state new means an established transfer is never throttled --
			// only the rate at which new connections are opened.
			if r.RateLimit && f.rateLimit > 0 {
				limitOver := &expr.Limit{
					Type:  expr.LimitTypePkts,
					Rate:  f.rateLimit,
					Unit:  expr.LimitTimeSecond,
					Burst: f.burst,
					Over:  true,
				}
				// A separate, independently rate-limited rule does the logging
				// and falls through without a verdict. Logging every dropped
				// packet during a flood is how a firewall log becomes the
				// second outage.
				if f.logDrops {
					f.conn.AddRule(&nftables.Rule{
						Table:    table,
						Chain:    fwd,
						UserData: ruleTag(r.ID, roleLog),
						Exprs: concat(
							match,
							ctStateNewOnly(),
							[]expr.Any{limitOver, logLimiter(), logPrefix(r.ID, "ratelimit")},
						),
					})
				}
				f.conn.AddRule(&nftables.Rule{
					Table:    table,
					Chain:    fwd,
					UserData: ruleTag(r.ID, roleDrop),
					Exprs: concat(
						match,
						ctStateNewOnly(),
						[]expr.Any{limitOver, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}},
					),
				})
			}

			// Accept the connection, counting it.
			f.conn.AddRule(&nftables.Rule{
				Table:    table,
				Chain:    fwd,
				UserData: ruleTag(r.ID, roleNew),
				Exprs: concat(
					match,
					ctStateNewOnly(),
					[]expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}},
				),
			})

			// Source handling. Only masquerade adds a rule here; direct
			// deliberately leaves the source address alone.
			if r.SrcMode == SrcModeMasquerade {
				f.conn.AddRule(&nftables.Rule{
					Table:    table,
					Chain:    post,
					UserData: ruleTag(r.ID, roleMasq),
					Exprs:    concat(match, []expr.Any{&expr.Masq{}}),
				})
			}
		}
	}

	if err := f.conn.Flush(); err != nil {
		return fmt.Errorf("forward: apply nftables ruleset: %w", err)
	}
	return nil
}

// Verify reads back what the kernel actually holds for each forward, including
// the packet counters.
//
// This is what backs the UI's kernel-state column and the connection figures. A
// forward that exists in the database but not in the kernel is the failure mode
// worth surfacing loudly: the administrator believes a port is open and it is
// not.
func (f *nftFirewall) Verify(ctx context.Context) (map[int64]Counters, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}

	present := map[int64]Counters{}
	for _, chain := range []string{chainPrerouting, chainPostrouting, chainForward} {
		rules, err := f.conn.GetRules(table, &nftables.Chain{Name: chain, Table: table})
		if err != nil {
			// A missing table means nothing has been applied yet, which is a
			// legitimate state rather than a failure.
			if isNoSuchFileOrDir(err) {
				return present, nil
			}
			return nil, fmt.Errorf("forward: read chain %q: %w", chain, err)
		}
		for _, r := range rules {
			id, role, ok := parseRuleTag(r.UserData)
			if !ok {
				continue
			}
			c := present[id]
			c.Rules++

			packets, bytes := counterOf(r)
			switch role {
			case roleNew:
				c.Accepted += packets
			case roleDrop, roleACL:
				c.Dropped += packets
			case roleDNAT:
				c.Bytes += bytes
			}
			present[id] = c
		}
	}
	return present, nil
}

// counterOf extracts the counter attached to a rule, if any.
func counterOf(r *nftables.Rule) (packets, bytes uint64) {
	for _, e := range r.Exprs {
		if c, ok := e.(*expr.Counter); ok {
			return c.Packets, c.Bytes
		}
	}
	return 0, 0
}

// Teardown removes our table entirely, for a clean shutdown.
func (f *nftFirewall) Teardown(ctx context.Context) error {
	f.conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
	if err := f.conn.Flush(); err != nil && !isNoSuchFileOrDir(err) {
		return fmt.Errorf("forward: remove nftables table: %w", err)
	}
	return nil
}

// --- expression helpers ----------------------------------------------------

func concat(groups ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// matchIPv4 restricts a rule in the inet family to IPv4. The tunnel pool is
// IPv4-only, so without this the offsets used by matchDaddr would be read
// against an IPv6 header.
func matchIPv4() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
	}
}

func matchIifname(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
	}
}

func matchOifname(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
	}
}

func matchL4Proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

// matchDport matches the transport-header destination port, which sits at
// offset 2 in both the TCP and the UDP header.
func matchDport(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
	}
}

// matchDaddr matches the IPv4 destination address at offset 16 of the header.
func matchDaddr(addr netip.Addr) []expr.Any {
	v4 := addr.As4()
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: v4[:]},
	}
}

func dnatTo(addr netip.Addr, port uint16) []expr.Any {
	v4 := addr.As4()
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: v4[:]},
		&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      unix.NFPROTO_IPV4,
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	}
}

// Conntrack state bits, as the kernel defines them in
// include/uapi/linux/netfilter/nf_conntrack_common.h:
//
//	enum ip_conntrack_info { IP_CT_ESTABLISHED = 0, IP_CT_RELATED = 1, ... }
//	#define NF_CT_STATE_BIT(ctinfo) (1 << ((ctinfo) % IP_CT_IS_REPLY + 1))
//
// x/sys/unix does not export these, so they are spelled out rather than
// hard-coded as a bare 12 that nobody could check.
const (
	ctStateEstablished = 1 << (0 + 1) // 0x02
	ctStateRelated     = 1 << (1 + 1) // 0x04
	ctStateNew         = 1 << (2 + 1) // 0x08
)

// ctStateEstablishedRelated matches packets belonging to a connection we have
// already accepted.
func ctStateEstablishedRelated() []expr.Any {
	return matchCtState(ctStateEstablished | ctStateRelated)
}

// ctStateNewOnly matches the first packet of a connection. Rate limiting and
// connection counting both key off this: counting every packet would measure
// traffic, not connections, and rate-limiting every packet would throttle
// established transfers rather than connection attempts.
func ctStateNewOnly() []expr.Any {
	return matchCtState(ctStateNew)
}

func matchCtState(mask uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(mask),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	}
}

// ifname renders an interface name as the fixed 16-byte NUL-padded field
// netlink expects.
func ifname(s string) []byte {
	b := make([]byte, 16)
	copy(b, s)
	return b
}

func protoNumber(p Proto) byte {
	if p == ProtoUDP {
		return unix.IPPROTO_UDP
	}
	return unix.IPPROTO_TCP
}

// matchDportRange matches a destination port or an inclusive range.
func matchDportRange(r PortRange) []expr.Any {
	if !r.IsRange() {
		return matchDport(r.Start)
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Range{
			Op:       expr.CmpOpEq,
			Register: 1,
			FromData: binaryutil.BigEndian.PutUint16(r.Start),
			ToData:   binaryutil.BigEndian.PutUint16(r.End),
		},
	}
}

// matchDportRangeAfterDNAT matches the port the packet carries once it has been
// translated. A range passes the port through unchanged, so the same range
// applies; a single-port forward has been rewritten to the target port.
func matchDportRangeAfterDNAT(r Rule, listen PortRange) []expr.Any {
	if listen.IsRange() {
		return matchDportRange(listen)
	}
	return matchDport(r.TargetPort)
}

// dnatToAddr translates the destination address only, leaving the port alone.
// This is what makes a port-range forward predictable: every port arrives at
// the peer as the port it was sent to.
func dnatToAddr(addr netip.Addr) []expr.Any {
	v4 := addr.As4()
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: v4[:]},
		&expr.NAT{
			Type:       expr.NATTypeDestNAT,
			Family:     unix.NFPROTO_IPV4,
			RegAddrMin: 1,
		},
	}
}

// matchSaddr matches an IPv4 source prefix at offset 12 of the header.
func matchSaddr(p netip.Prefix) []expr.Any {
	addr := p.Masked().Addr().As4()
	mask := net.CIDRMask(p.Bits(), 32)
	out := []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
	}
	// A /32 needs no masking step; anything shorter does.
	if p.Bits() != 32 {
		out = append(out, &expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte{mask[0], mask[1], mask[2], mask[3]},
			Xor:            []byte{0, 0, 0, 0},
		})
	}
	return append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr[:]})
}

// addACLRules programs the source access control list for one forward.
//
// Allow and deny are deliberately not symmetrical. "Allow listed only" ends
// with a catch-all drop, so a source nobody thought to list is refused --
// failing closed, which is the whole point of putting an ACL on an
// administrative service. "Deny listed" has no catch-all: it fails open by
// definition, and pretending otherwise would be worse than not offering it.
func (f *nftFirewall) addACLRules(table *nftables.Table, chain *nftables.Chain, r Rule, match []expr.Any) {
	if r.SrcPolicy == SrcPolicyAny || len(r.Sources) == 0 {
		return
	}

	switch r.SrcPolicy {
	case SrcPolicyDeny:
		for _, src := range r.Sources {
			if f.logDrops {
				f.conn.AddRule(&nftables.Rule{
					Table: table, Chain: chain, UserData: ruleTag(r.ID, roleLog),
					Exprs: concat(match, matchSaddr(src), ctStateNewOnly(),
						[]expr.Any{logLimiter(), logPrefix(r.ID, "acl")}),
				})
			}
			f.conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain, UserData: ruleTag(r.ID, roleACL),
				Exprs: concat(match, matchSaddr(src),
					[]expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}),
			})
		}

	case SrcPolicyAllow:
		// Permitted sources jump past the catch-all by being accepted outright.
		// Return traffic is already accepted at the top of the chain, so this
		// only ever sees the forward direction.
		for _, src := range r.Sources {
			f.conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain, UserData: ruleTag(r.ID, roleACLPass),
				Exprs: concat(match, matchSaddr(src),
					[]expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}}),
			})
		}
		if f.logDrops {
			f.conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain, UserData: ruleTag(r.ID, roleLog),
				Exprs: concat(match, ctStateNewOnly(),
					[]expr.Any{logLimiter(), logPrefix(r.ID, "acl")}),
			})
		}
		f.conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain, UserData: ruleTag(r.ID, roleACL),
			Exprs: concat(match, []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}),
		})
	}
}

// logLimiter caps how fast log lines are emitted.
//
// Unlike the connection limiter this is a plain (not "over") limit, so the rule
// matches while under the rate and stops matching above it -- which is exactly
// the behaviour wanted for logging: log the first few, then go quiet. Without
// it a flood would write millions of rows and turn the firewall log into a
// second outage.
func logLimiter() expr.Any {
	return &expr.Limit{
		Type:  expr.LimitTypePkts,
		Rate:  logRatePerSecond,
		Unit:  expr.LimitTimeSecond,
		Burst: logBurst,
	}
}

// logPrefix emits a kernel log line tagged so the reader can find it.
func logPrefix(id int64, reason string) expr.Any {
	return &expr.Log{
		Key:  1 << unix.NFTA_LOG_PREFIX,
		Data: []byte(fmt.Sprintf("%s%d:%s ", LogPrefix, id, reason)),
	}
}

const (
	logRatePerSecond = 5
	logBurst         = 5
)

// Rule roles, recorded in each rule's user data alongside the forward ID so a
// read-back can tell which counter is which.
const (
	roleDNAT    = "dnat"
	roleNew     = "new"
	roleDrop    = "drop"
	roleMasq    = "masq"
	roleACL     = "acl"
	roleACLPass = "aclpass"
	roleLog     = "log"
)

// ruleTag stores the originating forward's ID and the rule's role in the user
// data, so the kernel's rules can be attributed back to database rows on
// read-back. nftables carries user data opaquely and never interprets it.
func ruleTag(id int64, role string) []byte {
	return []byte("wgrouter:" + strconv.FormatInt(id, 10) + ":" + role)
}

func parseRuleTag(data []byte) (id int64, role string, ok bool) {
	const prefix = "wgrouter:"
	s := string(data)
	rest, found := strings.CutPrefix(s, prefix)
	if !found {
		return 0, "", false
	}
	idPart, rolePart, found := strings.Cut(rest, ":")
	if !found {
		return 0, "", false
	}
	id, err := strconv.ParseInt(idPart, 10, 64)
	if err != nil {
		return 0, "", false
	}
	return id, rolePart, true
}

// isNoSuchFileOrDir reports whether err means "our table is not there", which
// is the normal state before the first Apply rather than a failure.
func isNoSuchFileOrDir(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist)
}

var _ Firewall = (*nftFirewall)(nil)
