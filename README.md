# wgrouter

A single-binary WireGuard router control panel. It manages a WireGuard
interface and its peers, forwards WAN ports to peers inside the tunnel, and
presents all of it through a web UI styled after a HUMAX consumer router admin
panel.

Everything is done over netlink. wgrouter never shells out to `wg`, `ip`,
`nft` or `iptables`: passing user-supplied values to a shell as root is a
remote code execution waiting to happen, and parsing CLI output breaks silently
across versions.

## Status

Under construction, milestone by milestone.

| Milestone | State |
|---|---|
| 1. Design extraction (`docs/DESIGN.md`, `tokens.css`) | done |
| 2. Skeleton: config, store, migrations, auth, styled shell | done |
| 3. Read-only WireGuard: `internal/wg`, status, device list, SSE | done |
| 4. Provisioning: IPAM, add/remove device, config + QR | done |
| 5. Forwarding: nftables reconciler, masquerade and direct | done |
| 6. Source preservation: direct mode, connectivity test | partial |
| 7. Router status, diagnostics, connection statistics | done |

Milestone 6 is partial: `masquerade` and `direct` are implemented and
programmed into the kernel. Outstanding are the direct-mode connectivity test
and the per-forward connection log.

**Direct mode has a client-side prerequisite.** The peer only replies through
the tunnel for addresses inside its own `AllowedIPs`. The default is the tunnel
pool, which does *not* include arbitrary internet clients — so a direct-mode
forward will accept the connection and then hang. Give such peers
`-client-allowed-ips 0.0.0.0/0`, or the specific source ranges they must answer.

The screens for unfinished work render, are navigable, and say plainly what is
not wired up yet.

## What it does now

- Generates and persists the WireGuard server key on first run, creates and
  addresses the interface over netlink, and brings it up.
- Adds a device: generates its keypair and preshared key, allocates the lowest
  free tunnel address, pushes the peer to the kernel, and renders the client
  config and a QR code **once**. The private key is never stored.
- Lists devices with live handshake state, endpoint and byte counters, streamed
  over SSE. A peer is *online*, *idle* or *never connected* — never
  "disconnected", because there is no connection to drop.
- Forwards a WAN port to a peer, programming `inet wgrouter` and nothing else,
  then reading the ruleset back so the UI reports what the kernel actually has
  rather than what was requested.
- Reconciles both subsystems from the database on startup, after every change,
  and every 60 seconds, so hand-edited kernel state converges back. Both
  reconcilers diff rather than rebuild: replacing a WireGuard peer destroys its
  live session, and replacing an nftables rule resets its counters.
- Reports the router's own health — processor, memory, load, uptime, kernel and
  Go versions — read from procfs, never by shelling out to `top` or `free`.
- Counts connections through each forward from the kernel's own counters, over
  7 days, 30 days and all time, separating accepted from dropped.
- Rate-limits new connections per forward as basic flood protection
  (`-forward-rate-limit`, default 50/s with a burst of 100).
- Ships a diagnostics console: ping, traceroute, DNS lookup and TCP port check.
  The command set is closed and every tool is a Go socket call, so the target
  field cannot become a command.

## Build

Requires Go 1.25 or newer.

```sh
make build          # development build
make release        # static, stripped, CGO_ENABLED=0
make check          # go vet + staticcheck + tests
make race           # tests under the race detector
make integration    # tests needing root and real netlink (build-tagged, off by default)
```

The SQLite driver is `modernc.org/sqlite`, which is pure Go, so the release
build is a genuinely static binary with no cgo and no shared library
dependencies.

## Run

For a foreground run, use `run.sh` — it rebuilds when sources are newer than
the binary, acquires CAP_NET_ADMIN via sudo if the shell does not already hold
it, and passes signals straight through so Ctrl-C shuts down cleanly:

```sh
./run.sh                                   # detects the public address
PUBLIC_ENDPOINT=vpn.example.com ./run.sh   # skip the lookup
LISTEN=10.10.0.1:8080 ./run.sh             # bind inside the tunnel
```

With `PUBLIC_ENDPOINT` unset, `run.sh` asks a public API what this host looks
like from outside — `checkip.amazonaws.com`, then `api.ipify.org`, then
`icanhazip.com`, overridable with `IP_LOOKUP_URLS`. The answer is validated as
a routable unicast IPv4 address before use: it becomes the `Endpoint` in every
client config handed out, so a captive portal or a service returning HTML must
not be able to bake a dead endpoint into them.

This is a request to a third party, which the script says out loud. The daemon
itself never makes it — a router that needs an external service to reach before
it can start is a router that does not come back after a power cut.

Overridable: `PUBLIC_ENDPOINT`, `LISTEN`, `DB`, `LOG_LEVEL`, `WG_INTERFACE`,
`WG_LISTEN_PORT`, `TUNNEL_POOL`, `CLIENT_ALLOWED_IPS`, `TLS_CERT`, `TLS_KEY`.

Or invoke the binary directly. The only required setting is the public endpoint:

```sh
wgrouter -public-endpoint vpn.example.com
```

On first start it creates its database, applies migrations, and refuses to
serve anything but the setup wizard until an administrator account exists.

Every flag has a `WGROUTER_`-prefixed environment equivalent. Precedence is
flag > environment > default.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-public-endpoint` | `WGROUTER_PUBLIC_ENDPOINT` | **required** | Host peers dial. Cannot be auto-detected; see below. |
| `-wg-interface` | `WGROUTER_WG_INTERFACE` | `wg0` | Interface wgrouter creates and owns |
| `-wg-listen-port` | `WGROUTER_WG_LISTEN_PORT` | `51820` | WireGuard UDP port |
| `-tunnel-pool` | `WGROUTER_TUNNEL_POOL` | `10.10.0.0/24` | Peer address pool; the first usable address is the server's |
| `-client-dns` | `WGROUTER_CLIENT_DNS` | unset | Written into client configs; omitted when unset |
| `-client-allowed-ips` | `WGROUTER_CLIENT_ALLOWED_IPS` | the tunnel pool | `AllowedIPs` for generated client configs |
| `-wan-interface` | `WGROUTER_WAN_INTERFACE` | autodetected | Interface holding the default route |
| `-listen` | `WGROUTER_LISTEN` | the WireGuard interface IP | Admin UI address |
| `-tls-cert` / `-tls-key` | `WGROUTER_TLS_CERT` / `_KEY` | unset | Serve HTTPS |
| `-db` | `WGROUTER_DB` | `/var/lib/wgrouter/wgrouter.db` | SQLite path |
| `-log-level` | `WGROUTER_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `-forward-rate-limit` | `WGROUTER_FORWARD_RATE_LIMIT` | `50` | Max new connections per second per forward; `0` disables |
| `-forward-burst` | `WGROUTER_FORWARD_BURST` | `100` | How many may arrive at once before the limit applies |

### Why the public endpoint has no default

On a NAT'd cloud instance the public address is never present on a local
interface — the provider maps it externally. Anything derived from the routing
table would be the *private* address, and client configs built from it would
silently never connect. So wgrouter refuses to start without being told.

For the same reason, a port forward can be correct in the kernel and still
unreachable: the provider's own firewall (an OCI security list, an AWS security
group) has to allow the port too.

## Required capability

wgrouter needs `CAP_NET_ADMIN` to create the WireGuard interface, configure
peers and program nftables. It does not need to run as root.

**systemd** — a hardened unit is in [`deploy/wgrouter.service`](deploy/wgrouter.service):

```ini
User=wgrouter
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
```

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin wgrouter
install -m0755 wgrouter /usr/local/bin/wgrouter
install -m0644 deploy/wgrouter.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now wgrouter
```

**Docker** — the equivalent, needing host networking because it manages the
host's interfaces and firewall:

```sh
docker run -d --name wgrouter \
  --cap-add=NET_ADMIN \
  --network=host \
  -v /var/lib/wgrouter:/var/lib/wgrouter \
  -e WGROUTER_PUBLIC_ENDPOINT=vpn.example.com \
  wgrouter
```

## Source IP preservation

The point of a port forward is usually that the peer can see who connected. The
naive DNAT + masquerade approach destroys that: every connection appears to come
from the router's tunnel address, which breaks logging, geo-blocking, fail2ban
and per-client rate limiting on the peer.

wgrouter makes the tradeoff explicit, per forward:

| Mode | Peer sees the real client IP | Requires | Protocols | Use when |
|---|---|---|---|---|
| **Masquerade** *(default)* | No | Nothing | TCP, UDP | It has to work with no client-side changes. wgrouter records the origin in its own connection log as compensation. |
| **Direct** | Yes | The peer must route replies back through the tunnel — `AllowedIPs = 0.0.0.0/0` on the client, or an explicit route covering the clients it answers | TCP, UDP | You control the peer's routing. The best answer when available. |

Two failure modes worth knowing before you pick:

- **Direct** also depends on the client's reverse-path filtering. Packets arrive
  on the tunnel carrying arbitrary internet source addresses, and under strict
  `rp_filter` the kernel drops them silently — the tunnel handshakes and then
  passes nothing. Most distributions ship
  `net.ipv4.conf.default.rp_filter=1`, which a newly created `wg0` inherits.
  Generated direct-mode configs explain the check and carry the fix as
  commented-out lines; loosening source validation is left as the operator's
  decision rather than made for them.
- **Direct** depends on the peer's return path. If the peer's default route is
  its own LAN, replies leave the wrong way and the connection hangs. Asymmetric
  routing looks exactly like a firewall drop, so the UI shows each peer's
  negotiated `AllowedIPs` and offers a connectivity test.
PROXY protocol was specified in the original brief and has been **removed**. It
was never finished — it validated and stored but nothing wrote a PROXY v2
header, so a forward set to it behaved as plain DNAT while claiming to preserve
the client address. Migration `0002` converts any such row to `masquerade`.

## Layout

```
cmd/wgrouter/        main; configuration, startup, graceful shutdown
internal/config/     flags + environment; WAN detection from /proc/net/route
internal/store/      SQLite, embedded forward-only migrations, typed accessors
internal/auth/       argon2id password hashing, in-memory sessions, CSRF tokens
internal/wg/         the WireGuard interface: server key, peers, live state
internal/ipam/       tunnel address allocation policy
internal/device/     client config rendering and QR encoding
internal/forward/    nftables rules, rate limiting and the reconciler
internal/status/     the router's own health, from procfs
internal/diag/       the diagnostics console: ping, traceroute, DNS, TCP check
internal/server/     routing, middleware, handlers, HUMAX-styled screens
web/                 embedded templates and static assets
docs/DESIGN.md       the extracted HUMAX design language, with evidence
deploy/              systemd unit
```

Packages that touch the kernel sit behind interfaces so their tests run without
root; the tests that genuinely need netlink are behind the `integration` build
tag and excluded from `make test`.

## Security notes

- Session cookies are `HttpOnly` and `SameSite=Strict`. **`Secure` is set only
  when TLS is enabled** — marking a cookie `Secure` over plain HTTP means the
  browser never sends it back and login fails silently. Run with `-tls-cert`
  and `-tls-key` for the full set; wgrouter warns loudly at startup when it is
  serving plain HTTP.
- Passwords are argon2id (RFC 9106 second recommended profile: 64 MiB, t=3),
  encoded PHC-style with their parameters so the cost can be raised later
  without invalidating existing hashes.
- **Password hashing is bounded, in two ways.** Argon2 allocates 64 MiB per
  call, so an unauthenticated endpoint that hashes on demand turns a 200-byte
  request into 64 MiB of live heap — about 300,000× amplification, and fatal on
  the small instances this targets. A semaphore caps concurrent hashes (a
  256 MiB ceiling), and a per-source failure throttle backs off exponentially
  after 5 failures within 15 minutes. The throttle is per-address and in-memory
  on purpose: a persistent per-account lockout would let anyone who can reach
  the port lock the administrator out of their own router.
- The database file is created `0600` before the driver touches it. It holds
  password hashes, preshared keys and the server private key.
- Audit writes use a context detached from the request, so a client that
  disconnects right after a mutation cannot cancel the record of it.
- CSRF tokens are required on every mutating request: bound to the session when
  signed in, double-submit cookie for login and setup.
- The admin listener defaults to the WireGuard interface address, never
  `0.0.0.0`. Binding it anywhere else logs a prominent warning.
- Login takes the same time for an unknown username as a wrong password, so it
  is not a user-enumeration oracle.
- `X-Forwarded-For` is deliberately ignored. The admin listener is not expected
  to sit behind a proxy, and trusting a client-supplied header would let anyone
  forge their own audit entries.
- Every mutation writes to `audit_log`: who, what, when, from where — including
  every diagnostic run and the target it was pointed at.
- **The diagnostics console is not a shell.** The tool set is fixed, each tool
  is a Go socket call, and the target is validated against a conservative
  character set before it reaches a resolver. No command line is ever
  constructed, so there is nothing for a metacharacter to escape into.
- New connections through each port forward are rate-limited in nftables. The
  limit matches only `ct state new`, so an established transfer is never
  throttled — only the rate at which new connections are opened.
- **Client private keys are generated, shown once and discarded.** Only the
  public key and the preshared key are stored. A lost config cannot be
  re-downloaded — that is the point: compromising the admin panel must not
  yield every device's identity.
- A peer's `AllowedIPs` is exactly its own `/32`. WireGuard treats AllowedIPs
  as authorisation rather than just a route, so anything wider would let one
  client claim another's address.
- Forward targets are validated to be inside the tunnel pool. Forwarding a WAN
  port to an arbitrary address would make the router an open relay into
  whatever network it can reach.
- wgrouter owns the single nftables table `inet wgrouter` and never reads,
  flushes or reorders any other. Its own table is rebuilt from the database
  rather than diffed, so drift cannot accumulate.

## Design

The UI is not a generic dashboard; it reproduces the design language of a HUMAX
T3ATv2 router panel, extracted from a saved capture of its Home screen.
[`docs/DESIGN.md`](docs/DESIGN.md) records what was extracted, with line
citations, and — just as importantly — what could not be, because the capture's
stylesheet and images were not saved. Values that could not be recovered are
quarantined in a clearly marked block at the bottom of
[`web/static/css/tokens.css`](web/static/css/tokens.css) rather than being
passed off as authentic.
