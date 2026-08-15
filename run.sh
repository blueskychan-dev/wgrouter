#!/usr/bin/env bash
#
# run.sh — start wgrouter in the foreground.
#
# Every setting below can be overridden from the environment, e.g.
#
#     LISTEN=10.10.0.1:8080 ./run.sh
#     PUBLIC_ENDPOINT=vpn.example.com ./run.sh
#
# Ctrl-C stops it cleanly: wgrouter drains in-flight requests before exiting.
# The WireGuard interface and the nftables table are deliberately left in place
# on exit, so the tunnel keeps carrying traffic while the panel is restarted.

set -euo pipefail

cd "$(dirname "$0")"

# --- settings ---------------------------------------------------------------

# The address peers dial. Left empty on purpose: when unset, the script asks a
# public API what this host looks like from outside (see detect_public_ip). It
# cannot be found locally -- on a NAT'd cloud instance the provider maps the
# address externally and it never appears on any interface, so anything derived
# from the routing table would be the private one and every client config built
# from it would silently fail to connect.
#
# Set it to your own address or hostname to skip the lookup entirely.
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-}"

# Where to ask, in order. Each must return a bare IPv4 address and nothing else.
# More than one because any single service can be down, rate-limiting, or
# answering with a captive-portal page.
IP_LOOKUP_URLS="${IP_LOOKUP_URLS:-https://checkip.amazonaws.com https://api.ipify.org https://icanhazip.com}"

# Admin UI bind address.
LISTEN="${LISTEN:-0.0.0.0:8080}"

DB="${DB:-./wgrouter.db}"
LOG_LEVEL="${LOG_LEVEL:-info}"

# The WireGuard interface wgrouter creates and owns, its UDP port, and the
# address pool peers are allocated from. Overridable mainly so a second
# instance can be run side by side for testing without touching the live one.
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_LISTEN_PORT="${WG_LISTEN_PORT:-51820}"
TUNNEL_POOL="${TUNNEL_POOL:-10.10.0.0/24}"

# AllowedIPs written into generated client configs. Leave unset to default to
# the tunnel pool. Set to 0.0.0.0/0 if you use direct-mode port forwards: a peer
# only replies through the tunnel for addresses inside its own AllowedIPs, so
# with just the pool a direct forward accepts the connection and then hangs.
CLIENT_ALLOWED_IPS="${CLIENT_ALLOWED_IPS:-}"

# Optional TLS. With both set, session cookies are marked Secure.
TLS_CERT="${TLS_CERT:-}"
TLS_KEY="${TLS_KEY:-}"

# --- public address -----------------------------------------------------------

# is_public_ipv4 rejects anything that is not a routable unicast IPv4 address.
#
# The answer ends up as the Endpoint in every client config that gets handed
# out, so it is validated rather than trusted. A captive portal, a proxy, or a
# service that starts returning HTML would otherwise bake a garbage endpoint
# into configs that then silently never connect.
is_public_ipv4() {
    local ip="$1" a b
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for octet in "${BASH_REMATCH[@]:1}"; do
        (( octet <= 255 )) || return 1
    done
    a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
    # Private, loopback, link-local, CGNAT and multicast are all wrong answers:
    # if we get one, we asked something that is not on the public internet.
    (( a == 10 ))                          && return 1
    (( a == 127 ))                         && return 1
    (( a == 0 ))                           && return 1
    (( a == 169 && b == 254 ))             && return 1
    (( a == 172 && b >= 16 && b <= 31 ))   && return 1
    (( a == 192 && b == 168 ))             && return 1
    (( a == 100 && b >= 64 && b <= 127 ))  && return 1
    (( a >= 224 ))                         && return 1
    return 0
}

# detect_public_ip asks a public API what our address looks like from outside.
#
# This is necessary because the address is genuinely not discoverable locally:
# on a NAT'd cloud instance the provider maps it externally and it never appears
# on any interface, so anything derived from the routing table would be the
# private address and every generated client config would fail to connect.
#
# It is a request to a third party, which is why the script says so. Set
# PUBLIC_ENDPOINT to skip it entirely.
detect_public_ip() {
    local url ip
    for url in $IP_LOOKUP_URLS; do
        ip="$(curl -fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')" || continue
        if is_public_ipv4 "$ip"; then
            echo "run.sh: public address ${ip} (from ${url})" >&2
            printf '%s' "$ip"
            return 0
        fi
        if [[ -n "$ip" ]]; then
            echo "run.sh: ${url} returned something that is not a public IPv4 address, trying the next" >&2
        fi
    done
    return 1
}

if [[ -z "$PUBLIC_ENDPOINT" ]]; then
    echo "run.sh: no PUBLIC_ENDPOINT set, asking a public API for this host's address..." >&2
    if ! PUBLIC_ENDPOINT="$(detect_public_ip)"; then
        echo "run.sh: could not determine the public address." >&2
        echo "run.sh: set it explicitly, e.g.  PUBLIC_ENDPOINT=vpn.example.com ./run.sh" >&2
        exit 1
    fi
    echo "run.sh: NOTE - a detected address is whatever the internet sees today." >&2
    echo "run.sh:        It is written into every client config generated from now on," >&2
    echo "run.sh:        so if it is an ephemeral cloud IP those configs break when it" >&2
    echo "run.sh:        changes. Reserve the address, or use a DNS name, for anything" >&2
    echo "run.sh:        you intend to keep." >&2
fi

# --- build ------------------------------------------------------------------

# Rebuild when any source file is newer than the binary, so the script never
# silently runs a stale build.
if [[ ! -x ./wgrouter ]] || [[ -n "$(find . -name '*.go' -newer ./wgrouter -print -quit 2>/dev/null)" ]]; then
    echo "run.sh: building wgrouter..."
    go build -o wgrouter ./cmd/wgrouter
fi

# --- privileges -------------------------------------------------------------

# wgrouter needs CAP_NET_ADMIN to create the WireGuard interface and program
# nftables. It does not need to be root; deploy/wgrouter.service grants exactly
# that capability via systemd. For a foreground run, sudo is the simple path.
#
# Only the "Current:" line of capsh output is consulted — that is the effective
# set. The "Bounding set" line lists what a process *could* hold and includes
# cap_net_admin for an ordinary user, so matching anywhere in the output finds
# it even when the shell has no capabilities at all, and the run fails at link
# creation instead of escalating.
SUDO=""
if [[ $EUID -ne 0 ]]; then
    if ! capsh --print 2>/dev/null | grep -m1 '^Current:' | grep -q 'cap_net_admin'; then
        SUDO="sudo"
    fi
fi

# --- warn -------------------------------------------------------------------

case "$LISTEN" in
    0.0.0.0:*|:::*|\*:*)
        echo "run.sh: NOTE — admin UI is bound to every interface ($LISTEN)."
        if [[ -z "$TLS_CERT" ]]; then
            echo "run.sh:        Over plain HTTP. Reachability depends entirely on your"
            echo "run.sh:        cloud firewall (OCI security list) allowing the port."
        fi
        ;;
esac

# --- run --------------------------------------------------------------------

args=(
    -public-endpoint "$PUBLIC_ENDPOINT"
    -listen          "$LISTEN"
    -db              "$DB"
    -log-level       "$LOG_LEVEL"
    -wg-interface    "$WG_INTERFACE"
    -wg-listen-port  "$WG_LISTEN_PORT"
    -tunnel-pool     "$TUNNEL_POOL"
)
[[ -n "$CLIENT_ALLOWED_IPS" ]] && args+=(-client-allowed-ips "$CLIENT_ALLOWED_IPS")
[[ -n "$TLS_CERT" ]] && args+=(-tls-cert "$TLS_CERT")
[[ -n "$TLS_KEY"  ]] && args+=(-tls-key  "$TLS_KEY")

echo "run.sh: starting — admin UI on http://${LISTEN}"

# exec so wgrouter replaces this shell and receives SIGINT/SIGTERM directly,
# rather than bash swallowing them and leaving an orphaned process holding the
# port and the netlink sockets.
exec $SUDO ./wgrouter "${args[@]}"
