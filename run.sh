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

# The address peers dial. It cannot be auto-detected: on a NAT'd cloud instance
# the public address is never present on a local interface, so anything derived
# from the routing table would be the private one and every client config built
# from it would silently fail to connect. The default below is a placeholder
# from the documentation range — set this to your own address or hostname.
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-203.0.113.10}"

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
