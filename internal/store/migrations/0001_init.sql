-- 0001_init: the five tables wgrouter needs to boot.
--
-- Timestamps are Unix seconds stored as INTEGER. SQLite has no native date
-- type and text dates sort correctly but compare slowly; integers avoid both
-- problems and survive timezone changes on the host.

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,          -- argon2id PHC string; never a raw hash
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE settings (
    key        TEXT    PRIMARY KEY,
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
);

-- peers holds what WireGuard itself cannot tell us: the human name, the notes,
-- and the address we allocated. Everything else (handshakes, byte counters,
-- endpoints) is read live from the kernel and never cached here.
--
-- The private key is deliberately absent. It is generated, shown once at
-- creation time, and discarded. Only the public key is persisted.
CREATE TABLE peers (
    id            INTEGER PRIMARY KEY,
    name          TEXT    NOT NULL,
    public_key    TEXT    NOT NULL UNIQUE,
    preshared_key TEXT    NOT NULL,          -- symmetric: we must keep it to re-push to the kernel after a reboot
    tunnel_ip     TEXT    NOT NULL UNIQUE,   -- this UNIQUE is the IPAM arbiter; see internal/ipam
    notes         TEXT    NOT NULL DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at    INTEGER NOT NULL
);

-- forwards is the source of truth for NAT. The kernel is derived state:
-- nftables rules are rebuilt from these rows on startup and after any change.
CREATE TABLE forwards (
    id           INTEGER PRIMARY KEY,
    label        TEXT    NOT NULL,
    proto        TEXT    NOT NULL CHECK (proto IN ('tcp', 'udp', 'both')),
    listen_port  INTEGER NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    target_peer  TEXT    NOT NULL REFERENCES peers (public_key) ON DELETE CASCADE,
    target_ip    TEXT    NOT NULL,
    target_port  INTEGER NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
    preserve_src TEXT    NOT NULL CHECK (preserve_src IN ('masquerade', 'direct', 'proxy')),
    enabled      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at   INTEGER NOT NULL
);

-- Backstop against two enabled forwards claiming the same proto/port. It does
-- NOT catch a 'both' overlapping a 'tcp' on the same port -- SQLite cannot
-- express that -- so internal/forward checks overlap in Go as well. This index
-- exists so a bug there cannot corrupt the table.
CREATE UNIQUE INDEX forwards_enabled_port ON forwards (proto, listen_port) WHERE enabled = 1;

CREATE INDEX forwards_target_peer ON forwards (target_peer);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    at          INTEGER NOT NULL,
    actor       TEXT    NOT NULL,            -- username, or 'system' for unattended actions
    action      TEXT    NOT NULL,            -- stable machine-readable verb, e.g. 'peer.create'
    detail      TEXT    NOT NULL DEFAULT '',
    remote_addr TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX audit_log_at ON audit_log (at DESC);
