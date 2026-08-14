-- 0005: let a port-range forward have no target port.
--
-- A range forwards every port straight through to the same port on the peer, so
-- there is no single target port to store. Migration 0002's CHECK required
-- target_port BETWEEN 1 AND 65535, which made an otherwise valid range
-- unstorable.
--
-- The fix is to make the constraint say what the rule actually is, rather than
-- to write a placeholder port into the column and pretend it means something.
-- SQLite cannot alter a CHECK in place, so the table is rebuilt.

CREATE TABLE forwards_new (
    id              INTEGER PRIMARY KEY,
    label           TEXT    NOT NULL,
    proto           TEXT    NOT NULL CHECK (proto IN ('tcp', 'udp', 'both')),
    listen_port     INTEGER NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    listen_port_end INTEGER NOT NULL DEFAULT 0,
    target_peer     TEXT    NOT NULL REFERENCES peers (public_key) ON DELETE CASCADE,
    target_ip       TEXT    NOT NULL,

    -- Zero is permitted only for a range, where the port is preserved and a
    -- target port would be meaningless.
    target_port     INTEGER NOT NULL
                        CHECK (target_port BETWEEN 1 AND 65535
                               OR (target_port = 0 AND listen_port_end > listen_port)),

    preserve_src    TEXT    NOT NULL CHECK (preserve_src IN ('masquerade', 'direct')),
    rate_limit      INTEGER NOT NULL DEFAULT 1 CHECK (rate_limit IN (0, 1)),
    src_policy      TEXT    NOT NULL DEFAULT 'any' CHECK (src_policy IN ('any', 'allow', 'deny')),
    src_list        TEXT    NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at      INTEGER NOT NULL,

    -- A table-level constraint, because it spans two columns: a range must be a
    -- range. An end below the start would produce a rule the kernel rejects
    -- long after the mistake was made.
    CHECK (listen_port_end = 0 OR listen_port_end >= listen_port)
);

INSERT INTO forwards_new (id, label, proto, listen_port, listen_port_end, target_peer,
                          target_ip, target_port, preserve_src, rate_limit,
                          src_policy, src_list, enabled, created_at)
SELECT id, label, proto, listen_port, listen_port_end, target_peer,
       target_ip, target_port, preserve_src, rate_limit,
       src_policy, src_list, enabled, created_at
FROM forwards;

DROP TABLE forwards;
ALTER TABLE forwards_new RENAME TO forwards;

CREATE UNIQUE INDEX forwards_enabled_port ON forwards (proto, listen_port) WHERE enabled = 1;
CREATE INDEX forwards_target_peer ON forwards (target_peer);
