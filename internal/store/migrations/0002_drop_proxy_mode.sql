-- 0002_drop_proxy_mode: remove the PROXY-protocol source mode.
--
-- The mode was specified in the original brief but never finished: it
-- validated, stored and appeared in the UI, while nothing existed to actually
-- write a PROXY v2 header. A forward set to it therefore behaved as plain DNAT
-- while claiming to preserve the client address -- worse than not offering it,
-- because the administrator believes their backend is being told who connected.
--
-- SQLite cannot alter a CHECK constraint in place, so the table is rebuilt.
-- Any existing 'proxy' row becomes 'masquerade': that is the mode whose actual
-- behaviour is closest to what those forwards were already doing, and it is the
-- safe direction -- masquerade always works, where 'direct' silently hangs if
-- the peer does not route replies back through the tunnel.

CREATE TABLE forwards_new (
    id           INTEGER PRIMARY KEY,
    label        TEXT    NOT NULL,
    proto        TEXT    NOT NULL CHECK (proto IN ('tcp', 'udp', 'both')),
    listen_port  INTEGER NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    target_peer  TEXT    NOT NULL REFERENCES peers (public_key) ON DELETE CASCADE,
    target_ip    TEXT    NOT NULL,
    target_port  INTEGER NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
    preserve_src TEXT    NOT NULL CHECK (preserve_src IN ('masquerade', 'direct')),
    enabled      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at   INTEGER NOT NULL
);

INSERT INTO forwards_new (id, label, proto, listen_port, target_peer, target_ip,
                          target_port, preserve_src, enabled, created_at)
SELECT id, label, proto, listen_port, target_peer, target_ip, target_port,
       CASE preserve_src WHEN 'proxy' THEN 'masquerade' ELSE preserve_src END,
       enabled, created_at
FROM forwards;

DROP TABLE forwards;
ALTER TABLE forwards_new RENAME TO forwards;

-- Recreate the indexes the old table carried; they do not survive the rename.
CREATE UNIQUE INDEX forwards_enabled_port ON forwards (proto, listen_port) WHERE enabled = 1;
CREATE INDEX forwards_target_peer ON forwards (target_peer);
