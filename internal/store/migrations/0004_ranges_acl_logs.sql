-- 0004: port ranges, per-forward flood protection, source ACLs, firewall log.
--
-- Every new forwards column has a default that reproduces the previous
-- behaviour exactly, so existing rows keep working unchanged:
--   listen_port_end = 0   -> a single port, not a range
--   rate_limit      = 1   -> flood protection stays on, as it was globally
--   src_policy      = any -> no source restriction

ALTER TABLE forwards ADD COLUMN listen_port_end INTEGER NOT NULL DEFAULT 0;
ALTER TABLE forwards ADD COLUMN rate_limit      INTEGER NOT NULL DEFAULT 1 CHECK (rate_limit IN (0, 1));
ALTER TABLE forwards ADD COLUMN src_policy      TEXT    NOT NULL DEFAULT 'any' CHECK (src_policy IN ('any', 'allow', 'deny'));
ALTER TABLE forwards ADD COLUMN src_list        TEXT    NOT NULL DEFAULT '';

-- firewall_log records packets our rules dropped.
--
-- Written from the kernel's own log stream, which is rate-limited in nftables
-- before it is emitted: a flood is exactly when this table would otherwise
-- grow without bound, and a log that fills the disk during an attack is a
-- second outage on top of the first.
CREATE TABLE firewall_log (
    id         INTEGER PRIMARY KEY,
    at         INTEGER NOT NULL,
    reason     TEXT    NOT NULL,          -- 'ratelimit' | 'acl'
    forward_id INTEGER NOT NULL DEFAULT 0,
    src_ip     TEXT    NOT NULL DEFAULT '',
    src_port   INTEGER NOT NULL DEFAULT 0,
    dst_ip     TEXT    NOT NULL DEFAULT '',
    dst_port   INTEGER NOT NULL DEFAULT 0,
    proto      TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX firewall_log_at ON firewall_log (at DESC);
CREATE INDEX firewall_log_src ON firewall_log (src_ip);
