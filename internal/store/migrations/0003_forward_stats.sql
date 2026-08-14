-- 0003_forward_stats: connection statistics per forward.
--
-- Two tables, because "the last 7 days" and "since the router was built" have
-- very different storage shapes.
--
-- forward_stats holds one row per reconcile interval per forward, and is pruned.
-- It answers the windowed questions (7d, 30d) by summing rows inside a range.
-- At a 60-second interval that is ~1,440 rows per forward per day, which SQLite
-- handles comfortably at the retention below but not indefinitely.
--
-- forward_totals holds one row per forward, incremented by the same deltas and
-- never pruned. It answers "all time" without keeping the raw history forever.
-- Deriving all-time from forward_stats instead would mean either unbounded
-- growth or an all-time figure that silently shrinks when old rows are pruned.

CREATE TABLE forward_stats (
    id         INTEGER PRIMARY KEY,
    at         INTEGER NOT NULL,          -- Unix seconds, start of the interval
    forward_id INTEGER NOT NULL,          -- not a foreign key: history outlives the forward
    accepted   INTEGER NOT NULL DEFAULT 0,-- new connections accepted in the interval
    dropped    INTEGER NOT NULL DEFAULT 0,-- new connections dropped by the rate limit
    bytes      INTEGER NOT NULL DEFAULT 0 -- traffic on the forwarded port
);

-- The windowed queries all filter on time first, then group by forward.
CREATE INDEX forward_stats_at ON forward_stats (at DESC);
CREATE INDEX forward_stats_forward_at ON forward_stats (forward_id, at DESC);

CREATE TABLE forward_totals (
    forward_id INTEGER PRIMARY KEY,
    accepted   INTEGER NOT NULL DEFAULT 0,
    dropped    INTEGER NOT NULL DEFAULT 0,
    bytes      INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Deliberately no foreign key on forward_id in either table. A forward can be
-- deleted and its port reused; the statistics it accumulated are still a true
-- record of what happened, and cascading them away would quietly rewrite
-- history the operator may be relying on.
