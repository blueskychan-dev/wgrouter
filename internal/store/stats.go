package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"wgrouter/internal/forward"
)

// StatsRetention is how long raw per-interval samples are kept.
//
// Slightly over 30 days so the 30-day window is always complete rather than
// truncating on its own boundary. All-time figures do not depend on these rows;
// they live in forward_totals.
const StatsRetention = 32 * 24 * time.Hour

// RecordForwardStats adds one interval's counter deltas. It satisfies
// forward.Sink.
//
// The sample insert and the running total update share one transaction: if they
// could diverge, the all-time figure would drift away from the sum of the
// windows and neither number would be trustworthy.
func (s *Store) RecordForwardStats(ctx context.Context, at time.Time, deltas map[int64]forward.Counters) error {
	if len(deltas) == 0 {
		return nil
	}
	ts := at.Unix()

	return s.Tx(ctx, func(tx *sql.Tx) error {
		for id, d := range deltas {
			if d.Accepted == 0 && d.Dropped == 0 && d.Bytes == 0 {
				continue
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO forward_stats (at, forward_id, accepted, dropped, bytes)
				VALUES (?, ?, ?, ?, ?)`,
				ts, id, int64(d.Accepted), int64(d.Dropped), int64(d.Bytes)); err != nil {
				return fmt.Errorf("store: record forward stats: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO forward_totals (forward_id, accepted, dropped, bytes, first_seen, updated_at)
				VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (forward_id) DO UPDATE SET
					accepted   = accepted + excluded.accepted,
					dropped    = dropped  + excluded.dropped,
					bytes      = bytes    + excluded.bytes,
					updated_at = excluded.updated_at`,
				id, int64(d.Accepted), int64(d.Dropped), int64(d.Bytes), ts, ts); err != nil {
				return fmt.Errorf("store: update forward totals: %w", err)
			}
		}
		return nil
	})
}

// ConnStats is one window's figures.
type ConnStats struct {
	Accepted uint64
	Dropped  uint64
	Bytes    uint64
}

// Total is accepted plus dropped: every connection attempt seen.
func (c ConnStats) Total() uint64 { return c.Accepted + c.Dropped }

// DropRate is the share of attempts that were dropped, 0-100.
func (c ConnStats) DropRate() float64 {
	t := c.Total()
	if t == 0 {
		return 0
	}
	return float64(c.Dropped) / float64(t) * 100
}

// StatsWindows holds the figures the UI shows side by side.
type StatsWindows struct {
	Day7    ConnStats
	Day30   ConnStats
	AllTime ConnStats
}

// ForwardStats returns the windowed figures for one forward, or for every
// forward combined when id is zero.
func (s *Store) ForwardStats(ctx context.Context, id int64, now time.Time) (StatsWindows, error) {
	var out StatsWindows

	window := func(since time.Time) (ConnStats, error) {
		var c ConnStats
		var a, d, b sql.NullInt64
		var err error
		if id == 0 {
			err = s.db.QueryRowContext(ctx, `
				SELECT SUM(accepted), SUM(dropped), SUM(bytes)
				FROM forward_stats WHERE at >= ?`, since.Unix()).Scan(&a, &d, &b)
		} else {
			err = s.db.QueryRowContext(ctx, `
				SELECT SUM(accepted), SUM(dropped), SUM(bytes)
				FROM forward_stats WHERE at >= ? AND forward_id = ?`, since.Unix(), id).Scan(&a, &d, &b)
		}
		if err != nil {
			return c, fmt.Errorf("store: read forward stats: %w", err)
		}
		// SUM over no rows is NULL, not 0.
		c.Accepted = uint64(max64(a.Int64))
		c.Dropped = uint64(max64(d.Int64))
		c.Bytes = uint64(max64(b.Int64))
		return c, nil
	}

	var err error
	if out.Day7, err = window(now.AddDate(0, 0, -7)); err != nil {
		return out, err
	}
	if out.Day30, err = window(now.AddDate(0, 0, -30)); err != nil {
		return out, err
	}

	var a, d, b sql.NullInt64
	if id == 0 {
		err = s.db.QueryRowContext(ctx,
			`SELECT SUM(accepted), SUM(dropped), SUM(bytes) FROM forward_totals`).Scan(&a, &d, &b)
	} else {
		err = s.db.QueryRowContext(ctx,
			`SELECT accepted, dropped, bytes FROM forward_totals WHERE forward_id = ?`, id).Scan(&a, &d, &b)
		if err == sql.ErrNoRows {
			return out, nil
		}
	}
	if err != nil {
		return out, fmt.Errorf("store: read forward totals: %w", err)
	}
	out.AllTime = ConnStats{
		Accepted: uint64(max64(a.Int64)),
		Dropped:  uint64(max64(d.Int64)),
		Bytes:    uint64(max64(b.Int64)),
	}
	return out, nil
}

// PruneStats deletes samples older than the retention window.
func (s *Store) PruneStats(ctx context.Context, now time.Time) (int64, error) {
	cutoff := now.Add(-StatsRetention).Unix()
	res, err := s.db.ExecContext(ctx, `DELETE FROM forward_stats WHERE at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store: prune forward stats: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune forward stats: %w", err)
	}
	return n, nil
}

// max64 clamps a negative to zero. A counter delta should never be negative,
// but a corrupted row must not turn into an enormous unsigned value.
func max64(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}
