package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"wgrouter/internal/forward"
)

// Forward is a stored port forward, joined with the name of the peer it points
// at so the UI does not have to look it up separately.
type Forward struct {
	ID         int64
	Label      string
	Proto      forward.Proto
	Listen     forward.PortRange
	TargetPeer string // peer public key
	PeerID     int64  // joined from peers, for the edit form's device selector
	PeerName   string
	TargetIP   netip.Addr
	TargetPort uint16
	SrcMode    forward.SrcMode
	RateLimit  bool
	SrcPolicy  forward.SrcPolicy
	Sources    []netip.Prefix
	Enabled    bool
	CreatedAt  time.Time
}

// Rule converts a stored forward into the kernel-facing shape.
func (f Forward) Rule() forward.Rule {
	return forward.Rule{
		ID:         f.ID,
		Label:      f.Label,
		Proto:      f.Proto,
		Listen:     f.Listen.Normalised(),
		TargetIP:   f.TargetIP,
		TargetPort: f.TargetPort,
		SrcMode:    f.SrcMode,
		RateLimit:  f.RateLimit,
		SrcPolicy:  f.SrcPolicy,
		Sources:    f.Sources,
	}
}

// Forwards returns every forward, ordered by listen port.
func (s *Store) Forwards(ctx context.Context) ([]Forward, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT f.id, f.label, f.proto, f.listen_port, f.listen_port_end, f.target_peer,
		       COALESCE(p.id, 0), COALESCE(p.name, ''), f.target_ip, f.target_port,
		       f.preserve_src, f.rate_limit, f.src_policy, f.src_list, f.enabled, f.created_at
		FROM forwards f
		LEFT JOIN peers p ON p.public_key = f.target_peer`)
	if err != nil {
		return nil, fmt.Errorf("store: list forwards: %w", err)
	}
	defer rows.Close()

	var out []Forward
	for rows.Next() {
		f, err := scanForward(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list forwards: %w", err)
	}
	slices.SortFunc(out, func(a, b Forward) int {
		if a.Listen.Start != b.Listen.Start {
			return int(a.Listen.Start) - int(b.Listen.Start)
		}
		return int(a.ID - b.ID)
	})
	return out, nil
}

// EnabledForwardRules returns the kernel-facing rules for enabled forwards.
// It satisfies forward.RuleSource.
func (s *Store) EnabledForwardRules(ctx context.Context) ([]forward.Rule, error) {
	all, err := s.Forwards(ctx)
	if err != nil {
		return nil, err
	}
	var out []forward.Rule
	for _, f := range all {
		if f.Enabled {
			out = append(out, f.Rule())
		}
	}
	return out, nil
}

// ForwardByID looks up one forward.
func (s *Store) ForwardByID(ctx context.Context, id int64) (Forward, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT f.id, f.label, f.proto, f.listen_port, f.listen_port_end, f.target_peer,
		       COALESCE(p.id, 0), COALESCE(p.name, ''), f.target_ip, f.target_port,
		       f.preserve_src, f.rate_limit, f.src_policy, f.src_list, f.enabled, f.created_at
		FROM forwards f
		LEFT JOIN peers p ON p.public_key = f.target_peer
		WHERE f.id = ?`, id)
	f, err := scanForward(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Forward{}, ErrNotFound
	}
	return f, err
}

// CreateForward inserts a forward, rejecting one that collides with an
// existing enabled forward on the same listen port.
//
// The overlap check and the insert share one IMMEDIATE transaction. The partial
// unique index catches the same-protocol case, but it cannot express that
// 'both' overlaps 'tcp', so the Go check is the real guard and has to see a
// consistent snapshot to be worth anything.
func (s *Store) CreateForward(ctx context.Context, f Forward) (Forward, error) {
	var out Forward
	err := s.Tx(ctx, func(tx *sql.Tx) error {
		existing, err := enabledRulesTx(ctx, tx)
		if err != nil {
			return err
		}
		if f.Enabled {
			if err := forward.CheckOverlap(existing, f.Rule()); err != nil {
				return err
			}
		}

		now := time.Now().Unix()
		res, err := tx.ExecContext(ctx, `
			INSERT INTO forwards (label, proto, listen_port, listen_port_end, target_peer, target_ip,
			                      target_port, preserve_src, rate_limit, src_policy, src_list,
			                      enabled, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.Label, string(f.Proto), int(f.Listen.Start), int(f.Listen.Normalised().End),
			f.TargetPeer, f.TargetIP.String(), int(f.TargetPort), string(f.SrcMode),
			boolToInt(f.RateLimit), string(f.SrcPolicy), forward.FormatSources(f.Sources),
			boolToInt(f.Enabled), now)
		if err != nil {
			return fmt.Errorf("store: create forward: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("store: create forward: %w", err)
		}
		out = f
		out.ID = id
		out.CreatedAt = time.Unix(now, 0)
		return nil
	})
	if err != nil {
		return Forward{}, err
	}
	return out, nil
}

// UpdateForward replaces a forward's settings.
//
// The overlap check runs inside the same transaction as the update, against the
// other enabled forwards. CheckOverlap skips the row being edited, so changing
// a forward's target without moving its port is not a conflict with itself.
func (s *Store) UpdateForward(ctx context.Context, f Forward) error {
	return s.Tx(ctx, func(tx *sql.Tx) error {
		existing, err := enabledRulesTx(ctx, tx)
		if err != nil {
			return err
		}
		if f.Enabled {
			if err := forward.CheckOverlap(existing, f.Rule()); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE forwards
			SET label = ?, proto = ?, listen_port = ?, listen_port_end = ?, target_peer = ?,
			    target_ip = ?, target_port = ?, preserve_src = ?, rate_limit = ?,
			    src_policy = ?, src_list = ?
			WHERE id = ?`,
			f.Label, string(f.Proto), int(f.Listen.Start), int(f.Listen.Normalised().End),
			f.TargetPeer, f.TargetIP.String(), int(f.TargetPort), string(f.SrcMode),
			boolToInt(f.RateLimit), string(f.SrcPolicy), forward.FormatSources(f.Sources), f.ID)
		if err != nil {
			return fmt.Errorf("store: update forward %d: %w", f.ID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: update forward %d: %w", f.ID, err)
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// SetForwardEnabled toggles a forward, re-checking overlap when enabling.
//
// Enabling is the direction that can collide: a forward that was created while
// another held the port is legal as long as it stays disabled.
func (s *Store) SetForwardEnabled(ctx context.Context, id int64, enabled bool) error {
	return s.Tx(ctx, func(tx *sql.Tx) error {
		if enabled {
			f, err := forwardByIDTx(ctx, tx, id)
			if err != nil {
				return err
			}
			existing, err := enabledRulesTx(ctx, tx)
			if err != nil {
				return err
			}
			if err := forward.CheckOverlap(existing, f.Rule()); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `UPDATE forwards SET enabled = ? WHERE id = ?`, boolToInt(enabled), id)
		if err != nil {
			return fmt.Errorf("store: set forward %d enabled: %w", id, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: set forward %d enabled: %w", id, err)
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// DeleteForward removes a forward.
func (s *Store) DeleteForward(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM forwards WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete forward %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete forward %d: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// enabledRulesTx reads the enabled forwards inside a transaction.
func enabledRulesTx(ctx context.Context, tx *sql.Tx) ([]forward.Rule, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, label, proto, listen_port, listen_port_end, target_ip, target_port,
		       preserve_src, rate_limit, src_policy, src_list
		FROM forwards WHERE enabled = 1`)
	if err != nil {
		return nil, fmt.Errorf("store: read enabled forwards: %w", err)
	}
	defer rows.Close()

	var out []forward.Rule
	for rows.Next() {
		var (
			r                     forward.Rule
			proto, mode, targetIP string
			policy, srcList       string
			listenPort, listenEnd int
			targetPort, rateLimit int
		)
		if err := rows.Scan(&r.ID, &r.Label, &proto, &listenPort, &listenEnd, &targetIP,
			&targetPort, &mode, &rateLimit, &policy, &srcList); err != nil {
			return nil, fmt.Errorf("store: scan forward: %w", err)
		}
		addr, err := netip.ParseAddr(targetIP)
		if err != nil {
			return nil, fmt.Errorf("store: forward %d has an invalid target %q: %w", r.ID, targetIP, err)
		}
		sources, err := forward.ParseSources(srcList)
		if err != nil {
			return nil, fmt.Errorf("store: forward %d has an invalid source list: %w", r.ID, err)
		}
		r.Proto = forward.Proto(proto)
		r.SrcMode = forward.SrcMode(mode)
		r.Listen = forward.PortRange{Start: uint16(listenPort), End: uint16(listenEnd)}.Normalised()
		r.TargetPort = uint16(targetPort)
		r.TargetIP = addr
		r.RateLimit = rateLimit != 0
		r.SrcPolicy = forward.SrcPolicy(policy)
		r.Sources = sources
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read enabled forwards: %w", err)
	}
	return out, nil
}

func forwardByIDTx(ctx context.Context, tx *sql.Tx, id int64) (Forward, error) {
	row := tx.QueryRowContext(ctx, `
		SELECT id, label, proto, listen_port, listen_port_end, target_peer, 0, '', target_ip,
		       target_port, preserve_src, rate_limit, src_policy, src_list, enabled, created_at
		FROM forwards WHERE id = ?`, id)
	f, err := scanForward(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Forward{}, ErrNotFound
	}
	return f, err
}

func scanForward(sc scanner) (Forward, error) {
	var (
		f                     Forward
		proto, mode, targetIP string
		policy, srcList       string
		listenPort, listenEnd int
		targetPort, rateLimit int
		enabled               int
		createdAt             int64
	)
	err := sc.Scan(&f.ID, &f.Label, &proto, &listenPort, &listenEnd, &f.TargetPeer, &f.PeerID, &f.PeerName,
		&targetIP, &targetPort, &mode, &rateLimit, &policy, &srcList, &enabled, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Forward{}, err
		}
		return Forward{}, fmt.Errorf("store: scan forward: %w", err)
	}
	addr, err := netip.ParseAddr(targetIP)
	if err != nil {
		return Forward{}, fmt.Errorf("store: forward %d has an invalid target %q: %w", f.ID, targetIP, err)
	}
	sources, err := forward.ParseSources(srcList)
	if err != nil {
		return Forward{}, fmt.Errorf("store: forward %d has an invalid source list: %w", f.ID, err)
	}
	f.Proto = forward.Proto(proto)
	f.SrcMode = forward.SrcMode(mode)
	f.Listen = forward.PortRange{Start: uint16(listenPort), End: uint16(listenEnd)}.Normalised()
	f.TargetPort = uint16(targetPort)
	f.TargetIP = addr
	f.RateLimit = rateLimit != 0
	f.SrcPolicy = forward.SrcPolicy(policy)
	f.Sources = sources
	f.Enabled = enabled != 0
	f.CreatedAt = time.Unix(createdAt, 0)
	return f, nil
}
