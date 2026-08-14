package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"wgrouter/internal/ipam"
)

// Peer is a configured device. It holds only what WireGuard cannot tell us:
// the human name, the notes and the address we allocated. Handshakes, byte
// counters and endpoints are read live from the kernel and never cached here,
// because a cached copy would go stale the moment the tunnel moved.
type Peer struct {
	ID           int64
	Name         string
	PublicKey    string
	PresharedKey string
	TunnelIP     netip.Addr
	Notes        string
	Enabled      bool
	CreatedAt    time.Time
}

// allocationAttempts bounds the retry loop in CreatePeer.
//
// Each attempt only fails if another transaction committed the exact address
// this one picked, in the window between choosing and inserting. That is rare
// and self-limiting -- a loser re-reads and picks a different address -- so a
// small bound is enough, and an unbounded loop would turn a genuine constraint
// bug into a hang.
const allocationAttempts = 8

// CreatePeer allocates a tunnel address and inserts the peer.
//
// This is where the IPAM concurrency guarantee actually lives. The read of used
// addresses and the insert share one IMMEDIATE transaction, and the UNIQUE
// constraint on tunnel_ip is the arbiter: if two callers somehow choose the
// same address, exactly one insert succeeds and the other retries against
// freshly-read state. No mutex is involved, so the guarantee holds even if a
// second process ever writes to this database.
//
// If pinned is valid the caller has chosen a specific address; that removes the
// search but not the constraint, so a collision is reported rather than
// silently reassigned.
func (s *Store) CreatePeer(ctx context.Context, plan ipam.Plan, p Peer, pinned netip.Addr) (Peer, error) {
	var out Peer
	var lastErr error

	for attempt := 0; attempt < allocationAttempts; attempt++ {
		err := s.Tx(ctx, func(tx *sql.Tx) error {
			addr := pinned
			if !addr.IsValid() {
				used, err := usedAddresses(ctx, tx)
				if err != nil {
					return err
				}
				addr, err = plan.Next(used)
				if err != nil {
					return err
				}
			}

			now := time.Now().Unix()
			res, err := tx.ExecContext(ctx, `
				INSERT INTO peers (name, public_key, preshared_key, tunnel_ip, notes, enabled, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				p.Name, p.PublicKey, p.PresharedKey, addr.String(), p.Notes, boolToInt(p.Enabled), now)
			if err != nil {
				return err
			}
			id, err := res.LastInsertId()
			if err != nil {
				return fmt.Errorf("store: create peer: %w", err)
			}
			out = Peer{
				ID:           id,
				Name:         p.Name,
				PublicKey:    p.PublicKey,
				PresharedKey: p.PresharedKey,
				TunnelIP:     addr,
				Notes:        p.Notes,
				Enabled:      p.Enabled,
				CreatedAt:    time.Unix(now, 0),
			}
			return nil
		})
		if err == nil {
			return out, nil
		}

		// A collision on the public key is the caller's problem and will not
		// resolve by retrying; a collision on the address is exactly what the
		// retry exists for.
		switch {
		case isUniqueViolation(err, "peers.public_key"):
			return Peer{}, ErrDuplicateKey
		case isUniqueViolation(err, "peers.tunnel_ip"):
			if pinned.IsValid() {
				return Peer{}, ErrAddressTaken
			}
			lastErr = err
			continue
		default:
			return Peer{}, err
		}
	}
	return Peer{}, fmt.Errorf("store: allocate tunnel address after %d attempts: %w", allocationAttempts, lastErr)
}

// ErrDuplicateKey is returned when a peer with the same public key exists.
var ErrDuplicateKey = errors.New("a device with that public key already exists")

// ErrAddressTaken is returned when a pinned address is already allocated.
var ErrAddressTaken = errors.New("that tunnel address is already in use")

// usedAddresses reads the allocated set inside the caller's transaction.
//
// Disabled peers are included: disabling a device keeps its address so that
// re-enabling it does not silently move the device to a different IP and break
// every port forward pointing at it.
func usedAddresses(ctx context.Context, tx *sql.Tx) (map[netip.Addr]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT tunnel_ip FROM peers`)
	if err != nil {
		return nil, fmt.Errorf("store: read allocated addresses: %w", err)
	}
	defer rows.Close()

	used := make(map[netip.Addr]bool)
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("store: scan allocated address: %w", err)
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			// A row we cannot parse must still count as used. Treating it as
			// free would hand the same address out twice.
			return nil, fmt.Errorf("store: allocated address %q is not a valid IP: %w", s, err)
		}
		used[addr] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read allocated addresses: %w", err)
	}
	return used, nil
}

// Peers returns every configured peer, lowest address first.
func (s *Store) Peers(ctx context.Context) ([]Peer, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, public_key, preshared_key, tunnel_ip, notes, enabled, created_at
		FROM peers`)
	if err != nil {
		return nil, fmt.Errorf("store: list peers: %w", err)
	}
	defer rows.Close()

	var out []Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list peers: %w", err)
	}
	sortPeersByAddress(out)
	return out, nil
}

// PeerByID looks up one peer.
func (s *Store) PeerByID(ctx context.Context, id int64) (Peer, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, public_key, preshared_key, tunnel_ip, notes, enabled, created_at
		FROM peers WHERE id = ?`, id)
	p, err := scanPeer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Peer{}, ErrNotFound
	}
	return p, err
}

// DeletePeer removes a peer. Its forwards go with it, via ON DELETE CASCADE.
func (s *Store) DeletePeer(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM peers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete peer %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete peer %d: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPeerEnabled toggles whether a peer is pushed to the kernel.
func (s *Store) SetPeerEnabled(ctx context.Context, id int64, enabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE peers SET enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	if err != nil {
		return fmt.Errorf("store: set peer %d enabled: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: set peer %d enabled: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RenamePeer updates a peer's display name and notes.
func (s *Store) RenamePeer(ctx context.Context, id int64, name, notes string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE peers SET name = ?, notes = ? WHERE id = ?`, name, notes, id)
	if err != nil {
		return fmt.Errorf("store: rename peer %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rename peer %d: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanPeer(sc scanner) (Peer, error) {
	var (
		p         Peer
		addr      string
		enabled   int
		createdAt int64
	)
	if err := sc.Scan(&p.ID, &p.Name, &p.PublicKey, &p.PresharedKey, &addr, &p.Notes, &enabled, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Peer{}, err
		}
		return Peer{}, fmt.Errorf("store: scan peer: %w", err)
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return Peer{}, fmt.Errorf("store: peer %d has an invalid tunnel address %q: %w", p.ID, addr, err)
	}
	p.TunnelIP = a
	p.Enabled = enabled != 0
	p.CreatedAt = time.Unix(createdAt, 0)
	return p, nil
}

// sortPeersByAddress orders peers numerically by tunnel address.
//
// ORDER BY tunnel_ip in SQL would sort them as text, which puts .10 before .2.
// Sorting here keeps the list in the order an administrator expects to read it.
func sortPeersByAddress(ps []Peer) {
	slices.SortFunc(ps, func(a, b Peer) int { return a.TunnelIP.Compare(b.TunnelIP) })
}

// isUniqueViolation reports whether err is a UNIQUE constraint failure, and
// optionally whether it names a particular column.
//
// The driver's numeric code is checked first because it is stable; the message
// is only consulted to tell one column's constraint from another's, which the
// code alone cannot express.
func isUniqueViolation(err error, column string) bool {
	var serr *sqlite.Error
	if !errors.As(err, &serr) {
		return false
	}
	// The extended code carries the constraint kind in its high bits; the
	// primary code is the low byte.
	if serr.Code() != sqlite3.SQLITE_CONSTRAINT_UNIQUE && serr.Code()&0xff != sqlite3.SQLITE_CONSTRAINT {
		return false
	}
	if column == "" {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), strings.ToLower(column))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
