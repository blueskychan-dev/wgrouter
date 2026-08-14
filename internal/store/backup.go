package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// BackupVersion is the format version of an exported configuration.
//
// It is checked on import: restoring a file written by a future version could
// silently drop settings this build does not know about, which on a firewall
// means rules the operator believes are in place and are not.
const BackupVersion = 1

// Backup is an exported configuration.
//
// Deliberately absent: the audit log, the firewall log and the connection
// statistics. Those are a record of what happened on one router, not
// configuration, and restoring them onto another box would fabricate history.
type Backup struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Router    string    `json:"router_version"`

	// ServerPrivateKey is included because without it every client
	// configuration ever issued stops working after a restore. That makes this
	// file as sensitive as the database itself, which the UI says plainly.
	Settings []BackupSetting `json:"settings"`
	Peers    []BackupPeer    `json:"peers"`
	Forwards []BackupForward `json:"forwards"`
}

// BackupSetting is one settings row.
type BackupSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// BackupPeer is one device. The private key was never stored, so it cannot be
// exported: a restored device keeps working because the client still holds its
// own key, and the router only ever needed the public half.
type BackupPeer struct {
	Name         string `json:"name"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
	TunnelIP     string `json:"tunnel_ip"`
	Notes        string `json:"notes"`
	Enabled      bool   `json:"enabled"`
}

// BackupForward is one port forward.
type BackupForward struct {
	Label      string `json:"label"`
	Proto      string `json:"proto"`
	ListenPort int    `json:"listen_port"`
	ListenEnd  int    `json:"listen_port_end"`
	TargetPeer string `json:"target_peer"`
	TargetIP   string `json:"target_ip"`
	TargetPort int    `json:"target_port"`
	SrcMode    string `json:"preserve_src"`
	RateLimit  bool   `json:"rate_limit"`
	SrcPolicy  string `json:"src_policy"`
	SrcList    string `json:"src_list"`
	Enabled    bool   `json:"enabled"`
}

// ExportConfig serialises the router's configuration.
func (s *Store) ExportConfig(ctx context.Context, routerVersion string) ([]byte, error) {
	b := Backup{
		Version:   BackupVersion,
		CreatedAt: time.Now().UTC(),
		Router:    routerVersion,
	}

	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("store: export settings: %w", err)
	}
	for rows.Next() {
		var e BackupSetting
		if err := rows.Scan(&e.Key, &e.Value); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: export settings: %w", err)
		}
		b.Settings = append(b.Settings, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: export settings: %w", err)
	}

	rows, err = s.db.QueryContext(ctx,
		`SELECT name, public_key, preshared_key, tunnel_ip, notes, enabled FROM peers ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: export peers: %w", err)
	}
	for rows.Next() {
		var p BackupPeer
		var en int
		if err := rows.Scan(&p.Name, &p.PublicKey, &p.PresharedKey, &p.TunnelIP, &p.Notes, &en); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: export peers: %w", err)
		}
		p.Enabled = en != 0
		b.Peers = append(b.Peers, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: export peers: %w", err)
	}

	rows, err = s.db.QueryContext(ctx, `
		SELECT label, proto, listen_port, listen_port_end, target_peer, target_ip,
		       target_port, preserve_src, rate_limit, src_policy, src_list, enabled
		FROM forwards ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: export forwards: %w", err)
	}
	for rows.Next() {
		var f BackupForward
		var rl, en int
		if err := rows.Scan(&f.Label, &f.Proto, &f.ListenPort, &f.ListenEnd, &f.TargetPeer,
			&f.TargetIP, &f.TargetPort, &f.SrcMode, &rl, &f.SrcPolicy, &f.SrcList, &en); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: export forwards: %w", err)
		}
		f.RateLimit, f.Enabled = rl != 0, en != 0
		b.Forwards = append(b.Forwards, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: export forwards: %w", err)
	}

	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("store: encode backup: %w", err)
	}
	return append(out, '\n'), nil
}

// ImportConfig replaces peers, forwards and settings from a backup.
//
// The whole restore is one transaction. A half-applied import would leave the
// router with some of the old rules and some of the new, which is a firewall
// state nobody designed and nobody can reason about.
//
// User accounts are deliberately not touched: a backup must not be a way to
// replace the administrator's credentials, and restoring one should not lock
// the operator out of the box they are restoring.
func (s *Store) ImportConfig(ctx context.Context, data []byte) (Backup, error) {
	var b Backup
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("store: this does not look like a wgrouter backup: %w", err)
	}
	if b.Version == 0 {
		return b, fmt.Errorf("store: the file has no version field; it is not a wgrouter backup")
	}
	if b.Version > BackupVersion {
		return b, fmt.Errorf("store: backup version %d is newer than this build understands (%d); "+
			"upgrade wgrouter before restoring it", b.Version, BackupVersion)
	}

	err := s.Tx(ctx, func(tx *sql.Tx) error {
		// Forwards first: they reference peers, and dropping peers would
		// cascade them away anyway.
		if _, err := tx.ExecContext(ctx, `DELETE FROM forwards`); err != nil {
			return fmt.Errorf("store: clear forwards: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM peers`); err != nil {
			return fmt.Errorf("store: clear peers: %w", err)
		}

		now := time.Now().Unix()
		for _, p := range b.Peers {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO peers (name, public_key, preshared_key, tunnel_ip, notes, enabled, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				p.Name, p.PublicKey, p.PresharedKey, p.TunnelIP, p.Notes, boolToInt(p.Enabled), now); err != nil {
				return fmt.Errorf("store: restore peer %q: %w", p.Name, err)
			}
		}
		for _, f := range b.Forwards {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO forwards (label, proto, listen_port, listen_port_end, target_peer, target_ip,
				                      target_port, preserve_src, rate_limit, src_policy, src_list,
				                      enabled, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				f.Label, f.Proto, f.ListenPort, f.ListenEnd, f.TargetPeer, f.TargetIP,
				f.TargetPort, f.SrcMode, boolToInt(f.RateLimit), f.SrcPolicy, f.SrcList,
				boolToInt(f.Enabled), now); err != nil {
				return fmt.Errorf("store: restore forward %q: %w", f.Label, err)
			}
		}
		for _, kv := range b.Settings {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
				ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
				kv.Key, kv.Value, now); err != nil {
				return fmt.Errorf("store: restore setting %q: %w", kv.Key, err)
			}
		}
		return nil
	})
	return b, err
}

// Vacuum compacts the database file.
//
// VACUUM cannot run inside a transaction, so this deliberately bypasses Tx.
func (s *Store) Vacuum(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("store: vacuum: %w", err)
	}
	return nil
}

// ResetToFactory deletes every peer, forward, log and setting, keeping only the
// administrator accounts so the operator is not locked out of the box.
func (s *Store) ResetToFactory(ctx context.Context) error {
	return s.Tx(ctx, func(tx *sql.Tx) error {
		for _, t := range []string{"forwards", "peers", "settings", "audit_log", "firewall_log", "forward_stats", "forward_totals"} {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+t); err != nil {
				return fmt.Errorf("store: reset %s: %w", t, err)
			}
		}
		return nil
	})
}

// CountRows returns the row count of one of our own tables. The name is never
// user-supplied; every call site passes a constant.
func (s *Store) CountRows(ctx context.Context, table string) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count %s: %w", table, err)
	}
	return n, nil
}
