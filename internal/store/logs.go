package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Log settings keys.
const (
	SettingUserLogEnabled     = "log.user.enabled"
	SettingUserLogActions     = "log.user.actions" // comma-separated; empty means all
	SettingFirewallLogEnabled = "log.firewall.enabled"
	SettingFirewallLogReasons = "log.firewall.reasons"
)

// LogSettings is the operator's logging configuration.
type LogSettings struct {
	UserEnabled     bool
	UserActions     []string // empty means record everything
	FirewallEnabled bool
	FirewallReasons []string
}

// UserActionFilters lists the audit actions that can be filtered, grouped for
// the UI. Anything not listed is always recorded: a filter that could hide an
// authentication failure would defeat the point of an audit log.
var UserActionFilters = []struct {
	Value string
	Label string
}{
	{ActionLogin, "Sign-in"},
	{ActionLogout, "Sign-out"},
	{ActionPeerCreate, "Device added"},
	{ActionPeerUpdate, "Device changed"},
	{ActionPeerDelete, "Device deleted"},
	{ActionFwdCreate, "Forward added"},
	{ActionFwdUpdate, "Forward changed"},
	{ActionFwdDelete, "Forward deleted"},
	{ActionFwdToggle, "Forward toggled"},
	{ActionDiagnostic, "Diagnostic run"},
}

// alwaysAudited can never be filtered out.
//
// A security log an administrator can quietly switch off is worse than no log,
// because it still looks authoritative. Failed sign-ins, password changes and
// the first-run setup stay on whatever the filter says.
var alwaysAudited = map[string]bool{
	ActionLoginFailed:    true,
	ActionPasswordChange: true,
	ActionSetupComplete:  true,
	ActionLogSettings:    true,
}

// LoadLogSettings reads the logging configuration, with safe defaults.
func (s *Store) LoadLogSettings(ctx context.Context) (LogSettings, error) {
	ls := LogSettings{UserEnabled: true}

	v, err := s.SettingOr(ctx, SettingUserLogEnabled, "1")
	if err != nil {
		return ls, err
	}
	ls.UserEnabled = v != "0"

	v, err = s.SettingOr(ctx, SettingUserLogActions, "")
	if err != nil {
		return ls, err
	}
	ls.UserActions = splitList(v)

	v, err = s.SettingOr(ctx, SettingFirewallLogEnabled, "0")
	if err != nil {
		return ls, err
	}
	ls.FirewallEnabled = v == "1"

	v, err = s.SettingOr(ctx, SettingFirewallLogReasons, "")
	if err != nil {
		return ls, err
	}
	ls.FirewallReasons = splitList(v)
	return ls, nil
}

// SaveLogSettings writes the logging configuration.
func (s *Store) SaveLogSettings(ctx context.Context, ls LogSettings) error {
	set := func(k, v string) error { return s.SetSetting(ctx, k, v) }
	if err := set(SettingUserLogEnabled, boolSetting(ls.UserEnabled)); err != nil {
		return err
	}
	if err := set(SettingUserLogActions, strings.Join(ls.UserActions, ",")); err != nil {
		return err
	}
	if err := set(SettingFirewallLogEnabled, boolSetting(ls.FirewallEnabled)); err != nil {
		return err
	}
	return set(SettingFirewallLogReasons, strings.Join(ls.FirewallReasons, ","))
}

// ShouldAudit reports whether an action passes the current filter.
func (ls LogSettings) ShouldAudit(action string) bool {
	if alwaysAudited[action] {
		return true
	}
	if !ls.UserEnabled {
		return false
	}
	if len(ls.UserActions) == 0 {
		return true // no filter set means record everything
	}
	for _, a := range ls.UserActions {
		if a == action {
			return true
		}
	}
	return false
}

func boolSetting(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func splitList(v string) []string {
	var out []string
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// --- firewall log -----------------------------------------------------------

// FirewallEvent is one dropped packet.
type FirewallEvent struct {
	ID        int64
	At        time.Time
	Reason    string
	ForwardID int64
	SrcIP     string
	SrcPort   int
	DstIP     string
	DstPort   int
	Proto     string
}

// MaxFirewallLogRows bounds the table.
//
// The log is written from a rate-limited kernel stream, but a sustained attack
// still produces steady traffic for as long as it lasts. A hard ceiling means
// the worst case is a full log rather than a full disk -- the router staying up
// matters more than keeping every line.
const MaxFirewallLogRows = 50000

// RecordFirewallEvents appends dropped-packet records and trims the table.
func (s *Store) RecordFirewallEvents(ctx context.Context, events []FirewallEvent) error {
	if len(events) == 0 {
		return nil
	}
	return s.Tx(ctx, func(tx *sql.Tx) error {
		for _, e := range events {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO firewall_log (at, reason, forward_id, src_ip, src_port, dst_ip, dst_port, proto)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				e.At.Unix(), e.Reason, e.ForwardID, e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Proto); err != nil {
				return fmt.Errorf("store: record firewall event: %w", err)
			}
		}
		// Trim oldest-first, in one statement so the ceiling cannot be exceeded
		// between the insert and the delete.
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM firewall_log WHERE id IN (
				SELECT id FROM firewall_log ORDER BY id DESC LIMIT -1 OFFSET ?
			)`, MaxFirewallLogRows); err != nil {
			return fmt.Errorf("store: trim firewall log: %w", err)
		}
		return nil
	})
}

// FirewallLog returns recent events, newest first.
func (s *Store) FirewallLog(ctx context.Context, limit int) ([]FirewallEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, at, reason, forward_id, src_ip, src_port, dst_ip, dst_port, proto
		FROM firewall_log ORDER BY at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: read firewall log: %w", err)
	}
	defer rows.Close()

	var out []FirewallEvent
	for rows.Next() {
		var e FirewallEvent
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Reason, &e.ForwardID, &e.SrcIP, &e.SrcPort,
			&e.DstIP, &e.DstPort, &e.Proto); err != nil {
			return nil, fmt.Errorf("store: scan firewall event: %w", err)
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read firewall log: %w", err)
	}
	return out, nil
}

// ClearFirewallLog empties the firewall log.
func (s *Store) ClearFirewallLog(ctx context.Context) (int64, error) {
	return s.clearTable(ctx, "firewall_log")
}

// ClearAuditLog empties the user log.
func (s *Store) ClearAuditLog(ctx context.Context) (int64, error) {
	return s.clearTable(ctx, "audit_log")
}

// clearTable deletes every row of one of our own tables. The name is never
// user-supplied; it is a compile-time constant at both call sites.
func (s *Store) clearTable(ctx context.Context, table string) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM "+table)
	if err != nil {
		return 0, fmt.Errorf("store: clear %s: %w", table, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: clear %s: %w", table, err)
	}
	return n, nil
}
