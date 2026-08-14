package store

import (
	"context"
	"fmt"
	"time"
	"unicode/utf8"
)

// Audit action verbs. These are machine-readable and stable: the UI may change
// how it renders them, but stored history should not have to be rewritten.
const (
	ActionSetupComplete  = "setup.complete"
	ActionLogin          = "auth.login"
	ActionLoginFailed    = "auth.login_failed"
	ActionLogout         = "auth.logout"
	ActionPasswordChange = "auth.password_change"

	ActionPeerCreate   = "peer.create"
	ActionPeerDelete   = "peer.delete"
	ActionPeerUpdate   = "peer.update"
	ActionFwdCreate    = "forward.create"
	ActionFwdUpdate    = "forward.update"
	ActionFwdDelete    = "forward.delete"
	ActionFwdToggle    = "forward.toggle"
	ActionReconcile    = "kernel.reconcile"
	ActionDiagnostic   = "system.diagnostic"
	ActionLogSettings  = "system.log_settings"
	ActionLogCleared   = "system.log_cleared"
	ActionConfigExport = "system.config_export"
	ActionConfigImport = "system.config_import"
	ActionMaintenance  = "system.maintenance"
	ActionServerKeyGen = "wg.server_key_generate"
)

// ActorSystem is the actor recorded for unattended actions such as the
// periodic reconcile.
const ActorSystem = "system"

// AuditEntry is one recorded mutation.
type AuditEntry struct {
	ID         int64
	At         time.Time
	Actor      string
	Action     string
	Detail     string
	RemoteAddr string
}

// Audit records a mutation. Every state-changing request writes one of these:
// who did what, when, and from where.
//
// Audit failures are returned rather than swallowed, but callers should treat
// them as non-fatal for the request they accompany -- losing the audit line is
// bad, undoing a completed kernel change because we could not log it is worse.
func (s *Store) Audit(ctx context.Context, actor, action, detail, remoteAddr string) error {
	if actor == "" {
		actor = ActorSystem
	}
	// Defence in depth: the actor on a failed login is whatever username the
	// client sent. Handlers validate it, but this table must not become an
	// unauthenticated write amplifier if one of them ever forgets.
	actor = clamp(actor, 64)
	detail = clamp(detail, 512)
	remoteAddr = clamp(remoteAddr, 64)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (at, actor, action, detail, remote_addr) VALUES (?, ?, ?, ?, ?)`,
		time.Now().Unix(), actor, action, detail, remoteAddr)
	if err != nil {
		return fmt.Errorf("store: write audit entry %q: %w", action, err)
	}
	return nil
}

// clamp truncates s to at most n bytes, on a rune boundary so the result stays
// valid UTF-8.
func clamp(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// RecentAudit returns the most recent entries, newest first.
func (s *Store) RecentAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, at, actor, action, detail, remote_addr FROM audit_log ORDER BY at DESC, id DESC LIMIT ?`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("store: read audit log: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var (
			e  AuditEntry
			at int64
		)
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Detail, &e.RemoteAddr); err != nil {
			return nil, fmt.Errorf("store: scan audit entry: %w", err)
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read audit log: %w", err)
	}
	return out, nil
}
