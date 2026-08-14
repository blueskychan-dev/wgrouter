package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Setting keys used across the program. Keeping them as constants here stops
// the same string being spelled two ways in two packages.
const (
	// SettingServerPrivateKey is the WireGuard server private key, generated on
	// first run. Unlike peer private keys -- which are shown once and discarded
	// -- this one must persist: the interface is recreated from it after every
	// reboot, and regenerating it would invalidate every client config ever
	// handed out.
	SettingServerPrivateKey = "wg.server_private_key"

	// SettingServerPublicKey is cached alongside it so status pages do not have
	// to derive it on every request.
	SettingServerPublicKey = "wg.server_public_key"
)

// Setting reads a settings value. It returns ErrNotFound if the key is unset.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: read setting %q: %w", key, err)
	}
	return v, nil
}

// SettingOr reads a settings value, falling back to def when unset.
func (s *Store) SettingOr(ctx context.Context, key, def string) (string, error) {
	v, err := s.Setting(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return def, nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

// SetSetting writes a settings value, replacing any previous one.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("store: write setting %q: %w", key, err)
	}
	return nil
}
