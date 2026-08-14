package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// User is an admin account. Only the password hash is stored; the plaintext
// never reaches this package.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserCount returns how many admin accounts exist. Zero means the first-run
// setup wizard has not completed, and the server refuses to serve anything but
// the wizard until it has.
func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}
	return n, nil
}

// UserByName looks up an account. It returns ErrNotFound if there is no such
// user.
func (s *Store) UserByName(ctx context.Context, username string) (User, error) {
	var (
		u                    User
		createdAt, updatedAt int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at, updated_at FROM users WHERE username = ?`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: look up user %q: %w", username, err)
	}
	u.CreatedAt = time.Unix(createdAt, 0)
	u.UpdatedAt = time.Unix(updatedAt, 0)
	return u, nil
}

// CreateFirstUser creates the initial admin account, but only if no account
// exists yet.
//
// The check and the insert share one IMMEDIATE transaction so that two
// concurrent requests to the setup wizard cannot both succeed. Without that,
// whoever reaches an unconfigured router first would not reliably be the only
// one who gets an account.
func (s *Store) CreateFirstUser(ctx context.Context, username, passwordHash string) (User, error) {
	var u User
	err := s.Tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return fmt.Errorf("store: count users: %w", err)
		}
		if n > 0 {
			return ErrSetupComplete
		}
		now := time.Now().Unix()
		res, err := tx.ExecContext(ctx,
			`INSERT INTO users (username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)`,
			username, passwordHash, now, now)
		if err != nil {
			return fmt.Errorf("store: create user %q: %w", username, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("store: create user %q: %w", username, err)
		}
		u = User{
			ID:           id,
			Username:     username,
			PasswordHash: passwordHash,
			CreatedAt:    time.Unix(now, 0),
			UpdatedAt:    time.Unix(now, 0),
		}
		return nil
	})
	if err != nil {
		return User{}, err
	}
	return u, nil
}

// ErrSetupComplete is returned when the first-run wizard is attempted after an
// account already exists.
var ErrSetupComplete = errors.New("setup has already been completed")

// SetPassword replaces a user's password hash.
func (s *Store) SetPassword(ctx context.Context, userID int64, passwordHash string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		passwordHash, time.Now().Unix(), userID)
	if err != nil {
		return fmt.Errorf("store: set password for user %d: %w", userID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: set password for user %d: %w", userID, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
