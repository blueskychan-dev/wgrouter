// Package auth provides password hashing and session management for the admin
// UI.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. These follow the RFC 9106 "second recommended" profile
// (64 MiB, t=3) which is the usual balance for an interactive login on modest
// hardware -- this runs on routers and small cloud instances, not a GPU rig.
//
// The parameters are encoded into every hash, so raising them later does not
// invalidate existing passwords: old hashes keep verifying with their own
// stored parameters and are upgraded on the next successful login.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonKeyLen  = 32
	argonSaltLen = 16
)

// MinPasswordLength is the shortest password the setup wizard accepts. Length
// is the only property worth enforcing: composition rules push people toward
// predictable substitutions without adding real entropy.
const MinPasswordLength = 12

var (
	// ErrMismatch means the password did not match the hash.
	ErrMismatch = errors.New("auth: password does not match")
	// ErrBadHash means the stored hash could not be parsed.
	ErrBadHash = errors.New("auth: malformed password hash")
)

// argonThreads is the parallelism parameter, capped so a machine with many
// cores does not produce hashes that a smaller replacement machine cannot
// verify at the same cost.
func argonThreads() uint8 {
	n := runtime.NumCPU()
	if n > 4 {
		n = 4
	}
	if n < 1 {
		n = 1
	}
	return uint8(n)
}

// HashPassword returns a PHC-format argon2id hash:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<b64 salt>$<b64 hash>
func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read salt: %w", err)
	}
	threads := argonThreads()
	sum := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, threads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	), nil
}

// VerifyPassword checks password against a PHC-format hash. It returns
// ErrMismatch on a wrong password and ErrBadHash if the encoded hash is
// unusable.
func VerifyPassword(password, encoded string) error {
	params, salt, want, err := decodeHash(encoded)
	if err != nil {
		return err
	}
	got := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, uint32(len(want)))

	// Constant-time: a length-dependent early return would leak the hash length,
	// and a byte-wise compare would leak how much of it matched.
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// ValidatePassword applies the password policy. Kept separate from hashing so
// the HTTP layer can report the reason before doing 64 MiB of work.
func ValidatePassword(password string) error {
	if n := len([]rune(password)); n < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters (got %d)", MinPasswordLength, n)
	}
	if len(password) > 1024 {
		// Argon2 cost is independent of input length, but an unbounded field is
		// still an unbounded allocation from an unauthenticated endpoint.
		return errors.New("password must be at most 1024 bytes")
	}
	return nil
}

type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func decodeHash(encoded string) (p argonParams, salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[0] != "" {
		return p, nil, nil, ErrBadHash
	}
	if parts[1] != "argon2id" {
		return p, nil, nil, fmt.Errorf("%w: unsupported algorithm %q", ErrBadHash, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, ErrBadHash
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("%w: unsupported version %d", ErrBadHash, version)
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return p, nil, nil, ErrBadHash
	}
	if p.memory == 0 || p.time == 0 || p.threads == 0 {
		return p, nil, nil, fmt.Errorf("%w: zero cost parameter", ErrBadHash)
	}

	if salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4]); err != nil {
		return p, nil, nil, ErrBadHash
	}
	if hash, err = base64.RawStdEncoding.Strict().DecodeString(parts[5]); err != nil {
		return p, nil, nil, ErrBadHash
	}
	if len(salt) == 0 || len(hash) == 0 {
		return p, nil, nil, ErrBadHash
	}
	return p, salt, hash, nil
}

// NeedsRehash reports whether a stored hash was produced with weaker parameters
// than the current ones, so callers can transparently upgrade it after a
// successful login.
func NeedsRehash(encoded string) bool {
	p, _, _, err := decodeHash(encoded)
	if err != nil {
		return true
	}
	return p.memory < argonMemory || p.time < argonTime
}
