package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
)

// ErrNoPassword is returned when an account has no password set and one is required.
var ErrNoPassword = errors.New("no password set")

// bcryptCost is deliberately above the library default: a directory verifies a password once per
// bind, so the extra milliseconds cost nothing operationally and roughly quadruple the work an
// attacker must do per guess against a stolen hash.
const bcryptCost = 12

// HashPassword returns the bcrypt digest used for LDAP simple binds.
func HashPassword(password string) (string, error) {
	// bcrypt silently truncates at 72 bytes, so a longer passphrase would have its tail
	// ignored and two different passphrases could collide. Reject rather than truncate.
	if len(password) > 72 {
		return "", fmt.Errorf("password must not exceed 72 bytes")
	}

	h, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}

	return string(h), nil
}

// CheckPassword compares a password against a stored bcrypt digest.
func CheckPassword(hash, password string) bool {
	if len(hash) == 0 {
		return false
	}

	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// SetUserPassword sets a user's password on both sides of the service at once: the bcrypt digest
// that LDAP binds against, and a fresh set of Kerberos keys for every principal attached to the
// user. Doing it in one transaction is what keeps the two from drifting apart, which would show up
// as an account that can bind but cannot get a ticket, or the reverse.
func (s *Store) SetUserPassword(ctx context.Context, userName, password string, etypes []int32, expiresAt *time.Time) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	return s.write(ctx, func(tx *sql.Tx) error {
		u, err := s.getUser(ctx, tx, `name = ?`, userName)
		if err != nil {
			return err
		}

		now := time.Now().UTC()

		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET pass_bcrypt = ?, updated_at = ? WHERE id = ?`,
			hash, now.Unix(), u.ID,
		); err != nil {
			return err
		}

		principals, err := s.principalsForUserTx(ctx, tx, u.ID)
		if err != nil {
			return err
		}

		for i := range principals {
			p := &principals[i]

			keys, err := krbkeys.DeriveKeys(password, p.KrbName(), etypes)
			if err != nil {
				return err
			}

			if err := s.rollKeys(ctx, tx, p, keys, now); err != nil {
				return err
			}

			if _, err := tx.ExecContext(ctx,
				`UPDATE principals SET password_expires_at = ? WHERE id = ?`,
				nullTime(expiresAt), p.ID,
			); err != nil {
				return err
			}
		}

		return nil
	})
}

// SetPrincipalPassword derives fresh keys for one principal from a password. Service principals
// that are provisioned with a keytab use RandomizePrincipalKeys instead.
func (s *Store) SetPrincipalPassword(ctx context.Context, name krbkeys.Name, password string, etypes []int32) (*Principal, error) {
	keys, err := krbkeys.DeriveKeys(password, name, etypes)
	if err != nil {
		return nil, err
	}

	return s.SetKeys(ctx, name, keys, time.Now().UTC())
}

// RandomizePrincipalKeys replaces a principal's keys with random ones. There is no password to
// guess afterwards, which is why service principals and krbtgt should always be keyed this way.
func (s *Store) RandomizePrincipalKeys(ctx context.Context, name krbkeys.Name, etypes []int32) (*Principal, error) {
	keys, err := krbkeys.RandomKeys(etypes)
	if err != nil {
		return nil, err
	}

	return s.SetKeys(ctx, name, keys, time.Now().UTC())
}

// ClearUserPassword removes the LDAP password digest, leaving Kerberos keys untouched.
func (s *Store) ClearUserPassword(ctx context.Context, userName string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		u, err := s.getUser(ctx, tx, `name = ?`, userName)
		if err != nil {
			return err
		}

		_, err = tx.ExecContext(ctx,
			`UPDATE users SET pass_bcrypt = '', updated_at = ? WHERE id = ?`,
			time.Now().Unix(), u.ID)

		return err
	})
}

func (s *Store) principalsForUserTx(ctx context.Context, tx *sql.Tx, userID int64) ([]Principal, error) {
	rows, err := tx.QueryContext(ctx, principalSelect+` WHERE p.user_id = ? ORDER BY p.name`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Principal
	for rows.Next() {
		p, err := scanPrincipal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}

	return out, rows.Err()
}
