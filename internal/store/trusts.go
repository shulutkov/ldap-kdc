package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ListTrusts returns every configured cross-realm trust.
func (s *Store) ListTrusts(ctx context.Context) ([]Trust, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, remote_realm, direction, transitive, enabled, created_at, updated_at
		FROM trusts ORDER BY remote_realm`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Trust
	for rows.Next() {
		t, err := scanTrust(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}

	return out, rows.Err()
}

// GetTrust looks up the trust with a remote realm.
func (s *Store) GetTrust(ctx context.Context, realm string) (*Trust, error) {
	t, err := scanTrust(s.db.QueryRowContext(ctx, `
		SELECT id, remote_realm, direction, transitive, enabled, created_at, updated_at
		FROM trusts WHERE remote_realm = ?`, strings.ToUpper(realm)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}

	return t, err
}

// CreateTrust records a cross-realm relationship. The shared keys themselves live in the krbtgt
// principals the caller creates alongside it.
func (s *Store) CreateTrust(ctx context.Context, t *Trust) error {
	t.RemoteRealm = strings.ToUpper(t.RemoteRealm)
	now := time.Now().UTC()

	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO trusts (remote_realm, direction, transitive, enabled, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			t.RemoteRealm, string(t.Direction), t.Transitive, t.Enabled, now.Unix(), now.Unix())
		if err != nil {
			return err
		}

		if t.ID, err = res.LastInsertId(); err != nil {
			return err
		}

		t.CreatedAt = now
		t.UpdatedAt = now

		return nil
	})
}

// UpdateTrust loads a trust, applies mutate and writes it back.
func (s *Store) UpdateTrust(ctx context.Context, realm string, mutate func(*Trust) error) (*Trust, error) {
	var out *Trust

	err := s.write(ctx, func(tx *sql.Tx) error {
		t, err := scanTrust(tx.QueryRowContext(ctx, `
			SELECT id, remote_realm, direction, transitive, enabled, created_at, updated_at
			FROM trusts WHERE remote_realm = ?`, strings.ToUpper(realm)))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := mutate(t); err != nil {
			return err
		}

		now := time.Now().UTC()

		if _, err := tx.ExecContext(ctx, `
			UPDATE trusts SET direction = ?, transitive = ?, enabled = ?, updated_at = ?
			WHERE id = ?`,
			string(t.Direction), t.Transitive, t.Enabled, now.Unix(), t.ID,
		); err != nil {
			return err
		}

		t.UpdatedAt = now
		out = t

		return nil
	})

	return out, err
}

// DeleteTrust removes a trust record. The krbtgt principals that carry its keys are separate
// objects and are not removed here.
func (s *Store) DeleteTrust(ctx context.Context, realm string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM trusts WHERE remote_realm = ?`, strings.ToUpper(realm))
		if err != nil {
			return err
		}

		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}

		return nil
	})
}

func scanTrust(sc scanner) (*Trust, error) {
	var (
		t                Trust
		dir              string
		created, updated int64
	)

	if err := sc.Scan(&t.ID, &t.RemoteRealm, &dir, &t.Transitive, &t.Enabled, &created, &updated); err != nil {
		return nil, err
	}

	t.Direction = TrustDirection(dir)
	t.CreatedAt = time.Unix(created, 0).UTC()
	t.UpdatedAt = time.Unix(updated, 0).UTC()

	return &t, nil
}
