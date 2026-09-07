package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
)

// AddAlias gives a principal another name to answer to. Both names then reach the same keys, and
// the one the principal row holds stays the canonical one.
func (s *Store) AddAlias(ctx context.Context, name, alias krbkeys.Name) (*Principal, error) {
	return s.UpdatePrincipal(ctx, name, func(p *Principal) error {
		// The realm goes in with the name so that one belonging to another realm is refused
		// rather than quietly re-homed here.
		p.Aliases = append(p.Aliases, alias.String())

		return nil
	})
}

// RemoveAlias drops one of a principal's alternative names. Removing a name nobody registered is
// not an error: the caller asked for it to be gone and it is.
func (s *Store) RemoveAlias(ctx context.Context, name, alias krbkeys.Name) (*Principal, error) {
	return s.UpdatePrincipal(ctx, name, func(p *Principal) error {
		p.Aliases = slices.DeleteFunc(p.Aliases, func(a string) bool {
			return a == alias.Principal()
		})

		return nil
	})
}

// normalizeAliases parses a principal's aliases, rejecting the ones that cannot be one, and writes
// the cleaned list back. Sorting and de-duplicating here means the stored order is stable no matter
// how the list arrived.
func normalizeAliases(p *Principal) ([]krbkeys.Name, error) {
	var (
		out  []krbkeys.Name
		seen = make(map[string]bool, len(p.Aliases))
	)

	for _, raw := range p.Aliases {
		n, err := krbkeys.ParseName(raw, p.Realm)
		if err != nil {
			return nil, fmt.Errorf("alias %q: %w", raw, err)
		}

		// An alias names the same principal, so it lives in the same realm. A name in another
		// realm would be a referral, which is a different mechanism entirely.
		if n.Realm != p.Realm {
			return nil, fmt.Errorf("%w: alias %s is not in realm %s", ErrConflict, n, p.Realm)
		}
		if n.Principal() == p.Name {
			return nil, fmt.Errorf("%w: %s is the principal's own name", ErrConflict, n)
		}
		if seen[n.Principal()] {
			continue
		}

		seen[n.Principal()] = true

		out = append(out, n)
	}

	slices.SortFunc(out, func(a, b krbkeys.Name) int {
		switch {
		case a.Principal() < b.Principal():
			return -1
		case a.Principal() > b.Principal():
			return 1
		default:
			return 0
		}
	})

	p.Aliases = make([]string, 0, len(out))
	for _, n := range out {
		p.Aliases = append(p.Aliases, n.Principal())
	}

	if len(p.Aliases) == 0 {
		p.Aliases = nil
	}

	return out, nil
}

// nameTaken reports whether a principal other than except already answers to this name, either as
// its canonical name or as one of its aliases. SQLite enforces uniqueness within each of the two
// tables; the half that spans them is checked here, which is sound because every write goes
// through one serialized transaction.
func (s *Store) nameTaken(ctx context.Context, q querier, n krbkeys.Name, except int64) (bool, error) {
	var found int

	err := q.QueryRowContext(ctx, `
		SELECT 1 FROM principals WHERE name = ? AND realm = ? AND id <> ?
		UNION ALL
		SELECT 1 FROM principal_aliases WHERE name = ? AND realm = ? AND principal_id <> ?
		LIMIT 1`,
		n.Principal(), n.Realm, except, n.Principal(), n.Realm, except,
	).Scan(&found)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, err
	default:
		return true, nil
	}
}

// replaceAliases writes the alias table to match the in-memory principal.
func (s *Store) replaceAliases(ctx context.Context, tx *sql.Tx, p *Principal) error {
	names, err := normalizeAliases(p)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM principal_aliases WHERE principal_id = ?`, p.ID,
	); err != nil {
		return err
	}

	now := time.Now().Unix()

	for _, n := range names {
		taken, err := s.nameTaken(ctx, tx, n, p.ID)
		if err != nil {
			return err
		}
		if taken {
			return fmt.Errorf("%w: %s already names a principal in this realm", ErrConflict, n)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO principal_aliases (principal_id, name, realm, created_at)
			VALUES (?, ?, ?, ?)`, p.ID, n.Principal(), n.Realm, now,
		); err != nil {
			return err
		}
	}

	return nil
}

// loadAliases fetches the alternative names of several principals in one query.
func (s *Store) loadAliases(ctx context.Context, q querier, ids []int64) (map[int64][]string, error) {
	out := make(map[int64][]string, len(ids))

	if len(ids) == 0 {
		return out, nil
	}

	rows, err := q.QueryContext(ctx,
		`SELECT principal_id, name FROM principal_aliases
		 WHERE principal_id IN (`+placeholders(len(ids))+`) ORDER BY name`,
		toAnySlice(ids)...)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var (
			id   int64
			name string
		)
		if err := rows.Scan(&id, &name); err != nil {
			_ = rows.Close()

			return nil, err
		}
		out[id] = append(out[id], name)
	}

	return out, closeRows(rows)
}
