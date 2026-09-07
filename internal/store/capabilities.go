package store

import (
	"context"
	"database/sql"
)

// loadCapabilities fetches the capabilities of several owners of the same kind in one query.
func (s *Store) loadCapabilities(ctx context.Context, q querier, kind string, ownerIDs []int64) (map[int64][]Capability, error) {
	out := make(map[int64][]Capability, len(ownerIDs))
	if len(ownerIDs) == 0 {
		return out, nil
	}

	args := append([]any{kind}, toAnySlice(ownerIDs)...)

	rows, err := q.QueryContext(ctx,
		`SELECT owner_id, action, object FROM capabilities
		 WHERE owner_kind = ? AND owner_id IN (`+placeholders(len(ownerIDs))+`)
		 ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			id int64
			c  Capability
		)
		if err := rows.Scan(&id, &c.Action, &c.Object); err != nil {
			return nil, err
		}
		out[id] = append(out[id], c)
	}

	return out, rows.Err()
}

func (s *Store) replaceCapabilities(ctx context.Context, tx *sql.Tx, kind string, ownerID int64, caps []Capability) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM capabilities WHERE owner_kind = ? AND owner_id = ?`, kind, ownerID,
	); err != nil {
		return err
	}

	for _, c := range caps {
		if len(c.Action) == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO capabilities (owner_kind, owner_id, action, object) VALUES (?, ?, ?, ?)`,
			kind, ownerID, c.Action, c.Object,
		); err != nil {
			return err
		}
	}

	return nil
}
