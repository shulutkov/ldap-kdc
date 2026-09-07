package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

// ListGroups returns every group, ordered by gid.
func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, gid_number, description, created_at, updated_at
		FROM groups ORDER BY gid_number`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var (
		groups []Group
		ids    []int64
	)

	for rows.Next() {
		var (
			g       Group
			created int64
			updated int64
		)
		if err := rows.Scan(&g.ID, &g.Name, &g.GIDNumber, &g.Description, &created, &updated); err != nil {
			return nil, err
		}
		g.CreatedAt = time.Unix(created, 0).UTC()
		g.UpdatedAt = time.Unix(updated, 0).UTC()
		groups = append(groups, g)
		ids = append(ids, g.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	includes, err := s.loadIncludes(ctx, s.db, ids)
	if err != nil {
		return nil, err
	}
	caps, err := s.loadCapabilities(ctx, s.db, "group", ids)
	if err != nil {
		return nil, err
	}

	for i := range groups {
		groups[i].IncludeGroups = includes[groups[i].ID]
		groups[i].Capabilities = caps[groups[i].ID]
	}

	return groups, nil
}

// GetGroup looks a group up by name.
func (s *Store) GetGroup(ctx context.Context, name string) (*Group, error) {
	return s.getGroup(ctx, s.db, `name = ?`, name)
}

// GetGroupByGID looks a group up by gid number.
func (s *Store) GetGroupByGID(ctx context.Context, gid int) (*Group, error) {
	return s.getGroup(ctx, s.db, `gid_number = ?`, gid)
}

func (s *Store) getGroup(ctx context.Context, q querier, where string, arg any) (*Group, error) {
	var (
		g       Group
		created int64
		updated int64
	)

	err := q.QueryRowContext(ctx, `
		SELECT id, name, gid_number, description, created_at, updated_at
		FROM groups WHERE `+where, arg,
	).Scan(&g.ID, &g.Name, &g.GIDNumber, &g.Description, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	g.CreatedAt = time.Unix(created, 0).UTC()
	g.UpdatedAt = time.Unix(updated, 0).UTC()

	includes, err := s.loadIncludes(ctx, q, []int64{g.ID})
	if err != nil {
		return nil, err
	}
	caps, err := s.loadCapabilities(ctx, q, "group", []int64{g.ID})
	if err != nil {
		return nil, err
	}

	g.IncludeGroups = includes[g.ID]
	g.Capabilities = caps[g.ID]

	return &g, nil
}

// CreateGroup inserts a new group and fills in its id and timestamps.
func (s *Store) CreateGroup(ctx context.Context, g *Group) error {
	if len(g.Name) == 0 {
		return fmt.Errorf("group name is required")
	}
	if g.GIDNumber <= 0 {
		return fmt.Errorf("group gidNumber must be positive")
	}

	now := time.Now().UTC()

	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO groups (name, gid_number, description, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?)`,
			g.Name, g.GIDNumber, g.Description, now.Unix(), now.Unix())
		if err != nil {
			return err
		}

		id, err := res.LastInsertId()
		if err != nil {
			return err
		}

		g.ID = id
		g.CreatedAt = now
		g.UpdatedAt = now

		if err := s.allocateRID(ctx, tx, "group", g.ID, g.GIDNumber); err != nil {
			return err
		}

		if err := s.replaceIncludes(ctx, tx, g.ID, g.IncludeGroups); err != nil {
			return err
		}

		return s.replaceCapabilities(ctx, tx, "group", g.ID, g.Capabilities)
	})
}

// UpdateGroup loads the named group, hands it to mutate and writes the result back, all inside one
// write transaction so a concurrent update cannot be lost between the read and the write.
func (s *Store) UpdateGroup(ctx context.Context, name string, mutate func(*Group) error) (*Group, error) {
	var out *Group

	err := s.write(ctx, func(tx *sql.Tx) error {
		g, err := s.getGroup(ctx, tx, `name = ?`, name)
		if err != nil {
			return err
		}
		before := g.GIDNumber

		if err := mutate(g); err != nil {
			return err
		}

		now := time.Now().UTC()

		if _, err := tx.ExecContext(ctx, `
			UPDATE groups SET name = ?, gid_number = ?, description = ?, updated_at = ?
			WHERE id = ?`,
			g.Name, g.GIDNumber, g.Description, now.Unix(), g.ID,
		); err != nil {
			return err
		}

		if g.GIDNumber != before {
			if err := s.reallocateRID(ctx, tx, "group", g.ID, g.GIDNumber); err != nil {
				return err
			}
		}

		if err := s.replaceIncludes(ctx, tx, g.ID, g.IncludeGroups); err != nil {
			return err
		}
		if err := s.replaceCapabilities(ctx, tx, "group", g.ID, g.Capabilities); err != nil {
			return err
		}

		g.UpdatedAt = now
		out = g

		return nil
	})

	return out, err
}

// DeleteGroup removes a group. Users whose primary group it is keep the now dangling gid, which is
// visible in LDAP as a group name that no longer resolves; the API refuses the delete in that case.
func (s *Store) DeleteGroup(ctx context.Context, name string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		g, err := s.getGroup(ctx, tx, `name = ?`, name)
		if err != nil {
			return err
		}

		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users WHERE primary_group = ?`, g.GIDNumber,
		).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("group %s is the primary group of %d user(s)", name, n)
		}

		if _, err := tx.ExecContext(ctx, `DELETE FROM user_groups WHERE gid_number = ?`, g.GIDNumber); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM group_includes WHERE included_gid = ?`, g.GIDNumber); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM capabilities WHERE owner_kind = 'group' AND owner_id = ?`, g.ID); err != nil {
			return err
		}

		if err := releaseRID(ctx, tx, "group", g.ID); err != nil {
			return err
		}

		_, err = tx.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, g.ID)

		return err
	})
}

// ExpandGroup returns gid together with every gid it includes, transitively. A group that includes
// another lends it its membership, so this is the set that must be searched when listing members.
func (s *Store) ExpandGroup(ctx context.Context, gid int) ([]int, error) {
	seen := map[int]bool{gid: true}
	queue := []int{gid}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		rows, err := s.db.QueryContext(ctx, `
			SELECT gi.included_gid
			FROM group_includes gi
			JOIN groups g ON g.id = gi.group_id
			WHERE g.gid_number = ?`, cur)
		if err != nil {
			return nil, err
		}

		var next []int
		for rows.Next() {
			var g int
			if err := rows.Scan(&g); err != nil {
				_ = rows.Close()

				return nil, err
			}
			next = append(next, g)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()

			return nil, err
		}
		_ = rows.Close()

		for _, g := range next {
			// A cycle in the include graph would otherwise loop forever; the visited set
			// makes the expansion terminate and simply ignores the repeated edge.
			if !seen[g] {
				seen[g] = true
				queue = append(queue, g)
			}
		}
	}

	out := make([]int, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	sort.Ints(out)

	return out, nil
}

// GroupsContaining returns gid together with every gid that includes it, transitively. This is the
// full set of groups an account holding gid is a member of.
func (s *Store) GroupsContaining(ctx context.Context, gids []int) ([]int, error) {
	seen := make(map[int]bool, len(gids))
	queue := make([]int, 0, len(gids))

	for _, g := range gids {
		if !seen[g] {
			seen[g] = true
			queue = append(queue, g)
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		rows, err := s.db.QueryContext(ctx, `
			SELECT g.gid_number
			FROM groups g
			JOIN group_includes gi ON gi.group_id = g.id
			WHERE gi.included_gid = ?`, cur)
		if err != nil {
			return nil, err
		}

		var next []int
		for rows.Next() {
			var g int
			if err := rows.Scan(&g); err != nil {
				_ = rows.Close()

				return nil, err
			}
			next = append(next, g)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()

			return nil, err
		}
		_ = rows.Close()

		for _, g := range next {
			if !seen[g] {
				seen[g] = true
				queue = append(queue, g)
			}
		}
	}

	out := make([]int, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	sort.Ints(out)

	return out, nil
}

// GroupNames maps gid numbers to names for the gids given.
func (s *Store) GroupNames(ctx context.Context) (map[int]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT gid_number, name FROM groups`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make(map[int]string)
	for rows.Next() {
		var (
			gid  int
			name string
		)
		if err := rows.Scan(&gid, &name); err != nil {
			return nil, err
		}
		out[gid] = name
	}

	return out, rows.Err()
}

func (s *Store) loadIncludes(ctx context.Context, q querier, groupIDs []int64) (map[int64][]int, error) {
	out := make(map[int64][]int, len(groupIDs))
	if len(groupIDs) == 0 {
		return out, nil
	}

	rows, err := q.QueryContext(ctx,
		`SELECT group_id, included_gid FROM group_includes WHERE group_id IN (`+placeholders(len(groupIDs))+`) ORDER BY included_gid`,
		toAnySlice(groupIDs)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			id  int64
			gid int
		)
		if err := rows.Scan(&id, &gid); err != nil {
			return nil, err
		}
		out[id] = append(out[id], gid)
	}

	return out, rows.Err()
}

func (s *Store) replaceIncludes(ctx context.Context, tx *sql.Tx, groupID int64, gids []int) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM group_includes WHERE group_id = ?`, groupID); err != nil {
		return err
	}

	for _, gid := range gids {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO group_includes (group_id, included_gid) VALUES (?, ?)`,
			groupID, gid,
		); err != nil {
			return err
		}
	}

	return nil
}
