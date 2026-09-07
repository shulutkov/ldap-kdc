package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

// ListUsers returns every user, ordered by uid number.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, userSelect+` ORDER BY uid_number`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var (
		users []User
		ids   []int64
	)

	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
		ids = append(ids, u.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if err := s.decorateUsers(ctx, s.db, users, ids); err != nil {
		return nil, err
	}

	return users, nil
}

// GetUser looks a user up by name. Name matching is case-insensitive, as LDAP clients and Kerberos
// clients disagree about case far more often than administrators intend two distinct accounts.
func (s *Store) GetUser(ctx context.Context, name string) (*User, error) {
	return s.getUser(ctx, s.db, `name = ?`, name)
}

// GetUserByUID looks a user up by uid number.
func (s *Store) GetUserByUID(ctx context.Context, uid int) (*User, error) {
	return s.getUser(ctx, s.db, `uid_number = ?`, uid)
}

// GetUserByID looks a user up by row id.
func (s *Store) GetUserByID(ctx context.Context, id int64) (*User, error) {
	return s.getUser(ctx, s.db, `id = ?`, id)
}

func (s *Store) getUser(ctx context.Context, q querier, where string, arg any) (*User, error) {
	u, err := scanUser(q.QueryRowContext(ctx, userSelect+` WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return u, s.decorateUser(ctx, q, u)
}

const userSelect = `
	SELECT id, name, uid_number, primary_group, given_name, sn, mail, login_shell, home_dir,
	       disabled, pass_bcrypt, otp_secret, created_at, updated_at
	FROM users`

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(sc scanner) (*User, error) {
	var (
		u       User
		created int64
		updated int64
	)

	if err := sc.Scan(
		&u.ID, &u.Name, &u.UIDNumber, &u.PrimaryGroup, &u.GivenName, &u.SN, &u.Mail,
		&u.LoginShell, &u.Homedir, &u.Disabled, &u.PassBcrypt, &u.OTPSecret, &created, &updated,
	); err != nil {
		return nil, err
	}

	u.CreatedAt = time.Unix(created, 0).UTC()
	u.UpdatedAt = time.Unix(updated, 0).UTC()
	u.HasPassword = len(u.PassBcrypt) > 0
	u.HasOTP = len(u.OTPSecret) > 0

	return &u, nil
}

// decorateUser loads the child rows of a single user.
func (s *Store) decorateUser(ctx context.Context, q querier, u *User) error {
	us := []User{*u}
	if err := s.decorateUsers(ctx, q, us, []int64{u.ID}); err != nil {
		return err
	}

	*u = us[0]

	return nil
}

// decorateUsers loads group memberships, SSH keys, custom attributes, capabilities and app
// passwords for the given users in one query each, rather than one query per user.
func (s *Store) decorateUsers(ctx context.Context, q querier, users []User, ids []int64) error {
	if len(users) == 0 {
		return nil
	}

	index := make(map[int64]*User, len(users))
	for i := range users {
		index[users[i].ID] = &users[i]
	}

	ph := placeholders(len(ids))
	args := toAnySlice(ids)

	rows, err := q.QueryContext(ctx,
		`SELECT user_id, gid_number FROM user_groups WHERE user_id IN (`+ph+`) ORDER BY gid_number`, args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var gid int
		if err := rows.Scan(&id, &gid); err != nil {
			_ = rows.Close()

			return err
		}
		if u := index[id]; u != nil {
			u.OtherGroups = append(u.OtherGroups, gid)
		}
	}
	if err := closeRows(rows); err != nil {
		return err
	}

	rows, err = q.QueryContext(ctx,
		`SELECT user_id, key FROM user_ssh_keys WHERE user_id IN (`+ph+`) ORDER BY user_id, position`, args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var k string
		if err := rows.Scan(&id, &k); err != nil {
			_ = rows.Close()

			return err
		}
		if u := index[id]; u != nil {
			u.SSHKeys = append(u.SSHKeys, k)
		}
	}
	if err := closeRows(rows); err != nil {
		return err
	}

	rows, err = q.QueryContext(ctx,
		`SELECT user_id, name, value FROM user_attrs WHERE user_id IN (`+ph+`) ORDER BY user_id, name, position`, args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var (
			id        int64
			name, val string
		)
		if err := rows.Scan(&id, &name, &val); err != nil {
			_ = rows.Close()

			return err
		}
		if u := index[id]; u != nil {
			if u.CustomAttrs == nil {
				u.CustomAttrs = make(map[string][]string)
			}
			u.CustomAttrs[name] = append(u.CustomAttrs[name], val)
		}
	}
	if err := closeRows(rows); err != nil {
		return err
	}

	rows, err = q.QueryContext(ctx,
		`SELECT id, user_id, name, hash, created_at FROM user_app_passwords WHERE user_id IN (`+ph+`) ORDER BY id`, args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var (
			ap      AppPassword
			id      int64
			created int64
		)
		if err := rows.Scan(&ap.ID, &id, &ap.Name, &ap.Hash, &created); err != nil {
			_ = rows.Close()

			return err
		}
		ap.CreatedAt = time.Unix(created, 0).UTC()
		if u := index[id]; u != nil {
			u.AppPasswords = append(u.AppPasswords, ap)
		}
	}
	if err := closeRows(rows); err != nil {
		return err
	}

	caps, err := s.loadCapabilities(ctx, q, "user", ids)
	if err != nil {
		return err
	}
	for id, c := range caps {
		if u := index[id]; u != nil {
			u.Capabilities = c
		}
	}

	return nil
}

// CreateUser inserts a user. The caller sets credentials afterwards through SetPassword.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	if len(u.Name) == 0 {
		return fmt.Errorf("user name is required")
	}
	if u.UIDNumber <= 0 {
		return fmt.Errorf("user uidNumber must be positive")
	}

	now := time.Now().UTC()

	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO users (name, uid_number, primary_group, given_name, sn, mail,
			                   login_shell, home_dir, disabled, pass_bcrypt, otp_secret,
			                   created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			u.Name, u.UIDNumber, u.PrimaryGroup, u.GivenName, u.SN, u.Mail,
			u.LoginShell, u.Homedir, u.Disabled, u.PassBcrypt, u.OTPSecret,
			now.Unix(), now.Unix())
		if err != nil {
			return err
		}

		id, err := res.LastInsertId()
		if err != nil {
			return err
		}

		u.ID = id
		u.CreatedAt = now
		u.UpdatedAt = now

		if err := s.allocateRID(ctx, tx, "user", u.ID, u.UIDNumber); err != nil {
			return err
		}

		return s.writeUserChildren(ctx, tx, u)
	})
}

// UpdateUser loads the named user, applies mutate and writes the result back in one transaction.
func (s *Store) UpdateUser(ctx context.Context, name string, mutate func(*User) error) (*User, error) {
	var out *User

	err := s.write(ctx, func(tx *sql.Tx) error {
		u, err := s.getUser(ctx, tx, `name = ?`, name)
		if err != nil {
			return err
		}
		before := u.UIDNumber

		if err := mutate(u); err != nil {
			return err
		}

		now := time.Now().UTC()

		if _, err := tx.ExecContext(ctx, `
			UPDATE users SET name = ?, uid_number = ?, primary_group = ?, given_name = ?,
			                 sn = ?, mail = ?, login_shell = ?, home_dir = ?, disabled = ?,
			                 pass_bcrypt = ?, otp_secret = ?, updated_at = ?
			WHERE id = ?`,
			u.Name, u.UIDNumber, u.PrimaryGroup, u.GivenName, u.SN, u.Mail,
			u.LoginShell, u.Homedir, u.Disabled, u.PassBcrypt, u.OTPSecret, now.Unix(), u.ID,
		); err != nil {
			return err
		}

		if err := s.writeUserChildren(ctx, tx, u); err != nil {
			return err
		}

		// A changed uid means a changed security identifier, so the allocation has to move
		// with it or the account would keep presenting the previous one in its PAC.
		if u.UIDNumber != before {
			if err := s.reallocateRID(ctx, tx, "user", u.ID, u.UIDNumber); err != nil {
				return err
			}
		}

		// The Kerberos principal shares the account's name, so renaming the user renames it
		// too. Its keys were salted with the old name and no longer match, which is why the
		// caller must set a new password after a rename; the API says so explicitly.
		if _, err := tx.ExecContext(ctx,
			`UPDATE principals SET name = ?, updated_at = ? WHERE user_id = ? AND name != ?`,
			u.Name, now.Unix(), u.ID, u.Name,
		); err != nil {
			return err
		}

		u.UpdatedAt = now
		u.HasPassword = len(u.PassBcrypt) > 0
		u.HasOTP = len(u.OTPSecret) > 0
		out = u

		return nil
	})

	return out, err
}

// DeleteUser removes a user together with its principals and their keys.
func (s *Store) DeleteUser(ctx context.Context, name string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		u, err := s.getUser(ctx, tx, `name = ?`, name)
		if err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx,
			`DELETE FROM capabilities WHERE owner_kind = 'user' AND owner_id = ?`, u.ID,
		); err != nil {
			return err
		}

		if err := releaseRID(ctx, tx, "user", u.ID); err != nil {
			return err
		}

		// Principals, keys, groups, SSH keys and attributes all cascade from the user row.
		_, err = tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, u.ID)

		return err
	})
}

// writeUserChildren replaces the user's child rows to match the in-memory value.
func (s *Store) writeUserChildren(ctx context.Context, tx *sql.Tx, u *User) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_groups WHERE user_id = ?`, u.ID); err != nil {
		return err
	}
	gids := append([]int(nil), u.OtherGroups...)
	sort.Ints(gids)
	for _, gid := range gids {
		if gid == u.PrimaryGroup {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO user_groups (user_id, gid_number) VALUES (?, ?)`, u.ID, gid,
		); err != nil {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM user_ssh_keys WHERE user_id = ?`, u.ID); err != nil {
		return err
	}
	for i, k := range u.SSHKeys {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_ssh_keys (user_id, position, key) VALUES (?, ?, ?)`, u.ID, i, k,
		); err != nil {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM user_attrs WHERE user_id = ?`, u.ID); err != nil {
		return err
	}
	names := make([]string, 0, len(u.CustomAttrs))
	for n := range u.CustomAttrs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for i, v := range u.CustomAttrs[n] {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO user_attrs (user_id, name, position, value) VALUES (?, ?, ?, ?)`,
				u.ID, n, i, v,
			); err != nil {
				return err
			}
		}
	}

	return s.replaceCapabilities(ctx, tx, "user", u.ID, u.Capabilities)
}

// AddAppPassword stores a bcrypt hash as a named application password.
func (s *Store) AddAppPassword(ctx context.Context, userName, name, hash string) (*AppPassword, error) {
	var out *AppPassword

	err := s.write(ctx, func(tx *sql.Tx) error {
		u, err := s.getUser(ctx, tx, `name = ?`, userName)
		if err != nil {
			return err
		}

		now := time.Now().UTC()

		res, err := tx.ExecContext(ctx,
			`INSERT INTO user_app_passwords (user_id, name, hash, created_at) VALUES (?, ?, ?, ?)`,
			u.ID, name, hash, now.Unix())
		if err != nil {
			return err
		}

		id, err := res.LastInsertId()
		if err != nil {
			return err
		}

		out = &AppPassword{ID: id, Name: name, CreatedAt: now, Hash: hash}

		return nil
	})

	return out, err
}

// DeleteAppPassword removes one application password of a user.
func (s *Store) DeleteAppPassword(ctx context.Context, userName string, id int64) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		u, err := s.getUser(ctx, tx, `name = ?`, userName)
		if err != nil {
			return err
		}

		res, err := tx.ExecContext(ctx,
			`DELETE FROM user_app_passwords WHERE id = ? AND user_id = ?`, id, u.ID)
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

// UserGIDs returns every gid the user belongs to: the primary group, the secondary groups and
// every group that includes one of those, transitively.
func (s *Store) UserGIDs(ctx context.Context, u *User) ([]int, error) {
	direct := append([]int{u.PrimaryGroup}, u.OtherGroups...)

	return s.GroupsContaining(ctx, direct)
}

// GroupMembers returns the names of the users belonging to gid, following included groups.
func (s *Store) GroupMembers(ctx context.Context, gid int) ([]string, error) {
	gids, err := s.ExpandGroup(ctx, gid)
	if err != nil {
		return nil, err
	}

	ph := placeholders(len(gids))
	args := toAnySlice(gids)

	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT u.name
		FROM users u
		LEFT JOIN user_groups ug ON ug.user_id = u.id
		WHERE u.primary_group IN (`+ph+`) OR ug.gid_number IN (`+ph+`)
		ORDER BY u.name`, append(args, args...)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}

	return out, rows.Err()
}

// closeRows closes rows and reports any error the iteration accumulated.
func closeRows(rows *sql.Rows) error {
	err := rows.Err()
	if cerr := rows.Close(); err == nil {
		err = cerr
	}

	return err
}
