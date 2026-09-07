package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
)

// keyGenerationsKept is how many key versions survive a password change. The current one encrypts
// new tickets; the previous one still decrypts tickets and keytabs issued before the change, which
// is what keeps a running service from failing the moment its password rotates.
const keyGenerationsKept = 2

const principalSelect = `
	SELECT p.id, p.name, p.realm, p.user_id, p.kvno, p.enabled, p.requires_preauth,
	       p.allow_forwardable, p.allow_proxiable, p.allow_renewable, p.allow_postdate,
	       p.ok_as_delegate, p.ok_to_auth_as_delegate, p.max_ticket_life, p.max_renewable_life,
	       p.password_last_set, p.password_expires_at, p.expires_at, p.locked_until,
	       p.fail_count, p.last_success, p.last_failure, p.created_at, p.updated_at,
	       COALESCE(u.name, '')
	FROM principals p
	LEFT JOIN users u ON u.id = p.user_id`

func scanPrincipal(sc scanner) (*Principal, error) {
	var (
		p                Principal
		userID           sql.NullInt64
		maxTicket        int64
		maxRenew         int64
		pwLastSet        sql.NullInt64
		pwExpires        sql.NullInt64
		expires          sql.NullInt64
		locked           sql.NullInt64
		lastSuccess      sql.NullInt64
		lastFailure      sql.NullInt64
		created, updated int64
	)

	if err := sc.Scan(
		&p.ID, &p.Name, &p.Realm, &userID, &p.KVNO, &p.Enabled, &p.RequiresPreAuth,
		&p.AllowForwardable, &p.AllowProxiable, &p.AllowRenewable, &p.AllowPostdate,
		&p.OKAsDelegate, &p.OKToAuthAsDelegate, &maxTicket, &maxRenew,
		&pwLastSet, &pwExpires, &expires, &locked,
		&p.FailCount, &lastSuccess, &lastFailure, &created, &updated, &p.UserName,
	); err != nil {
		return nil, err
	}

	if userID.Valid {
		id := userID.Int64
		p.UserID = &id
	}

	p.MaxTicketLife = time.Duration(maxTicket) * time.Second
	p.MaxRenewableLife = time.Duration(maxRenew) * time.Second
	p.PasswordLastSet = timeFrom(pwLastSet)
	p.PasswordExpiresAt = timeFrom(pwExpires)
	p.ExpiresAt = timeFrom(expires)
	p.LockedUntil = timeFrom(locked)
	p.LastSuccess = timeFrom(lastSuccess)
	p.LastFailure = timeFrom(lastFailure)
	p.CreatedAt = time.Unix(created, 0).UTC()
	p.UpdatedAt = time.Unix(updated, 0).UTC()

	return &p, nil
}

// ListPrincipals returns principals without their key material, optionally filtered by realm.
func (s *Store) ListPrincipals(ctx context.Context, realm string) ([]Principal, error) {
	query := principalSelect
	args := []any{}

	if len(realm) > 0 {
		query += ` WHERE p.realm = ?`
		args = append(args, strings.ToUpper(realm))
	}
	query += ` ORDER BY p.realm, p.name`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var (
		out []Principal
		ids []int64
	)

	for rows.Next() {
		p, err := scanPrincipal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
		ids = append(ids, p.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	targets, err := s.loadPrincipalLists(ctx, s.db, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].AllowedToDelegateTo = targets.delegateTo[out[i].ID]
		out[i].AllowedToImpersonate = targets.impersonate[out[i].ID]
		out[i].Aliases = targets.aliases[out[i].ID]
	}

	return out, nil
}

// GetPrincipal loads a principal together with the keys of its current kvno.
func (s *Store) GetPrincipal(ctx context.Context, name krbkeys.Name) (*Principal, error) {
	return s.getPrincipal(ctx, s.db, name, 0)
}

// GetPrincipalKVNO loads a principal with the keys of a specific key version. A kvno of zero means
// the current one. Decrypting a ticket that was sealed before the last password change needs this.
func (s *Store) GetPrincipalKVNO(ctx context.Context, name krbkeys.Name, kvno int) (*Principal, error) {
	return s.getPrincipal(ctx, s.db, name, kvno)
}

func (s *Store) getPrincipal(ctx context.Context, q querier, name krbkeys.Name, kvno int) (*Principal, error) {
	p, err := scanPrincipal(q.QueryRowContext(ctx,
		principalSelect+` WHERE p.name = ? AND p.realm = ?`, name.Principal(), name.Realm))

	// A name nobody holds canonically may still be one of its aliases, which is the whole point
	// of having them: both names reach the same keys, and only the reply says which is real.
	if errors.Is(err, sql.ErrNoRows) {
		p, err = scanPrincipal(q.QueryRowContext(ctx, principalSelect+`
			WHERE p.id = (SELECT principal_id FROM principal_aliases
			              WHERE name = ? AND realm = ?)`, name.Principal(), name.Realm))
	}

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if kvno == 0 {
		kvno = p.KVNO
	}

	if p.Keys, err = s.loadKeys(ctx, q, p.ID, kvno); err != nil {
		return nil, err
	}

	lists, err := s.loadPrincipalLists(ctx, q, []int64{p.ID})
	if err != nil {
		return nil, err
	}
	p.AllowedToDelegateTo = lists.delegateTo[p.ID]
	p.AllowedToImpersonate = lists.impersonate[p.ID]
	p.Aliases = lists.aliases[p.ID]

	return p, nil
}

// loadKeys returns the decrypted keys of one key version, in stored preference order.
func (s *Store) loadKeys(ctx context.Context, q querier, principalID int64, kvno int) ([]krbkeys.Key, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT etype, key, salt, s2kparams
		FROM principal_keys WHERE principal_id = ? AND kvno = ?
		ORDER BY position, etype`, principalID, kvno)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []krbkeys.Key

	for rows.Next() {
		var (
			k      krbkeys.Key
			sealed []byte
		)
		if err := rows.Scan(&k.EType, &sealed, &k.Salt, &k.S2KParams); err != nil {
			return nil, err
		}

		if k.Value, err = s.openKey(principalID, kvno, k.EType, sealed); err != nil {
			return nil, fmt.Errorf("principal key %d/%d: %w", principalID, kvno, err)
		}

		out = append(out, k)
	}

	return out, rows.Err()
}

// CreatePrincipal inserts a principal with the given keys at kvno 1.
func (s *Store) CreatePrincipal(ctx context.Context, p *Principal, keys []krbkeys.Key) error {
	name, err := krbkeys.ParseName(p.Name, p.Realm)
	if err != nil {
		return err
	}

	p.Name = name.Principal()
	p.Realm = name.Realm

	if p.KVNO <= 0 {
		p.KVNO = 1
	}

	now := time.Now().UTC()

	return s.write(ctx, func(tx *sql.Tx) error {
		// The unique index catches a clash with another principal's own name; a clash with
		// somebody's alias spans two tables and has to be checked here.
		taken, err := s.nameTaken(ctx, tx, name, 0)
		if err != nil {
			return err
		}
		if taken {
			return fmt.Errorf("%w: %s already names a principal in this realm", ErrConflict, name)
		}

		res, err := tx.ExecContext(ctx, `
			INSERT INTO principals (name, realm, user_id, kvno, enabled, requires_preauth,
			        allow_forwardable, allow_proxiable, allow_renewable, allow_postdate,
			        ok_as_delegate, ok_to_auth_as_delegate, max_ticket_life, max_renewable_life,
			        password_last_set, password_expires_at, expires_at, locked_until,
			        created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			p.Name, p.Realm, userIDArg(p.UserID), p.KVNO, p.Enabled, p.RequiresPreAuth,
			p.AllowForwardable, p.AllowProxiable, p.AllowRenewable, p.AllowPostdate,
			p.OKAsDelegate, p.OKToAuthAsDelegate,
			int64(p.MaxTicketLife/time.Second), int64(p.MaxRenewableLife/time.Second),
			nullTime(p.PasswordLastSet), nullTime(p.PasswordExpiresAt),
			nullTime(p.ExpiresAt), nullTime(p.LockedUntil),
			now.Unix(), now.Unix())
		if err != nil {
			return err
		}

		if p.ID, err = res.LastInsertId(); err != nil {
			return err
		}

		p.CreatedAt = now
		p.UpdatedAt = now
		p.Keys = keys

		if err := s.writeKeys(ctx, tx, p.ID, p.KVNO, keys); err != nil {
			return err
		}

		if err := s.replacePrincipalLists(ctx, tx, p); err != nil {
			return err
		}

		return s.replaceAliases(ctx, tx, p)
	})
}

// UpdatePrincipal loads a principal, applies mutate and writes it back. Key material is not
// touched; use SetKeys for that.
func (s *Store) UpdatePrincipal(ctx context.Context, name krbkeys.Name, mutate func(*Principal) error) (*Principal, error) {
	var out *Principal

	err := s.write(ctx, func(tx *sql.Tx) error {
		p, err := s.getPrincipal(ctx, tx, name, 0)
		if err != nil {
			return err
		}
		if err := mutate(p); err != nil {
			return err
		}

		now := time.Now().UTC()

		if _, err := tx.ExecContext(ctx, `
			UPDATE principals SET enabled = ?, requires_preauth = ?, allow_forwardable = ?,
			       allow_proxiable = ?, allow_renewable = ?, allow_postdate = ?,
			       ok_as_delegate = ?, ok_to_auth_as_delegate = ?, max_ticket_life = ?,
			       max_renewable_life = ?, password_expires_at = ?, expires_at = ?,
			       locked_until = ?, fail_count = ?, updated_at = ?
			WHERE id = ?`,
			p.Enabled, p.RequiresPreAuth, p.AllowForwardable, p.AllowProxiable,
			p.AllowRenewable, p.AllowPostdate, p.OKAsDelegate, p.OKToAuthAsDelegate,
			int64(p.MaxTicketLife/time.Second), int64(p.MaxRenewableLife/time.Second),
			nullTime(p.PasswordExpiresAt), nullTime(p.ExpiresAt), nullTime(p.LockedUntil),
			p.FailCount, now.Unix(), p.ID,
		); err != nil {
			return err
		}

		if err := s.replacePrincipalLists(ctx, tx, p); err != nil {
			return err
		}

		if err := s.replaceAliases(ctx, tx, p); err != nil {
			return err
		}

		p.UpdatedAt = now
		out = p

		return nil
	})

	return out, err
}

// DeletePrincipal removes a principal and its keys.
func (s *Store) DeletePrincipal(ctx context.Context, name krbkeys.Name) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM principals WHERE name = ? AND realm = ?`, name.Principal(), name.Realm)
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

// SetKeys installs a new key version for the principal, bumping its kvno and pruning key versions
// older than keyGenerationsKept.
func (s *Store) SetKeys(ctx context.Context, name krbkeys.Name, keys []krbkeys.Key, passwordSet time.Time) (*Principal, error) {
	var out *Principal

	err := s.write(ctx, func(tx *sql.Tx) error {
		p, err := s.getPrincipal(ctx, tx, name, 0)
		if err != nil {
			return err
		}
		if err := s.rollKeys(ctx, tx, p, keys, passwordSet); err != nil {
			return err
		}

		out = p

		return nil
	})

	return out, err
}

// rollKeys installs keys as the principal's next key version and updates p in place. Retiring the
// old version rather than overwriting it is what lets tickets and keytabs from before the change
// keep working until they expire.
func (s *Store) rollKeys(ctx context.Context, tx *sql.Tx, p *Principal, keys []krbkeys.Key, passwordSet time.Time) error {
	kvno := p.KVNO + 1

	if err := s.writeKeys(ctx, tx, p.ID, kvno, keys); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM principal_keys WHERE principal_id = ? AND kvno <= ?`,
		p.ID, kvno-keyGenerationsKept,
	); err != nil {
		return err
	}

	now := time.Now().UTC()
	if passwordSet.IsZero() {
		passwordSet = now
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE principals SET kvno = ?, password_last_set = ?, fail_count = 0,
		       locked_until = NULL, updated_at = ?
		WHERE id = ?`,
		kvno, passwordSet.Unix(), now.Unix(), p.ID,
	); err != nil {
		return err
	}

	p.KVNO = kvno
	p.Keys = keys
	p.PasswordLastSet = &passwordSet
	p.FailCount = 0
	p.LockedUntil = nil
	p.UpdatedAt = now

	return nil
}

func (s *Store) writeKeys(ctx context.Context, tx *sql.Tx, principalID int64, kvno int, keys []krbkeys.Key) error {
	if len(keys) == 0 {
		return fmt.Errorf("refusing to store a principal with no keys")
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM principal_keys WHERE principal_id = ? AND kvno = ?`, principalID, kvno,
	); err != nil {
		return err
	}

	now := time.Now().Unix()

	for i, k := range keys {
		sealed, err := s.sealKey(principalID, kvno, k)
		if err != nil {
			return fmt.Errorf("sealing key: %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO principal_keys (principal_id, kvno, etype, position, key, salt, s2kparams, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			principalID, kvno, k.EType, i, sealed, k.Salt, k.S2KParams, now,
		); err != nil {
			return err
		}
	}

	return nil
}

// LockoutPolicy bounds password guessing against a principal, with the three knobs FreeIPA
// exposes as krbPwdMaxFailure, krbPwdFailureCountInterval and krbPwdLockoutDuration.
type LockoutPolicy struct {
	// MaxFailures is how many failures in a row lock the principal. Zero disables lockout.
	MaxFailures int
	// FailureCountInterval is how long a failure counts towards the total. Without it a
	// handful of typos spread over a year would eventually lock an account that nobody is
	// attacking.
	FailureCountInterval time.Duration
	// LockoutDuration is how long the principal stays locked.
	LockoutDuration time.Duration
}

// RecordAuthResult updates the principal's counters after an authentication attempt, applying the
// lockout policy on failure. This is what keeps an exposed KDC port from being a free
// offline-guessing oracle.
func (s *Store) RecordAuthResult(ctx context.Context, id int64, ok bool, policy LockoutPolicy) error {
	now := time.Now().UTC()

	return s.write(ctx, func(tx *sql.Tx) error {
		if ok {
			_, err := tx.ExecContext(ctx, `
				UPDATE principals SET fail_count = 0, locked_until = NULL,
				       last_success = ?, updated_at = ?
				WHERE id = ?`, now.Unix(), now.Unix(), id)

			return err
		}

		var (
			fails       int
			lastFailure sql.NullInt64
		)

		if err := tx.QueryRowContext(ctx,
			`SELECT fail_count, last_failure FROM principals WHERE id = ?`, id,
		).Scan(&fails, &lastFailure); err != nil {
			return err
		}

		// Failures older than the interval no longer count, so the tally reflects a burst of
		// attempts rather than the account's whole history.
		if policy.FailureCountInterval > 0 && lastFailure.Valid {
			if now.Sub(time.Unix(lastFailure.Int64, 0)) > policy.FailureCountInterval {
				fails = 0
			}
		}
		fails++

		var lockUntil any
		if policy.MaxFailures > 0 && fails >= policy.MaxFailures && policy.LockoutDuration > 0 {
			lockUntil = now.Add(policy.LockoutDuration).Unix()
		}

		_, err := tx.ExecContext(ctx, `
			UPDATE principals SET fail_count = ?, locked_until = ?, last_failure = ?, updated_at = ?
			WHERE id = ?`, fails, lockUntil, now.Unix(), now.Unix(), id)

		return err
	})
}

// PrincipalsForUser returns the principals attached to a user.
func (s *Store) PrincipalsForUser(ctx context.Context, userID int64) ([]Principal, error) {
	rows, err := s.db.QueryContext(ctx, principalSelect+` WHERE p.user_id = ? ORDER BY p.name`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var (
		out []Principal
		ids []int64
	)

	for rows.Next() {
		p, err := scanPrincipal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
		ids = append(ids, p.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	aliases, err := s.loadAliases(ctx, s.db, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Aliases = aliases[out[i].ID]
	}

	return out, nil
}

// principalLists holds the per-principal name lists: the two that govern delegation, and the
// alternative names the principal answers to.
type principalLists struct {
	delegateTo  map[int64][]string
	impersonate map[int64][]string
	aliases     map[int64][]string
}

// loadPrincipalLists fetches the delegation targets, impersonation restrictions and aliases of
// several principals in one query each.
func (s *Store) loadPrincipalLists(ctx context.Context, q querier, ids []int64) (principalLists, error) {
	out := principalLists{
		delegateTo:  make(map[int64][]string, len(ids)),
		impersonate: make(map[int64][]string, len(ids)),
		aliases:     make(map[int64][]string, len(ids)),
	}

	if len(ids) == 0 {
		return out, nil
	}

	aliases, err := s.loadAliases(ctx, q, ids)
	if err != nil {
		return principalLists{}, err
	}
	out.aliases = aliases

	for _, t := range []struct {
		table string
		dst   map[int64][]string
	}{
		{"delegation_targets", out.delegateTo},
		{"impersonation_targets", out.impersonate},
	} {
		rows, err := q.QueryContext(ctx,
			`SELECT principal_id, target FROM `+t.table+`
			 WHERE principal_id IN (`+placeholders(len(ids))+`) ORDER BY target`,
			toAnySlice(ids)...)
		if err != nil {
			return principalLists{}, err
		}

		for rows.Next() {
			var (
				id     int64
				target string
			)
			if err := rows.Scan(&id, &target); err != nil {
				_ = rows.Close()

				return principalLists{}, err
			}
			t.dst[id] = append(t.dst[id], target)
		}
		if err := closeRows(rows); err != nil {
			return principalLists{}, err
		}
	}

	return out, nil
}

// replacePrincipalLists writes both name lists to match the in-memory principal.
func (s *Store) replacePrincipalLists(ctx context.Context, tx *sql.Tx, p *Principal) error {
	for _, t := range []struct {
		table  string
		values []string
	}{
		{"delegation_targets", p.AllowedToDelegateTo},
		{"impersonation_targets", p.AllowedToImpersonate},
	} {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM `+t.table+` WHERE principal_id = ?`, p.ID,
		); err != nil {
			return err
		}

		list := append([]string(nil), t.values...)
		sort.Strings(list)

		for _, v := range list {
			if len(v) == 0 {
				continue
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT OR IGNORE INTO `+t.table+` (principal_id, target) VALUES (?, ?)`,
				p.ID, v,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func userIDArg(id *int64) any {
	if id == nil {
		return nil
	}

	return *id
}

// PrimaryPrincipals returns, for every user that has one, the Kerberos principal named after the
// account. The LDAP front end publishes its Kerberos state alongside the POSIX attributes, and
// doing that one user at a time would be a query per entry in every search.
func (s *Store) PrimaryPrincipals(ctx context.Context) (map[int64]Principal, error) {
	rows, err := s.db.QueryContext(ctx,
		principalSelect+` WHERE p.user_id IS NOT NULL AND p.name = u.name ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var (
		out = make(map[int64]Principal)
		ids []int64
	)

	for rows.Next() {
		p, err := scanPrincipal(rows)
		if err != nil {
			return nil, err
		}
		if p.UserID != nil {
			out[*p.UserID] = *p
			ids = append(ids, p.ID)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	aliases, err := s.loadAliases(ctx, s.db, ids)
	if err != nil {
		return nil, err
	}
	for uid, p := range out {
		p.Aliases = aliases[p.ID]
		out[uid] = p
	}

	return out, nil
}

// ServicePrincipalsOfClass returns the principals in a realm whose service class matches, for
// example every "HTTP/..." there is. It exists to make an unknown service name diagnosable: the
// usual cause is a client that rewrote the host name, and knowing which hosts are registered is
// what tells an administrator that.
func (s *Store) ServicePrincipalsOfClass(ctx context.Context, service, realm string, limit int) ([]string, error) {
	// The class becomes a LIKE prefix, so its wildcards have to be neutralised or a service
	// named with a percent sign would match everything.
	pattern := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(service) + `/%`

	rows, err := s.db.QueryContext(ctx, `
		SELECT name FROM principals
		WHERE realm = ? AND name LIKE ? ESCAPE '\'
		ORDER BY name LIMIT ?`, strings.ToUpper(realm), pattern, limit)
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
