package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrInvalidAttribute reports a custom attribute a directory object may not carry. It is a
// sentinel because both front ends have to answer it as a rejected request rather than as a
// failure of theirs: a bad request over LDAP is a constraint violation, over REST a 400.
var ErrInvalidAttribute = errors.New("invalid custom attribute")

// reservedAttrNames are the entry attributes the LDAP front end builds for itself, in the
// lower-case form LDAP compares names in.
//
// A custom attribute under one of these names would appear twice in the entry, which is malformed;
// and a directory whose attributes decide authorization elsewhere must not let one be forged. An
// account given memberOf or objectClass as a custom attribute would be claiming, in the same words
// the real ones use, a membership nobody granted it.
var reservedAttrNames = map[string]bool{
	"accountstatus": true, "cn": true, "description": true, "dn": true, "entrydn": true,
	"gecos": true, "gidnumber": true, "givenname": true, "hassubordinates": true,
	"homedirectory": true, "ipantsecurityidentifier": true, "ipasshpubkey": true,
	"krbcanonicalname": true, "krblastfailedauth": true, "krblastpwdchange": true,
	"krblastsuccessfulauth": true, "krbloginfailedcount": true, "krbmaxrenewableage": true,
	"krbmaxticketlife": true, "krbpasswordexpiration": true, "krbprincipalexpiration": true,
	"krbprincipalname": true, "krbticketflags": true, "loginshell": true, "mail": true,
	"member": true, "memberof": true, "memberuid": true, "objectclass": true, "ou": true,
	"shadowexpire": true, "shadowflag": true, "shadowinactive": true, "shadowlastchange": true,
	"shadowmax": true, "shadowmin": true, "shadowwarning": true, "sn": true,
	"sshpublickey": true, "uid": true, "uidnumber": true, "uniquemember": true,
	"userprincipalname": true,
}

// ValidateCustomAttrs rejects the attribute names a directory object may not carry.
//
// The rule lives here rather than in the LDAP package because this is the one place every write
// passes through -- the API, the bootstrap and an LDAP modify all end up here -- and because
// ldapsrv imports the store, not the other way round.
func ValidateCustomAttrs(attrs map[string][]string) error {
	for name, values := range attrs {
		trimmed := strings.TrimSpace(name)

		switch {
		case len(trimmed) != len(name) || len(trimmed) == 0:
			return fmt.Errorf("%w: %q is empty or padded with spaces", ErrInvalidAttribute, name)
		case reservedAttrNames[strings.ToLower(trimmed)]:
			return fmt.Errorf("%w: %q is built by the directory itself and cannot be overridden",
				ErrInvalidAttribute, name)
		}

		for _, v := range values {
			if len(v) == 0 {
				return fmt.Errorf("%w: %q has an empty value", ErrInvalidAttribute, name)
			}
		}
	}

	return nil
}

// loadAttrs fetches the custom attributes of several objects of one kind in a single query.
func (s *Store) loadAttrs(ctx context.Context, q querier, kind string, ownerIDs []int64) (map[int64]map[string][]string, error) {
	out := make(map[int64]map[string][]string, len(ownerIDs))

	if len(ownerIDs) == 0 {
		return out, nil
	}

	args := append([]any{kind}, toAnySlice(ownerIDs)...)

	rows, err := q.QueryContext(ctx,
		`SELECT owner_id, name, value FROM object_attrs
		 WHERE owner_kind = ? AND owner_id IN (`+placeholders(len(ownerIDs))+`)
		 ORDER BY name, position`, args...)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var (
			id          int64
			name, value string
		)
		if err := rows.Scan(&id, &name, &value); err != nil {
			_ = rows.Close()

			return nil, err
		}

		if out[id] == nil {
			out[id] = make(map[string][]string)
		}
		out[id][name] = append(out[id][name], value)
	}

	return out, closeRows(rows)
}

// replaceAttrs writes an object's custom attributes to match the value in memory.
func (s *Store) replaceAttrs(ctx context.Context, tx *sql.Tx, kind string, ownerID int64, attrs map[string][]string) error {
	if err := ValidateCustomAttrs(attrs); err != nil {
		return err
	}

	if err := deleteAttrs(ctx, tx, kind, ownerID); err != nil {
		return err
	}

	names := make([]string, 0, len(attrs))
	for n := range attrs {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		for i, v := range attrs[n] {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO object_attrs (owner_kind, owner_id, name, position, value)
				VALUES (?, ?, ?, ?, ?)`, kind, ownerID, n, i, v,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

// deleteAttrs removes every custom attribute of one object. The table is shared by both kinds of
// object and so cannot carry a foreign key, which is why a deletion has to say so explicitly.
func deleteAttrs(ctx context.Context, tx *sql.Tx, kind string, ownerID int64) error {
	_, err := tx.ExecContext(ctx,
		`DELETE FROM object_attrs WHERE owner_kind = ? AND owner_id = ?`, kind, ownerID)

	return err
}
