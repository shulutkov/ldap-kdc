package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Metadata keys holding the realm's identifier range.
const (
	MetaIDRangeBaseID           = "id_range_base_id"
	MetaIDRangeSize             = "id_range_size"
	MetaIDRangeBaseRID          = "id_range_base_rid"
	MetaIDRangeSecondaryBaseRID = "id_range_secondary_base_rid"
)

// IDRange maps POSIX ids onto Windows relative identifiers, the way FreeIPA's ipa-local range does.
//
// A RID is the tail of a security identifier, and Windows reserves everything below 1000 for
// well-known accounts: 500 is the domain administrator, 512 the domain admins group. Handing a
// POSIX id straight to a client as a RID would let uid 500 present itself as the administrator, so
// the range shifts ids to BaseRID and refuses anything outside its span.
type IDRange struct {
	// BaseID is the lowest POSIX id the range covers.
	BaseID int `json:"baseID"`
	// Size is how many consecutive ids it covers.
	Size int `json:"size"`
	// BaseRID is where the primary RID interval starts.
	BaseRID int `json:"baseRID"`
	// SecondaryBaseRID starts the interval an object falls back to when its primary RID is
	// already taken, which is how a user and a group with the same POSIX id stay distinct.
	SecondaryBaseRID int `json:"secondaryBaseRID"`
}

// DefaultIDRange covers the POSIX id space a directory normally allocates from, with both RID
// intervals clear of the well-known range and of each other.
func DefaultIDRange() IDRange {
	return IDRange{
		BaseID:           1,
		Size:             200000,
		BaseRID:          1000,
		SecondaryBaseRID: 100000000,
	}
}

// Validate reports whether the range is usable: inside the 32 bit RID space, clear of the
// well-known RIDs, and with two intervals that do not overlap.
func (r IDRange) Validate() error {
	const wellKnownRIDCeiling = 1000

	switch {
	case r.BaseID <= 0:
		return errors.New("id range base id must be positive")
	case r.Size <= 0:
		return errors.New("id range size must be positive")
	case r.BaseRID < wellKnownRIDCeiling:
		return fmt.Errorf("id range base rid must be at least %d, below which Windows reserves the RIDs",
			wellKnownRIDCeiling)
	case r.SecondaryBaseRID < wellKnownRIDCeiling:
		return fmt.Errorf("id range secondary base rid must be at least %d", wellKnownRIDCeiling)
	}

	if int64(r.BaseID)+int64(r.Size) > int64(^uint32(0)) {
		return errors.New("id range runs past the end of the id space")
	}

	for _, base := range []int{r.BaseRID, r.SecondaryBaseRID} {
		if int64(base)+int64(r.Size) > int64(^uint32(0)) {
			return errors.New("id range runs past the end of the RID space")
		}
	}

	// Overlapping intervals would defeat the fallback: the secondary RID of one object could
	// be the primary RID of another.
	lo, hi := r.BaseRID, r.SecondaryBaseRID
	if lo > hi {
		lo, hi = hi, lo
	}
	if lo+r.Size > hi {
		return errors.New("the primary and secondary RID intervals overlap")
	}

	return nil
}

// Contains reports whether a POSIX id falls inside the range.
func (r IDRange) Contains(id int) bool {
	return id >= r.BaseID && id < r.BaseID+r.Size
}

// rids returns the primary and secondary RID a POSIX id maps to.
func (r IDRange) rids(id int) (primary, secondary int) {
	offset := id - r.BaseID

	return r.BaseRID + offset, r.SecondaryBaseRID + offset
}

// IDRange returns the range this database allocates identifiers from.
func (s *Store) IDRange() IDRange { return s.idRange }

// EnsureIDRange pins the identifier range and allocates a RID to every object still without one,
// which is what FreeIPA's sidgen task does after a range is configured.
func (s *Store) EnsureIDRange(ctx context.Context, want IDRange) (IDRange, error) {
	if err := want.Validate(); err != nil {
		return IDRange{}, err
	}

	stored, err := s.readIDRange(ctx)
	switch {
	case err != nil && !errors.Is(err, ErrNotFound):
		return IDRange{}, err
	case err == nil:
		// The SIDs already handed out are derived from these numbers and are baked into
		// every PAC a client has cached and every ACL a member server wrote from one.
		if stored != want {
			return IDRange{}, fmt.Errorf(
				"database was initialized with id range %+v, which does not match the configured %+v",
				stored, want)
		}
	default:
		if err := s.writeIDRange(ctx, want); err != nil {
			return IDRange{}, err
		}
	}

	s.idRange = want

	if err := s.backfillSecurityIdentifiers(ctx); err != nil {
		return IDRange{}, err
	}

	return want, nil
}

func (s *Store) readIDRange(ctx context.Context) (IDRange, error) {
	var out IDRange

	for _, f := range []struct {
		key string
		dst *int
	}{
		{MetaIDRangeBaseID, &out.BaseID},
		{MetaIDRangeSize, &out.Size},
		{MetaIDRangeBaseRID, &out.BaseRID},
		{MetaIDRangeSecondaryBaseRID, &out.SecondaryBaseRID},
	} {
		v, err := s.GetMeta(ctx, f.key)
		if err != nil {
			return IDRange{}, err
		}

		n, err := strconv.Atoi(v)
		if err != nil {
			return IDRange{}, fmt.Errorf("stored %s is not a number: %w", f.key, err)
		}
		*f.dst = n
	}

	return out, nil
}

func (s *Store) writeIDRange(ctx context.Context, r IDRange) error {
	for _, f := range []struct {
		key   string
		value int
	}{
		{MetaIDRangeBaseID, r.BaseID},
		{MetaIDRangeSize, r.Size},
		{MetaIDRangeBaseRID, r.BaseRID},
		{MetaIDRangeSecondaryBaseRID, r.SecondaryBaseRID},
	} {
		if err := s.SetMeta(ctx, f.key, strconv.Itoa(f.value)); err != nil {
			return err
		}
	}

	return nil
}

// allocateRID gives an object its relative identifier, preferring the primary interval and falling
// back to the secondary one when that RID is already spoken for.
//
// An object whose POSIX id lies outside the range gets no identifier at all. That is FreeIPA's
// answer too, and it is the safe one: the alternative is handing out a RID that means something
// else, which a member server would read as a different account entirely.
func (s *Store) allocateRID(ctx context.Context, tx *sql.Tx, kind string, ownerID int64, posixID int) error {
	if !s.idRange.Contains(posixID) {
		return nil
	}

	primary, secondary := s.idRange.rids(posixID)
	now := time.Now().Unix()

	for _, rid := range []int{primary, secondary} {
		res, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO security_identifiers (rid, owner_kind, owner_id, created_at)
			VALUES (?, ?, ?, ?)`, rid, kind, ownerID, now)
		if err != nil {
			return err
		}

		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
	}

	return fmt.Errorf("no free relative identifier for %s %d: both %d and %d are taken",
		kind, posixID, primary, secondary)
}

// releaseRID drops an object's identifier, so a later object with the same POSIX id can take it.
func releaseRID(ctx context.Context, tx *sql.Tx, kind string, ownerID int64) error {
	_, err := tx.ExecContext(ctx,
		`DELETE FROM security_identifiers WHERE owner_kind = ? AND owner_id = ?`, kind, ownerID)

	return err
}

// reallocateRID moves an object to the identifier its new POSIX id implies. Changing a uid or gid
// changes the SID a member server sees, which is why the API warns about it.
func (s *Store) reallocateRID(ctx context.Context, tx *sql.Tx, kind string, ownerID int64, posixID int) error {
	if err := releaseRID(ctx, tx, kind, ownerID); err != nil {
		return err
	}

	return s.allocateRID(ctx, tx, kind, ownerID, posixID)
}

// RID returns the relative identifier allocated to an object, and whether it has one.
func (s *Store) RID(ctx context.Context, kind string, ownerID int64) (int, bool, error) {
	return ridFor(ctx, s.db, kind, ownerID)
}

func ridFor(ctx context.Context, q querier, kind string, ownerID int64) (int, bool, error) {
	var rid int

	err := q.QueryRowContext(ctx,
		`SELECT rid FROM security_identifiers WHERE owner_kind = ? AND owner_id = ?`,
		kind, ownerID).Scan(&rid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}

	return rid, true, nil
}

// backfillSecurityIdentifiers allocates identifiers to objects created before the range was
// configured, or whose allocation previously failed.
func (s *Store) backfillSecurityIdentifiers(ctx context.Context) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		for _, t := range []struct {
			kind  string
			query string
		}{
			{"user", `SELECT u.id, u.uid_number FROM users u
				  LEFT JOIN security_identifiers s
				    ON s.owner_kind = 'user' AND s.owner_id = u.id
				  WHERE s.rid IS NULL`},
			{"group", `SELECT g.id, g.gid_number FROM groups g
				   LEFT JOIN security_identifiers s
				     ON s.owner_kind = 'group' AND s.owner_id = g.id
				   WHERE s.rid IS NULL`},
		} {
			rows, err := tx.QueryContext(ctx, t.query)
			if err != nil {
				return err
			}

			type pending struct {
				id      int64
				posixID int
			}

			var todo []pending

			for rows.Next() {
				var p pending
				if err := rows.Scan(&p.id, &p.posixID); err != nil {
					_ = rows.Close()

					return err
				}
				todo = append(todo, p)
			}
			if err := closeRows(rows); err != nil {
				return err
			}

			for _, p := range todo {
				if err := s.allocateRID(ctx, tx, t.kind, p.id, p.posixID); err != nil {
					// One object that cannot be given an identifier must not stop the
					// service from starting; it simply gets no PAC.
					s.log.Warn().Err(err).Str("kind", t.kind).Int64("id", p.id).
						Msg("could not allocate a security identifier")
				}
			}
		}

		return nil
	})
}

// SecurityIDs are the relative identifiers a PAC is built from.
type SecurityIDs struct {
	// User is the account's own RID.
	User int
	// PrimaryGroup is the RID of its primary group.
	PrimaryGroup int
	// Groups holds the RIDs of every group the account belongs to.
	Groups []int
}

// SecurityIDsForUser resolves an account and its group membership into relative identifiers.
// It reports false when the account itself has no identifier, in which case no PAC can be issued
// for it.
func (s *Store) SecurityIDsForUser(ctx context.Context, u *User, gids []int) (SecurityIDs, bool, error) {
	var out SecurityIDs

	rid, ok, err := s.RID(ctx, "user", u.ID)
	if err != nil || !ok {
		return out, false, err
	}
	out.User = rid

	for _, gid := range gids {
		g, err := s.GetGroupByGID(ctx, gid)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}

			return out, false, err
		}

		grid, ok, err := s.RID(ctx, "group", g.ID)
		if err != nil {
			return out, false, err
		}
		if !ok {
			continue
		}

		out.Groups = append(out.Groups, grid)

		if gid == u.PrimaryGroup {
			out.PrimaryGroup = grid
		}
	}

	return out, true, nil
}

// RIDs returns every allocated relative identifier of a kind, keyed by the object it belongs to.
func (s *Store) RIDs(ctx context.Context, kind string) (map[int64]int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT owner_id, rid FROM security_identifiers WHERE owner_kind = ?`, kind)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make(map[int64]int)

	for rows.Next() {
		var (
			id  int64
			rid int
		)
		if err := rows.Scan(&id, &rid); err != nil {
			return nil, err
		}
		out[id] = rid
	}

	return out, rows.Err()
}
