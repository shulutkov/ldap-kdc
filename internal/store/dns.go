package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// DNSRecord is one resource record of the realm's zone. Value holds the record data in the
// presentation form a zone file would use.
type DNSRecord struct {
	ID   int64  `json:"id"`
	Name string `json:"name" example:"www.example.com"`
	Type string `json:"type" example:"A"`
	TTL  int    `json:"ttl"`
	// Value is the record data. For an address record it is the address.
	Value string `json:"value" example:"192.0.2.10"`
	// Origin says who put the record in the zone: empty for an administrator, "docker:<container
	// id>" for a registration that follows a running container. An automatic record is removed by
	// its origin, not by the API.
	Origin    string    `json:"origin,omitempty" example:"docker:3f2a9c"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// NormalizeDNSName puts a name in the form the store keeps: lower case, no trailing dot.
func NormalizeDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

const dnsRecordSelect = `SELECT id, name, type, ttl, value, origin, created_at, updated_at FROM dns_records`

func scanDNSRecord(sc scanner) (*DNSRecord, error) {
	var (
		r                DNSRecord
		created, updated int64
	)

	if err := sc.Scan(&r.ID, &r.Name, &r.Type, &r.TTL, &r.Value, &r.Origin, &created, &updated); err != nil {
		return nil, err
	}

	r.CreatedAt = time.Unix(created, 0).UTC()
	r.UpdatedAt = time.Unix(updated, 0).UTC()

	return &r, nil
}

// ListDNSRecords returns every record, ordered by name.
func (s *Store) ListDNSRecords(ctx context.Context) ([]DNSRecord, error) {
	rows, err := s.db.QueryContext(ctx, dnsRecordSelect+` ORDER BY name, type, value`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return collectDNSRecords(rows)
}

// LookupDNSRecords returns every record at a name, whatever its type. Answering a query needs the
// whole set: which types exist at a name is what separates an empty answer from a missing name.
func (s *Store) LookupDNSRecords(ctx context.Context, name string) ([]DNSRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		dnsRecordSelect+` WHERE name = ? ORDER BY type, value`, NormalizeDNSName(name))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return collectDNSRecords(rows)
}

// ListDiscoveredDNSRecords returns the records a source registered automatically, such as
// "docker", ordered by name. An administrator's records are never among them.
func (s *Store) ListDiscoveredDNSRecords(ctx context.Context, source string) ([]DNSRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		dnsRecordSelect+` WHERE origin LIKE ? ORDER BY name, type, value`, source+":%")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return collectDNSRecords(rows)
}

// LookupDNSAddressNames returns the names whose address records hold addr.
//
// Reverse answers are derived from the forward records rather than stored as PTR rows of their
// own. FreeIPA keeps a second copy and a synchronisation task to hold the two together, because
// BIND reads zones; deriving the answer means it cannot drift in the first place.
func (s *Store) LookupDNSAddressNames(ctx context.Context, addr netip.Addr) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, ttl FROM dns_records WHERE type IN ('A', 'AAAA') AND value = ? ORDER BY name`,
		addr.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []string

	for rows.Next() {
		var (
			name string
			ttl  int
		)
		if err := rows.Scan(&name, &ttl); err != nil {
			return nil, err
		}
		out = append(out, name)
	}

	return out, rows.Err()
}

// validateDNSRecord checks what every record needs, whoever it is from.
func validateDNSRecord(r *DNSRecord) error {
	r.Name = NormalizeDNSName(r.Name)
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	r.Value = strings.TrimSpace(r.Value)

	switch {
	case len(r.Name) == 0:
		return errors.New("record name is required")
	case len(r.Type) == 0:
		return errors.New("record type is required")
	case len(r.Value) == 0:
		return errors.New("record value is required")
	case r.TTL <= 0:
		return errors.New("record ttl must be positive")
	}

	return nil
}

// CreateDNSRecord adds a record an administrator made. Its origin is empty whatever the caller set:
// an automatic record can only come from the source that owns it, so the API cannot mint one.
func (s *Store) CreateDNSRecord(ctx context.Context, r *DNSRecord) error {
	if err := validateDNSRecord(r); err != nil {
		return err
	}

	return s.insertDNSRecord(ctx, r, "")
}

// CreateDiscoveredDNSRecord adds a record a source registered automatically, tagged with the origin
// that owns it. The origin is what removes it again, so it must be given.
func (s *Store) CreateDiscoveredDNSRecord(ctx context.Context, origin string, r *DNSRecord) error {
	if len(origin) == 0 {
		return errors.New("a discovered record needs an origin")
	}
	if err := validateDNSRecord(r); err != nil {
		return err
	}

	return s.insertDNSRecord(ctx, r, origin)
}

func (s *Store) insertDNSRecord(ctx context.Context, r *DNSRecord, origin string) error {
	now := time.Now().UTC()
	r.Origin = origin

	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO dns_records (name, type, ttl, value, origin, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			r.Name, r.Type, r.TTL, r.Value, origin, now.Unix(), now.Unix())
		if err != nil {
			return err
		}

		if r.ID, err = res.LastInsertId(); err != nil {
			return err
		}

		r.CreatedAt = now
		r.UpdatedAt = now

		return bumpZoneSerial(ctx, tx)
	})
}

// DeleteDNSRecord removes one administrator's record by id. A registered record is refused with
// ErrConflict: it belongs to the source that registered it, and goes when that does.
func (s *Store) DeleteDNSRecord(ctx context.Context, id int64) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		var origin string

		err := tx.QueryRowContext(ctx, `SELECT origin FROM dns_records WHERE id = ?`, id).Scan(&origin)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}

		if len(origin) > 0 {
			return fmt.Errorf("%w: record %d is registered by %s and is removed when that is", ErrConflict, id, origin)
		}

		return deleteDNSRecordTx(ctx, tx, id)
	})
}

// DeleteDiscoveredDNSRecord removes a record a source registered, once that source no longer
// stands behind it. An administrator's record is refused.
func (s *Store) DeleteDiscoveredDNSRecord(ctx context.Context, id int64) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		var origin string

		err := tx.QueryRowContext(ctx, `SELECT origin FROM dns_records WHERE id = ?`, id).Scan(&origin)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}

		if len(origin) == 0 {
			return fmt.Errorf("%w: record %d is an administrator's, not a registration", ErrConflict, id)
		}

		return deleteDNSRecordTx(ctx, tx, id)
	})
}

func deleteDNSRecordTx(ctx context.Context, tx *sql.Tx, id int64) error {
	res, err := tx.ExecContext(ctx, `DELETE FROM dns_records WHERE id = ?`, id)
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

	return bumpZoneSerial(ctx, tx)
}

// DeleteDNSRecordsAt removes every administrator's record at a name, optionally of one type only.
// Registered records at the name are left where they are.
func (s *Store) DeleteDNSRecordsAt(ctx context.Context, name, recordType string) (int64, error) {
	var removed int64

	err := s.write(ctx, func(tx *sql.Tx) error {
		query := `DELETE FROM dns_records WHERE name = ? AND origin = ''`
		args := []any{NormalizeDNSName(name)}

		if len(recordType) > 0 {
			query += ` AND type = ?`
			args = append(args, strings.ToUpper(recordType))
		}

		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}

		if removed, err = res.RowsAffected(); err != nil {
			return err
		}
		if removed == 0 {
			return fmt.Errorf("%w: no records at %s", ErrNotFound, name)
		}

		return bumpZoneSerial(ctx, tx)
	})

	return removed, err
}

func collectDNSRecords(rows *sql.Rows) ([]DNSRecord, error) {
	var out []DNSRecord

	for rows.Next() {
		r, err := scanDNSRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}

	return out, rows.Err()
}

// bumpZoneSerial raises the zone's serial inside the write that changed the zone. It takes the
// time when that is later than the serial, and otherwise adds one, so two changes in the same
// second still leave the serial different.
func bumpZoneSerial(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE dns_zone SET serial = MAX(serial + 1, ?) WHERE id = 1`, time.Now().Unix())

	return err
}

// ZoneSerial reports the zone's SOA serial. A secondary comparing serials sees the zone move
// exactly when its contents do, removals included.
func (s *Store) ZoneSerial(ctx context.Context) (uint32, error) {
	var serial int64

	if err := s.db.QueryRowContext(ctx, `SELECT serial FROM dns_zone WHERE id = 1`).Scan(&serial); err != nil {
		return 0, err
	}

	return uint32(serial), nil
}
