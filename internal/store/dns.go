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
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	TTL       int       `json:"ttl"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// NormalizeDNSName puts a name in the form the store keeps: lower case, no trailing dot.
func NormalizeDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

const dnsRecordSelect = `SELECT id, name, type, ttl, value, created_at, updated_at FROM dns_records`

func scanDNSRecord(sc scanner) (*DNSRecord, error) {
	var (
		r                DNSRecord
		created, updated int64
	)

	if err := sc.Scan(&r.ID, &r.Name, &r.Type, &r.TTL, &r.Value, &created, &updated); err != nil {
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

// CreateDNSRecord adds a record.
func (s *Store) CreateDNSRecord(ctx context.Context, r *DNSRecord) error {
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

	now := time.Now().UTC()

	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO dns_records (name, type, ttl, value, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			r.Name, r.Type, r.TTL, r.Value, now.Unix(), now.Unix())
		if err != nil {
			return err
		}

		if r.ID, err = res.LastInsertId(); err != nil {
			return err
		}

		r.CreatedAt = now
		r.UpdatedAt = now

		return nil
	})
}

// DeleteDNSRecord removes one record by id.
func (s *Store) DeleteDNSRecord(ctx context.Context, id int64) error {
	return s.write(ctx, func(tx *sql.Tx) error {
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

		return nil
	})
}

// DeleteDNSRecordsAt removes every record at a name, optionally of one type only.
func (s *Store) DeleteDNSRecordsAt(ctx context.Context, name, recordType string) (int64, error) {
	var removed int64

	err := s.write(ctx, func(tx *sql.Tx) error {
		query := `DELETE FROM dns_records WHERE name = ?`
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

		return nil
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

// LatestDNSChange reports when the zone last changed, which becomes the SOA serial. A secondary
// comparing serials then sees the zone move exactly when its contents do.
func (s *Store) LatestDNSChange(ctx context.Context) (time.Time, error) {
	var latest sql.NullInt64

	if err := s.db.QueryRowContext(ctx,
		`SELECT MAX(updated_at) FROM dns_records`).Scan(&latest); err != nil {
		return time.Time{}, err
	}

	if !latest.Valid {
		return time.Time{}, nil
	}

	return time.Unix(latest.Int64, 0).UTC(), nil
}
