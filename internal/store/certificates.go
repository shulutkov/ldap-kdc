package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// Certificate is one certificate an external authority has issued to an account and an
// administrator has imported. DER is the certificate itself; everything else is what listing,
// matching and directory publication need. The private key is never seen, let alone stored.
type Certificate struct {
	ID       int64  `json:"id"`
	UserName string `json:"userName"`
	// Issuer identifies the authority that issued the certificate: its authority key identifier
	// as lowercase hexadecimal, empty when the certificate carries none. Serial numbers are only
	// unique within one issuer, so the pair is what names a certificate.
	Issuer string `json:"issuer"`
	// Serial is the certificate's serial number as lowercase hexadecimal padded to an even
	// number of digits. It is text rather than an integer because an external authority's
	// serials do not fit into one: Vault, for one, issues 160-bit serial numbers.
	Serial    string    `json:"serial"`
	Subject   string    `json:"subject"`
	DER       []byte    `json:"-"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	CreatedAt time.Time `json:"createdAt"`
}

// normalizeSerial brings a serial number into the canonical spelling the table's UNIQUE
// constraint is meaningful under: lowercase, and padded with a leading zero to an even number
// of digits. It is applied on every write and lookup, so "AB", "ab" and "0ab" are one serial
// however the caller spelled it.
func normalizeSerial(serial string) string {
	s := strings.ToLower(serial)
	if len(s)%2 != 0 {
		s = "0" + s
	}

	return s
}

// AddCertificate stores an imported certificate. The serial is normalized on the way in, and
// its uniqueness within the issuer is the database's to enforce: the same certificate imported
// twice is a conflict, not a second row.
func (s *Store) AddCertificate(ctx context.Context, userName string, c *Certificate) error {
	c.Serial = normalizeSerial(c.Serial)
	c.Issuer = strings.ToLower(c.Issuer)

	return s.write(ctx, func(tx *sql.Tx) error {
		u, err := s.getUser(ctx, tx, `name = ?`, userName)
		if err != nil {
			return err
		}

		now := time.Now().UTC()
		res, err := tx.ExecContext(ctx, `
			INSERT INTO user_certificates
				(user_id, issuer, serial, subject, der, not_before, not_after, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			u.ID, c.Issuer, c.Serial, c.Subject, c.DER, c.NotBefore.Unix(), c.NotAfter.Unix(), now.Unix())
		if err != nil {
			return err
		}

		id, err := res.LastInsertId()
		if err != nil {
			return err
		}

		c.ID = id
		c.UserName = userName
		c.CreatedAt = now

		return nil
	})
}

const certificateSelect = `
	SELECT uc.id, u.name, uc.issuer, uc.serial, uc.subject, uc.der, uc.not_before, uc.not_after,
	       uc.created_at
	FROM user_certificates uc JOIN users u ON u.id = uc.user_id`

func (s *Store) listCertificates(ctx context.Context, q querier, where string, args ...any) ([]Certificate, error) {
	rows, err := q.QueryContext(ctx, certificateSelect+where, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Certificate
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}

	return out, rows.Err()
}

func scanCertificate(sc scanner) (*Certificate, error) {
	var (
		c        Certificate
		notBefor int64
		notAftr  int64
		created  int64
	)
	if err := sc.Scan(
		&c.ID, &c.UserName, &c.Issuer, &c.Serial, &c.Subject, &c.DER, &notBefor, &notAftr, &created,
	); err != nil {
		return nil, err
	}

	c.NotBefore = time.Unix(notBefor, 0).UTC()
	c.NotAfter = time.Unix(notAftr, 0).UTC()
	c.CreatedAt = time.Unix(created, 0).UTC()

	return &c, nil
}

// ListUserCertificates returns an account's certificates, oldest imported first.
func (s *Store) ListUserCertificates(ctx context.Context, userName string) ([]Certificate, error) {
	var out []Certificate

	err := s.readUser(ctx, userName, func(tx *sql.Tx) error {
		list, err := s.listCertificates(ctx, tx, ` WHERE u.name = ? ORDER BY uc.id`, userName)
		out = list

		return err
	})

	return out, err
}

// certificateBatch bounds how many accounts one query names. SQLite caps the parameters a
// statement may bind, and a directory with more accounts than that must still be read.
const certificateBatch = 500

// UserCertificates returns the certificates of the named accounts, grouped by the same ids the
// caller asked with, so a caller holding users it has already read need not re-read them. The
// ids are read in batches; a directory search over every account is one query per batch rather
// than one per account.
func (s *Store) UserCertificates(ctx context.Context, userIDs []int64) (map[int64][]Certificate, error) {
	out := make(map[int64][]Certificate, len(userIDs))

	seen := make(map[int64]bool, len(userIDs))
	ids := make([]int64, 0, len(userIDs))
	for _, id := range userIDs {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}

	for start := 0; start < len(ids); start += certificateBatch {
		if err := s.userCertificatesBatch(ctx, out, ids[start:min(start+certificateBatch, len(ids))]); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// userCertificatesBatch adds the certificates of one batch of accounts to out.
func (s *Store) userCertificatesBatch(ctx context.Context, out map[int64][]Certificate, ids []int64) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT uc.user_id, uc.id, u.name, uc.issuer, uc.serial, uc.subject, uc.der, uc.not_before,
		       uc.not_after, uc.created_at
		FROM user_certificates uc JOIN users u ON u.id = uc.user_id
		WHERE uc.user_id IN (`+placeholders(len(ids))+`) ORDER BY uc.user_id, uc.id`, toAnySlice(ids)...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			userID  int64
			c       Certificate
			notBef  int64
			notAft  int64
			created int64
		)
		if err := rows.Scan(
			&userID, &c.ID, &c.UserName, &c.Issuer, &c.Serial, &c.Subject, &c.DER, &notBef, &notAft, &created,
		); err != nil {
			return err
		}
		c.NotBefore = time.Unix(notBef, 0).UTC()
		c.NotAfter = time.Unix(notAft, 0).UTC()
		c.CreatedAt = time.Unix(created, 0).UTC()
		out[userID] = append(out[userID], c)
	}

	return rows.Err()
}

// GetCertificate returns one of an account's certificates, named by its issuer and serial.
func (s *Store) GetCertificate(ctx context.Context, userName string, issuer string, serial string) (*Certificate, error) {
	var out *Certificate

	issuer = strings.ToLower(issuer)
	serial = normalizeSerial(serial)

	err := s.readUser(ctx, userName, func(tx *sql.Tx) error {
		list, err := s.listCertificates(ctx, tx,
			` WHERE u.name = ? AND uc.issuer = ? AND uc.serial = ?`, userName, issuer, serial)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			return ErrNotFound
		}
		out = &list[0]

		return nil
	})

	return out, err
}

// DeleteCertificate removes one of an account's certificates, named by its issuer and serial.
// Removal rather than a revocation stamp is enough here: the certificate came from an authority
// elsewhere, and that authority's revocation list is where a still-valid certificate is called in.
func (s *Store) DeleteCertificate(ctx context.Context, userName string, issuer string, serial string) error {
	issuer = strings.ToLower(issuer)
	serial = normalizeSerial(serial)

	return s.write(ctx, func(tx *sql.Tx) error {
		u, err := s.getUser(ctx, tx, `name = ?`, userName)
		if err != nil {
			return err
		}

		res, err := tx.ExecContext(ctx,
			`DELETE FROM user_certificates WHERE user_id = ? AND issuer = ? AND serial = ?`,
			u.ID, issuer, serial)
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

// readUser runs fn inside a read that first proves the named account exists, so a missing account
// is ErrNotFound rather than an empty answer that looks like success. It is a plain read
// transaction: it does not take the write lock, so reading certificates never queues behind a
// write, and a write never queues behind a read of them.
func (s *Store) readUser(ctx context.Context, userName string, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := s.getUser(ctx, tx, `name = ?`, userName); err != nil {
		return err
	}

	return fn(tx)
}
