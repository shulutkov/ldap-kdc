package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	_ "modernc.org/sqlite" // pure Go SQLite driver, no cgo

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/secret"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a write would violate uniqueness, e.g. a duplicate user name.
var ErrConflict = errors.New("conflict")

// Store owns the database connection and the sealer that protects key material in it.
type Store struct {
	db     *sql.DB
	sealer *secret.Sealer
	log    zerolog.Logger

	// idRange maps POSIX ids onto Windows relative identifiers. It is pinned by EnsureIDRange
	// and read on every object creation.
	idRange IDRange

	// hashCost is the bcrypt work factor for stored password digests.
	hashCost int

	// writeMu serializes write transactions. SQLite allows a single writer, and taking the
	// lock in the process is cheaper and far more predictable than letting concurrent writers
	// collide and retry on SQLITE_BUSY.
	writeMu sync.Mutex
}

// Option adjusts a store at construction.
type Option func(*Store)

// WithPasswordHashCost sets the bcrypt work factor.
//
// It exists for tests. Hashing at the production cost is deliberately slow, and a suite that does
// it a hundred times spends minutes proving nothing about the cost; worse, on a loaded machine the
// delay pushes a password change past the five second deadline a Kerberos client allows for a
// reply. Nothing outside this repository can reach it: the package is internal.
func WithPasswordHashCost(cost int) Option {
	return func(s *Store) { s.hashCost = cost }
}

// Open opens (creating if needed) the database at path and brings its schema up to date.
func Open(ctx context.Context, path string, sealer *secret.Sealer, log zerolog.Logger, opts ...Option) (*Store, error) {
	if dir := filepath.Dir(path); len(dir) > 0 && dir != "." {
		if err := ensureDir(dir); err != nil {
			return nil, err
		}
	}

	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(10000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// WAL lets readers run while the single writer holds its transaction, so a modest pool is
	// useful; the writer is serialized by writeMu rather than by the pool size.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()

		return nil, fmt.Errorf("opening database %s: %w", path, err)
	}

	s := &Store{
		db: db, sealer: sealer, log: log,
		idRange:  DefaultIDRange(),
		hashCost: DefaultPasswordHashCost,
	}

	for _, opt := range opts {
		opt(s)
	}

	if err := s.migrate(ctx); err != nil {
		_ = db.Close()

		return nil, err
	}

	return s, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the connection for callers that need to run their own queries, such as health checks.
func (s *Store) DB() *sql.DB { return s.db }

// migrate applies every embedded migration that has not been recorded yet, in name order.
func (s *Store) migrate(ctx context.Context) error {
	const createTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
		name       TEXT PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`

	if _, err := s.db.ExecContext(ctx, createTable); err != nil {
		return fmt.Errorf("creating migration table: %w", err)
	}

	applied := make(map[string]bool)

	rows, err := s.db.QueryContext(ctx, `SELECT name FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("reading applied migrations: %w", err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			_ = rows.Close()

			return err
		}
		applied[n] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()

		return err
	}
	_ = rows.Close()

	entries, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(entries)

	for _, e := range entries {
		name := filepath.Base(e)
		if applied[name] {
			continue
		}

		body, err := migrationFS.ReadFile(e)
		if err != nil {
			return err
		}

		s.log.Info().Str("migration", name).Msg("applying migration")

		// Each migration runs in its own transaction so a failure leaves the schema at the
		// last complete version rather than half way through.
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()

			return fmt.Errorf("applying migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)`,
			name, time.Now().Unix(),
		); err != nil {
			_ = tx.Rollback()

			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %s: %w", name, err)
		}
	}

	return nil
}

// write runs fn inside a write transaction, serialized against other writers.
func (s *Store) write(ctx context.Context, fn func(tx *sql.Tx) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		_ = tx.Rollback()

		return translateErr(err)
	}

	if err := tx.Commit(); err != nil {
		return translateErr(err)
	}

	return nil
}

// GetMeta reads a metadata value, returning ErrNotFound when the key is absent.
func (s *Store) GetMeta(ctx context.Context, key string) (string, error) {
	var v string

	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}

	return v, err
}

// SetMeta writes a metadata value.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO meta (key, value) VALUES (?, ?)
			 ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
			key, value,
		)

		return err
	})
}

// translateErr maps driver-level constraint violations onto the package's sentinel errors, so
// callers can answer "already exists" without matching on driver message text everywhere.
func translateErr(err error) error {
	if err == nil {
		return nil
	}

	msg := err.Error()
	switch {
	case strings.Contains(msg, "UNIQUE constraint failed"),
		strings.Contains(msg, "PRIMARY KEY constraint failed"):
		return fmt.Errorf("%w: %s", ErrConflict, msg)
	default:
		return err
	}
}

// sealKey encrypts key material for storage. The principal id and kvno are bound in as associated
// data so a sealed key cannot be moved to another principal's row and be decrypted there.
func (s *Store) sealKey(principalID int64, kvno int, k krbkeys.Key) ([]byte, error) {
	return s.sealer.Seal(k.Value, keyContext(principalID, kvno, k.EType))
}

func (s *Store) openKey(principalID int64, kvno int, etype int32, sealed []byte) ([]byte, error) {
	return s.sealer.Open(sealed, keyContext(principalID, kvno, etype))
}

func keyContext(principalID int64, kvno int, etype int32) string {
	return fmt.Sprintf("principal-key:%d:%d:%d", principalID, kvno, etype)
}

// nullTime converts an optional time into a nullable SQL integer.
func nullTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}

	return t.Unix()
}

// timeFrom converts a nullable SQL integer back into an optional time.
func timeFrom(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}

	t := time.Unix(v.Int64, 0).UTC()

	return &t
}
