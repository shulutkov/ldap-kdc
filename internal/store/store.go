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

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // pure Go PostgreSQL driver, no cgo
	"github.com/rs/zerolog"
	_ "modernc.org/sqlite" // pure Go SQLite driver, no cgo

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/secret"
)

// Each dialect has a directory of its own: the migrations make the same tables, but in the types
// and syntax of the database they run on. A migration is the same file name in both.
//
//go:embed migrations
var migrationFS embed.FS

// writeLockKey is the PostgreSQL advisory lock that serializes write transactions across every
// process sharing a database, the way writeMu does within one.
const writeLockKey = 0x6c646b6463 // "ldkdc"

// migrateLockKey keeps two services starting at once from applying the same migration.
const migrateLockKey = writeLockKey + 1

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a write would violate uniqueness, e.g. a duplicate user name.
var ErrConflict = errors.New("conflict")

// Store owns the database connection and the sealer that protects key material in it.
type Store struct {
	db       *database
	dialect  dialect
	location string
	sealer   *secret.Sealer
	log      zerolog.Logger

	// idRange maps POSIX ids onto Windows relative identifiers. It is pinned by EnsureIDRange
	// and read on every object creation.
	idRange IDRange

	// hashCost is the bcrypt work factor for stored password digests.
	hashCost int

	// writeMu serializes write transactions. SQLite allows a single writer, and taking the
	// lock in the process is cheaper and far more predictable than letting concurrent writers
	// collide and retry on SQLITE_BUSY. On PostgreSQL it spares the pool connections that would
	// only queue on the advisory lock; the lock itself is what orders writers across processes.
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

// Open opens the database at target and brings its schema up to date. A postgres:// or
// postgresql:// URL names a PostgreSQL database, which has to exist. Anything else is SQLite: a
// sqlite:// URL, or the bare path of the file, created if needed.
func Open(ctx context.Context, target string, sealer *secret.Sealer, log zerolog.Logger, opts ...Option) (*Store, error) {
	d := targetDialect(target)

	var (
		raw *sql.DB
		err error
	)

	switch d {
	case dialectPostgres:
		raw, err = sql.Open("pgx", target)
	default:
		raw, err = openSQLite(strings.TrimPrefix(target, "sqlite://"))
	}
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// WAL lets readers run while the single writer holds its transaction, so a modest pool is
	// useful; the writer is serialized by writeMu rather than by the pool size.
	raw.SetMaxOpenConns(8)
	raw.SetMaxIdleConns(4)
	raw.SetConnMaxLifetime(time.Hour)

	if err := raw.PingContext(ctx); err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("opening database %s: %w", describeTarget(target, d), err)
	}

	s := &Store{
		db: &database{DB: raw, d: d}, dialect: d, location: describeTarget(target, d), sealer: sealer, log: log,
		idRange:  DefaultIDRange(),
		hashCost: DefaultPasswordHashCost,
	}

	for _, opt := range opts {
		opt(s)
	}

	if err := s.migrate(ctx); err != nil {
		_ = raw.Close()

		return nil, err
	}

	return s, nil
}

func openSQLite(path string) (*sql.DB, error) {
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

	return sql.Open("sqlite", dsn)
}

// describeTarget names a database for a message without the password a PostgreSQL URL may carry.
func describeTarget(target string, d dialect) string {
	if d != dialectPostgres {
		return "sqlite://" + strings.TrimPrefix(target, "sqlite://")
	}

	u, err := url.Parse(target)
	if err != nil {
		return "postgres"
	}

	return u.Redacted()
}

// Location names where the data lives for a log line: the SQLite file, or the PostgreSQL URL with
// its password removed.
func (s *Store) Location() string { return s.location }

// Dialect names the database the store runs on, "sqlite" or "postgres".
func (s *Store) Dialect() string { return s.dialect.String() }

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the connection for callers that need to run their own queries, such as health checks.
func (s *Store) DB() *sql.DB { return s.db.DB }

// migrate applies every embedded migration that has not been recorded yet, in name order.
func (s *Store) migrate(ctx context.Context) error {
	const createTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
		name       TEXT PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`

	if s.dialect == dialectPostgres {
		// Held for the whole run on one connection, so a second service starting against the same
		// database waits here until the first has finished, then finds nothing left to apply.
		conn, err := s.db.Conn(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()

		if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrateLockKey); err != nil {
			return fmt.Errorf("locking the schema: %w", err)
		}
		defer func() {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrateLockKey)
		}()
	}

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

	entries, err := fs.Glob(migrationFS, "migrations/"+s.dialect.String()+"/*.sql")
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
		// The script goes to the driver as written: it is not a query with placeholders, and a
		// question mark in one of its comments must stay a question mark.
		if _, err := tx.Tx.ExecContext(ctx, string(body)); err != nil {
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
func (s *Store) write(ctx context.Context, fn func(tx *Tx) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if s.dialect == dialectPostgres {
		// Released with the transaction. Several services may share the database, and the checks
		// made in Go under this lock -- that a name is free, that an id is unused -- hold only if
		// writers are ordered across all of them.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(?)`, writeLockKey); err != nil {
			_ = tx.Rollback()

			return err
		}
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
	return s.write(ctx, func(tx *Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO meta (key, value) VALUES (?, ?)
			 ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
			key, value,
		)

		return err
	})
}

// pgUniqueViolation is the SQLSTATE of a duplicate key.
const pgUniqueViolation = "23505"

// translateErr maps driver-level constraint violations onto the package's sentinel errors, so
// callers can answer "already exists" without matching on driver message text everywhere.
func translateErr(err error) error {
	if err == nil {
		return nil
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		return fmt.Errorf("%w: %s", ErrConflict, pgErr.Message)
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
// nullInt64 stores a pointer as an integer or as NULL, so a link that is absent is stored as no
// link rather than as a zero that means something else.
func nullInt64(v *int64) any {
	if v == nil {
		return nil
	}

	return *v
}

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
