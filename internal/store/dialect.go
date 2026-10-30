package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

// dialect is the database the store runs on. The two share the schema's shape and almost all of
// the SQL; what differs is confined to this file, the migrations directory each has, and the few
// statements that would not be portable as written.
type dialect int

const (
	dialectSQLite dialect = iota
	dialectPostgres
)

// targetDialect tells a PostgreSQL connection URL from a SQLite file path. A path never starts
// with a URL scheme, so the scheme alone is enough to choose.
func targetDialect(target string) dialect {
	if strings.HasPrefix(target, "postgres://") || strings.HasPrefix(target, "postgresql://") {
		return dialectPostgres
	}

	return dialectSQLite
}

func (d dialect) String() string {
	if d == dialectPostgres {
		return "postgres"
	}

	return "sqlite"
}

// rebind rewrites the "?" placeholders every query in this package is written with into the
// numbered ones PostgreSQL wants. A "?" inside a string literal is text, not a placeholder.
func (d dialect) rebind(query string) string {
	if d != dialectPostgres || !strings.Contains(query, "?") {
		return query
	}

	var (
		b       strings.Builder
		n       int
		literal bool
	)

	b.Grow(len(query) + 8)

	for i := 0; i < len(query); i++ {
		switch c := query[i]; {
		case c == '\'':
			literal = !literal
			b.WriteByte(c)
		case c == '?' && !literal:
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		default:
			b.WriteByte(c)
		}
	}

	return b.String()
}

// database is a *sql.DB whose queries take "?" placeholders on either dialect.
type database struct {
	*sql.DB
	d dialect
}

func (db *database) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return db.DB.ExecContext(ctx, db.d.rebind(query), args...)
}

func (db *database) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return db.DB.QueryContext(ctx, db.d.rebind(query), args...)
}

func (db *database) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return db.DB.QueryRowContext(ctx, db.d.rebind(query), args...)
}

func (db *database) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	tx, err := db.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &Tx{Tx: tx, d: db.d}, nil
}

// Tx is a *sql.Tx with the same placeholder rewriting as database.
type Tx struct {
	*sql.Tx
	d dialect
}

func (tx *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return tx.Tx.ExecContext(ctx, tx.d.rebind(query), args...)
}

func (tx *Tx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return tx.Tx.QueryContext(ctx, tx.d.rebind(query), args...)
}

func (tx *Tx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return tx.Tx.QueryRowContext(ctx, tx.d.rebind(query), args...)
}

// insertID runs an INSERT into a table with an "id" key and returns the key it was given.
// RETURNING does what LastInsertId does on SQLite, which PostgreSQL's driver has no equivalent of.
func insertID(ctx context.Context, q querier, query string, args ...any) (int64, error) {
	var id int64

	if err := q.QueryRowContext(ctx, query+" RETURNING id", args...).Scan(&id); err != nil {
		return 0, err
	}

	return id, nil
}
