package store

import (
	"context"
	"database/sql"
	"strings"
)

// querier is the part of *sql.DB and *sql.Tx this package needs, so read helpers can be reused
// inside a write transaction and see that transaction's own uncommitted rows.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// placeholders returns "?, ?, ..." with n entries, for an IN clause.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}

	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// toAnySlice converts a typed slice into the []any that database/sql wants for variadic args.
func toAnySlice[T any](in []T) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}

	return out
}
