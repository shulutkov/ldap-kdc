package store

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"sync"
	"testing"
)

func TestRebind(t *testing.T) {
	cases := []struct{ in, sqlite, postgres string }{
		{"SELECT 1", "SELECT 1", "SELECT 1"},
		{"WHERE a = ? AND b = ?", "WHERE a = ? AND b = ?", "WHERE a = $1 AND b = $2"},
		{"WHERE a = '?' AND b = ?", "WHERE a = '?' AND b = ?", "WHERE a = '?' AND b = $1"},
		{`name LIKE ? ESCAPE '\' LIMIT ?`, `name LIKE ? ESCAPE '\' LIMIT ?`, `name LIKE $1 ESCAPE '\' LIMIT $2`},
	}

	for _, c := range cases {
		if got := dialectSQLite.rebind(c.in); got != c.sqlite {
			t.Errorf("sqlite rebind(%q) = %q, want %q", c.in, got, c.sqlite)
		}
		if got := dialectPostgres.rebind(c.in); got != c.postgres {
			t.Errorf("postgres rebind(%q) = %q, want %q", c.in, got, c.postgres)
		}
	}
}

func TestTargetDialect(t *testing.T) {
	for target, want := range map[string]dialect{
		"ldap-kdc.db":                   dialectSQLite,
		"sqlite://ldap-kdc.db":          dialectSQLite,
		"sqlite:///var/lib/x.db":        dialectSQLite,
		"/var/lib/ldap-kdc/ldap-kdc.db": dialectSQLite,
		"postgres://u:p@db/ldap":        dialectPostgres,
		"postgresql://db/ldap":          dialectPostgres,
	} {
		if got := targetDialect(target); got != want {
			t.Errorf("targetDialect(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestDescribeTargetHidesPassword(t *testing.T) {
	got := describeTarget("postgres://ldap:s3cret@db:5432/ldap", dialectPostgres)
	if got != "postgres://ldap:xxxxx@db:5432/ldap" {
		t.Fatalf("describeTarget = %q", got)
	}
}

// The two directories hold one migration each under the same name; a migration written for one
// database and forgotten for the other would leave their schemas apart.
func TestMigrationsMatchAcrossDialects(t *testing.T) {
	names := func(dir string) []string {
		entries, err := fs.ReadDir(migrationFS, "migrations/"+dir)
		if err != nil {
			t.Fatal(err)
		}

		out := make([]string, 0, len(entries))
		for _, e := range entries {
			out = append(out, e.Name())
		}

		return out
	}

	lite, pg := names("sqlite"), names("postgres")
	if len(lite) == 0 || len(lite) != len(pg) {
		t.Fatalf("sqlite has %v, postgres has %v", lite, pg)
	}
	for i := range lite {
		if lite[i] != pg[i] {
			t.Fatalf("sqlite has %v, postgres has %v", lite, pg)
		}
	}
}

func TestStoreRunsOnTheChosenDatabase(t *testing.T) {
	want := "sqlite"
	if len(os.Getenv(postgresEnv)) > 0 {
		want = "postgres"
	}

	if got := testStore(t).Dialect(); got != want {
		t.Fatalf("dialect = %s, want %s", got, want)
	}
}

// Two stores on one database stand for two services sharing it. Racing to create the same trust,
// exactly one may win and every other must see ErrConflict, which is the driver's duplicate-key
// error translated -- on PostgreSQL that is a SQLSTATE rather than a message.
func TestConflictsAcrossStoresAreTranslated(t *testing.T) {
	if len(os.Getenv(postgresEnv)) == 0 {
		t.Skip("needs " + postgresEnv + ": SQLite is a file for one process")
	}

	ctx := context.Background()
	target := testTarget(t, t.TempDir())
	a, b := testStoreAt(t, target), testStoreAt(t, target)

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)

	for i := 0; i < 8; i++ {
		st := a
		if i%2 == 1 {
			st = b
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			err := st.CreateTrust(ctx, &Trust{RemoteRealm: "OTHER.EXAMPLE", Direction: TrustOutbound, Transitive: true, Enabled: true})
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()

				return
			}
			if !errors.Is(err, ErrConflict) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}

	wg.Wait()

	if wins != 1 {
		t.Fatalf("%d creations won, want exactly 1", wins)
	}
}
