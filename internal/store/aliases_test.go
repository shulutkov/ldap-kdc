package store

import (
	"context"
	"errors"
	"testing"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
)

const aliasRealm = "EXAMPLE.COM"

// newPrincipal creates a principal with random keys, which is all these tests need of it.
func newPrincipal(t *testing.T, s *Store, name string, aliases ...string) *Principal {
	t.Helper()

	n := krbkeys.MustParseName(name, aliasRealm)

	keys, err := krbkeys.RandomKeys(testEncTypes(t))
	if err != nil {
		t.Fatalf("RandomKeys: %v", err)
	}

	p := &Principal{
		Name: n.Principal(), Realm: n.Realm, Enabled: true, RequiresPreAuth: true,
		Aliases: aliases,
	}
	if err := s.CreatePrincipal(context.Background(), p, keys); err != nil {
		t.Fatalf("CreatePrincipal(%s): %v", name, err)
	}

	return p
}

func TestAPrincipalIsFoundByItsAliases(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	newPrincipal(t, s, "HTTP/www.example.com", "HTTP/web.example.com", "HTTP/intranet.example.com")

	for _, name := range []string{
		"HTTP/www.example.com",
		"HTTP/web.example.com",
		"HTTP/intranet.example.com",
	} {
		p, err := s.GetPrincipal(ctx, krbkeys.MustParseName(name, aliasRealm))
		if err != nil {
			t.Fatalf("GetPrincipal(%s): %v", name, err)
		}

		// Whichever name was asked for, the principal that comes back is the same one, and it
		// reports the canonical name rather than the one the lookup used.
		if p.Name != "HTTP/www.example.com" {
			t.Errorf("%s resolved to %s", name, p.Name)
		}
		if len(p.Keys) == 0 {
			t.Errorf("%s resolved to a principal with no keys", name)
		}
		if len(p.Aliases) != 2 {
			t.Errorf("%s: aliases = %v, want two", name, p.Aliases)
		}
	}
}

func TestAnAliasCannotTakeANameThatIsAlreadyHeld(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	newPrincipal(t, s, "HTTP/www.example.com")
	newPrincipal(t, s, "HTTP/app.example.com", "HTTP/web.example.com")

	for _, tc := range []struct {
		what  string
		alias string
	}{
		{"another principal's own name", "HTTP/www.example.com"},
		{"another principal's alias", "HTTP/web.example.com"},
	} {
		_, err := s.AddAlias(ctx,
			krbkeys.MustParseName("HTTP/mail.example.com", aliasRealm),
			krbkeys.MustParseName(tc.alias, aliasRealm))
		if err == nil {
			// Left unchecked this hands one name to two sets of keys, and which of them a
			// ticket is issued under becomes a matter of query order.
			t.Fatalf("%s was accepted as an alias", tc.what)
		}
	}

	// The failed attempts must not have created the principal they were made against.
	if _, err := s.GetPrincipal(ctx, krbkeys.MustParseName("HTTP/mail.example.com", aliasRealm)); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetPrincipal after a rejected alias: %v", err)
	}
}

func TestAPrincipalCannotTakeANameThatIsAlreadyAnAlias(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	newPrincipal(t, s, "HTTP/www.example.com", "HTTP/web.example.com")

	keys, err := krbkeys.RandomKeys(testEncTypes(t))
	if err != nil {
		t.Fatalf("RandomKeys: %v", err)
	}

	p := &Principal{Name: "HTTP/web.example.com", Realm: aliasRealm, Enabled: true}

	err = s.CreatePrincipal(ctx, p, keys)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("CreatePrincipal over an existing alias: %v, want a conflict", err)
	}
}

func TestAliasesAreEditedAndRemovedWithThePrincipal(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	name := krbkeys.MustParseName("HTTP/www.example.com", aliasRealm)
	newPrincipal(t, s, "HTTP/www.example.com", "HTTP/web.example.com")

	if _, err := s.AddAlias(ctx, name, krbkeys.MustParseName("HTTP/intranet.example.com", aliasRealm)); err != nil {
		t.Fatalf("AddAlias: %v", err)
	}

	p, err := s.RemoveAlias(ctx, name, krbkeys.MustParseName("HTTP/web.example.com", aliasRealm))
	if err != nil {
		t.Fatalf("RemoveAlias: %v", err)
	}
	if len(p.Aliases) != 1 || p.Aliases[0] != "HTTP/intranet.example.com" {
		t.Fatalf("aliases = %v, want only HTTP/intranet.example.com", p.Aliases)
	}

	// A removed alias stops resolving, or a name could be reassigned while still reaching the
	// keys it used to.
	if _, err := s.GetPrincipal(ctx, krbkeys.MustParseName("HTTP/web.example.com", aliasRealm)); !errors.Is(err, ErrNotFound) {
		t.Errorf("a removed alias still resolves: %v", err)
	}

	// Deleting the principal takes its remaining names with it, so they can be reused.
	if err := s.DeletePrincipal(ctx, name); err != nil {
		t.Fatalf("DeletePrincipal: %v", err)
	}
	if _, err := s.GetPrincipal(ctx, krbkeys.MustParseName("HTTP/intranet.example.com", aliasRealm)); !errors.Is(err, ErrNotFound) {
		t.Errorf("an alias outlived its principal: %v", err)
	}
}

func TestAnAliasOutsideThePrincipalsRealmIsRefused(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	name := krbkeys.MustParseName("HTTP/www.example.com", aliasRealm)
	newPrincipal(t, s, "HTTP/www.example.com")

	// A name in another realm is a referral, not an alias: this KDC holds no keys for it and
	// could not answer under it.
	if _, err := s.AddAlias(ctx, name, krbkeys.MustParseName("HTTP/www.other.com", "OTHER.COM")); err == nil {
		t.Error("an alias in a foreign realm was accepted")
	}
	if _, err := s.AddAlias(ctx, name, name); err == nil {
		t.Error("a principal was accepted as its own alias")
	}
}

func TestAnAccountIsNotLeftBehindWhenItsPrincipalCannotBeCreated(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	newPrincipal(t, s, "HTTP/www.example.com", "alice.smith")

	err := s.CreateAccount(ctx, NewAccount{
		User:     &User{Name: "alice", UIDNumber: 10000, PrimaryGroup: 5000},
		Realm:    aliasRealm,
		EncTypes: testEncTypes(t),
		Password: "a long enough password",
		Aliases:  []string{"alice.smith"},
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateAccount with a taken alias: %v, want a conflict", err)
	}

	// The account and its principal are created in separate transactions, so a failure in the
	// second has to take the first back: an account that can bind over LDAP and holds no
	// principal is the state this service does not have.
	if _, err := s.GetUser(ctx, "alice"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the account outlived the failed principal: %v", err)
	}
}

func TestAPasswordSetThroughAnAliasIsSaltedWithTheRealName(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	etypes := testEncTypes(t)
	canonical := krbkeys.MustParseName("HTTP/www.example.com", aliasRealm)
	newPrincipal(t, s, "HTTP/www.example.com", "HTTP/web.example.com")

	if _, err := s.SetPrincipalPassword(ctx,
		krbkeys.MustParseName("HTTP/web.example.com", aliasRealm),
		"a long enough password", etypes,
	); err != nil {
		t.Fatalf("SetPrincipalPassword: %v", err)
	}

	p, err := s.GetPrincipal(ctx, canonical)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}

	// A client derives its key from the principal's canonical salt, so keys salted with an
	// alias would leave the service unable to authenticate under its own name.
	want, err := krbkeys.DeriveKeys("a long enough password", canonical, etypes)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	got, ok := p.KeyFor(want[0].EType)
	if !ok {
		t.Fatal("the principal has no key of the expected enctype")
	}
	if string(got.Value) != string(want[0].Value) {
		t.Error("the key does not match a derivation from the canonical name")
	}
	if got.Salt != canonical.DefaultSalt() {
		t.Errorf("salt is %q, want %q", got.Salt, canonical.DefaultSalt())
	}
}
