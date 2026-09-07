package bootstrap

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/secret"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

const testRealm = "EXAMPLE.COM"

func testStore(t *testing.T) (*store.Store, Options) {
	t.Helper()

	ctx := context.Background()
	dir := t.TempDir()

	key, _, err := secret.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("master key: %v", err)
	}

	sealer, err := secret.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	// Hashing at the production cost would have this suite spend minutes proving nothing
	// about the cost, and on a loaded machine it pushes a password change past the five
	// second deadline a Kerberos client allows for a reply.
	st, err := store.Open(ctx, filepath.Join(dir, "boot.db"), sealer, zerolog.New(io.Discard), store.WithPasswordHashCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	etypes, err := krbkeys.ResolveEncTypes([]string{"aes256-cts-hmac-sha1-96"})
	if err != nil {
		t.Fatalf("enctypes: %v", err)
	}
	if _, err := st.EnsureRealm(ctx, testRealm, etypes); err != nil {
		t.Fatalf("EnsureRealm: %v", err)
	}
	if _, err := st.EnsureIDRange(ctx, store.DefaultIDRange()); err != nil {
		t.Fatalf("EnsureIDRange: %v", err)
	}

	return st, Options{
		Realm: testRealm, EncTypes: etypes, MinPasswordLength: 8, DefaultTTL: 3600,
	}
}

// apply runs a plan written as YAML, the way the service reads one from disk.
func apply(t *testing.T, st *store.Store, opts Options, body string) Summary {
	t.Helper()

	path := filepath.Join(t.TempDir(), "bootstrap.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing plan: %v", err)
	}

	plan, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	summary, err := Apply(context.Background(), st, plan, opts, zerolog.New(io.Discard))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	return summary
}

const fullPlan = `
groups:
  - name: staff
    gid_number: 5000
  - name: admins
    gid_number: 5001
    capabilities:
      - action: search
        object: "*"
      - action: write
        object: "*"

users:
  - name: alice
    uid_number: 10000
    primary_group: 5000
    given_name: Alice
    sn: Example
    mail: alice@example.com
    password: a sufficiently long password
  - name: admin
    primary_group: 5001
    password: another long enough password

principals:
  - name: HTTP/www.example.com
    ok_as_delegate: true

dns_records:
  - name: www.example.com
    type: A
    value: 192.0.2.20
`

func TestApplyCreatesTheWholeDirectory(t *testing.T) {
	ctx := context.Background()
	st, opts := testStore(t)

	summary := apply(t, st, opts, fullPlan)

	if summary.Created != 6 || summary.Existed != 0 {
		t.Fatalf("summary = %+v, want six objects created", summary)
	}

	// The account exists with the attributes the plan gave it.
	u, err := st.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u.UIDNumber != 10000 || u.PrimaryGroup != 5000 || u.Mail != "alice@example.com" {
		t.Errorf("account = %+v, not what the plan described", u)
	}

	// A seeded password has to work on both sides: an account usable over one protocol and not
	// the other is the failure this whole service exists to avoid.
	if !store.CheckPassword(u.PassBcrypt, "a sufficiently long password") {
		t.Error("the LDAP digest does not accept the seeded password")
	}

	name := krbkeys.MustParseName("alice", testRealm)

	p, err := st.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}

	want, err := krbkeys.DeriveKeys("a sufficiently long password", name, opts.EncTypes)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	got, ok := p.KeyFor(want[0].EType)
	if !ok || string(got.Value) != string(want[0].Value) {
		t.Error("the Kerberos key does not match the seeded password")
	}

	// And it is usable straight away, unlike a password an administrator sets through the API.
	if p.PasswordExpired(time.Now()) {
		t.Error("a seeded password was marked for change; nobody is there to change it")
	}

	// The service principal is keyed randomly, having no password in the plan.
	svc, err := st.GetPrincipal(ctx, krbkeys.MustParseName("HTTP/www.example.com", testRealm))
	if err != nil {
		t.Fatalf("service principal: %v", err)
	}
	if !svc.OKAsDelegate {
		t.Error("the service principal did not take the flag from the plan")
	}
	if len(svc.Keys) == 0 || len(svc.Keys[0].Salt) > 0 {
		t.Error("the service principal should hold random keys, not password derived ones")
	}

	records, err := st.LookupDNSRecords(ctx, "www.example.com")
	if err != nil || len(records) != 1 {
		t.Fatalf("DNS records: %v (%d)", err, len(records))
	}
	if records[0].TTL != 3600 {
		t.Errorf("record ttl = %d, want the zone default", records[0].TTL)
	}
}

func TestApplyIsIdempotentAndDoesNotResetCredentials(t *testing.T) {
	ctx := context.Background()
	st, opts := testStore(t)

	apply(t, st, opts, fullPlan)

	// Someone changes a password after the first start.
	const chosen = "the password alice chose herself"

	if err := st.SetUserPassword(ctx, "alice", chosen, opts.EncTypes, nil); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}

	summary := apply(t, st, opts, fullPlan)

	if summary.Created != 0 || summary.Existed != 6 {
		t.Errorf("summary = %+v, want everything found already present", summary)
	}

	// A plan that reset a password on every restart, because a file still named the account,
	// would be a hazard rather than a convenience.
	u, err := st.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !store.CheckPassword(u.PassBcrypt, chosen) {
		t.Error("re-applying the plan overwrote a password that had been changed since")
	}
}

func TestNumbersAreAllocatedWhenNotGiven(t *testing.T) {
	ctx := context.Background()
	st, opts := testStore(t)

	apply(t, st, opts, `
groups:
  - name: first
  - name: second
users:
  - name: someone
    primary_group: 5000
`)

	for name, want := range map[string]int{"first": 5000, "second": 5001} {
		g, err := st.GetGroup(ctx, name)
		if err != nil {
			t.Fatalf("GetGroup %s: %v", name, err)
		}
		if g.GIDNumber != want {
			t.Errorf("%s gid = %d, want %d", name, g.GIDNumber, want)
		}
	}

	u, err := st.GetUser(ctx, "someone")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u.UIDNumber != 10000 {
		t.Errorf("uid = %d, want 10000", u.UIDNumber)
	}
}

func TestEveryAccountGetsAPrincipal(t *testing.T) {
	ctx := context.Background()
	st, opts := testStore(t)

	apply(t, st, opts, `
groups:
  - name: staff
    gid_number: 5000
users:
  - name: nopassword
    primary_group: 5000
`)

	// An account provisioned without a password still has a principal. It simply holds random
	// keys, so no password produces them and no ticket can be had until one is set -- which is
	// how an LDAP-only account is expressed here, rather than by leaving out the principal.
	p, err := st.GetPrincipal(ctx, krbkeys.MustParseName("nopassword", testRealm))
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}
	if len(p.Keys) == 0 {
		t.Error("the principal holds no keys")
	}
	if p.PasswordLastSet != nil {
		t.Error("a password was recorded for an account that was given none")
	}
}

func TestAliasesInAPlanReachTheSamePrincipal(t *testing.T) {
	ctx := context.Background()
	st, opts := testStore(t)

	apply(t, st, opts, `
groups:
  - name: staff
    gid_number: 5000
users:
  - name: alice
    primary_group: 5000
    password: a long enough password
    aliases:
      - alice.smith
principals:
  - name: HTTP/www.example.com
    aliases:
      - HTTP/web.example.com
`)

	for _, tc := range []struct{ alias, canonical string }{
		{"alice.smith", "alice"},
		{"HTTP/web.example.com", "HTTP/www.example.com"},
	} {
		p, err := st.GetPrincipal(ctx, krbkeys.MustParseName(tc.alias, testRealm))
		if err != nil {
			t.Fatalf("GetPrincipal(%s): %v", tc.alias, err)
		}
		if p.Name != tc.canonical {
			t.Errorf("%s resolved to %s, want %s", tc.alias, p.Name, tc.canonical)
		}
	}
}

func TestAPlanClaimingOneNameTwiceIsRejected(t *testing.T) {
	_, opts := testStore(t)

	plan := &Plan{
		Users:      []User{{Name: "alice", PrimaryGroup: 5000, Aliases: []string{"admin"}}},
		Principals: []Principal{{Name: "admin"}},
	}

	if err := plan.Validate(opts); err == nil {
		t.Fatal("a plan handing one name to two accounts was accepted")
	}
}

func TestForceChangeMarksThePasswordExpired(t *testing.T) {
	ctx := context.Background()
	st, opts := testStore(t)

	apply(t, st, opts, `
groups:
  - name: staff
    gid_number: 5000
users:
  - name: newcomer
    primary_group: 5000
    password: a long enough password
    force_change: true
`)

	p, err := st.GetPrincipal(ctx, krbkeys.MustParseName("newcomer", testRealm))
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}
	if !p.PasswordExpired(time.Now()) {
		t.Error("force_change did not mark the password for change")
	}
}

func TestUnknownKeyIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap.yaml")
	if err := os.WriteFile(path, []byte("users:\n  - name: x\n    uidnumber: 1\n"), 0o600); err != nil {
		t.Fatalf("writing plan: %v", err)
	}

	// A file whose whole job is to be applied unattended must not silently drop a misspelling.
	if _, err := Load(path); err == nil {
		t.Fatal("an unknown key was accepted")
	}
}

func TestValidationRejectsBadPlans(t *testing.T) {
	_, opts := testStore(t)

	for _, tc := range []struct {
		name string
		plan Plan
		want string
	}{
		{
			name: "group without a name",
			plan: Plan{Groups: []Group{{GIDNumber: 5000}}},
			want: "name is required",
		},
		{
			name: "the same group twice",
			plan: Plan{Groups: []Group{{Name: "staff"}, {Name: "STAFF"}}},
			want: "appears twice",
		},
		{
			name: "user with no primary group",
			plan: Plan{Users: []User{{Name: "alice"}}},
			want: "no primary group",
		},
		{
			name: "password below the realm's minimum",
			plan: Plan{Users: []User{{Name: "alice", PrimaryGroup: 5000, Password: "short"}}},
			want: "at least 8",
		},
		{
			name: "principal that is not a principal name",
			plan: Plan{Principals: []Principal{{Name: "@"}}},
			want: "principals[0]",
		},
		{
			name: "record that would never answer",
			plan: Plan{DNSRecords: []DNSRecord{{Name: "a.example.com", Type: "A", Value: "not-an-ip"}}},
			want: "dns_records[0]",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.plan.Validate(opts)
			if err == nil {
				t.Fatalf("plan accepted, want %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestNothingIsAppliedWhenThePlanIsInvalid(t *testing.T) {
	ctx := context.Background()
	st, opts := testStore(t)

	path := filepath.Join(t.TempDir(), "bootstrap.yaml")
	// The group is fine; the user is not. Validation runs over the whole plan first, so the
	// group must not be left behind by a half-applied file.
	body := "groups:\n  - name: staff\n    gid_number: 5000\nusers:\n  - name: alice\n"

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing plan: %v", err)
	}

	plan, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if _, err := Apply(ctx, st, plan, opts, zerolog.New(io.Discard)); err == nil {
		t.Fatal("an invalid plan was applied")
	}

	if _, err := st.GetGroup(ctx, "staff"); err == nil {
		t.Error("part of an invalid plan was applied anyway")
	}
}

func TestEmptyPlanIsValid(t *testing.T) {
	st, opts := testStore(t)

	// A configuration may name a plan that has nothing in it yet.
	if summary := apply(t, st, opts, ""); summary.Created != 0 {
		t.Errorf("summary = %+v, want nothing done", summary)
	}
}

func TestPermissionWarningOnAPlanHoldingPasswords(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		body string
		warn bool
	}{
		{
			name: "readable by the group",
			mode: 0o640,
			body: "users:\n  - name: a\n    primary_group: 5000\n    password: a long enough one\n",
			warn: true,
		},
		{
			name: "owner only",
			mode: 0o600,
			body: "users:\n  - name: a\n    primary_group: 5000\n    password: a long enough one\n",
			warn: false,
		},
		{
			name: "no passwords to leak",
			mode: 0o644,
			body: "groups:\n  - name: staff\n",
			warn: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bootstrap.yaml")
			if err := os.WriteFile(path, []byte(tc.body), tc.mode); err != nil {
				t.Fatalf("writing plan: %v", err)
			}
			// WriteFile is subject to the umask, so the mode is set explicitly.
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			plan, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			var logged strings.Builder

			CheckFilePermissions(path, plan, zerolog.New(&logged))

			warned := strings.Contains(logged.String(), "readable beyond its owner")
			if warned != tc.warn {
				t.Errorf("warned = %v, want %v: %s", warned, tc.warn, logged.String())
			}
		})
	}
}
