package ldapsrv

import (
	"context"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glauth/ldap"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/secret"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

const (
	testRealm  = "EXAMPLE.COM"
	testBaseDN = "dc=example,dc=com"
	alicePass  = "alice's long password"
	adminPass  = "admin's long password"
)

type harness struct {
	store  *store.Store
	server *Server
	addr   string
	etypes []int32
}

func newHarness(t *testing.T) *harness {
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

	log := zerolog.New(io.Discard)

	// Hashing at the production cost would have this suite spend minutes proving nothing
	// about the cost, and on a loaded machine it pushes a password change past the five
	// second deadline a Kerberos client allows for a reply.
	st, err := store.Open(ctx, filepath.Join(dir, "dir.db"), sealer, log, store.WithPasswordHashCost(bcrypt.MinCost))
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

	sid, err := st.EnsureDomainSID(ctx, "")
	if err != nil {
		t.Fatalf("domain SID: %v", err)
	}
	if _, err := st.EnsureIDRange(ctx, store.DefaultIDRange()); err != nil {
		t.Fatalf("EnsureIDRange: %v", err)
	}

	h := &harness{store: st, etypes: etypes}
	h.seed(t)

	cfg := Config{
		BaseDN: testBaseDN, NameFormat: "cn", GroupFormat: "ou", SSHKeyAttr: "sshPublicKey",
		Realm: testRealm, DomainSID: sid, AnonymousDSE: true, EncTypes: etypes,
		LimitFailedBinds: true, NumberOfFailedBinds: 3,
		PeriodOfFailedBinds: 10 * time.Second, BlockFailedBindsFor: 60 * time.Second,
		PruneSourceTableEvery: time.Minute, PruneSourcesOlderThan: time.Minute,
	}

	srv, err := New(cfg, ListenerConfig{Enabled: true, Listen: "127.0.0.1:0"}, ListenerConfig{},
		st, log, metrics.New())
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	})

	h.server = srv
	h.addr = srv.Addrs()[0].String()

	return h
}

func (h *harness) seed(t *testing.T) {
	t.Helper()

	ctx := context.Background()

	for _, g := range []*store.Group{
		{Name: "staff", GIDNumber: 5000},
		{Name: "everyone", GIDNumber: 5001, IncludeGroups: []int{5000}},
		{Name: "admins", GIDNumber: 5002, Capabilities: []store.Capability{
			{Action: "search", Object: "*"},
			{Action: "write", Object: "*"},
		}},
	} {
		if err := h.store.CreateGroup(ctx, g); err != nil {
			t.Fatalf("CreateGroup %s: %v", g.Name, err)
		}
	}

	h.addUser(t, &store.User{
		Name: "alice", UIDNumber: 10000, PrimaryGroup: 5000,
		GivenName: "Alice", SN: "Example", Mail: "alice@example.com",
		Capabilities: []store.Capability{{Action: "search", Object: testBaseDN}},
		SSHKeys:      []string{"ssh-ed25519 AAAAC3Nz alice@laptop"},
	}, alicePass)

	// alice answers to a second name, which is what the entry publishes as a multivalued
	// krbPrincipalName.
	if _, err := h.store.AddAlias(ctx,
		krbkeys.MustParseName("alice", testRealm),
		krbkeys.MustParseName("alice.smith", testRealm),
	); err != nil {
		t.Fatalf("AddAlias: %v", err)
	}

	h.addUser(t, &store.User{Name: "admin", UIDNumber: 10001, PrimaryGroup: 5002}, adminPass)

	// bob has no search capability at all, which is what makes the authorization test mean
	// something.
	h.addUser(t, &store.User{Name: "bob", UIDNumber: 10002, PrimaryGroup: 5000}, "bob's long password")
}

func (h *harness) addUser(t *testing.T, u *store.User, password string) {
	t.Helper()

	ctx := context.Background()

	if err := h.store.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser %s: %v", u.Name, err)
	}

	keys, err := krbkeys.RandomKeys(h.etypes)
	if err != nil {
		t.Fatalf("RandomKeys: %v", err)
	}
	if err := h.store.CreatePrincipal(ctx, &store.Principal{
		Name: u.Name, Realm: testRealm, UserID: &u.ID, Enabled: true, RequiresPreAuth: true,
		AllowForwardable: true, AllowProxiable: true, AllowRenewable: true,
	}, keys); err != nil {
		t.Fatalf("CreatePrincipal %s: %v", u.Name, err)
	}

	if err := h.store.SetUserPassword(ctx, u.Name, password, h.etypes, nil); err != nil {
		t.Fatalf("SetUserPassword %s: %v", u.Name, err)
	}
}

func (h *harness) dial(t *testing.T) *ldap.Conn {
	t.Helper()

	conn, err := ldap.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(conn.Close)

	return conn
}

func aliceDN() string { return "cn=alice,ou=staff,ou=users," + testBaseDN }
func adminDN() string { return "cn=admin,ou=admins,ou=users," + testBaseDN }

func TestBind(t *testing.T) {
	h := newHarness(t)

	t.Run("with the right password", func(t *testing.T) {
		if err := h.dial(t).Bind(aliceDN(), alicePass); err != nil {
			t.Errorf("bind: %v", err)
		}
	})

	t.Run("with the wrong password", func(t *testing.T) {
		if err := h.dial(t).Bind(aliceDN(), "wrong"); err == nil {
			t.Error("bind with a wrong password succeeded")
		}
	})

	t.Run("by user principal name", func(t *testing.T) {
		if err := h.dial(t).Bind("alice@example.com", alicePass); err != nil {
			t.Errorf("bind by UPN: %v", err)
		}
	})

	t.Run("anonymously", func(t *testing.T) {
		if err := h.dial(t).Bind("", ""); err != nil {
			t.Errorf("anonymous bind: %v", err)
		}
	})

	t.Run("unauthenticated", func(t *testing.T) {
		// A DN with an empty password must never be accepted: RFC 4513 calls this an
		// unauthenticated bind, and treating it as success would authenticate anyone who
		// knows a DN.
		if err := h.dial(t).Bind(aliceDN(), ""); err == nil {
			t.Error("unauthenticated bind succeeded")
		}
	})

	t.Run("with the wrong primary group in the DN", func(t *testing.T) {
		if err := h.dial(t).Bind("cn=alice,ou=admins,ou=users,"+testBaseDN, alicePass); err == nil {
			t.Error("bind succeeded with a DN naming the wrong primary group")
		}
	})
}

func TestBindOnADisabledAccountFails(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	if _, err := h.store.UpdateUser(ctx, "alice", func(u *store.User) error {
		u.Disabled = true

		return nil
	}); err != nil {
		t.Fatalf("disabling: %v", err)
	}

	if err := h.dial(t).Bind(aliceDN(), alicePass); err == nil {
		t.Error("a disabled account bound successfully")
	}
}

func TestSearchUsers(t *testing.T) {
	h := newHarness(t)

	conn := h.dial(t)
	if err := conn.Bind(aliceDN(), alicePass); err != nil {
		t.Fatalf("bind: %v", err)
	}

	res, err := conn.Search(ldap.NewSearchRequest(
		testBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=posixAccount)(cn=alice))",
		[]string{"cn", "uidNumber", "gidNumber", "mail", "memberOf", "krbPrincipalName", "sshPublicKey"},
		nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	if len(res.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(res.Entries))
	}

	e := res.Entries[0]
	if e.DN != aliceDN() {
		t.Errorf("DN = %q, want %q", e.DN, aliceDN())
	}

	for _, tc := range []struct{ attr, want string }{
		{"cn", "alice"},
		{"uidNumber", "10000"},
		{"gidNumber", "5000"},
		{"mail", "alice@example.com"},
		{"krbPrincipalName", "alice@" + testRealm},
	} {
		if got := e.GetAttributeValue(tc.attr); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.attr, got, tc.want)
		}
	}

	// alice's primary group is staff, and everyone includes staff, so both must show up.
	memberOf := e.GetAttributeValues("memberOf")
	if len(memberOf) != 2 {
		t.Errorf("memberOf = %v, want the primary group and the group including it", memberOf)
	}
	for _, want := range []string{"ou=staff,ou=groups," + testBaseDN, "ou=everyone,ou=groups," + testBaseDN} {
		if !slices.Contains(memberOf, want) {
			t.Errorf("memberOf %v is missing %q", memberOf, want)
		}
	}

	if got := e.GetAttributeValue("sshPublicKey"); !strings.HasPrefix(got, "ssh-ed25519") {
		t.Errorf("sshPublicKey = %q", got)
	}
}

func TestSearchGroupsListsMembers(t *testing.T) {
	h := newHarness(t)

	conn := h.dial(t)
	if err := conn.Bind(aliceDN(), alicePass); err != nil {
		t.Fatalf("bind: %v", err)
	}

	res, err := conn.Search(ldap.NewSearchRequest(
		"ou=groups,"+testBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=groupOfUniqueNames)", []string{"ou", "gidNumber", "uniqueMember"}, nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	byName := make(map[string]*ldap.Entry, len(res.Entries))
	for _, e := range res.Entries {
		byName[e.GetAttributeValue("ou")] = e
	}

	staff, ok := byName["staff"]
	if !ok {
		t.Fatalf("staff group missing from %v", res.Entries)
	}
	if got := staff.GetAttributeValue("gidNumber"); got != "5000" {
		t.Errorf("staff gidNumber = %q, want 5000", got)
	}
	if members := staff.GetAttributeValues("uniqueMember"); len(members) != 2 {
		t.Errorf("staff has %d members, want alice and bob: %v", len(members), members)
	}

	// everyone includes staff, so its membership is inherited rather than direct.
	everyone, ok := byName["everyone"]
	if !ok {
		t.Fatal("everyone group missing")
	}
	if members := everyone.GetAttributeValues("uniqueMember"); len(members) != 2 {
		t.Errorf("everyone has %d members, want the two inherited from staff: %v", len(members), members)
	}
}

func TestSearchIsRefusedWithoutACapability(t *testing.T) {
	h := newHarness(t)

	conn := h.dial(t)
	if err := conn.Bind("cn=bob,ou=staff,ou=users,"+testBaseDN, "bob's long password"); err != nil {
		t.Fatalf("bind: %v", err)
	}

	_, err := conn.Search(ldap.NewSearchRequest(
		testBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=posixAccount)", []string{"cn"}, nil))
	if err == nil {
		t.Fatal("an account with no search capability searched the tree")
	}
	if !strings.Contains(err.Error(), "Insufficient Access Rights") {
		t.Errorf("error = %v, want insufficient access rights", err)
	}
}

func TestAnonymousSearchIsLimitedToTheRootDSE(t *testing.T) {
	h := newHarness(t)

	conn := h.dial(t)

	res, err := conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"namingContexts", "krbRealm"}, nil))
	if err != nil {
		t.Fatalf("root DSE search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("got %d entries, want the root DSE", len(res.Entries))
	}
	if got := res.Entries[0].GetAttributeValue("namingContexts"); got != testBaseDN {
		t.Errorf("namingContexts = %q, want %q", got, testBaseDN)
	}
	if got := res.Entries[0].GetAttributeValue("krbRealm"); got != testRealm {
		t.Errorf("krbRealm = %q, want %q", got, testRealm)
	}

	// Anything below the root DSE needs an identity.
	if _, err := conn.Search(ldap.NewSearchRequest(
		testBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=posixAccount)", []string{"cn"}, nil)); err == nil {
		t.Error("an anonymous client searched the tree")
	}
}

func TestModifyPasswordUpdatesKerberosKeys(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	conn := h.dial(t)
	if err := conn.Bind(adminDN(), adminPass); err != nil {
		t.Fatalf("bind: %v", err)
	}

	const replacement = "a brand new long password"

	req := ldap.NewModifyRequest(aliceDN())
	req.Replace("userPassword", []string{replacement})

	if err := conn.Modify(req); err != nil {
		t.Fatalf("modify: %v", err)
	}

	// The LDAP digest must accept the new password...
	u, err := h.store.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !store.CheckPassword(u.PassBcrypt, replacement) {
		t.Error("the LDAP digest was not updated")
	}

	// ...and so must the Kerberos key, or the account would authenticate over one protocol and
	// not the other. This is the whole reason the two live in one store.
	name := krbkeys.MustParseName("alice", testRealm)

	p, err := h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}

	want, err := krbkeys.DeriveKeys(replacement, name, h.etypes)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	got, ok := p.KeyFor(want[0].EType)
	if !ok {
		t.Fatal("principal lost its key")
	}
	if string(got.Value) != string(want[0].Value) {
		t.Error("the Kerberos key does not match the password set over LDAP")
	}

	if err := h.dial(t).Bind(aliceDN(), replacement); err != nil {
		t.Errorf("bind with the new password: %v", err)
	}
}

func TestModifyIsRefusedWithoutAWriteCapability(t *testing.T) {
	h := newHarness(t)

	conn := h.dial(t)
	if err := conn.Bind(aliceDN(), alicePass); err != nil {
		t.Fatalf("bind: %v", err)
	}

	// alice may search, but nothing grants her write, so she must not be able to reset another
	// account's password.
	req := ldap.NewModifyRequest("cn=bob,ou=staff,ou=users," + testBaseDN)
	req.Replace("userPassword", []string{"taking over bob's account"})

	if err := conn.Modify(req); err == nil {
		t.Fatal("a user without write capability changed another user's password")
	}
}

func TestUserMayChangeTheirOwnAttributes(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	conn := h.dial(t)
	if err := conn.Bind(aliceDN(), alicePass); err != nil {
		t.Fatalf("bind: %v", err)
	}

	req := ldap.NewModifyRequest(aliceDN())
	req.Replace("loginShell", []string{"/bin/zsh"})

	if err := conn.Modify(req); err != nil {
		t.Fatalf("modify: %v", err)
	}

	u, err := h.store.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u.LoginShell != "/bin/zsh" {
		t.Errorf("loginShell = %q, want /bin/zsh", u.LoginShell)
	}
}

func TestRepeatedFailuresBlockTheSource(t *testing.T) {
	h := newHarness(t)

	for range 3 {
		_ = h.dial(t).Bind(aliceDN(), "wrong")
	}

	// The block is per source address, so even the correct password is refused while the
	// timeout lasts. That is the point: it costs an attacker time rather than the account.
	if err := h.dial(t).Bind(aliceDN(), alicePass); err == nil {
		t.Error("a blocked source was allowed to bind")
	}
}

func TestEntriesCarryTheKerberosAndWindowsAttributes(t *testing.T) {
	h := newHarness(t)

	conn := h.dial(t)
	if err := conn.Bind(aliceDN(), alicePass); err != nil {
		t.Fatalf("bind: %v", err)
	}

	res, err := conn.Search(ldap.NewSearchRequest(
		testBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=posixAccount)(cn=alice))",
		[]string{
			"objectClass", "krbPrincipalName", "krbCanonicalName", "krbTicketFlags",
			"krbLastPwdChange", "krbLoginFailedCount", "ipaNTSecurityIdentifier",
		}, nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(res.Entries))
	}

	e := res.Entries[0]

	// The entry announces the Kerberos schema MIT and FreeIPA use, so a client that reads
	// either finds what it expects on the same object.
	classes := e.GetAttributeValues("objectClass")
	for _, want := range []string{"krbPrincipalAux", "krbTicketPolicyAux", "ipaNTUserAttrs"} {
		if !slices.Contains(classes, want) {
			t.Errorf("objectClass %v is missing %q", classes, want)
		}
	}

	if got := e.GetAttributeValue("krbCanonicalName"); got != "alice@"+testRealm {
		t.Errorf("krbCanonicalName = %q", got)
	}

	// As in FreeIPA, krbPrincipalName lists every name the account answers to while
	// krbCanonicalName names the real one, so a client can tell an alias from the identity it
	// stands for.
	names := e.GetAttributeValues("krbPrincipalName")
	for _, want := range []string{"alice@" + testRealm, "alice.smith@" + testRealm} {
		if !slices.Contains(names, want) {
			t.Errorf("krbPrincipalName %v is missing %q", names, want)
		}
	}

	// The bitmask is one of prohibitions: the account is forwardable, proxiable and renewable,
	// so those DISALLOW bits stay clear, leaving REQUIRES_PRE_AUTH (128) and
	// DISALLOW_POSTDATED (1), postdated tickets being off by default.
	if got := e.GetAttributeValue("krbTicketFlags"); got != "129" {
		t.Errorf("krbTicketFlags = %q, want 129 (REQUIRES_PRE_AUTH | DISALLOW_POSTDATED)", got)
	}

	if got := e.GetAttributeValue("krbLastPwdChange"); len(got) != 15 || !strings.HasSuffix(got, "Z") {
		t.Errorf("krbLastPwdChange = %q, want an LDAP generalized time", got)
	}

	if got := e.GetAttributeValue("krbLoginFailedCount"); got != "0" {
		t.Errorf("krbLoginFailedCount = %q, want 0", got)
	}

	// The security identifier is the realm's domain SID with the account's allocated RID.
	sid := e.GetAttributeValue("ipaNTSecurityIdentifier")
	if !strings.HasPrefix(sid, "S-1-5-21-") {
		t.Errorf("ipaNTSecurityIdentifier = %q, want a domain SID", sid)
	}

	rid, _, err := h.store.RID(context.Background(), "user", 1)
	if err != nil {
		t.Fatalf("RID: %v", err)
	}
	if !strings.HasSuffix(sid, "-"+strconv.Itoa(rid)) {
		t.Errorf("ipaNTSecurityIdentifier = %q, want it to end in the allocated RID %d", sid, rid)
	}
}

func TestGroupsCarryASecurityIdentifier(t *testing.T) {
	h := newHarness(t)

	conn := h.dial(t)
	if err := conn.Bind(aliceDN(), alicePass); err != nil {
		t.Fatalf("bind: %v", err)
	}

	res, err := conn.Search(ldap.NewSearchRequest(
		"ou=groups,"+testBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(ou=staff)", []string{"ipaNTSecurityIdentifier", "objectClass"}, nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(res.Entries))
	}

	if !slices.Contains(res.Entries[0].GetAttributeValues("objectClass"), "ipaNTGroupAttrs") {
		t.Error("the group does not announce ipaNTGroupAttrs")
	}
	if sid := res.Entries[0].GetAttributeValue("ipaNTSecurityIdentifier"); !strings.HasPrefix(sid, "S-1-5-21-") {
		t.Errorf("ipaNTSecurityIdentifier = %q", sid)
	}
}
