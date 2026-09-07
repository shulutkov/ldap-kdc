package kdc

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/client"
	krb5config "github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/secret"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

const (
	testRealm    = "EXAMPLE.COM"
	testPassword = "correct horse battery staple"
	testService  = "HTTP/www.example.com"
)

type harness struct {
	server  *Server
	store   *store.Store
	etypes  []int32
	address string
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

	st, err := store.Open(ctx, filepath.Join(dir, "kdc.db"), sealer, log)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	etypes, err := krbkeys.ResolveEncTypes([]string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"})
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

	srv, err := New(Config{
		Realm:            testRealm,
		DomainName:       "example.com",
		NetBIOSName:      "EXAMPLE",
		DomainSID:        sid,
		Listen:           "127.0.0.1:0",
		MaxTicketLife:    10 * time.Hour,
		MaxRenewableLife: 7 * 24 * time.Hour,
		ClockSkew:        5 * time.Minute,
		EncTypes:         etypes,
		RequirePreAuth:   true,
		IssuePAC:         true,
		AllowS4U:         true,
		UDPMaxSize:       4096,
		Lockout: store.LockoutPolicy{
			MaxFailures: 10, FailureCountInterval: time.Minute, LockoutDuration: time.Minute,
		},
	}, st, log, metrics.New())
	if err != nil {
		t.Fatalf("kdc: %v", err)
	}

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	})

	return &harness{server: srv, store: st, etypes: etypes, address: srv.Addr().String()}
}

// addUser creates a directory account with a Kerberos principal keyed from a password, the way the
// REST API does when an administrator sets one.
func (h *harness) addUser(t *testing.T, name, password string) *store.User {
	t.Helper()

	ctx := context.Background()

	if _, err := h.store.GetGroup(ctx, "users"); err != nil {
		if err := h.store.CreateGroup(ctx, &store.Group{Name: "users", GIDNumber: 5000}); err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
	}

	u := &store.User{Name: name, UIDNumber: 10000 + len(name), PrimaryGroup: 5000, GivenName: "Test", SN: "User"}
	if err := h.store.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	keys, err := krbkeys.RandomKeys(h.etypes)
	if err != nil {
		t.Fatalf("RandomKeys: %v", err)
	}

	p := &store.Principal{
		Name: name, Realm: testRealm, UserID: &u.ID,
		Enabled: true, RequiresPreAuth: true,
		AllowForwardable: true, AllowProxiable: true, AllowRenewable: true,
	}
	if err := h.store.CreatePrincipal(ctx, p, keys); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}

	if err := h.store.SetUserPassword(ctx, name, password, h.etypes, nil); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}

	return u
}

// addService creates a randomly keyed service principal and returns a keytab for it.
func (h *harness) addService(t *testing.T, name string) *keytab.Keytab {
	t.Helper()

	ctx := context.Background()

	kn := krbkeys.MustParseName(name, testRealm)

	keys, err := krbkeys.RandomKeys(h.etypes)
	if err != nil {
		t.Fatalf("RandomKeys: %v", err)
	}

	p := &store.Principal{
		Name: kn.Principal(), Realm: kn.Realm,
		Enabled: true, RequiresPreAuth: true,
		AllowForwardable: true, AllowProxiable: true, AllowRenewable: true,
	}
	if err := h.store.CreatePrincipal(ctx, p, keys); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}

	entries := make([]krbkeys.KeytabEntry, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, krbkeys.KeytabEntry{Name: kn, KVNO: p.KVNO, Key: k, Timestamp: time.Now()})
	}

	b, err := krbkeys.MarshalKeytab(entries)
	if err != nil {
		t.Fatalf("MarshalKeytab: %v", err)
	}

	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatalf("keytab round trip: %v", err)
	}

	return kt
}

// clientConfig builds a krb5.conf pointing every lookup at the test KDC.
func (h *harness) clientConfig(useTCP bool) *krb5config.Config {
	c := krb5config.New()

	names := make([]string, 0, len(h.etypes))
	for _, id := range h.etypes {
		names = append(names, krbkeys.EncTypeName(id))
	}

	c.LibDefaults.DefaultRealm = testRealm
	c.LibDefaults.DefaultTktEnctypes = names
	c.LibDefaults.DefaultTktEnctypeIDs = h.etypes
	c.LibDefaults.DefaultTGSEnctypes = names
	c.LibDefaults.DefaultTGSEnctypeIDs = h.etypes
	c.LibDefaults.PermittedEnctypes = names
	c.LibDefaults.PermittedEnctypeIDs = h.etypes
	// The library's default KDC options ask only for RENEWABLE-OK, so FORWARDABLE and
	// RENEWABLE are requested explicitly to exercise the KDC's flag policy.
	types.SetFlags(&c.LibDefaults.KDCDefaultOptions, []int{flags.Forwardable, flags.Renewable})
	c.LibDefaults.DNSLookupKDC = false
	c.LibDefaults.DNSLookupRealm = false
	c.LibDefaults.TicketLifetime = 10 * time.Hour
	c.LibDefaults.RenewLifetime = 7 * 24 * time.Hour

	if useTCP {
		// A preference limit of one byte forces every request onto TCP.
		c.LibDefaults.UDPPreferenceLimit = 1
	}

	c.DomainRealm["example.com"] = testRealm
	c.Realms = append(c.Realms, krb5config.Realm{
		Realm:         testRealm,
		DefaultDomain: "example.com",
		KDC:           []string{h.address},
		KPasswdServer: []string{h.address},
	})

	return c
}

// login runs an AS exchange and returns the reply, whose encrypted part the client has already
// opened with the password. Login itself keeps the TGT in an unexported session store, so the
// exchange is driven directly when the test needs to look at the ticket.
func login(t *testing.T, h *harness, user, password string, useTCP bool) messages.ASRep {
	t.Helper()

	cfg := h.clientConfig(useTCP)
	cl := client.NewWithPassword(user, testRealm, password, cfg)

	req, err := messages.NewASReqForTGT(testRealm, cfg, cl.Credentials.CName())
	if err != nil {
		t.Fatalf("building AS-REQ: %v", err)
	}

	rep, err := cl.ASExchange(testRealm, req, 0)
	if err != nil {
		t.Fatalf("AS exchange: %v", err)
	}

	return rep
}

func TestASExchangeIssuesATGT(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "alice", testPassword)

	for _, tc := range []struct {
		name   string
		useTCP bool
	}{
		{"over UDP", false},
		{"over TCP", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := login(t, h, "alice", testPassword, tc.useTCP)

			if rep.Ticket.TktVNO != iana.PVNO {
				t.Errorf("ticket version = %d, want %d", rep.Ticket.TktVNO, iana.PVNO)
			}
			if got := rep.Ticket.SName.PrincipalNameString(); got != "krbtgt/"+testRealm {
				t.Errorf("ticket is for %q, want krbtgt/%s", got, testRealm)
			}
			if rep.DecryptedEncPart.Key.KeyType != h.etypes[0] {
				t.Errorf("session key enctype = %d, want the KDC's first preference %d",
					rep.DecryptedEncPart.Key.KeyType, h.etypes[0])
			}
			if !rep.DecryptedEncPart.EndTime.After(time.Now()) {
				t.Error("ticket has already expired")
			}
		})
	}
}

func TestASExchangeRejectsAWrongPassword(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "alice", testPassword)

	cl := client.NewWithPassword("alice", testRealm, "not the password", h.clientConfig(false))

	err := cl.Login()
	if err == nil {
		t.Fatal("login with a wrong password succeeded")
	}
	if !strings.Contains(err.Error(), "KDC_ERR_PREAUTH_FAILED") {
		t.Errorf("error = %v, want KDC_ERR_PREAUTH_FAILED", err)
	}
}

func TestASExchangeRejectsAnUnknownPrincipal(t *testing.T) {
	h := newHarness(t)

	cl := client.NewWithPassword("nobody", testRealm, testPassword, h.clientConfig(false))

	err := cl.Login()
	if err == nil {
		t.Fatal("login as an unknown principal succeeded")
	}
	if !strings.Contains(err.Error(), "KDC_ERR_C_PRINCIPAL_UNKNOWN") {
		t.Errorf("error = %v, want KDC_ERR_C_PRINCIPAL_UNKNOWN", err)
	}
}

func TestASExchangeRefusesADisabledPrincipal(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.addUser(t, "alice", testPassword)

	if _, err := h.store.UpdatePrincipal(ctx, krbkeys.MustParseName("alice", testRealm), func(p *store.Principal) error {
		p.Enabled = false

		return nil
	}); err != nil {
		t.Fatalf("disabling principal: %v", err)
	}

	cl := client.NewWithPassword("alice", testRealm, testPassword, h.clientConfig(false))

	err := cl.Login()
	if err == nil {
		t.Fatal("a disabled principal was issued a ticket")
	}
	if !strings.Contains(err.Error(), "KDC_ERR_CLIENT_REVOKED") {
		t.Errorf("error = %v, want KDC_ERR_CLIENT_REVOKED", err)
	}
}

func TestTGSExchangeIssuesAServiceTicket(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "alice", testPassword)
	kt := h.addService(t, testService)

	cl := client.NewWithPassword("alice", testRealm, testPassword, h.clientConfig(false))
	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}

	tkt, key, err := cl.GetServiceTicket(testService)
	if err != nil {
		t.Fatalf("service ticket: %v", err)
	}
	if tkt.TktVNO != iana.PVNO {
		t.Errorf("ticket version = %d, want %d", tkt.TktVNO, iana.PVNO)
	}
	if len(key.KeyValue) == 0 {
		t.Error("service ticket carries no session key")
	}

	// The service must be able to open the ticket with its own keytab, which is the whole
	// point of the exchange.
	sname := types.PrincipalName{NameType: 3, NameString: strings.Split(testService, "/")}
	if err := tkt.DecryptEncPart(kt, &sname); err != nil {
		t.Fatalf("service could not decrypt its ticket: %v", err)
	}

	if tkt.DecryptedEncPart.CName.NameString[0] != "alice" {
		t.Errorf("ticket names %v, want alice", tkt.DecryptedEncPart.CName.NameString)
	}
}

func TestServiceTicketCarriesASignedPAC(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "alice", testPassword)
	kt := h.addService(t, testService)

	cl := client.NewWithPassword("alice", testRealm, testPassword, h.clientConfig(false))
	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}

	tkt, _, err := cl.GetServiceTicket(testService)
	if err != nil {
		t.Fatalf("service ticket: %v", err)
	}

	sname := types.PrincipalName{NameType: 3, NameString: strings.Split(testService, "/")}

	if err := tkt.DecryptEncPart(kt, &sname); err != nil {
		t.Fatalf("service could not decrypt its ticket: %v", err)
	}

	// GetPACType parses the PAC out of the decrypted ticket and verifies its server signature
	// against the keytab, so a pass here means a Windows or Samba service would accept it too.
	ok, pacType, err := tkt.GetPACType(kt, &sname, nil)
	if err != nil {
		t.Fatalf("PAC: %v", err)
	}
	if !ok {
		t.Fatal("service ticket carries no PAC")
	}

	info := pacType.KerbValidationInfo
	if info == nil {
		t.Fatal("PAC carries no logon information")
	}
	if info.EffectiveName.Value != "alice" {
		t.Errorf("PAC names %q, want alice", info.EffectiveName.Value)
	}

	// The PAC carries relative identifiers, not POSIX ids. They are allocated per object, so
	// the expected values come from the store rather than from the uid and gid.
	ctx := context.Background()

	u, err := h.store.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	gids, err := h.store.UserGIDs(ctx, u)
	if err != nil {
		t.Fatalf("UserGIDs: %v", err)
	}

	ids, ok, err := h.store.SecurityIDsForUser(ctx, u, gids)
	if err != nil || !ok {
		t.Fatalf("SecurityIDsForUser: %v (found %v)", err, ok)
	}

	if info.UserID != uint32(ids.User) {
		t.Errorf("PAC user RID = %d, want the allocated %d", info.UserID, ids.User)
	}
	if info.PrimaryGroupID != uint32(ids.PrimaryGroup) {
		t.Errorf("PAC primary group RID = %d, want the allocated %d", info.PrimaryGroupID, ids.PrimaryGroup)
	}
	if info.UserID == uint32(u.UIDNumber) {
		t.Error("the PAC is handing out the POSIX uid as a RID, which collides with the group space")
	}

	sids := info.GetGroupMembershipSIDs()
	if len(sids) == 0 {
		t.Error("PAC carries no group SIDs")
	}
	for _, s := range sids {
		if !strings.HasPrefix(s, "S-1-5-21-") {
			t.Errorf("group SID %q is not under the domain SID", s)
		}
	}
}

func TestTGTCarriesTheExpectedFlags(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "alice", testPassword)

	rep := login(t, h, "alice", testPassword, false)
	f := rep.DecryptedEncPart.Flags

	// The client asks for a renewable, forwardable ticket by default and this realm's policy
	// allows both, so a missing flag here means the policy plumbing dropped it.
	for _, tc := range []struct {
		flag int
		name string
	}{
		{flags.Renewable, "RENEWABLE"},
		{flags.Forwardable, "FORWARDABLE"},
		{flags.Initial, "INITIAL"},
		{flags.PreAuthent, "PRE-AUTHENT"},
	} {
		if !types.IsFlagSet(&f, tc.flag) {
			t.Errorf("TGT is missing the %s flag", tc.name)
		}
	}

	if rep.DecryptedEncPart.RenewTill.Before(rep.DecryptedEncPart.EndTime) {
		t.Error("renew-until is earlier than the ticket's own expiry")
	}
}

func TestUnknownServiceIsRefused(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "alice", testPassword)

	cl := client.NewWithPassword("alice", testRealm, testPassword, h.clientConfig(false))
	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}

	_, _, err := cl.GetServiceTicket("HTTP/nowhere.example.com")
	if err == nil {
		t.Fatal("a ticket was issued for an unknown service")
	}
	if !strings.Contains(err.Error(), "KDC_ERR_S_PRINCIPAL_UNKNOWN") {
		t.Errorf("error = %v, want KDC_ERR_S_PRINCIPAL_UNKNOWN", err)
	}
}

func TestReplayedAuthenticatorIsRejected(t *testing.T) {
	c := newReplayCache(time.Minute)

	now := time.Now()
	digest := []byte("ticket")

	if c.seen("EXAMPLE.COM", "alice", now, 1234, digest) {
		t.Fatal("first use reported as a replay")
	}
	if !c.seen("EXAMPLE.COM", "alice", now, 1234, digest) {
		t.Error("second use of the same authenticator was not caught")
	}
	if c.seen("EXAMPLE.COM", "alice", now, 1235, digest) {
		t.Error("a different authenticator was reported as a replay")
	}
	if c.size() != 2 {
		t.Errorf("cache holds %d entries, want 2", c.size())
	}
}
