package kpasswd

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/client"
	krb5config "github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/kadmin"
	"github.com/go-krb5/krb5/messages"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/shulutkov/ldap-kdc/internal/kdc"
	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/secret"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

const (
	testRealm = "EXAMPLE.COM"
	oldPass   = "the original password"
	newPass   = "an entirely different one"
)

type harness struct {
	store    *store.Store
	etypes   []int32
	kdcAddr  string
	pwAddr   string
	password *Server
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
	st, err := store.Open(ctx, filepath.Join(dir, "kdc.db"), sealer, log, store.WithPasswordHashCost(bcrypt.MinCost))
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

	m := metrics.New()

	kdcSrv, err := kdc.New(kdc.Config{
		Realm: testRealm, DomainName: "example.com", NetBIOSName: "EXAMPLE", DomainSID: sid,
		Listen: "127.0.0.1:0", MaxTicketLife: time.Hour, MaxRenewableLife: 24 * time.Hour,
		ClockSkew: 5 * time.Minute, EncTypes: etypes, RequirePreAuth: true,
		IssuePAC: true, AllowS4U: true, UDPMaxSize: 4096,
		Lockout: store.LockoutPolicy{
			MaxFailures: 10, FailureCountInterval: time.Minute, LockoutDuration: time.Minute,
		},
	}, st, log, m)
	if err != nil {
		t.Fatalf("kdc: %v", err)
	}
	if err := kdcSrv.Start(ctx); err != nil {
		t.Fatalf("kdc start: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = kdcSrv.Shutdown(c)
	})

	pwSrv, err := New(Config{
		Realm: testRealm, Listen: "127.0.0.1:0", ClockSkew: 5 * time.Minute,
		EncTypes: etypes, MinPasswordLength: 8,
	}, st, log, m)
	if err != nil {
		t.Fatalf("kpasswd: %v", err)
	}
	if err := pwSrv.Start(ctx); err != nil {
		t.Fatalf("kpasswd start: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = pwSrv.Shutdown(c)
	})

	h := &harness{
		store: st, etypes: etypes,
		kdcAddr: kdcSrv.Addr().String(), pwAddr: pwSrv.Addr().String(), password: pwSrv,
	}
	h.addUser(t, "alice", oldPass)

	return h
}

func (h *harness) addUser(t *testing.T, name, password string) {
	t.Helper()

	ctx := context.Background()

	if err := h.store.CreateGroup(ctx, &store.Group{Name: "users", GIDNumber: 5000}); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	u := &store.User{Name: name, UIDNumber: 10001, PrimaryGroup: 5000}
	if err := h.store.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	keys, err := krbkeys.RandomKeys(h.etypes)
	if err != nil {
		t.Fatalf("RandomKeys: %v", err)
	}

	p := &store.Principal{
		Name: name, Realm: testRealm, UserID: &u.ID,
		Enabled: true, RequiresPreAuth: true, AllowRenewable: true, AllowForwardable: true,
	}
	if err := h.store.CreatePrincipal(ctx, p, keys); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}

	if err := h.store.SetUserPassword(ctx, name, password, h.etypes, nil); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
}

func (h *harness) config() *krb5config.Config {
	c := krb5config.New()

	names := []string{"aes256-cts-hmac-sha1-96"}

	c.LibDefaults.DefaultRealm = testRealm
	c.LibDefaults.DefaultTktEnctypes = names
	c.LibDefaults.DefaultTktEnctypeIDs = h.etypes
	c.LibDefaults.DefaultTGSEnctypes = names
	c.LibDefaults.DefaultTGSEnctypeIDs = h.etypes
	c.LibDefaults.PermittedEnctypes = names
	c.LibDefaults.PermittedEnctypeIDs = h.etypes
	c.LibDefaults.DNSLookupKDC = false
	c.LibDefaults.DNSLookupRealm = false
	c.LibDefaults.TicketLifetime = time.Hour
	c.LibDefaults.RenewLifetime = 24 * time.Hour

	c.DomainRealm["example.com"] = testRealm
	c.Realms = append(c.Realms, krb5config.Realm{
		Realm:         testRealm,
		DefaultDomain: "example.com",
		KDC:           []string{h.kdcAddr},
		KPasswdServer: []string{h.pwAddr},
	})

	return c
}

func TestChangePasswordUpdatesBothCredentials(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	cl := client.NewWithPassword("alice", testRealm, oldPass, h.config())

	ok, err := cl.ChangePasswd(newPass)
	if err != nil {
		t.Fatalf("ChangePasswd: %v", err)
	}
	if !ok {
		t.Fatal("ChangePasswd reported failure")
	}

	// Kerberos: the new password must produce the stored key, and a login must now work.
	name := krbkeys.MustParseName("alice", testRealm)

	p, err := h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}

	want, err := krbkeys.DeriveKeys(newPass, name, h.etypes)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	got, ok := p.KeyFor(want[0].EType)
	if !ok {
		t.Fatal("principal lost its key")
	}
	if string(got.Value) != string(want[0].Value) {
		t.Error("the stored Kerberos key does not match the new password")
	}

	// LDAP: the digest must have moved with it, or the account could bind with the old
	// password after changing it.
	u, err := h.store.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !store.CheckPassword(u.PassBcrypt, newPass) {
		t.Error("the LDAP digest was not updated")
	}
	if store.CheckPassword(u.PassBcrypt, oldPass) {
		t.Error("the old password still verifies against the LDAP digest")
	}

	fresh := client.NewWithPassword("alice", testRealm, newPass, h.config())
	if err := fresh.Login(); err != nil {
		t.Errorf("login with the new password: %v", err)
	}

	stale := client.NewWithPassword("alice", testRealm, oldPass, h.config())
	if err := stale.Login(); err == nil {
		t.Error("login with the old password still succeeds")
	}
}

func TestChangePasswordRejectsAShortPassword(t *testing.T) {
	h := newHarness(t)

	cl := client.NewWithPassword("alice", testRealm, oldPass, h.config())

	_, err := cl.ChangePasswd("short")
	if err == nil {
		t.Fatal("a password below the minimum length was accepted")
	}
	if !strings.Contains(err.Error(), "at least 8") {
		t.Errorf("error = %v, want the length policy to be named", err)
	}
}

func TestChangePasswordRejectsAWrongCurrentPassword(t *testing.T) {
	h := newHarness(t)

	cl := client.NewWithPassword("alice", testRealm, "not the password", h.config())

	if _, err := cl.ChangePasswd(newPass); err == nil {
		t.Fatal("the password was changed without knowing the current one")
	}
}

func TestSetPasswordForAnotherPrincipalIsRefused(t *testing.T) {
	h := newHarness(t)

	ctx := context.Background()
	u := &store.User{Name: "bob", UIDNumber: 10002, PrimaryGroup: 5000}
	if err := h.store.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	keys, err := krbkeys.RandomKeys(h.etypes)
	if err != nil {
		t.Fatalf("RandomKeys: %v", err)
	}
	if err := h.store.CreatePrincipal(ctx, &store.Principal{
		Name: "bob", Realm: testRealm, UserID: &u.ID, Enabled: true, RequiresPreAuth: true,
	}, keys); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}

	cl := client.NewWithPassword("alice", testRealm, oldPass, h.config())

	// Setting another principal's password over this protocol is deliberately not offered:
	// alice must not be able to take over bob's account just by holding her own password.
	_, err = cl.SetPasswd(krbkeys.MustParseName("bob", testRealm).PrincipalName(), testRealm, newPass)
	if err == nil {
		t.Fatal("one user set another user's password")
	}
}

// TestAPRepIsSealedWithTheTicketSessionKey pins the key the reply's AP-REP is encrypted under.
//
// RFC 4120 Section 5.5.2 encrypts the AP-REP with the ticket's session key, even when the client
// offered a subkey for the messages that follow. The Go client library never opens the AP-REP, so
// this exchange succeeds against it either way; a client that does check, such as Heimdal's
// kpasswd, fails with a decryption error while the password has in fact already been changed.
func TestAPRepIsSealedWithTheTicketSessionKey(t *testing.T) {
	h := newHarness(t)
	cfg := h.config()

	cl := client.NewWithPassword("alice", testRealm, oldPass, cfg)

	asReq, err := messages.NewASReqForChgPasswd(testRealm, cfg, cl.Credentials.CName())
	if err != nil {
		t.Fatalf("building AS-REQ: %v", err)
	}

	asRep, err := cl.ASExchange(testRealm, asReq, 0)
	if err != nil {
		t.Fatalf("AS exchange for kadmin/changepw: %v", err)
	}

	msg, _, err := kadmin.ChangePasswdMsg(cl.Credentials.CName(), testRealm, newPass,
		asRep.Ticket, asRep.DecryptedEncPart.Key)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}

	raw, err := msg.Marshal()
	if err != nil {
		t.Fatalf("marshalling the request: %v", err)
	}

	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 464}
	reply := h.password.Handle(context.Background(), raw, addr, addr)

	if len(reply) < 6 {
		t.Fatalf("reply is %d bytes", len(reply))
	}

	apRepLen := int(binary.BigEndian.Uint16(reply[4:6]))
	if apRepLen == 0 {
		t.Fatalf("the request was refused: %q", reply[6:])
	}
	if apRepLen > len(reply)-6 {
		t.Fatalf("the AP-REP length runs past the reply")
	}

	var apRep messages.APRep
	if err := apRep.Unmarshal(reply[6 : 6+apRepLen]); err != nil {
		t.Fatalf("parsing the AP-REP: %v", err)
	}

	plain, err := crypto.DecryptEncPart(apRep.EncPart, asRep.DecryptedEncPart.Key, keyusage.AP_REP_ENCPART)
	if err != nil {
		t.Fatalf("the AP-REP does not open with the ticket session key: %v", err)
	}

	var part messages.EncAPRepPart
	if err := part.Unmarshal(plain); err != nil {
		t.Fatalf("parsing the AP-REP encrypted part: %v", err)
	}

	// A client checking sequence numbers takes the server's from here and expects the KRB-PRIV
	// that follows to carry the same one.
	if part.SequenceNumber == 0 {
		t.Error("the AP-REP announces no sequence number")
	}

	privLen := len(reply) - 6 - apRepLen
	if privLen <= 0 {
		t.Fatal("the reply carries no KRB-PRIV")
	}

	var priv messages.KRBPriv
	if err := priv.Unmarshal(reply[6+apRepLen:]); err != nil {
		t.Fatalf("parsing the KRB-PRIV: %v", err)
	}

	// The KRB-PRIV, unlike the AP-REP, is sealed with the subkey the client offered.
	subKey := msg.APREQ.Authenticator.SubKey
	if err := priv.DecryptEncPart(subKey); err != nil {
		t.Fatalf("the KRB-PRIV does not open with the client's subkey: %v", err)
	}

	if priv.DecryptedEncPart.SequenceNumber != part.SequenceNumber {
		t.Errorf("KRB-PRIV sequence number = %d, want the %d announced in the AP-REP",
			priv.DecryptedEncPart.SequenceNumber, part.SequenceNumber)
	}

	if code := binary.BigEndian.Uint16(priv.DecryptedEncPart.UserData[:2]); code != resultSuccess {
		t.Errorf("result code = %d (%s), want success", code, resultName(code))
	}
}
