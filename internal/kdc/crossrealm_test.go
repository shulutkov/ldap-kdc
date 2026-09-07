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
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/secret"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

const (
	localRealm  = "EXAMPLE.COM"
	remoteRealm = "PARTNER.COM"
	trustSecret = "the shared cross-realm secret"
)

// realmHarness is one realm: its own store and KDC.
type realmHarness struct {
	realm   string
	store   *store.Store
	address string
	etypes  []int32
}

func newRealm(t *testing.T, realm, netbios string) *realmHarness {
	t.Helper()

	ctx := context.Background()
	dir := t.TempDir()

	key, _, err := secret.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("%s master key: %v", realm, err)
	}

	sealer, err := secret.NewSealer(key)
	if err != nil {
		t.Fatalf("%s sealer: %v", realm, err)
	}

	log := zerolog.New(io.Discard)

	st, err := store.Open(ctx, filepath.Join(dir, "kdc.db"), sealer, log)
	if err != nil {
		t.Fatalf("%s store: %v", realm, err)
	}
	t.Cleanup(func() { _ = st.Close() })

	etypes, err := krbkeys.ResolveEncTypes([]string{"aes256-cts-hmac-sha1-96"})
	if err != nil {
		t.Fatalf("enctypes: %v", err)
	}
	if _, err := st.EnsureRealm(ctx, realm, etypes); err != nil {
		t.Fatalf("%s EnsureRealm: %v", realm, err)
	}

	sid, err := st.EnsureDomainSID(ctx, "")
	if err != nil {
		t.Fatalf("%s domain SID: %v", realm, err)
	}

	srv, err := New(Config{
		Realm: realm, DomainName: strings.ToLower(realm), NetBIOSName: netbios, DomainSID: sid,
		Listen: "127.0.0.1:0", MaxTicketLife: 10 * time.Hour, MaxRenewableLife: 24 * time.Hour,
		ClockSkew: 5 * time.Minute, EncTypes: etypes, RequirePreAuth: true,
		IssuePAC: true, AllowS4U: true, UDPMaxSize: 4096,
		Lockout: store.LockoutPolicy{
			MaxFailures: 10, FailureCountInterval: time.Minute, LockoutDuration: time.Minute,
		},
	}, st, log, metrics.New())
	if err != nil {
		t.Fatalf("%s kdc: %v", realm, err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("%s start: %v", realm, err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	})

	return &realmHarness{realm: realm, store: st, address: srv.Addr().String(), etypes: etypes}
}

// addTrustPrincipal installs a cross-realm key. Both realms derive it from the same password and
// the same principal name, so the salts, and therefore the keys, match on both sides.
func (h *realmHarness) addTrustPrincipal(t *testing.T, name krbkeys.Name) {
	t.Helper()

	keys, err := krbkeys.DeriveKeys(trustSecret, name, h.etypes)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	if err := h.store.CreatePrincipal(context.Background(), &store.Principal{
		Name: name.Principal(), Realm: name.Realm, Enabled: true, RequiresPreAuth: true,
		AllowForwardable: true, AllowProxiable: true, AllowRenewable: true,
	}, keys); err != nil {
		t.Fatalf("CreatePrincipal %s: %v", name, err)
	}
}

func (h *realmHarness) addTrust(t *testing.T, remote string, direction store.TrustDirection) {
	t.Helper()

	if err := h.store.CreateTrust(context.Background(), &store.Trust{
		RemoteRealm: remote, Direction: direction, Transitive: true, Enabled: true,
	}); err != nil {
		t.Fatalf("CreateTrust: %v", err)
	}
}

func (h *realmHarness) addUser(t *testing.T, name, password string) {
	t.Helper()

	ctx := context.Background()

	if err := h.store.CreateGroup(ctx, &store.Group{Name: "users", GIDNumber: 5000}); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	u := &store.User{Name: name, UIDNumber: 10000, PrimaryGroup: 5000}
	if err := h.store.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	keys, err := krbkeys.RandomKeys(h.etypes)
	if err != nil {
		t.Fatalf("RandomKeys: %v", err)
	}
	if err := h.store.CreatePrincipal(ctx, &store.Principal{
		Name: name, Realm: h.realm, UserID: &u.ID, Enabled: true, RequiresPreAuth: true,
		AllowForwardable: true, AllowProxiable: true, AllowRenewable: true,
	}, keys); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	if err := h.store.SetUserPassword(ctx, name, password, h.etypes, nil); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
}

func (h *realmHarness) addService(t *testing.T, spn string) {
	t.Helper()

	name := krbkeys.MustParseName(spn, h.realm)

	keys, err := krbkeys.RandomKeys(h.etypes)
	if err != nil {
		t.Fatalf("RandomKeys: %v", err)
	}
	if err := h.store.CreatePrincipal(context.Background(), &store.Principal{
		Name: name.Principal(), Realm: name.Realm, Enabled: true, RequiresPreAuth: true,
		AllowForwardable: true, AllowProxiable: true, AllowRenewable: true,
	}, keys); err != nil {
		t.Fatalf("CreatePrincipal %s: %v", spn, err)
	}
}

// twoRealmConfig points the client at both KDCs, the way a krb5.conf spanning a trust would.
func twoRealmConfig(local, remote *realmHarness) *krb5config.Config {
	c := krb5config.New()

	names := []string{"aes256-cts-hmac-sha1-96"}
	etypes := local.etypes

	c.LibDefaults.DefaultRealm = local.realm
	c.LibDefaults.DefaultTktEnctypes = names
	c.LibDefaults.DefaultTktEnctypeIDs = etypes
	c.LibDefaults.DefaultTGSEnctypes = names
	c.LibDefaults.DefaultTGSEnctypeIDs = etypes
	c.LibDefaults.PermittedEnctypes = names
	c.LibDefaults.PermittedEnctypeIDs = etypes
	c.LibDefaults.DNSLookupKDC = false
	c.LibDefaults.DNSLookupRealm = false
	c.LibDefaults.TicketLifetime = 10 * time.Hour
	c.LibDefaults.RenewLifetime = 24 * time.Hour

	c.DomainRealm[strings.ToLower(local.realm)] = local.realm
	c.DomainRealm[strings.ToLower(remote.realm)] = remote.realm

	for _, h := range []*realmHarness{local, remote} {
		c.Realms = append(c.Realms, krb5config.Realm{
			Realm:         h.realm,
			DefaultDomain: strings.ToLower(h.realm),
			KDC:           []string{h.address},
		})
	}

	return c
}

// TestCrossRealmReferral walks a client from its own realm to a service in a trusted one: the home
// KDC answers with a ticket for the remote realm's ticket-granting service, and the remote KDC
// turns that into the service ticket.
func TestCrossRealmReferral(t *testing.T) {
	local := newRealm(t, localRealm, "EXAMPLE")
	remote := newRealm(t, remoteRealm, "PARTNER")

	// The outbound half lives in the home realm and the inbound half in the remote one, both
	// under the same principal name so the shared secret produces the same key.
	crossName := krbkeys.Name{Components: []string{"krbtgt", remoteRealm}, Realm: localRealm}
	local.addTrustPrincipal(t, crossName)
	remote.addTrustPrincipal(t, crossName)

	local.addTrust(t, remoteRealm, store.TrustOutbound)
	remote.addTrust(t, localRealm, store.TrustInbound)

	local.addUser(t, "alice", testPassword)
	remote.addService(t, "HTTP/www.partner.com")

	cfg := twoRealmConfig(local, remote)
	cl := client.NewWithPassword("alice", localRealm, testPassword, cfg)

	asReq, err := messages.NewASReqForTGT(localRealm, cfg, cl.Credentials.CName())
	if err != nil {
		t.Fatalf("building AS-REQ: %v", err)
	}

	asRep, err := cl.ASExchange(localRealm, asReq, 0)
	if err != nil {
		t.Fatalf("AS exchange: %v", err)
	}

	spn := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/www.partner.com")

	tgsReq, err := messages.NewTGSReq(cl.Credentials.CName(), localRealm, localRealm, cfg,
		asRep.Ticket, asRep.DecryptedEncPart.Key, spn, false)
	if err != nil {
		t.Fatalf("building TGS-REQ: %v", err)
	}

	// TGSExchange follows the referral itself: it recognises a ticket-granting ticket for a
	// realm it did not ask for and re-sends the request there.
	_, tgsRep, err := cl.TGSExchange(tgsReq, localRealm, asRep.Ticket, asRep.DecryptedEncPart.Key, 0)
	if err != nil {
		t.Fatalf("cross-realm TGS exchange: %v", err)
	}

	if got := tgsRep.Ticket.SName.PrincipalNameString(); got != "HTTP/www.partner.com" {
		t.Errorf("service ticket is for %q, want HTTP/www.partner.com", got)
	}
	if tgsRep.Ticket.Realm != remoteRealm {
		t.Errorf("service ticket realm = %q, want %s", tgsRep.Ticket.Realm, remoteRealm)
	}

	// The ticket must still name the client in its own realm; that is what the remote service
	// authorizes against.
	if tgsRep.CRealm != localRealm {
		t.Errorf("client realm in the reply = %q, want %s", tgsRep.CRealm, localRealm)
	}
	if got := tgsRep.CName.PrincipalNameString(); got != "alice" {
		t.Errorf("client name = %q, want alice", got)
	}
}

// TestCrossRealmIsRefusedWithoutATrust checks that a referral is not handed out just because the
// cross-realm key happens to exist.
func TestCrossRealmIsRefusedWithoutATrust(t *testing.T) {
	local := newRealm(t, localRealm, "EXAMPLE")
	remote := newRealm(t, remoteRealm, "PARTNER")

	crossName := krbkeys.Name{Components: []string{"krbtgt", remoteRealm}, Realm: localRealm}
	local.addTrustPrincipal(t, crossName)
	remote.addTrustPrincipal(t, crossName)

	// The key is in place but no trust record says referrals are allowed.
	local.addUser(t, "alice", testPassword)
	remote.addService(t, "HTTP/www.partner.com")

	cfg := twoRealmConfig(local, remote)
	cl := client.NewWithPassword("alice", localRealm, testPassword, cfg)

	asReq, err := messages.NewASReqForTGT(localRealm, cfg, cl.Credentials.CName())
	if err != nil {
		t.Fatalf("building AS-REQ: %v", err)
	}

	asRep, err := cl.ASExchange(localRealm, asReq, 0)
	if err != nil {
		t.Fatalf("AS exchange: %v", err)
	}

	spn := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/www.partner.com")

	tgsReq, err := messages.NewTGSReq(cl.Credentials.CName(), localRealm, localRealm, cfg,
		asRep.Ticket, asRep.DecryptedEncPart.Key, spn, false)
	if err != nil {
		t.Fatalf("building TGS-REQ: %v", err)
	}

	_, _, err = cl.TGSExchange(tgsReq, localRealm, asRep.Ticket, asRep.DecryptedEncPart.Key, 0)
	if err == nil {
		t.Fatal("a referral was issued to a realm with no trust")
	}
	if !strings.Contains(err.Error(), "KDC_ERR_S_PRINCIPAL_UNKNOWN") {
		t.Errorf("error = %v, want the remote realm to be reported as unknown", err)
	}
}
