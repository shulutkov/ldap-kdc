package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/client"
	krb5config "github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/spnego"
	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/failban"
	"github.com/shulutkov/ldap-kdc/internal/jws"
	"github.com/shulutkov/ldap-kdc/internal/kdc"
	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

const accountPassword = "a long enough password"

// seedAdmins creates the two kinds of account the console tells apart: an administrator, whose
// group may write the whole directory, and an ordinary account whose group may not.
func (h *harness) seedAdmins(t *testing.T) {
	t.Helper()

	ctx := context.Background()

	for _, g := range []*store.Group{
		{Name: "admins", GIDNumber: 5000, Capabilities: []store.Capability{
			{Action: "search", Object: "*"},
			{Action: "write", Object: "*"},
		}},
		{Name: "staff", GIDNumber: 5001},
	} {
		if err := h.store.CreateGroup(ctx, g); err != nil {
			t.Fatalf("CreateGroup %s: %v", g.Name, err)
		}
	}

	for _, a := range []struct {
		name, mail string
		gid        int
	}{
		{"admin", "admin@example.com", 5000},
		{"bob", "bob@example.com", 5001},
	} {
		if err := h.store.CreateAccount(ctx, store.NewAccount{
			User:     &store.User{Name: a.name, PrimaryGroup: a.gid, Mail: a.mail},
			Realm:    testRealm,
			EncTypes: h.etypes,
			Password: accountPassword,
		}); err != nil {
			t.Fatalf("CreateAccount %s: %v", a.name, err)
		}
	}
}

// signIn posts a password sign-in and returns the status, the session and the refusal text.
func (h *harness) signIn(t *testing.T, login, password string) (int, sessionBody, string) {
	t.Helper()

	status, raw := h.raw(t, "POST", "/api/v1/auth/login", map[string]string{"login": login, "password": password}, "")

	var (
		session sessionBody
		refusal errorBody
	)
	if status == http.StatusOK {
		if err := json.Unmarshal(raw, &session); err != nil {
			t.Fatalf("decoding the session: %v", err)
		}
	} else {
		_ = json.Unmarshal(raw, &refusal)
	}

	return status, session, refusal.Error
}

func TestAnAdministratorSignsInWithAPassword(t *testing.T) {
	h := newHarness(t)
	h.seedAdmins(t)

	// By name and by mail address, because a person signing in to a page types the address they
	// know themselves by.
	for _, login := range []string{"admin", "admin@example.com"} {
		status, session, refusal := h.signIn(t, login, accountPassword)
		if status != http.StatusOK {
			t.Fatalf("sign-in as %s: status = %d (%s)", login, status, refusal)
		}
		if session.Subject != "admin" || session.Method != methodPassword {
			t.Errorf("session = %+v", session)
		}
		if !session.ExpiresAt.After(time.Now()) {
			t.Errorf("the session expires at %s, which has passed", session.ExpiresAt)
		}

		// The session opens the API exactly as the management token does.
		if status, raw := h.raw(t, "GET", "/api/v1/users", nil, session.Token); status != http.StatusOK {
			t.Fatalf("listing users with the session: status = %d, body = %s", status, raw)
		}

		_, raw := h.raw(t, "GET", "/api/v1/auth/whoami", nil, session.Token)

		var me whoAmIBody
		if err := json.Unmarshal(raw, &me); err != nil {
			t.Fatalf("whoami: %v", err)
		}
		if me.Subject != "admin" || me.Method != methodPassword || me.ExpiresAt == nil {
			t.Errorf("whoami = %+v", me)
		}
	}
}

func TestOnlyAdministratorsSignIn(t *testing.T) {
	h := newHarness(t)
	h.seedAdmins(t)

	// The right password for an account that does not administer the directory is refused as a
	// matter of authority, not of credentials. An LDAP bind would already have told the caller the
	// password was right, so saying so here gives nothing away.
	if status, _, _ := h.signIn(t, "bob", accountPassword); status != http.StatusForbidden {
		t.Errorf("an ordinary account signing in: status = %d, want 403", status)
	}

	// Every refusal of the credential reads the same, so the answer says nothing about which
	// accounts exist.
	wrongStatus, _, wrong := h.signIn(t, "admin", "not the password")
	missingStatus, _, missing := h.signIn(t, "nobody", "not the password")

	if wrongStatus != http.StatusUnauthorized || missingStatus != http.StatusUnauthorized {
		t.Errorf("statuses = %d, %d, want 401 for both", wrongStatus, missingStatus)
	}
	if wrong != missing {
		t.Errorf("a wrong password reads %q and an unknown account %q; they must not differ", wrong, missing)
	}
}

func TestAnApplicationPasswordDoesNotOpenTheConsole(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.seedAdmins(t)

	hash, err := h.store.HashPassword("an application password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := h.store.AddAppPassword(ctx, "admin", "backup", hash); err != nil {
		t.Fatalf("AddAppPassword: %v", err)
	}

	// It binds over LDAP, which is what it is for. Here it would be a way past the account's
	// one-time code into an interface that resets passwords.
	if status, _, _ := h.signIn(t, "admin", "an application password"); status != http.StatusUnauthorized {
		t.Errorf("status = %d, want the application password refused", status)
	}
}

func TestASessionEndsWithTheAuthorityBehindIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(h *harness)
	}{
		{"the group loses the capability", func(h *harness) {
			h.do(t, "PATCH", "/api/v1/groups/admins", map[string]any{
				"capabilities": []store.Capability{{Action: "search", Object: "*"}},
			})
		}},
		{"the account is disabled", func(h *harness) {
			h.do(t, "PATCH", "/api/v1/users/admin", map[string]any{"disabled": true})
		}},
		{"the account is removed", func(h *harness) {
			h.do(t, "DELETE", "/api/v1/users/admin", nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.seedAdmins(t)

			_, session, _ := h.signIn(t, "admin", accountPassword)
			tc.change(h)

			// A token is only a claim about the past. The directory is asked again on every
			// request, so the console closes at the next click, not when the token runs out.
			if status, _ := h.raw(t, "GET", "/api/v1/users", nil, session.Token); status != http.StatusUnauthorized {
				t.Errorf("status = %d, want the session refused", status)
			}
		})
	}
}

func TestOnlyTheAPIsOwnSessionsAreHonoured(t *testing.T) {
	h := newHarness(t)
	h.seedAdmins(t)

	claims := func(exp time.Time) map[string]any {
		return map[string]any{
			"iss": sessionIssuer, "aud": sessionAudience, "sub": "admin",
			"iat": time.Now().Unix(), "exp": exp.Unix(), "amr": []string{methodPassword},
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	other, err := jws.New(key)
	if err != nil {
		t.Fatalf("jws.New: %v", err)
	}

	forged, err := other.Sign(claims(time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	expired, err := h.server.sig.Sign(claims(time.Now().Add(-time.Minute)))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	for _, tc := range []struct{ name, token string }{
		// Every claim right, and a key that is not this API's — which is exactly what an id token
		// from the OIDC provider is, and why the two never share a key.
		{"signed by another key", forged},
		{"genuine but expired", expired},
		{"no credential at all", ""},
	} {
		if status, _ := h.raw(t, "GET", "/api/v1/users", nil, tc.token); status != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", tc.name, status)
		}
	}
}

func TestFailedSignInsAreThrottledWithTheBinds(t *testing.T) {
	h := newHarnessWith(t, func(c *Config) {
		c.Limiter = failban.New(failban.Config{
			Enabled: true, Threshold: 2, Window: time.Minute, BlockFor: time.Minute,
			PruneEvery: time.Minute, PruneOlder: time.Minute,
		})
	})
	h.seedAdmins(t)

	for range 2 {
		if status, _, _ := h.signIn(t, "admin", "a guess"); status != http.StatusUnauthorized {
			t.Fatalf("a guess: status = %d, want 401", status)
		}
	}

	// Once blocked, even the right password waits: the block costs a guesser time, and a
	// password that happens to be right on the next try must not end it.
	if status, _, _ := h.signIn(t, "admin", accountPassword); status != http.StatusTooManyRequests {
		t.Errorf("after the threshold: status = %d, want 429", status)
	}
}

func TestAnAdministratorSignsInWithKerberos(t *testing.T) {
	const spn = "HTTP/localhost"

	h := newHarnessWith(t, func(c *Config) { c.SPN = spn })
	h.seedAdmins(t)

	kdcAddr := startKDC(t, h)

	for _, tc := range []struct {
		user string
		want int
	}{
		{"admin", http.StatusOK},
		// A genuine ticket for an account that does not administer the directory.
		{"bob", http.StatusForbidden},
	} {
		t.Run(tc.user, func(t *testing.T) {
			cl := client.NewWithPassword(tc.user, testRealm, accountPassword, krb5ClientConfig(h, kdcAddr))
			if err := cl.Login(); err != nil {
				t.Fatalf("kinit %s: %v", tc.user, err)
			}
			defer cl.Destroy()

			// The client library does what a browser does on a Negotiate challenge: it obtains a
			// ticket for the SPN from the KDC and presents it.
			resp, err := spnego.NewClient(cl, &http.Client{}, spn).Get(h.base + "/api/v1/auth/negotiate")
			if err != nil {
				t.Fatalf("negotiate: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			raw, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d, body = %s", resp.StatusCode, tc.want, raw)
			}
			if tc.want != http.StatusOK {
				return
			}

			var session sessionBody
			if err := json.Unmarshal(raw, &session); err != nil {
				t.Fatalf("decoding the session: %v", err)
			}
			if session.Subject != tc.user || session.Method != methodKerberos {
				t.Errorf("session = %+v", session)
			}
			if status, _ := h.raw(t, "GET", "/api/v1/users", nil, session.Token); status != http.StatusOK {
				t.Errorf("the Kerberos session does not open the API: status = %d", status)
			}
		})
	}

	// The service principal was created by the API itself, keyed at random: no keytab file was
	// needed anywhere for any of this.
	p, err := h.store.GetPrincipal(context.Background(), krbkeys.MustParseName(spn, testRealm))
	if err != nil || p.UserID != nil || len(p.Keys) == 0 {
		t.Errorf("the sign-in principal: %+v, %v", p, err)
	}
}

func TestKerberosSignInIsOffWithoutAnSPN(t *testing.T) {
	h := newHarness(t)

	if status, _ := h.raw(t, "GET", "/api/v1/auth/negotiate", nil, ""); status != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when no SPN is configured", status)
	}
}

func TestTheConsoleIsServedUnderAStrictPolicy(t *testing.T) {
	h := newHarness(t)

	noRedirects := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	resp, err := noRedirects.Get(h.base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/ui/" {
		t.Errorf("GET / = %d to %q, want a redirect to /ui/", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp, err = http.Get(h.base + "/ui/")
	if err != nil {
		t.Fatalf("GET /ui/: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `id="root"`) {
		t.Fatalf("GET /ui/ = %d, %d bytes", resp.StatusCode, len(body))
	}

	// The page holds a session that can reset any password, so it may load itself and talk to this
	// API and nothing else, and may not be framed by anybody.
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("Content-Security-Policy %q lacks %q", csp, want)
		}
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q", resp.Header.Get("X-Frame-Options"))
	}
}

// startKDC runs this service's KDC over the harness's store, which is how the service runs: the API
// and the KDC share one directory, so a ticket the KDC issues is one the API can verify.
func startKDC(t *testing.T, h *harness) string {
	t.Helper()

	ctx := context.Background()

	sid, err := h.store.EnsureDomainSID(ctx, "")
	if err != nil {
		t.Fatalf("EnsureDomainSID: %v", err)
	}

	srv, err := kdc.New(kdc.Config{
		Realm: testRealm, DomainName: "example.com", NetBIOSName: "EXAMPLE", DomainSID: sid,
		Listen: "127.0.0.1:0", MaxTicketLife: 10 * time.Hour, MaxRenewableLife: 24 * time.Hour,
		ClockSkew: 5 * time.Minute, EncTypes: h.etypes, RequirePreAuth: true, IssuePAC: true,
		UDPMaxSize: 4096,
	}, h.store, zerolog.Nop(), metrics.New())
	if err != nil {
		t.Fatalf("kdc: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("starting the KDC: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	})

	return srv.Addr().String()
}

// krb5ClientConfig points a Kerberos client at the test KDC, over TCP.
func krb5ClientConfig(h *harness, kdcAddr string) *krb5config.Config {
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
	c.LibDefaults.DNSLookupKDC = false
	c.LibDefaults.DNSLookupRealm = false
	// A preference limit of one byte keeps every request on TCP.
	c.LibDefaults.UDPPreferenceLimit = 1

	c.DomainRealm["localhost"] = testRealm
	c.Realms = append(c.Realms, krb5config.Realm{Realm: testRealm, KDC: []string{kdcAddr}})

	return c
}
