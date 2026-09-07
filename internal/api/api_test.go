package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/keytab"
	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/secret"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

const (
	testRealm = "EXAMPLE.COM"
	testToken = "a-secret-management-token"
)

type harness struct {
	store  *store.Store
	base   string
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

	st, err := store.Open(ctx, filepath.Join(dir, "api.db"), sealer, log)
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

	srv, err := New(Config{
		Listen: "127.0.0.1:0", Realm: testRealm, EncTypes: etypes,
		Token: testToken, MinPasswordLength: 8,
	}, st, log, metrics.New())
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	})

	return &harness{store: st, base: "http://" + srv.Addr().String(), etypes: etypes}
}

// do sends an authenticated request and returns the status and decoded body.
func (h *harness) do(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()

	status, raw := h.raw(t, method, path, body, testToken)

	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: decoding %q: %v", method, path, raw, err)
		}
	}

	return status, out
}

// raw sends a request with the given token and returns the status and body bytes.
func (h *harness) raw(t *testing.T, method, path string, body any, token string) (int, []byte) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encoding request: %v", err)
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, h.base+path, reader)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if len(token) > 0 {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}

	return res.StatusCode, raw
}

func TestTokenIsRequired(t *testing.T) {
	h := newHarness(t)

	if status, _ := h.raw(t, "GET", "/api/v1/users", nil, ""); status != http.StatusUnauthorized {
		t.Errorf("without a token: status = %d, want 401", status)
	}

	if status, _ := h.raw(t, "GET", "/api/v1/users", nil, "the-wrong-token"); status != http.StatusUnauthorized {
		t.Errorf("with a wrong token: status = %d, want 401", status)
	}

	if status, _ := h.raw(t, "GET", "/api/v1/users", nil, testToken); status != http.StatusOK {
		t.Errorf("with the right token: status = %d, want 200", status)
	}

	// Health and metrics stay open so an orchestrator can scrape them without holding a
	// credential that can change passwords.
	if status, _ := h.raw(t, "GET", "/healthz", nil, ""); status != http.StatusOK {
		t.Errorf("/healthz: status = %d, want 200", status)
	}
	if status, _ := h.raw(t, "GET", "/metrics", nil, ""); status != http.StatusOK {
		t.Errorf("/metrics: status = %d, want 200", status)
	}
}

func TestCreatingAUserAlsoCreatesItsPrincipal(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	if status, _ := h.do(t, "POST", "/api/v1/groups", map[string]any{
		"name": "staff", "gidNumber": 5000,
	}); status != http.StatusCreated {
		t.Fatalf("creating group: status = %d", status)
	}

	status, body := h.do(t, "POST", "/api/v1/users", map[string]any{
		"name": "alice", "uidNumber": 10000, "primaryGroup": 5000,
		"mail": "alice@example.com", "password": "a long enough password",
	})
	if status != http.StatusCreated {
		t.Fatalf("creating user: status = %d, body = %v", status, body)
	}

	// The point of the unified service: one call leaves the account able to bind over LDAP and
	// to obtain a ticket.
	u, err := h.store.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !store.CheckPassword(u.PassBcrypt, "a long enough password") {
		t.Error("the LDAP digest was not set")
	}

	name := krbkeys.MustParseName("alice", testRealm)

	p, err := h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}

	want, err := krbkeys.DeriveKeys("a long enough password", name, h.etypes)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	got, ok := p.KeyFor(want[0].EType)
	if !ok {
		t.Fatal("principal has no key")
	}
	if string(got.Value) != string(want[0].Value) {
		t.Error("the Kerberos key does not match the password the API was given")
	}
}

func TestPasswordPolicyIsEnforced(t *testing.T) {
	h := newHarness(t)

	status, body := h.do(t, "POST", "/api/v1/users", map[string]any{
		"name": "shorty", "uidNumber": 10001, "primaryGroup": 5000, "password": "short",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "at least 8") {
		t.Errorf("error = %q, want the length policy to be named", msg)
	}
}

func TestUnknownFieldsAreRejected(t *testing.T) {
	h := newHarness(t)

	// A misspelled key silently ignored is how an administrator ends up believing a setting was
	// applied when it never was. Note that Go matches JSON names case-insensitively, so only a
	// genuinely different spelling is unknown.
	status, body := h.do(t, "POST", "/api/v1/groups", map[string]any{
		"name": "typo", "gid_number": 5001,
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %v", status, body)
	}
}

func TestDisablingAUserDisablesItsPrincipal(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	h.do(t, "POST", "/api/v1/groups", map[string]any{"name": "staff", "gidNumber": 5000})
	h.do(t, "POST", "/api/v1/users", map[string]any{
		"name": "bob", "uidNumber": 10002, "primaryGroup": 5000, "password": "a long enough password",
	})

	if status, body := h.do(t, "PATCH", "/api/v1/users/bob", map[string]any{"disabled": true}); status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}

	// Otherwise the account would be locked out of LDAP while still collecting tickets.
	p, err := h.store.GetPrincipal(ctx, krbkeys.MustParseName("bob", testRealm))
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}
	if p.Enabled {
		t.Error("the Kerberos principal is still enabled after the account was disabled")
	}
}

func TestServicePrincipalAndKeytab(t *testing.T) {
	h := newHarness(t)

	status, body := h.do(t, "POST", "/api/v1/principals", map[string]any{
		"name": "HTTP/www.example.com", "okAsDelegate": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("creating principal: status = %d, body = %v", status, body)
	}

	// A service principal is keyed randomly, so the keytab is the only way to hand the key to
	// the service.
	status, raw := h.raw(t, "GET", "/api/v1/principals/HTTP/www.example.com/keytab", nil, testToken)
	if status != http.StatusOK {
		t.Fatalf("keytab: status = %d, body = %s", status, raw)
	}

	kt := keytab.New()
	if err := kt.Unmarshal(raw); err != nil {
		t.Fatalf("the keytab does not parse: %v", err)
	}
	if len(kt.Entries) != len(h.etypes) {
		t.Errorf("keytab has %d entries, want %d", len(kt.Entries), len(h.etypes))
	}

	name := krbkeys.MustParseName("HTTP/www.example.com", testRealm)
	if _, _, err := kt.GetEncryptionKey(name.PrincipalName(), testRealm, 0, h.etypes[0]); err != nil {
		t.Errorf("the keytab has no usable key for the principal: %v", err)
	}
}

func TestRekeyingAPrincipalBumpsItsKVNO(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	h.do(t, "POST", "/api/v1/principals", map[string]any{"name": "HTTP/app.example.com"})

	name := krbkeys.MustParseName("HTTP/app.example.com", testRealm)

	before, err := h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}

	if status, body := h.do(t, "POST", "/api/v1/principals/HTTP/app.example.com/password",
		map[string]any{"randomize": true}); status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}

	after, err := h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}

	if after.KVNO != before.KVNO+1 {
		t.Errorf("kvno = %d, want %d", after.KVNO, before.KVNO+1)
	}
	if string(after.Keys[0].Value) == string(before.Keys[0].Value) {
		t.Error("the key did not actually change")
	}

	// The previous version has to survive, or every ticket already issued to the service stops
	// decrypting the moment its password rotates.
	prev, err := h.store.GetPrincipalKVNO(ctx, name, before.KVNO)
	if err != nil {
		t.Fatalf("previous kvno: %v", err)
	}
	if len(prev.Keys) == 0 {
		t.Error("the previous key version was discarded")
	}
}

func TestTheRealmsOwnTGTCannotBeDeleted(t *testing.T) {
	h := newHarness(t)

	// Deleting it would invalidate every ticket in the realm and leave the KDC unable to answer.
	status, _ := h.do(t, "DELETE", "/api/v1/principals/krbtgt/"+testRealm, nil)
	if status != http.StatusConflict {
		t.Errorf("status = %d, want 409", status)
	}
}

func TestTrustCreatesBothCrossRealmPrincipals(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	status, body := h.do(t, "POST", "/api/v1/trusts", map[string]any{
		"remoteRealm": "other.com", "direction": "bidirectional",
		"password": "the shared trust password",
	})
	if status != http.StatusCreated {
		t.Fatalf("status = %d, body = %v", status, body)
	}

	// Outbound referrals need krbtgt/OTHER.COM@EXAMPLE.COM; accepting their clients needs
	// krbtgt/EXAMPLE.COM@OTHER.COM. Both are keyed from the same shared password.
	for _, name := range []string{"krbtgt/OTHER.COM@EXAMPLE.COM", "krbtgt/EXAMPLE.COM@OTHER.COM"} {
		n := krbkeys.MustParseName(name, testRealm)

		p, err := h.store.GetPrincipal(ctx, n)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		want, err := krbkeys.DeriveKeys("the shared trust password", n, h.etypes)
		if err != nil {
			t.Fatalf("DeriveKeys: %v", err)
		}
		got, ok := p.KeyFor(want[0].EType)
		if !ok {
			t.Fatalf("%s has no key", name)
		}
		if string(got.Value) != string(want[0].Value) {
			t.Errorf("%s: key does not match the shared password", name)
		}
	}

	if status, _ := h.do(t, "DELETE", "/api/v1/trusts/other.com", nil); status != http.StatusNoContent {
		t.Fatalf("deleting trust: status = %d", status)
	}

	// Removing the relationship must remove its keys, or a revoked trust keeps working.
	if _, err := h.store.GetPrincipal(ctx, krbkeys.MustParseName("krbtgt/OTHER.COM@EXAMPLE.COM", testRealm)); err == nil {
		t.Error("the cross-realm principal survived the trust being deleted")
	}
}

func TestApplicationPasswordIsReturnedOnceAndVerifies(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	h.do(t, "POST", "/api/v1/groups", map[string]any{"name": "staff", "gidNumber": 5000})
	h.do(t, "POST", "/api/v1/users", map[string]any{
		"name": "carol", "uidNumber": 10003, "primaryGroup": 5000, "password": "a long enough password",
	})

	status, body := h.do(t, "POST", "/api/v1/users/carol/app-passwords", map[string]any{"name": "backup job"})
	if status != http.StatusCreated {
		t.Fatalf("status = %d, body = %v", status, body)
	}

	generated, _ := body["password"].(string)
	if len(generated) == 0 {
		t.Fatal("no generated password was returned")
	}

	u, err := h.store.GetUser(ctx, "carol")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if len(u.AppPasswords) != 1 {
		t.Fatalf("user has %d application passwords, want 1", len(u.AppPasswords))
	}
	if !store.CheckPassword(u.AppPasswords[0].Hash, generated) {
		t.Error("the returned password does not verify against the stored digest")
	}

	// Reading the list back must not expose the secret again.
	_, list := h.do(t, "GET", "/api/v1/users/carol/app-passwords", nil)
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), generated) {
		t.Error("the application password is readable after creation")
	}
}

func TestReadyReportsTheRealm(t *testing.T) {
	h := newHarness(t)

	status, body := h.do(t, "GET", "/readyz", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if body["realm"] != testRealm {
		t.Errorf("realm = %v, want %s", body["realm"], testRealm)
	}
}

func TestAdministrativeResetExpiresThePassword(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	h.do(t, "POST", "/api/v1/groups", map[string]any{"name": "staff", "gidNumber": 5000})
	h.do(t, "POST", "/api/v1/users", map[string]any{
		"name": "dave", "uidNumber": 10010, "primaryGroup": 5000,
		"password": "a long enough password",
	})

	name := krbkeys.MustParseName("dave", testRealm)

	// A password an administrator typed is one the administrator knows, so FreeIPA marks it
	// expired and the owner has to choose a final value at first login.
	p, err := h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}
	if !p.PasswordExpired(time.Now()) {
		t.Error("a password set at creation was not marked for change")
	}

	// The same for a later reset, and the reply says so.
	status, body := h.do(t, "POST", "/api/v1/users/dave/password",
		map[string]any{"password": "another long password"})
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}
	if body["mustChange"] != true {
		t.Errorf("mustChange = %v, want true", body["mustChange"])
	}

	// An administrator provisioning a service account can opt out.
	if status, _ := h.do(t, "POST", "/api/v1/users/dave/password",
		map[string]any{"password": "a third long password", "forceChange": false}); status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}

	p, err = h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}
	if p.PasswordExpired(time.Now()) {
		t.Error("forceChange=false still marked the password for change")
	}
}

func TestPrincipalReportsItsTicketFlags(t *testing.T) {
	h := newHarness(t)

	h.do(t, "POST", "/api/v1/principals", map[string]any{
		"name": "HTTP/flags.example.com", "okAsDelegate": true, "okToAuthAsDelegate": true,
	})

	_, body := h.do(t, "GET", "/api/v1/principals/HTTP/flags.example.com", nil)

	// The same policy MIT and FreeIPA keep in krbTicketFlags: REQUIRES_PRE_AUTH (128),
	// DISALLOW_POSTDATED (1), OK_AS_DELEGATE (0x100000) and OK_TO_AUTH_AS_DELEGATE (0x200000).
	want := float64(0x80 | 0x1 | 0x100000 | 0x200000)
	if got := body["krbTicketFlags"]; got != want {
		t.Errorf("krbTicketFlags = %v, want %v", got, want)
	}
}
