package api

import (
	"bytes"
	"compress/gzip"
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
	"golang.org/x/crypto/bcrypt"

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
	server *Server
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

	// Hashing at the production cost would have this suite spend minutes proving nothing
	// about the cost, and on a loaded machine it pushes a password change past the five
	// second deadline a Kerberos client allows for a reply.
	st, err := store.Open(ctx, filepath.Join(dir, "api.db"), sealer, log, store.WithPasswordHashCost(bcrypt.MinCost))
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
		Token: testToken, MinPasswordLength: 8, Docs: true,
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

	return &harness{store: st, server: srv, base: "http://" + srv.Addr().String(), etypes: etypes}
}

// asset fetches a documentation file with a chosen content coding, decompressing the answer
// itself. The default transport would add gzip and unwrap it silently, which is exactly the
// behaviour this has to tell apart.
func (h *harness) asset(t *testing.T, path, encoding string) ([]byte, http.Header) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, h.base+path, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Accept-Encoding", encoding)

	res, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s: status = %d", path, res.StatusCode)
	}

	if res.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("%s is not gzip: %v", path, err)
		}
		defer func() { _ = zr.Close() }()

		if body, err = io.ReadAll(zr); err != nil {
			t.Fatalf("decompressing %s: %v", path, err)
		}
	}

	return body, res.Header
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

func TestAliasesAreCreatedAndReplacedThroughTheAPI(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	h.do(t, "POST", "/api/v1/groups", map[string]any{"name": "staff", "gidNumber": 5000})

	status, body := h.do(t, "POST", "/api/v1/users", map[string]any{
		"name": "alice", "uidNumber": 10000, "primaryGroup": 5000,
		"password": "a long enough password", "aliases": []string{"alice.smith"},
	})
	if status != http.StatusCreated {
		t.Fatalf("creating user: status = %d, body = %v", status, body)
	}

	if p, err := h.store.GetPrincipal(ctx, krbkeys.MustParseName("alice.smith", testRealm)); err != nil {
		t.Fatalf("the alias does not resolve: %v", err)
	} else if p.Name != "alice" {
		t.Errorf("alice.smith resolved to %s", p.Name)
	}

	status, body = h.do(t, "POST", "/api/v1/principals", map[string]any{
		"name": "HTTP/www.example.com", "aliases": []string{"HTTP/web.example.com"},
	})
	if status != http.StatusCreated {
		t.Fatalf("creating principal: status = %d, body = %v", status, body)
	}

	// A name already spoken for cannot be handed to a second principal, whichever of the two
	// holds it canonically.
	if status, _ := h.do(t, "POST", "/api/v1/principals", map[string]any{
		"name": "HTTP/mail.example.com", "aliases": []string{"HTTP/web.example.com"},
	}); status != http.StatusConflict {
		t.Errorf("status = %d, want 409 for an alias another principal already answers to", status)
	}

	// PATCH replaces the list outright, so sending one without a name removes it.
	if status, body := h.do(t, "PATCH", "/api/v1/principals/HTTP/www.example.com", map[string]any{
		"aliases": []string{"HTTP/intranet.example.com"},
	}); status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}

	if _, err := h.store.GetPrincipal(ctx, krbkeys.MustParseName("HTTP/web.example.com", testRealm)); err == nil {
		t.Error("a replaced alias still resolves")
	}
	if _, err := h.store.GetPrincipal(ctx, krbkeys.MustParseName("HTTP/intranet.example.com", testRealm)); err != nil {
		t.Errorf("the new alias does not resolve: %v", err)
	}
}

func TestCustomAttributesOnGroupsAndUsers(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	status, body := h.do(t, "POST", "/api/v1/groups", map[string]any{
		"name": "engineering", "gidNumber": 5000,
		"customAttributes": map[string][]string{"costCentre": {"CC-42"}},
	})
	if status != http.StatusCreated {
		t.Fatalf("creating group: status = %d, body = %v", status, body)
	}

	h.do(t, "POST", "/api/v1/users", map[string]any{
		"name": "alice", "uidNumber": 10000, "primaryGroup": 5000,
		"customAttributes": map[string][]string{"departmentHead": {"engineering"}},
	})

	u, err := h.store.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if v := u.CustomAttrs["departmentHead"]; len(v) != 1 || v[0] != "engineering" {
		t.Errorf("user attributes = %v", u.CustomAttrs)
	}

	// PATCH replaces the set, the way the other list-shaped fields behave.
	if status, body := h.do(t, "PATCH", "/api/v1/groups/engineering", map[string]any{
		"customAttributes": map[string][]string{"owner": {"alice"}},
	}); status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}

	g, err := h.store.GetGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if _, ok := g.CustomAttrs["costCentre"]; ok {
		t.Errorf("a replaced attribute survived: %v", g.CustomAttrs)
	}

	// A name the directory builds itself is a bad request, not a server error: the caller can
	// fix it, and nothing about the service went wrong.
	status, body = h.do(t, "POST", "/api/v1/groups", map[string]any{
		"name": "forged", "gidNumber": 5001,
		"customAttributes": map[string][]string{"objectClass": {"top"}},
	})
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %v", status, body)
	}
}

func TestTheDocumentationIsServed(t *testing.T) {
	h := newHarness(t)

	// The page and the document sit outside the token check: a browser cannot put an
	// Authorization header on the address bar, so a documentation page behind the token would be
	// unreachable by the only client that can use it.
	status, page := h.raw(t, "GET", "/api/docs/", nil, "")
	if status != http.StatusOK {
		t.Fatalf("the documentation page: status = %d", status)
	}
	for _, want := range []string{"swagger-ui-bundle.js", "swagger-ui.css", "../openapi.json"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("the page does not load %s", want)
		}
	}

	// Swagger UI is embedded rather than fetched from a CDN, so the assets it names must be
	// served by this binary too. They are stored compressed, which the browser asks for; a client
	// that does not has to be given the decompressed bytes rather than a blob it cannot read.
	for _, asset := range []struct{ name, contains string }{
		{"swagger-ui-bundle.js", "SwaggerUIBundle"},
		{"swagger-ui.css", ".swagger-ui"},
	} {
		for _, encoding := range []string{"gzip", "identity"} {
			body, header := h.asset(t, "/api/docs/"+asset.name, encoding)

			if got := header.Get("Content-Encoding"); encoding == "gzip" && got != "gzip" {
				t.Errorf("%s: Content-Encoding = %q, want the stored gzip to be passed through", asset.name, got)
			} else if encoding == "identity" && len(got) > 0 {
				t.Errorf("%s: Content-Encoding = %q for a client that did not ask", asset.name, got)
			}

			if !strings.Contains(string(body), asset.contains) {
				t.Errorf("%s with Accept-Encoding %s: %d bytes that do not look like the asset",
					asset.name, encoding, len(body))
			}
		}
	}

	if status, raw := h.raw(t, "GET", "/api/openapi.json", nil, ""); status != http.StatusOK {
		t.Errorf("the OpenAPI document: status = %d, body = %s", status, raw)
	}
}

func TestTheGeneratedDocumentDescribesEveryRoute(t *testing.T) {
	h := newHarness(t)

	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(h.server.spec, &doc); err != nil {
		t.Fatalf("the document does not parse: %v", err)
	}

	// The document is generated from the route table, so the two cannot drift apart -- but a
	// route whose entry carries no documentation would quietly be missing from it, and an
	// endpoint nobody can find is not far from one that does not exist.
	for _, r := range append(h.server.publicRoutes(), h.server.apiRoutes()...) {
		method, pattern, _ := strings.Cut(r.pattern, " ")

		if len(r.docs) == 0 {
			t.Errorf("%s carries no documentation", r.pattern)

			continue
		}

		for _, d := range r.docs {
			path := documentedPath(pattern, d)

			methods, ok := doc.Paths[path]
			if !ok {
				t.Errorf("%s is missing from the document", path)

				continue
			}
			if _, ok := methods[strings.ToLower(method)]; !ok {
				t.Errorf("%s %s is missing from the document", method, path)
			}
		}
	}
}

func TestEveryReferenceInTheDocumentResolves(t *testing.T) {
	h := newHarness(t)

	var doc map[string]any
	if err := json.Unmarshal(h.server.spec, &doc); err != nil {
		t.Fatalf("the document does not parse: %v", err)
	}

	// A reference to a schema that is not there renders as an empty box in Swagger UI and as
	// nothing at all in a generated client, which is the sort of mistake a reader blames on the
	// service rather than on the document.
	refs := collectRefs(doc)
	if len(refs) == 0 {
		t.Fatal("the document holds no schema references at all")
	}

	for _, ref := range refs {
		if !resolves(doc, ref) {
			t.Errorf("%s points at nothing", ref)
		}
	}
}

// collectRefs gathers every $ref in the document.
func collectRefs(node any) []string {
	switch n := node.(type) {
	case map[string]any:
		var out []string

		for k, v := range n {
			if k == "$ref" {
				if ref, ok := v.(string); ok {
					out = append(out, ref)
				}

				continue
			}
			out = append(out, collectRefs(v)...)
		}

		return out
	case []any:
		var out []string
		for _, v := range n {
			out = append(out, collectRefs(v)...)
		}

		return out
	default:
		return nil
	}
}

// resolves follows a local JSON pointer through the document.
func resolves(doc map[string]any, ref string) bool {
	pointer, ok := strings.CutPrefix(ref, "#/")
	if !ok {
		return false
	}

	var current any = doc

	for _, step := range strings.Split(pointer, "/") {
		m, ok := current.(map[string]any)
		if !ok {
			return false
		}
		if current, ok = m[step]; !ok {
			return false
		}
	}

	return true
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
