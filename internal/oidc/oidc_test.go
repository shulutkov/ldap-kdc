package oidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/secret"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

const (
	theUI = "https://gitkeep.example/"
	theCP = "https://cp.gitkeep.example/ui/"
	// The client ids are the RESOURCES the tokens are for: an id token's audience is the client
	// id, and that is what a service checking "is this for me" compares against.
	uiClient = "https://mcp.gitkeep.example"
	cpClient = "https://cp.gitkeep.example"
	password = "correct horse battery staple"
)

type harness struct {
	*testing.T
	srv    *Server
	http   *httptest.Server
	client *http.Client
}

func setup(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	key, _, err := secret.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := secret.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(dir, "oidc.db"), sealer, zerolog.New(io.Discard),
		store.WithPasswordHashCost(bcrypt.MinCost))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.CreateGroup(ctx, &store.Group{Name: "owners", GIDNumber: 5000}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, &store.User{
		Name: "alice", UIDNumber: 10001, PrimaryGroup: 5000,
		GivenName: "Alice", SN: "Example", Mail: "alice@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserPassword(ctx, "alice", password, nil, nil); err != nil {
		t.Fatal(err)
	}

	srv, err := New(ctx, Config{
		Issuer:         "https://auth.example",
		AllowedOrigins: []string{"https://gitkeep.example"},
		Clients: []Client{
			{ID: uiClient, Name: "the UI", RedirectURIs: []string{theUI},
				PostLogoutRedirect: []string{theUI}},
			{ID: cpClient, Name: "the control plane", RedirectURIs: []string{theCP}},
		},
		SessionLifetime: 12 * time.Hour, SessionIdle: 2 * time.Hour,
		CodeLifetime: 5 * time.Minute, TokenLifetime: time.Hour,
	}, st, zerolog.New(io.Discard), metrics.New())
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)
	// The issuer has to be the address the test actually reaches, or the redirects it builds
	// point at a host that is not listening.
	srv.cfg.Issuer = ts.URL

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	return &harness{T: t, srv: srv, http: ts, client: &http.Client{
		Jar: jar,
		// Stop at the redirect back to the relying party: that is the answer under test, and
		// following it would try to reach a host that does not exist.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), "https://") {
				return http.ErrUseLastResponse
			}

			return nil
		},
	}}
}

// authorize starts a flow and returns the last response, which is either the login form or the
// redirect carrying the code.
func (h *harness) authorize(client, redirect, verifier string, extra url.Values) *http.Response {
	h.Helper()
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id":             {client},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"scope":                 {"openid email groups"},
		"state":                 {"st-" + client},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		q[k] = vs
	}
	res, err := h.client.Get(h.http.URL + pathAuthorize + "?" + q.Encode())
	if err != nil {
		h.Fatal(err)
	}

	return res
}

// signIn completes the login form the response is showing.
func (h *harness) signIn(res *http.Response, login, pass string) *http.Response {
	h.Helper()
	body := read(h.T, res)
	req := between(body, `name="req" value="`, `"`)
	if req == "" {
		h.Fatalf("no sign-in form in:\n%s", body)
	}
	out, err := h.client.PostForm(h.http.URL+pathLogin, url.Values{
		"req": {req}, "login": {login}, "password": {pass},
	})
	if err != nil {
		h.Fatal(err)
	}

	return out
}

// codeFrom reads the authorization code out of the redirect back to the client.
func (h *harness) codeFrom(res *http.Response) string {
	h.Helper()
	loc := res.Header.Get("Location")
	if loc == "" {
		h.Fatalf("no redirect; the response was %d:\n%s", res.StatusCode, read(h.T, res))
	}
	u, err := url.Parse(loc)
	if err != nil {
		h.Fatal(err)
	}
	if e := u.Query().Get("error"); e != "" {
		h.Fatalf("the flow ended in %s: %s", e, u.Query().Get("error_description"))
	}

	return u.Query().Get("code")
}

// exchange trades a code for tokens.
func (h *harness) exchange(client, redirect, code, verifier string) (map[string]any, int) {
	h.Helper()
	res, err := h.client.PostForm(h.http.URL+pathToken, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"client_id":     {client},
		"code_verifier": {verifier},
	})
	if err != nil {
		h.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()

	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		h.Fatal(err)
	}

	return out, res.StatusCode
}

// read returns the body and puts it back, so a test may look at a response and then hand it to a
// helper that looks again.
// decode reads a JSON body, whatever the status.
func decode(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}

	return out
}

func read(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	res.Body = io.NopCloser(bytes.NewReader(b))

	return string(b)
}

func between(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}

	return rest[:j]
}

// payload decodes a JWT's claims without verifying it; the signature has its own test.
func payload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}

	return claims
}
