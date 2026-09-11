package oidc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

const servicePassword = "a sufficiently long service password"

// serviceAccounts turns the fixture into one with the grant enabled and two accounts: one in the
// service account group and one that is merely a user.
func serviceAccounts(t *testing.T, h *harness) {
	t.Helper()
	ctx := t.Context()

	if err := h.srv.st.CreateGroup(ctx, &store.Group{Name: "service-accounts", GIDNumber: 5100}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []*store.User{
		{Name: "robot", UIDNumber: 10002, PrimaryGroup: 5000, OtherGroups: []int{5100}, Mail: "robot@example.com"},
		{Name: "bystander", UIDNumber: 10003, PrimaryGroup: 5000, Mail: "bystander@example.com"},
	} {
		if err := h.srv.st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		if err := h.srv.st.SetUserPassword(ctx, u.Name, servicePassword, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	h.srv.cfg.ServiceAccountGroup = "service-accounts"
}

// ask posts a client credentials request with HTTP Basic, the way most clients do it.
func (h *harness) ask(name, secret, resource string) (map[string]any, int) {
	h.Helper()
	form := url.Values{"grant_type": {"client_credentials"}}
	if resource != "" {
		form.Set("resource", resource)
	}
	req, err := http.NewRequest(http.MethodPost, h.http.URL+pathToken, strings.NewReader(form.Encode()))
	if err != nil {
		h.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(name, secret)

	res, err := h.client.Do(req)
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

// A service account asks in its own name and gets a token that says so.
func TestAServiceAccountGetsATokenOfItsOwn(t *testing.T) {
	h := setup(t)
	serviceAccounts(t, h)

	out, status := h.ask("robot", servicePassword, uiClient)
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("no access_token in %v", out)
	}
	// An id token asserts that somebody signed in, and nobody did.
	if _, ok := out["id_token"]; ok {
		t.Error("a client credentials response carries an id_token")
	}

	claims := payload(t, token)
	// The KIND travels with the subject: a consumer must be able to tell a robot from a person
	// without guessing, and a rule written about people must not match a machine.
	if claims["sub"] != "client:robot" {
		t.Errorf("sub = %v, want client:robot", claims["sub"])
	}
	if claims["aud"] != uiClient {
		t.Errorf("aud = %v, want %s", claims["aud"], uiClient)
	}
	groups, _ := claims["groups"].([]any)
	if len(groups) == 0 {
		t.Error("no groups: a service account's rights come from the directory like everybody else's")
	}
}

// The credentials may come either way the RFC allows; refusing one would refuse half the clients.
func TestBothClientAuthenticationMethodsWork(t *testing.T) {
	h := setup(t)
	serviceAccounts(t, h)

	res, err := h.client.PostForm(h.http.URL+pathToken, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"robot"},
		"client_secret": {servicePassword},
		"resource":      {uiClient},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("client_secret_post answered %d: %s", res.StatusCode, read(t, res))
	}
}

// The account is found the same two ways the sign-in form finds it.
func TestAServiceAccountMayBeNamedByMail(t *testing.T) {
	h := setup(t)
	serviceAccounts(t, h)

	if _, status := h.ask("robot@example.com", servicePassword, uiClient); status != http.StatusOK {
		t.Errorf("naming the account by mail answered %d", status)
	}
}

// Everything that must NOT get a token. Each is one refusal with one message: which of them it was
// is exactly what a guesser is trying to learn.
func TestTheGrantRefuses(t *testing.T) {
	for _, tc := range []struct {
		name     string
		account  string
		secret   string
		resource string
		prepare  func(*testing.T, *harness)
		wantCode string
	}{
		{
			name: "an account that is not a service account",
			// The gate: without it every person's password would double as a machine key.
			account: "bystander", secret: servicePassword, resource: uiClient,
			wantCode: "invalid_client",
		},
		{
			name:    "the wrong secret",
			account: "robot", secret: "not the password", resource: uiClient,
			wantCode: "invalid_client",
		},
		{
			name:    "an account that does not exist",
			account: "nobody", secret: servicePassword, resource: uiClient,
			wantCode: "invalid_client",
		},
		{
			name:    "a disabled account",
			account: "robot", secret: servicePassword, resource: uiClient,
			prepare: func(t *testing.T, h *harness) {
				if _, err := h.srv.st.UpdateUser(t.Context(), "robot", func(u *store.User) error {
					u.Disabled = true

					return nil
				}); err != nil {
					t.Fatal(err)
				}
			},
			wantCode: "invalid_client",
		},
		{
			// A token has to say what it is for; one that names nobody is a token for everybody.
			name:    "no audience at all",
			account: "robot", secret: servicePassword, resource: "",
			wantCode: "invalid_target",
		},
		{
			// And the audience must be something this provider serves, or the token is pointed at
			// somebody else's service.
			name:    "an audience this provider does not serve",
			account: "robot", secret: servicePassword, resource: "https://somebody.else",
			wantCode: "invalid_target",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := setup(t)
			serviceAccounts(t, h)
			if tc.prepare != nil {
				tc.prepare(t, h)
			}
			out, status := h.ask(tc.account, tc.secret, tc.resource)
			if status == http.StatusOK {
				t.Fatalf("a token was issued: %v", out)
			}
			if out["error"] != tc.wantCode {
				t.Errorf("error = %v, want %s", out["error"], tc.wantCode)
			}
			if d, _ := out["error_description"].(string); strings.Contains(strings.ToLower(d), "disabled") ||
				strings.Contains(strings.ToLower(d), "no such") {
				t.Errorf("the refusal says which half was wrong: %q", d)
			}
		})
	}
}

// With no group configured the grant is off, and discovery says so rather than letting a client
// find out at the endpoint.
func TestWithNoGroupTheGrantIsOffAndUnadvertised(t *testing.T) {
	h := setup(t) // the fixture configures no service account group

	out, status := h.ask("robot", servicePassword, uiClient)
	if status == http.StatusOK {
		t.Fatalf("a token was issued with the grant switched off: %v", out)
	}
	if out["error"] != "unsupported_grant_type" {
		t.Errorf("error = %v, want unsupported_grant_type", out["error"])
	}

	res, err := h.client.Get(h.http.URL + pathDiscovery)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(read(t, res)), &doc); err != nil {
		t.Fatal(err)
	}
	for _, g := range doc["grant_types_supported"].([]any) {
		if g == "client_credentials" {
			t.Error("discovery advertises a grant that is switched off")
		}
	}
}

// And with one configured, discovery advertises the grant and the ways to authenticate for it.
func TestDiscoveryAdvertisesTheGrantWhenItIsOn(t *testing.T) {
	h := setup(t)
	serviceAccounts(t, h)

	res, err := h.client.Get(h.http.URL + pathDiscovery)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(read(t, res)), &doc); err != nil {
		t.Fatal(err)
	}
	has := func(field, want string) bool {
		for _, v := range doc[field].([]any) {
			if v == want {
				return true
			}
		}

		return false
	}
	if !has("grant_types_supported", "client_credentials") {
		t.Error("grant_types_supported does not mention client_credentials")
	}
	for _, m := range []string{"client_secret_basic", "client_secret_post"} {
		if !has("token_endpoint_auth_methods_supported", m) {
			t.Errorf("token_endpoint_auth_methods_supported does not mention %s", m)
		}
	}
}

// Losing the group takes the rights away at the next request, not at the next restart: membership
// is read fresh with the rest of the account.
func TestRemovalFromTheGroupTakesEffectAtOnce(t *testing.T) {
	h := setup(t)
	serviceAccounts(t, h)

	if _, status := h.ask("robot", servicePassword, uiClient); status != http.StatusOK {
		t.Fatal("the service account could not get a token to begin with")
	}
	if _, err := h.srv.st.UpdateUser(t.Context(), "robot", func(u *store.User) error {
		u.OtherGroups = nil

		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if out, status := h.ask("robot", servicePassword, uiClient); status == http.StatusOK {
		t.Fatalf("a token was issued after the account left the group: %v", out)
	}
}
