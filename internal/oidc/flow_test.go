package oidc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// THE test: one sign-in, and the SECOND application gets its code with no form in between. That is
// the whole reason this provider exists — a provider without a browser session makes every
// application ask for a password again, and nothing on the application's side can mend it.
func TestOneSignInServesEveryClient(t *testing.T) {
	h := setup(t)

	// The first application: nobody is signed in, so the form is shown.
	res := h.authorize(uiClient, theUI, "verifier-one-that-is-long-enough-for-pkce", nil)
	body := read(t, res)
	if !strings.Contains(body, `name="password"`) {
		t.Fatalf("expected a sign-in form first, got:\n%s", body)
	}

	back := h.signIn(res, "alice", password)
	first := h.codeFrom(back)
	if first == "" {
		t.Fatal("no code after signing in")
	}

	// The second application, same browser. No form: the session decides.
	res2 := h.authorize(cpClient, theCP, "verifier-two-that-is-long-enough-for-pkce", nil)
	if res2.StatusCode == http.StatusOK {
		t.Fatalf("the second application was shown a form:\n%s", read(t, res2))
	}
	if code := h.codeFrom(res2); code == "" {
		t.Fatal("the second application got no code")
	}
}

// The tokens have to say what the relying parties verify: this provider as the issuer, the client
// as the audience, and the account's own claims.
func TestTheTokenSaysWhoItIsForAndWhoItIsAbout(t *testing.T) {
	h := setup(t)
	const verifier = "verifier-one-that-is-long-enough-for-pkce"

	res := h.authorize(uiClient, theUI, verifier, nil)
	code := h.codeFrom(h.signIn(res, "alice", password))

	out, status := h.exchange(uiClient, theUI, code, verifier)
	if status != http.StatusOK {
		t.Fatalf("exchange answered %d: %v", status, out)
	}
	idToken, _ := out["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token in %v", out)
	}
	claims := payload(t, idToken)

	for field, want := range map[string]any{
		"iss":   h.srv.cfg.Issuer,
		"aud":   uiClient,
		"sub":   "alice",
		"email": "alice@example.com",
		"name":  "Alice Example",
	} {
		if got := claims[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
	groups, _ := claims["groups"].([]any)
	if len(groups) != 1 || groups[0] != "owners" {
		t.Errorf("groups = %v, want [owners]", claims["groups"])
	}
	if _, ok := claims["auth_time"]; !ok {
		t.Error("no auth_time: a relying party cannot tell how old the sign-in is")
	}

	// And the signature verifies against the key JWKS publishes — checked through the provider's
	// own verifier, which is what /userinfo uses.
	if sub, err := h.srv.verify(idToken); err != nil || sub != "alice" {
		t.Errorf("verify = %q, %v", sub, err)
	}
}

// The code is the credential the exchange rests on, so every promise made when it was issued has
// to still hold when it is spent.
func TestTheCodeIsBoundToItsRequest(t *testing.T) {
	const verifier = "verifier-one-that-is-long-enough-for-pkce"

	t.Run("a wrong verifier is refused", func(t *testing.T) {
		h := setup(t)
		code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))
		out, status := h.exchange(uiClient, theUI, code, "some-other-verifier-entirely-here")
		if status == http.StatusOK {
			t.Fatalf("a wrong verifier bought a token: %v", out)
		}
		if out["error"] != "invalid_grant" {
			t.Errorf("error = %v, want invalid_grant", out["error"])
		}
	})

	t.Run("another client cannot spend it", func(t *testing.T) {
		h := setup(t)
		code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))
		if out, status := h.exchange(cpClient, theUI, code, verifier); status == http.StatusOK {
			t.Fatalf("another client spent the code: %v", out)
		}
	})

	t.Run("it is good once", func(t *testing.T) {
		h := setup(t)
		code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))
		if _, status := h.exchange(uiClient, theUI, code, verifier); status != http.StatusOK {
			t.Fatal("the first exchange failed")
		}
		if out, status := h.exchange(uiClient, theUI, code, verifier); status == http.StatusOK {
			t.Fatalf("the code was spent twice: %v", out)
		}
	})
}

// Where the answer would go is the one thing that cannot be taken from the request: an unknown
// client or an unregistered redirect must be shown to the PERSON, never sent onward.
func TestAnUntrustedDestinationIsNotRedirectedTo(t *testing.T) {
	h := setup(t)

	for _, tc := range []struct{ name, client, redirect string }{
		{"unknown client", "https://somebody.else", theUI},
		{"unregistered redirect", uiClient, "https://attacker.example/collect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := h.authorize(tc.client, tc.redirect, "verifier-one-that-is-long-enough-for-pkce", nil)
			if res.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", res.StatusCode)
			}
			if loc := res.Header.Get("Location"); loc != "" {
				t.Errorf("it redirected to %q", loc)
			}
			_ = read(t, res)
		})
	}
}

// PKCE is not optional here: without it an intercepted code is a token.
func TestPKCEIsRequired(t *testing.T) {
	h := setup(t)
	res, err := h.client.Get(h.http.URL + pathAuthorize + "?" + url.Values{
		"client_id": {uiClient}, "redirect_uri": {theUI}, "response_type": {"code"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	loc := res.Header.Get("Location")
	if loc == "" || !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("a request with no challenge was not refused: %d %q", res.StatusCode, loc)
	}
	_ = read(t, res)
}

// prompt is how a relying party overrides the session in either direction.
func TestPrompt(t *testing.T) {
	const verifier = "verifier-one-that-is-long-enough-for-pkce"

	t.Run("login asks again even with a session", func(t *testing.T) {
		h := setup(t)
		h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password)

		res := h.authorize(cpClient, theCP, verifier, url.Values{"prompt": {"login"}})
		if !strings.Contains(read(t, res), `name="password"`) {
			t.Error("prompt=login did not ask again")
		}
	})

	t.Run("none refuses rather than asking", func(t *testing.T) {
		h := setup(t)
		res := h.authorize(uiClient, theUI, verifier, url.Values{"prompt": {"none"}})
		loc := res.Header.Get("Location")
		if !strings.Contains(loc, "error=login_required") {
			t.Errorf("prompt=none with no session gave %q", loc)
		}
		_ = read(t, res)
	})

	t.Run("none succeeds silently once there is a session", func(t *testing.T) {
		h := setup(t)
		h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password)

		res := h.authorize(cpClient, theCP, verifier, url.Values{"prompt": {"none"}})
		if code := h.codeFrom(res); code == "" {
			t.Error("prompt=none with a session got no code")
		}
	})
}

// A logout button that only clears the application's own token is a logout button that does
// nothing: the next sign-in completes silently against a session nobody ended.
func TestEndSessionReallyEndsIt(t *testing.T) {
	h := setup(t)
	const verifier = "verifier-one-that-is-long-enough-for-pkce"
	h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password)

	res, err := h.client.Get(h.http.URL + pathEndAuth + "?" + url.Values{
		"post_logout_redirect_uri": {theUI},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, theUI) {
		t.Errorf("it did not return to the registered address: %q", loc)
	}
	_ = read(t, res)

	if again := h.authorize(uiClient, theUI, verifier, nil); !strings.Contains(read(t, again), `name="password"`) {
		t.Error("the session survived the logout")
	}
}

// An unregistered address is not somewhere to send a browser on a request that carries no
// credential at all.
func TestEndSessionIgnoresAnUnregisteredReturn(t *testing.T) {
	h := setup(t)
	res, err := h.client.Get(h.http.URL + pathEndAuth + "?" + url.Values{
		"post_logout_redirect_uri": {"https://attacker.example/"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if loc := res.Header.Get("Location"); loc != "" {
		t.Errorf("it followed an unregistered address: %q", loc)
	}
	_ = read(t, res)
}

// A refusal must not say which half was wrong: that is what a guesser is trying to learn.
func TestARefusalSaysNothingUseful(t *testing.T) {
	h := setup(t)
	const verifier = "verifier-one-that-is-long-enough-for-pkce"

	for _, tc := range []struct{ name, login, pass string }{
		{"wrong password", "alice", "not the password"},
		{"no such account", "nobody", password},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := read(t, h.signIn(h.authorize(uiClient, theUI, verifier, nil), tc.login, tc.pass))
			if !strings.Contains(body, "Incorrect login or password.") {
				t.Errorf("unexpected page:\n%s", body)
			}
			for _, leak := range []string{"disabled", "no such", "unknown account"} {
				if strings.Contains(strings.ToLower(body), leak) {
					t.Errorf("the refusal mentions %q", leak)
				}
			}
		})
	}
}

// A person signs in with the address they know themselves by, not only the account name.
func TestSigningInByMailAddress(t *testing.T) {
	h := setup(t)
	const verifier = "verifier-one-that-is-long-enough-for-pkce"

	code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice@example.com", password))
	if code == "" {
		t.Fatal("no code after signing in by mail address")
	}
}

// Discovery is how a relying party is configured with one URL, so what it advertises has to be
// what this provider actually does.
func TestDiscoveryDescribesThisProvider(t *testing.T) {
	h := setup(t)

	res, err := h.client.Get(h.http.URL + pathDiscovery)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(read(t, res)), &doc); err != nil {
		t.Fatal(err)
	}

	for field, want := range map[string]string{
		"issuer":                 h.srv.cfg.Issuer,
		"authorization_endpoint": h.srv.cfg.Issuer + pathAuthorize,
		"token_endpoint":         h.srv.cfg.Issuer + pathToken,
		"jwks_uri":               h.srv.cfg.Issuer + pathKeys,
		"end_session_endpoint":   h.srv.cfg.Issuer + pathEndAuth,
	} {
		if doc[field] != want {
			t.Errorf("%s = %v, want %v", field, doc[field], want)
		}
	}
	methods, _ := doc["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, want [S256]", doc["code_challenge_methods_supported"])
	}

	// And the keys are there, under the id the tokens are signed with.
	keys, err := h.client.Get(h.http.URL + pathKeys)
	if err != nil {
		t.Fatal(err)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal([]byte(read(t, keys)), &jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0]["kid"] != h.srv.sig.kid || jwks.Keys[0]["alg"] != "ES256" {
		t.Errorf("jwks = %v", jwks.Keys)
	}
}

// A single-page application never shares an origin with its provider, so it can read none of this
// without being allowed to — and an origin nobody allowed must not be.
func TestCORSIsAllowedOnlyForConfiguredOrigins(t *testing.T) {
	h := setup(t)

	for _, tc := range []struct {
		origin string
		want   string
	}{
		{"https://gitkeep.example", "https://gitkeep.example"},
		{"https://attacker.example", ""},
	} {
		req, _ := http.NewRequest(http.MethodGet, h.http.URL+pathDiscovery, nil)
		req.Header.Set("Origin", tc.origin)
		res, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Header.Get("Access-Control-Allow-Origin"); got != tc.want {
			t.Errorf("origin %s: Access-Control-Allow-Origin = %q, want %q", tc.origin, got, tc.want)
		}
		_ = read(t, res)
	}
}

// The directory is the authority at every step, not only at sign-in: an account switched off after
// somebody signed in must not be able to spend the code that session produced.
func TestAnAccountDisabledAfterSignInGetsNoToken(t *testing.T) {
	h := setup(t)
	const verifier = "verifier-one-that-is-long-enough-for-pkce"

	code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))

	if _, err := h.srv.st.UpdateUser(t.Context(), "alice", func(u *store.User) error {
		u.Disabled = true

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	out, status := h.exchange(uiClient, theUI, code, verifier)
	if status == http.StatusOK {
		t.Fatalf("a disabled account was issued a token: %v", out)
	}
}
