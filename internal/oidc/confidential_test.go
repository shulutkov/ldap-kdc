package oidc

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const clientSecret = "a secret only a server can keep"

// exchangeWith trades a code for tokens, presenting the client secret however the caller asked.
func (h *harness) exchangeWith(code, verifier string, basic bool, secret string) (map[string]any, int) {
	h.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {theUI},
		"code_verifier": {verifier},
	}
	if !basic {
		form.Set("client_id", uiClient)
		if secret != "" {
			form.Set("client_secret", secret)
		}
	}
	req, err := http.NewRequest(http.MethodPost, h.http.URL+pathToken, strings.NewReader(form.Encode()))
	if err != nil {
		h.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(uiClient, secret)
	}
	res, err := h.client.Do(req)
	if err != nil {
		h.Fatal(err)
	}

	return decode(h.T, res), res.StatusCode
}

// exchangeBasic trades a code for tokens with the credentials in an Authorization header, exactly
// as the caller spelled them — which is the point: how they are spelled is what this tests.
func (h *harness) exchangeBasic(code, verifier, id, secret string) (map[string]any, int) {
	h.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {theUI},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequest(http.MethodPost, h.http.URL+pathToken, strings.NewReader(form.Encode()))
	if err != nil {
		h.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(id+":"+secret)))
	res, err := h.client.Do(req)
	if err != nil {
		h.Fatal(err)
	}
	return decode(h.T, res), res.StatusCode
}

// confidential turns the fixture's first client into one that keeps a secret.
func confidential(h *harness) {
	h.srv.cfg.Clients[0].Secret = clientSecret
}

func TestAConfidentialClientMustPresentItsSecret(t *testing.T) {
	const verifier = "verifier-one-that-is-long-enough-for-pkce"

	// Basic cannot carry an id with a colon in it, and every URL has one — so a deployment that
	// names its clients by URL uses the form. This is not a limitation of the provider but of the
	// scheme: RFC 7617 forbids a colon in the userid, and everything before the first one is read
	// as the id.
	t.Run("with the secret, in the form, for a URL-shaped id", func(t *testing.T) {
		h := setup(t)
		confidential(h)
		code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))
		out, status := h.exchangeWith(code, verifier, false, clientSecret)
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, out)
		}
	})

	// And in Basic, which is what a client library reaches for first when the discovery document
	// offers it. RFC 6749 §2.3.1 has both halves form-urlencoded before they go in, which is
	// precisely what lets a URL-shaped id — a colon in every one of them — be carried at all.
	// Without the matching decode on this side, the provider advertised the method and then
	// refused every client that believed it, with "unknown client" while the secret was correct.
	t.Run("with the secret, in Basic, encoded as the RFC asks", func(t *testing.T) {
		h := setup(t)
		confidential(h)
		code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))
		out, status := h.exchangeBasic(code, verifier, url.QueryEscape(uiClient), url.QueryEscape(clientSecret))
		if status != http.StatusOK {
			t.Fatalf("client_secret_basic answered %d: %v", status, out)
		}
	})

	// A secret with nothing to encode in it passes through the decode unchanged, so a client that
	// did not encode is served too — as long as the value holds no "+" or "%", which in this
	// encoding mean something else and cannot be told apart from themselves.
	t.Run("with a plain secret in Basic", func(t *testing.T) {
		h := setup(t)
		confidential(h)
		h.srv.cfg.Clients[0].Secret = "plainsecret"
		code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))
		out, status := h.exchangeBasic(code, verifier, url.QueryEscape(uiClient), "plainsecret")
		if status != http.StatusOK {
			t.Fatalf("a secret sent unencoded answered %d: %v", status, out)
		}
	})

	t.Run("with the secret, in the form", func(t *testing.T) {
		h := setup(t)
		confidential(h)
		code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))
		if _, status := h.exchangeWith(code, verifier, false, clientSecret); status != http.StatusOK {
			t.Fatalf("client_secret_post answered %d", status)
		}
	})

	t.Run("without it", func(t *testing.T) {
		h := setup(t)
		confidential(h)
		code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))
		out, status := h.exchangeWith(code, verifier, false, "")
		if status == http.StatusOK {
			t.Fatalf("a confidential client got a token with no secret: %v", out)
		}
		if out["error"] != "invalid_client" {
			t.Errorf("error = %v, want invalid_client", out["error"])
		}
	})

	t.Run("with the wrong one", func(t *testing.T) {
		h := setup(t)
		confidential(h)
		code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))
		if _, status := h.exchangeWith(code, verifier, false, "not it"); status == http.StatusOK {
			t.Fatal("the wrong secret bought a token")
		}
	})

	// The secret is checked BEFORE the code is spent, or a wrong guess would burn the code of the
	// person who legitimately holds it.
	t.Run("a wrong secret does not spend the code", func(t *testing.T) {
		h := setup(t)
		confidential(h)
		code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))
		if _, status := h.exchangeWith(code, verifier, false, "not it"); status == http.StatusOK {
			t.Fatal("the wrong secret bought a token")
		}
		if _, status := h.exchangeWith(code, verifier, false, clientSecret); status != http.StatusOK {
			t.Error("the code was spent by the failed attempt")
		}
	})

	// PKCE is not replaced by the secret: the two answer different questions, and a confidential
	// client that got away without a verifier would be one intercepted redirect from a token.
	t.Run("the secret does not excuse a bad verifier", func(t *testing.T) {
		h := setup(t)
		confidential(h)
		code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))
		if _, status := h.exchangeWith(code, "a-completely-different-verifier", false, clientSecret); status == http.StatusOK {
			t.Fatal("a wrong verifier bought a token from a confidential client")
		}
	})
}

// A page cannot keep a secret, so a request that brings one for a public client is refused rather
// than ignored: somebody believes in a credential that decides nothing.
func TestAPublicClientIsRefusedASecret(t *testing.T) {
	h := setup(t)
	const verifier = "verifier-one-that-is-long-enough-for-pkce"
	code := h.codeFrom(h.signIn(h.authorize(uiClient, theUI, verifier, nil), "alice", password))

	out, status := h.exchangeWith(code, verifier, false, "a secret nobody configured")
	if status == http.StatusOK {
		t.Fatalf("a secret was accepted for a public client: %v", out)
	}
	if out["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", out["error"])
	}
}
