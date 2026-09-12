package oidc

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// token exchanges an authorization code for tokens.
//
// Public clients only, so there is no client authentication to check and PKCE carries the whole
// proof: the party exchanging the code must present the verifier the challenge was derived from.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.tokenError(w, http.StatusBadRequest, "invalid_request", "malformed form")

		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
	case "client_credentials":
		// A service account asking for a token in its own name. Nobody signed in, so nothing here
		// applies — a different function entirely.
		s.clientCredentials(w, r)

		return
	default:
		s.tokenError(w, http.StatusBadRequest, "unsupported_grant_type",
			"authorization_code and client_credentials are served")

		return
	}

	// Which client is exchanging, and whether it proved it. A confidential client's secret is
	// checked BEFORE the code is spent: a wrong secret must not burn somebody else's code.
	//
	// The ID it returns is the one every later check uses, and that is the point: a client
	// authenticating with Basic sends no client_id field at all, so a comparison against the form
	// would read an empty string and refuse the exchange as somebody else's code.
	clientID, err := s.authenticateClient(r)
	if err != nil {
		s.result("token", "bad-client-secret")
		s.tokenError(w, http.StatusUnauthorized, "invalid_client", err.Error())

		return
	}

	code, ok := s.codes.take(r.Form.Get("code"))
	if !ok {
		s.result("token", "unknown-code")
		s.tokenError(w, http.StatusBadRequest, "invalid_grant", "the code is unknown, expired or already used")

		return
	}
	// Everything the code was issued for must still hold. The redirect is checked because the
	// code was bound to it; the client because a code issued to one client must not be
	// exchangeable by another.
	switch {
	case clientID != code.clientID:
		s.result("token", "wrong-client")
		s.tokenError(w, http.StatusBadRequest, "invalid_grant", "this code was issued to another client")

		return
	case r.Form.Get("redirect_uri") != code.redirect:
		s.result("token", "wrong-redirect")
		s.tokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the one the code was issued for")

		return
	case !verifyPKCE(code.challenge, r.Form.Get("code_verifier")):
		s.result("token", "bad-verifier")
		s.tokenError(w, http.StatusBadRequest, "invalid_grant", "the code verifier does not match the challenge")

		return
	}

	claims, err := s.claims(r.Context(), code.subject)
	if err != nil {
		s.result("token", "directory-error")
		s.tokenError(w, http.StatusInternalServerError, "server_error", "cannot read the account")

		return
	}
	// Re-read and re-checked at every exchange: the directory is the authority, and an account
	// disabled since sign-in must not receive a fresh token from a session that predates it.
	if claims == nil {
		s.result("token", "account-gone")
		s.tokenError(w, http.StatusBadRequest, "invalid_grant", "the account is gone or disabled")

		return
	}

	now := time.Now()
	body := map[string]any{
		"token_type": "Bearer",
		"expires_in": int(s.cfg.TokenLifetime.Seconds()),
		"scope":      "openid profile email groups",
	}

	idToken, err := s.mint(code.clientID, claims, now, code.authTime, code.nonce)
	if err != nil {
		s.tokenError(w, http.StatusInternalServerError, "server_error", "cannot sign the token")

		return
	}
	body["id_token"] = idToken
	// The access token is the same assertion without the nonce, which is an id token's business.
	// One key, one audience: a deployment that identifies its services by URL gets an access
	// token addressed to the same service the id token is.
	access, err := s.mint(code.clientID, claims, now, code.authTime, "")
	if err != nil {
		s.tokenError(w, http.StatusInternalServerError, "server_error", "cannot sign the token")

		return
	}
	body["access_token"] = access

	s.result("token", "ok")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

// authenticateClient checks the secret of a confidential client, and lets a public one through.
//
// Public and confidential is not a setting to get wrong in the lenient direction, so the rule is
// stated from the CLIENT's side rather than the request's: a client configured with a secret must
// present it, however the request was shaped, and one configured without cannot be authenticated
// by a secret it does not have. A request that carries a secret for a public client is refused
// rather than ignored — it means somebody believes in a credential that decides nothing.
func (s *Server) authenticateClient(r *http.Request) (string, error) {
	id := strings.TrimSpace(r.Form.Get("client_id"))
	secret := r.Form.Get("client_secret")
	// HTTP Basic carries the two separated by a colon, so it cannot carry a raw id that CONTAINS
	// one — and a deployment whose client ids are URLs has a colon in every one of them (RFC 7617
	// forbids it in the userid outright). That is exactly why RFC 6749 §2.3.1 says both halves are
	// FORM-URLENCODED before they go into Basic: encoded, a URL-shaped id carries no colon and no
	// slash, and the scheme works for it like for any other.
	//
	// So the decode is not a nicety, it is the other half of the contract. Without it this server
	// advertised client_secret_basic in its discovery document and then refused every client that
	// believed it — a client library picks basic by default when it is offered, so the sign-in of
	// the one confidential client on this stand failed with "unknown client" while its secret was
	// correct and its authorize request was fine.
	//
	// Decoded ALWAYS, not on a guess. "+" means a space in this encoding, so a client that put a
	// raw "+" in Basic instead of %2B is read as having sent a space — that ambiguity is the
	// encoding's, and guessing per value ("decode only if it looks encoded") trades a rare
	// out-of-spec client for a common one that followed the rule and would then fail.
	if name, pass, ok := r.BasicAuth(); ok {
		id, secret = formDecode(name), formDecode(pass)
	}
	client, known := s.client(id)
	if !known {
		return "", errors.New("unknown client")
	}
	switch {
	case client.Secret == "" && secret != "":
		return "", errors.New("this client is public and takes no secret")
	case client.Secret == "":
		return id, nil
	case subtle.ConstantTimeCompare([]byte(client.Secret), []byte(secret)) != 1:
		return "", errors.New("the client secret is wrong")
	}

	return id, nil
}

// formDecode undoes the encoding RFC 6749 §2.3.1 asks a client for, and leaves alone a value that
// was never encoded.
func formDecode(v string) string {
	out, err := url.QueryUnescape(v)
	if err != nil {
		return v // not an encoding after all: judge the value as it arrived
	}
	return out
}

// mint signs one assertion about a subject for one audience.
func (s *Server) mint(audience string, c *subjectClaims, now, authTime time.Time, nonce string) (string, error) {
	claims := map[string]any{
		"iss":       s.cfg.Issuer,
		"sub":       c.Subject,
		"aud":       audience,
		"iat":       now.Unix(),
		"exp":       now.Add(s.cfg.TokenLifetime).Unix(),
		"auth_time": authTime.Unix(),
	}
	if c.Email != "" {
		claims["email"] = c.Email
		claims["email_verified"] = true
	}
	if c.Name != "" {
		claims["name"] = c.Name
	}
	if len(c.Groups) > 0 {
		claims["groups"] = c.Groups
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	return s.sig.sign(claims)
}

func (s *Server) tokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}
