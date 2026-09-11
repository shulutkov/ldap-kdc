package oidc

import (
	"encoding/json"
	"net/http"
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
	case r.Form.Get("client_id") != code.clientID:
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
