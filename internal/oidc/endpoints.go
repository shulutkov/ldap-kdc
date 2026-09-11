package oidc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// discovery is the document every client reads to find the rest. Serving it is what lets a relying
// party be configured with one URL.
func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                s.cfg.Issuer,
		"authorization_endpoint":                s.cfg.Issuer + pathAuthorize,
		"token_endpoint":                        s.cfg.Issuer + pathToken,
		"userinfo_endpoint":                     s.cfg.Issuer + pathUserInfo,
		"jwks_uri":                              s.cfg.Issuer + pathKeys,
		"end_session_endpoint":                  s.cfg.Issuer + pathEndAuth,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 s.grants(),
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce",
			"email", "email_verified", "name", "groups",
		},
		"token_endpoint_auth_methods_supported": s.clientAuth(),
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// grants and clientAuth describe what this provider actually does, which depends on whether a
// service account group is configured: advertising a grant that is switched off sends a client to
// an endpoint that will refuse it, and discovery is supposed to spare them that.
func (s *Server) grants() []string {
	if s.cfg.ServiceAccountGroup == "" {
		return []string{"authorization_code"}
	}

	return []string{"authorization_code", "client_credentials"}
}

func (s *Server) clientAuth() []string {
	if s.cfg.ServiceAccountGroup == "" {
		return []string{"none"}
	}

	return []string{"none", "client_secret_basic", "client_secret_post"}
}

// keys publishes the public half of the signing key.
func (s *Server) keys(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.sig.jwks()) }

// userinfo answers with the same claims the token carries, for a client that would rather ask than
// read the token. The access token is this provider's own, so it is verified the only way that
// matters here: it must be one we signed, unexpired, and about an account that still exists.
func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if raw == "" || raw == r.Header.Get("Authorization") {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "a bearer token is required", http.StatusUnauthorized)

		return
	}
	sub, err := s.verify(raw)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, err.Error(), http.StatusUnauthorized)

		return
	}
	claims, err := s.claims(r.Context(), sub)
	if err != nil || claims == nil {
		http.Error(w, "the account is gone or disabled", http.StatusUnauthorized)

		return
	}

	out := map[string]any{"sub": claims.Subject}
	if claims.Email != "" {
		out["email"] = claims.Email
		out["email_verified"] = true
	}
	if claims.Name != "" {
		out["name"] = claims.Name
	}
	if len(claims.Groups) > 0 {
		out["groups"] = claims.Groups
	}
	writeJSON(w, out)
}

// endSession signs the person out of the PROVIDER, which is what makes a logout button mean
// something: without it, a relying party can only forget its own token, and the next sign-in
// completes silently against a session nobody ended.
//
// The redirect back is only followed when the client registered it. An unregistered one is
// ignored, not obeyed: this endpoint takes no credential, so anybody can link to it.
func (s *Server) endSession(w http.ResponseWriter, r *http.Request) {
	s.sessions.end(r)
	clearCookie(w, s.secure)
	s.result("end-session", "ok")

	q := r.URL.Query()
	target := q.Get("post_logout_redirect_uri")
	if target == "" {
		writeJSON(w, map[string]string{"status": "signed out"})

		return
	}
	for _, c := range s.cfg.Clients {
		if !registered(c.PostLogoutRedirect, target) {
			continue
		}
		u, err := url.Parse(target)
		if err != nil {
			break
		}
		if state := q.Get("state"); state != "" {
			p := u.Query()
			p.Set("state", state)
			u.RawQuery = p.Encode()
		}
		http.Redirect(w, r, u.String(), http.StatusSeeOther)

		return
	}

	s.log.Info().Str("uri", target).Msg("post_logout_redirect_uri is not registered; not following it")
	writeJSON(w, map[string]string{"status": "signed out"})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
