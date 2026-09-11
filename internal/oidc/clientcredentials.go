package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// clientCredentials issues a token to a SERVICE ACCOUNT — an account in this directory presenting
// its own name and password, with no person involved (RFC 6749 §4.4).
//
// The whole design is "there is no second credential store". A service account is an account here:
// the client id is its name (or its mail address, as on the sign-in form), the client secret is its
// password, and the decision is store.Authenticate — the same one the LDAP bind and the sign-in
// form make. A disabled account gets nothing; an application password works, which is what
// application passwords are FOR, since a machine has nowhere to type a one-time code.
//
// Three things are deliberately narrow.
//
// Membership is the switch. Only accounts in the configured group may do this, and with no group
// configured the grant is refused outright — otherwise every person's password would quietly double
// as a machine key, which is not a thing to arrive at by default.
//
// The audience is required and checked. A token has to say what it is FOR, and the answer must be a
// resource this provider actually serves — one of the registered client ids. A token minted for an
// audience nobody here knows is a token pointed at somebody else's service.
//
// The subject carries its KIND: `client:<name>`, not the account's mail. A consumer that reads
// subjects can then tell a robot from a person without guessing, and a rule written about people
// does not match a machine one string away.
func (s *Server) clientCredentials(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ServiceAccountGroup == "" {
		s.result("client-credentials", "disabled")
		s.tokenError(w, http.StatusBadRequest, "unsupported_grant_type",
			"this provider issues no tokens to service accounts: no service account group is configured")

		return
	}

	name, secret, ok := clientCredentialsOf(r)
	if !ok {
		s.result("client-credentials", "no-credential")
		w.Header().Set("WWW-Authenticate", `Basic realm="service accounts"`)
		s.tokenError(w, http.StatusUnauthorized, "invalid_client",
			"present the account and its password, by HTTP Basic or as client_id and client_secret")

		return
	}

	audience := strings.TrimSpace(r.Form.Get("resource"))
	if audience == "" {
		audience = strings.TrimSpace(r.Form.Get("audience"))
	}
	if audience == "" {
		s.result("client-credentials", "no-audience")
		s.tokenError(w, http.StatusBadRequest, "invalid_target",
			"name the resource this token is for, as resource=<uri> (RFC 8707)")

		return
	}
	if !slices.ContainsFunc(s.cfg.Clients, func(c Client) bool { return c.ID == audience }) {
		s.result("client-credentials", "unknown-audience")
		s.tokenError(w, http.StatusBadRequest, "invalid_target",
			"this provider serves no resource by that name")

		return
	}

	claims, outcome := s.serviceAccount(r.Context(), name, secret)
	s.result("client-credentials", string(outcome))
	if claims == nil {
		// One refusal for every reason — no such account, wrong password, not a service account,
		// disabled. Which of them it was is exactly what a guesser is trying to learn.
		s.log.Info().Str("client", name).Str("outcome", string(outcome)).Str("src", clientIP(r)).
			Msg("service account refused")
		s.tokenError(w, http.StatusUnauthorized, "invalid_client", "the account or the secret is wrong")

		return
	}

	now := time.Now()
	// No id_token: an id token asserts that somebody SIGNED IN, and nobody did. No session cookie
	// either — a machine has no browser to carry one.
	token, err := s.mint(audience, claims, now, now, "")
	if err != nil {
		s.tokenError(w, http.StatusInternalServerError, "server_error", "cannot sign the token")

		return
	}
	s.log.Info().Str("client", claims.Subject).Str("audience", audience).Str("src", clientIP(r)).
		Msg("token issued to a service account")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(s.cfg.TokenLifetime.Seconds()),
	})
}

// serviceAccount resolves and authenticates the account, and reports why not when it will not do.
// A nil result is a refusal whatever the outcome says; the outcome is for the log and the counter,
// never for the answer.
func (s *Server) serviceAccount(ctx context.Context, name, secret string) (*subjectClaims, store.Outcome) {
	u := s.lookup(ctx, name)
	if u == nil {
		return nil, store.OutcomeInvalid
	}
	if outcome := store.Authenticate(u, secret); !outcome.Granted() {
		return nil, outcome
	}

	claims, err := s.claims(ctx, u.Name)
	if err != nil || claims == nil {
		return nil, store.OutcomeInvalid
	}
	// The gate: membership, read fresh with everything else, so removing an account from the group
	// stops it at the next request rather than at the next restart.
	if !slices.Contains(claims.Groups, s.cfg.ServiceAccountGroup) {
		return nil, "not-a-service-account"
	}
	// The kind travels with the subject. Everything else about the account stays as it is.
	claims.Subject = "client:" + claims.Subject

	return claims, store.OutcomeOK
}

// clientCredentialsOf reads the client's credentials from wherever the client put them: HTTP Basic
// (client_secret_basic) or the form (client_secret_post). Both are in RFC 6749, clients differ on
// which they use, and refusing one of them would be refusing half the clients for no reason.
func clientCredentialsOf(r *http.Request) (name, secret string, ok bool) {
	if name, secret, ok = r.BasicAuth(); ok && name != "" {
		return name, secret, true
	}
	name = strings.TrimSpace(r.Form.Get("client_id"))
	secret = r.Form.Get("client_secret")

	return name, secret, name != "" && secret != ""
}
