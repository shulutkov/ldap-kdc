package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/x/identity"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// Who may use this API, and how they prove it.
//
// A directory administrator — an account that may write the whole directory, which is the rule
// store.IsDirectoryAdmin states for every door — or an automation holding the configured management
// token. Nobody else, and never anonymously: an interface that can reset any account's password is
// not one to leave open on the assumption that nobody else can reach its port.
//
// A person proves it once, with a password or with a Kerberos ticket through SPNEGO, and receives a
// short-lived session token. The token is checked against the directory as it is NOW on every
// request, so an administrator who is disabled or loses the capability loses the console at the next
// click rather than when the token runs out.

const (
	// metaSigningKey is where the sessions' signing key lives. It is not the OIDC provider's key:
	// see package jws for why the two never share one.
	metaSigningKey = "api_signing_key"

	sessionIssuer   = "ldap-kdc/api"
	sessionAudience = "ldap-kdc/admin"

	// defaultSessionLifetime is short on purpose: the session opens every account's password.
	defaultSessionLifetime = time.Hour
)

// How a caller authenticated.
const (
	methodToken    = "token"
	methodPassword = "password"
	methodKerberos = "kerberos"
)

// caller is who a request is being served for.
type caller struct {
	Subject string
	Method  string
	// Expires is when a session ends; zero for the management token, which does not.
	Expires time.Time
}

type callerKey struct{}

func callerFrom(r *http.Request) *caller {
	c, _ := r.Context().Value(callerKey{}).(*caller)

	return c
}

// authenticate admits a request carrying the management token or a valid administrator's session.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || len(presented) == 0 {
			challenge(w, "sign in, or present the management token")

			return
		}

		var c *caller

		// A constant time comparison keeps the check from leaking the token's prefix through how
		// long it takes to fail.
		if len(s.cfg.Token) > 0 && subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.Token)) == 1 {
			c = &caller{Subject: "management token", Method: methodToken}
		} else {
			session, err := s.session(r.Context(), presented)
			if err != nil {
				s.log.Info().Err(err).Str("src", clientIP(r)).Msg("session refused")
				challenge(w, "the session is not valid; sign in again")

				return
			}
			c = session
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
	})
}

func challenge(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="ldap-kdc"`)
	writeError(w, http.StatusUnauthorized, "%s", message)
}

// sessionClaims is what a session token says.
type sessionClaims struct {
	Iss string   `json:"iss"`
	Aud string   `json:"aud"`
	Sub string   `json:"sub"`
	Exp int64    `json:"exp"`
	Amr []string `json:"amr"`
}

// session verifies a session token and re-checks, against the directory, that its subject still
// administers it.
func (s *Server) session(ctx context.Context, token string) (*caller, error) {
	var claims sessionClaims
	if err := s.sig.Verify(token, &claims); err != nil {
		return nil, err
	}

	switch {
	case claims.Iss != sessionIssuer:
		return nil, errors.New("issued by somebody else")
	case claims.Aud != sessionAudience:
		return nil, errors.New("not a session for this API")
	case claims.Exp == 0 || !timeNow().Before(time.Unix(claims.Exp, 0)):
		return nil, errors.New("expired")
	case len(claims.Sub) == 0:
		return nil, errors.New("no subject")
	}

	u, err := s.st.GetUser(ctx, claims.Sub)
	if err != nil {
		return nil, fmt.Errorf("account %s: %w", claims.Sub, err)
	}

	admin, err := s.st.IsDirectoryAdmin(ctx, u, s.cfg.BaseDN)
	if err != nil {
		return nil, err
	}
	if !admin {
		return nil, fmt.Errorf("%s no longer administers the directory", u.Name)
	}

	method := methodPassword
	if len(claims.Amr) > 0 {
		method = claims.Amr[0]
	}

	return &caller{Subject: u.Name, Method: method, Expires: time.Unix(claims.Exp, 0).UTC()}, nil
}

// loginRequest is a sign-in with a password.
type loginRequest struct {
	Login    string `json:"login" required:"true" description:"An account name or its mail address." example:"admin"`
	Password string `json:"password" required:"true" format:"password" description:"The account's own password, with the one-time code appended where the account has one — as for an LDAP bind."`
}

// sessionBody answers a successful sign-in.
type sessionBody struct {
	Token     string    `json:"token" description:"Present it as a bearer on every request until it expires."`
	Subject   string    `json:"subject" example:"admin"`
	Method    string    `json:"method" enum:"password,kerberos"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// whoAmIBody is who the API takes the caller to be.
type whoAmIBody struct {
	Subject   string     `json:"subject" example:"admin"`
	Method    string     `json:"method" enum:"token,password,kerberos"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// handleLogin signs an administrator in with a password.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	src := clientIP(r)

	// The limiter is the LDAP front end's: a guesser blocked from binding is blocked here too.
	if s.cfg.Limiter.Blocked(src) {
		writeError(w, http.StatusTooManyRequests, "too many failed sign-ins from this address; wait and try again")

		return
	}

	var req loginRequest
	if !decode(w, r, &req) {
		return
	}

	outcome := store.OutcomeInvalid

	u, err := s.st.UserByLogin(r.Context(), req.Login)
	switch {
	case err == nil:
		outcome = store.Authenticate(u, req.Password)
	case !errors.Is(err, store.ErrNotFound):
		writeStoreError(w, err)

		return
	}

	// An application password is refused even though it authenticates a bind. It exists for a
	// program that cannot be handed a one-time code, and accepting it here would let the console be
	// opened with a credential that skips the account's second factor.
	if outcome != store.OutcomeOK {
		s.cfg.Limiter.NoteFailure(src)
		s.log.Info().Str("login", req.Login).Str("outcome", string(outcome)).Str("src", src).
			Msg("console sign-in refused")
		// One message for every refusal. Which of "no such account", "wrong password" and
		// "disabled" it was is exactly what a guesser is trying to learn.
		writeError(w, http.StatusUnauthorized, "incorrect login or password")

		return
	}

	s.cfg.Limiter.NoteSuccess(src)
	s.admit(w, r, u, methodPassword)
}

// handleNegotiate signs an administrator in with the Kerberos ticket their browser already holds.
//
// A browser configured to trust this host answers the Negotiate challenge by itself, so the person
// types nothing; one that is not configured simply receives the challenge and the page falls back to
// the password form.
func (s *Server) handleNegotiate(w http.ResponseWriter, r *http.Request) {
	if len(s.spn.Components) == 0 {
		writeError(w, http.StatusNotFound, "Kerberos sign-in is not configured on this service")

		return
	}

	kt, err := s.keytab(r.Context())
	if err != nil {
		s.log.Error().Err(err).Str("spn", s.spn.String()).Msg("cannot build the keytab for Kerberos sign-in")
		writeError(w, http.StatusServiceUnavailable, "Kerberos sign-in is unavailable")

		return
	}

	spnego.SPNEGOKRB5Authenticate(http.HandlerFunc(s.negotiated), kt,
		service.KeytabPrincipal(s.spn.Principal()),
		// The PAC is not needed: who the account is, and what it may do, is read from the
		// directory this service is, not from what a ticket says about it.
		service.DecodePAC(false),
	).ServeHTTP(w, r)
}

// negotiated runs once SPNEGO has verified the ticket.
func (s *Server) negotiated(w http.ResponseWriter, r *http.Request) {
	id := identity.FromHTTPRequestContext(r)
	if id == nil || !id.Authenticated() {
		writeError(w, http.StatusUnauthorized, "no Kerberos identity was established")

		return
	}

	// A trusted realm's KDC can hand its own users a ticket for this service through a referral.
	// Its accounts are not this directory's, however their names read, so only this realm's
	// tickets sign in here.
	if !strings.EqualFold(id.Domain(), s.cfg.Realm) {
		s.log.Info().Str("principal", id.UserName()+"@"+id.Domain()).Str("src", clientIP(r)).
			Msg("console sign-in refused: a ticket from another realm")
		writeError(w, http.StatusForbidden, "a ticket from realm %s does not sign in to this directory", id.Domain())

		return
	}

	name, err := krbkeys.ParseName(id.UserName(), s.cfg.Realm)
	if err != nil {
		writeError(w, http.StatusForbidden, "%s", err)

		return
	}

	// The principal is looked up rather than its name taken for an account name: a ticket may be
	// in one of the account's aliases, and a service principal is nobody's account at all.
	p, err := s.st.GetPrincipal(r.Context(), name)
	if err != nil || p.UserID == nil {
		writeError(w, http.StatusForbidden, "%s is not a directory account", name)

		return
	}

	u, err := s.st.GetUserByID(r.Context(), *p.UserID)
	if err != nil {
		writeStoreError(w, err)

		return
	}

	s.admit(w, r, u, methodKerberos)
}

// admit issues a session to an authenticated account that administers the directory.
func (s *Server) admit(w http.ResponseWriter, r *http.Request, u *store.User, method string) {
	admin, err := s.st.IsDirectoryAdmin(r.Context(), u, s.cfg.BaseDN)
	if err != nil {
		writeStoreError(w, err)

		return
	}
	if !admin {
		s.log.Info().Str("subject", u.Name).Str("method", method).Str("src", clientIP(r)).
			Msg("console sign-in refused: not a directory administrator")
		writeError(w, http.StatusForbidden, "%s does not administer the directory", u.Name)

		return
	}

	now := timeNow()
	expires := now.Add(s.cfg.SessionLifetime)

	token, err := s.sig.Sign(map[string]any{
		"iss": sessionIssuer,
		"aud": sessionAudience,
		"sub": u.Name,
		"iat": now.Unix(),
		"exp": expires.Unix(),
		"amr": []string{method},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot sign the session")

		return
	}

	s.log.Info().Str("subject", u.Name).Str("method", method).Str("src", clientIP(r)).
		Msg("administrator signed in")

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, sessionBody{
		Token: token, Subject: u.Name, Method: method, ExpiresAt: expires.Truncate(time.Second),
	})
}

// handleWhoAmI tells the console who it is signed in as. The page asks rather than decoding its
// token: what it shows has to be what the server enforces.
func (s *Server) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	if c == nil {
		challenge(w, "sign in")

		return
	}

	body := whoAmIBody{Subject: c.Subject, Method: c.Method}
	if !c.Expires.IsZero() {
		body.ExpiresAt = &c.Expires
	}

	writeJSON(w, http.StatusOK, body)
}

// ensureSPN makes sure the principal Kerberos sign-in is accepted for exists.
//
// This service is its own KDC, so creating it is all a deployment needs: its keys are random and
// live in the same store as everything else, and no keytab file is written anywhere.
func (s *Server) ensureSPN(ctx context.Context) error {
	if len(s.cfg.SPN) == 0 {
		return nil
	}

	name, err := krbkeys.ParseName(s.cfg.SPN, s.cfg.Realm)
	if err != nil {
		return fmt.Errorf("api: spn: %w", err)
	}
	if len(name.Components) != 2 || name.Components[0] != "HTTP" {
		return fmt.Errorf("api: spn %q must be HTTP/<host name the console is reached by>", s.cfg.SPN)
	}
	if !strings.EqualFold(name.Realm, s.cfg.Realm) {
		return fmt.Errorf("api: spn %s is not in realm %s", name, s.cfg.Realm)
	}

	s.spn = name

	p, err := s.st.GetPrincipal(ctx, name)
	switch {
	case err == nil:
		if p.UserID != nil {
			return fmt.Errorf("api: spn %s names a directory account, not a service", name)
		}

		return nil
	case !errors.Is(err, store.ErrNotFound):
		return err
	}

	keys, err := krbkeys.RandomKeys(s.cfg.EncTypes)
	if err != nil {
		return err
	}

	if err := s.st.CreatePrincipal(ctx, &store.Principal{
		Name: name.Principal(), Realm: name.Realm, Enabled: true, RequiresPreAuth: true,
	}, keys); err != nil {
		return fmt.Errorf("api: creating %s: %w", name, err)
	}

	s.log.Info().Str("spn", name.String()).Msg("created the service principal for Kerberos sign-in")

	return nil
}

// keytab builds the sign-in principal's keytab from the store for one request.
//
// Building it per sign-in means a re-keyed principal is honoured at once. The previous key version
// is included, because a browser may still hold a ticket issued just before the change.
func (s *Server) keytab(ctx context.Context) (*keytab.Keytab, error) {
	p, err := s.st.GetPrincipal(ctx, s.spn)
	if err != nil {
		return nil, err
	}

	generations := [][]krbkeys.Key{p.Keys}
	kvnos := []int{p.KVNO}

	if p.KVNO > 1 {
		if prev, err := s.st.GetPrincipalKVNO(ctx, s.spn, p.KVNO-1); err == nil && len(prev.Keys) > 0 {
			generations = append(generations, prev.Keys)
			kvnos = append(kvnos, p.KVNO-1)
		}
	}

	var entries []krbkeys.KeytabEntry

	for i, keys := range generations {
		for _, k := range keys {
			// The entry is named as configured, which may be an alias: a ticket carries the name
			// the browser asked for, and that is the name its key is looked up by.
			entries = append(entries, krbkeys.KeytabEntry{Name: s.spn, KVNO: kvnos[i], Key: k, Timestamp: timeNow()})
		}
	}

	raw, err := krbkeys.MarshalKeytab(entries)
	if err != nil {
		return nil, err
	}

	kt := keytab.New()
	if err := kt.Unmarshal(raw); err != nil {
		return nil, err
	}

	return kt, nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}
