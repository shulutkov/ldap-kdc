// Package oidc serves the directory's accounts to browsers as an OpenID Connect provider.
//
// It exists so that one sign-in reaches every interface a deployment puts in front of this
// directory. A provider that keeps no browser session makes each of them ask for a password again,
// however recently the person typed one — which is the whole of the complaint this package
// answers, and is not something a relying party can fix on its own.
//
// The scope is deliberately small: the authorization code flow with PKCE, for public clients,
// against the accounts already here. No consent screen, no refresh tokens, no dynamic
// registration, no confidential clients. What it does carry is the part the accounts make cheap —
// the same credential decision as an LDAP bind (store.Authenticate), and the groups the directory
// already resolves.
package oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// Client is a relying party this provider will issue tokens to.
//
// The id is any string, and that is not laxity: an id token's audience IS the client id, so a
// deployment whose services identify themselves by URL has to be able to say so here. Nothing is
// issued to an id that is not listed, and nothing is redirected to a URI that is not.
type Client struct {
	ID                 string
	Name               string
	RedirectURIs       []string
	PostLogoutRedirect []string
}

// Config is everything the provider is configured with.
type Config struct {
	Listen string
	TLS    *tls.Config

	// Issuer is what lands in every token's iss and what the BROWSER must reach. It is the
	// provider's public address, which on a stand behind a proxy is not the address it binds.
	Issuer string

	// AllowedOrigins are the web origins permitted to read discovery, the keys and the token
	// endpoint from script. A browser page on another origin cannot do it without this.
	AllowedOrigins []string

	Clients []Client

	SessionLifetime time.Duration
	SessionIdle     time.Duration
	CodeLifetime    time.Duration
	TokenLifetime   time.Duration
}

// Server is the provider.
type Server struct {
	cfg     Config
	st      *store.Store
	log     zerolog.Logger
	metrics *metrics.Metrics

	sig      *signer
	sessions *sessions
	codes    *codes
	pending  *pendingRequests

	// secure marks the session cookie Secure, which follows the issuer rather than the listener:
	// the provider may serve plain HTTP behind a proxy that terminates TLS.
	secure bool

	http *http.Server
	ln   net.Listener
}

// New builds the provider. The signing key is loaded — or created and sealed — here, so a
// misconfigured store fails at start rather than at the first sign-in.
func New(ctx context.Context, cfg Config, st *store.Store, log zerolog.Logger, m *metrics.Metrics) (*Server, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("oidc: no issuer — it is what lands in every token and what the browser must reach")
	}
	iss, err := url.Parse(cfg.Issuer)
	if err != nil || iss.Scheme == "" || iss.Host == "" {
		return nil, fmt.Errorf("oidc: issuer %q is not an absolute URL", cfg.Issuer)
	}
	if strings.HasSuffix(cfg.Issuer, "/") {
		// Discovery is served at <issuer>/.well-known/…, and every verifier compares the iss
		// claim to the issuer it was configured with byte for byte. A trailing slash is the
		// difference between agreeing and not.
		return nil, fmt.Errorf("oidc: issuer %q must not end in a slash", cfg.Issuer)
	}
	if len(cfg.Clients) == 0 {
		return nil, errors.New("oidc: no clients configured — nothing could obtain a token")
	}
	for _, c := range cfg.Clients {
		if c.ID == "" || len(c.RedirectURIs) == 0 {
			return nil, fmt.Errorf("oidc: client %q needs an id and at least one redirect URI", c.ID)
		}
	}

	sig, err := loadOrCreateSigner(ctx, st)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:      cfg,
		st:       st,
		log:      log.With().Str("component", "oidc").Logger(),
		metrics:  m,
		sig:      sig,
		sessions: newSessions(cfg.SessionLifetime, cfg.SessionIdle),
		codes:    newCodes(cfg.CodeLifetime),
		pending:  newPendingRequests(cfg.CodeLifetime),
		secure:   iss.Scheme == "https",
	}
	s.http = &http.Server{Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}

	return s, nil
}

// Paths the provider serves. They are relative to the issuer and appear in discovery, so a client
// never has to be told them.
const (
	pathDiscovery = "/.well-known/openid-configuration"
	pathKeys      = "/keys"
	pathAuthorize = "/auth"
	pathToken     = "/token"
	pathUserInfo  = "/userinfo"
	pathEndAuth   = "/end-session"
	pathLogin     = "/auth/login"
)

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+pathDiscovery, s.cors(s.discovery))
	mux.HandleFunc("OPTIONS "+pathDiscovery, s.preflight)
	mux.HandleFunc("GET "+pathKeys, s.cors(s.keys))
	mux.HandleFunc("OPTIONS "+pathKeys, s.preflight)
	mux.HandleFunc("GET "+pathAuthorize, s.authorize)
	mux.HandleFunc("GET "+pathLogin, s.loginForm)
	mux.HandleFunc("POST "+pathLogin, s.login)
	mux.HandleFunc("POST "+pathToken, s.cors(s.token))
	mux.HandleFunc("OPTIONS "+pathToken, s.preflight)
	mux.HandleFunc("GET "+pathUserInfo, s.cors(s.userinfo))
	mux.HandleFunc("OPTIONS "+pathUserInfo, s.preflight)
	mux.HandleFunc("GET "+pathEndAuth, s.endSession)

	return mux
}

// Start binds the listener and serves.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("oidc: listening on %s: %w", s.cfg.Listen, err)
	}
	s.ln = ln

	s.log.Info().Str("address", ln.Addr().String()).Str("issuer", s.cfg.Issuer).
		Int("clients", len(s.cfg.Clients)).Bool("tls", s.cfg.TLS != nil).
		Msg("OpenID Connect provider listening")

	go func() {
		var err error
		if s.cfg.TLS != nil {
			s.http.TLSConfig = s.cfg.TLS
			err = s.http.ServeTLS(ln, "", "")
		} else {
			err = s.http.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error().Err(err).Msg("OpenID Connect provider stopped")
		}
	}()

	return nil
}

// Shutdown stops serving.
func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }

// client returns the registered client with this id.
func (s *Server) client(id string) (Client, bool) {
	for _, c := range s.cfg.Clients {
		if c.ID == id {
			return c, true
		}
	}

	return Client{}, false
}

// registered reports whether uri is one the client declared. The comparison is exact, per OAuth
// 2.1: prefix and wildcard matching are how redirect URIs turn into open redirects.
func registered(uris []string, uri string) bool { return slices.Contains(uris, uri) }

// cors lets a page on a permitted origin read this endpoint. A browser SPA fetches discovery, the
// keys and the token endpoint from its OWN origin, which is never the provider's.
func (s *Server) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.allowOrigin(w, r)
		next(w, r)
	}
}

func (s *Server) preflight(w http.ResponseWriter, r *http.Request) {
	s.allowOrigin(w, r)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) allowOrigin(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" || !slices.Contains(s.cfg.AllowedOrigins, origin) {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Add("Vary", "Origin")
}
