// Package api serves the REST management interface: the place where users, groups, Kerberos
// principals and their credentials are created and changed.
package api

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// Config is what the API needs to know about the service it manages.
type Config struct {
	Listen   string
	TLS      *tls.Config
	Realm    string
	EncTypes []int32

	// Token, when set, must be presented as a bearer token on every /api request.
	Token string
	// MinPasswordLength is enforced on every password the API sets.
	MinPasswordLength int

	// DNSZones are the zones the name server answers for, used to reject records that would
	// never be served. DNSDefaultTTL applies to a record created without one.
	DNSZones      []string
	DNSDefaultTTL int
}

// Server is the REST management interface.
type Server struct {
	cfg     Config
	st      *store.Store
	log     zerolog.Logger
	metrics *metrics.Metrics

	http *http.Server
	ln   net.Listener
}

// New builds the management server.
func New(cfg Config, st *store.Store, log zerolog.Logger, m *metrics.Metrics) (*Server, error) {
	if len(cfg.Realm) == 0 {
		return nil, errors.New("api: realm is required")
	}

	s := &Server{
		cfg:     cfg,
		st:      st,
		log:     log.With().Str("component", "api").Logger(),
		metrics: m,
	}

	s.http = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		TLSConfig:         cfg.TLS,
	}

	return s, nil
}

// routes builds the request multiplexer.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.Handle("GET /metrics", promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{}))

	api := http.NewServeMux()

	api.HandleFunc("GET /api/v1/stats", s.handleStats)

	api.HandleFunc("GET /api/v1/users", s.handleListUsers)
	api.HandleFunc("POST /api/v1/users", s.handleCreateUser)
	api.HandleFunc("GET /api/v1/users/{name}", s.handleGetUser)
	api.HandleFunc("PATCH /api/v1/users/{name}", s.handlePatchUser)
	api.HandleFunc("DELETE /api/v1/users/{name}", s.handleDeleteUser)
	api.HandleFunc("POST /api/v1/users/{name}/password", s.handleSetUserPassword)
	api.HandleFunc("GET /api/v1/users/{name}/app-passwords", s.handleListAppPasswords)
	api.HandleFunc("POST /api/v1/users/{name}/app-passwords", s.handleCreateAppPassword)
	api.HandleFunc("DELETE /api/v1/users/{name}/app-passwords/{id}", s.handleDeleteAppPassword)

	api.HandleFunc("GET /api/v1/groups", s.handleListGroups)
	api.HandleFunc("POST /api/v1/groups", s.handleCreateGroup)
	api.HandleFunc("GET /api/v1/groups/{name}", s.handleGetGroup)
	api.HandleFunc("PATCH /api/v1/groups/{name}", s.handlePatchGroup)
	api.HandleFunc("DELETE /api/v1/groups/{name}", s.handleDeleteGroup)
	api.HandleFunc("GET /api/v1/groups/{name}/members", s.handleGroupMembers)

	// Service principal names carry slashes ("HTTP/host.example.com"), so the trailing wildcard
	// has to swallow the rest of the path rather than stop at the first separator.
	api.HandleFunc("GET /api/v1/principals", s.handleListPrincipals)
	api.HandleFunc("POST /api/v1/principals", s.handleCreatePrincipal)
	api.HandleFunc("GET /api/v1/principals/{name...}", s.handlePrincipalGet)
	api.HandleFunc("POST /api/v1/principals/{name...}", s.handlePrincipalPost)
	api.HandleFunc("PATCH /api/v1/principals/{name...}", s.handlePatchPrincipal)
	api.HandleFunc("DELETE /api/v1/principals/{name...}", s.handleDeletePrincipal)

	api.HandleFunc("GET /api/v1/dns/records", s.handleListDNSRecords)
	api.HandleFunc("POST /api/v1/dns/records", s.handleCreateDNSRecord)
	api.HandleFunc("DELETE /api/v1/dns/records/{id}", s.handleDeleteDNSRecord)

	api.HandleFunc("GET /api/v1/trusts", s.handleListTrusts)
	api.HandleFunc("POST /api/v1/trusts", s.handleCreateTrust)
	api.HandleFunc("GET /api/v1/trusts/{realm}", s.handleGetTrust)
	api.HandleFunc("PATCH /api/v1/trusts/{realm}", s.handlePatchTrust)
	api.HandleFunc("DELETE /api/v1/trusts/{realm}", s.handleDeleteTrust)

	mux.Handle("/api/", s.authenticate(api))

	return s.observe(mux)
}

// Start binds the listener and serves in the background.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("api: listening on %s: %w", s.cfg.Listen, err)
	}

	s.ln = ln

	if len(s.cfg.Token) == 0 {
		host, _, _ := net.SplitHostPort(ln.Addr().String())
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			// Without a token the API is open to anyone who can reach the port, and it can
			// set any account's password. Refusing to say so quietly would be worse.
			s.log.Warn().Str("address", ln.Addr().String()).
				Msg("management API has no token and is not bound to loopback: anyone who can reach this port can change any password")
		}
	}

	s.log.Info().Str("address", ln.Addr().String()).Bool("tls", s.cfg.TLS != nil).
		Bool("token", len(s.cfg.Token) > 0).Msg("management API listening")

	go func() {
		var err error
		if s.cfg.TLS != nil {
			err = s.http.ServeTLS(ln, "", "")
		} else {
			err = s.http.Serve(ln)
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error().Err(err).Msg("management API stopped")
		}
	}()

	return nil
}

// Addr reports the bound address.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}

	return s.ln.Addr()
}

// Shutdown stops the API, letting in-flight requests finish.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// authenticate enforces the bearer token when one is configured.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.cfg.Token) == 0 {
			next.ServeHTTP(w, r)

			return
		}

		presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		// A constant time comparison keeps the check from leaking the token's prefix through
		// how long it takes to fail.
		if !ok || subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ldap-kdc"`)
			writeError(w, http.StatusUnauthorized, "a valid bearer token is required")

			return
		}

		next.ServeHTTP(w, r)
	})
}

// observe records request outcomes and logs failures.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		route := r.Pattern
		if len(route) == 0 {
			route = "unmatched"
		}

		s.metrics.APIRequests.WithLabelValues(r.Method, route, strconv.Itoa(rec.status)).Inc()

		if rec.status >= http.StatusBadRequest {
			s.log.Info().Str("method", r.Method).Str("path", r.URL.Path).
				Int("status", rec.status).Str("from", r.RemoteAddr).Msg("request failed")
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// errorBody is the shape of every failure reply.
type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	if body == nil {
		return
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, errorBody{Error: fmt.Sprintf(format, args...)})
}

// writeStoreError maps a store failure onto the closest HTTP status.
func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "already exists")
	default:
		writeError(w, http.StatusInternalServerError, "%s", err)
	}
}

// decode reads a JSON request body, rejecting unknown fields so a misspelled key is reported
// rather than silently ignored.
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body: %s", err)

		return false
	}

	return true
}

// principalName resolves a name from the request path against the service realm.
func (s *Server) principalName(w http.ResponseWriter, raw string) (krbkeys.Name, bool) {
	name, err := krbkeys.ParseName(raw, s.cfg.Realm)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)

		return krbkeys.Name{}, false
	}

	return name, true
}

// checkPassword applies the realm's password rules before anything is written.
func (s *Server) checkPassword(w http.ResponseWriter, password string) bool {
	switch {
	case len(password) < s.cfg.MinPasswordLength:
		writeError(w, http.StatusBadRequest, "password must be at least %d characters", s.cfg.MinPasswordLength)

		return false
	case len(password) > 72:
		// The LDAP side stores a bcrypt digest, which ignores everything past 72 bytes; a
		// longer password would silently authenticate on its first 72.
		writeError(w, http.StatusBadRequest, "password must not exceed 72 bytes")

		return false
	default:
		return true
	}
}
