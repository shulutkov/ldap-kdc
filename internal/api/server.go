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
	// Docs serves the OpenAPI document and the Swagger UI that renders it.
	Docs bool
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

	// spec is the OpenAPI document, rendered once from the route table.
	spec []byte
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

	// The document is built here rather than on request: it cannot change while the process
	// runs, and a mistake in the route table is then a start-up failure rather than a broken
	// page found by whoever opened it.
	spec, err := s.buildSpec()
	if err != nil {
		return nil, fmt.Errorf("api: building the OpenAPI document: %w", err)
	}

	s.spec = spec

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

// route is one pattern, the handler that answers it, and what the OpenAPI document says about it.
//
// The routes live in a table rather than in a sequence of calls because the document is generated
// from this very table when the service starts: there is one list of what this API does, and the
// router and the documentation both read it.
type route struct {
	pattern string
	handler http.HandlerFunc
	docs    []operationDoc
}

// publicRoutes are the endpoints outside the bearer token: an orchestrator's probes and the
// metrics a scraper reads, neither of which should need a credential that can change passwords.
func (s *Server) publicRoutes() []route {
	return []route{
		{"GET /healthz", s.handleHealth, []operationDoc{{
			tag: "operations", public: true, summary: "Liveness",
			description: "Reports that the process is running. It never touches the database, " +
				"so a stuck query cannot make a healthy process look dead to an orchestrator.",
			responses: []responseDoc{ok(new(statusBody), "The process is running.")},
		}}},
		{"GET /readyz", s.handleReady, []operationDoc{{
			tag: "operations", public: true, summary: "Readiness",
			description: "Reports whether the service can serve: the database answers and the realm is initialised.",
			responses: []responseDoc{
				ok(new(statusBody), "Ready."),
				{status: http.StatusServiceUnavailable, body: new(statusBody), description: "Not ready, with the reason."},
			},
		}}},
		{"GET /metrics", s.handleMetrics, []operationDoc{{
			tag: "operations", public: true, summary: "Prometheus metrics",
			responses: []responseDoc{{
				status: http.StatusOK, body: new(string), contentType: "text/plain",
				description: "Metrics in the Prometheus text format.",
			}},
		}}},
	}
}

// apiRoutes is everything under /api/v1, which is everything behind the bearer token.
//
// Service principal names carry slashes ("HTTP/host.example.com"), so their patterns take a
// trailing wildcard that swallows the rest of the path and the actions under a principal are
// matched inside the handler. The document names those actions as the paths they are.
func (s *Server) apiRoutes() []route {
	return []route{
		{"GET /api/v1/stats", s.handleStats, []operationDoc{{
			tag: "operations", summary: "What the directory holds",
			responses: []responseDoc{ok(new(statsBody), "Counts and the realm's enctypes."), unauthorized},
		}}},

		{"GET /api/v1/users", s.handleListUsers, []operationDoc{{
			tag: "users", summary: "List accounts",
			responses: []responseDoc{ok(new(usersBody), "Every account."), unauthorized},
		}}},
		{"POST /api/v1/users", s.handleCreateUser, []operationDoc{{
			tag: "users", summary: "Create an account",
			description: "Creates the directory account and the Kerberos principal named after it. " +
				"There is no state where one exists without the other: an account meant never to " +
				"use Kerberos is simply given no password, and its principal keeps the random keys " +
				"it starts with, which no password produces.",
			request:   new(createUserRequest),
			responses: []responseDoc{created(new(userBody), "Created."), badRequest, unauthorized, conflict},
		}}},
		{"GET /api/v1/users/{name}", s.handleGetUser, []operationDoc{{
			tag: "users", summary: "Read an account", request: new(getUserReq),
			responses: []responseDoc{ok(new(userBody), "The account and the principals attached to it."), unauthorized, notFound},
		}}},
		{"PATCH /api/v1/users/{name}", s.handlePatchUser, []operationDoc{{
			tag: "users", summary: "Edit an account",
			description: "Only the fields present are changed. Disabling an account disables its " +
				"principals too, or it would keep collecting tickets after being locked out of LDAP.",
			request:   new(patchUserReq),
			responses: []responseDoc{ok(new(userBody), "The account as it now stands."), badRequest, unauthorized, notFound},
		}}},
		{"DELETE /api/v1/users/{name}", s.handleDeleteUser, []operationDoc{{
			tag: "users", summary: "Remove an account",
			description: "Principals, keys, group memberships and attributes go with it.",
			request:     new(getUserReq),
			responses:   []responseDoc{noContent("Removed."), unauthorized, notFound},
		}}},
		{"POST /api/v1/users/{name}/password", s.handleSetUserPassword, []operationDoc{{
			tag: "users", summary: "Set an account's password",
			description: "Writes both credential forms at once. The password is expired by default, " +
				"so its owner chooses the final value at first login: one an administrator typed is " +
				"one the administrator knows, and FreeIPA expires an administrative reset for the " +
				"same reason.",
			request:   new(setUserPasswordReq),
			responses: []responseDoc{ok(new(passwordSetBody), "Set."), badRequest, unauthorized, notFound},
		}}},
		{"GET /api/v1/users/{name}/app-passwords", s.handleListAppPasswords, []operationDoc{{
			tag: "users", summary: "List an account's application passwords", request: new(getUserReq),
			responses: []responseDoc{ok(new(appPasswordsBody), "The application passwords, without their secrets."), unauthorized, notFound},
		}}},
		{"POST /api/v1/users/{name}/app-passwords", s.handleCreateAppPassword, []operationDoc{{
			tag: "users", summary: "Mint an application password",
			description: "An additional password that authenticates one application over LDAP. " +
				"Revoking it does not disturb the account's own password. A generated secret is " +
				"returned once, here, because nothing stores it in the clear.",
			request:   new(appPasswordReq),
			responses: []responseDoc{created(new(appPasswordBody), "Created."), badRequest, unauthorized, notFound},
		}}},
		{"DELETE /api/v1/users/{name}/app-passwords/{id}", s.handleDeleteAppPassword, []operationDoc{{
			tag: "users", summary: "Revoke an application password", request: new(appPasswordPath),
			responses: []responseDoc{noContent("Revoked."), badRequest, unauthorized, notFound},
		}}},

		{"GET /api/v1/groups", s.handleListGroups, []operationDoc{{
			tag: "groups", summary: "List groups",
			responses: []responseDoc{ok(new(groupsBody), "Every group."), unauthorized},
		}}},
		{"POST /api/v1/groups", s.handleCreateGroup, []operationDoc{{
			tag: "groups", summary: "Create a group", request: new(createGroupRequest),
			responses: []responseDoc{created(new(groupBody), "Created."), badRequest, unauthorized, conflict},
		}}},
		{"GET /api/v1/groups/{name}", s.handleGetGroup, []operationDoc{{
			tag: "groups", summary: "Read a group", request: new(groupPath),
			responses: []responseDoc{ok(new(groupBody), "The group."), unauthorized, notFound},
		}}},
		{"PATCH /api/v1/groups/{name}", s.handlePatchGroup, []operationDoc{{
			tag: "groups", summary: "Edit a group", request: new(patchGroupReq),
			responses: []responseDoc{ok(new(groupBody), "The group as it now stands."), badRequest, unauthorized, notFound},
		}}},
		{"DELETE /api/v1/groups/{name}", s.handleDeleteGroup, []operationDoc{{
			tag: "groups", summary: "Remove a group",
			description: "Refused while the group is any account's primary group.",
			request:     new(groupPath),
			responses:   []responseDoc{noContent("Removed."), unauthorized, notFound},
		}}},
		{"GET /api/v1/groups/{name}/members", s.handleGroupMembers, []operationDoc{{
			tag: "groups", summary: "Resolved membership",
			description: "Follows included groups, so this is the set the LDAP entry publishes.",
			request:     new(groupPath),
			responses:   []responseDoc{ok(new(membersBody), "Member account names."), unauthorized, notFound},
		}}},

		{"GET /api/v1/principals", s.handleListPrincipals, []operationDoc{{
			tag: "principals", summary: "List principals", request: new(principalsQuery),
			responses: []responseDoc{ok(new(principalsBody), "Principals, without key material."), unauthorized},
		}}},
		{"POST /api/v1/principals", s.handleCreatePrincipal, []operationDoc{{
			tag: "principals", summary: "Create a principal",
			description: "A service principal is better left without a password: random keys cannot " +
				"be guessed, and the keytab is fetched from this API.",
			request:   new(createPrincipalRequest),
			responses: []responseDoc{created(new(principalBody), "Created."), badRequest, unauthorized, conflict},
		}}},
		{"GET /api/v1/principals/{name...}", s.handlePrincipalGet, []operationDoc{
			{
				tag: "principals", summary: "Read a principal", request: new(principalPath),
				responses: []responseDoc{
					ok(new(principalBody), "The principal, its policy and the krbTicketFlags bitmask MIT and FreeIPA store."),
					badRequest, unauthorized, notFound,
				},
			},
			{
				path: "/api/v1/principals/{name}/keytab",
				tag:  "principals", summary: "Keytab for the current key version",
				request: new(principalPath),
				responses: []responseDoc{
					{status: http.StatusOK, body: new(keytabFile), contentType: "application/octet-stream", description: "A keytab file."},
					unauthorized, notFound, conflict,
				},
			},
		}},
		{"POST /api/v1/principals/{name...}", s.handlePrincipalPost, []operationDoc{{
			path: "/api/v1/principals/{name}/password",
			tag:  "principals", summary: "Re-key a principal",
			description: "The previous key version is kept, so tickets and keytabs issued before the " +
				"change keep working until they expire. The salt follows the principal's canonical " +
				"name, so a password set through an alias produces the same keys as one set through " +
				"the real name.",
			request:   new(principalPasswordReq),
			responses: []responseDoc{ok(new(principalBody), "Re-keyed."), badRequest, unauthorized, notFound},
		}}},
		{"PATCH /api/v1/principals/{name...}", s.handlePatchPrincipal, []operationDoc{{
			tag: "principals", summary: "Edit a principal's policy", request: new(patchPrincipalReq),
			responses: []responseDoc{ok(new(principalBody), "The principal as it now stands."), badRequest, unauthorized, notFound, conflict},
		}}},
		{"DELETE /api/v1/principals/{name...}", s.handleDeletePrincipal, []operationDoc{{
			tag: "principals", summary: "Remove a principal",
			description: "The realm's own ticket-granting principal cannot be removed; without it no " +
				"ticket in circulation would verify.",
			request:   new(principalPath),
			responses: []responseDoc{noContent("Removed."), badRequest, unauthorized, notFound, conflict},
		}}},

		{"GET /api/v1/dns/records", s.handleListDNSRecords, []operationDoc{{
			tag: "dns", summary: "List resource records", request: new(dnsRecordsQuery),
			responses: []responseDoc{ok(new(dnsRecordsBody), "The records, and the zones this service answers for."), unauthorized},
		}}},
		{"POST /api/v1/dns/records", s.handleCreateDNSRecord, []operationDoc{{
			tag: "dns", summary: "Create a resource record",
			description: "Reverse answers are computed from the address records rather than stored, " +
				"so there are no PTR records to write and nothing that can drift out of step.",
			request:   new(createDNSRecordRequest),
			responses: []responseDoc{created(new(dnsRecordBody), "Created."), badRequest, unauthorized, conflict},
		}}},
		{"DELETE /api/v1/dns/records/{id}", s.handleDeleteDNSRecord, []operationDoc{{
			tag: "dns", summary: "Remove a resource record", request: new(dnsRecordPath),
			responses: []responseDoc{noContent("Removed."), badRequest, unauthorized, notFound},
		}}},

		{"GET /api/v1/trusts", s.handleListTrusts, []operationDoc{{
			tag: "trusts", summary: "List cross-realm trusts",
			responses: []responseDoc{ok(new(trustsBody), "Every trust."), unauthorized},
		}}},
		{"POST /api/v1/trusts", s.handleCreateTrust, []operationDoc{{
			tag: "trusts", summary: "Create a cross-realm trust",
			description: "A trust is two principals: krbtgt/REMOTE@LOCAL refers this realm's clients " +
				"outwards, and krbtgt/LOCAL@REMOTE accepts the remote realm's clients here. Both are " +
				"keyed from the same shared password, which is exactly the string entered on the " +
				"other side.",
			request:   new(createTrustRequest),
			responses: []responseDoc{created(new(trustBody), "Created."), badRequest, unauthorized, conflict},
		}}},
		{"GET /api/v1/trusts/{realm}", s.handleGetTrust, []operationDoc{{
			tag: "trusts", summary: "Read a trust", request: new(trustPath),
			responses: []responseDoc{ok(new(trustBody), "The trust."), unauthorized, notFound},
		}}},
		{"PATCH /api/v1/trusts/{realm}", s.handlePatchTrust, []operationDoc{{
			tag: "trusts", summary: "Edit a trust", request: new(patchTrustReq),
			responses: []responseDoc{ok(new(trustBody), "The trust as it now stands."), badRequest, unauthorized, notFound},
		}}},
		{"DELETE /api/v1/trusts/{realm}", s.handleDeleteTrust, []operationDoc{{
			tag: "trusts", summary: "Remove a trust",
			description: "The shared krbtgt principals go with it, which is what stops tickets flowing.",
			request:     new(trustPath),
			responses:   []responseDoc{noContent("Removed."), unauthorized, notFound},
		}}},
	}
}

// routes builds the request multiplexer.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	for _, r := range s.publicRoutes() {
		mux.HandleFunc(r.pattern, r.handler)
	}

	s.docsRoutes(mux)

	api := http.NewServeMux()
	for _, r := range s.apiRoutes() {
		api.HandleFunc(r.pattern, r.handler)
	}

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
	case errors.Is(err, store.ErrInvalidAttribute):
		writeError(w, http.StatusBadRequest, "%s", err)
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
