package oidc

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// request is an authorization request waiting for the person to sign in.
//
// It is held HERE rather than round-tripped through the form, because everything in it was already
// validated — the client, the redirect, the challenge — and a form field is something a browser
// can edit.
type request struct {
	id        string
	client    Client
	redirect  string
	state     string
	nonce     string
	challenge string
	issued    time.Time
}

type pendingRequests struct {
	mu      sync.Mutex
	byID    map[string]*request
	timeout time.Duration
	now     func() time.Time
}

func newPendingRequests(timeout time.Duration) *pendingRequests {
	return &pendingRequests{byID: map[string]*request{}, timeout: timeout, now: time.Now}
}

func (p *pendingRequests) put(req *request) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	req.id = id
	req.issued = p.now()

	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range p.byID {
		if p.now().Sub(v.issued) > p.timeout {
			delete(p.byID, k)
		}
	}
	p.byID[id] = req

	return id, nil
}

// get keeps the request: the form may be submitted more than once, because a wrong password is an
// ordinary thing to do.
func (p *pendingRequests) get(id string) (*request, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	req, ok := p.byID[id]
	if !ok || p.now().Sub(req.issued) > p.timeout {
		return nil, false
	}

	return req, true
}

func (p *pendingRequests) done(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.byID, id)
}

// authorize starts the flow.
//
// Two refusals here do NOT redirect, and the difference matters: an unknown client or an
// unregistered redirect URI means the place the error would be sent to is not trustworthy, so it
// is shown to the person instead. Everything else is the client's own problem and goes back to it
// as an error parameter, which is what a client can act on.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	client, ok := s.client(q.Get("client_id"))
	if !ok {
		s.fail(w, http.StatusBadRequest, "unknown client", q.Get("client_id"))

		return
	}
	redirect := q.Get("redirect_uri")
	if !registered(client.RedirectURIs, redirect) {
		s.fail(w, http.StatusBadRequest, "this redirect URI is not registered for the client", redirect)

		return
	}

	state := q.Get("state")
	switch {
	case q.Get("response_type") != "code":
		s.redirectError(w, r, redirect, state, "unsupported_response_type", "only the authorization code flow is served")

		return
	case q.Get("code_challenge_method") != "S256":
		s.redirectError(w, r, redirect, state, "invalid_request", "code_challenge_method must be S256")

		return
	case q.Get("code_challenge") == "":
		s.redirectError(w, r, redirect, state, "invalid_request", "a code_challenge is required")

		return
	}

	req := &request{
		client:    client,
		redirect:  redirect,
		state:     state,
		nonce:     q.Get("nonce"),
		challenge: q.Get("code_challenge"),
	}

	// The session is what makes the second client silent, and prompt is how a client says it
	// wants otherwise: prompt=login forces the form, prompt=none forbids it.
	prompts := strings.Fields(q.Get("prompt"))
	sess, signedIn := s.sessions.get(r)

	switch {
	case signedIn && !slices.Contains(prompts, "login"):
		s.issueCode(w, r, req, sess.subject, sess.signedIn)

		return
	case slices.Contains(prompts, "none"):
		s.redirectError(w, r, redirect, state, "login_required", "nobody is signed in and prompt=none forbids asking")

		return
	}

	id, err := s.pending.put(req)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "cannot start the sign-in", "")

		return
	}
	http.Redirect(w, r, pathLogin+"?req="+url.QueryEscape(id), http.StatusSeeOther)
}

// loginForm renders the sign-in page for a pending request.
func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	req, ok := s.pending.get(r.URL.Query().Get("req"))
	if !ok {
		s.fail(w, http.StatusBadRequest, "this sign-in has expired; start again from the application", "")

		return
	}
	s.renderLogin(w, req, "")
}

// login checks the credential and, on success, starts a session and issues the code.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, http.StatusBadRequest, "malformed form", "")

		return
	}
	req, ok := s.pending.get(r.Form.Get("req"))
	if !ok {
		s.fail(w, http.StatusBadRequest, "this sign-in has expired; start again from the application", "")

		return
	}

	name := strings.TrimSpace(r.Form.Get("login"))
	outcome, subject := s.check(r.Context(), name, r.Form.Get("password"))
	s.result("login", string(outcome))

	if !outcome.Granted() {
		// One message for every refusal. Which of "no such account", "wrong password" and
		// "disabled" it was is exactly what a guesser is trying to learn.
		s.log.Info().Str("login", name).Str("outcome", string(outcome)).Str("src", clientIP(r)).
			Msg("sign-in refused")
		s.renderLogin(w, req, "Incorrect login or password.")

		return
	}

	sess, err := s.sessions.start(subject)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "cannot start a session", "")

		return
	}
	setCookie(w, sess, s.secure, s.cfg.SessionLifetime)
	s.log.Info().Str("subject", subject).Str("client", req.client.ID).Str("src", clientIP(r)).
		Msg("signed in")

	s.pending.done(req.id)
	s.issueCode(w, r, req, subject, sess.signedIn)
}

// check resolves a login to an account and decides the credential.
//
// The login is a user name or the account's mail address, because a person who signs in to a web
// page types the address they know themselves by — and mail is what the deployment's services read
// as the subject claim.
func (s *Server) check(ctx context.Context, login, password string) (store.Outcome, string) {
	u := s.lookup(ctx, login)
	if u == nil {
		return store.OutcomeInvalid, ""
	}

	return store.Authenticate(u, password), u.Name
}

// lookup resolves a login to an account by name or by mail address. Shared with the client
// credentials grant, where the same two spellings are the ones a service account will be
// configured with.
func (s *Server) lookup(ctx context.Context, login string) *store.User {
	if login == "" {
		return nil
	}
	if u, err := s.st.GetUser(ctx, login); err == nil {
		return u
	}

	return s.userByMail(ctx, login)
}

// userByMail finds an account by its mail address. A miss is not an error here: the caller has
// already failed to find it by name, and both misses are one refusal.
func (s *Server) userByMail(ctx context.Context, mail string) *store.User {
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		s.log.Error().Err(err).Msg("cannot read the directory to resolve a login")

		return nil
	}
	for i := range users {
		if strings.EqualFold(users[i].Mail, mail) {
			u, err := s.st.GetUser(ctx, users[i].Name)
			if err != nil {
				return nil
			}

			return u
		}
	}

	return nil
}

// issueCode completes the authorization: mint a code and send the browser back.
func (s *Server) issueCode(w http.ResponseWriter, r *http.Request, req *request, subject string, authTime time.Time) {
	code, err := s.codes.issue(&authCode{
		clientID:  req.client.ID,
		redirect:  req.redirect,
		challenge: req.challenge,
		subject:   subject,
		nonce:     req.nonce,
		authTime:  authTime,
	})
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "cannot issue a code", "")

		return
	}

	u, err := url.Parse(req.redirect)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "the registered redirect URI will not parse", req.redirect)

		return
	}
	q := u.Query()
	q.Set("code", code)
	if req.state != "" {
		q.Set("state", req.state)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// redirectError sends an OAuth error back to the client.
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirect, state, code, desc string) {
	u, err := url.Parse(redirect)
	if err != nil {
		s.fail(w, http.StatusBadRequest, desc, "")

		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// fail shows a refusal to the PERSON, for the cases where sending it onward would mean trusting an
// address the request supplied.
func (s *Server) fail(w http.ResponseWriter, status int, message, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = errorPage.Execute(w, map[string]string{"Message": message, "Detail": detail})
}

func (s *Server) renderLogin(w http.ResponseWriter, req *request, problem string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = loginPage.Execute(w, map[string]any{
		"Request": req.id,
		"Client":  clientLabel(req.client),
		"Problem": problem,
		"Action":  pathLogin,
	})
}

func clientLabel(c Client) string {
	if c.Name != "" {
		return c.Name
	}

	return c.ID
}

// clientIP is the address an attempt came from, for the log. It is the socket's peer and nothing
// else: a header would be whatever the client chose to send.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

func (s *Server) result(op, outcome string) {
	if s.metrics == nil {
		return
	}
	s.metrics.OIDCRequests.WithLabelValues(op, outcome).Inc()
}
