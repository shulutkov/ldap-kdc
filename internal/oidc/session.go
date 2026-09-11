package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// cookieName carries the browser session. It is the whole point of this provider: without a
// session every client asks for a password again, however recently the person typed one.
const cookieName = "ldap_kdc_session"

// session is one signed-in browser.
//
// It holds a NAME and not a user record: the directory is the authority and may disable the
// account or change its groups between one client and the next, so every authorization re-reads it
// rather than trusting what was true at sign-in.
type session struct {
	id       string
	subject  string
	signedIn time.Time
	lastUsed time.Time
}

// sessions is the live set. In memory on purpose: this is one process, a session is worth one
// password entry, and a restart of the directory is not a moment to be preserving browser state
// through. Codes are the same, and for the same reason.
type sessions struct {
	mu       sync.Mutex
	byID     map[string]*session
	lifetime time.Duration // absolute: how long a sign-in is good for however active
	idle     time.Duration // how long it survives without being used
	now      func() time.Time
}

func newSessions(lifetime, idle time.Duration) *sessions {
	return &sessions{
		byID:     map[string]*session{},
		lifetime: lifetime,
		idle:     idle,
		now:      time.Now,
	}
}

// start records a sign-in and returns the session to set a cookie for.
func (s *sessions) start(subject string) (*session, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	now := s.now()
	sess := &session{id: id, subject: subject, signedIn: now, lastUsed: now}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[id] = sess
	s.sweepLocked(now)

	return sess, nil
}

// get returns the live session for a request, touching it so the idle window restarts.
func (s *sessions) get(r *http.Request) (*session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.byID[c.Value]
	if !ok {
		return nil, false
	}
	now := s.now()
	if s.expiredLocked(sess, now) {
		delete(s.byID, sess.id)

		return nil, false
	}
	sess.lastUsed = now

	return sess, true
}

// end drops the session a request carries, if any.
func (s *sessions) end(r *http.Request) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, c.Value)
}

func (s *sessions) expiredLocked(sess *session, now time.Time) bool {
	if s.lifetime > 0 && now.Sub(sess.signedIn) > s.lifetime {
		return true
	}

	return s.idle > 0 && now.Sub(sess.lastUsed) > s.idle
}

// sweepLocked drops what has expired. Called on the way in rather than on a timer: the set is
// small, and a provider nobody is using should not be waking up to tidy it.
func (s *sessions) sweepLocked(now time.Time) {
	for id, sess := range s.byID {
		if s.expiredLocked(sess, now) {
			delete(s.byID, id)
		}
	}
}

// setCookie writes the session cookie.
//
// SameSite=Lax and not Strict: coming back from a relying party IS a cross-site top-level
// navigation, and Strict would withhold the cookie exactly then — every sign-in would look like
// the first one. Secure follows the issuer, because a cookie marked Secure is simply not sent over
// the plain HTTP a test stand may be using.
func setCookie(w http.ResponseWriter, sess *session, secure bool, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    sess.id,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge.Seconds()),
	})
}

// clearCookie removes it.
func clearCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// randomID is 256 bits of randomness: a session id is a bearer credential for as long as it lives,
// and guessing one is signing in as somebody else.
func randomID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
