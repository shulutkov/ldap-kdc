package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// authCode is an issued authorization code, held until it is exchanged.
//
// Everything the exchange must agree with is recorded at issue: the client it was issued to, the
// redirect it was issued for, and the PKCE challenge. A code that carried none of this could be
// replayed by whoever intercepted the redirect.
type authCode struct {
	code      string
	clientID  string
	redirect  string
	challenge string
	subject   string
	nonce     string
	authTime  time.Time
	issued    time.Time
}

// codes are the outstanding authorization codes.
type codes struct {
	mu      sync.Mutex
	byCode  map[string]*authCode
	timeout time.Duration
	now     func() time.Time
}

func newCodes(timeout time.Duration) *codes {
	return &codes{byCode: map[string]*authCode{}, timeout: timeout, now: time.Now}
}

func (c *codes) issue(a *authCode) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	a.code = id
	a.issued = c.now()

	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.byCode {
		if c.now().Sub(v.issued) > c.timeout {
			delete(c.byCode, k)
		}
	}
	c.byCode[id] = a

	return id, nil
}

// take returns the code and REMOVES it, whatever happens next. A code is good once: if the
// exchange that follows fails on the verifier or the redirect, the right answer is still that this
// code is spent, because the only party who should have had it has now used it.
func (c *codes) take(code string) (*authCode, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	a, ok := c.byCode[code]
	if !ok {
		return nil, false
	}
	delete(c.byCode, code)

	if c.now().Sub(a.issued) > c.timeout {
		return nil, false
	}

	return a, true
}

// verifyPKCE checks a code verifier against the challenge recorded at issue.
//
// S256 only. The plain method is in the RFC and is worth nothing here: it proves the exchanging
// party saw the challenge, which is exactly what an interceptor of the authorization request saw
// too.
func verifyPKCE(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	return subtle.ConstantTimeCompare([]byte(challenge), []byte(want)) == 1
}
