package oidc

import (
	"errors"
	"time"
)

// verify checks one of this provider's own tokens and returns its subject.
//
// Only its own: the sole caller is /userinfo, which is asked with a token this provider signed
// minutes ago. There is no key discovery and no audience rule, because a check with exactly one
// issuer and one key has no use for either.
func (s *Server) verify(token string) (string, error) {
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	if err := s.sig.Verify(token, &claims); err != nil {
		return "", err
	}

	switch {
	case claims.Iss != s.cfg.Issuer:
		return "", errors.New("issued by somebody else")
	case claims.Exp == 0 || time.Now().After(time.Unix(claims.Exp, 0)):
		return "", errors.New("expired")
	case claims.Sub == "":
		return "", errors.New("no subject")
	}

	return claims.Sub, nil
}
