package oidc

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

// verify checks one of this provider's own tokens and returns its subject.
//
// Only its own: the sole caller is /userinfo, which is asked with a token this provider signed
// minutes ago. It is deliberately not a general JWT verifier — there is no key discovery, no
// algorithm negotiation and no audience rule, because all three would be places to get wrong for
// a check that has exactly one issuer and one key.
func (s *Server) verify(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("not a compact JWS")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return "", errors.New("malformed signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	sv := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&s.sig.key.PublicKey, sum[:], r, sv) {
		return "", errors.New("the signature is not ours")
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("malformed payload")
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", errors.New("malformed claims")
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
