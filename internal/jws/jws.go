// Package jws signs and verifies the compact ES256 tokens this service issues.
//
// Two doors issue tokens — the OpenID Connect provider, and the management API when an
// administrator signs in — and they share this code but never a key. A key is named by the caller
// and lives sealed in the store under that name, so an id token a relying party holds can never be
// replayed as an administrative session: it was signed by a different key, and no audience rule has
// to be relied on to say so.
package jws

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// Signer holds one signing key and the key id it is published under.
type Signer struct {
	key *ecdsa.PrivateKey
	kid string
}

// LoadOrCreate reads the sealed key stored under metaKey, or generates and seals one on first use.
//
// The key has to SURVIVE a restart, and that is not a nicety: every token in circulation was signed
// with it, so a key invented at each start would end every session silently, as a signature that no
// longer verifies.
//
// ES256 rather than RS256: the curve key is a fraction of the size, the signature is 64 bytes, and
// RFC 7518 makes ES256 mandatory to implement, so every consumer accepts it.
func LoadOrCreate(ctx context.Context, st *store.Store, metaKey string) (*Signer, error) {
	sealed, err := st.GetMeta(ctx, metaKey)
	switch {
	case err == nil && len(sealed) > 0:
		raw, err := st.OpenSecret(sealed, metaKey)
		if err != nil {
			return nil, fmt.Errorf("open the stored signing key %s: %w", metaKey, err)
		}
		key, err := x509.ParseECPrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("parse the stored signing key %s: %w", metaKey, err)
		}

		return New(key)
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	stored, err := st.SealSecret(der, metaKey)
	if err != nil {
		return nil, err
	}
	if err := st.SetMeta(ctx, metaKey, stored); err != nil {
		return nil, err
	}

	return New(key)
}

// New wraps a key. The key id is derived from the public key, so it is stable across restarts and
// changes exactly when the key does.
func New(key *ecdsa.PrivateKey) (*Signer, error) {
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pub)

	return &Signer{key: key, kid: base64.RawURLEncoding.EncodeToString(sum[:16])}, nil
}

// KeyID is the id the key is published under.
func (s *Signer) KeyID() string { return s.kid }

// JWKS is the public half, in the shape a verifier fetches.
func (s *Signer) JWKS() map[string]any {
	return map[string]any{"keys": []map[string]any{{
		"kty": "EC",
		"crv": "P-256",
		"alg": "ES256",
		"use": "sig",
		"kid": s.kid,
		"x":   b64(s.key.PublicKey.X, 32),
		"y":   b64(s.key.PublicKey.Y, 32),
	}}}
}

// Sign produces a compact JWS over claims.
//
// Written out rather than taken from a library because it is forty lines and the alternative is a
// dependency in a service that already implements Kerberos: the whole of ES256 here is "hash the
// signing input, sign it, and write r and s as fixed-width halves". The fixed width is the part
// worth saying out loud — ECDSA values are big integers, and a verifier reading a short r as if it
// were the whole 32 bytes rejects the token.
func (s *Signer) Sign(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": s.kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)

	sum := sha256.Sum256([]byte(input))
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 0, 64)
	sig = append(sig, pad(r, 32)...)
	sig = append(sig, pad(sv, 32)...)

	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify checks that token carries this key's signature and decodes its claims into dst.
//
// It is deliberately not a general JWT verifier: there is no key discovery and no algorithm
// negotiation, because a check with exactly one key has no use for either and both are places to
// get wrong. What the claims MEAN — issuer, audience, expiry — is the caller's to decide, since only
// the caller knows which door the token is being presented at.
func (s *Signer) Verify(token string, dst any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("not a compact JWS")
	}

	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("malformed header")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil || header.Alg != "ES256" {
		// Refusing any other algorithm by name, before the signature is looked at, is what keeps
		// "alg": "none" from ever being a question.
		return errors.New("not an ES256 token")
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return errors.New("malformed signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	sv := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&s.key.PublicKey, sum[:], r, sv) {
		return errors.New("the signature is not ours")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("malformed payload")
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return errors.New("malformed claims")
	}

	return nil
}

// pad writes a big integer into exactly size bytes, left-padded with zeros.
func pad(v *big.Int, size int) []byte {
	b := v.Bytes()
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)

	return out
}

func b64(v *big.Int, size int) string { return base64.RawURLEncoding.EncodeToString(pad(v, size)) }
