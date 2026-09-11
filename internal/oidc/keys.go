package oidc

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

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// MetaSigningKey is where the token signing key lives, sealed with the master key like every other
// secret in the database.
//
// It has to SURVIVE a restart, and that is not a nicety: the key is what JWKS publishes and what
// every issued token was signed with, so a key invented at each start invalidates every live
// session and every token a relying party is still holding — silently, as a signature that no
// longer verifies.
const MetaSigningKey = "oidc_signing_key"

// signer holds the key tokens are signed with and the key id JWKS publishes it under.
type signer struct {
	key *ecdsa.PrivateKey
	kid string
}

// loadOrCreateSigner reads the sealed signing key, or generates and seals one on first use.
//
// ES256 rather than RS256: the curve key is a fraction of the size, the signature is 64 bytes, and
// every consumer of this service already accepts it (RFC 7518 makes ES256 mandatory to implement
// for JWS).
func loadOrCreateSigner(ctx context.Context, st *store.Store) (*signer, error) {
	sealed, err := st.GetMeta(ctx, MetaSigningKey)
	switch {
	case err == nil && sealed != "":
		raw, err := st.OpenSecret(sealed, MetaSigningKey)
		if err != nil {
			return nil, fmt.Errorf("open the stored signing key: %w", err)
		}
		key, err := x509.ParseECPrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("parse the stored signing key: %w", err)
		}
		return newSigner(key)
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
	stored, err := st.SealSecret(der, MetaSigningKey)
	if err != nil {
		return nil, err
	}
	if err := st.SetMeta(ctx, MetaSigningKey, stored); err != nil {
		return nil, err
	}

	return newSigner(key)
}

// newSigner derives the key id from the public key, so it is stable across restarts and changes
// exactly when the key does.
func newSigner(key *ecdsa.PrivateKey) (*signer, error) {
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pub)

	return &signer{key: key, kid: base64.RawURLEncoding.EncodeToString(sum[:16])}, nil
}

// jwks is the public half, in the shape a verifier fetches.
func (s *signer) jwks() map[string]any {
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

// sign produces a compact JWS over claims.
//
// Written out rather than taken from a library because it is forty lines and the alternative is a
// dependency in a service that already implements Kerberos: the whole of ES256 here is "hash the
// signing input, sign it, and write r and s as fixed-width halves". The fixed width is the part
// worth saying out loud — ECDSA values are big integers, and a verifier reading a short r as if it
// were the whole 32 bytes rejects the token.
func (s *signer) sign(claims map[string]any) (string, error) {
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
