// Package secret seals the Kerberos key material that the store keeps on disk.
//
// A KDC cannot hash its principals' keys the way a password database does: it has to reproduce the
// exact long-term key to decrypt a client's pre-authentication and to encrypt a ticket. The keys
// are therefore reversible by construction, and the only protection left is to encrypt them with a
// key that lives outside the database file, so that a stolen or backed-up .db is not by itself a
// stolen realm.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// KeySize is the length of the master key in bytes (AES-256).
const KeySize = 32

// Sealer encrypts and decrypts key material with the master key.
type Sealer struct {
	aead cipher.AEAD
}

// LoadOrCreateMasterKey reads the master key from path, creating it with 0600 permissions if the
// file does not exist. It reports whether the key was newly generated.
func LoadOrCreateMasterKey(path string) (key []byte, created bool, err error) {
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(b) != KeySize {
			return nil, false, fmt.Errorf("master key %s is %d bytes, want %d", path, len(b), KeySize)
		}
		return b, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, fmt.Errorf("reading master key: %w", err)
	}

	if dir := filepath.Dir(path); len(dir) > 0 && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, false, fmt.Errorf("creating master key directory: %w", err)
		}
	}

	key = make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, false, fmt.Errorf("generating master key: %w", err)
	}

	// O_EXCL so that two processes racing to initialize the same deployment cannot each write a
	// different key and leave half the database undecryptable.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("creating master key: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Write(key); err != nil {
		return nil, false, fmt.Errorf("writing master key: %w", err)
	}
	if err := f.Sync(); err != nil {
		return nil, false, fmt.Errorf("syncing master key: %w", err)
	}

	return key, true, nil
}

// NewSealer returns a Sealer over the given master key.
func NewSealer(masterKey []byte) (*Sealer, error) {
	if len(masterKey) != KeySize {
		return nil, fmt.Errorf("master key is %d bytes, want %d", len(masterKey), KeySize)
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext, binding it to context so that a ciphertext lifted from one principal's
// row cannot be replayed into another's. The nonce is prepended to the returned bytes.
func (s *Sealer) Seal(plaintext []byte, context string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	return s.aead.Seal(nonce, nonce, plaintext, []byte(context)), nil
}

// Open reverses Seal. The context must match the one given to Seal.
func (s *Sealer) Open(ciphertext []byte, context string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(ciphertext) < n {
		return nil, errors.New("sealed value is too short")
	}

	plaintext, err := s.aead.Open(nil, ciphertext[:n], ciphertext[n:], []byte(context))
	if err != nil {
		return nil, fmt.Errorf("opening sealed value (wrong master key?): %w", err)
	}

	return plaintext, nil
}
