package store

import "encoding/base64"

// SealSecret protects an arbitrary value with the store's master key and returns it as text, so it
// can be kept in the metadata table beside values that need no protection.
//
// The context string is bound into the seal: a ciphertext lifted from one key's row cannot be
// opened as another's, which is what keeps "sealed" from meaning only "encrypted with the same key
// as everything else".
func (s *Store) SealSecret(plaintext []byte, context string) (string, error) {
	sealed, err := s.sealer.Seal(plaintext, context)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenSecret reverses SealSecret. The context must be the one it was sealed under.
func (s *Store) OpenSecret(text, context string) ([]byte, error) {
	sealed, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}

	return s.sealer.Open(sealed, context)
}
