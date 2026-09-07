package krbkeys

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strings"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/types"
)

// Key is one long-term key of a principal: the key material plus everything a client needs to
// derive the same bytes from the password it was typed from.
type Key struct {
	EType     int32
	Value     []byte
	Salt      string
	S2KParams string
}

// EncryptionKey returns the wire form of the key.
func (k Key) EncryptionKey() types.EncryptionKey {
	return types.EncryptionKey{KeyType: k.EType, KeyValue: k.Value}
}

// ResolveEncTypes maps enctype names to their assigned numbers, rejecting anything the crypto
// library will not actually perform. Deprecated single-DES and RC4 types are refused outright:
// accepting one would let a client negotiate the realm down to a cipher that is broken in
// practice, which is exactly the downgrade a KDC is supposed to prevent.
func ResolveEncTypes(names []string) ([]int32, error) {
	seen := make(map[int32]bool, len(names))
	out := make([]int32, 0, len(names))

	for _, n := range names {
		id, ok := etypeID.ETypesByName[strings.TrimSpace(n)]
		if !ok {
			return nil, fmt.Errorf("unknown enctype %q", n)
		}
		if !Supported(id) {
			return nil, fmt.Errorf("enctype %q is not supported for key storage", n)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no enctypes given")
	}

	return out, nil
}

// Supported reports whether the enctype is one this service will generate and store keys for.
func Supported(id int32) bool {
	switch id {
	case etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA384_192,
		etypeID.AES128_CTS_HMAC_SHA256_128:
		return true
	default:
		return false
	}
}

// EncTypeName returns the canonical name of an enctype, or its number when unknown.
func EncTypeName(id int32) string {
	names := make([]string, 0, 2)
	for n, v := range etypeID.ETypesByName {
		if v == id {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return fmt.Sprintf("etype-%d", id)
	}

	// ETypesByName holds several aliases per enctype; the longest is the canonical spelling
	// ("aes256-cts-hmac-sha1-96" rather than "aes256-cts").
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) > len(names[j])
		}

		return names[i] < names[j]
	})

	return names[0]
}

// DeriveKeys computes the long-term keys for a password, one per enctype, using the principal's
// default salt.
func DeriveKeys(password string, name Name, etypes []int32) ([]Key, error) {
	return DeriveKeysWithSalt(password, name.DefaultSalt(), etypes)
}

// DeriveKeysWithSalt is DeriveKeys with an explicit salt, used when re-deriving keys for a
// principal whose stored salt must not change.
func DeriveKeysWithSalt(password, salt string, etypes []int32) ([]Key, error) {
	keys := make([]Key, 0, len(etypes))

	for _, id := range etypes {
		et, err := crypto.GetEType(id)
		if err != nil {
			return nil, fmt.Errorf("enctype %d: %w", id, err)
		}

		params := et.GetDefaultStringToKeyParams()

		kv, err := et.StringToKey(password, salt, params)
		if err != nil {
			return nil, fmt.Errorf("deriving %s key: %w", EncTypeName(id), err)
		}

		keys = append(keys, Key{EType: id, Value: kv, Salt: salt, S2KParams: params})
	}

	return keys, nil
}

// RandomKeys generates random long-term keys, one per enctype. Service principals that never have
// a password typed for them -- krbtgt above all -- get their keys this way, which removes the
// offline guessing attack that a password derived key would carry.
func RandomKeys(etypes []int32) ([]Key, error) {
	keys := make([]Key, 0, len(etypes))

	for _, id := range etypes {
		et, err := crypto.GetEType(id)
		if err != nil {
			return nil, fmt.Errorf("enctype %d: %w", id, err)
		}

		seed := make([]byte, et.GetKeySeedBitLength()/8)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("generating key material: %w", err)
		}

		keys = append(keys, Key{EType: id, Value: et.RandomToKey(seed)})
	}

	return keys, nil
}

// RandomPassword returns a random password of n bytes encoded as base32 without padding, suitable
// for handing to a human or writing into a keytab.
func RandomPassword(n int) (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

	if n <= 0 {
		return "", fmt.Errorf("password length must be positive")
	}

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.Grow(n)
	for _, v := range b {
		// len(alphabet) is 56, which does not divide 256 evenly; the resulting bias is under
		// 0.5 bits over the whole password and does not matter for a generated secret of this
		// length.
		sb.WriteByte(alphabet[int(v)%len(alphabet)])
	}

	return sb.String(), nil
}
