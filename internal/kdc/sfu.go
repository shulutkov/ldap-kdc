package kdc

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
	"github.com/go-krb5/x/encoding/asn1"
)

// optionCNameInAddlTkt is KDC option bit 14, which MS-SFU calls constrained-delegation: the client
// named in the additional ticket, not the one in the TGT, is the subject of the request. The
// library's flag constants stop short of it because RFC 4120 leaves the bit unassigned.
const optionCNameInAddlTkt = 14

// paForUser is the PA-FOR-USER pre-authentication datum of MS-SFU section 2.2.1. A service sends
// it to ask for a ticket to itself on behalf of a user it has authenticated by some other means,
// which is what makes protocol transition possible.
type paForUser struct {
	UserName    types.PrincipalName `asn1:"explicit,tag:0"`
	UserRealm   string              `asn1:"generalstring,explicit,tag:1"`
	Cksum       types.Checksum      `asn1:"explicit,tag:2"`
	AuthPackage string              `asn1:"generalstring,explicit,tag:3"`
}

func (p *paForUser) unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, p, asn1.WithUnmarshalAllowTypeGeneralString(true))

	return err
}

// checksumData is the byte string the PA-FOR-USER checksum covers: the name type as a little
// endian 32 bit integer, then every name component, the realm and the auth package, concatenated
// with no separators (MS-SFU section 2.2.1).
func (p *paForUser) checksumData() []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(p.UserName.NameType))

	for _, c := range p.UserName.NameString {
		out = append(out, c...)
	}
	out = append(out, p.UserRealm...)
	out = append(out, p.AuthPackage...)

	return out
}

// verify checks the PA-FOR-USER checksum against the TGT session key. The checksum is the only
// thing tying the request to the service that holds the TGT; without it any client could ask for a
// ticket in any user's name.
func (p *paForUser) verify(sessionKey types.EncryptionKey) error {
	data := p.checksumData()

	if p.Cksum.CksumType == chksumtype.KERB_CHECKSUM_HMAC_MD5 {
		want := hmacMD5Checksum(sessionKey.KeyValue, keyusage.KERB_NON_KERB_CKSUM_SALT, data)
		if !hmac.Equal(want, p.Cksum.Checksum) {
			return fmt.Errorf("PA-FOR-USER checksum does not verify")
		}

		return nil
	}

	et, err := crypto.GetChecksumEType(p.Cksum.CksumType)
	if err != nil {
		return fmt.Errorf("PA-FOR-USER checksum type %d: %w", p.Cksum.CksumType, err)
	}

	if !et.VerifyChecksum(sessionKey.KeyValue, data, p.Cksum.Checksum, keyusage.KERB_NON_KERB_CKSUM_SALT) {
		return fmt.Errorf("PA-FOR-USER checksum does not verify")
	}

	return nil
}

// hmacMD5Checksum implements the KERB_CHECKSUM_HMAC_MD5 of RFC 4757 section 4.
//
// It is implemented here rather than taken from the crypto registry because reaching it there
// means registering the whole deprecated RC4-HMAC enctype, which would then be available for
// clients to negotiate for encryption. This realm refuses RC4 keys; only the checksum survives,
// and only because MS-SFU pins PA-FOR-USER to it regardless of the session key's own enctype.
func hmacMD5Checksum(key []byte, usage uint32, data []byte) []byte {
	sig := hmac.New(md5.New, key)
	sig.Write([]byte("signaturekey\x00"))
	ksign := sig.Sum(nil)

	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], translateUsage(usage))

	inner := md5.New()
	inner.Write(t[:])
	inner.Write(data)

	outer := hmac.New(md5.New, ksign)
	outer.Write(inner.Sum(nil))

	return outer.Sum(nil)
}

// translateUsage maps Kerberos key usage numbers onto the message types RFC 4757 was written
// against, matching the mapping every other implementation applies.
func translateUsage(usage uint32) uint32 {
	switch usage {
	case 3, 9:
		return 8
	case 23:
		return 13
	default:
		return usage
	}
}
