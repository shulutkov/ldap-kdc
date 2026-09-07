package kdc

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/adtype"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/pac"
	"github.com/go-krb5/krb5/types"
	"github.com/go-krb5/x/encoding/asn1"
	"github.com/go-krb5/x/rpc/mstypes"
	"github.com/go-krb5/x/rpc/ndr"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// PAC info buffer types used here, from MS-PAC section 2.4.
const (
	pacTypeLogonInfo         uint32 = 1
	pacTypeServerChecksum    uint32 = 6
	pacTypeKDCChecksum       uint32 = 7
	pacTypeClientInfo        uint32 = 10
	pacTypeS4UDelegationInfo uint32 = 11
)

// Group attributes marking a membership as mandatory, enabled and enabled by default, which is
// what a normal security group carries (MS-PAC section 2.2.1).
const groupAttributesEnabled uint32 = 0x00000007

// userAccountControlNormal marks an ordinary enabled account (MS-SAMR ADS_UF_NORMAL_ACCOUNT).
const userAccountControlNormal uint32 = 0x00000010

// neverFileTime is the FILETIME Windows uses for "no expiry".
var neverFileTime = mstypes.FileTime{LowDateTime: 0xFFFFFFFF, HighDateTime: 0x7FFFFFFF}

// pacSubject is everything the PAC says about the client being issued a ticket.
type pacSubject struct {
	User      *store.User
	Principal *store.Principal
	// IDs are the relative identifiers allocated to the account and its groups. They are read
	// from the store rather than derived from the POSIX ids: uid and gid spaces are
	// independent, so deriving would hand a user and a group with the same number the same SID.
	IDs      store.SecurityIDs
	AuthTime time.Time
}

// buildPAC assembles a signed PAC for the subject. The server signature lets the target service
// confirm the KDC issued the authorization data in its ticket; the KDC signature over that
// signature lets the KDC confirm, on a later S4U2Proxy or renewal, that a service did not rewrite
// the group membership in a PAC it was handed.
func (s *Server) buildPAC(subj pacSubject, serverKey, kdcKey krbkeys.Key, delegation *pac.S4UDelegationInfo) ([]byte, error) {
	logonInfo, err := s.marshalLogonInfo(subj)
	if err != nil {
		return nil, err
	}

	clientInfo := marshalClientInfo(subj.User.Name, subj.AuthTime)

	buffers := []pacBuffer{
		{Type: pacTypeLogonInfo, Data: logonInfo},
		{Type: pacTypeClientInfo, Data: clientInfo},
	}

	if delegation != nil {
		b, err := ndr.Marshal(delegation)
		if err != nil {
			return nil, fmt.Errorf("marshalling S4U delegation info: %w", err)
		}
		buffers = append(buffers, pacBuffer{Type: pacTypeS4UDelegationInfo, Data: b})
	}

	serverSig, err := emptySignature(serverKey)
	if err != nil {
		return nil, err
	}
	kdcSig, err := emptySignature(kdcKey)
	if err != nil {
		return nil, err
	}

	buffers = append(buffers,
		pacBuffer{Type: pacTypeServerChecksum, Data: serverSig},
		pacBuffer{Type: pacTypeKDCChecksum, Data: kdcSig},
	)

	blob, offsets := assemblePAC(buffers)

	// MS-PAC 2.8.1: the server signature covers the whole PAC with both signature values
	// zeroed, and the KDC signature covers the server signature's bytes alone.
	serverStart := offsets[len(offsets)-2] + 4
	kdcStart := offsets[len(offsets)-1] + 4

	serverSum, err := checksum(serverKey, blob)
	if err != nil {
		return nil, fmt.Errorf("computing PAC server signature: %w", err)
	}
	copy(blob[serverStart:serverStart+len(serverSum)], serverSum)

	kdcSum, err := checksum(kdcKey, serverSum)
	if err != nil {
		return nil, fmt.Errorf("computing PAC KDC signature: %w", err)
	}
	copy(blob[kdcStart:kdcStart+len(kdcSum)], kdcSum)

	return blob, nil
}

// verifyPACKDCSignature checks that a PAC carried in a ticket was signed by this KDC. It is what
// makes it safe to reuse a PAC from a ticket a service presented back to us.
func verifyPACKDCSignature(blob []byte, kdcKey krbkeys.Key) error {
	var p pac.PACType
	if err := p.Unmarshal(blob); err != nil {
		return fmt.Errorf("parsing PAC: %w", err)
	}

	var serverSig, kdcSig []byte

	for _, b := range p.Buffers {
		start, end, ok := bufferBounds(b.Offset, b.CBBufferSize, len(blob))
		if !ok {
			return fmt.Errorf("PAC buffer of type %d lies outside the PAC", b.ULType)
		}

		switch b.ULType {
		case pacTypeServerChecksum:
			serverSig = blob[start:end]
		case pacTypeKDCChecksum:
			kdcSig = blob[start:end]
		}
	}

	if len(serverSig) < 4 || len(kdcSig) < 4 {
		return fmt.Errorf("PAC is missing its signatures")
	}

	et, err := crypto.GetChecksumEType(int32(binary.LittleEndian.Uint32(kdcSig[:4])))
	if err != nil {
		return fmt.Errorf("PAC KDC signature type: %w", err)
	}

	want, err := et.GetChecksumHash(kdcKey.Value, serverSig[4:], uint32(keyusage.KERB_NON_KERB_CKSUM_SALT))
	if err != nil {
		return fmt.Errorf("computing PAC KDC signature: %w", err)
	}

	if !bytes.Equal(want, kdcSig[4:4+len(want)]) {
		return fmt.Errorf("PAC KDC signature does not verify")
	}

	return nil
}

// resignPAC re-signs an existing PAC for a new target service, leaving its contents alone. This is
// the path a cross-realm client takes: the authorization data was authored by the client's own
// realm and this KDC only vouches for having relayed it unchanged.
func resignPAC(blob []byte, serverKey, kdcKey krbkeys.Key) ([]byte, error) {
	var p pac.PACType
	if err := p.Unmarshal(blob); err != nil {
		return nil, fmt.Errorf("parsing PAC: %w", err)
	}

	out := make([]byte, len(blob))
	copy(out, blob)

	var serverStart, serverEnd, kdcStart, kdcEnd int

	for _, b := range p.Buffers {
		start, end, ok := bufferBounds(b.Offset, b.CBBufferSize, len(out))
		if !ok {
			return nil, fmt.Errorf("PAC buffer of type %d lies outside the PAC", b.ULType)
		}

		switch b.ULType {
		case pacTypeServerChecksum:
			serverStart, serverEnd = start, end
		case pacTypeKDCChecksum:
			kdcStart, kdcEnd = start, end
		}
	}

	if serverEnd-serverStart < 4 || kdcEnd-kdcStart < 4 {
		return nil, fmt.Errorf("PAC is missing its signatures")
	}

	// Rewrite both signature buffers with this realm's checksum types, zeroed, then sign.
	newServer, err := emptySignature(serverKey)
	if err != nil {
		return nil, err
	}
	newKDC, err := emptySignature(kdcKey)
	if err != nil {
		return nil, err
	}

	if len(newServer) != serverEnd-serverStart || len(newKDC) != kdcEnd-kdcStart {
		// A differently sized signature would shift every later buffer, so the PAC would have
		// to be rebuilt rather than patched. Refusing keeps this path honest.
		return nil, fmt.Errorf("cannot re-sign a PAC whose signature sizes differ from this realm's")
	}

	copy(out[serverStart:serverEnd], newServer)
	copy(out[kdcStart:kdcEnd], newKDC)

	serverSum, err := checksum(serverKey, out)
	if err != nil {
		return nil, fmt.Errorf("computing PAC server signature: %w", err)
	}
	copy(out[serverStart+4:serverEnd], serverSum)

	kdcSum, err := checksum(kdcKey, serverSum)
	if err != nil {
		return nil, fmt.Errorf("computing PAC KDC signature: %w", err)
	}
	copy(out[kdcStart+4:kdcEnd], kdcSum)

	return out, nil
}

// marshalLogonInfo renders the KERB_VALIDATION_INFO that carries the account's identity and group
// membership as NDR.
func (s *Server) marshalLogonInfo(subj pacSubject) ([]byte, error) {
	sid, err := parseSID(s.cfg.DomainSID)
	if err != nil {
		return nil, err
	}

	groups := make([]mstypes.GroupMembership, 0, len(subj.IDs.Groups))
	for _, rid := range subj.IDs.Groups {
		groups = append(groups, mstypes.GroupMembership{
			RelativeID: uint32(rid),
			Attributes: groupAttributesEnabled,
		})
	}

	fullName := strings.TrimSpace(subj.User.GivenName + " " + subj.User.SN)
	if len(fullName) == 0 {
		fullName = subj.User.Name
	}

	passwordLastSet := mstypes.FileTime{}
	if subj.Principal != nil && subj.Principal.PasswordLastSet != nil {
		passwordLastSet = mstypes.GetFileTime(*subj.Principal.PasswordLastSet)
	}

	passwordMustChange := neverFileTime
	if subj.Principal != nil && subj.Principal.PasswordExpiresAt != nil {
		passwordMustChange = mstypes.GetFileTime(*subj.Principal.PasswordExpiresAt)
	}

	info := pac.KerbValidationInfo{
		LogOnTime:          mstypes.GetFileTime(subj.AuthTime),
		LogOffTime:         neverFileTime,
		KickOffTime:        neverFileTime,
		PasswordLastSet:    passwordLastSet,
		PasswordCanChange:  mstypes.FileTime{},
		PasswordMustChange: passwordMustChange,
		EffectiveName:      unicodeString(subj.User.Name),
		FullName:           unicodeString(fullName),
		LogonScript:        unicodeString(""),
		ProfilePath:        unicodeString(""),
		HomeDirectory:      unicodeString(subj.User.Homedir),
		HomeDirectoryDrive: unicodeString(""),
		UserID:             uint32(subj.IDs.User),
		PrimaryGroupID:     uint32(subj.IDs.PrimaryGroup),
		GroupCount:         uint32(len(groups)),
		GroupIDs:           groups,
		UserSessionKey:     mstypes.UserSessionKey{},
		LogonServer:        unicodeString(s.cfg.NetBIOSName),
		LogonDomainName:    unicodeString(s.cfg.NetBIOSName),
		LogonDomainID:      sid,
		UserAccountControl: userAccountControlNormal,
	}

	b, err := ndr.Marshal(&info)
	if err != nil {
		return nil, fmt.Errorf("marshalling PAC logon info: %w", err)
	}

	return b, nil
}

// marshalClientInfo renders PAC_CLIENT_INFO, which is a plain little-endian structure rather than
// NDR: the TGT authentication time and the account name in UTF-16.
func marshalClientInfo(name string, authTime time.Time) []byte {
	nameBytes := utf16LE(name)

	buf := new(bytes.Buffer)
	ft := mstypes.GetFileTime(authTime)
	_ = binary.Write(buf, binary.LittleEndian, ft.LowDateTime)
	_ = binary.Write(buf, binary.LittleEndian, ft.HighDateTime)
	_ = binary.Write(buf, binary.LittleEndian, uint16(len(nameBytes)))
	buf.Write(nameBytes)

	return buf.Bytes()
}

// pacBuffer is one info buffer awaiting placement in the PAC.
type pacBuffer struct {
	Type uint32
	Data []byte
}

// assemblePAC lays out the PACTYPE header, the buffer descriptors and the buffers themselves,
// padding each buffer to the 8 byte alignment MS-PAC requires. It returns the blob and the offset
// each buffer landed at.
func assemblePAC(buffers []pacBuffer) ([]byte, []int) {
	const headerLen = 8
	const descriptorLen = 16

	offset := headerLen + descriptorLen*len(buffers)
	offset = align8(offset)

	offsets := make([]int, len(buffers))
	total := offset

	for i, b := range buffers {
		offsets[i] = total
		total = align8(total + len(b.Data))
	}

	out := make([]byte, total)

	binary.LittleEndian.PutUint32(out[0:4], uint32(len(buffers)))
	binary.LittleEndian.PutUint32(out[4:8], 0) // Version

	for i, b := range buffers {
		d := headerLen + descriptorLen*i
		binary.LittleEndian.PutUint32(out[d:d+4], b.Type)
		binary.LittleEndian.PutUint32(out[d+4:d+8], uint32(len(b.Data)))
		binary.LittleEndian.PutUint64(out[d+8:d+16], uint64(offsets[i]))
		copy(out[offsets[i]:], b.Data)
	}

	return out, offsets
}

// bufferBounds resolves a PAC info buffer descriptor against the blob it points into. The library
// checks this while parsing but does not export the result, and an offset or size out of range
// would otherwise slice out of bounds.
func bufferBounds(offset uint64, size uint32, total int) (start, end int, ok bool) {
	if total < 0 || offset > uint64(total) || uint64(size) > uint64(total)-offset {
		return 0, 0, false
	}

	return int(offset), int(offset) + int(size), true
}

func align8(n int) int {
	if r := n % 8; r != 0 {
		return n + (8 - r)
	}

	return n
}

// emptySignature builds a signature buffer for the key's checksum type with a zeroed value, ready
// to be filled in once the PAC is laid out.
func emptySignature(k krbkeys.Key) ([]byte, error) {
	et, err := crypto.GetEType(k.EType)
	if err != nil {
		return nil, fmt.Errorf("signature enctype %d: %w", k.EType, err)
	}

	size := et.GetHMACBitLength() / 8

	buf := make([]byte, 4+size)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(et.GetHashID()))

	return buf, nil
}

// checksum computes the keyed checksum a PAC signature uses.
func checksum(k krbkeys.Key, data []byte) ([]byte, error) {
	et, err := crypto.GetEType(k.EType)
	if err != nil {
		return nil, err
	}

	return et.GetChecksumHash(k.Value, data, uint32(keyusage.KERB_NON_KERB_CKSUM_SALT))
}

// unicodeString wraps a Go string as the RPC_UNICODE_STRING the PAC expects, with lengths counted
// in bytes as MS-DTYP requires.
func unicodeString(s string) mstypes.RPCUnicodeString {
	n := uint16(len(utf16.Encode([]rune(s))) * 2)

	return mstypes.RPCUnicodeString{Length: n, MaximumLength: n, Value: s}
}

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)

	for i, r := range u {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}

	return out
}

// parseSID turns "S-1-5-21-a-b-c" into the RPC_SID the PAC carries.
func parseSID(s string) (mstypes.RPCSID, error) {
	parts := strings.Split(strings.TrimSpace(s), "-")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "S") {
		return mstypes.RPCSID{}, fmt.Errorf("malformed SID %q", s)
	}

	rev, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return mstypes.RPCSID{}, fmt.Errorf("malformed SID revision in %q: %w", s, err)
	}

	auth, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return mstypes.RPCSID{}, fmt.Errorf("malformed SID authority in %q: %w", s, err)
	}

	subs := make([]uint32, 0, len(parts)-3)
	for _, p := range parts[3:] {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return mstypes.RPCSID{}, fmt.Errorf("malformed SID sub-authority in %q: %w", s, err)
		}
		subs = append(subs, uint32(v))
	}

	if len(subs) > 15 {
		return mstypes.RPCSID{}, fmt.Errorf("SID %q has more than 15 sub-authorities", s)
	}

	var ia [6]byte
	// The identifier authority is stored big endian, unlike everything else in the structure.
	for i := range ia {
		ia[5-i] = byte(auth >> (8 * i))
	}

	return mstypes.RPCSID{
		Revision:            uint8(rev),
		SubAuthorityCount:   uint8(len(subs)),
		IdentifierAuthority: ia,
		SubAuthority:        subs,
	}, nil
}

// authorizationData builds the authorization data to seal into a ticket: an AD-IF-RELEVANT
// wrapping the Microsoft PAC. Wrapping it in AD-IF-RELEVANT is what lets a service that does not
// understand the PAC ignore it instead of rejecting the ticket (RFC 4120 section 5.2.6.1).
func (s *Server) authorizationData(
	ctx context.Context,
	client *store.Principal,
	clientName krbkeys.Name,
	server *store.Principal,
	authTime time.Time,
	delegation *pac.S4UDelegationInfo,
) (types.AuthorizationData, *protocolError) {
	if !s.cfg.IssuePAC || client.UserID == nil {
		return nil, nil
	}

	user, err := s.st.GetUserByID(ctx, *client.UserID)
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not load account for PAC", err)
	}

	gids, err := s.st.UserGIDs(ctx, user)
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not resolve group membership for PAC", err)
	}

	ids, ok, err := s.st.SecurityIDsForUser(ctx, user, gids)
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not resolve security identifiers", err)
	}
	if !ok {
		// The account sits outside the realm's identifier range, so there is no SID that
		// means it. Issuing a PAC with a made-up one would name a different account to a
		// member server, so the ticket goes out without authorization data instead.
		s.log.Warn().Str("principal", clientName.String()).Int("uidNumber", user.UIDNumber).
			Msg("no security identifier for this account, issuing the ticket without a PAC")

		return nil, nil
	}

	serverKey, ok := selectKey(server, s.cfg.EncTypes, nil)
	if !ok {
		return nil, krbErr(errorcode.KDC_ERR_SVC_UNAVAILABLE, "service principal holds no usable key")
	}

	kdcKey, perr := s.krbtgtKey(ctx)
	if perr != nil {
		return nil, perr
	}

	blob, err := s.buildPAC(pacSubject{
		User:      user,
		Principal: client,
		IDs:       ids,
		AuthTime:  authTime,
	}, serverKey, kdcKey, delegation)
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not build PAC", err)
	}

	return wrapPAC(blob)
}

// wrapPAC places a PAC blob inside the AD-IF-RELEVANT container a ticket carries.
func wrapPAC(blob []byte) (types.AuthorizationData, *protocolError) {
	inner := types.AuthorizationData{{ADType: adtype.ADWin2KPAC, ADData: blob}}

	b, err := asn1.Marshal(inner,
		asn1.WithMarshalSlicePreserveTypes(true),
		asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not marshal PAC authorization data", err)
	}

	return types.AuthorizationData{{ADType: adtype.ADIfRelevant, ADData: b}}, nil
}

// extractPAC finds the PAC inside a ticket's authorization data, if it carries one.
func extractPAC(ad types.AuthorizationData) ([]byte, error) {
	for _, entry := range ad {
		switch entry.ADType {
		case adtype.ADWin2KPAC:
			return entry.ADData, nil
		case adtype.ADIfRelevant:
			var inner types.AuthorizationData
			if err := inner.Unmarshal(entry.ADData); err != nil {
				return nil, fmt.Errorf("parsing AD-IF-RELEVANT: %w", err)
			}

			if blob, err := extractPAC(inner); err != nil || blob != nil {
				return blob, err
			}
		}
	}

	return nil, nil
}

// krbtgtKey returns the key of the realm's ticket-granting principal, which signs every PAC.
func (s *Server) krbtgtKey(ctx context.Context) (krbkeys.Key, *protocolError) {
	tgt, err := s.st.GetPrincipal(ctx, s.tgsName())
	if err != nil {
		return krbkeys.Key{}, krbErrf(errorcode.KRB_ERR_GENERIC, "ticket-granting principal is unavailable", err)
	}

	k, ok := selectKey(tgt, s.cfg.EncTypes, nil)
	if !ok {
		return krbkeys.Key{}, krbErr(errorcode.KDC_ERR_SVC_UNAVAILABLE,
			"ticket-granting principal holds no usable key")
	}

	return k, nil
}
