package kdc

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/asn1apptag"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
	"github.com/go-krb5/x/encoding/asn1"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// handleASReq runs the AS exchange: it authenticates the client with its long-term key and issues
// a ticket for the requested service, normally the realm's ticket-granting service.
func (s *Server) handleASReq(ctx context.Context, raw []byte, from net.Addr) ([]byte, *protocolError) {
	var req messages.ASReq
	if err := req.Unmarshal(raw); err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "malformed AS-REQ", err)
	}

	body := &req.ReqBody
	now := time.Now().UTC()

	if !strings.EqualFold(body.Realm, s.cfg.Realm) {
		return nil, krbErr(errorcode.KDC_ERR_WRONG_REALM, "this KDC serves realm %s", s.cfg.Realm)
	}
	if len(body.CName.NameString) == 0 {
		return nil, krbErr(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, "request carries no client name")
	}

	clientName := krbkeys.NameFromPrincipalName(body.CName, s.cfg.Realm)

	serverName := s.tgsName()
	if len(body.SName.NameString) > 0 {
		serverName = krbkeys.NameFromPrincipalName(body.SName, s.cfg.Realm)
	}

	client, err := s.st.GetPrincipal(ctx, clientName)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, withClient(krbErr(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN,
				"no principal %s", clientName), clientName)
		}

		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "internal error", err)
	}

	server, err := s.st.GetPrincipal(ctx, serverName)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, withClient(krbErr(errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
				"no principal %s", serverName), clientName)
		}

		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "internal error", err)
	}

	if status := client.Status(now); status != store.PrincipalOK {
		return nil, withClient(clientStatusError(status), clientName)
	}
	if status := server.Status(now); status != store.PrincipalOK {
		return nil, withClient(serverStatusError(status), clientName)
	}

	// An expired password still has to buy a ticket for the password changing service, or the
	// user would have no way to fix it without an administrator.
	if client.PasswordExpired(now) && !serverName.IsChangePW() {
		return nil, withClient(krbErr(errorcode.KDC_ERR_KEY_EXPIRED,
			"password expired, change it against kadmin/changepw"), clientName)
	}

	sessionEType, ok := s.selectSessionEType(body.EType)
	if !ok {
		return nil, withClient(krbErr(errorcode.KDC_ERR_ETYPE_NOSUPP,
			"no enctype in common with the KDC"), clientName)
	}

	replyKey, ok := selectKey(client, s.cfg.EncTypes, body.EType)
	if !ok {
		return nil, withClient(krbErr(errorcode.KDC_ERR_ETYPE_NOSUPP,
			"principal holds no key of an enctype the client offered"), clientName)
	}

	preAuthDone, perr := s.checkPreAuth(ctx, &req, client, clientName, body, now)
	if perr != nil {
		return nil, perr
	}

	if preAuthDone {
		if err := s.st.RecordAuthResult(ctx, client.ID, true, s.cfg.Lockout); err != nil {
			s.log.Warn().Err(err).Str("principal", clientName.String()).Msg("could not record successful authentication")
		}
	}

	times, perr := s.computeTimes(body, client, server, now)
	if perr != nil {
		return nil, withClient(perr, clientName)
	}

	tktFlags := ticketFlags(body, client, server, times, true, preAuthDone)

	authzData, perr := s.authorizationData(ctx, client, clientName, server, times.AuthTime, nil)
	if perr != nil {
		return nil, withClient(perr, clientName)
	}

	serverKey, ok := selectKey(server, s.cfg.EncTypes, nil)
	if !ok {
		return nil, withClient(krbErr(errorcode.KDC_ERR_SVC_UNAVAILABLE,
			"service principal holds no usable key"), clientName)
	}

	tkt, sessionKey, err := mintTicket(ticketSpec{
		Client:            clientName,
		Server:            serverName,
		ServerKey:         serverKey,
		ServerKVNO:        server.KVNO,
		SessionEType:      sessionEType,
		Flags:             tktFlags,
		AuthTime:          times.AuthTime,
		StartTime:         times.StartTime,
		EndTime:           times.EndTime,
		RenewTill:         times.RenewTill,
		Addresses:         body.Addresses,
		AuthorizationData: authzData,
	})
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not issue ticket", err)
	}

	encPart := messages.EncKDCRepPart{
		Key:       sessionKey,
		LastReqs:  []messages.LastReq{{LRType: 0, LRValue: now}},
		Nonce:     body.Nonce,
		Flags:     tktFlags,
		AuthTime:  times.AuthTime,
		StartTime: times.StartTime,
		EndTime:   times.EndTime,
		RenewTill: times.RenewTill,
		SRealm:    serverName.Realm,
		SName:     serverName.PrincipalName(),
		CAddr:     body.Addresses,
	}

	if client.PasswordExpiresAt != nil {
		encPart.KeyExpiration = *client.PasswordExpiresAt
	}

	encBytes, err := marshalEncKDCRepPart(&encPart, asn1apptag.EncASRepPart)
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not build reply", err)
	}

	encData, err := crypto.GetEncryptedData(encBytes, replyKey.EncryptionKey(), keyusage.AS_REP_ENCPART, client.KVNO)
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not encrypt reply", err)
	}

	paData, err := s.etypeInfo2PAData(client, body.EType)
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not build reply", err)
	}

	rep := messages.ASRep{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_AS_REP,
		PAData:  paData,
		CRealm:  clientName.Realm,
		CName:   clientName.PrincipalName(),
		Ticket:  tkt,
		EncPart: encData,
	}

	out, err := rep.Marshal()
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not marshal reply", err)
	}

	s.metrics.KDCTicketsIssued.WithLabelValues("tgt").Inc()
	s.log.Info().
		Str("client", clientName.String()).
		Str("server", serverName.String()).
		Str("from", addrString(from)).
		Bool("preauth", preAuthDone).
		Time("expires", times.EndTime).
		Msg("AS-REP issued")

	return out, nil
}

// checkPreAuth validates PA-ENC-TIMESTAMP, the proof that the client knows its own key.
//
// Without it the KDC would hand anyone an AS-REP encrypted in the account's long-term key, which is
// an offline password cracking target; that is why a missing pre-authentication is answered with
// KDC_ERR_PREAUTH_REQUIRED and the salt hints rather than with a ticket.
func (s *Server) checkPreAuth(
	ctx context.Context,
	req *messages.ASReq,
	client *store.Principal,
	clientName krbkeys.Name,
	body *messages.KDCReqBody,
	now time.Time,
) (bool, *protocolError) {
	var pa *types.PAData

	for i := range req.PAData {
		if req.PAData[i].PADataType == patype.PA_ENC_TIMESTAMP {
			pa = &req.PAData[i]

			break
		}
	}

	required := s.cfg.RequirePreAuth || client.RequiresPreAuth

	if pa == nil {
		if !required {
			return false, nil
		}

		edata, err := s.preAuthHint(client, body.EType)
		if err != nil {
			return false, krbErrf(errorcode.KRB_ERR_GENERIC, "could not build pre-authentication hint", err)
		}

		return false, &protocolError{
			Code:   errorcode.KDC_ERR_PREAUTH_REQUIRED,
			EText:  "pre-authentication required",
			EData:  edata,
			Client: &clientName,
		}
	}

	var ts types.PAEncTimestamp
	if err := ts.Unmarshal(pa.PADataValue); err != nil {
		return false, withClient(krbErrf(errorcode.KDC_ERR_PREAUTH_FAILED,
			"malformed pre-authentication data", err), clientName)
	}

	key, ok := client.KeyFor(ts.EType)
	if !ok {
		edata, err := s.preAuthHint(client, body.EType)
		if err != nil {
			return false, krbErrf(errorcode.KRB_ERR_GENERIC, "could not build pre-authentication hint", err)
		}

		return false, &protocolError{
			Code:   errorcode.KDC_ERR_PREAUTH_FAILED,
			EText:  "pre-authentication used an enctype the principal has no key for",
			EData:  edata,
			Client: &clientName,
		}
	}

	plain, err := crypto.DecryptEncPart(types.EncryptedData(ts), key.EncryptionKey(), keyusage.AS_REQ_PA_ENC_TIMESTAMP)
	if err != nil {
		s.recordFailure(ctx, client, clientName)

		return false, withClient(krbErrf(errorcode.KDC_ERR_PREAUTH_FAILED,
			"pre-authentication did not verify", err), clientName)
	}

	var tsEnc types.PAEncTSEnc
	if err := tsEnc.Unmarshal(plain); err != nil {
		s.recordFailure(ctx, client, clientName)

		return false, withClient(krbErrf(errorcode.KDC_ERR_PREAUTH_FAILED,
			"malformed pre-authentication timestamp", err), clientName)
	}

	if skew := now.Sub(tsEnc.PATimestamp); skew > s.cfg.ClockSkew || skew < -s.cfg.ClockSkew {
		return false, withClient(krbErr(errorcode.KRB_AP_ERR_SKEW,
			"client clock differs from the KDC by more than %s", s.cfg.ClockSkew), clientName)
	}

	return true, nil
}

// recordFailure notes a failed authentication, which is what drives principal lockout.
func (s *Server) recordFailure(ctx context.Context, client *store.Principal, name krbkeys.Name) {
	if err := s.st.RecordAuthResult(ctx, client.ID, false, s.cfg.Lockout); err != nil {
		s.log.Warn().Err(err).Str("principal", name.String()).Msg("could not record failed authentication")
	}
}

// preAuthHint builds the METHOD-DATA telling the client which pre-authentication to attempt and
// with which salt, so it can derive the right key from the user's password.
func (s *Server) preAuthHint(client *store.Principal, offered []int32) ([]byte, error) {
	info, err := s.etypeInfo2PAData(client, offered)
	if err != nil {
		return nil, err
	}

	md := types.MethodData{{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: []byte{}}}
	md = append(md, info...)

	return asn1.Marshal(md,
		asn1.WithMarshalSlicePreserveTypes(true),
		asn1.WithMarshalSliceAllowStrings(true))
}

// etypeInfo2PAData renders the principal's salts as PA-ETYPE-INFO2, restricted to the enctypes the
// client offered so it is not told about keys it cannot use.
func (s *Server) etypeInfo2PAData(client *store.Principal, offered []int32) ([]types.PAData, error) {
	var entries types.ETypeInfo2

	for _, want := range s.cfg.EncTypes {
		if offered != nil && !slices.Contains(offered, want) {
			continue
		}

		k, ok := client.KeyFor(want)
		if !ok {
			continue
		}

		entry := types.ETypeInfo2Entry{EType: k.EType, Salt: k.Salt}

		if len(k.S2KParams) > 0 {
			// The wire form is the raw iteration count, while the store keeps the hex
			// spelling the crypto library uses for string-to-key parameters.
			raw, err := hex.DecodeString(k.S2KParams)
			if err != nil {
				return nil, fmt.Errorf("principal %s has malformed s2kparams: %w", client.FullName(), err)
			}
			entry.S2KParams = raw
		}

		entries = append(entries, entry)
	}

	if len(entries) == 0 {
		return nil, nil
	}

	b, err := asn1.Marshal(entries,
		asn1.WithMarshalSlicePreserveTypes(true),
		asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, err
	}

	return []types.PAData{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: b}}, nil
}

// withClient tags a protocol error with the client it concerns, so the KRB-ERROR echoes the name.
func withClient(e *protocolError, name krbkeys.Name) *protocolError {
	n := name
	e.Client = &n

	return e
}
