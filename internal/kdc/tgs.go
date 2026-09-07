package kdc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/asn1apptag"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/pac"
	"github.com/go-krb5/krb5/types"
	"github.com/go-krb5/x/encoding/asn1"
	"github.com/go-krb5/x/rpc/mstypes"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// tgsAuth is the authenticated context of a TGS request: who presented which ticket-granting
// ticket, and the keys that came with it.
type tgsAuth struct {
	APReq messages.APReq
	// TGT is the decrypted ticket the requester presented.
	TGT messages.EncTicketPart
	// TicketServer is the principal the presented ticket was issued for, which tells a local
	// TGT apart from one a trusted realm issued.
	TicketServer krbkeys.Name
	// Client is the identity inside the presented ticket.
	Client krbkeys.Name
	// SessionKey is the key shared with the requester; ReplyKey is what the reply is sealed
	// with, which is the authenticator's subkey when it offered one.
	SessionKey types.EncryptionKey
	ReplyKey   types.EncryptionKey
	ReplyUsage uint32
	// CrossRealm reports that the presented ticket came from another realm.
	CrossRealm bool
}

// handleTGSReq runs the TGS exchange: it authenticates a ticket-granting ticket and issues a
// further ticket, whether for a service in this realm, for a trusted realm's TGS, or on behalf of
// another user through S4U.
func (s *Server) handleTGSReq(ctx context.Context, raw []byte, from net.Addr) ([]byte, *protocolError) {
	var req messages.TGSReq
	if err := req.Unmarshal(raw); err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "malformed TGS-REQ", err)
	}

	body := &req.ReqBody
	now := time.Now().UTC()

	// A validation request is the one case where an INVALID ticket is the point rather than an
	// error, so the flag check is relaxed for it alone.
	allowInvalid := types.IsFlagSet(&body.KDCOptions, flags.Validate)

	auth, perr := s.authenticateTGS(ctx, &req, raw, now, allowInvalid)
	if perr != nil {
		return nil, perr
	}

	if len(body.SName.NameString) == 0 {
		return nil, withClient(krbErr(errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
			"request names no service"), auth.Client)
	}

	targetRealm := strings.ToUpper(body.Realm)
	if len(targetRealm) == 0 {
		targetRealm = s.cfg.Realm
	}

	target := krbkeys.Name{
		Components: append([]string(nil), body.SName.NameString...),
		Realm:      targetRealm,
	}

	switch {
	case types.IsFlagSet(&body.KDCOptions, flags.Renew):
		return s.renewTicket(ctx, auth, body, target, now, from)
	case types.IsFlagSet(&body.KDCOptions, flags.Validate):
		return s.validateTicket(ctx, auth, body, target, now, from)
	case types.IsFlagSet(&body.KDCOptions, flags.EncTktInSkey):
		return nil, withClient(krbErr(errorcode.KDC_ERR_BADOPTION,
			"user-to-user authentication is not supported"), auth.Client)
	case types.IsFlagSet(&body.KDCOptions, optionCNameInAddlTkt):
		return s.s4u2Proxy(ctx, auth, &req, body, target, now, from)
	}

	if pa := findPAData(req.PAData, patype.PA_FOR_USER); pa != nil {
		return s.s4u2Self(ctx, auth, pa, body, target, now, from)
	}

	return s.serviceTicket(ctx, auth, body, target, now, from)
}

// authenticateTGS validates the AP-REQ that every TGS request carries: it decrypts the presented
// ticket with the key of the principal it was issued for, checks the authenticator against the
// ticket's session key, rejects replays and verifies the checksum over the request body.
func (s *Server) authenticateTGS(
	ctx context.Context,
	req *messages.TGSReq,
	raw []byte,
	now time.Time,
	allowInvalid bool,
) (*tgsAuth, *protocolError) {
	pa := findPAData(req.PAData, patype.PA_TGS_REQ)
	if pa == nil {
		return nil, krbErr(errorcode.KDC_ERR_PADATA_TYPE_NOSUPP, "request carries no PA-TGS-REQ")
	}

	var apReq messages.APReq
	if err := apReq.Unmarshal(pa.PADataValue); err != nil {
		return nil, krbErrf(errorcode.KDC_ERR_PADATA_TYPE_NOSUPP, "malformed AP-REQ", err)
	}

	ticketServer := krbkeys.NameFromPrincipalName(apReq.Ticket.SName, apReq.Ticket.Realm)

	// The ticket must have been issued for a ticket-granting service: this realm's own, or the
	// one shared with a realm that trusts us. Anything else would let a service ticket be
	// spent as if it were a TGT.
	if !ticketServer.IsTGS() {
		return nil, krbErr(errorcode.KDC_ERR_POLICY, "presented ticket is not a ticket-granting ticket")
	}

	crossRealm := !strings.EqualFold(ticketServer.Realm, s.cfg.Realm)

	tgtPrincipal, err := s.st.GetPrincipalKVNO(ctx, ticketServer, apReq.Ticket.EncPart.KVNO)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, krbErr(errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
				"no key for %s", ticketServer)
		}

		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "internal error", err)
	}

	tgtKey, ok := tgtPrincipal.KeyFor(apReq.Ticket.EncPart.EType)
	if !ok {
		return nil, krbErr(errorcode.KDC_ERR_ETYPE_NOSUPP,
			"no key of enctype %d for %s", apReq.Ticket.EncPart.EType, ticketServer)
	}

	if err := apReq.Ticket.Decrypt(tgtKey.EncryptionKey()); err != nil {
		return nil, krbErrf(errorcode.KRB_AP_ERR_BAD_INTEGRITY, "could not decrypt the presented ticket", err)
	}

	tgt := apReq.Ticket.DecryptedEncPart
	client := krbkeys.NameFromPrincipalName(tgt.CName, tgt.CRealm)

	if err := apReq.DecryptAuthenticator(tgt.Key); err != nil {
		return nil, withClient(krbErrf(errorcode.KRB_AP_ERR_BAD_INTEGRITY,
			"could not decrypt the authenticator", err), client)
	}

	authn := apReq.Authenticator

	// The authenticator has to name the same principal as the ticket it came with; otherwise a
	// captured ticket could be paired with a freshly minted authenticator for someone else.
	if !strings.EqualFold(authn.CRealm, tgt.CRealm) || !authn.CName.Equal(tgt.CName) {
		return nil, withClient(krbErr(errorcode.KRB_AP_ERR_BADMATCH,
			"authenticator does not match the ticket"), client)
	}

	if skew := now.Sub(authn.CTime); skew > s.cfg.ClockSkew || skew < -s.cfg.ClockSkew {
		return nil, withClient(krbErr(errorcode.KRB_AP_ERR_SKEW,
			"client clock differs from the KDC by more than %s", s.cfg.ClockSkew), client)
	}

	digest := sha256.Sum256(apReq.Ticket.EncPart.Cipher)
	if s.replay.seen(authn.CRealm, client.Principal(), authn.CTime, authn.Cusec, digest[:]) {
		return nil, withClient(krbErr(errorcode.KRB_AP_ERR_REPEAT,
			"this authenticator has already been used"), client)
	}

	if perr := s.checkTicketValidity(&tgt, now, client, allowInvalid); perr != nil {
		return nil, perr
	}

	if perr := s.verifyBodyChecksum(raw, &authn, tgt.Key, client); perr != nil {
		return nil, perr
	}

	auth := &tgsAuth{
		APReq:        apReq,
		TGT:          tgt,
		TicketServer: ticketServer,
		Client:       client,
		SessionKey:   tgt.Key,
		ReplyKey:     tgt.Key,
		ReplyUsage:   keyusage.TGS_REP_ENCPART_SESSION_KEY,
		CrossRealm:   crossRealm,
	}

	// A subkey in the authenticator means the client wants the reply sealed with it instead of
	// the ticket's session key (RFC 4120 section 5.4.2).
	if authn.SubKey.KeyType != 0 && len(authn.SubKey.KeyValue) > 0 {
		auth.ReplyKey = authn.SubKey
		auth.ReplyUsage = keyusage.TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY
	}

	return auth, nil
}

// verifyBodyChecksum confirms the authenticator's checksum covers the request body exactly as it
// arrived. The body is taken from the original bytes rather than re-encoded, because a re-encoding
// that differs by a single byte would fail a checksum that is in fact correct.
func (s *Server) verifyBodyChecksum(raw []byte, authn *types.Authenticator, sessionKey types.EncryptionKey, client krbkeys.Name) *protocolError {
	if authn.Cksum.CksumType == 0 || len(authn.Cksum.Checksum) == 0 {
		return withClient(krbErr(errorcode.KRB_AP_ERR_INAPP_CKSUM,
			"authenticator carries no checksum over the request body"), client)
	}

	bodyBytes, err := rawReqBody(raw)
	if err != nil {
		return withClient(krbErrf(errorcode.KRB_ERR_GENERIC, "malformed request", err), client)
	}

	et, err := crypto.GetChecksumEType(authn.Cksum.CksumType)
	if err != nil {
		return withClient(krbErrf(errorcode.KDC_ERR_SUMTYPE_NOSUPP,
			"unsupported checksum type", err), client)
	}

	if !et.VerifyChecksum(sessionKey.KeyValue, bodyBytes, authn.Cksum.Checksum,
		keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM) {
		return withClient(krbErr(errorcode.KRB_AP_ERR_MODIFIED,
			"the request body does not match its checksum"), client)
	}

	return nil
}

// rawReqBody extracts the encoded KDC-REQ-BODY from a TGS-REQ without re-encoding it.
func rawReqBody(raw []byte) ([]byte, error) {
	var outer struct {
		PVNO    int                  `asn1:"explicit,tag:1"`
		MsgType int                  `asn1:"explicit,tag:2"`
		PAData  types.PADataSequence `asn1:"explicit,optional,tag:3"`
		ReqBody asn1.RawValue        `asn1:"explicit,tag:4"`
	}

	if _, err := asn1.UnmarshalWithParams(raw, &outer,
		fmt.Sprintf("application,explicit,tag:%d", asn1apptag.TGSREQ),
		asn1.WithUnmarshalAllowTypeGeneralString(true),
	); err != nil {
		return nil, err
	}

	return outer.ReqBody.Bytes, nil
}

// checkTicketValidity applies the time and flag rules that make a presented ticket usable.
func (s *Server) checkTicketValidity(tkt *messages.EncTicketPart, now time.Time, client krbkeys.Name, allowInvalid bool) *protocolError {
	if !tkt.StartTime.IsZero() && now.Add(s.cfg.ClockSkew).Before(tkt.StartTime) {
		return withClient(krbErr(errorcode.KRB_AP_ERR_TKT_NYV, "ticket is not yet valid"), client)
	}
	if !tkt.EndTime.IsZero() && now.Add(-s.cfg.ClockSkew).After(tkt.EndTime) {
		return withClient(krbErr(errorcode.KRB_AP_ERR_TKT_EXPIRED, "ticket has expired"), client)
	}
	if !allowInvalid && types.IsFlagSet(&tkt.Flags, flags.Invalid) {
		return withClient(krbErr(errorcode.KRB_AP_ERR_TKT_NYV,
			"ticket is postdated and has not been validated"), client)
	}

	return nil
}

// serviceTicket issues an ordinary ticket for a service, or a referral to a trusted realm when the
// service lives elsewhere.
func (s *Server) serviceTicket(
	ctx context.Context,
	auth *tgsAuth,
	body *messages.KDCReqBody,
	target krbkeys.Name,
	now time.Time,
	from net.Addr,
) ([]byte, *protocolError) {
	// A service in another realm cannot be reached directly; the client is handed a ticket for
	// that realm's ticket-granting service and goes on from there (RFC 4120 section 1.2).
	switch {
	case target.IsTGS() && !strings.EqualFold(target.Components[1], s.cfg.Realm):
		if perr := s.checkOutboundTrust(ctx, target.Components[1]); perr != nil {
			return nil, withClient(perr, auth.Client)
		}
		// A cross-realm ticket-granting ticket is issued under the local realm, keyed with
		// the secret this realm shares with the remote one.
		target = krbkeys.Name{Components: target.Components, Realm: s.cfg.Realm}

	case !strings.EqualFold(target.Realm, s.cfg.Realm):
		referral, perr := s.referralName(ctx, target.Realm)
		if perr != nil {
			return nil, withClient(perr, auth.Client)
		}
		target = referral

	default:
		// The client named a service without saying which realm it belongs to, which is the
		// normal case: it only knows a host name. When this realm does not hold the service,
		// the host name is matched against the realms this one trusts and the client is
		// referred there (RFC 6806 section 8).
		if remote, ok := s.realmForHostBasedName(ctx, target); ok {
			referral, perr := s.referralName(ctx, remote)
			if perr != nil {
				return nil, withClient(perr, auth.Client)
			}
			target = referral
		}
	}

	return s.issueTicket(ctx, issueSpec{
		Auth:       auth,
		Body:       body,
		Client:     auth.Client,
		Target:     target,
		Now:        now,
		From:       from,
		SourceTGT:  &auth.TGT,
		TicketKind: ticketKind(target),
	})
}

// s4u2Self issues a ticket to the requesting service in another user's name, without that user
// taking part: protocol transition, MS-SFU section 3.
func (s *Server) s4u2Self(
	ctx context.Context,
	auth *tgsAuth,
	pa *types.PAData,
	body *messages.KDCReqBody,
	target krbkeys.Name,
	now time.Time,
	from net.Addr,
) ([]byte, *protocolError) {
	if !s.cfg.AllowS4U {
		return nil, withClient(krbErr(errorcode.KDC_ERR_BADOPTION,
			"protocol transition is disabled in this realm"), auth.Client)
	}

	var pfu paForUser
	if err := pfu.unmarshal(pa.PADataValue); err != nil {
		return nil, withClient(krbErrf(errorcode.KDC_ERR_PADATA_TYPE_NOSUPP,
			"malformed PA-FOR-USER", err), auth.Client)
	}

	if err := pfu.verify(auth.SessionKey); err != nil {
		return nil, withClient(krbErrf(errorcode.KRB_AP_ERR_MODIFIED,
			"PA-FOR-USER did not verify", err), auth.Client)
	}

	// The service may only ask for a ticket to itself. Letting it name a third party would turn
	// protocol transition into an unconstrained impersonation primitive.
	if !target.Equal(auth.Client) {
		return nil, withClient(krbErr(errorcode.KDC_ERR_BADOPTION,
			"a protocol transition request may only name the requesting service"), auth.Client)
	}

	requester, err := s.st.GetPrincipal(ctx, auth.Client)
	if err != nil {
		return nil, withClient(krbErrf(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN,
			"requesting service is unknown", err), auth.Client)
	}

	subject := krbkeys.NameFromPrincipalName(pfu.UserName, pfu.UserRealm)
	if !strings.EqualFold(subject.Realm, s.cfg.Realm) {
		return nil, withClient(krbErr(errorcode.KDC_ERR_POLICY,
			"protocol transition is limited to principals of this realm"), auth.Client)
	}

	if perr := impersonationAllowed(requester, subject); perr != nil {
		return nil, withClient(perr, auth.Client)
	}

	// A ticket to oneself in another user's name is not an escalation: the service could assert
	// that identity internally just as well, which is why MIT and Active Directory let any
	// service ask. What the OK_TO_AUTH_AS_DELEGATE flag governs is whether the result is
	// forwardable, because only a forwardable ticket can go on to be delegated to a third
	// service.
	s.log.Info().
		Str("service", auth.Client.String()).
		Str("onBehalfOf", subject.String()).
		Bool("forwardable", requester.OKToAuthAsDelegate).
		Str("from", addrString(from)).
		Msg("protocol transition requested")

	return s.issueTicket(ctx, issueSpec{
		Auth:        auth,
		Body:        body,
		Client:      subject,
		Target:      target,
		Now:         now,
		From:        from,
		Forwardable: requester.OKToAuthAsDelegate,
		TicketKind:  "s4u2self",
	})
}

// impersonationAllowed applies the principal's impersonation restriction, FreeIPA's
// ipaAllowToImpersonate. An empty list allows any principal, as a missing attribute does there.
func impersonationAllowed(requester *store.Principal, subject krbkeys.Name) *protocolError {
	if len(requester.AllowedToImpersonate) == 0 {
		return nil
	}

	for _, a := range requester.AllowedToImpersonate {
		if strings.EqualFold(a, subject.String()) {
			return nil
		}
		if !strings.Contains(a, "@") && strings.EqualFold(a, subject.Principal()) {
			return nil
		}
	}

	return krbErr(errorcode.KDC_ERR_BADOPTION,
		"%s is not permitted to act on behalf of %s", requester.FullName(), subject)
}

// s4u2Proxy issues a ticket to a third service in the name of the user who is already holding a
// ticket to the requesting service: constrained delegation, MS-SFU section 4.
func (s *Server) s4u2Proxy(
	ctx context.Context,
	auth *tgsAuth,
	req *messages.TGSReq,
	body *messages.KDCReqBody,
	target krbkeys.Name,
	now time.Time,
	from net.Addr,
) ([]byte, *protocolError) {
	if !s.cfg.AllowS4U {
		return nil, withClient(krbErr(errorcode.KDC_ERR_BADOPTION,
			"constrained delegation is disabled in this realm"), auth.Client)
	}
	if len(body.AdditionalTickets) == 0 {
		return nil, withClient(krbErr(errorcode.KDC_ERR_BADOPTION,
			"constrained delegation requires an evidence ticket"), auth.Client)
	}

	requester, err := s.st.GetPrincipal(ctx, auth.Client)
	if err != nil {
		return nil, withClient(krbErrf(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN,
			"requesting service is unknown", err), auth.Client)
	}

	if !delegationAllowed(requester.AllowedToDelegateTo, target) {
		return nil, withClient(krbErr(errorcode.KDC_ERR_BADOPTION,
			"%s is not permitted to delegate to %s", auth.Client, target), auth.Client)
	}

	// The evidence ticket was issued to the requesting service, so only its own key opens it.
	evidence := body.AdditionalTickets[0]

	evidenceServer := krbkeys.NameFromPrincipalName(evidence.SName, evidence.Realm)
	if !evidenceServer.Equal(auth.Client) {
		return nil, withClient(krbErr(errorcode.KDC_ERR_BADOPTION,
			"the evidence ticket was not issued to the requesting service"), auth.Client)
	}

	evidencePrincipal, err := s.st.GetPrincipalKVNO(ctx, evidenceServer, evidence.EncPart.KVNO)
	if err != nil {
		return nil, withClient(krbErrf(errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
			"no key for the evidence ticket's service", err), auth.Client)
	}

	evidenceKey, ok := evidencePrincipal.KeyFor(evidence.EncPart.EType)
	if !ok {
		return nil, withClient(krbErr(errorcode.KDC_ERR_ETYPE_NOSUPP,
			"no key of the evidence ticket's enctype"), auth.Client)
	}

	if err := evidence.Decrypt(evidenceKey.EncryptionKey()); err != nil {
		return nil, withClient(krbErrf(errorcode.KRB_AP_ERR_BAD_INTEGRITY,
			"could not decrypt the evidence ticket", err), auth.Client)
	}

	inner := evidence.DecryptedEncPart

	// Only a forwardable ticket may be delegated: the flag is the user's consent, carried in
	// the ticket the user obtained.
	if !types.IsFlagSet(&inner.Flags, flags.Forwardable) {
		return nil, withClient(krbErr(errorcode.KDC_ERR_BADOPTION,
			"the evidence ticket is not forwardable"), auth.Client)
	}

	if perr := s.checkTicketValidity(&inner, now, auth.Client, false); perr != nil {
		return nil, perr
	}

	// The evidence ticket is sealed with the requesting service's own key, so the service could
	// have rewritten it, PAC and all, before handing it back. The KDC signature is made with the
	// krbtgt key, which no service holds, so checking it is what stops a compromised service
	// from delegating a user with group membership it invented.
	if s.cfg.IssuePAC {
		blob, err := extractPAC(inner.AuthorizationData)
		if err != nil {
			return nil, withClient(krbErrf(errorcode.KDC_ERR_BADOPTION,
				"the evidence ticket's authorization data is malformed", err), auth.Client)
		}

		if blob != nil {
			kdcKey, perr := s.krbtgtKey(ctx)
			if perr != nil {
				return nil, perr
			}

			if err := verifyPACKDCSignature(blob, kdcKey); err != nil {
				return nil, withClient(krbErrf(errorcode.KRB_AP_ERR_MODIFIED,
					"the evidence ticket's authorization data was altered", err), auth.Client)
			}
		}
	}

	subject := krbkeys.NameFromPrincipalName(inner.CName, inner.CRealm)

	if perr := impersonationAllowed(requester, subject); perr != nil {
		return nil, withClient(perr, auth.Client)
	}

	s.log.Info().
		Str("service", auth.Client.String()).
		Str("onBehalfOf", subject.String()).
		Str("target", target.String()).
		Str("from", addrString(from)).
		Msg("constrained delegation requested")

	return s.issueTicket(ctx, issueSpec{
		Auth:        auth,
		Body:        body,
		Client:      subject,
		Target:      target,
		Now:         now,
		From:        from,
		SourceTGT:   &inner,
		Forwardable: true,
		Delegation: &pac.S4UDelegationInfo{
			S4U2proxyTarget:      unicodeString(target.String()),
			TransitedListSize:    1,
			S4UTransitedServices: []mstypes.RPCUnicodeString{unicodeString(auth.Client.String())},
		},
		TicketKind: "s4u2proxy",
	})
}

// renewTicket reissues a renewable ticket with a fresh validity window, up to the renew-until time
// fixed when it was first issued.
func (s *Server) renewTicket(
	ctx context.Context,
	auth *tgsAuth,
	body *messages.KDCReqBody,
	target krbkeys.Name,
	now time.Time,
	from net.Addr,
) ([]byte, *protocolError) {
	tgt := auth.TGT

	if !types.IsFlagSet(&tgt.Flags, flags.Renewable) {
		return nil, withClient(krbErr(errorcode.KDC_ERR_BADOPTION, "ticket is not renewable"), auth.Client)
	}
	if tgt.RenewTill.IsZero() || !now.Before(tgt.RenewTill) {
		return nil, withClient(krbErr(errorcode.KRB_AP_ERR_TKT_EXPIRED,
			"the renewable lifetime of this ticket has run out"), auth.Client)
	}
	if !target.Equal(auth.TicketServer) {
		return nil, withClient(krbErr(errorcode.KDC_ERR_BADOPTION,
			"a renewal must name the same service as the ticket it renews"), auth.Client)
	}

	server, perr := s.loadTarget(ctx, target, auth.Client)
	if perr != nil {
		return nil, perr
	}

	client, perr := s.loadClientPrincipal(ctx, auth)
	if perr != nil {
		return nil, perr
	}

	end := now.Add(s.effectiveLife(client.MaxTicketLife, server.MaxTicketLife, s.cfg.MaxTicketLife))
	if end.After(tgt.RenewTill) {
		end = tgt.RenewTill
	}

	// The renewed ticket keeps the original's flags except INITIAL, which only ever belongs to
	// a ticket obtained directly from an AS exchange.
	newFlags := copyFlags(tgt.Flags)
	types.UnsetFlag(&newFlags, flags.Initial)

	return s.finishTicket(ctx, finishSpec{
		Auth:       auth,
		Body:       body,
		Client:     auth.Client,
		Target:     target,
		Server:     server,
		Flags:      newFlags,
		AuthTime:   tgt.AuthTime,
		StartTime:  now,
		EndTime:    end,
		RenewTill:  tgt.RenewTill,
		AuthzData:  tgt.AuthorizationData,
		Transited:  tgt.Transited,
		Now:        now,
		From:       from,
		TicketKind: "renewal",
		ReuseAuthz: true,
	})
}

// validateTicket clears the INVALID flag from a postdated ticket whose start time has arrived.
func (s *Server) validateTicket(
	ctx context.Context,
	auth *tgsAuth,
	body *messages.KDCReqBody,
	target krbkeys.Name,
	now time.Time,
	from net.Addr,
) ([]byte, *protocolError) {
	tgt := auth.TGT

	if !types.IsFlagSet(&tgt.Flags, flags.Invalid) {
		return nil, withClient(krbErr(errorcode.KDC_ERR_BADOPTION,
			"ticket is already valid"), auth.Client)
	}
	if !tgt.StartTime.IsZero() && now.Add(s.cfg.ClockSkew).Before(tgt.StartTime) {
		return nil, withClient(krbErr(errorcode.KRB_AP_ERR_TKT_NYV,
			"the ticket's start time has not arrived"), auth.Client)
	}
	if !target.Equal(auth.TicketServer) {
		return nil, withClient(krbErr(errorcode.KDC_ERR_BADOPTION,
			"a validation must name the same service as the ticket it validates"), auth.Client)
	}

	server, perr := s.loadTarget(ctx, target, auth.Client)
	if perr != nil {
		return nil, perr
	}

	newFlags := copyFlags(tgt.Flags)
	types.UnsetFlag(&newFlags, flags.Invalid)

	return s.finishTicket(ctx, finishSpec{
		Auth:       auth,
		Body:       body,
		Client:     auth.Client,
		Target:     target,
		Server:     server,
		Flags:      newFlags,
		AuthTime:   tgt.AuthTime,
		StartTime:  tgt.StartTime,
		EndTime:    tgt.EndTime,
		RenewTill:  tgt.RenewTill,
		AuthzData:  tgt.AuthorizationData,
		Transited:  tgt.Transited,
		Now:        now,
		From:       from,
		TicketKind: "validation",
		ReuseAuthz: true,
	})
}

// issueSpec describes a ticket to issue on behalf of a client identity that may not be the one
// that presented the TGT.
type issueSpec struct {
	Auth   *tgsAuth
	Body   *messages.KDCReqBody
	Client krbkeys.Name
	Target krbkeys.Name
	Now    time.Time
	From   net.Addr

	// SourceTGT, when set, is the ticket whose flags and transited path this one inherits.
	SourceTGT *messages.EncTicketPart
	// Forwardable forces the flag on regardless of what the request asked for, which is how
	// S4U tickets are marked delegable.
	Forwardable bool
	Delegation  *pac.S4UDelegationInfo
	TicketKind  string
}

// issueTicket applies policy to a request and mints the resulting ticket.
func (s *Server) issueTicket(ctx context.Context, spec issueSpec) ([]byte, *protocolError) {
	server, perr := s.loadTarget(ctx, spec.Target, spec.Auth.Client)
	if perr != nil {
		return nil, perr
	}

	// The service was found under one of its aliases and the client asked to be told the real
	// name, so the ticket is issued in that name (RFC 6806 section 5). Without the flag the
	// ticket keeps the requested name, which is what a client that never asked expects to find
	// in its credential cache.
	if types.IsFlagSet(&spec.Body.KDCOptions, flags.Canonicalize) {
		spec.Target = server.KrbName()
	}

	// Policy limits come from the identity the ticket is being issued for, which under S4U is
	// not the principal that presented the TGT.
	client, perr := s.loadPolicyPrincipal(ctx, spec.Client)
	if perr != nil {
		return nil, perr
	}

	times, perr := s.computeTimes(spec.Body, client, server, spec.Now)
	if perr != nil {
		return nil, withClient(perr, spec.Auth.Client)
	}

	// A derived ticket can never outlive the ticket it was derived from.
	if spec.SourceTGT != nil && !spec.SourceTGT.EndTime.IsZero() && times.EndTime.After(spec.SourceTGT.EndTime) {
		times.EndTime = spec.SourceTGT.EndTime
	}

	tktFlags := ticketFlags(spec.Body, client, server, times, false, ticketWasPreAuthenticated(spec.SourceTGT))
	if spec.Forwardable {
		types.SetFlag(&tktFlags, flags.Forwardable)
	}

	transited, perr := s.transitedFor(ctx, spec)
	if perr != nil {
		return nil, perr
	}

	return s.finishTicket(ctx, finishSpec{
		Auth:       spec.Auth,
		Body:       spec.Body,
		Client:     spec.Client,
		Target:     spec.Target,
		Server:     server,
		Flags:      tktFlags,
		AuthTime:   authTimeFor(spec),
		StartTime:  times.StartTime,
		EndTime:    times.EndTime,
		RenewTill:  times.RenewTill,
		Transited:  transited,
		Delegation: spec.Delegation,
		Now:        spec.Now,
		From:       spec.From,
		TicketKind: spec.TicketKind,
	})
}

// finishSpec is a fully decided ticket, ready to be sealed and wrapped in a TGS-REP.
type finishSpec struct {
	Auth   *tgsAuth
	Body   *messages.KDCReqBody
	Client krbkeys.Name
	Target krbkeys.Name
	Server *store.Principal

	Flags     asn1.BitString
	AuthTime  time.Time
	StartTime time.Time
	EndTime   time.Time
	RenewTill time.Time
	Transited messages.TransitedEncoding

	// AuthzData and ReuseAuthz carry the previous ticket's authorization data through a renewal
	// or validation, where the contents must not change.
	AuthzData  types.AuthorizationData
	ReuseAuthz bool
	Delegation *pac.S4UDelegationInfo

	Now        time.Time
	From       net.Addr
	TicketKind string
}

// finishTicket seals the ticket and builds the TGS-REP around it.
func (s *Server) finishTicket(ctx context.Context, spec finishSpec) ([]byte, *protocolError) {
	sessionEType, ok := s.selectSessionEType(spec.Body.EType)
	if !ok {
		return nil, withClient(krbErr(errorcode.KDC_ERR_ETYPE_NOSUPP,
			"no enctype in common with the KDC"), spec.Auth.Client)
	}

	serverKey, ok := selectKey(spec.Server, s.cfg.EncTypes, nil)
	if !ok {
		return nil, withClient(krbErr(errorcode.KDC_ERR_SVC_UNAVAILABLE,
			"service principal holds no usable key"), spec.Auth.Client)
	}

	authzData := spec.AuthzData

	if !spec.ReuseAuthz {
		var perr *protocolError
		if authzData, perr = s.tgsAuthorizationData(ctx, spec); perr != nil {
			return nil, perr
		}
	}

	tkt, sessionKey, err := mintTicket(ticketSpec{
		Client:            spec.Client,
		Server:            spec.Target,
		ServerKey:         serverKey,
		ServerKVNO:        spec.Server.KVNO,
		SessionEType:      sessionEType,
		Flags:             spec.Flags,
		AuthTime:          spec.AuthTime,
		StartTime:         spec.StartTime,
		EndTime:           spec.EndTime,
		RenewTill:         spec.RenewTill,
		Addresses:         spec.Body.Addresses,
		AuthorizationData: authzData,
		Transited:         spec.Transited,
	})
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not issue ticket", err)
	}

	encPart := messages.EncKDCRepPart{
		Key:       sessionKey,
		LastReqs:  []messages.LastReq{{LRType: 0, LRValue: spec.Now}},
		Nonce:     spec.Body.Nonce,
		Flags:     spec.Flags,
		AuthTime:  spec.AuthTime,
		StartTime: spec.StartTime,
		EndTime:   spec.EndTime,
		RenewTill: spec.RenewTill,
		SRealm:    spec.Target.Realm,
		SName:     spec.Target.PrincipalName(),
		CAddr:     spec.Body.Addresses,
	}

	encBytes, err := marshalEncKDCRepPart(&encPart, asn1apptag.EncTGSRepPart)
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not build reply", err)
	}

	encData, err := crypto.GetEncryptedData(encBytes, spec.Auth.ReplyKey, spec.Auth.ReplyUsage, 0)
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not encrypt reply", err)
	}

	rep := messages.TGSRep{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_TGS_REP,
		CRealm:  spec.Client.Realm,
		CName:   spec.Client.PrincipalName(),
		Ticket:  tkt,
		EncPart: encData,
	}

	out, err := rep.Marshal()
	if err != nil {
		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "could not marshal reply", err)
	}

	kind := spec.TicketKind
	if len(kind) == 0 {
		kind = "service"
	}

	s.metrics.KDCTicketsIssued.WithLabelValues(kind).Inc()
	s.log.Info().
		Str("client", spec.Client.String()).
		Str("server", spec.Target.String()).
		Str("kind", kind).
		Str("from", addrString(spec.From)).
		Time("expires", spec.EndTime).
		Msg("TGS-REP issued")

	return out, nil
}

// tgsAuthorizationData decides what authorization data the new ticket carries: a PAC rebuilt from
// the directory for a local client, or the one from the presented ticket re-signed for the new
// service when the client belongs to another realm.
func (s *Server) tgsAuthorizationData(ctx context.Context, spec finishSpec) (types.AuthorizationData, *protocolError) {
	if !s.cfg.IssuePAC {
		return nil, nil
	}

	if strings.EqualFold(spec.Client.Realm, s.cfg.Realm) {
		client, err := s.st.GetPrincipal(ctx, spec.Client)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, withClient(krbErr(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN,
					"no principal %s", spec.Client), spec.Auth.Client)
			}

			return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "internal error", err)
		}

		return s.authorizationData(ctx, client, spec.Client, spec.Server, spec.AuthTime, spec.Delegation)
	}

	// The client's own realm authored this PAC, and it arrived inside a ticket sealed with the
	// key only that realm and this one share, so its integrity is already established. It is
	// relayed and re-signed for the target service rather than rebuilt, because this realm
	// holds no account for the client.
	//
	// Note that the group membership in it is asserted by the remote realm: a trust is a
	// statement that its claims are accepted. There is no SID filtering here, so only extend a
	// trust to a realm whose administrators you would grant the same authority directly.
	blob, err := extractPAC(spec.Auth.TGT.AuthorizationData)
	if err != nil || blob == nil {
		return nil, nil
	}

	kdcKey, perr := s.krbtgtKey(ctx)
	if perr != nil {
		return nil, perr
	}

	serverKey, ok := selectKey(spec.Server, s.cfg.EncTypes, nil)
	if !ok {
		return nil, withClient(krbErr(errorcode.KDC_ERR_SVC_UNAVAILABLE,
			"service principal holds no usable key"), spec.Auth.Client)
	}

	resigned, err := resignPAC(blob, serverKey, kdcKey)
	if err != nil {
		s.log.Warn().Err(err).Str("client", spec.Client.String()).
			Msg("dropping a cross-realm PAC that could not be re-signed")

		return nil, nil
	}

	ad, perr := wrapPAC(resigned)
	if perr != nil {
		return nil, perr
	}

	return ad, nil
}

// loadTarget resolves the service a ticket is being requested for.
func (s *Server) loadTarget(ctx context.Context, target krbkeys.Name, requester krbkeys.Name) (*store.Principal, *protocolError) {
	server, err := s.st.GetPrincipal(ctx, target)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.explainUnknownService(ctx, target)

			return nil, withClient(krbErr(errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
				"no principal %s", target), requester)
		}

		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "internal error", err)
	}

	if status := server.Status(time.Now().UTC()); status != store.PrincipalOK {
		return nil, withClient(serverStatusError(status), requester)
	}

	return server, nil
}

// explainUnknownService logs what an administrator needs to see when a service ticket is refused
// for a name nobody registered.
//
// By far the most common cause is not a missing principal but a rewritten name: a client asked for
// a host-based service, and its Kerberos library canonicalised the host through DNS before turning
// it into a principal. With no reverse zone, or one that answers with a different name, the client
// ends up asking for a principal that was never meant to exist. Naming the services that do exist
// is what makes that visible; the hint stays in the log rather than in the KRB-ERROR, because the
// requester should not be handed an inventory of this realm's services.
func (s *Server) explainUnknownService(ctx context.Context, target krbkeys.Name) {
	if len(target.Components) < 2 {
		return
	}

	known, err := s.st.ServicePrincipalsOfClass(ctx, target.Components[0], target.Realm, 10)
	if err != nil {
		s.log.Debug().Err(err).Msg("could not look up sibling service principals")

		return
	}

	if len(known) == 0 {
		return
	}

	s.log.Info().
		Str("requested", target.String()).
		Strs("registered", known).
		Msg("unknown service principal, but this realm holds others of the same class: " +
			"if the client derived this name from a host address, set rdns = false and " +
			"dns_canonicalize_hostname = false in its krb5.conf")
}

// loadClientPrincipal loads the principal that presented the TGT, if this realm holds it.
func (s *Server) loadClientPrincipal(ctx context.Context, auth *tgsAuth) (*store.Principal, *protocolError) {
	return s.loadPolicyPrincipal(ctx, auth.Client)
}

// loadPolicyPrincipal returns the principal whose policy limits apply, or a permissive stand-in
// for a client this realm does not hold, which is the normal case for a cross-realm request.
func (s *Server) loadPolicyPrincipal(ctx context.Context, name krbkeys.Name) (*store.Principal, *protocolError) {
	if !strings.EqualFold(name.Realm, s.cfg.Realm) {
		return &store.Principal{
			Name:             name.Principal(),
			Realm:            name.Realm,
			Enabled:          true,
			AllowForwardable: true,
			AllowProxiable:   true,
			AllowRenewable:   true,
		}, nil
	}

	p, err := s.st.GetPrincipal(ctx, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, withClient(krbErr(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN,
				"no principal %s", name), name)
		}

		return nil, krbErrf(errorcode.KRB_ERR_GENERIC, "internal error", err)
	}

	if status := p.Status(time.Now().UTC()); status != store.PrincipalOK {
		return nil, withClient(clientStatusError(status), name)
	}

	return p, nil
}

// realmForHostBasedName finds the trusted realm a host-based service name belongs to, when this
// realm does not hold the service itself.
//
// The match is on the host name's domain: a service on a host under partner.com belongs to the
// realm PARTNER.COM, which is the convention every Kerberos deployment follows and the only
// mapping available without asking the client to spell the realm out. The longest matching domain
// wins, so a trust with a more specific realm takes precedence.
func (s *Server) realmForHostBasedName(ctx context.Context, target krbkeys.Name) (string, bool) {
	if len(target.Components) < 2 {
		return "", false
	}

	// A service this realm actually holds is never referred elsewhere.
	if _, err := s.st.GetPrincipal(ctx, target); err == nil {
		return "", false
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", false
	}

	host := strings.ToLower(target.Components[len(target.Components)-1])

	trusts, err := s.st.ListTrusts(ctx)
	if err != nil {
		s.log.Warn().Err(err).Msg("could not read trusts while resolving a referral")

		return "", false
	}

	var best string

	for i := range trusts {
		t := &trusts[i]
		if !t.Allows(store.TrustOutbound) {
			continue
		}

		domain := strings.ToLower(t.RemoteRealm)
		if host != domain && !strings.HasSuffix(host, "."+domain) {
			continue
		}

		if len(domain) > len(best) {
			best = t.RemoteRealm
		}
	}

	return best, len(best) > 0
}

// referralName picks the ticket-granting principal to refer a client to for a remote realm.
func (s *Server) referralName(ctx context.Context, remote string) (krbkeys.Name, *protocolError) {
	remote = strings.ToUpper(remote)

	if perr := s.checkOutboundTrust(ctx, remote); perr != nil {
		return krbkeys.Name{}, perr
	}

	return krbkeys.Name{Components: []string{"krbtgt", remote}, Realm: s.cfg.Realm}, nil
}

// checkOutboundTrust confirms this realm is willing to send clients to the remote one.
func (s *Server) checkOutboundTrust(ctx context.Context, remote string) *protocolError {
	remote = strings.ToUpper(remote)

	trust, err := s.st.GetTrust(ctx, remote)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return krbErr(errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
				"realm %s is not trusted by %s", remote, s.cfg.Realm)
		}

		return krbErrf(errorcode.KRB_ERR_GENERIC, "internal error", err)
	}

	if !trust.Allows(store.TrustOutbound) {
		return krbErr(errorcode.KDC_ERR_PATH_NOT_ACCEPTED,
			"the trust with %s does not allow referrals in this direction", remote)
	}

	return nil
}

// transitedFor builds the transited-realm field of the new ticket. When the client came from
// another realm, the realm that issued the presented ticket is added to the path so the service
// can see which realms vouched for the identity (RFC 4120 section 3.3.3.2).
func (s *Server) transitedFor(ctx context.Context, spec issueSpec) (messages.TransitedEncoding, *protocolError) {
	if spec.SourceTGT == nil {
		return messages.TransitedEncoding{}, nil
	}

	transited := spec.SourceTGT.Transited

	if !spec.Auth.CrossRealm {
		return transited, nil
	}

	issuing := strings.ToUpper(spec.Auth.TicketServer.Realm)
	clientRealm := strings.ToUpper(spec.Client.Realm)

	trust, err := s.st.GetTrust(ctx, issuing)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return transited, krbErr(errorcode.KDC_ERR_PATH_NOT_ACCEPTED,
				"realm %s is not trusted by %s", issuing, s.cfg.Realm)
		}

		return transited, krbErrf(errorcode.KRB_ERR_GENERIC, "internal error", err)
	}

	if !trust.Allows(store.TrustInbound) {
		return transited, krbErr(errorcode.KDC_ERR_PATH_NOT_ACCEPTED,
			"the trust with %s does not accept clients from it", issuing)
	}

	// A path that already crossed a realm before reaching us may only continue if the trust
	// was declared transitive; otherwise this realm would silently vouch for realms it has no
	// relationship with.
	if len(transited.Contents) > 0 && !trust.Transitive {
		return transited, krbErr(errorcode.KDC_ERR_PATH_NOT_ACCEPTED,
			"the trust with %s is not transitive", issuing)
	}

	// The issuing realm belongs in the path only when it is neither endpoint of the hop.
	if issuing != clientRealm && issuing != strings.ToUpper(s.cfg.Realm) {
		transited = appendTransited(transited, issuing)
	}

	return transited, nil
}

// appendTransited adds a realm to a DOMAIN-X500-COMPRESS transited encoding. No compression is
// applied: RFC 4120 permits the plain comma separated list, and an explicit path is what an
// administrator reading a ticket wants to see.
func appendTransited(t messages.TransitedEncoding, realm string) messages.TransitedEncoding {
	existing := string(t.Contents)

	for _, r := range strings.Split(existing, ",") {
		if strings.EqualFold(strings.TrimSpace(r), realm) {
			return t
		}
	}

	if len(existing) == 0 {
		existing = realm
	} else {
		existing += "," + realm
	}

	return messages.TransitedEncoding{TRType: 1, Contents: []byte(existing)}
}

// authTimeFor keeps the original authentication time when the new ticket derives from an existing
// one, so a service can see how long ago the user actually proved their identity.
func authTimeFor(spec issueSpec) time.Time {
	if spec.SourceTGT != nil && !spec.SourceTGT.AuthTime.IsZero() {
		return spec.SourceTGT.AuthTime
	}

	return spec.Now
}

// ticketWasPreAuthenticated reports whether the ticket a request derives from was itself obtained
// with pre-authentication, so the flag can be carried forward.
func ticketWasPreAuthenticated(t *messages.EncTicketPart) bool {
	if t == nil {
		return false
	}

	return types.IsFlagSet(&t.Flags, flags.PreAuthent)
}

// ticketKind labels the issued ticket for metrics.
func ticketKind(target krbkeys.Name) string {
	if target.IsTGS() {
		return "cross-realm-tgt"
	}

	return "service"
}

// delegationAllowed reports whether target appears in a service's allowed delegation list. The
// comparison ignores the realm when the entry carries none, which is how these lists are usually
// written.
func delegationAllowed(allowed []string, target krbkeys.Name) bool {
	want := target.String()

	for _, a := range allowed {
		if strings.EqualFold(a, want) {
			return true
		}
		if !strings.Contains(a, "@") && strings.EqualFold(a, target.Principal()) {
			return true
		}
	}

	return false
}

// copyFlags returns an independent copy of a flag set, so amending it cannot disturb the ticket it
// came from.
func copyFlags(in asn1.BitString) asn1.BitString {
	out := types.NewKrbFlags()
	copy(out.Bytes, in.Bytes)

	if in.BitLength > 0 {
		out.BitLength = in.BitLength
	}

	return out
}

// findPAData returns the pre-authentication datum of the given type, or nil.
func findPAData(pas types.PADataSequence, want int32) *types.PAData {
	for i := range pas {
		if pas[i].PADataType == want {
			return &pas[i]
		}
	}

	return nil
}
