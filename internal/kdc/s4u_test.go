package kdc

import (
	"context"
	"strings"
	"testing"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
	"github.com/go-krb5/x/encoding/asn1"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

const (
	frontEndSPN = "HTTP/app.example.com"
	backEndSPN  = "MSSQLSvc/db.example.com"
	servicePass = "the front end service password"
)

// s4uSetup builds a realm with a user, a front-end service trusted for delegation and a back-end
// service it is allowed to delegate to.
func s4uSetup(t *testing.T) (*harness, messages.ASRep) {
	t.Helper()

	ctx := context.Background()
	h := newHarness(t)
	h.addUser(t, "alice", testPassword)

	// The front end has a password because it must obtain its own ticket-granting ticket before
	// it can ask for anything on a user's behalf.
	frontName := krbkeys.MustParseName(frontEndSPN, testRealm)

	keys, err := krbkeys.DeriveKeys(servicePass, frontName, h.etypes)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	if err := h.store.CreatePrincipal(ctx, &store.Principal{
		Name: frontName.Principal(), Realm: frontName.Realm,
		Enabled: true, RequiresPreAuth: true,
		AllowForwardable: true, AllowProxiable: true, AllowRenewable: true,
		OKToAuthAsDelegate:  true,
		AllowedToDelegateTo: []string{backEndSPN + "@" + testRealm},
	}, keys); err != nil {
		t.Fatalf("CreatePrincipal front end: %v", err)
	}

	h.addService(t, backEndSPN)

	cfg := h.clientConfig(false)
	cl := client.NewWithPassword(frontEndSPN, testRealm, servicePass, cfg)

	asReq, err := messages.NewASReqForTGT(testRealm, cfg, cl.Credentials.CName())
	if err != nil {
		t.Fatalf("building AS-REQ: %v", err)
	}

	asRep, err := cl.ASExchange(testRealm, asReq, 0)
	if err != nil {
		t.Fatalf("front end AS exchange: %v", err)
	}

	return h, asRep
}

// tgsRequest builds a TGS-REQ from a ticket-granting ticket, applying mutate to the body before the
// authenticator checksum is computed over it.
//
// The library builds an ordinary request and seals it in one step, which leaves no room to add the
// S4U options and pre-authentication data that this exchange needs, so the pieces are assembled
// here instead.
func tgsRequest(
	t *testing.T,
	h *harness,
	cname types.PrincipalName,
	tgt messages.Ticket,
	sessionKey types.EncryptionKey,
	sname types.PrincipalName,
	mutate func(body *messages.KDCReqBody),
	extraPA []types.PAData,
) []byte {
	t.Helper()

	req, err := messages.NewTGSReq(cname, testRealm, testRealm, h.clientConfig(false), tgt, sessionKey, sname, false)
	if err != nil {
		t.Fatalf("building TGS-REQ: %v", err)
	}

	if mutate != nil {
		mutate(&req.ReqBody)
	}

	body, err := req.ReqBody.Marshal()
	if err != nil {
		t.Fatalf("marshalling request body: %v", err)
	}

	et, err := crypto.GetEType(sessionKey.KeyType)
	if err != nil {
		t.Fatalf("etype: %v", err)
	}

	cksum, err := et.GetChecksumHash(sessionKey.KeyValue, body,
		keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
	if err != nil {
		t.Fatalf("checksum: %v", err)
	}

	auth, err := types.NewAuthenticator(testRealm, cname)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	auth.Cksum = types.Checksum{CksumType: et.GetHashID(), Checksum: cksum}

	apReq, err := messages.NewAPReq(tgt, sessionKey, auth)
	if err != nil {
		t.Fatalf("AP-REQ: %v", err)
	}

	apb, err := apReq.Marshal()
	if err != nil {
		t.Fatalf("marshalling AP-REQ: %v", err)
	}

	req.PAData = append(types.PADataSequence{{PADataType: patype.PA_TGS_REQ, PADataValue: apb}}, extraPA...)

	raw, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshalling TGS-REQ: %v", err)
	}

	return raw
}

// forUserPAData builds the PA-FOR-USER naming the user the service is acting for, signed with the
// service's own ticket-granting session key.
func forUserPAData(t *testing.T, user string, sessionKey types.EncryptionKey) types.PAData {
	t.Helper()

	userName := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{user}}

	pfu := paForUser{
		UserName:    userName,
		UserRealm:   testRealm,
		AuthPackage: "Kerberos",
	}

	pfu.Cksum = types.Checksum{
		CksumType: chksumtype.KERB_CHECKSUM_HMAC_MD5,
		Checksum:  hmacMD5Checksum(sessionKey.KeyValue, keyusage.KERB_NON_KERB_CKSUM_SALT, pfu.checksumData()),
	}

	b, err := asn1.Marshal(pfu,
		asn1.WithMarshalSlicePreserveTypes(true),
		asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		t.Fatalf("marshalling PA-FOR-USER: %v", err)
	}

	return types.PAData{PADataType: patype.PA_FOR_USER, PADataValue: b}
}

// exchange sends a request straight to the KDC and returns the reply, or the error text when the
// KDC refused.
func exchange(t *testing.T, h *harness, raw []byte) (messages.TGSRep, string) {
	t.Helper()

	reply := h.server.Handle(context.Background(), raw, nil)

	var rep messages.TGSRep
	if err := rep.Unmarshal(reply); err != nil {
		var kerr messages.KRBError
		if uerr := kerr.Unmarshal(reply); uerr != nil {
			t.Fatalf("reply is neither a TGS-REP nor a KRB-ERROR: %v", err)
		}

		return rep, kerr.Error()
	}

	return rep, ""
}

func TestS4U2SelfIssuesATicketInAnotherUsersName(t *testing.T) {
	h, asRep := s4uSetup(t)

	self := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, frontEndSPN)

	raw := tgsRequest(t, h, asRep.CName, asRep.Ticket, asRep.DecryptedEncPart.Key, self, nil,
		[]types.PAData{forUserPAData(t, "alice", asRep.DecryptedEncPart.Key)})

	rep, errText := exchange(t, h, raw)
	if len(errText) > 0 {
		t.Fatalf("S4U2Self refused: %s", errText)
	}

	// The ticket is issued to the service, but in the user's name: that is protocol transition.
	if got := rep.CName.PrincipalNameString(); got != "alice" {
		t.Errorf("ticket names %q, want alice", got)
	}
	if got := rep.Ticket.SName.PrincipalNameString(); got != frontEndSPN {
		t.Errorf("ticket is for %q, want %s", got, frontEndSPN)
	}

	if err := rep.DecryptEncPart(asRep.DecryptedEncPart.Key); err != nil {
		t.Fatalf("decrypting the reply: %v", err)
	}

	// It has to be forwardable, or the constrained delegation that follows it is impossible.
	if !types.IsFlagSet(&rep.DecryptedEncPart.Flags, flags.Forwardable) {
		t.Error("the S4U2Self ticket is not forwardable")
	}
}

func TestS4U2SelfWithoutTheDelegationFlagIsNotForwardable(t *testing.T) {
	ctx := context.Background()
	h, asRep := s4uSetup(t)

	// MIT and Active Directory let any service ask for a ticket to itself in a user's name: the
	// service could assert that identity internally anyway. What OK_TO_AUTH_AS_DELEGATE governs
	// is whether the ticket is forwardable, and only a forwardable one can be delegated onwards.
	if _, err := h.store.UpdatePrincipal(ctx, krbkeys.MustParseName(frontEndSPN, testRealm),
		func(p *store.Principal) error {
			p.OKToAuthAsDelegate = false

			return nil
		}); err != nil {
		t.Fatalf("clearing the delegation flag: %v", err)
	}

	self := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, frontEndSPN)

	raw := tgsRequest(t, h, asRep.CName, asRep.Ticket, asRep.DecryptedEncPart.Key, self, nil,
		[]types.PAData{forUserPAData(t, "alice", asRep.DecryptedEncPart.Key)})

	rep, errText := exchange(t, h, raw)
	if len(errText) > 0 {
		t.Fatalf("protocol transition refused: %s", errText)
	}

	if err := rep.DecryptEncPart(asRep.DecryptedEncPart.Key); err != nil {
		t.Fatalf("decrypting the reply: %v", err)
	}

	if types.IsFlagSet(&rep.DecryptedEncPart.Flags, flags.Forwardable) {
		t.Error("the ticket is forwardable without OK_TO_AUTH_AS_DELEGATE")
	}

	// And because it is not forwardable, the delegation that would follow it is refused.
	backEnd := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, backEndSPN)

	proxy := tgsRequest(t, h, asRep.CName, asRep.Ticket, asRep.DecryptedEncPart.Key, backEnd,
		func(body *messages.KDCReqBody) {
			types.SetFlag(&body.KDCOptions, optionCNameInAddlTkt)
			body.AdditionalTickets = []messages.Ticket{rep.Ticket}
		}, nil)

	if _, errText := exchange(t, h, proxy); len(errText) == 0 {
		t.Fatal("a non-forwardable evidence ticket was accepted for delegation")
	} else if !strings.Contains(errText, "KDC_ERR_BADOPTION") {
		t.Errorf("error = %q, want KDC_ERR_BADOPTION", errText)
	}
}

func TestImpersonationIsLimitedToThePermittedPrincipals(t *testing.T) {
	ctx := context.Background()
	h, asRep := s4uSetup(t)

	// FreeIPA's ipaAllowToImpersonate narrows which users a service may act for; an empty list
	// means any of them, so naming someone else here must exclude alice.
	if _, err := h.store.UpdatePrincipal(ctx, krbkeys.MustParseName(frontEndSPN, testRealm),
		func(p *store.Principal) error {
			p.AllowedToImpersonate = []string{"bob@" + testRealm}

			return nil
		}); err != nil {
		t.Fatalf("restricting impersonation: %v", err)
	}

	self := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, frontEndSPN)

	raw := tgsRequest(t, h, asRep.CName, asRep.Ticket, asRep.DecryptedEncPart.Key, self, nil,
		[]types.PAData{forUserPAData(t, "alice", asRep.DecryptedEncPart.Key)})

	if _, errText := exchange(t, h, raw); len(errText) == 0 {
		t.Fatal("a service impersonated a user outside its permitted list")
	} else if !strings.Contains(errText, "KDC_ERR_BADOPTION") {
		t.Errorf("error = %q, want KDC_ERR_BADOPTION", errText)
	}
}

func TestS4U2SelfRejectsAForgedChecksum(t *testing.T) {
	h, asRep := s4uSetup(t)

	self := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, frontEndSPN)

	// The checksum is the only thing binding the request to the service that holds the ticket.
	// Signing it with the wrong key stands in for a client that made the request up.
	wrongKey := types.EncryptionKey{
		KeyType:  asRep.DecryptedEncPart.Key.KeyType,
		KeyValue: make([]byte, len(asRep.DecryptedEncPart.Key.KeyValue)),
	}

	raw := tgsRequest(t, h, asRep.CName, asRep.Ticket, asRep.DecryptedEncPart.Key, self, nil,
		[]types.PAData{forUserPAData(t, "alice", wrongKey)})

	if _, errText := exchange(t, h, raw); len(errText) == 0 {
		t.Fatal("a PA-FOR-USER with a bad checksum was accepted")
	} else if !strings.Contains(errText, "KRB_AP_ERR_MODIFIED") {
		t.Errorf("error = %q, want KRB_AP_ERR_MODIFIED", errText)
	}
}

func TestS4U2ProxyDelegatesToAPermittedService(t *testing.T) {
	h, asRep := s4uSetup(t)

	evidence := s4u2SelfTicket(t, h, asRep)

	backEnd := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, backEndSPN)

	raw := tgsRequest(t, h, asRep.CName, asRep.Ticket, asRep.DecryptedEncPart.Key, backEnd,
		func(body *messages.KDCReqBody) {
			types.SetFlag(&body.KDCOptions, optionCNameInAddlTkt)
			body.AdditionalTickets = []messages.Ticket{evidence}
		}, nil)

	rep, errText := exchange(t, h, raw)
	if len(errText) > 0 {
		t.Fatalf("S4U2Proxy refused: %s", errText)
	}

	// The back end receives a ticket naming the user, not the front end that asked for it.
	if got := rep.CName.PrincipalNameString(); got != "alice" {
		t.Errorf("delegated ticket names %q, want alice", got)
	}
	if got := rep.Ticket.SName.PrincipalNameString(); got != backEndSPN {
		t.Errorf("delegated ticket is for %q, want %s", got, backEndSPN)
	}
}

func TestS4U2ProxyIsRefusedForAnUnlistedService(t *testing.T) {
	ctx := context.Background()
	h, asRep := s4uSetup(t)

	evidence := s4u2SelfTicket(t, h, asRep)

	// The delegation list is the whole point of "constrained": a service may impersonate a user
	// only towards the services an administrator named.
	if _, err := h.store.UpdatePrincipal(ctx, krbkeys.MustParseName(frontEndSPN, testRealm),
		func(p *store.Principal) error {
			p.AllowedToDelegateTo = []string{"HTTP/somewhere.else@" + testRealm}

			return nil
		}); err != nil {
		t.Fatalf("narrowing the delegation list: %v", err)
	}

	backEnd := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, backEndSPN)

	raw := tgsRequest(t, h, asRep.CName, asRep.Ticket, asRep.DecryptedEncPart.Key, backEnd,
		func(body *messages.KDCReqBody) {
			types.SetFlag(&body.KDCOptions, optionCNameInAddlTkt)
			body.AdditionalTickets = []messages.Ticket{evidence}
		}, nil)

	if _, errText := exchange(t, h, raw); len(errText) == 0 {
		t.Fatal("a service delegated to a target it was not permitted to reach")
	} else if !strings.Contains(errText, "KDC_ERR_BADOPTION") {
		t.Errorf("error = %q, want KDC_ERR_BADOPTION", errText)
	}
}

// s4u2SelfTicket runs a protocol transition and returns the resulting ticket, which is the evidence
// a constrained delegation request carries.
func s4u2SelfTicket(t *testing.T, h *harness, asRep messages.ASRep) messages.Ticket {
	t.Helper()

	self := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, frontEndSPN)

	raw := tgsRequest(t, h, asRep.CName, asRep.Ticket, asRep.DecryptedEncPart.Key, self, nil,
		[]types.PAData{forUserPAData(t, "alice", asRep.DecryptedEncPart.Key)})

	rep, errText := exchange(t, h, raw)
	if len(errText) > 0 {
		t.Fatalf("S4U2Self refused: %s", errText)
	}

	return rep.Ticket
}
