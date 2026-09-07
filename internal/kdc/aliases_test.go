package kdc

import (
	"context"
	"testing"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
)

// addAlias gives an existing principal another name to answer to.
func (h *harness) addAlias(t *testing.T, principal, alias string) {
	t.Helper()

	if _, err := h.store.AddAlias(context.Background(),
		krbkeys.MustParseName(principal, testRealm),
		krbkeys.MustParseName(alias, testRealm),
	); err != nil {
		t.Fatalf("AddAlias(%s -> %s): %v", alias, principal, err)
	}
}

// asRequest drives an AS exchange at the message level. The client library refuses any reply whose
// cname differs from the request, which is precisely what canonicalization produces, so the
// exchange is built here instead: the pre-authentication is encrypted with the principal's stored
// key rather than derived from a password, which also keeps the salt out of the question.
func asRequest(t *testing.T, h *harness, cname, keyOf string, canonicalize bool) (messages.ASRep, string) {
	t.Helper()

	ctx := context.Background()

	req, err := messages.NewASReqForTGT(testRealm, h.clientConfig(false),
		types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, cname))
	if err != nil {
		t.Fatalf("building AS-REQ: %v", err)
	}

	if canonicalize {
		types.SetFlag(&req.ReqBody.KDCOptions, flags.Canonicalize)
	}

	p, err := h.store.GetPrincipal(ctx, krbkeys.MustParseName(keyOf, testRealm))
	if err != nil {
		t.Fatalf("GetPrincipal(%s): %v", keyOf, err)
	}

	key, ok := p.KeyFor(h.etypes[0])
	if !ok {
		t.Fatalf("%s holds no key of enctype %d", keyOf, h.etypes[0])
	}

	ts, err := types.GetPAEncTSEncAsnMarshalled()
	if err != nil {
		t.Fatalf("timestamp: %v", err)
	}

	enc, err := crypto.GetEncryptedData(ts, key.EncryptionKey(), keyusage.AS_REQ_PA_ENC_TIMESTAMP, p.KVNO)
	if err != nil {
		t.Fatalf("encrypting the timestamp: %v", err)
	}

	encb, err := enc.Marshal()
	if err != nil {
		t.Fatalf("marshalling the timestamp: %v", err)
	}

	req.PAData = types.PADataSequence{{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: encb}}

	raw, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshalling AS-REQ: %v", err)
	}

	reply := h.server.Handle(ctx, raw, nil)

	var rep messages.ASRep
	if err := rep.Unmarshal(reply); err != nil {
		var kerr messages.KRBError
		if uerr := kerr.Unmarshal(reply); uerr != nil {
			t.Fatalf("reply is neither an AS-REP nor a KRB-ERROR: %v", err)
		}

		return rep, kerr.Error()
	}

	return rep, ""
}

// ticketClient opens a ticket-granting ticket with the realm's own key and returns the client name
// sealed inside it.
func ticketClient(t *testing.T, h *harness, tkt messages.Ticket) string {
	t.Helper()

	krbtgt, err := h.store.GetPrincipal(context.Background(),
		krbkeys.MustParseName("krbtgt/"+testRealm, testRealm))
	if err != nil {
		t.Fatalf("GetPrincipal(krbtgt): %v", err)
	}

	key, ok := krbtgt.KeyFor(tkt.EncPart.EType)
	if !ok {
		t.Fatalf("krbtgt holds no key of enctype %d", tkt.EncPart.EType)
	}

	if err := tkt.Decrypt(key.EncryptionKey()); err != nil {
		t.Fatalf("decrypting the ticket: %v", err)
	}

	return tkt.DecryptedEncPart.CName.PrincipalNameString()
}

func TestAnAliasAuthenticatesAsThePrincipalItNames(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "alice", testPassword)
	h.addAlias(t, "alice", "alice.smith")

	// The password is the account's own, because both names reach the same keys. That is the
	// point of an alias, as against a second account that would need its own credentials.
	rep := login(t, h, "alice.smith", testPassword, false)

	// Nothing asked for canonicalization, so the reply names what was requested: a client that
	// did not ask to be renamed compares the reply against what it sent, and this library
	// refuses the exchange outright when the two differ.
	if got := rep.CName.PrincipalNameString(); got != "alice.smith" {
		t.Errorf("reply names %q, want the requested alice.smith", got)
	}
	if got := rep.Ticket.SName.PrincipalNameString(); got != "krbtgt/"+testRealm {
		t.Errorf("ticket is for %q, want krbtgt/%s", got, testRealm)
	}
}

func TestCanonicalizationAnswersInTheRealName(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "alice", testPassword)
	h.addAlias(t, "alice", "alice.smith")

	for _, tc := range []struct {
		name         string
		canonicalize bool
		want         string
	}{
		{"without the flag the requested name is echoed", false, "alice.smith"},
		{"with the flag the real name comes back", true, "alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep, errText := asRequest(t, h, "alice.smith", "alice", tc.canonicalize)
			if len(errText) > 0 {
				t.Fatalf("AS exchange refused: %s", errText)
			}

			if got := rep.CName.PrincipalNameString(); got != tc.want {
				t.Errorf("reply names %q, want %q", got, tc.want)
			}

			// The ticket has to name the same client as the reply, or the KDC would be
			// telling the client one thing and every service it visits another.
			if got := ticketClient(t, h, rep.Ticket); got != tc.want {
				t.Errorf("ticket names %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAServiceIsReachedThroughItsAlias(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "alice", testPassword)
	h.addService(t, testService)
	h.addAlias(t, testService, "HTTP/web.example.com")

	asRep := login(t, h, "alice", testPassword, false)

	for _, tc := range []struct {
		name         string
		canonicalize bool
		want         string
	}{
		{"the requested name is kept", false, "HTTP/web.example.com"},
		{"canonicalization renames the ticket", true, testService},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/web.example.com")

			var mutate func(body *messages.KDCReqBody)
			if tc.canonicalize {
				mutate = func(body *messages.KDCReqBody) {
					types.SetFlag(&body.KDCOptions, flags.Canonicalize)
				}
			}

			raw := tgsRequest(t, h, asRep.CName, asRep.Ticket, asRep.DecryptedEncPart.Key, sname, mutate, nil)

			rep, errText := exchange(t, h, raw)
			if len(errText) > 0 {
				t.Fatalf("TGS refused a service alias: %s", errText)
			}

			if got := rep.Ticket.SName.PrincipalNameString(); got != tc.want {
				t.Errorf("ticket is for %q, want %q", got, tc.want)
			}
		})
	}
}
