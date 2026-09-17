package kdc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/krb5/types"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// s4uClientSetup is s4uSetup with the back end's keytab kept, so the delegated ticket can be
// accepted the way the back end would accept it, and the front end logged in over the network the
// way a real service does.
func s4uClientSetup(t *testing.T) (*harness, *client.Client, *keytab.Keytab) {
	t.Helper()

	ctx := context.Background()
	h := newHarness(t)
	h.addUser(t, "alice", testPassword)

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

	kt := h.addService(t, backEndSPN)

	cl := client.NewWithPassword(frontEndSPN, testRealm, servicePass, h.clientConfig(false))
	if err := cl.Login(); err != nil {
		t.Fatalf("front end login: %v", err)
	}

	return h, cl, kt
}

func TestClientImpersonateIsAcceptedAsTheUserByTheBackEnd(t *testing.T) {
	_, cl, kt := s4uClientSetup(t)

	alice := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")

	imp, err := cl.Impersonate(alice, testRealm, backEndSPN)
	if err != nil {
		t.Fatalf("Impersonate: %v", err)
	}

	if got := imp.Ticket.SName.PrincipalNameString(); got != backEndSPN {
		t.Fatalf("ticket is for %q, want %s", got, backEndSPN)
	}

	initiator := spnego.SPNEGOClient(cl, backEndSPN, spnego.OnBehalfOf(imp), spnego.MutualAuthentication())

	ct, err := initiator.InitSecContext()
	if err != nil {
		t.Fatalf("InitSecContext: %v", err)
	}

	b, err := ct.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var st spnego.SPNEGOToken
	if err := st.Unmarshal(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	ok, ctx, status := spnego.SPNEGOService(kt).AcceptSecContext(&st)
	if !ok {
		t.Fatalf("the back end refused the delegated ticket: %d %s", status.Code, status.Message)
	}

	creds := ctx.Value(spnego.CTXKey).(*credentials.Credentials)
	if creds.UserName() != "alice" {
		t.Fatalf("the back end sees %q, want alice", creds.UserName())
	}

	ad := creds.GetADCredentials()
	t.Logf("back end sees %s@%s, PAC user %q, %d group SIDs", creds.UserName(), creds.Domain(), ad.EffectiveName, len(ad.GroupMembershipSIDs))

	if ad.EffectiveName != "alice" {
		t.Errorf("PAC names %q, want alice: the groups the back end authorizes by are not the user's", ad.EffectiveName)
	}

	reply, err := st.ResponseToken()
	if err != nil {
		t.Fatalf("ResponseToken: %v", err)
	}

	if err := initiator.VerifyMutual(reply); err != nil {
		t.Fatalf("VerifyMutual: %v", err)
	}
}

func TestClientImpersonateToAnUnlistedServiceIsTheKDCsRefusal(t *testing.T) {
	h, cl, _ := s4uClientSetup(t)
	h.addService(t, "HTTP/elsewhere.example.com")

	_, err := cl.Impersonate(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"), testRealm, "HTTP/elsewhere.example.com")
	if err == nil {
		t.Fatal("delegated to a service outside the list")
	}

	var kerr messages.KRBError
	if !errors.As(err, &kerr) {
		t.Fatalf("error %v does not carry the KDC's KRB_ERROR", err)
	}

	if !strings.Contains(err.Error(), "KDC_ERR_BADOPTION") {
		t.Errorf("error = %v, want KDC_ERR_BADOPTION", err)
	}

	t.Logf("refusal: %v", err)
}

func TestClientImpersonateWithoutTrustToAuthenticateForDelegationStopsBeforeTheTarget(t *testing.T) {
	h, cl, _ := s4uClientSetup(t)

	if _, err := h.store.UpdatePrincipal(context.Background(), krbkeys.MustParseName(frontEndSPN, testRealm),
		func(p *store.Principal) error {
			p.OKToAuthAsDelegate = false

			return nil
		}); err != nil {
		t.Fatalf("clearing the delegation flag: %v", err)
	}

	_, err := cl.Impersonate(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"), testRealm, backEndSPN)
	if !errors.Is(err, client.ErrEvidenceNotForwardable) {
		t.Fatalf("error = %v, want ErrEvidenceNotForwardable", err)
	}

	t.Logf("refusal: %v", err)
}
