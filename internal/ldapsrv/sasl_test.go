package ldapsrv

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/glauth/ldap"
	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/metrics"
)

// A full handshake needs a ticket, and a ticket needs the KDC — that is the stand's test, driven by
// a real client. What is tested here is everything the directory decides on its own: what it
// offers, what it refuses, and the key it would verify against.

const testSPN = "ldap/dc.example.com"

// saslHandler builds a handler over the harness store with the service principal given.
func saslHandler(t *testing.T, h *harness, spn string) *Handler {
	t.Helper()

	return NewHandler(Config{
		BaseDN: testBaseDN, NameFormat: "cn", GroupFormat: "ou", Realm: testRealm,
		EncTypes: h.etypes, SPN: spn,
	}, h.store, zerolog.New(io.Discard), metrics.New())
}

// TestTheRootDSEOffersOnlyWhatTheDirectoryCanDo: a client reads the mechanisms before it decides
// how to bind, so advertising GSSAPI on a directory with no service principal would send every
// Kerberos client down a path that always fails.
func TestTheRootDSEOffersOnlyWhatTheDirectoryCanDo(t *testing.T) {
	h := newHarness(t)

	withSPN := saslHandler(t, h, testSPN).entries.rootDSE("")
	without := saslHandler(t, h, "").entries.rootDSE("")

	mechanisms := func(e *ldap.Entry) []string {
		for _, a := range e.Attributes {
			if a.Name == "supportedSASLMechanisms" {
				return a.Values
			}
		}
		t.Fatal("the root DSE carries no supportedSASLMechanisms attribute at all")

		return nil
	}

	if got := mechanisms(withSPN); !slices.Equal(got, []string{saslMechanism}) {
		t.Errorf("with a service principal the root DSE offers %v, want %v", got, []string{saslMechanism})
	}
	if got := mechanisms(without); len(got) != 0 {
		t.Errorf("with no service principal the root DSE offers %v, want nothing", got)
	}
}

// TestSASLIsRefusedWithoutAServicePrincipal: the setting is what turns the mechanism on, and a
// directory without it refuses as a directory that does not speak SASL, not as one that does and
// dislikes the caller.
func TestSASLIsRefusedWithoutAServicePrincipal(t *testing.T) {
	h := newHarness(t)

	code, creds, dn, err := saslHandler(t, h, "").BindSASL(saslMechanism, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code != ldap.LDAPResultAuthMethodNotSupported {
		t.Errorf("code = %v, want authMethodNotSupported", code)
	}
	if len(creds) > 0 || len(dn) > 0 {
		t.Errorf("a refusal carried credentials %q and dn %q", creds, dn)
	}
}

// TestAnUnknownMechanismIsRefused: this directory speaks one, and a client asking for another is
// told so rather than having its token read as GSSAPI.
func TestAnUnknownMechanismIsRefused(t *testing.T) {
	h := newHarness(t)

	code, _, _, err := saslHandler(t, h, testSPN).BindSASL("PLAIN", []byte("user\x00pass"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if code != ldap.LDAPResultAuthMethodNotSupported {
		t.Errorf("code = %v, want authMethodNotSupported", code)
	}
}

// TestAMalformedTokenIsInvalidCredentials drives the first leg with something that is not a
// Kerberos token at all: the service keytab is built, the token fails to parse, and the client is
// told what a failed bind is told — no more, and no panic.
func TestAMalformedTokenIsInvalidCredentials(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	handler := saslHandler(t, h, testSPN)

	if err := handler.EnsureServicePrincipal(ctx); err != nil {
		t.Fatalf("EnsureServicePrincipal: %v", err)
	}

	code, _, _, err := handler.BindSASL(saslMechanism, []byte("this is not an AP-REQ"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if code != ldap.LDAPResultInvalidCredentials {
		t.Errorf("code = %v, want invalidCredentials", code)
	}
}

// TestTheServicePrincipalIsCreatedOnce: the directory is its own KDC, so the key a bind is verified
// against is a row it can write itself. An operator who had to create it by hand would discover the
// omission as "the ticket did not verify", which names the wrong thing.
func TestTheServicePrincipalIsCreatedOnce(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	handler := saslHandler(t, h, testSPN)

	if err := handler.EnsureServicePrincipal(ctx); err != nil {
		t.Fatalf("first call: %v", err)
	}

	name, err := krbkeys.ParseName(testSPN, testRealm)
	if err != nil {
		t.Fatal(err)
	}
	p, err := h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("the principal was not created: %v", err)
	}
	if len(p.Keys) == 0 {
		t.Error("the principal was created with no keys")
	}

	// Called again on every start, so it has to be idempotent rather than merely tolerant.
	if err := handler.EnsureServicePrincipal(ctx); err != nil {
		t.Fatalf("second call: %v", err)
	}
	again, err := h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if again.KVNO != p.KVNO {
		t.Errorf("the second call re-keyed the principal: kvno %d then %d", p.KVNO, again.KVNO)
	}
}

// TestAServicePrincipalThatIsNotTheDirectorysIsRefused: a name of the wrong shape or the wrong
// realm fails at startup, where an operator is looking, instead of at every bind.
func TestAServicePrincipalThatIsNotTheDirectorysIsRefused(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	for name, spn := range map[string]string{
		"not an ldap service": "HTTP/dc.example.com",
		"another realm":       "ldap/dc.example.com@ELSEWHERE.COM",
		"no host at all":      "ldap",
	} {
		t.Run(name, func(t *testing.T) {
			err := saslHandler(t, h, spn).EnsureServicePrincipal(ctx)
			if err == nil {
				t.Fatalf("%q was accepted", spn)
			}
			if !strings.Contains(err.Error(), "spn") {
				t.Errorf("error = %q, want it to name the setting at fault", err)
			}
		})
	}
}
