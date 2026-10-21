package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// requireVault skips a vault test when the stand came up without OpenBao (E2E_VAULT_IMAGE=off).
func requireVault(t *testing.T) {
	t.Helper()

	if shared.vault == nil {
		t.Skip("the vault container is disabled (E2E_VAULT_IMAGE=off)")
	}
}

// mustVaultExec runs a shell command in the vault container, authenticated to the API as root.
func (s *stand) mustVaultExec(t *testing.T, script string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out, err := s.vaultExec(ctx, []string{
		"BAO_ADDR=http://127.0.0.1:8200",
		"BAO_TOKEN=" + s.vaultToken,
	}, "sh", "-c", script)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return out
}

// vaultCA fetches the PKI's CA certificate through the client container and leaves it at
// /tmp/vault-ca.pem there.
func vaultCA(t *testing.T) string {
	t.Helper()

	return shared.mustRun(t, "curl -sf http://"+vaultHost+":8200/v1/pki/ca/pem | tee /tmp/vault-ca.pem")
}

// vaultLogin performs the SPNEGO login from the client container and returns the response body,
// failing the test with the whole exchange on any other outcome.
func vaultLogin(t *testing.T, cache string) string {
	t.Helper()

	status := shared.mustRun(t, "KRB5CCNAME=FILE:"+cache+" "+
		"curl -s --negotiate -u : -X POST http://"+vaultHost+":8200/v1/auth/kerberos/login "+
		"-o /tmp/vault-login.json -w '%{http_code}'")

	body := shared.mustRun(t, "cat /tmp/vault-login.json")

	if strings.TrimSpace(status) != "200" {
		t.Fatalf("the kerberos login failed with HTTP %s:\n%s", strings.TrimSpace(status), body)
	}

	return body
}

// issueUserCert logs seeded-user in to OpenBao over Kerberos — the same way a person with a
// ticket would — and has the PKI issue a certificate. The login carrying the user-certs policy
// proves the group membership was read from the directory: nothing in OpenBao itself names that
// policy for the account. The certificate is left at /tmp/vault-user-cert.pem in the client
// container and returned in PEM.
func issueUserCert(t *testing.T) string {
	t.Helper()

	shared.mustRun(t, kinitTo("/tmp/cc-vault", seededUser, seededPassword))

	login := vaultLogin(t, "/tmp/cc-vault")

	if !strings.Contains(login, "user-certs") {
		t.Fatalf("the kerberos login did not map the vault-users group to its policy:\n%s", login)
	}

	return shared.mustRun(t,
		"TOK=$(echo '"+login+"' | jq -r '.auth.client_token') && "+
			"curl -sf -H \"X-Vault-Token: $TOK\" -X POST "+
			"-d '{\"common_name\":\"seeded-user.example.com\",\"ttl\":\"24h\"}' "+
			"http://"+vaultHost+":8200/v1/pki/issue/user | "+
			"jq -r '.data.certificate' | tee /tmp/vault-user-cert.pem")
}

// TestVaultKerberosLoginIssuesUserCertificate is the round a user makes with nothing but a
// Kerberos ticket: the ticket is their credential, the directory says which groups they are in,
// and the groups say what the PKI will do for them.
func TestVaultKerberosLoginIssuesUserCertificate(t *testing.T) {
	requireVault(t)

	issueUserCert(t)

	vaultCA(t)

	out := shared.mustRun(t, "openssl verify -CAfile /tmp/vault-ca.pem /tmp/vault-user-cert.pem")
	if !strings.Contains(out, "OK") {
		t.Errorf("the issued certificate does not verify against the CA:\n%s", out)
	}
}

// TestVaultSwitchesToLDAPS turns the kerberos plugin's directory connection into a TLS one, with
// the CA it has to trust being the PKI's own — the certificate on :636 is the one the service
// enrolled for itself at stand setup, which is what closes the loop.
func TestVaultSwitchesToLDAPS(t *testing.T) {
	requireVault(t)

	ca := vaultCA(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := shared.vault.CopyToContainer(ctx, []byte(ca), "/tmp/vault-ca.pem", 0o644); err != nil {
		t.Fatalf("copying the CA into the vault: %v", err)
	}

	// The LDAP configuration merges with what is already written, so only the scheme and the CA
	// to trust change here.
	shared.mustVaultExec(t, "bao write auth/kerberos/config/ldap "+
		"url=ldaps://"+kdcHost+" certificate=@/tmp/vault-ca.pem")

	// A kerberos login now makes the plugin bind and search over LDAPS.
	shared.mustRun(t, kinitTo("/tmp/cc-vault2", seededUser, seededPassword))

	vaultLogin(t, "/tmp/cc-vault2")

	// The certificate the plugin just trusted is the enrolled one, and it verifies for a plain
	// TLS client too.
	out, _ := shared.run(t, "echo | openssl s_client -connect "+kdcHost+":636 -CAfile /tmp/vault-ca.pem 2>&1")
	if !strings.Contains(out, "Verify return code: 0 (ok)") {
		t.Errorf("the LDAPS certificate does not verify:\n%s", out)
	}

	search := shared.mustRun(t, "LDAPTLS_CACERT=/tmp/vault-ca.pem "+
		"ldapsearch -x -H ldaps://"+kdcHost+":636 -D '"+vaultBindDN+"' -w '"+vaultBindPass+"' "+
		"-b 'ou=users,dc=example,dc=com' '(uid="+seededUser+")' cn")
	if !strings.Contains(search, "cn: "+seededUser) {
		t.Errorf("the LDAPS search did not find the account:\n%s", search)
	}
}

// TestVaultIssuedCertificatePublishedInLDAP brings the certificate full circle: issued by the
// PKI, handed to the account it belongs to, and read back from the directory byte for byte.
func TestVaultIssuedCertificatePublishedInLDAP(t *testing.T) {
	requireVault(t)

	cert := issueUserCert(t)

	shared.mustAPI(t, "POST", "/users/"+seededUser+"/certificates/import",
		map[string]any{"certificate": cert}, http.StatusCreated)

	search := shared.mustRun(t,
		"ldapsearch -x -H ldap://"+kdcHost+" -D '"+vaultBindDN+"' -w '"+vaultBindPass+"' "+
			"-b 'cn="+seededUser+",ou=seeded,ou=users,dc=example,dc=com' "+
			"-LLL -o ldif-wrap=no '(cn="+seededUser+")' 'userCertificate;binary'")
	if !strings.Contains(search, "userCertificate;binary::") {
		t.Fatalf("the account does not publish a certificate:\n%s", search)
	}

	shared.mustRun(t,
		"ldapsearch -x -H ldap://"+kdcHost+" -D '"+vaultBindDN+"' -w '"+vaultBindPass+"' "+
			"-b 'cn="+seededUser+",ou=seeded,ou=users,dc=example,dc=com' "+
			"-LLL -o ldif-wrap=no '(cn="+seededUser+")' 'userCertificate;binary' | "+
			"awk '/^userCertificate;binary::/ {print $2}' | base64 -d > /tmp/ldap-cert.der && "+
			"openssl x509 -in /tmp/vault-user-cert.pem -outform DER > /tmp/vault-cert.der && "+
			"cmp /tmp/ldap-cert.der /tmp/vault-cert.der")
}
