package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// TestDNSDiscovery checks the records a Kerberos client needs before it can do anything at all.
//
// The queries name the server explicitly. On a user-defined network Docker puts its own resolver
// in the container's resolv.conf and makes ours the upstream, so a query left to the resolver can
// be answered by Docker for names it happens to know -- container names and their addresses among
// them. Asking directly is the only way to be sure whose answer is under test; that the resolver
// path works as a whole is what the kinit tests below demonstrate.
func TestDNSDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		want  string
	}{
		{"KDC service record", dig("-t SRV _kerberos._udp." + domain), "88 " + kdcHost + "."},
		{"password service record", dig("-t SRV _kpasswd._udp." + domain), "464 " + kdcHost + "."},
		{"directory service record", dig("-t SRV _ldap._tcp." + domain), "389 " + kdcHost + "."},
		{"realm of the domain", dig("-t TXT _kerberos." + domain), `"` + realm + `"`},
		{"the server's own address", dig("-t A " + kdcHost), serviceIP},
		{"reverse of that address", dig("-x " + serviceIP), kdcHost + "."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := shared.mustRun(t, tc.query)
			if !strings.Contains(out, tc.want) {
				t.Errorf("%s\ngot:  %q\nwant: it to contain %q", tc.query, strings.TrimSpace(out), tc.want)
			}
		})
	}
}

// TestNamesOutsideTheZoneAreRefused checks that the name server has not become an open resolver.
func TestNamesOutsideTheZoneAreRefused(t *testing.T) {
	out := shared.mustRun(t, "dig @"+serviceIP+" +noall +comments -t A www.google.com")
	if !strings.Contains(out, "status: REFUSED") {
		t.Errorf("got %q, want the query to be refused", strings.TrimSpace(out))
	}
}

// TestKinitFindsTheKDCThroughDNS is the scenario the DNS server exists for: a client configured
// with nothing but a realm name locates the KDC through the service records and authenticates.
func TestKinitFindsTheKDCThroughDNS(t *testing.T) {
	const (
		user     = "alice"
		password = "a sufficiently long password"
	)

	shared.addUser(t, user, password, false)

	// The client's krb5.conf carries no [realms] block, so a ticket here can only mean the SRV
	// lookup worked, the A record resolved, and the KDC answered.
	out := shared.mustRun(t, kinit(user, password))
	if len(strings.TrimSpace(out)) > 0 {
		t.Logf("kinit said: %s", strings.TrimSpace(out))
	}

	tickets := shared.mustRun(t, "klist")
	if !strings.Contains(tickets, "krbtgt/"+realm+"@"+realm) {
		t.Errorf("no ticket-granting ticket in the cache:\n%s", tickets)
	}
	if !strings.Contains(tickets, user+"@"+realm) {
		t.Errorf("the cache does not name the principal:\n%s", tickets)
	}
}

// TestServiceTicketWithHostCanonicalization exercises the reverse zone. MIT krb5 resolves a
// host-based service name forward and then back again before building the principal, so the
// answer this service gives to the reverse query decides which principal is asked for.
func TestServiceTicketWithHostCanonicalization(t *testing.T) {
	const (
		user     = "bob"
		password = "another long enough password"
		host     = "www." + domain
		spn      = "HTTP/" + host
		hostIP   = "10.99.0.20"
	)

	shared.addUser(t, user, password, false)

	shared.mustAPI(t, "POST", "/principals", map[string]any{"name": spn},
		http.StatusCreated, http.StatusConflict)
	shared.mustAPI(t, "POST", "/dns/records", map[string]any{
		"name": host, "type": "A", "value": hostIP,
	}, http.StatusCreated, http.StatusConflict)

	// Forward and reverse have to agree, or the canonicalisation produces a name nobody
	// registered. The reverse answer is derived from the address record just created.
	if out := shared.mustRun(t, dig("-x "+hostIP)); !strings.Contains(out, host+".") {
		t.Fatalf("reverse lookup gave %q, want %s.", strings.TrimSpace(out), host)
	}

	shared.mustRun(t, kinit(user, password))

	// kvno builds the principal from the host name the way any GSSAPI application would.
	out, code := shared.run(t, "kvno "+spn)
	if code != 0 {
		t.Fatalf("kvno failed:\n%s", out)
	}
	if !strings.Contains(out, spn+"@"+realm) {
		t.Errorf("kvno output does not name the service principal:\n%s", out)
	}

	tickets := shared.mustRun(t, "klist")
	if !strings.Contains(tickets, spn+"@"+realm) {
		t.Errorf("no service ticket in the cache:\n%s", tickets)
	}
}

// TestForcedPasswordChange follows the first login of an account an administrator provisioned:
// the password it was given is expired, so the owner has to choose one before getting a ticket.
func TestForcedPasswordChange(t *testing.T) {
	const (
		user    = "carol"
		initial = "the initial password"
		chosen  = "the password carol chose"
	)

	shared.addUser(t, user, initial, true)

	// MIT krb5 answers an expired password by starting a password change of its own rather than
	// simply refusing, so the check is that it says the password has expired at all.
	out, _ := shared.run(t, "KRB5CCNAME=FILE:/tmp/cc-carol "+kinit(user, initial))
	if !strings.Contains(strings.ToLower(out), "expired") {
		t.Errorf("the administratively set password was accepted without a change being demanded:\n%s", out)
	}

	changed := shared.mustRun(t,
		"printf '%s\\n%s\\n%s\\n' '"+initial+"' '"+chosen+"' '"+chosen+"' | kpasswd "+user+"@"+realm)
	if !strings.Contains(strings.ToLower(changed), "changed") {
		t.Fatalf("kpasswd did not report a change:\n%s", changed)
	}

	// The new password works over Kerberos...
	shared.mustRun(t, "KRB5CCNAME=FILE:/tmp/cc-carol2 "+kinit(user, chosen))

	// ...and over LDAP, because the two credentials are set together. Reading anything needs a
	// capability, so the account is granted one first: what is under test is the password, not
	// the authorization.
	shared.mustAPI(t, "PATCH", "/users/"+user, map[string]any{
		"capabilities": []map[string]string{{"action": "search", "object": "*"}},
	}, http.StatusOK)

	search := shared.mustRun(t, ldapsearch(user, chosen, "(cn="+user+")", "cn"))
	if !strings.Contains(search, "cn: "+user) {
		t.Errorf("the LDAP bind did not accept the new password:\n%s", search)
	}

	// The old password must not still work.
	if _, code := shared.run(t, ldapsearch(user, initial, "(cn="+user+")", "cn")); code == 0 {
		t.Error("the superseded password still binds")
	}
}

// TestLDAPSearch checks the directory half with the reference client.
func TestLDAPSearch(t *testing.T) {
	const (
		user     = "dave"
		password = "yet another long password"
	)

	shared.addUser(t, user, password, false)

	// Reading the tree needs a capability, so an account without one sees nothing.
	_, code := shared.run(t, ldapsearch(user, password, "(objectClass=posixAccount)", "cn"))
	if code == 0 {
		t.Error("an account with no search capability read the directory")
	}

	shared.mustAPI(t, "PATCH", "/users/"+user, map[string]any{
		"capabilities": []map[string]string{{"action": "search", "object": "*"}},
	}, http.StatusOK)

	out := shared.mustRun(t, ldapsearch(user, password, "(objectClass=posixAccount)",
		"cn uidNumber krbPrincipalName ipaNTSecurityIdentifier"))

	for _, want := range []string{
		"cn: " + user,
		"krbPrincipalName: " + user + "@" + realm,
		"ipaNTSecurityIdentifier: S-1-5-21-",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the entry is missing %q:\n%s", want, out)
		}
	}
}

// TestWrongPasswordIsRefused checks the negative path through the real client.
func TestWrongPasswordIsRefused(t *testing.T) {
	const (
		user     = "erin"
		password = "the correct long password"
	)

	shared.addUser(t, user, password, false)

	out, code := shared.run(t, "KRB5CCNAME=FILE:/tmp/cc-erin "+kinit(user, "not the password"))
	if code == 0 {
		t.Fatalf("a wrong password produced a ticket:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "preauthentication failed") &&
		!strings.Contains(strings.ToLower(out), "password incorrect") {
		t.Errorf("unexpected failure:\n%s", out)
	}
}

// dig builds a query aimed at the service under test rather than at whatever the container's
// resolver happens to be.
func dig(args string) string {
	return "dig @" + serviceIP + " +short " + args
}

// kinit builds a command that feeds the password in without a terminal.
func kinit(user, password string) string {
	return "printf '%s\\n' '" + password + "' | kinit " + user + "@" + realm
}

// ldapsearch builds a simple-bind search against the directory.
func ldapsearch(user, password, filter, attrs string) string {
	dn := "cn=" + user + ",ou=e2e,ou=users,dc=example,dc=com"

	return "ldapsearch -x -H ldap://" + kdcHost + " -D '" + dn + "' -w '" + password +
		"' -b 'dc=example,dc=com' '" + filter + "' " + attrs
}
