// Package ldapsrv serves the directory over LDAP, backed by the same store the KDC authenticates
// against.
package ldapsrv

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/glauth/ldap"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// entryBuilder turns store objects into LDAP entries. The DN layout follows glauth's, so clients
// and configurations written against it keep working:
//
//	<nameformat>=<user>,<groupformat>=<primary group>,ou=users,<basedn>
//	<groupformat>=<group>,ou=groups,<basedn>
type entryBuilder struct {
	cfg Config
	st  *store.Store
}

// UserDN returns the distinguished name of a user, given the name of its primary group.
func (b *entryBuilder) UserDN(user *store.User, primaryGroup string) string {
	return fmt.Sprintf("%s=%s,%s=%s,ou=users,%s",
		b.cfg.NameFormat, user.Name, b.cfg.GroupFormat, primaryGroup, b.cfg.BaseDN)
}

// GroupDN returns the distinguished name of a group.
func (b *entryBuilder) GroupDN(name string) string {
	return fmt.Sprintf("%s=%s,ou=groups,%s", b.cfg.GroupFormat, name, b.cfg.BaseDN)
}

// PosixAccounts renders every user as a posixAccount entry.
func (b *entryBuilder) PosixAccounts(ctx context.Context) ([]*ldap.Entry, error) {
	users, err := b.st.ListUsers(ctx)
	if err != nil {
		return nil, err
	}

	groupNames, err := b.st.GroupNames(ctx)
	if err != nil {
		return nil, err
	}

	// The Kerberos state and the security identifiers are fetched for every account at once;
	// asking per entry would be a pair of queries for each result of every search.
	principals, err := b.st.PrimaryPrincipals(ctx)
	if err != nil {
		return nil, err
	}

	rids, err := b.st.RIDs(ctx, "user")
	if err != nil {
		return nil, err
	}

	entries := make([]*ldap.Entry, 0, len(users))

	for i := range users {
		u := &users[i]

		gids, err := b.st.UserGIDs(ctx, u)
		if err != nil {
			return nil, err
		}

		var principal *store.Principal
		if p, ok := principals[u.ID]; ok {
			principal = &p
		}

		entries = append(entries, b.accountEntry(u, groupNames, gids, principal, rids[u.ID]))
	}

	return entries, nil
}

func (b *entryBuilder) accountEntry(
	u *store.User,
	groupNames map[int]string,
	gids []int,
	principal *store.Principal,
	rid int,
) *ldap.Entry {
	primary := groupNames[u.PrimaryGroup]

	// The object classes name both the POSIX schema and the Kerberos one MIT and FreeIPA use,
	// so a client that knows either can read what it expects from the same entry.
	classes := []string{"posixAccount", "shadowAccount", "inetOrgPerson", "top"}
	if principal != nil {
		classes = append(classes, "krbPrincipalAux", "krbTicketPolicyAux")
	}
	if rid > 0 {
		classes = append(classes, "ipaNTUserAttrs")
	}

	attrs := []*ldap.EntryAttribute{
		{Name: b.cfg.NameFormat, Values: []string{u.Name}},
		{Name: "uid", Values: []string{u.Name}},
		{Name: "ou", Values: []string{primary}},
		{Name: "uidNumber", Values: []string{strconv.Itoa(u.UIDNumber)}},
		{Name: "gidNumber", Values: []string{strconv.Itoa(u.PrimaryGroup)}},
		{Name: "objectClass", Values: classes},
	}

	if len(u.GivenName) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{u.GivenName}})
	}
	if len(u.SN) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "sn", Values: []string{u.SN}})
	}

	status := "active"
	if u.Disabled {
		status = "inactive"
	}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{status}})

	if len(u.Mail) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{u.Mail}})
	}

	// The Kerberos identity is published alongside the POSIX one, so a client that has to map
	// an account to a principal can read it here instead of guessing at the realm. As in
	// FreeIPA, krbPrincipalName lists every name the account answers to and krbCanonicalName
	// says which of them is the real one.
	//
	// userPrincipalName is the SAME name under the spelling Active Directory uses, and it is the
	// one a client written for AD searches by. It used to carry the account's mail address, which
	// is a different fact that merely tends to look alike: an AD client then found nothing, and an
	// account with no mail published no logon name at all. Measured against OpenBao's kerberos auth
	// method (2026-09-08), which takes the realm off the presented ticket and searches
	// `(userPrincipalName=<account>@<REALM>)` with no way to be told another attribute — a valid
	// ticket authenticated and the account was then unfindable.
	if len(b.cfg.Realm) > 0 {
		name := u.Name + "@" + b.cfg.Realm
		names := []string{name}

		if principal != nil {
			for _, a := range principal.Aliases {
				names = append(names, a+"@"+principal.Realm)
			}
		}

		attrs = append(attrs,
			&ldap.EntryAttribute{Name: "krbPrincipalName", Values: names},
			&ldap.EntryAttribute{Name: "krbCanonicalName", Values: []string{name}},
			&ldap.EntryAttribute{Name: "userPrincipalName", Values: []string{name}},
		)
	}

	attrs = append(attrs, b.kerberosAttributes(principal)...)

	if sid := b.securityIdentifier(rid); len(sid) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "ipaNTSecurityIdentifier", Values: []string{sid}})
	}

	shell := u.LoginShell
	if len(shell) == 0 {
		shell = "/bin/bash"
	}

	home := u.Homedir
	if len(home) == 0 {
		home = "/home/" + u.Name
	}

	attrs = append(attrs,
		&ldap.EntryAttribute{Name: "loginShell", Values: []string{shell}},
		&ldap.EntryAttribute{Name: "homeDirectory", Values: []string{home}},
		&ldap.EntryAttribute{Name: "description", Values: []string{u.Name}},
		&ldap.EntryAttribute{Name: "gecos", Values: []string{u.Name}},
		&ldap.EntryAttribute{Name: "memberOf", Values: b.groupDNs(gids)},
		&ldap.EntryAttribute{Name: "shadowExpire", Values: []string{"-1"}},
		&ldap.EntryAttribute{Name: "shadowFlag", Values: []string{"134538308"}},
		&ldap.EntryAttribute{Name: "shadowInactive", Values: []string{"-1"}},
		&ldap.EntryAttribute{Name: "shadowLastChange", Values: []string{"11000"}},
		&ldap.EntryAttribute{Name: "shadowMax", Values: []string{"99999"}},
		&ldap.EntryAttribute{Name: "shadowMin", Values: []string{"-1"}},
		&ldap.EntryAttribute{Name: "shadowWarning", Values: []string{"7"}},
	)

	if len(u.SSHKeys) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: b.cfg.SSHKeyAttr, Values: u.SSHKeys})
	}

	attrs = append(attrs, customAttributes(u.CustomAttrs)...)

	return &ldap.Entry{DN: b.UserDN(u, primary), Attributes: attrs}
}

// customAttributes renders an object's custom attributes in name order, so two searches of the
// same entry return them the same way round.
//
// They are published exactly as they were stored. The directory has no opinion about what they
// mean -- that an account heads a department, that a group owns a cost centre -- which is what
// makes them useful to whatever reads this directory to decide something.
func customAttributes(attrs map[string][]string) []*ldap.EntryAttribute {
	names := make([]string, 0, len(attrs))
	for k := range attrs {
		names = append(names, k)
	}
	sort.Strings(names)

	out := make([]*ldap.EntryAttribute, 0, len(names))
	for _, k := range names {
		out = append(out, &ldap.EntryAttribute{Name: k, Values: attrs[k]})
	}

	return out
}

// kerberosAttributes publishes the principal's state under the attribute names MIT's LDAP backend
// and FreeIPA use, so an administrator can read a ticket policy or a lockout counter with the same
// query they would run against either.
func (b *entryBuilder) kerberosAttributes(p *store.Principal) []*ldap.EntryAttribute {
	if p == nil {
		return nil
	}

	attrs := []*ldap.EntryAttribute{
		{Name: "krbTicketFlags", Values: []string{strconv.FormatInt(int64(p.TicketFlags()), 10)}},
		{Name: "krbLoginFailedCount", Values: []string{strconv.Itoa(p.FailCount)}},
	}

	// A zero lifetime means the realm default applies, and MIT leaves the attribute off in that
	// case rather than claiming a limit of zero seconds.
	for _, d := range []struct {
		name  string
		value time.Duration
	}{
		{"krbMaxTicketLife", p.MaxTicketLife},
		{"krbMaxRenewableAge", p.MaxRenewableLife},
	} {
		if d.value > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{
				Name:   d.name,
				Values: []string{strconv.Itoa(int(d.value / time.Second))},
			})
		}
	}

	for _, t := range []struct {
		name  string
		value *time.Time
	}{
		{"krbLastPwdChange", p.PasswordLastSet},
		{"krbPasswordExpiration", p.PasswordExpiresAt},
		{"krbPrincipalExpiration", p.ExpiresAt},
		{"krbLastSuccessfulAuth", p.LastSuccess},
		{"krbLastFailedAuth", p.LastFailure},
	} {
		if t.value != nil {
			attrs = append(attrs, &ldap.EntryAttribute{
				Name:   t.name,
				Values: []string{generalizedTime(*t.value)},
			})
		}
	}

	return attrs
}

// securityIdentifier renders a relative identifier as the full SID a Windows member server reads.
func (b *entryBuilder) securityIdentifier(rid int) string {
	if rid <= 0 || len(b.cfg.DomainSID) == 0 {
		return ""
	}

	return b.cfg.DomainSID + "-" + strconv.Itoa(rid)
}

// generalizedTime formats a time the way LDAP's GeneralizedTime syntax wants it.
func generalizedTime(t time.Time) string {
	return t.UTC().Format("20060102150405Z")
}

// PosixGroups renders every group. Under ou=groups they are groupOfUniqueNames listing member DNs;
// under ou=users they are posixGroups listing member names, which is what nsswitch expects.
func (b *entryBuilder) PosixGroups(ctx context.Context, hierarchy string) ([]*ldap.Entry, error) {
	groups, err := b.st.ListGroups(ctx)
	if err != nil {
		return nil, err
	}

	groupNames, err := b.st.GroupNames(ctx)
	if err != nil {
		return nil, err
	}

	rids, err := b.st.RIDs(ctx, "group")
	if err != nil {
		return nil, err
	}

	asUniqueNames := hierarchy == "ou=groups"
	entries := make([]*ldap.Entry, 0, len(groups))

	for i := range groups {
		g := &groups[i]

		members, err := b.st.GroupMembers(ctx, g.GIDNumber)
		if err != nil {
			return nil, err
		}

		attrs := []*ldap.EntryAttribute{
			{Name: b.cfg.GroupFormat, Values: []string{g.Name}},
			{Name: "cn", Values: []string{g.Name}},
			{Name: "gidNumber", Values: []string{strconv.Itoa(g.GIDNumber)}},
		}

		description := g.Description
		if len(description) == 0 {
			description = g.Name
		}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{description}})

		classes := []string{"posixGroup", "top"}
		if asUniqueNames {
			classes = []string{"groupOfUniqueNames", "top"}
		}

		if sid := b.securityIdentifier(rids[g.ID]); len(sid) > 0 {
			classes = append(classes, "ipaNTGroupAttrs")
			attrs = append(attrs, &ldap.EntryAttribute{
				Name:   "ipaNTSecurityIdentifier",
				Values: []string{sid},
			})
		}

		if asUniqueNames {
			attrs = append(attrs, &ldap.EntryAttribute{
				Name:   "uniqueMember",
				Values: b.memberDNs(ctx, members, groupNames),
			})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: members})
		}

		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: classes})
		attrs = append(attrs, customAttributes(g.CustomAttrs)...)

		dn := fmt.Sprintf("%s=%s,%s,%s", b.cfg.GroupFormat, g.Name, hierarchy, b.cfg.BaseDN)
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}

	return entries, nil
}

// memberDNs turns member names into their distinguished names.
func (b *entryBuilder) memberDNs(ctx context.Context, names []string, groupNames map[int]string) []string {
	out := make([]string, 0, len(names))

	for _, n := range names {
		u, err := b.st.GetUser(ctx, n)
		if err != nil {
			continue
		}
		out = append(out, b.UserDN(u, groupNames[u.PrimaryGroup]))
	}

	sort.Strings(out)

	return out
}

// groupDNs maps gid numbers to group DNs.
func (b *entryBuilder) groupDNs(gids []int) []string {
	out := make([]string, 0, len(gids))

	names, err := b.st.GroupNames(context.Background())
	if err != nil {
		return out
	}

	for _, gid := range gids {
		if n, ok := names[gid]; ok {
			out = append(out, b.GroupDN(n))
		}
	}

	sort.Strings(out)

	return out
}

// rootDSE describes the server to a client that has not bound yet.
func (b *entryBuilder) rootDSE(dn string) *ldap.Entry {
	return &ldap.Entry{DN: dn, Attributes: []*ldap.EntryAttribute{
		// A client probing the root DSE almost always filters on (objectClass=*), so the
		// attribute has to be present or the entry is filtered out of its own reply.
		{Name: "objectClass", Values: []string{"top", "LDAProotDSE"}},
		{Name: "supportedLDAPVersion", Values: []string{"3"}},
		{Name: "supportedSASLMechanisms", Values: []string{}},
		{Name: "supportedControl", Values: []string{}},
		{Name: "supportedCapabilities", Values: []string{}},
		{Name: "subschemaSubentry", Values: []string{"cn=schema"}},
		{Name: "namingContexts", Values: []string{b.cfg.BaseDN}},
		{Name: "defaultNamingContext", Values: []string{b.cfg.BaseDN}},
		{Name: "vendorName", Values: []string{"ldap-kdc"}},
		{Name: "krbRealm", Values: []string{b.cfg.Realm}},
	}}
}

// topLevelRoot renders the naming context entry itself.
func (b *entryBuilder) topLevelRoot() *ldap.Entry {
	attrs := []*ldap.EntryAttribute{
		{Name: "objectClass", Values: []string{"organizationalUnit", "dcObject", "top"}},
	}

	for rdn := range strings.SplitSeq(b.cfg.BaseDN, ",") {
		if k, v, ok := strings.Cut(rdn, "="); ok {
			attrs = append(attrs, &ldap.EntryAttribute{Name: k, Values: []string{v}})
		}
	}

	return &ldap.Entry{DN: b.cfg.BaseDN, Attributes: attrs}
}

// container renders an organizational unit node such as ou=users or ou=groups.
func (b *entryBuilder) container(name string) *ldap.Entry {
	return &ldap.Entry{
		DN: fmt.Sprintf("ou=%s,%s", name, b.cfg.BaseDN),
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{name}},
			{Name: "objectClass", Values: []string{"organizationalUnit", "top"}},
		},
	}
}
