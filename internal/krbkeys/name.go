// Package krbkeys turns passwords into Kerberos long-term keys and formats the results as keytabs.
package krbkeys

import (
	"fmt"
	"strings"

	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/types"
)

// Name is a parsed Kerberos principal name: its components and the realm it belongs to.
type Name struct {
	Components []string
	Realm      string
}

// ParseName splits "HTTP/host.example.com@EXAMPLE.COM" into components and realm. A name without
// an "@" takes defaultRealm. The realm is upper-cased, matching the convention every KDC follows
// and which clients rely on when they compare a ticket's realm to their own.
func ParseName(s, defaultRealm string) (Name, error) {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return Name{}, fmt.Errorf("empty principal name")
	}

	var realm string

	// A backslash escapes an "@" inside a component, so only an unescaped one separates the realm.
	if i := lastUnescapedIndex(s, '@'); i >= 0 {
		realm, s = s[i+1:], s[:i]
	} else {
		realm = defaultRealm
	}

	realm = strings.ToUpper(realm)
	if len(realm) == 0 {
		return Name{}, fmt.Errorf("principal %q has no realm and no default realm was given", s)
	}

	comps := splitUnescaped(s, '/')
	for _, c := range comps {
		if len(c) == 0 {
			return Name{}, fmt.Errorf("principal %q has an empty component", s)
		}
	}

	return Name{Components: comps, Realm: realm}, nil
}

// MustParseName is ParseName for names known to be well formed at the call site.
func MustParseName(s, defaultRealm string) Name {
	n, err := ParseName(s, defaultRealm)
	if err != nil {
		panic(err)
	}

	return n
}

// NameFromPrincipalName converts the wire form into a Name.
func NameFromPrincipalName(pn types.PrincipalName, realm string) Name {
	comps := make([]string, len(pn.NameString))
	copy(comps, pn.NameString)

	return Name{Components: comps, Realm: strings.ToUpper(realm)}
}

// Principal returns the name without the realm, e.g. "HTTP/host.example.com".
func (n Name) Principal() string {
	return strings.Join(n.Components, "/")
}

// String returns the full name, e.g. "HTTP/host.example.com@EXAMPLE.COM".
func (n Name) String() string {
	return n.Principal() + "@" + n.Realm
}

// Type reports the name type to advertise on the wire. Multi-component names are service
// instances; single component names are ordinary principals.
func (n Name) Type() int32 {
	if len(n.Components) > 1 {
		return nametype.KRB_NT_SRV_INST
	}

	return nametype.KRB_NT_PRINCIPAL
}

// PrincipalName returns the wire form.
func (n Name) PrincipalName() types.PrincipalName {
	comps := make([]string, len(n.Components))
	copy(comps, n.Components)

	return types.PrincipalName{NameType: n.Type(), NameString: comps}
}

// IsTGS reports whether this is a ticket-granting service name, i.e. "krbtgt/<realm>".
func (n Name) IsTGS() bool {
	return len(n.Components) == 2 && n.Components[0] == "krbtgt"
}

// IsChangePW reports whether this names the password changing service.
func (n Name) IsChangePW() bool {
	return len(n.Components) == 2 && n.Components[0] == "kadmin" && n.Components[1] == "changepw"
}

// Equal compares two names case-sensitively in the components and case-insensitively in the realm.
func (n Name) Equal(o Name) bool {
	if len(n.Components) != len(o.Components) || !strings.EqualFold(n.Realm, o.Realm) {
		return false
	}
	for i := range n.Components {
		if n.Components[i] != o.Components[i] {
			return false
		}
	}

	return true
}

// DefaultSalt returns the RFC 4120 default salt for the name: the realm followed by the
// concatenated components, with no separators. Clients compute the same string when they turn the
// typed password into a key, so it has to match byte for byte or every login fails.
func (n Name) DefaultSalt() string {
	return n.Realm + strings.Join(n.Components, "")
}

// lastUnescapedIndex finds the last occurrence of c that is not preceded by a backslash.
func lastUnescapedIndex(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != c {
			continue
		}
		if i == 0 || s[i-1] != '\\' {
			return i
		}
	}

	return -1
}

// splitUnescaped splits on unescaped occurrences of sep, dropping the escaping backslashes.
func splitUnescaped(s string, sep byte) []string {
	var (
		out []string
		cur strings.Builder
		esc bool
	)

	for i := 0; i < len(s); i++ {
		switch {
		case esc:
			cur.WriteByte(s[i])
			esc = false
		case s[i] == '\\':
			esc = true
		case s[i] == sep:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	out = append(out, cur.String())

	return out
}
