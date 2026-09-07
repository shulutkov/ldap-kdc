// Package store is the single source of truth for the directory: users, groups, Kerberos
// principals and their key material, all in one SQLite database.
//
// Both protocol front ends read from here, which is the point of the whole service: an LDAP bind
// and a Kerberos AS exchange authenticate the same account against credentials that were set once.
// They cannot share one credential, though. An LDAP simple bind compares a password against a
// bcrypt hash, while Kerberos must reproduce the principal's long-term key exactly; a hash cannot
// be turned back into a key. So a password set through this package writes both forms, and an
// account that only ever received a hash can bind over LDAP but cannot obtain a ticket until its
// password is set here.
package store

import (
	"time"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
)

// Capability grants an account the right to perform an action on an object, following glauth's
// model: action is typically "search" and object an LDAP subtree or "*".
type Capability struct {
	Action string `json:"action"`
	Object string `json:"object"`
}

// AppPassword is an additional password that authenticates a single application. Revoking one does
// not disturb the account's main password.
type AppPassword struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`

	// Hash is the bcrypt digest and is never serialized.
	Hash string `json:"-"`
}

// User is a directory account: what LDAP publishes and what a user principal is attached to.
type User struct {
	ID           int64               `json:"id"`
	Name         string              `json:"name"`
	UIDNumber    int                 `json:"uidNumber"`
	PrimaryGroup int                 `json:"primaryGroup"`
	OtherGroups  []int               `json:"otherGroups"`
	GivenName    string              `json:"givenName,omitempty"`
	SN           string              `json:"sn,omitempty"`
	Mail         string              `json:"mail,omitempty"`
	LoginShell   string              `json:"loginShell,omitempty"`
	Homedir      string              `json:"homeDirectory,omitempty"`
	Disabled     bool                `json:"disabled"`
	SSHKeys      []string            `json:"sshKeys,omitempty"`
	CustomAttrs  map[string][]string `json:"customAttributes,omitempty"`
	Capabilities []Capability        `json:"capabilities,omitempty"`
	AppPasswords []AppPassword       `json:"appPasswords,omitempty"`
	CreatedAt    time.Time           `json:"createdAt"`
	UpdatedAt    time.Time           `json:"updatedAt"`

	// PassBcrypt and OTPSecret back the LDAP bind and are never serialized.
	PassBcrypt string `json:"-"`
	OTPSecret  string `json:"-"`

	// HasOTP and HasPassword report credential state without revealing it.
	HasOTP      bool `json:"hasOTP"`
	HasPassword bool `json:"hasPassword"`
}

// Group is a POSIX group. Groups may include other groups, and membership is resolved
// transitively when answering LDAP searches and when building a PAC.
type Group struct {
	ID            int64        `json:"id"`
	Name          string       `json:"name"`
	GIDNumber     int          `json:"gidNumber"`
	Description   string       `json:"description,omitempty"`
	IncludeGroups []int        `json:"includeGroups,omitempty"`
	Capabilities  []Capability `json:"capabilities,omitempty"`
	CreatedAt     time.Time    `json:"createdAt"`
	UpdatedAt     time.Time    `json:"updatedAt"`
}

// Principal is a Kerberos identity. A principal with UserID set is the Kerberos face of that
// directory user; one without is a service principal or krbtgt.
type Principal struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Realm  string `json:"realm"`
	UserID *int64 `json:"userId,omitempty"`
	// UserName is filled in on read for convenience and ignored on write.
	UserName string `json:"userName,omitempty"`

	KVNO    int  `json:"kvno"`
	Enabled bool `json:"enabled"`
	// RequiresPreAuth demands PA-ENC-TIMESTAMP in the AS exchange. Clearing it re-opens offline
	// AS-REP cracking against this principal's password.
	RequiresPreAuth bool `json:"requiresPreAuth"`

	AllowForwardable bool `json:"allowForwardable"`
	AllowProxiable   bool `json:"allowProxiable"`
	AllowRenewable   bool `json:"allowRenewable"`
	AllowPostdate    bool `json:"allowPostdate"`
	// OKAsDelegate tells clients this service may be trusted with forwarded credentials.
	OKAsDelegate bool `json:"okAsDelegate"`
	// OKToAuthAsDelegate is the flag MIT calls OK_TO_AUTH_AS_DELEGATE and Active Directory
	// calls TrustedToAuthForDelegation. Protocol transition itself is open to any service, but
	// only one carrying this flag receives a forwardable ticket, and only a forwardable ticket
	// can go on to be delegated.
	OKToAuthAsDelegate bool `json:"okToAuthAsDelegate"`
	// AllowedToDelegateTo lists the services this one may forward a user's identity to via
	// S4U2Proxy. An empty list disables constrained delegation for the principal.
	AllowedToDelegateTo []string `json:"allowedToDelegateTo,omitempty"`
	// AllowedToImpersonate narrows which principals may be impersonated, matching FreeIPA's
	// ipaAllowToImpersonate. An empty list means any principal, as a missing attribute does
	// there.
	AllowedToImpersonate []string `json:"allowedToImpersonate,omitempty"`

	// MaxTicketLife and MaxRenewableLife of zero mean "use the realm default".
	MaxTicketLife    time.Duration `json:"-"`
	MaxRenewableLife time.Duration `json:"-"`

	PasswordLastSet   *time.Time `json:"passwordLastSet,omitempty"`
	PasswordExpiresAt *time.Time `json:"passwordExpiresAt,omitempty"`
	ExpiresAt         *time.Time `json:"expiresAt,omitempty"`
	LockedUntil       *time.Time `json:"lockedUntil,omitempty"`

	FailCount   int        `json:"failCount"`
	LastSuccess *time.Time `json:"lastSuccess,omitempty"`
	LastFailure *time.Time `json:"lastFailure,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	// Keys holds the long-term keys of the current kvno, decrypted. Never serialized.
	Keys []krbkeys.Key `json:"-"`
}

// FullName returns "name@REALM".
func (p *Principal) FullName() string { return p.Name + "@" + p.Realm }

// Name returns the parsed principal name.
func (p *Principal) KrbName() krbkeys.Name {
	return krbkeys.MustParseName(p.Name, p.Realm)
}

// KeyFor returns the principal's key of the given enctype.
func (p *Principal) KeyFor(etype int32) (krbkeys.Key, bool) {
	for _, k := range p.Keys {
		if k.EType == etype {
			return k, true
		}
	}

	return krbkeys.Key{}, false
}

// EncTypes lists the enctypes the principal holds keys for, in stored preference order.
func (p *Principal) EncTypes() []int32 {
	out := make([]int32, 0, len(p.Keys))
	for _, k := range p.Keys {
		out = append(out, k.EType)
	}

	return out
}

// PrincipalStatus says whether a principal may be used, and if not, why. The reasons are kept
// apart because Kerberos gives each its own error code: an expired account and a revoked one are
// different answers to the client.
type PrincipalStatus int

// Principal statuses, in the order they are checked.
const (
	PrincipalOK PrincipalStatus = iota
	PrincipalDisabled
	PrincipalExpired
	PrincipalLockedOut
	PrincipalNoKeys
)

// String describes the status for logs and error text.
func (s PrincipalStatus) String() string {
	switch s {
	case PrincipalOK:
		return "usable"
	case PrincipalDisabled:
		return "principal is disabled"
	case PrincipalExpired:
		return "principal has expired"
	case PrincipalLockedOut:
		return "principal is locked out"
	case PrincipalNoKeys:
		return "principal has no keys"
	default:
		return "principal is unusable"
	}
}

// Status reports whether the principal may be used at time t.
func (p *Principal) Status(t time.Time) PrincipalStatus {
	switch {
	case !p.Enabled:
		return PrincipalDisabled
	case p.ExpiresAt != nil && !t.Before(*p.ExpiresAt):
		return PrincipalExpired
	case p.LockedUntil != nil && t.Before(*p.LockedUntil):
		return PrincipalLockedOut
	case len(p.Keys) == 0:
		return PrincipalNoKeys
	default:
		return PrincipalOK
	}
}

// PasswordExpired reports whether the principal's password must be changed before it can be used.
// The moment of expiry counts as expired, which is what lets an administrative reset mark a
// password for immediate change.
func (p *Principal) PasswordExpired(t time.Time) bool {
	return p.PasswordExpiresAt != nil && !t.Before(*p.PasswordExpiresAt)
}

// TrustDirection says which way a cross-realm trust flows.
type TrustDirection string

const (
	// TrustOutbound lets local clients obtain tickets in the remote realm.
	TrustOutbound TrustDirection = "outbound"
	// TrustInbound lets remote clients obtain tickets in this realm.
	TrustInbound TrustDirection = "inbound"
	// TrustBidirectional is both directions.
	TrustBidirectional TrustDirection = "bidirectional"
)

// Trust is a cross-realm relationship. The shared keys live in ordinary principals:
// krbtgt/REMOTE@LOCAL for the outbound direction, krbtgt/LOCAL@REMOTE for the inbound one.
type Trust struct {
	ID          int64          `json:"id"`
	RemoteRealm string         `json:"remoteRealm"`
	Direction   TrustDirection `json:"direction"`
	// Transitive allows this realm to be used as a waypoint towards realms beyond the remote
	// one; it is recorded in the transited field of issued tickets.
	Transitive bool      `json:"transitive"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// Allows reports whether the trust permits tickets to flow in the given direction.
func (t *Trust) Allows(d TrustDirection) bool {
	if !t.Enabled {
		return false
	}

	return t.Direction == d || t.Direction == TrustBidirectional
}

// Ticket flags as MIT Kerberos and FreeIPA record them in krbTicketFlags. The wire form is a
// bitmask of prohibitions rather than permissions, which is why most of these are DISALLOW.
const (
	KDBDisallowPostdated   int32 = 0x00000001
	KDBDisallowForwardable int32 = 0x00000002
	KDBDisallowTGTBased    int32 = 0x00000004
	KDBDisallowRenewable   int32 = 0x00000008
	KDBDisallowProxiable   int32 = 0x00000010
	KDBDisallowDupSKey     int32 = 0x00000020
	KDBDisallowAllTix      int32 = 0x00000040
	KDBRequiresPreAuth     int32 = 0x00000080
	KDBRequiresHWAuth      int32 = 0x00000100
	KDBRequiresPwChange    int32 = 0x00000200
	KDBDisallowSvr         int32 = 0x00001000
	KDBPwChangeService     int32 = 0x00002000
	KDBSupportDesMD5       int32 = 0x00004000
	KDBNewPrinc            int32 = 0x00008000
	KDBOKAsDelegate        int32 = 0x00100000
	KDBOKToAuthAsDelegate  int32 = 0x00200000
	KDBNoAuthDataRequired  int32 = 0x00400000
	KDBLockdownKeys        int32 = 0x00800000
)

// TicketFlags renders the principal's policy as the krbTicketFlags bitmask MIT and FreeIPA store,
// so a tool that reads either can make sense of this directory. The booleans are kept as the
// storage form because a bitmask in a database column is unreadable, but this is the value they
// mean.
func (p *Principal) TicketFlags() int32 {
	var f int32

	if !p.AllowPostdate {
		f |= KDBDisallowPostdated
	}
	if !p.AllowForwardable {
		f |= KDBDisallowForwardable
	}
	if !p.AllowRenewable {
		f |= KDBDisallowRenewable
	}
	if !p.AllowProxiable {
		f |= KDBDisallowProxiable
	}
	if !p.Enabled {
		f |= KDBDisallowAllTix
	}
	if p.RequiresPreAuth {
		f |= KDBRequiresPreAuth
	}
	if p.OKAsDelegate {
		f |= KDBOKAsDelegate
	}
	if p.OKToAuthAsDelegate {
		f |= KDBOKToAuthAsDelegate
	}
	if p.KrbName().IsChangePW() {
		f |= KDBPwChangeService
	}

	return f
}
