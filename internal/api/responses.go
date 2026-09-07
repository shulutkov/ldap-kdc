package api

import (
	"time"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// The bodies this API answers with.
//
// They are declared rather than assembled as maps because the OpenAPI document is generated from
// these very types at start-up: a field renamed here changes the document in the same commit, and
// there is no second description of the API to fall out of step with the first.

// errorBody is the shape of every refusal.
type errorBody struct {
	Error string `json:"error" description:"What was wrong with the request."`
}

// statusBody answers the liveness and readiness probes.
type statusBody struct {
	Status string `json:"status" example:"ok"`
	Realm  string `json:"realm,omitempty" example:"EXAMPLE.COM"`
	Reason string `json:"reason,omitempty" description:"Why the service is not ready."`
}

// statsBody summarises what the directory holds.
type statsBody struct {
	Realm      string     `json:"realm" example:"EXAMPLE.COM"`
	Users      userCounts `json:"users"`
	Groups     int        `json:"groups"`
	Principals int        `json:"principals"`
	Trusts     int        `json:"trusts"`
	EncTypes   []string   `json:"encTypes" description:"The enctypes this realm issues keys for, in preference order."`
}

type userCounts struct {
	Total    int `json:"total"`
	Disabled int `json:"disabled"`
	// WithoutPassword is worth surfacing rather than leaving to be discovered by a failed
	// login: such an account can bind to nothing and obtain no ticket.
	WithoutPassword int `json:"withoutPassword" description:"Accounts that can neither bind nor obtain a ticket."`
}

type usersBody struct {
	Users []store.User `json:"users"`
}

type userBody struct {
	User *store.User `json:"user"`
	// Principals is present when a single account is read, and lists the Kerberos identities
	// attached to it.
	Principals []store.Principal `json:"principals,omitempty"`
}

type passwordSetBody struct {
	Status     string `json:"status" example:"password set"`
	MustChange bool   `json:"mustChange" description:"Whether the account has to replace this password at its next login."`
}

type appPasswordsBody struct {
	AppPasswords []store.AppPassword `json:"appPasswords"`
}

type appPasswordBody struct {
	AppPassword *store.AppPassword `json:"appPassword"`
	// Password is returned once, here, when the secret was generated: nothing stores it in the
	// clear, so this is the only chance to read it.
	Password string `json:"password,omitempty"`
}

type groupsBody struct {
	Groups []store.Group `json:"groups"`
}

type groupBody struct {
	Group *store.Group `json:"group"`
}

type membersBody struct {
	Members []string `json:"members" description:"Account names, following included groups."`
}

type principalsBody struct {
	Principals []store.Principal `json:"principals"`
}

type principalBody struct {
	Principal *store.Principal `json:"principal"`
	// The remaining fields are filled in when a single principal is read. Lifetimes are
	// rendered as durations and the policy also as the bitmask MIT and FreeIPA store, so a
	// value read here can be compared with one read from either.
	EncTypes         []string `json:"encTypes,omitempty"`
	MaxTicketLife    string   `json:"maxTicketLife,omitempty" example:"10h0m0s"`
	MaxRenewableLife string   `json:"maxRenewableLife,omitempty" example:"168h0m0s"`
	KrbTicketFlags   *int32   `json:"krbTicketFlags,omitempty" example:"129"`
}

type dnsRecordsBody struct {
	Records []store.DNSRecord `json:"records"`
	Zones   []string          `json:"zones" description:"The zones this service answers for."`
}

type dnsRecordBody struct {
	Record *store.DNSRecord `json:"record"`
}

type trustsBody struct {
	Trusts []store.Trust `json:"trusts"`
}

type trustBody struct {
	Trust *store.Trust `json:"trust"`
}

// timeNow exists so the trust handler and the principal handler agree on "now".
func timeNow() time.Time { return time.Now().UTC() }
