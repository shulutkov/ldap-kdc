package ldapsrv

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/glauth/ldap"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// Config is what the LDAP front end needs beyond the store.
type Config struct {
	BaseDN      string
	NameFormat  string
	GroupFormat string
	SSHKeyAttr  string
	Realm       string
	// DomainSID is the realm's Windows domain SID, published on entries as the prefix of
	// ipaNTSecurityIdentifier.
	DomainSID string

	// AnonymousDSE lets an unauthenticated client read the root DSE, which some clients
	// (SSSD among them) insist on doing before they bind.
	AnonymousDSE bool
	// IgnoreCapabilities disables the per-account search authorization entirely.
	IgnoreCapabilities bool

	// EncTypes is used when a password is set through LDAP, so the Kerberos keys move with it.
	EncTypes []int32

	LimitFailedBinds      bool
	NumberOfFailedBinds   int
	PeriodOfFailedBinds   time.Duration
	BlockFailedBindsFor   time.Duration
	PruneSourceTableEvery time.Duration
	PruneSourcesOlderThan time.Duration
}

// Handler implements the LDAP operations against the store.
type Handler struct {
	cfg     Config
	st      *store.Store
	log     zerolog.Logger
	metrics *metrics.Metrics
	entries *entryBuilder
	limiter *bindLimiter
}

var emailPattern = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// NewHandler builds the LDAP operation handler.
func NewHandler(cfg Config, st *store.Store, log zerolog.Logger, m *metrics.Metrics) *Handler {
	cfg.BaseDN = strings.ToLower(cfg.BaseDN)

	return &Handler{
		cfg:     cfg,
		st:      st,
		log:     log.With().Str("component", "ldap").Logger(),
		metrics: m,
		entries: &entryBuilder{cfg: cfg, st: st},
		limiter: newBindLimiter(cfg),
	}
}

// Bind authenticates a simple bind against the account's password digest, its one-time password
// and any application passwords it holds.
func (h *Handler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	start := time.Now()
	defer func() { h.metrics.LDAPDuration.WithLabelValues("bind").Observe(time.Since(start).Seconds()) }()

	ctx := context.Background()
	bindDN = strings.ToLower(strings.TrimSpace(bindDN))

	if h.limiter.blocked(conn) {
		h.result("bind", "blocked")

		return ldap.LDAPResultUnwillingToPerform, nil
	}

	// An empty DN with an empty password is an anonymous bind, which establishes no identity.
	if len(bindDN) == 0 && len(bindSimplePw) == 0 {
		h.result("bind", "anonymous")

		return ldap.LDAPResultSuccess, nil
	}

	// A DN with an empty password is LDAP's unauthenticated bind. Returning success would hand
	// the caller the named account's authorization state without any proof, so it is refused.
	if len(bindDN) > 0 && len(bindSimplePw) == 0 {
		h.log.Info().Str("dn", bindDN).Str("src", sourceAddr(conn)).Msg("unauthenticated bind refused")
		h.result("bind", "unauthenticated")

		return ldap.LDAPResultUnwillingToPerform, nil
	}

	user, code := h.findBindUser(ctx, bindDN, true)
	if code != ldap.LDAPResultSuccess {
		h.limiter.noteFailure(conn)
		h.result("bind", "unknown-user")

		return code, nil
	}

	if user.Disabled {
		h.log.Info().Str("dn", bindDN).Str("src", sourceAddr(conn)).Msg("bind on a disabled account")
		h.result("bind", "disabled")

		return ldap.LDAPResultInvalidCredentials, nil
	}

	// The full string is kept: an application password is presented on its own, without the
	// one-time code that the account's main password would carry.
	presented := bindSimplePw
	password := bindSimplePw
	otpValid := len(user.OTPSecret) == 0

	if len(user.OTPSecret) > 0 && len(bindSimplePw) > 6 {
		code := bindSimplePw[len(bindSimplePw)-6:]
		password = bindSimplePw[:len(bindSimplePw)-6]
		otpValid = totp.Validate(code, user.OTPSecret)
	}

	for _, ap := range user.AppPasswords {
		if store.CheckPassword(ap.Hash, presented) {
			h.limiter.noteSuccess(conn)
			h.log.Info().Str("dn", bindDN).Str("appPassword", ap.Name).Str("src", sourceAddr(conn)).
				Msg("bind succeeded with an application password")
			h.result("bind", "ok-app-password")

			return ldap.LDAPResultSuccess, nil
		}
	}

	if !otpValid {
		h.limiter.noteFailure(conn)
		h.log.Info().Str("dn", bindDN).Str("src", sourceAddr(conn)).Msg("invalid one-time code")
		h.result("bind", "bad-otp")

		return ldap.LDAPResultInvalidCredentials, nil
	}

	// An account with no password digest cannot bind at all. Falling through to success here
	// would let every account created but never given a password authenticate with anything.
	if len(user.PassBcrypt) == 0 || !store.CheckPassword(user.PassBcrypt, password) {
		h.limiter.noteFailure(conn)
		h.log.Info().Str("dn", bindDN).Str("src", sourceAddr(conn)).Msg("invalid credentials")
		h.result("bind", "invalid")

		return ldap.LDAPResultInvalidCredentials, nil
	}

	h.limiter.noteSuccess(conn)
	h.log.Info().Str("dn", bindDN).Str("src", sourceAddr(conn)).Msg("bind succeeded")
	h.result("bind", "ok")

	return ldap.LDAPResultSuccess, nil
}

// Search answers a search request with the entries the bound account is allowed to see. Filtering,
// scope and attribute selection are applied by the server, so this produces the candidate set.
func (h *Handler) Search(boundDN string, req ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	start := time.Now()
	defer func() { h.metrics.LDAPDuration.WithLabelValues("search").Observe(time.Since(start).Seconds()) }()

	ctx := context.Background()

	boundDN = strings.ToLower(boundDN)
	searchBaseDN := strings.ToLower(strings.TrimSpace(req.BaseDN))
	anonymous := len(boundDN) == 0

	if h.limiter.blocked(conn) {
		h.result("search", "blocked")

		// The library reports the result code only when an error accompanies it, so every
		// refusal below returns both.
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultUnwillingToPerform},
			errors.New("source is serving a timeout after repeated failed binds")
	}

	// The root DSE is the one thing a client may read before binding, and only when the realm
	// allows it.
	if len(searchBaseDN) == 0 {
		if req.Scope != ldap.ScopeBaseObject {
			h.result("search", "no-base-dn")

			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultUnwillingToPerform},
				errors.New("a search with no base DN must be scoped to the base object")
		}
		if anonymous && !h.cfg.AnonymousDSE {
			h.result("search", "anonymous-denied")

			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights},
				errors.New("anonymous access to the root DSE is disabled")
		}

		h.result("search", "ok")

		return success([]*ldap.Entry{h.entries.rootDSE(searchBaseDN)}), nil
	}

	if anonymous {
		h.result("search", "anonymous-denied")

		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights},
			errors.New("a search below the root DSE requires an authenticated bind")
	}

	boundUser, code := h.findBindUser(ctx, boundDN, false)
	if code != ldap.LDAPResultSuccess {
		h.result("search", "unknown-bind-dn")

		return ldap.ServerSearchResult{ResultCode: code},
			fmt.Errorf("bind DN %s does not name a known account", boundDN)
	}

	if searchBaseDN == "cn=schema" {
		h.result("search", "ok")

		return success([]*ldap.Entry{{DN: "cn=schema", Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"schema"}},
			{Name: "objectClass", Values: []string{"subschema", "top"}},
			{Name: "hasSubordinates", Values: []string{"false"}},
		}}}), nil
	}

	if !strings.HasSuffix(searchBaseDN, h.cfg.BaseDN) {
		h.result("search", "outside-base-dn")

		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights},
			fmt.Errorf("search base %s is outside %s", searchBaseDN, h.cfg.BaseDN)
	}

	if !h.cfg.IgnoreCapabilities {
		allowed, err := h.hasCapability(ctx, boundUser, "search", searchBaseDN)
		if err != nil {
			h.result("search", "error")

			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
		}
		if !allowed {
			h.log.Info().Str("dn", boundDN).Str("base", searchBaseDN).Msg("search denied by capabilities")
			h.result("search", "denied")

			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights},
				fmt.Errorf("no capability allows %s to search %s", boundDN, searchBaseDN)
		}
	}

	entries, err := h.candidates(ctx, searchBaseDN, req)
	if err != nil {
		h.result("search", "error")

		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
	}

	h.log.Debug().Str("dn", boundDN).Str("base", searchBaseDN).Str("filter", req.Filter).
		Int("entries", len(entries)).Msg("search")
	h.result("search", "ok")

	return success(entries), nil
}

// candidates gathers the entries that could match, based on where in the tree the search starts.
func (h *Handler) candidates(ctx context.Context, searchBaseDN string, req ldap.SearchRequest) ([]*ldap.Entry, error) {
	usersNode := "ou=users," + h.cfg.BaseDN
	groupsNode := "ou=groups," + h.cfg.BaseDN

	var entries []*ldap.Entry

	switch {
	case searchBaseDN == h.cfg.BaseDN:
		if req.Scope == ldap.ScopeBaseObject || req.Scope == ldap.ScopeWholeSubtree {
			entries = append(entries, h.entries.topLevelRoot())
		}
		entries = append(entries, h.entries.container("users"), h.entries.container("groups"))

		if req.Scope == ldap.ScopeWholeSubtree {
			return h.appendAll(ctx, entries)
		}

		return entries, nil

	case searchBaseDN == groupsNode:
		if req.Scope == ldap.ScopeBaseObject || req.Scope == ldap.ScopeWholeSubtree {
			entries = append(entries, h.entries.container("groups"))
		}
		if req.Scope != ldap.ScopeBaseObject {
			groups, err := h.entries.PosixGroups(ctx, "ou=groups")
			if err != nil {
				return nil, err
			}
			entries = append(entries, groups...)
		}

		return entries, nil

	case searchBaseDN == usersNode:
		if req.Scope == ldap.ScopeBaseObject || req.Scope == ldap.ScopeWholeSubtree {
			entries = append(entries, h.entries.container("users"))
		}
		if req.Scope != ldap.ScopeBaseObject {
			groups, err := h.entries.PosixGroups(ctx, "ou=users")
			if err != nil {
				return nil, err
			}
			entries = append(entries, groups...)
		}
		if req.Scope == ldap.ScopeWholeSubtree {
			users, err := h.entries.PosixAccounts(ctx)
			if err != nil {
				return nil, err
			}
			entries = append(entries, users...)
		}

		return entries, nil
	}

	// Anywhere deeper in the tree, offer every object and let the server's scope and filter
	// handling narrow it down; entries outside the search base are dropped here first.
	all, err := h.appendAll(ctx, nil)
	if err != nil {
		return nil, err
	}

	for _, e := range all {
		if strings.HasSuffix(strings.ToLower(e.DN), searchBaseDN) {
			entries = append(entries, e)
		}
	}

	return entries, nil
}

// appendAll adds every group and user entry to the list.
func (h *Handler) appendAll(ctx context.Context, entries []*ldap.Entry) ([]*ldap.Entry, error) {
	underUsers, err := h.entries.PosixGroups(ctx, "ou=users")
	if err != nil {
		return nil, err
	}
	entries = append(entries, underUsers...)

	underGroups, err := h.entries.PosixGroups(ctx, "ou=groups")
	if err != nil {
		return nil, err
	}
	entries = append(entries, underGroups...)

	users, err := h.entries.PosixAccounts(ctx)
	if err != nil {
		return nil, err
	}

	return append(entries, users...), nil
}

// Add is not offered over LDAP. The protocol library does not expose the contents of an add
// request to a server handler, so there is nothing here to act on; objects are created through the
// REST API instead.
func (h *Handler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	h.log.Info().Str("dn", boundDN).Msg("add refused: create objects through the management API")
	h.result("add", "unsupported")

	return ldap.LDAPResultUnwillingToPerform, nil
}

// Modify changes an existing entry. Setting userPassword here goes through the same path the
// management API uses, so the account's Kerberos keys are regenerated along with the digest.
func (h *Handler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	start := time.Now()
	defer func() { h.metrics.LDAPDuration.WithLabelValues("modify").Observe(time.Since(start).Seconds()) }()

	ctx := context.Background()

	actor, code := h.findBindUser(ctx, strings.ToLower(boundDN), false)
	if code != ldap.LDAPResultSuccess {
		h.result("modify", "unknown-bind-dn")

		return code, nil
	}

	dn := strings.ToLower(strings.TrimSpace(req.Dn))

	kind, name, err := h.classifyDN(dn)
	if err != nil {
		h.result("modify", "bad-dn")

		return ldap.LDAPResultNoSuchObject, nil
	}

	// A user may always change their own attributes; anything else needs an explicit write
	// capability, which is how an administrator account is distinguished from an ordinary one.
	self := kind == "user" && strings.EqualFold(name, actor.Name)
	if !self {
		allowed, err := h.hasCapability(ctx, actor, "write", dn)
		if err != nil {
			h.result("modify", "error")

			return ldap.LDAPResultOperationsError, err
		}
		if !allowed {
			h.log.Info().Str("dn", boundDN).Str("target", dn).Msg("modify denied by capabilities")
			h.result("modify", "denied")

			return ldap.LDAPResultInsufficientAccessRights, nil
		}
	}

	if kind != "user" {
		h.result("modify", "unsupported-object")

		return ldap.LDAPResultUnwillingToPerform, nil
	}

	changes := collectChanges(req)

	if pw, ok := changes["userpassword"]; ok && len(pw) > 0 {
		if err := h.st.SetUserPassword(ctx, name, pw[0], h.cfg.EncTypes, nil); err != nil {
			h.log.Error().Err(err).Str("user", name).Msg("could not set password")
			h.result("modify", "error")

			return ldap.LDAPResultOperationsError, err
		}

		h.log.Info().Str("user", name).Str("by", boundDN).Msg("password changed over LDAP")
		delete(changes, "userpassword")
	}

	if len(changes) == 0 {
		h.result("modify", "ok")

		return ldap.LDAPResultSuccess, nil
	}

	if _, err := h.st.UpdateUser(ctx, name, func(u *store.User) error {
		return applyUserChanges(u, changes)
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.result("modify", "no-such-object")

			return ldap.LDAPResultNoSuchObject, nil
		}

		h.log.Error().Err(err).Str("user", name).Msg("could not modify user")
		h.result("modify", "error")

		return ldap.LDAPResultOperationsError, err
	}

	h.log.Info().Str("user", name).Str("by", boundDN).Msg("user modified over LDAP")
	h.result("modify", "ok")

	return ldap.LDAPResultSuccess, nil
}

// Delete removes a user or group.
func (h *Handler) Delete(boundDN, deleteDN string, conn net.Conn) (ldap.LDAPResultCode, error) {
	ctx := context.Background()

	actor, code := h.findBindUser(ctx, strings.ToLower(boundDN), false)
	if code != ldap.LDAPResultSuccess {
		h.result("delete", "unknown-bind-dn")

		return code, nil
	}

	dn := strings.ToLower(strings.TrimSpace(deleteDN))

	kind, name, err := h.classifyDN(dn)
	if err != nil {
		h.result("delete", "bad-dn")

		return ldap.LDAPResultNoSuchObject, nil
	}

	allowed, err := h.hasCapability(ctx, actor, "write", dn)
	if err != nil {
		h.result("delete", "error")

		return ldap.LDAPResultOperationsError, err
	}
	if !allowed {
		h.result("delete", "denied")

		return ldap.LDAPResultInsufficientAccessRights, nil
	}

	switch kind {
	case "user":
		err = h.st.DeleteUser(ctx, name)
	case "group":
		err = h.st.DeleteGroup(ctx, name)
	default:
		h.result("delete", "unsupported-object")

		return ldap.LDAPResultUnwillingToPerform, nil
	}

	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.result("delete", "no-such-object")

			return ldap.LDAPResultNoSuchObject, nil
		}

		h.result("delete", "error")

		return ldap.LDAPResultOperationsError, err
	}

	h.log.Info().Str("dn", dn).Str("by", boundDN).Msg("object deleted over LDAP")
	h.result("delete", "ok")

	return ldap.LDAPResultSuccess, nil
}

// Close is called when a client disconnects.
func (h *Handler) Close(boundDN string, conn net.Conn) error { return nil }

// findBindUser resolves a bind DN to an account, accepting either a distinguished name or a user
// principal name in mail form.
func (h *Handler) findBindUser(ctx context.Context, dn string, checkGroup bool) (*store.User, ldap.LDAPResultCode) {
	if emailPattern.MatchString(dn) {
		users, err := h.st.ListUsers(ctx)
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		for i := range users {
			if strings.EqualFold(users[i].Mail, dn) {
				u, err := h.st.GetUser(ctx, users[i].Name)
				if err != nil {
					return nil, ldap.LDAPResultOperationsError
				}

				return u, ldap.LDAPResultSuccess
			}
		}

		return nil, ldap.LDAPResultInvalidCredentials
	}

	if !strings.HasSuffix(dn, ","+h.cfg.BaseDN) {
		return nil, ldap.LDAPResultInvalidCredentials
	}

	parts := strings.Split(strings.TrimSuffix(dn, ","+h.cfg.BaseDN), ",")

	var userName, groupName string

	switch {
	case len(parts) == 1:
		userName = trimRDN(parts[0], h.cfg.NameFormat)
	case len(parts) == 2, len(parts) == 3 && parts[2] == "ou=users":
		userName = trimRDN(parts[0], h.cfg.NameFormat)
		groupName = trimRDN(parts[1], h.cfg.GroupFormat)
	default:
		return nil, ldap.LDAPResultInvalidCredentials
	}

	user, err := h.st.GetUser(ctx, userName)
	if err != nil {
		return nil, ldap.LDAPResultInvalidCredentials
	}

	// The DN embeds the primary group, so a mismatch means the caller supplied a name that does
	// not identify this account and must not be treated as if it did.
	if checkGroup && len(groupName) > 0 {
		g, err := h.st.GetGroup(ctx, groupName)
		if err != nil || g.GIDNumber != user.PrimaryGroup {
			return nil, ldap.LDAPResultInvalidCredentials
		}
	}

	return user, ldap.LDAPResultSuccess
}

// hasCapability reports whether the account, or any group it belongs to, grants the action on the
// object.
func (h *Handler) hasCapability(ctx context.Context, u *store.User, action, object string) (bool, error) {
	if capabilityMatches(u.Capabilities, action, object) {
		return true, nil
	}

	gids, err := h.st.UserGIDs(ctx, u)
	if err != nil {
		return false, err
	}

	for _, gid := range gids {
		g, err := h.st.GetGroupByGID(ctx, gid)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}

			return false, err
		}
		if capabilityMatches(g.Capabilities, action, object) {
			return true, nil
		}
	}

	return false, nil
}

// capabilityMatches reports whether a capability list grants the action on the object. A capability
// on a subtree covers everything beneath it.
func capabilityMatches(caps []store.Capability, action, object string) bool {
	for _, c := range caps {
		if !strings.EqualFold(c.Action, action) {
			continue
		}

		target := strings.ToLower(c.Object)
		switch {
		case target == "*":
			return true
		case target == object:
			return true
		case strings.HasSuffix(object, ","+target):
			return true
		}
	}

	return false
}

// classifyDN says whether a DN names a user or a group, and what it is called.
func (h *Handler) classifyDN(dn string) (kind, name string, err error) {
	if !strings.HasSuffix(dn, ","+h.cfg.BaseDN) {
		return "", "", fmt.Errorf("DN %s is outside %s", dn, h.cfg.BaseDN)
	}

	parts := strings.Split(strings.TrimSuffix(dn, ","+h.cfg.BaseDN), ",")

	switch {
	case len(parts) == 2 && parts[1] == "ou=groups":
		return "group", trimRDN(parts[0], h.cfg.GroupFormat), nil
	case len(parts) == 3 && parts[2] == "ou=users":
		return "user", trimRDN(parts[0], h.cfg.NameFormat), nil
	case len(parts) == 2 && parts[1] != "ou=users":
		return "user", trimRDN(parts[0], h.cfg.NameFormat), nil
	default:
		return "", "", fmt.Errorf("DN %s does not name a user or a group", dn)
	}
}

// trimRDN strips the attribute prefix from a relative distinguished name.
func trimRDN(rdn, attr string) string {
	if v, ok := strings.CutPrefix(rdn, attr+"="); ok {
		return v
	}

	if _, v, ok := strings.Cut(rdn, "="); ok {
		return v
	}

	return rdn
}

// collectChanges flattens a modify request into the final value of each attribute. Add and replace
// both set the value; a delete with no values clears the attribute.
func collectChanges(req ldap.ModifyRequest) map[string][]string {
	out := make(map[string][]string)

	for _, a := range req.AddAttributes {
		name := strings.ToLower(a.AttrType)
		out[name] = append(out[name], a.AttrVals...)
	}
	for _, a := range req.ReplaceAttributes {
		out[strings.ToLower(a.AttrType)] = a.AttrVals
	}
	for _, a := range req.DeleteAttributes {
		if len(a.AttrVals) == 0 {
			out[strings.ToLower(a.AttrType)] = nil
		}
	}

	return out
}

// applyUserChanges writes the modifiable attributes onto a user.
func applyUserChanges(u *store.User, changes map[string][]string) error {
	for name, values := range changes {
		first := ""
		if len(values) > 0 {
			first = values[0]
		}

		switch name {
		case "givenname":
			u.GivenName = first
		case "sn":
			u.SN = first
		case "mail":
			u.Mail = first
		case "loginshell":
			u.LoginShell = first
		case "homedirectory":
			u.Homedir = first
		case "accountstatus":
			u.Disabled = strings.EqualFold(first, "inactive")
		case "uidnumber":
			n, err := strconv.Atoi(first)
			if err != nil {
				return fmt.Errorf("uidNumber must be a number")
			}
			u.UIDNumber = n
		case "gidnumber":
			n, err := strconv.Atoi(first)
			if err != nil {
				return fmt.Errorf("gidNumber must be a number")
			}
			u.PrimaryGroup = n
		case "sshpublickey", "ipasshpubkey":
			u.SSHKeys = values
		default:
			// Anything the schema does not name is kept as a custom attribute rather than
			// rejected, which is how glauth's customattributes behave.
			if u.CustomAttrs == nil {
				u.CustomAttrs = make(map[string][]string)
			}
			if values == nil {
				delete(u.CustomAttrs, name)
			} else {
				u.CustomAttrs[name] = values
			}
		}
	}

	return nil
}

func success(entries []*ldap.Entry) ldap.ServerSearchResult {
	return ldap.ServerSearchResult{
		Entries:    entries,
		Referrals:  []string{},
		Controls:   []ldap.Control{},
		ResultCode: ldap.LDAPResultSuccess,
	}
}

// result records the outcome of an operation for metrics.
func (h *Handler) result(op, outcome string) {
	switch op {
	case "bind":
		h.metrics.LDAPBinds.WithLabelValues(outcome).Inc()
	case "search":
		h.metrics.LDAPSearches.WithLabelValues(outcome).Inc()
	}
}
