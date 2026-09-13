package store

import (
	"context"
	"errors"
	"strings"
)

// HasCapability reports whether the account, or any group it belongs to, grants the action on the
// object.
//
// It lives in the store for the reason store.Authenticate does: more than one door asks it. The LDAP
// front end asks before a search or a modify, the management API before it lets anybody in, and two
// doors that decide authority separately are two doors that eventually disagree about who is an
// administrator.
func (s *Store) HasCapability(ctx context.Context, u *User, action, object string) (bool, error) {
	object = strings.ToLower(object)

	if CapabilityMatches(u.Capabilities, action, object) {
		return true, nil
	}

	gids, err := s.UserGIDs(ctx, u)
	if err != nil {
		return false, err
	}

	for _, gid := range gids {
		g, err := s.GetGroupByGID(ctx, gid)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}

			return false, err
		}
		if CapabilityMatches(g.Capabilities, action, object) {
			return true, nil
		}
	}

	return false, nil
}

// CapabilityMatches reports whether a capability list grants the action on the object. A capability
// on a subtree covers everything beneath it.
func CapabilityMatches(caps []Capability, action, object string) bool {
	object = strings.ToLower(object)

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

// IsDirectoryAdmin reports whether the account administers the directory: whether it may write the
// whole of it, the base DN and everything beneath.
//
// That is the definition the directory already uses rather than a new one. An account an LDAP
// client can use to rewrite every entry is an administrator whatever else it is called, and one
// that cannot is not — so a separate "admins" setting would only be a second answer to the same
// question, waiting to disagree with the first.
func (s *Store) IsDirectoryAdmin(ctx context.Context, u *User, baseDN string) (bool, error) {
	if u == nil || u.Disabled {
		return false, nil
	}

	return s.HasCapability(ctx, u, "write", baseDN)
}
