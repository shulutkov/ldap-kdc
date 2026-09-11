package oidc

import (
	"context"
	"errors"
	"strings"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// subjectClaims is what this provider says about a person.
type subjectClaims struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
}

// claims reads the account afresh and builds what goes in a token. A nil result with no error
// means the account is gone or switched off since the session began — the caller refuses.
//
// The subject is the account NAME, not a number: it is stable, it is what the directory is
// administered by, and it is what a rule in a relying party is written against. Deployments that
// key on the mail address read the email claim instead, which is why both are here.
func (s *Server) claims(ctx context.Context, name string) (*subjectClaims, error) {
	u, err := s.st.GetUser(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, nil
	}

	groups, err := s.groupNames(ctx, u)
	if err != nil {
		return nil, err
	}

	return &subjectClaims{
		Subject: u.Name,
		Email:   u.Mail,
		Name:    strings.TrimSpace(u.GivenName + " " + u.SN),
		Groups:  groups,
	}, nil
}

// groupNames resolves the account's groups by NAME, transitively, the same membership a Kerberos
// PAC carries. Names and not gid numbers, because that is what a policy in a relying party is
// written with.
func (s *Server) groupNames(ctx context.Context, u *store.User) ([]string, error) {
	gids, err := s.st.UserGIDs(ctx, u)
	if err != nil {
		return nil, err
	}
	all, err := s.st.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	byGID := make(map[int]string, len(all))
	for i := range all {
		byGID[all[i].GIDNumber] = all[i].Name
	}

	out := make([]string, 0, len(gids))
	for _, gid := range gids {
		if name, ok := byGID[gid]; ok {
			out = append(out, name)
		}
	}

	return out, nil
}
