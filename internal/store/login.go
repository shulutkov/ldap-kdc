package store

import (
	"context"
	"errors"
	"strings"
)

// UserByLogin resolves what a person types to sign in — an account name or its mail address — to
// the account.
//
// Shared by every door that takes a login rather than a DN, because a person who signs in to a web
// page types the address they know themselves by, and it has to find the same account whichever
// page asked.
func (s *Store) UserByLogin(ctx context.Context, login string) (*User, error) {
	login = strings.TrimSpace(login)
	if len(login) == 0 {
		return nil, ErrNotFound
	}

	u, err := s.GetUser(ctx, login)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	if !strings.Contains(login, "@") {
		return nil, ErrNotFound
	}

	users, err := s.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for i := range users {
		if strings.EqualFold(users[i].Mail, login) {
			return s.GetUser(ctx, users[i].Name)
		}
	}

	return nil, ErrNotFound
}
