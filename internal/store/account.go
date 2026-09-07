package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
)

// NewAccount describes a directory account to create together with the Kerberos identity that goes
// with it.
type NewAccount struct {
	User *User

	// Realm and EncTypes govern the principal created alongside the account.
	Realm    string
	EncTypes []int32

	// Password, when given, is set on both sides at once. Without it the account exists but can
	// neither bind nor obtain a ticket until a password is set.
	Password string
	// PasswordExpiresAt marks the password for change; nil leaves it usable.
	PasswordExpiresAt *time.Time

	// Aliases are further Kerberos names the account answers to.
	Aliases []string
}

// CreateAccount creates a user, its Kerberos principal and its credentials in one operation.
//
// It lives here rather than in the callers because there are two of them -- the management API and
// the bootstrap -- and an account provisioned one way has to be indistinguishable from one
// provisioned the other. The alternative is two sequences that drift, which in this service means
// an account that authenticates over one protocol and not the other.
func (s *Store) CreateAccount(ctx context.Context, a NewAccount) error {
	if a.User == nil || len(a.User.Name) == 0 {
		return fmt.Errorf("account name is required")
	}

	if a.User.UIDNumber == 0 {
		next, err := s.NextUIDNumber(ctx)
		if err != nil {
			return err
		}
		a.User.UIDNumber = next
	}

	if err := s.CreateUser(ctx, a.User); err != nil {
		return err
	}

	// Every account is a principal. There is no state where one exists without the other: an
	// account that could bind over LDAP and never obtain a ticket is a half-provisioned
	// identity, and FreeIPA has no such thing either. An account not meant to use Kerberos
	// simply keeps the random keys it starts with, which no password can produce.
	name := krbkeys.Name{Components: []string{a.User.Name}, Realm: a.Realm}

	keys, err := krbkeys.RandomKeys(a.EncTypes)
	if err != nil {
		return err
	}

	p := &Principal{
		Name: name.Principal(), Realm: name.Realm, UserID: &a.User.ID,
		Enabled: !a.User.Disabled, RequiresPreAuth: true,
		AllowForwardable: true, AllowProxiable: true, AllowRenewable: true,
		Aliases: a.Aliases,
	}

	if err := s.CreatePrincipal(ctx, p, keys); err != nil {
		return s.undoAccount(ctx, a.User.Name, err)
	}

	if len(a.Password) > 0 {
		if err := s.SetUserPassword(ctx, a.User.Name, a.Password, a.EncTypes, a.PasswordExpiresAt); err != nil {
			return s.undoAccount(ctx, a.User.Name, err)
		}
	}

	return nil
}

// undoAccount takes back a partly created account after a later step failed.
//
// The steps cannot share one transaction -- each takes the store's write lock in turn -- so the
// only way to keep the promise that an account and its principal come together is to remove what
// was already written. Deleting the user takes its principal with it through the foreign key.
func (s *Store) undoAccount(ctx context.Context, name string, cause error) error {
	if err := s.DeleteUser(ctx, name); err != nil {
		return errors.Join(cause, fmt.Errorf("removing the half-created account %s: %w", name, err))
	}

	return cause
}

// NextUIDNumber picks a free uid above every existing one, starting at 10000.
func (s *Store) NextUIDNumber(ctx context.Context) (int, error) {
	return s.nextNumber(ctx, `SELECT COALESCE(MAX(uid_number), 0) FROM users`, 10000)
}

// NextGIDNumber picks a free gid above every existing one, starting at 5000.
func (s *Store) NextGIDNumber(ctx context.Context) (int, error) {
	return s.nextNumber(ctx, `SELECT COALESCE(MAX(gid_number), 0) FROM groups`, 5000)
}

func (s *Store) nextNumber(ctx context.Context, query string, floor int) (int, error) {
	var highest int

	if err := s.db.QueryRowContext(ctx, query).Scan(&highest); err != nil {
		return 0, err
	}

	if highest < floor {
		return floor, nil
	}

	return highest + 1, nil
}
