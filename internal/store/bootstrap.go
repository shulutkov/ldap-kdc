package store

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
)

// Metadata keys held in the meta table.
const (
	// MetaRealm records the realm the database was initialized for.
	MetaRealm = "realm"
	// MetaDomainSID records the Windows domain SID that PACs are issued under.
	MetaDomainSID = "domain_sid"
)

// EnsureRealm prepares an empty or existing database for use with the given realm: it pins the
// realm, creates the ticket-granting principal and the password changing principal, and reports
// whether it had to initialize anything.
func (s *Store) EnsureRealm(ctx context.Context, realm string, etypes []int32) (initialized bool, err error) {
	realm = strings.ToUpper(realm)

	switch existing, err := s.GetMeta(ctx, MetaRealm); {
	case err == nil && existing != realm:
		// Every stored key is salted with the realm name, so serving a different realm from
		// the same database would fail every pre-authentication with no obvious cause. Refuse
		// instead, and let the operator decide.
		return false, fmt.Errorf("database was initialized for realm %s, not %s", existing, realm)
	case err != nil && !errors.Is(err, ErrNotFound):
		return false, err
	case errors.Is(err, ErrNotFound):
		if err := s.SetMeta(ctx, MetaRealm, realm); err != nil {
			return false, err
		}
		initialized = true
	}

	for _, name := range []string{"krbtgt/" + realm, "kadmin/changepw"} {
		created, err := s.ensureServicePrincipal(ctx, krbkeys.MustParseName(name, realm), etypes)
		if err != nil {
			return initialized, err
		}
		initialized = initialized || created
	}

	return initialized, nil
}

// ensureServicePrincipal creates a randomly keyed principal if it does not already exist.
func (s *Store) ensureServicePrincipal(ctx context.Context, name krbkeys.Name, etypes []int32) (bool, error) {
	switch _, err := s.GetPrincipal(ctx, name); {
	case err == nil:
		return false, nil
	case !errors.Is(err, ErrNotFound):
		return false, err
	}

	keys, err := krbkeys.RandomKeys(etypes)
	if err != nil {
		return false, err
	}

	now := time.Now().UTC()

	p := &Principal{
		Name:             name.Principal(),
		Realm:            name.Realm,
		Enabled:          true,
		RequiresPreAuth:  true,
		AllowForwardable: true,
		AllowProxiable:   true,
		AllowRenewable:   true,
		PasswordLastSet:  &now,
	}

	if err := s.CreatePrincipal(ctx, p, keys); err != nil {
		return false, err
	}

	return true, nil
}

// EnsureDomainSID pins the domain SID used in PACs. A configured value wins; otherwise a stored one
// is reused, and only a database that has neither gets a freshly generated SID.
func (s *Store) EnsureDomainSID(ctx context.Context, configured string) (string, error) {
	stored, err := s.GetMeta(ctx, MetaDomainSID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return "", err
	}

	switch {
	case len(configured) > 0 && len(stored) > 0 && configured != stored:
		// The SID is baked into every PAC a client has already cached and into every ACL a
		// Windows member server derived from one. Changing it silently would leave those
		// pointing at an identity that no longer exists.
		return "", fmt.Errorf("configured domain SID %s does not match the stored %s", configured, stored)
	case len(configured) > 0:
		if len(stored) == 0 {
			if err := s.SetMeta(ctx, MetaDomainSID, configured); err != nil {
				return "", err
			}
		}

		return configured, nil
	case len(stored) > 0:
		return stored, nil
	}

	sid, err := generateDomainSID()
	if err != nil {
		return "", err
	}
	if err := s.SetMeta(ctx, MetaDomainSID, sid); err != nil {
		return "", err
	}

	return sid, nil
}

// generateDomainSID builds an S-1-5-21 domain SID from random sub-authorities, the same shape a
// Windows domain uses.
func generateDomainSID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return fmt.Sprintf("S-1-5-21-%d-%d-%d",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint32(b[4:8]),
		binary.LittleEndian.Uint32(b[8:12]),
	), nil
}
