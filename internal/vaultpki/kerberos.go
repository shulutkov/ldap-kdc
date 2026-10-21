package vaultpki

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/go-krb5/krb5/client"
	krb5config "github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/spnego"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
)

// kerberosToken is the default TokenSource: it logs the configured principal in to this
// service's own KDC with the keys the store holds, gets a ticket for Vault's service
// principal, and wraps the AP-REQ in the SPNEGO token Vault's kerberos login expects.
func (m *Manager) kerberosToken(ctx context.Context, cfg Config) ([]byte, error) {
	name, err := krbkeys.ParseName(cfg.Principal, m.kdc.Realm)
	if err != nil {
		return nil, err
	}

	p, err := m.st.GetPrincipal(ctx, name)
	if err != nil {
		return nil, err
	}

	if len(p.Keys) == 0 {
		return nil, fmt.Errorf("principal %s has no keys", name)
	}

	// The library's keytab type builds entries only from passwords, which a randomly keyed
	// service principal does not have, so the keytab is marshalled from the stored keys and
	// parsed straight back.
	entries := make([]krbkeys.KeytabEntry, 0, len(p.Keys))
	for _, k := range p.Keys {
		entries = append(entries, krbkeys.KeytabEntry{
			Name: name, KVNO: p.KVNO, Key: k, Timestamp: time.Now(),
		})
	}

	blob, err := krbkeys.MarshalKeytab(entries)
	if err != nil {
		return nil, err
	}

	kt := keytab.New()
	if err := kt.Unmarshal(blob); err != nil {
		return nil, fmt.Errorf("keytab: %w", err)
	}

	cl := client.NewWithKeytab(name.Principal(), name.Realm, kt, m.krb5Config(name.Realm, p.Keys))
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("login as %s: %w", name, err)
	}
	defer cl.Destroy()

	spn := cfg.ServicePrincipal
	if len(spn) == 0 {
		u, err := url.Parse(cfg.Address)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", cfg.Address, err)
		}
		spn = "HTTP/" + u.Hostname()
	}

	token, err := spnego.SPNEGOClient(cl, spn).InitSecContext()
	if err != nil {
		return nil, fmt.Errorf("service ticket for %s: %w", spn, err)
	}

	raw, err := token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("spnego token: %w", err)
	}

	return raw, nil
}

// krb5Config is the client-side krb5.conf: this realm, this KDC, no DNS discovery, and the
// enctypes the principal actually has keys for.
func (m *Manager) krb5Config(realm string, keys []krbkeys.Key) *krb5config.Config {
	c := krb5config.New()

	var (
		ids   []int32
		names []string
	)
	seen := map[int32]bool{}

	for _, k := range keys {
		if seen[k.EType] {
			continue
		}
		seen[k.EType] = true
		ids = append(ids, k.EType)
		names = append(names, krbkeys.EncTypeName(k.EType))
	}

	c.LibDefaults.DefaultRealm = realm
	c.LibDefaults.DefaultTktEnctypes = names
	c.LibDefaults.DefaultTktEnctypeIDs = ids
	c.LibDefaults.DefaultTGSEnctypes = names
	c.LibDefaults.DefaultTGSEnctypeIDs = ids
	c.LibDefaults.PermittedEnctypes = names
	c.LibDefaults.PermittedEnctypeIDs = ids
	c.LibDefaults.DNSLookupKDC = false
	c.LibDefaults.DNSLookupRealm = false
	c.LibDefaults.TicketLifetime = time.Hour
	c.LibDefaults.RenewLifetime = 24 * time.Hour

	c.Realms = append(c.Realms, krb5config.Realm{
		Realm: realm,
		KDC:   []string{m.kdc.Addr},
	})

	return c
}
