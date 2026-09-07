// Package bootstrap brings a realm up with a directory that was described in advance.
//
// It exists for the cases where a service has to be usable the moment it starts and nobody is
// there to provision it: a continuous integration job, a test stand, a development container. The
// alternative is a pile of REST calls in a start-up script, which has to be kept in step with the
// service by hand and tends not to be.
//
// Applying a plan creates what is missing and leaves alone what is already there. It is not a
// reconciler: a service that reset an account's password on every restart, because a file still
// named it, would be a hazard rather than a convenience.
package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"

	"github.com/shulutkov/ldap-kdc/internal/dnssrv"
	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// Capability grants an account or a group the right to perform an action on an object.
type Capability struct {
	Action string `yaml:"action"`
	Object string `yaml:"object"`
}

// Group is a POSIX group to create.
type Group struct {
	Name string `yaml:"name"`
	// GIDNumber is allocated automatically when left out.
	GIDNumber     int          `yaml:"gid_number"`
	Description   string       `yaml:"description"`
	IncludeGroups []int        `yaml:"include_groups"`
	Capabilities  []Capability `yaml:"capabilities"`

	// CustomAttrs are published on the group's LDAP entry as they are given.
	CustomAttrs map[string][]string `yaml:"custom_attributes"`
}

// User is a directory account to create, with the Kerberos principal that goes with it.
type User struct {
	Name string `yaml:"name"`
	// UIDNumber is allocated automatically when left out.
	UIDNumber    int      `yaml:"uid_number"`
	PrimaryGroup int      `yaml:"primary_group"`
	OtherGroups  []int    `yaml:"other_groups"`
	GivenName    string   `yaml:"given_name"`
	SN           string   `yaml:"sn"`
	Mail         string   `yaml:"mail"`
	LoginShell   string   `yaml:"login_shell"`
	Homedir      string   `yaml:"home_directory"`
	Disabled     bool     `yaml:"disabled"`
	SSHKeys      []string `yaml:"ssh_keys"`

	CustomAttrs  map[string][]string `yaml:"custom_attributes"`
	Capabilities []Capability        `yaml:"capabilities"`
	OTPSecret    string              `yaml:"otp_secret"`

	Password string `yaml:"password"`

	// ForceChange marks the password expired, as an administrative reset through the API does.
	// It defaults to false here, the opposite way round: an account written into a plan is
	// meant to be used by whatever runs next, not by a person who will be asked to choose.
	ForceChange bool `yaml:"force_change"`

	// Aliases are further Kerberos names the account answers to.
	Aliases []string `yaml:"aliases"`
}

// Principal is a Kerberos identity with no directory account behind it: a service.
type Principal struct {
	Name string `yaml:"name"`

	// Password keys the principal from a string. Leaving it out is the better choice for a
	// service: random keys cannot be guessed, and the keytab is fetched from the API.
	Password string `yaml:"password"`

	Enabled            *bool `yaml:"enabled"`
	RequiresPreAuth    *bool `yaml:"requires_pre_auth"`
	AllowForwardable   *bool `yaml:"allow_forwardable"`
	AllowProxiable     *bool `yaml:"allow_proxiable"`
	AllowRenewable     *bool `yaml:"allow_renewable"`
	AllowPostdate      *bool `yaml:"allow_postdate"`
	OKAsDelegate       *bool `yaml:"ok_as_delegate"`
	OKToAuthAsDelegate *bool `yaml:"ok_to_auth_as_delegate"`

	AllowedToDelegateTo  []string `yaml:"allowed_to_delegate_to"`
	AllowedToImpersonate []string `yaml:"allowed_to_impersonate"`

	// Aliases are further names this principal answers to.
	Aliases []string `yaml:"aliases"`

	MaxTicketLife    time.Duration `yaml:"max_ticket_life"`
	MaxRenewableLife time.Duration `yaml:"max_renewable_life"`
}

// DNSRecord is one resource record to place in the realm's zone.
type DNSRecord struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
	// TTL falls back to the zone's default when left out.
	TTL int `yaml:"ttl"`
}

// Plan is the directory as it should exist once the service has started.
type Plan struct {
	Groups     []Group     `yaml:"groups"`
	Users      []User      `yaml:"users"`
	Principals []Principal `yaml:"principals"`
	DNSRecords []DNSRecord `yaml:"dns_records"`
}

// Options are the realm-level facts the plan is applied against.
type Options struct {
	Realm             string
	EncTypes          []int32
	MinPasswordLength int
	// DefaultTTL applies to a record that does not carry one.
	DefaultTTL int
}

// Summary counts what applying a plan did, so a start-up log says whether it had any effect.
type Summary struct {
	Created int
	Existed int
}

// Load reads a plan from a YAML file.
func Load(path string) (*Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	// A misspelled key in a file whose whole job is to be applied unattended would otherwise
	// mean an account quietly missing an attribute nobody notices until it matters.
	dec.KnownFields(true)

	var plan Plan

	if err := dec.Decode(&plan); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	return &plan, nil
}

// CheckFilePermissions warns when a plan holding passwords is readable by anyone but its owner.
func CheckFilePermissions(path string, plan *Plan, log zerolog.Logger) {
	if !plan.hasSecrets() {
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		return
	}

	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		log.Warn().Str("file", path).Str("mode", fmt.Sprintf("%04o", mode)).
			Msg("the bootstrap plan contains passwords and is readable beyond its owner")
	}
}

// hasSecrets reports whether the plan carries a password in the clear.
func (p *Plan) hasSecrets() bool {
	for _, u := range p.Users {
		if len(u.Password) > 0 {
			return true
		}
	}

	for _, pr := range p.Principals {
		if len(pr.Password) > 0 {
			return true
		}
	}

	return false
}

// Validate reports what is wrong with a plan without touching the database, so a bad file is
// rejected before any of it has been applied.
func (p *Plan) Validate(opts Options) error {
	seenGroups := make(map[string]bool, len(p.Groups))

	for i, g := range p.Groups {
		if len(g.Name) == 0 {
			return fmt.Errorf("groups[%d]: name is required", i)
		}
		if seenGroups[strings.ToLower(g.Name)] {
			return fmt.Errorf("groups[%d]: %s appears twice", i, g.Name)
		}
		seenGroups[strings.ToLower(g.Name)] = true

		if err := store.ValidateCustomAttrs(g.CustomAttrs); err != nil {
			return fmt.Errorf("groups[%d]: %s: %w", i, g.Name, err)
		}
	}

	seenUsers := make(map[string]bool, len(p.Users))

	// Every Kerberos name the plan mentions, canonical or alias, has to be free: two accounts
	// answering to one name is a state the directory cannot hold, and finding that out halfway
	// through would leave the realm part built.
	names := newNameSet(opts.Realm)

	for i, u := range p.Users {
		switch {
		case len(u.Name) == 0:
			return fmt.Errorf("users[%d]: name is required", i)
		case seenUsers[strings.ToLower(u.Name)]:
			return fmt.Errorf("users[%d]: %s appears twice", i, u.Name)
		case u.PrimaryGroup <= 0:
			return fmt.Errorf("users[%d]: %s has no primary group", i, u.Name)
		}

		seenUsers[strings.ToLower(u.Name)] = true

		if err := checkPassword(u.Password, opts.MinPasswordLength); err != nil {
			return fmt.Errorf("users[%d]: %s: %w", i, u.Name, err)
		}

		if err := names.claim(u.Name, u.Aliases, u.Name); err != nil {
			return fmt.Errorf("users[%d]: %w", i, err)
		}

		if err := store.ValidateCustomAttrs(u.CustomAttrs); err != nil {
			return fmt.Errorf("users[%d]: %s: %w", i, u.Name, err)
		}
	}

	for i, pr := range p.Principals {
		if len(pr.Name) == 0 {
			return fmt.Errorf("principals[%d]: name is required", i)
		}
		if _, err := krbkeys.ParseName(pr.Name, opts.Realm); err != nil {
			return fmt.Errorf("principals[%d]: %w", i, err)
		}
		if err := checkPassword(pr.Password, opts.MinPasswordLength); err != nil {
			return fmt.Errorf("principals[%d]: %s: %w", i, pr.Name, err)
		}

		if err := names.claim(pr.Name, pr.Aliases, pr.Name); err != nil {
			return fmt.Errorf("principals[%d]: %w", i, err)
		}
	}

	for i, r := range p.DNSRecords {
		record := store.DNSRecord{Name: r.Name, Type: r.Type, Value: r.Value, TTL: ttlOr(r.TTL, opts.DefaultTTL)}
		if err := dnssrv.ValidateRecord(record); err != nil {
			return fmt.Errorf("dns_records[%d]: %w", i, err)
		}
	}

	return nil
}

// nameSet collects the Kerberos names a plan hands out, so that a name claimed twice is reported
// against the file rather than discovered as a constraint violation partway through applying it.
type nameSet struct {
	realm string
	owner map[string]string
}

func newNameSet(realm string) *nameSet {
	return &nameSet{realm: realm, owner: make(map[string]string)}
}

// claim records a principal's canonical name and its aliases as belonging to owner.
func (s *nameSet) claim(canonical string, aliases []string, owner string) error {
	for _, raw := range append([]string{canonical}, aliases...) {
		n, err := krbkeys.ParseName(raw, s.realm)
		if err != nil {
			return err
		}

		if prev, ok := s.owner[n.String()]; ok {
			return fmt.Errorf("%s is claimed by both %s and %s", n, prev, owner)
		}

		s.owner[n.String()] = owner
	}

	return nil
}

// checkPassword applies the realm's length rule to a password the plan carries.
func checkPassword(password string, minLength int) error {
	if len(password) == 0 {
		return nil
	}

	if len(password) < minLength {
		return fmt.Errorf("password must be at least %d characters", minLength)
	}

	return nil
}

// Apply creates everything in the plan that does not exist yet.
func Apply(ctx context.Context, st *store.Store, plan *Plan, opts Options, log zerolog.Logger) (Summary, error) {
	var summary Summary

	if err := plan.Validate(opts); err != nil {
		return summary, err
	}

	// Groups come first: an account names its primary group by number, and a group that does
	// not exist yet has no number to name.
	for _, g := range plan.Groups {
		created, err := applyGroup(ctx, st, g)
		if err != nil {
			return summary, fmt.Errorf("group %s: %w", g.Name, err)
		}
		summary.count(created)

		log.Info().Str("group", g.Name).Bool("created", created).Msg("bootstrap group")
	}

	for _, u := range plan.Users {
		created, err := applyUser(ctx, st, u, opts)
		if err != nil {
			return summary, fmt.Errorf("user %s: %w", u.Name, err)
		}
		summary.count(created)

		log.Info().Str("user", u.Name).Bool("created", created).Msg("bootstrap user")
	}

	for _, p := range plan.Principals {
		created, err := applyPrincipal(ctx, st, p, opts)
		if err != nil {
			return summary, fmt.Errorf("principal %s: %w", p.Name, err)
		}
		summary.count(created)

		log.Info().Str("principal", p.Name).Bool("created", created).Msg("bootstrap principal")
	}

	for _, r := range plan.DNSRecords {
		created, err := applyDNSRecord(ctx, st, r, opts)
		if err != nil {
			return summary, fmt.Errorf("dns record %s %s: %w", r.Name, r.Type, err)
		}
		summary.count(created)
	}

	return summary, nil
}

func (s *Summary) count(created bool) {
	if created {
		s.Created++

		return
	}

	s.Existed++
}

func applyGroup(ctx context.Context, st *store.Store, g Group) (bool, error) {
	switch _, err := st.GetGroup(ctx, g.Name); {
	case err == nil:
		return false, nil
	case !errors.Is(err, store.ErrNotFound):
		return false, err
	}

	gid := g.GIDNumber
	if gid == 0 {
		next, err := st.NextGIDNumber(ctx)
		if err != nil {
			return false, err
		}
		gid = next
	}

	return true, st.CreateGroup(ctx, &store.Group{
		Name:          g.Name,
		GIDNumber:     gid,
		Description:   g.Description,
		IncludeGroups: g.IncludeGroups,
		Capabilities:  capabilities(g.Capabilities),
		CustomAttrs:   g.CustomAttrs,
	})
}

func applyUser(ctx context.Context, st *store.Store, u User, opts Options) (bool, error) {
	switch _, err := st.GetUser(ctx, u.Name); {
	case err == nil:
		return false, nil
	case !errors.Is(err, store.ErrNotFound):
		return false, err
	}

	var expiry *time.Time
	if u.ForceChange {
		now := time.Now().UTC()
		expiry = &now
	}

	account := store.NewAccount{
		User: &store.User{
			Name: u.Name, UIDNumber: u.UIDNumber, PrimaryGroup: u.PrimaryGroup,
			OtherGroups: u.OtherGroups, GivenName: u.GivenName, SN: u.SN, Mail: u.Mail,
			LoginShell: u.LoginShell, Homedir: u.Homedir, Disabled: u.Disabled,
			SSHKeys: u.SSHKeys, CustomAttrs: u.CustomAttrs, OTPSecret: u.OTPSecret,
			Capabilities: capabilities(u.Capabilities),
		},
		Realm:             opts.Realm,
		EncTypes:          opts.EncTypes,
		Password:          u.Password,
		PasswordExpiresAt: expiry,
		Aliases:           u.Aliases,
	}

	return true, st.CreateAccount(ctx, account)
}

func applyPrincipal(ctx context.Context, st *store.Store, p Principal, opts Options) (bool, error) {
	name, err := krbkeys.ParseName(p.Name, opts.Realm)
	if err != nil {
		return false, err
	}

	switch _, err := st.GetPrincipal(ctx, name); {
	case err == nil:
		return false, nil
	case !errors.Is(err, store.ErrNotFound):
		return false, err
	}

	var keys []krbkeys.Key

	if len(p.Password) > 0 {
		keys, err = krbkeys.DeriveKeys(p.Password, name, opts.EncTypes)
	} else {
		keys, err = krbkeys.RandomKeys(opts.EncTypes)
	}
	if err != nil {
		return false, err
	}

	principal := &store.Principal{
		Name: name.Principal(), Realm: name.Realm,
		Enabled:              boolOr(p.Enabled, true),
		RequiresPreAuth:      boolOr(p.RequiresPreAuth, true),
		AllowForwardable:     boolOr(p.AllowForwardable, true),
		AllowProxiable:       boolOr(p.AllowProxiable, true),
		AllowRenewable:       boolOr(p.AllowRenewable, true),
		AllowPostdate:        boolOr(p.AllowPostdate, false),
		OKAsDelegate:         boolOr(p.OKAsDelegate, false),
		OKToAuthAsDelegate:   boolOr(p.OKToAuthAsDelegate, false),
		AllowedToDelegateTo:  p.AllowedToDelegateTo,
		AllowedToImpersonate: p.AllowedToImpersonate,
		Aliases:              p.Aliases,
		MaxTicketLife:        p.MaxTicketLife,
		MaxRenewableLife:     p.MaxRenewableLife,
	}

	return true, st.CreatePrincipal(ctx, principal, keys)
}

func applyDNSRecord(ctx context.Context, st *store.Store, r DNSRecord, opts Options) (bool, error) {
	existing, err := st.LookupDNSRecords(ctx, r.Name)
	if err != nil {
		return false, err
	}

	wantType := strings.ToUpper(strings.TrimSpace(r.Type))

	for _, e := range existing {
		if e.Type == wantType && e.Value == strings.TrimSpace(r.Value) {
			return false, nil
		}
	}

	record := &store.DNSRecord{
		Name: r.Name, Type: wantType, Value: r.Value, TTL: ttlOr(r.TTL, opts.DefaultTTL),
	}

	return true, st.CreateDNSRecord(ctx, record)
}

// capabilities converts the plan's form into the store's.
func capabilities(in []Capability) []store.Capability {
	if len(in) == 0 {
		return nil
	}

	out := make([]store.Capability, 0, len(in))
	for _, c := range in {
		out = append(out, store.Capability{Action: c.Action, Object: c.Object})
	}

	return out
}

func boolOr(v *bool, fallback bool) bool {
	if v == nil {
		return fallback
	}

	return *v
}

func ttlOr(ttl, fallback int) int {
	if ttl > 0 {
		return ttl
	}

	if fallback > 0 {
		return fallback
	}

	return 3600
}
