// Package config defines the on-disk configuration of the service and its defaults.
//
// The configuration covers only what an operator sets once and rarely changes: listeners, realm
// identity, crypto policy and the location of the database. Everything that is managed day to day
// -- users, groups, principals, keys -- lives in the store and is edited through the REST API.
//
// Values come from three places, each overriding the one before it: the defaults declared in the
// envDefault struct tags, the environment, and the YAML file. The file has the last word, so a
// setting written there is what the service runs with regardless of what the surrounding
// environment happens to hold.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"gopkg.in/yaml.v3"
)

// Server holds the identity of the directory: the Kerberos realm, the LDAP naming context and the
// Windows domain SID that PACs are issued under.
type Server struct {
	Realm string `yaml:"realm" env:"REALM"`

	// BaseDN is the LDAP naming context, e.g. "dc=example,dc=com". Derived from Domain when
	// left empty.
	BaseDN string `yaml:"base_dn" env:"BASE_DN"`

	// Domain is the DNS domain used for the realm mapping and UPN suffixes. Derived from Realm
	// when left empty.
	Domain string `yaml:"domain" env:"DOMAIN"`

	// DomainSID is the SID the PAC is issued under, e.g. "S-1-5-21-a-b-c". Generated on first
	// start and persisted in the store when left empty.
	DomainSID string `yaml:"domain_sid" env:"DOMAIN_SID"`

	// NetBIOSName names the domain in the PAC's logon domain field. Derived from the first
	// label of Realm when left empty.
	NetBIOSName string `yaml:"netbios_name" env:"NETBIOS_NAME"`

	// NameFormat is the RDN attribute used for user entries, e.g. "cn" or "uid".
	NameFormat string `yaml:"name_format" env:"NAME_FORMAT" envDefault:"cn"`

	// GroupFormat is the RDN attribute used for group entries, e.g. "ou" or "cn".
	GroupFormat string `yaml:"group_format" env:"GROUP_FORMAT" envDefault:"ou"`

	// SSHKeyAttr is the attribute name SSH keys are published under.
	SSHKeyAttr string `yaml:"ssh_key_attr" env:"SSH_KEY_ATTR" envDefault:"sshPublicKey"`

	// AnonymousDSE allows unauthenticated clients to read the root DSE.
	AnonymousDSE bool `yaml:"anonymous_dse" env:"ANONYMOUS_DSE"`

	// The identifier range maps POSIX ids onto the Windows relative identifiers that appear in
	// issued PACs, the way FreeIPA's ipa-local range does. It is pinned in the database on
	// first start, because every SID handed out is derived from it.
	//
	// IDRangeBaseID is the lowest uid or gid the range covers and IDRangeSize how many it
	// spans; an account outside it gets no SID and therefore no PAC.
	IDRangeBaseID int `yaml:"id_range_base_id" env:"ID_RANGE_BASE_ID" envDefault:"1"`
	IDRangeSize   int `yaml:"id_range_size" env:"ID_RANGE_SIZE" envDefault:"200000"`

	// IDRangeBaseRID is where RIDs start. It must clear 1000, below which Windows reserves the
	// RIDs for well-known accounts such as the domain administrator.
	IDRangeBaseRID int `yaml:"id_range_base_rid" env:"ID_RANGE_BASE_RID" envDefault:"1000"`

	// IDRangeSecondaryBaseRID starts the interval an object falls back to when its primary RID
	// is already taken, which is how a user and a group sharing a POSIX id stay distinct.
	IDRangeSecondaryBaseRID int `yaml:"id_range_secondary_base_rid" env:"ID_RANGE_SECONDARY_BASE_RID" envDefault:"100000000"`
}

// Database locates the SQLite file and the master key that seals key material inside it.
type Database struct {
	Path string `yaml:"path" env:"PATH" envDefault:"ldap-kdc.db"`

	// MasterKeyFile holds the 32 byte key that all Kerberos key material is sealed with. It is
	// generated on first start if the file does not exist.
	MasterKeyFile string `yaml:"master_key_file" env:"MASTER_KEY_FILE" envDefault:"master.key"`
}

// LDAP is the cleartext LDAP listener, optionally offering StartTLS.
type LDAP struct {
	Enabled  bool   `yaml:"enabled" env:"ENABLED" envDefault:"true"`
	Listen   string `yaml:"listen" env:"LISTEN" envDefault:"0.0.0.0:389"`
	TLS      bool   `yaml:"tls" env:"TLS"`
	CertPath string `yaml:"cert_path" env:"CERT_PATH"`
	KeyPath  string `yaml:"key_path" env:"KEY_PATH"`
}

// LDAPS is the implicit-TLS LDAP listener.
type LDAPS struct {
	Enabled  bool   `yaml:"enabled" env:"ENABLED"`
	Listen   string `yaml:"listen" env:"LISTEN" envDefault:"0.0.0.0:636"`
	CertPath string `yaml:"cert_path" env:"CERT_PATH"`
	KeyPath  string `yaml:"key_path" env:"KEY_PATH"`
}

// KDC is the Kerberos ticket-granting service.
type KDC struct {
	Enabled bool `yaml:"enabled" env:"ENABLED" envDefault:"true"`

	// Listen is used for both TCP and UDP.
	Listen string `yaml:"listen" env:"LISTEN" envDefault:"0.0.0.0:88"`

	MaxTicketLife    time.Duration `yaml:"max_ticket_life" env:"MAX_TICKET_LIFE" envDefault:"10h"`
	MaxRenewableLife time.Duration `yaml:"max_renewable_life" env:"MAX_RENEWABLE_LIFE" envDefault:"168h"`
	ClockSkew        time.Duration `yaml:"clock_skew" env:"CLOCK_SKEW" envDefault:"5m"`

	// EncTypes lists the enctypes the KDC will use, most preferred first. Keys are generated
	// for every enctype in this list when a password is set.
	EncTypes []string `yaml:"enc_types" env:"ENC_TYPES" envDefault:"aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96,aes256-cts-hmac-sha384-192,aes128-cts-hmac-sha256-128"`

	// RequirePreAuth denies AS exchanges that carry no PA-ENC-TIMESTAMP. Turning it off exposes
	// every principal to offline AS-REP cracking; it exists only for principals that predate
	// pre-authentication.
	RequirePreAuth bool `yaml:"require_pre_auth" env:"REQUIRE_PRE_AUTH" envDefault:"true"`

	// IssuePAC adds a Microsoft PAC to issued tickets, which Windows and Samba services
	// require for authorization.
	IssuePAC bool `yaml:"issue_pac" env:"ISSUE_PAC" envDefault:"true"`

	// AllowS4U enables protocol transition (S4U2Self) and constrained delegation (S4U2Proxy).
	AllowS4U bool `yaml:"allow_s4u" env:"ALLOW_S4U" envDefault:"true"`

	// UDPMaxSize bounds a single datagram; larger replies set the TCP-required bit.
	UDPMaxSize int `yaml:"udp_max_size" env:"UDP_MAX_SIZE" envDefault:"4096"`
}

// KPasswd is the RFC 3244 password change service.
type KPasswd struct {
	Enabled bool   `yaml:"enabled" env:"ENABLED" envDefault:"true"`
	Listen  string `yaml:"listen" env:"LISTEN" envDefault:"0.0.0.0:464"`

	// MinPasswordLength rejects shorter passwords on change and set operations.
	MinPasswordLength int `yaml:"min_password_length" env:"MIN_PASSWORD_LENGTH" envDefault:"8"`
}

// DNS is the authoritative name server for the realm's zone.
//
// It exists because Kerberos leans on DNS in two places: clients find the KDC through SRV records,
// and, more awkwardly, a client that is given a host-based service name canonicalises the host
// through DNS before turning it into a principal. Without a reverse zone that answers with the
// names this realm uses, that canonicalisation produces a principal nobody registered, and every
// such client has to be configured with rdns turned off instead.
type DNS struct {
	Enabled bool   `yaml:"enabled" env:"ENABLED"`
	Listen  string `yaml:"listen" env:"LISTEN" envDefault:"0.0.0.0:53"`

	// Zone is the forward zone served. It defaults to the server's domain.
	Zone string `yaml:"zone" env:"ZONE"`

	// ExtraZones are further forward zones this server answers for. They carry no discovery
	// records of their own — only what is put in them — and exist because a deployment's PUBLIC
	// names are usually not its realm's: until something answers for them, such a name is a
	// convention in one client's hosts file rather than a fact of the deployment.
	ExtraZones []string `yaml:"extra_zones" env:"EXTRA_ZONES" envSeparator:","`

	// ReverseZones are the in-addr.arpa and ip6.arpa zones this server answers for. Reverse
	// answers are derived from the address records, so no PTR records need maintaining.
	ReverseZones []string `yaml:"reverse_zones" env:"REVERSE_ZONES"`

	// Hostname is this server's fully qualified name: the zone's name server and the target of
	// every service record. It is not guessed from the operating system, because a wrong SRV
	// target sends every client somewhere that does not answer.
	Hostname string `yaml:"hostname" env:"HOSTNAME"`

	// Addresses are the addresses Hostname resolves to, and the ones reverse queries answer for.
	Addresses []string `yaml:"addresses" env:"ADDRESSES"`

	// Mailbox is the zone contact written into the SOA record.
	Mailbox string `yaml:"mailbox" env:"MAILBOX"`

	TTL time.Duration `yaml:"ttl" env:"TTL" envDefault:"1h"`
}

// Bootstrap points at a plan describing the directory a fresh realm should come up with.
//
// It is meant for the cases where nobody is present to provision the service: a continuous
// integration job, a test stand, a development container. Applying a plan creates what is missing
// and leaves alone what is already there, so a restart is not a reset.
type Bootstrap struct {
	// File is the plan to apply on start-up. An empty path applies nothing.
	File string `yaml:"file" env:"FILE"`
}

// API is the REST management interface.
type API struct {
	Enabled  bool   `yaml:"enabled" env:"ENABLED" envDefault:"true"`
	Listen   string `yaml:"listen" env:"LISTEN" envDefault:"127.0.0.1:5555"`
	TLS      bool   `yaml:"tls" env:"TLS"`
	CertPath string `yaml:"cert_path" env:"CERT_PATH"`
	KeyPath  string `yaml:"key_path" env:"KEY_PATH"`

	// Token, when set, is required as "Authorization: Bearer <token>" on every request.
	Token string `yaml:"token" env:"TOKEN"`

	// TokenFile reads Token from a file, so the secret need not sit in the configuration.
	TokenFile string `yaml:"token_file" env:"TOKEN_FILE"`

	// Docs serves the OpenAPI document at /api/openapi.json and Swagger UI at /api/docs. Both
	// sit outside the token check, because a browser cannot put a header on the address bar;
	// turn it off on a service whose management port is reachable more widely than its
	// administrators.
	Docs bool `yaml:"docs" env:"DOCS" envDefault:"true"`
}

// OIDCClient is a relying party the provider will issue tokens to.
//
// The id may be any string, and a deployment that identifies its services by URL should use the
// service's URL: an id token's audience IS the client id, so that is what a service checking
// "is this token for me" compares against.
type OIDCClient struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
	// Secret makes the client CONFIDENTIAL: an application that runs on a server and can keep one.
	// Leave it empty for a page, which cannot. It is demanded in addition to PKCE, not instead.
	Secret             string   `yaml:"secret"`
	SecretFile         string   `yaml:"secret_file"`
	RedirectURIs       []string `yaml:"redirect_uris"`
	PostLogoutRedirect []string `yaml:"post_logout_redirect_uris"`
}

// OIDC serves the directory's accounts to browsers as an OpenID Connect provider, so one sign-in
// reaches every interface a deployment puts in front of it.
type OIDC struct {
	Enabled  bool   `yaml:"enabled" env:"ENABLED"`
	Listen   string `yaml:"listen" env:"LISTEN" envDefault:"127.0.0.1:5557"`
	TLS      bool   `yaml:"tls" env:"TLS"`
	CertPath string `yaml:"cert_path" env:"CERT_PATH"`
	KeyPath  string `yaml:"key_path" env:"KEY_PATH"`

	// Issuer is what lands in every token's iss claim and what the BROWSER must reach — the
	// public address, which behind a proxy is not the address this binds. It must not end in a
	// slash: verifiers compare it to the iss claim byte for byte.
	Issuer string `yaml:"issuer" env:"ISSUER"`

	// AllowedOrigins are the web origins whose pages may read discovery, the keys and the token
	// endpoint from script. A single-page application never shares an origin with its provider.
	AllowedOrigins []string `yaml:"allowed_origins" env:"ALLOWED_ORIGINS" envSeparator:","`

	// SessionLifetime is how long one sign-in is good for however active; SessionIdle is how
	// long it survives unused. The session is the whole point: without it every application
	// asks for a password again.
	SessionLifetime time.Duration `yaml:"session_lifetime" env:"SESSION_LIFETIME" envDefault:"12h"`
	SessionIdle     time.Duration `yaml:"session_idle" env:"SESSION_IDLE" envDefault:"2h"`

	// CodeLifetime bounds an authorization code and an unfinished sign-in; TokenLifetime bounds
	// an issued token.
	CodeLifetime  time.Duration `yaml:"code_lifetime" env:"CODE_LIFETIME" envDefault:"5m"`
	TokenLifetime time.Duration `yaml:"token_lifetime" env:"TOKEN_LIFETIME" envDefault:"1h"`

	// ServiceAccountGroup names the directory group whose members may use the client credentials
	// grant — a service account asking for a token with its own name and password, no person
	// involved. Empty turns the grant off entirely, which is the right default: without a gate
	// every person's password would double as a machine key.
	ServiceAccountGroup string `yaml:"service_account_group" env:"SERVICE_ACCOUNT_GROUP"`

	Clients []OIDCClient `yaml:"clients"`
}

// Behaviors carries the policy knobs that bound password guessing and directory reads.
type Behaviors struct {
	IgnoreCapabilities    bool          `yaml:"ignore_capabilities" env:"IGNORE_CAPABILITIES"`
	LimitFailedBinds      bool          `yaml:"limit_failed_binds" env:"LIMIT_FAILED_BINDS" envDefault:"true"`
	NumberOfFailedBinds   int           `yaml:"number_of_failed_binds" env:"NUMBER_OF_FAILED_BINDS" envDefault:"3"`
	PeriodOfFailedBinds   time.Duration `yaml:"period_of_failed_binds" env:"PERIOD_OF_FAILED_BINDS" envDefault:"10s"`
	BlockFailedBindsFor   time.Duration `yaml:"block_failed_binds_for" env:"BLOCK_FAILED_BINDS_FOR" envDefault:"60s"`
	PruneSourceTableEvery time.Duration `yaml:"prune_source_table_every" env:"PRUNE_SOURCE_TABLE_EVERY" envDefault:"10m"`
	PruneSourcesOlderThan time.Duration `yaml:"prune_sources_older_than" env:"PRUNE_SOURCES_OLDER_THAN" envDefault:"10m"`
}

// Config is the whole configuration file.
type Config struct {
	Debug         bool `yaml:"debug" env:"DEBUG"`
	StructuredLog bool `yaml:"structured_log" env:"STRUCTURED_LOG"`

	Server    Server    `yaml:"server" envPrefix:"SERVER_"`
	Database  Database  `yaml:"database" envPrefix:"DB_"`
	LDAP      LDAP      `yaml:"ldap" envPrefix:"LDAP_"`
	LDAPS     LDAPS     `yaml:"ldaps" envPrefix:"LDAPS_"`
	KDC       KDC       `yaml:"kdc" envPrefix:"KDC_"`
	KPasswd   KPasswd   `yaml:"kpasswd" envPrefix:"KPASSWD_"`
	DNS       DNS       `yaml:"dns" envPrefix:"DNS_"`
	API       API       `yaml:"api" envPrefix:"API_"`
	OIDC      OIDC      `yaml:"oidc" envPrefix:"OIDC_"`
	Bootstrap Bootstrap `yaml:"bootstrap" envPrefix:"BOOTSTRAP_"`
	Behaviors Behaviors `yaml:"behaviors" envPrefix:"BEHAVIORS_"`

	// Path is the file this configuration was read from. It is filled in by Load rather than
	// configured.
	Path string `yaml:"-" env:"-"`
}

var realmRE = regexp.MustCompile(`^[A-Z0-9][A-Z0-9.-]*[A-Z0-9]$`)

// Load builds the configuration from the environment and the YAML file at path, then validates it.
// An empty path configures the service from the environment alone; a path that does not exist is
// an error, because silently running on defaults is not what someone naming a file meant.
func Load(path string) (*Config, error) {
	cfg := &Config{}

	// The defaults live in envDefault tags, so this one call yields both them and whatever the
	// environment overrides.
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("reading configuration from the environment: %w", err)
	}

	if len(path) > 0 {
		if err := cfg.loadFile(path); err != nil {
			return nil, err
		}
	}

	if err := cfg.normalize(); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadFile overlays the YAML document at path onto the configuration. Keys absent from the file
// keep the value the environment or the defaults gave them.
func (c *Config) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	// A misspelled key silently ignored is how an operator ends up believing a setting was
	// applied when it never was.
	dec.KnownFields(true)

	// An empty file is a valid configuration: everything then comes from the environment.
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	c.Path = path

	return nil
}

// normalize fills in the fields that are derived from others and resolves paths relative to the
// configuration file, so a relative database path means "next to the configuration".
func (c *Config) normalize() error {
	c.Server.Realm = strings.ToUpper(strings.TrimSpace(c.Server.Realm))

	if len(c.Server.Domain) == 0 {
		c.Server.Domain = strings.ToLower(c.Server.Realm)
	}
	c.Server.Domain = strings.ToLower(c.Server.Domain)

	if len(c.Server.NetBIOSName) == 0 {
		c.Server.NetBIOSName = strings.SplitN(c.Server.Realm, ".", 2)[0]
	}
	c.Server.NetBIOSName = strings.ToUpper(c.Server.NetBIOSName)

	if len(c.Server.BaseDN) == 0 {
		c.Server.BaseDN = baseDNFromDomain(c.Server.Domain)
	}
	c.Server.BaseDN = strings.ToLower(c.Server.BaseDN)

	if len(c.DNS.Zone) == 0 {
		c.DNS.Zone = c.Server.Domain
	}
	c.DNS.Zone = strings.ToLower(c.DNS.Zone)
	c.DNS.Hostname = strings.ToLower(c.DNS.Hostname)

	if len(c.API.TokenFile) > 0 {
		b, err := os.ReadFile(c.resolve(c.API.TokenFile))
		if err != nil {
			return fmt.Errorf("reading api token file: %w", err)
		}
		c.API.Token = strings.TrimSpace(string(b))
	}

	c.Database.Path = c.resolve(c.Database.Path)
	c.Database.MasterKeyFile = c.resolve(c.Database.MasterKeyFile)
	c.LDAP.CertPath = c.resolve(c.LDAP.CertPath)
	c.LDAP.KeyPath = c.resolve(c.LDAP.KeyPath)
	c.LDAPS.CertPath = c.resolve(c.LDAPS.CertPath)
	c.LDAPS.KeyPath = c.resolve(c.LDAPS.KeyPath)
	c.API.CertPath = c.resolve(c.API.CertPath)
	c.API.KeyPath = c.resolve(c.API.KeyPath)
	c.Bootstrap.File = c.resolve(c.Bootstrap.File)

	return nil
}

// baseDNFromDomain turns "example.com" into "dc=example,dc=com".
func baseDNFromDomain(domain string) string {
	parts := strings.Split(domain, ".")
	dc := make([]string, 0, len(parts))

	for _, p := range parts {
		if len(p) > 0 {
			dc = append(dc, "dc="+p)
		}
	}

	return strings.Join(dc, ",")
}

// resolve interprets a relative path as relative to the directory holding the configuration file.
func (c *Config) resolve(p string) string {
	if len(p) == 0 || filepath.IsAbs(p) || len(c.Path) == 0 {
		return p
	}

	return filepath.Join(filepath.Dir(c.Path), p)
}

// Validate reports the first configuration error that would keep the service from starting.
func (c *Config) Validate() error {
	if len(c.Server.Realm) == 0 {
		return errors.New("server.realm is required")
	}
	if !realmRE.MatchString(c.Server.Realm) {
		return fmt.Errorf("server.realm %q is not a valid realm name", c.Server.Realm)
	}
	if len(c.Server.DomainSID) > 0 && !strings.HasPrefix(c.Server.DomainSID, "S-1-5-21-") {
		return fmt.Errorf("server.domain_sid %q must be an S-1-5-21 domain SID", c.Server.DomainSID)
	}
	if len(c.Database.Path) == 0 {
		return errors.New("database.path is required")
	}
	if len(c.Database.MasterKeyFile) == 0 {
		return errors.New("database.master_key_file is required")
	}

	if err := c.validateListeners(); err != nil {
		return err
	}

	if err := c.validateTLS(); err != nil {
		return err
	}

	if err := c.validateOIDC(); err != nil {
		return err
	}

	// A named plan that cannot be read is a start-up failure waiting to happen, so it is caught
	// here where --check-config will find it.
	if len(c.Bootstrap.File) > 0 {
		if _, err := os.Stat(c.Bootstrap.File); err != nil {
			return fmt.Errorf("bootstrap.file: %w", err)
		}
	}

	return c.validateKerberos()
}

// validateOIDC checks the provider's own settings — the ones whose absence would only surface at
// somebody's first sign-in.
func (c *Config) validateOIDC() error {
	if !c.OIDC.Enabled {
		return nil
	}
	if len(c.OIDC.Issuer) == 0 {
		return errors.New("oidc.issuer is required: it is what lands in every token and what the browser must reach")
	}
	u, err := url.Parse(c.OIDC.Issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("oidc.issuer %q must be an absolute URL", c.OIDC.Issuer)
	}
	// Discovery hangs off the issuer and every verifier compares it to the iss claim byte for
	// byte, so a trailing slash is the difference between agreeing and not.
	if strings.HasSuffix(c.OIDC.Issuer, "/") {
		return fmt.Errorf("oidc.issuer %q must not end in a slash", c.OIDC.Issuer)
	}
	if len(c.OIDC.Clients) == 0 {
		return errors.New("oidc.clients is empty: nothing could obtain a token")
	}
	for _, cl := range c.OIDC.Clients {
		if len(cl.ID) == 0 {
			return errors.New("every oidc client needs an id")
		}
		if len(cl.RedirectURIs) == 0 {
			return fmt.Errorf("oidc client %q has no redirect_uris, so it could never be sent an answer", cl.ID)
		}
	}

	return nil
}

// validateListeners checks that every enabled listener has a usable address.
func (c *Config) validateListeners() error {
	for _, l := range []struct {
		enabled bool
		name    string
		addr    string
	}{
		{c.LDAP.Enabled, "ldap.listen", c.LDAP.Listen},
		{c.LDAPS.Enabled, "ldaps.listen", c.LDAPS.Listen},
		{c.KDC.Enabled, "kdc.listen", c.KDC.Listen},
		{c.KPasswd.Enabled, "kpasswd.listen", c.KPasswd.Listen},
		{c.DNS.Enabled, "dns.listen", c.DNS.Listen},
		{c.API.Enabled, "api.listen", c.API.Listen},
		{c.OIDC.Enabled, "oidc.listen", c.OIDC.Listen},
	} {
		if !l.enabled {
			continue
		}
		if _, _, err := net.SplitHostPort(l.addr); err != nil {
			return fmt.Errorf("%s: %w", l.name, err)
		}
	}

	return nil
}

// validateTLS checks that every listener asked to serve TLS has a certificate to serve it with.
func (c *Config) validateTLS() error {
	for _, t := range []struct {
		enabled  bool
		name     string
		certPath string
		keyPath  string
	}{
		{c.LDAP.Enabled && c.LDAP.TLS, "ldap", c.LDAP.CertPath, c.LDAP.KeyPath},
		{c.LDAPS.Enabled, "ldaps", c.LDAPS.CertPath, c.LDAPS.KeyPath},
		{c.API.Enabled && c.API.TLS, "api", c.API.CertPath, c.API.KeyPath},
		{c.OIDC.Enabled && c.OIDC.TLS, "oidc", c.OIDC.CertPath, c.OIDC.KeyPath},
	} {
		if !t.enabled {
			continue
		}
		if len(t.certPath) == 0 || len(t.keyPath) == 0 {
			return fmt.Errorf("%s.cert_path and %s.key_path are required when %s serves TLS",
				t.name, t.name, t.name)
		}
	}

	return nil
}

// validateKerberos checks the realm's crypto and ticket policy.
func (c *Config) validateKerberos() error {
	if c.KDC.Enabled && len(c.KDC.EncTypes) == 0 {
		return errors.New("kdc.enc_types must list at least one enctype")
	}
	if c.KDC.MaxTicketLife <= 0 {
		return errors.New("kdc.max_ticket_life must be positive")
	}
	if c.KDC.MaxRenewableLife < c.KDC.MaxTicketLife {
		return errors.New("kdc.max_renewable_life must not be shorter than kdc.max_ticket_life")
	}
	if c.KDC.ClockSkew <= 0 {
		return errors.New("kdc.clock_skew must be positive")
	}
	if c.KDC.UDPMaxSize < 576 {
		return errors.New("kdc.udp_max_size must be at least 576")
	}
	if c.KPasswd.Enabled && !c.KDC.Enabled {
		return errors.New("kpasswd requires the kdc to be enabled")
	}

	return c.validateDNS()
}

// validateDNS checks the zone this server would answer for.
func (c *Config) validateDNS() error {
	if !c.DNS.Enabled {
		return nil
	}

	if len(c.DNS.Hostname) == 0 {
		return errors.New("dns.hostname is required: it is the zone's name server and the target of every service record")
	}
	if !strings.Contains(c.DNS.Hostname, ".") {
		return fmt.Errorf("dns.hostname %q must be fully qualified", c.DNS.Hostname)
	}
	if len(c.DNS.Addresses) == 0 {
		return errors.New("dns.addresses is required: it is what dns.hostname resolves to")
	}

	for _, a := range c.DNS.Addresses {
		if _, err := netip.ParseAddr(a); err != nil {
			return fmt.Errorf("dns.addresses: %q is not an IP address", a)
		}
	}

	if c.DNS.TTL <= 0 {
		return errors.New("dns.ttl must be positive")
	}

	return nil
}

// KrbTGTPrincipal is the name of the realm's own ticket-granting principal.
func (c *Config) KrbTGTPrincipal() string {
	return "krbtgt/" + c.Server.Realm
}
