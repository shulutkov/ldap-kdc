package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// write puts a YAML document in a temporary directory and returns its path.
func write(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ldap-kdc.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	return path
}

const minimal = "server:\n  realm: EXAMPLE.COM\n"

func TestDefaultsComeFromTheStructTags(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, tc := range []struct {
		name string
		got  any
		want any
	}{
		{"server.name_format", cfg.Server.NameFormat, "cn"},
		{"server.group_format", cfg.Server.GroupFormat, "ou"},
		{"server.ssh_key_attr", cfg.Server.SSHKeyAttr, "sshPublicKey"},
		{"ldap.enabled", cfg.LDAP.Enabled, true},
		{"ldap.listen", cfg.LDAP.Listen, "0.0.0.0:389"},
		{"ldaps.enabled", cfg.LDAPS.Enabled, false},
		{"kdc.listen", cfg.KDC.Listen, "0.0.0.0:88"},
		{"kdc.max_ticket_life", cfg.KDC.MaxTicketLife, 10 * time.Hour},
		{"kdc.max_renewable_life", cfg.KDC.MaxRenewableLife, 168 * time.Hour},
		{"kdc.clock_skew", cfg.KDC.ClockSkew, 5 * time.Minute},
		{"kdc.require_pre_auth", cfg.KDC.RequirePreAuth, true},
		{"kdc.issue_pac", cfg.KDC.IssuePAC, true},
		{"kdc.allow_s4u", cfg.KDC.AllowS4U, true},
		{"kdc.udp_max_size", cfg.KDC.UDPMaxSize, 4096},
		{"kpasswd.min_password_length", cfg.KPasswd.MinPasswordLength, 8},
		{"api.listen", cfg.API.Listen, "127.0.0.1:5555"},
		{"behaviors.limit_failed_binds", cfg.Behaviors.LimitFailedBinds, true},
		{"behaviors.number_of_failed_binds", cfg.Behaviors.NumberOfFailedBinds, 3},
		{"behaviors.block_failed_binds_for", cfg.Behaviors.BlockFailedBindsFor, time.Minute},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}

	want := []string{
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha384-192",
		"aes128-cts-hmac-sha256-128",
	}
	if strings.Join(cfg.KDC.EncTypes, ",") != strings.Join(want, ",") {
		t.Errorf("kdc.enc_types = %v, want %v", cfg.KDC.EncTypes, want)
	}
}

func TestEnvironmentOverridesTheDefaults(t *testing.T) {
	t.Setenv("SERVER_REALM", "FROM.ENV")
	t.Setenv("KDC_LISTEN", "127.0.0.1:8888")
	t.Setenv("KDC_MAX_TICKET_LIFE", "2h")
	t.Setenv("KDC_ENC_TYPES", "aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96")
	t.Setenv("LDAP_ENABLED", "false")

	// An empty path configures the service from the environment alone.
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Realm != "FROM.ENV" {
		t.Errorf("realm = %q, want FROM.ENV", cfg.Server.Realm)
	}
	if cfg.KDC.Listen != "127.0.0.1:8888" {
		t.Errorf("kdc.listen = %q", cfg.KDC.Listen)
	}
	if cfg.KDC.MaxTicketLife != 2*time.Hour {
		t.Errorf("kdc.max_ticket_life = %v, want 2h", cfg.KDC.MaxTicketLife)
	}
	if len(cfg.KDC.EncTypes) != 2 {
		t.Errorf("kdc.enc_types = %v, want two entries", cfg.KDC.EncTypes)
	}
	if cfg.LDAP.Enabled {
		t.Error("ldap.enabled should be false when the environment says so")
	}
}

func TestFileOverridesTheEnvironment(t *testing.T) {
	t.Setenv("SERVER_REALM", "FROM.ENV")
	t.Setenv("KDC_LISTEN", "127.0.0.1:8888")
	t.Setenv("KDC_CLOCK_SKEW", "1m")

	// The file has the last word: a setting written there is what the service runs with,
	// whatever the surrounding environment holds.
	cfg, err := Load(write(t, `
server:
  realm: FROM.FILE
kdc:
  listen: 127.0.0.1:9999
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Realm != "FROM.FILE" {
		t.Errorf("realm = %q, want FROM.FILE", cfg.Server.Realm)
	}
	if cfg.KDC.Listen != "127.0.0.1:9999" {
		t.Errorf("kdc.listen = %q, want the file's value", cfg.KDC.Listen)
	}

	// A key the file does not mention keeps whatever the environment gave it.
	if cfg.KDC.ClockSkew != time.Minute {
		t.Errorf("kdc.clock_skew = %v, want the environment's 1m", cfg.KDC.ClockSkew)
	}
}

func TestFileCanTurnOffASettingThatDefaultsToOn(t *testing.T) {
	cfg, err := Load(write(t, `
server:
  realm: EXAMPLE.COM
ldap:
  enabled: false
kdc:
  require_pre_auth: false
  issue_pac: false
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// These default to true, and a false in the file has to survive: reading the file before
	// applying defaults would quietly turn them back on.
	if cfg.LDAP.Enabled {
		t.Error("ldap.enabled is true despite the file setting it to false")
	}
	if cfg.KDC.RequirePreAuth {
		t.Error("kdc.require_pre_auth is true despite the file setting it to false")
	}
	if cfg.KDC.IssuePAC {
		t.Error("kdc.issue_pac is true despite the file setting it to false")
	}
}

func TestDerivedFields(t *testing.T) {
	cfg, err := Load(write(t, "server:\n  realm: corp.example.com\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Realm != "CORP.EXAMPLE.COM" {
		t.Errorf("realm = %q, want it upper-cased", cfg.Server.Realm)
	}
	if cfg.Server.Domain != "corp.example.com" {
		t.Errorf("domain = %q", cfg.Server.Domain)
	}
	if cfg.Server.BaseDN != "dc=corp,dc=example,dc=com" {
		t.Errorf("base_dn = %q", cfg.Server.BaseDN)
	}
	if cfg.Server.NetBIOSName != "CORP" {
		t.Errorf("netbios_name = %q, want the first label of the realm", cfg.Server.NetBIOSName)
	}
}

func TestExplicitFieldsAreNotDerived(t *testing.T) {
	cfg, err := Load(write(t, `
server:
  realm: EXAMPLE.COM
  domain: internal.example.net
  base_dn: dc=custom
  netbios_name: SHORT
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Domain != "internal.example.net" {
		t.Errorf("domain = %q", cfg.Server.Domain)
	}
	if cfg.Server.BaseDN != "dc=custom" {
		t.Errorf("base_dn = %q", cfg.Server.BaseDN)
	}
	if cfg.Server.NetBIOSName != "SHORT" {
		t.Errorf("netbios_name = %q", cfg.Server.NetBIOSName)
	}
}

func TestRelativePathsResolveNextToTheFile(t *testing.T) {
	path := write(t, minimal)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	dir := filepath.Dir(path)

	if cfg.Database.Path != filepath.Join(dir, "ldap-kdc.db") {
		t.Errorf("database.path = %q, want it beside the config", cfg.Database.Path)
	}
	if cfg.Database.MasterKeyFile != filepath.Join(dir, "master.key") {
		t.Errorf("database.master_key_file = %q", cfg.Database.MasterKeyFile)
	}
}

func TestTokenFileIsRead(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "api.token"), []byte("  the-token\n"), 0o600); err != nil {
		t.Fatalf("writing token: %v", err)
	}

	path := filepath.Join(dir, "ldap-kdc.yaml")
	if err := os.WriteFile(path, []byte(minimal+"api:\n  token_file: api.token\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.API.Token != "the-token" {
		t.Errorf("api.token = %q, want the file's trimmed contents", cfg.API.Token)
	}
}

func TestUnknownKeyIsRejected(t *testing.T) {
	// A misspelled key silently ignored is how an operator ends up believing a setting was
	// applied when it never was.
	_, err := Load(write(t, "server:\n  realm: EXAMPLE.COM\n  nameformat: uid\n"))
	if err == nil {
		t.Fatal("an unknown key was accepted")
	}
	if !strings.Contains(err.Error(), "nameformat") {
		t.Errorf("error = %v, want the offending key to be named", err)
	}
}

func TestMissingFileIsAnError(t *testing.T) {
	// Naming a file that is not there means the operator expects its contents to apply;
	// starting on defaults instead would be a surprise.
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("a missing configuration file was accepted")
	}
}

func TestValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "no realm",
			body: "debug: true\n",
			want: "server.realm is required",
		},
		{
			name: "malformed realm",
			body: "server:\n  realm: \"not a realm\"\n",
			want: "is not a valid realm name",
		},
		{
			name: "foreign domain SID",
			body: "server:\n  realm: EXAMPLE.COM\n  domain_sid: S-1-5-32-544\n",
			want: "S-1-5-21",
		},
		{
			name: "ldaps without a certificate",
			body: minimal + "ldaps:\n  enabled: true\n",
			want: "ldaps.cert_path",
		},
		{
			name: "renewable life shorter than ticket life",
			body: minimal + "kdc:\n  max_ticket_life: 10h\n  max_renewable_life: 1h\n",
			want: "max_renewable_life",
		},
		{
			name: "no enctypes",
			body: minimal + "kdc:\n  enc_types: []\n",
			want: "at least one enctype",
		},
		{
			name: "unusable listen address",
			body: minimal + "kdc:\n  listen: nonsense\n",
			want: "kdc.listen",
		},
		{
			name: "kpasswd without a kdc",
			body: minimal + "kdc:\n  enabled: false\nkpasswd:\n  enabled: true\n",
			want: "kpasswd requires the kdc",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(write(t, tc.body))
			if err == nil {
				t.Fatalf("configuration was accepted, want %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestDisabledListenerNeedsNoAddress(t *testing.T) {
	// Only listeners that are actually enabled have to be configured.
	if _, err := Load(write(t, minimal+"ldap:\n  enabled: false\n  listen: \"\"\n")); err != nil {
		t.Errorf("Load: %v", err)
	}
}
