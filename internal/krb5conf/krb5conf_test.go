package krb5conf

import (
	"strings"
	"testing"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/config"
)

func stand() *config.Config {
	cfg := &config.Config{}
	cfg.Server.Realm = "ADH.LOCAL"
	cfg.KDC.Enabled = true
	cfg.KDC.Listen = "0.0.0.0:88"
	cfg.KDC.MaxTicketLife = 24 * time.Hour
	cfg.KDC.MaxRenewableLife = 168 * time.Hour
	cfg.KDC.EncTypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}
	cfg.KPasswd.Enabled = true
	cfg.KPasswd.Listen = "0.0.0.0:464"
	cfg.DNS.Enabled = true
	return cfg
}

func TestWithNameServerNeedsNoRealmsBlock(t *testing.T) {
	out, err := Render(stand(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"default_realm = ADH.LOCAL",
		"dns_lookup_realm = true",
		"dns_lookup_kdc = true",
		"ticket_lifetime = 24h",
		"renew_lifetime = 168h",
		"default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96",
		"    .adh.local = ADH.LOCAL",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\n[realms]\n") || strings.Contains(out, "\n        kdc = ") {
		t.Errorf("a name-server client must not name the KDC:\n%s", out)
	}
	if strings.Contains(out, "rdns") || strings.Contains(out, "canonicalize") {
		t.Errorf("reverse DNS and canonicalisation are left at the library defaults:\n%s", out)
	}
}

func TestWithoutNameServerNamesTheKDCAndPasswordService(t *testing.T) {
	cfg := stand()
	cfg.DNS.Enabled = false
	out, err := Render(cfg, Options{Host: "kdc.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[realms]",
		"ADH.LOCAL = {",
		"kdc = kdc.example.com:88",
		"kpasswd_server = kdc.example.com:464",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "dns_lookup") {
		t.Errorf("DNS lookups must be off without the name server:\n%s", out)
	}
}

func TestSpecificBindAddressTakesItsHost(t *testing.T) {
	cfg := stand()
	cfg.DNS.Enabled = false
	cfg.KDC.Listen = "10.0.0.5:8088"
	cfg.KPasswd.Listen = "10.0.0.5:4640"
	out, err := Render(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "kdc = 10.0.0.5:8088") || !strings.Contains(out, "kpasswd_server = 10.0.0.5:4640") {
		t.Errorf("the bound address and port are not used:\n%s", out)
	}
}

func TestUnspecifiedBindNeedsAHost(t *testing.T) {
	cfg := stand()
	cfg.DNS.Enabled = false
	if _, err := Render(cfg, Options{}); err == nil {
		t.Fatal("an unspecified bind address was accepted without -host")
	}
}

func TestDurationsAreWrittenInTheFormKrb5ReadsBack(t *testing.T) {
	if got := duration(90 * time.Minute); got != "90m" {
		t.Errorf("90m: got %q", got)
	}
	if got := duration(10 * time.Hour); got != "10h" {
		t.Errorf("10h: got %q", got)
	}
}

func TestRealmIsRequired(t *testing.T) {
	cfg := stand()
	cfg.Server.Realm = ""
	if _, err := Render(cfg, Options{}); err == nil {
		t.Fatal("a config without a realm rendered")
	}
}

func TestHostsZoneIsMappedToTheRealm(t *testing.T) {
	cfg := stand()
	cfg.Server.Domain = "adh.local"
	cfg.DNS.Zone = "adh.adh.svc.cluster.local"
	out, err := Render(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"    .adh.adh.svc.cluster.local = ADH.LOCAL",
		"    adh.adh.svc.cluster.local = ADH.LOCAL",
		"    .adh.local = ADH.LOCAL",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
