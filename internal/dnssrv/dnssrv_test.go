package dnssrv

import (
	"context"
	"io"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/secret"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

const (
	testRealm = "EXAMPLE.COM"
	testZone  = "example.com"
	testHost  = "kdc.example.com"
	testAddr  = "192.0.2.10"
)

type harness struct {
	store *store.Store
	addr  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	ctx := context.Background()
	dir := t.TempDir()

	key, _, err := secret.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("master key: %v", err)
	}

	sealer, err := secret.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	log := zerolog.New(io.Discard)

	st, err := store.Open(ctx, filepath.Join(dir, "dns.db"), sealer, log)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv, err := New(Config{
		Listen:       "127.0.0.1:0",
		Realm:        testRealm,
		Zone:         testZone,
		ReverseZones: []string{"2.0.192.in-addr.arpa"},
		Hostname:     testHost,
		Addresses:    []string{testAddr},
		TTL:          time.Hour,
		Services: []Service{
			{Names: []string{"_kerberos._udp", "_kerberos._tcp"}, Port: 88},
			{Names: []string{"_kpasswd._udp"}, Port: 464},
			{Names: []string{"_ldap._tcp"}, Port: 389},
		},
	}, st, log, metrics.New())
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	})

	return &harness{store: st, addr: srv.Addr().String()}
}

// ask sends a real query over the wire and returns the reply.
func (h *harness) ask(t *testing.T, name string, qtype uint16) *dns.Msg {
	t.Helper()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)

	reply, err := dns.Exchange(m, h.addr)
	if err != nil {
		t.Fatalf("query %s %s: %v", name, dns.TypeToString[qtype], err)
	}

	return reply
}

func (h *harness) addRecord(t *testing.T, name, recordType, value string) {
	t.Helper()

	r := &store.DNSRecord{Name: name, Type: recordType, Value: value, TTL: 3600}
	if err := h.store.CreateDNSRecord(context.Background(), r); err != nil {
		t.Fatalf("CreateDNSRecord: %v", err)
	}
}

func TestApexCarriesSOAAndNS(t *testing.T) {
	h := newHarness(t)

	reply := h.ask(t, testZone, dns.TypeSOA)
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[reply.Rcode])
	}
	if !reply.Authoritative {
		t.Error("the answer is not marked authoritative")
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("got %d answers, want the SOA", len(reply.Answer))
	}

	soa, ok := reply.Answer[0].(*dns.SOA)
	if !ok {
		t.Fatalf("answer is %T, want a SOA", reply.Answer[0])
	}
	if soa.Ns != dns.Fqdn(testHost) {
		t.Errorf("SOA name server = %q, want %q", soa.Ns, dns.Fqdn(testHost))
	}
	if soa.Mbox != "hostmaster.example.com." {
		t.Errorf("SOA mailbox = %q", soa.Mbox)
	}

	ns := h.ask(t, testZone, dns.TypeNS)
	if len(ns.Answer) != 1 {
		t.Fatalf("got %d NS answers, want 1", len(ns.Answer))
	}
}

func TestServiceDiscoveryRecords(t *testing.T) {
	h := newHarness(t)

	// These are what let a client find the KDC with nothing in krb5.conf but the realm name.
	for _, tc := range []struct {
		name string
		port uint16
	}{
		{"_kerberos._udp." + testZone, 88},
		{"_kerberos._tcp." + testZone, 88},
		{"_kpasswd._udp." + testZone, 464},
		{"_ldap._tcp." + testZone, 389},
	} {
		reply := h.ask(t, tc.name, dns.TypeSRV)
		if reply.Rcode != dns.RcodeSuccess {
			t.Errorf("%s: rcode = %s", tc.name, dns.RcodeToString[reply.Rcode])

			continue
		}
		if len(reply.Answer) != 1 {
			t.Errorf("%s: got %d answers, want 1", tc.name, len(reply.Answer))

			continue
		}

		srv, ok := reply.Answer[0].(*dns.SRV)
		if !ok {
			t.Errorf("%s: answer is %T", tc.name, reply.Answer[0])

			continue
		}
		if srv.Port != tc.port {
			t.Errorf("%s: port = %d, want %d", tc.name, srv.Port, tc.port)
		}
		if srv.Target != dns.Fqdn(testHost) {
			t.Errorf("%s: target = %q, want %q", tc.name, srv.Target, dns.Fqdn(testHost))
		}
	}

	// RFC 4120 section 7.2.3: the realm of a domain is discoverable from this record.
	txt := h.ask(t, "_kerberos."+testZone, dns.TypeTXT)
	if len(txt.Answer) != 1 {
		t.Fatalf("got %d TXT answers, want 1", len(txt.Answer))
	}
	if got := txt.Answer[0].(*dns.TXT).Txt; len(got) != 1 || got[0] != testRealm {
		t.Errorf("realm TXT = %v, want %s", got, testRealm)
	}
}

func TestServerHostResolvesToItsConfiguredAddress(t *testing.T) {
	h := newHarness(t)

	reply := h.ask(t, testHost, dns.TypeA)
	if len(reply.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(reply.Answer))
	}
	if got := reply.Answer[0].(*dns.A).A.String(); got != testAddr {
		t.Errorf("address = %s, want %s", got, testAddr)
	}
}

func TestReverseIsDerivedFromTheAddressRecords(t *testing.T) {
	h := newHarness(t)

	h.addRecord(t, "www.example.com", "A", "192.0.2.20")

	// This is the point of serving DNS at all: a Kerberos client that canonicalises a
	// host-based service name through reverse DNS must get back the name the realm uses, or it
	// asks the KDC for a principal nobody registered.
	reply := h.ask(t, "20.2.0.192.in-addr.arpa", dns.TypePTR)
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[reply.Rcode])
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(reply.Answer))
	}
	if got := reply.Answer[0].(*dns.PTR).Ptr; got != "www.example.com." {
		t.Errorf("PTR = %q, want www.example.com.", got)
	}

	// The server's own address answers too, though it comes from configuration rather than a
	// record; otherwise the host running the KDC is the one host without a reverse answer.
	own := h.ask(t, "10.2.0.192.in-addr.arpa", dns.TypePTR)
	if len(own.Answer) != 1 {
		t.Fatalf("got %d answers for the server's own address, want 1", len(own.Answer))
	}
	if got := own.Answer[0].(*dns.PTR).Ptr; got != dns.Fqdn(testHost) {
		t.Errorf("PTR = %q, want %q", got, dns.Fqdn(testHost))
	}

	// Deleting the address record takes the reverse answer with it, because there is only one
	// copy of the fact.
	records, err := h.store.LookupDNSRecords(context.Background(), "www.example.com")
	if err != nil || len(records) != 1 {
		t.Fatalf("LookupDNSRecords: %v (%d records)", err, len(records))
	}
	if err := h.store.DeleteDNSRecord(context.Background(), records[0].ID); err != nil {
		t.Fatalf("DeleteDNSRecord: %v", err)
	}

	if gone := h.ask(t, "20.2.0.192.in-addr.arpa", dns.TypePTR); gone.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN once the address record is gone",
			dns.RcodeToString[gone.Rcode])
	}
}

func TestMissingNameAndMissingTypeAreDifferent(t *testing.T) {
	h := newHarness(t)

	h.addRecord(t, "www.example.com", "A", "192.0.2.20")

	// A name that exists without the type asked for is an empty answer with the zone's SOA;
	// a name that does not exist at all is NXDOMAIN. Resolvers cache the two differently.
	nodata := h.ask(t, "www.example.com", dns.TypeMX)
	if nodata.Rcode != dns.RcodeSuccess {
		t.Errorf("existing name, absent type: rcode = %s, want NOERROR",
			dns.RcodeToString[nodata.Rcode])
	}
	if len(nodata.Answer) != 0 {
		t.Errorf("existing name, absent type: got %d answers, want none", len(nodata.Answer))
	}
	if len(nodata.Ns) != 1 {
		t.Error("existing name, absent type: the SOA is missing from the authority section")
	}

	missing := h.ask(t, "nowhere.example.com", dns.TypeA)
	if missing.Rcode != dns.RcodeNameError {
		t.Errorf("absent name: rcode = %s, want NXDOMAIN", dns.RcodeToString[missing.Rcode])
	}
	if len(missing.Ns) != 1 {
		t.Error("absent name: the SOA is missing from the authority section")
	}
}

func TestNamesOutsideTheZoneAreRefused(t *testing.T) {
	h := newHarness(t)

	// An identity service that resolved arbitrary names would be an open resolver.
	reply := h.ask(t, "www.google.com", dns.TypeA)
	if reply.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[reply.Rcode])
	}
	if reply.RecursionAvailable {
		t.Error("the server advertises recursion")
	}
}

func TestStoredRecordOverridesTheGeneratedOne(t *testing.T) {
	h := newHarness(t)

	// An operator who writes an address for this host means it, even though the configuration
	// also carries one.
	h.addRecord(t, testHost, "A", "192.0.2.99")

	reply := h.ask(t, testHost, dns.TypeA)
	if len(reply.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(reply.Answer))
	}
	if got := reply.Answer[0].(*dns.A).A.String(); got != "192.0.2.99" {
		t.Errorf("address = %s, want the stored 192.0.2.99", got)
	}

	// The generated records of other types at that name survive.
	if soa := h.ask(t, testZone, dns.TypeSOA); len(soa.Answer) != 1 {
		t.Error("the apex lost its SOA")
	}
}

func TestCNAMEAnswersForAnyType(t *testing.T) {
	h := newHarness(t)

	h.addRecord(t, "alias.example.com", "CNAME", "www.example.com.")

	reply := h.ask(t, "alias.example.com", dns.TypeA)
	if len(reply.Answer) != 1 {
		t.Fatalf("got %d answers, want the CNAME", len(reply.Answer))
	}
	if _, ok := reply.Answer[0].(*dns.CNAME); !ok {
		t.Errorf("answer is %T, want a CNAME", reply.Answer[0])
	}
}

func TestReverseNameParsing(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
		ok   bool
	}{
		{"10.2.0.192.in-addr.arpa", "192.0.2.10", true},
		{"1.0.0.127.in-addr.arpa", "127.0.0.1", true},
		{
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
			"2001:db8::1", true,
		},
		{"192.0.2.10", "", false},
		{"1.2.3.in-addr.arpa", "", false},
		{"z.2.0.192.in-addr.arpa", "", false},
	} {
		got, ok := addrFromARPA(tc.name)
		if ok != tc.ok {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.ok)

			continue
		}
		if !tc.ok {
			continue
		}
		if got != netip.MustParseAddr(tc.want) {
			t.Errorf("%s = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestRecordValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record store.DNSRecord
		valid  bool
	}{
		{"good A", store.DNSRecord{Name: "a.example.com", Type: "A", Value: "192.0.2.1", TTL: 60}, true},
		{"good SRV", store.DNSRecord{Name: "_x._tcp.example.com", Type: "SRV", Value: "0 100 88 kdc.example.com.", TTL: 60}, true},
		{"bad address", store.DNSRecord{Name: "a.example.com", Type: "A", Value: "not-an-ip", TTL: 60}, false},
		{"unknown type", store.DNSRecord{Name: "a.example.com", Type: "NOPE", Value: "x", TTL: 60}, false},
		{"no ttl", store.DNSRecord{Name: "a.example.com", Type: "A", Value: "192.0.2.1"}, false},
		{"no name", store.DNSRecord{Type: "A", Value: "192.0.2.1", TTL: 60}, false},
	} {
		err := ValidateRecord(tc.record)
		if tc.valid && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("%s: accepted, want a rejection", tc.name)
		}
	}
}
