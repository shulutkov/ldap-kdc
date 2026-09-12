// Package dnssrv serves the realm's DNS zone authoritatively, so that Kerberos clients can find
// the KDC and, above all, so that reverse lookups answer with the names this realm actually uses.
//
// It is not a resolver. A query for anything outside the zones configured here is refused rather
// than followed, which keeps an identity service from doubling as an open resolver.
package dnssrv

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// Service is one Kerberos or directory service advertised through SRV records.
type Service struct {
	// Names are the SRV owner labels, such as "_kerberos._udp".
	Names []string
	Port  int
}

// Config describes the zone this server is authoritative for.
type Config struct {
	Listen string

	// Realm is the Kerberos realm, published in the _kerberos TXT record so a client can
	// discover it from its domain name alone.
	Realm string
	// Zone is the PRIMARY forward zone, normally the realm's domain in lower case. It is the one
	// the realm's own discovery records live in.
	Zone string
	// ExtraZones are further forward zones this server answers for, and they carry no discovery
	// records of their own — only what was put in them.
	//
	// They exist because a deployment's public names are usually not its realm's: a stand reached
	// at gitkeep.ru has a realm called STAND.LOCAL, and until something answers for the public
	// name, that name is a convention in one client's hosts file rather than a fact of the
	// deployment. Which shows up the first time a SERVICE rather than a browser has to reach it.
	ExtraZones []string
	// ReverseZones are the in-addr.arpa and ip6.arpa zones this server answers for. Without
	// one, reverse lookups fall to whatever else the network runs, and a Kerberos client that
	// canonicalises host names through reverse DNS will ask for the wrong service principal.
	ReverseZones []string

	// Hostname is this server's fully qualified name. It is the zone's name server, the target
	// of every SRV record, and the name the configured addresses resolve to.
	Hostname  string
	Addresses []string

	// Mailbox is the zone contact, written into the SOA. An address form is accepted and
	// converted to the dotted form the SOA record uses.
	Mailbox string

	TTL time.Duration

	// Services are advertised as SRV records under the zone.
	Services []Service
}

// normalize fills in what can be derived and puts names in their canonical form.
func (c *Config) normalize() error {
	c.Realm = strings.ToUpper(strings.TrimSpace(c.Realm))
	c.Zone = store.NormalizeDNSName(c.Zone)
	c.Hostname = store.NormalizeDNSName(c.Hostname)

	if len(c.Zone) == 0 {
		return fmt.Errorf("dns: zone is required")
	}
	if len(c.Hostname) == 0 {
		return fmt.Errorf("dns: hostname is required")
	}
	if c.TTL <= 0 {
		c.TTL = time.Hour
	}

	if len(c.Mailbox) == 0 {
		c.Mailbox = "hostmaster@" + c.Zone
	}

	for i, z := range c.ReverseZones {
		c.ReverseZones[i] = store.NormalizeDNSName(z)
	}

	for _, a := range c.Addresses {
		if _, err := netip.ParseAddr(a); err != nil {
			return fmt.Errorf("dns: address %q: %w", a, err)
		}
	}

	return nil
}

// soaMailbox renders the contact address in the form a SOA record carries: the "@" becomes a dot,
// and any dot in the local part is escaped.
func soaMailbox(mailbox string) string {
	local, domain, found := strings.Cut(mailbox, "@")
	if !found {
		return dns.Fqdn(mailbox)
	}

	return dns.Fqdn(strings.ReplaceAll(local, ".", `\.`) + "." + domain)
}

// generated returns the records this server maintains itself, at the given name: the zone apex,
// the server's own addresses and the service discovery records.
//
// They are computed rather than stored, so they cannot fall out of step with the configuration
// they describe, and an operator cannot half-delete the realm's own discovery records.
func (s *Server) generated(name string) []dns.RR {
	var out []dns.RR

	zone := dns.Fqdn(s.cfg.Zone)
	host := dns.Fqdn(s.cfg.Hostname)
	ttl := uint32(s.cfg.TTL / time.Second)

	switch {
	case name == s.cfg.Zone:
		out = append(out, s.soa(s.cfg.Zone), &dns.NS{
			Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
			Ns:  host,
		})

	// An extra zone gets an apex too — a zone without one is not a zone, and a resolver asking for
	// its SOA is entitled to an answer — but nothing else: the discovery records belong to the
	// realm, and publishing them under a second name would advertise a second realm.
	case slices.Contains(s.cfg.ExtraZones, name):
		out = append(out, s.soa(name), &dns.NS{
			Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
			Ns:  host,
		})

	case name == s.cfg.Hostname:
		for _, a := range s.cfg.Addresses {
			addr, err := netip.ParseAddr(a)
			if err != nil {
				continue
			}

			hdr := dns.RR_Header{Name: host, Class: dns.ClassINET, Ttl: ttl}

			if addr.Is4() {
				hdr.Rrtype = dns.TypeA
				out = append(out, &dns.A{Hdr: hdr, A: addr.AsSlice()})
			} else {
				hdr.Rrtype = dns.TypeAAAA
				out = append(out, &dns.AAAA{Hdr: hdr, AAAA: addr.AsSlice()})
			}
		}

	case name == "_kerberos."+s.cfg.Zone:
		// RFC 4120 section 7.2.3: a client that knows only its domain finds the realm here.
		out = append(out, &dns.TXT{
			Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{s.cfg.Realm},
		})
	}

	for _, svc := range s.cfg.Services {
		if svc.Port <= 0 {
			continue
		}

		for _, label := range svc.Names {
			if name != label+"."+s.cfg.Zone {
				continue
			}

			out = append(out, &dns.SRV{
				Hdr: dns.RR_Header{
					Name: dns.Fqdn(name), Rrtype: dns.TypeSRV,
					Class: dns.ClassINET, Ttl: ttl,
				},
				Priority: 0,
				Weight:   100,
				Port:     uint16(svc.Port),
				Target:   host,
			})
		}
	}

	return out
}

// soa builds the zone's start of authority. The serial follows the newest record change, so a
// secondary comparing serials sees the zone move when its contents do.
func (s *Server) soa(zone string) *dns.SOA {
	ttl := uint32(s.cfg.TTL / time.Second)

	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA,
			Class: dns.ClassINET, Ttl: ttl,
		},
		Ns:      dns.Fqdn(s.cfg.Hostname),
		Mbox:    soaMailbox(s.cfg.Mailbox),
		Serial:  s.serial(),
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  ttl,
	}
}

// stored turns the records held for a name into resource records. A value that does not parse is
// dropped with a warning rather than failing the whole answer: one bad row should cost one record.
func (s *Server) stored(ctx context.Context, name string) []dns.RR {
	records, err := s.st.LookupDNSRecords(ctx, name)
	if err != nil {
		s.log.Error().Err(err).Str("name", name).Msg("could not read records")

		return nil
	}

	out := make([]dns.RR, 0, len(records))

	for _, r := range records {
		text := fmt.Sprintf("%s %d IN %s %s", dns.Fqdn(r.Name), r.TTL, r.Type, r.Value)

		rr, err := dns.NewRR(text)
		if err != nil || rr == nil {
			s.log.Warn().Err(err).Str("record", text).Msg("skipping a record that does not parse")

			continue
		}

		out = append(out, rr)
	}

	return out
}

// records returns everything this server has at a name, generated and stored together. A stored
// record wins over a generated one of the same type, so an operator can override the addresses
// configured for this host without editing the configuration file.
func (s *Server) records(ctx context.Context, name string) []dns.RR {
	stored := s.stored(ctx, name)

	types := make(map[uint16]bool, len(stored))
	for _, rr := range stored {
		types[rr.Header().Rrtype] = true
	}

	out := stored

	for _, rr := range s.generated(name) {
		if !types[rr.Header().Rrtype] {
			out = append(out, rr)
		}
	}

	return out
}

// reverseNames answers a reverse query by finding the names whose address records hold the address
// the query asks about.
func (s *Server) reverseNames(ctx context.Context, qname string) []dns.RR {
	addr, ok := addrFromARPA(qname)
	if !ok {
		return nil
	}

	ttl := uint32(s.cfg.TTL / time.Second)

	var out []dns.RR

	// The server's own addresses come from configuration rather than from a record, so they
	// are matched here too; otherwise the host running the KDC would be the one host in the
	// realm without a reverse answer.
	for _, a := range s.cfg.Addresses {
		if parsed, err := netip.ParseAddr(a); err == nil && parsed == addr {
			out = append(out, &dns.PTR{
				Hdr: dns.RR_Header{
					Name: dns.Fqdn(qname), Rrtype: dns.TypePTR,
					Class: dns.ClassINET, Ttl: ttl,
				},
				Ptr: dns.Fqdn(s.cfg.Hostname),
			})
		}
	}

	names, err := s.st.LookupDNSAddressNames(ctx, addr)
	if err != nil {
		s.log.Error().Err(err).Str("name", qname).Msg("could not read address records")

		return out
	}

	for _, n := range names {
		if dns.Fqdn(n) == dns.Fqdn(s.cfg.Hostname) && len(out) > 0 {
			continue
		}

		out = append(out, &dns.PTR{
			Hdr: dns.RR_Header{
				Name: dns.Fqdn(qname), Rrtype: dns.TypePTR,
				Class: dns.ClassINET, Ttl: ttl,
			},
			Ptr: dns.Fqdn(n),
		})
	}

	return out
}

// addrFromARPA turns a reverse lookup name back into the address it asks about.
func addrFromARPA(name string) (netip.Addr, bool) {
	name = store.NormalizeDNSName(name)

	if rest, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		labels := strings.Split(rest, ".")
		if len(labels) != 4 {
			return netip.Addr{}, false
		}

		// The labels run least significant first, so the address is their reverse.
		octets := make([]string, 4)
		for i, l := range labels {
			octets[3-i] = l
		}

		addr, err := netip.ParseAddr(strings.Join(octets, "."))

		return addr, err == nil && addr.Is4()
	}

	rest, ok := strings.CutSuffix(name, ".ip6.arpa")
	if !ok {
		return netip.Addr{}, false
	}

	labels := strings.Split(rest, ".")
	if len(labels) != 32 {
		return netip.Addr{}, false
	}

	var sb strings.Builder

	for i := len(labels) - 1; i >= 0; i-- {
		if len(labels[i]) != 1 {
			return netip.Addr{}, false
		}
		if _, err := strconv.ParseUint(labels[i], 16, 8); err != nil {
			return netip.Addr{}, false
		}

		sb.WriteString(labels[i])

		if i%4 == 0 && i > 0 {
			sb.WriteByte(':')
		}
	}

	addr, err := netip.ParseAddr(sb.String())

	return addr, err == nil && addr.Is6()
}

// ValidateRecord checks that a record would actually be servable, by building it exactly as the
// server will. Rejecting a malformed value here means an operator learns about it while making the
// change, rather than through a record that quietly never answers.
func ValidateRecord(r store.DNSRecord) error {
	name := store.NormalizeDNSName(r.Name)
	if len(name) == 0 {
		return fmt.Errorf("record name is required")
	}
	if r.TTL <= 0 {
		return fmt.Errorf("record ttl must be positive")
	}

	recordType := strings.ToUpper(strings.TrimSpace(r.Type))
	if _, ok := dns.StringToType[recordType]; !ok {
		return fmt.Errorf("unknown record type %q", r.Type)
	}

	text := fmt.Sprintf("%s %d IN %s %s", dns.Fqdn(name), r.TTL, recordType, strings.TrimSpace(r.Value))

	rr, err := dns.NewRR(text)
	if err != nil {
		return fmt.Errorf("%s record %q: %w", recordType, r.Value, err)
	}
	if rr == nil {
		return fmt.Errorf("%s record %q is empty", recordType, r.Value)
	}

	return nil
}

// InZone reports whether a name belongs to one of the zones given.
func InZone(name string, zones []string) bool {
	name = store.NormalizeDNSName(name)

	for _, z := range zones {
		if inZone(name, store.NormalizeDNSName(z)) {
			return true
		}
	}

	return false
}
