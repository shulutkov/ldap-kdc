package dnssrv

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// Server answers authoritatively for the realm's zones.
type Server struct {
	cfg     Config
	st      *store.Store
	log     zerolog.Logger
	metrics *metrics.Metrics

	udp *dns.Server
	tcp *dns.Server

	addr net.Addr
	wg   sync.WaitGroup
}

// New builds the DNS server.
func New(cfg Config, st *store.Store, log zerolog.Logger, m *metrics.Metrics) (*Server, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}

	return &Server{
		cfg:     cfg,
		st:      st,
		log:     log.With().Str("component", "dns").Logger(),
		metrics: m,
	}, nil
}

// Start binds the UDP and TCP listeners and serves until Shutdown.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("dns: listening on tcp %s: %w", s.cfg.Listen, err)
	}

	s.addr = ln.Addr()

	// With a configured port of zero the kernel chose one for TCP, and UDP has to answer on the
	// same port or a client that retries over the other transport reaches nothing.
	udpAddr := s.cfg.Listen
	if _, port, err := net.SplitHostPort(s.cfg.Listen); err == nil && port == "0" {
		udpAddr = ln.Addr().String()
	}

	pc, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		_ = ln.Close()

		return fmt.Errorf("dns: listening on udp %s: %w", udpAddr, err)
	}

	s.tcp = &dns.Server{Listener: ln, Handler: s}
	s.udp = &dns.Server{PacketConn: pc, Handler: s}

	s.log.Info().
		Str("address", ln.Addr().String()).
		Str("zone", s.cfg.Zone).
		Strs("reverseZones", s.cfg.ReverseZones).
		Msg("DNS server listening")

	for _, srv := range []*dns.Server{s.tcp, s.udp} {
		s.wg.Add(1)

		go func() {
			defer s.wg.Done()

			if err := srv.ActivateAndServe(); err != nil {
				s.log.Debug().Err(err).Msg("listener stopped")
			}
		}()
	}

	return nil
}

// Addr reports the bound TCP address.
func (s *Server) Addr() net.Addr { return s.addr }

// Shutdown stops the listeners and waits for in-flight queries.
func (s *Server) Shutdown(ctx context.Context) error {
	for _, srv := range []*dns.Server{s.udp, s.tcp} {
		if srv == nil {
			continue
		}
		if err := srv.ShutdownContext(ctx); err != nil && !errors.Is(err, net.ErrClosed) {
			s.log.Debug().Err(err).Msg("shutdown")
		}
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// serial is the SOA serial: the time of the last record change, or the zone's configuration if it
// has never been edited.
func (s *Server) serial() uint32 {
	latest, err := s.st.LatestDNSChange(context.Background())
	if err != nil || latest.IsZero() {
		return 1
	}

	return uint32(latest.Unix())
}

// ServeDNS answers one query.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()

	reply := s.answer(context.Background(), r)

	s.metrics.DNSQueries.WithLabelValues(
		dns.TypeToString[questionType(r)], dns.RcodeToString[reply.Rcode],
	).Inc()
	s.metrics.DNSDuration.Observe(time.Since(start).Seconds())

	if err := w.WriteMsg(reply); err != nil {
		s.log.Debug().Err(err).Str("to", w.RemoteAddr().String()).Msg("could not write reply")
	}
}

// answer builds the reply for a query.
func (s *Server) answer(ctx context.Context, r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	// This server holds zones; it does not chase anything it does not hold.
	m.RecursionAvailable = false

	if r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 {
		m.Rcode = dns.RcodeNotImplemented

		return m
	}

	q := r.Question[0]
	if q.Qclass != dns.ClassINET {
		m.Rcode = dns.RcodeNotImplemented

		return m
	}

	name := store.NormalizeDNSName(q.Name)

	switch zone, reverse := s.zoneFor(name); {
	case len(zone) == 0:
		// Refusing rather than resolving is what keeps this from being an open resolver.
		m.Rcode = dns.RcodeRefused

	case reverse:
		s.answerReverse(ctx, m, name, zone, q.Qtype)

	default:
		s.answerForward(ctx, m, name, q.Qtype)
	}

	return m
}

// zoneFor finds the zone a name belongs to, and whether it is a reverse zone.
func (s *Server) zoneFor(name string) (zone string, reverse bool) {
	if inZone(name, s.cfg.Zone) {
		return s.cfg.Zone, false
	}

	for _, z := range s.cfg.ReverseZones {
		if inZone(name, z) {
			return z, true
		}
	}

	return "", false
}

func inZone(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// answerForward fills in a reply from the forward zone.
func (s *Server) answerForward(ctx context.Context, m *dns.Msg, name string, qtype uint16) {
	records := s.records(ctx, name)

	if len(records) == 0 {
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{s.soa()}

		return
	}

	m.Answer = matching(records, qtype)

	if len(m.Answer) == 0 {
		// A name that exists without the type asked for is an empty answer, not a missing
		// name, and the difference is what lets a resolver cache the right thing.
		m.Ns = []dns.RR{s.soa()}
	}
}

// answerReverse fills in a reply from a reverse zone.
func (s *Server) answerReverse(ctx context.Context, m *dns.Msg, name, zone string, qtype uint16) {
	if name == zone {
		m.Answer = matching(s.reverseApex(zone), qtype)
		if len(m.Answer) == 0 {
			m.Ns = []dns.RR{s.soa()}
		}

		return
	}

	records := s.reverseNames(ctx, name)

	if len(records) == 0 {
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{s.soa()}

		return
	}

	m.Answer = matching(records, qtype)

	if len(m.Answer) == 0 {
		m.Ns = []dns.RR{s.soa()}
	}
}

// reverseApex is the authority data at the top of a reverse zone.
func (s *Server) reverseApex(zone string) []dns.RR {
	soa := s.soa()
	soa.Hdr.Name = dns.Fqdn(zone)

	return []dns.RR{soa, &dns.NS{
		Hdr: dns.RR_Header{
			Name: dns.Fqdn(zone), Rrtype: dns.TypeNS,
			Class: dns.ClassINET, Ttl: uint32(s.cfg.TTL / time.Second),
		},
		Ns: dns.Fqdn(s.cfg.Hostname),
	}}
}

// matching selects the records a question asks for. A CNAME answers for any type, which is what
// lets an alias stand in for the name a client actually wanted.
func matching(records []dns.RR, qtype uint16) []dns.RR {
	var out []dns.RR

	for _, rr := range records {
		t := rr.Header().Rrtype

		if qtype == dns.TypeANY || t == qtype || (t == dns.TypeCNAME && qtype != dns.TypeCNAME) {
			out = append(out, rr)
		}
	}

	return out
}

// questionType reports the type asked about, for metrics.
func questionType(r *dns.Msg) uint16 {
	if len(r.Question) == 0 {
		return 0
	}

	return r.Question[0].Qtype
}
