// Package kdc implements the Kerberos 5 Key Distribution Centre: the AS exchange that turns a
// password into a ticket-granting ticket, and the TGS exchange that turns a TGT into service
// tickets, including protocol transition, constrained delegation and cross-realm referrals.
package kdc

import (
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// Config is everything the KDC needs that does not live in the store.
type Config struct {
	Realm       string
	DomainName  string
	NetBIOSName string
	DomainSID   string

	Listen string

	MaxTicketLife    time.Duration
	MaxRenewableLife time.Duration
	ClockSkew        time.Duration

	// EncTypes lists the session key enctypes the KDC will negotiate, most preferred first.
	EncTypes []int32

	RequirePreAuth bool
	IssuePAC       bool
	AllowS4U       bool

	UDPMaxSize int

	// Lockout bounds password guessing through the AS exchange.
	Lockout store.LockoutPolicy
}

// Server is a running KDC.
type Server struct {
	cfg     Config
	st      *store.Store
	log     zerolog.Logger
	metrics *metrics.Metrics
	replay  *replayCache

	tcp net.Listener
	udp net.PacketConn

	wg      sync.WaitGroup
	closing atomic.Bool
}

// New builds a KDC over the given store.
func New(cfg Config, st *store.Store, log zerolog.Logger, m *metrics.Metrics) (*Server, error) {
	if len(cfg.Realm) == 0 {
		return nil, errors.New("kdc: realm is required")
	}
	if len(cfg.EncTypes) == 0 {
		return nil, errors.New("kdc: at least one enctype is required")
	}
	if cfg.ClockSkew <= 0 {
		return nil, errors.New("kdc: clock skew must be positive")
	}

	return &Server{
		cfg:     cfg,
		st:      st,
		log:     log.With().Str("component", "kdc").Logger(),
		metrics: m,
		// The replay window matches the clock skew: an authenticator older than the skew is
		// rejected on its timestamp anyway, so nothing outside that window needs remembering.
		replay: newReplayCache(2 * cfg.ClockSkew),
	}, nil
}

// tgsName is the realm's own ticket-granting principal.
func (s *Server) tgsName() krbkeys.Name {
	return krbkeys.Name{Components: []string{"krbtgt", s.cfg.Realm}, Realm: s.cfg.Realm}
}

// Start binds the TCP and UDP listeners and serves until Shutdown is called.
func (s *Server) Start(ctx context.Context) error {
	var err error

	if s.tcp, err = net.Listen("tcp", s.cfg.Listen); err != nil {
		return fmt.Errorf("kdc: listening on tcp %s: %w", s.cfg.Listen, err)
	}

	// Both transports must answer on the same port. When the configured port is zero the
	// kernel picked one for TCP, so UDP has to be bound to that same address rather than to
	// another arbitrary port.
	udpAddr := s.cfg.Listen
	if _, port, err := net.SplitHostPort(s.cfg.Listen); err == nil && port == "0" {
		udpAddr = s.tcp.Addr().String()
	}

	if s.udp, err = net.ListenPacket("udp", udpAddr); err != nil {
		_ = s.tcp.Close()

		return fmt.Errorf("kdc: listening on udp %s: %w", udpAddr, err)
	}

	s.log.Info().Str("address", s.cfg.Listen).Str("realm", s.cfg.Realm).Msg("KDC listening")

	s.wg.Add(2)
	go s.serveTCP(ctx)
	go s.serveUDP(ctx)

	return nil
}

// Shutdown stops the listeners and waits for in-flight requests to finish.
func (s *Server) Shutdown(ctx context.Context) error {
	if !s.closing.CompareAndSwap(false, true) {
		return nil
	}

	if s.tcp != nil {
		_ = s.tcp.Close()
	}
	if s.udp != nil {
		_ = s.udp.Close()
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

// Addr reports the bound TCP address, which is useful when the configured port was zero.
func (s *Server) Addr() net.Addr {
	if s.tcp == nil {
		return nil
	}

	return s.tcp.Addr()
}

func (s *Server) serveTCP(ctx context.Context) {
	defer s.wg.Done()

	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			if s.closing.Load() {
				return
			}
			s.log.Error().Err(err).Msg("accept failed")

			continue
		}

		s.wg.Go(func() {
			s.handleTCPConn(ctx, conn)
		})
	}
}

// handleTCPConn serves one request per connection, which is what RFC 4120 section 7.2.2 describes
// and what every client does in practice.
func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		if !errors.Is(err, io.EOF) {
			s.log.Debug().Err(err).Str("from", conn.RemoteAddr().String()).Msg("short TCP request")
		}

		return
	}

	// The top bit is reserved by RFC 4120 for a future extension and must be masked off before
	// the value is read as a length; treating it as part of the length would let a peer ask for
	// a 2 GiB allocation.
	size := binary.BigEndian.Uint32(lenBuf[:]) &^ 0x80000000

	const maxRequest = 1 << 20
	if size == 0 || size > maxRequest {
		s.log.Debug().Uint32("size", size).Str("from", conn.RemoteAddr().String()).Msg("rejecting oversized TCP request")

		return
	}

	req := make([]byte, size)
	if _, err := io.ReadFull(conn, req); err != nil {
		s.log.Debug().Err(err).Str("from", conn.RemoteAddr().String()).Msg("truncated TCP request")

		return
	}

	reply := s.Handle(ctx, req, conn.RemoteAddr())
	if len(reply) == 0 {
		return
	}

	out := make([]byte, 4+len(reply))
	binary.BigEndian.PutUint32(out[:4], uint32(len(reply)))
	copy(out[4:], reply)

	if _, err := conn.Write(out); err != nil {
		s.log.Debug().Err(err).Str("to", conn.RemoteAddr().String()).Msg("could not write TCP reply")
	}
}

func (s *Server) serveUDP(ctx context.Context) {
	defer s.wg.Done()

	buf := make([]byte, 65535)

	for {
		n, addr, err := s.udp.ReadFrom(buf)
		if err != nil {
			if s.closing.Load() {
				return
			}
			s.log.Error().Err(err).Msg("UDP read failed")

			continue
		}

		req := make([]byte, n)
		copy(req, buf[:n])

		s.wg.Go(func() {

			reply := s.Handle(ctx, req, addr)
			if len(reply) == 0 {
				return
			}

			// A reply that will not fit in a datagram must not be truncated: the client is
			// told to retry over TCP, which is what RFC 4120 section 7.2.1 prescribes.
			if len(reply) > s.cfg.UDPMaxSize {
				perr := krbErr(errorcode.KRB_ERR_RESPONSE_TOO_BIG,
					"response of %d bytes exceeds the UDP limit, retry over TCP", len(reply))
				reply = s.errorReply(perr, s.tgsName().PrincipalName(), s.cfg.Realm)
			}

			if _, err := s.udp.WriteTo(reply, addr); err != nil {
				s.log.Debug().Err(err).Str("to", addr.String()).Msg("could not write UDP reply")
			}
		})
	}
}

// Handle processes one Kerberos request and returns the bytes to send back. It is exported so the
// exchange can be exercised without binding a socket.
func (s *Server) Handle(ctx context.Context, req []byte, from net.Addr) []byte {
	mt, err := messageType(req)
	if err != nil {
		s.log.Debug().Err(err).Str("from", addrString(from)).Msg("unparsable request")
		s.metrics.KDCRequests.WithLabelValues("unknown", "malformed").Inc()

		return s.errorReply(krbErr(errorcode.KRB_ERR_GENERIC, "could not determine message type"),
			s.tgsName().PrincipalName(), s.cfg.Realm)
	}

	switch mt {
	case msgtype.KRB_AS_REQ:
		return s.timed(ctx, "as", func(ctx context.Context) ([]byte, *protocolError) {
			return s.handleASReq(ctx, req, from)
		}, from)
	case msgtype.KRB_TGS_REQ:
		return s.timed(ctx, "tgs", func(ctx context.Context) ([]byte, *protocolError) {
			return s.handleTGSReq(ctx, req, from)
		}, from)
	default:
		s.metrics.KDCRequests.WithLabelValues("unknown", "unsupported").Inc()

		return s.errorReply(krbErr(errorcode.KRB_ERR_GENERIC, "unsupported message type %d", mt),
			s.tgsName().PrincipalName(), s.cfg.Realm)
	}
}

// timed runs an exchange handler, records its outcome and turns a protocol error into the reply.
func (s *Server) timed(
	ctx context.Context,
	exchange string,
	fn func(context.Context) ([]byte, *protocolError),
	from net.Addr,
) []byte {
	start := time.Now()

	reply, perr := fn(ctx)

	s.metrics.KDCDuration.WithLabelValues(exchange).Observe(time.Since(start).Seconds())

	if perr != nil {
		s.metrics.KDCRequests.WithLabelValues(exchange, errorcode.Lookup(perr.Code)).Inc()
		s.log.Info().
			Str("exchange", exchange).
			Str("from", addrString(from)).
			Str("error", errorcode.Lookup(perr.Code)).
			AnErr("cause", perr.Internal).
			Msg("request refused")

		return s.errorReply(perr, s.tgsName().PrincipalName(), s.cfg.Realm)
	}

	s.metrics.KDCRequests.WithLabelValues(exchange, "ok").Inc()

	return reply
}

// messageType reads the application tag that identifies a Kerberos message.
func messageType(b []byte) (int, error) {
	var raw asn1.RawValue

	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		return 0, err
	}
	if raw.Class != asn1.ClassApplication {
		return 0, errors.New("message is not an application-tagged Kerberos structure")
	}

	return raw.Tag, nil
}

func addrString(a net.Addr) string {
	if a == nil {
		return "-"
	}

	return a.String()
}
