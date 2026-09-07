package ldapsrv

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/glauth/ldap"
	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// ListenerConfig describes one of the two LDAP listeners.
type ListenerConfig struct {
	Enabled bool
	Listen  string
	// TLS holds the certificate: on the plain listener it enables StartTLS, on the secure one
	// it is the transport itself.
	TLS *tls.Config
}

// Server runs the LDAP and LDAPS listeners over a shared handler.
type Server struct {
	handler *Handler
	log     zerolog.Logger

	ldap  ListenerConfig
	ldaps ListenerConfig

	mu      sync.Mutex
	running []*runningListener
	wg      sync.WaitGroup
}

// runningListener pairs a protocol server with the address it answers on.
//
// Each listener gets its own ldap.Server because the library's Serve loop leaves only through that
// server's Quit channel, and it closes the channel on the way out. Two listeners sharing one server
// would therefore race to close the same channel, and the loser would panic on shutdown.
type runningListener struct {
	server *ldap.Server
	addr   net.Addr
	kind   string
}

// New builds the LDAP server.
func New(cfg Config, plain, secure ListenerConfig, st *store.Store, log zerolog.Logger, m *metrics.Metrics) (*Server, error) {
	if len(cfg.BaseDN) == 0 {
		return nil, errors.New("ldap: base DN is required")
	}
	if secure.Enabled && secure.TLS == nil {
		return nil, errors.New("ldap: ldaps is enabled but no certificate was configured")
	}

	return &Server{
		handler: NewHandler(cfg, st, log, m),
		log:     log.With().Str("component", "ldap").Logger(),
		ldap:    plain,
		ldaps:   secure,
	}, nil
}

// Start binds the enabled listeners and serves in the background.
func (s *Server) Start(ctx context.Context) error {
	if s.ldap.Enabled {
		ln, err := net.Listen("tcp", s.ldap.Listen)
		if err != nil {
			return fmt.Errorf("ldap: listening on %s: %w", s.ldap.Listen, err)
		}

		s.serve(ln, "LDAP", s.ldap.TLS)
	}

	if s.ldaps.Enabled {
		ln, err := tls.Listen("tcp", s.ldaps.Listen, s.ldaps.TLS)
		if err != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.Shutdown(shutdownCtx)
			cancel()

			return fmt.Errorf("ldaps: listening on %s: %w", s.ldaps.Listen, err)
		}

		// The connection is already encrypted, so StartTLS must not be offered on it.
		s.serve(ln, "LDAPS", nil)
	}

	return nil
}

// serve wires a protocol server onto one listener and starts its accept loop.
func (s *Server) serve(ln net.Listener, kind string, startTLS *tls.Config) {
	srv := ldap.NewServer()
	// Filters, scopes and attribute selection are applied by the library rather than by the
	// handler, which is what makes an ordinary ldapsearch behave as clients expect.
	srv.EnforceLDAP = true
	srv.TLSConfig = startTLS

	srv.BindFunc("", s.handler)
	srv.SearchFunc("", s.handler)
	srv.ModifyFunc("", s.handler)
	srv.DeleteFunc("", s.handler)
	srv.AddFunc("", s.handler)
	srv.CloseFunc("", s.handler)

	s.mu.Lock()
	s.running = append(s.running, &runningListener{server: srv, addr: ln.Addr(), kind: kind})
	s.mu.Unlock()

	s.log.Info().Str("address", ln.Addr().String()).Bool("starttls", startTLS != nil).
		Msgf("%s listening", kind)

	s.wg.Go(func() {

		if err := srv.Serve(ln); err != nil {
			s.log.Error().Err(err).Msgf("%s listener stopped", kind)
		}
	})
}

// Addrs reports the bound addresses, which is what a caller needs when the configured port was zero.
func (s *Server) Addrs() []net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]net.Addr, 0, len(s.running))
	for _, r := range s.running {
		out = append(out, r.addr)
	}

	return out
}

// Shutdown stops the listeners and waits for the accept loops to finish.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	running := s.running
	s.running = nil
	s.mu.Unlock()

	for _, r := range running {
		// Serve closes its own listener when it sees this, so there is nothing else to close.
		// The send is guarded because a loop that has already exited would block it forever.
		select {
		case r.server.Quit <- true:
		case <-ctx.Done():
			return ctx.Err()
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
