// Package vaultpki enrolls the LDAPS listener's certificate with a Vault-compatible PKI
// (Vault or OpenBao). The service logs in to Vault over Kerberos — against its own KDC —
// and asks the PKI to sign a freshly generated key's CSR. The integration is configured at
// run time through the management API, not the configuration file.
package vaultpki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// The defaults a configuration field takes when the management request leaves it out.
const (
	defaultPKIPath       = "pki"
	defaultRole          = "ldaps"
	defaultTTL           = 720 * time.Hour
	defaultRenewBefore   = 24 * time.Hour
	defaultRetryInterval = 5 * time.Second
)

// minRenewDelay keeps a certificate that is already inside its renewal window from spinning
// the enrollment loop: the renewal is retried at this interval rather than in a tight loop.
const minRenewDelay = 10 * time.Second

// Config is the integration as the management API last set it.
type Config struct {
	// Address is the Vault base URL, e.g. "https://vault.example.com:8200".
	Address string
	// Plaintext allows an http:// address. Off by default: the SPNEGO token and the Vault token
	// the login returns both cross the wire in headers, and over plain HTTP anyone on the path
	// can take them. It exists for test rigs whose Vault has no listener certificate.
	Plaintext bool
	// Principal is the principal in this realm the Vault login authenticates as.
	Principal string
	// ServicePrincipal is the principal Vault's kerberos auth expects a ticket for.
	// Empty means "HTTP/<host of Address>".
	ServicePrincipal string
	// PKIPath is the mount of the PKI secrets engine.
	PKIPath string
	// Role is the PKI role the CSR is signed under.
	Role string
	// CommonName is the certificate's subject CN; DNSNames and IPs are its SANs.
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	// TTL is the lifetime asked of the PKI; the issuer may shorten it.
	TTL time.Duration
	// RenewBefore is how long before expiry the certificate is replaced.
	RenewBefore time.Duration
	// RetryInterval is how long a failed enrollment waits before trying again.
	RetryInterval time.Duration
}

// defaults fills the fields a configuration may leave out and normalizes the address.
func (c *Config) defaults() {
	for len(c.Address) > 0 && c.Address[len(c.Address)-1] == '/' {
		c.Address = c.Address[:len(c.Address)-1]
	}
	if len(c.PKIPath) == 0 {
		c.PKIPath = defaultPKIPath
	}
	if len(c.Role) == 0 {
		c.Role = defaultRole
	}
	if c.TTL <= 0 {
		c.TTL = defaultTTL
	}
	if c.RenewBefore <= 0 {
		c.RenewBefore = defaultRenewBefore
	}
	if c.RetryInterval <= 0 {
		c.RetryInterval = defaultRetryInterval
	}
}

// KDC says where this service's own KDC answers, which is where the Vault login's AS and
// TGS requests go.
type KDC struct {
	Realm string
	// Addr is a host:port the Kerberos client library can dial, typically 127.0.0.1 and the
	// KDC's listen port.
	Addr string
}

// TokenSource produces the SPNEGO token Vault's kerberos login expects in the Negotiate
// header. It is a field rather than a fixed call so tests can enroll without a KDC.
type TokenSource func(ctx context.Context, cfg Config) ([]byte, error)

// Status is a point-in-time report of the enrollment loop.
type Status struct {
	Configured bool
	Enrolled   bool
	NotAfter   time.Time
	LastError  string
	Attempts   int
}

// ErrNoCertificate is what CertHolder answers a TLS handshake with before the first
// enrollment has delivered a certificate.
var ErrNoCertificate = errors.New("no certificate yet")

// CertHolder holds the certificate the LDAPS listener currently serves. The listener reads
// it through GetCertificate on every handshake, so a renewal needs no listener restart.
type CertHolder struct {
	cert atomic.Pointer[tls.Certificate]
}

// Set installs the certificate handshakes serve from now on.
func (h *CertHolder) Set(cert *tls.Certificate) {
	h.cert.Store(cert)
}

// GetCertificate is a tls.Config.GetCertificate callback.
func (h *CertHolder) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := h.cert.Load()
	if cert == nil {
		return nil, ErrNoCertificate
	}

	return cert, nil
}

// Manager runs the enrollment loop: log in to Vault over Kerberos, have a key's CSR signed,
// hand the certificate to the holder, and do it again before it expires.
type Manager struct {
	st     *store.Store
	kdc    KDC
	holder *CertHolder
	log    zerolog.Logger

	// parent is the process's shutdown context; every enrollment loop's context derives
	// from it, so a loop never outlives the process.
	parent context.Context

	tokenSource TokenSource
	httpClient  *http.Client

	// lifecycle serializes Configure and Stop. Each stops the running loop before it starts or
	// records anything, so two management requests arriving together cannot each start a loop
	// and leave one of them running with nothing able to cancel it.
	lifecycle sync.Mutex

	mu       sync.Mutex
	cfg      *Config
	cancel   context.CancelFunc
	done     chan struct{}
	enrolled bool
	notAfter time.Time
	lastErr  string
	attempts int
}

// Option adjusts a Manager, for tests that enroll without Kerberos or against a TLS test
// server.
type Option func(*Manager)

// WithTokenSource replaces the Kerberos SPNEGO token source.
func WithTokenSource(ts TokenSource) Option {
	return func(m *Manager) { m.tokenSource = ts }
}

// WithHTTPClient replaces the HTTP client Vault is talked to with.
func WithHTTPClient(cl *http.Client) Option {
	return func(m *Manager) { m.httpClient = cl }
}

// NewManager builds the enrollment manager. It is inert until Configure is called, which is
// what the management API does when the integration is set up.
func NewManager(parent context.Context, st *store.Store, kdc KDC, holder *CertHolder, log zerolog.Logger, opts ...Option) *Manager {
	m := &Manager{
		st:     st,
		kdc:    kdc,
		holder: holder,
		log:    log.With().Str("component", "vaultpki").Logger(),
		parent: parent,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	m.tokenSource = m.kerberosToken

	for _, o := range opts {
		o(m)
	}

	return m
}

// Configure installs a configuration and (re)starts the enrollment loop. A loop already
// running for a previous configuration is stopped first.
func (m *Manager) Configure(cfg Config) {
	cfg.defaults()

	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()

	m.stopLoop()

	m.mu.Lock()
	m.cfg = &cfg
	m.enrolled = false
	m.lastErr = ""

	ctx, cancel := context.WithCancel(m.parent)
	m.cancel = cancel
	m.done = make(chan struct{})
	done := m.done
	m.mu.Unlock()

	m.log.Info().Str("address", cfg.Address).Str("principal", cfg.Principal).
		Str("role", cfg.PKIPath+"/"+cfg.Role).Msg("vault pki enrollment configured")

	go m.run(ctx, cfg, done)
}

// Stop ends the enrollment loop and forgets the configuration. The certificate already in
// the holder keeps being served; there is no reason a reconfiguration should break the
// connections the last certificate still answers.
func (m *Manager) Stop() {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()

	m.stopLoop()

	// What was enrolled belongs to the configuration just forgotten, so the status forgets it
	// too; the attempt count is history and stays.
	m.mu.Lock()
	m.cfg = nil
	m.enrolled = false
	m.notAfter = time.Time{}
	m.lastErr = ""
	m.mu.Unlock()
}

// stopLoop cancels the running loop, if any, and waits for it to leave.
func (m *Manager) stopLoop() {
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	m.cancel, m.done = nil, nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
		<-done
	}
}

// Status reports the loop's state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()

	return Status{
		Configured: m.cfg != nil,
		Enrolled:   m.enrolled,
		NotAfter:   m.notAfter,
		LastError:  m.lastErr,
		Attempts:   m.attempts,
	}
}

// run is the enrollment loop: enroll, then sleep until renewal is due — or until the retry
// interval has passed when the enrollment failed.
func (m *Manager) run(ctx context.Context, cfg Config, done chan struct{}) {
	defer close(done)

	for {
		cert, err := m.Enroll(ctx, cfg)

		// A canceled context means Configure or Stop is asking this loop to leave, and the
		// error is just how the in-flight request noticed.
		if err != nil && ctx.Err() != nil {
			return
		}

		var wait time.Duration

		m.mu.Lock()
		m.attempts++
		if err != nil {
			m.lastErr = err.Error()
			wait = cfg.RetryInterval
		} else {
			m.enrolled = true
			m.notAfter = cert.Leaf.NotAfter
			m.lastErr = ""
			wait = renewDelay(cert.Leaf.NotAfter, cfg.RenewBefore, time.Now())
		}
		m.mu.Unlock()

		if err != nil {
			m.log.Warn().Err(err).Msg("vault pki enrollment failed")
		} else {
			m.holder.Set(cert)
			m.log.Info().Time("notAfter", cert.Leaf.NotAfter).Dur("renewIn", wait).
				Msg("vault pki certificate enrolled")

			// The issuer may hand back less lifetime than was asked for, a role's max_ttl say.
			// The renewal then comes earlier than renew_before, which is worth an operator's
			// attention: the requested ttl is not the one in force.
			if time.Until(cert.Leaf.NotAfter) < cfg.RenewBefore {
				m.log.Warn().Time("notAfter", cert.Leaf.NotAfter).Dur("renewBefore", cfg.RenewBefore).
					Msg("vault pki issued less lifetime than renew_before; renewing earlier")
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// renewDelay is how long the loop sleeps after a successful enrollment. Normally that is until
// the renewal window opens. When the issuer gave a lifetime shorter than the window, the window
// is already open, and renewing at once would issue a certificate every few seconds for as long
// as the issuer keeps shortening it. So the renewal then comes at two thirds of the lifetime
// actually granted, which ties the rate of issuance to the lifetime rather than to a floor.
func renewDelay(notAfter time.Time, renewBefore time.Duration, now time.Time) time.Duration {
	remaining := notAfter.Sub(now)

	if d := remaining - renewBefore; d >= minRenewDelay {
		return d
	}
	if d := remaining * 2 / 3; d >= minRenewDelay {
		return d
	}

	return minRenewDelay
}

// CheckAddress insists on an http(s) URL with a host, and on https unless the configuration
// allows plaintext.
func CheckAddress(cfg Config) error {
	u, err := url.Parse(cfg.Address)
	if err != nil || len(u.Host) == 0 {
		return fmt.Errorf("address %q is not a URL with a host", cfg.Address)
	}

	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && cfg.Plaintext:
		return nil
	case u.Scheme == "http":
		return fmt.Errorf("address %q is plain http; set plaintext to allow it", cfg.Address)
	default:
		return fmt.Errorf("address %q must be an https URL", cfg.Address)
	}
}

// loginToken gets the SPNEGO token from the token source and gives up when ctx does. The
// Kerberos client takes no context of its own, so a KDC that does not answer would otherwise
// hold the loop, and with it a management request waiting for the loop to leave, indefinitely.
// The abandoned call finishes by itself, when the client's own network timeout runs out.
func (m *Manager) loginToken(ctx context.Context, cfg Config) ([]byte, error) {
	type result struct {
		token []byte
		err   error
	}

	ch := make(chan result, 1)
	go func() {
		token, err := m.tokenSource(ctx, cfg)
		ch <- result{token, err}
	}()

	select {
	case r := <-ch:
		return r.token, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Enroll performs one enrollment: Kerberos login to Vault, a fresh key and CSR, the PKI's
// signature, and the pair ready for a TLS listener.
func (m *Manager) Enroll(ctx context.Context, cfg Config) (*tls.Certificate, error) {
	cfg.defaults()

	if err := CheckAddress(cfg); err != nil {
		return nil, err
	}

	token, err := m.loginToken(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("kerberos login token: %w", err)
	}

	vault := &vaultClient{address: cfg.Address, http: m.httpClient}

	clientToken, err := vault.loginKerberos(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("vault login: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cfg.CommonName},
		DNSNames:    cfg.DNSNames,
		IPAddresses: cfg.IPs,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	certPEM, err := vault.signCSR(ctx, clientToken, cfg.PKIPath, cfg.Role, csrPEM, cfg.CommonName, cfg.TTL)
	if err != nil {
		return nil, fmt.Errorf("vault sign: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encoding key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("the signed certificate does not pair with the key: %w", err)
	}

	if pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
		return nil, fmt.Errorf("the signed certificate does not parse: %w", err)
	}

	return &pair, nil
}
