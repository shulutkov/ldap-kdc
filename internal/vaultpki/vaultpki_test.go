package vaultpki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// fakeVault is a test double of a Vault server: it takes any Negotiate token for a client
// token, and signs whatever CSR it is sent with a throwaway CA.
type fakeVault struct {
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
	caPEM string

	// seen records what the enrollment sent, for the assertions.
	negotiate atomic.Value // string
	xToken    atomic.Value // string
	signTTL   atomic.Value // string

	loginStatus int
	signStatus  int

	// lifetime is how long the issued certificates last; zero means 72 hours. A PKI whose role
	// caps the lifetime is what a short one stands for.
	lifetime time.Duration
	// signs counts the CSRs the fake signed.
	signs atomic.Int32

	srv *httptest.Server
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA: %v", err)
	}

	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA: %v", err)
	}

	v := &fakeVault{
		ca:    ca,
		key:   key,
		caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/kerberos/login", v.handleLogin)
	mux.HandleFunc("POST /v1/pki/sign/ldaps", v.handleSign)
	v.srv = httptest.NewTLSServer(mux)
	t.Cleanup(v.srv.Close)

	return v
}

func (v *fakeVault) handleLogin(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Negotiate ") {
		v.writeErrors(w, http.StatusBadRequest, "no negotiate header")

		return
	}
	v.negotiate.Store(auth)

	if v.loginStatus != 0 {
		v.writeErrors(w, v.loginStatus, "kerberos auth failed")

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"auth": map[string]any{"client_token": "test-client-token"},
	})
}

func (v *fakeVault) handleSign(w http.ResponseWriter, r *http.Request) {
	v.signs.Add(1)
	v.xToken.Store(r.Header.Get("X-Vault-Token"))

	if v.signStatus != 0 {
		v.writeErrors(w, v.signStatus, "role not allowed")

		return
	}

	if r.Header.Get("X-Vault-Token") != "test-client-token" {
		v.writeErrors(w, http.StatusForbidden, "bad token")

		return
	}

	var body struct {
		CSR        string `json:"csr"`
		CommonName string `json:"common_name"`
		TTL        string `json:"ttl"`
	}
	raw, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(raw, &body); err != nil {
		v.writeErrors(w, http.StatusBadRequest, "bad body")

		return
	}
	v.signTTL.Store(body.TTL)

	block, _ := pem.Decode([]byte(body.CSR))
	if block == nil {
		v.writeErrors(w, http.StatusBadRequest, "bad csr")

		return
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		v.writeErrors(w, http.StatusBadRequest, "bad csr signature")

		return
	}

	life := v.lifetime
	if life == 0 {
		life = 72 * time.Hour
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(life),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, v.ca, csr.PublicKey, v.key)
	if err != nil {
		v.writeErrors(w, http.StatusInternalServerError, "signing failed")

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{
			"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			"issuing_ca":  v.caPEM,
		},
	})
}

func (v *fakeVault) writeErrors(w http.ResponseWriter, status int, msgs ...string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": msgs})
}

// testManager builds a Manager whose Kerberos login is replaced by a stub, so enrollment
// runs against the fake Vault alone, over the TLS the fake Vault serves.
func testManager(t *testing.T, vault *fakeVault, tokenSeen *atomic.Value) *Manager {
	t.Helper()

	return NewManager(context.Background(), nil, KDC{}, &CertHolder{}, zerolog.New(io.Discard),
		WithHTTPClient(vault.srv.Client()),
		WithTokenSource(func(_ context.Context, cfg Config) ([]byte, error) {
			if tokenSeen != nil {
				tokenSeen.Store(cfg.Principal)
			}

			return []byte("spnego-token"), nil
		}))
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %s", what)
}

func TestEnroll(t *testing.T) {
	vault := newFakeVault(t)

	var tokenSeen atomic.Value
	m := testManager(t, vault, &tokenSeen)

	cert, err := m.Enroll(context.Background(), Config{
		Address:    vault.srv.URL + "/",
		Principal:  "svc-vault",
		PKIPath:    "pki",
		Role:       "ldaps",
		CommonName: "kdc.example.com",
		DNSNames:   []string{"kdc.example.com", "ldap.example.com"},
		IPs:        []net.IP{net.ParseIP("192.0.2.10")},
		TTL:        720 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// The address went out without its trailing slash, the token source was given the
	// principal, and the negotiate header and the vault token both crossed.
	if tokenSeen.Load() != "svc-vault" {
		t.Errorf("token source principal = %v", tokenSeen.Load())
	}
	if auth, _ := vault.negotiate.Load().(string); !strings.HasPrefix(auth, "Negotiate ") {
		t.Errorf("negotiate header = %q", auth)
	}
	if tok, _ := vault.xToken.Load().(string); tok != "test-client-token" {
		t.Errorf("x-vault-token = %q", tok)
	}
	if ttl, _ := vault.signTTL.Load().(string); ttl != "720h0m0s" {
		t.Errorf("sign ttl = %q", ttl)
	}

	if cert.Leaf == nil {
		t.Fatal("the enrolled certificate has no parsed leaf")
	}
	if cert.Leaf.Subject.CommonName != "kdc.example.com" {
		t.Errorf("common name = %q", cert.Leaf.Subject.CommonName)
	}
	if got := strings.Join(cert.Leaf.DNSNames, ","); got != "kdc.example.com,ldap.example.com" {
		t.Errorf("dns names = %q", got)
	}
	if len(cert.Leaf.IPAddresses) != 1 || !cert.Leaf.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) {
		t.Errorf("ip addresses = %v", cert.Leaf.IPAddresses)
	}

	// The chain carries the issuing CA behind the leaf, so a TLS client that trusts the CA
	// verifies it.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(vault.caPEM))

	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "ldap.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("the enrolled certificate does not verify against the CA: %v", err)
	}
}

func TestEnrollPropagatesVaultErrors(t *testing.T) {
	vault := newFakeVault(t)
	m := testManager(t, vault, nil)

	vault.loginStatus = http.StatusForbidden
	if _, err := m.Enroll(context.Background(), Config{Address: vault.srv.URL, Role: "ldaps"}); err == nil ||
		!strings.Contains(err.Error(), "kerberos auth failed") {
		t.Errorf("login error = %v", err)
	}

	vault.loginStatus = 0
	vault.signStatus = http.StatusInternalServerError
	if _, err := m.Enroll(context.Background(), Config{Address: vault.srv.URL, Role: "ldaps"}); err == nil ||
		!strings.Contains(err.Error(), "role not allowed") {
		t.Errorf("sign error = %v", err)
	}

	var ve *vaultError
	vault.signStatus = http.StatusInternalServerError
	_, err := m.Enroll(context.Background(), Config{Address: vault.srv.URL, Role: "ldaps"})
	if !errors.As(err, &ve) || ve.status != http.StatusInternalServerError {
		t.Errorf("error = %v, want a vaultError with status 500", err)
	}
}

func TestRenewDelay(t *testing.T) {
	now := time.Now()

	// A certificate valid for another 30 days, renewed a day before expiry: the sleep ends
	// 29 days from now.
	if d := renewDelay(now.Add(30*24*time.Hour), 24*time.Hour, now); d != 29*24*time.Hour {
		t.Errorf("renewDelay = %v, want 29 days", d)
	}

	// A lifetime shorter than the renewal margin, which the issuer may hand back, renews at two
	// thirds of what it granted: a day's certificate is replaced after 16 hours.
	if d := renewDelay(now.Add(24*time.Hour), 24*time.Hour, now); d != 16*time.Hour {
		t.Errorf("renewDelay for a 24h lifetime = %v, want 16h", d)
	}
	if d := renewDelay(now.Add(time.Hour), 24*time.Hour, now); d != 40*time.Minute {
		t.Errorf("renewDelay for a 1h lifetime = %v, want 40m", d)
	}

	// Below the floor the loop still waits the floor rather than spinning.
	if d := renewDelay(now.Add(5*time.Second), 24*time.Hour, now); d != minRenewDelay {
		t.Errorf("renewDelay for a 5s lifetime = %v, want %v", d, minRenewDelay)
	}
}

// TestShortLifetimeDoesNotSpin checks, end to end through the loop, that a lifetime shorter than
// the renewal margin is not renewed at once: the next signing waits for the scheduled renewal.
// The schedule itself is pinned in TestRenewDelay, which is where a spin would show.
func TestShortLifetimeDoesNotSpin(t *testing.T) {
	vault := newFakeVault(t)
	vault.lifetime = time.Hour

	m := testManager(t, vault, nil)
	t.Cleanup(m.Stop)

	m.Configure(Config{
		Address:     vault.srv.URL,
		Principal:   "svc-vault",
		Role:        "ldaps",
		CommonName:  "kdc.example.com",
		RenewBefore: 24 * time.Hour,
	})

	waitFor(t, "enrollment", func() bool { return m.Status().Enrolled })
	time.Sleep(200 * time.Millisecond)

	if n := vault.signs.Load(); n != 1 {
		t.Errorf("certificates signed = %d, want 1: the renewal is due after 40 minutes", n)
	}
}

func TestCheckAddress(t *testing.T) {
	for _, tc := range []struct {
		addr      string
		plaintext bool
		ok        bool
	}{
		{"https://vault.example.com:8200", false, true},
		{"http://vault.example.com:8200", false, false},
		{"http://vault.example.com:8200", true, true},
		{"ftp://vault.example.com", true, false},
		{"https://", false, false},
		{"not a url", false, false},
	} {
		err := CheckAddress(Config{Address: tc.addr, Plaintext: tc.plaintext})
		if (err == nil) != tc.ok {
			t.Errorf("CheckAddress(%q, plaintext=%v) = %v, want ok=%v", tc.addr, tc.plaintext, err, tc.ok)
		}
	}
}

func TestEnrollRefusesPlaintextByDefault(t *testing.T) {
	vault := newFakeVault(t)
	m := NewManager(context.Background(), nil, KDC{}, &CertHolder{}, zerolog.New(io.Discard),
		WithTokenSource(func(context.Context, Config) ([]byte, error) {
			t.Error("the token source was asked for a token before the address was checked")

			return nil, nil
		}))

	plain := strings.Replace(vault.srv.URL, "https://", "http://", 1)
	if _, err := m.Enroll(context.Background(), Config{Address: plain, Role: "ldaps"}); err == nil ||
		!strings.Contains(err.Error(), "plaintext") {
		t.Errorf("Enroll over plain http = %v, want a refusal naming plaintext", err)
	}
	if vault.signs.Load() != 0 {
		t.Error("a refused enrollment still reached the PKI")
	}
}

// TestManagerConfigureConcurrently covers management requests reconfiguring at once: no loop may
// be left behind that Stop cannot reach, so after Stop the attempts stop moving.
func TestManagerConfigureConcurrently(t *testing.T) {
	vault := newFakeVault(t)

	m := testManager(t, vault, nil)
	cfg := Config{
		Address:       vault.srv.URL,
		Principal:     "svc-vault",
		Role:          "ldaps",
		CommonName:    "kdc.example.com",
		RetryInterval: time.Millisecond,
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Configure(cfg)
		}()
	}
	wg.Wait()

	m.Stop()

	// With no loop left, the attempt count stops moving; an orphaned loop would keep enrolling.
	before := m.Status().Attempts
	time.Sleep(100 * time.Millisecond)
	if after := m.Status().Attempts; after != before {
		t.Errorf("attempts moved from %d to %d after Stop: a loop survived", before, after)
	}
}

func TestStopForgetsEnrollment(t *testing.T) {
	vault := newFakeVault(t)
	m := testManager(t, vault, nil)

	m.Configure(Config{
		Address:    vault.srv.URL,
		Principal:  "svc-vault",
		Role:       "ldaps",
		CommonName: "kdc.example.com",
	})
	waitFor(t, "enrollment", func() bool { return m.Status().Enrolled })

	m.Stop()

	st := m.Status()
	if st.Configured || st.Enrolled || !st.NotAfter.IsZero() || len(st.LastError) != 0 {
		t.Errorf("status after Stop = %+v, want nothing enrolled or configured", st)
	}
	if st.Attempts == 0 {
		t.Error("attempts were forgotten by Stop; they are history and should stay")
	}
}

// TestKerberosLoginHonoursContext: a KDC that never answers must not hold the enrollment past
// its context.
func TestKerberosLoginHonoursContext(t *testing.T) {
	vault := newFakeVault(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	m := NewManager(context.Background(), nil, KDC{}, &CertHolder{}, zerolog.New(io.Discard),
		WithHTTPClient(vault.srv.Client()),
		WithTokenSource(func(context.Context, Config) ([]byte, error) {
			<-release

			return []byte("never"), nil
		}))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := m.Enroll(ctx, Config{Address: vault.srv.URL, Role: "ldaps"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Enroll with a hung KDC = %v, want the context's deadline", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Enroll took %v to give up on its context", elapsed)
	}
}

func TestManagerConfigureStatusStop(t *testing.T) {
	vault := newFakeVault(t)

	holder := &CertHolder{}
	m := NewManager(context.Background(), nil, KDC{}, holder, zerolog.New(io.Discard),
		WithHTTPClient(vault.srv.Client()),
		WithTokenSource(func(context.Context, Config) ([]byte, error) { return []byte("x"), nil }))
	t.Cleanup(m.Stop)

	if st := m.Status(); st.Configured || st.Enrolled || st.Attempts != 0 {
		t.Fatalf("initial status = %+v", st)
	}

	m.Configure(Config{
		Address:       vault.srv.URL,
		Principal:     "svc-vault",
		Role:          "ldaps",
		CommonName:    "kdc.example.com",
		RetryInterval: 20 * time.Millisecond,
	})

	waitFor(t, "enrollment", func() bool { return m.Status().Enrolled })

	st := m.Status()
	if !st.Configured || st.Attempts < 1 || len(st.LastError) != 0 {
		t.Errorf("status after enrollment = %+v", st)
	}
	if want := time.Now().Add(72 * time.Hour); st.NotAfter.Before(time.Now()) || st.NotAfter.After(want) {
		t.Errorf("notAfter = %v, want within (now, %v)", st.NotAfter, want)
	}

	// The holder the LDAPS listener reads now answers a handshake.
	if _, err := holder.GetCertificate(nil); err != nil {
		t.Errorf("holder has no certificate after enrollment: %v", err)
	}

	m.Stop()
	if st := m.Status(); st.Configured {
		t.Errorf("configured after Stop = true")
	}
}

func TestManagerReconfiguresWithoutRacing(t *testing.T) {
	vault := newFakeVault(t)

	m := NewManager(context.Background(), nil, KDC{}, &CertHolder{}, zerolog.New(io.Discard),
		WithHTTPClient(vault.srv.Client()),
		WithTokenSource(func(context.Context, Config) ([]byte, error) { return []byte("x"), nil }))

	// Configuring while a loop runs must stop the old loop before the new one starts; with
	// -race this is what watches it.
	cfg := Config{
		Address:       vault.srv.URL,
		Principal:     "svc-vault",
		Role:          "ldaps",
		CommonName:    "kdc.example.com",
		RetryInterval: 10 * time.Millisecond,
	}

	m.Configure(cfg)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5; i++ {
			m.Configure(cfg)
			_ = m.Status()
		}
	}()

	waitFor(t, "reconfigurations", func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	})

	m.Stop()

	if _, err := m.Enroll(context.Background(), Config{Address: vault.srv.URL, Role: "ldaps"}); err != nil {
		t.Fatalf("Enroll after Stop: %v", err)
	}
}

func TestManagerRecordsFailures(t *testing.T) {
	m := NewManager(context.Background(), nil, KDC{}, &CertHolder{}, zerolog.New(io.Discard),
		WithTokenSource(func(context.Context, Config) ([]byte, error) {
			return nil, errors.New("no kdc here")
		}))
	t.Cleanup(m.Stop)

	m.Configure(Config{
		Address:       "https://127.0.0.1:1",
		Principal:     "svc-vault",
		Role:          "ldaps",
		CommonName:    "kdc.example.com",
		RetryInterval: 20 * time.Millisecond,
	})

	waitFor(t, "a failed attempt", func() bool { return m.Status().Attempts > 0 })

	st := m.Status()
	if !st.Configured || st.Enrolled {
		t.Errorf("status = %+v, want configured but not enrolled", st)
	}
	if !strings.Contains(st.LastError, "no kdc here") {
		t.Errorf("lastError = %q", st.LastError)
	}
}

// TestCertHolderHandshake is the deferred-LDAPS contract at the tls.Config level: with
// GetCertificate backed by an empty holder the handshake fails, and once the enrollment has
// delivered a certificate it succeeds.
func TestCertHolderHandshake(t *testing.T) {
	holder := &CertHolder{}

	if _, err := holder.GetCertificate(nil); !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("GetCertificate before enrollment = %v, want ErrNoCertificate", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: holder.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()

	dial := func() error {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}

		return conn.Close()
	}

	if err := dial(); err == nil {
		t.Fatal("handshake succeeded before any certificate was enrolled")
	}

	vault := newFakeVault(t)
	m := testManager(t, vault, nil)

	cert, err := m.Enroll(context.Background(), Config{
		Address:    vault.srv.URL,
		Role:       "ldaps",
		CommonName: "kdc.example.com",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	holder.Set(cert)

	if err := dial(); err != nil {
		t.Fatalf("handshake after enrollment: %v", err)
	}
}
