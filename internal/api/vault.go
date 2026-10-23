package api

import (
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
	"github.com/shulutkov/ldap-kdc/internal/vaultpki"
)

// The Vault PKI integration enrolls the LDAPS listener's certificate: the service logs in to
// Vault (or OpenBao) over Kerberos — against its own KDC — and has the PKI sign a fresh key's
// CSR. It is set up here, at run time, rather than in the configuration file, because it is a
// relationship with a deployment's Vault and not a property of one configuration.

// vaultConfigRequest is the integration as a management request describes it. Durations are
// Go duration strings, as on the principal endpoints.
type vaultConfigRequest struct {
	Address       string   `json:"address" required:"true" description:"The Vault base URL, e.g. https://vault.example.com:8200. Must be https unless plaintext is set."`
	Plaintext     bool     `json:"plaintext,omitempty" description:"Allows an http address. The Kerberos token and Vault's token then travel unencrypted, so this is for test rigs only."`
	Principal     string   `json:"principal" required:"true" description:"The principal in this realm the Vault login authenticates as. Its keys stay in the store; the enrollment reads them from there."`
	ServiceSPN    string   `json:"service_principal,omitempty" description:"The principal Vault's kerberos auth expects a ticket for. Defaults to HTTP/<host of address>."`
	PKIPath       string   `json:"pki_path,omitempty" description:"The mount of the PKI secrets engine. Defaults to pki."`
	Role          string   `json:"role" required:"true" description:"The PKI role the CSR is signed under."`
	CommonName    string   `json:"common_name" required:"true" description:"The certificate's subject CN, the name LDAPS answers for."`
	SANDNS        []string `json:"san_dns,omitempty" description:"DNS subject alternative names."`
	SANIPs        []string `json:"san_ips,omitempty" description:"IP subject alternative names."`
	TTL           string   `json:"ttl,omitempty" description:"The lifetime asked of the PKI, e.g. 720h. Defaults to 720h."`
	RenewBefore   string   `json:"renew_before,omitempty" description:"How long before expiry the certificate is replaced. Defaults to 24h."`
	RetryInterval string   `json:"retry_interval,omitempty" description:"How long a failed enrollment waits before trying again. Defaults to 5s."`
}

// vaultStatusBody is what the enrollment loop reports.
type vaultStatusBody struct {
	Configured bool       `json:"configured"`
	Enrolled   bool       `json:"enrolled"`
	NotAfter   *time.Time `json:"not_after"`
	LastError  string     `json:"last_error"`
	Attempts   int        `json:"attempts"`
}

func vaultStatus(st vaultpki.Status) vaultStatusBody {
	body := vaultStatusBody{
		Configured: st.Configured,
		Enrolled:   st.Enrolled,
		LastError:  st.LastError,
		Attempts:   st.Attempts,
	}
	if !st.NotAfter.IsZero() {
		notAfter := st.NotAfter
		body.NotAfter = &notAfter
	}

	return body
}

// vaultManager returns the enrollment manager, or refuses the request when this build runs
// without one.
func (s *Server) vaultManager(w http.ResponseWriter) *vaultpki.Manager {
	if s.cfg.Vault == nil {
		writeError(w, http.StatusServiceUnavailable, "the vault pki integration is not available on this server")

		return nil
	}

	return s.cfg.Vault
}

// handlePutVaultConfig installs the integration and starts the enrollment loop.
func (s *Server) handlePutVaultConfig(w http.ResponseWriter, r *http.Request) {
	m := s.vaultManager(w)
	if m == nil {
		return
	}

	var req vaultConfigRequest
	if !decode(w, r, &req) {
		return
	}

	switch {
	case len(req.Address) == 0:
		writeError(w, http.StatusBadRequest, "address is required")

		return
	case len(req.Principal) == 0:
		writeError(w, http.StatusBadRequest, "principal is required")

		return
	case len(req.CommonName) == 0:
		writeError(w, http.StatusBadRequest, "common_name is required")

		return
	case len(req.Role) == 0:
		writeError(w, http.StatusBadRequest, "role is required")

		return
	}

	if err := vaultpki.CheckAddress(vaultpki.Config{Address: req.Address, Plaintext: req.Plaintext}); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)

		return
	}

	name, err := krbkeys.ParseName(req.Principal, s.cfg.Realm)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)

		return
	}

	if _, err := s.st.GetPrincipal(r.Context(), name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "unknown principal %s", name)

			return
		}

		writeStoreError(w, err)

		return
	}

	ttl, err := parseVaultDuration(req.TTL, 720*time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ttl: %s", err)

		return
	}

	renewBefore, err := parseVaultDuration(req.RenewBefore, 24*time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, "renew_before: %s", err)

		return
	}

	retryInterval, err := parseVaultDuration(req.RetryInterval, 5*time.Second)
	if err != nil {
		writeError(w, http.StatusBadRequest, "retry_interval: %s", err)

		return
	}

	if ttl <= renewBefore {
		writeError(w, http.StatusBadRequest, "ttl must be longer than renew_before")

		return
	}

	if retryInterval <= 0 {
		writeError(w, http.StatusBadRequest, "retry_interval must be positive")

		return
	}

	ips := make([]net.IP, 0, len(req.SANIPs))
	for _, raw := range req.SANIPs {
		ip := net.ParseIP(raw)
		if ip == nil {
			writeError(w, http.StatusBadRequest, "san_ips: %q is not an IP address", raw)

			return
		}
		ips = append(ips, ip)
	}

	m.Configure(vaultpki.Config{
		Address:          req.Address,
		Plaintext:        req.Plaintext,
		Principal:        req.Principal,
		ServicePrincipal: req.ServiceSPN,
		PKIPath:          req.PKIPath,
		Role:             req.Role,
		CommonName:       req.CommonName,
		DNSNames:         req.SANDNS,
		IPs:              ips,
		TTL:              ttl,
		RenewBefore:      renewBefore,
		RetryInterval:    retryInterval,
	})

	s.log.Info().Str("address", req.Address).Str("principal", name.String()).
		Str("role", req.Role).Msg("vault pki integration configured")

	writeJSON(w, http.StatusOK, vaultStatus(m.Status()))
}

// handleGetVaultStatus reports the enrollment loop's state.
func (s *Server) handleGetVaultStatus(w http.ResponseWriter, r *http.Request) {
	m := s.vaultManager(w)
	if m == nil {
		return
	}

	writeJSON(w, http.StatusOK, vaultStatus(m.Status()))
}

// handleDeleteVaultConfig stops the enrollment loop and forgets the configuration.
func (s *Server) handleDeleteVaultConfig(w http.ResponseWriter, r *http.Request) {
	m := s.vaultManager(w)
	if m == nil {
		return
	}

	m.Stop()

	s.log.Info().Msg("vault pki integration removed")
	w.WriteHeader(http.StatusNoContent)
}

// parseVaultDuration reads a Go duration string, an empty string meaning the default.
func parseVaultDuration(s string, def time.Duration) (time.Duration, error) {
	if len(s) == 0 {
		return def, nil
	}

	return time.ParseDuration(s)
}
