package api

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// The certificate endpoints record certificates an external authority — the deployment's Vault,
// or whatever else it trusts — has already issued to an account. This service issues nothing
// itself: it stores the public half so the directory can publish it as userCertificate;binary,
// which is what a smart-card style client looks up. The private half is never sent here and
// never stored.

// certificateImportRequest carries the certificate to record, in PEM.
type certificateImportRequest struct {
	Certificate string `json:"certificate" required:"true" description:"An X.509 certificate in PEM, issued to the account by an external authority."`
}

// certificateImportReq pairs the path parameter with the body, for the generated document.
type certificateImportReq struct {
	userPath
	certificateImportRequest
}

// certificateBody describes one stored certificate. There is deliberately no DER in it: the
// certificate itself is served by the directory, and a listing of metadata is all managing the
// records takes.
type certificateBody struct {
	// Issuer is the authority that issued the certificate, as its authority key identifier in
	// hexadecimal. A certificate is named by this with its serial, since serials are only unique
	// within one issuer.
	Issuer string `json:"issuer"`
	// Serial is hexadecimal, because an issuing authority's serial numbers do not fit into a
	// JSON number: Vault issues 160-bit ones.
	Serial    string    `json:"serial"`
	Subject   string    `json:"subject"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	CreatedAt time.Time `json:"createdAt"`
}

type certificatesBody struct {
	Certificates []certificateBody `json:"certificates"`
}

// handleListUserCertificates lists an account's certificates, without their DER.
func (s *Server) handleListUserCertificates(w http.ResponseWriter, r *http.Request) {
	certs, err := s.st.ListUserCertificates(r.Context(), r.PathValue("name"))
	if err != nil {
		writeStoreError(w, err)

		return
	}

	body := certificatesBody{Certificates: make([]certificateBody, 0, len(certs))}
	for _, c := range certs {
		body.Certificates = append(body.Certificates, certificateBody{
			Issuer: c.Issuer, Serial: c.Serial, Subject: c.Subject,
			NotBefore: c.NotBefore, NotAfter: c.NotAfter, CreatedAt: c.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, body)
}

// handleImportUserCertificate records a certificate an external authority issued to the account.
// The certificate is parsed before anything is stored, so what the directory later publishes is
// known to be a certificate rather than a blob the store was talked into keeping.
func (s *Server) handleImportUserCertificate(w http.ResponseWriter, r *http.Request) {
	var req certificateImportRequest
	if !decode(w, r, &req) {
		return
	}

	block, _ := pem.Decode([]byte(req.Certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		writeError(w, http.StatusBadRequest, "the certificate must be a PEM-encoded X.509 certificate")

		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "the certificate does not parse: %s", err)

		return
	}

	if cert.SerialNumber.Sign() <= 0 {
		// A non-positive serial is not a certificate an issuer meant to exist (RFC 5280 wants
		// them positive), and it has no business being published.
		writeError(w, http.StatusBadRequest, "the certificate's serial number must be positive")

		return
	}

	name := r.PathValue("name")

	// What the store keeps is the certificate and the facts a listing is read by: the serial the
	// issuer assigned — as hexadecimal, an authority's serials being wider than any integer —
	// the subject, and the validity window. Everything else a reader might want it can parse out
	// of the DER itself.
	// The issuer is the authority key identifier: the same for every certificate one authority
	// signs, so serial numbers are checked for uniqueness within it and not across all of them.
	c := &store.Certificate{
		Issuer:    hex.EncodeToString(cert.AuthorityKeyId),
		Serial:    cert.SerialNumber.Text(16),
		Subject:   cert.Subject.String(),
		DER:       cert.Raw,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}

	if err := s.st.AddCertificate(r.Context(), name, c); err != nil {
		writeStoreError(w, err)

		return
	}

	s.log.Info().Str("user", name).Str("issuer", c.Issuer).Str("serial", c.Serial).Msg("certificate imported")
	writeJSON(w, http.StatusCreated, certificateBody{
		Issuer: c.Issuer, Serial: c.Serial, Subject: c.Subject,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, CreatedAt: c.CreatedAt,
	})
}
