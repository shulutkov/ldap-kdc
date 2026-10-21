package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

// testCertificatePEM generates a throwaway self-signed certificate, standing in for what an
// external authority like Vault would have issued.
func testCertificatePEM(t *testing.T, serial *big.Int, commonName string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Example"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCertificateImportAndList(t *testing.T) {
	h := newHarness(t)

	h.do(t, "POST", "/api/v1/groups", map[string]any{"name": "staff", "gidNumber": 5000})
	h.do(t, "POST", "/api/v1/users", map[string]any{
		"name": "alice", "uidNumber": 10000, "primaryGroup": 5000,
	})

	pemText := testCertificatePEM(t, big.NewInt(1001), "alice")

	status, body := h.do(t, "POST", "/api/v1/users/alice/certificates/import",
		map[string]any{"certificate": pemText})
	if status != http.StatusCreated {
		t.Fatalf("import: status = %d, body = %v", status, body)
	}
	// 1001 is 0x3e9: the serial crosses the API as hexadecimal, because an authority's serial
	// numbers do not fit into a JSON number.
	if body["serial"] != "03e9" {
		t.Errorf("serial = %v, want 03e9", body["serial"])
	}
	if subject, _ := body["subject"].(string); subject != "CN=alice,O=Example" {
		t.Errorf("subject = %q", subject)
	}
	for _, field := range []string{"notBefore", "notAfter", "createdAt"} {
		if _, ok := body[field]; !ok {
			t.Errorf("the answer carries no %s: %v", field, body)
		}
	}

	// A 160-bit serial, the size Vault issues: it must import, not be refused for not fitting
	// into an integer.
	wideBytes := make([]byte, 20)
	wideBytes[0] = 0x01
	widePEM := testCertificatePEM(t, new(big.Int).SetBytes(wideBytes), "alice")
	status, body = h.do(t, "POST", "/api/v1/users/alice/certificates/import",
		map[string]any{"certificate": widePEM})
	if status != http.StatusCreated {
		t.Fatalf("import of a 160-bit serial: status = %d, body = %v", status, body)
	}
	if want := "01" + strings.Repeat("00", 19); body["serial"] != want {
		t.Errorf("wide serial = %v, want %s", body["serial"], want)
	}

	// The imports must be visible in the listing, as metadata only: the DER is the directory's
	// to publish, not this API's to echo.
	status, list := h.do(t, "GET", "/api/v1/users/alice/certificates", nil)
	if status != http.StatusOK {
		t.Fatalf("list: status = %d, body = %v", status, list)
	}
	certs, _ := list["certificates"].([]any)
	if len(certs) != 2 {
		t.Fatalf("list = %v, want two certificates", list)
	}
	c, _ := certs[0].(map[string]any)
	if c["serial"] != "03e9" || c["subject"] != "CN=alice,O=Example" {
		t.Errorf("listed certificate = %v", c)
	}

	// Importing the same certificate again is a conflict: the serial is already on record.
	if status, body := h.do(t, "POST", "/api/v1/users/alice/certificates/import",
		map[string]any{"certificate": pemText}); status != http.StatusConflict {
		t.Errorf("re-import: status = %d, want 409, body = %v", status, body)
	}

	// Something that is not a certificate is a bad request, never a stored blob.
	for _, garbage := range []string{"not a pem at all", "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"} {
		if status, body := h.do(t, "POST", "/api/v1/users/alice/certificates/import",
			map[string]any{"certificate": garbage}); status != http.StatusBadRequest {
			t.Errorf("garbage import: status = %d, want 400, body = %v", status, body)
		}
	}

	// A missing account is not found, as it is for every other user-scoped operation.
	if status, _ := h.do(t, "POST", "/api/v1/users/nobody/certificates/import",
		map[string]any{"certificate": pemText}); status != http.StatusNotFound {
		t.Errorf("import for a missing account: status = %d, want 404", status)
	}
	if status, _ := h.do(t, "GET", "/api/v1/users/nobody/certificates", nil); status != http.StatusNotFound {
		t.Errorf("list for a missing account: status = %d, want 404", status)
	}
}
