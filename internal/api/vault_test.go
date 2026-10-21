package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/vaultpki"
)

// vaultTestManager is a real enrollment manager whose Kerberos login is stubbed out: the API
// tests exercise configuration and status, not the enrollment itself, and there is no KDC
// behind them.
func vaultTestManager() *vaultpki.Manager {
	return vaultpki.NewManager(context.Background(), nil, vaultpki.KDC{}, &vaultpki.CertHolder{},
		zerolog.New(io.Discard),
		vaultpki.WithTokenSource(func(context.Context, vaultpki.Config) ([]byte, error) {
			return nil, errors.New("no kerberos in this test")
		}))
}

func TestVaultConfigLifecycle(t *testing.T) {
	m := vaultTestManager()
	t.Cleanup(m.Stop)

	h := newHarnessWith(t, func(c *Config) { c.Vault = m })

	// Nothing configured yet.
	status, body := h.do(t, "GET", "/api/v1/vault/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d, body = %v", status, body)
	}
	if body["configured"] != false || body["enrolled"] != false {
		t.Errorf("initial status = %v", body)
	}

	// A principal the enrollment would log in as.
	status, body = h.do(t, "POST", "/api/v1/principals", map[string]any{"name": "svc-vault"})
	if status != http.StatusCreated {
		t.Fatalf("creating the principal: %d, body = %v", status, body)
	}

	status, body = h.do(t, "PUT", "/api/v1/vault/config", map[string]any{
		"address":     "https://vault.example.com:8200",
		"principal":   "svc-vault",
		"role":        "ldaps",
		"common_name": "kdc.example.com",
		"san_dns":     []string{"kdc.example.com"},
		"san_ips":     []string{"192.0.2.10"},
		"ttl":         "168h",
	})
	if status != http.StatusOK {
		t.Fatalf("put: %d, body = %v", status, body)
	}
	if body["configured"] != true {
		t.Errorf("configured after PUT = %v", body)
	}

	status, body = h.do(t, "GET", "/api/v1/vault/status", nil)
	if status != http.StatusOK || body["configured"] != true {
		t.Errorf("status after PUT: %d, body = %v", status, body)
	}

	status, _ = h.do(t, "DELETE", "/api/v1/vault/config", nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete: %d", status)
	}

	status, body = h.do(t, "GET", "/api/v1/vault/status", nil)
	if status != http.StatusOK || body["configured"] != false {
		t.Errorf("status after DELETE: %d, body = %v", status, body)
	}
}

func TestVaultConfigValidation(t *testing.T) {
	m := vaultTestManager()
	t.Cleanup(m.Stop)

	h := newHarnessWith(t, func(c *Config) { c.Vault = m })

	if status, body := h.do(t, "POST", "/api/v1/principals", map[string]any{"name": "svc-vault"}); status != http.StatusCreated {
		t.Fatalf("creating the principal: %d, body = %v", status, body)
	}

	valid := map[string]any{
		"address":     "https://vault.example.com",
		"principal":   "svc-vault",
		"role":        "ldaps",
		"common_name": "kdc.example.com",
	}

	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"no address", func(b map[string]any) { delete(b, "address") }},
		{"no principal", func(b map[string]any) { delete(b, "principal") }},
		{"no role", func(b map[string]any) { delete(b, "role") }},
		{"no common name", func(b map[string]any) { delete(b, "common_name") }},
		{"broken URL", func(b map[string]any) { b["address"] = "not a url" }},
		{"not http", func(b map[string]any) { b["address"] = "gopher://vault.example.com" }},
		{"unknown principal", func(b map[string]any) { b["principal"] = "nobody" }},
		{"ttl not longer than renew_before", func(b map[string]any) {
			b["ttl"] = "1h"
			b["renew_before"] = "2h"
		}},
		{"bad ttl", func(b map[string]any) { b["ttl"] = "forever" }},
		{"bad san ip", func(b map[string]any) { b["san_ips"] = []string{"not-an-ip"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{}
			for k, v := range valid {
				body[k] = v
			}
			tc.mutate(body)

			status, out := h.do(t, "PUT", "/api/v1/vault/config", body)
			if status != http.StatusBadRequest {
				t.Errorf("status = %d, want 400: %v", status, out)
			}
		})
	}
}

func TestVaultEndpoints503WithoutManager(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/vault/status", nil},
		{"PUT", "/api/v1/vault/config", map[string]any{}},
		{"DELETE", "/api/v1/vault/config", nil},
	} {
		status, out := h.do(t, tc.method, tc.path, tc.body)
		if status != http.StatusServiceUnavailable {
			t.Errorf("%s %s: status = %d, want 503: %v", tc.method, tc.path, status, out)
		}
	}
}
