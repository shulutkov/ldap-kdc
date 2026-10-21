package vaultpki

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// vaultClient talks to a Vault-compatible API over plain HTTP. The address is expected to
// have no trailing slash, which Config.defaults arranges.
type vaultClient struct {
	address string
	http    *http.Client
}

// vaultError is a non-2xx answer from Vault, carrying the messages its error object lists.
type vaultError struct {
	status int
	errs   []string
}

func (e *vaultError) Error() string {
	if len(e.errs) == 0 {
		return fmt.Sprintf("vault answered %s", http.StatusText(e.status))
	}

	return fmt.Sprintf("vault answered %s: %s", http.StatusText(e.status), strings.Join(e.errs, "; "))
}

// loginKerberos exchanges a SPNEGO token for a Vault client token at the kerberos auth
// mount.
func (c *vaultClient) loginKerberos(ctx context.Context, spnegoToken []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.address+"/v1/auth/kerberos/login", bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(spnegoToken))
	req.Header.Set("Content-Type", "application/json")

	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}

	if err := c.do(req, &out); err != nil {
		return "", err
	}

	if len(out.Auth.ClientToken) == 0 {
		return "", fmt.Errorf("vault login carried no client token")
	}

	return out.Auth.ClientToken, nil
}

// signCSR asks the PKI to sign the CSR under a role, and returns the certificate with its
// issuing CA appended, both in PEM.
func (c *vaultClient) signCSR(ctx context.Context, token, pkiPath, role string, csrPEM []byte, commonName string, ttl time.Duration) ([]byte, error) {
	body, err := json.Marshal(map[string]string{
		"csr":         string(csrPEM),
		"common_name": commonName,
		"ttl":         ttl.String(),
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.address+"/v1/"+pkiPath+"/sign/"+role, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	var out struct {
		Data struct {
			Certificate string `json:"certificate"`
			IssuingCA   string `json:"issuing_ca"`
		} `json:"data"`
	}

	if err := c.do(req, &out); err != nil {
		return nil, err
	}

	if len(out.Data.Certificate) == 0 {
		return nil, fmt.Errorf("vault's answer carried no certificate")
	}

	chain := strings.TrimSpace(out.Data.Certificate) + "\n"
	if ca := strings.TrimSpace(out.Data.IssuingCA); len(ca) > 0 && ca != strings.TrimSpace(out.Data.Certificate) {
		chain += ca + "\n"
	}

	return []byte(chain), nil
}

// do sends one request and decodes a 2xx answer, mapping anything else onto a vaultError.
func (c *vaultClient) do(req *http.Request, dst any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ve := &vaultError{status: resp.StatusCode}

		var errBody struct {
			Errors []string `json:"errors"`
		}
		if json.Unmarshal(raw, &errBody) == nil {
			ve.errs = errBody.Errors
		}

		return ve
	}

	return json.Unmarshal(raw, dst)
}
