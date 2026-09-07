// Package tlsutil builds the TLS configuration the listeners share.
package tlsutil

import (
	"crypto/tls"
	"fmt"
)

// Load reads a certificate and key from disk and returns a server TLS configuration.
//
// The minimum version is pinned to 1.2: this service carries passwords and Kerberos key material,
// and the older protocol versions have no safe cipher suites left.
func Load(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading certificate %s: %w", certPath, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
