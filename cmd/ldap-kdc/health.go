package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/config"
)

// runHealth probes the running service through its management API: /readyz by default, /healthz
// with -live. The shipped image is scratch — no shell, no wget — so the binary checks itself,
// which is what a container's healthcheck runs:
//
//	healthcheck:
//	  test: ["CMD", "ldap-kdc", "health", "-c", "/etc/ldap-kdc/ldap-kdc.yaml"]
//
// The exit code is the verdict: 0 when the probe answers 200, 1 otherwise. Nothing beside the
// one HTTP connection is opened — no store, no master key.
func runHealth(args []string) error {
	flags := flag.NewFlagSet("health", flag.ContinueOnError)
	configPath := flags.String("config", "ldap-kdc.yaml", "path to the configuration file")
	flags.StringVar(configPath, "c", "ldap-kdc.yaml", "path to the configuration file (shorthand)")
	live := flags.Bool("live", false, "probe liveness (/healthz) instead of readiness (/readyz)")
	timeout := flags.Duration("timeout", 3*time.Second, "how long the probe may take")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "usage: ldap-kdc health [-c CONFIG] [-live] [-timeout DURATION]")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}

	cfg, err := config.LoadForClients(*configPath)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	listen, tlsOn, err := probeAddress(cfg)
	if err != nil {
		return err
	}

	scheme := "http"
	transport := &http.Transport{}
	if tlsOn {
		scheme = "https"
		// The probe connects by loopback address, which no served certificate names; it wants
		// "the server answers a TLS handshake", not the peer's identity.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	endpoint := "/readyz"
	if *live {
		endpoint = "/healthz"
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+listen+endpoint, nil)
	if err != nil {
		return err
	}

	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s: %s", endpoint, resp.Status, body)
	}

	fmt.Printf("%s: %s", endpoint, body)

	return nil
}

// probeAddress picks the address the probes are served on, and whether they are served over TLS.
// A listener bound to every interface is probed through loopback; one bound to a specific address
// is probed there.
func probeAddress(cfg *config.Config) (listen string, tlsOn bool, err error) {
	if !cfg.API.Enabled {
		return "", false, errors.New("api.enabled is false; without the management API there are no probes to ask")
	}

	listen, tlsOn = cfg.API.Listen, cfg.API.TLS
	if shareOIDCListener(cfg) {
		// The probes ride on the provider's listener when the two share an address.
		listen, tlsOn = cfg.OIDC.Listen, cfg.OIDC.TLS
	}

	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", false, fmt.Errorf("listen address %q: %w", listen, err)
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		host = "127.0.0.1"
	}

	return net.JoinHostPort(host, port), tlsOn, nil
}
