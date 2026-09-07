// Command ldap-kdc serves one directory over both LDAP and Kerberos, managed through a REST API.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/api"
	"github.com/shulutkov/ldap-kdc/internal/bootstrap"
	"github.com/shulutkov/ldap-kdc/internal/config"
	"github.com/shulutkov/ldap-kdc/internal/dnssrv"
	"github.com/shulutkov/ldap-kdc/internal/kdc"
	"github.com/shulutkov/ldap-kdc/internal/kpasswd"
	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/ldapsrv"
	"github.com/shulutkov/ldap-kdc/internal/logging"
	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/secret"
	"github.com/shulutkov/ldap-kdc/internal/store"
	"github.com/shulutkov/ldap-kdc/internal/tlsutil"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

// shutdownTimeout bounds how long the process waits for in-flight work when stopping.
const shutdownTimeout = 15 * time.Second

func main() {
	var (
		configPath  = flag.String("config", "ldap-kdc.yaml", "path to the configuration file")
		checkConfig = flag.Bool("check-config", false, "validate the configuration and exit")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.StringVar(configPath, "c", "ldap-kdc.yaml", "path to the configuration file (shorthand)")
	flag.Parse()

	if *showVersion {
		fmt.Println("ldap-kdc", version)

		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(1)
	}

	if *checkConfig {
		source := cfg.Path
		if len(source) == 0 {
			source = "the environment"
		}

		fmt.Printf("configuration from %s is valid (realm %s, base DN %s)\n",
			source, cfg.Server.Realm, cfg.Server.BaseDN)

		return
	}

	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

// service is one of the listeners the process runs.
type service struct {
	name     string
	shutdown func(context.Context) error
}

func run(cfg *config.Config) error {
	log := logging.New(cfg.Debug, cfg.StructuredLog)
	log.Info().Str("version", version).Str("realm", cfg.Server.Realm).Msg("starting")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	encTypes, err := krbkeys.ResolveEncTypes(cfg.KDC.EncTypes)
	if err != nil {
		return fmt.Errorf("kdc.enctypes: %w", err)
	}

	masterKey, created, err := secret.LoadOrCreateMasterKey(cfg.Database.MasterKeyFile)
	if err != nil {
		return err
	}
	if created {
		// Losing this file means losing every stored key, which is a very different outage
		// from losing the database, so it is worth saying out loud exactly once.
		log.Warn().Str("file", cfg.Database.MasterKeyFile).
			Msg("generated a new master key; back it up, the database cannot be read without it")
	}

	sealer, err := secret.NewSealer(masterKey)
	if err != nil {
		return err
	}

	st, err := store.Open(ctx, cfg.Database.Path, sealer, log)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	initialized, err := st.EnsureRealm(ctx, cfg.Server.Realm, encTypes)
	if err != nil {
		return err
	}
	if initialized {
		log.Info().Str("realm", cfg.Server.Realm).Str("database", cfg.Database.Path).
			Msg("realm initialized")
	}

	domainSID, err := st.EnsureDomainSID(ctx, cfg.Server.DomainSID)
	if err != nil {
		return err
	}

	idRange, err := st.EnsureIDRange(ctx, store.IDRange{
		BaseID:           cfg.Server.IDRangeBaseID,
		Size:             cfg.Server.IDRangeSize,
		BaseRID:          cfg.Server.IDRangeBaseRID,
		SecondaryBaseRID: cfg.Server.IDRangeSecondaryBaseRID,
	})
	if err != nil {
		return err
	}

	log.Info().
		Str("domainSID", domainSID).
		Int("idRangeBase", idRange.BaseID).
		Int("idRangeSize", idRange.Size).
		Msg("domain identity")

	if err := applyBootstrap(ctx, cfg, st, encTypes, log); err != nil {
		return err
	}

	m := metrics.New()

	var services []service

	// Shutting down in reverse order of start-up keeps the store alive until the last listener
	// that might still be answering a request has stopped.
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		for _, s := range slices.Backward(services) {
			if err := s.shutdown(shutdownCtx); err != nil {
				log.Warn().Err(err).Str("service", s.name).Msg("did not stop cleanly")
			}
		}

		log.Info().Msg("stopped")
	}()

	if cfg.LDAP.Enabled || cfg.LDAPS.Enabled {
		srv, err := startLDAP(ctx, cfg, domainSID, encTypes, st, log, m)
		if err != nil {
			return err
		}
		services = append(services, service{"ldap", srv.Shutdown})
	}

	if cfg.KDC.Enabled {
		srv, err := kdc.New(kdc.Config{
			Realm:            cfg.Server.Realm,
			DomainName:       cfg.Server.Domain,
			NetBIOSName:      cfg.Server.NetBIOSName,
			DomainSID:        domainSID,
			Listen:           cfg.KDC.Listen,
			MaxTicketLife:    cfg.KDC.MaxTicketLife,
			MaxRenewableLife: cfg.KDC.MaxRenewableLife,
			ClockSkew:        cfg.KDC.ClockSkew,
			EncTypes:         encTypes,
			RequirePreAuth:   cfg.KDC.RequirePreAuth,
			IssuePAC:         cfg.KDC.IssuePAC,
			AllowS4U:         cfg.KDC.AllowS4U,
			UDPMaxSize:       cfg.KDC.UDPMaxSize,
			// The KDC reuses the LDAP-side failed bind policy, so an account is protected
			// against guessing by the same numbers whichever protocol is attacked. The three
			// knobs are what FreeIPA exposes as krbPwdMaxFailure,
			// krbPwdFailureCountInterval and krbPwdLockoutDuration.
			Lockout: store.LockoutPolicy{
				MaxFailures:          cfg.Behaviors.NumberOfFailedBinds,
				FailureCountInterval: cfg.Behaviors.PeriodOfFailedBinds,
				LockoutDuration:      cfg.Behaviors.BlockFailedBindsFor,
			},
		}, st, log, m)
		if err != nil {
			return err
		}
		if err := srv.Start(ctx); err != nil {
			return err
		}
		services = append(services, service{"kdc", srv.Shutdown})
	}

	if cfg.KPasswd.Enabled {
		srv, err := kpasswd.New(kpasswd.Config{
			Realm:             cfg.Server.Realm,
			Listen:            cfg.KPasswd.Listen,
			ClockSkew:         cfg.KDC.ClockSkew,
			EncTypes:          encTypes,
			MinPasswordLength: cfg.KPasswd.MinPasswordLength,
		}, st, log, m)
		if err != nil {
			return err
		}
		if err := srv.Start(ctx); err != nil {
			return err
		}
		services = append(services, service{"kpasswd", srv.Shutdown})
	}

	if cfg.DNS.Enabled {
		srv, err := dnssrv.New(dnssrv.Config{
			Listen:       cfg.DNS.Listen,
			Realm:        cfg.Server.Realm,
			Zone:         cfg.DNS.Zone,
			ReverseZones: cfg.DNS.ReverseZones,
			Hostname:     cfg.DNS.Hostname,
			Addresses:    cfg.DNS.Addresses,
			Mailbox:      cfg.DNS.Mailbox,
			TTL:          cfg.DNS.TTL,
			Services:     discoveryServices(cfg),
		}, st, log, m)
		if err != nil {
			return err
		}
		if err := srv.Start(ctx); err != nil {
			return err
		}
		services = append(services, service{"dns", srv.Shutdown})
	}

	if cfg.API.Enabled {
		var apiTLS *tls.Config
		if cfg.API.TLS {
			if apiTLS, err = tlsutil.Load(cfg.API.CertPath, cfg.API.KeyPath); err != nil {
				return err
			}
		}

		srv, err := api.New(api.Config{
			Listen:            cfg.API.Listen,
			TLS:               apiTLS,
			Realm:             cfg.Server.Realm,
			EncTypes:          encTypes,
			Token:             cfg.API.Token,
			Docs:              cfg.API.Docs,
			MinPasswordLength: cfg.KPasswd.MinPasswordLength,
			DNSZones:          servedZones(cfg),
			DNSDefaultTTL:     int(cfg.DNS.TTL / time.Second),
		}, st, log, m)
		if err != nil {
			return err
		}
		if err := srv.Start(ctx); err != nil {
			return err
		}
		services = append(services, service{"api", srv.Shutdown})
	}

	if len(services) == 0 {
		return errors.New("no listeners are enabled; there is nothing to serve")
	}

	log.Info().Int("services", len(services)).Msg("running")

	<-ctx.Done()
	log.Info().Msg("shutting down")

	return nil
}

// applyBootstrap brings the directory up to the plan named in the configuration, before any
// listener starts. Doing it here rather than after means a client that sees the service accept a
// connection sees a directory that is already what the plan described.
func applyBootstrap(
	ctx context.Context,
	cfg *config.Config,
	st *store.Store,
	encTypes []int32,
	log zerolog.Logger,
) error {
	if len(cfg.Bootstrap.File) == 0 {
		return nil
	}

	plan, err := bootstrap.Load(cfg.Bootstrap.File)
	if err != nil {
		return err
	}

	bootstrap.CheckFilePermissions(cfg.Bootstrap.File, plan, log)

	summary, err := bootstrap.Apply(ctx, st, plan, bootstrap.Options{
		Realm:             cfg.Server.Realm,
		EncTypes:          encTypes,
		MinPasswordLength: cfg.KPasswd.MinPasswordLength,
		DefaultTTL:        int(cfg.DNS.TTL / time.Second),
	}, log)
	if err != nil {
		return fmt.Errorf("applying %s: %w", cfg.Bootstrap.File, err)
	}

	log.Info().
		Str("file", cfg.Bootstrap.File).
		Int("created", summary.Created).
		Int("existed", summary.Existed).
		Msg("bootstrap plan applied")

	return nil
}

// discoveryServices lists the SRV records the zone advertises, taken from the listeners this
// process actually runs. A client that reads them can then find the KDC and the directory without
// being told either address by hand.
func discoveryServices(cfg *config.Config) []dnssrv.Service {
	var out []dnssrv.Service

	add := func(enabled bool, listen string, names ...string) {
		if !enabled {
			return
		}

		port := listenPort(listen)
		if port == 0 {
			return
		}

		out = append(out, dnssrv.Service{Names: names, Port: port})
	}

	// RFC 4120 section 7.2.3 names the first two; the -master forms tell a client where to send
	// a password change or an initial ticket request when replicas exist.
	add(cfg.KDC.Enabled, cfg.KDC.Listen, "_kerberos._udp", "_kerberos._tcp",
		"_kerberos-master._udp", "_kerberos-master._tcp")
	add(cfg.KPasswd.Enabled, cfg.KPasswd.Listen, "_kpasswd._udp", "_kpasswd._tcp",
		"_kerberos-adm._tcp")
	add(cfg.LDAP.Enabled, cfg.LDAP.Listen, "_ldap._tcp")
	add(cfg.LDAPS.Enabled, cfg.LDAPS.Listen, "_ldaps._tcp")

	return out
}

// servedZones lists the zones the name server answers for, so the management API can refuse a
// record that would be stored and never served.
func servedZones(cfg *config.Config) []string {
	if !cfg.DNS.Enabled {
		return nil
	}

	return append([]string{cfg.DNS.Zone}, cfg.DNS.ReverseZones...)
}

// listenPort extracts the port from a listen address, or zero when it has none.
func listenPort(listen string) int {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}

	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}

	return n
}

// startLDAP builds and starts the LDAP and LDAPS listeners.
func startLDAP(
	ctx context.Context,
	cfg *config.Config,
	domainSID string,
	encTypes []int32,
	st *store.Store,
	log zerolog.Logger,
	m *metrics.Metrics,
) (*ldapsrv.Server, error) {
	var (
		startTLS *tls.Config
		ldapsTLS *tls.Config
		err      error
	)

	if cfg.LDAP.Enabled && cfg.LDAP.TLS {
		if startTLS, err = tlsutil.Load(cfg.LDAP.CertPath, cfg.LDAP.KeyPath); err != nil {
			return nil, err
		}
	}
	if cfg.LDAPS.Enabled {
		if ldapsTLS, err = tlsutil.Load(cfg.LDAPS.CertPath, cfg.LDAPS.KeyPath); err != nil {
			return nil, err
		}
	}

	srv, err := ldapsrv.New(
		ldapsrv.Config{
			BaseDN:                cfg.Server.BaseDN,
			NameFormat:            cfg.Server.NameFormat,
			GroupFormat:           cfg.Server.GroupFormat,
			SSHKeyAttr:            cfg.Server.SSHKeyAttr,
			Realm:                 cfg.Server.Realm,
			DomainSID:             domainSID,
			AnonymousDSE:          cfg.Server.AnonymousDSE,
			IgnoreCapabilities:    cfg.Behaviors.IgnoreCapabilities,
			EncTypes:              encTypes,
			LimitFailedBinds:      cfg.Behaviors.LimitFailedBinds,
			NumberOfFailedBinds:   cfg.Behaviors.NumberOfFailedBinds,
			PeriodOfFailedBinds:   cfg.Behaviors.PeriodOfFailedBinds,
			BlockFailedBindsFor:   cfg.Behaviors.BlockFailedBindsFor,
			PruneSourceTableEvery: cfg.Behaviors.PruneSourceTableEvery,
			PruneSourcesOlderThan: cfg.Behaviors.PruneSourcesOlderThan,
		},
		ldapsrv.ListenerConfig{Enabled: cfg.LDAP.Enabled, Listen: cfg.LDAP.Listen, TLS: startTLS},
		ldapsrv.ListenerConfig{Enabled: cfg.LDAPS.Enabled, Listen: cfg.LDAPS.Listen, TLS: ldapsTLS},
		st, log, m,
	)
	if err != nil {
		return nil, err
	}

	if err := srv.Start(ctx); err != nil {
		return nil, err
	}

	return srv, nil
}
