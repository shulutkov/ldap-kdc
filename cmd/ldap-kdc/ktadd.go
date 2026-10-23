package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/config"
	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/logging"
	"github.com/shulutkov/ldap-kdc/internal/secret"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// runKtadd adds the keys of one or more principals to a keytab file, the way MIT's ktadd does. It
// works on the database directly, as kadmin.local does, so it runs where the service's data is:
// in the pod or on the host the service runs on, with the configuration and the master key in
// reach. The service may be running at the same time; SQLite serializes the two.
//
// Unlike ktadd, it does not give the principal new keys unless -randkey says so. Re-keying
// invalidates every keytab issued before, so the default leaves the keys alone.
func runKtadd(args []string) error {
	flags := flag.NewFlagSet("ktadd", flag.ContinueOnError)
	configPath := flags.String("config", "ldap-kdc.yaml", "path to the configuration file")
	flags.StringVar(configPath, "c", "ldap-kdc.yaml", "path to the configuration file (shorthand)")
	keytabPath := flags.String("k", "", "keytab file to add the keys to; created when it does not exist")
	randKey := flags.Bool("randkey", false,
		"give each principal new random keys first; keytabs issued before stop working once their kvno is gone")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "usage: ldap-kdc ktadd -k FILE [-c CONFIG] [-randkey] PRINCIPAL...")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return err
	}

	if len(*keytabPath) == 0 {
		return errors.New("-k FILE is required")
	}
	if flags.NArg() == 0 {
		return errors.New("name at least one principal")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	encTypes, err := krbkeys.ResolveEncTypes(cfg.KDC.EncTypes)
	if err != nil {
		return fmt.Errorf("kdc.enctypes: %w", err)
	}

	sealer, err := existingSealer(cfg.Database.MasterKeyFile)
	if err != nil {
		return err
	}

	ctx := context.Background()
	log := logging.New(cfg.Debug, cfg.StructuredLog)

	st, err := store.Open(ctx, cfg.Database.Path, sealer, log)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	now := time.Now()
	var added []krbkeys.KeytabEntry
	for _, raw := range flags.Args() {
		name, err := krbkeys.ParseName(raw, cfg.Server.Realm)
		if err != nil {
			return err
		}

		var p *store.Principal
		if *randKey {
			p, err = st.RandomizePrincipalKeys(ctx, name, encTypes)
		} else {
			p, err = st.GetPrincipal(ctx, name)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", raw, err)
		}
		if len(p.Keys) == 0 {
			return fmt.Errorf("%s: principal has no keys; set a password or randomize it first", raw)
		}

		// The keys are salted with the canonical name, so the entries carry that name even when the
		// principal was asked for under an alias.
		canonical := p.KrbName()
		for _, k := range p.Keys {
			added = append(added, krbkeys.KeytabEntry{
				Name: canonical, KVNO: p.KVNO, Key: k, Timestamp: now,
			})
		}
	}

	existing, err := readKeytab(*keytabPath)
	if err != nil {
		return err
	}

	blob, err := krbkeys.MarshalKeytab(krbkeys.MergeKeytab(existing, added))
	if err != nil {
		return err
	}

	if err := writeFileAtomic(*keytabPath, blob); err != nil {
		return err
	}

	fmt.Printf("added %d key(s) for %d principal(s) to %s\n",
		len(added), flags.NArg(), *keytabPath)

	return nil
}

// existingSealer loads the master key without creating it: a ktadd that created a key would seal
// nothing it could open, so a missing key means the wrong machine or the wrong configuration.
func existingSealer(path string) (*secret.Sealer, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("master key: %w (the service creates it on first start)", err)
	}
	if len(key) != secret.KeySize {
		return nil, fmt.Errorf("master key %s is %d bytes, want %d", path, len(key), secret.KeySize)
	}

	return secret.NewSealer(key)
}

// readKeytab returns the entries of an existing keytab, or none when the file does not exist yet.
func readKeytab(path string) ([]krbkeys.KeytabEntry, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading keytab: %w", err)
	}

	entries, err := krbkeys.ParseKeytab(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	return entries, nil
}

// writeFileAtomic replaces path through a temporary file in the same directory, so a crash leaves
// either the old keytab or the new one, never a half-written file. Keytabs hold keys: 0600.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".ktadd-*")
	if err != nil {
		return fmt.Errorf("writing keytab: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("writing keytab: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("writing keytab: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("writing keytab: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing keytab: %w", err)
	}

	return os.Rename(tmp.Name(), path)
}
