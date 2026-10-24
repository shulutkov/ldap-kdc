package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shulutkov/ldap-kdc/internal/config"
	"github.com/shulutkov/ldap-kdc/internal/krb5conf"
)

// runKrb5Conf prints the Kerberos client configuration of the realm, or writes it to a file. It reads
// the configuration only: no store is opened and no listener starts.
func runKrb5Conf(args []string) error {
	flags := flag.NewFlagSet("krb5conf", flag.ContinueOnError)
	configPath := flags.String("config", "ldap-kdc.yaml", "path to the configuration file")
	flags.StringVar(configPath, "c", "ldap-kdc.yaml", "path to the configuration file (shorthand)")
	host := flags.String("host", "", "host clients reach the KDC and the password service on, when the name server is off")
	out := flags.String("o", "", "write the file here instead of standard output")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "usage: ldap-kdc krb5conf [-c CONFIG] [-host NAME] [-o FILE]")
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

	text, err := krb5conf.Render(cfg, krb5conf.Options{Host: *host, Source: *configPath})
	if err != nil {
		return err
	}

	if *out == "" {
		_, err := fmt.Print(text)
		return err
	}
	return writeConfigAtomic(*out, []byte(text))
}

// writeConfigAtomic replaces path through a temporary file in the same directory, world-readable: the
// file holds no secret, and containers read it as an unprivileged user.
func writeConfigAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".krb5conf-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
