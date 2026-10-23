package config

import (
	"strings"
	"testing"
	"time"
)

const dockerDNS = "dns:\n  enabled: true\n  hostname: kdc.example.com\n  addresses: [192.0.2.10]\n"

func TestDockerDiscoveryDefaults(t *testing.T) {
	cfg, err := Load(write(t, minimal+dockerDNS+"  docker:\n    enabled: true\n    networks: [app, 10.1.0.0/16]\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	d := cfg.DNS.Docker
	if d.Endpoint != "unix:///var/run/docker.sock" {
		t.Errorf("endpoint = %q, want the default socket", d.Endpoint)
	}
	if d.ResyncEvery != time.Minute {
		t.Errorf("resync_every = %v, want 1m", d.ResyncEvery)
	}
	if len(d.Networks) != 2 || d.Networks[0] != "app" || d.Networks[1] != "10.1.0.0/16" {
		t.Errorf("networks = %v", d.Networks)
	}
}

func TestDockerDiscoveryValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml string
		want string
	}{
		"without dns": {
			yaml: minimal + "dns:\n  docker:\n    enabled: true\n    networks: [app]\n",
			want: "requires dns to be enabled",
		},
		"without networks": {
			yaml: minimal + dockerDNS + "  docker:\n    enabled: true\n",
			want: "networks is required",
		},
		"empty network entry": {
			yaml: minimal + dockerDNS + "  docker:\n    enabled: true\n    networks: [app, \"\"]\n",
			want: "empty entry",
		},
		"ipv6 prefix": {
			yaml: minimal + dockerDNS + "  docker:\n    enabled: true\n    networks: [\"fd00::/64\"]\n",
			want: "not an IPv4 CIDR",
		},
		"unknown scheme": {
			yaml: minimal + dockerDNS + "  docker:\n    enabled: true\n    networks: [app]\n    endpoint: ftp://nope\n",
			want: "must be unix:// or tcp://",
		},
		"socket without a path": {
			yaml: minimal + dockerDNS + "  docker:\n    enabled: true\n    networks: [app]\n    endpoint: unix://\n",
			want: "names no socket path",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestDockerDiscoveryOffIsNotValidated(t *testing.T) {
	// Off means off: a section with nothing in it is not an error.
	if _, err := Load(write(t, minimal+dockerDNS+"  docker:\n    enabled: false\n")); err != nil {
		t.Fatalf("disabled discovery was validated: %v", err)
	}
}
