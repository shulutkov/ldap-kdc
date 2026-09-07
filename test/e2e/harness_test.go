// Package e2e drives the built service from outside, over the network, with the reference clients.
//
// Everything else in this repository is tested against Go libraries. That proves the two halves of
// one library agree with each other, which is a weaker statement than it looks: two bugs found so
// far were invisible to the Go client and obvious to Heimdal. Here the questions are asked by MIT
// krb5, OpenLDAP and BIND's dig, running in a container that reaches the service the way a real
// client would -- including finding it through DNS in the first place.
//
// It is a separate module so that the container machinery stays out of the service's own
// dependency graph, and it is skipped when no container runtime is reachable.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	dockercontainer "github.com/moby/moby/api/types/container"
	dockernetwork "github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// e2eImage is the tag the shipped Dockerfile is built under for this suite.
const e2eImage = "ldap-kdc:e2e"

const (
	realm     = "EXAMPLE.COM"
	domain    = "example.com"
	kdcHost   = "kdc.example.com"
	apiToken  = "e2e-token"
	subnet    = "10.99.0.0/24"
	gateway   = "10.99.0.1"
	serviceIP = "10.99.0.10"
	// reverseZone is the in-addr.arpa zone covering the network above.
	reverseZone = "0.99.10.in-addr.arpa"
)

// serviceConfig is the configuration the service runs with inside its container. The addresses are
// fixed because the zone has to name them before the container that owns them exists.
const serviceConfig = `
server:
  realm: ` + realm + `
  anonymous_dse: true

database:
  path: /var/lib/ldap-kdc/ldap-kdc.db
  master_key_file: /var/lib/ldap-kdc/master.key

ldap:
  listen: 0.0.0.0:389

ldaps:
  enabled: false

kdc:
  listen: 0.0.0.0:88

kpasswd:
  listen: 0.0.0.0:464
  min_password_length: 8

dns:
  enabled: true
  listen: 0.0.0.0:53
  hostname: ` + kdcHost + `
  addresses:
    - ` + serviceIP + `
  reverse_zones:
    - ` + reverseZone + `

api:
  listen: 0.0.0.0:5555
  token: ` + apiToken + `
`

// stand is the running pair of containers plus the address of the management API.
type stand struct {
	client  testcontainers.Container
	apiBase string
}

var shared *stand

func TestMain(m *testing.M) {
	ctx := context.Background()

	if err := dockerAvailable(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "skipping the end-to-end suite: no container runtime:", err)
		os.Exit(0)
	}

	s, cleanup, err := newStand(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not bring up the end-to-end stand:", err)
		cleanup()
		os.Exit(1)
	}

	shared = s
	code := m.Run()

	cleanup()
	os.Exit(code)
}

// dockerAvailable reports whether a container runtime can be reached, so the suite can be skipped
// rather than failed on a machine without one.
func dockerAvailable(ctx context.Context) error {
	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		return err
	}
	defer func() { _ = provider.Close() }()

	return provider.Health(ctx)
}

// newStand builds the service binary, puts it in an image with a configuration file, and starts it
// next to a client container whose resolver points at it.
func newStand(ctx context.Context) (*stand, func(), error) {
	var terminators []func()

	cleanup := func() {
		for i := len(terminators) - 1; i >= 0; i-- {
			terminators[i]()
		}
	}

	if err := buildImage(); err != nil {
		return nil, cleanup, err
	}

	// A fixed subnet is what lets the zone name the service's address before the container that
	// owns it exists.
	net, err := network.New(ctx, network.WithIPAM(&dockernetwork.IPAM{
		Driver: "default",
		Config: []dockernetwork.IPAMConfig{{
			Subnet:  netip.MustParsePrefix(subnet),
			Gateway: netip.MustParseAddr(gateway),
		}},
	}))
	if err != nil {
		return nil, cleanup, fmt.Errorf("creating network: %w", err)
	}
	terminators = append(terminators, func() { _ = net.Remove(ctx) })

	service, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			// The image under test is the one that ships: same Dockerfile, same scratch
			// base, same unprivileged user. Anything proved here is proved about the
			// artifact rather than about a convenient stand-in for it.
			Image: e2eImage,
			Files: []testcontainers.ContainerFile{{
				Reader:            strings.NewReader(serviceConfig),
				ContainerFilePath: "/etc/ldap-kdc/ldap-kdc.yaml",
				FileMode:          0o644,
			}},
			// The service runs as an unprivileged user and still has to bind 53, 88, 389 and
			// 464. Opening the low ports to unprivileged processes in this namespace is what
			// makes that possible, and asking for it here means the arrangement the image
			// documents is the one under test.
			HostConfigModifier: func(hc *dockercontainer.HostConfig) {
				hc.Sysctls = map[string]string{"net.ipv4.ip_unprivileged_port_start": "0"}
			},
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {kdcHost, "ldap-kdc"}},
			EndpointSettingsModifier: func(settings map[string]*dockernetwork.EndpointSettings) {
				settings[net.Name] = &dockernetwork.EndpointSettings{
					IPAMConfig: &dockernetwork.EndpointIPAMConfig{
						IPv4Address: netip.MustParseAddr(serviceIP),
					},
				}
			},
			ExposedPorts: []string{"5555/tcp"},
			WaitingFor: wait.ForHTTP("/readyz").
				WithPort("5555/tcp").
				WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		return nil, cleanup, fmt.Errorf("starting the service: %w", err)
	}
	terminators = append(terminators, func() { _ = service.Terminate(ctx) })

	host, err := service.Host(ctx)
	if err != nil {
		return nil, cleanup, err
	}

	port, err := service.MappedPort(ctx, "5555/tcp")
	if err != nil {
		return nil, cleanup, err
	}

	client, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    "testdata",
				Dockerfile: "Dockerfile.client",
				KeepImage:  true,
			},
			Networks: []string{net.Name},
			// The client resolves through the service, which is the only way the discovery
			// records can be exercised: a resolver takes a server, not a port.
			HostConfigModifier: func(hc *dockercontainer.HostConfig) {
				hc.DNS = []netip.Addr{netip.MustParseAddr(serviceIP)}
				hc.DNSSearch = []string{domain}
			},
			Files: []testcontainers.ContainerFile{{
				Reader:            strings.NewReader(clientKrb5Conf),
				ContainerFilePath: "/etc/krb5.conf",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForExec([]string{"true"}).WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		return nil, cleanup, fmt.Errorf("starting the client: %w", err)
	}
	terminators = append(terminators, func() { _ = client.Terminate(ctx) })

	return &stand{
		client:  client,
		apiBase: fmt.Sprintf("http://%s:%s/api/v1", host, port.Port()),
	}, cleanup, nil
}

// clientKrb5Conf deliberately carries no [realms] section: the client has to find the KDC through
// the service records, which is the whole point of serving DNS. rdns is left at its default of
// true so that host canonicalisation is exercised rather than avoided.
const clientKrb5Conf = `[libdefaults]
    default_realm = ` + realm + `
    dns_lookup_realm = true
    dns_lookup_kdc = true
    rdns = true
    forwardable = true
`

// buildImage builds the shipped image through the docker command rather than through the library's
// own build call.
//
// The Dockerfile cross-compiles by way of BUILDPLATFORM and TARGETARCH, which only BuildKit
// defines; the library builds through the daemon's older API, where those expand to nothing and
// the build fails. The command line has BuildKit, and using it also means the layer cache is the
// same one an ordinary build fills.
func buildImage() error {
	cmd := exec.Command("docker", "build", "--build-arg", "VERSION=e2e", "-t", e2eImage, ".")
	cmd.Dir = "../.."

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("building the image: %w: %s", err, out)
	}

	return nil
}

// run executes a shell command in the client container and returns its output and exit code.
func (s *stand) run(t *testing.T, script string) (string, int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	code, reader, err := s.client.Exec(ctx, []string{"sh", "-c", script}, tcexec.Multiplexed())
	if err != nil {
		t.Fatalf("running %q: %v", script, err)
	}

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading the output of %q: %v", script, err)
	}

	return string(out), code
}

// mustRun executes a command and fails the test if it does not succeed.
func (s *stand) mustRun(t *testing.T, script string) string {
	t.Helper()

	out, code := s.run(t, script)
	if code != 0 {
		t.Fatalf("command failed (exit %d): %s\n%s", code, script, out)
	}

	return out
}

// api sends a request to the management interface and returns the decoded body.
func (s *stand) api(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()

	var reader io.Reader

	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encoding request: %v", err)
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, s.apiBase+path, reader)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+apiToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}

	out := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}

	return res.StatusCode, out
}

// mustAPI sends a request and fails unless the status is one of those expected.
func (s *stand) mustAPI(t *testing.T, method, path string, body any, want ...int) map[string]any {
	t.Helper()

	status, out := s.api(t, method, path, body)

	for _, w := range want {
		if status == w {
			return out
		}
	}

	t.Fatalf("%s %s: status %d, want %v: %v", method, path, status, want, out)

	return nil
}

// addUser creates an account with a usable password. Passwords set through the API are expired by
// default, which is right for an administrator provisioning a person and wrong for a fixture, so
// most tests opt out.
func (s *stand) addUser(t *testing.T, name, password string, forceChange bool) {
	t.Helper()

	s.mustAPI(t, "POST", "/groups", map[string]any{
		"name": "e2e", "gidNumber": 6000,
	}, http.StatusCreated, http.StatusConflict)

	s.mustAPI(t, "POST", "/users", map[string]any{
		"name": name, "primaryGroup": 6000,
		"password": password, "forceChange": forceChange,
	}, http.StatusCreated)
}
