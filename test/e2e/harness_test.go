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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

	// The objects the bootstrap plan below brings up before anything else runs.
	seededUser     = "seeded-user"
	seededAlias    = "seeded.alias"
	seededPassword = "the seeded account password"
	seededHost     = "seeded.example.com"
	seededHostIP   = "10.99.0.30"

	// The OpenBao container and the directory objects that exist for it.
	vaultHost     = "vault.example.com"
	vaultIP       = "10.99.0.20"
	vaultSPN      = "HTTP/" + vaultHost
	vaultEnroll   = "svc-vault-enroll"
	vaultBind     = "svc-vault-ldap"
	vaultBindPass = "the vault ldap bind password"
	vaultBindDN   = "cn=" + vaultBind + ",ou=svc,ou=users,dc=example,dc=com"
)

// vaultDisabled reports whether the stand should come up without OpenBao at all; the vault tests
// then skip.
func vaultDisabled() bool {
	return os.Getenv("E2E_VAULT_IMAGE") == "off"
}

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
  enabled: true

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

bootstrap:
  file: /etc/ldap-kdc/bootstrap.yaml
`

// bootstrapPlan is the directory the service is expected to come up with. Everything in it is
// there before the first listener accepts a connection, so a test can use it without provisioning
// anything of its own -- which is the point of the mechanism.
const bootstrapPlan = `
groups:
  - name: seeded
    gid_number: 7000
    capabilities:
      - action: search
        object: "*"
  - name: svc
    gid_number: 7001
  - name: vault-users
    gid_number: 7002
  - name: vault-enroll
    gid_number: 7003

users:
  - name: seeded-user
    primary_group: 7000
    other_groups:
      - 7002
    given_name: Seeded
    sn: Account
    password: ` + seededPassword + `
    aliases:
      - ` + seededAlias + `
  - name: ` + vaultEnroll + `
    primary_group: 7001
    other_groups:
      - 7003
  - name: ` + vaultBind + `
    primary_group: 7001
    password: ` + vaultBindPass + `
    capabilities:
      - action: search
        object: "*"

principals:
  - name: HTTP/` + seededHost + `
  - name: ` + vaultSPN + `

dns_records:
  - name: ` + seededHost + `
    type: A
    value: ` + seededHostIP + `
  - name: ` + vaultHost + `
    type: A
    value: ` + vaultIP + `
`

// stand is the running set of containers plus the address of the management API. vault is nil
// when E2E_VAULT_IMAGE=off, and the vault tests then skip.
type stand struct {
	client     testcontainers.Container
	vault      testcontainers.Container
	vaultToken string
	apiBase    string
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

	// The containers' resolver is the service itself, and a resolver takes a file, not a port:
	// /etc/resolv.conf is Docker's own mount, so the only way to replace it is another mount on
	// top. With Docker's embedded DNS out of the way the service's zone answers everything —
	// including the reverse queries, which Docker would otherwise answer with container names.
	resolvConf, err := writeResolvConf()
	if err != nil {
		return nil, cleanup, err
	}
	terminators = append(terminators, func() { _ = os.RemoveAll(filepath.Dir(resolvConf)) })

	service, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			// The image under test is the one that ships: same Dockerfile, same scratch
			// base, same unprivileged user. Anything proved here is proved about the
			// artifact rather than about a convenient stand-in for it.
			Image: e2eImage,
			Files: []testcontainers.ContainerFile{
				{
					Reader:            strings.NewReader(serviceConfig),
					ContainerFilePath: "/etc/ldap-kdc/ldap-kdc.yaml",
					FileMode:          0o644,
				},
				{
					Reader:            strings.NewReader(bootstrapPlan),
					ContainerFilePath: "/etc/ldap-kdc/bootstrap.yaml",
					FileMode:          0o644,
				},
			},
			// The service runs as an unprivileged user and still has to bind 53, 88, 389 and
			// 464. Opening the low ports to unprivileged processes in this namespace is what
			// makes that possible, and asking for it here means the arrangement the image
			// documents is the one under test.
			HostConfigModifier: func(hc *dockercontainer.HostConfig) {
				hc.Sysctls = map[string]string{"net.ipv4.ip_unprivileged_port_start": "0"}
			},
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {kdcHost, "ldap-kdc"}},
			// The address goes onto the endpoint the aliases were registered on rather than
			// onto a fresh one: replacing the settings wholesale would drop the aliases, and
			// with them the name other containers resolve this one by.
			EndpointSettingsModifier: fixedIP(serviceIP),
			ExposedPorts:             []string{"5555/tcp"},
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

	var vault testcontainers.Container

	if !vaultDisabled() {
		arch := runtime.GOARCH

		vault, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				// The image is built for the stand: the kerberos auth plugin and the pkcs11
				// seal plugin are not part of the stock OpenBao build, and the SoftHSM token
				// the server auto-unseals against is initialized when the image is built.
				FromDockerfile: testcontainers.FromDockerfile{
					Context:    "testdata",
					Dockerfile: "Dockerfile.openbao",
					BuildArgs:  map[string]*string{"TARGETARCH": &arch},
					KeepImage:  true,
				},
				Cmd: []string{"server", "-config=/openbao/config.hcl"},
				Files: []testcontainers.ContainerFile{{
					Reader:            strings.NewReader(vaultKrb5Conf),
					ContainerFilePath: "/etc/krb5.conf",
					FileMode:          0o644,
				}},
				Networks:       []string{net.Name},
				NetworkAliases: map[string][]string{net.Name: {vaultHost}},
				// The ldap-kdc container resolves this very name through Docker's resolver
				// when it enrolls, so the alias has to survive — hence the in-place modifier.
				EndpointSettingsModifier: fixedIP(vaultIP),
				HostConfigModifier:       useServiceDNS(resolvConf),
				WaitingFor:               wait.ForListeningPort("8200/tcp").WithStartupTimeout(120 * time.Second),
			},
			Started: true,
		})
		if err != nil {
			return nil, cleanup, fmt.Errorf("starting the vault: %w", err)
		}
		terminators = append(terminators, func() { _ = vault.Terminate(ctx) })
	}

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
			Networks:           []string{net.Name},
			HostConfigModifier: useServiceDNS(resolvConf),
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

	s := &stand{
		client:  client,
		vault:   vault,
		apiBase: fmt.Sprintf("http://%s:%s/api/v1", host, port.Port()),
	}

	if vault != nil {
		if err := s.setupVault(ctx); err != nil {
			return nil, cleanup, fmt.Errorf("setting up the vault: %w", err)
		}
	}

	return s, cleanup, nil
}

// writeResolvConf writes the resolver configuration the client and vault containers are given:
// the service's own name server, full stop. It lands in a fresh temp directory because the path
// is bind-mounted into the containers and has to outlive them.
func writeResolvConf() (string, error) {
	dir, err := os.MkdirTemp("", "ldap-kdc-e2e-resolv")
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, "resolv.conf")
	body := "nameserver " + serviceIP + "\nsearch " + domain + "\n"

	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		_ = os.RemoveAll(dir)

		return "", err
	}

	return path, nil
}

// useServiceDNS mounts that resolver file over the container's /etc/resolv.conf. Docker manages
// the file as a mount of its own, so neither an image file nor a copied-in file could replace
// it — a mount on top of a mount can.
func useServiceDNS(resolvConf string) func(*dockercontainer.HostConfig) {
	return func(hc *dockercontainer.HostConfig) {
		hc.Binds = append(hc.Binds, resolvConf+":/etc/resolv.conf:ro")
	}
}

// fixedIP pins a container to an address on its network without touching the rest of the
// endpoint settings, which is where the network aliases live.
func fixedIP(ip string) func(map[string]*dockernetwork.EndpointSettings) {
	return func(settings map[string]*dockernetwork.EndpointSettings) {
		for _, es := range settings {
			es.IPAMConfig = &dockernetwork.EndpointIPAMConfig{
				IPv4Address: netip.MustParseAddr(ip),
			}
		}
	}
}

// clientKrb5Conf deliberately carries no [realms] section: the client has to find the KDC through
// the service records, which is the whole point of serving DNS. rdns is left at its default of
// true so that host canonicalisation is exercised rather than avoided — the containers resolve
// through the service itself (their resolv.conf is bind-mounted, see newStand), so the reverse
// answer for an address is the zone's, not Docker's.
const clientKrb5Conf = `[libdefaults]
    default_realm = ` + realm + `
    dns_lookup_realm = true
    dns_lookup_kdc = true
    rdns = true
    forwardable = true
`

// vaultKrb5Conf names the KDC explicitly: the container's resolver answers for this zone, but a
// Kerberos configuration that does not depend on DNS at all is one less moving part when the
// kerberos plugin reads it.
const vaultKrb5Conf = `[libdefaults]
    default_realm = ` + realm + `
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    ` + realm + ` = {
        kdc = ` + kdcHost + `
    }

[domain_realm]
    .` + domain + ` = ` + realm + `
    ` + domain + ` = ` + realm + `
`

// vaultExec runs a command in the vault container and returns its combined output.
func (s *stand) vaultExec(ctx context.Context, env []string, cmd ...string) (string, error) {
	code, reader, err := s.vault.Exec(ctx, cmd, tcexec.Multiplexed(), tcexec.WithEnv(env))
	if err != nil {
		return "", fmt.Errorf("exec %q: %w", strings.Join(cmd, " "), err)
	}

	out, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("reading the output of %q: %w", strings.Join(cmd, " "), err)
	}

	if code != 0 {
		return string(out), fmt.Errorf("%q exited %d: %s", strings.Join(cmd, " "), code, strings.TrimSpace(string(out)))
	}

	return string(out), nil
}

// apiRaw sends a request to the management interface and returns the undecoded body, for the
// endpoints that do not answer in JSON.
func (s *stand) apiRaw(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var reader io.Reader

	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, s.apiBase+path, reader)
	if err != nil {
		return 0, nil, err
	}

	req.Header.Set("Authorization", "Bearer "+apiToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = res.Body.Close() }()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, nil, err
	}

	return res.StatusCode, raw, nil
}

// setupVault turns the freshly started OpenBao into the PKI the scenario needs: initialized and
// unsealed (the seal is a SoftHSM token, so unsealing is the server's own business and there is
// deliberately no `bao operator unseal` here), the kerberos auth method registered from the
// plugin the image was built with and wired to the directory, the PKI mounted with a root and
// the two roles, and the service itself enrolled for its LDAPS certificate through the
// management API.
func (s *stand) setupVault(ctx context.Context) error {
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "e2e vault setup: "+format+"\n", args...)
	}

	env := []string{"BAO_ADDR=http://127.0.0.1:8200"}

	// With an auto-seal the barrier key goes to the HSM and what init hands out are recovery
	// keys, so the shares arguments are the recovery ones.
	out, err := s.vaultExec(ctx, env, "bao", "operator", "init",
		"-recovery-shares=1", "-recovery-threshold=1", "-format=json")
	if err != nil {
		return err
	}

	var init struct {
		RootToken string `json:"root_token"`
	}
	if err := json.Unmarshal([]byte(out), &init); err != nil || len(init.RootToken) == 0 {
		return fmt.Errorf("parsing operator init output: %w: %s", err, out)
	}
	s.vaultToken = init.RootToken

	// The proof that the SoftHSM seal does its job: nobody unsealed the server, and yet.
	out, err = s.vaultExec(ctx, env, "bao", "status", "-format=json")
	if err != nil {
		return err
	}

	var seal struct {
		Sealed bool `json:"sealed"`
	}
	if err := json.Unmarshal([]byte(out), &seal); err != nil || seal.Sealed {
		return fmt.Errorf("the vault did not auto-unseal against SoftHSM: %w: %s", err, out)
	}
	logf("auto-unsealed via pkcs11/SoftHSM")

	root := append(env, "BAO_TOKEN="+init.RootToken)

	// The kerberos auth method left the server binary with OpenBao 2.x and lives in the
	// openbao-plugins collection now; the image was built with the plugin and its SHA-256.
	sum, err := s.vaultExec(ctx, env, "cat", "/openbao/plugins/openbao-plugin-auth-kerberos.sha256")
	if err != nil {
		return err
	}

	if _, err := s.vaultExec(ctx, root, "bao", "plugin", "register",
		"-sha256="+strings.TrimSpace(sum),
		"-command=openbao-plugin-auth-kerberos", "auth", "kerberos"); err != nil {
		return err
	}

	// The login endpoint answers the unauthenticated request with a Negotiate challenge, which
	// only reaches the client if both headers are allowed through the core.
	if _, err := s.vaultExec(ctx, root, "bao", "auth", "enable",
		"-passthrough-request-headers=Authorization",
		"-allowed-response-headers=www-authenticate",
		"kerberos"); err != nil {
		return err
	}

	// The plugin verifies incoming service tickets against this keytab. PAC decoding stays off:
	// the PAC this KDC issues is not one the plugin's Kerberos library can read, and group
	// membership comes from LDAP below anyway.
	status, keytab, err := s.apiRaw(ctx, "GET", "/principals/HTTP%2F"+vaultHost+"/keytab", nil)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("fetching the %s keytab: status %d: %w: %s", vaultSPN, status, err, keytab)
	}

	if err := s.vault.CopyToContainer(ctx,
		[]byte(base64.StdEncoding.EncodeToString(keytab)), "/tmp/vault.keytab.b64", 0o644); err != nil {
		return err
	}

	if _, err := s.vaultExec(ctx, root, "bao", "write", "auth/kerberos/config",
		"keytab=@/tmp/vault.keytab.b64",
		"service_account="+vaultSPN,
		"decode_pac=false"); err != nil {
		return err
	}

	if _, err := s.vaultExec(ctx, root, "bao", "write", "auth/kerberos/config/ldap",
		"url=ldap://"+kdcHost,
		"binddn="+vaultBindDN,
		"bindpass="+vaultBindPass,
		"userdn=ou=users,dc=example,dc=com",
		"groupdn=ou=groups,dc=example,dc=com",
		"userattr=uid",
		"groupattr=cn",
		"upndomain="+realm); err != nil {
		return err
	}

	policies := map[string]string{
		"user-certs": `path "pki/issue/user" { capabilities = ["update"] }`,
		"enroll":     `path "pki/sign/ldaps" { capabilities = ["update"] }`,
	}
	for name, doc := range policies {
		if _, err := s.vaultExec(ctx, root, "sh", "-c",
			"printf '%s' '"+doc+"' | bao policy write "+name+" -"); err != nil {
			return err
		}
	}

	if _, err := s.vaultExec(ctx, root, "bao", "write",
		"auth/kerberos/groups/vault-users", "policies=user-certs"); err != nil {
		return err
	}
	if _, err := s.vaultExec(ctx, root, "bao", "write",
		"auth/kerberos/groups/vault-enroll", "policies=enroll"); err != nil {
		return err
	}

	if _, err := s.vaultExec(ctx, root, "bao", "secrets", "enable", "pki"); err != nil {
		return err
	}
	if _, err := s.vaultExec(ctx, root, "bao", "secrets", "tune", "-max-lease-ttl=87600h", "pki"); err != nil {
		return err
	}
	if _, err := s.vaultExec(ctx, root, "bao", "write", "pki/root/generate/internal",
		"common_name="+domain, "ttl=87600h"); err != nil {
		return err
	}
	if _, err := s.vaultExec(ctx, root, "bao", "write", "pki/roles/user",
		"allow_any_name=true", "enforce_hostnames=false", "max_ttl=720h"); err != nil {
		return err
	}
	if _, err := s.vaultExec(ctx, root, "bao", "write", "pki/roles/ldaps",
		"allowed_domains="+kdcHost, "allow_bare_domains=true", "allow_ip_sans=true",
		"key_type=any", "max_ttl=8760h"); err != nil {
		return err
	}

	// The service itself is the first kerberos login the mount sees: it enrolls the LDAPS
	// certificate against the ldaps role from here on, and renews it before expiry.
	status, raw, err := s.apiRaw(ctx, "PUT", "/vault/config", map[string]any{
		"address":        "http://" + vaultHost + ":8200",
		"principal":      vaultEnroll,
		"pki_path":       "pki",
		"role":           "ldaps",
		"common_name":    kdcHost,
		"san_dns":        []string{kdcHost},
		"san_ips":        []string{serviceIP},
		"ttl":            "720h",
		"renew_before":   "24h",
		"retry_interval": "5s",
	})
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("configuring the vault integration: status %d: %w: %s", status, err, raw)
	}

	deadline := time.Now().Add(90 * time.Second)
	for {
		var st struct {
			Enrolled  bool   `json:"enrolled"`
			LastError string `json:"last_error"`
			Attempts  int    `json:"attempts"`
		}

		status, raw, err := s.apiRaw(ctx, "GET", "/vault/status", nil)
		if err == nil && status == http.StatusOK {
			if json.Unmarshal(raw, &st) == nil && st.Enrolled {
				logf("enrolled after %d attempt(s)", st.Attempts)

				return nil
			}
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("the service did not enroll in 90s: last_error=%q attempts=%d", st.LastError, st.Attempts)
		}

		time.Sleep(2 * time.Second)
	}
}

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
