# End-to-end test rig

The end-to-end suite in `test/e2e/` drives the built service from outside, over the network, with
the reference clients: MIT krb5 (`kinit`, `klist`, `kvno`, `kpasswd`), OpenLDAP (`ldapsearch`) and
BIND's `dig`, plus `curl` and `openssl` for the OpenBao scenarios. Everything else in the
repository is tested against Go libraries, which only proves that two halves of one library agree
with each other — bugs have been found that were invisible to the Go client and obvious to
Heimdal. Here the questions are asked by third-party clients reaching the service the way a real
client would, including finding it through DNS in the first place.

The suite is a separate Go module (`test/e2e/go.mod`, module `ldap-kdc/test/e2e`) so that the
container machinery (`testcontainers-go`, the Docker API types) stays out of the service's own
dependency graph.

## Skipping without a container runtime

`TestMain` in `test/e2e/harness_test.go` probes for a container runtime before doing anything (`dockerAvailable` uses
`testcontainers.NewDockerProvider` and its `Health` check). If none is
reachable, the suite prints

```
skipping the end-to-end suite: no container runtime: <error>
```

to stderr and exits with code 0 — the run counts as a pass, not a failure. If the stand fails to
come up, the exit code is 1.

## Stand architecture

`newStand` in `test/e2e/harness_test.go` builds one shared stand for the whole suite (stored in
the package-level `shared` variable) and tears it down after all tests run.

```
                 host
                  │  only published port: 5555/tcp (mapped, random host port)
                  ▼
┌────────────────────────── 10.99.0.0/24, gateway 10.99.0.1 ─────────────────────────┐
│                                                                                    │
│  10.99.0.10  ldap-kdc          aliases: kdc.example.com, ldap-kdc                  │
│              image ldap-kdc:e2e, built from the repo Dockerfile                    │
│              serves LDAP :389, LDAPS :636, KDC :88, kpasswd :464,                  │
│              DNS :53, API :5555 — all container-to-container except 5555           │
│                                                                                    │
│  10.99.0.20  openbao           alias: vault.example.com                            │
│              image built from testdata/Dockerfile.openbao                          │
│                                                                                    │
│  (dynamic)   client            image built from testdata/Dockerfile.client         │
│              MIT krb5 + ldap-utils + dnsutils; every test execs into it            │
│                                                                                    │
│  10.99.0.30  seeded.example.com     — DNS record only, no container                │
│  10.99.0.40  www.example.com        — DNS record only, created by a test           │
└────────────────────────────────────────────────────────────────────────────────────┘
```

The network is created with a fixed IPAM (`network.WithIPAM`, subnet `10.99.0.0/24`, gateway
`10.99.0.1`). The addresses are fixed because the DNS zone has to name them before the container
that owns them exists. Containers are pinned to their addresses with an
`EndpointSettingsModifier` (`fixedIP`) that edits the existing endpoint in place — replacing the
settings wholesale would drop the network aliases other containers resolve them by.

Only the management API port `5555/tcp` is exposed to the host (a Docker-mapped random port; the
harness derives `apiBase` as `http://<host>:<port>/api/v1`). Every other flow — Kerberos, LDAP,
DNS, OpenBao — runs strictly container-to-container.

### The three images

- **Service** — `ldap-kdc:e2e`, built by shelling out to
  `docker build --build-arg VERSION=e2e -t ldap-kdc:e2e .` from the repository root (`buildImage`). This is the shipped
  image: same `Dockerfile`, same `scratch` base, same
  unprivileged user, so anything proved here is proved about the release artifact. The build goes
  through the docker CLI rather than testcontainers' own builder because the Dockerfile
  cross-compiles via `BUILDPLATFORM`/`TARGETARCH`, which only BuildKit defines; the library's
  build path uses the daemon's older API where those expand to nothing and the build fails. The
  CLI also shares the BuildKit layer cache with ordinary local builds.
- **Client** — built from `test/e2e/testdata/Dockerfile.client` (Debian stable-slim with
  `krb5-user`, `ldap-utils`, `dnsutils`, `ca-certificates`, `curl`, `jq`, `openssl`;
  `CMD ["sleep", "infinity"]`).
  Built with `KeepImage: true`, so the image survives between runs and is not rebuilt unless the
  Dockerfile changes.
- **OpenBao** — built from `test/e2e/testdata/Dockerfile.openbao` (base
  `ghcr.io/openbao/openbao:latest`), also with `KeepImage: true`. The stock image carries neither
  the kerberos auth method nor a PKCS#11 seal — both live in the `openbao-plugins` collection now —
  so the image bakes in `openbao-plugin-auth-kerberos` (`KERBEROS_PLUGIN_VERSION=v0.1.0`, with its
  SHA-256 written next to it for `bao plugin register`) and `openbao-plugin-kms-pkcs11`
  (`PKCS11_PLUGIN_VERSION=v0.2.1`), plus SoftHSM initialized at build time with a token
  (`--label openbao --pin 1234 --so-pin 5678`) and an AES-32 key (`bao-root-key-aes`) for
  auto-unseal. The harness passes `TARGETARCH=<runtime.GOARCH>` as a build argument, mapped to
  `linux_amd64_v1` / `linux_arm64_v8` plugin assets. The server configuration (`testdata/openbao-config.hcl`) uses
  in-memory storage, plain HTTP on `0.0.0.0:8200`, declares
  the `kms "pkcs11"` plugin (a seal plugin must exist before the server unseals, so it cannot be
  registered through the API) and a `seal "pkcs11"` block pointing at the SoftHSM module.

The service container gets two files copied in at `/etc/ldap-kdc/ldap-kdc.yaml` and
`/etc/ldap-kdc/bootstrap.yaml`, and a `HostConfigModifier` sets the sysctl
`net.ipv4.ip_unprivileged_port_start=0` so the unprivileged process can bind 53, 88, 389 and
464 — the same arrangement the image documents. Startup waits are: `GET /readyz` on 5555 for the
service (60 s), listening port 8200 for OpenBao (120 s), and `wait.ForExec(["true"])` for the
client (60 s).

### Service configuration and bootstrap plan

The stand runs with this configuration (`serviceConfig`; see [configuration](configuration.md)
for the full key reference):

```yaml
server:
  realm: EXAMPLE.COM
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
  hostname: kdc.example.com
  addresses: [ 10.99.0.10 ]
  reverse_zones: [ 0.99.10.in-addr.arpa ]
api:
  listen: 0.0.0.0:5555
  token: e2e-token
bootstrap:
  file: /etc/ldap-kdc/bootstrap.yaml
```

The bootstrap plan (`bootstrapPlan`; see [bootstrap](bootstrap.md)) creates, before any listener
accepts a connection: groups `seeded` (gid 7000, with a `search *` capability), `svc` (7001),
`vault-users` (7002), `vault-enroll` (7003); the user `seeded-user` (password `the seeded account
password`, alias `seeded.alias`, member of `seeded` and `vault-users`); the service accounts
`svc-vault-enroll` and `svc-vault-ldap` (the latter with a password and a `search *` capability);
the principals `HTTP/seeded.example.com` and `HTTP/vault.example.com`; and A records
`seeded.example.com → 10.99.0.30` and `vault.example.com → 10.99.0.20`.

## DNS design

The client and OpenBao containers resolve through the service itself. `writeResolvConf` writes a
resolver file into a fresh temp directory:

```
nameserver 10.99.0.10
search example.com
```

and `useServiceDNS` bind-mounts it read-only over the container's `/etc/resolv.conf`. A mount on
top of a mount is the only way: Docker manages `/etc/resolv.conf` as a mount of its own, so
neither an image file nor a copied-in file could replace it.

The reason for displacing Docker's embedded DNS is reverse lookup. On a user-defined network
Docker puts its own resolver in `resolv.conf` and answers PTR queries itself — with container
names — which breaks Kerberos host canonicalization. The client's `krb5.conf` therefore
deliberately keeps `rdns = true` (the default, restored rather than avoided) and carries no
`[realms]` section at all:

```
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = true
    dns_lookup_kdc = true
    rdns = true
    forwardable = true
```

The OpenBao container gets the opposite — a `krb5.conf` with an explicit `kdc = kdc.example.com`
and `dns_lookup_realm = false` / `dns_lookup_kdc = false` — because a Kerberos configuration that
does not depend on DNS is one less moving part when the kerberos plugin reads it.

`TestDNSDiscovery` queries the server explicitly (`dig @10.99.0.10 +short ...`) rather than
through the resolver, because the resolver could be answered by Docker for names it happens to
know. That the resolver path works as a whole is what the `kinit` tests demonstrate. The test
asserts:

- `SRV _kerberos._udp.example.com` → `88 kdc.example.com.`
- `SRV _kpasswd._udp.example.com` → `464 kdc.example.com.`
- `SRV _ldap._tcp.example.com` → `389 kdc.example.com.`
- `TXT _kerberos.example.com` → `"EXAMPLE.COM"`
- `A kdc.example.com` → `10.99.0.10`, and `PTR 10.99.0.10` → `kdc.example.com.`
- `A vault.example.com` → `10.99.0.20`, and `PTR 10.99.0.20` → `vault.example.com.`

See [dns](dns.md) for the served zones and [kerberos](kerberos.md) for why canonicalization
matters.

## What the suite covers

All tests share the one stand; they run sequentially against it.

`test/e2e/e2e_test.go`:

- **TestDNSDiscovery** — the SRV/TXT/A/PTR records listed above, asked of the server directly.
- **TestNamesOutsideTheZoneAreRefused** — `dig A www.google.com` returns `status: REFUSED`; the
  name server is not an open resolver.
- **TestKinitFindsTheKDCThroughDNS** — user `alice` authenticates with a `krb5.conf` that names
  no KDC; a ticket here can only mean the SRV lookup worked, the A record resolved, and the KDC
  answered. `klist` shows `krbtgt/EXAMPLE.COM@EXAMPLE.COM` for `alice@EXAMPLE.COM`.
- **TestServiceTicketWithHostCanonicalization** — registers the principal
  `HTTP/www.example.com` and an A record `www.example.com → 10.99.0.40` (an address no container
  owns, so the reverse query falls through Docker's resolver to the zone under test), then checks
  that forward and reverse agree and that `kvno HTTP/www.example.com` — which canonicalizes the
  way any GSSAPI application would — produces a service ticket for that SPN.
- **TestForcedPasswordChange** — `carol` is provisioned with an expired password (`forceChange: true`); `kinit` answers
  "expired" rather than a ticket, `kpasswd` sets a new
  password, and the new password then works over both Kerberos and an LDAP simple bind while the
  old one is refused (the two credentials are set together).
- **TestLDAPSearch** — `dave` with no search capability sees exactly one entry in a subtree
  search: his own. A bind by principal name (`dave@EXAMPLE.COM`, UPN-style) reaches the same
  entry. After a search capability is granted, the entry shows `krbPrincipalName` and
  `ipaNTSecurityIdentifier: S-1-5-21-...`. See [directory](directory.md).
- **TestWrongPasswordIsRefused** — a wrong password fails `kinit` with "preauthentication
  failed" / "password incorrect".
- **TestBootstrappedDirectoryIsUsableImmediately** — the seeded account kinits with the
  password from the plan and is not asked to change it; the seeded A record answers forward and (derived from it) in
  reverse; `kvno HTTP/seeded.example.com` succeeds; an LDAP search shows
  `givenName: Seeded` and the plan-granted capability lets the account read the tree.
- **TestAnAliasReachesTheSameAccount** — `kinit seeded.alias` works with the account's own
  password and caches the ticket under the alias; `kinit -C` (CANONICALIZE) returns the real
  name `seeded-user@EXAMPLE.COM`. The directory entry publishes both `krbPrincipalName` values
  and a `krbCanonicalName`, the way FreeIPA does.
- **TestTheDocumentationShipsInTheImage** — `GET /docs/`, `/docs/swagger-ui-bundle.js` and
  `/openapi.json` answer 200 without a token, from the host. The image is `scratch`-based, so the
  embedded documentation surviving into it is what is under test. See [api](api.md).

`test/e2e/vault_test.go` (all three call `requireVault`, which skips when
`E2E_VAULT_IMAGE=off`):

- **TestVaultKerberosLoginIssuesUserCertificate** — `seeded-user` kinits, logs in to OpenBao
  with SPNEGO (`curl --negotiate -u :` against `/v1/auth/kerberos/login`), and the login response
  carries the `user-certs` policy — proving the kerberos plugin read the `vault-users` group
  membership from the directory, since nothing in OpenBao itself names that policy for the
  account. The test then has the PKI issue a certificate through `pki/issue/user` and verifies it
  with `openssl verify` against the CA fetched from `/v1/pki/ca/pem`.
- **TestVaultSwitchesToLDAPS** — rewrites the plugin's LDAP configuration to
  `url=ldaps://kdc.example.com` with the PKI's own CA as the trust anchor; a fresh kerberos login
  then binds and searches over LDAPS. The certificate on :636 is the one the service enrolled for
  itself during stand setup, and the test verifies it both with `openssl s_client` and with an
  LDAPS `ldapsearch` bound as `svc-vault-ldap`.
- **TestVaultIssuedCertificatePublishedInLDAP** — issues a user certificate, imports it through
  `POST /api/v1/users/seeded-user/certificates/import`, reads `userCertificate;binary` back over
  LDAP and compares the DER byte for byte with what the PKI issued.

## OpenBao setup

`setupVault` (called once from `newStand`) turns the freshly started OpenBao into the PKI the
scenario needs. The full explanation of why each piece exists is in
[openbao-pki](openbao-pki.md); the mechanics are:

1. `bao operator init -recovery-shares=1 -recovery-threshold=1` — with an auto-seal the barrier
   key goes to the HSM and init hands out recovery keys. The root token is kept for later calls.
2. `bao status` must report `sealed: false` — nobody runs `bao operator unseal`; the SoftHSM seal
   doing its job is part of what is under test.
3. Register the kerberos auth plugin (`bao plugin register -sha256=... auth kerberos`, the digest
   read from the image) and enable it with `-passthrough-request-headers=Authorization
   -allowed-response-headers=www-authenticate`, so the Negotiate challenge reaches the client.
4. Fetch the `HTTP/vault.example.com` keytab through the management API
   (`GET /api/v1/principals/HTTP%2Fvault.example.com/keytab`), base64-encode it into the
   container, and write `auth/kerberos/config` with `service_account=HTTP/vault.example.com` and
   `decode_pac=false` (the PAC this KDC issues is not one the plugin's Kerberos library can read;
   group membership comes from LDAP anyway).
5. Write `auth/kerberos/config/ldap` pointing at `ldap://kdc.example.com`, bound as
   `cn=svc-vault-ldap,ou=svc,ou=users,dc=example,dc=com`, with `userdn`/`groupdn`,
   `userattr=uid`, `groupattr=cn`, `upndomain=EXAMPLE.COM`.
6. Policies `user-certs` (`update` on `pki/issue/user`) and `enroll` (`update` on
   `pki/sign/ldaps`), mapped through `auth/kerberos/groups/vault-users` and
   `auth/kerberos/groups/vault-enroll`.
7. Mount `pki`, tune `max-lease-ttl=87600h`, generate an internal root (`common_name=example.com`),
   and create the roles `user` (`allow_any_name=true`, `enforce_hostnames=false`,
   `max_ttl=720h`) and `ldaps` (`allowed_domains=kdc.example.com`, `allow_bare_domains=true`,
   `allow_ip_sans=true`, `key_type=any`, `max_ttl=8760h`).
8. Enroll the service itself for its LDAPS certificate via `PUT /api/v1/vault/config`
   (principal `svc-vault-enroll`, role `ldaps`, `common_name=kdc.example.com`,
   `san_dns=[kdc.example.com]`, `san_ips=[10.99.0.10]`, `ttl=720h`, `renew_before=24h`,
   `retry_interval=5s`) and poll `GET /api/v1/vault/status` until `enrolled` is true (90 s
   deadline, 2 s interval). This is the first kerberos login the mount sees.

## Running the suite

```sh
make e2e                          # cd test/e2e && go test -timeout 900s ./...
E2E_VAULT_IMAGE=off make e2e      # stand without OpenBao; the three vault tests skip
```

Or directly, with the usual `go test` flags:

```sh
cd test/e2e
go test -v -run TestDNSDiscovery ./...
go test -timeout 900s ./...       # keep the 15-minute budget make e2e sets
```

Notes:

- A container runtime is required; without one the suite prints a skip message and passes.
- The first run builds all three images. The client and OpenBao images are built with
  `KeepImage: true` and reused across runs; `ldap-kdc:e2e` is rebuilt on every run, but through
  the shared BuildKit cache an unchanged tree rebuilds in seconds.
- `-v` shows the `e2e vault setup: ...` progress lines the harness writes to stderr.
- Each command executed in a container has a 60 s deadline (`run`, `mustRun`, `mustVaultExec`).
- Cleanup removes the containers, the network and the temporary resolv.conf directory, in reverse
  order of creation.

### CI

`.github/workflows/test.yml` runs `make e2e` on `ubuntu-latest` after `gofmt`, `make vet` and
`make test`, on every branch push, pull request and `workflow_call` (the release workflow calls
it). A GitHub runner always has a container runtime, which is exactly where a suite with this
purpose belongs. The job timeout is 30 minutes; the Go module cache keys include
`test/e2e/go.sum` alongside the main `go.sum`.

## Adding a test

Add a `TestXxx` function to `e2e_test.go`, or to a new `_test.go` file in `package e2e` if it has
its own theme (the vault tests live in `vault_test.go`). The stand is already running — use the
package-level `shared`:

- `shared.run(t, script)` / `shared.mustRun(t, script)` — run `sh -c script` in the client
  container; `mustRun` fails the test on a non-zero exit. Output is multiplexed stdout+stderr.
- `shared.api(t, method, path, body)` / `shared.mustAPI(t, method, path, body, want...)` — call
  the management API from the host with the suite's bearer token; `mustAPI` fails unless the
  status is one of `want`. `shared.apiRaw` is the variant for non-JSON responses.
- `shared.addUser(t, name, password, forceChange)` — creates a user in a shared `e2e` group (gid
  6000); the group creation tolerates `409 Conflict` so every test can call it.
- Helpers `dig`, `kinit`/`kinitTo`, `ldapsearch`/`ldapsearchDN` build the client commands. Named
  credential caches (`kinitTo`) keep one test's tickets out of another's `klist`.
- Vault tests must start with `requireVault(t)` so they skip under `E2E_VAULT_IMAGE=off`, and use
  `shared.mustVaultExec` to run `bao` commands in the OpenBao container as root.

Tests share one stand and do not run in parallel — do not call `t.Parallel()`, and prefer the
seeded objects over provisioning new ones where the plan already has what you need. Keep the
suite inside the 15-minute budget `make e2e` sets (`-timeout 900s`); a new test should cost
seconds, not minutes.

## Conflict with the docker-compose stand

The [docker-compose stand](docker-compose.md) uses the same fixed subnet — `10.99.0.0/24` with
gateway `10.99.0.1`, the service at `10.99.0.10` and OpenBao at `10.99.0.20` — because it is
wired the way this suite wires its containers. Docker will not create two networks with
overlapping subnets, so `make e2e` fails while the compose stand is up (and vice versa). Stop the
compose stand (`docker compose down`) before running the end-to-end suite, or run the suite
first.
