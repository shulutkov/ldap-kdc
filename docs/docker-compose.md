# The Docker Compose stand

`docker-compose.yaml` at the repository root runs ldap-kdc and OpenBao the way the end-to-end
suite wires them — but standing still, for poking at by hand:

```sh
docker compose up -d --build
./compose/setup.sh
```

When `setup.sh` finishes, the stand has: a realm `EXAMPLE.COM` with a demo user `alice`;
OpenBao initialized and auto-unsealed, its kerberos auth method reading this directory; a PKI
root CA with roles for user and server certificates; ldap-kdc's LDAPS listener serving a
certificate enrolled from that CA; and the kerberos auth method talking to the directory over
LDAPS. Everything below explains the pieces.

## Podman

The same stand runs under Podman, with four differences from Docker. Each is about the Podman
socket or about the network's resolver.

**The socket.** Registration reads the container list and events from the Podman API socket, which
Podman provides through systemd. Enable it, then point `dns.docker.endpoint` at it:

```sh
systemctl --user enable --now podman.socket      # rootless
sudo systemctl enable --now podman.socket        # rootful
```

```yaml
dns:
  docker:
    endpoint: unix:///run/podman/podman.sock       # rootful; rootless: $XDG_RUNTIME_DIR/podman/podman.sock
```

**SELinux and the socket.** On an SELinux host the socket carries the label `var_run_t`, and a
container's default label does not let it connect to that socket. Two ways out, and the choice is
yours:

- `security_opt: ["label=disable"]` on the `ldap-kdc` service. Simple, and it lifts SELinux
  confinement for that one container: the KDC process is no longer isolated by the policy.
- Give the socket a label the policy allows the container to use, so the container keeps its
  confinement. This is the cleaner option, and it is the one to prefer where the policy can be
  adjusted.

**Root.** The socket of a rootful Podman is root's: any client that can talk to it can start a
container with the host's root filesystem. Mounting it read-only does not change that, because
the API is reached over the socket, not through the file. The service gets the socket's group (`group_add`) and reads
it; it does not run as root. Treat the mount as root on the host.

**The resolver.** On a network with Podman's DNS enabled, Podman (aardvark) puts its own address
into each container's `resolv.conf` (`10.99.0.1` on the stand's subnet) and answers names and
reverse queries itself. A reverse query for `10.99.0.31` then yields the container's short name (`nn`), not the zone's
name (`nn.example.com`), and Kerberos host canonicalization breaks. Create
the network with DNS disabled, so every query goes to ldap-kdc:

```sh
podman network create --disable-dns --subnet 10.99.0.0/24 example.com
```

Then mark the network `external: true` in the compose file and make the containers use the
service's address as their resolver (`dns: 10.99.0.10` and `dns_search: example.com`). Recreating
the network and the containers keeps the volumes, so the data survives.

## Layout

```
docker-compose.yaml        the two services and the network
compose/ldap-kdc.yaml      the service configuration (realm, listeners, DNS zone, API token)
compose/bootstrap.yaml     the directory the stand comes up with
compose/krb5.conf          the Kerberos client configuration inside the OpenBao container
compose/setup.sh           the wiring: init, plugins, auth, PKI, enrollment, the switch to LDAPS
compose/vault-keys.json    created by setup.sh: OpenBao's root token and recovery key (0600,
                           git-ignored — never commit it)
```

The network is `ldap-kdc-example`, `10.99.0.0/24`, with fixed addresses — ldap-kdc at
`10.99.0.10`, OpenBao at `10.99.0.20` — because the DNS zone and the enrollment name the
addresses before the containers exist. **The stand shares this subnet with the end-to-end
suite**, so the two cannot run at the same time: `docker compose down` before `make e2e`.

## What runs

### ldap-kdc

Built from the repository's own Dockerfile (`ldap-kdc:compose`), configured by
`compose/ldap-kdc.yaml`. Two things to notice in that file:

- `ldaps: { enabled: true }` with **no certificate paths** — the deferred listener that waits
  for the enrollment (see `docs/openbao-pki.md`).
- `dns` serves the zone `example.com` from the fixed address, with the reverse zone, so the
  OpenBao container and any client you attach resolve `kdc.example.com` and
  `vault.example.com` from the service itself. Port 53 is deliberately not published — DNS
  lives inside the network, and publishing it on a desktop asks for conflicts.

Published on `127.0.0.1`: `5555` (management API), `389`, `636`, `464` and `88` (TCP and UDP).
The process runs unprivileged and still binds 53/88/389/464 inside its namespace thanks to the
`net.ipv4.ip_unprivileged_port_start=0` sysctl in the compose file. The healthcheck is the
binary's own `ldap-kdc health` — the scratch image carries neither shell nor wget — and OpenBao
waits for it (`depends_on: service_healthy`).

### OpenBao

Built from `test/e2e/testdata/Dockerfile.openbao` — the stand's own image with the kerberos
auth plugin, the pkcs11 KMS plugin, a SoftHSM token and the server configuration baked in (auto-unseal; see
`docs/openbao-pki.md` for why it looks this way). It resolves names through
ldap-kdc (`dns: 10.99.0.10`) and mounts `compose/krb5.conf` so the kerberos plugin finds the
KDC. Published on `127.0.0.1:8200` (plain HTTP — nothing leaves the Docker network).

## What setup.sh does

The script is idempotent — run it again and every step that is already done is skipped. It
needs only `curl`, `jq` and `docker compose` on the host; every `bao` invocation runs inside
the OpenBao container. In order:

1. Waits for ldap-kdc's `/readyz` and for OpenBao to answer `/v1/sys/init` (OpenBao 2.7
   returns 501 on `/v1/sys/health` before initialization regardless of the query flags, so the
   init endpoint is the reliable probe).
2. Initializes OpenBao — `-recovery-shares=1 -recovery-threshold=1`, because an auto-sealed
   server has recovery keys, not unseal keys — and saves the root token and recovery key to
   `compose/vault-keys.json` (mode 0600). Then confirms the server unsealed itself. On reruns
   the token is read from that file; if OpenBao was reinitialized while the file survived, the
   script says so and tells you to `docker compose down -v`.
3. Fetches the `HTTP/vault.example.com` keytab through the management API, registers the
   kerberos plugin by the SHA-256 baked into the image, and enables the auth method with the
   Authorization passthrough it needs.
4. Configures the auth method: the keytab and service account, then the LDAP connection (`ldap://kdc.example.com` for
   now — LDAPS does not exist yet) with the bind account
   `svc-vault-ldap`.
5. Writes the `user-certs` and `enroll` policies and maps the LDAP groups `vault-users` and
   `vault-enroll` to them.
6. Enables the PKI engine, generates the root CA, and creates the `user` and `ldaps` roles.
7. Calls `PUT /api/v1/vault/config` on ldap-kdc and polls `/api/v1/vault/status` until the
   enrollment lands (failures are reported with the loop's `last_error`).
8. Switches the auth method's LDAP connection to `ldaps://kdc.example.com` with the freshly
   minted CA as the trust anchor — the stand's end state is Kerberos over LDAPS.

## Trying it out

The stand's Kerberos and LDAP ports are published, so host tools work against `127.0.0.1` —
but a host `krb5.conf` needs an explicit realm block because the zone's SRV records point at
the container addresses, and reverse lookups of those addresses are answered by Docker itself
rather than by the zone, so `rdns` must be off:

```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    rdns = false

[realms]
    EXAMPLE.COM = {
        kdc = 127.0.0.1:88
    }
```

```sh
kinit alice@EXAMPLE.COM                 # password: alice demo password
```

The more faithful client is a throwaway container inside the stand's network, where the zone
resolves everything (the e2e client image carries MIT krb5, curl with GSS-API, jq and openssl;
building it once is what the `docker build` line does):

```sh
docker build -t ldap-kdc-e2e-client -f test/e2e/testdata/Dockerfile.client test/e2e/testdata

docker run --rm -it --network ldap-kdc-example --dns 10.99.0.10 \
  ldap-kdc-e2e-client bash
```

Inside it, the whole integration is one login away:

```sh
# Kerberos login to OpenBao — the token carries user-certs via alice's LDAP group
printf 'alice demo password\n' | kinit alice@EXAMPLE.COM
TOKEN=$(curl -s --negotiate -u : -X POST \
  http://vault.example.com:8200/v1/auth/kerberos/login | jq -r .auth.client_token)

# A user certificate from the PKI role
curl -s -H "X-Vault-Token: $TOKEN" -X POST \
  -d '{"common_name":"alice.example.com","ttl":"24h"}' \
  http://vault.example.com:8200/v1/pki/issue/user | jq -r .data.certificate > alice.pem
curl -s http://vault.example.com:8200/v1/pki/ca/pem > ca.pem
openssl verify -CAfile ca.pem alice.pem

# Back into the directory: import and read through LDAP(S)
curl -s -X PUT -H "Authorization: Bearer compose-token" \
  -H 'Content-Type: application/json' \
  --data "$(jq -n --arg pem "$(cat alice.pem)" '{certificate:$pem}')" \
  http://127.0.0.1:5555/api/v1/users/alice/certificates/import        # run on the host

LDAPTLS_CACERT=ca.pem ldapsearch -x -H ldaps://kdc.example.com:636 \
  -D "cn=svc-vault-ldap,ou=svc,ou=users,dc=example,dc=com" \
  -w 'vault ldap bind password' \
  -b "cn=alice,ou=users,ou=users,dc=example,dc=com" 'userCertificate;binary'
```

(The exact base DN of alice's entry depends on her primary group —
`cn=alice,ou=users,ou=users,dc=example,dc=com` for the shipped bootstrap plan; check with a
plain search if in doubt.)

The management API is at `http://127.0.0.1:5555` with the token `compose-token`
(`/api/docs` renders the OpenAPI document in a browser), and OpenBao's UI/API is at
`http://127.0.0.1:8200` with the root token from `compose/vault-keys.json`.

## Tearing down and resetting

```sh
docker compose down        # stop, keep the database and the CA
docker compose down -v     # also drop the ldap-kdc volume — the realm starts over
```

`down -v` does not remove `compose/vault-keys.json`; `setup.sh` overwrites it when it
reinitializes OpenBao, so there is nothing to clean by hand. OpenBao's own storage is
in-memory — every container start is an uninitialized server, which is why `setup.sh` exists
as a script rather than a container.

## Customizing

- **Realm and domain**: edit `compose/ldap-kdc.yaml` (`server.realm`, the DNS zone is derived
  from the domain) and `compose/bootstrap.yaml` together, plus `compose/krb5.conf`, then
  `down -v` — a realm name cannot change on an existing database.
- **More users**: add them to `compose/bootstrap.yaml` (bootstrap is create-only; existing
  objects are left alone) or through the API.
- **Another OpenBao / plugin version**: the build args at the top of
  `test/e2e/testdata/Dockerfile.openbao` (`KERBEROS_PLUGIN_VERSION`,
  `PKCS11_PLUGIN_VERSION`) — remember the compose file and the e2e harness share that image.
