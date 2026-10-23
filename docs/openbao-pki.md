# OpenBao / Vault PKI integration

ldap-kdc holds no certificate authority of its own. In a test rig the CA is one more thing to
operate, and OpenBao (or HashiCorp Vault — the API is the same) already is one. The integration
described here lets the service do two things with that CA:

1. **Enroll its own LDAPS certificate.** The service logs in to OpenBao over Kerberos — against
   its own KDC — and has the PKI secrets engine sign a CSR for the name the LDAPS listener
   answers for. The private key is generated locally and never leaves the service; only the CSR
   crosses the wire.
2. **Publish externally issued user certificates through LDAP.** A certificate OpenBao issued to
   a person can be imported through the management API and appears as `userCertificate;binary`
   on the account's entry.

Everything is wired at run time through the REST API, not in the configuration file: the
integration is a relationship with a deployment's OpenBao, not a property of one configuration.
An untouched service behaves exactly as before.

## The bootstrap sequence

The order matters, and each step is described in detail further down:

```
1. ldap-kdc starts. The LDAPS listener comes up WITHOUT a certificate (ldaps.enabled with no
   cert_path); TLS handshakes fail until step 5 lands one.
2. The bootstrap plan creates the directory objects the integration needs: the service
   principal OpenBao will expect tickets for, the account ldap-kdc will log in as, the bind
   account OpenBao will read groups through, and the DNS name of the OpenBao container.
3. OpenBao starts and is initialized. The management API hands over the service principal's
   keytab; the kerberos auth method, its LDAP group lookup, the policies and the PKI engine
   are configured.
4. PUT /api/v1/vault/config tells ldap-kdc where OpenBao is. The enrollment loop starts:
   Kerberos login -> CSR -> sign -> certificate.
5. The LDAPS listener begins serving the enrolled certificate. The loop renews it before
   expiry; the listener is never restarted.
6. OpenBao's kerberos auth is switched from ldap:// to ldaps:// — the integration is what
   makes the secure connection possible at all.
```

Step 4 tolerates OpenBao not being ready yet: a failed enrollment waits `retry_interval` and
tries again, so the service never blocks on the CA.

## Directory objects the integration needs

All of them are plain bootstrap-plan entries (see `compose/bootstrap.yaml` for a complete,
working example):

| Object                           | Kind               | Purpose                                                                                                                                                                            |
|----------------------------------|--------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `HTTP/vault.example.com`         | service principal  | What OpenBao's kerberos auth method expects tickets for. No password — random keys; the keytab leaves through the API exactly once, into OpenBao.                                  |
| `svc-vault-enroll`               | user, no password  | The account ldap-kdc authenticates to OpenBao as. Random keys that live in the store and never leave it — the enrollment builds its keytab in memory.                              |
| `svc-vault-ldap`                 | user with password | The bind account the kerberos auth method reads the directory (users and groups) through. Needs the `search` capability on `*`, or the directory only ever shows it its own entry. |
| `vault-users`                    | group              | Members map to the `user-certs` policy — they may pull certificates from the PKI role.                                                                                             |
| `vault-enroll`                   | group              | Maps `svc-vault-enroll` to the `enroll` policy — the right to call `pki/sign/ldaps` and nothing else.                                                                              |
| `vault.example.com A 10.99.0.20` | DNS record         | The name everything — clients, ldap-kdc, the kerberos plugin — resolves OpenBao by.                                                                                                |

## How the enrollment works

The implementation lives in `internal/vaultpki` and runs as a background loop inside the
service:

1. **Keytab from the store.** The configured principal's current keys are read from the store (`GetPrincipalKVNO`),
   marshalled into an in-memory keytab (`krbkeys.MarshalKeytab`), and
   handed to the Kerberos client library. No file, no password, nothing on disk.
2. **Tickets from the KDC that runs in the same process.** The client is configured with the
   service realm and `127.0.0.1:<kdc port>` as the KDC, DNS discovery off. It does an AS
   exchange for the login principal and a TGS exchange for `HTTP/<host of the Vault address>`
   (or `service_principal` if overridden).
3. **SPNEGO login.** The service ticket goes into a Negotiate token, posted to
   `/v1/auth/kerberos/login`. OpenBao answers with a client token carrying whatever policies
   the account's LDAP groups map to.
4. **A fresh key and a CSR.** An ECDSA P-256 key is generated, and a CSR is built with the
   configured common name and SANs. The key never leaves the process.
5. **Signing.** `POST /v1/<pki_path>/sign/<role>` with the CSR and the requested TTL. The
   returned certificate (with the issuing CA appended) and the local key become the listener's
   `tls.Certificate`.
6. **Renewal.** The loop sleeps until `not_after - renew_before`. If the PKI handed back less
   lifetime than that — a role's `max_ttl` shorter than the requested `ttl` — the window is
   already open, and the loop renews at two thirds of the lifetime actually granted instead, so
   a short lifetime costs one issuance per two thirds of it rather than one every few seconds.
   A warning is logged when this happens; the fix is on the PKI side, or a `ttl` the role allows.
   The loop then enrolls again. The new
   certificate is swapped into an atomic holder; the listener's `tls.Config` reads it through
   `GetCertificate`, so ongoing and new handshakes pick it up with no restart.

Any failure at any step — OpenBao down, sealed, role missing, policy denied — is recorded as
`last_error` and retried every `retry_interval`. The service itself never blocks.

### Deferred LDAPS

`ldaps:` with `enabled: true` and **no** `cert_path`/`key_path` is the configuration that makes
this a bootstrap sequence rather than a chicken-and-egg problem: the listener starts on its
port immediately, handshakes fail with "no certificate yet" until the first enrollment lands,
and from then on the enrolled certificate is served. Set both paths and the certificate comes
from disk as before — the enrollment machinery can still be configured, but nothing requires
it. One path without the other remains a configuration error. `readyz` does not wait for the
certificate: a realm that enrolls from a CA is up before its CA is.

## API reference

All endpoints require the management bearer token, like everything else under `/api/v1`.
Durations are Go duration strings (`720h`, `5s`).

### `PUT /api/v1/vault/config`

Installs the integration and starts the enrollment loop. A repeated PUT reconfigures and
restarts it. The configuration lives in memory — a restart of the service forgets it, which
suits the rig model where the harness sets everything up from scratch.

```json
{
  "address": "https://vault.example.com:8200",
  "principal": "svc-vault-enroll",
  "service_principal": "HTTP/vault.example.com",
  "pki_path": "pki",
  "role": "ldaps",
  "common_name": "kdc.example.com",
  "san_dns": [
    "kdc.example.com"
  ],
  "san_ips": [
    "10.99.0.10"
  ],
  "ttl": "720h",
  "renew_before": "24h",
  "retry_interval": "5s"
}
```

| Field               | Required | Default                  | Meaning                                                                                                  |
|---------------------|----------|--------------------------|----------------------------------------------------------------------------------------------------------|
| `address`           | yes      | —                        | OpenBao base URL; must be `https`, or `http` with `plaintext`. The host part also names the SPN unless overridden. |
| `plaintext`         | no       | `false`                  | Allows an `http` address. The SPNEGO token and OpenBao's token then cross the network unencrypted; for test rigs only. |
| `principal`         | yes      | —                        | Principal in this realm the login authenticates as. Must exist in the store, or the call fails with 400. |
| `service_principal` | no       | `HTTP/<host of address>` | The principal OpenBao's kerberos auth expects a ticket for.                                              |
| `pki_path`          | no       | `pki`                    | Mount of the PKI secrets engine.                                                                         |
| `role`              | yes      | —                        | The role the CSR is signed under.                                                                        |
| `common_name`       | yes      | —                        | Subject CN — the name LDAPS answers for.                                                                 |
| `san_dns`           | no       | —                        | DNS subject alternative names.                                                                           |
| `san_ips`           | no       | —                        | IP subject alternative names; each must parse as an IP.                                                  |
| `ttl`               | no       | `720h`                   | Lifetime asked of the PKI (the role's `max_ttl` may clamp it). Must exceed `renew_before`.               |
| `renew_before`      | no       | `24h`                    | How long before expiry the certificate is replaced.                                                      |
| `retry_interval`    | no       | `5s`                     | Backoff between failed enrollments. Must be positive.                                                    |

Responds `200` with the status body (below). Validation failures are `400`.

### `GET /api/v1/vault/status`

```json
{
  "configured": true,
  "enrolled": true,
  "not_after": "2026-10-29T12:00:00Z",
  "last_error": "",
  "attempts": 1
}
```

`attempts` counts enrollment tries since the last configure; `last_error` holds the most recent
failure (an empty string once an enrollment has succeeded after earlier failures is not
guaranteed — check `enrolled`).

### `DELETE /api/v1/vault/config`

Stops the loop and forgets the configuration (`204`). The LDAPS listener keeps serving its
last certificate.

### `POST /api/v1/users/{name}/certificates/import`

Takes a certificate an external CA issued to the account and stores it:

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n..."
}
```

`201` with the stored metadata; `400` for unparseable PEM or a non-positive serial number;
`404` for an unknown user; `409` when a certificate with the same serial from the same issuer is
already stored.
The service keeps no private keys and offers no issuance or revocation here — those are the
CA's job; what it stores is public by nature.

### `GET /api/v1/users/{name}/certificates`

Lists the account's imported certificates as metadata (no DER):

```json
{
  "certificates": [
    {
      "serial": "01abc...",
      "subject": "CN=...",
      "notBefore": "...",
      "notAfter": "...",
      "createdAt": "..."
    }
  ]
}
```

The issuer is the certificate's authority key identifier in lowercase hex, empty when the
certificate carries none. Serial numbers are unique per issuer, not across the store: two
authorities may both issue serial `2a`, and each certificate is named by its issuer and serial
together.

The serial is the lowercase hex form of the certificate's serial number, zero-padded to an
even length. It is stored as text because an external CA's serial need not fit an integer —
OpenBao issues 160-bit serials. Lookups normalize the same way, so `AB`, `ab` and `0ab` name
the same certificate.

### LDAP publication

Every stored certificate whose validity window covers the current time is published on the
account's entry as `userCertificate;binary`, one value per certificate, raw DER. Expired
certificates stay in the store but leave the entry; deleting the user deletes the certificates (`ON DELETE CASCADE`).

## Setting up OpenBao

A complete, tested reference is `compose/setup.sh` — what follows explains what it does and
why. Two OpenBao 2.x specifics shape everything:

- **The kerberos auth method is an external plugin** (`openbao-plugin-auth-kerberos`), not part
  of the server binary. It must sit in the `plugin_directory` before the server starts and be
  registered with its SHA-256.
- **Auto-unseal against PKCS#11 needs the KMS plugin** (`openbao-plugin-kms-pkcs11`) — the OSS
  server binary has no built-in `pkcs11` seal. A seal plugin cannot be registered through the
  API (it must exist before unseal, which is before any API call), so it is declared in the
  server configuration instead:

```hcl
plugin "kms" "pkcs11" {
  command = "openbao-plugin-kms-pkcs11"
  version = "v0.2.1"
}

seal "pkcs11" {
  lib = "/usr/lib/softhsm/libsofthsm2.so"
  token_label = "openbao"
  pin = "1234"
  key_label = "bao-root-key-aes"
}
```

The stand's image (`test/e2e/testdata/Dockerfile.openbao`) bakes in both plugins, SoftHSM with
an initialized token, and a pre-generated AES-256 root key — OpenBao deliberately does not
create key material in an HSM itself, so `pkcs11-tool --keygen` runs at image build. With an
auto-seal, initialization uses **recovery** shares, not key shares, and no `operator unseal`
ever runs:

```sh
bao operator init -recovery-shares=1 -recovery-threshold=1 -format=json
```

### Kerberos auth

```sh
bao plugin register -sha256=<sha256 of the plugin binary> \
    -command=openbao-plugin-auth-kerberos auth kerberos
bao auth enable -passthrough-request-headers=Authorization \
    -allowed-response-headers=www-authenticate kerberos
bao write auth/kerberos/config keytab=@vault.keytab.b64 \
    service_account=HTTP/vault.example.com decode_pac=false
bao write auth/kerberos/config/ldap \
    url=ldap://kdc.example.com \
    binddn=cn=svc-vault-ldap,ou=svc,ou=users,dc=example,dc=com \
    bindpass='...' \
    userdn=ou=users,dc=example,dc=com \
    groupdn=ou=groups,dc=example,dc=com \
    userattr=uid groupattr=cn upndomain=EXAMPLE.COM
```

Details that cost time if missed:

- The keytab is a base64 string. The harness fetches it from
  `GET /api/v1/principals/HTTP%2Fvault.example.com/keytab` and encodes it in Go — a shell
  `base64` on a minimal container wraps lines and breaks the decode.
- `decode_pac=false` matters: by default the plugin tries to parse the PAC in our tickets, the
  gokrb5 PAC parser rejects it, and the login fails. Group membership comes from LDAP anyway.
- `userattr=uid` is required because the entry's RDN is `cn` while the login name lives in
  `uid`. The group directory holds `groupOfUniqueNames` entries with `uniqueMember`, which the
  plugin's default group filter already matches.
- The plugin needs a `/etc/krb5.conf` (or working DNS discovery) to find the KDC.
- The initial `url=ldap://...` is intentional — LDAPS does not exist yet. After enrollment
  lands, switch with just the delta (the plugin merges with the stored config):

```sh
bao write auth/kerberos/config/ldap url=ldaps://kdc.example.com certificate=@openbao-ca.pem
```

### Policies and group mapping

```sh
bao policy write user-certs - <<'EOF'
path "pki/issue/user" { capabilities = ["update"] }
EOF
bao policy write enroll - <<'EOF'
path "pki/sign/ldaps" { capabilities = ["update"] }
EOF
bao write auth/kerberos/groups/vault-users policies=user-certs
bao write auth/kerberos/groups/vault-enroll policies=enroll
```

The group names are the LDAP groups' `cn`s. A login token then carries the policies of every
group the account belongs to — this is the group-membership path the end-to-end suite asserts
on.

### The PKI engine

```sh
bao secrets enable pki
bao secrets tune -max-lease-ttl=87600h pki          # a 10-year root needs the mount raised first
bao write pki/root/generate/internal common_name=example.com ttl=87600h
bao write pki/roles/user allow_any_name=true enforce_hostnames=false max_ttl=720h
bao write pki/roles/ldaps allowed_domains=kdc.example.com allow_bare_domains=true \
    allow_ip_sans=true key_type=any max_ttl=8760h
```

`key_type=any` on the `ldaps` role is load-bearing: the role defaults to RSA and refuses the
service's ECDSA CSR with "role requires keys of type rsa". `allow_ip_sans=true` is what lets
the certificate carry the listener's IP address.

## Security notes

- This is a testing rig. The compose stand's passwords, the SoftHSM PIN and the API token are
  public by construction. The OpenBao listener is plain HTTP, so the stand's enrollment sends
  `"plaintext": true` explicitly; a production configuration uses an `https` address and never
  sets it.
- The enrollment principal and the Vault service principal both hold random keys that exist
  only in the store (and, for the latter, in the one keytab handed to OpenBao). Rotate either
  with `POST /api/v1/principals/{name}/password {"randomize": true}`; the previous key version
  is kept, so OpenBao keeps accepting tickets until its keytab is refreshed.
- The management token can do everything here — enroll, import, re-key anyone. Bind the API to
  loopback or set `api.token`, as the operational notes say.
- The configuration is in-memory: nothing about the integration survives a service restart, so
  a database copy does not carry OpenBao tokens either (the Vault token itself is never
  persisted).

## Troubleshooting

| Symptom                                                                       | Likely cause                                                                                                                                                        |
|-------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `GET /api/v1/vault/status` shows `last_error: ... connection refused` forever | OpenBao is not up or not reachable by that name from the service container; the loop keeps retrying — fix the address and PUT again.                                |
| `last_error: ... 403` on sign                                                 | The login principal's groups do not map to a policy allowing `pki/sign/<role>`; check `auth/kerberos/groups` and the LDAP group membership.                         |
| `last_error: role requires keys of type rsa`                                  | The PKI role predates `key_type=any` — see the role command above.                                                                                                  |
| Kerberos login to OpenBao fails with a PAC parse error                        | `decode_pac` left at its default `true`.                                                                                                                            |
| Login succeeds but the token has no expected policies                         | Group lookup failed: bind account without the `search` capability, wrong `userattr`, or the group name in `auth/kerberos/groups` is not the LDAP `cn`.              |
| `bao operator init` answers "not applicable to seal type pkcs11"              | You passed `-key-shares` to an auto-sealed server; use `-recovery-shares`.                                                                                          |
| `/v1/sys/health` returns 501 before init regardless of query flags            | Known OpenBao 2.7 behavior — poll `/v1/sys/init` instead.                                                                                                           |
| `kinit`/SPNEGO canonicalizes the Vault SPN to a container name                | Docker's embedded DNS answered the PTR query itself. Point the container's resolver at ldap-kdc (the e2e rig bind-mounts its own `resolv.conf`; see `docs/e2e.md`). |
| Import answers 409 on a fresh certificate                                     | Serial collision — the serial is unique per issuer; the same serial from the same issuer is already stored. Delete the old entry first.                             |
| The certificate is imported but absent from LDAP                              | It is outside its validity window; only in-window certificates are published.                                                                                       |
