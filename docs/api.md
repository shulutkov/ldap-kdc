# REST management API

The REST management API is the control surface of ldap-kdc: it is where accounts, groups,
Kerberos principals and their credentials, DNS records, cross-realm trusts and the Vault PKI
integration are created and changed. Every write reaches both sides of the directory at once —
setting a password stores the bcrypt digest an LDAP simple bind compares against and the
long-term keys a Kerberos AS exchange needs.

All management endpoints live under the base URL `/api/v1` on the address `api.listen`
(default `127.0.0.1:5555`; see [configuration](configuration.md)). When `api.tls` is set, the
listener serves HTTPS with `api.cert_path` / `api.key_path`. If `api.listen` and `oidc.listen`
are written as the same address, the management API and the console ride on the OpenID
provider's listener instead of binding their own — one name and no port for the whole
directory ([architecture](architecture.md), [OIDC provider](oidc.md)).

The [administrators' console](console.md) at `/ui/` (enabled by `api.ui`, default `true`) is a
client of this API: everything the page does, it does through these endpoints as the
administrator who signed in.

## Authentication

There is no anonymous access to `/api/v1`. Every request carries
`Authorization: Bearer <token>`, where the token is one of two kinds:

- **Management token** — the value of `api.token` (or the trimmed contents of
  `api.token_file`, which is how the secret is kept out of the configuration file). Accepted on
  every `/api/v1` request beside administrators' sessions; it never expires. This is the
  credential for automation. If no token is configured and the listener is bound to something
  other than loopback, the service logs a loud warning at start: anyone who can reach the port
  can change any password.
- **Administrator session** — a short-lived JWS obtained from a sign-in endpoint (below). Only
  an account that may write the whole directory (a *directory administrator*) is admitted. The
  session is checked against the directory as it is *now* on every request: an administrator
  who is disabled or loses the capability loses the API at the next request, not when the
  token runs out.

A refused request gets `401 Unauthorized` with a `WWW-Authenticate: Bearer realm="ldap-kdc"`
header.

### Open paths

These endpoints sit outside the bearer check, so orchestrators, scrapers and browsers do not
need a credential that can change passwords:

| Path                                    | Why it is open                                  |
|-----------------------------------------|-------------------------------------------------|
| `GET /healthz`                          | liveness probe                                  |
| `GET /readyz`                           | readiness probe                                 |
| `GET /metrics`                          | Prometheus scrape                               |
| `POST /api/v1/auth/login`               | sign-in with a password                         |
| `GET /api/v1/auth/negotiate`            | sign-in with Kerberos (SPNEGO)                  |
| `GET /api/openapi.json`                 | the OpenAPI document, when `api.docs` is on     |
| `GET /api/docs` and `GET /api/docs/...` | Swagger UI, when `api.docs` is on               |
| `GET /ui/...` and `GET /`               | the console's static files, when `api.ui` is on |

Everything else — including the authenticated copy of the OpenAPI document at
`GET /api/v1/openapi.json` — requires the bearer token.

### Signing in

**Password:** `POST /api/v1/auth/login`

```json
{
  "login": "admin",
  "password": "the account's password"
}
```

`login` is an account name or its mail address. Where the account has a one-time code, it is
appended to the password, exactly as for an LDAP bind. An application password is refused here:
it exists for programs that cannot be handed a one-time code, and accepting it would let the
console be opened with a credential that skips the account's second factor. Only the account's
own password signs in.

Failed attempts count towards the same per-address failure limiter as failed LDAP binds — a
guesser blocked at one door is blocked at both — and the reason for a refusal is deliberately
one message (`incorrect login or password`, 401) for "no such account", "wrong password" and
"disabled" alike. A blocked source address gets `429 Too Many Requests`. A valid account that
does not administer the directory gets `403 Forbidden`.

**Kerberos:** `GET /api/v1/auth/negotiate`

SPNEGO: the endpoint answers with a `Negotiate` challenge, which a browser configured to trust
the host answers with its ticket for the principal named by `api.spn`
(`HTTP/<host name the console is reached by>`). The service creates that principal with random
keys at start when missing — it is its own KDC, so no keytab is written anywhere. Only this
realm's tickets sign in (a trusted realm's do not), the ticket must belong to a directory
account, and that account must administer the directory. When `api.spn` is empty the endpoint
answers `404`. See [console](console.md) for the browser side.

**Success response (both):** `200 OK`

```json
{
  "token": "eyJ...",
  "subject": "admin",
  "method": "password",
  "expiresAt": "2026-10-21T13:00:00Z"
}
```

Present `token` as the bearer on every request until it expires. `method` is `password` or
`kerberos`. The response carries `Cache-Control: no-store`.

**Session lifetime** is bounded by `api.session_lifetime` (default `1h`). It is short on
purpose: a session opens every account's password. There is no logout or token-revocation
endpoint — the token is stateless, and expiry (or losing directory-administrator status, which
is re-checked per request) is what ends it.

**Who am I:** `GET /api/v1/auth/whoami` (authenticated) reports who the API takes the caller
to be:

```json
{
  "subject": "admin",
  "method": "password",
  "expiresAt": "2026-10-21T13:00:00Z"
}
```

`method` is one of `token`, `password`, `kerberos`; `expiresAt` is omitted for the management
token, which does not expire.

## Self-description

The API describes itself. The OpenAPI document is built **from the route table and the Go
types the handlers decode and encode**, once, when the service starts — a mistake in the route
table is a start-up failure, not a broken page, and a field renamed in the code changes the
document in the same commit. There is no second description to drift out of step.

- `GET /api/openapi.json` — the document, outside the token check (a browser cannot put an
  `Authorization` header on the address bar). The document describes the surface, not the
  directory; every endpoint it describes stays behind the token.
- `GET /api/docs` — Swagger UI (swagger-ui-dist 5.32.15) rendering the document, embedded in
  the binary so it works air-gapped and matches the build it ships with. Its **Authorize**
  button is where the bearer token goes.
- `GET /api/v1/openapi.json` — the same document behind the token, so the console can build
  its forms from it even where `api.docs` keeps the public copy off.

Set `api.docs: false` on a service whose management port is reachable more widely than its
administrators (default `true`; see [configuration](configuration.md)).

## Errors and conventions

Every refusal has the same shape:

```json
{
  "error": "what was wrong with the request"
}
```

Status codes used across the API:

| Status | Meaning                                                                       |
|--------|-------------------------------------------------------------------------------|
| `400`  | Malformed request, or refused by policy (validation, password rules, ...)     |
| `401`  | No valid bearer token                                                         |
| `403`  | Authenticated, but not a directory administrator                              |
| `404`  | No such object                                                                |
| `409`  | The object exists, or the name is already taken                               |
| `429`  | Too many failed sign-ins from this address (login only)                       |
| `503`  | A facility is not available on this server (e.g. no Vault enrollment manager) |

Conventions that apply everywhere:

- **Strict decoding.** Request bodies are JSON, decoded with unknown fields rejected and a
  1 MiB body limit — a misspelled key is reported, not silently ignored.
- **PATCH semantics.** Only the fields present are changed; absent fields are left alone.
  List- and map-valued fields (`otherGroups`, `sshKeys`, `customAttributes`, `includeGroups`,
  `aliases`, ...) are **replace** fields: sending the list replaces what is there, so leaving a
  value out of a list you send removes it.
- **Password rules.** Every password the API sets must be at least
  `kpasswd.min_password_length` characters (default 8) and at most 72 bytes — the LDAP side
  stores a bcrypt digest, which ignores anything past 72 bytes.
- **No key material or secrets in responses.** User objects never carry the password hash or
  the OTP secret; principal listings never carry keys; application-password hashes are never
  serialized.

## Operations and session

| Method | Path                     | Purpose                                                                                         |
|--------|--------------------------|-------------------------------------------------------------------------------------------------|
| GET    | `/healthz`               | Liveness. Never touches the database, so a stuck query cannot make a healthy process look dead. |
| GET    | `/readyz`                | Readiness: the database answers and the realm is initialised.                                   |
| GET    | `/metrics`               | Prometheus text format.                                                                         |
| GET    | `/api/v1/stats`          | What the directory holds: counts and the realm's enctypes.                                      |
| POST   | `/api/v1/auth/login`     | Sign in with a password (see above).                                                            |
| GET    | `/api/v1/auth/negotiate` | Sign in with Kerberos (see above).                                                              |
| GET    | `/api/v1/auth/whoami`    | Who the API takes the caller to be.                                                             |

`GET /healthz` answers `{"status": "ok"}`. `GET /readyz` answers
`{"status": "ok", "realm": "EXAMPLE.COM"}` when ready, or `503` with
`{"status": "unavailable", "reason": "..."}` when not.

`GET /api/v1/stats` answers:

```json
{
  "realm": "EXAMPLE.COM",
  "users": {
    "total": 12,
    "disabled": 1,
    "withoutPassword": 2
  },
  "groups": 5,
  "principals": 30,
  "trusts": 1,
  "encTypes": [
    "aes256-cts-hmac-sha1-96",
    "aes128-cts-hmac-sha1-96"
  ]
}
```

`withoutPassword` counts accounts that can neither bind nor obtain a ticket — worth surfacing
rather than discovering through a failed login.

## Users

A directory account and its Kerberos principal are created together: there is no state where
one exists without the other. An account meant never to use Kerberos is simply given no
password, and its principal keeps the random keys it starts with, which no password produces.

| Method   | Path                                       | Purpose                                                              |
|----------|--------------------------------------------|----------------------------------------------------------------------|
| GET      | `/api/v1/users`                            | List every account.                                                  |
| POST     | `/api/v1/users`                            | Create an account (and its principal).                               |
| GET      | `/api/v1/users/{name}`                     | Read one account, its DN and the principals attached to it.          |
| PATCH    | `/api/v1/users/{name}`                     | Edit an account.                                                     |
| DELETE   | `/api/v1/users/{name}`                     | Remove it — principals, keys, memberships and attributes go with it. |
| POST     | `/api/v1/users/{name}/password`            | Set the password on both sides at once.                              |
| GET POST | `/api/v1/users/{name}/app-passwords`       | List, mint application passwords.                                    |
| DELETE   | `/api/v1/users/{name}/app-passwords/{id}`  | Revoke one.                                                          |
| GET      | `/api/v1/users/{name}/certificates`        | List imported certificates (metadata only).                          |
| POST     | `/api/v1/users/{name}/certificates/import` | Import a certificate PEM.                                            |

### Create: `POST /api/v1/users` → `201`

```json
{
  "name": "alice",
  "uidNumber": 1001,
  "primaryGroup": 5000,
  "otherGroups": [
    5100
  ],
  "givenName": "Alice",
  "sn": "Smith",
  "mail": "alice@example.com",
  "loginShell": "/bin/bash",
  "homeDirectory": "/home/alice",
  "disabled": false,
  "sshKeys": [
    "ssh-ed25519 AAAA..."
  ],
  "customAttributes": {
    "departmentHead": [
      "engineering"
    ]
  },
  "capabilities": [
    {
      "action": "search",
      "object": "dc=example,dc=com"
    }
  ],
  "otpSecret": "...",
  "password": "initial password",
  "forceChange": true,
  "aliases": [
    "alice.smith"
  ]
}
```

Only `name` is required. `uidNumber` is allocated automatically when left out (0). `password`
is optional and sets both credential forms at creation; `forceChange` (default `true`) marks
the password expired so its owner chooses the final value at first login — a password an
administrator typed is one the administrator knows, and FreeIPA expires an administrative
reset for the same reason. `aliases` are further Kerberos names the account answers to ([Kerberos](kerberos.md)).
Conflicting names get `409`.

The response is the created account:

```json
{
  "user": {
    "id": 3,
    "name": "alice",
    "uidNumber": 1001,
    "primaryGroup": 5000,
    "otherGroups": [
      5100
    ],
    "givenName": "Alice",
    "sn": "Smith",
    "mail": "alice@example.com",
    "loginShell": "/bin/bash",
    "homeDirectory": "/home/alice",
    "disabled": false,
    "sshKeys": [
      "ssh-ed25519 AAAA..."
    ],
    "customAttributes": {
      "departmentHead": [
        "engineering"
      ]
    },
    "capabilities": [
      {
        "action": "search",
        "object": "dc=example,dc=com"
      }
    ],
    "appPasswords": [],
    "hasOTP": false,
    "hasPassword": true,
    "createdAt": "...",
    "updatedAt": "..."
  },
  "dn": "cn=alice,ou=staff,ou=users,dc=example,dc=com"
}
```

`dn` is where the account is found over LDAP; it embeds the primary group's name, so it moves
when the account's primary group changes or that group is renamed. `GET` on a single account
adds a `principals` array of the Kerberos identities attached to it. The password hash and OTP
secret are never serialized; `hasPassword` / `hasOTP` say whether they exist.

### Edit: `PATCH /api/v1/users/{name}` → `200`

Carries only the fields being changed (`uidNumber`, `primaryGroup`, `otherGroups`,
`givenName`, `sn`, `mail`, `loginShell`, `homeDirectory`, `disabled`, `sshKeys`,
`customAttributes`, `capabilities`, `otpSecret`). Setting `disabled` also disables the
account's principals — otherwise the account would keep collecting tickets after being locked
out of LDAP. Note the replace semantics for list and map fields: `customAttributes` replaces
the whole set, so a name left out of the object is removed. Attributes the directory builds
itself (`memberOf`, `objectClass`, the `krb*` set, ...) are refused with `400`.

A user's Kerberos aliases are edited through `PATCH /api/v1/principals/{name}` like any other
principal's (see below).

### Password: `POST /api/v1/users/{name}/password` → `200`

```json
{
  "password": "new password",
  "forceChange": true,
  "expiresAt": "2026-11-01T00:00:00Z"
}
```

Writes the LDAP digest and the Kerberos keys at once. `forceChange` (default `true`) expires
the password immediately; `expiresAt` sets an explicit next-change time and overrides
`forceChange`. Response:

```json
{
  "status": "password set",
  "mustChange": true
}
```

### Application passwords

An application password authenticates one application over LDAP. Revoking it does not disturb
the account's own password. `POST /api/v1/users/{name}/app-passwords` with
`{"name": "backup-agent"}` (and an optional `"password"`) returns `201` with the record —
`{"id": 1, "name": "backup-agent", "createdAt": "..."}` — and, when the secret was generated,
a `password` field shown **once**: nothing stores it in the clear. `GET` lists them without
secrets; `DELETE .../app-passwords/{id}` revokes one (`204`).

### Certificates

These endpoints record certificates an external authority has already issued to the account;
this service issues nothing itself, and the private key is neither accepted nor stored. The
stored certificate is published on the LDAP entry as `userCertificate;binary`, which is what a
smart-card style client looks up. For how the enrollment itself works, see
[OpenBao/Vault PKI](openbao-pki.md).

`POST /api/v1/users/{name}/certificates/import` takes `{"certificate": "-----BEGIN CERTIFICATE-----\n..."}`
(PEM). The certificate is parsed and validated before anything is stored — a non-positive
serial number (RFC 5280 wants them positive) is refused with `400`. Responses carry metadata
only:

```json
{
  "serial": "39dd5b22...",
  "subject": "CN=alice",
  "notBefore": "...",
  "notAfter": "...",
  "createdAt": "..."
}
```

`serial` is hexadecimal, because an issuing authority's serials do not fit a JSON number (Vault issues 160-bit ones).
`GET` lists them as `{"certificates": [...]}`.

## Groups

POSIX groups, which may include other groups.

| Method | Path                            | Purpose                                                             |
|--------|---------------------------------|---------------------------------------------------------------------|
| GET    | `/api/v1/groups`                | List every group.                                                   |
| POST   | `/api/v1/groups`                | Create one.                                                         |
| GET    | `/api/v1/groups/{name}`         | Read one.                                                           |
| PATCH  | `/api/v1/groups/{name}`         | Edit one.                                                           |
| DELETE | `/api/v1/groups/{name}`         | Remove it — refused while the group is any account's primary group. |
| GET    | `/api/v1/groups/{name}/members` | Resolved membership, following included groups.                     |

Create body (`name` required; `gidNumber` allocated automatically when left out):

```json
{
  "name": "staff",
  "gidNumber": 5000,
  "description": "The staff group",
  "includeGroups": [
    5001
  ],
  "capabilities": [],
  "customAttributes": {}
}
```

`includeGroups` are the gid numbers of groups whose members count as members of this one.
`GET .../members` follows that inclusion transitively, so the answer — `{"members": [...]}` of
account names — is the same set the LDAP entry publishes. `PATCH` may rename the group (`name`): the gid stays, and with
it every membership, include and `primary_group` that names
the group by it — only what the group is called changes, and with it the DN of every account
whose primary group it is.

## Principals

Kerberos identities: policy, keys and keytabs. Service principal names carry slashes (`HTTP/www.example.com`), so
`{name}` swallows the rest of the path; the principal's realm may
be appended (`HTTP/host@OTHER.COM`), and without one the service realm applies.

| Method | Path                                 | Purpose                                                               |
|--------|--------------------------------------|-----------------------------------------------------------------------|
| GET    | `/api/v1/principals`                 | List principals (optionally `?realm=`). No key material.              |
| POST   | `/api/v1/principals`                 | Create one.                                                           |
| GET    | `/api/v1/principals/{name}`          | Read one: attributes, policy, enctypes, the `krbTicketFlags` bitmask. |
| PATCH  | `/api/v1/principals/{name}`          | Edit attributes and policy.                                           |
| DELETE | `/api/v1/principals/{name}`          | Remove it.                                                            |
| POST   | `/api/v1/principals/{name}/password` | Re-key from a password or `{"randomize": true}`.                      |
| GET    | `/api/v1/principals/{name}/keytab`   | Keytab for the current key version.                                   |

### Create: `POST /api/v1/principals` → `201`

```json
{
  "name": "HTTP/www.example.com",
  "userName": "reporter",
  "enabled": true,
  "requiresPreAuth": true,
  "allowForwardable": true,
  "allowProxiable": true,
  "allowRenewable": true,
  "allowPostdate": false,
  "okAsDelegate": false,
  "okToAuthAsDelegate": false,
  "allowedToDelegateTo": [
    "HTTP/backend.example.com"
  ],
  "allowedToImpersonate": [],
  "aliases": [
    "HTTP/www"
  ],
  "maxTicketLife": "10h",
  "maxRenewableLife": "168h",
  "expiresAt": null,
  "password": "..."
}
```

The boolean policy flags default as shown (`allowPostdate`, `okAsDelegate`,
`okToAuthAsDelegate` default to `false`, the rest to `true`). `userName` links the principal
to a directory account, so setting that account's password re-keys this principal too — and a
SASL GSSAPI bind under the principal binds as the account, with the account's capabilities.
`maxTicketLife` / `maxRenewableLife` are Go duration strings; empty means the realm default.

Leave `password` out for a service principal: it is created with random keys, which cannot be
guessed, and the keytab is fetched from this API. (A password, when given, is checked against
the realm's password rules.)

### Read: `GET /api/v1/principals/{name}` → `200`

```json
{
  "principal": {
    "id": 7,
    "name": "HTTP/www.example.com",
    "realm": "EXAMPLE.COM",
    "userId": 3,
    "userName": "reporter",
    "kvno": 1,
    "enabled": true,
    "requiresPreAuth": true,
    "allowForwardable": true,
    "allowProxiable": true,
    "allowRenewable": true,
    "allowPostdate": false,
    "okAsDelegate": false,
    "okToAuthAsDelegate": false,
    "allowedToDelegateTo": [
      "HTTP/backend.example.com"
    ],
    "allowedToImpersonate": [],
    "aliases": [
      "HTTP/www"
    ],
    "passwordLastSet": "...",
    "passwordExpiresAt": null,
    "expiresAt": null,
    "lockedUntil": null,
    "failCount": 0,
    "lastSuccess": null,
    "lastFailure": null,
    "createdAt": "...",
    "updatedAt": "..."
  },
  "encTypes": [
    "aes256-cts-hmac-sha1-96"
  ],
  "maxTicketLife": "10h0m0s",
  "maxRenewableLife": "168h0m0s",
  "krbTicketFlags": 129
}
```

`krbTicketFlags` repeats the policy as the bitmask MIT and FreeIPA store, so a value read here
can be compared with one read from either.

### Edit: `PATCH /api/v1/principals/{name}` → `200`

All create-time policy fields, plus `userName` (an empty string unlinks — settable here
because a machine principal usually exists before the account it acts as, and re-creating it
to add the link would issue a new key and invalidate every keytab already distributed),
`passwordExpiresAt`, and `unlock`, which clears a lockout imposed by repeated failed
pre-authentications (`{"unlock": true}` resets `lockedUntil` and `failCount`).

`aliases` **replaces** the principal's alternative names outright, so sending the list without
one removes it. The canonical name is not part of the list and cannot be changed here. Both
names reach the same keys: `kinit alice.smith` takes alice's password. A name can belong to
one principal only, canonically or as an alias; handing it to a second is refused (`409`).

### Re-key: `POST /api/v1/principals/{name}/password` → `200`

```json
{
  "password": "new password"
}
```

or `{"randomize": true}` to replace the keys with random ones. The **previous key version is
kept**, so tickets and keytabs issued before the change keep working until they expire — and
the key's salt follows the principal's canonical name, so a password set through an alias
produces the same keys as one set through the real name.

### Keytab: `GET /api/v1/principals/{name}/keytab` → `200`

An `application/octet-stream` keytab file holding the current key version, named
`HTTP_www.example.com.keytab` (slashes replaced with underscores) in the
`Content-Disposition` header. A principal with no keys answers `409`.

### Delete: `DELETE /api/v1/principals/{name}` → `204`

The realm's own ticket-granting principal (`krbtgt/<REALM>@<REALM>`) cannot be removed (`409`) — without it no ticket in
circulation would verify.

## DNS records

The realm's zone, managed through the store; the name server answers from it ([DNS](dns.md)). Reverse answers are
computed from the address records rather than stored, so
there are no PTR records to write and nothing that can drift out of step.

| Method | Path                       | Purpose                                                                 |
|--------|----------------------------|-------------------------------------------------------------------------|
| GET    | `/api/v1/dns/records`      | List records (optionally `?name=` for one name), plus the zones served. |
| POST   | `/api/v1/dns/records`      | Create a record.                                                        |
| DELETE | `/api/v1/dns/records/{id}` | Remove one.                                                             |

Create body:

```json
{
  "name": "www.example.com",
  "type": "A",
  "value": "192.0.2.10",
  "ttl": 300
}
```

`value` is the record data exactly as a zone file would write it — `"192.0.2.10"` for an A
record, `"0 100 88 kdc.example.com."` for an SRV. `ttl` defaults to the zone's (`dns.ttl`,
default 1h) when omitted. The record is validated by parsing it as a master-file line before
it is stored, and a name outside every zone this server answers for (`dns.zone`,
`dns.extra_zones`, `dns.reverse_zones`) is refused with `400` — a record that would be stored
and never answered is a setting that looks applied and is not. Responses:

```json
{
  "records": [
    {
      "id": 1,
      "name": "www.example.com",
      "type": "A",
      "ttl": 300,
      "value": "192.0.2.10",
      "createdAt": "...",
      "updatedAt": "..."
    }
  ],
  "zones": [
    "example.com",
    "2.0.192.in-addr.arpa"
  ]
}
```

## Trusts

Cross-realm relationships ([Kerberos](kerberos.md)).

| Method | Path                     | Purpose                                             |
|--------|--------------------------|-----------------------------------------------------|
| GET    | `/api/v1/trusts`         | List every trust.                                   |
| POST   | `/api/v1/trusts`         | Create one.                                         |
| GET    | `/api/v1/trusts/{realm}` | Read one.                                           |
| PATCH  | `/api/v1/trusts/{realm}` | Edit `direction`, `transitive`, `enabled`.          |
| DELETE | `/api/v1/trusts/{realm}` | Remove it; the shared krbtgt principals go with it. |

Create body:

```json
{
  "remoteRealm": "PARTNER.COM",
  "direction": "bidirectional",
  "transitive": true,
  "enabled": true,
  "password": "the shared secret"
}
```

`direction` is `outbound`, `inbound` or `bidirectional` (default); `transitive` and `enabled`
default to `true`. A trust is two principals, not one: `krbtgt/REMOTE@LOCAL` refers this
realm's clients outwards, and `krbtgt/LOCAL@REMOTE` accepts the remote realm's clients here.
Both are keyed from the same shared password — which is exactly the string entered on the
other side — so the password is supplied, not generated. Only the principals the direction
needs are created; a principal that already exists is re-keyed rather than refused, because
rotating a trust password is a normal operation. A realm cannot trust itself (`400`).
Deleting the trust deletes both krbtgt principals, which is what stops tickets flowing.

## Vault PKI enrollment

The Vault (or OpenBao) PKI integration enrolls the LDAPS listener's certificate: the service
logs in to Vault over Kerberos — against its own KDC, as the given principal — and has the PKI
sign a fresh key's CSR, replacing the certificate before it expires. It is configured at run
time through these endpoints, not in the configuration file, because it is a relationship with
a deployment's Vault, not a property of one configuration. Full walkthrough:
[OpenBao PKI](openbao-pki.md). On a server without an enrollment manager the endpoints answer
`503`.

| Method | Path                   | Purpose                                                                                                          |
|--------|------------------------|------------------------------------------------------------------------------------------------------------------|
| PUT    | `/api/v1/vault/config` | Install the integration and start the enrollment loop. Replaces any configuration already running.               |
| GET    | `/api/v1/vault/status` | Enrollment state.                                                                                                |
| DELETE | `/api/v1/vault/config` | Stop the loop and forget the configuration. The enrolled certificate keeps being served until the process stops. |

Configure:

```json
{
  "address": "https://vault.example.com:8200",
  "principal": "ldapsvc",
  "service_principal": "HTTP/vault.example.com",
  "pki_path": "pki",
  "role": "ldap-kdc",
  "common_name": "ldap.example.com",
  "san_dns": [
    "ldap.example.com"
  ],
  "san_ips": [
    "192.0.2.5"
  ],
  "ttl": "720h",
  "renew_before": "24h",
  "retry_interval": "5s"
}
```

Required: `address` (an http (s) URL), `principal` (must exist in this realm — its keys stay in
the store and the enrollment reads them from there), `role`, `common_name` (the certificate's
subject CN, the name LDAPS answers for). Defaults: `service_principal` is
`HTTP/<host of address>`, `pki_path` is `pki`, `ttl` `720h`, `renew_before` `24h`,
`retry_interval` `5s`; `ttl` must be longer than `renew_before`. Status:

```json
{
  "configured": true,
  "enrolled": true,
  "not_after": "2026-11-20T00:00:00Z",
  "last_error": "",
  "attempts": 1
}
```

## curl recipes

Assuming `$API` is the API base (`http://127.0.0.1:5555/api/v1`) and `$TOKEN` the management
token (`api.token`):

```sh
AUTH="Authorization: Bearer $TOKEN"

# Sign in as an administrator instead (when you have no management token):
TOKEN=$(curl -s -X POST $API/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login":"admin","password":"..."}' | jq -r .token)

# Create a user (account and Kerberos principal together):
curl -s -X POST $API/users -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "name": "alice", "primaryGroup": 5000,
  "givenName": "Alice", "sn": "Smith", "mail": "alice@example.com",
  "password": "initial password"
}'

# Reset a password (expired by default, so alice picks the final one at first login):
curl -s -X POST $API/users/alice/password -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"password": "temporary password"}'

# Create a service principal with random keys and fetch its keytab:
curl -s -X POST $API/principals -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name": "HTTP/www.example.com"}'
curl -s "$API/principals/HTTP/www.example.com/keytab" -H "$AUTH" -o http.keytab

# Add a DNS record:
curl -s -X POST $API/dns/records -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name": "www.example.com", "type": "A", "value": "192.0.2.10"}'
```
