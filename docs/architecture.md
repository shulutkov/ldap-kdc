# Architecture

How the service is put together: the single store every front end shares, the order the process
starts in, the facts that are fixed once a database is initialized, and the packages and
dependencies that implement each part.

For what each setting does, see [configuration](configuration.md); for what each listener speaks,
see [directory](directory.md), [kerberos](kerberos.md), [dns](dns.md), [api](api.md) and
[oidc](oidc.md).

## What it is, and what it is for

`ldap-kdc` is one Go binary that serves one directory over LDAP/LDAPS, Kerberos (a KDC with AS and
TGS exchanges), kpasswd (RFC 3244), an authoritative DNS server, a REST management API with a web
console, and an OpenID Connect provider. It is built to stand up test rigs: a realm, accounts,
service principals, DNS and tokens in one process and one file, so that what is being tested is
the thing under test and not the identity infrastructure around it — a FreeIPA- or
Active-Directory-like environment in a single container.

**It is not a production directory.** The database is a single SQLite file (or one
PostgreSQL database) with no replication of the service's own, failover or backup but the one you
take. There is no tamper-evident audit trail. The master key
that seals all key material sits in a file on the same disk as the database it protects — that
defeats a stolen database, not a stolen host; there is no HSM or KMS. The management API is a
single bearer token with no scopes. The Kerberos, LDAP and OIDC implementations are written here
rather than taken from an established, security-reviewed library. Where a directory has to survive
people, hardware and time, use FreeIPA, Samba AD, 389-ds or Active Directory.

## The single store

Everything the service knows lives in one database (SQLite by default, PostgreSQL optionally), owned by the `store`
package (`internal/store`). This is a
design constraint, not an implementation shortcut, and the reason is
cryptographic: an LDAP simple bind compares a password against an irreversible digest (bcrypt
here), but a KDC cannot work from a digest. To decrypt a client's pre-authentication and to seal a
ticket, the KDC must reproduce the principal's long-term key exactly, so the key must be stored
reversibly, derived from the password with string-to-key at the moment the password is set.

Setting a password — through the REST API, through `kpasswd`, or by replacing `userPassword` over
LDAP — therefore writes both credential forms in one transaction: a bcrypt digest for LDAP binds
and one long-term key per configured enctype for Kerberos. The consequence cuts both ways: an
account that only ever received a digest can bind over LDAP but can never obtain a ticket, and two
protocols served from one store can never disagree about a password. The same
`store.Authenticate` also decides OIDC logins, so browser sign-in, LDAP bind and the service
account grant apply one credential policy.

### Sealing at rest

Kerberos keys are reversible by construction, so they are never stored in clear. Everything sealed
in the database is encrypted with AES-256-GCM under a 32-byte master key held in a separate file
(`database.master_key_file`), implemented in `internal/secret`:

- `LoadOrCreateMasterKey` reads the key file, or generates it with mode `0600` using
  `O_CREATE|O_EXCL` (so two processes racing to initialize the same deployment cannot each write a
  different key), creating the parent directory with mode `0700`. A file of the wrong length is
  rejected.
- `Sealer.Seal` prepends a fresh random nonce to the ciphertext; `Sealer.Open` requires the same
  context string the value was sealed with.

Each principal key is sealed with **AEAD associated data** naming the row it belongs to (`internal/store/store.go`,
`keyContext`): the string
`principal-key:<principal-id>:<kvno>:<etype>`. A sealed key lifted from one principal's row cannot
be replayed into another's — the GCM tag check fails — and neither can an old key version be moved
onto a new kvno.

The master key is the one file whose loss cannot be recovered from: without it every stored key is
unreadable and the realm has to be rebuilt. Back it up separately from the database; see
[operations](operations.md).

### Choosing the database

`database.url` names the database, and its scheme selects it: `sqlite://` or `postgres://`. The rest of the service cannot tell them apart: both speak the same
SQL through one set of queries written with `?` placeholders, which the PostgreSQL side renumbers to
`$1, $2, …` (`dialect.go`). What differs is confined to a few places:

| Concern                     | SQLite                              | PostgreSQL                                            |
|-----------------------------|-------------------------------------|-------------------------------------------------------|
| Schema                      | `migrations/sqlite/`                | `migrations/postgres/`, the same file names           |
| Key columns                 | `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGINT GENERATED BY DEFAULT AS IDENTITY`             |
| Flags                       | `INTEGER` 0 / 1                     | `BOOLEAN`                                             |
| Names compared without case | `COLLATE NOCASE`                    | `CITEXT` (the `citext` extension)                     |
| Key material, certificates  | `BLOB`                              | `BYTEA`                                               |
| New row's id                | `INSERT … RETURNING id` on both     |                                                       |
| Ordering of writers         | `writeMu`, one process              | `writeMu` plus `pg_advisory_xact_lock`, every process |
| Concurrent start-up         | one process                         | `pg_advisory_lock` around the migrations              |
| Duplicate key               | message `UNIQUE constraint failed`  | SQLSTATE `23505`; both become `store.ErrConflict`     |

Timestamps are Unix seconds in an integer column on both, so the Go code reads and writes one
representation. A migration is added to both directories under the same name; a test fails if the
two lists drift apart.

Because writers are ordered across processes by the advisory lock, several services may share one
PostgreSQL database and the checks made in Go under the write lock (that a principal name is free,
that a relative identifier is unused) still hold. That is not high availability: what a
service keeps in memory, the Kerberos replay cache among it, is its own, and nothing coordinates
the instances beyond the database.

### SQLite specifics

`store.Open` uses the pure-Go `modernc.org/sqlite` driver (no cgo) with these pragmas in the DSN:

| Pragma         | Value    | Why                                                       |
|----------------|----------|-----------------------------------------------------------|
| `journal_mode` | `WAL`    | readers run while the single writer holds its transaction |
| `busy_timeout` | `10000`  | wait out a contended write instead of failing             |
| `foreign_keys` | `1`      | enforce references                                        |
| `synchronous`  | `NORMAL` | the WAL-appropriate durability setting                    |

The connection pool is capped at 8 open / 4 idle connections with a one-hour connection lifetime.
Writes are serialized in-process by a mutex (`writeMu`): SQLite allows a single writer, and taking
the lock in the process is cheaper and more predictable than letting concurrent writers collide on
`SQLITE_BUSY`. Driver-level uniqueness violations are translated into the sentinel error
`store.ErrConflict`; lookups that find nothing return `store.ErrNotFound`.

### Schema migrations

The schema lives in embedded SQL files under `internal/store/migrations/`, applied in name order
on open and recorded in a `schema_migrations` table. Each migration runs in its own transaction,
so a failure leaves the schema at the last complete version.

| Migration                    | Creates                                                                                                                                                                                         |
|------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `0001_init.sql`              | `meta`, `groups`, `group_includes`, `users`, `user_groups`, `user_ssh_keys`, `user_attrs`, `user_app_passwords`, `capabilities`, `principals`, `principal_keys`, `delegation_targets`, `trusts` |
| `0002_freeipa_alignment.sql` | `security_identifiers`, `impersonation_targets`; renames `principals.allow_tgt_based_auth` to `ok_to_auth_as_delegate`                                                                          |
| `0003_dns.sql`               | `dns_records`                                                                                                                                                                                   |
| `0004_principal_aliases.sql` | `principal_aliases`                                                                                                                                                                             |
| `0005_object_attrs.sql`      | `object_attrs`                                                                                                                                                                                  |
| `0006_user_certificates.sql` | `user_certificates`                                                                                                                                                                             |

The `meta` table is a key/value store for facts that must survive restarts and must not change
silently; see [Immutable facts after initialization](#immutable-facts-after-initialization).

## Startup sequence

`cmd/ldap-kdc/main.go` runs the process in a fixed order. The binary's flags are `-c`/`--config`
(default `ldap-kdc.yaml`), `--check-config` (validate and exit) and `--version`.

1. **Configuration** — `config.Load` merges defaults, environment variables and the YAML file, in
   that order of precedence (see [configuration](configuration.md)).
2. **Enctypes** — `krbkeys.ResolveEncTypes` maps `kdc.enc_types` to enctype numbers, refusing
   single-DES and RC4 outright. The default list is `aes256-cts-hmac-sha1-96`,
   `aes128-cts-hmac-sha1-96`, `aes256-cts-hmac-sha384-192`, `aes128-cts-hmac-sha256-128`.
3. **Master key** — `secret.LoadOrCreateMasterKey`; a freshly generated key is logged once with an
   explicit warning to back it up.
4. **Store** — `store.Open` opens the database (for SQLite it creates the directory if needed and
   sets the pragmas above) and applies pending migrations.
5. **`EnsureRealm`** — pins the realm name in `meta` (upper-cased), refusing to open a database
   initialized for a different one, and creates the `krbtgt/<REALM>` and `kadmin/changepw`
   principals with random keys when missing (both pre-auth-required and forwardable/proxiable/
   renewable).
6. **`EnsureDomainSID`** — pins the Windows domain SID PACs are issued under.
7. **`EnsureIDRange`** — pins the POSIX-id→RID mapping range and backfills security identifiers
   for any object still without one.
8. **Bootstrap** — if `bootstrap.file` is set, the plan is loaded, its file permissions are
   checked (passwords are in the clear, so the file must not be world-readable), validated whole
   and applied: groups, accounts, service principals and DNS records. See [bootstrap](bootstrap.md).
9. **Shared machinery** — Prometheus metrics; one `failban` limiter for every door that takes a
   password, so a guesser blocked from LDAP binds cannot carry on at the console sign-in; the
   Vault PKI enrollment manager and the certificate holder an LDAPS listener without certificate
   paths waits on.
10. **Listeners**, in this order, each only when enabled: LDAP/LDAPS, KDC, kpasswd, DNS, the REST
    API, and the OIDC provider. If the API and the provider are given the same listen address,
    they share one listener — the console and API ride on the provider's port (`/ui/`, `/api/`,
    `/.well-known`, `/keys`). If nothing is enabled the process exits with an error.

**Bootstrap runs before any listener accepts** on purpose: a client that sees the service accept a
connection sees a directory that is already what the plan described. The e2e suite relies on this —
fixtures exist before the first connection, and `kinit` as a seeded account succeeds with nothing
having provisioned it at run time. See [e2e](e2e.md).

Shutdown is the mirror image: on `SIGINT`/`SIGTERM` the listeners stop in reverse order of start-up
with a 15-second bound, so the store stays alive until the last listener that might still be
answering a request has stopped.

## Immutable facts after initialization

Three facts are pinned in the `meta` table on first start and changing any of them against an
existing database is refused rather than applied:

- **Realm name** (`meta` key `realm`). Every stored Kerberos key is salted with the realm name, so
  serving a different realm from the same database would fail every pre-authentication with no
  obvious cause. `EnsureRealm` compares the configured realm with the stored one and aborts on
  mismatch. Renaming a realm means rebuilding the database.
- **Domain SID** (`domain_sid`). An explicitly configured `server.domain_sid` wins on first start;
  afterwards the stored value is reused and a conflicting configured value aborts start-up. With
  neither, a random `S-1-5-21-<n>-<n>-<n>` SID is generated. The SID is baked into every PAC a
  client has cached and every ACL a Windows or Samba member server derived from one, so a silent
  change would strand those.
- **ID range** (`id_range_base_id`, `id_range_size`, `id_range_base_rid`,
  `id_range_secondary_base_rid`). The range maps POSIX ids onto Windows RIDs, starting at or above
  RID 1000 (below which Windows reserves well-known accounts); the secondary interval keeps a user
  and a group sharing a POSIX id distinct. Defaults: base id 1, size 200000, base RID 1000,
  secondary base RID 100000000. RIDs are allocated once per object, stored in
  `security_identifiers`, and the stored range must match the configured one on every start.

A fourth fact is immutable in practice rather than by check: **the master key**. Nothing prevents
pointing the service at a different key file, but every sealed value then fails to open and the
realm is unreadable.

## Component map

Each component is a package under `internal/`; all of them sit on the one store.

**`ldapsrv` — LDAP directory.** Serves bind (simple, with TOTP appended and application passwords;
SASL GSSAPI with a Kerberos ticket when `server.ldap_spn` is set), search, modify and delete over
LDAP and LDAPS, with StartTLS on the plain port. The DN layout follows glauth's (`cn=user,ou=group,ou=users,$BASE`).
Entry construction happens here: `memberOf`, the `krb*`
attributes, custom attributes. See [directory](directory.md).

**`kdc` — Kerberos KDC.** The AS and TGS exchanges over UDP and TCP: PA-ENC-TIMESTAMP
pre-authentication, AES-only enctypes, ticket flag policy, renewal, the Microsoft PAC, S4U2Self
and S4U2Proxy, cross-realm referrals, a replay cache and per-principal lockout. See
[kerberos](kerberos.md).

**`kpasswd` — password changing.** RFC 3244 over UDP and TCP; changes the requester's own password
and re-keys both credential forms in the same transaction. Changing someone else's password goes
through the REST API.

**`dnssrv` — authoritative DNS.** Serves the realm's zone plus `dns.extra_zones` — SOA/NS at the
apex, the Kerberos and LDAP SRV discovery records, address records managed through the REST API —
and computes reverse answers from those address records rather than storing a second copy.
Authoritative only: names outside the configured zones are refused. See [dns](dns.md).

**`api` — REST management API and console host.** Everything under `/api/v1` behind a bearer
token, plus open `/healthz`, `/readyz` and `/metrics`; the administrator sign-in (password or
SPNEGO) that mints console sessions; the OpenAPI document generated from the route table and the
embedded Swagger UI. See [api](api.md).

**`oidc` — OpenID Connect provider.** Authorization code flow with PKCE, discovery, JWKS,
`/auth`, `/token`, `/userinfo`, `/end-session`, and the client credentials grant for members of
`oidc.service_account_group`. Sign-in is decided by the same `store.Authenticate` as an LDAP bind.
See [oidc](oidc.md).

**Console UI (`ui/`, embedded).** A React/TypeScript single-page console for directory
administrators, built by `make ui` into `internal/api/ui/dist` and embedded in the binary. It
renders forms from the API's own OpenAPI document and every change it makes is an ordinary
authorized API request. See [console](console.md).

**`failban` — shared throttling.** One per-address limiter built from the `behaviors.*_failed_binds`
settings and shared by LDAP binds, console sign-in and every other door that takes a password. The
KDC-side account lockout uses the same three knobs, applied per principal.

**`bootstrap` — provisioning plans.** Loads the YAML plan named by `bootstrap.file`, validates it
whole before applying anything, creates what is missing and leaves alone what is there. Seeded
passwords are usable immediately (`force_change: true` opts out per account). See
[bootstrap](bootstrap.md).

**`vaultpki` — certificate enrollment.** An enrollment loop driven at run time through the
management API (`PUT /api/v1/vault/config`): logs in to an OpenBao/Vault server over Kerberos
against this service's own KDC, generates the private key locally, and asks the PKI to sign a CSR
for the LDAPS listener's certificate, renewing before expiry. See [openbao-pki](openbao-pki.md).

Supporting packages: `config` (loading and validation), `krbkeys` (principal names, salts,
string-to-key, keytab encoding), `jws` (ES256 token signing, one sealed key per issuer), `secret`
(master key and AEAD sealing), `logging` (zerolog setup), `metrics` (Prometheus collectors),
`tlsutil` (TLS configuration shared by the listeners).

## Package layout

```
cmd/ldap-kdc        the binary: flags, start-up order, ordered shutdown
internal/store      SQLite and PostgreSQL store: users, groups, principals, sealed keys, migrations, meta
internal/krbkeys    principal names, salts, string-to-key, keytab encoding
internal/kdc        AS and TGS exchanges, PAC, S4U, cross-realm, replay cache
internal/kpasswd    RFC 3244 password changing
internal/ldapsrv    LDAP handler, entry construction, failed-bind throttling
internal/dnssrv     authoritative zone and reverse answers from the store
internal/api        REST API, administrator sign-in, OpenAPI, Swagger UI, console embed
internal/oidc       OpenID Connect provider
internal/bootstrap  provisioning plans applied at start-up
internal/vaultpki   LDAPS certificate enrollment against OpenBao/Vault PKI
internal/jws        ES256 signing and verification, one sealed key per issuer
internal/failban    failed-attempt throttling shared by every password door
internal/secret     master key handling and AEAD sealing
internal/config     configuration loading and validation
internal/logging    the process-wide logger
internal/metrics    Prometheus collectors shared by the front ends
internal/tlsutil    TLS configuration the listeners share
ui                  the administrators' console (React), built into internal/api/ui/dist
test/e2e            containerized end-to-end suite, its own Go module
```

## External dependencies

From `go.mod` (module `github.com/shulutkov/ldap-kdc`):

| Dependency                                         | Used for                                                                                            |
|----------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `modernc.org/sqlite`                               | pure-Go SQLite driver — the whole store builds without cgo                                          |
| `github.com/jackc/pgx/v5`                          | pure-Go PostgreSQL driver (`database/sql` adapter), likewise without cgo                            |
| `github.com/glauth/ldap`                           | the LDAP server protocol handling in `ldapsrv`; the schema and DN layout also originate from glauth |
| `github.com/go-krb5/krb5` + `github.com/go-krb5/x` | Kerberos message types and crypto; the KDC grew out of a mock KDC built on it                       |
| `github.com/miekg/dns`                             | the authoritative name server (the library CoreDNS is built on)                                     |
| `github.com/pquerna/otp`                           | TOTP for LDAP binds                                                                                 |
| `github.com/prometheus/client_golang`              | `/metrics`                                                                                          |
| `github.com/rs/zerolog`                            | structured logging                                                                                  |
| `github.com/swaggest/openapi-go`                   | generating the OpenAPI document from the route table and handler types                              |
| `golang.org/x/crypto`                              | bcrypt password digests                                                                             |
| `github.com/caarlos0/env/v11` + `gopkg.in/yaml.v3` | configuration from environment and file                                                             |

Two `replace` directives pin forked libraries:

- `github.com/glauth/ldap => github.com/shulutkov/glauth-ldap` — a fork of glauth's LDAP library,
  reworked around the writable store this service is built on.
- `github.com/go-krb5/krb5 => github.com/shulutkov/krb5` — per the comment in `go.mod`, "the fork
  with the SASL GSSAPI fix: a sealed selection where integrity was negotiated is taken, as ldap3
  sends it (2026-10-05)" — needed so the Vault PKI enrollment's SPNEGO login and other GSSAPI
  clients interoperate.

The end-to-end suite under `test/e2e` is a separate Go module so the container machinery stays out
of the service's dependency graph.
