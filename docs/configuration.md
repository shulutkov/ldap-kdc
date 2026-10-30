# Configuration

ldap-kdc reads one YAML file — conventionally `ldap-kdc.yaml` — that holds the settings an
operator fixes once: listeners, realm identity, crypto policy and the location of the database.
Users, groups, principals and their credentials are not configuration; they live in the database
and are managed through the REST API (see [api](api.md)) or a bootstrap plan (see
[bootstrap](bootstrap.md)).

Every value comes from one of three places, each overriding the one before it:

1. the defaults built into the binary,
2. the environment,
3. the YAML file.

**The file has the last word.** A key written in the file wins over the environment; delete the
key to let the environment supply it.

## Locating the file

The binary takes one flag for the configuration path:

```sh
ldap-kdc -c /etc/ldap-kdc/ldap-kdc.yaml
ldap-kdc --config /etc/ldap-kdc/ldap-kdc.yaml   # same thing, long form
```

Both `-c` and `--config` default to `ldap-kdc.yaml` in the current working directory. A named
file that does not exist is a fatal error — silently running on defaults is not what someone
naming a file meant. To configure the service from the environment alone, pass an empty path:
`ldap-kdc -c ''`.

Two more flags relate to configuration:

```sh
ldap-kdc --check-config -c ldap-kdc.yaml   # validate and exit, printing realm and base DN
ldap-kdc --version                         # print the version and exit
```

The YAML parser runs with known-fields checking: a misspelled key is a parse error, not a
silently ignored setting. An empty file is valid — everything then comes from the environment
and the defaults.

## Environment overrides

Every setting can also come from the environment, named `<SECTION>_<NAME>`: the realm is
`SERVER_REALM`, the KDC address is `KDC_LISTEN`. Section prefixes are:

| YAML section | Env prefix                    | YAML section | Env prefix   |
|--------------|-------------------------------|--------------|--------------|
| (top level)  | — (`DEBUG`, `STRUCTURED_LOG`) | `kpasswd`    | `KPASSWD_`   |
| `server`     | `SERVER_`                     | `dns`        | `DNS_`       |
| `database`   | `DB_` (not `DATABASE_`)       | `api`        | `API_`       |
| `ldap`       | `LDAP_`                       | `oidc`       | `OIDC_`      |
| `ldaps`      | `LDAPS_`                      | `bootstrap`  | `BOOTSTRAP_` |
| `kdc`        | `KDC_`                        | `behaviors`  | `BEHAVIORS_` |

The env name is the prefix plus the upper-cased YAML key: `api.token_file` is `API_TOKEN_FILE`,
`kdc.max_ticket_life` is `KDC_MAX_TICKET_LIFE`. List values are comma-separated
(`KDC_ENC_TYPES=aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96`). The `oidc.clients` list is
structured data and has no environment form.

## Value formats

- **Durations** are Go duration strings: `10s`, `5m`, `1h`, `168h`. This holds in both the file
  and the environment. A bare number is rejected (it is not interpreted as seconds or
  nanoseconds).
- **Sizes and counts** are plain integers in bytes or items (`kdc.udp_max_size: 4096`,
  `kpasswd.min_password_length: 8`). There are no size suffixes.
- **Booleans** are `true` / `false`.
- **Listen addresses** are `host:port` and must parse as such when the listener is enabled (`0.0.0.0:88`,
  `127.0.0.1:5555`).

## Relative paths

A relative path in the configuration means "next to the configuration file": it is resolved
against the directory holding the YAML file. Absolute paths are used as given, and when no file
was loaded (environment-only configuration) relative paths stay relative to the working
directory.

Resolved this way: the file of a `sqlite://` `database.url`, `database.master_key_file`, `ldap.cert_path`,
`ldap.key_path`, `ldaps.cert_path`, `ldaps.key_path`, `api.cert_path`, `api.key_path`,
`api.token_file` (when it is read) and `bootstrap.file`.

Not resolved: `oidc.cert_path`, `oidc.key_path` and each OIDC client's `secret_file` are used
verbatim, so relative values there are interpreted against the process working directory. Give
them as absolute paths.

## Derived values

Several settings default from others during normalization, before validation:

- `server.realm` is trimmed and upper-cased.
- `server.domain` defaults to the realm, lower-cased.
- `server.netbios_name` defaults to the first label of the realm, upper-cased (`EXAMPLE.COM` →
  `EXAMPLE`).
- `server.base_dn` defaults to the domain rendered as domain components (`example.com` → `dc=example,dc=com`).
- `dns.zone` defaults to `server.domain`; `dns.mailbox` defaults to `hostmaster@<zone>`.
- `server.ssh_key_attr` (the older singular), when set, replaces the whole `ssh_key_attrs` list.
- `api.token_file`, when set, is read and its content becomes `api.token`.

## Top level

| Key              | Type | Default | Meaning                                                           |
|------------------|------|---------|-------------------------------------------------------------------|
| `debug`          | bool | `false` | Verbose logging.                                                  |
| `structured_log` | bool | `false` | Line-delimited JSON instead of the human-readable console format. |

## `server` — realm identity

| Key                           | Env                                  | Type   | Default                        | Meaning                                                                                                                                                                                             |
|-------------------------------|--------------------------------------|--------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `realm`                       | `SERVER_REALM`                       | string | —                              | The Kerberos realm. Required; upper-cased; must match `^[A-Z0-9][A-Z0-9.-]*[A-Z0-9]$`. Written into every key salt, so it cannot be changed after first start without re-keying every principal.    |
| `domain`                      | `SERVER_DOMAIN`                      | string | realm, lower-cased             | DNS domain used for the realm mapping and UPN suffixes.                                                                                                                                             |
| `base_dn`                     | `SERVER_BASE_DN`                     | string | derived from `domain`          | LDAP naming context, e.g. `dc=example,dc=com`.                                                                                                                                                      |
| `netbios_name`                | `SERVER_NETBIOS_NAME`                | string | first realm label              | Short domain name in issued PACs.                                                                                                                                                                   |
| `domain_sid`                  | `SERVER_DOMAIN_SID`                  | string | generated on first start       | Domain SID PACs are issued under; must begin with `S-1-5-21-`. Persisted in the database — do not change it afterwards.                                                                             |
| `name_format`                 | `SERVER_NAME_FORMAT`                 | string | `cn`                           | RDN attribute for user entries (`cn=alice,ou=users,...`).                                                                                                                                           |
| `group_format`                | `SERVER_GROUP_FORMAT`                | string | `ou`                           | RDN attribute for group entries.                                                                                                                                                                    |
| `ldap_spn`                    | `SERVER_LDAP_SPN`                    | string | empty                          | Service principal a SASL GSSAPI bind is accepted for, e.g. `ldap/dc.example.com`. Empty turns SASL off and the root DSE offers no mechanisms. The principal is created on first start when missing. |
| `ssh_key_attrs`               | `SERVER_SSH_KEY_ATTRS`               | list   | `[sshPublicKey, ipaSshPubKey]` | Attribute names SSH keys are published under — the same keys under each. Must name at least one attribute; duplicates (case-insensitive) and empties are dropped.                                   |
| `ssh_key_attr`                | `SERVER_SSH_KEY_ATTR`                | string | empty                          | Older singular form; when set it **is** the whole list.                                                                                                                                             |
| `anonymous_dse`               | `SERVER_ANONYMOUS_DSE`               | bool   | `false`                        | Let unauthenticated clients read the root DSE. SSSD needs this.                                                                                                                                     |
| `id_range_base_id`            | `SERVER_ID_RANGE_BASE_ID`            | int    | `1`                            | Lowest uid/gid the SID-mapping range covers; must be positive.                                                                                                                                      |
| `id_range_size`               | `SERVER_ID_RANGE_SIZE`               | int    | `200000`                       | How many POSIX ids the range spans; must be positive and fit the 32-bit id space. An account outside the range gets no SID and no PAC.                                                              |
| `id_range_base_rid`           | `SERVER_ID_RANGE_BASE_RID`           | int    | `1000`                         | Where RIDs start. Must be ≥ 1000, below which Windows reserves RIDs for well-known accounts.                                                                                                        |
| `id_range_secondary_base_rid` | `SERVER_ID_RANGE_SECONDARY_BASE_RID` | int    | `100000000`                    | Fallback interval for an object whose primary RID is taken (a user and a group may share a POSIX id). Must be ≥ 1000 and not overlap the primary interval.                                          |

The ID range is pinned in the database on first start; changing it later renames every account
as far as a member server is concerned. See [directory](directory.md).

## `database`

| Key               | Env                  | Type   | Default                | Meaning                                                                                                                                                                                                            |
|-------------------|----------------------|--------|------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `url`             | `DB_URL`             | string | `sqlite://ldap-kdc.db` | The database. `sqlite://` followed by the file — relative to the configuration file, or absolute as `sqlite:///var/lib/ldap-kdc/ldap-kdc.db` — or `postgres://user:password@host:5432/dbname?sslmode=verify-full`. |
| `master_key_file` | `DB_MASTER_KEY_FILE` | string | `master.key`           | The 32-byte key every Kerberos key in the database is sealed with. Generated on first start; back it up separately — the database cannot be read without it.                                                       |

With a `postgres://` URL the database must already exist and the role must be able to create tables in it. The
first start also runs `CREATE EXTENSION IF NOT EXISTS citext`, which PostgreSQL 13 and later allow
the database's owner to do (the extension ships in `postgresql-contrib` on some distributions). The
URL accepts everything pgx does, including `sslmode`, and the standard `PG*` environment variables (`PGPASSWORD`,
`PGSSLROOTCERT`, …) fill in what it leaves out, which keeps the password out of the
configuration file. The log never prints the password. See [architecture](architecture.md) for how
the two databases differ.

## `ldap` — cleartext listener

| Key         | Env              | Type    | Default       | Meaning                                                              |
|-------------|------------------|---------|---------------|----------------------------------------------------------------------|
| `enabled`   | `LDAP_ENABLED`   | bool    | `true`        | Serve LDAP.                                                          |
| `listen`    | `LDAP_LISTEN`    | address | `0.0.0.0:389` | Bind address.                                                        |
| `tls`       | `LDAP_TLS`       | bool    | `false`       | Offer StartTLS on the plain port.                                    |
| `cert_path` | `LDAP_CERT_PATH` | path    | empty         | Certificate for StartTLS. With `tls: true`, both paths are required. |
| `key_path`  | `LDAP_KEY_PATH`  | path    | empty         | Private key for the certificate.                                     |

## `ldaps` — implicit-TLS listener

| Key         | Env               | Type    | Default       | Meaning               |
|-------------|-------------------|---------|---------------|-----------------------|
| `enabled`   | `LDAPS_ENABLED`   | bool    | `false`       | Serve LDAPS.          |
| `listen`    | `LDAPS_LISTEN`    | address | `0.0.0.0:636` | Bind address.         |
| `cert_path` | `LDAPS_CERT_PATH` | path    | empty         | Certificate to serve. |
| `key_path`  | `LDAPS_KEY_PATH`  | path    | empty         | Private key.          |

Unlike every other TLS listener, LDAPS may start with **no certificate at all**: with neither
path set the listener comes up anyway, handshakes fail until a certificate arrives from the
Vault PKI enrollment (`PUT /api/v1/vault/config`, see [openbao-pki](openbao-pki.md)), and the
listener then serves whatever the enrollment delivered. With both paths set the certificate
comes from disk and the enrollment machinery stays off. Half a pair — only one of the two paths
— is a configuration error.

## `kdc` — Kerberos ticket-granting service

| Key                  | Env                      | Type        | Default                  | Meaning                                                                                                                                                  |
|----------------------|--------------------------|-------------|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `enabled`            | `KDC_ENABLED`            | bool        | `true`                   | Serve the KDC.                                                                                                                                           |
| `listen`             | `KDC_LISTEN`             | address     | `0.0.0.0:88`             | Bind address, used for both TCP and UDP.                                                                                                                 |
| `max_ticket_life`    | `KDC_MAX_TICKET_LIFE`    | duration    | `10h`                    | Longest ticket lifetime. Must be positive.                                                                                                               |
| `max_renewable_life` | `KDC_MAX_RENEWABLE_LIFE` | duration    | `168h`                   | Longest renewable window. Must not be shorter than `max_ticket_life`.                                                                                    |
| `clock_skew`         | `KDC_CLOCK_SKEW`         | duration    | `5m`                     | Accepted clock skew. Must be positive. Also used by kpasswd.                                                                                             |
| `enc_types`          | `KDC_ENC_TYPES`          | list        | the four AES types below | Enctypes the KDC will use, most preferred first; a key is generated for each whenever a password is set. Must be non-empty when the KDC is enabled.      |
| `require_pre_auth`   | `KDC_REQUIRE_PRE_AUTH`   | bool        | `true`                   | Require PA-ENC-TIMESTAMP. Turning this off exposes every principal to offline AS-REP cracking.                                                           |
| `issue_pac`          | `KDC_ISSUE_PAC`          | bool        | `true`                   | Add a Microsoft PAC to issued tickets; Windows and Samba services need it.                                                                               |
| `allow_s4u`          | `KDC_ALLOW_S4U`          | bool        | `true`                   | Allow protocol transition (S4U2Self) and constrained delegation (S4U2Proxy), still gated per principal by `allowTGTBasedAuth` and `allowedToDelegateTo`. |
| `udp_max_size`       | `KDC_UDP_MAX_SIZE`       | int (bytes) | `4096`                   | Bound on a single datagram; larger replies set the TCP-required bit. Minimum 576.                                                                        |

Allowed `enc_types` values — anything else is refused at start-up:

- `aes256-cts-hmac-sha1-96` (aliases `aes256-cts`, `aes256-sha1`)
- `aes128-cts-hmac-sha1-96` (aliases `aes128-cts`, `aes128-sha1`)
- `aes256-cts-hmac-sha384-192` (alias `aes256-sha2`)
- `aes128-cts-hmac-sha256-128` (alias `aes128-sha2`)

The default list is all four, in the order shown above. Single-DES and RC4 (`arcfour-*`) names
are recognized but **refused**: they are broken in practice, and accepting one would let a
client negotiate the realm down to it. Unknown names are an error. There is no PKINIT
configuration anywhere in this service — the `kdc` section above is complete.

See [kerberos](kerberos.md) for how these interact with ticket issuance.

## `kpasswd` — password change service

| Key                   | Env                           | Type    | Default       | Meaning                                                                                                          |
|-----------------------|-------------------------------|---------|---------------|------------------------------------------------------------------------------------------------------------------|
| `enabled`             | `KPASSWD_ENABLED`             | bool    | `true`        | Serve the RFC 3244 password change service. Requires the KDC to be enabled.                                      |
| `listen`              | `KPASSWD_LISTEN`              | address | `0.0.0.0:464` | Bind address.                                                                                                    |
| `min_password_length` | `KPASSWD_MIN_PASSWORD_LENGTH` | int     | `8`           | Shorter passwords are rejected on change and set operations. The same minimum is enforced by the management API. |

## `dns` — authoritative name server

The realm's authoritative server: clients find the KDC through its SRV records, and reverse
answers keep host canonicalization producing principals that exist. It is authoritative only —
a query outside its zones is refused, so the service cannot become an open resolver. See
[dns](dns.md).

| Key             | Env                 | Type     | Default             | Meaning                                                                                                                                                                                  |
|-----------------|---------------------|----------|---------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `enabled`       | `DNS_ENABLED`       | bool     | `false`             | Serve DNS.                                                                                                                                                                               |
| `listen`        | `DNS_LISTEN`        | address  | `0.0.0.0:53`        | Bind address.                                                                                                                                                                            |
| `zone`          | `DNS_ZONE`          | string   | `server.domain`     | The forward zone served.                                                                                                                                                                 |
| `extra_zones`   | `DNS_EXTRA_ZONES`   | list     | empty               | Further forward zones answered for. They carry none of the realm's discovery records — only what is put in them.                                                                         |
| `reverse_zones` | `DNS_REVERSE_ZONES` | list     | empty               | `in-addr.arpa` / `ip6.arpa` zones answered for. Reverse answers are derived from the address records; there are no PTR records to maintain.                                              |
| `hostname`      | `DNS_HOSTNAME`      | string   | empty               | This server's fully qualified name — the zone's name server and the target of every service record. Required when enabled, and must contain a dot. Deliberately not guessed from the OS. |
| `addresses`     | `DNS_ADDRESSES`     | list     | empty               | The addresses `hostname` resolves to; what reverse queries answer with. Required when enabled; every entry must parse as an IP address.                                                  |
| `mailbox`       | `DNS_MAILBOX`       | string   | `hostmaster@<zone>` | Zone contact written into the SOA. Address form is accepted and converted to the dotted SOA form.                                                                                        |
| `ttl`           | `DNS_TTL`           | duration | `1h`                | Record TTL. Must be positive. Also the default TTL the management API offers for records.                                                                                                |

## `api` — REST management interface and console

| Key                | Env                    | Type     | Default          | Meaning                                                                                                                                                                                                                                                    |
|--------------------|------------------------|----------|------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `enabled`          | `API_ENABLED`          | bool     | `true`           | Serve the management API.                                                                                                                                                                                                                                  |
| `listen`           | `API_LISTEN`           | address  | `127.0.0.1:5555` | Bind address. Keep it on loopback unless a token is set: this interface can change any account's password.                                                                                                                                                 |
| `tls`              | `API_TLS`              | bool     | `false`          | Serve HTTPS. Both `cert_path` and `key_path` are then required.                                                                                                                                                                                            |
| `cert_path`        | `API_CERT_PATH`        | path     | empty            | Certificate.                                                                                                                                                                                                                                               |
| `key_path`         | `API_KEY_PATH`         | path     | empty            | Private key.                                                                                                                                                                                                                                               |
| `token`            | `API_TOKEN`            | string   | empty            | Accepted as `Authorization: Bearer <token>` on every `/api` request, beside administrators' sessions. The API never answers anonymously. Prefer the environment or `token_file` over writing the secret here.                                              |
| `token_file`       | `API_TOKEN_FILE`       | path     | empty            | Reads the token from a file so the secret need not sit in the configuration. When both are set, the file wins; the two are not rejected as a conflict.                                                                                                     |
| `docs`             | `API_DOCS`             | bool     | `true`           | Serve the OpenAPI document at `/api/openapi.json` and Swagger UI at `/api/docs`. Both sit outside the token check (a browser cannot put a header on the address bar); turn off where the management port is reachable more widely than its administrators. |
| `ui`               | `API_UI`               | bool     | `true`           | Serve the administrators' console at `/ui/`. Only accounts that may write the whole directory can sign in.                                                                                                                                                 |
| `spn`              | `API_SPN`              | string   | empty            | Service principal Kerberos sign-in to the console is accepted for: `HTTP/` plus the host name the console is reached by. Created with random keys on start when missing — no keytab is written. Empty turns Kerberos sign-in off, leaving passwords only.  |
| `session_lifetime` | `API_SESSION_LIFETIME` | duration | `1h`             | How long an administrator's session lasts. Short, because it can reset any account's password.                                                                                                                                                             |

**Shared listener:** writing the same address in `api.listen` and `oidc.listen` asks for one
listener serving both — the console at `/ui/`, the management API at `/api/`, the provider at
`/.well-known` and `/keys`. The provider's TLS is then what serves them, and `api.tls` is
beside the point. Different addresses give each its own port. See [oidc](oidc.md) and
[console](console.md).

## `oidc` — OpenID Connect provider

| Key                     | Env                          | Type     | Default          | Meaning                                                                                                                                                                                                                                                             |
|-------------------------|------------------------------|----------|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `enabled`               | `OIDC_ENABLED`               | bool     | `false`          | Serve the provider.                                                                                                                                                                                                                                                 |
| `listen`                | `OIDC_LISTEN`                | address  | `127.0.0.1:5557` | Bind address.                                                                                                                                                                                                                                                       |
| `tls`                   | `OIDC_TLS`                   | bool     | `false`          | Serve HTTPS. Both `cert_path` and `key_path` are then required.                                                                                                                                                                                                     |
| `cert_path`             | `OIDC_CERT_PATH`             | path     | empty            | Certificate (not resolved against the config directory — use an absolute path).                                                                                                                                                                                     |
| `key_path`              | `OIDC_KEY_PATH`              | path     | empty            | Private key (same caveat).                                                                                                                                                                                                                                          |
| `issuer`                | `OIDC_ISSUER`                | string   | empty            | What lands in every token's `iss` and what the **browser** must reach — the public address, which behind a proxy is not the bind address. Required when enabled; must be an absolute URL and must not end in a slash (verifiers compare it to `iss` byte for byte). |
| `allowed_origins`       | `OIDC_ALLOWED_ORIGINS`       | list     | empty            | Web origins whose pages may read discovery, the keys and the token endpoint from script. A single-page application never shares an origin with its provider.                                                                                                        |
| `session_lifetime`      | `OIDC_SESSION_LIFETIME`      | duration | `12h`            | How long one sign-in is good for, however active.                                                                                                                                                                                                                   |
| `session_idle`          | `OIDC_SESSION_IDLE`          | duration | `2h`             | How long a sign-in survives unused.                                                                                                                                                                                                                                 |
| `code_lifetime`         | `OIDC_CODE_LIFETIME`         | duration | `5m`             | Bounds an authorization code and an unfinished sign-in.                                                                                                                                                                                                             |
| `token_lifetime`        | `OIDC_TOKEN_LIFETIME`        | duration | `1h`             | Bounds an issued token.                                                                                                                                                                                                                                             |
| `service_account_group` | `OIDC_SERVICE_ACCOUNT_GROUP` | string   | empty            | Directory group whose members may use the client credentials grant — a service account asking for a token with its own name and password. Empty turns the grant off: without a gate every person's password would double as a machine key.                          |
| `clients`               | —                            | list     | (see below)      | The relying parties. Must be non-empty when the provider is enabled.                                                                                                                                                                                                |

Each entry of `clients`:

| Key                         | Type   | Meaning                                                                                                                                                                                                                                                 |
|-----------------------------|--------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `id`                        | string | Client id; required. May be any string — an id token's audience **is** the client id, so a deployment that identifies services by URL should use the service's URL.                                                                                     |
| `name`                      | string | Display name.                                                                                                                                                                                                                                           |
| `secret`                    | string | Makes the client confidential — one that runs on a server and can keep it. Demanded at the token endpoint in addition to PKCE, not instead. HTTP Basic cannot carry an id containing a colon, so a client named by URL presents the secret in the form. |
| `secret_file`               | path   | Reads the secret from a file instead. When both are set the file wins. Not resolved against the config directory — use an absolute path.                                                                                                                |
| `redirect_uris`             | list   | Matched **whole**: prefix matching is how a redirect turns into an open redirect.                                                                                                                                                                       |
| `post_logout_redirect_uris` | list   | Where the browser may be sent after logout.                                                                                                                                                                                                             |

A client with **no** `redirect_uris` is an audience, not an application: the name machines get
tokens for (a registry, a proxy), which has nowhere to send a person back to. It takes part in
the client credentials grant and is refused at `/auth` with a line saying exactly that.

## `bootstrap`

| Key    | Env              | Type | Default | Meaning                                                                                                                                                                                                                                                                       |
|--------|------------------|------|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `file` | `BOOTSTRAP_FILE` | path | empty   | A directory described in advance, applied on start-up before any listener starts. Applying a plan creates what is missing and leaves alone what is there, so a restart is not a reset. The file must exist if named. Leave empty in production and provision through the API. |

Meant for continuous integration, test stands and development containers. The plan's format is
documented in [bootstrap](bootstrap.md) and `bootstrap.example.yaml`.

## `behaviors` — policy knobs

| Key                        | Env                                  | Type     | Default | Meaning                                                                                     |
|----------------------------|--------------------------------------|----------|---------|---------------------------------------------------------------------------------------------|
| `ignore_capabilities`      | `BEHAVIORS_IGNORE_CAPABILITIES`      | bool     | `false` | Skip per-account search authorization: every authenticated account can read the whole tree. |
| `limit_failed_binds`       | `BEHAVIORS_LIMIT_FAILED_BINDS`       | bool     | `true`  | Throttle password guessing — over LDAP by source address, over Kerberos per principal.      |
| `number_of_failed_binds`   | `BEHAVIORS_NUMBER_OF_FAILED_BINDS`   | int      | `3`     | Failures tolerated inside the window before blocking.                                       |
| `period_of_failed_binds`   | `BEHAVIORS_PERIOD_OF_FAILED_BINDS`   | duration | `10s`   | The counting window.                                                                        |
| `block_failed_binds_for`   | `BEHAVIORS_BLOCK_FAILED_BINDS_FOR`   | duration | `60s`   | How long a blocked source or principal is refused.                                          |
| `prune_source_table_every` | `BEHAVIORS_PRUNE_SOURCE_TABLE_EVERY` | duration | `10m`   | How often the source table is pruned.                                                       |
| `prune_sources_older_than` | `BEHAVIORS_PRUNE_SOURCES_OLDER_THAN` | duration | `10m`   | Age at which a source entry is dropped.                                                     |

One limiter covers every door that takes a password — LDAP binds, Kerberos pre-authentication
and the console sign-in — so a guesser blocked on one protocol cannot simply carry on at
another. The Kerberos-side numbers correspond to FreeIPA's `krbPwdMaxFailure`,
`krbPwdFailureCountInterval` and `krbPwdLockoutDuration`.

## Validation summary

`ldap-kdc --check-config` reports the first error that would keep the service from starting:

- `server.realm` is required and must match the realm pattern; `server.domain_sid` must begin
  with `S-1-5-21-`; `server.ssh_key_attrs` must name at least one attribute.
- `database.url` must be a `sqlite://` or `postgres://` URL, and `database.master_key_file` is required.
- Every **enabled** listener's address must parse as `host:port`.
- TLS: `ldap` (with `tls: true`), `api` (with `tls: true`) and `oidc` (with `tls: true`) require
  both `cert_path` and `key_path`. `ldaps` requires both or neither (the deferred-certificate
  rule above).
- `kdc.enc_types` must be non-empty when the KDC is enabled; `max_ticket_life` and `clock_skew`
  must be positive; `max_renewable_life` must not be shorter than `max_ticket_life`;
  `udp_max_size` ≥ 576; `kpasswd` requires the KDC.
- DNS, when enabled: `hostname` required and fully qualified, `addresses` required and all valid
  IPs, `ttl` positive.
- OIDC, when enabled: `issuer` required, absolute, no trailing slash; `clients` non-empty and
  every client needs an `id`.
- `bootstrap.file`, when named, must exist.
- At start-up the ID range is checked as it is pinned: positive base and size, RIDs ≥ 1000,
  ranges inside the 32-bit space, primary and secondary intervals non-overlapping.

## Minimal example

Enough to run a realm from the built-in defaults (LDAP, KDC and kpasswd enabled on their
standard ports, API on loopback):

```yaml
server:
  realm: EXAMPLE.COM

database:
  url: sqlite:///var/lib/ldap-kdc/ldap-kdc.db
  master_key_file: /var/lib/ldap-kdc/master.key
```

## Full example

A shortened rendering of `ldap-kdc.example.yaml`, which is the canonical commented reference:

```yaml
debug: false
structured_log: false

server:
  realm: EXAMPLE.COM
  # domain: example.com            # derived from the realm
  # base_dn: dc=example,dc=com     # derived from the domain
  # netbios_name: EXAMPLE          # first label of the realm
  # domain_sid: S-1-5-21-...       # generated on first start, then pinned
  name_format: cn
  group_format: ou
  # ldap_spn: ldap/dc.example.com  # empty turns SASL GSSAPI off
  ssh_key_attrs:
    - sshPublicKey
    - ipaSshPubKey
  anonymous_dse: true
  id_range_base_id: 1
  id_range_size: 200000
  id_range_base_rid: 1000
  id_range_secondary_base_rid: 100000000

database:
  url: sqlite:///var/lib/ldap-kdc/ldap-kdc.db
  master_key_file: /var/lib/ldap-kdc/master.key

ldap:
  enabled: true
  listen: 0.0.0.0:389
  tls: false                       # StartTLS; needs cert_path and key_path

ldaps:
  enabled: false
  listen: 0.0.0.0:636
  # No cert_path: handshakes fail until the Vault PKI enrollment delivers one.

kdc:
  enabled: true
  listen: 0.0.0.0:88               # TCP and UDP
  max_ticket_life: 10h
  max_renewable_life: 168h
  clock_skew: 5m
  enc_types:
    - aes256-cts-hmac-sha1-96
    - aes128-cts-hmac-sha1-96
    - aes256-cts-hmac-sha384-192
    - aes128-cts-hmac-sha256-128
  require_pre_auth: true
  issue_pac: true
  allow_s4u: true
  udp_max_size: 4096

kpasswd:
  enabled: true
  listen: 0.0.0.0:464
  min_password_length: 8

dns:
  enabled: false
  listen: 0.0.0.0:53
  # zone: example.com              # defaults to server.domain
  reverse_zones:
    - 2.0.192.in-addr.arpa
  hostname: kdc.example.com
  addresses:
    - 192.0.2.10
  # mailbox: hostmaster@example.com
  ttl: 1h

api:
  enabled: true
  listen: 127.0.0.1:5555           # same address as oidc.listen shares one listener
  tls: false
  # token_file: /etc/ldap-kdc/api.token
  docs: true
  ui: true
  # spn: HTTP/ldap-kdc.example.com
  session_lifetime: 1h

oidc:
  enabled: false
  listen: 127.0.0.1:5557
  tls: false
  # issuer: https://auth.example.com   # required when enabled, no trailing slash
  allowed_origins:
    - https://app.example.com
  session_lifetime: 12h
  session_idle: 2h
  code_lifetime: 5m
  token_lifetime: 1h
  # service_account_group: service-accounts
  clients:
    - id: https://app.example.com
      name: The application
      # secret_file: /etc/ldap-kdc/app.secret
      redirect_uris:
        - https://app.example.com/
      post_logout_redirect_uris:
        - https://app.example.com/

bootstrap:
# file: /etc/ldap-kdc/bootstrap.yaml

behaviors:
  ignore_capabilities: false
  limit_failed_binds: true
  number_of_failed_binds: 3
  period_of_failed_binds: 10s
  block_failed_binds_for: 60s
  prune_source_table_every: 10m
  prune_sources_older_than: 10m
```
