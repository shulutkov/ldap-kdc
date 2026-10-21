# Operations

Running the service: installation shapes, the privileges it needs and why, where its state
lives, what to back up, what can never change, and how it starts, stops and reports on itself.

For the settings themselves see [configuration](configuration.md); for the day-one provisioning
file see [bootstrap](bootstrap.md); for the compose stand see [docker-compose](docker-compose.md).

## Installation shapes

### Container image

The published image is `ghcr.io/shulutkov/ldap-kdc`, built and pushed by the release workflow
(`.github/workflows/release.yml`) when a `v*` tag passes the test suite. A release tag publishes
the semver tags `1.2.3`, `1.2`, `1` and `latest`; a pre-release publishes only its own version, so
`latest` never moves to something unfinished. Both `linux/amd64` and `linux/arm64` are built.

The image is built from the shipped `Dockerfile` and its properties matter for operations:

- **`FROM scratch`** — the image contains the static binary and three directories, nothing else.
  There is no shell, no package manager and no debugging tools. You cannot `docker exec sh` into
  it; diagnose from the logs (stderr), the [health and metrics endpoints](#health-readiness-and-metrics),
  or the management API. The image is about seven megabytes.
- **Non-root** — the process runs as uid/gid `65532` (the distroless "nonroot" id; there is no
  `/etc/passwd`, so the id is numeric). All files the image carries are owned by `65532:65532`.
- **Pure Go** — `CGO_ENABLED=0`; the SQLite driver is pure Go, so the binary is fully static.
- **Entrypoint** — `ENTRYPOINT ["/usr/local/bin/ldap-kdc"]`, `CMD ["-c", "/etc/ldap-kdc/ldap-kdc.yaml"]`.
  Arguments to `docker run <image> ...` replace the CMD, e.g. `docker run <image> -version`.
- **Exposed ports** — `53/tcp 53/udp 88/tcp 88/udp 389/tcp 636/tcp 464/tcp 464/udp 5555/tcp`.
  The EXPOSE list is documentation only; publishing is still up to `-p`/`-P`.

Build the image locally with `make image` (tags `ghcr.io/shulutkov/ldap-kdc:$VERSION`, overridable
via `IMAGE` and `VERSION`).

### Binary from source

```sh
make build                     # builds the console (needs node), then the binary that embeds it
./ldap-kdc -version            # prints the version stamped at build time
./ldap-kdc -c ldap-kdc.yaml --check-config
./ldap-kdc -c ldap-kdc.yaml
```

`make build` runs `make ui` first, so the binary always embeds the console its sources describe.
When node is not on `PATH`, pass `NODE_BIN=/path/to/node/bin`. A bare `go build` compiles but
embeds no console — `/ui/` serves a placeholder page instead. The binary's flags:

| Flag             | Effect                                                            |
|------------------|-------------------------------------------------------------------|
| `-c`, `-config`  | configuration file path (default `ldap-kdc.yaml`)                 |
| `--check-config` | validate the configuration and exit 0, printing realm and base DN |
| `-version`       | print the version and exit                                        |

An empty path (`-c ""`) configures the service from the environment alone; a path that does not
exist is an error, not a silent fall-back to defaults. See [configuration](configuration.md) for
the defaults → environment → file precedence.

### systemd unit

The shipped unit is `ldap-kdc.service`, installed as `/etc/systemd/system/ldap-kdc.service`,
with the binary at `/usr/local/bin/ldap-kdc` and the configuration at
`/etc/ldap-kdc/ldap-kdc.yaml`. Create the service account with the sysusers fragment quoted in
the unit's header comment:

```sh
printf 'u ldap-kdc - "ldap-kdc directory service" /var/lib/ldap-kdc -\n' \
    > /etc/sysusers.d/ldap-kdc.conf && systemd-sysusers
install -m 0755 ldap-kdc /usr/local/bin/ldap-kdc
install -m 0644 ldap-kdc.service /etc/systemd/system/ldap-kdc.service
systemctl daemon-reload && systemctl enable --now ldap-kdc
```

The unit's design, in short:

- `After=network-online.target` — a KDC that starts before the host has its address binds only
  the loopback and every remote client times out, silently.
- `StateDirectory=ldap-kdc`, `StateDirectoryMode=0700` — creates `/var/lib/ldap-kdc` owned by the
  service account on first start. 0700 because the database plus the master key in it *are* the
  realm: every principal's long-term key is recoverable from the two together.
- `AmbientCapabilities=CAP_NET_BIND_SERVICE` with `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` —
  binding ports 88, 389 and 464 is the *only* privilege the service needs; the bounding set keeps
  a compromised process from acquiring any other capability even though it holds the realm's keys.
- The rest is standard lockdown: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes`,
  `PrivateTmp`, `PrivateDevices`, `ProtectKernel{Tunables,Modules,Logs}`, `ProtectControlGroups`,
  `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`, `RestrictNamespaces`,
  `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`,
  `RemoveIPC`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, and
  `SystemCallFilter=@system-service` with `~@privileged @resources` removed.
- `Type=exec`, `Restart=on-failure`, `RestartSec=2s`.

The unit's comment names ports 88, 389 and 464; `CAP_NET_BIND_SERVICE` covers the whole privileged
range, so the DNS listener on 53 and LDAPS on 636 bind the same way. Note that
`ProtectSystem=strict` makes `/etc` read-only to the service; configuration is only ever read, and
all writes go to the state directory.

## Binding ports below 1024 as non-root

DNS (53), Kerberos (88), LDAP (389), LDAPS (636) and kpasswd (464) all default to privileged
ports, and the shipped image and unit both run the process unprivileged. Whether that works
depends on `net.ipv4.ip_unprivileged_port_start`:

- **Container (stock Linux Docker/Podman):** pass the sysctl for the container's namespace:

  ```sh
  docker run \
    --sysctl net.ipv4.ip_unprivileged_port_start=0 \
    -v ./ldap-kdc.yaml:/etc/ldap-kdc/ldap-kdc.yaml:ro \
    -v ldap-kdc-data:/var/lib/ldap-kdc \
    -p 53:53/udp -p 88:88/udp -p 88:88 -p 389:389 -p 464:464/udp \
    ghcr.io/shulutkov/ldap-kdc:latest
  ```

  Docker Desktop already opens the whole range and needs no flag.
- **Kubernetes:** the sysctl is in the safe set since 1.22, so a pod can simply ask for it:

  ```yaml
  securityContext:
    sysctls:
      - name: net.ipv4.ip_unprivileged_port_start
        value: "0"
  ```

- **systemd on a host:** no sysctl is needed — the unit grants `CAP_NET_BIND_SERVICE` instead,
  which is the narrower answer.
- **Failing all of that:** point the listeners at high ports in the configuration. Then the ports
  the service's DNS SRV records advertise are taken from the configured listen addresses, so they
  must match what clients actually reach, not some port-mapping fiction — or discovery sends every
  client somewhere nothing is listening. See [dns](dns.md).

## State, volumes and file ownership

All mutable state lives under one directory — `/var/lib/ldap-kdc` in the image and the systemd
unit — holding exactly two things that matter:

| File (defaults from `database.*`) | What it is                                                                          |
|-----------------------------------|-------------------------------------------------------------------------------------|
| `ldap-kdc.db`                     | the SQLite database: accounts, groups, principals, sealed keys, DNS records, trusts |
| `master.key`                      | the 32-byte master key that seals every Kerberos key in the database                |

Configuration is conventionally mounted at `/etc/ldap-kdc` (read-only: the service never writes
it). Relative paths in the configuration — including `database.path` and `database.master_key_file` —
resolve against the directory holding the configuration file, not the working directory.

In the image, `/var/lib/ldap-kdc` is declared a `VOLUME` and the whole tree is pre-created owned
by `65532:65532`; a named volume initialized from the image inherits that ownership. If you bind-mount
a host directory instead, `chown 65532:65532` it first, or the first start fails creating the
master key. `/tmp` exists in the image (same ownership) because SQLite spills large sorts and
vacuums there.

The master key file is created on first start with mode `0600` (`O_EXCL`, so two racing first
starts cannot each write a different key and leave half the database undecryptable); its directory
is created `0700`. When the service generates it, the log carries exactly one warning:

```text
generated a new master key; back it up, the database cannot be read without it
```

## Start-up and shutdown

Start-up order, from `cmd/ldap-kdc/main.go`:

1. Load and validate the configuration (`--check-config` stops after this).
2. Load or create the master key, then open the database and run [migrations](#migrations-and-upgrades).
3. Pin the realm's identity in the store (see [immutability](#immutability-rules)): realm name,
   domain SID, identifier range; create the `krbtgt/<REALM>` and `kadmin/changepw` principals with
   random keys on first start.
4. Apply the bootstrap plan, if `bootstrap.file` names one, **before any listener starts** — a
   client that sees the service accept a connection sees a directory that already matches the plan.
5. Start the enabled listeners: LDAP/LDAPS, KDC, kpasswd, DNS, the management API, the OIDC
   provider. If every listener is disabled the process exits with
   `no listeners are enabled; there is nothing to serve`.

The process handles `SIGINT` and `SIGTERM`. On a signal it shuts the services down in the reverse
order of start-up — the store outlives the last listener that might still be answering from it —
bounded by a 15-second timeout; a service that misses the deadline is logged (`did not stop
cleanly`) and the exit continues.

## Health, readiness and metrics

All three are served on the management API listener (default `127.0.0.1:5555`), outside the bearer
token, so an orchestrator or scraper needs no credential that can change passwords. If the API is
disabled, none of them exist. If the API shares the OIDC provider's listener (same `listen`
address for `api` and `oidc`), the probes ride on that listener instead. See
[api](api.md) and [oidc](oidc.md).

- **`GET /healthz`** — liveness. Answers `200 {"status":"ok"}` whenever the process runs. It
  deliberately never touches the database: a stuck query cannot make a healthy process look dead.
- **`GET /readyz`** — readiness. Pings the database and checks that the realm is initialized;
  answers `200 {"status":"ok","realm":"EXAMPLE.COM"}` or
  `503 {"status":"unavailable","reason":"..."}`. It does **not** wait for anything deferred: an
  LDAPS listener started without `cert_path` serves no certificate until the first Vault PKI
  enrollment lands (handshakes fail until then), and `/readyz` still reports ready. Readiness here
  means "the store answers and the realm exists", not "every handshake you might attempt succeeds".
- **`GET /metrics`** — Prometheus text format. A private registry with the standard Go and process
  collectors plus the service's own families:

| Metric                            | Labels                      | Meaning                              |
|-----------------------------------|-----------------------------|--------------------------------------|
| `ldap_binds_total`                | `result`                    | LDAP bind attempts by result         |
| `ldap_searches_total`             | `result`                    | LDAP search operations by result     |
| `ldap_operation_duration_seconds` | `operation`                 | histogram, LDAP handling time        |
| `kdc_requests_total`              | `exchange`, `result`        | AS/TGS requests by result            |
| `kdc_request_duration_seconds`    | `exchange`                  | histogram, KDC handling time         |
| `kdc_tickets_issued_total`        | `kind`                      | tickets issued by kind               |
| `kpasswd_requests_total`          | `result`                    | password-change requests by result   |
| `api_requests_total`              | `method`, `route`, `status` | REST requests                        |
| `oidc_requests_total`             | `operation`, `result`       | OIDC operations by result            |
| `dns_queries_total`               | `type`, `rcode`             | DNS queries by record type and rcode |
| `dns_query_duration_seconds`      | —                           | histogram, DNS answer time           |
## Logging

Logs go to stderr via zerolog. Two top-level configuration keys shape them:

```yaml
debug: false            # true lowers the level from info to debug
structured_log: false   # true emits line-delimited JSON; false is a human-readable console format
```

Both are also environment variables (`DEBUG`, `STRUCTURED_LOG`). Structured mode is what a log
shipper wants; console mode carries RFC 3339 timestamps. Notable warnings to alert on: the master
key generation notice (once, first start), the "management API has no token and is not bound to
loopback" warning, the bootstrap file permission warning, and per-service `did not stop cleanly`
on shutdown.

## Backup and restore

Back up **two files, separately**: the database and the master key. They fail differently and
recover differently.

- **Lose the database, keep the key:** the realm is gone — every account, group, principal and DNS
  record with it — but a rebuilt realm over the same key can at least re-seal identical material.
  In practice: rebuild from a bootstrap plan and re-provision.
- **Lose the master key, keep the database:** every sealed Kerberos key is unreadable — the sealing
  is AES-256-GCM and there is no recovery path. The realm must be rebuilt from scratch: every
  principal re-keyed, every keytab re-issued, every password reset. The bcrypt digests in the
  database survive, but a digest cannot re-derive a Kerberos key, so nothing can be salvaged for
  the KDC side. This is why the image declares the volume and the unit makes the directory `0700`,
  and why the start-up log says to back the key up the moment it is generated.

For a consistent database snapshot, stop the service or use SQLite's own tooling; the database
runs in WAL mode, so copying the `.db` file from under a running writer risks missing the WAL's
contents — copy `-wal` and `-shm` along with it at minimum, and prefer a quiesced copy.

## Immutability rules

Checked at start-up, enforced by the store, and each refusal exists because changing the value
silently would corrupt something a client already holds:

- **Realm name** (`server.realm`) — written into every key's salt. Opening a database initialized
  for a different realm fails start-up: `database was initialized for realm X, not Y`. Renaming a
  realm means a new database and re-keying every principal.
- **Domain SID** (`server.domain_sid`) — baked into every PAC a client has cached and every ACL a
  member server derived from one. A configured SID that disagrees with the stored one fails
  start-up. Left empty, it is generated on first start and persisted.
- **Identifier range** (`server.id_range_*`) — pinned in the database on first start; a configured
  range that differs from the pinned one fails start-up, because every RID already handed out is
  derived from it.
- **POSIX ids** — RIDs in the PAC are allocated once per object from the `uidNumber`/`gidNumber`
  and stored. Keep ids stable and inside the configured range (and inside 32 bits): changing an
  account's uid changes the SID a member server sees, and an id outside the range gets no SID and
  therefore no PAC — the ticket is still issued, only the Windows/Samba authorization data is
  missing.

## Failed-authentication throttling

One policy, configured under `behaviors:`, protects every door that takes a password — and it is
one limiter in the process, so a guesser blocked from binding over LDAP cannot simply carry on at
the console's sign-in with the same list:

| Key                        | Default | Meaning                                               |
|----------------------------|---------|-------------------------------------------------------|
| `limit_failed_binds`       | `true`  | master switch for the throttling                      |
| `number_of_failed_binds`   | `3`     | failures within the window that trigger a block       |
| `period_of_failed_binds`   | `10s`   | the counting window; older failures do not accumulate |
| `block_failed_binds_for`   | `60s`   | how long a tripped source or principal is refused     |
| `prune_source_table_every` | `10m`   | how often the source table is pruned                  |
| `prune_sources_older_than` | `10m`   | idle age at which a source is dropped from the table  |

Two mechanisms share these knobs, from `cmd/ldap-kdc/main.go`:

- **Per source address** (`internal/failban`): failed LDAP binds and failed console/API sign-ins.
  A successful attempt clears the source's history; only failures inside the window count.
- **Per principal** (the KDC's lockout, `store.LockoutPolicy`): `number_of_failed_binds`,
  `period_of_failed_binds` and `block_failed_binds_for` double as what FreeIPA exposes as
  `krbPwdMaxFailure`, `krbPwdFailureCountInterval` and `krbPwdLockoutDuration` — an account is
  protected against guessing by the same numbers whichever protocol is attacked.

The per-source table is in memory: a restart clears it, which is also the operator's way to
un-block an address.

## Migrations and upgrades

The schema is managed by migrations embedded in the binary (`internal/store/migrations/*.sql`,
applied in name order). On every start-up the service applies each migration not yet recorded in
the `schema_migrations` table, each in its own transaction, so a failed migration leaves the schema
at the last complete version and the start-up fails loudly rather than half-way. There is nothing
to run by hand and no down-migration: **upgrades are forward-only**.

Upgrading is therefore: back up the database and master key, start the new image tag or binary
against the same files, read the `applying migration` log lines. Downgrading to a build older than
the newest applied migration is not supported — restore the pre-upgrade backup instead. Pin the
image to a release tag (e.g. `ghcr.io/shulutkov/ldap-kdc:1.2.3`) rather than `latest` where a
rollback plan matters.

## Security checklist

- **Management API token.** The API can change any account's password. Set `api.token` (preferably
  via `API_TOKEN` or `api.token_file`, not in the YAML) for any automation, and keep
  `api.listen` on loopback — its default is `127.0.0.1:5555`. With no token and a non-loopback
  address the service logs an explicit warning. The API never answers anonymously: without a token
  only a signed-in directory administrator's session gets in.
- **Bootstrap file permissions.** A plan holds passwords in clear text. Keep it mode `0600`; the
  service checks and warns on start-up when a plan containing passwords is readable by group or
  other. See [bootstrap](bootstrap.md).
- **TLS everywhere it matters.** LDAPS or StartTLS on the directory (`ldaps.cert_path`/`key_path`,
  or `ldap.tls` with certificate paths), TLS on the OIDC provider a browser talks to, TLS on the
  API if it leaves loopback. Over an untrusted network a cleartext LDAP bind is not optional
  protection. See [directory](directory.md) and [openbao-pki](openbao-pki.md) for enrolling the
  LDAPS certificate from a Vault PKI.
- **`api.docs: false`** where the management port is reachable more widely than its administrators —
  the OpenAPI document and Swagger UI sit outside the token check so a browser can reach them.
- **Keep pre-authentication on.** `kdc.require_pre_auth: false` exposes every principal to offline
  AS-REP cracking; it exists only for principals that predate pre-auth.
- **Protect the state directory.** The database plus `master.key` together are every principal's
  long-term key: mode `0700`, owned by the service account, backed up separately.
- **Trustworthy trusts only.** There is no SID filtering on inbound cross-realm PACs — extend a trust
  only to a realm whose administrators you would grant the same authority directly. See
  [kerberos](kerberos.md).

## Capacity and performance notes

Only what the code justifies:

- **Single node, single writer.** The store is SQLite on local disk; write transactions are
  serialized on an in-process mutex, deliberately — one predictable writer beats concurrent writers
  colliding on `SQLITE_BUSY`. There is no replication and no failover. See
  [architecture](architecture.md).
- **WAL mode with a small pool.** The database opens with `journal_mode(WAL)`,
  `synchronous(NORMAL)`, `busy_timeout(10000)`, foreign keys on, at most 8 open connections (4
  idle). WAL lets readers run while the single writer holds its transaction, so reads scale with
  the pool while writes serialize.
- **Password hashing is the deliberate cost.** Setting or verifying a password pays a bcrypt
  verification; the failed-bind throttling exists partly because each guessing attempt costs the
  server that hash and the attacker nothing.
- **Scale expectations.** This service is built for test stands and CI: a realm in one process and
  one file that starts in a second. Where a directory has to survive people, hardware and time,
  use one built for it (FreeIPA, Samba AD, 389-ds, Active Directory).
