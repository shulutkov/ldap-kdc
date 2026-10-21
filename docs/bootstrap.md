# Bootstrap plans

A bootstrap plan is a YAML file that describes the directory the service should come up with:
groups, users, Kerberos service principals and DNS records. It exists for the cases where nobody
is present to provision the realm — a continuous integration job, a test stand, a development
container. The alternative is a pile of REST calls in a start-up script, which has to be kept in
step with the service by hand and tends not to be.

A complete annotated plan ships in the repository root as `bootstrap.example.yaml`; the
[docker-compose](docker-compose.md) stand applies `compose/bootstrap.yaml` the same way.

## Enabling

Point the service at a plan through the [configuration](configuration.md):

```yaml
bootstrap:
  file: /etc/ldap-kdc/bootstrap.yaml
```

or through the environment:

```sh
BOOTSTRAP_FILE=/etc/ldap-kdc/bootstrap.yaml ldap-kdc --config /etc/ldap-kdc/ldap-kdc.yaml
```

An empty path (the default) applies nothing. A relative path is resolved against the
configuration file's directory. `Config.Validate` stats the named file, so `--check-config`
catches a plan that cannot be read before the service ever starts.

## When it runs

`applyBootstrap` in `cmd/ldap-kdc/main.go` runs after the store is opened and the realm is
initialized, but **before any listener starts** — before LDAP, the KDC, kpasswd, DNS, the API and
OIDC begin accepting connections. A client that sees an open port sees the finished directory;
there is no window in which the service is reachable but the plan is only half applied.

The realm-level facts the plan is applied against come from the configuration:

| Option              | Taken from                                  |
|---------------------|---------------------------------------------|
| `Realm`             | `server.realm`                              |
| `EncTypes`          | `kdc.enc_types` (resolved names)            |
| `MinPasswordLength` | `kpasswd.min_password_length` (default `8`) |
| `DefaultTTL`        | `dns.ttl` (default `1h`), in seconds        |

## Create-only semantics

Applying a plan **creates what is missing and leaves alone what is already there**. It is not a
reconciler: a service that reset an account's password on every restart because a file still
named it would be a hazard rather than a convenience. Change something afterwards — through the
[API](api.md), an LDAP modify, or a password change — and it stays changed.

Concretely, each entry is looked up first:

- A group whose `name` already exists is left untouched.
- A user whose `name` already exists is left untouched.
- A principal whose canonical name already exists is left untouched.
- A DNS record is skipped when a record with the same name, type **and** value already exists;
  the same name with a different value is a new record (that is how multi-valued A records are
  written).

### The one exception: renaming a group

A group's identity is its **number**, not its name — `primary_group`, `other_groups` and
`include_groups` all name gids. So when the plan names a group that does not exist, but its
`gid_number` is held by a group under a *different* name, that group is **renamed** to the
planned name instead of a new one being created. This is the only place a group can be renamed
at all; without it the insert would have met the gid's unique index and the operator would have
read `UNIQUE constraint failed: groups.gid_number` for having renamed a group in the file that
declares it.

Only the name follows the rename. The plan does not reconcile a group's other fields (`capabilities`,
`custom_attributes`, …) on any path — not on rename, not on an existing group.

The start-up log reports the outcome: one line per entry (`bootstrap group`, `bootstrap user`,
`bootstrap principal`, `bootstrap group renamed`), then a summary
`bootstrap plan applied` with `created` and `existed` counts.

## Validation before write

Two layers keep a bad file from producing a half-built realm:

1. **Strict parsing.** `Load` decodes with `yaml.Decoder.KnownFields(true)`: a misspelled or
   unknown key anywhere in the file is an error, not a silently dropped attribute. In a file
   whose whole job is to be applied unattended, an account quietly missing an attribute is the
   failure mode this rules out.
2. **Whole-plan validation.** `Apply` calls `Plan.Validate` before writing anything. Validation
   never touches the database, so an invalid plan is rejected with zero side effects — there are
   no partial plans. If validation passes but a write later fails, `Apply` stops at the first
   error and start-up aborts.

Validation checks:

- `groups`: `name` is required; names are unique case-insensitively; `custom_attributes` pass
  `store.ValidateCustomAttrs`.
- `users`: `name` is required and unique case-insensitively; `primary_group` must be positive;
  `password`, when present, is at least `MinPasswordLength` characters; `custom_attributes` pass
  the same check.
- `principals`: `name` is required and must parse as a Kerberos principal (`krbkeys.ParseName` against the realm).
- **Name claiming across the whole plan**: every Kerberos name the plan hands out — each user's
  name, each principal's name, and every `aliases` entry — is parsed against the realm and must
  be unique. Two accounts answering to one name is a state the directory cannot hold, and it is
  reported against the file (`X is claimed by both A and B`) rather than discovered as a
  constraint violation halfway through applying it.
- `dns_records`: each record is built exactly as the server will serve it (`dnssrv.ValidateRecord`): the name must be
  non-empty, the TTL positive after fallback, the
  type a known DNS record type, and the value must parse as a valid rdata for that type.

Note what validation does **not** do: it does not check that a user's `primary_group` or
`other_groups` exist. Groups are applied first precisely so that a group the plan itself defines
has a number by the time an account names it.

## Groups

```yaml
groups:
  - name: admins
    gid_number: 5000
    description: Realm administrators
    include_groups: [ 5001 ]
    capabilities:
      - action: search
        object: "*"
    custom_attributes:
      costCentre: [ "CC-42" ]
```

| Key                 | Type                                | Default        | Semantics                                                                                                                                                                                                    |
|---------------------|-------------------------------------|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `name`              | string                              | — (required)   | The group's name. Unique case-insensitively within the plan.                                                                                                                                                 |
| `gid_number`        | int                                 | auto-allocated | The group's identity. When `0` or omitted, the next free gid is allocated, starting at `5000` (above every existing one). When set and held by a differently-named group, that group is renamed (see above). |
| `description`       | string                              | empty          | Free-text description, published on the LDAP entry.                                                                                                                                                          |
| `include_groups`    | list of int                         | empty          | Gids of groups whose memberships this group inherits — nested groups, by number.                                                                                                                             |
| `capabilities`      | list of [capability](#capabilities) | empty          | Rights granted to every member of the group.                                                                                                                                                                 |
| `custom_attributes` | map string → list of strings        | empty          | Attributes the directory has no opinion about, published on the group's LDAP entry as given. See [custom attributes](#custom-attributes).                                                                    |

## Users

A user entry creates a directory account **and** the Kerberos principal that goes with it —
there is no state where one exists without the other.

```yaml
users:
  - name: alice
    uid_number: 10001
    primary_group: 5001
    other_groups: [ 5000 ]
    given_name: Alice
    sn: Smith
    mail: alice@example.com
    login_shell: /bin/bash
    home_directory: /home/alice
    ssh_keys:
      - "ssh-ed25519 AAAAC3Nz... alice@laptop"
    password: a sufficiently long password
    force_change: false
    aliases: [ alice.smith ]
    otp_secret: JBSWY3DPEHPK3PXP
    capabilities:
      - action: search
        object: dc=example,dc=com
    custom_attributes:
      departmentHead: [ "staff" ]
```

| Key                 | Type                                | Default                   | Semantics                                                                                                                                                                                                                                                                                                                                                      |
|---------------------|-------------------------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `name`              | string                              | — (required)              | Account name; also the Kerberos principal name in the realm. Unique case-insensitively within the plan.                                                                                                                                                                                                                                                        |
| `uid_number`        | int                                 | auto-allocated            | When `0` or omitted, the next free uid is allocated, starting at `10000`.                                                                                                                                                                                                                                                                                      |
| `primary_group`     | int                                 | — (required, must be > 0) | Gid of the account's primary group. Groups are applied first so the number exists.                                                                                                                                                                                                                                                                             |
| `other_groups`      | list of int                         | empty                     | Gids of further groups the account belongs to.                                                                                                                                                                                                                                                                                                                 |
| `given_name`        | string                              | empty                     | First name (`givenName`).                                                                                                                                                                                                                                                                                                                                      |
| `sn`                | string                              | empty                     | Surname.                                                                                                                                                                                                                                                                                                                                                       |
| `mail`              | string                              | empty                     | Mail address.                                                                                                                                                                                                                                                                                                                                                  |
| `login_shell`       | string                              | empty                     | POSIX login shell.                                                                                                                                                                                                                                                                                                                                             |
| `home_directory`    | string                              | empty                     | POSIX home directory.                                                                                                                                                                                                                                                                                                                                          |
| `disabled`          | bool                                | `false`                   | A disabled account is created with its Kerberos principal disabled.                                                                                                                                                                                                                                                                                            |
| `ssh_keys`          | list of strings                     | empty                     | Public keys, published under the attributes named by `server.ssh_key_attrs` (default `sshPublicKey,ipaSshPubKey`).                                                                                                                                                                                                                                             |
| `custom_attributes` | map string → list of strings        | empty                     | See [custom attributes](#custom-attributes).                                                                                                                                                                                                                                                                                                                   |
| `capabilities`      | list of [capability](#capabilities) | empty                     | Rights granted to this account alone.                                                                                                                                                                                                                                                                                                                          |
| `otp_secret`        | string                              | empty                     | A TOTP shared secret. When set, an LDAP simple bind must append the current six-digit code to the password. Never serialized back out.                                                                                                                                                                                                                         |
| `password`          | string                              | empty                     | The account's password, in the clear. See [passwords and keys](#passwords-and-kerberos-keys). Empty means the account starts with random Kerberos keys no password can produce, and no usable LDAP password.                                                                                                                                                   |
| `force_change`      | bool                                | `false`                   | Marks the password expired (its expiry is set to now), as an administrative reset through the API does — the KDC demands a change at first login. The default is the opposite of the API's: an account written into a plan is meant to be used by whatever runs next, not by a person who will be asked to choose. Set it to `true` to demand a change anyway. |
| `aliases`           | list of strings                     | empty                     | Further Kerberos names the account answers to. All names reach the same keys; a client that asks for canonicalization is told the real name in the reply. Each alias must parse as a principal name and be unique across the plan.                                                                                                                             |

### Capabilities

A capability grants an account or a group the right to perform an action on an object, following
glauth's model:

```yaml
capabilities:
  - action: search
    object: dc=example,dc=com   # an LDAP subtree, or "*" for everything
  - action: write
    object: "*"
```

`action` is typically `search` (which LDAP subtrees the account may read — an account with no
search capability sees its own entry alone) or `write` (required for LDAP modify operations).
`object` is an LDAP subtree DN or `*`. Capabilities on a group apply to every member. The whole
per-account check can be switched off with `behaviors.ignore_capabilities`; see
[configuration](configuration.md).

### Custom attributes

`custom_attributes` maps an attribute name to its values, and the pair is published on the LDAP
entry exactly as given — a policy engine elsewhere can filter on it like any other attribute.
Names that are empty, padded with spaces, or reserved for attributes the directory builds itself (`memberOf`,
`objectClass`, `uidNumber`, `krbPrincipalName`, `sshPublicKey`, …) are rejected at
validation time: a custom attribute under a reserved name would appear twice in the entry, and an
account that could write its own `memberOf` would be claiming a membership nobody granted it.

## Principals

A principal entry is a Kerberos identity with **no directory account** behind it: a service.

```yaml
principals:
  - name: HTTP/www.example.com          # no realm suffix needed; the realm is added
    enabled: true
    requires_pre_auth: true
    allow_forwardable: true
    allow_renewable: true
    ok_as_delegate: true
    aliases:
      - HTTP/web.example.com
    max_ticket_life: 10h

  - name: HTTP/app.example.com
    ok_to_auth_as_delegate: true
    allowed_to_delegate_to:
      - MSSQLSvc/db.example.com@EXAMPLE.COM
    allowed_to_impersonate:
      - alice@EXAMPLE.COM
```

| Key                      | Type            | Default             | Semantics                                                                                                                                                                                                               |
|--------------------------|-----------------|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `name`                   | string          | — (required)        | Principal name; a name without `@REALM` takes the configured realm. The realm is upper-cased.                                                                                                                           |
| `password`               | string          | empty               | Keys the principal from a string. **Leaving it out is the better choice for a service**: the principal gets random keys that cannot be guessed, and its keytab is fetched from the API.                                 |
| `enabled`                | bool            | `true`              | Whether the KDC issues tickets for this principal.                                                                                                                                                                      |
| `requires_pre_auth`      | bool            | `true`              | Demands PA-ENC-TIMESTAMP in the AS exchange. Clearing it re-opens offline AS-REP cracking against the principal's password.                                                                                             |
| `allow_forwardable`      | bool            | `true`              | May hold forwardable tickets.                                                                                                                                                                                           |
| `allow_proxiable`        | bool            | `true`              | May hold proxiable tickets.                                                                                                                                                                                             |
| `allow_renewable`        | bool            | `true`              | May hold renewable tickets.                                                                                                                                                                                             |
| `allow_postdate`         | bool            | `false`             | May hold postdated tickets.                                                                                                                                                                                             |
| `ok_as_delegate`         | bool            | `false`             | Tells clients this service may be trusted with forwarded credentials.                                                                                                                                                   |
| `ok_to_auth_as_delegate` | bool            | `false`             | MIT's `OK_TO_AUTH_AS_DELEGATE`, AD's `TrustedToAuthForDelegation`: only a service carrying it receives a forwardable S4U2Self ticket, and only a forwardable ticket can go on to be delegated.                          |
| `allowed_to_delegate_to` | list of strings | empty               | Services this one may forward a user's identity to via S4U2Proxy (constrained delegation). An empty list disables constrained delegation. Entries are full principal names, e.g. `MSSQLSvc/db.example.com@EXAMPLE.COM`. |
| `allowed_to_impersonate` | list of strings | empty               | Narrows which principals may be impersonated (FreeIPA's `ipaAllowToImpersonate`). An empty list means **any** principal.                                                                                                |
| `aliases`                | list of strings | empty               | Further names this principal answers to, spelled without the realm as `name` is.                                                                                                                                        |
| `max_ticket_life`        | duration        | `0` = realm default | Per-principal ticket lifetime cap, as a Go duration string (`10h`, `168h`). Zero uses `kdc.max_ticket_life`.                                                                                                            |
| `max_renewable_life`     | duration        | `0` = realm default | Per-principal renewable lifetime cap. Zero uses `kdc.max_renewable_life`.                                                                                                                                               |

Note the boolean fields are tri-state in the plan: omitted means the default in the table, an
explicit `false` means `false`. Durations are YAML strings parsed by `time.ParseDuration` —
`max_ticket_life: 10h`, not an integer.

## DNS records

```yaml
dns_records:
  - name: www.example.com
    type: A
    value: 192.0.2.20
    ttl: 300
```

| Key     | Type   | Default        | Semantics                                                                                                                                     |
|---------|--------|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `name`  | string | — (required)   | Record owner name.                                                                                                                            |
| `type`  | string | — (required)   | Record type, case-insensitive (`A`, `AAAA`, `CNAME`, …); validated against the DNS type registry and the value parsed as that type's rdata.   |
| `value` | string | — (required)   | The rdata. A record with the same name and type but a different value is an additional record, which is how multi-valued answers are written. |
| `ttl`   | int    | fallback chain | Seconds. When `0` or omitted: `dns.ttl` from the configuration (default `1h`); when that is zero too, `3600`.                                 |

Records live in the realm's zone. Reverse answers are derived from them, so there are no PTR
records to write. See [dns](dns.md) for the zone the server answers for.

## Passwords and Kerberos keys

A password in the plan is never stored. What the directory keeps:

- For a **user**, `SetUserPassword` writes a bcrypt digest (what LDAP binds check) and derives a
  fresh set of Kerberos keys for the account's principal — one key per enctype in
  `kdc.enc_types`, via `krbkeys.DeriveKeys` with the RFC 4120 default salt: the realm followed by
  the concatenated name components, no separators (`EXAMPLE.COMalice`). Clients compute the same
  string when they turn a typed password into a key, so it must match byte for byte. The salt
  follows the canonical name, so a password set through an alias produces the same keys.
- For a **principal** with a `password`, the same derivation against the principal's own name.
- For a **principal without** a password, `krbkeys.RandomKeys` generates random long-term keys,
  one per enctype. Random keys cannot be guessed offline, which removes the attack a
  password-derived key carries — the right choice for any service. Nobody ever types a password
  for such a principal; instead its **keytab is fetched from the API** once the service is up:

  ```sh
  curl -f -H "Authorization: Bearer $TOKEN" \
    http://localhost:8080/api/v1/principals/HTTP/www.example.com/keytab \
    -o www.keytab
  ```

  (`GET /api/v1/principals/{name}/keytab` returns a keytab file holding the current key version;
  see [api](api.md).)

The same one-account-one-principal rule makes a **user without** a password start with random
keys as well: the account exists, but no password can produce its keys, and no password is set
for LDAP binds either.

Passwords in the plan must satisfy the realm's length rule (`kpasswd.min_password_length`,
default 8); a shorter one fails validation before anything is written.

## File permissions

Passwords here are in the clear. When a plan contains any `password` (user or principal) and the
file's mode grants any access beyond its owner — any of the `0077` bits set — start-up logs a
warning naming the file and its mode:

```
WARN the bootstrap plan contains passwords and is readable beyond its owner file=/etc/ldap-kdc/bootstrap.yaml mode=0644
```

Keep the file readable by its owner alone (`chmod 600`), and prefer setting real accounts'
passwords through the [API](api.md) rather than a plan. The check only warns — it does not block
start-up, because a throwaway test stand has no reason to be stopped by it — and it is skipped
entirely for plans without passwords.

## A complete example

```yaml
# bootstrap.yaml — the directory this realm comes up with.
# Apply with:  bootstrap.file: /etc/ldap-kdc/bootstrap.yaml   (or BOOTSTRAP_FILE)

groups:
  - name: admins
    gid_number: 5000            # explicit, so users below can name it
    capabilities:
      - action: search          # members may read the whole tree…
        object: "*"
      - action: write           # …and modify it over LDAP
        object: "*"

  - name: staff
    # gid_number omitted: the next free number from 5000 up is allocated.
    custom_attributes:
      costCentre: [ "CC-42" ]     # published on the LDAP entry as given

users:
  - name: admin
    primary_group: 5000         # by gid, so a renamed group keeps its members
    given_name: Ada
    sn: Admin
    mail: admin@example.com
    password: a sufficiently long password
    # force_change defaults to false: a seeded password is usable straight away,
    # because whatever runs next is going to use it and nobody is there to be
    # asked for a new one. Set true to demand a change at first login anyway.

  - name: alice
    primary_group: 5000         # her uid_number is auto-allocated from 10000 up
    password: another long enough password
    ssh_keys:
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop"
    aliases:
      - alice.smith             # alice.smith@REALM reaches the same keys
    capabilities:
      - action: search
        object: dc=example,dc=com
    custom_attributes:
      departmentHead: [ "staff" ]

principals:
  # No password: random keys that cannot be guessed. Fetch the keytab from the
  # API once the service is up (see "Passwords and Kerberos keys" above).
  - name: HTTP/www.example.com
    ok_as_delegate: true        # clients may forward credentials to it
    aliases:
      - HTTP/web.example.com

  # Trusted to act for others — a constrained-delegation test rig.
  - name: HTTP/app.example.com
    ok_to_auth_as_delegate: true
    allowed_to_delegate_to:
      - MSSQLSvc/db.example.com@EXAMPLE.COM
    allowed_to_impersonate:
      - alice@EXAMPLE.COM

dns_records:
  # PTR answers are derived from these; there are no reverse records to write.
  - name: www.example.com
    type: A
    value: 192.0.2.20

  - name: app.example.com
    type: A
    value: 192.0.2.21
    ttl: 300                    # otherwise dns.ttl from the configuration
```

Remember the semantics when iterating on this file: restart the service and **only new entries
are created**. Editing `password:` for an existing user changes nothing — the account already
exists. Use the API (or delete the database and start fresh, which is usually right for a test
rig) to change what already exists. The rename rule above is the single exception, and it covers
group names only.

## See also

- [configuration](configuration.md) — `bootstrap.file`, `kpasswd.min_password_length`,
  `kdc.enc_types`, `dns.ttl`
- [directory](directory.md) — how groups, users and capabilities appear over LDAP
- [kerberos](kerberos.md) — principal flags, delegation, enctypes and salts
- [dns](dns.md) — the zone the records land in
- [api](api.md) — the reconciling alternative, and the keytab endpoint
- [docker-compose](docker-compose.md) — a stand that applies a plan on every fresh start
