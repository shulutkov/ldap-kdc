# The LDAP directory service

The directory is served over LDAP and LDAPS from the same SQLite store the KDC authenticates
against, so a password change, a disabled account or a new group is visible to both at once. The
DN layout and the attribute schema follow glauth's, so clients and configurations written against
glauth keep working; on top of that, entries carry the Kerberos and FreeIPA/Active Directory
attributes a client of either looks for.

The layout is fixed by the code (`internal/ldapsrv/directory.go`, `internal/ldapsrv/handler.go`),
not by data: there is no way to create an entry at an arbitrary DN. Objects are created through
the [management API](api.md), and the directory renders them.

## Configuration

Relevant keys from the [configuration file](configuration.md):

```yaml
server:
  realm: EXAMPLE.COM
  base_dn: dc=example,dc=com        # derived from realm when omitted
  domain_sid: S-1-5-21-...          # generated on first start when omitted
  name_format: cn                   # RDN attribute of user entries (default cn)
  group_format: ou                  # RDN attribute of group entries (default ou)
  ldap_spn: ldap/dc.example.com     # SASL GSSAPI service principal; empty turns SASL off
  ssh_key_attrs: # SSH keys are published under every name listed
    - sshPublicKey
    - ipaSshPubKey
  anonymous_dse: false              # let unauthenticated clients read the root DSE
  id_range_base_id: 1               # POSIX id -> RID mapping (see "Security identifiers")
  id_range_size: 200000
  id_range_base_rid: 1000
  id_range_secondary_base_rid: 100000000

ldap:
  enabled: true                     # default true
  listen: 0.0.0.0:389               # default 0.0.0.0:389
  tls: false                        # offer StartTLS on this port; needs cert_path/key_path
  # cert_path: /etc/ldap-kdc/tls.crt
  # key_path: /etc/ldap-kdc/tls.key

ldaps:
  enabled: false                    # default false
  listen: 0.0.0.0:636               # default 0.0.0.0:636
  # cert_path: /etc/ldap-kdc/tls.crt
  # key_path: /etc/ldap-kdc/tls.key

behaviors:
  ignore_capabilities: false        # skip per-account search authorization
  limit_failed_binds: true          # throttle password guessing (see "Throttling")
  number_of_failed_binds: 3
  period_of_failed_binds: 10s
  block_failed_binds_for: 60s
  prune_source_table_every: 10m
  prune_sources_older_than: 10m
```

Every key also has an environment form (`SERVER_LDAP_SPN`, `LDAP_LISTEN`, `LDAPS_ENABLED`,
`BEHAVIORS_LIMIT_FAILED_BINDS`, ...); see [configuration](configuration.md).

Notes:

- `server.base_dn` is lowercased at start-up; DNs in binds and searches are matched
  case-insensitively by lowercasing both sides.
- `server.ssh_key_attr` (singular) is the older spelling; when set, it replaces the whole list.
  Validation requires at least one SSH key attribute name.
- `ldaps` with neither `cert_path` nor `key_path` is legal and starts the listener in deferred
  certificate mode (see below). Setting only one of the pair is a configuration error.

## The two listeners: StartTLS vs LDAPS

The server runs up to two listeners over one shared handler (`internal/ldapsrv/server.go`):

- `ldap` — cleartext LDAP. When `ldap.tls: true` and a certificate pair is configured, the
  listener offers **StartTLS**: clients connect in cleartext and upgrade with the StartTLS
  extended operation.
- `ldaps` — implicit TLS from the first byte. StartTLS is deliberately **not** offered on this
  port, because the connection is already encrypted.

Both listeners require TLS 1.2 or newer (`internal/tlsutil`). `ldap.tls: true` without a
certificate pair is a startup error, as is `ldaps.enabled: true` with only half a pair.

### Deferred certificate mode (LDAPS)

With `ldaps.enabled: true` and **no** `cert_path`/`key_path`, the listener starts anyway and takes
its certificate from an in-memory holder: TLS handshakes simply fail until the Vault PKI
enrollment delivers one through `PUT /api/v1/vault/config`. The certificate is then renewed in
place, without restarting the listener. With both paths set, the certificate comes from disk and
the enrollment machinery stays off. See [OpenBao / Vault PKI integration](openbao-pki.md).

## DN layout

The layout mirrors glauth's:

```
<name_format>=<user>,<group_format>=<primary group>,ou=users,<base_dn>   user entries
<group_format>=<group>,ou=groups,<base_dn>                               group entries
<group_format>=<group>,ou=users,<base_dn>                                POSIX copies of groups
```

With the defaults (`name_format: cn`, `group_format: ou`, `base_dn: dc=example,dc=com`), a user
`alice` whose primary group is `staff`, and that group, appear as:

```
cn=alice,ou=staff,ou=users,dc=example,dc=com
ou=staff,ou=groups,dc=example,dc=com
ou=staff,ou=users,dc=example,dc=com
```

A user's DN embeds its **primary group**, so a bind DN whose group part does not match the
account's current primary group is refused. There is no `ou` container above the user: the
containers are exactly `ou=users` and `ou=groups` under the base DN.

Groups are rendered **twice**:

- Under `ou=groups` as `groupOfUniqueNames` with `uniqueMember` holding member DNs — the shape
  LDAP-aware applications group by.
- Under `ou=users` as `posixGroup` with `memberUid` holding member login names — the shape
  nsswitch/sssd expect.

Both copies carry the same `gidNumber`, `cn`, description and security identifier.

## User entries

Every user is rendered as one entry (`accountEntry` in `internal/ldapsrv/directory.go`).

### Object classes

Always: `posixAccount`, `shadowAccount`, `inetOrgPerson`, `top`.
Additionally:

- `krbPrincipalAux`, `krbTicketPolicyAux` — when the account has a Kerberos principal;
- `ipaNTUserAttrs` — when the account has a security identifier (see below).

### Attributes

| Attribute                                                                                                                                                    | Value                                                                                   | When present                                                               |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| `cn` (or `name_format`)                                                                                                                                      | the login name                                                                          | always                                                                     |
| `uid`                                                                                                                                                        | the login name                                                                          | always                                                                     |
| `ou`                                                                                                                                                         | primary group name                                                                      | always                                                                     |
| `uidNumber`, `gidNumber`                                                                                                                                     | POSIX ids; `gidNumber` is the primary group's GID                                       | always                                                                     |
| `givenName`, `sn`                                                                                                                                            | first and last name                                                                     | when set                                                                   |
| `accountStatus`                                                                                                                                              | `active` or `inactive`                                                                  | always; `inactive` means the account is disabled                           |
| `mail`                                                                                                                                                       | email address                                                                           | when set                                                                   |
| `krbPrincipalName`                                                                                                                                           | every principal name the account answers to: `name@REALM` plus each alias `alias@REALM` | when `server.realm` is set (aliases only when the account has a principal) |
| `krbCanonicalName`                                                                                                                                           | `name@REALM` — which of the names is the real one                                       | when `server.realm` is set                                                 |
| `userPrincipalName`                                                                                                                                          | `name@REALM` — the same name in the spelling Active Directory clients search by         | when `server.realm` is set                                                 |
| `krbTicketFlags`                                                                                                                                             | ticket flags as a decimal integer                                                       | when the account has a principal                                           |
| `krbLoginFailedCount`                                                                                                                                        | failed pre-authentication counter                                                       | when the account has a principal                                           |
| `krbMaxTicketLife`, `krbMaxRenewableAge`                                                                                                                     | seconds; omitted when zero (the realm default applies, as MIT's LDAP backend does)      | when set on the principal                                                  |
| `krbLastPwdChange`, `krbPasswordExpiration`, `krbPrincipalExpiration`, `krbLastSuccessfulAuth`, `krbLastFailedAuth`                                          | GeneralizedTime (`20060102150405Z`), UTC                                                | when set on the principal                                                  |
| `ipaNTSecurityIdentifier`                                                                                                                                    | `<domain SID>-<RID>`                                                                    | when the account has a RID and `domain_sid` is known                       |
| `loginShell`                                                                                                                                                 | login shell, default `/bin/bash`                                                        | always                                                                     |
| `homeDirectory`                                                                                                                                              | home directory, default `/home/<name>`                                                  | always                                                                     |
| `description`, `gecos`                                                                                                                                       | the login name                                                                          | always                                                                     |
| `memberOf`                                                                                                                                                   | DNs of every group the account belongs to, sorted                                       | always                                                                     |
| `shadowExpire` `-1`, `shadowFlag` `134538308`, `shadowInactive` `-1`, `shadowLastChange` `11000`, `shadowMax` `99999`, `shadowMin` `-1`, `shadowWarning` `7` | fixed shadow-account placeholders                                                       | always                                                                     |
| `sshPublicKey`, `ipaSshPubKey`                                                                                                                               | the account's SSH keys — the same values under **every** name in `server.ssh_key_attrs` | when the account has keys                                                  |
| `userCertificate;binary`                                                                                                                                     | DER of each imported certificate whose validity window covers now                       | when the account has valid imported certificates                           |
| custom attributes                                                                                                                                            | stored as-is, sorted by name                                                            | when set                                                                   |

`userPassword` is never emitted. Kerberos keys never leave the store.

`userCertificate;binary` carries certificates an administrator imported through the management
API (`POST /api/v1/users/{name}/certificates/import`), the same thing Active Directory publishes
for a smart-card logon certificate; expired and not-yet-valid certificates are filtered out. See
[OpenBao / Vault PKI integration](openbao-pki.md) for how such certificates get issued.

### Security identifiers (SID/RID mapping)

`ipaNTSecurityIdentifier` is `<server.domain_sid>-<RID>`. The RID comes from the identifier range
pinned in the database on first start (`server.id_range_*`), the way FreeIPA's ipa-local range
works:

- a POSIX id inside `[id_range_base_id, id_range_base_id + id_range_size)` maps to the primary
  RID `id_range_base_rid + (id - id_range_base_id)`;
- if that RID is already taken (the uid and gid spaces are independent and can collide), the
  object falls back to `id_range_secondary_base_rid + (id - id_range_base_id)`;
- a POSIX id outside the range gets **no** RID, hence no SID on the entry and no PAC in tickets.

Groups get the same treatment under `ipaNTGroupAttrs`/`ipaNTSecurityIdentifier`. Changing the
range after first start is refused: the SIDs already handed out are baked into issued PACs and
member-server ACLs.

## Group entries

| Attribute                 | `ou=groups` copy                                                    | `ou=users` copy                           |
|---------------------------|---------------------------------------------------------------------|-------------------------------------------|
| object classes            | `groupOfUniqueNames`, `top` (+ `ipaNTGroupAttrs` when a RID exists) | `posixGroup`, `top` (+ `ipaNTGroupAttrs`) |
| `cn` (and `group_format`) | group name                                                          | group name                                |
| `gidNumber`               | GID                                                                 | GID                                       |
| `description`             | the description, or the group name when empty                       | same                                      |
| membership                | `uniqueMember`: member user DNs, sorted                             | `memberUid`: member login names           |
| `ipaNTSecurityIdentifier` | when a RID exists                                                   | when a RID exists                         |
| custom attributes         | stored as-is, sorted by name                                        | same                                      |

## Root DSE, schema and containers

A base-scope search on the empty DN returns the root DSE:

```
objectClass: top, LDAProotDSE
supportedLDAPVersion: 3
supportedSASLMechanisms: GSSAPI        # only when server.ldap_spn is set; empty otherwise
supportedControl: (empty)
supportedCapabilities: (empty)
subschemaSubentry: cn=schema
namingContexts: <base_dn>
defaultNamingContext: <base_dn>
vendorName: ldap-kdc
krbRealm: <realm>
```

The root DSE is the only thing readable without a bind, and only when `server.anonymous_dse:
true` — some clients (SSSD among them) probe it before binding. With it false, an anonymous probe
gets `Insufficient access rights`; a bound client may always read it. A search with an empty base
DN must be base-scoped; anything else is `Unwilling to perform`.

`cn=schema` answers a stub subschema entry (`objectClass: subschema`, `hasSubordinates: false`).
The base DN itself renders as `organizationalUnit` + `dcObject` with each of its RDNs as an
attribute, and `ou=users`/`ou=groups` render as plain `organizationalUnit` containers.

## Binds

### Simple bind by DN

The bind DN is lowercased and must resolve to an account. Accepted shapes (with defaults):

```
cn=alice,ou=staff,ou=users,dc=example,dc=com    # the canonical user DN
cn=alice,ou=staff,dc=example,dc=com             # without ou=users
cn=alice,dc=example,dc=com                      # name only
```

When the DN names a group, it must be the account's current primary group — a stale DN after a
primary-group change is refused. Every refusal answers the client `Invalid credentials` (49) and
nothing more; the journal carries the real reason (`no account by that name`, `the DN is outside
this directory's base`, `the primary group in the DN is not this account's`, ...), because the
code alone is useless to the operator.

### Bind by user principal name or mail

A bind DN in mail form (matching the email pattern) is first looked up as an account's `mail`
attribute, then as a principal of this realm, `user@REALM` — or one of its aliases — the way an
Active Directory client binds by UPN. The realm must match `server.realm` (case-insensitively):

```
alice@EXAMPLE.COM
alice@example.com      # matches the account's mail attribute
```

### Password, password+TOTP, application passwords

The credential decision is `store.Authenticate`, shared with the OIDC login form so the two doors
cannot disagree:

- The account's own password, bcrypt-verified.
- **TOTP appended**: when the account has an OTP secret, the last 6 characters of the presented
  string are the one-time code and the rest is the password (the LDAP convention — a simple bind
  has no separate field). A right password with a wrong or missing code is refused.
- **Application passwords**: any of the account's application passwords, presented whole, with no
  code appended.
- A disabled account, and an account that was never given a password, cannot bind at all.

Two edge cases are answered deliberately: an empty DN with an empty password is an anonymous
bind, which succeeds but establishes no identity; a non-empty DN with an empty password (LDAP's
"unauthenticated bind") is refused with `Unwilling to perform` — accepting it would hand out the
named account's authorization state without proof.

### SASL GSSAPI

A client holding a Kerberos ticket binds with it instead of a password (RFC 4752), e.g.
`ldapsearch -Y GSSAPI`. Enabled by `server.ldap_spn`; empty turns SASL off — the root DSE then
advertises no mechanisms and a SASL bind is refused with `Auth method not supported`.

- The principal must be `ldap/<host name the directory is reached by>` in this realm. On start,
  `EnsureServicePrincipal` creates it with **random keys** when missing — this service is its own
  KDC, so the key is a row in the same store and there is **no keytab file** to write, distribute
  or rotate. A configured SPN that names a directory account rather than a service principal is a
  startup error. The keytab each handshake is verified against is built from the store on the
  spot, including the previous key version, so a re-keyed principal is honoured at once.
- The exchange takes three legs (AP-REQ/AP-REP, an empty token answered with the offered
  security layers, then the client's selection). Only the **"no security layer"** choice is
  offered: SASL message protection would duplicate what StartTLS and LDAPS already do, and Active
  Directory refuses the combination outright. A client selecting anything else gets
  `Inappropriate authentication`. An authorization identity (act-as) is not supported either.
- Mutual authentication is mandatory: the directory answers the AP-REQ with an AP-REP.
- A user principal binds as its own account. A *service* principal binds as an account only when
  it is linked to one; an unlinked service principal authenticates but binds as nobody. A
  disabled account cannot bind.
- An unfinished handshake is forgotten after one minute; failed SASL binds feed the same
  throttling limiter as password binds.

## Search authorization

Filtering, scope and attribute selection are applied by the protocol library; the handler decides **which entries a
bound account may see** (`internal/ldapsrv/handler.go`):

- Anonymous: the root DSE only, and only with `server.anonymous_dse: true`. Everything below it
  requires an authenticated bind.
- A bound account may search any base DN inside `server.base_dn` (a base outside it is
  `Insufficient access rights`), but unless it holds the **capability** `search` on that base —
  its own or through a group — the answer contains **its own account entry and nothing else**.
  That is the self-read every directory allows: whatever verified the password over LDAP can read
  the account's DN and `memberOf` as the account itself.
- A capability's object is a subtree: `search` on `dc=example,dc=com` covers everything beneath
  it, and `*` covers everything. `behaviors.ignore_capabilities: true` turns the check off and
  lets every authenticated account read the whole tree.

Capabilities are managed per user and per group through the [management API](api.md); the console
needs the wider `write` capability on the base DN, see [console](console.md).

## Modify, delete, add

- **Modify** changes user entries. A user may always modify their **own** entry; anything else
  needs the `write` capability on the target DN. Setting `userPassword` goes through the same
  path as the management API: the bcrypt digest and the account's Kerberos keys are regenerated
  together (`kdc.enc_types` decides which). Modifiable attributes: `givenName`, `sn`, `mail`,
  `loginShell`, `homeDirectory`, `accountStatus` (`inactive` disables), `uidNumber`, `gidNumber`,
  `sshPublicKey`/`ipaSshPubKey`; anything else is stored as a custom attribute. Attributes the
  directory builds itself (e.g. `memberOf`) are refused with `Constraint violation` rather than
  stored, so an authorization rule reading the directory never sees a forged membership. Group
  entries cannot be modified over LDAP.
- **Delete** removes a user or group and requires the `write` capability on the target DN. There
  is no self-delete exception.
- **Add** is not offered: it is refused with `Unwilling to perform`; create objects through the
  [management API](api.md) or a [bootstrap plan](bootstrap.md).

## Throttling failed binds

`behaviors.limit_failed_binds` (default `true`) throttles password guessing per source address:
`number_of_failed_binds` (3) failures within `period_of_failed_binds` (10s) block the source for
`block_failed_binds_for` (60s), during which binds and searches from it are refused with
`Unwilling to perform`. A successful bind clears the source's history, and only failures inside
the window count — one failure a day never accumulates into a block. The source table is pruned
every `prune_source_table_every` (10m), dropping entries idle for `prune_sources_older_than`
(10m).

The limiter is **shared** with every other door that takes a password — the management API's
sign-in among them — so a guesser locked out of LDAP cannot carry on at the console with the same
list (`internal/failban`).

## Examples

```sh
# Anonymous root DSE probe (needs server.anonymous_dse: true)
ldapsearch -x -H ldap://kdc.example.com -b "" -s base "(objectClass=*)"

# Simple bind by full DN, subtree search of the whole directory
ldapsearch -x -H ldap://kdc.example.com \
  -D "cn=alice,ou=staff,ou=users,dc=example,dc=com" -w 'secret' \
  -b "dc=example,dc=com" "(objectClass=posixAccount)"

# Bind by UPN; with an OTP secret the code is appended to the password
ldapsearch -x -H ldap://kdc.example.com \
  -D "alice@EXAMPLE.COM" -w 'secret123456' \
  -b "ou=groups,dc=example,dc=com" "(objectClass=groupOfUniqueNames)"

# Bind by mail address
ldapsearch -x -H ldap://kdc.example.com \
  -D "alice@example.com" -w 'secret' \
  -b "dc=example,dc=com" "(uid=alice)"

# Application password, presented whole
ldapsearch -x -H ldap://kdc.example.com \
  -D "cn=alice,ou=staff,ou=users,dc=example,dc=com" -w 'app-password-value' \
  -b "dc=example,dc=com" "(uid=alice)"

# SASL GSSAPI with a ticket for this realm (kinit first; needs server.ldap_spn)
kinit alice
ldapsearch -Y GSSAPI -H ldap://kdc.example.com \
  -b "dc=example,dc=com" "(uid=alice)"

# StartTLS on the plain port
ldapsearch -x -ZZ -H ldap://kdc.example.com \
  -D "alice@EXAMPLE.COM" -w 'secret' \
  -b "dc=example,dc=com" "(uid=alice)"

# LDAPS
ldapsearch -x -H ldaps://kdc.example.com:636 \
  -D "alice@EXAMPLE.COM" -w 'secret' \
  -b "dc=example,dc=com" "(uid=alice)"

# An account without a search capability sees only its own entry, and reads memberOf from it
ldapsearch -x -H ldap://kdc.example.com \
  -D "alice@EXAMPLE.COM" -w 'secret' \
  -b "dc=example,dc=com" "(objectClass=*)" memberOf

# Change your own password over LDAP (Kerberos keys move with it)
ldapmodify -x -H ldap://kdc.example.com \
  -D "alice@EXAMPLE.COM" -w 'old-secret' <<'EOF'
dn: cn=alice,ou=staff,ou=users,dc=example,dc=com
changetype: modify
replace: userPassword
userPassword: new-secret
EOF
```

## See also

- [Configuration](configuration.md) — every key, its environment form and its default.
- [Kerberos KDC](kerberos.md) — the principals and ticket policies the directory publishes.
- [Management API](api.md) — creating and modifying users, groups, capabilities, certificates.
- [OpenBao / Vault PKI](openbao-pki.md) — the deferred LDAPS certificate and user certificate
  import.
- [Operations](operations.md) — throttling, logging and metrics.
