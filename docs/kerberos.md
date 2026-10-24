# Kerberos: the KDC and kpasswd

The Kerberos side of ldap-kdc is two services: the KDC proper (AS and TGS exchanges, RFC 4120)
and the password service (RFC 3244). Both share the principal store with the rest of the binary,
so a password set anywhere — the REST API, an LDAP modify, `kpasswd` — re-keys both credential
forms at once. Configuration lives in the `kdc` and `kpasswd` sections of the main file; see
[configuration](configuration.md) for the general rules (environment overrides, file precedence).

```yaml
kdc:
  enabled: true
  listen: 0.0.0.0:88              # TCP and UDP, same port
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
```

The values shown are the defaults. Validation at startup: `kdc.enc_types` must be non-empty,
`max_ticket_life` must be positive, `max_renewable_life` must be at least `max_ticket_life`,
`clock_skew` must be positive, and enabling `kpasswd` without the KDC is refused. Once the
database has been initialized the realm cannot change: every stored key is salted with the realm
name, so a different `server.realm` against an existing database fails at startup rather than
failing every login later.

## What the KDC speaks

AS-REQ/AS-REP and TGS-REQ/TGS-REP, each over TCP and UDP on the same address. On TCP one request
is served per connection with the RFC 4120 4-byte length prefix; requests over 1 MiB are dropped.
On UDP a reply larger than `udp_max_size` is answered with `KRB_ERR_RESPONSE_TOO_BIG`, which tells
the client to retry over TCP — the reply is never truncated.

Beyond plain ticket issuance the TGS exchange handles:

- **Renewal** — a TGS request with the RENEW option against a renewable ticket re-issues it with a
  fresh window, up to the renew-till time fixed at issuance. The renewed ticket keeps the
  original's flags and authorization data, except INITIAL.
- **Validation of postdated tickets** — the VALIDATE option clears the INVALID flag from a
  postdated ticket whose start time has arrived.
- **S4U2Self and S4U2Proxy** — see below.
- **Cross-realm referrals** — see below.

User-to-user authentication (ENC-TKT-IN-SKEY) is refused with `KDC_ERR_BADOPTION`. PKINIT, FAST
and Kerberos-side OTP are not implemented.

## Pre-authentication

PA-ENC-TIMESTAMP is required by default, both realm-wide (`require_pre_auth: true`) and per
principal (`requiresPreAuth`, also defaulting to true when a principal is created). Either one
being set makes the KDC demand it. A request without pre-authentication is answered with
`KDC_ERR_PREAUTH_REQUIRED` and METHOD-DATA carrying PA-ETYPE-INFO2 entries — one per key the
principal holds that the client offered an enctype for — each with the principal's salt and
string-to-key parameters, so the client can derive the right key from the typed password. The
AS-REP repeats the same PA-ETYPE-INFO2 hint.

A timestamp that fails to decrypt is `KDC_ERR_PREAUTH_FAILED` and counts towards lockout; one
outside `clock_skew` is `KRB_AP_ERR_SKEW`. Turning pre-authentication off (either switch) re-opens
offline AS-REP cracking against the principal's password — it exists for principals that predate
pre-authentication, not as a convenience.

An expired password is not a dead end: the AS exchange still issues a ticket when the request
names `kadmin/changepw`, so the owner can set a new password; any other service is answered with
`KDC_ERR_KEY_EXPIRED`.

## Encryption types

Only the AES families are supported, for both key storage and session keys:

| enctype                      | number | notes                           |
|------------------------------|--------|---------------------------------|
| `aes256-cts-hmac-sha1-96`    | 18     | default preference order, first |
| `aes128-cts-hmac-sha1-96`    | 17     |                                 |
| `aes256-cts-hmac-sha384-192` | 20     | SHA-2 family, RFC 8009          |
| `aes128-cts-hmac-sha256-128` | 19     |                                 |

Anything else — single-DES, RC4-HMAC, Camellia — is refused at configuration time by name
resolution, and the KDC never holds a key of such a type. RC4 in particular is refused rather
than accepted for compatibility, however old the client. Session-key negotiation prefers the
KDC's own order over the client's, so realm policy, not the client, decides the enctype. A key is
generated for every configured enctype whenever a password is set or a principal is randomized.

Long-term keys come in two kinds: password-derived (`DeriveKeys`, salted with the RFC 4120 default
salt — realm plus concatenated components, e.g. `EXAMPLE.COMalice`) and random (`RandomKeys`, used
for `krbtgt`, `kadmin/changepw` and any service principal created without a password). Random keys
remove the offline guessing attack a password-derived key would carry.

## Ticket flags and lifetimes

A flag the client requested but policy denies is silently dropped from the ticket — the client
reads what it got from the reply. Policy comes from three places: the client principal, the
service principal, and the realm defaults in `kdc.*`.

| Flag                 | Request option                 | Granted when                                                    |
|----------------------|--------------------------------|-----------------------------------------------------------------|
| FORWARDABLE          | `forwardable` / `kinit -f`     | requested AND both principals have `allowForwardable`           |
| PROXIABLE            | `proxiable` / `kinit -p`       | requested AND both have `allowProxiable`                        |
| RENEWABLE            | `renewable` / `kinit -r`       | requested AND both have `allowRenewable`                        |
| MAY-POSTDATE         | `allow_postdate`               | requested AND the client principal has `allowPostdate`          |
| POSTDATED + INVALID  | `postdated` with a `from` time | the client principal has `allowPostdate`                        |
| OK-AS-DELEGATE       | —                              | the service principal has `okAsDelegate`                        |
| INITIAL, PRE-AUTHENT | —                              | set on AS tickets; PRE-AUTHENT when pre-authentication happened |

A start time in the future without the POSTDATED option is `KDC_ERR_CANNOT_POSTDATE`. The
RENEWABLE-OK option yields a shorter renewable ticket when the requested end time exceeds policy (RFC 4120 §3.1.3). A
requested `till` of `19700101000000Z` means "the latest policy allows", as
Heimdal sends it.

Lifetimes: the end time is the requested `till` clamped to `start + min(client.maxTicketLife,
server.maxTicketLife, kdc.max_ticket_life)`; renew-till is clamped the same way against
`maxRenewableLife` / `kdc.max_renewable_life`. A per-principal value of zero (the API renders it
as an empty string) means "use the realm default". A ticket derived from another — renewal,
S4U, cross-realm — can never outlive the ticket it derives from.

Per-principal policy is managed through the REST API (`POST`/`PATCH /api/v1/principals/{name}`):
`allowForwardable`, `allowProxiable`, `allowRenewable`, `allowPostdate`, `okAsDelegate`,
`okToAuthAsDelegate`, `maxTicketLife`, `maxRenewableLife`, `expiresAt`, `passwordExpiresAt`.
The read view repeats the policy as the `krbTicketFlags` bitmask MIT and FreeIPA record, with the
same bit values. See [api](api.md).

## The PAC

With `issue_pac: true` (the default), tickets for principals linked to a directory account carry a
Microsoft PAC inside an AD-IF-RELEVANT wrapper, so a service that does not understand it ignores
it rather than rejecting the ticket. The buffers, per MS-PAC:

- **KERB_VALIDATION_INFO (1)** — the account's logon name and full name, home directory, password
  timestamps, group membership as RID list, `userAccountControl` (NORMAL_ACCOUNT), the logon
  server and domain names (both the realm's `server.netbios_name`) and the domain SID (`server.domain_sid`, generated on
  first start and pinned in the database).
- **PAC_CLIENT_INFO (10)** — the account name and the TGT authentication time.
- **S4U_DELEGATION_INFO (11)** — only on S4U2Proxy tickets; the delegation target and the path of
  services the identity passed through.
- **Server checksum (6)** — keyed with the target service's key, so the service can confirm the
  KDC authored the authorization data in its ticket.
- **KDC checksum (7)** — keyed with the `krbtgt` key over the server signature, so the KDC can
  confirm on a later S4U2Proxy or renewal that a service did not rewrite the group membership in a
  PAC it was handed.

RIDs are not derived from `uidNumber`/`gidNumber` directly: they are allocated once per object
from the realm's identifier range (`server.id_range_base_id`, `id_range_size`,
`id_range_base_rid` default 1000, `id_range_secondary_base_rid` default 100000000) and stored, the
way FreeIPA's ipa-local range works — the uid and gid spaces are independent, so a user and a
group that share a number must not end up with the same SID. An account outside the range gets its
ticket without a PAC; the ticket still works for ordinary Kerberos services.

Not implemented: the `PAC_REQUESTOR` and `PAC_ATTRIBUTES_INFO` buffers (CVE-2022-37967),
`UPN_DNS_INFO`, and per-service PAC suppression through `NO_AUTH_DATA_REQUIRED`.

## S4U2Self and S4U2Proxy

Both are realm-gated by `allow_s4u` (default true) and then gated per principal.

**S4U2Self (protocol transition).** A service sends a TGS request naming itself plus a
PA-FOR-USER padata — the subject's name and realm, with a checksum keyed by the service's TGT
session key (HMAC-MD5 is accepted because MS-SFU pins it, regardless of the session key's
enctype). Rules:

- the target must be the requesting service itself — anything else is `KDC_ERR_BADOPTION`;
- the subject must be a principal of this realm;
- `allowedToImpersonate` on the requesting service narrows who may be impersonated (FreeIPA's
  `ipaAllowToImpersonate`); an empty list allows anyone, as a missing attribute does there;
- the resulting ticket is forwardable only if the service has `okToAuthAsDelegate` (MIT's
  `OK_TO_AUTH_AS_DELEGATE`, AD's TrustedToAuthForDelegation) — and even then, not when the user's
  own policy forbids forwarding. Without the flag the ticket is never forwardable, whatever the
  request asked for, which is what keeps the flag deciding something: only a forwardable ticket
  can go on to be delegated.

**S4U2Proxy (constrained delegation).** A TGS request with KDC option bit 14 (CNAME-IN-ADDL-TKT) and the user's ticket
to the requesting service as the additional (evidence) ticket. Rules:

- the target must appear in the requesting service's `allowedToDelegateTo` list (an empty list
  disables constrained delegation for the principal; entries match case-insensitively, and an
  entry without `@REALM` matches the principal part only);
- the evidence ticket must have been issued to the requesting service, must be valid, and must be
  forwardable — the flag is the user's consent, carried in the ticket the user obtained;
- when PACs are issued, the evidence ticket's PAC KDC signature is verified against the `krbtgt`
  key — the requesting service holds its own key and could have rewritten the PAC otherwise;
- `allowedToImpersonate` applies to the evidence ticket's subject, exactly as in S4U2Self;
- the issued ticket is forwardable and carries S4U_DELEGATION_INFO.

## Cross-realm trusts

A trust is a row in the `trusts` table plus the shared keys, which live in ordinary principals:
`krbtgt/REMOTE@LOCAL` lets this realm's clients be referred outwards, `krbtgt/LOCAL@REMOTE` lets
the remote realm's clients be accepted here. Both realms derive the keys from the same password,
so the same string is entered on each side:

```sh
curl -s -X POST $API/trusts -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "remoteRealm": "PARTNER.COM", "direction": "bidirectional",
  "password": "the shared trust secret"
}'
```

`direction` is `outbound`, `inbound` or `bidirectional` (default); `transitive` and `enabled`
default to true. The matching krbtgt principals are created alongside, or re-keyed when they
already exist — re-keying is a normal operation, and because the remote realm is unique a password
rotation is done by deleting and re-creating the trust. `PATCH /api/v1/trusts/{realm}` edits
direction, transitivity and the enabled switch; `DELETE` removes the record and both krbtgt
principals. There is no trust object in the bootstrap plan — trusts are created through the API
only.

**Referrals.** A TGS request for `krbtgt/OTHER@THIS-REALM` with an outbound trust is answered with
a cross-realm TGT keyed with the shared secret. A request that names a service in another realm
directly is referred to that realm's TGS. Host-based referral (RFC 6806 §8) covers the common case
where the client only knows a host name: when this realm does not hold the requested service, the
host component is matched against the lowercased names of trusted realms — a service on a host
under `partner.com` belongs to `PARTNER.COM` — longest match wins, outbound-enabled trusts only.

**Inbound.** A TGT presented from a remote realm decrypts against `krbtgt/LOCAL@REMOTE`; the trust
must allow inbound, and a path that already crossed another realm continues only when the trust is
`transitive` (`KDC_ERR_PATH_NOT_ACCEPTED` otherwise). The issuing realm is recorded in the
ticket's transited field. The PAC authored by the client's own realm is relayed and re-signed for
the target service rather than rebuilt — with **no SID filtering**: a trust is a statement that
the remote realm's claims are accepted. Extend one only to a realm whose administrators you would
grant the same authority directly.

## Principals, aliases, keys and keytabs

**Name forms.** `name`, `service/host`, `name/instance` — components separated by `/`, with an
optional `@REALM` (the realm is upper-cased; without one the service realm applies; a backslash
escapes a literal `@` or `/`). Multi-component names are advertised as `KRB_NT_SRV_INST`, single
components as `KRB_NT_PRINCIPAL`. On first start two principals are created automatically with
random keys: `krbtgt/<REALM>` and `kadmin/changepw`. The realm's own krbtgt cannot be deleted
through the API.

**Aliases.** A principal answers to every name in its `aliases` list with the same keys:
`kinit alice.smith` takes alice's password. The reply names whatever was asked for, unless the
request carries the CANONICALIZE option — `kinit -C`, or `canonicalize = true` in `krb5.conf` —
in which case the ticket comes back in the canonical name (RFC 6806 §5). A name belongs to one
principal only, canonically or as an alias. LDAP publishes every name as `krbPrincipalName` and
the real one as `krbCanonicalName`; see [directory](directory.md).

**Key rotation.** Re-keying — a password change or a randomization — bumps the principal's `kvno`
and keeps the previous generation (two key versions are kept in total), so tickets and keytabs
issued before the change still decrypt until they expire. Rotation also clears the lockout
counters. Password-set keys are derived with the salt of the canonical name, so a password set
through an alias produces the same keys as one set through the real name.

**Keytabs.** `GET /api/v1/principals/{name}/keytab` downloads an MIT keytab (version 2 format)
with one entry per configured enctype at the current kvno — for a service principal created
without a password this is the only way the key leaves the service:

```sh
curl -s -o HTTP_www.example.com.keytab \
  -H "$AUTH" "$API/principals/HTTP/www.example.com/keytab"
```

**Client configuration.** `ldap-kdc krb5conf` prints the Kerberos client configuration of the realm
the service runs with, so a client's `krb5.conf` is generated from the same settings as the KDC:
the realm, the enctypes, the ticket lifetimes, and the addresses. With the name server on, the
configuration finds the KDC and the realm through the zone's records and names no host; without it,
the KDC and the password service are named explicitly. `[domain_realm]` maps the name server's
`dns.zone`, where the hosts are named, and `server.domain` to the realm. The file holds no secret.

```sh
ldap-kdc krb5conf -c ldap-kdc.yaml > krb5.conf                 # the name server is on
ldap-kdc krb5conf -c ldap-kdc.yaml -host kdc.example.com -o krb5.conf   # the name server is off
```

Only the configuration is read: the bootstrap plan does not need to exist for this.

**ktadd.** `ldap-kdc ktadd` adds the keys of one or more principals to a keytab file, as MIT's
`ktadd -k` does. It works on the database directly, like `kadmin.local`, so it runs where the
service's data is — in the container or on the host, with the configuration and the master key in
reach. The service may be running at the same time.

```sh
ldap-kdc ktadd -c ldap-kdc.yaml -k /etc/security/nn.keytab HTTP/nn.adh.local nn/nn.adh.local
ldap-kdc ktadd -c ldap-kdc.yaml -k /etc/security/nn.keytab hdfs
```

The keytab is merged, not overwritten: an entry for the same principal, kvno and key type is
replaced by the new one, and every other entry stays. A file that does not exist is created with
mode 0600. Unlike MIT's `ktadd`, the principal keeps its keys by default, because a new key
invalidates every keytab issued before it. Pass `-randkey` to give the principal new random keys
first (MIT's default). A missing master key is an error: `ktadd` never creates one.

Re-key a principal with `POST /api/v1/principals/{name}/password` and either
`{"password": "..."}` or `{"randomize": true}`.

## kpasswd (RFC 3244)

The password service listens on TCP and UDP at `kpasswd.listen` (default `0.0.0.0:464`). The
request is an AP-REQ for `kadmin/changepw` plus a KRB-PRIV carrying the new password; the ticket
must be INITIAL — obtained directly from an AS exchange with the current password, not renewed —
which is what proves the requester typed it just now. Protocol version 1 changes the sender's own
password; the RFC 3244 set-password version (`0xff80`) is parsed but only ever applied to the
requester's own principal — setting someone else's password goes through the REST API, where the
change is authenticated and logged. Failures use the RFC 3244 result codes (a malformed request is
`1`, a policy rejection `4`, a non-initial ticket `7`).

Policy: the new password must be at least `min_password_length` characters (default 8) and at most
72 bytes — the LDAP side stores a bcrypt digest, which ignores anything past that. A successful
change re-keys every Kerberos principal linked to the account and rewrites the LDAP digest in the
same transaction, bumps the kvno (keeping the previous generation) and clears any lockout. Password
history, character classes and minimum/maximum age are not implemented.

**Forced change.** An administrator can expire a password — `force_change: true` on a bootstrap
user, or `expiresAt`/`forceChange` on the API password endpoints — which sets
`passwordExpiresAt`. From then on the AS exchange answers `KDC_ERR_KEY_EXPIRED` for everything
except `kadmin/changepw`, so the owner's next `kinit` fails with a clear error and `kpasswd` is
the way through:

```sh
$ kinit alice
kinit: Password has expired while getting initial credentials
$ kpasswd alice        # prompts for old and new password
Password for alice@EXAMPLE.COM: ...
```

## Lockout and replay protection

Password guessing through the AS exchange is bounded per principal by the lockout policy, taken
from the `behaviors` section (the same knobs FreeIPA exposes as `krbPwdMaxFailure`,
`krbPwdFailureCountInterval`, `krbPwdLockoutDuration`):

```yaml
behaviors:
  number_of_failed_binds: 3       # failures before lockout; 0 disables Kerberos lockout
  period_of_failed_binds: 10s     # how long a failure counts
  block_failed_binds_for: 60s     # how long the lock lasts
```

The KDC reads these three numbers directly (the `limit_failed_binds` switch gates the LDAP-side
throttle by source address, not this per-principal policy).

A failed pre-authentication increments the principal's counter; failures older than the interval
no longer count, and a successful authentication resets the tally. A locked principal is answered
as revoked until `lockedUntil` passes. An administrator can clear it immediately with
`PATCH /api/v1/principals/{name}` and `{"unlock": true}`. Related status codes: a disabled
principal and a locked-out one answer `KDC_ERR_CLIENT_REVOKED`, an expired account answers
`KDC_ERR_NAME_EXP`, and an expired service principal answers `KDC_ERR_SERVICE_EXP`.

The KDC also keeps an authenticator replay cache (RFC 4120 §3.2.3): every TGS authenticator is
remembered for twice the clock skew — anything older is rejected on its timestamp anyway — keyed
on the client, its timestamp and a digest of the presented ticket. A repeat is answered with
`KRB_AP_ERR_REPEAT`.

## Client configuration

With the built-in name server enabled, an MIT krb5 client needs no `[realms]` block at all — the
KDC is found through `_kerberos._udp`/`_tcp` SRV records, the password service through
`_kpasswd._udp`, and the realm itself through the `_kerberos` TXT record (see [dns](dns.md)):

```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = true
    dns_lookup_kdc = true
```

Without DNS discovery, spell the servers out:

```ini
[libdefaults]
    default_realm = EXAMPLE.COM

[realms]
    EXAMPLE.COM = {
        kdc = kdc.example.com:88
        kpasswd_server = kdc.example.com:464
        admin_server = kdc.example.com:464
    }
```

One pitfall worth configuring away: MIT krb5 defaults `dns_canonicalize_hostname` and `rdns` to
true, so a client asking for a host-based service rewrites the host name through DNS before
turning it into a principal. With no reverse zone — or one that answers with different names — it
ends up asking for a principal nobody registered, and the exchange fails with
`KDC_ERR_S_PRINCIPAL_UNKNOWN`. Either run the realm's reverse zones (recommended; see
[dns](dns.md)) or turn the canonicalization off on the client:

```ini
[libdefaults]
    dns_canonicalize_hostname = false
    rdns = false
```

When the KDC refuses a service name it has never heard of while holding other principals of the
same class, it logs the registered ones — that hint stays in the log rather than the KRB-ERROR.

Everyday commands against this realm:

```sh
kinit alice                          # password login, gets a TGT
kinit alice.smith                    # an alias reaches the same keys
kinit -C alice.smith                 # ticket comes back in the canonical name
kinit -r 7d alice                    # renewable TGT (clamped to policy)
klist                                # inspect the credential cache
kvno HTTP/www.example.com            # fetch a service ticket, shows its kvno
klist -k -t HTTP_www.example.com.keytab   # inspect a downloaded keytab
kpasswd alice                        # change a password (RFC 3244)
kdestroy                             # drop the cache
```

## Not implemented

Stated plainly: user-to-user authentication (ENC-TKT-IN-SKEY), PKINIT, FAST and Kerberos-side OTP (the one-time password
applies to LDAP binds only), password history and character-class rules,
`PAC_REQUESTOR`/`PAC_ATTRIBUTES_INFO`/`UPN_DNS_INFO` PAC buffers, `NO_AUTH_DATA_REQUIRED`, SID
filtering on inbound cross-realm PACs, and the kadmin RPC protocol (administration is the REST
API). For the wider comparison with FreeIPA and Active Directory see [architecture](architecture.md)
and the README.
