# ldap-kdc

One directory served over both LDAP and Kerberos, managed through a REST API.

An account created here can bind over LDAP **and** obtain a Kerberos ticket, because both
credentials are written from the same password in the same transaction. That is the point of the
service: the two protocols normally need two different secrets, and keeping them in step by hand is
where directory deployments go wrong.

## Why one store is not optional

An LDAP simple bind compares a password against an irreversible digest. Kerberos cannot do that: to
decrypt a client's pre-authentication and to seal a ticket, the KDC has to reproduce the
principal's long-term key exactly, and a key cannot be derived from a bcrypt digest.

So a password set through this service writes both forms at once:

* a bcrypt digest, for LDAP binds;
* one long-term key per configured enctype, derived with string-to-key, for Kerberos.

The consequence is worth stating plainly: **an account that only ever received a digest can bind
over LDAP but can never obtain a ticket.** Setting the password through the REST API, through
`kpasswd`, or by writing `userPassword` over LDAP fixes both sides together.

Key material is reversible by construction, so everything stored is sealed with AES-256-GCM under a
master key held in a separate file. A stolen database is not, by itself, a stolen realm.

## What it speaks

**LDAP / LDAPS** — bind (with TOTP and application passwords), search, modify, delete. StartTLS on
the plain port. The DN layout follows glauth's, so existing client configuration keeps working:

```
cn=alice,ou=staff,ou=users,dc=example,dc=com     a user, under its primary group
ou=staff,ou=groups,dc=example,dc=com             a group
```

**Kerberos (KDC)** — AS and TGS exchanges over TCP and UDP with:

* PA-ENC-TIMESTAMP pre-authentication, required by default, answered with PA-ETYPE-INFO2 salt hints;
* AES enctypes only (SHA-1 and SHA-2 families); single-DES and RC4 are refused outright;
* ticket flags from the request, clamped by per-principal and realm policy: forwardable, proxiable,
  renewable, postdated, ok-as-delegate;
* renewal and validation of postdated tickets;
* a Microsoft PAC with group membership, signed so Windows and Samba services accept it;
* S4U2Self (protocol transition) and S4U2Proxy (constrained delegation), each gated per principal;
* cross-realm referrals, including host-based referral by domain name (RFC 6806 §8);
* an authenticator replay cache and per-principal lockout after repeated failures.

**kpasswd (RFC 3244)** — users change their own password with the standard tool, and both
credential forms move together.

**DNS** — an authoritative name server for the realm's zone: SOA and NS at the apex, the service
discovery records Kerberos clients look for, address records managed through the REST API, and
reverse answers derived from those address records rather than kept as a second copy. It is
authoritative only; a name outside the configured zones is refused rather than resolved, so the
service cannot become an open resolver.

**REST** — the management surface, plus `/healthz`, `/readyz` and Prometheus `/metrics`.

## Getting started

```sh
go build -o ldap-kdc ./cmd/ldap-kdc

cp ldap-kdc.example.yaml ldap-kdc.yaml
$EDITOR ldap-kdc.yaml          # set server.realm and api.token at least

./ldap-kdc -c ldap-kdc.yaml --check-config
./ldap-kdc -c ldap-kdc.yaml
```

Every setting also has an environment variable, named `<SECTION>_<NAME>`: the realm is
`SERVER_REALM`, the KDC address `KDC_LISTEN`, the management token
`API_TOKEN`. The order is defaults, then the environment, then the file, so a key written
in the YAML is what the service runs with; delete it to let the environment supply the value. With
no file at all the service configures itself from the environment alone.

The first start generates the master key, creates the database, and provisions the realm's
`krbtgt/REALM` and `kadmin/changepw` principals with random keys. Back up the master key file.

### First accounts

```sh
API=http://127.0.0.1:5555/api/v1
AUTH="Authorization: Bearer $TOKEN"

# A group whose members may read the directory and manage it.
curl -s -X POST $API/groups -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "name": "admins", "gidNumber": 5000,
  "capabilities": [{"action":"search","object":"*"}, {"action":"write","object":"*"}]
}'

# A user. Its Kerberos principal is created alongside it and keyed from the same password.
curl -s -X POST $API/users -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "name": "alice", "primaryGroup": 5000,
  "givenName": "Alice", "sn": "Example", "mail": "alice@example.com",
  "password": "a sufficiently long password"
}'
```

Then both of these work:

```sh
ldapsearch -H ldap://127.0.0.1:389 -x \
  -D "cn=alice,ou=admins,ou=users,dc=example,dc=com" -w '...' \
  -b "dc=example,dc=com" "(objectClass=posixAccount)"

kinit alice@EXAMPLE.COM
```

### A service principal

Service principals are keyed randomly — there is no password to guess — and the key reaches the
service as a keytab:

```sh
curl -s -X POST $API/principals -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name": "HTTP/www.example.com"}'

curl -s $API/principals/HTTP/www.example.com/keytab -H "$AUTH" -o http.keytab
```

## REST reference

Everything under `/api/` requires `Authorization: Bearer <token>` when `api.token` is set.
`/healthz`, `/readyz` and `/metrics` are always open, so a scraper does not need a credential that
can change passwords.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/stats` | realm summary: counts, enctypes, accounts without a password |
| GET POST | `/api/v1/users` | list, create (creates the principal too unless `createPrincipal: false`) |
| GET PATCH DELETE | `/api/v1/users/{name}` | read, edit, remove |
| POST | `/api/v1/users/{name}/password` | set the password on both sides |
| GET POST | `/api/v1/users/{name}/app-passwords` | list, mint (the secret is returned once) |
| DELETE | `/api/v1/users/{name}/app-passwords/{id}` | revoke one |
| GET POST | `/api/v1/groups` | list, create |
| GET PATCH DELETE | `/api/v1/groups/{name}` | read, edit, remove |
| GET | `/api/v1/groups/{name}/members` | resolved membership, following included groups |
| GET POST | `/api/v1/principals` | list, create |
| GET PATCH DELETE | `/api/v1/principals/{name}` | read, edit policy, remove |
| POST | `/api/v1/principals/{name}/password` | re-key from a password or `{"randomize": true}` |
| GET | `/api/v1/principals/{name}/keytab` | keytab for the current key version |
| GET POST | `/api/v1/dns/records` | list (optionally `?name=`), create a record |
| DELETE | `/api/v1/dns/records/{id}` | remove one |
| GET POST | `/api/v1/trusts` | list, create a cross-realm trust |
| GET PATCH DELETE | `/api/v1/trusts/{realm}` | read, edit, remove |

Principal names may carry a realm (`HTTP/host@OTHER.COM`); without one the service realm applies.
A password change keeps the previous key version, so tickets and keytabs issued before the change
keep working until they expire.

### Cross-realm trust

Both realms derive the shared keys from the same password, so the same string is entered on each
side:

```sh
curl -s -X POST $API/trusts -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "remoteRealm": "PARTNER.COM", "direction": "bidirectional",
  "password": "the shared trust secret"
}'
```

This creates `krbtgt/PARTNER.COM@EXAMPLE.COM` for outbound referrals and
`krbtgt/EXAMPLE.COM@PARTNER.COM` for inbound ones. A client asking for a service on a host under
`partner.com` is referred to that realm's ticket-granting service.

## Authorization

An authenticated LDAP client still needs a capability to read anything, granted on the account or
on any group it belongs to:

```json
{"capabilities": [{"action": "search", "object": "ou=users,dc=example,dc=com"}]}
```

`object` may be `*`, an exact DN, or a subtree that covers the request. `write` governs LDAP modify
and delete; a user may always change their own attributes without it. Set
`behaviors.ignorecapabilities` to drop the check entirely.

## Operational notes

* **Back up the master key** separately from the database. Without it every stored key is
  unreadable and the realm has to be rebuilt.
* **The realm name cannot change.** It is part of every salt, so the service refuses to open a
  database that was initialized for a different one.
* **The domain SID cannot change** once members have derived ACLs from it.
* **RIDs in the PAC come from POSIX ids**: `uidNumber` for users, `gidNumber` for groups. Keep them
  stable and inside 32 bits.
* **Bind the REST API to loopback or set a token.** It can set any account's password; the service
  logs a warning if it is reachable without one.

### Client configuration

With the name server enabled and a reverse zone for the addresses in use, an MIT krb5 client needs
no `[realms]` block at all:

```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = true
    dns_lookup_kdc = true
```

The KDC is found through `_kerberos._udp.example.com`, the password service through
`_kpasswd._udp`, and the realm itself through the `_kerberos` TXT record.

Without a reverse zone the client's own canonicalisation works against you. MIT krb5 defaults
`dns_canonicalize_hostname` and `rdns` to true, so a program asking for a host-based service --
anything using GSSAPI, such as `ssh`, `curl --negotiate` or `ldapsearch -Y GSSAPI` -- resolves the
host forward, then looks the address back up, and builds the service principal from whatever the
PTR said. With no PTR record, or one naming something else, it asks the KDC for a principal that
was never created and the exchange fails with `KDC_ERR_S_PRINCIPAL_UNKNOWN`. Explicit principal
names, as `kgetcred HTTP/www.example.com` uses, are unaffected, which is why the failure tends to
appear only once a real application is involved.

If you run this service without its name server, or point clients at a DNS server whose reverse
zone you do not control, turn the canonicalisation off on the client:

```ini
[libdefaults]
    dns_canonicalize_hostname = false
    rdns = false
```

`rdns` alone is enough to stop the reverse lookup, and `dns_canonicalize_hostname = false` is what
MIT recommends when reverse DNS cannot be trusted; it subsumes `rdns`, which has no effect once
canonicalisation is off. The KDC also logs a hint of its own: when it refuses a service name it has
never heard of while holding other principals of the same class, it says so and names them.

## Running as a container

The published image is `ghcr.io/shulutkov/ldap-kdc`, tagged with each release. It is built from
`scratch`: the static binary, three directories and nothing else -- no shell, no package manager,
about seven megabytes -- and the process runs as an unprivileged user rather than root.

```sh
docker run \
  --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  -v ./ldap-kdc.yaml:/etc/ldap-kdc/ldap-kdc.yaml:ro \
  -v ldap-kdc-data:/var/lib/ldap-kdc \
  -p 53:53/udp -p 88:88/udp -p 88:88 -p 389:389 -p 464:464/udp \
  ghcr.io/shulutkov/ldap-kdc:latest
```

The sysctl is there because DNS, Kerberos, LDAP and the password service all live below port 1024,
which an unprivileged process may not bind while the kernel reserves that range. Docker Desktop
already opens it and needs no flag; a stock Linux Docker does not. Kubernetes has had the same
sysctl in its safe set since 1.22, so a pod can simply ask for it:

```yaml
securityContext:
  sysctls:
    - name: net.ipv4.ip_unprivileged_port_start
      value: "0"
```

Failing either, move the listeners to high ports in the configuration -- but then set the ports the
service records advertise to what clients actually reach, not what the process bound, or the SRV
records will send them somewhere nothing is listening.

Mount a volume over `/var/lib/ldap-kdc`. It holds the database and the master key, and the key is
the one file whose loss cannot be recovered from.

## Continuous integration

Two workflows, in `.github/workflows`:

* **test** runs on every branch push and pull request: `gofmt`, `go vet` over both modules, the
  unit and integration suites under the race detector, then the end-to-end suite. Nothing is
  skipped for want of a container runtime, because a runner has one.
* **release** runs on a `v*` tag. It calls the test workflow first, then builds the image for
  amd64 and arm64 and pushes it to the registry. A tag that does not pass does not get an image.

The end-to-end suite builds the same `Dockerfile` that ships and asks for the same sysctl, so what
CI proves is proved about the artifact rather than about a stand-in for it.

## Compared with FreeIPA

FreeIPA is the reference for this combination -- 389-ds and an MIT KDC over one store -- so its
mechanisms are what this service is measured against. Where the two differ, it is recorded here
rather than left to be discovered.

**Aligned.** Enctypes are the AES family FreeIPA has permitted since 4.8, in the same order.
Pre-authentication is required by default, as it is on every FreeIPA principal. Ticket policy is
published as the `krbTicketFlags` bitmask MIT and FreeIPA store, with the same bit values, and
`krbMaxTicketLife` and `krbMaxRenewableAge` alongside it. Accounts carry the Kerberos state under
its usual names -- `krbPrincipalName`, `krbCanonicalName`, `krbLastPwdChange`,
`krbPasswordExpiration`, `krbPrincipalExpiration`, `krbLoginFailedCount`, `krbLastSuccessfulAuth`,
`krbLastFailedAuth` -- and announce `krbPrincipalAux` and `krbTicketPolicyAux`. Lockout uses the
three knobs FreeIPA exposes as `krbPwdMaxFailure`, `krbPwdFailureCountInterval` and
`krbPwdLockoutDuration`. An administratively set password is expired, so its owner chooses the
final value at first login. Protocol transition follows MIT: any service may ask for a ticket to
itself in a user's name, and `OK_TO_AUTH_AS_DELEGATE` decides whether that ticket is forwardable.
Impersonation can be narrowed per service, as `ipaAllowToImpersonate` does. Expired accounts answer
`KDC_ERR_NAME_EXP` and expired services `KDC_ERR_SERVICE_EXP`, rather than both being reported as
revoked.

**Identifiers.** POSIX ids are mapped to Windows RIDs through a range with a primary and a
secondary base, and the RID is allocated once per object and stored, exactly as FreeIPA's
`find_sid_for_id` does. This matters: the uid and gid spaces are independent, so deriving a RID
from the number alone gives a user and a group that share a number the same SID, and a member
server reads one as the other. RIDs also start above 1000, below which Windows reserves them --
mapping uid 500 straight through would present that account as the domain administrator.

**DNS.** FreeIPA runs BIND with the bind-dyndb-ldap driver, which reads zones out of the directory
and keeps PTR records in step with A records through a synchronisation option. The zone here is
served directly from the store by an authoritative server built on the same DNS library CoreDNS
uses, and reverse answers are computed from the address records rather than stored, so there is
nothing to synchronise and nothing that can drift. What FreeIPA has and this does not: DNSSEC
signing, zone transfers to secondaries, per-server DNS locations, and dynamic updates from clients.

**Deliberately different.** The tree keeps glauth's layout -- `cn=user,ou=group,ou=users,$BASE` --
rather than FreeIPA's `uid=user,cn=users,cn=accounts,$SUFFIX`, so existing glauth configuration
keeps working; moving it is a decision for whoever deploys this, not one to make silently.
Administration is the REST API rather than the kadmin RPC protocol. Service principals live in the
Kerberos store and are not published as LDAP entries.

**Not implemented.** Password history, character-class rules and minimum or maximum password age;
per-group password policies with priority. PKINIT, FAST and Kerberos-side OTP -- the one-time
password here applies to LDAP binds only. The `PAC_REQUESTOR` and `PAC_ATTRIBUTES_INFO` buffers
that Windows and Samba added for CVE-2022-37967, and `UPN_DNS_INFO`. Per-service suppression of the
PAC through `NO_AUTH_DATA_REQUIRED`. SID filtering on inbound cross-realm PACs. Replication: this
is a single node, where FreeIPA is multi-master. And everything outside the directory itself --
the certificate authority, DNS, host enrolment and SSSD integration.

## Limitations

Stated plainly, because finding them at deployment time is worse:

* **LDAP add is not supported.** The protocol library does not expose the contents of an add request
  to a server handler, so there is nothing to act on; objects are created through the REST API. The
  server answers `unwillingToPerform`.
* **The RFC 3062 password-modify extended operation is not wired**, for the same reason. Replacing
  `userPassword` with an ordinary modify works and re-keys Kerberos with it.
* **`kpasswd` only changes the requester's own password.** Setting someone else's goes through the
  REST API, where the change is authenticated and logged.
* **No SID filtering on inbound cross-realm PACs.** Group membership asserted by a trusted realm is
  relayed as authored. Extend a trust only to a realm whose administrators you would grant the same
  authority directly.
* **An account outside the identifier range gets no PAC.** Its ticket is still issued and works for
  ordinary Kerberos services; only Windows and Samba authorization data is missing.
* **User-to-user authentication (ENC-TKT-IN-SKEY) is not implemented**; such requests are refused
  with `KDC_ERR_BADOPTION`.
* **Single node.** SQLite with one writer; there is no replication.

## Layout

```
cmd/ldap-kdc      the binary: configuration, start-up, ordered shutdown
internal/store    SQLite: users, groups, principals, sealed key material, migrations
internal/krbkeys  principal names, salts, string-to-key, keytab encoding
internal/kdc      AS and TGS exchanges, PAC, S4U, cross-realm, replay cache
internal/kpasswd  RFC 3244 password changing
internal/ldapsrv  LDAP handler, entry construction, failed-bind throttling
internal/api      REST management interface
internal/secret   master key handling and AEAD sealing
```

## Tests

```sh
go test ./...     # unit and integration, no container runtime needed
make e2e          # end to end against the reference clients
```

The suite drives real protocol clients rather than mocks: the KDC is exercised with the Kerberos
client library over both UDP and TCP, service tickets are decrypted with a keytab this service
issued, PAC signatures are verified as a Samba member server would, `kpasswd` is driven by the
library's own `ChangePasswd`, cross-realm referrals run between two live KDCs, and S4U2Self and
S4U2Proxy requests are assembled by hand because no client library builds them.

### End to end

One Go library agreeing with itself is not interoperability, so a second suite drives the built
binary from outside, in containers:

```sh
make e2e          # or: cd test/e2e && go test ./...
```

It compiles the service, puts it in an image with a configuration file, and starts it next to a
Debian container holding MIT krb5, OpenLDAP's clients and BIND's `dig`. The client's resolver
points at the service and its `krb5.conf` carries nothing but a realm name, so the suite covers the
things only a real client can show: that `kinit` finds the KDC through the SRV records with no
`[realms]` block at all, that `kvno HTTP/www.example.com` resolves the host forward and back with
`rdns` left on and still asks for the principal that exists, that an administratively set password
makes `kinit` demand a change and `kpasswd` complete it, and that the new password then works over
both Kerberos and LDAP.

It lives in its own Go module so the container machinery stays out of the service's dependency
graph, and it skips itself when no container runtime is reachable.

The same checks can be run by hand against the system tools:

```sh
export KRB5_CONFIG=./krb5.conf KRB5CCNAME=FILE:./ccache
kinit alice@EXAMPLE.COM                  # AS exchange
kgetcred HTTP/www.example.com            # TGS exchange
kpasswd alice@EXAMPLE.COM                # RFC 3244
ldapsearch -H ldap://127.0.0.1:389 -x -D "cn=alice,ou=..." -W -b "dc=example,dc=com"
```

Both bugs that only a third-party client could surface were found this way: an `till` of
`19700101000000Z`, which RFC 4120 defines as "the maximum policy allows" and which Heimdal sends on
every TGS request, and the AP-REP in a kpasswd reply, which must be sealed with the ticket session
key rather than the client's subkey. Each now has a regression test.

## Origins

The LDAP schema and DN layout come from [glauth](https://github.com/glauth/glauth); the Kerberos
message handling grew out of a mock KDC built on [go-krb5](https://github.com/go-krb5/krb5). Both
were reworked around a single writable store, which is what makes one password serve both
protocols.
