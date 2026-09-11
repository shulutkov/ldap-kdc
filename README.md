# ldap-kdc

One directory served over both LDAP and Kerberos, managed through a REST API.

An account created here can bind over LDAP **and** obtain a Kerberos ticket, because both
credentials are written from the same password in the same transaction. That is the point of the
service: the two protocols normally need two different secrets, and keeping them in step by hand is
where directory deployments go wrong.

## For testing, not for production

This is a directory for **test stands, continuous integration and development** — somewhere to get
a realm, accounts and tokens in one process and one file, so that what is being tested is the thing
under test and not the identity infrastructure around it. It is not a production directory, and the
list below is what to weigh before treating it as one rather than a to-do list that ends.

- **One process, one file, no replication.** The database is SQLite on local disk. There is no
  second copy, no failover and no backup but the one you take: every account and every key is in
  that file, and losing it loses the realm.
- **No audit trail worth the name.** Operations are logged; there is no tamper-evident record, no
  retention policy and nothing to answer "who changed this, when" after the fact.
- **The master key sits beside what it protects.** Key material is sealed with AES-256-GCM under a
  key in a file on the same disk. That defeats a stolen database; it does not defeat a stolen host,
  and there is no HSM or KMS behind it.
- **The management API is a bearer token.** One token, no scopes, no rotation, no per-administrator
  identity — and it can change any account's password.
- **The bootstrap plan carries passwords in clear text.** It exists to stand a realm up
  reproducibly, which is the opposite of what a production credential wants.
- **Not audited, and young.** The Kerberos, LDAP and OIDC sides are implemented here rather than
  taken from an established library. They are tested, they interoperate with the standard clients,
  and they have not been through anybody's security review.

Where a directory has to survive people, hardware and time, use one built for it — FreeIPA, Samba
AD, 389-ds, Active Directory — and let this one do what it is good at: being the whole of an
identity realm in one binary that starts in a second and is thrown away afterwards.

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

**OpenID Connect** — the same accounts, served to browsers, so that one sign-in reaches every
interface in front of this directory. The authorization code flow with PKCE for public clients:
discovery, JWKS, `/auth`, `/token`, `/userinfo` and `/end-session`; and the client credentials
grant for service accounts.

What it is FOR is the session. A provider that keeps none makes every application ask for a
password again, however recently the person typed one — and no application can mend that from its
own side, because the prompt is not its own. Here a sign-in sets a cookie, and the next
application's authorization completes without a form; `prompt=login` overrides it, `prompt=none`
refuses rather than asking, and `/end-session` ends it for everything at once, which is what makes
a logout button mean something.

The credential is decided by the same code as an LDAP bind — password, one-time code appended,
application passwords, disabled accounts — because two doors that decide credentials separately are
two doors that eventually disagree. Tokens carry the account's name as `sub`, its mail address, its
display name and its groups, resolved transitively exactly as a Kerberos PAC resolves them.

A client id may be any string. An id token's audience IS the client id, so a deployment that
identifies its services by URL should register the service's URL as the id; the service then checks
"is this token for me" against the name it already knows itself by.

**A service account is an account here too.** With `oidc.service_account_group` set, a member of
that group may ask for a token in its own name — client id is the account, client secret is its
password — and the same `store.Authenticate` decides it, so an application password works and a
disabled account gets nothing. Three things are narrow on purpose: membership is the switch, and
with no group configured the grant is refused outright, because otherwise every person's password
would quietly double as a machine key; the audience is required and must be a resource this
provider serves (`resource=<uri>`, RFC 8707), since a token naming nobody is a token for everybody;
and the subject carries its kind — `client:<name>` — so a consumer can tell a robot from a person
without guessing, and a rule written about people does not match a machine. No id token is issued
and no session cookie is set: nobody signed in, and a machine has no browser.

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

### A service account with an OIDC token

A machine that speaks OIDC rather than Kerberos asks in its own name. Set
`oidc.service_account_group`, put the account in that group, and it may exchange its password for a
token addressed to one of the registered resources:

```sh
curl -s -X POST $API/groups -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name": "service-accounts", "gidNumber": 5100}'

curl -s -X POST $API/users -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "name": "reporter", "primaryGroup": 5000, "otherGroups": [5100],
  "password": "a sufficiently long password"
}'

curl -s -X POST https://auth.example.com/token \
  -u 'reporter:a sufficiently long password' \
  -d grant_type=client_credentials \
  --data-urlencode 'resource=https://api.example.com'
```

The token that comes back has `sub` of `client:reporter`, the account's groups, and
`aud` of the resource that was asked for. Give the machine an **application password** rather than
the account's own (`POST $API/users/reporter/app-passwords`) and it can be withdrawn on its own,
without touching anything else the account does.

## REST reference

Everything under `/api/` requires `Authorization: Bearer <token>` when `api.token` is set.
`/healthz`, `/readyz` and `/metrics` are always open, so a scraper does not need a credential that
can change passwords.

The API describes itself. `/api/openapi.json` is an OpenAPI document **generated from the code** --
the route table and the Go types the handlers decode and encode -- when the service starts, so it
cannot drift from what the service does and there is no generator to run before a build. `/api/docs`
renders it with Swagger UI, embedded in the binary: it works in an air-gapped network, matches the
build it ships with, and costs the browser no third party. Both sit outside the token check, because
a browser cannot put a header on the address bar; the endpoints they describe do not, and Swagger
UI's **Authorize** button is where the token goes. Set `api.docs: false` where the management port is
reachable more widely than its administrators.

The prose in the document comes from the route table and from `description` tags on the fields
themselves, next to what they describe. Adding an endpoint means adding its row to that table --
handler, pattern and documentation together -- which is also what makes an undocumented route
impossible to add by accident.

| Method           | Path                                      | Purpose                                                      |
|------------------|-------------------------------------------|--------------------------------------------------------------|
| GET              | `/api/v1/stats`                           | realm summary: counts, enctypes, accounts without a password |
| GET POST         | `/api/v1/users`                           | list, create (the Kerberos principal is created with it)     |
| GET PATCH DELETE | `/api/v1/users/{name}`                    | read, edit, remove                                           |
| POST             | `/api/v1/users/{name}/password`           | set the password on both sides                               |
| GET POST         | `/api/v1/users/{name}/app-passwords`      | list, mint (the secret is returned once)                     |
| DELETE           | `/api/v1/users/{name}/app-passwords/{id}` | revoke one                                                   |
| GET POST         | `/api/v1/groups`                          | list, create                                                 |
| GET PATCH DELETE | `/api/v1/groups/{name}`                   | read, edit, remove (incl. `customAttributes`)                |
| GET              | `/api/v1/groups/{name}/members`           | resolved membership, following included groups               |
| GET POST         | `/api/v1/principals`                      | list, create                                                 |
| GET PATCH DELETE | `/api/v1/principals/{name}`               | read, edit policy and `aliases`, remove                      |
| POST             | `/api/v1/principals/{name}/password`      | re-key from a password or `{"randomize": true}`              |
| GET              | `/api/v1/principals/{name}/keytab`        | keytab for the current key version                           |
| GET POST         | `/api/v1/dns/records`                     | list (optionally `?name=`), create a record                  |
| DELETE           | `/api/v1/dns/records/{id}`                | remove one                                                   |
| GET POST         | `/api/v1/trusts`                          | list, create a cross-realm trust                             |
| GET PATCH DELETE | `/api/v1/trusts/{realm}`                  | read, edit, remove                                           |

Principal names may carry a realm (`HTTP/host@OTHER.COM`); without one the service realm applies.
A password change keeps the previous key version, so tickets and keytabs issued before the change
keep working until they expire.

### Aliases

A principal can answer to more than one name. Pass `"aliases": ["alice.smith"]` when creating a
user or a service principal, or send the list again in a `PATCH` on the principal to change it --
the field replaces what is there, so leaving a name out removes it. Every account is a principal,
so a user's aliases are edited through `/api/v1/principals/{name}` like any other.

Both names reach the same keys: `kinit alice.smith` takes alice's password. The reply names
whatever was asked for, unless the request carries the CANONICALIZE option -- `kinit -C`, or
`canonicalize = true` in `krb5.conf` -- in which case the ticket comes back in the canonical name,
as RFC 6806 requires. LDAP publishes every name as `krbPrincipalName` and the real one as
`krbCanonicalName`. A name can belong to one principal only, canonically or as an alias, and the
attempt to hand it to a second is refused rather than resolved by query order.

### Custom attributes

Users and groups carry attributes the service itself has no opinion about, published on the LDAP
entry exactly as they were given:

```sh
curl -s -X PATCH $API/users/alice -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "customAttributes": {"departmentHead": ["engineering"], "clearance": ["secret"]}
}'
```

They are ordinary attributes once published, so a system that decides something about an account
asks the directory rather than keeping a table of its own:

```sh
ldapsearch ... "(&(objectClass=posixAccount)(departmentHead=engineering))"
```

`customAttributes` replaces the whole set, so a name left out of the object is removed. The same
field exists on groups, in the bootstrap plan as `custom_attributes`, and over LDAP: an attribute
name the schema does not define is stored as a custom one by an ordinary modify.

What cannot be set this way is any attribute the directory builds itself -- `memberOf`,
`objectClass`, `uidNumber`, the `krb*` set and the rest. Those are refused with a 400 over REST and
a constraint violation over LDAP. The reason is not tidiness: an entry carrying two `memberOf`
attributes, one of them written by the account it belongs to, is exactly what an authorization
rule reading this directory must never see.

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
{
  "capabilities": [
    {
      "action": "search",
      "object": "ou=users,dc=example,dc=com"
    }
  ]
}
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
anything using GSSAPI, such as `ssh`, `curl --negotiate` or `psql` with `gssencmode=require` --
resolves the host forward, then looks the address back up, and builds the service principal from
whatever the PTR said. With no PTR record, or one naming something else, it asks the KDC for a
principal that was never created and the exchange fails with `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
Explicit principal names, as `kgetcred HTTP/www.example.com` uses, are unaffected, which is why the
failure tends to appear only once a real application is involved.

The LDAP port here is not one of those destinations. Binds are simple binds and no SASL mechanism is
offered, so `ldapsearch -Y GSSAPI` against this service fails at the bind rather than at the ticket.
A ticket obtained from this realm is for a service somewhere else.

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

## Bringing a realm up with a directory

A service that starts empty is awkward for anything automated: a test stand, a continuous
integration job or a development container has to provision itself before it can do anything, and
that provisioning has to be kept in step with the service by hand. So the directory can be
described in advance and applied at start-up:

```yaml
bootstrap:
  file: /etc/ldap-kdc/bootstrap.yaml
```

The plan holds groups, accounts, service principals and DNS records; `bootstrap.example.yaml`
covers the shape of it. Two things are worth knowing about how it behaves.

It **creates what is missing and leaves alone what is there**. It is not a reconciler. A service
that reset an account's password on every restart, because a file still named the account, would
be a hazard rather than a convenience, so a password changed after the first start survives.

A seeded password is **usable straight away**, where a password set through the API is expired so
its owner picks their own. The plan is aimed at whatever runs next, and there is nobody there to be
asked; `force_change: true` restores the other behaviour per account.

The whole plan is validated before any of it is applied, so a file with a mistake in the third
account does not leave the first two behind. Passwords in it are in the clear: keep it readable by
its owner alone, which the service checks and warns about on start-up.

The end-to-end suite uses this for its own fixtures, which is the closest thing to a demonstration
that it works: an account, a service principal and an address record exist before the first
listener accepts a connection, and `kinit` as that account succeeds without anything having
provisioned it.

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
Impersonation can be narrowed per service, as `ipaAllowToImpersonate` does. A principal may answer
to several names: `krbPrincipalName` is multivalued, `krbCanonicalName` names the real one, and a
request carrying the CANONICALIZE option -- what `kinit -C` and `canonicalize = true` in `krb5.conf`
set -- is answered in the canonical name, as RFC 6806 section 5 requires. Expired accounts answer
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
Administration is the REST API rather than the kadmin RPC protocol, and it describes itself through
an embedded OpenAPI document. Service principals live in the Kerberos store and are not published
as LDAP entries. Attributes outside the schema follow glauth: any name is accepted and published as
given, where FreeIPA would have the attribute defined in the schema first. The names the directory
builds itself are the exception and cannot be taken.

**Not implemented.** Password history, character-class rules and minimum or maximum password age;
per-group password policies with priority. PKINIT, FAST and Kerberos-side OTP -- the one-time
password here applies to LDAP binds only. The `PAC_REQUESTOR` and `PAC_ATTRIBUTES_INFO` buffers
that Windows and Samba added for CVE-2022-37967, and `UPN_DNS_INFO`. Per-service suppression of the
PAC through `NO_AUTH_DATA_REQUIRED`. SID filtering on inbound cross-realm PACs. Replication: this
is a single node, where FreeIPA is multi-master. And everything outside the directory itself --
the certificate authority, DNS, host enrolment and SSSD integration.

## Compared with Active Directory

Nothing here reimplements Active Directory. But clients written for AD are the ones most likely to
arrive at a realm that is not one, so what they find and what they do not is recorded rather than
left to a login that fails without saying why.

**The logon name.** `userPrincipalName` carries the account's canonical Kerberos principal --
`alice@EXAMPLE.COM`, the same identity `krbCanonicalName` publishes, under the spelling AD uses. It
is deliberately not the mail address. The two look alike because an AD deployment usually gives its
UPN a suffix matching the mail domain, but they are different facts: an account with no mailbox
still has a logon name. Publishing mail under this name left such an account with no logon name at
all, and a client searching by one found nothing. Measured against OpenBao's Kerberos auth method
(2026-09-08): configured with a UPN domain, it searches `(userPrincipalName=<account>@<REALM>)`, and
a ticket that authenticated perfectly well belonged to an account it then could not find. The realm
is the only suffix published -- AD's alternative UPN suffixes have no equivalent -- and a client
that can be told to search another attribute (`uid`, `cn`) never needs this one. That is the usual
answer: the UPN filter is a client's choice, not its only one.

**Names AD has under other spellings.** `sAMAccountName`: the short logon name is `uid`, and the DN
is built from `cn`. `objectSid`: the SID is here as FreeIPA's `ipaNTSecurityIdentifier`, in textual
form -- `S-1-5-21-...-<rid>` -- rather than the binary octet string AD stores. `pwdLastSet`,
`accountExpires` and the rest of the account state: the MIT and FreeIPA names listed above,
`krbLastPwdChange`, `krbPasswordExpiration`, `krbPrincipalExpiration`, `krbTicketFlags`, alongside
the `shadow*` set. `userAccountControl` exists only inside the PAC, where a member server reads it.

**Names with no counterpart.** `objectGUID`: there is no opaque per-object handle -- an object is
named by its DN and carries a SID, and that is all. `unicodePwd`: no password, in any encoding, is
readable over LDAP, and changing one goes through modify, `kpasswd` or the REST API.

**Binding.** AD accepts a UPN or `DOMAIN\user` as a simple bind name. Here a bind name is a DN under
the base, or an address-shaped string -- and that string is matched against `mail`, not against
`userPrincipalName`. So `alice@EXAMPLE.COM` binds only when it is also the account's mail address:
the UPN is a name to search BY, not one to bind AS. There is no SASL either: the root DSE answers an
empty `supportedSASLMechanisms`, so there is no GSSAPI bind, no NTLM, and no LDAP signing or
sealing. LDAPS or StartTLS is what protects a bind, and over an untrusted network it is not
optional.

**The tree.** The layout is glauth's -- `cn=alice,ou=staff,ou=users,$BASE` -- and not
`CN=Alice,CN=Users,DC=example,DC=com`. The root DSE answers `defaultNamingContext`, which is what an
AD-shaped client probes for first, but there is no configuration naming context, no Global Catalog
on port 3268, and the schema subentry answers without carrying any definitions. Nested membership
needs no special search: `memberOf` already lists every group the account reaches, including the
ones reached through other groups, so there is nothing for AD's chain-matching rule to do.

**Kerberos.** AES only. RC4-HMAC, which AD kept as a default long after it stopped being defensible
and which older clients still offer, is refused rather than accepted for compatibility. The PAC is
issued and signed so Windows and Samba services accept it, with RIDs mapped from POSIX ids;
`PAC_REQUESTOR`, `PAC_ATTRIBUTES_INFO` and `UPN_DNS_INFO` are not implemented. A trust is a shared
key created through the REST API, not an AD trust object: no NETLOGON, no trust discovery, and no
SID filtering on what a trusted realm asserts.

**Not a domain controller.** No SMB, no netlogon, no group policy, no DFS: a Windows machine cannot
join this realm the way it joins a domain. What works is the Kerberos side -- a service that
validates tickets and reads the PAC does not care which KDC issued them.

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
internal/api      REST management interface, OpenAPI document, embedded Swagger UI
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
