# DNS

ldap-kdc carries an authoritative DNS server for the realm's zones. It exists because Kerberos
leans on DNS twice: clients find the KDC through SRV records (`dns_lookup_kdc`), and a client
handed a host-based service name canonicalises the host through DNS before turning it into a
principal — including reverse DNS. Without a reverse zone answering with the names the realm
actually uses, that canonicalisation asks for a principal nobody registered, and every client has
to be configured with `rdns = false` instead. Running the name server in the same binary means an
e2e rig needs no external DNS at all: one container answers for the realm, its hosts and its
addresses.

The server is **authoritative only**. A query for a name outside the configured zones is answered
`REFUSED`, not resolved, so the service can never act as an open resolver. Replies set the
authoritative bit and never offer recursion (`RecursionAvailable = false`).

## Configuration

The `dns` section of [ldap-kdc.example.yaml](../ldap-kdc.example.yaml); see
[configuration](configuration.md) for the file/environment precedence rules. Every key is also
settable as `DNS_<NAME>`.

```yaml
dns:
  enabled: false               # default: off
  listen: 0.0.0.0:53           # default; TCP and UDP on the same address
  # zone: example.com          # default: server.domain
  # extra_zones:
  #   - example.net
  reverse_zones:
    - 2.0.192.in-addr.arpa
  hostname: kdc.example.com    # required when the server is enabled
  addresses: # the addresses hostname resolves to
    - 192.0.2.10
  # mailbox: hostmaster@example.com   # default: hostmaster@<zone>
  ttl: 1h                      # default: 1h
```

| Key             | Default             | Meaning                                                                                                                        |
|-----------------|---------------------|--------------------------------------------------------------------------------------------------------------------------------|
| `enabled`       | `false`             | Bind the DNS listeners.                                                                                                        |
| `listen`        | `0.0.0.0:53`        | One address for both TCP and UDP.                                                                                              |
| `zone`          | `server.domain`     | The primary forward zone; the realm's discovery records live here.                                                             |
| `extra_zones`   | none                | Further forward zones, answered but carrying no discovery records.                                                             |
| `reverse_zones` | none                | `in-addr.arpa` / `ip6.arpa` zones answered for.                                                                                |
| `hostname`      | none — **required** | This server's FQDN: the zone's NS, the target of every SRV record, the name `addresses` resolve to. Never guessed from the OS. |
| `addresses`     | none                | IP addresses of `hostname`; each must parse as an IP. Used for A/AAAA answers and reverse lookups of this host.                |
| `mailbox`       | `hostmaster@<zone>` | SOA contact; an `@` form is converted to the dotted SOA form (dots in the local part are escaped).                             |
| `ttl`           | `1h`                | Zone default TTL, applied to generated records, the SOA `MINIMUM` field, and records created without a TTL.                    |

Zone and hostname are lower-cased and stripped of a trailing dot; the realm is upper-cased. With
no zone configured it defaults to `server.domain`; with no hostname the server refuses to start
(`dns: hostname is required`).

If `listen` uses port `0`, the kernel-chosen TCP port is reused for UDP, so a client that retries
over the other transport still reaches the server.

### Port 53 is privileged

Binding port 53 below the `net.ipv4.ip_unprivileged_port_start` threshold requires either root or
lowering the threshold. The compose setup sets `net.ipv4.ip_unprivileged_port_start: "0"` as a
sysctls entry; see [operations](operations.md) and [docker-compose](docker-compose.md).

## Zones

`zoneFor` classifies each query name: the primary `zone`, then `extra_zones`, then
`reverse_zones` (suffix match on the zone name). A name in none of them is refused.

- **Primary zone** — carries the apex, this server's address records, and all of the realm's
  discovery records.
- **Extra zones** — get an apex (SOA and NS) and nothing else automatically. They carry only
  records stored in them, and deliberately publish no discovery records: advertising the realm
  under a second name would advertise a second realm.
- **Reverse zones** — get an apex (SOA and NS) and PTR answers derived from the address records (below). A reverse
  zone's SOA names the primary zone's name server and mailbox, with the owner
  name set to the reverse zone itself.

## Records generated automatically

Generated records are computed from the configuration at answer time, so they cannot fall out of
step with it and cannot be half-deleted. All of them carry the zone TTL.

At the **zone apex** (and each extra-zone apex):

```
example.com.  3600  IN  SOA  kdc.example.com. hostmaster.example.com. <serial> 3600 900 604800 3600
example.com.  3600  IN  NS   kdc.example.com.
```

SOA fields: `Ns` is `dns.hostname`, `Mbox` is `dns.mailbox` in dotted form, `Refresh` 3600,
`Retry` 900, `Expire` 604800, `Minttl` the zone TTL. The **serial** is the Unix time of the newest
change to the stored records (`MAX(updated_at)` of the `dns_records` table), or `1` when the zone
has never been edited — a secondary comparing serials sees the zone move when its contents do.

At **`dns.hostname`**: one `A` or `AAAA` record per entry of `dns.addresses` (v4 becomes A,
v6 becomes AAAA).

At **`_kerberos.<zone>`**: a `TXT` record whose single string is the realm (RFC 4120 §7.2.3 — a client that knows only
its domain discovers the realm here):

```
_kerberos.example.com.  3600  IN  TXT  "EXAMPLE.COM"
```

**SRV discovery records** are derived from the listeners this process actually runs, so a client
reading them finds only services that answer. Each service is published with `Priority 0`,
`Weight 100`, the listener's port, and `Target` = `dns.hostname`:

| Listener  | SRV owner names                                                                      | Port             |
|-----------|--------------------------------------------------------------------------------------|------------------|
| `kdc`     | `_kerberos._udp`, `_kerberos._tcp`, `_kerberos-master._udp`, `_kerberos-master._tcp` | `kdc.listen`     |
| `kpasswd` | `_kpasswd._udp`, `_kpasswd._tcp`, `_kerberos-adm._tcp`                               | `kpasswd.listen` |
| `ldap`    | `_ldap._tcp`                                                                         | `ldap.listen`    |
| `ldaps`   | `_ldaps._tcp`                                                                        | `ldaps.listen`   |

A disabled listener contributes nothing, as does one listening on port `0`. The `-master` forms
tell a client where to send a password change or initial ticket request when replicas exist.

A **stored record wins over a generated one of the same type at the same name** — storing an `A`
record for `kdc.example.com` overrides the configured `addresses` for that name without editing
the configuration file.

## Stored records

Any other record lives in the database (`dns_records` table) and is managed through
[bootstrap](bootstrap.md) or the [REST API](api.md). The value is written in zone-file
presentation form, exactly as it will be served.

Bootstrap plan (`dns_records`, TTL falls back to the zone default):

```yaml
dns_records:
  - name: www.example.com
    type: A
    value: 192.0.2.20
    # ttl: 3600
```

Applying a plan is idempotent: a record whose `type` and `value` already exist at the name is left
alone. Every record is validated before it is stored (see Validation below).

REST API:

```sh
# Create
curl -X POST http://127.0.0.1:5555/api/v1/dns/records \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "www.example.com", "type": "A", "value": "192.0.2.20"}'

# List everything, or one name
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5555/api/v1/dns/records
curl -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:5555/api/v1/dns/records?name=www.example.com'

# Remove by id (ids come from the list response)
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5555/api/v1/dns/records/3
```

Endpoints and shapes:

- `POST /api/v1/dns/records` — body `{"name", "type", "value", "ttl?"}`. `ttl` is seconds and
  defaults to the zone TTL. Answers `201 {"record": {...}}`; `400` on a record that fails
  validation or is outside every served zone; `409` when the same `(name, type, value)` already
  exists.
- `GET /api/v1/dns/records` — answers `200 {"records": [...], "zones": [...]}`, where `zones`
  lists every zone the server answers for. The optional `?name=` query filters to one name.
  Record objects carry `id`, `name`, `type`, `ttl`, `value`, `createdAt`, `updatedAt`.
- `DELETE /api/v1/dns/records/{id}` — answers `204`; `404` when the id does not exist.

### Validation

Both bootstrap and the API build the record exactly as the server will serve it —
`<name> <ttl> IN <TYPE> <value>` — and reject anything that does not parse, so an operator learns
about a malformed record while making the change rather than through a record that quietly never
answers. Rules:

- `name` is required; it is normalised to lower case without a trailing dot.
- `ttl` must be positive (the zone default is filled in first when omitted).
- `type` must be a record type the DNS library knows (upper-cased before use).
- `value` must parse as the record data of that type.
- When the DNS server is enabled, the API additionally refuses a record whose name is outside
  every served zone — such a record would be stored and never answered.

A stored record that fails to parse at answer time (only possible after direct database edits) is
skipped with a warning rather than failing the whole answer: one bad row costs one record.

## Reverse lookups

PTR records are never stored. A reverse query is turned back into the address it asks about (`in-addr.arpa` labels
reversed; `ip6.arpa` nibbles reassembled), and the answer is every name
whose `A`/`AAAA` record holds that address, plus `dns.hostname` when the address is one of
`dns.addresses` — the server's own addresses come from configuration, so they are matched too.
Forward and reverse therefore cannot drift apart: create the `A` record and the `PTR` answer
exists.

The reverse zone apex answers SOA and NS queries. Any other name in a reverse zone with no
matching address is `NXDOMAIN`.

## Answer behaviour

- Names in no served zone: `REFUSED`.
- Non-QUERY opcodes, queries with other than one question, and non-IN classes: `NOTIMP`.
- In-zone name with no records: `NXDOMAIN`, with the zone's SOA in the authority section. The
  authority section names the zone the question fell in — not always the primary one — so a
  resolver caches the negative answer against the right zone.
- In-zone name that exists but lacks the queried type: empty answer (`NOERROR`, no records), SOA
  in authority — an empty answer, not a missing name, so a resolver caches the right thing.
- An `ANY` query returns every record at the name. A `CNAME` at a name answers for any other type
  asked about, letting an alias stand in for the name a client wanted.
- Every query and its rcode are counted in the `dns_queries_total` /
  `dns_query_duration_seconds` metrics ([operations](operations.md)).

## Trying it

With the compose rig running ([docker-compose](docker-compose.md)), ask the server directly —
asking directly rather than through a resolver is also how the e2e tests pin down whose answer is
under test ([e2e](e2e.md)):

```sh
dig @192.0.2.10 -t SRV _kerberos._udp.example.com    # 0 100 88 kdc.example.com.
dig @192.0.2.10 -t TXT _kerberos.example.com         # "EXAMPLE.COM"
dig @192.0.2.10 -t A kdc.example.com                 # 192.0.2.10
dig @192.0.2.10 -x 192.0.2.10                        # kdc.example.com.
dig @192.0.2.10 -t A www.google.com                  # status: REFUSED
```

## How Kerberos clients use it

With nothing but the realm name configured, an MIT krb5 client locates everything through this
server ([kerberos](kerberos.md)):

```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = true   # _kerberos.<domain> TXT
    dns_lookup_kdc = true     # _kerberos._udp/_tcp.<domain> SRV
```

`dns_lookup_kdc` reads `_kerberos._udp.<domain>` / `_kerberos._tcp.<domain>` for the KDC and
`_kpasswd._udp.<domain>` for password changes; `dns_lookup_realm` maps the host's domain to the
realm through the `_kerberos` TXT record. The e2e suite proves the whole path: a client whose
`krb5.conf` has no `[realms]` block at all gets a ticket, and a service ticket for
`HTTP/www.example.com` is issued after forward and reverse agree on the host name.

## Limitations

- **No recursion and no forwarding** — by design; point clients' resolvers at a recursor that
  delegates the realm's zones here, or at this server directly in an isolated rig.
- **No DNSSEC** — no signing, no DNSKEY/DS/RRSIG records.
- **No zone transfers** — AXFR/IXFR are not implemented; the SOA serial exists so that the zone's
  freshness is visible, not to serve transfers.
- **No dynamic updates** — records change only through bootstrap or the REST API.
- Reverse answers are only as complete as the `A`/`AAAA` records stored: an address with no
  address record has no PTR answer.
