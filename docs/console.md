# The admin console

The console is the web interface for the people who administer the directory. It is a single-page
React application (sources in `ui/`, Vite + TypeScript) that the binary embeds and serves itself at
`/ui/` on the management API listener — there is no separate hosting, no CDN and no runtime
dependency, so a service deployed on an air-gapped network still serves its own pages.

Everything the console does it does through the [management API](api.md), as the administrator who
signed in. The page holds no data and no logic of its own beyond rendering: every list is a `GET`,
every change is one API request, and each of those requests is authorised by the server on its own.

Related chapters: [configuration](configuration.md) for the `api.*` keys, [api](api.md) for the
endpoints the console calls, [directory](directory.md) for accounts, groups and capabilities,
[kerberos](kerberos.md) for principals and keytabs.

## Where it is served

- The console lives on the API listener: `api.listen` (default `127.0.0.1:5555`), with optional TLS (`api.tls`,
  `api.cert_path`, `api.key_path`). `GET /` on that listener redirects to `/ui/`.
- When `api.listen` and `oidc.listen` are the **same address**, the console and the whole management
  API ride on the OpenID provider's listener instead — one name, one port, the console at `/ui/` and
  the provider at `/.well-known` and `/keys` (see [oidc](oidc.md) and `cmd/ldap-kdc/main.go`).
- `api.enabled: false` takes down the console together with the API; there is no console without the
  API it talks to.

### Disabling the console

`api.ui: false` (default `true`, environment `API_UI=false`) leaves the console out while the API
keeps serving. `/ui/` then answers 404. This is the setting for a deployment whose administrators
drive the API with `curl` or automation only.

### Building it in

The console's build output is **not committed**. `make build` runs `make ui` first (`npm ci && npm run build` in `ui/`),
which produces `internal/api/ui/dist`, and the Go build embeds
that directory (`//go:embed ui/dist` in `internal/api/console.go`). The container image build runs
`make build` too. When node is not on `PATH`, pass `NODE_BIN=/path/to/node/bin`.

A bare `go build` without a prior `make ui` embeds whatever happens to be in
`internal/api/ui/dist`; `make test` and `make vet` write a placeholder page there ("The console was
not built into this binary") when no build is present, so a binary built outside `make build` can
serve a stub instead of the console.

### Response headers

Every response under `/ui/` carries a strict set of headers (`internal/api/console.go`):

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
    img-src 'self' data:; connect-src 'self'; form-action 'self';
    frame-ancestors 'none'; base-uri 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cache-Control: no-store
```

The policy lets the page load itself and talk to its own API and nothing else, so a directory value
that turned out to contain markup is inert in the browser.

## Who may sign in

Only **directory administrators**. There is no separate "console admins" list: an administrator is
an account that holds the `write` capability over the whole base DN (`server.base_dn`) — or over
`*` — either on the account itself or on any group it belongs to, transitively (`store.IsDirectoryAdmin` in
`internal/store/authority.go`). A disabled account is never an
administrator. The reasoning: an account that can rewrite every entry through an LDAP client is an
administrator whatever it is called, and a second definition would only disagree with the first.

This check runs at sign-in **and again on every request** (see [The session](#the-session) below).

## Signing in with a password

The password form posts to `POST /api/v1/auth/login`:

```json
{
  "login": "admin",
  "password": "the account's own password"
}
```

- `login` is an account name or its mail address (`store.UserByLogin`).
- The password is the account's **own** password, with the one-time code appended where the account
  has one — exactly as for an LDAP bind.
- **Application passwords are refused**, even though one authenticates an LDAP bind. An application
  password exists for programs that cannot be handed a one-time code; accepting it here would be a
  way past the account's second factor into the console.
- All refusals — unknown account, wrong password, disabled account — return the same
  `401 incorrect login or password`, so the response does not tell a guesser which one it was.
- An account that authenticates but does not administer the directory gets `403`.

Failed sign-ins count against the **same per-address limiter as failed LDAP binds**
(`behaviors.limit_failed_binds` and friends: by default 3 failures within 10 s block the source
address for 60 s). A blocked source gets `429 too many failed sign-ins` until the block lifts. A
guesser locked out of the console is locked out of LDAP binds too, and vice versa.

## Signing in with a Kerberos ticket (SPNEGO)

When `api.spn` is set, the console tries Kerberos sign-in first: on arrival it calls
`GET /api/v1/auth/negotiate`, and a browser configured to trust the host answers the Negotiate
challenge with the ticket it already holds — the person types nothing. A browser that is not
configured, or holds no ticket, just gets the challenge back and the page falls back to the password
form. Right after **Sign out** the console does *not* retry Kerberos on its own (a marker in
session storage suppresses it), or the ticket the browser still holds would sign the person straight
back in.

### Configuring it: `api.spn`

```yaml
api:
  spn: HTTP/ldap-kdc.example.com
```

The value must be `HTTP/<host name the console is reached by>` — literally the name a browser asks
the KDC for. Validation at start-up (`ensureSPN` in `internal/api/auth.go`):

- exactly two components, the first one `HTTP`;
- the realm must be the service's own realm (`server.realm`);
- the principal must not name a directory account — it is a service.

If the principal does not exist yet, the service **creates it at start-up with random keys**
(pre-authentication required), in the same store as everything else. This service is its own KDC, so
there is no keytab file to write, protect or keep in step. If the principal exists already, it is
used as-is.

For each sign-in request the server builds the principal's keytab **from the store, on the spot**,
including the previous key version (`kvno - 1`) when there is one, so a ticket issued just before a
re-key still verifies. Re-keying `api.spn`'s principal therefore takes effect immediately; no
restart, no file distribution.

Leave `api.spn` empty to turn Kerberos sign-in off; the negotiate endpoint then answers
`404 Kerberos sign-in is not configured on this service` and the console goes straight to the
password form.

### What the person needs

- A ticket for an account **in this realm**: `kinit alice`, with the realm's `krb5.conf` in place
  (see [kerberos](kerberos.md)).
- Name resolution for the console host: the browser must resolve the host part of `api.spn` —
  served by this service's own [DNS](dns.md) when the rig uses it, or a hosts entry.
- A browser told to negotiate with that host:

  ```text
  Chrome / Edge   AuthServerAllowlist = ldap-kdc.example.com       (policy)
  Firefox         network.negotiate-auth.trusted-uris = ldap-kdc.example.com
  Safari, macOS   works with a ticket from kinit, or the Kerberos SSO extension
  ```

### What is accepted

SPNEGO verifies the ticket against the store-built keytab, then (`negotiated` in
`internal/api/auth.go`):

1. **Realm.** Only this realm's tickets sign in. A trusted realm's KDC can hand its own users a
   ticket for this service through a referral, but those accounts are not this directory's, so a
   ticket from another realm is refused with `403`.
2. **Account.** The ticket's principal is looked up in the store — through aliases too — and must
   resolve to a **user account**. A ticket in one of the account's aliases signs the account in; a
   service principal (no account attached) is refused with `403`, whatever its name.
3. **Administrator.** The account must pass the directory-administrator check like any password
   sign-in.

The PAC is not decoded (`service.DecodePAC(false)`): who the account is and what it may do is read
from the directory this service is, not from what a ticket claims.

## The session

Both sign-in paths end in the same thing: a short-lived session token, returned as

```json
{
  "token": "…",
  "subject": "admin",
  "method": "password",
  "expiresAt": "2026-10-21T15:04:05Z"
}
```

- The token is a signed JWT (`iss` `ldap-kdc/api`, `aud` `ldap-kdc/admin`, `sub` the account name,
  `amr` the sign-in method). It is signed with its own key — the sealed `api_signing_key` metadata
  entry in the store — **never the OIDC provider's key**, so an id token issued to a relying party
  cannot be presented here, and a console session cannot be presented there.
- Its lifetime is `api.session_lifetime` (default `1h`, environment `API_SESSION_LIFETIME`). It is
  deliberately short: the session can reset every account's password.
- The console keeps the token in **session storage** (`ldap-kdc.token`): it survives a reload of the
  tab and dies with it. It is presented as `Authorization: Bearer <token>` on every API call.
- **The token is re-checked against the directory on every request**: its subject must still exist
  and still administer the directory *as it is now*. An administrator who is disabled, removed, or
  whose group loses the `write` capability is out at the next click — `401`, and the console returns
  to the sign-in page — not when the token expires.
- `GET /api/v1/auth/whoami` is how the page learns who it is signed in as (`subject`, `method`,
  `expiresAt`). It asks rather than decoding its own token: what it shows has to be what the server
  enforces. The signed-in identity and method are shown in the header, with the session's end as a
  tooltip.

The management token `api.token` is *not* a console credential: it is a bearer token for automation (see [api](api.md)).
The console signs in only through the two paths above.

## A tour of the console

Navigation is hash-based: `#/overview`, `#/users`, `#/groups`, `#/principals`, `#/dns`, `#/trusts`,
each list with a filter box and a **New** button, each item opening an editor.

### Forms come from the API itself

Objects are edited in **forms, not JSON**. The console fetches the OpenAPI document the service
generates from its own route table (`GET /api/v1/openapi.json`, served behind the session token so
it works with `api.docs: false`) and renders each operation's request body with
react-jsonschema-form. Field names, types, required-ness, descriptions and defaults all come from
the Go types the handlers decode — the page keeps no second list, so a form cannot offer a field the
API does not take (and the API rejects unknown fields anyway). An edit sends **only the fields that
changed** as a `PATCH`; a creation leaves blank fields to the service's defaults. The usual ajv
validator is left out on purpose — ajv compiles schemas with `new Function`, which the console's CSP
refuses — so the browser checks what markup can express (required fields, numbers) and the API
decides the rest and says why.

### Overview

The landing page reads `GET /api/v1/stats` and shows the realm, counts of users (total, disabled,
without a password), groups, principals and trusts, the realm's encryption types, and who is signed
in. A hint warns that an account without a password can neither bind over LDAP nor obtain a ticket
until one is set.

### Users

The list shows `name`, `uidNumber`, `mail`, password state and status. The editor groups the fields
into **Identity** (`name`, `givenName`, `sn`, `mail`), **Credentials** (`password`, `forceChange`,
`otpSecret` — rendered as a password field), **POSIX account** (`primaryGroup`, `otherGroups`,
`uidNumber`, `loginShell`, `homeDirectory`, `sshKeys`), **Kerberos** (`aliases`), **Access control**
(`disabled`, `capabilities`) and **Custom attributes** (`customAttributes`). A facts panel shows
what is not editable: the account's id and DN, whether a password and a one-time code are set, and
the created/updated timestamps.

One extra action: **Set password** (`POST /api/v1/users/{name}/password`). The password set this way
is **expired at once**, so its owner chooses the final value at the next sign-in — a password an
administrator typed is one the administrator knows.

Creating a user creates its Kerberos principal with it; disabling a user disables its principals
too; deleting a user removes principals, keys, memberships and attributes with it.

Note: **application passwords and certificate import are not in the console** — they exist only as
API endpoints (`/api/v1/users/{name}/app-passwords`, `/api/v1/users/{name}/certificates`, see
[api](api.md)). The console's user editor has no controls for them.

### Groups

List columns: `name`, `gidNumber`, `description`, capabilities. The editor has **Identity** (`name`,
`gidNumber`, `description`), **Membership** (`includeGroups` — groups whose members this group
absorbs), **Access control** (`capabilities`) and **Custom attributes**. Deleting a group that is
still some account's primary group is refused. Capabilities on a group are how an account becomes a
directory administrator, so this is where console access itself is granted.

### Service principals

The list shows `name@realm`, the attached account (if any), `kvno`, whether pre-authentication is
required, and a status badge (enabled / locked / disabled). The editor's groups: **Identity**
(`name`, `userName`, `aliases`), **Credentials** (`password`), **Status** (`enabled`, `expiresAt`,
`passwordExpiresAt`), **Ticket policy** (`requiresPreAuth`, `allowForwardable`, `allowProxiable`,
`allowRenewable`, `allowPostdate`, `maxTicketLife`, `maxRenewableLife`) and **Delegation**
(`okAsDelegate`, `okToAuthAsDelegate`, `allowedToDelegateTo`, `allowedToImpersonate`). The facts
panel shows `kvno`, password last set / expires, failure count and lockout time.

Three extra actions:

- **Download keytab** — `GET /api/v1/principals/{name}/keytab`, fetched with the bearer token and
  handed to the browser as a `<name>.keytab` file (slashes and `@` replaced by `_`), for the current
  key version.
- **Randomize keys** — `POST /api/v1/principals/{name}/password` with `{"randomize": true}`. The
  previous key version is kept, so keytabs and tickets issued before the change keep working until
  the tickets expire.
- **Unlock** — shown only while the principal is locked out (`lockedUntil` set); a `PATCH` with
  `{"unlock": true}`.

### DNS records

List columns: `name`, `type`, `value`, `ttl`. Create and delete only — a record is not edited in
place (there is no `PATCH` for DNS in the API). Records are validated against the zones this service
answers for, and a record created without a TTL gets `dns.ttl`. There are no PTR records to manage:
reverse answers are computed from the address records, so nothing can drift out of step (see
[dns](dns.md)).

### Trusts

List columns: remote realm, direction, transitive, status. The editor's groups are **Identity**
(`remoteRealm`, `direction`), **Policy** (`transitive`, `enabled`) and **Credentials** (`password`).
Creating a trust makes the two `krbtgt` principals, keyed from the shared password that is entered
on both sides (see [kerberos](kerberos.md)).

## Authorization of console actions

There is exactly one gate: being a directory administrator at the moment of the request. The console
has no per-action roles, no read-only mode and no capability mapping of its own — every button
resolves to an ordinary API call, and the server authorises that call against the directory as it
stands. Hiding or showing a control is a courtesy, never the boundary; anything the page would let
you click, the API would let you `curl` with the same session. The corollary is that console access
is all-or-nothing: an account that may sign in may do everything the console offers, including
granting the `write` capability to other accounts.

## Limitations

- **No Kerberos ticket forwarding.** The browser's ticket is used once, to authenticate the sign-in;
  it is not delegated. The console then acts with the session token and the account's standing
  administrator rights, not with Kerberos credentials — a console action never appears at some third
  service as the administrator's ticket.
- **This realm only.** Kerberos sign-in accepts no tickets from trusted realms, and no service
  principals — only accounts of this directory.
- **No session renewal.** The token expires at `api.session_lifetime` however active the tab is;
  the console sends you back to sign in.
- **Per-tab sessions.** The token lives in session storage, so a new tab signs in again.
- **Application passwords cannot sign in**, by design.
- **Not everything the API does is in the page**: application passwords, certificate import, and the
  Vault PKI enrollment endpoints are API-only (see [api](api.md) and [openbao-pki](openbao-pki.md)).
