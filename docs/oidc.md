# OpenID Connect provider

The OIDC provider serves the directory's accounts to browsers, so that **one sign-in reaches every
interface a deployment puts in front of this directory**. The accounts, passwords, one-time codes,
application passwords and groups are the same ones the LDAP bind and the Kerberos KDC already know;
there is no second credential store.

The scope is deliberately small:

- the discovery document and a JWKS,
- the authorization code flow with PKCE, for public and confidential clients,
- `/auth`, `/token`, `/userinfo` and `/end-session`,
- the client credentials grant for service accounts.

There is no consent screen, no refresh token grant and no dynamic client registration. Clients are
registered statically in the [configuration](configuration.md).

Enable it with `oidc.enabled: true`. The provider is off by default.

## Configuration

All keys live under the `oidc` section of `ldap-kdc.yaml`; each also has an environment variable
named `OIDC_<NAME>` (see [configuration](configuration.md)).

| Key                     | Default                 | Meaning                                                                                            |
|-------------------------|-------------------------|----------------------------------------------------------------------------------------------------|
| `enabled`               | `false`                 | Start the provider.                                                                                |
| `listen`                | `127.0.0.1:5557`        | Bind address for the provider's HTTP listener.                                                     |
| `tls`                   | `false`                 | Serve TLS on `listen`, using `cert_path`/`key_path`.                                               |
| `cert_path`, `key_path` | empty                   | Both required when `tls: true` (startup fails otherwise).                                          |
| `issuer`                | **required**            | The provider's public URL. Lands in every token's `iss` and is what the browser must reach.        |
| `allowed_origins`       | empty                   | Web origins whose pages may read discovery, the JWKS, `/token` and `/userinfo` from script (CORS). |
| `session_lifetime`      | `12h`                   | Absolute bound on one sign-in, however active.                                                     |
| `session_idle`          | `2h`                    | How long a session survives without being used.                                                    |
| `code_lifetime`         | `5m`                    | Lifetime of an authorization code **and** of an unfinished sign-in.                                |
| `token_lifetime`        | `1h`                    | Lifetime of an issued id/access token.                                                             |
| `service_account_group` | empty                   | Directory group whose members may use the client credentials grant. Empty disables the grant.      |
| `clients`               | **required, non-empty** | The relying parties.                                                                               |

### Validation rules

`ldap-kdc --check-config` (and startup) refuse an enabled provider when:

- `issuer` is missing, is not an absolute URL, or **ends in a slash** — verifiers compare the
  issuer to the `iss` claim byte for byte, so `https://auth.example.com/` and
  `https://auth.example.com` disagree;
- `clients` is empty, or any client has an empty `id`;
- `tls: true` is set without both `cert_path` and `key_path`.

The issuer is the public address, which behind a TLS-terminating proxy is *not* the address in
`listen`. Set it to what the browser actually reaches.

### Client registration

Each entry of `oidc.clients` is:

```yaml
clients:
  - id: https://app.example.com          # any string; REQUIRED
    name: The application                # shown on the sign-in page; optional
    secret_file: /etc/ldap-kdc/app.secret  # makes the client CONFIDENTIAL; optional
    # secret: "..."                      # inline alternative to secret_file
    redirect_uris: # matched EXACTLY, whole string
      - https://app.example.com/
    post_logout_redirect_uris: # same exact-match rule
      - https://app.example.com/
```

- `id` may be any string, and that is not laxity: **an id token's audience is the client id**. A
  deployment that identifies its services by URL should register the service's URL as the id; the
  service checking "is this token for me" then compares against the name it already knows itself
  by. Nothing is issued to an unregistered id, and nothing is redirected to an unregistered URI.
- `redirect_uris` are matched whole, per OAuth 2.1 — prefix or wildcard matching is how a redirect
  turns into an open redirect.
- A client with **no `redirect_uris` is an audience, not an application**: the name machines get
  tokens *for* (a registry, a proxy). It takes part in the client credentials grant, and `/auth`
  refuses it with an error page saying exactly that.
- `secret` / `secret_file` — when both are set, the file wins. The file is read at startup and
  trimmed; prefer it over the inline key so the secret does not sit in the configuration.

### Signing key

Tokens are signed with **ES256** (ECDSA over P-256). The key is generated on first start, sealed
with the master key, and stored in the database under the meta key `oidc_signing_key`. It is the
provider's own key and nothing else signs with it — the management API's administrative sessions
use a different key, so an id token can never be presented to the API as an administrator session.

Sessions, authorization codes and pending sign-ins live **in memory only**. A restart ends every
browser session and invalidates every outstanding code.

## Endpoints

All paths are relative to the issuer and are published in the discovery document, so a client never
has to be told them.

### `GET /.well-known/openid-configuration`

The document every client reads to find the rest. Example:

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/auth",
  "token_endpoint": "https://auth.example.com/token",
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  "jwks_uri": "https://auth.example.com/keys",
  "end_session_endpoint": "https://auth.example.com/end-session",
  "response_types_supported": [
    "code"
  ],
  "grant_types_supported": [
    "authorization_code",
    "client_credentials"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "ES256"
  ],
  "scopes_supported": [
    "openid",
    "profile",
    "email",
    "groups"
  ],
  "claims_supported": [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "email",
    "email_verified",
    "name",
    "groups"
  ],
  "token_endpoint_auth_methods_supported": [
    "none",
    "client_secret_basic",
    "client_secret_post"
  ],
  "code_challenge_methods_supported": [
    "S256"
  ]
}
```

`grant_types_supported` and `token_endpoint_auth_methods_supported` reflect the configuration:
without `service_account_group` they are `["authorization_code"]` and `["none"]`. Note that the
`scope` parameter of an authorization request is not validated — every issued token carries all
supported claims.

### `GET /keys`

The JWKS — the public half of the signing key:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "alg": "ES256",
      "use": "sig",
      "kid": "...",
      "x": "...",
      "y": "..."
    }
  ]
}
```

### `GET /auth` — authorization endpoint

Starts the authorization code flow. Query parameters:

| Parameter               | Rule                                                         |
|-------------------------|--------------------------------------------------------------|
| `client_id`             | Must be a registered client id.                              |
| `redirect_uri`          | Must equal one of the client's `redirect_uris` exactly.      |
| `response_type`         | Must be `code`.                                              |
| `code_challenge`        | Required.                                                    |
| `code_challenge_method` | Must be `S256` — `plain` is refused.                         |
| `state`                 | Opaque, returned to the client.                              |
| `nonce`                 | Echoed into the id token.                                    |
| `prompt`                | Space-separated; `login` forces the form, `none` forbids it. |

Two refusals do **not** redirect, because the address the error would be sent to is not
trustworthy: an unknown `client_id` and an unregistered `redirect_uri` are shown to the person as
an HTML error page instead. Everything else goes back to the client as `error` /
`error_description` (plus `state`) on the redirect URI:

- `unsupported_response_type` — anything but `code`;
- `invalid_request` — missing `code_challenge` or a method other than `S256`;
- `login_required` — nobody is signed in and `prompt=none` forbids asking.

With a live session and no `prompt=login`, the flow completes silently and the browser is
redirected back immediately. Otherwise the browser is sent to the sign-in form at
`GET/POST /auth/login?req=<id>`, an internal page that asks for `login` and `password`. Every
refusal shows the same message — "Incorrect login or password." — because which of "no such
account", "wrong password" and "disabled" it was is exactly what a guesser is trying to learn.

On success the browser is redirected to `redirect_uri` with `code` and `state` query parameters.
A code is single-use and expires after `code_lifetime`.

### `POST /token` — token endpoint

Form-encoded (`application/x-www-form-urlencoded`). Two grants.

**`grant_type=authorization_code`**, with `code`, `redirect_uri`, `code_verifier` and — for a
confidential client — its secret:

- The client is identified by HTTP Basic (`client_secret_basic`) or by `client_id` /
  `client_secret` form fields (`client_secret_post`). A public client sends `client_id` only; a
  client configured with a secret **must** present it, and a request carrying a secret for a public
  client is refused rather than ignored.
- The code must match on client id and `redirect_uri`, and the PKCE verifier must hash to the
  recorded challenge. The account is **re-read from the directory at every exchange**: an account
  disabled since sign-in gets no token from a session that predates it.
- The client's secret is checked *before* the code is spent, so a wrong secret does not burn
  somebody else's code. Either way, a presented code is consumed even if the exchange then fails.

Errors are JSON with the usual OAuth codes: `invalid_client` (401), `invalid_grant` (400),
`unsupported_grant_type` (400). Success:

```json
{
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email groups",
  "id_token": "eyJ...",
  "access_token": "eyJ..."
}
```

Both tokens are ES256 JWTs signed by the same key and addressed to the same audience (the client
id); the access token is the same assertion without the `nonce`, which is an id token's business.

**`grant_type=client_credentials`** — see [Service accounts](#service-accounts) below.

### `GET /userinfo`

Requires `Authorization: Bearer <access_token>`. The token is verified as one this provider
signed, unexpired, with `iss` equal to the issuer, and the account is re-read — a deleted or
disabled account gets a 401. Answers with the same claims the token carries:

```json
{
  "sub": "alice",
  "email": "alice@example.com",
  "email_verified": true,
  "name": "Alice Example",
  "groups": [
    "staff",
    "admins"
  ]
}
```

A missing or invalid token gets `401` with `WWW-Authenticate: Bearer error="invalid_token"`.

### `GET /end-session` — global logout

Signs the person out of the **provider**: the server-side session is deleted and the cookie
cleared. This is what makes a logout button mean something — without it a relying party can only
forget its own token, and the next sign-in would complete silently against a session nobody ended.

With a `post_logout_redirect_uri` that exactly matches one of **any** registered client's
`post_logout_redirect_uris`, the browser is redirected there (303), with `state` appended if the
request carried one. An unregistered URI is ignored, not obeyed — the endpoint takes no credential,
so anybody can link to it — and the response is a small JSON body instead:

```json
{
  "status": "signed out"
}
```

## Sessions

The session is the whole point of the provider. A successful sign-in sets a cookie:

- name `ldap_kdc_session`, path `/`, `HttpOnly`, `SameSite=Lax`, value 256 bits of randomness;
- `Secure` follows the **issuer scheme**, not the listener: with an `https://` issuer the cookie is
  marked `Secure` even when the provider itself serves plain HTTP behind a TLS-terminating proxy;
- `Max-Age` equals `session_lifetime`.

Two clocks bound a session: `session_lifetime` is absolute — how long one sign-in is good for
however active — and `session_idle` is how long it survives without being used; every use restarts
the idle window. Expired sessions are swept lazily, on the way in, rather than by a timer.

The session is shared across **all** registered clients: after signing in once, every other
client's `/auth` completes without a form. `prompt=login` forces the form anyway; `prompt=none`
turns "would have to ask" into a `login_required` redirect error instead of showing one. The
session holds the account *name*, not a snapshot: each authorization re-reads the directory, so a
disabled account or a changed group membership takes effect at the next request.

## Credentials: the same decision as an LDAP bind

The login form and the client credentials grant decide credentials with `store.Authenticate`, the
identical function an LDAP simple bind uses — because two doors that decide credentials separately
are two doors that eventually disagree. Concretely:

- the login may be the account **name or its mail address**;
- an account whose password has a TOTP secret expects the one-time code **appended** to the
  password (the last six characters of the string), the LDAP simple-bind convention;
- **application passwords** work, presented whole and carrying no code — which is what they are
  for, since a machine has nowhere to type a one-time code;
- a **disabled** account gets nothing, and an account with no password cannot authenticate at all;
- an unknown account, a wrong password and a disabled account all produce the same refusal.

## Tokens and claims

Id tokens and access tokens carry:

| Claim                     | Value                                                                                                                           |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `iss`                     | The configured `issuer`.                                                                                                        |
| `sub`                     | The account **name** — stable, and what directory rules are written against. For service accounts: `client:<name>` (see below). |
| `aud`                     | The client id the token was issued for.                                                                                         |
| `iat`, `exp`              | Issue and expiry; lifetime is `token_lifetime`.                                                                                 |
| `auth_time`               | When the person signed in.                                                                                                      |
| `nonce`                   | The authorization request's nonce — id token only.                                                                              |
| `email`, `email_verified` | The account's mail address; `email_verified` is `true` when present. Omitted when the account has none.                         |
| `name`                    | Display name, `givenName` + `sn`. Omitted when empty.                                                                           |
| `groups`                  | The account's groups **by name, resolved transitively** — the same membership a Kerberos PAC carries. Omitted when empty.       |

Deployments that key on the mail address read `email`; `sub` stays the account name.

## Public and confidential clients

A client configured **without** a secret is **public** — a page, which can keep nothing — and PKCE
is the whole of its proof. A client configured **with** a secret is **confidential**: it runs on a
server and can keep one, and the token endpoint demands the secret **in addition to PKCE, not
instead of it**. The secret proves which application is exchanging; PKCE proves it is the one the
browser was sent from; neither answers the other's question. Hence PKCE (`S256`) is required from
every client, confidential or not.

### The colon-in-client-id caveat

HTTP Basic separates the id from the secret with a colon, so it cannot carry a *raw* id that
contains one — and a deployment naming its clients by URL has a colon in every id. The RFC answer
is that both halves are form-urlencoded before they go into Basic (RFC 6749 §2.3.1), and this
server decodes them accordingly, so a properly encoding client library can use
`client_secret_basic` with a URL-shaped id. A client that cannot do that presents the secret in the
form instead: `client_secret_post`. Both methods are advertised in discovery and accepted at
`/token`.

## Service accounts

A service account is an account in this directory: the client id is its **name** (or mail address),
the client secret is its **password**, and the same `store.Authenticate` decides it — an
application password works and a disabled account gets nothing. There is no second credential
store. Three things are deliberately narrow:

1. **Membership is the switch.** Only accounts in `oidc.service_account_group` may use the grant,
   and with no group configured the grant is refused outright (`unsupported_grant_type`) — without
   a gate every person's password would quietly double as a machine key. Membership is read fresh
   on every request, so removing an account from the group stops it immediately.
2. **The audience is required and checked.** The request must name the resource the token is for
   as `resource=<uri>` (RFC 8707; `audience=` is accepted as a synonym), and it must be one of the
   registered client ids — typically an audience-only client with no `redirect_uris`. A token
   naming nobody is a token for everybody, so an unknown or missing audience is refused (`invalid_target`).
3. **The subject carries its kind**: `client:<name>`, not the bare account name. A consumer can
   tell a robot from a person without guessing, and a rule written about people does not match a
   machine one string away.

No id token is issued and no session cookie is set: nobody signed in, and a machine has no browser.
Credentials arrive by HTTP Basic or as `client_id`/`client_secret` form fields. The response is:

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

The token's `sub` is `client:<name>`, its `aud` is the requested resource, and it carries the
account's `groups`. Give the machine an **application password** rather than the account's own
(`POST /api/v1/users/<name>/app-passwords`, see [the API](api.md)) and the machine credential can
be withdrawn on its own.

## CORS

A single-page application never shares an origin with its provider, so without help its script
could read nothing. `allowed_origins` lists the web origins permitted to read **discovery, the
JWKS, `/token` and `/userinfo`** from script. The `Origin` header is matched exactly against the
list; a match gets `Access-Control-Allow-Origin: <origin>` (plus `Vary: Origin`), and `OPTIONS`
preflights on those endpoints answer with `Access-Control-Allow-Methods: GET, POST, OPTIONS`,
`Access-Control-Allow-Headers: Authorization, Content-Type` and a 600-second max age. `/auth`,
`/auth/login` and `/end-session` are browser navigations, not fetches, and carry no CORS headers.

## Sharing the listener with the management API

Writing the **same address** in `api.listen` and `oidc.listen` asks for one listener serving both:
the console at `/ui/`, the management API at `/api/`, and the provider at `/.well-known`, `/keys`
and the rest — one name and no port to remember. The provider's mux routes its own paths (they are
more specific than `/` and win) and hands everything else to the API handler. In this arrangement **the provider's TLS
is what serves them**: `api.tls` and its certificate paths are beside the
point — set `oidc.tls` (and its `cert_path`/`key_path`) instead. Written with different addresses,
each gets a port of its own, which is what a deployment that keeps the management surface on
loopback wants. See [the console](console.md) and [the API](api.md).

## Examples

### A public client (single-page application)

```yaml
oidc:
  enabled: true
  listen: 0.0.0.0:5557
  issuer: https://auth.example.com
  allowed_origins:
    - https://app.example.com
  clients:
    - id: https://app.example.com
      name: The application
      redirect_uris:
        - https://app.example.com/
      post_logout_redirect_uris:
        - https://app.example.com/
```

No secret: the page cannot keep one. `allowed_origins` lets the SPA's script fetch discovery, the
JWKS and the token endpoint from its own origin.

### A confidential client (a server-side portal)

```yaml
    - id: portal
      name: The staff portal
      secret_file: /etc/ldap-kdc/portal.secret
      redirect_uris:
        - https://portal.example.com/oidc/callback
      post_logout_redirect_uris:
        - https://portal.example.com/
```

The portal presents `portal` and the secret at `/token`, by Basic or in the form, in addition to
its PKCE verifier. Had the id been a URL (`https://portal.example.com`), the form (`client_secret_post`) would be the
robust choice — see the colon caveat above.

### An audience-only client for machine tokens

```yaml
    - id: https://api.example.com
      name: The API machines call
      # no redirect_uris: audience only, no browser sign-in
```

### Walkthrough: authorization code flow with curl

```sh
ISSUER=https://auth.example.com

# 1. Discover the endpoints.
curl -s $ISSUER/.well-known/openid-configuration

# 2. Build a PKCE pair.
VERIFIER=$(openssl rand -base64 32 | tr -d '=+/')
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr -d '=+/')

# 3. Send the browser to /auth. With no session this 303s to the sign-in form;
#    sign in, and the browser comes back with ?code=...&state=...
open "$ISSUER/auth?response_type=code&client_id=https://app.example.com\
&redirect_uri=https://app.example.com/&scope=openid\
&code_challenge=$CHALLENGE&code_challenge_method=S256&state=xyz"

# 4. Exchange the code (public client: client_id, no secret).
curl -s -X POST $ISSUER/token \
  -d grant_type=authorization_code \
  -d client_id=https://app.example.com \
  -d code=THE_CODE \
  --data-urlencode 'redirect_uri=https://app.example.com/' \
  -d code_verifier=$VERIFIER

# A confidential client adds its secret — here in the form, because a URL-shaped
# id does not fit HTTP Basic raw:
curl -s -X POST $ISSUER/token \
  -d grant_type=authorization_code \
  -d client_id=portal \
  -d client_secret="$(cat /etc/ldap-kdc/portal.secret)" \
  -d code=THE_CODE \
  --data-urlencode 'redirect_uri=https://portal.example.com/oidc/callback' \
  -d code_verifier=$VERIFIER

# 5. Ask /userinfo with the access token.
curl -s $ISSUER/userinfo -H "Authorization: Bearer $ACCESS_TOKEN"

# 6. Global logout.
curl -s "$ISSUER/end-session?post_logout_redirect_uri=https://app.example.com/&state=xyz" \
  --cookie 'ldap_kdc_session=...'   # navigation endpoint: the browser carries the cookie
```

### Walkthrough: client credentials grant

With `oidc.service_account_group: service-accounts` set and the account `reporter` in that group
(see [bootstrap](bootstrap.md) or the [API](api.md) for creating it):

```sh
curl -s -X POST https://auth.example.com/token \
  -u 'reporter:a sufficiently long password' \
  -d grant_type=client_credentials \
  --data-urlencode 'resource=https://api.example.com'
```

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

The token's `sub` is `client:reporter` and its `aud` is `https://api.example.com`. The same request
with an account outside the group, a wrong password, or a resource that is not a registered client
id is refused.

## See also

- [Configuration](configuration.md) — the full `oidc` section, environment variable names.
- [Directory](directory.md) — the accounts, groups and application passwords behind the claims.
- [Kerberos](kerberos.md) — the PAC resolves the same transitive group membership.
- [API](api.md) and [console](console.md) — user administration and the shared listener.
- [Docker Compose](docker-compose.md) and [end-to-end tests](e2e.md) — a working rig to sign in against.
