# ldap-kdc documentation

ldap-kdc is an LDAP directory, a Kerberos KDC, a kpasswd service, an authoritative DNS server,
a REST management API and an OpenID Connect provider in one binary, sharing one store — a
FreeIPA/Active-Directory-like environment that fits in a single container, built for test rigs.

## Getting started

- The repository [README](../README.md) is the narrative introduction: what the service
  speaks, why it looks the way it does, and the first accounts to create.
- [Configuration](configuration.md) — every key of `ldap-kdc.yaml`, defaults, validation
  rules, environment overrides.
- [Bootstrap](bootstrap.md) — the plan that shapes the directory before the first listener
  accepts a connection.
- [Operations](operations.md) — containers, systemd, the unprivileged low-port sysctl,
  backups, health and metrics, upgrades.

## The services

- [Architecture](architecture.md) — the single-store design, sealed key material, the startup
  sequence, the package map.
- [The LDAP directory](directory.md) — DN layout, schema, the bind flavors (password, TOTP,
  application passwords, UPN, SASL GSSAPI), authorization, TLS.
- [The Kerberos KDC and kpasswd](kerberos.md) — enctypes, pre-authentication, ticket policy,
  the PAC, S4U2Self/S4U2Proxy, cross-realm trusts, keytabs, password changes.
- [The DNS server](dns.md) — the zone, the Kerberos discovery records, reverse answers, the
  authoritative-only stance.
- [The REST API](api.md) — authentication, the self-generated OpenAPI document, the full
  route reference.
- [The OpenID Connect provider](oidc.md) — the code flow with PKCE, the shared session,
  confidential and public clients, service accounts.
- [The admin console](console.md) — the embedded UI, password and Kerberos sign-in.

## The OpenBao / Vault PKI integration

- [OpenBao PKI](openbao-pki.md) — enrolling the LDAPS certificate over a Kerberos login,
  importing CA-issued user certificates into the directory, the API and the OpenBao-side
  setup.
- [The Docker Compose stand](docker-compose.md) — ldap-kdc and OpenBao standing together for
  poking at by hand.

## Development

- [The end-to-end rig](e2e.md) — the three-container suite with MIT krb5, OpenLDAP and
  OpenBao as the reference clients, and how to add a test to it.
