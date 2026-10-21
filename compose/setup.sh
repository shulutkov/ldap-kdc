#!/usr/bin/env bash
# setup.sh — wires a freshly started `docker compose up -d` stand together, end to end:
#
#   1. initializes OpenBao (its barrier key goes to the SoftHSM token the image was built with,
#      so unsealing is the server's own business — there is deliberately no `bao operator
#      unseal` anywhere in here) and stashes the root token and recovery key in
#      compose/vault-keys.json;
#   2. registers the kerberos auth plugin and points it at the directory, over what starts as
#      plain LDAP;
#   3. mounts a PKI with a root CA and two roles, and maps the directory's groups to policies;
#   4. enrolls ldap-kdc's own LDAPS certificate through its management API;
#   5. and only then switches the plugin's directory connection to LDAPS — trusting the CA the
#      PKI just made, verifying against the certificate the service just enrolled.
#
# The script is idempotent: rerunning it rewrites the same configuration and skips what exists.
# It needs bash, curl and jq on the host; everything OpenBao-side runs through docker compose
# exec, so no bao binary is needed locally.
set -euo pipefail
cd "$(dirname "$0")/.."

API=http://127.0.0.1:5555
TOKEN=compose-token
KEYS=compose/vault-keys.json
BIND_PASSWORD='vault ldap bind password'
VAULT_INIT='http://127.0.0.1:8200/v1/sys/init'

exec_bao() {
    docker compose exec -T -e BAO_ADDR=http://127.0.0.1:8200 openbao bao "$@"
}

bao() {
    docker compose exec -T -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$ROOT_TOKEN" openbao bao "$@"
}

wait_for() { # wait_for <what> <command...>
    local what=$1; shift
    local i
    for i in $(seq 1 60); do
        if "$@" > /dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    echo "setup: $what did not happen in two minutes" >&2
    return 1
}

echo '==> waiting for ldap-kdc'
wait_for 'ldap-kdc readiness' curl -fs -o /dev/null "$API/readyz"

echo '==> waiting for openbao'
wait_for 'openbao to answer' curl -fs -o /dev/null "$VAULT_INIT"

echo '==> initializing openbao'
if [ "$(curl -fs "$VAULT_INIT" | jq -r .initialized)" = true ]; then
    if [ ! -f "$KEYS" ]; then
        echo "setup: openbao is already initialized but $KEYS is not there to read" >&2
        echo 'setup: either restore the file, or wipe the stand with `docker compose down -v`' >&2
        exit 1
    fi
else
    # With an auto-seal, init hands out recovery keys rather than unseal key shares.
    exec_bao operator init -recovery-shares=1 -recovery-threshold=1 -format=json > "$KEYS"
    chmod 600 "$KEYS"
fi
ROOT_TOKEN=$(jq -r .root_token "$KEYS")

echo '==> checking the auto-unseal'
# Nobody runs `bao operator unseal` here or anywhere else: if the SoftHSM seal works, the
# server unseals itself the moment it is initialized.
for _ in $(seq 1 60); do
    if [ "$(bao status -format=json | jq -r .sealed)" = false ]; then
        break
    fi
    sleep 2
done
if [ "$(bao status -format=json | jq -r .sealed)" != false ]; then
    echo 'setup: openbao did not auto-unseal against SoftHSM' >&2
    exit 1
fi

echo '==> registering the kerberos plugin'
# The image was built with the plugin and its SHA-256, the sum the plugin catalog wants.
sha=$(docker compose exec -T openbao cat /openbao/plugins/openbao-plugin-auth-kerberos.sha256 | tr -d '[:space:]')
bao plugin register -sha256="$sha" -command=openbao-plugin-auth-kerberos auth kerberos > /dev/null

if bao auth list -format=json | jq -e 'has("kerberos/")' > /dev/null; then
    bao auth tune -passthrough-request-headers=Authorization \
        -allowed-response-headers=www-authenticate kerberos/ > /dev/null
else
    # The login endpoint answers an unauthenticated request with a Negotiate challenge, which
    # only reaches the client if both headers are allowed through the core.
    bao auth enable -passthrough-request-headers=Authorization \
        -allowed-response-headers=www-authenticate kerberos
fi

echo '==> configuring the kerberos auth method'
# The plugin verifies incoming service tickets against this keytab. PAC decoding stays off:
# the PAC this KDC issues is not one the plugin's Kerberos library can read, and group
# membership comes from the directory below anyway.
curl -fs -H "Authorization: Bearer $TOKEN" \
    "$API/api/v1/principals/HTTP%2Fvault.example.com/keytab" | base64 | tr -d '\n' |
    bao write auth/kerberos/config keytab=- \
        service_account=HTTP/vault.example.com decode_pac=false

bao write auth/kerberos/config/ldap \
    url=ldap://kdc.example.com \
    binddn=cn=svc-vault-ldap,ou=svc,ou=users,dc=example,dc=com \
    bindpass="$BIND_PASSWORD" \
    userdn=ou=users,dc=example,dc=com \
    groupdn=ou=groups,dc=example,dc=com \
    userattr=uid \
    groupattr=cn \
    upndomain=EXAMPLE.COM

echo '==> mapping groups to policies'
printf '%s' 'path "pki/issue/user" { capabilities = ["update"] }' | bao policy write user-certs - > /dev/null
printf '%s' 'path "pki/sign/ldaps" { capabilities = ["update"] }' | bao policy write enroll - > /dev/null

bao write auth/kerberos/groups/vault-users policies=user-certs
bao write auth/kerberos/groups/vault-enroll policies=enroll

echo '==> setting up the PKI'
if ! bao secrets list -format=json | jq -e 'has("pki/")' > /dev/null; then
    bao secrets enable pki > /dev/null
fi
bao secrets tune -max-lease-ttl=87600h pki > /dev/null

if ! bao read pki/cert/ca > /dev/null 2>&1; then
    bao write pki/root/generate/internal common_name=example.com ttl=87600h > /dev/null
fi

bao write pki/roles/user allow_any_name=true enforce_hostnames=false max_ttl=720h
# key_type=any: the enrollment's CSR arrives with a key it already made, of a type it chose.
bao write pki/roles/ldaps allowed_domains=kdc.example.com allow_bare_domains=true \
    allow_ip_sans=true key_type=any max_ttl=8760h

echo '==> enrolling the LDAPS certificate'
curl -fs -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{
        "address": "http://vault.example.com:8200",
        "principal": "svc-vault-enroll",
        "pki_path": "pki",
        "role": "ldaps",
        "common_name": "kdc.example.com",
        "san_dns": ["kdc.example.com"],
        "san_ips": ["10.99.0.10"],
        "ttl": "720h",
        "renew_before": "24h",
        "retry_interval": "5s"
    }' "$API/api/v1/vault/config" > /dev/null

enrolled=
for _ in $(seq 1 60); do
    if [ "$(curl -fs -H "Authorization: Bearer $TOKEN" "$API/api/v1/vault/status" | jq -r .enrolled)" = true ]; then
        enrolled=true
        break
    fi
    sleep 2
done
if [ -z "$enrolled" ]; then
    echo 'setup: the service did not enroll in two minutes:' >&2
    curl -s -H "Authorization: Bearer $TOKEN" "$API/api/v1/vault/status" >&2
    exit 1
fi

echo '==> switching the kerberos auth to LDAPS'
# The LDAP configuration merges with what is already written, so only the scheme and the CA to
# trust change here. The certificate on :636 is the one enrolled a moment ago.
curl -fs http://127.0.0.1:8200/v1/pki/ca/pem |
    bao write auth/kerberos/config/ldap url=ldaps://kdc.example.com certificate=-

echo
echo 'The stand is up:'
echo '  - ldap-kdc management API and console: http://127.0.0.1:5555 (token: compose-token)'
echo '  - LDAPS on 127.0.0.1:636, certificate enrolled from the OpenBao PKI'
echo '  - OpenBao on http://127.0.0.1:8200, kerberos auth reading the directory over LDAPS'
echo "  - OpenBao root token and recovery key: $KEYS"
