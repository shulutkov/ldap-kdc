# The shipped image: the binary and the three directories it needs, on nothing.
#
# Nothing here needs cgo -- the SQLite driver is pure Go -- so the binary is static and the runtime
# layer can be empty. There is no shell in it, and the process does not run as root.

ARG GO_VERSION=1.27

# The builder runs on whatever the machine is and cross-compiles to the target. With cgo disabled
# that costs nothing, and it keeps a multi-architecture build from running an emulated toolchain.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# Dependencies resolve in their own layer, so a source change does not re-download them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/ldap-kdc \
        ./cmd/ldap-kdc

# A scratch image has no mkdir, so the directory tree is laid out here and copied over whole.
#
#   /var/lib/ldap-kdc  the database and the master key that decrypts it
#   /etc/ldap-kdc      the configuration, normally mounted read-only
#   /tmp               SQLite spills large sorts and vacuums here
RUN mkdir -p /rootfs/var/lib/ldap-kdc /rootfs/etc/ldap-kdc /rootfs/tmp

FROM scratch

# An unprivileged, nameless account: with no /etc/passwd to resolve, the id has to be numeric.
# 65532 is the conventional "nonroot" id, the one distroless uses.
COPY --from=build --chown=65532:65532 /rootfs/ /
COPY --from=build /out/ldap-kdc /usr/local/bin/ldap-kdc

USER 65532:65532

# Losing the master key means losing every Kerberos key in the realm, so this wants a volume.
VOLUME ["/var/lib/ldap-kdc"]

# DNS, Kerberos, LDAP, LDAPS, the password service and the management API.
#
# All but the last are below 1024. Whether an unprivileged process may bind them depends on the
# runtime: the kernel default reserves everything under 1024, while Docker Desktop already opens
# the whole range. Where it is still reserved, tell the kernel otherwise for this namespace:
#
#   docker run --sysctl net.ipv4.ip_unprivileged_port_start=0 ...
#
# Kubernetes has had that sysctl in its safe set since 1.22, so a pod may simply ask for it.
# Failing either, point the listeners at high ports in the configuration -- but then the ports the
# service records advertise have to match what clients actually reach, not what the process bound.
EXPOSE 53/tcp 53/udp 88/tcp 88/udp 389/tcp 636/tcp 464/tcp 464/udp 5555/tcp

ENTRYPOINT ["/usr/local/bin/ldap-kdc"]
CMD ["-c", "/etc/ldap-kdc/ldap-kdc.yaml"]
