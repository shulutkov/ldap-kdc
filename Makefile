BINARY := ldap-kdc
IMAGE  ?= ghcr.io/shulutkov/ldap-kdc
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build image test e2e check fmt vet clean

## build: compile the service
build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/ldap-kdc

## image: build the shipped container image for this machine's architecture
image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

## test: the unit and integration suites, no container runtime needed
test:
	go test -race ./...

## e2e: drive the built binary from a container with MIT krb5, OpenLDAP and dig.
## Needs a container runtime; skips itself when none is reachable.
e2e:
	cd test/e2e && go test -timeout 900s ./...

## check: everything that has to pass before a change lands
check: fmt vet test e2e

fmt:
	gofmt -l . | tee /dev/stderr | (! read)

vet:
	go vet ./...
	cd test/e2e && go vet ./...

clean:
	rm -f $(BINARY)
