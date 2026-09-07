BINARY := ldap-kdc
IMAGE  ?= ghcr.io/shulutkov/ldap-kdc
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

SWAGGER_UI_VERSION ?= 5.32.15

.PHONY: build image test e2e check fmt vet swagger-ui clean

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

## swagger-ui: refresh the vendored Swagger UI, which is embedded in the binary.
## The files are stored compressed: they are minified bundles nobody reads, and the service
## serves them as they are to a browser that asked for gzip.
swagger-ui:
	@dir=internal/api/swaggerui; \
	for f in swagger-ui.css swagger-ui-bundle.js; do \
		curl -sfL --retry 3 -o "$$dir/$$f" \
			"https://cdn.jsdelivr.net/npm/swagger-ui-dist@$(SWAGGER_UI_VERSION)/$$f" || exit 1; \
		gzip -9 -f "$$dir/$$f"; \
	done; \
	echo "swagger-ui-dist $(SWAGGER_UI_VERSION) vendored into $$dir"

clean:
	rm -f $(BINARY)
