BINARY := ldap-kdc
IMAGE  ?= ghcr.io/shulutkov/ldap-kdc
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# How the binary is linked. The image build overrides both to strip the binary and drop build paths;
# a plain `make build` keeps the symbols a debugger wants.
LDFLAGS    ?= -X main.version=$(VERSION)
BUILDFLAGS ?=

SWAGGER_UI_VERSION ?= 5.32.15

# NODE_BIN points at a node installation's bin directory when node is not on PATH.
NODE_BIN ?=
NPM = PATH="$(NODE_BIN)$(if $(NODE_BIN),:)$$PATH" npm

# The console's build, which the binary embeds. It is not committed: `make build` produces it.
UI_DIST := internal/api/ui/dist
# npm writes this at the end of an install, so it is newer than the lock file exactly when what is
# installed is what the lock file names.
UI_DEPS := ui/node_modules/.package-lock.json

.PHONY: build image test e2e check fmt vet ui ui-deps swagger-ui clean

## build: the console, then the binary that embeds it. This is the one way the service is built —
## the image build runs it too — because a binary built without `make ui` embeds whatever happened
## to be in internal/api/ui/dist, or nothing at all.
build: ui
	go build $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ldap-kdc

## image: build the shipped container image for this machine's architecture
image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

## test: the unit and integration suites; no container runtime and no node needed
test: $(UI_DIST)/index.html
	go test -race ./...

## e2e: drive the built binary from a container with MIT krb5, OpenLDAP and dig.
## Needs a container runtime; skips itself when none is reachable.
e2e:
	cd test/e2e && go test -timeout 900s ./...

## check: everything that has to pass before a change lands
check: fmt vet test e2e

fmt:
	gofmt -l . | tee /dev/stderr | (! read)

vet: $(UI_DIST)/index.html
	go vet ./...
	cd test/e2e && go vet ./...

## ui: build the administrators' console into internal/api/ui/dist, where the binary embeds it.
ui: ui-deps
	cd ui && $(NPM) run build

## ui-deps: install the console's dependencies, when the lock file changed since the last install.
ui-deps: $(UI_DEPS)

$(UI_DEPS): ui/package.json ui/package-lock.json
	cd ui && $(NPM) ci --no-audit --no-fund

# go:embed refuses a directory with no files in it, and the Go packages have to compile for vet and
# the tests, which exercise the API rather than the console. So where no build is present they get a
# page saying so — only then: a real build already has an index.html, and this never replaces it.
$(UI_DIST)/index.html:
	mkdir -p $(UI_DIST)
	printf '%s\n' '<!doctype html><title>ldap-kdc</title><div id="root">The console was not built into this binary: build it with make build.</div>' > $@

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
	rm -rf $(UI_DIST)
