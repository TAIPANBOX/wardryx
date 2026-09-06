VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
STATICCHECK ?= staticcheck

.PHONY: build test test-race test-integration vet fmt lint staticcheck check serve clean

build:
	go build $(LDFLAGS) -o bin/wardryx ./cmd/wardryx

test:
	go test ./...

test-race:
	go test -race ./...

# Requires a running Postgres; set DATABASE_URL.
test-integration:
	go test -tags integration ./internal/store/

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet staticcheck
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

# Static analysis beyond go vet. Install: go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck:
	@command -v $(STATICCHECK) >/dev/null 2>&1 && $(STATICCHECK) ./... || echo "staticcheck not installed; skipping (go install honnef.co/go/tools/cmd/staticcheck@latest)"

# Offline dry-run demo: evaluate the bundled fixture passports against the
# bundled fixture policy and print the decisions.
check: build
	./bin/wardryx check ./cmd/wardryx/testdata/passports ./cmd/wardryx/testdata/policy.yaml

# Serve demo: in-memory store, no policy loaded (every request allowed),
# events disabled. Ctrl-C to stop.
#
# WARDRYX_ALLOW_DEVKEY=1 opts into the insecure devkey -> default/admin
# credential for this local run; -addr binds loopback only, which
# startupKeyPosture requires for that opt-in to start rather than refuse
# (see CLAUDE.md's W1 finding and cmd/wardryx/main.go's bindWarning). Without
# either, `serve` now refuses to start rather than installing devkey
# silently on every interface.
serve: build
	WARDRYX_ALLOW_DEVKEY=1 ./bin/wardryx serve -addr 127.0.0.1:8090

clean:
	rm -rf bin
