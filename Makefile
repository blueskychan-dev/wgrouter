BINARY      := wgrouter
CMD         := ./cmd/wgrouter
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -X main.version=$(VERSION)
STATICCHECK ?= staticcheck

.PHONY: all
all: check build

.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

# CGO_ENABLED=0 is the point of choosing a pure-Go SQLite driver: the result is
# a single static binary that runs on any Linux of the same architecture.
.PHONY: release
release:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w $(LDFLAGS)" -o $(BINARY) $(CMD)

.PHONY: test
test:
	go test ./...

.PHONY: race
race:
	go test -race ./...

.PHONY: cover
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: vet
vet:
	go vet ./...

.PHONY: staticcheck
staticcheck:
	@command -v $(STATICCHECK) >/dev/null 2>&1 || { \
		echo "staticcheck not found: go install honnef.co/go/tools/cmd/staticcheck@latest"; exit 1; }
	$(STATICCHECK) ./...

.PHONY: fmt
fmt:
	gofmt -l -w .

.PHONY: check
check: vet staticcheck test

# Tests that need root and a real kernel: netlink, WireGuard, nftables. Excluded
# from the default suite by a build tag so `make test` stays runnable anywhere.
.PHONY: integration
integration:
	go test -tags=integration -count=1 ./...

.PHONY: clean
clean:
	rm -f $(BINARY) coverage.out
