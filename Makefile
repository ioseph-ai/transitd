# transitd developer Makefile.
#
# Deliberately plain `make` (no Task/just/mage) and zero new tool
# prerequisites for contributors: every target is a thin wrapper around a
# command the Go toolchain (or an already-expected dev tool) provides, so CI
# and a local checkout run exactly the same thing. External tools that are
# not part of the Go toolchain (golangci-lint, gofumpt, govulncheck,
# goreleaser) are looked up on PATH and the targets that need them say so
# when they are missing.

SHELL   := /bin/bash

GO      ?= go
PKG     ?= ./...
GOLANGCI_LINT ?= golangci-lint
GOFUMPT ?= gofumpt
GOVULNCHECK ?= govulncheck
GORELEASER ?= goreleaser
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build test unit integration lint fmt vulncheck golden-update release-dry clean

all: build

# build compiles every package (no install).
build:
	$(GO) build $(PKG)

# build-binaries builds the two shipped commands into ./bin. `build` alone only
# compiles packages; an operator (or a smoke test) wants the actual executables,
# which is what this target produces: the agent and transitctl, the control
# channel's client.
build-binaries:
	$(GO) build -o bin/transitd ./cmd/transitd
	$(GO) build -o bin/transitctl ./cmd/transitctl

# test is the CI parity target: race detector, no result caching.
test:
	$(GO) test -race -count=1 $(PKG)

# unit is an alias for test (documented so the intent reads clearly).
unit: test

# integration drives the integration tier through docker compose and the
# `integration` build tag. It needs only a docker daemon: the tagged tests in
# test/integration bring the lab in test/compose.yaml up and down themselves
# (TestMain runs `docker compose up -d --wait` and `down -v`), so this target
# is exactly what CI runs. The `up -d` below is a warm-up so a compose failure
# surfaces as a clear error before `go test` starts; `set -e` in the test then
# owns the run.
integration:
	@command -v docker >/dev/null 2>&1 || { \
		echo "integration: docker is required for the compose lab"; \
		exit 1; \
	}
	@set -e; \
	trap 'docker compose -f test/compose.yaml down -v' EXIT; \
	docker compose -f test/compose.yaml up -d; \
	$(GO) test -tags=integration -count=1 ./test/...

# lint runs golangci-lint with the repo config (.golangci.yml).
lint:
	$(GOLANGCI_LINT) run

# fmt rewrites the tree in gofumpt style. On a clean tree it produces no diff.
fmt:
	$(GOFUMPT) -l -w .

# vulncheck scans dependencies for known vulnerabilities.
vulncheck:
	$(GOVULNCHECK) $(PKG)

# golden-update regenerates committed golden fixtures. The decide regression
# baseline (internal/decide/testdata/golden/decide) is the current user: the
# TestGoldenDecide harness rebuilds each scenario file from the engine's actual
# output when UPDATE_GOLDEN=1. Detect the "no golden tests yet" case explicitly
# and report it; a real TestGolden failure still fails, and a discovery failure
# (go test -list) propagates instead of reading as 0.
golden-update:
	@list="$$($(GO) test $(PKG) -list 'TestGolden')" || exit $$?; \
	if [[ "$$(printf '%s\n' "$$list" | grep -c '^TestGolden')" -eq 0 ]]; then \
		echo "no golden tests yet"; \
	else \
		UPDATE_GOLDEN=1 $(GO) test $(PKG) -run TestGolden; \
	fi

# release-dry builds a goreleaser snapshot locally (never publishes). Report
# it as unavailable only when the tool is missing; a failed build still fails.
release-dry:
	@command -v $(GORELEASER) >/dev/null 2>&1 || { echo "goreleaser not installed"; exit 0; }; \
	$(GORELEASER) release --snapshot --clean

clean:
	$(GO) clean
	rm -f coverage.out
	rm -rf dist/
