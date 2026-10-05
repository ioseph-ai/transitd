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

# test is the CI parity target: race detector, no result caching.
test:
	$(GO) test -race -count=1 $(PKG)

# unit is an alias for test (documented so the intent reads clearly).
unit: test

# integration drives the integration tier through docker compose and the
# `integration` build tag. NOTE: test/compose.yaml and the tagged tests land
# in a later PR (the integration-tier PR), not this one — until that merges
# this target fails fast with a pointer instead of a cryptic docker error.
integration:
	@if [[ ! -f test/compose.yaml ]]; then \
		echo "integration: test/compose.yaml not found — the integration-tier PR has not landed yet"; \
		exit 1; \
	fi
	@set -e; \
	trap 'docker compose -f test/compose.yaml down -v' EXIT; \
	docker compose -f test/compose.yaml up -d --wait; \
	$(GO) test -tags=integration -count=1 $(PKG)

# lint runs golangci-lint with the repo config (.golangci.yml).
lint:
	$(GOLANGCI_LINT) run

# fmt rewrites the tree in gofumpt style. On a clean tree it produces no diff.
fmt:
	$(GOFUMPT) -l -w .

# vulncheck scans dependencies for known vulnerabilities.
vulncheck:
	$(GOVULNCHECK) $(PKG)

# golden-update regenerates golden vtysh batches. Detect the "no golden tests
# yet" case explicitly and report it; a real TestGolden failure still fails.
golden-update:
	@if [[ "$$($(GO) test $(PKG) -list 'TestGolden' 2>/dev/null | grep -c '^TestGolden')" -eq 0 ]]; then \
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
