# Contributing to transitd

Thanks for taking a look. transitd is a small, pre-1.0 project, so the process
here is deliberately lightweight.

## Ground rules

- Be civil. Attack the change, not the person.
- **No DCO and no CLA.** You do not need to sign-off commits or sign a
  contributor agreement. Contributions are accepted under the project's
  license (see `LICENSE`); by opening a pull request you confirm you have the
  right to submit the code.
- **Small pull requests are strongly preferred.** A focused PR that does one
  thing is easier to review, easier to revert, and lands faster than a large
  one. If you have several independent changes, send several PRs (or split an
  existing one) rather than bundling them.
- For anything non-trivial or design-shaped, **open an issue first** and agree
  on the approach before writing code. This is especially true for changes to
  the decision/safety path — that code is load-bearing and we would rather
  agree on the design up front.

## Development loop

transitd is a single static Go binary. You need a recent Go (the module
targets the version in `go.mod`, and CI tracks it).

```sh
go build ./...
go test ./...
```

`go test` builds and runs the unit tests with the race detector behavior CI
uses when you pass `-race`; run `go test -race ./...` before pushing if you
touched anything concurrent (the gossip/decide path is).

### Make targets

There is a `Makefile` with the common targets. `make test` and `make lint`
are the intended entry points once it lands; if the targets are not present
yet, fall back to the `go` commands above. Use:

```sh
make test    # unit tests (race)
make lint    # formatting + static analysis
```

The Makefile is being added separately; this document describes how the
targets are meant to behave, not a fixed implementation. If a target is
missing or broken, that is a bug — file it.

## Formatting

Go code must be formatted with **gofumpt** (the stricter superset of `gofmt`
used by this project). CI checks formatting on every PR.

```sh
go install mvdan.cc/gofumpt@latest
gofumpt -l -w .
```

If `gofumpt` reports nothing, you are clean. Do not hand-format around it.

`golangci-lint` runs in CI with the repository's configuration; run it
locally if you have it:

```sh
golangci-lint run
```

## Tests

- Add or update tests with every behavioral change. Table-driven tests are
  the house style.
- **Golden files:** the decide/act path is tested against golden `vtysh`
  command batches. If you intentionally change a command batch, the golden
  file must be updated, and the change to it is part of the review. To
  regenerate the golden output:

  ```sh
  UPDATE_GOLDEN=1 go test ./...
  ```

  (The exact env var and targets may evolve; the convention — regenerate
  deliberately, never blindly — does not.) Review the golden diff before
  committing it: it is the machine-readable statement of what the agent will
  do to a router.
- Integration tests run against FRR containers via docker compose and are
  heavier; see the repository docs for how to run them locally.

## What we look for in review

- The change is small and does what it says.
- Tests cover the behavior (including the failure/safety path).
- **No site-specific values anywhere** — not in fixtures, not in examples,
  not in test data, not in comments. Use documentation ranges only:
  `2001:db8::/32`, `192.0.2.0/24`, `198.51.100.0/24`, AS 64496–64511.
  A real address or ASN in a PR is a blocking problem, even in a comment.
- Docs updated when behavior, configuration, or operations change.

## Security

Do **not** open public issues for security problems. See [SECURITY.md](SECURITY.md)
for the private reporting process and the trust model (in short: the gossip
key is root-equivalent on the routing plane, and vtysh access is not a
privilege boundary).

## Pull requests

Open the PR against `master`, fill in the pull-request template, and keep the
description focused on *why*. CI must be green. Do not merge your own PR if
you are not the maintainer; a maintainer merges after review. Do not
force-push to shared branches.
