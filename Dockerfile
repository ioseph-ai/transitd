# Release image for transitd.
#
# GoReleaser builds the static transitd binary for every target platform before
# the image build, and docker (v2) copies those pre-built binaries into a
# temporary build context laid out as <os>/<arch>/<binary>. This Dockerfile
# therefore only copies the matching platform's binary into a distroless base
# — it never compiles anything (no `go build` here).
#
# Base is distroless static: the binary is CGO-free and needs no libc, shell,
# or package manager, which keeps the attack surface minimal.
#
# NOTE: this image intentionally ships only the transitd binary. transitctl (the
# control-channel client, issue #2) is a separate release artifact: it belongs on
# an operator's workstation or management host, not on the router, so it is not
# copied here. Bundling a static `ping` (a #7 container-contents decision) is out
# of scope for the pipeline-only change in #17.
FROM gcr.io/distroless/static-debian12

ARG TARGETPLATFORM

COPY $TARGETPLATFORM/transitd /usr/local/bin/transitd

ENTRYPOINT ["/usr/local/bin/transitd"]
