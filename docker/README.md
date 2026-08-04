# Development images

Distroless container images for the `mint` and `evidence` services, built
entirely inside Docker from the repository root:

```sh
docker build -f docker/Dockerfile --target mint -t registry-mint .
docker build -f docker/Dockerfile --target evidence -t registry-evidence .
```

These images are **not release evidence**. The released Notary and Relay
images are assembled from `release/docker/` with byte-reproducible binaries
built outside Docker by `release/scripts/build-release-binaries.sh`; if Mint
or Evidence images ever become release artifacts, they follow that path, not
this one.

## Build architecture

Both targets share one multi-stage file using
[cargo-chef](https://github.com/LukeMathWalker/cargo-chef) so dependency
compilation is an ordinary image layer, cacheable by registry-backed or CI
layer caches across ephemeral runners (which BuildKit `--mount=type=cache`
mounts are not). Each binary has its own recipe filtered to its transitive
dependency closure (`cargo chef prepare --bin`), so a manifest change in an
unrelated workspace member (for example Relay) invalidates neither image, and
neither image compiles heavyweight dependencies it does not use.

The builder and runtime base images are pinned to the same digests the rest
of the repository uses: `rust:1.95-trixie` and
`gcr.io/distroless/cc-debian13:nonroot`. Both final images run as the
distroless `nonroot` user (65532) with no shell or package tools.

## Running Mint locally

The configuration is a startup-only artifact. Mount it read-only at
`/etc/registry-mint` with the signing key and client registry beside it, at
the paths the configuration names (relative paths resolve against the
configuration file's directory). The listener address in the configuration
must be an IP the container can bind. Use a private network address for a
Compose deployment:

```sh
docker run --rm \
  -v "$PWD/deploy/mint:/etc/registry-mint:ro" \
  registry-mint
```

`mint check` validates a deployment without opening a socket:

```sh
docker run --rm -v "$PWD/deploy/mint:/etc/registry-mint:ro" registry-mint check
```

## Running Evidence locally

The runtime file, governed bundle, and secret root are startup-only
artifacts; mount them read-only under `/etc/registry-evidence`. The image
expects the operator runtime at `/etc/registry-evidence/runtime.yaml`
(`REGISTRY_EVIDENCE_RUNTIME`). The runtime's `bundleDirectory`, secret
provider `root`, audit `path`, and any `trustProfiles.*.caBundleFile` are
validated absolute paths, interpreted inside the container: every one of
them must resolve to a mount. Point the audit destination under
`/var/lib/registry-evidence`, which is writable by the nonroot user, and
give it a named volume; the audit chain is append-only state that must
outlive the container.

The evidence and metrics listeners deliberately refuse wildcard and public
bind addresses: `bindHost` must be loopback, RFC 1918 private IPv4, or IPv6
unique-local. `0.0.0.0` will not start, and `127.0.0.1` is unreachable
through Docker port publishing. Give the container a static private address
on a user-defined network and bind that:

```sh
docker network create --subnet 172.28.0.0/24 registry-evidence-net
docker run --rm \
  --network registry-evidence-net --ip 172.28.0.10 \
  -v "$PWD/deploy/evidence:/etc/registry-evidence:ro" \
  -v evidence-audit:/var/lib/registry-evidence \
  registry-evidence
```

with `listener.bindHost: 172.28.0.10` in `runtime.yaml`. TLS and public
exposure are upstream concerns by design; front this listener with your
operator-network proxy. `evidence check` validates the bundle without
serving:

```sh
docker run --rm -v "$PWD/deploy/evidence:/etc/registry-evidence:ro" registry-evidence check
```

## Health probes

Neither image declares a Docker `HEALTHCHECK`: distroless has no shell or
curl, and neither binary has a healthcheck subcommand (the released Notary
and Relay binaries do). Both services serve `GET /health` on their listener;
use HTTP probes from your orchestrator.

For an approved Evidence candidate, use the operator-owned
[Compose adapter](compose/README.md), select reviewed image provenance separately, and run
`evidence check` inside the target container context.
