# Development images

Distroless container images for the `mint` and `evidence` services, built
entirely inside Docker from the repository root:

```sh
docker build -f docker/Dockerfile --target mint -t registry-mint .
docker build -f docker/Dockerfile --target evidence -t registry-evidence .
```

These locally built images are **not release evidence**. Starting with
`v0.21.0`, the official Evidence, Mint, and Relay images are
`ghcr.io/registrystack/evidence:v0.21.0`,
`ghcr.io/registrystack/mint:v0.21.0`, and
`ghcr.io/registrystack/relay:v0.21.0`. They are assembled from
`release/docker/` with byte-reproducible binaries built outside Docker by
`release/scripts/build-release-binaries.sh`. Published deployments should pin
the selected image by the digest recorded in the release manifest.

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
distroless `nonroot` user (UID and GID 65532) with no shell or package tools.
The official images have the same nonroot runtime identity and publish it as
the machine-readable `org.registrystack.runtime.uid` and
`org.registrystack.runtime.gid` OCI labels.

## Running Mint locally

The configuration is a startup-only artifact. Mount it read-only at
`/etc/registry-mint` with the signing key and client registry beside it, at
the paths the configuration names (relative paths resolve against the
configuration file's directory). The listener address in the configuration
must be an IP the container can bind. Use a private network address for a
Compose deployment. Point `audit.path` under `/var/lib/registry-mint/audit`
and mount that directory on persistent storage owned by UID and GID 65532:

```sh
docker run --rm \
  -v "$PWD/deploy/mint:/etc/registry-mint:ro" \
  -v mint-audit:/var/lib/registry-mint \
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

The default Evidence listener accepts only loopback, RFC 1918 private IPv4,
or IPv6 unique-local addresses. A container deployment may instead declare
`listener.networkExposure: container-private` and bind `0.0.0.0` or `::`.
That explicit mode treats the container network and upstream TLS proxy as the
operator-owned exposure boundary. It still rejects concrete public addresses,
hostnames, and multicast addresses. The metrics listener remains private-only.

For example:

```sh
docker network create registry-evidence-net
docker run --rm \
  --network registry-evidence-net \
  -v "$PWD/deploy/evidence:/etc/registry-evidence:ro" \
  -v evidence-audit:/var/lib/registry-evidence \
  registry-evidence
```

with `listener.bindHost: 0.0.0.0` and
`listener.networkExposure: container-private` in `runtime.yaml`. TLS and
public exposure are upstream concerns by design; front this listener with your
operator-network proxy. `evidence check` validates the bundle without serving.
Add `--require-runtime-dependencies` in the target container to prove audit
writability, signer readiness, source credentials, and JWKS reachability:

```sh
docker run --rm -v "$PWD/deploy/evidence:/etc/registry-evidence:ro" \
  -v evidence-audit:/var/lib/registry-evidence \
  registry-evidence check --require-runtime-dependencies \
  --require-audit-under /var/lib/registry-evidence
```

`--require-audit-under ABSOLUTE_DIRECTORY` adds one further proof: the
configured audit sink has to resolve at or below the directory the deployment
declares persistent. Evidence resolves its own configured destination exactly
as startup does and canonicalizes both sides, so a sink configured outside the
declared root, and a symlink inside the root that leads out of it, both fail
closed. The option proves containment only; the writability and chain proofs
still have to pass.

Relay provides the equivalent `relay check --runtime
/etc/relay/runtime.yaml`; Mint provides `mint check
--require-runtime-dependencies`. Both accept the same
`--require-audit-under`. For a Compose deployment containing any
combination of the three official products, use
`docker/runtime-preflight.py` to verify the common container posture first and
then run each product's native check in its actual mounts and network. The
preflight rejects host or shared network namespaces, entrypoint or command
overrides, alternate Evidence or Mint configuration paths, privileged mode,
replacement builds, added capabilities or supplementary groups, host devices,
any security option other than one `no-new-privileges` entry, multiple
replicas, lifecycle hooks, dynamic-loader overrides, inherited mounts,
executable- or library-shadowing mounts, writable configuration or secret
trees, anonymous audit volumes, service-level tmpfs, any long-form
tmpfs except the required read-only mount at `/dev/shm`, and
driver-option-backed named volumes. Docker's
implicit writable `/dev/shm` would otherwise let an unused durable audit
volume hide an ephemeral configured sink. With `/dev/shm` read-only, the fixed
nonroot identity, and the read-only root filesystem, the audit root is the only
usable regular-file write lane. It may be a Docker-managed local named volume
with no driver options or an explicit bind outside known ephemeral host paths.
The preflight then hands that validated root to each
native check as `--require-audit-under`, which splits the proof along the
ownership boundary: the adapter owns storage persistence and never reads
product configuration, while the product owns configuration resolution and
never infers which mounts are durable. Neither a durable mount sitting unused
beside an ephemeral configured sink nor a symlink leading out of the mount
satisfies both halves.

Every native check runs under a bounded deadline. It defaults to 1800 seconds
because validating a retained audit chain can legitimately take longer than a
short deployment timeout, and `--native-check-timeout-seconds SECONDS` selects
any deadline from 30 to 21600 seconds. An expired deadline names the service
that exceeded it and fails the preflight.

Selected Compose dependencies are honored. A cold Evidence check can check,
start with `--no-deps`, and readiness-probe a declared Mint dependency before
checking Evidence. The dependency lane is an explicit allowlist: only a
selected service whose product is Mint may be started, because Relay's existing
healthcheck is liveness-only and is not accepted as readiness, and a
`depends_on` edge to a service the operator did not select starts nothing. The
plan orders every dependency before its dependent, rejects a cycle in the
selected services before running anything, and is otherwise the given selection
order. `docker/compose/docker-compose.mint.yaml` is the cold Mint and Evidence
fixture for that lane; it publishes no host port.

Services started for dependency checking remain under the operator's Compose
lifecycle. The preflight names them, and the command that stops them, on
success and on failure, so a partially completed run is recoverable with the
same Compose files. `--dependency-timeout-seconds` bounds both Mint startup and
readiness polling under one shared deadline. Mint's `MINT_HEALTHCHECK_URL`
selects a numeric private `/ready` listener when loopback is not the configured
bind. Native checks consume the exact rendered Compose JSON already
validated by the static pass, rather than re-reading mutable Compose or
environment files.

## Health probes

Neither image declares a Docker `HEALTHCHECK`. Mint provides a strict
`mint healthcheck` command for its private `/ready` endpoint; Evidence serves
`GET /health` and expects an operator-owned HTTP probe. The image itself does
not guess which listener address is reachable from the container namespace.

For an approved Evidence release or candidate, use the operator-owned
[Compose adapter](compose/README.md), pin the reviewed image digest, and run
`evidence check` inside the target container context.
