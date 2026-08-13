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
  registry-evidence check --require-runtime-dependencies
```

Relay provides the equivalent `relay check --runtime
/etc/relay/runtime.yaml`; Mint provides `mint check
--require-runtime-dependencies`. For a Compose deployment containing any
combination of the three official products, use
`docker/runtime-preflight.py` to verify the common container posture first and
then run each product's native check in its actual mounts and network. The
preflight rejects host or shared network namespaces, entrypoint or command
overrides, alternate Evidence or Mint configuration paths, privileged mode,
added capabilities, inherited mounts, writable configuration or secret trees,
anonymous audit volumes, and named volumes backed by tmpfs. Audit storage must
be an explicit durable named volume or bind mount. Name the exact mount target
for every selected service so the product can prove that its resolved audit
destination is at or below that root:

```sh
python3 docker/runtime-preflight.py \
  --compose-file <compose.yaml> \
  --service evidence=evidence \
  --audit-root evidence=/var/lib/registry-evidence
```

The product owns configuration resolution and the adapter owns mount
persistence. A decoy persistent volume does not satisfy the check when the
configured audit sink is elsewhere. The adapter also rejects an asserted root
that is read-only, ephemeral, duplicated, or shadowed by another mount or
`tmpfs`.

For a cold deployment in which Evidence consumes a selected Mint service,
declare Mint as an internal dependency. When Mint binds a private Compose
address instead of loopback, set its service environment
`MINT_HEALTHCHECK_URL=http://<private-address>:<port>/ready`:

```sh
python3 docker/runtime-preflight.py \
  --compose-file <compose.yaml> \
  --service mint=mint \
  --audit-root mint=/var/lib/registry-mint \
  --service evidence=evidence \
  --audit-root evidence=/var/lib/registry-evidence \
  --dependency-service mint \
  --native-check-timeout-seconds 600 \
  --dependency-timeout-seconds 120
```

Repeat `--dependency-service` in startup order when more than one selected
Mint or Relay service must serve a later check. For each declared dependency,
the adapter runs its native check, starts only that service with `--no-deps`,
and accepts only its product-owned readiness probe before continuing. Evidence
cannot be a dependency because its released image has no process-local probe
command. Undeclared Compose services are never started, and ordinary
single-product checks retain the isolated `--no-deps` behavior.

Started dependencies remain running after success or any later failure so the
operator can inspect or route the validated deployment. The adapter performs
no automatic cleanup. To return to a cold state, stop the exact declared
dependency services with `docker compose stop <service>...`; do not use `down
-v`, which would delete retained audit volumes. Native-check deadlines accept
30 through 86,400 seconds. Dependency-readiness deadlines accept 5 through 600
seconds. Compose output and dependency response bodies are discarded.

## Health probes

Neither development image declares a Docker `HEALTHCHECK`. Evidence serves
`GET /health` for an orchestrator HTTP probe. Mint also serves `GET /health`
and provides `mint healthcheck`, a bounded private-address probe of `/ready`
for container and process supervisors. Set `MINT_HEALTHCHECK_URL` to the
container's configured private listener address when it does not bind the
loopback default.

For an approved Evidence release or candidate, use the operator-owned
[Compose adapter](compose/README.md), pin the reviewed image digest, and run
`evidence check` inside the target container context.
