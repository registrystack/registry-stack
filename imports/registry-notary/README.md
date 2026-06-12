# Registry Notary

> **Experimental:** This codebase is under active development. Its APIs are evolving quickly and may be unstable.

Release label: pre-1.0 technical release for evaluation and integration pilots.

Standalone Registry Notary workspace, claim evaluation, federated delegated
evaluation, credential issuance, and attestation service.

This repository owns claim configuration, claim evaluation, disclosure policy,
Registry Notary API routes, credential issuance primitives, static-peer
federation, HTTP source connectors, fail-closed API key and bearer-token auth,
and redacted audit event emission. Registry Relay or Registry Manifest may
publish metadata that points to a Registry Notary, but Registry Notary does
not import or link Registry Relay code.

Shared security and operations primitives come from sibling
`registry-platform-*` crates, including audit envelopes, auth common code,
cache/replay stores, HTTP security helpers, OIDC, OpenID4VCI, and SD-JWT
support.

See [`docs/README.md`](docs/README.md) for the full documentation map: tutorials,
operator guides, conformance references, and design history.

## Try locally with registryctl

For the first local tutorial, use
[Verify a claim from your registry API](https://docs.registrystack.org/tutorials/verify-claim-registry-api/).
It uses `registryctl` to add Registry Notary to a local registry API project, start both services,
and run the Notary smoke checks without cloning this repository.

If you already have a source API, use
[Verify a claim from your own API](https://docs.registrystack.org/tutorials/verify-claim-own-api/).
That path creates a standalone Notary project and points it at an API you operate.

## Layout

- [`crates/registry-notary-core`](crates/registry-notary-core/README.md):
  portable Registry Notary domain, config, auth, audit, request, response, and
  SD-JWT VC contracts.
- [`crates/registry-notary-server`](crates/registry-notary-server/README.md):
  Axum routes, runtime evaluation, renderers, credential issuance wiring, HTTP
  Registry Data API and DCI source connectors, auth middleware, audit emission,
  and standalone app assembly.
- [`crates/registry-notary-client`](crates/registry-notary-client/README.md):
  typed Rust HTTP client, JSON facade, route-aware retry, bounded response
  reads, JWKS refresh, and redacted errors.
- [`crates/registry-notary-bin`](crates/registry-notary-bin/README.md):
  process startup, config loading, bind address, tracing, graceful shutdown, and
  OpenAPI generation.
- [`crates/registry-notary-openfn-sidecar`](crates/registry-notary-openfn-sidecar/README.md):
  synchronous Registry Data API-shaped sidecar for running pinned OpenFn adaptor
  jobs behind Registry Notary source lookups.
- [`bindings/python`](bindings/python): `registry-notary` sync and async
  dictionary-friendly Python wrapper.
- [`bindings/node`](bindings/node): `@registry-notary/client` Promise client
  with TypeScript declarations.
- [`docs/`](docs/README.md): guides, tutorials, and references for integrators,
  operators, and maintainers, sorted by reader. Demo configs live in
  `demo/config/`.
- [`specs/`](specs/README.md): design specifications and implementation traces for
  self-attestation, static-peer federation, manifest-backed federation,
  the `/v1` REST route cleanup, OpenID4VCI wallet facade, OpenFn sidecar source
  integration, and scalability.

## Credential Conformance

Registry Notary issues SD-JWT VC credentials using `application/dc+sd-jwt`,
EdDSA over named Ed25519 signing keys, and `did:jwk` holder binding. The
supported wire contract and explicit non-support list are in
[`docs/sd-jwt-vc-conformance-profile.md`](docs/sd-jwt-vc-conformance-profile.md).
Signing key configuration and rotation are covered in
[`docs/signing-key-provider.md`](docs/signing-key-provider.md).

## Federated Evaluation

Registry Notary includes a static-peer delegated evaluation slice. Wire
profile, config shape, replay limitation, and rollout checklist are in
[`docs/federated-evaluation-operator-guide.md`](docs/federated-evaluation-operator-guide.md)
and the design record at
[`specs/federated-evaluation-mvp-spec.md`](specs/federated-evaluation-mvp-spec.md).

## Local Run

Use the task runner for the normal local path:

```bash
just setup
just run
```

If `just` is not available, use the raw Cargo fallback:

```bash
export REGISTRY_NOTARY_API_KEY_HASH='sha256:<sha256-hex-of-your-api-key>'
export REGISTRY_NOTARY_BEARER_TOKEN_HASH='sha256:<sha256-hex-of-your-bearer-token>'
export REGISTRY_NOTARY_AUDIT_HASH_SECRET='<stable-random-audit-hash-secret>'
export EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN='<registry-relay-source-token>'
export REGISTRY_NOTARY_ISSUER_JWK='{"kty":"OKP","crv":"Ed25519","d":"...","x":"...","alg":"EdDSA"}'
cargo run -p registry-notary-bin -- --config demo/config/registry-notary.yaml
```

Config-aware commands and server startup also accept `--env-file` for
env-backed local runs:

```bash
cargo run -p registry-notary-bin -- \
  --config demo/config/registry-notary.yaml \
  --env-file .env.local
```

The demo config uses HTTP source connections, so claim evaluation requires a
source service at the configured `base_url`. The binary still starts fail-closed:
no Registry Notary route is served without a configured API key or bearer token.

## Operating Relay And Notary Together

Relay publishes metadata evidence offerings that point callers to Notary; Notary
calls Relay as an HTTP source when a claim profile needs registry data.
Credential wiring, port conventions, replay store, metrics, and audit sink
configuration: [`docs/operator-config-reference.md`](docs/operator-config-reference.md).
Credential status states and verifier caveats:
[`docs/credential-lifecycle-status.md`](docs/credential-lifecycle-status.md).

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p registry-notary-server --no-default-features
cargo test --workspace --all-features
# cargo-deny is pinned through this wrapper.
./scripts/cargo-deny-check.sh
cargo build --workspace --all-features
cargo run -p registry-notary-bin -- openapi > target/registry-notary.openapi.json
```

Use the wrapper for dependency policy checks. It installs and runs the pinned
`cargo-deny` version expected by `deny.toml`, so older global installs do not
break local or CI verification.

Run the first-push preflight before opening or updating PRs that touch Rust,
Cargo features, Dockerfiles, workflows, perf config, or companion repository
refs:

```bash
just ci-preflight
```

The preflight stages a temporary workspace, checks out Platform and Crosswalk at
the workflow-pinned refs, then runs locked Cargo metadata and check commands.
It catches `Cargo.lock` drift and companion-ref skew before the heavyweight CI
jobs reach Docker, perf, or security scans.

Registry Notary depends on sibling `../registry-platform` path crates. CI checks
out `registry-platform` at `REGISTRY_PLATFORM_REF` beside this repository before
running Cargo jobs. Private platform checkouts require a repository secret named
`REGISTRY_PLATFORM_TOKEN`.

Run the focused Platform compatibility gate before merging Platform-facing
changes:

```bash
REGISTRY_PLATFORM_SOURCE_DIR=../registry-platform scripts/check-platform-compat.sh
```

The script validates the all-feature server build and the Platform security API
integration tests. Set `CROSSWALK_SOURCE_DIR` when Crosswalk is not at
`../crosswalk`. CEL is disabled by default; enable with `registry-notary-cel`.

## Docker

The Docker build needs the sibling Platform and Crosswalk workspaces. Build
with Docker BuildKit and pass both named contexts:

```bash
docker build \
  --build-context registry-platform=../registry-platform \
  --build-context crosswalk=../crosswalk \
  -t registry-notary .
```

Default builds compile CEL and PKCS#11 into one release-capable image; runtime
behavior remains config-gated. Release images publish to
`ghcr.io/jeremi/registry-notary` from stable `vX.Y.Z` tags and
`registry-stack-technical-preview-<date-or-version>` tags; deployments should
consume release tags or immutable digests. The OpenFn sidecar image builds from
`Dockerfile.openfn-sidecar` with the same named contexts.

See [`docs/deployment-hardening-runbook.md`](docs/deployment-hardening-runbook.md)
for listener, admin port, healthcheck, config expansion, and rollback guidance.

## OpenAPI

Registry Notary owns its OpenAPI output. Generate the current document with:

```bash
cargo run -p registry-notary-bin -- openapi
```

## Distribution

The workspace crates are not published to crates.io. Consumers should use the
Docker image or a pinned git tag/revision.

## Security

Report vulnerabilities through GitHub Security Advisories. See
[`SECURITY.md`](SECURITY.md) for scope and acknowledgement expectations.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
