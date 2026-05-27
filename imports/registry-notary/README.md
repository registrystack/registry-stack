# Registry Witness

> **Experimental:** This codebase is under active development. Its APIs are evolving quickly and may be unstable.

Standalone Registry Witness workspace, claim evaluation, federated delegated
evaluation, credential issuance, and attestation service.

This repository owns claim configuration, claim evaluation, disclosure policy,
Registry Witness API routes, credential issuance primitives, static-peer
federation, HTTP source connectors, fail-closed API key and bearer-token auth,
and redacted audit event emission. Registry Relay or Registry Manifest may
publish metadata that points to a Registry Witness, but Registry Witness does
not import or link Registry Relay code.

## Layout

- [`crates/registry-witness-core`](crates/registry-witness-core/README.md):
  portable Registry Witness domain, config, auth, audit, request, response, and
  SD-JWT VC contracts.
- [`crates/registry-witness-server`](crates/registry-witness-server/README.md):
  Axum routes, runtime evaluation, renderers, credential issuance wiring, HTTP
  Registry Data API and DCI source connectors, auth middleware, audit emission,
  and standalone app assembly.
- [`crates/registry-witness-bin`](crates/registry-witness-bin/README.md):
  process startup, config loading, bind address, tracing, graceful shutdown, and
  OpenAPI generation.
- [`crates/registry-witness-openfn-sidecar`](crates/registry-witness-openfn-sidecar/README.md):
  synchronous Registry Data API-shaped sidecar for running pinned OpenFn adaptor
  jobs behind Registry Witness source lookups.
- `demo/config/registry-witness.yaml`: split demo config used by
  `registry-relay`'s narrated Registry Witness walkthrough.
- [`docs/openspp-disability-dci.md`](docs/openspp-disability-dci.md):
  OpenSPP Disability Registry DCI demo backend setup, known interop boundaries,
  and demo SD-JWT VC caveats.
- [`docs/federated-witness-manifest-spec.md`](docs/federated-witness-manifest-spec.md):
  Registry Manifest-backed federation, peer discovery, trust, delegated
  evaluation, credential issuance, and audit checkpoint design.
- [`docs/federated-evaluation-mvp-spec.md`](docs/federated-evaluation-mvp-spec.md):
  first practical federation slice for static-peer, signed delegated
  evaluation.
- [`docs/federated-evaluation-operator-guide.md`](docs/federated-evaluation-operator-guide.md):
  minimal static-peer setup, env vars, replay limitation, and verification
  checklist for the MVP.
- [`docs/witness-scenario-catalog.md`](docs/witness-scenario-catalog.md):
  scenario catalog for where Witness helps, who is involved, current support
  status, and the gaps surfaced by local evaluation, federation, proof, issuance,
  and audit workflows.

## Credential Conformance

Registry Witness currently issues SD-JWT VC credentials using
`application/dc+sd-jwt`, EdDSA over Ed25519 issuer keys, and `did:jwk` holder
binding. The supported wire contract and explicit non-support list are defined
in [`docs/sd-jwt-vc-conformance-profile.md`](docs/sd-jwt-vc-conformance-profile.md).

## Federated Evaluation

Registry Witness includes a first federation slice for static-peer delegated
evaluation. When `federation.enabled` is true, the standalone router mounts:

```text
POST /federation/v1/evaluations
```

The endpoint accepts a compact JWS request with
`typ = registry-witness-request+jwt`, verifies the trusted peer and local
policy before any source read, evaluates one configured profile, emits audit,
and returns a compact JWS response with
`typ = registry-witness-response+jwt`.

The MVP is deliberately scoped to delegated evaluation. It does not implement
open federation, dynamic trust chains, audit checkpoint exchange, or federated
credential issuance. See
[`docs/federated-evaluation-mvp-spec.md`](docs/federated-evaluation-mvp-spec.md)
and
[`docs/federated-evaluation-operator-guide.md`](docs/federated-evaluation-operator-guide.md)
for the wire profile, config shape, replay limitation, and rollout checklist.

## Local Run

```bash
export REGISTRY_WITNESS_API_KEY_HASH=sha256:ca2b7917b5d2bdc05d445ce8d50c3adad19ac355d6d40ede18b1f341d7c6e546
export REGISTRY_WITNESS_BEARER_TOKEN_HASH=sha256:f2721a9dae064d1fdbc74cae1fb1baf26fac01b8aac160ae5acab97c35667d7f
export REGISTRY_WITNESS_AUDIT_HASH_SECRET=dev-registry-witness-audit-hash-secret
export EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN=dev-source-token
export REGISTRY_WITNESS_ISSUER_JWK='{"kty":"OKP","crv":"Ed25519","d":"...","x":"...","alg":"EdDSA"}'
cargo run -p registry-witness-bin -- --config demo/config/registry-witness.yaml
```

The demo config uses HTTP source connections, so claim evaluation requires a
source service at the configured `base_url`. The binary still starts fail-closed:
no Registry Witness route is served without a configured API key or bearer token.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p registry-witness-server --no-default-features
cargo test --workspace --all-features
cargo build --workspace --all-features
cargo run -p registry-witness-bin -- openapi > target/registry-witness.openapi.json
```

Registry Witness depends on sibling `../registry-platform` path crates. CI checks
out `registry-platform` at `REGISTRY_PLATFORM_REF` beside this repository before
running Cargo jobs. Private platform checkouts require a repository secret named
`REGISTRY_PLATFORM_TOKEN`.

CEL is enabled by default through the `registry-witness-cel` feature and is
implemented through the local `crosswalk-core` crate at
`../cel-mapping/crates/crosswalk-core`.

## Docker

The Docker build also needs the sibling platform workspace. Build with Docker
BuildKit and pass `../registry-platform` as a named context:

```bash
docker build --build-context registry-platform=../registry-platform -t registry-witness .
```

## OpenAPI

Registry Witness owns its OpenAPI output. Generate the current document with:

```bash
cargo run -p registry-witness-bin -- openapi
```

## Distribution

The workspace crates are not published to crates.io. Consumers should use the
Docker image or a pinned git tag/revision.

## Security

Report vulnerabilities through GitHub Security Advisories. See
[`SECURITY.md`](SECURITY.md) for scope and acknowledgement expectations.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
