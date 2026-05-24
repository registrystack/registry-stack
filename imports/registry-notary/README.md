# Registry Witness

Standalone Registry Witness workspace, claim evaluation, credential issuance, and attestation service.

This repository owns claim configuration, claim evaluation, disclosure policy,
Registry Witness API routes, credential issuance primitives, HTTP source
connectors, fail-closed API key and bearer-token auth, and redacted audit event
emission. Registry Relay may publish metadata that points to a Registry Witness,
but Registry Witness does not import or link Registry Relay code.

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
- `demo/config/registry-witness.yaml`: split demo config used by
  `registry-relay`'s narrated Registry Witness walkthrough.

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
implemented through `cel-mapper-core`, pinned to the published
`cel-mapper-core-v0.1.1` tag in `PublicSchema/cel-mapping`.

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
