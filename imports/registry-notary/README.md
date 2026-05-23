# Evidence Server

Standalone Evidence Server workspace extracted from `registry_relay`.

This repository owns claim configuration, claim evaluation, disclosure policy,
Evidence Server API routes, credential issuance primitives, HTTP source
connectors, fail-closed API key and bearer-token auth, and redacted audit event
emission. Registry Relay may publish metadata that points to an Evidence Server,
but Evidence Server does not import or link Registry Relay code.

## Layout

- `crates/evidence-core`: portable Evidence Server domain, config, auth, audit,
  request, response, and SD-JWT VC contracts.
- `crates/evidence-server`: Axum routes, runtime evaluation, renderers,
  credential issuance wiring, HTTP Registry Data API and DCI source connectors,
  auth middleware, audit emission, and standalone app assembly.
- `crates/evidence-server-bin`: process startup, config loading, bind address,
  tracing, and graceful shutdown.
- `demo/config/evidence-server.yaml`: split demo config used by
  `registry_relay`'s narrated Evidence Server walkthrough.

## Local Run

```bash
export EVIDENCE_SERVER_API_KEY=dev-evidence-api-key
export EVIDENCE_SERVER_BEARER_TOKEN=dev-evidence-bearer-token
export EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN=dev-source-token
export EVIDENCE_SERVER_ISSUER_JWK='{"kty":"OKP","crv":"Ed25519","d":"...","x":"...","alg":"EdDSA"}'
cargo run -p evidence-server-bin -- --config demo/config/evidence-server.yaml
```

The demo config uses HTTP source connections, so claim evaluation requires a
source service at the configured `base_url`. The binary still starts fail-closed:
no Evidence Server route is served without a configured API key or bearer token.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p evidence-server --no-default-features
cargo test --workspace --all-features
cargo build --workspace --all-features
cargo run -p evidence-server-bin -- openapi > target/evidence-server.openapi.json
```

CEL is enabled by default through the `evidence-server-cel` feature and is
implemented through `cel-mapper-core`, pinned to the published
`cel-mapper-core-v0.1.1` tag in `PublicSchema/cel-mapping`.

## OpenAPI

Evidence Server owns its OpenAPI output. Generate the current document with:

```bash
cargo run -p evidence-server-bin -- openapi
```
