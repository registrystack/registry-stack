# Registry Platform

> **Experimental:** This codebase is under active development. Its APIs are evolving quickly and may be unstable.

Release label: pre-1.0 technical release for evaluation and integration pilots.

Shared Rust security and operational primitives for Registry Relay, Registry
Notary, and related registry services.

The workspace is consumed by applications through a pinned git tag. It centralizes
the pieces that should behave identically across services: outbound HTTP policy,
authentication helpers, OIDC verification, audit chaining, browser-facing HTTP
security, SD-JWT VC support, crypto primitives, operations posture contracts,
and integration-test fixtures.

## Crates

| Crate | Purpose |
| --- | --- |
| [`registry-config-report`](crates/registry-config-report/README.md) | Shared configuration diagnostic and explanation report schemas, fixtures, serde types, and redaction helpers. |
| [`registry-platform-audit`](crates/registry-platform-audit/README.md) | Tamper-evident audit envelopes, async sinks, JSONL verification, and redaction helpers. |
| [`registry-platform-authcommon`](crates/registry-platform-authcommon/README.md) | Provider-independent authentication helpers for Bearer tokens and API-key fingerprints. |
| [`registry-platform-cache`](crates/registry-platform-cache/README.md) | Generic cache-store trait, redacted hashed keys, in-memory cache, and Redis backend for higher-level primitives. |
| [`registry-platform-config`](crates/registry-platform-config/README.md) | Config Bundle v1 manifests, trust anchors, file-closure verification, and local break-glass override contracts. |
| [`registry-platform-crypto`](crates/registry-platform-crypto/README.md) | Ed25519 JWK parsing, provider-backed signing, verification, DID validation, and JSON canonicalization. |
| [`registry-platform-httpsec`](crates/registry-platform-httpsec/README.md) | Axum/Tower HTTP security middleware, CORS policy validation, body limits, and RFC 9457 Problem Details responses. |
| [`registry-platform-httputil`](crates/registry-platform-httputil/README.md) | Outbound HTTP clients, bounded response reads, URL construction, and SSRF-resistant fetch validation. |
| [`registry-platform-oid4vci`](crates/registry-platform-oid4vci/README.md) | OID4VCI protocol constants, issuer metadata, holder proof validation, and credential endpoint wire types. |
| [`registry-platform-oidc`](crates/registry-platform-oidc/README.md) | OIDC discovery, JWKS caching, and JWT verifier configuration shared by registry services. |
| [`registry-platform-ops`](crates/registry-platform-ops/README.md) | Shared public operations posture schemas, examples, and redaction fixtures. |
| [`registry-platform-replay`](crates/registry-platform-replay/README.md) | Shared replay and consumable nonce semantics over cache stores for nonce and JWT `jti` rejection. |
| [`registry-platform-sdjwt`](crates/registry-platform-sdjwt/README.md) | SD-JWT VC issuance and holder-proof validation helpers. |
| [`registry-platform-testing`](crates/registry-platform-testing/README.md) | Mock IdP, mock HTTP upstreams, key fixtures, and cross-crate assertions for consumers. |

Parked source retained in this repository: `crates/registry-platform-sts` is not
a workspace member or release artifact until Assisted Access or the delegation
profile work promotes a consumer (#298).

## Design Principles

- Fail closed on malformed security input.
- Prefer explicit allowlists over broad defaults.
- Keep network fetches bounded by URL policy, byte limits, and timeouts.
- Avoid secret material in debug output and logs.
- Keep crate APIs small enough that application code can compose them directly.
- Treat test fixtures as a supported surface for downstream integration tests.

## Compatibility

- Rust edition: 2021.
- License: Apache-2.0.
- Publication: crates are private to this workspace (`publish = false`).
- Versioning: all crates currently share the workspace version `0.2.1`.
- Signing support: v0.2.1 supports EdDSA/Ed25519 for platform-owned signing and
  verification, including a provider abstraction for local JWKs and external
  signing adapters. OIDC JWT verification is caller-configurable for provider
  compatibility, but consumers should keep algorithm allowlists as narrow as
  their provider supports.

## Consuming the Workspace

Registry applications should depend on a pinned git tag or revision and enable
only the crates they need.

```toml
[dependencies]
registry-platform-httputil = { git = "https://github.com/jeremi/registry-platform", tag = "v0.2.1" }
registry-platform-oidc = { git = "https://github.com/jeremi/registry-platform", tag = "v0.2.1" }
```

The `registry-platform-httputil` crate uses `rustls` for outbound HTTPS.

## Development

### Toolchain pins

- Rust: pinned in [`rust-toolchain.toml`](rust-toolchain.toml) (currently `1.95.0`).
- `cargo-deny`: install `0.19.7` or newer to match CI; older versions (≤ `0.14.x`) cannot parse the `[graph]` syntax used in [`deny.toml`](deny.toml).

```sh
cargo install --locked cargo-deny@0.19.7
```

### Common commands

Run checks from the workspace root:

```sh
cargo fmt --check
cargo build --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
GITLEAKS_CONFIG_TOML="$(cat <<'TOML'
[extend]
useDefault = true

[[allowlists]]
description = "Ignore generated Rust build output."
paths = ["(^|/)target/"]
TOML
)" gitleaks dir --no-banner --redact --verbose --timeout 120 .
```

For focused work on one crate:

```sh
cargo test -p registry-platform-oidc
```

## Repository Files

- [`CHANGELOG.md`](CHANGELOG.md) records release-level changes.
- [`deny.toml`](deny.toml) defines dependency, license, advisory, and source
  policy.
- [`rustfmt.toml`](rustfmt.toml) and [`clippy.toml`](clippy.toml) define shared
  Rust hygiene defaults.

## Security Notes

This repository contains reusable primitives, not a complete application security
boundary. Consumers remain responsible for service authorization, tenant
isolation, audit retention, secret provisioning, and deployment configuration.

Governed runtime configuration integrations should follow the public
[`governed-configuration`](docs/governed-configuration.md) guide for signed
local bundle verification, trust anchors, anti-rollback state, emergency
override files, and verification result vocabulary.

Secret-provider integrations should follow the
[`secret-provider-readiness`](docs/secret-provider-readiness.md) contract for
provider labels, readiness-gated apply, and posture-safe redaction.

The in-memory cache and replay stores are for tests and single-process
development. Services that require replay protection across restarts or
active-active deployments need a durable shared backend such as Redis.

Report security-sensitive issues privately before opening a public issue.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
