# Registry Platform

Shared Rust security and operational primitives for Registry Relay, Registry
Witness, and related registry services.

The workspace is consumed by applications through a pinned git tag. It centralizes
the pieces that should behave identically across services: outbound HTTP policy,
authentication helpers, OIDC verification, audit chaining, browser-facing HTTP
security, SD-JWT VC support, crypto primitives, and integration-test fixtures.

## Crates

| Crate | Purpose |
| --- | --- |
| [`registry-platform-audit`](crates/registry-platform-audit/README.md) | Tamper-evident audit envelopes, async sinks, JSONL verification, and redaction helpers. |
| [`registry-platform-authcommon`](crates/registry-platform-authcommon/README.md) | Provider-independent authentication helpers for Bearer tokens and API-key fingerprints. |
| [`registry-platform-crypto`](crates/registry-platform-crypto/README.md) | Ed25519 JWK parsing, signing, verification, DID validation, and JSON canonicalization. |
| [`registry-platform-httpsec`](crates/registry-platform-httpsec/README.md) | Axum/Tower HTTP security middleware, CORS policy validation, body limits, and RFC 7807 responses. |
| [`registry-platform-httputil`](crates/registry-platform-httputil/README.md) | Outbound HTTP clients, bounded response reads, URL construction, and SSRF-resistant fetch validation. |
| [`registry-platform-oidc`](crates/registry-platform-oidc/README.md) | OIDC discovery, JWKS caching, and JWT verifier configuration shared by registry services. |
| [`registry-platform-sdjwt`](crates/registry-platform-sdjwt/README.md) | SD-JWT VC issuance and holder-proof validation helpers. |
| [`registry-platform-testing`](crates/registry-platform-testing/README.md) | Mock IdP, mock HTTP upstreams, key fixtures, and cross-crate assertions for consumers. |

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
- Versioning: all crates currently share the workspace version `0.1.2`.
- Signing support: v0.1.2 supports EdDSA/Ed25519 for platform-owned signing and
  verification. OIDC JWT verification is caller-configurable for provider
  compatibility, but consumers should keep algorithm allowlists as narrow as
  their provider supports.

## Consuming the Workspace

Registry applications should depend on a pinned git tag or revision and enable
only the crates they need.

```toml
[dependencies]
registry-platform-httputil = { git = "https://github.com/jeremi/registry-platform", tag = "v0.1.2" }
registry-platform-oidc = { git = "https://github.com/jeremi/registry-platform", tag = "v0.1.2" }
```

The `registry-platform-httputil` crate defaults to `rustls`. Use
`default-features = false` with the `native-tls` feature only when a consumer has
a concrete platform requirement.

## Development

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
isolation, replay storage, audit retention, secret provisioning, and deployment
configuration.

Report security-sensitive issues privately before opening a public issue.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
