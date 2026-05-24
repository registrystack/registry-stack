# Release Notes

## 0.2.0 (rename)

- Renamed: `evidence-server` → `registry-witness`. No backward compatibility; no aliases.
  - Crates: `evidence-core` → `registry-witness-core`, `evidence-server` → `registry-witness-server`,
    `evidence-server-bin` → `registry-witness-bin`.
  - Binary: `evidence-server` → `registry-witness`.
  - Media type: `application/vnd.evidence-server.claim-result+json` → `application/vnd.registry-witness.claim-result+json`.
  - Default audience: `"evidence-server"` → `"registry-witness"`.
  - Cargo feature: `evidence-server-cel` → `registry-witness-cel`.
  - Project-labeled env vars: `EVIDENCE_SERVER_API_KEY`, `EVIDENCE_SERVER_BEARER_TOKEN`,
    `EVIDENCE_SERVER_ISSUER_JWK` → `REGISTRY_WITNESS_API_KEY_HASH`,
    `REGISTRY_WITNESS_BEARER_TOKEN_HASH`, `REGISTRY_WITNESS_ISSUER_JWK`. The
    renamed auth variables hold `sha256:<64 hex>` fingerprints, not plaintext
    tokens.
  - Demo config: `demo/config/evidence-server.yaml` → `demo/config/registry-witness.yaml`.

## 0.1.0

- Initial Evidence Server repository cut from `registry_relay`.
- Preserves `evidence-core` and `evidence-server` crate behavior as an
  independent Cargo workspace.
- Adds `evidence-server-bin` for standalone config loading, binding, tracing,
  shutdown, fail-closed API key and bearer-token auth, and redacted audit event
  output.
- Adds HTTP Registry Data API and DCI source connectors so claim evaluation can
  use external source registries without linking Registry Relay.
- Keeps CEL enabled by default through `cel-mapper-core`, pinned to
  `PublicSchema/cel-mapping` tag `cel-mapper-core-v0.1.0`.
- Adds a `cargo run -p evidence-server-bin -- openapi` command for owned
  Evidence Server OpenAPI output.

Known non-goals for this cut:

- Registry Relay cleanup and removal of embedded Evidence Server routes are
  owned by the Relay cleanup worker.
- OIDC/JWKS discovery is follow-up; the standalone binary supports API keys and
  static bearer tokens.
