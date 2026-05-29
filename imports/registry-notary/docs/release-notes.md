# Release Notes

## 0.3.0

- Added citizen self-attestation flows, including bearer-token subject binding,
  rate limiting, denial audit metadata, and SD-JWT VC issuance.
- Added OpenID4VCI issuer primitives and HTTP routes for credential issuer
  metadata, credential offers, nonce creation, and credential issuance.
- Added the OpenFn sidecar source for isolated worker execution.
- Hardened SD-JWT VC conformance for `dc+sd-jwt`, holder binding, proof
  validation, and OpenAPI documentation.
- Replaced fake Problem Details type URLs with
  `https://docs.registry-notary.dev/problems/...`.
- Changed self-attestation subject-binding hashes to keyed HMAC values and
  stopped recording raw query strings in request spans or audit paths.
- Known limitations: this release is `dc+sd-jwt` only, does not serve
  `/.well-known/jwt-vc-issuer`, does not provide credential revocation/status,
  and leaves retention/erasure workflows to the operator.

## 0.2.1

- Added `evidence.source_connections[].allow_insecure_private_network` for
  Docker Compose and private-network demos that need HTTP source registries.
  The escape hatch is opt-in, keeps cloud metadata endpoints blocked, and
  leaves the strict HTTPS policy as the default.

## 0.2.0 (rename)

- Renamed: `evidence-server` → `registry-notary`. No backward compatibility; no aliases.
  - Crates: `evidence-core` → `registry-notary-core`, `evidence-server` → `registry-notary-server`,
    `evidence-server-bin` → `registry-notary-bin`.
  - Binary: `evidence-server` → `registry-notary`.
  - Media type: `application/vnd.evidence-server.claim-result+json` → `application/vnd.registry-notary.claim-result+json`.
  - Default audience: `"evidence-server"` → `"registry-notary"`.
  - Cargo feature: `evidence-server-cel` → `registry-notary-cel`.
  - Project-labeled env vars: `EVIDENCE_SERVER_API_KEY`, `EVIDENCE_SERVER_BEARER_TOKEN`,
    `EVIDENCE_SERVER_ISSUER_JWK` → `REGISTRY_NOTARY_API_KEY_HASH`,
    `REGISTRY_NOTARY_BEARER_TOKEN_HASH`, `REGISTRY_NOTARY_ISSUER_JWK`. The
    renamed auth variables hold `sha256:<64 hex>` fingerprints, not plaintext
    tokens.
  - Demo config: `demo/config/evidence-server.yaml` → `demo/config/registry-notary.yaml`.

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
