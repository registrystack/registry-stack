# Changelog

## Unreleased

- BREAKING: `registry-platform-ops` replaces deployment-waiver `reason` with
  required `reference` plus optional omitted `summary` in the shared posture
  contract. It now owns the common 128-byte reference and 256-character summary
  validation authority used by Relay and Notary. The default posture allowlist
  continues to exclude all waiver metadata.

## v0.12.0 - 2026-07-19

### Added

- `registry-platform-ops` now carries the restricted per-resource Relay
  refresh-health posture contract and a matching reference fixture.
- `CredentialFingerprintProvider`, `KeyProviderKind`, and `KeyStatus` expose
  declaration-ordered `ALL` rosters so config-schema generation consumes the
  same closed labels as runtime parsing and diagnostics.

## v0.11.0 - 2026-07-18

- BREAKING: shared configuration `${VAR}` expansion now rejects environment
  variables that are unset or empty. `${VAR:-fallback}` uses its fallback for
  either state, `${VAR:-}` explicitly expands to empty, and `${VAR:?message}`
  reports its message for either state. Whitespace-only values remain non-empty.

## v0.10.0 - 2026-07-17

### Added

- `registry-platform-canonical-json` is the single shared RFC 8785 JSON
  Canonicalization Scheme implementation for Registry Stack hashes,
  signatures, JWK thumbprints, manifests, policies, and generated artifacts.
- `registry-platform-httputil` now provides the fixed-destination transport,
  closed JSON response decoding, signed DCI verification, bounded OAuth
  client-credentials flow, and typed Relay client primitives used by governed
  consultations.
- `registry-platform-audit` now provides typed durable-operation and governed
  pseudonym-keyring contracts for product-owned PostgreSQL state planes.

### Changed

- BREAKING: `registry-platform-ops` Notary posture now reports the global
  `notary.state` backend and uses `postgresql`, `in_memory`, and `state`
  vocabulary. The retired per-domain Redis replay and credential-status
  values are removed from the schema, examples, redaction fixtures, and
  allowlist.
- `registry-platform-cache` and `registry-platform-replay` retain only bounded
  in-memory implementations for focused tests and explicit single-process
  local development. Product runtimes own typed durable correctness state.

### Security

- Raw signed, hashed, or structurally interpreted JSON now uses the shared
  strict parser. Duplicate object members and integer tokens that are not
  exactly representable as IEEE 754 binary64 are rejected before
  interpretation instead of being silently overwritten or rounded.
- Public JWK and `did:jwk` parsing is bounded to 64 KiB, rejects duplicate
  members, and rejects symmetric or asymmetric private members. Non-secret
  extension metadata remains accepted, so implementers do not need to strip
  ordinary provider metadata from public keys.

## v0.9.0 - 2026-07-10

### Added

- Registry Config Bundle v1 is the shared offline configuration contract for
  Relay and Notary. The CLI `config apply-bundle` command and live HTTP apply
  surfaces are removed. First use `registryctl bundle verify` for stateless
  signature and binding verification, then place the signed bundle on the
  node. For a genuinely absent, version-specific antirollback state path,
  start the product server with `--initialize-state`; that boot verifies the
  bundle and initializes state. The product's read-only
  `config verify-bundle` command remains, but it requires accepted state to
  exist, so use it only for later candidate validation and restarts. Replace
  retired TUF-era fields inside `config_trust` with the
  current Config Bundle v1 trust fields because strict parsing rejects the old
  schema. Acceptance uses the durable
  `config_trust.antirollback_state_path`. Missing state fails closed except
  during that intentional first boot; a lower sequence or a different bundle
  at the accepted sequence is rejected as non-monotonic.
- `registry-platform-audit`: `JsonlFileSink::with_rotation_single_writer`, a
  constructor that takes a process-lifetime advisory lock on `<path>.lock`
  (refusing to start if another process holds it) and verifies the on-disk
  tail before each append, failing with `ChainForkDetected` instead of
  extending a diverged chain. Registry Relay and Registry Notary file sinks
  use it; `new` and `with_rotation` are unchanged.
- `registry-platform-audit`: `quarantine_and_recover_chain`, the offline
  recovery primitive behind `registry-relay audit quarantine` (#196). It
  archives the corrupt file set to `<name>.corrupt-<ts>`, starts a fresh
  chain whose first record is a hash-linked `audit.chain.break` event chained
  onto the last verifiable tail (torn trailing lines from an unclean stop are
  treated as a break, not an abort), and leaves off-host shipping as the
  completeness guarantee. Recovery also quarantines a legacy
  `<active-path>.anchor.json` sidecar left behind by pre-removal releases,
  renaming it with the same `.corrupt-<timestamp>` suffix as the quarantined
  data files.
- `registry-platform-ops`: `AuditSinkKind` and `audit_shipping_target(sink,
  offhost_shipping_declared)`, a shared classifier that maps a sink kind and
  the `deployment.evidence.audit_offhost_shipping` attestation onto the
  posture/doctor shipping-state fields (`shipping_target_configured`,
  `shipping_target`), so Registry Relay and Registry Notary cannot drift on
  the classification.
- `registry-platform-ops`: `registry.audit.ack_cursor.v1`, the JSON Schema
  contract for the local state file written by whatever ships audit events
  off-host (`acked_at`, `last_acked_hash`, optional `writer`), plus
  `evaluate_ack_health(cursor_path, now, max_age)`, a shared helper that reads
  the cursor and classifies it as `stale`, `missing`, `invalid`, or
  `unverified`; a fresh cursor becomes `ok` only after
  `AckObservation::bind_to_audit_tail` confirms that `last_acked_hash` equals
  the runtime's current keyed audit-chain tail. The default freshness window is
  `DEFAULT_AUDIT_ACK_MAX_AGE` (900s); a cursor whose `acked_at` is more than
  300s ahead of `now` is treated as `invalid` rather than perpetually fresh.
  An unreadable file, malformed JSON, a contract violation, or a
  non-RFC3339 `acked_at` all fail closed to `invalid` with a `detail` message,
  never silently to `ok`. Reads are capped at 16 KiB and reject non-regular
  files and symlinks, which prevents FIFO reads and allocation from an unbounded
  file. Relay and Notary add a 500 ms bounded worker around this synchronous
  helper in public runtime handlers. Tail equality proves the trusted shipper's
  claimed watermark belongs to the live chain and that the local backlog is
  zero. Because the cursor is unsigned local state, it is still not
  cryptographic proof of remote receipt.

### Changed

- Operators must back up antirollback state before an upgrade and keep
  release-specific bundle and state restore sets. A rollback restores the
  antirollback state belonging to that release. Deleting or reinitializing
  state to force an older bundle to load breaks the antirollback guarantee and
  is not a supported recovery procedure.
- Parked `registry-platform-sts` outside the active workspace until Assisted
  Access or delegation-profile work promotes a release-surface consumer (#298).
  The source remains in git, but the crate is no longer built as part of
  workspace CI or listed as a load-bearing platform crate. Its standalone fuzz
  target and Lab commons-check caller are parked with it, and NP-23 denial-audit
  parity is deferred until a named consumer reactivates the crate (#246; revisit
  tracked by #298).
- `registry-platform-audit`'s `JsonlFileSink::new` default rotation retention
  is raised from 5 files to 50 files (~500 MiB at the 10 MiB default file
  size), so the crate default no longer silently discards audit history after
  ~50 MiB. Consumers that pass explicit rotation settings via
  `JsonlFileSink::with_rotation` (Registry Relay and Registry Notary both
  configure 100 MB x 14 files) are unaffected. The safer default remains for
  future standalone consumers when a release-surface consumer is promoted.
- `registry-platform-audit` chain verification now treats the first retained
  record's `prev_hash` as the retained-set boundary. **Removed the local
  trusted-anchor verification API**: `ChainVerificationAnchors`,
  `verify_chain_with_anchors`, `verify_jsonl_lines_with_anchors`, and the
  `LastHashMismatch` error variant are gone, and the `.anchor.json`
  completeness-anchor sidecar is no longer written or read. Consumers verify
  retained-set internal consistency with `verify_chain`; completeness comes
  from off-host shipping evidence
  (`deployment.evidence.audit_offhost_shipping`), not a local anchor. Local
  verification detects edits, insertions, reordering, and interior deletions
  within the retained set only; leading or trailing truncation and a
  self-consistent full rewrite of the retained set are not locally
  detectable.
- `registry-platform-ops`'s `registry.ops.posture.v1` schema:
  `posture.audit` gains two required fields, `shipping_target_configured`
  (bool) and `shipping_target` (one of `stdout`, `syslog`,
  `declared_external`, `none`, `unknown`), reporting the sink type and the
  off-host shipping attestation. These are declared, config-derived state;
  the separate fields described next report observed delivery health. The schema is
  `additionalProperties: false` and keeps the `v1` identifier, so posture
  documents produced before this release fail against the new schema and
  vice versa: producers and strict validators pinned to
  `registry.ops.posture.v1` must upgrade together.
- BREAKING: `registry-platform-ops`'s `registry.ops.posture.v1` schema:
  `posture.audit` gains two more required, nullable fields, `shipping_health`
  (one of `ok`, `stale`, `missing`, `invalid`, `unverified`, or `null`) and
  `shipping_observed_at` (an RFC3339 timestamp, or `null`), reporting the
  observed freshness of off-host audit shipping from the ack cursor described
  above under Added. `shipping_health` is `null` iff
  `shipping_target_configured` is `false`; `shipping_observed_at` is `null`
  when no contract-valid cursor timestamp was read. `shipping_health` is
  `"unverified"` when a shipping target is
  declared but no cursor is configured or an offline caller cannot bind it to a
  live chain. `ok` requires a fresh cursor whose watermark equals the live
  keyed chain tail. This fills the delivery-health gap without claiming the
  unsigned local cursor cryptographically proves remote receipt. The schema keeps the `v1`
  identifier and `additionalProperties: false`, so this is the second breaking
  change to `posture.audit` under the `v1` identifier in this release:
  producers and strict validators pinned to `registry.ops.posture.v1` must
  upgrade together, and a validator built against the previous field set
  rejects documents carrying the new fields.
- BREAKING: `AckObservation` gains the public `last_acked_hash` field and the
  `unverified` and `invalid` constructors. Rebinding an `ok` observation now
  rechecks the supplied live tail and fails closed if the tail changed.
  Product gate inputs rename `audit_shipping_declared_external` to
  `audit_shipping_target_configured` in Notary `GateInput` and Relay
  `DeploymentFacts`, because stdout and syslog now require observed shipping
  health under `evidence_grade` too.
- `registry-config-report`'s `registry.config.diagnostic_report.v1` schema:
  the `audit_shipping` block gains optional `shipping_health` and
  `shipping_observed_at` fields with the same semantics as the posture fields
  above. Optional, so existing diagnostic report consumers are unaffected.
- `registry-config-report`'s `registryctl.validation.report.v1` schema now
  preserves the optional product `audit_shipping` block in aggregated doctor
  output, so valid Relay and Notary reports continue to validate after
  registryctl combines them.

### Fixed

- The named Relay and Notary `registry.ops.posture.v1` examples now match the
  live product projections and no longer claim checkpoint hashes or successful
  verification that those endpoints do not emit.

## v0.3.1 - 2026-06-21

### Security

- (AUDIT-03) `registry-platform-audit` now derives independent, domain-separated
  sub-keys for the audit chain HMAC and the identifier HMAC from the master
  environment secret using an internal HKDF-Expand (RFC 5869) over SHA-256, with
  distinct per-purpose `info` labels (`registry-platform-audit/chain-key/v1` and
  `registry-platform-audit/identifier-key/v1`). Previously both HMACs used the
  identical raw env material, so a leak of one key exposed the other. **This
  changes persisted chain and identifier hash values**; acceptable pre-beta
  (crate is `version 0.3.1`, `publish = false`) and only affects legacy
  pre-beta logs, which were already unkeyed/dev-only. Explicit `keyed(secret)`
  construction is unchanged (caller-owned key material).
- (AUDIT-02) `AuditHashSecret` now holds its HMAC key behind a
  `Zeroize`/`ZeroizeOnDrop` newtype so the raw key bytes are scrubbed when the
  last shared reference is dropped.
- (AUDIT-05) The query-redaction secret-parameter denylist now covers OAuth /
  OIDC and generic credential parameter names (`access_token`, `refresh_token`,
  `id_token`, `client_secret`, `client_assertion`, `assertion`, `bearer`,
  `code`, `private_key`, `credential`, `credentials`, `passwd`, `pwd`,
  `session_token`).
- (AUDIT-01 / AUDIT-06) The unkeyed verification and tail-hash convenience paths
  (`verify_jsonl_lines`, `AuditSink::tail_hash`) are now `#[deprecated]` and
  carry prominent warnings; production callers must use the keyed
  `*_with_hasher` variants with an explicit `AuditChainHasher`.
  `AuditSink::tail_hash_with_hasher` now fails closed by default so legacy custom
  tailable sinks cannot silently ignore the supplied keyed hasher through an
  unkeyed trait fallback.
- (REPORT-01) `registry-config-report` now exposes `ConfigExplanation::resolved_config`
  as a `RedactedConfig` newtype that can only be constructed via
  `RedactedConfig::redacted(..)` (which runs redaction internally), making
  redaction unbypassable at the type level for producers. Deserializing
  `RedactedConfig` now treats the input as untrusted and collapses it to
  `REDACTED_VALUE`; consumers that need to inspect rendered report JSON can use
  the wire-only `ConfigExplanationDocument` type. The wire format is unchanged
  (`#[serde(transparent)]`).
- (REPORT-03) `RequiredEnvVar` is documented as operator-sensitive (it enumerates
  secret env-var names and presence) and now offers `RequiredEnvVar::public_safe()`,
  a compatibility projection that collapses non-public entries to a generic
  not-checked placeholder. `RequiredEnvVar::public_safe_entries(..)` omits
  non-public entries entirely for public-facing lists so names, presence, and
  sensitive-entry counts are not disclosed.
- (OIDC-01) `registry-platform-oidc` `fetch_discovery_with_policy` now fails closed
  with `OidcError::MissingIssuer` when `jwks_uri_override` is set but `issuer` is
  empty, preserving an issuer binding when discovery is skipped.
- (HTTPSEC-01) `registry-platform-httpsec` `security_headers` now emits
  `Strict-Transport-Security` (`max-age=63072000; includeSubDomains`) by default,
  with `SecurityHeadersLayer::without_hsts()` / `with_hsts(..)` opt-outs.
- (HTTPSEC-02) `CorsPolicy::layer()` (which panics on an invalid policy) is now
  `#[deprecated]` in favor of the fallible `CorsPolicy::try_layer()`.

## v0.3.0 — 2026-06-13

### Added

- Posture profile gate vocabulary in `registry-platform-ops` (#55, PR #58): shared
  `DeploymentProfile`, `GateSeverity`, `DeploymentFinding`, `DeploymentWaiver`,
  `DeploymentFindingWaiver`, and `AuditAssurance` types plus the
  `registry.ops.posture.v1` finding and waiver shapes consumed by the Notary and
  Relay deployment-profile gates.
- Parser fuzz regression jobs (#51, PR #57): CI fuzz coverage for platform parsers.
- Emergency posture schema (#61, PR #62): adds the six `configuration.emergency`
  posture leaves to the default-tier allowlist and break-glass approval metadata
  shapes; contract tests pin schema validation, default-tier filtering, the
  change-class grammar, and the no-reason / no-approver-identity rule.
- STS bridge in `registry-platform` (PR #64): security-token-service bridge that
  backs Assisted Access token exchange.

## v0.2.1 — 2026-06-12

### Fixed

- (Issue #50) `authcommon::parse_bearer_token` now byte-compares the `Bearer `
  scheme prefix before calling `split_at(6)`, preventing a panic when a
  multibyte UTF-8 character straddles the scheme boundary.

## v0.2.0

### Security

- (F-P3-1) `crypto::sign` now wraps the decoded Ed25519 seed in
  `Zeroizing<[u8; 32]>` so key material is zeroed on drop.
- (F-P2-1) `AuditHashSecret` `Debug` impl confirmed to emit `<redacted>`,
  never the raw bytes; regression test added.
- (F-P2-2) `SdJwtIssuer` `Debug` impl confirmed to redact the private
  scalar; regression test added.
- (F-P6-1) `OidcDiscoveryConfig::jwks_uri_override` now carries a doc
  comment warning that setting it bypasses issuer-to-key-endpoint binding.

### Changed

- (Issue #10) Added provider-backed EdDSA signing via
  `SigningProvider`/`LocalJwkSigner`; SD-JWT issuance is now async and uses the
  provider `kid` as the JWT header source of truth.
- Added `registry-platform-ops` with the public
  `registry.ops.posture.v1` JSON Schema, Relay and Notary examples, shared
  finding/artifact/audit summary shapes, and sensitivity-tier redaction
  fixtures. Runtime services currently emit default posture; restricted posture
  is a contract tier for future/admin-gated surfaces, not runtime-emitted yet.
- (F-oid4vci-1) Remove `pub const PKCE_METHOD_S256`. Callers use the
  literal `"S256"`; the constant added no value and implied ownership of
  the PKCE method name.

### Fixed

- (F-P10-1) `getrandom = "0.4"` hoisted from `sdjwt/Cargo.toml` into
  `[workspace.dependencies]`; all consumers now share one pin.
- (F-testing-1) Sibling path-dep versions aligned to `"0.1.2"` across
  `testing`, `sdjwt`, `oid4vci`, and `oidc` `Cargo.toml` files
  (previously pinned at stale `"0.1.0"`).
- (F-crypto-2) `jsonwebtoken` removed from `crypto/Cargo.toml`; it was
  never referenced in source.

### Tests

- (F-P4-1) Integration test proves `RequestBodyLimitLayer` rejects a
  body 1 byte over 1 MiB with 413, and `body_limit_problem_response`
  returns the full RFC 7807 shape.
- (F-httpsec-2) Integration test asserts non-allowlisted Origin does not
  receive `Access-Control-Allow-Origin`.
- (F-httpsec-3) Unit test for `Problem` JSON serialisation shape
  (`type`/`title`/`status`/`detail`); cross-crate integration test
  extended with same assertions.
- (F-crypto-3) Unit tests for all three `DidError` variants: missing
  prefix, method not allowed, unsupported method.
- (F-sdjwt-2) `validate_holder_proof` rejects structurally malformed
  compact JWTs (no dots, two segments, four segments, invalid
  base64url characters).
- (F-oid4vci-2) Test confirms `validate_proof_jwt` does not track nonce
  reuse across calls (caller responsibility documented).
- (F-oid4vci-3) Serialisation round-trip tests for
  `CredentialConfigurationMetadata` (SD-JWT VC) and `CredentialOffer`
  (authorization_code flow).
- (F-P8-1) `#[ignore]` micro-benchmarks added for EdDSA sign and verify;
  doc comments cite measured µs/op on M5 Max (release mode).
- Focused posture contract tests validate the Relay and Notary examples, reject
  malformed posture documents including missing `posture.audit` and invalid
  artifact SHA-256 references, and prove the default redaction fixture omits
  secrets, subject ids, raw rows, claim values, SD-JWT disclosures, token hashes,
  private key material, private source URLs, and restricted topology while the
  restricted fixture may include restricted-only contract fields.

### Docs

- (F-oid4vci-4) `crates/registry-platform-oid4vci/README.md` created.
- (F-testing-2) `crates/registry-platform-testing/README.md` rewritten
  to document all public items.
- Added pre-release review report at `docs/release-review-0.1.2.md`.
- `docs/SECURITY_PRINCIPLES.md` §9 clarified: platform crates surface
  outcomes as `Result` types; consumer applications own audit wiring.
- `README.md`: toolchain pins and `cargo-deny` install hint added.

## v0.1.2

- Hardened OIDC verifier policy against mixed symmetric/asymmetric algorithm
  allowlists, JWK/header algorithm mismatches, and multi-audience ID-token
  `azp` gaps.
- Tightened OID4VCI proof validation, SD-JWT holder-proof headers, and JWK
  thumbprint construction.
- Added OpenID4VCI metadata primitives consumed by Registry Notary.

## v0.1.1

- Hardened shared security primitives for registry consumers, including
  outbound fetch validation, auth helpers, audit handling, and credential key
  utilities.

## v0.1.0

- Initial registry-platform workspace with eight crates: audit, authcommon,
  crypto, httpsec, httputil, oidc, sdjwt, and testing.
- Adds fail-closed Bearer/API-key parsing, outbound SSRF policy, bounded body
  reads, OIDC discovery/JWKS/token verification, tamper-evident audit chaining,
  RFC 7807 Problem Details, HTTP security middleware, Ed25519 JWK helpers,
  SD-JWT issuance/holder-proof validation, and shared test fixtures.
- Supports EdDSA/Ed25519 for platform-owned signing and verification in
  v0.1.0. Other JWK algorithms are rejected as unsupported until a consumer
  requires them.
- Ships canonical `clippy.toml`, `rustfmt.toml`, `deny.toml`, hygiene checks,
  versioning docs, and security principles for consumer alignment.
