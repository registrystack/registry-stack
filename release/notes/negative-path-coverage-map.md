# Negative-Path Coverage Map

Issue: [#200](https://github.com/registrystack/registry-stack/issues/200)

Generated: 2026-07-09

This is the public release-readiness map for negative-path coverage. It maps
the internal checklist row identifiers to public evidence or disposition without
copying adversarial scenario detail into the public repository.

The source checklist remains in the private internal repository. Public rows
below intentionally name only the stable checklist ID, coverage state, and
public evidence or disposition.

## Coverage Terms

- `Covered`: current tests exercise the denial path and expected side effects.
- `Partial`: current tests cover part of the row, but more route, audit, or
  product-surface coverage is needed before release sign-off.
- `Gap`: the row still needs a linked test PR or maintainer-approved deferral.

## Map

- `NP-01`: Partial.
  Public anchors: `crates/registry-platform-oidc/src/provider.rs`,
  `crates/registry-platform-crypto/src/lib.rs`, and
  `crates/registry-platform-sdjwt/src/lib.rs`.
  Disposition: keep open for release sign-off until product-surface coverage is
  complete.
- `NP-02`: Partial.
  Public anchors: `crates/registry-platform-oidc/src/provider.rs`,
  `crates/registry-platform-sts/src/lib.rs`, and
  `crates/registry-notary-server/src/api.rs`.
  Disposition: keep open for release sign-off until audit assertions are
  complete across affected surfaces.
- `NP-03`: Partial.
  Public anchors: `crates/registry-platform-oidc/src/provider.rs`,
  `crates/registry-platform-sdjwt/src/lib.rs`, and
  `crates/registry-notary-server/src/api.rs`.
  Disposition: keep open for route-level denial and audit parity.
- `NP-04`: Partial.
  Public anchor: `crates/registry-platform-oidc/src/provider.rs`.
  Disposition: keep open for product-surface assertions.
- `NP-05`: Partial.
  Public anchors: `crates/registry-relay/tests/dataset_routes.rs`,
  `crates/registry-relay/tests/entity_routes.rs`, and
  `crates/registry-relay/tests/observability_metrics.rs`.
  Disposition: keep open for complete audit assertion parity.
- `NP-06`: Partial.
  Public anchors: `crates/registry-platform-pdp/src/lib.rs` and
  `crates/registry-relay/tests/entity_routes.rs`.
  Disposition: adapter-level coverage remains to be closed or deferred.
- `NP-07`: Covered.
  Public anchor: `crates/registry-relay/tests/error_taxonomy.rs`.
  Disposition: no new release work identified from the current map.
- `NP-08`: Partial.
  Public anchors:
  `crates/registry-relay/tests/entity_routes.rs::governed_entity_policy_ignores_unverified_trust_provenance_without_leak`
  and
  `crates/registry-relay/tests/entity_routes.rs::governed_entity_policy_ignores_unverified_source_freshness_header_without_leak`.
  Disposition: this branch adds denial and audit non-disclosure coverage for the
  Relay governed-entity trust-provenance and freshness paths; keep open for any
  remaining route parity.
- `NP-09`: Partial.
  Public anchors: `crates/registry-relay/tests/spdci_api_standards.rs` and
  `crates/registry-relay/tests/error_taxonomy.rs`.
  Disposition: keep open for complete side-effect assertions.
- `NP-10`: Partial.
  Public anchor: `crates/registry-notary-server/src/server.rs`.
  Disposition: Notary parity coverage remains to be added or explicitly
  deferred.
- `NP-11`: Partial.
  Public anchor: `crates/registry-notary-server/src/connector/mod.rs`.
  Disposition: keep open for product-surface denial and audit assertions.
- `NP-12`: Partial.
  Public anchor: `crates/registry-notary-server/tests/metadata_core.rs`.
  Disposition: keep open for route-level parity.
- `NP-13`: Partial.
  Public anchors: `crates/registry-notary-server/tests/deployment_profile_gates.rs`,
  `crates/registry-notary-server/tests/admin_reload.rs`,
  `crates/registry-notary-server/tests/standalone.rs`,
  `crates/registry-notary-server/tests/standalone_http.rs`, and
  `crates/registry-notary-server/src/api.rs`.
  Disposition: product paths have coverage; STS audit-abort parity remains to
  be closed or deferred.
- `NP-14`: Partial.
  Public anchors: `crates/registry-notary-server/tests/admin_auth_extraction_contract.rs`
  and `crates/registry-notary-server/tests/observability_metrics.rs`.
  Disposition: keep open for full audit parity.
- `NP-15`: Covered.
  Public anchors: `crates/registry-notary-server/src/server.rs` and
  `crates/registry-notary-server/tests/e2e_health.rs`.
  Disposition: no new release work identified from the current map.
- `NP-16`: Gap.
  Public anchor: internal checklist only.
  Disposition: deferred to a maintainer-owned follow-up bundle; public scenario
  detail remains intentionally omitted.
- `NP-17`: Gap.
  Public anchor: internal checklist only.
  Disposition: deferred to a maintainer-owned follow-up bundle; public scenario
  detail remains intentionally omitted.
- `NP-18`: Gap.
  Public anchor: internal checklist only.
  Disposition: deferred to a maintainer-owned follow-up bundle; public scenario
  detail remains intentionally omitted.
- `NP-19`: Partial.
  Public anchor: `crates/registry-notary-server/src/api.rs`.
  Disposition: keep open for complete side-effect assertions.
- `NP-20`: Partial.
  Public anchor: `crates/registry-platform-sdjwt/src/lib.rs`.
  Disposition: product audit coverage remains to be closed or deferred.
- `NP-21`: Covered.
  Public anchors: `crates/registry-notary-server/src/api.rs` and
  `crates/registry-platform-sdjwt/src/lib.rs`.
  Disposition: no new release work identified from the current map.
- `NP-22`: Partial.
  Public anchor: `crates/registry-notary-server/tests/standalone.rs`.
  Disposition: keep open for product-surface parity.
- `NP-23`: Partial.
  Public anchor: `crates/registry-platform-sts/src/lib.rs`.
  Disposition: focused route and audit coverage remains to be added or deferred.
- `NP-24`: Partial.
  Public anchor: `crates/registry-notary-server/tests/standalone.rs`.
  Disposition: Notary behavior is covered; Relay handling is a deliberate
  product decision that needs explicit release sign-off.
- `NP-25`: Gap.
  Public anchor: internal checklist only.
  Disposition: current behavior contradicts the target release posture; release
  closure requires a behavior decision plus tests or an explicit deferral.
- `NP-26`: Partial.
  Public anchors: `crates/registry-notary-server/src/config.rs`,
  `crates/registry-notary-server/src/deployment.rs`, and
  `crates/registry-notary-server/tests/standalone.rs`.
  Disposition: verify against the post-#314 signed-bundle surface before
  release sign-off.
- `NP-27`: Partial.
  Public anchors: `crates/registry-notary-server/src/runtime.rs` and
  `crates/registry-notary-server/src/api.rs`.
  Disposition: keep open for complete route and audit parity.
- `NP-28`: Partial.
  Public anchors: `crates/registry-notary-server/src/api.rs` and
  `crates/registry-notary-server/src/runtime.rs`.
  Disposition: focused denial coverage remains to be added or deferred.
- `NP-29`: Partial.
  Public anchors: `crates/registry-notary-server/tests/standalone_http.rs` and
  `crates/registry-relay/src/federation/mod.rs`.
  Disposition: keep open for complete product-surface parity.

## Release Decision

This map records the current state; it does not close every release gap. Before
checking the release-readiness item, each row marked `Partial` or `Gap` must
have either a linked test PR that asserts denial plus audit-record correctness,
or a maintainer-approved deferral with rationale.
