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
  Public anchors: `crates/registry-relay/src/auth/oidc/provider.rs`,
  `crates/registry-notary-server/tests/sd_jwt_vc_verifier_compat.rs`,
  `crates/registry-platform-crypto/src/lib.rs`, and
  `crates/registry-platform-sdjwt/src/lib.rs`.
  Disposition: keep open for complete product-surface audit parity.
- `NP-02`: Partial.
  Public anchors: `crates/registry-relay/src/auth/oidc/provider.rs`,
  `crates/registry-notary-server/src/api.rs`, and
  `crates/registry-platform-sts/src/lib.rs`.
  Disposition: keep open for remaining STS and audit assertions.
- `NP-03`: Partial.
  Public anchors: `crates/registry-relay/src/auth/oidc/provider.rs`,
  `crates/registry-platform-sdjwt/src/lib.rs`, and
  `crates/registry-notary-server/src/api.rs`.
  Disposition: keep open for route-level denial and audit parity.
- `NP-04`: Partial.
  Public anchors: `crates/registry-relay/src/auth/oidc/provider.rs` and
  `crates/registry-platform-oidc/src/lib.rs`.
  Disposition: keep open for product-surface response and audit assertions.
- `NP-05`: Partial.
  Public anchors: `crates/registry-relay/tests/dataset_routes.rs`,
  `crates/registry-relay/tests/entity_routes.rs`, and
  `crates/registry-relay/tests/observability_metrics.rs`.
  Disposition: keep open for full cross-route audit parity.
- `NP-06`: Partial.
  Public anchors: `crates/registry-platform-pdp/src/lib.rs` and
  `crates/registry-relay/tests/entity_routes.rs`.
  Disposition: adapter-level coverage remains to be closed or deferred.
- `NP-07`: Covered.
  Public anchor: `crates/registry-relay/tests/error_taxonomy.rs`.
  Disposition: no new release work identified from the current map.
- `NP-08`: Partial.
  Public anchors:
  `crates/registry-relay/tests/entity_routes.rs::governed_entity_policy_ignores_unverified_trust_provenance_without_leak`,
  `crates/registry-relay/tests/entity_routes.rs::governed_entity_policy_ignores_unverified_source_freshness_header_without_leak`,
  and `crates/registry-relay/src/api/governed.rs`.
  Disposition: keep open for remaining governed-route parity.
- `NP-09`: Partial.
  Public anchors: `crates/registry-relay/tests/spdci_api_standards.rs` and
  `crates/registry-relay/tests/error_taxonomy.rs`.
  Disposition: keep open for complete raw-value and side-effect assertions.
- `NP-10`: Covered.
  Public anchors: `crates/registry-relay/src/server.rs` and
  `crates/registry-notary-server/tests/standalone_http.rs`.
  Disposition: Relay asserts denial plus audit for this middleware path; Notary
  asserts stable early-boundary problem responses, server-owned request ids, and
  non-disclosure where the audited route layer has not run.
- `NP-11`: Partial.
  Public anchor: `crates/registry-relay/src/connector/mod.rs`.
  Disposition: config-load denial is covered; product-surface diagnostic and
  audit expectations remain to be signed off.
- `NP-12`: Partial.
  Public anchor: `crates/registry-manifest-core/tests/metadata_core.rs`.
  Disposition: validation-limit coverage exists; runtime load and serving-state
  side effects remain to be closed or deferred.
- `NP-13`: Partial.
  Public anchors: `crates/registry-relay/tests/deployment_profile_gates.rs`,
  `crates/registry-relay/src/api/admin.rs`,
  `crates/registry-notary-server/src/standalone.rs`,
  `crates/registry-notary-server/tests/standalone_http.rs`, and
  `crates/registry-notary-server/src/api.rs`.
  Disposition: product paths have coverage; STS audit-abort parity remains to
  be closed or deferred.
- `NP-14`: Partial.
  Public anchors: `crates/registry-relay/tests/admin_auth_extraction_contract.rs`
  and `crates/registry-relay/tests/observability_metrics.rs`.
  Disposition: keep open for broad admin-route and audit parity.
- `NP-15`: Covered.
  Public anchors: `crates/registry-relay/src/server.rs` and
  `crates/registry-relay/tests/e2e_health.rs`.
  Disposition: no new release work identified from the current map.
- `NP-16`: Gap.
  Public anchor: internal checklist only.
  Disposition: deferred to the maintainer-owned minimization follow-up bundle;
  public scenario detail remains intentionally omitted.
- `NP-17`: Gap.
  Public anchor: internal checklist only.
  Disposition: deferred to the maintainer-owned minimization follow-up bundle;
  public scenario detail remains intentionally omitted.
- `NP-18`: Gap.
  Public anchor: internal checklist only.
  Disposition: deferred to the maintainer-owned minimization follow-up bundle;
  public scenario detail remains intentionally omitted.
- `NP-19`: Partial.
  Public anchor: `crates/registry-notary-server/src/api.rs`.
  Disposition: keep open for complete side-effect and audit assertions.
- `NP-20`: Partial.
  Public anchor: `crates/registry-platform-sdjwt/src/lib.rs`.
  Disposition: product-level audit coverage remains to be closed or deferred.
- `NP-21`: Covered.
  Public anchors: `crates/registry-notary-server/src/api.rs` and
  `crates/registry-platform-sdjwt/src/lib.rs`.
  Disposition: no new release work identified from the current map.
- `NP-22`: Partial.
  Public anchor: `crates/registry-notary-server/src/standalone.rs`.
  Disposition: keep open for product-surface HTTP audit and no-response parity.
- `NP-23`: Partial.
  Public anchor: `crates/registry-platform-sts/src/lib.rs`.
  Disposition: focused route, no-mint, and audit coverage remains to be added
  or deferred.
- `NP-24`: Partial.
  Public anchor: `crates/registry-notary-server/src/standalone.rs`.
  Disposition: Notary behavior is covered; Relay handling is a deliberate
  product difference that needs explicit release sign-off.
- `NP-25`: Covered.
  Public anchors: `crates/registry-notary-core/src/deployment.rs` and
  `crates/registry-notary-server/tests/deployment_gates_test.rs`.
  Disposition: current Notary startup gates require an explicit deployment
  profile, keep `local` as the development opt-out, and reject unknown profile
  values.
- `NP-26`: Partial.
  Public anchors: `crates/registry-notary-core/src/config.rs`,
  `crates/registry-notary-core/src/deployment.rs`,
  `crates/registry-notary-server/src/standalone.rs`, and
  `crates/registry-notary-server/tests/standalone_http.rs`.
  Disposition: verify against the post-#314 signed-bundle surface before
  release sign-off.
- `NP-27`: Partial.
  Public anchors: `crates/registry-notary-server/src/runtime.rs` and
  `crates/registry-notary-server/src/api.rs`.
  Disposition: keep open for focused route, no-source-read, and audit parity.
- `NP-28`: Partial.
  Public anchors: `crates/registry-notary-server/src/api.rs` and
  `crates/registry-notary-server/src/runtime.rs`.
  Disposition: focused denial and audit coverage remains to be added or
  deferred.
- `NP-29`: Partial.
  Public anchors: `crates/registry-notary-server/tests/standalone_http.rs` and
  `crates/registry-notary-server/src/federation/mod.rs`.
  Disposition: keep open for complete product-surface parity.

## Release Decision

This map records the current state; it does not close every release gap. Before
checking the release-readiness item, each row marked `Partial` or `Gap` must
have either a linked test PR that asserts denial plus audit-record correctness,
or a maintainer-approved deferral with rationale.
