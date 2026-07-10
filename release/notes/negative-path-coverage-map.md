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
  and `crates/registry-notary-server/src/api.rs`.
  Disposition: keep open for remaining active product-surface audit assertions.
  The parked STS source is outside the release surface until #298 promotes a
  named consumer.
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
- `NP-08`: Covered.
  Public anchors:
  `crates/registry-relay/tests/entity_routes.rs::governed_entity_policy_ignores_unverified_trust_provenance_without_leak`,
  `crates/registry-relay/tests/entity_routes.rs::governed_entity_policy_ignores_unverified_source_freshness_header_without_leak`,
  `crates/registry-relay/tests/entity_routes.rs::governed_entity_policy_ignores_unverified_raw_pdp_context_headers_without_leak`,
  `crates/registry-relay/tests/entity_routes.rs::governed_entity_policy_ignores_unverified_source_observed_at_header_without_leak`,
  and `crates/registry-relay/src/api/governed.rs`.
  Disposition: governed-route denial, audit provenance, and response
  non-disclosure are covered for the mapped forged-context inputs.
- `NP-09`: Covered.
  Public anchors:
  `crates/registry-relay/tests/spdci_api_standards.rs::disabled_details_malformed_filter_value_records_generic_error_without_value_leak`
  and `crates/registry-relay/tests/error_taxonomy.rs`.
  Disposition: malformed-filter denial now asserts a stable error code, one
  audit record, hashed table identity, zero returned rows, and no raw value or
  backend detail disclosure.
- `NP-10`: Covered.
  Public anchors:
  `crates/registry-relay/src/server.rs::body_limit_layer_returns_problem_details_and_audit_code`,
  `crates/registry-relay/src/server.rs::uri_length_layer_returns_problem_details_and_audit_code`,
  and `crates/registry-notary-server/tests/standalone_http.rs`.
  Disposition: Relay asserts denial plus audit for this middleware path; Notary
  asserts stable early-boundary problem responses, server-owned request ids, and
  non-disclosure where the audited route layer has not run.
- `NP-11`: Partial.
  Public anchors:
  `crates/registry-relay/src/connector/mod.rs::postgres_sslmode_rejects_default_prefer`,
  `crates/registry-relay/src/connector/mod.rs::postgres_sslmode_rejects_explicit_prefer`,
  `crates/registry-relay/src/connector/mod.rs::postgres_sslmode_rejects_disable`,
  and `crates/registry-relay/src/connector/mod.rs::postgres_sslmode_parse_error_does_not_leak_url`.
  Disposition: config-load denial is covered; product-surface diagnostic and
  audit expectations remain to be signed off.
- `NP-12`: Partial.
  Public anchor: `crates/registry-manifest-core/tests/metadata_core.rs`.
  Disposition: validation-limit coverage exists; runtime load and serving-state
  side effects remain to be closed or deferred.
- `NP-13`: Covered.
  Public anchors: `crates/registry-relay/tests/deployment_profile_gates.rs`,
  `crates/registry-relay/src/api/admin.rs`,
  `crates/registry-notary-server/src/standalone.rs`,
  `crates/registry-notary-server/tests/standalone_http.rs`, and
  `crates/registry-notary-server/src/api.rs`.
  Disposition: active Relay and Notary product paths cover audit-failure abort
  behavior.
- `NP-14`: Covered.
  Public anchors:
  `crates/registry-relay/tests/admin_auth_extraction_contract.rs::admin_handlers_use_required_scoped_extractors`,
  `crates/registry-relay/tests/observability_metrics.rs::denied_admin_and_metrics_requests_do_not_leak_privileged_surfaces`,
  and `crates/registry-relay/tests/observability_metrics.rs::metrics_do_not_expose_sensitive_or_high_cardinality_values`.
  Disposition: current admin and metrics surfaces assert required scoped
  extractors, stable unauthenticated and wrong-scope denials, denial audit
  records, bounded metrics labels, and no privileged admin-state disclosure.
- `NP-15`: Covered.
  Public anchors: `crates/registry-relay/src/server.rs` and
  `crates/registry-relay/tests/e2e_health.rs`.
  Disposition: no new release work identified from the current map.
- `NP-16`: Gap.
  Public anchor: internal checklist only.
  Disposition: deferred to a maintainer-owned follow-up bundle;
  public scenario detail remains intentionally omitted.
- `NP-17`: Gap.
  Public anchor: internal checklist only.
  Disposition: deferred to a maintainer-owned follow-up bundle;
  public scenario detail remains intentionally omitted.
- `NP-18`: Gap.
  Public anchor: internal checklist only.
  Disposition: deferred to a maintainer-owned follow-up bundle;
  public scenario detail remains intentionally omitted.
- `NP-19`: Covered.
  Public anchors:
  `crates/registry-notary-server/src/api.rs::issue_credential_rejects_purpose_mismatch`
  and `crates/registry-notary-server/tests/standalone_http.rs::direct_credential_purpose_mismatch_denial_is_audited_and_redacted`.
  Disposition: purpose mismatch is denied before credential signing, and the
  direct `/v1/credentials` product route now returns a stable problem response,
  emits a redacted `credential_denied` audit record with self-attestation access
  mode and hashed identifiers, and produces no `credential_issued` event.
- `NP-20`: Covered.
  Public anchors:
  `crates/registry-platform-sdjwt/src/lib.rs::holder_proof_rejects_wrong_type_and_dangerous_headers`,
  `crates/registry-notary-server/src/api.rs::strict_credential_issue_rejects_oid4vci_proof_shape`,
  and `crates/registry-notary-server/tests/standalone_http.rs::strict_credentials_issue_rejects_oid4vci_proof_at_http_boundary`.
  Disposition: platform holder-proof validation and the direct
  `/v1/credentials` product route both reject the wrong proof class, return the
  stable `credential.holder_proof_required` problem, emit a redacted
  `credential_denied` audit record with profile and holder-binding metadata,
  and return no credential material.
- `NP-21`: Covered.
  Public anchors:
  `crates/registry-platform-sdjwt/src/lib.rs::holder_proof_enforces_audience_lifetime_and_bindings`,
  `crates/registry-notary-server/tests/sd_jwt_vc_verifier_compat.rs::missing_cnf_when_holder_binding_required_fails_with_holder_binding_required`,
  and `crates/registry-notary-server/tests/sd_jwt_vc_verifier_compat.rs::holder_proof_mismatch_fails_with_holder_binding_proof_invalid`.
  Disposition: holder-binding failure coverage cites named Notary verifier and
  platform holder-proof tests for required confirmation and proof-mismatch
  denial behavior.
- `NP-22`: Covered.
  Public anchors:
  `crates/registry-notary-server/src/standalone.rs::notary_transaction_token_auth_consumes_jti_once`,
  `crates/registry-notary-server/src/standalone.rs::consume_notary_token_jti_rejects_missing_jti_for_transaction_typ`,
  and `crates/registry-notary-server/tests/standalone_http.rs::preauth_transaction_token_jti_denials_are_stable_and_redacted`.
  Disposition: single-use transaction-token `jti` enforcement, missing-`jti`
  fail-closed behavior, replay denial, product-surface HTTP audit parity, and
  response/audit redaction are covered.
- `NP-23`: Gap.
  Public anchor: parked source under `crates/registry-platform-sts`.
  Disposition: maintainer-approved deferral recorded by #246 and #334. STS has
  no promoted release-surface consumer and is parked outside workspace CI and
  release artifacts. Revisit denial-audit parity only when #298 promotes a
  named consumer, then restore the crate's fuzz and adversarial-review coverage
  before treating it as release evidence.
- `NP-24`: Partial.
  Public anchors:
  `crates/registry-notary-server/src/standalone.rs::source_json_reader_rejects_oversized_body`,
  `crates/registry-notary-server/src/standalone.rs::http_sources_reject_private_source_urls_before_fetch`,
  and `crates/registry-notary-server/src/standalone.rs::http_sources_reject_cloud_metadata_source_urls_before_fetch`.
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
- `NP-27`: Covered.
  Public anchors:
  `crates/registry-notary-server/src/runtime.rs::evaluate_denies_missing_scope_before_reading_source`,
  `crates/registry-notary-server/src/api.rs::pdp_pre_source_denial_audit_records_zero_source_and_no_forward`,
  and `crates/registry-notary-server/tests/standalone_http.rs::evaluate_policy_denial_records_zero_source_and_redacted_audit`.
  Disposition: the direct runtime path, API audit helper, and standalone
  `/v1/evaluations` product route now cover pre-source denial, stable PDP
  problem shape, zero upstream source reads, `source_read_count = 0`,
  `forwarded = false`, and response/audit redaction.
- `NP-28`: Covered.
  Public anchors:
  `crates/registry-notary-server/tests/standalone_http.rs::direct_credential_pre_evaluation_denials_are_audited_and_redacted`,
  `crates/registry-notary-server/tests/standalone_http.rs::direct_credential_operation_denial_is_audited_and_preserves_denial_code`,
  `crates/registry-notary-server/tests/standalone_http.rs::direct_credential_rate_limit_is_audited_with_stored_context`,
  `crates/registry-notary-server/tests/standalone_http.rs::direct_credential_binding_denials_are_audited_and_redacted`,
  `crates/registry-notary-server/tests/standalone_http.rs::direct_credential_holder_proof_replay_is_audited_and_redacted`,
  `crates/registry-notary-server/tests/standalone_http.rs::direct_credential_purpose_mismatch_denial_is_audited_and_redacted`,
  `crates/registry-notary-server/tests/standalone_http.rs::strict_credentials_issue_rejects_oid4vci_proof_at_http_boundary`,
  `crates/registry-notary-server/tests/self_attestation_guard_test.rs::self_attestation_credential_issuance_rejects_disallowed_profile`,
  `crates/registry-notary-server/src/api.rs::evaluation_access_uses_stored_claim_version_scope`,
  `crates/registry-notary-server/src/runtime.rs::credential_profile_for_rejects_profile_not_listed_in_claim`,
  and `crates/registry-notary-server/src/api.rs::issue_credential_fails_closed_when_status_record_write_fails`.
  Disposition: caller-triggered pre-evaluation request, classification, and
  lookup denials emit a minimal `credential_denied` event without recording an
  untrusted evaluation id. Evaluation-bound binding, stored-access, policy,
  proof, and replay denials share redacted stored-evaluation context and
  preserve structured self-attestation denial codes, including issue-time
  assurance failures. Credential issuance rate limiting retains its dedicated
  `credential_issue_rate_limited` decision with the same safe stored context.
  Authentication failures retain the auth middleware taxonomy; missing handler
  state, disabled evidence, audit-key derivation, replay-store failure,
  credential-profile or issuer resolution, signing, and status failures remain
  service errors rather than being relabeled as credential policy denials.
  Tests assert stable problem responses, no unintended
  credential issuance, no credential material, redacted audit records,
  `source_read_count = 0`, and `forwarded = false` on credential denial paths.
- `NP-29`: Partial.
  Public anchors:
  `crates/registry-notary-server/tests/standalone_http.rs::federation_evaluation_returns_signed_response_and_rejects_replay`,
  `crates/registry-notary-server/tests/standalone_http.rs::federation_auth_exempt_route_still_requires_valid_jws`,
  `crates/registry-notary-server/tests/standalone_http.rs::federation_denial_happens_before_source_read`,
  `crates/registry-notary-server/tests/standalone_http.rs::federation_stale_source_observation_returns_signed_evaluation_error`,
  and `crates/registry-notary-server/src/federation/audit.rs::federation_audit_event`.
  Disposition: federation coverage already exercises disabled-route behavior,
  invalid JWS denial, replay denial, no-source-read denials, and signed stale
  source errors with audit redaction. The remaining blocker is complete
  denied-audit context parity for post-verification federation denials; current
  denied outcomes do not carry every peer/profile/purpose/JTI/subject hash field
  that success and signed-error outcomes can carry, so this needs maintainer
  decision or explicit deferral before release sign-off.

## Release Decision

This map records the current state; it does not close every release gap. Before
checking the release-readiness item, each row marked `Partial` or `Gap` must
have either a linked test PR that asserts denial plus audit-record correctness,
or a maintainer-approved deferral with rationale.
