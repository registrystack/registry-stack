# Negative-Path Coverage Map

Issue: [#200](https://github.com/registrystack/registry-stack/issues/200)

Generated: 2026-07-10

Citation refresh: 2026-07-17. This refresh verified that the named public
anchors resolve in the current tree; it did not rerun the historical evidence
collection behind this map.

Retirement refresh: 2026-08-03. Registry Notary was retired from this
repository, and the parked `registry-platform-sts` crate was removed with it.
Rows whose evidence lived in those crates are kept rather than deleted, because
deleting them would erase the record of what was once claimed and of what is
now unproven. They are restated as `Retired evidence`, their anchors are named
as they stood at tag
[`v0.16.3`](https://github.com/registrystack/registry-stack/tree/v0.16.3), the
last release that shipped them, and their recorded findings are labelled
historical. Rows with both maintained and retired anchors keep only the
maintained anchors as current evidence, and a row that loses its
product-surface evidence to the retirement is downgraded, never left claiming
coverage it no longer has.

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
- `Retired evidence`: the row's anchors lived in a product or crate that has
  since been retired, so the row proves nothing about a maintained product. The
  state it held before the retirement is shown in parentheses. It counts as
  neither coverage nor an open gap until someone re-scopes the scenario against
  a maintained product.

## Map

- `NP-01`: Partial.
  Public anchors: `crates/registry-relay/src/auth/oidc/provider.rs`,
  `crates/registry-platform-crypto/src/lib.rs`, and
  `crates/registry-platform-sdjwt/src/lib.rs`.
  Retired anchor (`v0.16.3`):
  `crates/registry-notary-server/tests/sd_jwt_vc_verifier_compat.rs`.
  Disposition: keep open for complete product-surface audit parity.
- `NP-02`: Partial.
  Public anchor: `crates/registry-relay/src/auth/oidc/provider.rs`.
  Retired anchor (`v0.16.3`): `crates/registry-notary-server/src/api.rs`.
  Disposition: keep open for remaining active product-surface audit assertions.
  The parked STS source referenced here left the tree with the retirement; see
  `NP-23`.
- `NP-03`: Partial.
  Public anchors: `crates/registry-relay/src/auth/oidc/provider.rs` and
  `crates/registry-platform-sdjwt/src/lib.rs`.
  Retired anchor (`v0.16.3`): `crates/registry-notary-server/src/api.rs`.
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
  `crates/registry-relay/src/server.rs::body_limit_layer_returns_problem_details_and_audit_code`
  and `crates/registry-relay/src/server.rs::uri_length_layer_returns_problem_details_and_audit_code`.
  Retired anchor (`v0.16.3`):
  `crates/registry-notary-server/tests/standalone_http.rs`.
  Disposition: Relay asserts denial plus audit for this middleware path, and
  that alone carries the row on the maintained surface. The retired anchor
  additionally asserted stable early-boundary problem responses, server-owned
  request ids, and non-disclosure where the audited route layer had not run;
  that evidence is historical.
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
  Public anchors: `crates/registry-relay/tests/deployment_profile_gates.rs` and
  `crates/registry-relay/src/api/admin.rs`.
  Retired anchors (`v0.16.3`):
  `crates/registry-notary-server/src/standalone.rs`,
  `crates/registry-notary-server/tests/standalone_http.rs`, and
  `crates/registry-notary-server/src/api.rs`.
  Disposition: the active Relay product path covers audit-failure abort
  behavior. The Notary paths that shared this row are historical.
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
- `NP-19`: Retired evidence (was Covered).
  Retired anchors (`v0.16.3`):
  `crates/registry-notary-server/src/api/tests/credentials.rs::issue_credential_rejects_purpose_mismatch`
  and `crates/registry-notary-server/tests/standalone_http/credentials.rs::direct_credential_purpose_mismatch_denial_is_audited_and_redacted`.
  Historical disposition: purpose mismatch is denied before credential signing, and the
  direct `/v1/credentials` product route now returns a stable problem response,
  emits a redacted `credential_denied` audit record with subject-access
  mode and hashed identifiers, and produces no `credential_issued` event.
- `NP-20`: Partial.
  Public anchor:
  `crates/registry-platform-sdjwt/src/lib.rs::holder_proof_rejects_wrong_type_and_dangerous_headers`.
  Retired anchors (`v0.16.3`):
  `crates/registry-notary-server/src/api/tests/credentials.rs::strict_credential_issue_rejects_oid4vci_proof_shape`
  and `crates/registry-notary-server/tests/standalone_http/credentials.rs::strict_credentials_issue_rejects_oid4vci_proof_at_http_boundary`.
  Disposition: platform holder-proof validation still rejects the wrong proof
  class. The product-surface half of this row lived on the retired
  `/v1/credentials` route, which historically returned the stable
  `credential.holder_proof_required` problem, emitted a redacted
  `credential_denied` audit record with profile and holder-binding metadata,
  and returned no credential material. No maintained product surface asserts
  that today, so the row is downgraded from `Covered` and stays open.
- `NP-21`: Partial.
  Public anchor:
  `crates/registry-platform-sdjwt/src/lib.rs::holder_proof_enforces_audience_lifetime_and_bindings`.
  Retired anchors (`v0.16.3`):
  `crates/registry-notary-server/tests/sd_jwt_vc_verifier_compat.rs::missing_cnf_when_holder_binding_required_fails_with_holder_binding_required`
  and `crates/registry-notary-server/tests/sd_jwt_vc_verifier_compat.rs::holder_proof_mismatch_fails_with_holder_binding_proof_invalid`.
  Disposition: the platform holder-proof test still covers audience, lifetime,
  and binding enforcement. The required-confirmation and proof-mismatch
  verifier evidence was Notary's, so the row is downgraded from `Covered` and
  stays open for a maintained verifier surface.
- `NP-22`: Retired evidence (was Covered).
  Retired anchors (`v0.16.3`):
  `crates/registry-notary-server/src/standalone/tests/auth.inc::notary_transaction_token_auth_consumes_jti_once`,
  `crates/registry-notary-server/src/standalone/tests/auth.inc::consume_notary_token_jti_rejects_missing_jti_for_transaction_typ`,
  and `crates/registry-notary-server/tests/standalone_http/preauth.rs::preauth_transaction_token_jti_denials_are_stable_and_redacted`.
  Historical disposition: single-use transaction-token `jti` enforcement, missing-`jti`
  fail-closed behavior, replay denial, product-surface HTTP audit parity, and
  response/audit redaction are covered.
- `NP-23`: Retired evidence (was Gap).
  Retired anchor (`v0.16.3`): parked source under `crates/registry-platform-sts`.
  Historical disposition: maintainer-approved deferral recorded by #246 and #334. STS has
  no promoted release-surface consumer and is parked outside workspace CI and
  release artifacts. Revisit denial-audit parity only when #298 promotes a
  named consumer, then restore the crate's fuzz and adversarial-review coverage
  before treating it as release evidence.
  Retirement note: the crate was removed from the tree by the Notary
  retirement, so there is no parked source left to promote. If transaction-token
  exchange returns to the stack, this row needs fresh evidence rather than the
  recorded deferral.
- `NP-24`: Partial.
  Public anchor:
  `crates/registry-relay/src/auth/api_key.rs::authorization_header_wins_over_x_api_key`.
  Retired anchors (`v0.16.3`):
  `crates/registry-notary-server/src/standalone/tests/auth.inc::static_auth_rejects_multiple_credential_headers`,
  `crates/registry-notary-server/src/standalone/tests/auth.inc::static_auth_rejects_api_key_with_malformed_authorization_header`,
  and `crates/registry-notary-server/tests/standalone_http/preauth.rs::preauth_transaction_token_jti_denials_are_stable_and_redacted`.
  Disposition: the multiple-credentials rejection evidence was Notary's and is
  historical. Historically Notary rejected API-key plus Bearer and API-key plus
  malformed Authorization before choosing or falling back to either source,
  with a stable `auth.multiple_credentials` denial and a matching redacted
  audit record. What remains on the maintained surface is Relay's documented
  behavior: when both credential headers are present, Authorization takes
  precedence over `x-api-key` rather than being rejected as multiple
  credentials. The row stays open for a decision on whether Relay should reject
  instead, and for the HTTP response and audit evidence that would go with it.
- `NP-25`: Retired evidence (was Covered).
  Retired anchors (`v0.16.3`): `crates/registry-notary-core/src/deployment.rs` and
  `crates/registry-notary-server/src/standalone/tests/deployment_gates.rs`.
  Historical disposition: Notary startup gates required an explicit deployment
  profile, kept `local` as the development opt-out, and rejected unknown
  profile values.
- `NP-26`: Retired evidence (was Partial).
  Retired anchors (`v0.16.3`):
  `crates/registry-notary-core/src/config/evidence/relay.rs`,
  `crates/registry-notary-core/src/config/tests/relay.rs::relay_connection_requires_https_origin_or_explicit_loopback`,
  `crates/registry-notary-core/src/config/tests/relay.rs::relay_token_file_and_private_cidrs_are_exact_and_bounded`,
  `crates/registry-notary-server/src/relay_client.rs`,
  and `crates/registry-notary-server/src/relay_client/tests.rs::status_size_redirect_and_retry_behavior_is_closed`.
  Historical disposition: the direct-source and sidecar network model was
  already out of release evidence when this row was written. The Notary-to-Relay
  consultation boundary that replaced it validated one configured HTTPS origin
  with an explicit loopback exception, bounded the private CIDR exception list
  and both metadata and result response bodies, and rejected redirects without
  retrying. That boundary retired with the product; Relay's own outbound
  posture is not covered by this row.
- `NP-27`: Retired evidence (was Covered).
  Retired anchors (`v0.16.3`):
  `crates/registry-notary-server/src/runtime/tests/evaluation.rs::registry_backed_preflight_denial_makes_zero_relay_calls`,
  `crates/registry-notary-server/src/runtime/tests/evaluation.rs::evaluate_denies_missing_scope`,
  and `crates/registry-notary-server/src/api/tests/audit.rs::pdp_pre_evaluation_denial_audit_records_zero_consultations_and_no_forward`.
  Historical disposition: the runtime and API audit boundaries cover pre-evaluation
  denial, stable PDP problem shape, zero Relay consultations,
  `relay_consultation_count = 0`,
  `forwarded = false`, and response/audit redaction.
- `NP-28`: Retired evidence (was Covered).
  Retired anchors (`v0.16.3`):
  `crates/registry-notary-server/tests/standalone_http/credentials.rs::direct_credential_pre_evaluation_denials_are_audited_and_redacted`,
  `crates/registry-notary-server/tests/standalone_http/credentials.rs::direct_credential_operation_denial_is_audited_and_preserves_denial_code`,
  `crates/registry-notary-server/tests/standalone_http/credentials.rs::direct_credential_rate_limit_is_audited_with_stored_context`,
  `crates/registry-notary-server/tests/standalone_http/credentials.rs::direct_credential_binding_denials_are_audited_and_redacted`,
  `crates/registry-notary-server/tests/standalone_http/credentials.rs::direct_credential_holder_proof_replay_is_audited_and_redacted`,
  `crates/registry-notary-server/tests/standalone_http/credentials.rs::direct_credential_purpose_mismatch_denial_is_audited_and_redacted`,
  `crates/registry-notary-server/tests/standalone_http/credentials.rs::direct_credential_disallowed_profile_preserves_profile_denial`,
  `crates/registry-notary-server/tests/standalone_http/credentials.rs::strict_credentials_issue_rejects_oid4vci_proof_at_http_boundary`,
  `crates/registry-notary-server/src/api/tests/evaluations.rs::evaluation_access_uses_stored_claim_version_scope`,
  `crates/registry-notary-server/src/runtime/tests/render.rs::credential_profile_for_rejects_profile_not_listed_in_claim`,
  and `crates/registry-notary-server/src/api/tests/credentials.rs::issue_credential_fails_closed_when_status_record_write_fails`.
  Historical disposition: caller-triggered pre-evaluation request, classification, and
  lookup denials emit a minimal `credential_denied` event without recording an
  untrusted evaluation id. Evaluation-bound binding, stored-access, policy,
  proof, and replay denials share redacted stored-evaluation context and
  preserve structured subject-access denial codes, including issue-time
  assurance failures. Credential issuance rate limiting retains its dedicated
  `credential_issue_rate_limited` decision with the same safe stored context.
  Authentication failures retain the auth middleware taxonomy; missing handler
  state, disabled evidence, audit-key derivation, replay-store failure,
  credential-profile or issuer resolution, signing, and status failures remain
  service errors rather than being relabeled as credential policy denials.
  Tests assert stable problem responses, no unintended
  credential issuance, no credential material, redacted audit records,
  `relay_consultation_count = 0`, and `forwarded = false` on credential denial paths.
- `NP-29`: Retired evidence (was Covered).
  Retired anchors (`v0.16.3`):
  `crates/registry-notary-server/tests/standalone_http/federation.rs::federation_evaluation_returns_signed_response_and_rejects_replay`,
  `crates/registry-notary-server/tests/standalone_http/federation.rs::federation_auth_exempt_route_still_requires_valid_jws`,
  `crates/registry-notary-server/tests/standalone_http/federation.rs::federation_denial_happens_before_claim_evaluation`,
  `crates/registry-notary-server/tests/standalone_http/federation.rs::federation_emergency_kid_denylist_blocks_before_claim_evaluation`,
  `crates/registry-notary-server/tests/standalone_http/federation.rs::federation_emergency_node_id_denylist_blocks_before_claim_evaluation`,
  `crates/registry-notary-server/tests/standalone_http/federation.rs::federation_request_claims_must_match_profile_before_claim_evaluation`,
  `crates/registry-notary-server/tests/standalone_http/federation.rs::federation_stale_claim_result_returns_signed_evaluation_error`,
  and `crates/registry-notary-server/src/federation/mod.rs::federation_response_signing_failure_emits_denial_audit_with_context`.
  Historical disposition: pre-verification signature and emergency-denylist denials omit
  untrusted request context. After signature verification, denial records retain
  the configured issuer and peer evaluation scopes plus the request profile and
  purpose, hash the peer id and request JTI, and include a pairwise
  subject-reference hash when the locally allowed profile and subject are
  structurally valid. Tests cover replay,
  policy, claim-mismatch, unknown-key, denylisted-key, denylisted-node, and
  signed stale-claim outcomes; preserve pre-evaluation denial ordering; and assert
  that raw subject ids and request JTIs do not reach audit records.
  Response-signing failures retain the already assembled redacted context.

## Release Decision

This map records the current state; it does not close every release gap. Before
checking the release-readiness item, each row marked `Partial` or `Gap` must
have either a linked test PR that asserts denial plus audit-record correctness,
or a maintainer-approved deferral with rationale.
Each row marked `Retired evidence` must be re-scoped against a maintained
product and then covered, deferred, or explicitly declared out of scope. A
retired row must never be counted as coverage.
