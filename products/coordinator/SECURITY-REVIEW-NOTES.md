# Registry Coordinator security review notes

This file lists what the Coordinator enforces for authentication,
authorization, custody of stored payloads, and audit, with the code that
enforces each item and the test that exercises it. It states behaviour only.
The supported boundary is in `PILOT-CONTRACT.md`.

## Authentication

- Every `/v1` route requires a bearer access token. The verifier accepts a
  token of type `at+jwt` signed with RS256 or ES256 for the configured issuer
  and audience, from a client `deployment.authentication.allowedClients`
  lists, with a lifetime of at most 3600 seconds
  (`AccessConfig::authenticator`,
  `crates/registry-coordinator/src/access.rs`).
- A token that carries an assertion-issuer claim is refused unless the runtime
  file configures `assertionIssuers` (`Authenticator::authenticate`).
- The caller is the verified issuer, subject, and client. A token without an
  issuer, or with a subject that is empty, longer than 512 characters, or
  holds a control character, is refused.
- A missing or refused token answers `coordinator.access.unauthenticated`
  (HTTP 401). A verifier that cannot fetch or parse its keys answers
  `coordinator.access.unavailable`, never an acceptance.
- Tests: `verified_subject_owns_runs_and_exact_policy_restricts_flow_action`
  (`tests/deployment_surface.rs`) and
  `split_activation_and_real_router_enforce_owned_progress_and_operator_recovery`
  (`tests/deployment_postgres.rs`, `postgres-test`).

## Authorization

- `deployment.authentication.policies` holds 1 to 64 policies. The caller
  gets the first policy whose `clientId` equals the verified client and whose
  `requiredScopes` are all in the token. No matching policy answers
  `coordinator.access.denied` (HTTP 403).
- A policy lists the `actions` and the `flows` it permits. An action or a
  flow outside the lists answers `coordinator.access.denied`
  (`Caller::authorize`).
- A run belongs to the caller that started it. The owner is a keyed
  commitment over the database identity and the verified issuer and subject
  (`Store::owner`, `crates/registry-coordinator/src/store/recovery.rs`), so
  an identifier in the workflow input or a grant reference gives no
  ownership. Status, list, inspection, retry, cancellation, and
  reconciliation select by that owner, and a run another caller owns answers
  `coordinator.command.run-absent`, as a run that does not exist does.
- A policy with `operator: true` reads and recovers runs it does not own, and
  only such a policy may set or release a restore hold, release the
  admission hold, complete execution recovery, or run retention
  (`Store::operator`). The default is `false`.
- A repeated start key under the same verified issuer, subject, and flow
  returns the original run when the input matches and is refused when it
  differs.
- Tests: `owned_and_operator_flow_policy_is_applied_before_the_list_limit`
  and `protected_rows_enforce_owner_and_authenticate_cross_run_swaps`
  (`tests/postgres_state.rs`, `postgres-test`), and
  `invalid_references_and_foreign_owners_cannot_authorize_recovery`
  (`tests/recovery_audit.rs`, `postgres-test`).

## Authority at the products the Coordinator calls

- The Coordinator holds no authority of the products it calls. It acquires a
  credential when a call is attempted and the receiving product decides the
  call.
- A call bound to a Casework task grant exchanges for a task assertion on
  each attempt, under the grant's own identifier and deadline. A wait, a
  retry, or a restart does not extend that deadline, and a call with a grant
  never falls back to standing authority
  (`crates/registry-coordinator/src/adapters.rs`).
- `invoke-breg-action` accepts no grant and uses a standing Base Registry
  Engine service identity.
- Remote error text is not copied into stored state or a report: a failure is
  recorded as one of the closed codes `operations::failure_code` lists.
- Tests: `task_binding_requires_an_unexpired_approval_and_never_uses_standing_authority`,
  `authority_deadline_mismatch_and_revocation_never_reach_breg`,
  `declined_credentials_and_invalid_commands_never_reach_the_product`, and
  `one_dispatch_attempt_does_not_retry_or_expose_remote_error_values`
  (`tests/http_boundary.rs`).

## Custody of stored payloads

- Workflow inputs, call outputs, prepared commands, and the definition
  snapshot of a run are stored as authenticated ciphertext through
  `registry_platform_crypto::sealed_value`. The associated data binds each
  value to its database identity, run, purpose, and step
  (`crates/registry-coordinator/src/protected_state.rs`), so a value moved to
  another run or step does not open.
- A deployment holds at most 16 payload key versions and one separate
  admission key. Key material is named by secret reference in the runtime
  file and is never part of a package.
- A runtime database role separate from the migration role cannot migrate
  or activate. Only `coordinatorctl apply` resolves the migration
  credential.
- Tests: `protected_rows_enforce_owner_and_authenticate_cross_run_swaps`,
  `terminal_retention_keeps_spent_start_keys_across_payload_rotation`, and
  `changing_admission_key_cannot_reopen_a_spent_identity`
  (`tests/postgres_state.rs`, `postgres-test`).

## Audit

- A recovery action opens its audit record before it changes state
  (`Store::audited`, `crates/registry-coordinator/src/store/recovery.rs`).
  When the audit sink refuses the record, the action answers
  `coordinator.command.audit-unavailable` and changes nothing.
- The record names the actor, the run, and the reason an operator supplies
  as keyed references (`Store::reference`), never as the text supplied.
- Tests: `every_recovery_action_audits_the_keyed_investigation_reference` and
  `recovery_audit_failure_preserves_request_and_response_release_gates`
  (`tests/recovery_audit.rs`, `postgres-test`).
