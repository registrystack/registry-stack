# Registry Document Store security review notes

Review notes for security-sensitive Document Store changes, held in tracked
material because commit messages do not survive a squash. Each section names
the threat it answers, the defaults the product ships, where Rust enforces it,
the tests that pin it, and the residual risk it accepts.
`contracts/security-invariant-matrix.yaml` lists the invariants these notes
explain.

## Bootstrap surface

### Threat

A product skeleton that answers routes before their rules exist would let a
caller reach document behaviour no authorization, verification, or audit
rule governs.

### Enforcement and defaults

The runtime serves `GET /health` and nothing else. Every other path answers
404 `request.not-found` and another method on health answers 405
`request.method-not-allowed`, both as `application/problem+json` with the
caller's trace echoed (`crates/registry-documents/src/http.rs`). Health needs
no credential and reveals nothing beyond the fact the process is serving.

### Residual risk

None beyond an unauthenticated liveness signal, which every Registry Stack
runtime exposes.

## Configuration refusals

### Threat

A deployment starts with a weakened setting: plaintext database transport,
no content verifier, any client of the issuer admitted, or plaintext hook and
verifier destinations. A diagnostic that repeats a refused value leaks secret
reference names or internal hosts into logs.

### Enforcement and defaults

`crates/registry-documents/src/config.rs` refuses, before anything binds:

- `database.testOnlyPlaintext` outside test builds;
- `contentVerification.type: disabled` unless the listener declares
  `development-loopback`;
- `allowedClients: unrestricted`;
- an `http` content verifier or hook URL outside development;
- a secret reference to an undeclared provider.

The shared runtime loader refuses an environment expression in a secret
reference, and `crates/registry-documents-core/src/project.rs` refuses one
anywhere in `documents.yaml`, as well as an empty `requiredScopes` or
`requesterClients` list.

Findings name the member by JSON Pointer and the rule, never the value.
`documentsctl check` reports the same findings offline.

### Tests

`plaintext_database_is_refused_outside_test_builds`,
`disabled_content_verification_requires_development_loopback`,
`unrestricted_clients_are_refused`,
`a_plaintext_hook_destination_is_refused_outside_development`,
`a_reference_to_a_disabled_provider_is_refused`,
`a_refused_runtime_configuration_names_the_finding_without_the_value`,
`shared_runtime_loader_refuses_environment_expressions_in_secret_references`,
`a_substitution_expression_is_refused_in_the_authored_file`, and
`an_empty_scope_or_client_list_is_refused_at_its_member`.

### Residual risk

The storage, content verification, and authentication blocks are parsed and
checked but not yet acted on, and the runtime does not open its package, so
`package.expectedDigest` is checked for form only. Their enforcement is owed by the invariant rows
marked pending, which become enforced only with the change that adds their
negative tests.
