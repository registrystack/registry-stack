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

The authentication block is parsed and checked but not yet acted on. Its
enforcement is owed by the invariant rows marked pending, which become
enforced only with the change that adds their negative tests. Storage,
content verification, and the package pin are acted on since the custody and
verification slice; see that section.

## Custody, upload, verification, and release (2026-10-22)

### Threat

Bytes other than the ones a custodian declared enter custody; an oversized
or mistyped body exhausts memory or slips past the policy; concurrent
requests finalize twice or overrun a quota; a version is released before a
verifier approved those exact bytes, after a verifier change, or after the
stored bytes changed; content is written somewhere other than the storage the
deployment pinned.

### Enforcement and defaults

`crates/registry-documents/src/service.rs`, `content.rs`, and
`verification.rs` enforce, with the invariant rows DOCUMENTS-SEC-09 and
DOCUMENTS-SEC-14 to DOCUMENTS-SEC-20:

- Reservation (`POST /documents`) refuses an unknown policy, a length above
  the policy or deployment ceiling, a media type outside the policy list by
  exact match, and a custodian over its per-policy byte quota. The quota sum
  runs under a transaction advisory lock per custodian and policy, so
  concurrent reservations cannot overrun it.
- Upload (`PUT /uploads/{id}/content`) has its own body limit at the
  deployment ceiling and a five-minute transfer deadline, requires
  `Content-Type` to equal the reserved type, never inspects the bytes for a
  type, refuses a declared length other than the reserved one, and stops
  reading at the reserved length plus one byte. The body is hashed while read
  and buffered under a fixed 256 MiB budget of concurrent uploads; past it the
  upload answers 503. Nothing is written until digest and length match, and
  no database transaction is open while bytes arrive. Finalization locks the
  version row, so concurrent uploads finalize once.
- On S3, each attempt commits a staged row naming a fresh, server-chosen
  object before writing it. Identical content is never shared between
  documents.
- The storage binding is pinned at the first write; a later start under
  another backend, bucket, or scope is refused, and a running deployment
  whose pin moved finalizes nothing.
- Verification runs on the shared dispatch worker, enqueued in the
  finalizing transaction under a key of the version and the verifier binding
  digest. Backoff starts at 30 seconds, doubles to at most one hour with
  equal jitter, and gives up after about seven days. An unavailable verifier
  never releases; a dead-lettered job leaves the version pending and
  suspended. At startup, every finalized version verified or queued under
  another binding is suspended and re-queued, and a job under a superseded
  binding dead-letters without a verdict.
- Download releases only an approved version whose verdict is bound to its
  computed digest, media type, and the current binding. It reads the whole
  content and checks digest and length before the first byte; a mismatch
  answers 503, sends no byte, and writes a `storage-integrity` audit entry.
- Reservation, upload, verification, and download each write an audit
  request entry before they act and a response entry with outcome and byte
  count after. The journal names a caller only by a keyed reference. A
  request whose audit entry cannot be written is refused with 503; a
  verification attempt whose entry cannot be written logs an error.
- Startup refuses a package other than the one `package.expectedDigest`
  pins.

### Tests

`crates/registry-documents/tests/postgres_documents.rs` and
`crates/registry-documents/tests/postgres_s3.rs`, both under the
`postgres-test` feature against a disposable database; the S3 suite runs
against a loopback fake object store and verifier. The rows in
`contracts/security-test-traceability.yaml` name each test.

### Residual risk

- Authentication is owed by WP4. The `documents` binary serves no
  unauthenticated document route: the router that carries them is compiled
  only into test builds, where a synthetic caller stands in for the verified
  token, and a unit test proves the served router answers 404 on each
  document path. Read access in the test router is the custodian subject or
  the reserving caller; WP4 replaces it with access profiles and grants.
- Upload expiry, erasure of expired reservations, and the sweep of S3
  objects a failed or losing attempt left behind are owed by WP5. Until then
  such objects and rows stay in place.
- Replaying a dead-lettered verification job is owed by WP7; until then an
  operator cannot release a version whose job dead-lettered.
- There is no operator command to apply the schema yet; serving refuses a
  database without it.
- The shared runtime configuration conformance gate has no Document Store
  row, so DOCUMENTS-SEC-13 is partial: the package pin is enforced and
  tested, but the shared gate does not yet require it.
