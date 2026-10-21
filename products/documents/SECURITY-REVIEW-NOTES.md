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

The runtime serves `GET /health` without a credential and the document
routes behind access-token verification (see "Access profiles, document
grants, and release" below), and nothing else. Every other path answers
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

- Reservation (`POST /documents`) refuses an unknown policy, an empty
  document, a length above the policy or deployment ceiling, a media type outside the policy list by
  exact match, and a custodian over its per-policy byte quota. The quota sum
  runs under a transaction advisory lock per custodian and policy, so
  concurrent reservations cannot overrun it.
- Upload (`PUT /uploads/{id}/content`) has no body-limit layer of its own
  and a transfer deadline of `transfers.minimumDeadlineSeconds` plus
  `transfers.mebibyteAllowanceSeconds` per started mebibyte. It requires `Content-Type` to equal
  the reserved type, never inspects the bytes for a type, refuses a declared
  length above the deployment ceiling or other than the reserved one before
  reading, and stops reading at the reserved length plus one byte, so the
  reservation's policy bound is what limits the body. The body is hashed while read
  and buffered under one transfer budget, the larger of 256 MiB and the
  deployment ceiling, shared with downloads and verification; past it the
  upload answers 503. Nothing is written until digest and length match, and
  no database transaction is open while bytes arrive. Finalization locks the
  version row, so concurrent uploads finalize once.
- On S3, credentials are resolved and the bucket is checked for versioning
  once, at startup; each object's store is derived from that activation.
  Each attempt commits a staged row naming a fresh, server-chosen object
  before writing it, and the write checks versioning again before it sends. Identical content is never shared between
  documents.
- The storage binding is pinned at the first write; a later start under
  another backend, bucket, or scope is refused, and a running deployment
  whose pin moved finalizes nothing.
- Verification runs on the shared dispatch worker, enqueued in the
  finalizing transaction under a key of the version and the verifier binding
  digest. Backoff starts at 30 seconds, doubles to at most one hour with
  equal jitter, and gives up after about seven days. An unavailable verifier
  never releases; a dead-lettered job leaves the version pending and
  suspended. At startup, every finalized version not rejected and recorded
  under another binding is suspended and re-queued, and its pending job under
  the old binding is cancelled; a job already leased under it ends without a
  verdict. A worker whose binding differs from the version's retries the job
  rather than ending it, so instances with different verifiers can run side
  by side during a rollout. A verdict that changes no row while the version
  is still under the same binding and not rejected is not delivered; the job
  is retried once its lease lapses.
- Download releases only an approved version whose verdict is bound to its
  computed digest, media type, and the binding it is currently recorded
  under; the database refuses a releasable row that breaks any of the
  three. It reads the whole
  content and checks digest and length before the first byte; a mismatch
  answers 503, sends no byte, and writes a `storage-integrity` audit entry.
- Reservation, upload, verification, and download each write an audit
  request entry before they act and a response entry with outcome and byte
  count after. The journal names a caller only by a keyed reference. A
  request whose audit entry cannot be written is refused with 503. A
  verification attempt whose leasing entry cannot be written is refused
  before the verifier is asked and records no verdict; a result entry that
  cannot be written after the verdict commits logs an error.
- Startup refuses a package other than the one `package.expectedDigest`
  pins.

### Tests

`crates/registry-documents/tests/postgres_documents.rs` and
`crates/registry-documents/tests/postgres_s3.rs`, both under the
`postgres-test` feature against a disposable database; the S3 suite runs
against a loopback fake object store and verifier. The rows in
`contracts/security-test-traceability.yaml` name each test.

### Residual risk

- Upload expiry, erasure of expired reservations, and the sweep of S3
  objects a failed or losing attempt left behind are owed by WP5. Until then
  such objects and rows stay in place.
- During a verifier rollout, an older instance may still finalize a version
  under its binding after a newer instance swept. That version can be
  approved and released under the older binding by a worker that holds it,
  and stays so until the next restart sweeps it; a worker under the newer
  binding only retries its job. Finish a verifier change by restarting every
  instance.

## Access profiles, document grants, and release (2026-10-22)

### Threat

A caller without a verified token, or under the wrong access profile,
reserves, reads, or downloads a document; a caller places a document in
custody it may not hold or under an institution it does not act for; a
retried request reserves twice or answers a stale success; a grant releases
another version, to another reader, or after it expired or was revoked; an
unauthorized caller learns a document exists; concurrent or stalled transfers
exhaust memory; a caller-chosen label is trusted.

### Enforcement and defaults

`crates/registry-documents/src/auth.rs`, `http.rs`, `service.rs`,
`service/grants.rs`, and `transfer.rs` enforce, with the invariant rows
DOCUMENTS-SEC-10, DOCUMENTS-SEC-19, and DOCUMENTS-SEC-21 to DOCUMENTS-SEC-33:

- Every document route verifies the bearer token through
  `registry-platform-oidc` (issuer, audience, `at+jwt`, allowed clients,
  signature from the configured key set) and resolves exactly one access
  profile from its client, scopes, and actor kind before it reads the body
  or the store; a JSON body is buffered, under the default body limit, only
  after the caller is verified. A refused token answers 401 with a `Bearer`
  challenge; a key set the runtime cannot reach answers 503, never 401.
- Custody: a reservation needs the caller's profile among the policy's
  `custodyProfiles`. A service may name any custodian; a human caller only
  itself, matched by issuer, subject, and kind. The policy's `custodian`
  rule decides what naming another subject means (DOCUMENTS-DEC-15): under
  `represented-principal` that subject becomes the custodian; under
  `institution` the reserving service stays the custodian and the subject
  is recorded only as the represented principal, with no standing until
  granted. Owner standing matches the reserving system's issuer, subject,
  and kind. The issuing institution is
  the profile's `institution`; a body that names another is refused with
  `custody.not-permitted`.
- Idempotency: `POST /documents` and grant issue require an
  `Idempotency-Key`, scoped to issuer, subject, operation, and key, with the
  request body's digest. Another body answers 409 `idempotency.key-reused`;
  a key older than `retention.receiptRetentionDays` answers 410
  `idempotency.expired`; neither reserves anything. A replay re-runs
  authorization first, so a caller who lost authority gets the refusal, not
  the cached success. A finalized upload answers a repeat of the same bytes
  with the same view and other bytes with 409 `upload.finalized`.
- Pushed grants, no live predicate: a grant names one exact version, one
  recipient issuer, subject, and actor kind (DOCUMENTS-DEC-16), and an
  expiry frozen at issue from the
  policy default within its maximum. Grants are issued and revoked by the
  custodian or the owning system under a granting profile. Nothing extends
  a grant, names an organization, or invites a reader; release consults the
  stored grant row only, never current claims beyond the recipient's
  identity and recipient-role profile.
- Release: download answers only the custodian, or the holder of an
  unrevoked, unexpired grant on that exact version, and only while the
  version is releasable under the current verifier binding. Otherwise the
  custodian gets 409, and every other caller, grant holders included, 404.
  The reserving system that is not the custodian sees metadata but gets no
  bytes; its download answers 403 `profile.not-authorized`
  (DOCUMENTS-DEC-10). The database keeps a grant only on a version of its
  own document and only of a known actor kind.
- Uniform 404: read, download, and every grant route answer
  `resource.not-found` for a document the caller has no standing on, the
  same as an unknown identifier; 403 goes only to a caller who already sees
  the document. Download refusals are audited with the code answered.
- Download budget: downloads, uploads, and verification share one transfer
  budget, the larger of 256 MiB and the deployment ceiling. A transfer that
  finds no room answers 503 with `Retry-After` and is never queued; a
  background verification attempt waits for room only within its attempt
  timeout, then ends as a transient failure, so it never holds its job lease
  past the attempt deadline. Every
  transfer has a deadline of a floor plus a per-MiB allowance; a stalled
  upload is cut off with 503, and a stalled download ends in a body error
  and lets go of its bytes. The database client is released before content
  is read from object storage, and the digest check still runs before the
  first byte is sent. Transient copies can reach about twice the budget;
  `RUNTIME-CONFIG.md` states the memory to provision.
- Untrusted label: a label is one to 256 bytes without control characters,
  stored and returned exactly as written. The Store never interprets it,
  and a client must render it as untrusted text.
- Audit ordering: every audited request writes its request entry before it
  acts, the upload before it looks up its reservation, so a probe of an
  unknown or another caller's upload is journalled. A request entry that
  cannot be written answers 503 and changes nothing. The response entry is
  written after the operation commits; if it cannot be written the caller
  gets 503, the committed state stands, the request entry is in the
  journal, and a retry with the same `Idempotency-Key` answers the
  committed result.
- The journal records a caller-supplied identifier (policy id, media type,
  version id) only once it parses under its bounded grammar, and the marker
  `unparsed` otherwise.
- `GET /document-policies` lists only the policies the caller's profile may
  reserve under, with their size, media type, and grant expiry bounds.

### Review calls

The lead reviewer settled these points of the access slice; the rows and
decisions above carry them:

- A grant stores its recipient's actor kind and release compares it, so a
  human's grant is never redeemable by a service that shares the subject
  value (DOCUMENTS-SEC-24).
- Under institutional custody, custody always stays with the reserving
  institution; a named person is only the represented principal and has no
  standing without a grant. Citizen delivery is unchanged
  (DOCUMENTS-SEC-32).
- The owning system that sees a document but may not download it gets 403
  `profile.not-authorized`, not 404 (DOCUMENTS-SEC-10, DOCUMENTS-DEC-10).
- Requests that find the transfer budget spent are refused at once; the
  background verifier waits for room only within its attempt timeout
  (DOCUMENTS-SEC-28).
- The audit response entry is written after commit: a request entry that
  cannot be written refuses and changes nothing, and a response entry that
  cannot be written answers 503 while the committed state stands and a retry
  under the same key answers it (DOCUMENTS-SEC-30).

### Tests

`crates/registry-documents/tests/postgres_documents.rs` and
`crates/registry-documents/tests/postgres_startup.rs` mint ES256 access
tokens from a test key whose public half the runtime reads as a static key
set, and call the served router; the startup suite does so over a socket.
The unit tests in `auth.rs` and `transfer.rs` cover token refusal shapes and
the budget and deadline. `contracts/security-test-traceability.yaml` names
each test.

### Residual risk

- Restore caveat: grants and revocations live in PostgreSQL. Restoring a
  backup older than a revocation brings the revoked grant back as active
  unless the audit journal written since the backup is restored too and
  the revocations it records are re-applied. Treat a database restore as a
  security event and re-revoke from the journal.
- A download already admitted when its grant is revoked finishes within its
  transfer deadline (DOCUMENTS-DEC-11); the deadline bounds the window.
- The documents list filters each fetched row by the policy's standing
  rules, so its page can be shorter than its limit while a next cursor
  remains; the received-grants list selects only redeemable grants before
  its limit (DOCUMENTS-DEC-13).
- The recipient resolver and display names are out of scope: a grant names
  a recipient only by issuer, subject, and actor kind, and the granting
  system must know them. A recipient's grant follows the subject, so an issuer that reuses a
  subject for another person would release to that person.
- The label is caller text. A client that renders it as markup, or trusts it
  to describe the bytes, can mislead its user; the Store makes no claim
  about it.
- A document whose policy the deployed package no longer declares is shown
  to nobody, custodian included, and each such access logs a warning; it
  stays in custody until erasure (WP5).

## Activation and dead-letter replay (2026-10-22)

### Threat

The serving process changes the schema or records a package as active
nobody reviewed; the runtime serves a database no operator activated, one
belonging to another deployment, or one whose active package is not the
configured one; a dead-lettered verification is re-queued by a caller other
than the operator, or by a replay issued from a stale listing.

### Enforcement and defaults

- `documentsctl apply` is the only path that changes the schema. It connects
  with `database.migrationUrlRef`, verifies the package at `package.root`
  against `package.expectedDigest` when pinned, applies the embedded schema,
  records the package digest in the shared activation ledger
  (`documents_activations`, created at the end of `0100_documents.sql`), and
  grants the runtime role what serving needs. When the two credentials name
  different roles, the runtime role is split from the migration role.
  Applying the active package again records nothing; a changed package
  records a successor naming its predecessor (DOCUMENTS-DEC-17).
- The operator reference is stored only as an activation-scoped keyed hash;
  backup references are bounded in count and text and recorded as written.
  An invalid reference is refused before anything is written.
- `documentsctl plan` and `status` write nothing.
- `serve` reads the ledger before the schema and refuses a database with no
  active package, one recorded for another `identity.databaseId`, or one
  whose active package is not the verified one. It then refuses a schema
  other than this release's, a runtime role that lost its grants, and a
  runtime role that gained authority over the schema after a split apply.
- `documentsctl verification list` and `replay` run over the runtime
  credential against an activated database. Replay names the job's current
  generation, bumps it, and returns the job to pending; the version stays
  pending and suspended until a verifier approves it. No HTTP route lists or
  replays a job (DOCUMENTS-DEC-18).
- Apply and replay write their audit records to the `documentsctl`
  companion journal. An apply whose ledger row committed but whose audit
  record was not accepted reports `audit.unconfirmed` with the
  activation id, and `status` confirms it. Either command refuses with
  `audit.unavailable` and changes nothing when its journal cannot be
  opened. A replay whose audit request is not accepted changes nothing and
  reports `audit.unavailable`; one that committed but whose audit response
  was not accepted reports `audit.unconfirmed` with the job's new
  generation, and `verification list` confirms it; one the database failed
  reports `database.unavailable`. Only a job someone else changed during
  the replay is refused as `documents.verification.changed`.

### Tests

`crates/registry-documents/tests/postgres_operator.rs` runs plan, apply,
status, serve, and replay against a disposable database, including a limited
role that cannot apply the schema. `crates/registry-documentsctl/tests/postgres_cli.rs`
runs the built `documentsctl` binary from `init` to `status`. Both run only
under the `postgres-test` feature. `contracts/security-test-traceability.yaml`
names each test under DOCUMENTS-SEC-34 to DOCUMENTS-SEC-36.

### Residual risk

- The migration credential holds authority over the schema. Keep it off the
  serving host; when the two credentials name the same role, apply records a
  single-role activation and the runtime keeps that authority.
- Anyone holding the runtime credential can replay a dead-lettered job. A
  replay only re-queues verification and releases nothing, so the risk is
  repeated verifier load, not disclosure.
- The companion journal lives on the host the operator command runs on;
  collect it with the runtime's journal.
- `documentsctl init` refuses an existing path before it stages the
  starter, but an empty directory another local process creates at that
  path before the final rename is replaced by the starter; the window needs
  write access to the parent directory and loses no content.
