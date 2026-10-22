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
- an `http` content verifier or hook URL outside development; a hook URL
  needs both a loopback address and `development-loopback` to use `http`,
  and a non-loopback `http` hook address is refused at startup;
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
  So does content gone from a version that is not under removal. A database
  or object storage outage answers the same 503 but writes
  `storage-unavailable`, logged at warn, so the integrity outcome stays a
  signal worth alarming on. Content removed between the record read and the
  content read is re-read and answered as a version under removal.
- Reservation, upload, verification, and download each write an audit
  request entry before they act and a response entry with outcome and byte
  count after. A download's `released` entry is written before the body
  streams: it means the content was admitted for transfer, not that the
  caller received every byte. The journal names a caller only by a keyed reference. A
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

- Upload expiry and the sweep of S3 objects a failed or losing attempt left
  behind are covered under "Retention, removal, and erasure" below.
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
  `idempotency.expired` and stays spent, since its row holds only digests
  and the resource id and is never pruned; neither reserves anything. A replay re-runs
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
  to nobody, custodian included, and each such access logs a warning. Its
  custodian cannot remove it either (DOCUMENTS-DEC-26); it stays in custody
  until the policy is declared again.

## Activation and dead-letter replay (2026-10-22)

### Threat

The serving process changes the schema or records a package as active
nobody reviewed; the runtime serves a database no operator activated, one
belonging to another deployment, or one whose active package is not the
configured one; a dead-lettered verification or erasure is re-queued by a
caller other than the operator, or by a replay issued from a stale listing;
content whose removal was requested is verified again.

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
- A verification replay refuses a version whose erasure is pending or done,
  or whose document has a removal requested, with
  `documents.verification.removal-requested`. The check reads the version
  before the dispatcher's replay transaction; a removal that commits between
  the two is still safe, because the verification
  worker records no verdict for a version under removal and sets its job
  aside before reading the bytes.
- `documentsctl erasure list` and `erasure replay` mirror the verification
  verbs over the erasure jobs, with the same generation fence, companion
  audit, and outcome reports under `documents.erasure.*`. The sweep never
  re-arms a dead-lettered erasure, so replay is the only way back; a replay
  while `cleanup.erasure` is paused returns the job to pending and it waits
  for the worker. `documentsctl erasure status` reports whether erasure is
  active or paused and counts the versions awaiting their grace, those due,
  and the dead-lettered erasure jobs.
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
status, serve, both replays, and the erasure status against a disposable database, including a limited
role that cannot apply the schema. `crates/registry-documentsctl/tests/postgres_cli.rs`
runs the built `documentsctl` binary from `init` to `status`. Both run only
under the `postgres-test` feature. `contracts/security-test-traceability.yaml`
names each test under DOCUMENTS-SEC-34 to DOCUMENTS-SEC-36.

### Residual risk

- The migration credential holds authority over the schema. Keep it off the
  serving host; when the two credentials name the same role, apply records a
  single-role activation and the runtime keeps that authority.
- Anyone holding the runtime credential can replay a dead-lettered job. A
  verification replay only re-queues verification and releases nothing, so
  the risk is repeated verifier load, not disclosure. An erasure replay only
  re-queues an erasure the custodian or a rejection already armed; it
  cannot choose what is erased.
- The companion journal lives on the host the operator command runs on;
  collect it with the runtime's journal.
- `documentsctl init` refuses an existing path before it stages the
  starter, but an empty directory another local process creates at that
  path before the final rename is replaced by the starter; the window needs
  write access to the parent directory and loses no content.

## Retention, removal, and erasure

### Threat

A removed document is still released through a grant, a download, or a
late verdict; someone other than its custodian removes it; a grant expiry
silently erases bytes the custodian still holds; a sweep reports a version
erased while the bytes are still servable, erases twice, or strands a
version half done after a crash; a paused deployment erases anyway; erasure
cascades into the grant, verification, or custody records an investigation
needs; an S3 object an abandoned upload left behind stays forever.

### Enforcement and defaults

`crates/registry-documents/src/service/erasure.rs`, `erasure.rs`,
`runtime.rs`, `verification.rs`, `service/grants.rs`, and
`migrations/0100_documents.sql` enforce, with the invariant rows
DOCUMENTS-SEC-37 to DOCUMENTS-SEC-46 and the decisions DOCUMENTS-DEC-19 to
DOCUMENTS-DEC-26:

- Only the custodian may remove a document, through
  `POST /documents/{documentId}/erasure`; every other caller with standing
  gets 403 and every caller without it 404. A repeat answers the same view
  and moves nothing.
- The removal request is one transaction: the version becomes erasure
  pending and suspended, every active grant on the document is revoked, and
  pending verification is cancelled. Grant issue holds the version row and
  refuses an erasing version; download needs a releasable version, which
  the database refuses for a version under removal; a verdict that
  arrives later records nothing; and a verification job leased across the
  request ends at its next attempt, before the bytes are read, without
  asking the verifier. No release that starts after the request
  commits serves the version; a download admitted before it may finish (see
  Residual risk).
- Grant expiry and revocation erase nothing. The grace is frozen at the
  request from the policy's `cleanupGraceHours`; changing the policy later
  moves no due time.
- A rejection arms the erasure of the rejected bytes in the transaction that
  records the verdict, due after the policy's `cleanupGraceHours` (the
  version's upload window when the policy is no longer declared), and the
  same sweep erases them. The version reads `rejected`, then `erased`. A
  dead-lettered verification is not a verdict and keeps its bytes for a
  replay (DOCUMENTS-DEC-21).
- The sweep arms one erasure job per due version on
  `registry-platform-dispatch` and records `erased` only in the transaction
  that deletes the content row (PostgreSQL) or after every committed S3
  object answered 404 to a read following its delete. An unconfirmed delete
  leaves the version pending and the job retries for about seven days, then
  dead-letters and is not re-armed.
- A job lease, `FOR UPDATE SKIP LOCKED` batches, and conditional updates
  (`WHERE erasure_state = 'pending'`) make a crash mid-batch resume without
  erasing twice or stranding a version.
- `cleanup.erasure: paused` stops the erasure worker, the arming, and the
  orphan sweep; serving, removal requests, and upload expiry continue.
- Upload expiry runs on every pass: a reservation whose upload window
  (`upload_expires_at`, the reservation time plus the policy's
  `cleanupGraceHours`) lapsed is expired and takes no more bytes. On S3,
  an uncommitted object older than the longest transfer deadline plus ten
  minutes is deleted, and its staging row with it. An upload whose commit
  arrives after that finds no staging row and is refused, so no object is
  left that no row names. An object whose delete fails is skipped for the
  rest of the pass and counted, the count logged once per pass, and the
  next pass retries it.
- Every foreign key in the schema is `ON DELETE RESTRICT`, with the choice
  stated beside it. Erasure deletes bytes and keeps documents, versions,
  grants, verification history, and idempotency receipts. One CHECK holds
  the erasure state and its timestamps together, another refuses a
  releasable version under removal, and every nullable comparison in a
  CHECK is guarded with `IS NOT NULL`.
- Removal requests, erasure outcomes, upload expiry, and orphan erasure are
  audited with `begin` before the change and `finish` after it. An upload
  expiry batch or an orphan's staged-row deletion that does not commit
  finishes its entry as `failed` before the pass reports the error, and the
  next pass retries it.

### Tests

`crates/registry-documents/tests/postgres_documents.rs` and
`crates/registry-documents/tests/postgres_s3.rs` under the `postgres-test`
feature; the S3 suite's fake store can fail a delete, accept a delete it
does not honour, and store an object while answering 503. The unit tests in
`registry-documents-core/src/access.rs` and `src/erasure.rs` cover removal
standing and the erasure retry window. `contracts/security-test-traceability.yaml`
names each test.

### Residual risk

- "Erased" means the Store can no longer serve the bytes. PostgreSQL keeps
  them on disk after the delete: vacuum only marks the space reusable, so
  the bytes stay on their pages until overwritten or until `VACUUM FULL`
  rewrites the table. Backups, WAL archives, replicas, and S3 bucket
  versioning or replication outside the Store's key keep them for as long
  as the operator retains those copies.
- A download admitted before the removal request commits is not
  interrupted: `release` holds no transaction across the transfer, so it
  may finish after the commit, within its transfer deadline. The same
  window applies to a revoked grant (DOCUMENTS-DEC-11); both are proven by
  `a_transfer_admitted_before_a_revocation_completes`.
- Restore caveat: erasure requests and erasures newer than a backup are
  lost on restore unless the audit file is restored too and its requests
  are repeated. The restore drill in `README.md` runs with serving stopped
  and erasure paused.
- A version whose erasure dead-lettered stays pending and unservable until
  an operator replays it with `documentsctl erasure replay`; `documentsctl
  erasure status` counts the dead letters and `erasure list` names them.
- The Rust client has no method for the erasure route yet.
- Removal ends every active grant on the document whatever state its
  version is in. The document row records the first request, so a removal
  after a rejection is a first removal: it revokes the grants issued while
  the version was approved, and the version keeps the rejection's due time.
  Only a repeat of a recorded removal changes nothing
  (`removing_a_rejected_document_revokes_its_grants`). A rejection alone
  revokes no grant: a grant on a rejected version releases nothing and
  stays listed as active until it expires or is revoked.
- A paused deployment keeps due bytes for as long as it stays paused, and
  orphan S3 objects accumulate meanwhile.

## Document events for after-commit observers (2026-10-22)

### Threat

An observer learns more about a document or the person it describes than
the event needs, or hears about documents held under a policy it was never
meant to observe; an observer is told about a transition that never
committed; a slow or hostile observer delays or blocks a verdict or a grant
change; a project author runs code inside the Store or chooses where events
go; an observer's answer changes a document, a version, or a grant.

### Enforcement and defaults

- Three triggers, `document-version.ready`, `document-version.rejected`, and
  `document-grant.changed`, each with a closed field inventory. A hook
  projects a subset of it, and the project reader and hook compilation refuse
  any other field (DOCUMENTS-SEC-48). No field carries content, a label, a
  media type, a name, a subject, or anything about the described person.
  `actorKind`, only `service` or `human`, appears on grant events alone
  (DOCUMENTS-DEC-30). Each family
  publishes a generated closed data schema under `generated/events/`
  (DOCUMENTS-DEC-32).
- Each hook declares the policies whose documents it hears about; a required,
  non-empty list of declared policies, reviewed with the package. Capture
  matches the trigger and the document's policy, so a hook never reports a
  document under a policy it does not name (DOCUMENTS-SEC-48,
  DOCUMENTS-DEC-33). Routing by custodian is not offered.
- The envelope subject carries the record's revision, which every recorded
  change of a version or a grant raises by one, so a receiver can order
  events about one record (DOCUMENTS-DEC-27).
- The outbox and delivery rows are written in the transaction of the verdict,
  the grant issue, the grant revocation, or the removal request that revokes
  a version's grants, so a rollback reports nothing; a capture that cannot
  be written or committed fails the transition (DOCUMENTS-SEC-49,
  DOCUMENTS-DEC-29). Only a change of state emits: a repeated verdict, an
  issue replay, a repeated revocation, and a repeated removal do not. A
  removal emits one revoked event for each grant it revokes. Grant expiry is
  not a recorded transition and emits nothing; the `issued` event carries
  `expiresAt` (DOCUMENTS-DEC-28).
- Delivery runs after commit in the shared `registry-platform-hooks` worker:
  a signed Version 1 envelope with source
  `urn:registrystack:documents:<project id>` and type the hook id
  (DOCUMENTS-DEC-27), under the destination's timeout (100 to 10000 ms) and
  attempt budget (1 to 20), with backoff from 30 seconds to an hour, then a
  dead letter. Delivery never touches the transition (DOCUMENTS-SEC-50).
- Hooks accept only the shared URL-only capabilities: `phase: after`, a `url`
  handler, no `when`, no `principal` (DOCUMENTS-SEC-51). Every proposal an
  observer returns is refused and recorded as
  `documents.hook.proposal-unsupported` (DOCUMENTS-SEC-52).
- A hook names only a destination id; the URL, the signing key reference,
  the timeout, and the attempt budget come from `destinations.hooks` in the
  operator's runtime configuration. Startup refuses an unbound destination,
  an unresolved key, and a retained delivery whose binding no longer matches
  (DOCUMENTS-SEC-53). Plain `http` needs both a loopback address and the
  `development-loopback` listener. A pending delivery pins its binding, so a
  hook moves to a new URL or key under a new destination id while the old
  entry stays until its deliveries drain or expire (DOCUMENTS-DEC-31).
- Hooks are part of the package, so changing one takes `documentsctl apply`;
  the delivery tables come with the embedded schema, and a split runtime role
  is granted them with the rest of what serving needs (DOCUMENTS-DEC-31).
- Each delivery attempt and its outcome are written to the Document Store
  audit journal as `documents.hook-delivery`, carrying ids, the package
  digest, and the outcome, never the payload.

### Tests

`crates/registry-documents/src/hooks_tests.rs` covers compilation refusals,
projections, the published schemas, and destination activation without a
database. `crates/registry-documents/tests/postgres_hooks.rs` runs capture,
rollback, a capture whose commit fails, removal events, policy scoping,
revisions, delivery to a local receiver, proposal refusal, retry and dead
letter, a binding pinned by a pending delivery, and a split runtime role
against a disposable database under the
`postgres-test` feature. `contracts/security-test-traceability.yaml` names
each test under DOCUMENTS-SEC-48 to DOCUMENTS-SEC-53.

### Residual risk

- An observer learns that a document exists, when it became ready or was
  rejected, and when grants on it change, keyed by stable ids. Bind only
  destinations entitled to that timing.
- Grant expiry produces no event. A receiver that forgets the `expiresAt` an
  `issued` event carried treats an expired grant as live until it is
  revoked.
- Terminal delivery rows and their payloads are not yet pruned; a captured
  payload stops being sent after `retention.hookPayloadRetentionDays` but
  stays in the database until pruning lands.
- A database activated before the delivery tables were part of the embedded
  schema does not gain them; pre-1.0 deployments are recreated.
