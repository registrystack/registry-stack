# Registry Document Store changelog

## Unreleased

The Document Store is held out of releases.

- The product skeleton: `registry-documents-core`, the `registry-documents`
  runtime and `documents` binary, `registry-documentsctl` and the
  `documentsctl` binary, and the `registry-documents-client` Rust client.
- `DocumentsProject` and `DocumentsRuntimeConfig` formats at `v1alpha1`, with
  generated JSON Schemas, starter examples, and `documentsctl check`.
- The runtime checks its whole configuration before it binds, confirms its
  database answers, and serves only `GET /health`; every other route answers
  `request.not-found`.
- The `registry-documents` problem vocabulary is published in the identifiers
  catalog.
- Document custody under a document policy: reservation refuses an unknown
  policy, a size above the policy or deployment ceiling, a media type outside
  the policy list, and a custodian over its per-policy byte quota, before any
  byte moves.
- Content upload hashes and bounds the body while reading it, finalizes only
  when digest and length match the reservation, and keeps nothing otherwise.
  Concurrent uploads to one reservation finalize once.
- PostgreSQL `bytea` storage, or S3 storage through the shared object storage
  block, with the storage binding pinned at the first upload. Identical
  content uploaded twice is stored twice.
- Content verification on dispatch through the shared HTTP verifier, with
  backoff for about seven days before a job dead-letters. A version is
  released only on an approved verdict bound to its digest, media type, and
  the current verifier binding; a verifier change at restart suspends and
  re-verifies.
- Download checks stored content against its digest before the first byte
  and refuses a mismatch.
- Audit entries for reservation, upload, verification, and download.
- Verification under mixed verifier bindings: a worker under another binding
  retries a job rather than ending it, a restart cancels the jobs it
  supersedes, a verdict that records nothing is retried, and the database
  refuses a releasable version whose verdict binding is not its current one.
  S3 storage is activated once at startup, and an empty reservation is
  refused as `request.unprocessable`.
- Every document route is served behind bearer access-token verification
  through `registry-platform-oidc` and access-profile resolution. Access
  profiles gain an optional `institution`, recorded as the issuing
  institution of every document reserved under the profile.
- Custody placement follows the policy's `custodyProfiles`: a service may
  name any custodian, a human only itself (`custody.not-permitted`).
- `POST /documents` and grant issue take a required `Idempotency-Key`,
  answering `idempotency.key-reused` for another body and
  `idempotency.expired` after `retention.receiptRetentionDays`. A repeated
  upload of the same content answers the finalized view.
- Document grants: issue, list, received list, and revoke, each naming one
  exact version, one recipient, and an expiry fixed at issue. Download
  releases only to the custodian or an active grant holder, and every other
  caller gets a uniform `resource.not-found`.
- `GET /document-policies` lists the policies a caller may reserve under,
  with their bounds. Lists page by cursor in a stable order, at most 100
  items a page. Documents carry an optional, untrusted `label`.
- Document policies carry a required `custodian` rule: `institution`
  keeps custody with the reserving service and records a named person as
  the represented principal only; `represented-principal` places custody
  in the named person.
- A grant request names the recipient's actor `kind`, and release matches
  it. The owning system that is not the custodian gets
  `profile.not-authorized` on download.
- One transfer budget for uploads, downloads, and verification, and a
  per-transfer deadline set by the new `transfers` runtime block
  (`minimumDeadlineSeconds`, `mebibyteAllowanceSeconds`).
- New problem codes `custody.not-permitted`, `idempotency.key-reused`,
  `idempotency.expired`, and `resource.not-found`.
- The OpenAPI document describes every route with its bearer security.
- `documentsctl init`, `package`, `plan`, `apply`, and `status`. `apply`
  applies the schema over the migration credential, records the verified
  package digest in an activation ledger, and grants the runtime role;
  `serve` refuses a database with no active package, one recorded for
  another `identity.databaseId`, or one whose active package is not the
  configured one.
- `documentsctl verification list` and `verification replay` show
  dead-lettered verification jobs and return one to pending under its next
  generation, audited in the `documentsctl` companion journal.
- Removal from custody: `POST /documents/{documentId}/erasure`, custodian
  only, suspends release, revokes the document's active grants, cancels
  pending verification, and schedules erasure after the policy's
  `cleanupGraceHours`. Removing a rejected document still revokes its
  grants. Grant expiry and revocation erase nothing.
- A rejected version's bytes are erased `cleanupGraceHours` after the
  verdict; the version reads `rejected`, then `erased`. A dead-lettered
  verification keeps its bytes for a replay.
- `cleanupGraceHours` is at least 1; a project that sets it to 0 is refused.
- A cleanup sweep expires lapsed uploads, erases due versions through a
  dispatch job (PostgreSQL row deletion, or S3 delete confirmed by a 404),
  and, on S3, deletes objects abandoned uploads left behind. A version is
  recorded erased only once the Store can no longer serve its bytes.
- `cleanup.erasure: paused` halts erasure without halting the runtime.
- Every foreign key is `ON DELETE RESTRICT`; erasure keeps documents,
  versions, grants, and verification history.
- `products/documents/README.md` gains a restore drill.
