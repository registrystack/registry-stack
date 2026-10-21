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
- One transfer budget for uploads, downloads, and verification, and a
  per-transfer deadline set by the new `transfers` runtime block
  (`minimumDeadlineSeconds`, `mebibyteAllowanceSeconds`).
- New problem codes `custody.not-permitted`, `idempotency.key-reused`,
  `idempotency.expired`, and `resource.not-found`.
- The OpenAPI document describes every route with its bearer security.
