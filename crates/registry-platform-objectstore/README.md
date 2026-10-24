# registry-platform-objectstore

Bounded outbound transports a registry runtime keeps content bytes with: an
S3-compatible object store and an external HTTP content verifier. Both read
their configuration from the shared blocks `ObjectStorageConfig` and
`AttachmentVerifierConfig` in `registry-platform-config`, and both take a
namespace from the calling product, so two products never share keys or
bindings by accident.

## What It Provides

- `S3Settings::from_config` and `S3Settings::activate`: one bucket, path-style
  or virtual-hosted, signed with AWS Signature Version 4 over `reqwest`.
  Activation resolves the credentials, computes the binding digest, and probes
  `?versioning=`; a bucket whose versioning was ever enabled or suspended is
  refused.
- `S3ObjectStore::put`, `get`, and `delete`. A write reads the object back and
  checks its SHA-256; a read checks length and SHA-256 before returning bytes;
  a delete is confirmed by a `404` on a following read.
- `S3ObjectStore::scoped`: the store of another scope in the same bucket,
  sharing the activated store's credentials and HTTP client. It resolves and
  sends nothing, so a product that keeps one object per scope activates once
  at startup and derives each object's store from it.
- `ObjectNamespace`: the product's key prefix, binding domain, and object size
  bound. Objects live at
  `{bucket path}/{key prefix}/{sha256(scope)}/{content sha256}`.
- `HttpVerifierSettings::from_config` and `HttpVerifierSettings::activate`,
  and `HttpVerifier::verify`: one `POST` of the exact content bytes, answered
  by `200` with `{"verdict":"approved"}` or `{"verdict":"rejected"}`.
- `VerifierNamespace`: the product's binding domain and content size bound.

The transports own bytes and verdicts only. References, locking, pending
writes, deletion retries, quarantine, and release authority stay with the
calling product and its database.

## Wire contract

S3 requests sign exactly `host`, `x-amz-content-sha256`, `x-amz-date`, and,
when a session token is configured, `x-amz-security-token`. Credentials and
the `authorization` header are marked sensitive.

A verification request carries exactly `authorization: Bearer <token>`,
`content-type`, `accept: application/json`, and `x-content-sha256`, and the
content bytes as the body. The configured `policyId` is never sent: it only
enters the verifier binding digest. The response body is limited to 1024
bytes and must be exactly one `verdict` member.

Each request attempt is bounded by `attemptTimeoutMilliseconds` (default
10000, from 100 to 60000); the connect timeout is the smaller of that and
five seconds.

## Binding digests

- Object storage: SHA-256 of the JSON array
  `[binding domain, bucket URL, region, scope]`, where the scope is the
  product-supplied scope input.
- Verifier: SHA-256 of the JSON array `[binding domain, url, policyId]`.

Neither digest commits to a credential or a timeout, so rotating a secret or
tuning a timeout keeps the binding; moving the bucket, region, verifier URL,
or policy changes it. The calling product records and compares the digest.

## Security review notes

- Scope: the S3 adapter and verifier transport moved here unchanged in
  protocol, headers, timeouts, and refusals from the Base Registry Engine's
  attachment storage and verification. The BReg namespace keeps the key
  prefix `breg`, the binding domains `breg-attachment-s3-v1` and
  `breg-attachment-verification-http-v1`, and therefore the same digests and
  object keys.
- Destinations: `url` must be `https`, or `http` on a loopback address only.
  Userinfo, query, fragment, and (for S3) a non-root path are refused. Virtual
  hosted style refuses IP hosts.
- Outbound client: built by `registry-platform-httputil`'s
  `OutboundClientBuilder`, with rustls, proxies ignored, retries and redirects
  disabled, and an optional exact CA bundle (`caBundleRef`, S3 only).
- Secrets: read through `SecretResolver` only, bounded to visible ASCII, and
  never placed in `Debug`, errors, or logs. Errors are closed enums with fixed
  messages; no URL, object key, credential, or response body reaches them.
- Integrity: every read and write is checked against the expected SHA-256 and
  length; a versioned object (`x-amz-version-id` other than `null`, or
  `x-amz-delete-marker`) is refused, so a deletion cannot leave a recoverable
  older version behind. A body lost or stalled in transit is `Unavailable`,
  not `Integrity`: only a body that arrives and fails its size or digest
  check says something about the stored bytes.
- Fail closed: a verifier timeout, non-`200` status, malformed, duplicate,
  unknown, or oversized verdict is `Unavailable`, never an approval. Invalid
  digests and content types are refused before any request is sent.
- Not covered: the transport never retries; the calling product owns retry
  and quarantine policy and any concurrency limit on outbound calls.
