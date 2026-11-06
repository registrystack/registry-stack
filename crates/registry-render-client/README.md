# Registry Render client

A bounded client for the optional Render HTTP adapter. It shares no runtime
code with the rendering library. Configure a resource-specific bearer token,
then call `RenderClient::render` once with a document type and the HTTP request
object. It requests the JSON PDF representation, validates its checksum,
requires matching response trace context, and checks the bounded product
problem envelope. It follows no redirects or ambient proxies. Every digest is
labelled, `sha256:<hex>`: a `RenderedDocument` carries `pdf_digest`, checked
against the bytes, and `data_digest`, beside their deprecated bare hex
`pdf_sha256` and `data_sha256`, which must agree with them.

Known RFC3339, asset name, base64, JPEG/PNG prefix and size errors are refused
before a language facade asks its provider for a token. The client permits a
body up to 8 MiB, with 2 MiB per asset; the serving adapter's default request
ceiling remains 1 MiB and can be configured up to 8 MiB. The server owns document
schema and locale selection. Successful `documentVersion` must name the
requested type and its unsigned version.

`RenderClientError` exposes the shared `TransportKind` and `is_outcome_unknown()`.
A refused connection establishes no exchange; a timeout, broken response or
invalid protocol response may follow a completed render. Rendering remains a
pure calculation and establishes no issuance authority. Retain the exact
inputs when deciding whether to repeat it.

The method performs one exchange. Its optional `correlation_key` (1 to 128
visible ASCII characters) is sent as `Idempotency-Key` and must be echoed
exactly. Render's correlation key offers no durable idempotency, so this
client adds no mutation retry. Pure CLI and library rendering require neither
this client nor an issuer.

## Sealing

`RenderClient::seal` calls `POST /v1/seal/{type}` with the render request body
and a credential carrying the `render:seal` scope. The route exists only when
the server configures seals; otherwise the answer is the `render.not-found`
problem. It returns a `SealedDocument`: the signed PDF bytes, `document_digest`
(the first revision), `signed_file_digest` (the whole file), `data_digest`,
`document_version`, `package_digest` (the package, in the form
`package.expectedDigest` takes, so a sealing client needs no `render:render`
to pin it), warnings, and `seal` facts (`id`, a `SealLevel` of `BaselineB` for
`B-B` or `BaselineT` for `B-T`, `certificate_digest`, `timestamped_at`, the
timestamp authority's time, at `B-T` only, and `test_only` for a seal the
server declares `trust: test-only`). There is no `pdfDigest`.

A success body may carry members this client does not know; it ignores them
and still checks every member above. `SealedDocument`, `SealFacts` and
`SealLevel` are `#[non_exhaustive]`, so a later member or level is not a
breaking change; a level this client does not know is refused as `protocol`.

Before returning, the client checks that every digest is labelled, that the
bytes hash to `signedFileDigest`,
that `documentDigest` is the hash of a prefix ending at one of the file's
`%%EOF` markers (found by byte search, not PDF parsing), and that the facts fit
the level. It does not validate the signature, the certificate chain or the
timestamp token; that stays with the relying party.

Sealing is never resent. A second seal is a second valid file with another
signing time, so after an uncertain exchange (`is_outcome_unknown()`) the
caller decides. The optional `correlation_key` is the same as `render`'s: sent
as `Idempotency-Key`, echoed exactly, and not a deduplication promise. The
seal route's problem codes are `render.signing-unavailable`
and `render.seal-certificate-invalid` (503), `render.timestamp-failed` (502),
`render.document-not-sealable` (400) and `render.seal-client-not-allowed` (403).

The Node and Python bindings call `seal` too. They return the sealed document
as JSON with the server's member names (the PDF as `pdfBase64`), which is how
`SealedDocument` serializes, and check the correlation key with
`RenderClient::validate_correlation_key` before acquiring a token.

Run `cargo test --locked -p registry-render-client` for the HTTP boundary tests.
