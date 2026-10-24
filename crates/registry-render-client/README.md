# Registry Render client

A bounded client for the optional Render HTTP adapter. It shares no runtime
code with the rendering library. Configure a resource-specific bearer token,
then call `RenderClient::render` once with a document type and the HTTP request
object. It requests the JSON PDF representation, validates its checksum,
requires matching response trace context, and checks the bounded product
problem envelope. It follows no redirects or ambient proxies.

Known RFC3339, asset name, base64, JPEG/PNG prefix and size errors are refused
before a language facade asks its provider for a token. The client permits a
body up to 8 MiB, with 2 MiB per asset; the serving adapter's default request
ceiling remains 1 MiB and can be configured up to 8 MiB. The server owns document
schema and locale selection. Successful `documentVersion` must name the
requested type and its unsigned version.

`RenderClientError` exposes the shared `TransportKind` and `outcome_unknown`.
A refused connection establishes no exchange; a timeout, broken response or
invalid protocol response may follow a completed render. Rendering remains a
pure calculation and establishes no issuance authority. Retain the exact
inputs when deciding whether to repeat it.

The method performs one exchange. Render's correlation key offers no durable
idempotency, so this client adds no mutation retry. Pure CLI and library
rendering require neither this client nor an issuer.

Run `cargo test --locked -p registry-render-client` for the HTTP boundary tests.
