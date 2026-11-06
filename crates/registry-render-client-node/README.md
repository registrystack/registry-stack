# Registry Render native client

Internal binding used by the unified Registry Stack client. HTTP behavior and
validation belong to `registry-render-client`. The public facade accepts an
explicit token or a resource-bound provider and performs one render or seal
exchange. Every digest is labelled, `sha256:<hex>`. A render returns
`pdfDigest` and `dataDigest` beside their deprecated bare hex `pdfSha256` and
`dataSha256`. A seal returns the signed PDF as `pdfBase64` with the server's
digests, `packageDigest` and seal facts, once the Rust client has checked them.

Request and correlation key validation run before token acquisition. The
optional correlation key is sent as `Idempotency-Key` and checked when echoed;
it is not a deduplication promise. Provider failures retain the
provider's classification. Transport errors expose their shared kind and
whether an exchange may have completed. No automatic retry is added.
