# registry-notary-client

Typed Registry Notary HTTP client, JSON facade, and language-wrapper boundary
support.

The crate is intentionally strict about transport defaults, authentication
configuration, route-specific retry, bounded response bodies, and redacted error
surfaces.

## Redaction Contract

Client DTOs may expose credential material through typed fields so callers can
store or verify credentials intentionally. They must not expose that material
through incidental formatting surfaces. `Debug`, `Display`, portable errors,
and exception wrappers must omit response bodies, holder proofs, compact
credentials, issuer-signed JWTs, SD-JWT disclosures, OID4VCI nonces, and raw
problem details.

When adding a new response or error family, prefer a redacted `Debug`
implementation or a wrapper whose debug output shows only routing metadata such
as request id, retry headers, status, code, or stable identifiers. Regression
tests should format both success responses and mapped errors with `Debug` and
`Display` and assert that representative credential, proof, disclosure, nonce,
and raw-body fragments are absent.
