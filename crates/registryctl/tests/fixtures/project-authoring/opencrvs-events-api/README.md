# Synthetic OpenCRVS Events API example

This maintained project exercises Registry Stack's generic OAuth client
credentials, bounded HTTP, and Rhai authoring path against a wholly synthetic
OpenCRVS Events API-shaped search.

It is a non-starter example. It does not add an OpenCRVS connector, select
runtime behavior from `source.product`, contact a country deployment, or prove
compatibility with any OpenCRVS release or configuration.

The reviewed source authority is one read-only
`POST /api/events/events/search` request. The request selects the synthetic
birth event type and one exact synthetic tracking ID, limits the response to
two records, and projects only the event type and registration predicate.

The fixture set covers:

- Exact OAuth JSON request and two-member no-expiry bearer response
- Match, no-match, ambiguity, and exact-selector mismatch
- Source rejection and structurally malformed source data
- Source timeout
- OAuth redirect, media type, token type, extra-member, and expiry rejection

Registryctl's generated fixture cases additionally prove malformed JSON,
response-byte enforcement, authorization before OAuth or source access, request
authority, and output minimization. A raw-response unit test proves malformed
OAuth JSON and duplicate members are rejected before Events API access;
authored YAML cannot preserve those parser cases.
