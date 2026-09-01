# Registry Relay Rust client

`registry-relay-client` is the canonical Rust SDK for the fixed Registry Relay
V2 HTTP API. It covers process probes, discovery, consultation operations,
artifacts, and the bounded SDMX data and structure profiles without depending
on the Relay runtime.

One method call performs at most one HTTP exchange. The client does not follow
redirects, use ambient proxies, retry, advance pagination, or fetch referenced
schemas. Callers remain responsible for deciding whether and when to repeat a
request.

## Configure a client

```rust
use std::sync::Arc;
use registry_relay_client::{RelayClient, RelayClientConfig, StaticToken};
use url::Url;

# fn build() -> Result<RelayClient, Box<dyn std::error::Error>> {
let token = Arc::new(StaticToken::new("short-lived-access-token")?);
let config = RelayClientConfig::new(
    Url::parse("https://relay.example/institution-a")?,
)
.with_token_provider(token);
let client = RelayClient::new(config)?;
# Ok(client)
# }
```

The base URL may include a deployment prefix. Each route segment is appended
without replacing that prefix. HTTPS is required except for loopback HTTP.
Credentials, a query, a fragment, and ambiguous empty path segments are
refused at construction.

The token provider is optional. When present, it is called once for an
auth-eligible request. `health`, `ready`, and `openapi` never call it and never
send authorization. `PrivateKeyJwt` and `StaticToken` are re-exported from the
shared platform client primitives.

Explicit access-profile selectors use Relay's bounded lower-case kebab grammar:
ASCII lower-case letters, digits, and single interior hyphens, up to 128 bytes.

## Discovery and consultation

```rust,no_run
use registry_relay_client::{
    Conditional, ListRequest, RecordFormat, RecordOptions,
    ResourceListRequest,
};
# async fn run(client: &registry_relay_client::RelayClient) -> Result<(), registry_relay_client::RelayClientError> {
let resources = client
    .resources(ResourceListRequest::default().page_size(50)?, None)
    .await?;

let options = RecordOptions::default()
    .fields(["name", "status"])?
    .access_profile("caseworker")?
    .format(RecordFormat::JsonLd);
let request = ListRequest::default()
    .options(options)
    .page_size(25)?
    .filter("status", "active")?;

let page = client.list_records("people", &request, None).await?;
if let Conditional::Complete(complete) = page {
    if let Some(next) = complete.value.continuation {
        // Pagination occurs only because the caller explicitly asks for it.
        let _next_page = client.continue_collection(&next, None).await?;
    }
}
# let _ = resources;
# Ok(())
# }
```

A collection continuation is an opaque cursor bound to its route, requested
wire format, and access profile. Its validated serializable projection supports
language bindings and persistence without admitting first-page fields,
filters, bbox, or page size. A caller cannot combine those facts with a cursor.

### Registry Record response profile

Relay's pre-1.0 Registry Record compatibility line places the homogeneous
Registry, dataset, and entity-type identifiers in
`RecordEnvelope.meta` or `RecordCollection.meta`. They are exposed by
`RecordResponseMetadata`, not by `Record`; `Record` contains only the
per-record fields and Relay-owned extensions. This deliberately rejects the
former per-record `registryIdentifier` placement.

For `RecordFormat::JsonLd`, `json_ld_context` is present as a
`RelayJsonLdContext` only when Relay returns exactly the governed two-item
context array. The client verifies its fixed Registry Record context identifier
and that its Relay context matches `meta.links.context`. Ordinary JSON has no
JSON-LD context. GeoJSON remains a separately named media profile with
`GeoJsonRecordProperties` and `RelayRecordMetadata`.

List and named search use distinct first-page types. `ListRequest` permits only
declared equality filters and has no bbox API. `SearchRequest::new(bbox)` makes
the closed point-bbox search input mandatory and exposes no filter API.

Lookups serialize exactly `{"selectors": {...}}`; selector names and scalar
values are bounded before a request is built. List filters cannot collide
with Relay's reserved query names. Field lists reject empty or duplicate names,
and bounding boxes reject non-finite coordinates, invalid latitude/longitude,
south-to-north inversion, and antimeridian crossing.

## Conditional responses

Cacheable operations return `Conditional<T>`. A complete response may carry a
validated `StrongEtag`. Supply that tag to a later call to send
`If-None-Match`:

```rust,no_run
use registry_relay_client::Conditional;
# async fn run(client: &registry_relay_client::RelayClient) -> Result<(), registry_relay_client::RelayClientError> {
let first = client.openapi(None).await?;
if let Conditional::Complete(complete) = first {
    if let Some(etag) = complete.metadata.etag() {
        match client.openapi(Some(etag)).await? {
            Conditional::NotModified(not_modified) => {
                assert_eq!(&not_modified.etag, etag);
            }
            Conditional::Complete(_) => {}
        }
    }
}
# Ok(())
# }
```

Only a strong quoted lower-case SHA-256 tag is accepted. A `304` must echo the
requested tag and have an empty bounded body.

## SDMX and artifacts

```rust,no_run
use registry_relay_client::{SdmxDataFormat, SdmxDataRequest};
# async fn run(client: &registry_relay_client::RelayClient) -> Result<(), registry_relay_client::RelayClientError> {
let request = SdmxDataRequest::new("AGENCY", "FLOW", "1.0.0")?
    .constraint("TIME_PERIOD", "ge:2020+le:2024")?
    .limit(500)?
    .format(SdmxDataFormat::Json);
let document = client.sdmx_data(&request, None).await?;
let artifact = client.artifact("people--list-schema", None).await?;
# let _ = (document, artifact);
# Ok(())
# }
```

The SDMX context is fixed to `dataflow`. Query construction percent-encodes a
literal plus as `%2B`, preserving SDMX range semantics instead of allowing
form decoding to turn it into a space. SDMX and OpenAPI media types are exact.
Artifacts preserve their single syntactically valid, bounded server-declared
media type and otherwise remain raw bytes.

## Response security

Before returning any body, the client enforces bounded headers and body,
exactly one canonical lower-case W3C Trace Context v0 `traceparent`, and the
route's response media type. A Relay Problem must be the exact six-member
document for one `registry-relay-http-contract::ProblemCode`, including exact
status and header/body trace equality. Only a registered `429` may expose one
numeric `Retry-After` from 1 through 60 seconds.

Errors intentionally retain only fixed local reasons, public status/problem
codes, validated trace identifiers, and bounded retry guidance. They never
include credentials, selectors, filters, response bodies, header values, URLs,
or reqwest error chains. Raw response bytes are also omitted from `Debug`.
