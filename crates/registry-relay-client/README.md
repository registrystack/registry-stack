# Registry Relay Rust client

`registry-relay-client` is the canonical bounded Rust client for the fixed
Registry Relay V2 HTTP API. Product-specific BReg routes, request types,
Problems, and entity tags are owned by `registry-breg-client`.

One method performs at most one explicitly initiated HTTP exchange. The client
does not follow redirects, use ambient proxies, retry, advance pagination, or
fetch referenced resources.

The existing Relay-only Node and Python package names are unchanged.

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

The base URL may include a deployment prefix. HTTPS is required except for
loopback HTTP. Credentials, queries, fragments, and ambiguous empty path
segments are refused at construction.

The token provider is optional. When present, it is called once for an
auth-eligible request. `health`, `ready`, and `openapi` never acquire or send a
token.

## Consultation

```rust,no_run
use registry_relay_client::{
    Conditional, ListRequest, RecordFormat, RecordOptions, ResourceListRequest,
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
        let _next_page = client.continue_collection(&next, None).await?;
    }
}
# let _ = resources;
# Ok(())
# }
```

A continuation is an opaque cursor bound to its Relay route, representation,
and access profile. The caller must initiate every subsequent page request.
List, lookup, search, SDMX, metadata, OpenAPI, and artifact inputs remain
separate closed request types.

## Registry Record profile

Relay uses the neutral `registry-record` DTOs for ordinary JSON and JSON-LD
Registry Record responses. The shared decoder rejects duplicate JSON members,
unknown envelope members, invalid identifiers, and inconsistent collection
metadata. Relay-owned extensions and GeoJSON remain Relay-specific types.

## Conditional responses

Cacheable operations return `Conditional<T>`. A complete response may carry a
validated `StrongEtag`. A `304` response must echo the requested tag and carry
an empty bounded body.

## Response security

Before returning a body, the client enforces bounded headers and body, exactly
one canonical lower-case W3C Trace Context v0 `traceparent`, and the route's
exact response media type. A Relay Problem must match the closed Relay HTTP
contract, including status and header/body trace equality.

Errors retain fixed local reasons, public status or problem codes, validated
trace identifiers, and bounded retry guidance. They do not retain credentials,
selectors, response bodies, header values, URLs, or transport error chains.
