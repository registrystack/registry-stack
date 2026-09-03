# Base Registry Engine Rust client

`registry-breg-client` is the canonical bounded Rust client for Base Registry
Engine. Its public API uses the BReg technical family and the
`BaseRegistryClient` entry point.

One method performs at most one explicitly initiated HTTP exchange. The client
does not follow redirects, use ambient proxies, retry, advance pagination, or
fetch referenced resources.

## Configure a client

```rust
use std::sync::Arc;
use registry_breg_client::{
    BaseRegistryClient, BaseRegistryClientConfig, StaticToken,
};
use url::Url;

# fn build() -> Result<BaseRegistryClient, Box<dyn std::error::Error>> {
let token = Arc::new(StaticToken::new("short-lived-access-token")?);
let config = BaseRegistryClientConfig::new(
    Url::parse("https://breg.example/institution-a")?,
)
.with_token_provider(token);
let client = BaseRegistryClient::new(config)?;
# Ok(client)
# }
```

The base URL may include a deployment prefix. HTTPS is required except for
loopback HTTP. Credentials, queries, fragments, and ambiguous empty path
segments are refused at construction.

Health and readiness never acquire a token. Caller-filtered OpenAPI, metadata,
schemas, record operations, and lifecycle actions may use one configured token.

## Read records

```rust,no_run
use registry_breg_client::{BRegListRequest, BRegRecordFormat, BRegRecordOptions};

# async fn run(client: &registry_breg_client::BaseRegistryClient) -> Result<(), registry_breg_client::BaseRegistryClientError> {
let options = BRegRecordOptions::default()
    .access_profile("caseworker.v1")?
    .select(["legalName", "status"])?
    .format(BRegRecordFormat::JsonLd);
let request = BRegListRequest::default().options(options).top(25)?;
let first = client.list_records("companies", &request).await?;
if let Some(next) = first.value.continuation {
    let _next_page = client.continue_list(&next).await?;
}
# Ok(())
# }
```

The opaque continuation carries only its route, representation, profile, and
skip-token facts. First-page query parameters cannot be combined with it.

## Registry Record profile

BReg uses the neutral `registry-record` DTOs for ordinary JSON and JSON-LD
Registry Record responses. The shared decoder rejects duplicate JSON members,
unknown envelope members, invalid identifiers, and inconsistent collection
metadata. BReg-specific response metadata, ETags, operations, and lifecycle
extensions remain in this crate.

## Writes and lifecycle actions

Fetch caller-filtered Registry Metadata before selecting an exact direct-write
or lifecycle binding. A write binding is executable only when its method,
route, request contract, operation kind, capabilities, registry, primary
dataset, entity, profile, revision, and client origin form a complete known
contract.

Builders validate API field names, permissions, required create fields,
whole-field JSON Patch paths, operation counts, I-JSON values, and encoded body
size before token acquisition or HTTP I/O. The client never generates an
idempotency key and never retries a mutation.

Lifecycle action ETags are not interchangeable with record ETags. After a
success or refusal, refetch the record before deciding which transition is
currently available.

## Response security

Before returning a body, the client enforces bounded headers and body, exactly
one canonical lower-case W3C Trace Context v0 `traceparent`, BReg's exact
response media type, and the closed BReg Problem vocabulary. Registry Metadata
and lifecycle JSON are decoded with strict duplicate-member rejection.

Errors retain fixed local reasons, public status or problem codes, validated
trace identifiers, and bounded retry guidance. They do not retain credentials,
selectors, response bodies, header values, URLs, or transport error chains.
