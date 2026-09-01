# Registry Relay and Server Rust client

`registry-relay-client` is the canonical Rust SDK for the fixed Registry Relay
V2 HTTP API and Registry Server discovery, record, and mutation surfaces. The
crate name is retained for source compatibility. Relay and Server share the
Registry Record v1 response model, while product-specific routes, queries,
Problems, entity tags, and credential policies remain separate.

One method call performs at most one HTTP exchange. The client does not follow
redirects, use ambient proxies, retry, advance pagination, or fetch referenced
schemas. Callers remain responsible for deciding whether and when to repeat a
request.

The Rust crate supports both products. The Node and Python packages remain
Relay-only in this slice.

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

## Registry Server discovery, reads, and writes

Use `RegistryServerClient` for Server routes. Its API is additive and does not
change `RelayClient` behavior:

```rust,no_run
use std::sync::Arc;
use registry_relay_client::{
    RegistryServerClient, RegistryServerClientConfig, ServerListRequest,
    ServerRecordFormat, ServerRecordOptions, StaticToken,
};
use url::Url;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let token = Arc::new(StaticToken::new("short-lived-access-token")?);
let config = RegistryServerClientConfig::new(
    Url::parse("https://server.example/institution-a")?,
)
.with_token_provider(token);
let client = RegistryServerClient::new(config)?;

let options = ServerRecordOptions::default()
    .access_profile("caseworker.v1")?
    .select(["legalName", "status"])?
    .format(ServerRecordFormat::JsonLd);
let request = ServerListRequest::default().options(options).top(25)?;
let first = client.list_records("companies", &request).await?;
if let Some(next) = first.value.continuation {
    // The opaque continuation carries only route, representation, profile,
    // and $skiptoken facts. It cannot admit first-page query parameters.
    let _next_page = client.continue_list(&next).await?;
}
# Ok(())
# }
```

The Server client covers credential-free health and readiness, caller-filtered
OpenAPI, typed Registry Metadata v1, entity schemas, canonical UUID record
reads, list, explicit continuation, lookup, direct Create and PATCH, and all
seven change-request lifecycle actions. Revisions, snapshots, relationships,
GIS/GeoJSON, batch operations, webhooks, immediate actions, and administrative
routes remain outside the typed client surface.

Server OpenAPI, metadata, schemas, and record operations may use one configured
bearer token. Health and readiness never acquire one. An `accessProfile` is a
disclosure selector, not authority, and the client never retries or falls back
after a concealed response.

Server record responses use the shared `RegistryRecordSingleResponse` and
`RegistryRecordCollectionResponse` DTOs. Ordinary JSON must omit `@context`;
Server JSON-LD must use the exact scalar Registry Record context. The client
validates canonical UUIDs and revisions, the exact Registry Record profile and
relative `describedby` Link, and Server `"rs-..."` ETags. It treats context,
schema, and Link targets as inert identifiers and never fetches them.

### Capability-driven direct writes

Fetch caller-filtered metadata with `registry_contract`, then select one exact
operation identifier and access profile. Legacy entity summaries and writable
field lists cannot authorize a write by themselves. A binding is executable
only when its method, route, request contract, operation kind, capabilities,
registry, primary dataset, entity, profile, registry revision, and client
origin form a complete known contract.

```rust,no_run
use registry_relay_client::{
    RegistryServerDirectWrite, RegistryServerIdempotencyKey,
    ServerCreateRequest, ServerPatchRequest, ServerRecordFormat,
};
use serde_json::{Map, json};
use uuid::Uuid;

# async fn run(client: &registry_relay_client::RegistryServerClient) -> Result<(), Box<dyn std::error::Error>> {
let contract = client.registry_contract(Some("company-writer")).await?;
let create = match contract.value.select_direct_write(
    "records.company.create",
    "company-writer",
)? {
    RegistryServerDirectWrite::Create(binding) => binding,
    RegistryServerDirectWrite::Patch(_) => unreachable!(),
};
let request = ServerCreateRequest::new(Map::from_iter([
    ("legalName".to_owned(), json!("Example Ltd")),
]))?;
let key = RegistryServerIdempotencyKey::parse("create-company-123")?;
let created = client
    .create_record(&create, &request, &key, ServerRecordFormat::Json)
    .await?;

// PATCH requires an ETag returned by a fresh read through the same route and
// access profile. Do not use a lifecycle action If-Match value here.
let patch = match contract.value.select_direct_write(
    "records.company.patch",
    "company-writer",
)? {
    RegistryServerDirectWrite::Patch(binding) => binding,
    RegistryServerDirectWrite::Create(_) => unreachable!(),
};
let patch_request = ServerPatchRequest::builder()
    .replace("legalName", json!("Example Company Ltd"))?
    .build()?;
let patch_key = RegistryServerIdempotencyKey::parse("patch-company-123-v2")?;
let record_id = Uuid::parse_str(&created.value.data.record_identifier)?;
let etag = created.metadata.etag().expect("create returns an ETag");
let _updated = client
    .patch_record(
        &patch,
        record_id,
        etag,
        &patch_request,
        &patch_key,
        ServerRecordFormat::Json,
    )
    .await?;
# Ok(())
# }
```

The builders validate API field names, permissions, required Create fields,
whole-field JSON Patch paths, operation counts, I-JSON values, and encoded body
size before token acquisition or HTTP I/O. The client never generates an
idempotency key and never retries a mutation. If a caller retries after an
unknown outcome, it must reuse the same operation binding, body, precondition,
representation, and idempotency key. A changed registry metadata revision or a
fresh `412 precondition.failed` response requires an explicit metadata or
record refresh and a new user decision.

### Change-request lifecycle

Change-request records use the shared Registry Record envelope with a
Server-owned `request` extension. Select lifecycle authority from the same
caller-filtered metadata, then promote only the actor-bound actions returned on
a fresh record:

```rust,no_run
use registry_relay_client::{
    RegistryServerIdempotencyKey, RegistryServerLifecycleOperation,
    ServerRecordOptions,
};

# async fn run(client: &registry_relay_client::RegistryServerClient) -> Result<(), Box<dyn std::error::Error>> {
let profile = "case-reviewer";
let contract = client.registry_contract(Some(profile)).await?;
let authority = contract.value.select_lifecycle("case", profile)?;
# let record_id = "00000000-0000-4000-8000-000000000001";
let record = client
    .get_record(
        "cases",
        record_id,
        &ServerRecordOptions::default().access_profile(profile)?,
    )
    .await?;
let action = client
    .lifecycle_actions(&authority, &record.value)?
    .into_iter()
    .find(|action| action.operation() == RegistryServerLifecycleOperation::ApproveRequest)
    .expect("the caller is currently offered approve");
let key = RegistryServerIdempotencyKey::parse("approve-case-123-v7")?;
let _receipt = client.execute_lifecycle_action(&action, &key).await?;

// Refetch before showing or attempting the next transition. The receipt is a
// distinct lifecycle shape, not a Registry Record or a new action authority.
# Ok(())
# }
```

Submit, approve, reject, request revision, revise, cancel, and apply are
supported. Promotion binds the metadata revision, selected profile, entity,
primary dataset, record UUID and revision, exact relative action href,
action-specific strong `If-Match`, stage, proposal version, effect digest,
review snapshot, and retention shape. A receipt must carry the expected next
record revision.
Lifecycle action ETags are never interchangeable with record ETags. A retry
after an unknown outcome must reuse the exact promoted action and key. After a
success or refusal, refetch the record before deciding what is possible next.

Caller-filtered immediate-action metadata is exposed only as bounded inert
JSON. Registry Server does not yet supply a protocol discriminator plus a
server-checked contract fingerprint on target-condition and invoke requests,
so stale activation metadata cannot be bound safely across the final request.
The Rust client therefore provides no generic immediate-action invocation API
and fails closed instead of guessing one.

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
