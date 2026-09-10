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

The opaque continuation carries its route, representation, profile, skip-token,
and the first page's registry, dataset, and entity identifiers. First-page query
parameters cannot be combined with it, and every continued page must retain the
same collection identity.

## Native collection capabilities

Native Point queries use `BRegBoundingBox` and `BRegListRequest::bbox` for JSON,
or the separate `get_geojson_record`, `list_geojson_records`, and
`continue_geojson_list` methods for GeoJSON. Boxes contain exact decimal strings
in west, south, east, north order. Edges are inclusive; zero-area boxes are valid.
The client validates coordinate and wire bounds, and the server enforces the
profile's geometry/query grants and span limits. GeoJSON get responses have no
mutation ETag. The `/v1/gis` QGIS adapter routes are outside SDK scope.

The runnable `native_geojson` example prints each FeatureCollection as one JSON
line. Run it against an existing spatial registry from the workspace root,
replacing the route, profile, box, and owner-only token file with your deployment's
values:

```sh
BREG_BASE_URL=https://registry.example.com \
BREG_ENTITY_ROUTE=establishments BREG_ACCESS_PROFILE=map-reader \
BREG_BBOX=100,13,101,14 BREG_TOKEN_FILE=/path/to/access-token \
cargo run --locked -p registry-breg-client --example native_geojson
```

If the registry refuses the box, inspect the selected profile's parsed spatial
descriptor and request an allowed span. Renew an expired token before retrying
a read. The example advances pages explicitly and does not fetch linked resources.

`BRegCurrentListRequest`, `BRegAsOfListRequest`, `BRegSnapshotListRequest`, and
`BRegRelationshipListRequest` separate route-specific options. Snapshot responses
expose a reusable snapshot reference; their continuations retain it across
writes. Relationship methods take the entity route, source-record UUID, and path
route independently. Temporal and relationship requests reject bbox combinations.

Parsed metadata retains selectors, read paths, vocabulary labels, reference
operations, actions, and change-request capabilities. Descriptions grant no
authority. `select_immediate_action`, `select_batch`, and `select_tombstone`
require complete executable contracts bound to the source, profile, and package.
Optional descriptors may be absent on older servers; absent executable contracts
produce an unsupported selection error. Upgrade clients and servers together
because older strict metadata decoders can reject added descriptors.

Immediate action target conditions are an explicit read before invocation;
invocation never refreshes them. Batch builders send one atomic same-entity
create/patch request, with per-item conditions and optional batch-level correction
context. Batch responses have a dedicated snapshot/results type. Tombstone
returns a native revision envelope and removes the record from live lists while
permitted retained history remains readable.

The maintained capability inventory is
`products/breg/contracts/client-capabilities.json`; the BReg client-contract gate
checks it against compiled OpenAPI and Rust, Node, and Python entry points.

## Registry Record decoding

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

For rejection and requested revision, `action.with_reason("Please correct the submitted values.")?`
returns a copy carrying optional reviewer text. Node uses `action.withReason(text)`
and Python uses `action.with_reason(text)`. Text is preserved exactly, including
empty strings and whitespace; the limit is 4096 Unicode characters and NUL is
refused. Other lifecycle actions refuse reasons. Existing actions omit `reason`.
Persist the prepared action after adding its reason, and reuse the same action
and idempotency key for an explicit retry.

`BRegRequestMetadata::decisions()` exposes typed current-proposal decisions.
`reason_present()` distinguishes an absent reason from one whose text is
withheld or erased; `reason()` returns only disclosed retained text.
`retained_history()` keeps historical decisions as inert JSON. Node and Python
preserve both surfaces in the returned record's `request` extension.

Lifecycle action ETags are not interchangeable with record ETags. After a
success or refusal, refetch the record before deciding which transition is
currently available.

## Response security

Before returning a body, the client enforces bounded headers and body, exactly
one canonical lower-case W3C Trace Context v0 `traceparent`, BReg's exact
response media type, and the closed BReg Problem vocabulary. Registry Metadata
and lifecycle JSON are decoded with strict duplicate-member rejection. Storage-pattern
conflicts preserve the `MutationConflict` classification; their optional paired
`entityId` and `fieldId` members are bounded, validated and discarded. Evidence
dependency failures likewise validate and discard an optional `/evidence/<alias>`
path while preserving `ActionEvidenceFailed`. Other extensions remain refused.

Errors retain fixed local reasons, public status or problem codes, validated
trace identifiers, and bounded retry guidance. They do not retain credentials,
selectors, response bodies, header values, URLs, or transport error chains.

### Explicit recovery across process restarts

`prepare_create` and `prepare_lifecycle_action` return inert bounded evidence
with `as_bytes()` and `from_slice()`. Persist it in an owner-only file before
sending the mutation. The evidence contains request values and the caller's
idempotency key; its Debug representation is redacted. It contains no tokens.

After restart, fetch caller-filtered `registry_contract` again under the same
principal and selected profile. Select the current Create binding or lifecycle
authority, then call `recover_create` or `recover_lifecycle_action`. Recovery
requires the same source and registry revision and revalidates the original
request against that authority before returning the request/action and original
key for an explicitly initiated send. Never replace an uncertain action with a
newly advertised action. Lifecycle recovery retains the original record evidence,
so an applied request whose current record no longer advertises Apply can still
replay the original precondition and body. The runtime remains responsible for
current authorization, preconditions, and exact idempotency replay.

These APIs do not authenticate saved evidence or bind a token provider to a
principal. The application must protect its state and bind attempts to its exact
inputs, selected client/profile, governed package, and database generation.
Reclamation invalidates attempts; a token refresh does not create a new attempt.
Opaque authority handles are never deserialized from saved state.

`record_revisions(route, id, profile)` retrieves at most the newest 100 retained
revisions as inert JSON bytes over the native `/revisions` route. There is no
revision-list continuation. `get_record_revision` retrieves one retained revision
as inert JSON bytes. Proposal history has a separate pagination contract: read
`request.history.nextAfterProposalVersion`, then pass it to record-get options
as `request_history_after_proposal_version` until the returned cursor is null.


`BRegMetadataOperation::query()` retains typed caller-filtered query capabilities,
including the request workflow filter fields advertised by the runtime. Field
labels, entity labels, and title fields are descriptive hints and do not create
operation authority. `decode_exact_json` decodes bounded JSON with duplicate
refusal and rejects literals that would silently round. Mutation builders retain
the server's additional integer restrictions. The Node facade offers explicit
JSON text input and result methods for values outside JavaScript's safe range.
