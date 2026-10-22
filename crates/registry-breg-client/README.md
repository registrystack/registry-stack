# Base Registry Engine Rust client

`registry-breg-client` is the canonical bounded Rust client for
Base Registry Engine (BReg). Its public API uses the BReg technical family and the
`BaseRegistryClient` entry point.

One method performs one explicitly initiated HTTP exchange, except that a
keyed mutation whose outcome is unknown is resent under the same key (see
[Unknown outcomes and the same-key retry](#unknown-outcomes-and-the-same-key-retry)).
The client does not follow redirects, use ambient proxies, advance pagination,
or fetch referenced resources.

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
schemas, record operations, Actions, and Proposals may use one configured token.

When a service forwards a human access token, derive a caller-scoped client
instead of constructing another transport:

```rust,no_run
use registry_breg_client::BearerToken;

# async fn run(client: &registry_breg_client::BaseRegistryClient) -> Result<(), Box<dyn std::error::Error>> {
let caller = client.with_bearer_token(BearerToken::new("forwarded-access-token")?);
let metadata = caller.registry_contract(Some("caseworker.v1")).await?;
# let _ = metadata;
# Ok(())
# }
```

The derived value reuses the original connection pool and leaves the original
client's configured credential unchanged. Each derived value owns its token, so
different callers can use the same base client concurrently without a mutable
credential slot. Keep it within the inbound request that supplied the token.

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
operations, Actions, Proposal capabilities, and optional caller-filtered
statistical dataset descriptions. `BRegMetadata::statistical_datasets()` returns
validated inert JSON; release-only readers can receive these descriptions with
no entities or entity operations. Descriptions grant no entity authority.
`select_action`, `select_batch`, and `select_tombstone`
require complete executable contracts bound to the source, profile, and package.
A descriptor the engine does not serve is absent, and an absent executable
contract produces an unsupported selection error. Metadata decoding ignores
unknown object members while retaining duplicate-member and resource-bound refusals. An unknown
`requiredCapabilities` value disables only the operation that names it.
Well-formed unsupported statistical vocabulary omits only the affected dataset;
unsupported descriptive selector or spatial vocabulary omits only that
capability. An unsupported temporal mode keeps its `temporal`
descriptor as served and uninterpreted, because null already means the
collection is not temporal. Unsupported executable vocabulary remains inert until
exact selection. Known field shapes, references, identities, and disclosure grants
remain strict. See `products/breg/metadata.md` for the failure scopes.

Immediate action target conditions are an explicit read before invocation;
invocation never refreshes them. Batch builders send one atomic same-entity
create/patch request, with per-item conditions and optional batch-level correction
context. Batch responses have a dedicated snapshot/results type. Tombstone
returns a native revision envelope and removes the record from live lists while
permitted retained history remains readable.

An immediate Action with reference inputs may advertise an optional
`routes.availability` contract. Build `BRegActionAvailabilityRequest` from the
selected opaque Action binding, one reference input's API name, and any supplied
input subset, then call `action_availability`. The target reference must be a
present canonical UUID. Every supplied value is validated before credentials or
I/O, but unrelated required form inputs may remain absent. The result distinguishes
available, guard-not-satisfied, input-required, and not-disclosed observations.
This unkeyed POST is sent once. It evaluates current field-guard availability
only; invocation remains the authoritative commit check, and a readable guard
failure is the typed 412 `action.guard_failed` problem.

The maintained capability inventory is
`products/breg/contracts/client-capabilities.json`; the BReg client-contract gate
checks it against compiled OpenAPI and Rust, Node, and Python entry points.

## Registry Record decoding

BReg uses the neutral `registry-record` DTOs for ordinary JSON and JSON-LD
Registry Record responses. The shared decoder rejects duplicate JSON members,
unknown envelope members, invalid identifiers, and inconsistent collection
metadata. BReg-specific response metadata, ETags, and operations remain in this
crate. Standalone Proposals have their own response contract.

## Writes and Actions

Fetch caller-filtered Registry Metadata before selecting an exact direct-write
or Action binding. A write binding is executable only when its method,
route, request contract, operation kind, capabilities, registry, primary
dataset, entity, profile, revision, and client origin form a complete known
contract.

Builders validate API field names, permissions, required create fields,
whole-field JSON Patch paths, operation counts, I-JSON values, and encoded body
size before token acquisition or HTTP I/O. The client never generates an
idempotency key.

### Unknown outcomes and the same-key retry

A 5xx answer may follow a commit, and so may a timeout or a broken exchange
after the request was sent. `BaseRegistryClientError::is_outcome_unknown()`
reports those cases, and an oversized or unparseable answer, as true; it is
false for a request or configuration defect, a token failure, a connection
that was never established, every typed 4xx refusal such as
`idempotency.conflict` (409) and `idempotency.expired` (410), and two typed
500 failures:
`action.handler_failed` and `statistical_dataset.domain_violation`. The engine
returns those two only with the attempt rolled back, and the same request
fails the same way, so the client never resends them. `action.evidence_failed`
and `service.unavailable` (503) stay unknown and are resent.

The client resends a keyed mutation (Create, PATCH, attachment upload and
delete, Proposal transitions, immediate Actions, batches, tombstones, and
statistical publication and withdrawal) whose outcome is unknown, with the
same key, headers, and body bytes, at most twice by default, waiting 250 ms
and then 500 ms, or the service's `Retry-After` when that is longer and at
most 5 seconds. A longer requested wait ends the retries. Configure the count
with `BaseRegistryClientConfig::with_maximum_mutation_retries` (0 to 2; 0 disables
the resend). Reads, ingestion run calls, and action target-condition requests
are never resent. Each attempt has the full attempt timeout, so a call can
take up to three attempt timeouts plus the waits.

BReg holds a response under the key only for a committed success, so a resend
after a 5xx either replays that success or runs the operation again.

When the returned error still reports `is_outcome_unknown()`, recover by
sending the same request with the same key. A new key could apply the
mutation twice. A refusal that answers a resend does not prove the earlier
attempt left no effect, so the client then returns the earlier unknown-outcome
error instead of the refusal.

BReg keeps a key spent for good but holds its response only for the receipt
horizon (`retention.receiptRetentionDays`, 7 days by default). The same
request under the same key after that horizon gets `idempotency.expired`
(410) and does not run again: an earlier attempt committed and its response is
gone. `is_outcome_unknown()` is false for it and the client never resends it;
read the resource to learn its current state.

`select_action` selects an Action's declared immediate or Proposal mode.
Immediate Actions use `invoke_action`; Proposal-mode Actions use
`start_proposal`. Proposal transitions are promoted from an authorized
`BRegProposal`, separately from ordinary Registry Record writes. Their
conditions are not record ETags. Read the current Proposal before choosing a
new transition; recover an uncertain command from its original prepared bytes.

Application result references grant no target authority. Read a target through
an ordinary authorized `get_record`; a retained result revision records
application provenance, not the target's current revision or write condition.

## Standalone Proposal observation

A Proposal-mode Action uses `start_proposal` with a
`BRegActionInvocationRequest` to create a draft. `prepare_proposal` and
`execute_proposal` send its promoted `edit`, `submit`, `revise`, `rebase`,
`retry`, `cancel`, or `apply` transition only when available to the caller.
Submit freezes the exact submission. Apply carries `submissionVersion` and
`effectDigest`, with optional `reason` text of at most 4096 Unicode characters
and no NUL. Persist `BRegPreparedProposal` before dispatch; after restart,
`recover_proposal` restores the original condition, body and key under current
ordinary authority. A later status read does not recover an uncertain command.

Recovery requires a freshly authorized Proposal observation, obtained with Get
or as an item from List, and a matching transition or receipt-only recovery link.
The Get flow needs a current `get` grant; an authorized List item can also supply
the observation. Losing all such read access, including access to a current
target row, prevents recovery by that caller. Preserve the evidence for an
authorized operator; do not infer failure or submit the mutation under a new key.

Use `select_proposal_get` on the current `registry_contract`, then use
`get_proposal` for an authorized representation. Its optional `applicationStatus`
reports the retained frozen submission's awaiting-review, pending, applying,
blocked, applied or cancelled state, with closed recovery reasons and bounded
automatic retry progress. A review outcome is never an application reason: the
`apply` link's availability reports `review-rejected`,
`review-changes-requested` or `review-ended`, each with recovery `revise`. Applied state includes the separate exact application evidence. Match
Proposal ID, Action revision, submission version and effect digest before using
that evidence to continue a dependent workflow. A blocked state does not claim
that application can never occur.

When the selected profile also holds the supplemental
`get-application-actor` Proposal operation, Proposal Get and
`read_proposal_submission` include `appliedBy`, the stored keyed actor
pseudonym, and `appliedAt` together in the application member. List omits both.
The client exposes no raw issuer or subject for the applier.

Automatic recovery Apply and Retry require an explicit current grant and a
verified human caller. An observing service gains no recovery authority.
The built-in executor uses its own governed system grant.

`select_proposals` and `list_proposals` read one bounded page; advance its
cursor explicitly. `read_proposal_review_status` and
`read_proposal_review_context` use the Proposal's separately promoted review
links. `upload_proposal_attachment`, `download_proposal_attachment`, and
`delete_proposal_attachment` use its governed slot links, not record fields.
Mutation receipts retain the selected slot. Disclosed upload metadata must match
those exact bytes, media type and length; deletion must not retain a disclosed
value. Get and readable-attachment grants are separate from write authority, so a
successful write may omit value metadata. An omitted value does not independently
prove its stored content. An invalid receipt leaves the mutation outcome unknown;
retain the original condition, bytes and key for same-command recovery.

## Response security

Before returning a body, the client enforces bounded headers and body, exactly
one canonical lower-case W3C Trace Context v0 `traceparent`, BReg's exact
response media type, and a strict BReg Problem envelope. Registry Metadata
and Proposal JSON are decoded with strict duplicate-member rejection. Storage-pattern
conflicts preserve the `MutationConflict` classification; their optional paired
`recordType` and `fieldId` members are bounded, validated and discarded. An
optional `fieldPath` is retained only after it matches BReg's closed grammar and
the known problem code that permits that location. Row-local constraint conflicts
expose `constraint()` as a `BRegConstraintViolation`: bounded `recordType` and
`constraintId`, a closed `constraintKind`, and either `left`/`right` or `field`.
The server omits the entire extension if any referenced field is unreadable.
Unique and temporal non-overlap conflicts remain generic. Node.js and Python
expose the same members in `error.constraint`; Node keeps that property
non-enumerable, and Rust Debug and Python exception messages omit its values.
Unknown object members are
ignored after duplicate rejection; recognized extensions on known codes retain
their existing validation.

A valid unrecognized Problem code returns `UnrecognizedProblem` with only its
HTTP status and trace identifier. Node.js and Python expose kind `problem` with
no code or typed extensions, including for an unknown `404`. Known
`resource.not_found` still exposes `not-found`. Unknown `4xx` outcomes are known
refusals; unknown `5xx` outcomes may have committed and use the existing bounded
same-key retry rules. Malformed envelopes and mismatched status, trace, or BReg
type/code URI still fail as protocol errors. Malformed known codes cannot fall
back to unknown-code handling.

Errors retain fixed local reasons, public status or problem codes, validated
trace identifiers, bounded problem locations, and bounded retry guidance. They
do not retain credentials, selectors, response bodies, header values, URLs, or
transport error chains.

### Explicit recovery across process restarts

`prepare_create` returns inert bounded `BRegPreparedCreate` evidence with
`as_bytes()` and `from_slice()`. Persist it in an owner-only file before sending
the mutation. It contains the request values and caller's idempotency key, has
a redacted Debug representation, and contains no token.

After restart, fetch caller-filtered `registry_contract` again under the same
principal and selected profile. Select the current Create binding, then call
`recover_create`. Recovery requires the same source and registry revision and
revalidates the original request against that authority before returning the
request and original key
for an explicitly initiated send. The runtime remains responsible for current
authorization, preconditions, and exact idempotency replay.

For Actions, Rust callers use `prepare_action` before the first `invoke_action`
or `start_proposal`, then retain `BRegPreparedAction` bytes in the same protected
attempt. After reacquiring metadata under the same principal and profile,
`recover_action` requires the original inputs and idempotency key and restores
the exact opaque target-condition tokens and invocation bytes. It performs no
network exchange and never acquires replacement conditions. `invoke_action` or
`start_proposal` remains the explicit send, including after recovery. The saved
bytes contain input values and must be treated as private application state.

These APIs do not authenticate saved evidence or bind a token provider to a
principal. The application must protect its state and bind attempts to its exact
inputs, selected client/profile, governed package, and database generation.
Reclamation invalidates attempts; a token refresh does not create a new attempt.
Opaque authority handles are never deserialized from saved state.

`record_revisions(route, id, profile)` retrieves at most the newest 100 retained
revisions as inert JSON bytes over the native `/revisions` route. There is no
revision-list continuation. `get_record_revision` retrieves one retained revision
as inert JSON bytes. Standalone Proposal listing uses the separate
`select_proposals` and `list_proposals` contract.

`BRegMetadataOperation::query()` retains typed caller-filtered query
capabilities. Field labels, entity labels, and title fields are descriptive
hints and do not create operation authority. `decode_exact_json` decodes bounded JSON with duplicate
refusal and rejects literals that would silently round. Mutation builders retain
the server's additional integer restrictions. The Node facade offers explicit
JSON text input and result methods for values outside JavaScript's safe range.
