# GovStack facade and reusable source packs

## Purpose

Expose selected GovStack Digital Registries Read and direct Write operations through maintained Rust protocol behavior over the shared Adapter engine.
Keep source access reusable by the facade, Evidence and ingestion hosts.
Deployments own their schema-bound transformations and the public views they expose.
This contract selects bounded reads plus synchronous direct Create and conditional Update. It makes no general GovStack conformance claim.
The API basis is the [unified draft contract](https://jeremi.github.io/bb-digital-registries/api/openapi.yaml); its `write.openapi.yaml` URL is an alias for that document.

## Boundaries

A source pack owns source operations, authentication requirements, bounded requests, native errors, identity resolution and source continuation.
A source operation declares only the semantics and prerequisites its implementation can support.
A source brand, a timestamp or a successfully decoded page is not proof of history, temporal selection, uniqueness or traversal guarantees.

A project selects source operations and supplies its transformation, versioned output schema, collection and Registry identifiers, named inputs and access policy.
Transformations are reviewed, digest-covered artifacts with the existing script and execution limits.
Their output is validated before disclosure.
A transformation cannot grant source authority, read secrets or create source-backed guarantees.
Shared mapping parameters and scripts may be reused without requiring a separate transformation-package format.

The GovStack host owns the canonical `/govstack/registries` mount, versioned HTTP paths, methods, request and response shapes, problem mapping, headers, cursor context and capability annotations.
Generated OpenAPI uses `/govstack/registries` as `servers.url` and keeps its operation paths relative under `/v1/...`.
The facade crate exposes this protocol through its `govstack::consultation` and `govstack::write` modules in the same crate; the shared engine remains responsible for generic source execution, projections and schema validation.
The host adds no separate crate, deployed service, or project-specific runtime configuration.
It reuses the facade's authentication, access admission, bounded engine and durable journal.
Evidence consumes the source pack through its listener-free engine binding and keeps its own facts contract, assertion evaluation, authorization, signing and release audit.
It does not need to construct a GovStack Record.
An Evidence Source can select a package-owned projection of matched native facts and its own versioned facts schema without changing its pack.
No-match, ambiguous and unresolved outcomes are preserved, and projection failures prevent derivation under the original acquisition deadline.

## Schemas and capabilities

Each Consultation collection selects its public data schema once through `dataSchema`, referencing the project artifact inventory.
The schema is JSON Schema with a stable versioned identity and an exact artifact digest.
Nested objects, bounded arrays and local schema definitions are supported.
Schemas are self-contained reviewed artifacts; `$ref` references stay inside the selected document.
Build and load verify its exact pin, and serving performs no remote schema fetch.
The compiler wraps the data schema in the fixed protocol envelopes and emits the concrete OpenAPI contract.
An input schema describes each enabled selector or named Search separately from the response schema.
The public contract never implies that every payload field is searchable.

Pack support, project enablement and caller-visible availability are distinct.
The loaded plan derives the effective operation set from the selected Rust protocol, source bindings, transformations, schema checks and deployment policy.
Source-dependent features require declared source semantics and verified prerequisites.
Host-provided features do not require an upstream feature of the same name.
Unsupported capabilities and feature declarations fail explicitly instead of being advertised or silently ignored.

The facade serves caller-filtered `GET /govstack/registries/v1/capabilities` with `Cache-Control: no-store`.
Entries reference stable operation identifiers in a version-specific HTTPS OpenAPI contract and identify their Registry and Collection. Read entries select a view; Write entries use `family: write`, and Update identifies its companion Retrieve operation and view.
The contract supplies input and output schemas and the selected features.
Discovery does not grant access to any Record or replace authorization at invocation.
No credentials, source addresses, private configuration or unsupported pack operations enter this response.

## Selected read surface

Implement Retrieve, exact Lookup, List and named Search where the project binds an eligible source route.
The initial binding supports one exact identifier selector and one declared scalar-equality Search per Collection; composite selectors, additional comparisons and multiple named operations require corresponding checked source/input bindings before they can be advertised.
Lookup resolves at most one permitted Record and preserves declared uniqueness and protected-existence outcomes.
List and Search require a declared deterministic source order with a unique tie-breaker, bounded pages and explicit completion.
A cursor is opaque, excludes personal data and binds the operation, Registry, Collection, query, view, page size and applicable caller/access context.
Every page applies current authorization.
An empty advancing page is permitted; an unavailable source guarantee is never reported as completion.

The maintained DHIS2 example exercises the selected baseline reads with an explicit unique order.
The maintained OpenCRVS example exercises exact reads through documented synthetic fixtures; it does not claim live-source verification.
Neither example advertises retained revisions, recorded-time, effective-time, complete traversal or snapshot traversal without source-backed implementation and evidence.
Unsupported optional features are rejected in authoring and requests.
A generated frontend can discover operations and schemas; it does not infer domain workflows or field meanings.

## Selected direct Write surface

`POST /govstack/registries/v1/collections/{collectionId}/records` accepts a closed `{"data": ...}` input and returns 201 with Location, a strong ETag and a receipt containing collectionId, recordId and the same ETag.
The source assigns the durable Record identifier. An upsert with a client-selected identifier is not this Create guarantee.

`PATCH /govstack/registries/v1/collections/{collectionId}/records/{recordId}` accepts `application/merge-patch+json` and a nonempty domain merge patch under `data`.
Null removes an optional member under RFC 7396; required fields and unsupported nested changes are refused by the selected input schema.
One strong If-Match is required: missing returns 428, malformed returns 400, and a mismatched guard returns generic 412 without a mutation.
The source must compare and commit atomically. A preliminary read and timestamp comparison is insufficient.
A synchronous commit returns bodyless 204, no Content-Type, and a new strong ETag.

The project selects `write.collections`, a Create input schema, an Update input schema, and a `bindingTransforms` entry for each enabled write binding.
These transformations receive only validated domain data and produce the native route input; they are not inferred by reversing the read projection.
A matching Consultation collection supplies Registry, view and read data schema once. A Write-only Update supplies those facts and a `writable-read` binding explicitly.
Both arrangements expose one companion Retrieve path, not a second writable-record resource.
That read must acquire its body and native validator under the same authoritative source evaluation and source access context used by the mutation.
The facade seals the native validator as authenticated opaque state, bound to Registry, Collection, Record, view and the deployment/source/access closure.
Fixed Write deployments supply the existing 32-byte `cursorKeyRef`; a separately derived key and nonce domain protect guards, and previous-key opening supports rotation. The public tag reveals equality, not encoded native values. Native conditions may be opaque revision tokens rather than HTTP ETags; their strength comes from the source compare-and-commit guarantee. The pack validates any source-specific syntax. A native condition over 128 bytes is outside this initial bounded profile.
The receipt and a later companion GET share an ETag only while the source guard state, read currency and effective context remain identical.

The reusable source route declares `writeSupport`: source-assigned Create or strong atomic conditional Update, plus an exact keyed replay window.
This explicit declaration is a source-author obligation; it is not established merely by parsing the pack.
The initial execution plan admits deterministic preparation and one source-idempotent HTTP POST inside an idempotent consumer.
A source pack can normalize a known native rejection through a pure, terminal `onException` predicate and a typed outcome. Not-found maps to404, invalid domain input to422, and a source rejection of the generated request to502; these settle without reissuing a mutation. Unknown delivery or unclassified source outcomes remain recoverable.
Native source keys include the trusted caller, logical deployment, method and target, so clients sharing a source service credential cannot collide on a raw key. They also include a random generation drawn when the claim is inserted: every resend of one claim repeats its native key, and a key reused after the replay window is processed as a new request under a new native key.
The host retains status, exact body, optional Content-Type, Location and ETag together with the terminal audit transaction.
A retry rechecks current facade authorization; canonical JSON, method, URI, media type and If-Match determine request equality.
It preserves the original Problem body while generating per-attempt trace headers.
A matching in-flight request returns 409 and a changed fingerprint returns 422.
The configured facade response-retention window cannot exceed the declared native replay window.
Successful capability discovery and admitted Write results publish that configured `idempotencyReplayWindow` as decimal seconds in `x-registry-idempotency-replay-window-seconds`, a Registry Stack operational extension. The header is computed from runtime policy, not repeated in the project.
The separate external-gateway effective contract retains its read-only scope; GovStack Write discovery comes from the canonical capability endpoint and generated OpenAPI.
No domain request payload is persisted to recover an uncertain source send; the client must resubmit the same request so the source can return its original receipt.

The [BReg HTTP example](examples/breg-govstack/README.md) supplies explicit schemas and transformations for a flat contact payload, using native server identifiers, batch receipts and atomic source preconditions.
The source pack stays ordinary HTTP and introduces no BReg runtime or client dependency into the Adapter engine or facade.
DHIS2 Write is unavailable in this profile: the maintained tracker import is an upsert and does not demonstrate the required atomic precondition or authoritative write receipt.
SourceReference is explicitly refused until a selected source implements its evidence validation.
Named transitions, governed Change Requests and asynchronous Write are not selected in this increment.

## Definition of done

1. Source acquisition and deployment-owned transformation are separate, digest-covered execution steps; two different projections reuse the same source pack without modifying its source routes.
2. A versioned project-selected data schema supports nested objects and arrays; invalid schema references, digest mismatches, undeclared output and incorrectly typed output are refused visibly.
3. The built-in Consultation host mounts maintained Rust protocol definitions at `/govstack/registries`, without requiring deployments to author standard envelopes, paths or problem mappings.
4. Enabled reads, generated OpenAPI and caller capability discovery agree on operation, Registry, Collection, view, input and output schema and supported features.
5. Authentication and scope denial precede source effects; required audit failure releases no protected result; discovery remains advisory and caller-filtered.
6. Continuation is bound to the effective transformation/schema deployment and original request/access context; malformed, expired or mismatched cursors are refused before source execution.
7. Fixture-backed DHIS2 baseline and OpenCRVS exact-read journeys execute through the served facade; unsupported Search, ordering and history claims are rejected.
8. The same source pack remains usable by Evidence without a GovStack facade dependency; focused Evidence engine regressions pass.
9. Unit, integration and served end-to-end tests cover the changed boundaries, including negative cases; format, clippy, generated-schema drift, configuration and dependency-direction checks pass.
10. Maintained examples and authoring commands demonstrate check, compile and replay with no handwritten duplicate public contract; product documentation states the selected draft, supported surface and evidence limits accurately.
11. Selected Create returns a source-assigned identifier and a consistent Location/ETag/receipt; the companion GET and Update share the selected guard context.
12. Update validates its domain patch before effects, preserves RFC 7396 removal semantics for the declared schema, refuses missing or stale conditions, and returns bodyless 204 with its committed ETag.
13. Canonical idempotency, exact semantic-header replay, uncertain-send recovery and audit failure are covered by unit, PostgreSQL integration and real source/facade journeys.
14. Source limitations and unselected Write capabilities are explicit in generated metadata, maintained examples and verification reports.
