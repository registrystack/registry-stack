# Consultation facade and reusable source packs

## Purpose

Expose the GovStack Digital Registries Consultation draft through maintained Rust protocol behavior over the shared Adapter engine.
Keep source access reusable by the facade, Evidence and ingestion hosts.
Deployments own their schema-bound transformations and the public views they expose.
This contract selects a bounded read surface and makes no general GovStack conformance claim.

## Boundaries

A source pack owns source operations, authentication requirements, bounded requests, native errors, identity resolution and source continuation.
A source operation declares only the semantics and prerequisites its implementation can support.
A source brand, a timestamp or a successfully decoded page is not proof of history, temporal selection, uniqueness or traversal guarantees.

A project selects source operations and supplies its transformation, versioned output schema, collection and Registry identifiers, named inputs and access policy.
Transformations are reviewed, digest-covered artifacts with the existing script and execution limits.
Their output is validated before disclosure.
A transformation cannot grant source authority, read secrets or create source-backed guarantees.
Shared mapping parameters and scripts may be reused without requiring a separate transformation-package format.

The GovStack host owns the versioned HTTP paths, methods, request and response shapes, problem mapping, headers, cursor context and capability annotations.
It reuses the facade's authentication, access admission, bounded engine and durable journal.
It does not add a second deployed service.
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

The facade serves caller-filtered `GET /v1/capabilities` with `Cache-Control: no-store`.
Entries reference stable operation identifiers in a version-specific HTTPS OpenAPI contract and identify their Registry, Collection and view.
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

## Definition of done

1. Source acquisition and deployment-owned transformation are separate, digest-covered execution steps; two different projections reuse the same source pack without modifying its source routes.
2. A versioned project-selected data schema supports nested objects and arrays; invalid schema references, digest mismatches, undeclared output and incorrectly typed output are refused visibly.
3. The built-in Consultation path uses maintained Rust protocol definitions, without requiring deployments to author standard envelopes, paths or problem mappings.
4. Enabled reads, generated OpenAPI and caller capability discovery agree on operation, Registry, Collection, view, input and output schema and supported features.
5. Authentication and scope denial precede source effects; required audit failure releases no protected result; discovery remains advisory and caller-filtered.
6. Continuation is bound to the effective transformation/schema deployment and original request/access context; malformed, expired or mismatched cursors are refused before source execution.
7. Fixture-backed DHIS2 baseline and OpenCRVS exact-read journeys execute through the served facade; unsupported Search, ordering and history claims are rejected.
8. The same source pack remains usable by Evidence without a GovStack facade dependency; focused Evidence engine regressions pass.
9. Unit, integration and served end-to-end tests cover the changed boundaries, including negative cases; format, clippy, generated-schema drift, configuration and dependency-direction checks pass.
10. Maintained examples and authoring commands demonstrate check, compile and replay with no handwritten duplicate public contract; product documentation states the selected draft, supported surface and evidence limits accurately.
