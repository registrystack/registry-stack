# registry-relay API guide

This guide describes the V1 HTTP contract from a client and operator point of view. It is the practical reference for calling a running gateway.

The V1 route shape is dataset-scoped and entity-oriented. Storage table ids stay
out of public URLs; callers use dataset ids, entity names, record ids,
relationships, aggregate ids, and standards adapter roots.

## Listeners and surfaces

The data-plane listener is `server.bind`. It serves health probes, docs, catalog metadata, dataset metadata, entity reads, evidence-offering discovery, aggregates, OpenAPI, and optional standards adapters.

The admin listener is optional and only exists when `server.admin_bind` is configured. Admin routes must stay on a private network. They are never mounted on the public data-plane listener.

The public URL space is structured as follows:

- `/v1/datasets/{dataset_id}/entities/{entity}/...` and related aggregate, measure, and dimension routes are the entity-oriented data-plane surface.
- `/v1/attribute-releases` and `/v1/attribute-releases/{profile_id}/versions/{version}/resolve` (feature: `attribute-release`, off by default for 1.0) resolve governed identity attribute-release profiles to minimized claim bundles.
- `/metadata/*` is the standards-facing metadata surface: catalog, DCAT, SHACL, policies, evidence offerings, and dataset/entity descriptors.
- `/.well-known/api-catalog` is the public well-known discovery entry point.
- `/ogc/v1/*` (feature: `ogcapi-features`) exposes spatial entities as OGC API Features collections.
- `/ogc/v1/records/*` (feature: `ogcapi-records`) exposes a metadata-only catalog view.
- `/ogc/edr/v1/*` (feature: `ogcapi-edr`) exposes spatial aggregates as OGC EDR area collections.
- `/dci/{registry}/registry/sync/*` (feature: `spdci-api-standards`) provides SP DCI standards adapter routes.
- `/healthz`, `/ready`, `/docs`, and `/docs/scalar.js` are unauthenticated.
- `/openapi.json` and `/docs` serve the machine-readable and human-readable API surface respectively.

The curated OpenAPI artifact, including documented request methods, path parameters, and security requirements, is in [`openapi/registry-relay.openapi.json`](../openapi/registry-relay.openapi.json). Runtime OpenAPI is generated separately from the running data-plane config at `/openapi.json` and browsable at `/docs`. Admin-route exposure is verified by the project's security test suite.

For SP DCI, `sync/search` is the generic path for any configured
`standards.spdci.registries` entry. The disability-status, details, and support
paths are Disability Registry-specific and return unknown-resource errors unless
the named `{registry}` points at the same dataset/entity as
`standards.spdci.disability_registry`.

Most admin routes are documented only in this guide because they are served on the separate `server.admin_bind` listener, not the public data-plane. The committed OpenAPI artifact also includes the table-specific ingest reload route because it is part of the documented operator contract.

Admin routes on `server.admin_bind`:

```text
GET /healthz
GET /ready
GET /metrics
GET /admin/v1/capabilities
GET /admin/v1/posture
POST /admin/v1/datasets/{dataset_id}/tables/{table_id}/reload
POST /admin/v1/reload
```

`GET /metrics` returns Prometheus-style `text/plain` metrics for operators. It is intentionally admin-listener only, requires `registry_relay:metrics_read`, and is not mounted on `server.bind`.

`GET /admin/v1/capabilities` returns redacted admin capability metadata for callers with `registry_relay:ops_read`. Use it before invoking product-specific reload operations.

`GET /admin/v1/posture` returns a redacted operations posture document for callers with `registry_relay:ops_read`. Pass `?tier=restricted` only to trusted operations users who need the restricted posture projection.

`POST /admin/v1/reload` reloads every configured source resource and returns a compact `status` plus `counts` summary. It requires `registry_relay:admin`, does not reload startup runtime config, and has a table-specific companion route when you need to reload only one source. Reload-all publishes as one coherent generation: if any source resource cannot prepare, Relay keeps the previous generation active and returns `500` with `status: "failed"`.

Relay no longer exposes admin config verify, dry-run, or apply routes. Signed
config bundles are verified only at boot from the local paths in
`config_trust`. Operators can use `registry-relay config verify-bundle` for an
offline local bundle check before deploying the bundle and restarting Relay.

The audit record stores the approval reference, emergency change class, expiry, rate-limit identity, and hashes of approver identity and free-text `reason`. It does not store raw reason text or raw approver identity.

## Authentication

The gateway runs in one of two auth modes, fixed at startup by `auth.mode`:

* `api_key`: high-entropy shared secret with a SHA-256 fingerprint loaded from an environment variable.
* `oidc`: bearer JWT verified against an external OpenID Connect / OAuth2 IdP's JWKS.

### API key

Clients send either header:

```http
Authorization: Bearer <api-key>
```

or:

```http
x-api-key: <api-key>
```

When both are present, `Authorization` wins. The gateway hashes the presented raw key with SHA-256 and compares it to fingerprints resolved from `auth.api_keys[].fingerprint`.

### OIDC bearer JWT

Clients send:

```http
Authorization: Bearer <jwt>
```

The OIDC mode does not accept `x-api-key`. The gateway validates the standard claims (`iss`, `aud`, `exp`, optional `nbf`) against the configured `auth.oidc` block, looks up the signing key in the cached JWKS (refreshed on unknown `kid`), and verifies the signature. The Principal's `principal_id` is taken from the token's `sub` (preferred), then `client_id`, then `azp`. Token verification failures map to granular `auth.*` codes, including `token_expired`, `audience_mismatch`, and `kid_unknown`, so audit pipelines can distinguish IdP outages from policy denials; see `docs/configuration.md` for the full table.

Scopes are independent. Grant the narrowest scope that lets the caller do its job:

| Scope suffix | Allows |
| --- | --- |
| `metadata` | Catalog, dataset summaries, entity schema, and OpenAPI visibility for that dataset |
| `rows` | Entity collection, single-record, and relationship reads |
| `evidence_verification` | Evidence-oriented standards adapter calls and integrations that must stay separate from row reads |
| `aggregate` | Aggregate discovery and configured aggregate execution |

Global admin-listener scopes are independent of dataset scopes: `registry_relay:admin` for reload and configuration mutation, `registry_relay:metrics_read` for metrics, and `registry_relay:ops_read` for read-only posture and capability discovery.

## Entity reads

Entity routes use configured entity names, not storage table ids. For example:

```text
GET /v1/datasets/social_registry/entities/individual/records?municipality_code=riverbend&limit=50
GET /v1/datasets/social_registry/entities/individual/records/ind-123
GET /v1/datasets/social_registry/entities/household/records/hh-42/relationships/members
```

Only fields exposed through `entities[].fields` appear in responses. If `fields` is omitted, every table column is exposed under its declared name. Storage-only columns should therefore be hidden by explicitly listing the public fields.

## Filters

Filters are opt-in. A query parameter is accepted only when its field appears in `entities[].api.allowed_filters`.

Common forms:

```text
?id=ind-123
?id.eq=ind-123
?id.in=ind-123,ind-456
?payment_amount.gte=100
?payment_amount.lte=500
```

Operators are configured per field with `ops: [eq, in, gte, lte, between]`. Arbitrary SQL is never exposed.

Some entities declare `required_filters`. Protected reads for those entities must carry a principal-bound equality filter for at least one listed field or the gateway returns `400 entity.filter_required`; caller-supplied filters can narrow results but do not satisfy the gate. The list is an OR gate, so configure multiple fields only when each field is an acceptable row boundary.

Collection reads accept at most 20 filter parameters. The cap applies before query planning so overly broad or machine-generated requests fail predictably.

## Pagination and conditional requests

Collection routes support `limit` up to the entity's configured `max_limit`. Responses may include an opaque cursor for the next page. Treat cursors as server-owned tokens and pass them back unchanged. A cursor is bound to the query shape and the current snapshot generation; malformed, tampered, or stale cursors fail with `query.cursor_invalid`.

Entity collection and record responses include validators where supported. Clients can use `If-None-Match` to avoid re-downloading unchanged content. A matching validator returns `304 Not Modified`.

## Purpose headers

Entities can require a `Data-Purpose` header for row reads and OGC feature reads.

```http
Data-Purpose: https://data.example.gov/purposes/service-intake-check
```

**Frozen semantics:**

- Header **presence** can be required per entity via `require_purpose_header: true`. A missing header when required returns `400 auth.purpose_required`.
- When the header is present, the value is **always recorded verbatim** in the audit trail.
- Without an entity `governed_policy`, purpose **values are not enforced** at the consultation layer. Relay records the value but does not validate, compare, or allowlist it.
- With an entity `governed_policy`, governed evidence-gateway routes evaluate the configured PDP purpose allowlist and return a stable `pdp.*` denial when the purpose is not permitted.
- **Registry Notary** is the purpose-certification layer.
- Value-level allowlists remain additive opt-in configuration and do not change the default `require_purpose_header` behavior.

Use stable, reviewable purpose IRIs. Do not put secrets, bearer tokens, or personal data in this header; it is recorded in audit logs.

## Governed request context

Registry Relay treats client-supplied Policy Decision Point (PDP) context as
untrusted. Relay passes each header in this table to the PDP only when the
authenticated principal has the exact
`registry:trust:<scope_field>:<header_value>` scope.

| Header | Scope field | Classification |
| --- | --- | --- |
| `x-registry-subject-ref` | `subject_ref` | Scope-gated |
| `x-registry-relationship` | `relationship` | Scope-gated |
| `x-registry-on-behalf-of` | `on_behalf_of` | Scope-gated |
| `x-registry-credential-format` | `requested_credential_format` | Scope-gated |
| `x-registry-source-observed-at-unix-seconds` | `source_observed_at_unix_seconds` | Scope-gated |

An absent or nonmatching scope makes the header absent from PDP context. A
policy that requires the field or matches its value then denies the request.
`Data-Purpose` remains a caller-stated purpose, not proof of identity,
delegation, legal basis, consent, or source freshness.

Policy authors must not make a Permit decision depend on unauthenticated
request context. Use only server-derived context or values authenticated by an
exact-value trust scope. An adapter that adds another client-supplied
trust-context field must apply the same guard before the PDP evaluates it.

## Metadata, catalog, and OpenAPI

`GET /metadata/catalog` and `GET /metadata/dcat/bregdcat-ap` return only datasets visible to the authenticated principal's metadata scopes.

The metadata catalog is route-neutral and does not inline Relay-specific runtime
adapters. Standards routes remain canonical at their protocol roots, such as
`/ogc/v1/records`, `/ogc/v1`, and `/dci/{registry}/registry/sync/...`.
`/v1/datasets/{dataset_id}` acts as the Relay-native discovery surface that
connects them back to the native dataset model.

`GET /metadata/*` is the canonical standards-facing metadata surface. When the runtime config points at a split metadata manifest, these routes render from the compiled portable manifest and filter the compiled view to the caller's metadata scopes. They expose catalog JSON, base DCAT, application-profile DCAT, SHACL, dataset/entity metadata, evidence-offering metadata, Draft 2020-12 JSON Schemas, and link-free OGC Records bodies. Visible aggregate distributions advertise native JSON, SDMX JSON 2.1, CSV, and, for configured spatial aggregates when built with `ogcapi-edr`, the OGC EDR `/area` endpoint. They do not grant row, evidence verification, aggregate, or admin access.

Relay-native discovery remains under `/v1/datasets` and runtime entity routes. Portable metadata consumers should use `/metadata/*` or static publication.

Metadata responses include private validators for the authenticated view. Clients can send `If-None-Match`; unchanged metadata returns `304 Not Modified`. The gateway also sets `Cache-Control: private, no-store` and `Vary: Authorization` so shared caches do not reuse one principal's scoped catalog for another caller.

`GET /openapi.json` is auth-gated and metadata-filtered by default. The generated document includes only the operations and dataset/entity tags visible to the caller. Local demos and controlled tooling can set `server.openapi_requires_auth: false`; in that mode, unauthenticated callers receive the full configured OpenAPI surface. `GET /docs` serves the local Scalar viewer and can load the document with or without a bearer token depending on that setting.

Static publication uses the same portable metadata model without starting Relay. See [metadata.md](metadata.md) for the manifest model, CLI commands, publication layout, and split metadata startup errors.

When built with `ogcapi-features`, OGC API Features exposes spatial entities as read-only GeoJSON Features:

```text
GET /ogc/v1
GET /ogc/v1/conformance
GET /ogc/v1/collections
GET /ogc/v1/datasets/{dataset_id}/collections
GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}
GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items
GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}
```

Spatial collections are configured per entity with `spatial`. An entity is only exposed as an OGC collection when that block is present.

Auth and scope requirements for OGC API Features routes:

| Route | Required scope |
| --- | --- |
| `GET /ogc/v1` | metadata scope on at least one spatial entity |
| `GET /ogc/v1/conformance` | metadata scope on at least one spatial entity |
| `GET /ogc/v1/collections` | metadata scope for each listed dataset |
| `GET /ogc/v1/datasets/{dataset_id}/collections` | metadata scope for the dataset |
| `GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}` | metadata scope for the collection's dataset |
| `GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items` | read scope for the collection's entity |
| `GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}` | read scope for the collection's entity |

Required filters, purpose headers, and field projection all apply on item routes. `bbox` alone does not satisfy a non-spatial `required_filters` constraint; item-by-id reads also enforce required filters to prevent filter-bypass via direct feature links. When multiple `required_filters` are configured, any one principal-bound equality filter on a listed field satisfies the gate. Item links in FeatureCollections preserve active required filters so they remain valid when followed.

OGC item routes return `application/geo+json`; landing, conformance, and collection routes return `application/json`. Errors return `application/problem+json` with a stable `code` extension member.

Error codes for OGC and spatial failures:

| Code | Condition |
| --- | --- |
| `ogc.collection_not_found` | Dataset or collection not registered, not spatially exposed, or not visible |
| `ogc.feature_not_found` | Feature not registered, not visible, or outside required filter context |
| `ogc.record_not_found` | OGC Records item not registered or not visible |
| `spatial.geometry_invalid` | Geometry field is malformed at runtime |
| `spatial.geometry_too_large` | Geometry exceeds the configured vertex limit |
| `spatial.bbox_invalid` | `bbox` parameter is malformed, uses an unsupported shape, or crosses the antimeridian |
| `spatial.filter_unsupported` | A named parameter cannot be evaluated for this collection (carries `parameter` field) |
| `spatial.crs_unsupported` | Requested `bbox-crs` is not CRS84 |
| `query.cursor_invalid` | OGC `after` cursor is malformed, expired, or bound to a different query context |

Pagination on item routes uses `limit` (capped by the entity's `max_limit`) and the opaque signed `after` cursor. The cursor binds dataset id, collection id, normalized filters, `bbox`, `bbox-crs`, `datetime`, limit, and caller identity; any change invalidates it. `numberMatched` is omitted; `numberReturned` and `links` (`self`, `first`, `next`) are always present on FeatureCollections.

Spatial query parameter behavior: `bbox` is parsed as `minx,miny,maxx,maxy` in CRS84 longitude-latitude order; six-value 3D bbox values are rejected. `bbox-crs` accepts `http://www.opengis.net/def/crs/OGC/1.3/CRS84` only. `datetime` requires a configured `datetime_field`; open-open intervals (`../..`) are rejected. Broad `bbox` queries that exceed `max_bbox_degrees` are rejected before data access.

Conformance boundaries for the current OGC Features surface: it claims `http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core`, `http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/geojson`, and `http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/oas30`. It supports point fields and existing GeoJSON geometry fields; WKT and WKB are not yet supported. Antimeridian bboxes, reprojection, and formal Queryables are not yet supported. For operator rollout details and configuration of the `spatial` entity block, see [standards-adapter-operator-guide.md](standards-adapter-operator-guide.md).

When built with `ogcapi-records`, OGC API Records exposes a metadata-only catalog view:

```text
GET /ogc/v1/records
GET /ogc/v1/records/conformance
GET /ogc/v1/records/collections
GET /ogc/v1/records/collections/datasets
GET /ogc/v1/records/collections/datasets/items
GET /ogc/v1/records/collections/datasets/items/{dataset_id}
```

The initial Records surface has one collection, `datasets`, where each item is a record describing a visible `dcat:Dataset`. It uses the same metadata scopes as `/metadata/catalog`; it does not expose row data, bypass required filters, or claim searchable-catalog conformance.

`GET /ogc/v1/records/collections/datasets/items` supports metadata-side discovery parameters:

- `q`: case-insensitive text search across visible dataset and entity metadata.
- `limit`: maximum records to return, from 1 to 1000.
- `after`: opaque signed pagination cursor from a `rel=next` link.

Dataset Records do not currently support `bbox` or `datetime` filtering because the catalog metadata only carries `spatial_coverage` IRIs and no temporal coverage field. The endpoint rejects unsupported spatial/search parameters instead of pretending those fields are filterable.

## Evidence verification and aggregates

Evidence offerings are declared metadata resources that describe what kind of evidence a registry can check and the authority, assurance, purpose, and request shape for that check:

```text
GET /metadata/evidence-offerings
GET /metadata/evidence-offerings/individual_name_evidence
```

Metadata reads require the caller's `metadata` scope for the owning dataset. They do not execute a check or disclose row data. Relay publishes discovery records only; Registry Notary executes verification. Evidence offerings carry `access.kind: registry-notary` metadata with the advertised Notary endpoint or discovery URL; clients submit claims and evidence to Registry Notary, not Relay. For the complete client handoff sequence, see [client-integration.md](client-integration.md).

The list endpoint accepts metadata-only filters:

```text
GET /metadata/evidence-offerings?evidence_type=BirthCertificate
GET /metadata/evidence-offerings?country=TH
GET /metadata/evidence-offerings?procedure_context=https://example.gov/procedure/benefit-intake
```

Aggregates are predeclared in config. Clients can list available aggregates and execute one by id:

```text
GET /v1/datasets/social_registry/aggregates
GET /v1/datasets/social_registry/measures
GET /v1/datasets/social_registry/dimensions
GET /v1/datasets/social_registry/aggregates/by_municipality
GET /v1/datasets/social_registry/aggregates/by_municipality/structure
POST /v1/datasets/social_registry/aggregates/by_municipality/query
```

Measure and dimension discovery is dataset-scoped and generated from aggregate declarations. Reused measure or dimension ids are merged into one discovery record with `queryable_via`, `valid_dimensions` for measures, and links back to the aggregate routes. `GET /v1/datasets/{dataset_id}/aggregates/{aggregate_id}/metadata` remains a deprecated compatibility alias for `/structure` while the runtime still mounts it.

Aggregate JSON results use `observations` for rows and `structure` for dimensions/measures.

**JSON**

- Query bodies should use `measures`; `indicators` is accepted only as a deprecated compatibility alias.
- Disclosure control is configured per aggregate.
- Suppressed or masked groups are normal results, not errors.
- Temporal query bounds are supported for aggregates that declare a `temporal_field`; requests with temporal bounds against aggregates without one are rejected instead of guessing.
- POST queries may set `max_rows`; truncated results are marked with `completeness.complete: false` and `completeness.truncated: true` so a partial cube is not confused with a complete one.

**CSV**

- Available with `?f=csv`, request `"format": "csv"`, or `Accept: text/csv` and carries `X-Registry-Relay-*` and `X-SPDCI-*` disclosure/freshness headers plus a `Link: rel="describedby"` header to aggregate structure.

**SDMX JSON 2.1**

- Available with `?f=sdmx-json`, request `"format": "sdmx-json"`, or `Accept: application/vnd.sdmx.data+json;version=2.1`; messages declare the official schema at `https://json.sdmx.org/2.1/sdmx-json-data-schema.json`.

**OGC EDR**

- When built with `ogcapi-edr`, configured `admin_area` spatial aggregates are also exposed as OGC EDR `/area` collections under `/ogc/edr/v1`.

## Attribute release

`registry-relay` can resolve a governed identity attribute-release profile: an
exactly-one-subject lookup that maps configured source fields (or CEL
expressions) into a minimized, OIDC/UserInfo-style claim bundle for a named
profile. This beta surface is compiled only when Relay is built with the
off-by-default `attribute-release` feature.

```text
GET  /v1/attribute-releases
POST /v1/attribute-releases/{profile_id}/versions/{version}/resolve
```

`GET /v1/attribute-releases` lists the release profiles visible to the
authenticated caller: a profile appears only when the caller holds that
profile's `release_scope`. The response never includes source internals
(table ids, source field names); it is `private, no-store` and
`Vary: Authorization`.

`POST /v1/attribute-releases/{profile_id}/versions/{version}/resolve` resolves
one subject against the named `(profile_id, version)` pair, which is globally
unique and has no "latest" alias. Each profile declares its own
`release_scope`, a dataset-bound scope that must differ from the entity's
`read_scope`; the scope suffix convention for this capability is
`<dataset_id>:identity_release`, one of the scope levels an API key can be
granted alongside `metadata`, `aggregate`, `rows`, `verify`, and
`evidence_verification`. A profile may also declare a `purpose`: when it does,
the request's `Data-Purpose` header must equal it, or the gateway returns
`400 auth.purpose_required` (header absent) or `403 auth.purpose_denied`
(header present but mismatched), before any source read. A profile that omits
`purpose` carries no such gate.

Request body:

```json
{
  "subject": { "id_type": "NATIONAL_ID", "value": "NID-1" },
  "claims": ["given_name"]
}
```

`claims` is optional: absent resolves the profile's full default claim set; an
explicit empty list is rejected with `400 filter.invalid_value`; a name
outside the profile's configured claims is denied. `subject.value` accepts
only a non-blank scalar (string, number, or boolean); `subject.id_type` must
match the profile's configured type when one is set. Either failure returns
`400 release.subject_invalid`.

Successful response (`200`):

```json
{
  "profile_id": "civil_identity",
  "profile_version": "v1",
  "claims": {
    "given_name": "Ada",
    "full_name": "Ada Lovelace"
  }
}
```

`claims` carries only the released, minimized claim bundle: never the raw
registry row, never a raw or hashed subject value. A `source` block
(`dataset`, `entity`, `subject_id_type`, `cardinality`, `checked_at`) is added
only when the profile sets `response.include_source_metadata: true`; it is
absent by default.

Every denial after profile resolution collapses to one public code, so a
caller cannot distinguish "no such subject" from "subject exists but was
denied":

| Condition | Code | Status |
| --- | --- | --- |
| Unknown `(profile_id, version)` | `release.profile_not_found` | 404 |
| Invalid subject id_type or value | `release.subject_invalid` | 400 |
| No matching row, more than one matching row, a false release-condition predicate, a required claim unavailable, or a requested claim name outside the profile's configured set | `release.subject_denied` | 403 |
| Backing source unavailable | `release.source_unavailable` | 503 |

A successful release is cacheable only when the profile sets
`response.max_age_seconds`, which yields `private, max-age=N`; the default is
`private, no-store`. Every response carries `Vary: Authorization`. Denials are
always `private, no-store`, regardless of the profile's caching setting.

## Problem details

Errors use RFC 9457 Problem Details with a stable `code` field:

```json
{
  "type": "https://id.registrystack.org/problems/registry-relay/auth/scope_denied",
  "title": "Scope denied",
  "status": 403,
  "code": "auth.scope_denied",
  "detail": "required scope: social_registry:rows"
}
```

The exact text in `detail` is operator-facing but intentionally scrubbed. Do not depend on it programmatically. Use the HTTP status and `code`.

Startup-only split metadata failures use stable `metadata.manifest.*` and `runtime.binding.*` codes logged to stderr; see [metadata.md](metadata.md) for the full table.

## Credential issuance

Relay does not issue response credentials, host DID documents, or publish credential-support schemas and contexts. Use Registry Notary for credential issuance and verification workflows. See [provenance.md](provenance.md) for migration notes.
