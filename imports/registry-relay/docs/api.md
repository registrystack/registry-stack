# registry-relay API Guide

This guide describes the V1 HTTP contract from a client and operator point of view. It is the practical reference for calling a running gateway.

## Listeners And Surfaces

The data-plane listener is `server.bind`. It serves health probes, docs, catalog metadata, dataset metadata, entity reads, evidence-offering discovery, aggregates, OpenAPI, optional standards adapters, and optional provenance resources.

The admin listener is optional and only exists when `server.admin_bind` is configured. Admin routes must stay on a private network. They are never mounted on the public data-plane listener.

Public unauthenticated routes:

```text
GET /health
GET /ready
GET /docs
GET /docs/scalar.js
```

Auth-gated data-plane routes:

```text
GET /openapi.json
GET /metadata
GET /metadata/catalog
GET /metadata/dcat
GET /metadata/dcat/{profile}
GET /metadata/shacl
GET /metadata/policies
GET /metadata/profiles
GET /metadata/profiles/{profile}
GET /metadata/datasets
GET /metadata/datasets/{dataset_id}
GET /metadata/datasets/{dataset_id}/policy
GET /metadata/datasets/{dataset_id}/entities
GET /metadata/datasets/{dataset_id}/entities/{entity}
GET /metadata/datasets/{dataset_id}/entities/{entity}/schema
GET /metadata/datasets/{dataset_id}/entities/{entity}/shacl
GET /metadata/schema/{dataset_id}/{entity}/schema.json
GET /metadata/ogc/records
GET /metadata/ogc/records/{record_id}
GET /metadata/evidence-offerings
GET /metadata/evidence-offerings/{offering_id}
GET /datasets
GET /datasets/{dataset_id}
GET /datasets/{dataset_id}/{entity}/schema
GET /datasets/{dataset_id}/{entity}
GET /datasets/{dataset_id}/{entity}/{id}
GET /datasets/{dataset_id}/{entity}/{id}/{relationship}
GET /datasets/{dataset_id}/aggregates
GET /datasets/{dataset_id}/aggregates/{aggregate_id}
POST /datasets/{dataset_id}/aggregates/{aggregate_id}/query
GET /datasets/{dataset_id}/aggregates/{aggregate_id}/metadata
GET /datasets/{dataset_id}/indicators
GET /datasets/{dataset_id}/indicators/{indicator_id}
GET /datasets/{dataset_id}/dimensions
GET /datasets/{dataset_id}/dimensions/{dimension_id}
GET /ogc/v1                                 (feature: ogcapi-features)
GET /ogc/v1/conformance                     (feature: ogcapi-features)
GET /ogc/v1/collections                     (feature: ogcapi-features)
GET /ogc/v1/datasets/{dataset_id}/collections  (feature: ogcapi-features)
GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}  (feature: ogcapi-features)
GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items  (feature: ogcapi-features)
GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}  (feature: ogcapi-features)
GET /ogc/v1/records                         (feature: ogcapi-records)
GET /ogc/v1/records/conformance             (feature: ogcapi-records)
GET /ogc/v1/records/collections             (feature: ogcapi-records)
GET /ogc/v1/records/collections/{collection_id}  (feature: ogcapi-records)
GET /ogc/v1/records/collections/{collection_id}/items  (feature: ogcapi-records)
GET /ogc/v1/records/collections/{collection_id}/items/{record_id}  (feature: ogcapi-records)
GET /ogc/edr/v1                             (feature: ogcapi-edr)
GET /ogc/edr/v1/conformance                 (feature: ogcapi-edr)
GET /ogc/edr/v1/collections                 (feature: ogcapi-edr)
GET /ogc/edr/v1/collections/{collection_id} (feature: ogcapi-edr)
GET|POST /ogc/edr/v1/collections/{collection_id}/area  (feature: ogcapi-edr)
POST /dci/{registry}/registry/sync/search   (feature: spdci-api-standards)
POST /dci/{registry}/registry/sync/disabled (feature: spdci-api-standards)
POST /dci/{registry}/registry/sync/get-disability-details  (feature: spdci-api-standards)
POST /dci/{registry}/registry/sync/get-disability-support  (feature: spdci-api-standards)
```

For SP DCI, `sync/search` is the generic path for any configured
`standards.spdci.registries` entry. The disability-status, details, and support
paths are Disability Registry-specific and return unknown-resource errors unless
the named `{registry}` points at the same dataset/entity as
`standards.spdci.disability_registry`.

When `provenance.enabled: true`, public verifier-support routes are mounted for `/.well-known/did.json` in gateway issuer mode and for `/schemas/{claim_type}/{version}` plus `/contexts/{vocab}/{version}`.

Admin routes on `server.admin_bind`:

```text
GET /metrics
POST /admin/datasets/{dataset_id}/tables/{table_id}/reload
POST /admin/reload
```

`GET /metrics` returns Prometheus-style `text/plain` metrics for operators. It is intentionally admin-listener only and is not mounted on `server.bind`.

`POST /admin/reload` reloads every configured resource and returns a compact per-resource report. Use the table-specific route when you need to reload only one source.

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
X-Api-Key: <api-key>
```

When both are present, `Authorization` wins. The gateway hashes the presented raw key with SHA-256 and compares it to fingerprints loaded from the environment variables named by `auth.api_keys[].hash_env`.

### OIDC bearer JWT

Clients send:

```http
Authorization: Bearer <jwt>
```

The OIDC mode does not accept `X-Api-Key`. The gateway validates the standard claims (`iss`, `aud`, `exp`, optional `nbf`) against the configured `auth.oidc` block, looks up the signing key in the cached JWKS (refreshed on unknown `kid`), and verifies the signature. The Principal's `principal_id` is taken from the token's `sub` (preferred), then `client_id`, then `azp`. Token verification failures map to granular `auth.*` codes (`token_expired`, `audience_mismatch`, `kid_unknown`, etc.) so audit pipelines can distinguish IdP outages from policy denials; see `docs/configuration.md` for the full table.

Scopes are independent. Grant the narrowest scope that lets the caller do its job:

| Scope suffix | Allows |
| --- | --- |
| `metadata` | Catalog, dataset summaries, entity schema, and OpenAPI visibility for that dataset |
| `rows` | Entity collection, single-record, and relationship reads |
| `evidence_verification` | Evidence-oriented standards adapter calls and integrations that must stay separate from row reads |
| `aggregate` | Aggregate discovery and configured aggregate execution |
| `admin` | Admin listener operations |

## Entity Reads

Entity routes use configured entity names, not storage table ids. For example:

```text
GET /datasets/social_registry/individual?municipality_code=riverbend&limit=50
GET /datasets/social_registry/individual/ind-123
GET /datasets/social_registry/household/hh-42/members
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

Some entities declare `required_filters`. Collection reads for those entities must include at least one of those fields or the gateway returns `400 entity.filter_required`. This protects sensitive resources from accidental unfiltered enumeration.

## Pagination And Conditional Requests

Collection routes support `limit` up to the entity's configured `max_limit`. Responses may include an opaque cursor for the next page. Treat cursors as server-owned tokens and pass them back unchanged.

Entity collection and record responses include validators where supported. Clients can use `If-None-Match` to avoid re-downloading unchanged content. A matching validator returns `304 Not Modified`.

## Purpose Headers

Entities can require a purpose string for row reads and OGC feature reads:

```http
Data-Purpose: https://data.example.gov/purposes/service-intake-check
```

When `require_purpose_header: true`, missing purpose returns `400 auth.purpose_required`. Use stable, reviewable purpose IRIs. Do not put secrets, bearer tokens, or personal data in this header because it is recorded in audit logs.

## Metadata, Catalog, And OpenAPI

`GET /metadata/catalog` and `GET /metadata/dcat/bregdcat-ap` return only datasets visible to the authenticated principal's metadata scopes.

The metadata catalog is route-neutral and does not inline Relay-specific runtime
adapters. Standards routes remain canonical at their protocol roots, such as
`/ogc/v1/records`, `/ogc/v1`, and `/dci/{registry}/registry/sync/...`.
`/datasets/{dataset_id}` acts as the Relay-native discovery surface that
connects them back to the native dataset model.

`GET /metadata/*` is the canonical standards-facing metadata surface. When the runtime config points at a split metadata manifest, these routes render from the compiled portable manifest and filter the compiled view to the caller's metadata scopes. They expose catalog JSON, base DCAT, application-profile DCAT, SHACL, dataset/entity metadata, evidence-offering metadata, Draft 2020-12 JSON Schemas, and link-free OGC Records bodies. They do not grant row, evidence verification, aggregate, or admin access.

Relay-native discovery remains under `/datasets` and runtime entity routes. Portable metadata consumers should use `/metadata/*` or static publication.

`GET /openapi.json` is also auth-gated and metadata-filtered. The generated document includes only the operations and dataset/entity tags visible to the caller. `GET /docs` serves the local Scalar viewer and asks for a bearer token before fetching `GET /openapi.json`.

Static publication uses the same portable metadata model without starting Relay. For local validation and artifact generation:

```sh
just metadata-validate profiles/example-civil-registration/fixtures/metadata.yaml
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml dcat target/metadata/dcat.jsonld
just metadata-publish profiles/example-civil-registration/fixtures/metadata.yaml target/metadata/public
```

The published bundle includes `index.json`, `metadata.yaml`, `catalog.json`, `evidence-offerings.json`, per-offering evidence documents, policy JSON-LD, `dcat.jsonld`, profile DCAT JSON-LD, `shacl.jsonld`, and per-entity JSON Schemas. Static artifacts are broad metadata publication surfaces; caller-scoped discovery still belongs to authenticated Relay routes.

See [metadata.md](metadata.md) for the manifest model, publication layout, and split metadata startup errors.

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

Spatial collections are configured per entity with `spatial`. Discovery routes require metadata scope; item routes require the entity's row-read scope and preserve required filters, purpose headers, projection, audit, and opaque cursor pagination. Phase 1 supports point fields and existing GeoJSON geometry fields. `bbox` works for point geometry and for entities with precomputed bbox fields; `bbox-crs` accepts CRS84 only; `datetime` requires `spatial.datetime_field`.

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

## Evidence Verification And Aggregates

Evidence offerings are declared metadata resources that describe what kind of evidence a registry can check and the authority, assurance, purpose, and request shape for that check:

```text
GET /metadata/evidence-offerings
GET /metadata/evidence-offerings/individual_name_evidence
```

Metadata reads require the caller's `metadata` scope for the owning dataset. They do not execute a check or disclose row data. Evidence offerings are discovery records for Registry Witness. Relay publishes `access.kind: registry-witness` metadata with the advertised Witness endpoint or discovery URL; clients submit claims and evidence to Registry Witness, not Relay.

Aggregates are predeclared in config. Clients can list available aggregates and execute one by id:

```text
GET /datasets/social_registry/aggregates
GET /datasets/social_registry/indicators
GET /datasets/social_registry/dimensions
GET /datasets/social_registry/aggregates/by_municipality
POST /datasets/social_registry/aggregates/by_municipality/query
```

Indicator and dimension discovery is dataset-scoped and generated from aggregate declarations. Reused indicator or dimension ids are merged into one discovery record with `queryable_via`, `valid_dimensions` for indicators, and links back to the aggregate routes.

Disclosure control is configured per aggregate. Suppressed or masked groups are normal results, not errors. Temporal query bounds are supported for aggregates that declare a `temporal_field`; requests with temporal bounds against aggregates without one are rejected instead of guessing. CSV output is available with `?f=csv` or request `"format": "csv"` and carries `X-Registry-Relay-*` and `X-SPDCI-*` disclosure/freshness headers plus a `Link: rel="describedby"` header to aggregate metadata. When built with `ogcapi-edr`, configured `admin_area` spatial aggregates are also exposed as OGC EDR `/area` collections under `/ogc/edr/v1`.

## Problem Details

Errors use RFC 9457 Problem Details with a stable `code` field:

```json
{
  "type": "https://registry-relay.dev/problems/auth/scope_denied",
  "title": "Scope denied",
  "status": 403,
  "code": "auth.scope_denied",
  "detail": "required scope: social_registry:rows"
}
```

The exact text in `detail` is operator-facing but intentionally scrubbed. Do not depend on it programmatically. Use the HTTP status and `code`.

Startup-only split metadata failures use stable codes in logs:

| Code | Meaning |
| --- | --- |
| `metadata.manifest.file_not_found` | Configured metadata manifest cannot be read |
| `metadata.manifest.parse_failed` | Metadata YAML did not deserialize |
| `metadata.manifest.version_unsupported` | Metadata manifest schema version is not supported |
| `metadata.manifest.validation_failed` | Manifest failed semantic validation |
| `runtime.binding.dataset_missing` | Runtime dataset is absent from compiled metadata |
| `runtime.binding.entity_missing` | Runtime entity is absent from compiled metadata |
| `runtime.binding.table_missing` | Runtime entity points at an unknown runtime table |
| `runtime.binding.field_missing` | Runtime field or claim binding is absent from compiled metadata |
| `runtime.binding.filter_missing` | Runtime filter binding is absent from compiled metadata |
| `runtime.binding.relationship_missing` | Runtime relationship binding is absent from compiled metadata |

## Provenance Opt-In

When `provenance.enabled: true`, callers can request signed Verifiable Credentials for supported response families:

```http
Accept: application/vc+jwt
```

Plain JSON remains the default when the caller does not opt in. See [provenance.md](provenance.md) for signer config, DID Web behavior, VC-JWT shape, and verification steps.
