# registry-relay API Guide

This guide describes the V1 HTTP contract from a client and operator point of view. It is the practical reference for calling a running gateway.

The V1 route shape is dataset-scoped and entity-oriented. Storage table ids stay
out of public URLs; callers use dataset ids, entity names, record ids,
relationships, aggregate ids, and standards adapter roots.

## Listeners And Surfaces

The data-plane listener is `server.bind`. It serves health probes, docs, catalog metadata, dataset metadata, entity reads, evidence-offering discovery, aggregates, OpenAPI, optional standards adapters, and optional provenance resources.

The admin listener is optional and only exists when `server.admin_bind` is configured. Admin routes must stay on a private network. They are never mounted on the public data-plane listener.

The public URL space is structured as follows:

- `/v1/datasets/{dataset_id}/entities/{entity}/...` and related aggregate, measure, and dimension routes are the entity-oriented data-plane surface.
- `/metadata/*` is the standards-facing metadata surface: catalog, DCAT, SHACL, policies, evidence offerings, and dataset/entity descriptors.
- `/.well-known/api-catalog` is the public well-known discovery entry point.
- `/ogc/v1/*` (feature: `ogcapi-features`) exposes spatial entities as OGC API Features collections.
- `/ogc/v1/records/*` (feature: `ogcapi-records`) exposes a metadata-only catalog view.
- `/ogc/edr/v1/*` (feature: `ogcapi-edr`) exposes spatial aggregates as OGC EDR area collections.
- `/dci/{registry}/registry/sync/*` (feature: `spdci-api-standards`) provides SP DCI standards adapter routes.
- `/.well-known/did.json`, `/schemas/{claim_type}/{version}`, and `/contexts/{vocab}/{version}` are provenance verifier-support routes, mounted only when `provenance.enabled: true`.
- `/healthz`, `/ready`, `/docs`, and `/docs/scalar.js` are unauthenticated.
- `/openapi.json` and `/docs` serve the machine-readable and human-readable API surface respectively.

The curated public OpenAPI surface, including documented request methods, path parameters, and security requirements, is in [`openapi/registry-relay.openapi.json`](../openapi/registry-relay.openapi.json) and is served at runtime from `/openapi.json` and browsable at `/docs`. The security assurance route inventory remains the source for mounted public and admin exposure checks.

For SP DCI, `sync/search` is the generic path for any configured
`standards.spdci.registries` entry. The disability-status, details, and support
paths are Disability Registry-specific and return unknown-resource errors unless
the named `{registry}` points at the same dataset/entity as
`standards.spdci.disability_registry`.

When `provenance.enabled: true`, public verifier-support routes are mounted for `/.well-known/did.json` in gateway issuer mode and for `/schemas/{claim_type}/{version}` plus `/contexts/{vocab}/{version}`.

Admin routes are not present in the OpenAPI artifact because they are served on the separate `server.admin_bind` listener, not the public data-plane. Their canonical reference is this document.

Admin routes on `server.admin_bind`:

```text
GET /healthz
GET /ready
GET /metrics
GET /admin/v1/capabilities
GET /admin/v1/posture
POST /admin/v1/config/verify
POST /admin/v1/config/dry-run
POST /admin/v1/config/apply
POST /admin/v1/datasets/{dataset_id}/tables/{table_id}/reload
POST /admin/v1/reload
```

`GET /metrics` returns Prometheus-style `text/plain` metrics for operators. It is intentionally admin-listener only and is not mounted on `server.bind`.

`GET /admin/v1/capabilities` returns redacted admin capability metadata for callers with `registry_relay:ops_read`. Use it before invoking product-specific reload or governed config operations.

`GET /admin/v1/posture` returns a redacted operations posture document for callers with `registry_relay:ops_read`. Pass `?tier=restricted` only to trusted operations users who need the restricted posture projection.

`POST /admin/v1/reload` reloads every configured source resource and returns a compact `status` plus `counts` summary. It does not reload startup runtime config. Use the table-specific route when you need to reload only one source.

The governed config routes require the independent `registry_relay:admin` scope:

- `POST /admin/v1/config/verify` validates a candidate config and reports whether Relay could live-apply it or would need a restart.
- `POST /admin/v1/config/dry-run` performs the same validation path used by apply and returns `rejected_restart_required` for candidates that cannot be swapped live.
- `POST /admin/v1/config/apply` applies only a signed TUF config target and only when the live-change classifier accepts the change. Inline `config_yaml` candidates are accepted for verify and dry-run, but apply rejects them with `registry.admin.config.inline_apply_rejected`.

The config request body accepts exactly one candidate source:

```json
{
  "bundle_id": "ops-bundle-2026-06-05",
  "stream_id": "default",
  "sequence": 42,
  "previous_config_hash": "sha256:...",
  "root_version": 3,
  "config_yaml": "instance:\n  id: relay-prod\n..."
}
```

or:

```json
{
  "tuf": {
    "root_path": "/etc/registry-relay/trust/root.json",
    "metadata_dir": "/etc/registry-relay/trust/metadata",
    "targets_dir": "/etc/registry-relay/trust/targets",
    "datastore_dir": "/var/lib/registry-relay/config-tuf",
    "target_name": "registry-relay.yaml"
  }
}
```

or a remote TUF repository:

```json
{
  "tuf": {
    "root_path": "/etc/registry-relay/trust/root.json",
    "metadata_base_url": "https://config.example.gov/registry-relay/metadata/",
    "targets_base_url": "https://config.example.gov/registry-relay/targets/",
    "datastore_dir": "/var/lib/registry-relay/config-tuf",
    "target_name": "registry-relay.yaml"
  }
}
```

Remote TUF sources are recorded as `signed_bundle_endpoint`; local TUF directory
sources are recorded as `signed_bundle_file`; inline diagnostics are recorded as
`local_file`. Remote TUF requests must match a repository configured by the
operator under `config_trust.remote_tuf_repositories` before any fetch occurs.
HTTP loopback remote repositories are accepted only when that configured
repository sets `allow_dev_insecure_fetch_urls: true`; request bodies cannot
enable insecure fetching by themselves.

Break-glass is apply-only. `verify` and `dry-run` reject any break-glass fields. `apply` accepts break-glass only for signed TUF targets and only when the approval is present, the signed bundle includes the requested emergency change class, and local anti-rollback rate limits allow it. The rolling-window rate-limit policy comes from local `config_trust.break_glass_rate_limit`; clients must not include it in the request:

```json
{
  "break_glass": true,
  "break_glass_approval": {
    "approved_by": "ops@example.gov",
    "reason": "recover from bad live config",
    "approval_reference": "INC-4242",
    "emergency_change_class": "emergency_break_glass",
    "expires_at_unix_seconds": 1780000000,
    "rate_limit_identity": "registry-relay/relay-prod/production/default"
  }
}
```

The audit record stores the approval reference, approver, emergency change class, expiry, and rate-limit identity. It hashes the free-text `reason` and does not store the raw reason.

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

When both are present, `Authorization` wins. The gateway hashes the presented raw key with SHA-256 and compares it to fingerprints resolved from `auth.api_keys[].fingerprint`.

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

Some entities declare `required_filters`. Collection reads for those entities must include at least one of those fields or the gateway returns `400 entity.filter_required`. This protects sensitive resources from accidental unfiltered enumeration.

Collection reads accept at most 20 filter parameters. The cap applies before query planning so overly broad or machine-generated requests fail predictably.

## Pagination And Conditional Requests

Collection routes support `limit` up to the entity's configured `max_limit`. Responses may include an opaque cursor for the next page. Treat cursors as server-owned tokens and pass them back unchanged. A cursor is bound to the query shape and the current snapshot generation; malformed, tampered, or stale cursors fail with `query.cursor_invalid`.

Entity collection and record responses include validators where supported. Clients can use `If-None-Match` to avoid re-downloading unchanged content. A matching validator returns `304 Not Modified`.

## Purpose Headers

Entities can require a `Data-Purpose` header for row reads and OGC feature reads.

```http
Data-Purpose: https://data.example.gov/purposes/service-intake-check
```

**Frozen semantics** (2026-06-11 evidence-contracts decision record, D5):

- Header **presence** can be required per entity via `require_purpose_header: true`. A missing header when required returns `400 auth.purpose_required`.
- When the header is present, the value is **always recorded verbatim** in the audit trail.
- Purpose **values are not enforced** at the consultation layer. Relay does not validate, compare, or allowlist values.
- **Registry Notary** is the purpose-certification layer.
- Value-level allowlists, if ever added, will arrive as additive opt-in configuration and will not change this default behavior.

Use stable, reviewable purpose IRIs. Do not put secrets, bearer tokens, or personal data in this header; it is recorded in audit logs.

## Metadata, Catalog, And OpenAPI

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

Required filters, purpose headers, and field projection all apply on item routes. `bbox` alone does not satisfy a non-spatial `required_filters` constraint; item-by-id reads also enforce required filters to prevent filter-bypass via direct feature links. Item links in FeatureCollections preserve active required filters so they remain valid when followed.

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

Conformance boundaries for Phase 1: the OGC Features surface claims `http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core`, `http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/geojson`, and `http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/oas30`. Phase 1 supports point fields and existing GeoJSON geometry fields; WKT and WKB are deferred. Antimeridian bboxes, reprojection, and formal Queryables are deferred. For operator rollout details and configuration of the `spatial` entity block, see [standards-adapter-operator-guide.md](standards-adapter-operator-guide.md).

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

Aggregate JSON results use `observations` for rows and `structure` for dimensions/measures. Query bodies should use `measures`; `indicators` is accepted only as a deprecated compatibility alias. Disclosure control is configured per aggregate. Suppressed or masked groups are normal results, not errors. Temporal query bounds are supported for aggregates that declare a `temporal_field`; requests with temporal bounds against aggregates without one are rejected instead of guessing. POST queries may set `max_rows`; truncated results are marked with `completeness.complete: false` and `completeness.truncated: true` so a partial cube is not confused with a complete one. CSV output is available with `?f=csv`, request `"format": "csv"`, or `Accept: text/csv` and carries `X-Registry-Relay-*` and `X-SPDCI-*` disclosure/freshness headers plus a `Link: rel="describedby"` header to aggregate structure. SDMX JSON 2.1 is available with `?f=sdmx-json`, request `"format": "sdmx-json"`, or `Accept: application/vnd.sdmx.data+json;version=2.1`; messages declare the official schema at `https://json.sdmx.org/2.1/sdmx-json-data-schema.json`. When built with `ogcapi-edr`, configured `admin_area` spatial aggregates are also exposed as OGC EDR `/area` collections under `/ogc/edr/v1`.

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

Startup-only split metadata failures use stable `metadata.manifest.*` and `runtime.binding.*` codes logged to stderr; see [metadata.md](metadata.md) for the full table.

## Provenance Opt-In

When `provenance.enabled: true`, callers can request signed Verifiable Credentials for entity record and aggregate result responses by sending `Accept: application/vc+jwt`; plain JSON remains the default when the caller does not opt in. See [provenance.md](provenance.md) for signer config, DID Web behavior, VC-JWT shape, and verification steps.
