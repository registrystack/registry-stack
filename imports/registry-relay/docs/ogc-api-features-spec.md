# OGC API Features Spec

Status: proposed

This document specifies a read-only OGC API Features surface for Registry Relay entities that expose GIS data. It is a product and implementation spec for a future feature, not current runtime behavior.

## Decision

Implement OGC API Features as a small Registry Relay API family backed by the existing entity registry, query engine, auth, audit, and catalog model.

Use `ogcapi-types` for OGC response payload structs after verifying its JSON field names against the target OGC examples. Do not use `ogcapi-services` for routing or storage. Do not patch or depend on `ST_AsGeoJSON` as a prerequisite. Geometry output conversion should live in Registry Relay because it needs entity config, field visibility, primary keys, links, auth, and audit context.

Use `geodatafusion` later as an optional spatial predicate engine, not as the first output-formatting mechanism. The first useful implementation should support point geometries and existing GeoJSON geometry fields without requiring DataFusion spatial UDFs.

Mount the surface under `/ogc/v1`. Treat this as the first stable Registry Relay OGC API family path. Breaking changes go under a later versioned path.

## Goals

- Expose selected GIS-capable registry entities as OGC API Features collections.
- Preserve existing Registry Relay boundaries: dataset scopes, required filters, purpose headers, field projection, audit records, provenance version metadata, and source abstraction.
- Keep storage table ids private.
- Make spatial support opt-in per entity.
- Support read-only feature discovery, collection reads, item reads, `bbox`, `bbox-crs`, `datetime`, `limit`, and cursor pagination.
- Keep non-spatial registry APIs and aggregate APIs unchanged.

## Non-Goals

- No write transactions.
- No tiles, maps, styles, coverages, processes, EDR, or STAC in the first slice.
- No general GIS server behavior.
- No arbitrary SQL or arbitrary CQL filter execution.
- No reprojection in the first slice.
- No PostGIS-specific public API.
- No dependence on OGC API Services' storage and router model.
- No `ST_AsGeoJSON` implementation as a prerequisite.
- No support for WKT or WKB geometry in Phase 1.

## Dependencies

Initial feature:

```toml
[features]
ogcapi-features = ["dep:ogcapi-types", "dep:geojson"]
```

Candidate optional later feature:

```toml
spatial-datafusion = ["dep:geodatafusion"]
```

`spatial-datafusion` should only be needed when the gateway must evaluate spatial predicates against WKT, WKB, or GeoArrow-compatible geometry columns. It should not be required for point fields, existing GeoJSON geometry fields, or precomputed bbox fields.

Before adding `ogcapi-types`, add serialization tests around the exact payloads in this spec. Confirm field names such as `timeStamp`, `numberMatched`, `numberReturned`, `collections`, `crs`, and `storageCrs` match the OGC JSON contract.

## Configuration

Add an optional `spatial` block to `EntityConfig`. The existing config structs use `serde(deny_unknown_fields)`, so implementation must add this field to the real entity config before any YAML example below can parse.

An entity is exposed as an OGC collection only when this block is present and valid. The existing primary key remains the current `ResourceConfig.primary_key: Option<String>` bare column name. Do not introduce a `primary_key: { name, type }` shape for this feature.

Point geometry:

```yaml
datasets:
  - id: civic_registry
    entities:
      - name: facilities
        table: facilities
        primary_key: facility_id
        spatial:
          collection_id: facilities
          title: Public facilities
          description: Public facility locations from the civic registry.
          geometry:
            kind: point
            longitude_field: lon
            latitude_field: lat
            crs: http://www.opengis.net/def/crs/OGC/1.3/CRS84
          datetime_field: updated_at
          max_bbox_degrees: 5.0
          max_geometry_vertices: 10000
```

Existing GeoJSON geometry:

```yaml
spatial:
  collection_id: parcels
  title: Land parcels
  geometry:
    kind: geojson
    field: geometry
    crs: http://www.opengis.net/def/crs/OGC/1.3/CRS84
  bbox_fields:
    min_x: bbox_min_x
    min_y: bbox_min_y
    max_x: bbox_max_x
    max_y: bbox_max_y
  datetime_field: updated_at
  max_bbox_degrees: 1.0
  max_geometry_vertices: 50000
```

Deferred WKT geometry:

```yaml
spatial:
  collection_id: parcels
  title: Land parcels
  geometry:
    kind: wkt
    field: geom_wkt
    crs: http://www.opengis.net/def/crs/OGC/1.3/CRS84
  bbox_fields:
    min_x: bbox_min_x
    min_y: bbox_min_y
    max_x: bbox_max_x
    max_y: bbox_max_y
```

### Config Rules

- `collection_id` defaults to the entity name when omitted.
- `collection_id` must be unique within its dataset.
- Public OGC URLs include `dataset_id`, so two datasets may both expose `collection_id: facilities` without collision.
- `geometry` is a tagged enum. The tag is `kind`, with Phase 1 values `point` and `geojson`. Values `wkt` and `wkb` are reserved for Phase 2.
- `point` requires `longitude_field` and `latitude_field`.
- `geojson` requires `field`.
- `longitude_field`, `latitude_field`, and bbox fields must resolve to exposed entity fields with numeric types.
- GeoJSON, WKT, and WKB fields must resolve to exposed entity fields.
- `datetime_field`, when present, must resolve to an exposed date or timestamp field.
- `max_bbox_degrees` caps query bbox width and height in CRS84 degrees. Use a conservative default when omitted.
- `max_geometry_vertices` caps vertices decoded from a GeoJSON geometry field. Reject oversized geometries before returning them.
- Initial CRS support is CRS84 only: `http://www.opengis.net/def/crs/OGC/1.3/CRS84`.
- Do not claim EPSG:4326 is equivalent to CRS84. EPSG:4326 has latitude-longitude axis ordering in EPSG definitions, while OGC API Features defaults to CRS84 to keep longitude-latitude coordinates explicit.
- If a config uses EPSG:4326 during migration, either reject it or require an explicit `axis_order: lon_lat_assumed` warning field before normalizing internally to CRS84. Phase 1 should prefer rejection.

## Routes

Mount read-only OGC routes on the public server under an auth-gated router:

```text
GET /ogc/v1
GET /ogc/v1/conformance
GET /ogc/v1/collections
GET /ogc/v1/datasets/{dataset_id}/collections
GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}
GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items
GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}
```

These routes are auth-gated. The health, docs, catalog, and existing entity URL spaces are unchanged.

The top-level `/ogc/v1/collections` endpoint lists visible collections across datasets. Collection detail and item URLs are dataset-scoped to avoid collisions in a multi-dataset registry.

## Auth And Visibility

OGC routes reuse existing dataset scopes. The code field is `read_scope`; this spec uses "read scope" for item access.

| Route | Required scope |
| --- | --- |
| `GET /ogc/v1` | at least one visible dataset metadata scope |
| `GET /ogc/v1/conformance` | at least one visible dataset metadata scope |
| `GET /ogc/v1/collections` | metadata scope for listed datasets |
| `GET /ogc/v1/datasets/{dataset_id}/collections` | metadata scope for the dataset |
| `GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}` | metadata scope for the collection's dataset |
| `GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items` | read scope for the collection's entity |
| `GET /ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}` | read scope for the collection's entity |

Required filters and purpose headers continue to apply to item routes. The OGC surface must not become a bypass around existing enumeration protections.

If an entity declares `api.required_filters`, collection item reads must include one required filter from the existing allowed filter set. `bbox` alone does not satisfy a required non-spatial filter unless a future config explicitly allows it.

Item-by-id reads also preserve required filter semantics. A request to `/items/{feature_id}` for an entity with `api.required_filters` must include the required filter parameters and must only return the item if the requested feature matches those filters. This intentionally diverges from the existing entity item lookup behavior to avoid a leak where a filtered FeatureCollection exposes canonical item links that can then be fetched without the filter context.

Canonical item links in FeatureCollections must include the active required filters or an opaque signed token that preserves the filter context. Do not emit bare `/items/{feature_id}` links for protected collections when required filters were used to authorize enumeration.

Field projection must reuse the same per-principal projection path used by entity routes. OGC properties are derived after entity field visibility has been applied, then geometry carrier fields are removed from properties unless explicitly exposed by a future config.

## Enumeration Controls

The following controls are required for Phase 1:

- Enforce `api.required_filters` on collection and item-by-id routes.
- Treat a world bbox such as `-180,-90,180,90` as a normal broad query, not as a privileged access path.
- Reject `bbox` values whose width or height exceeds the collection's `max_bbox_degrees`.
- Reuse global request rate limiting when present.
- Cap page traversal by signed cursor context or token policy. The cursor must bind dataset id, collection id, caller identity or key fingerprint, normalized filters, bbox, bbox-crs, datetime, projection context, limit, and sort key.
- Return stable errors without revealing whether an invisible dataset, collection, or feature exists.

If Registry Relay later adds a stronger rate-limit primitive, OGC routes should be included in the same policy namespace as entity reads.

## Query Parameters

Initial supported parameters:

```text
limit
bbox
bbox-crs
datetime
after
```

Entity filters are also accepted using the existing Registry Relay filter syntax, but only when declared in `api.allowed_filters`.

Examples:

```text
GET /ogc/v1/datasets/civic_registry/collections/facilities/items?bbox=100.5,13.7,100.8,13.9&limit=50
GET /ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic&limit=25
GET /ogc/v1/datasets/civic_registry/collections/facilities/items?datetime=2026-01-01T00:00:00Z/..
```

Unsupported OGC query parameters should return `application/problem+json` with a stable Registry Relay error code in an extension member. Do not silently ignore unknown filter semantics.

### `bbox`

`bbox` is parsed as `minx,miny,maxx,maxy` in CRS84 longitude-latitude order. Six-number 3D bbox values are rejected in Phase 1.

If `minx > maxx`, the bbox crosses the antimeridian. Phase 1 should reject this with `spatial.bbox_invalid` and a detail that antimeridian bboxes are not supported yet. A later implementation may split it into two longitude ranges joined by OR.

Point geometry translation:

```text
longitude >= minx
longitude <= maxx
latitude >= miny
latitude <= maxy
```

Bbox column overlap translation:

```text
max_x >= minx
min_x <= maxx
max_y >= miny
min_y <= maxy
```

GeoJSON geometry without bbox columns cannot support `bbox` in Phase 1. Startup validation may allow such entities, but `bbox` requests for them must return `spatial.filter_unsupported` with `parameter: "bbox"`.

### `bbox-crs`

Phase 1 supports only CRS84. If `bbox-crs` is absent, CRS84 is assumed.

Accept this value:

```text
http://www.opengis.net/def/crs/OGC/1.3/CRS84
```

Any other value returns `spatial.crs_unsupported`. EPSG:4326 is not accepted as an alias in Phase 1.

### `datetime`

`datetime` requires `spatial.datetime_field`.

Supported forms:

```text
2026-01-01T00:00:00Z
2026-01-01T00:00:00Z/2026-02-01T00:00:00Z
2026-01-01T00:00:00Z/..
../2026-02-01T00:00:00Z
```

Exact instants map to equality using the stored field precision. Timestamp fields compare at timestamp precision. Date fields compare at date precision after parsing the instant into UTC date. Closed and half-open ranges map to existing `gte` and `lte` filters.

Reject open-open intervals:

```text
../..
```

If `datetime` is supplied for a collection without `datetime_field`, return `spatial.filter_unsupported` with `parameter: "datetime"`.

### `after`

`after` is an opaque signed cursor token. It is not a raw primary key.

The token must bind:

- dataset id
- collection id
- normalized filters
- `bbox`
- `bbox-crs`
- `datetime`
- limit
- principal or API key fingerprint
- sort key and last seen primary key

Changing any bound query parameter invalidates the cursor. This reuses the existing `CursorSigner` integrity model instead of weakening pagination for OGC clients.

## Response Shapes

Use `application/json` for landing, conformance, and collection metadata. Use `application/geo+json` for Feature and FeatureCollection responses.

Landing page:

```json
{
  "title": "Registry Relay OGC API",
  "description": "Spatial collections exposed from registry datasets.",
  "links": [
    { "href": "/ogc/v1", "rel": "self", "type": "application/json", "title": "Landing page" },
    { "href": "/ogc/v1/conformance", "rel": "conformance", "type": "application/json", "title": "Conformance" },
    { "href": "/ogc/v1/collections", "rel": "data", "type": "application/json", "title": "Collections" },
    { "href": "/openapi.json", "rel": "service-desc", "type": "application/vnd.oai.openapi+json;version=3.0", "title": "OpenAPI definition" }
  ]
}
```

Conformance:

```json
{
  "conformsTo": [
    "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core",
    "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/geojson",
    "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/oas30"
  ]
}
```

If OpenAPI output is disabled for a deployment, omit the `oas30` URI.

Collections:

```json
{
  "links": [
    { "href": "/ogc/v1/collections", "rel": "self", "type": "application/json" }
  ],
  "collections": [
    {
      "id": "civic_registry.facilities",
      "title": "Public facilities",
      "description": "Public facility locations from the civic registry.",
      "itemType": "feature",
      "crs": [
        "http://www.opengis.net/def/crs/OGC/1.3/CRS84"
      ],
      "storageCrs": "http://www.opengis.net/def/crs/OGC/1.3/CRS84",
      "extent": {
        "spatial": { "bbox": [[100.45, 13.58, 100.92, 13.95]] },
        "temporal": { "interval": [["2024-01-01T00:00:00Z", null]] }
      },
      "properties": {
        "dataset_id": "civic_registry",
        "collection_id": "facilities",
        "propertyNames": ["facility_id", "name", "facility_type", "operator", "updated_at"],
        "supportedQueryParameters": ["limit", "bbox", "bbox-crs", "datetime", "after", "facility_type"]
      },
      "links": [
        { "href": "/ogc/v1/datasets/civic_registry/collections/facilities", "rel": "self", "type": "application/json" },
        { "href": "/ogc/v1/datasets/civic_registry/collections/facilities/items", "rel": "items", "type": "application/geo+json" }
      ]
    }
  ]
}
```

FeatureCollection:

```json
{
  "type": "FeatureCollection",
  "timeStamp": "2026-05-17T09:30:00Z",
  "numberReturned": 1,
  "links": [
    {
      "href": "/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic&limit=1",
      "rel": "self",
      "type": "application/geo+json"
    },
    {
      "href": "/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic&limit=1",
      "rel": "first",
      "type": "application/geo+json"
    },
    {
      "href": "/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic&limit=1&after=eyJ2IjoxLCJjIjoiLi4uIn0",
      "rel": "next",
      "type": "application/geo+json"
    }
  ],
  "features": [
    {
      "type": "Feature",
      "id": "FAC-001",
      "geometry": { "type": "Point", "coordinates": [100.61, 13.76] },
      "properties": {
        "name": "Bang Rak Health Center",
        "facility_type": "clinic",
        "operator": "Bangkok Metropolitan Administration",
        "updated_at": "2026-04-20T10:15:00Z"
      },
      "links": [
        {
          "href": "/ogc/v1/datasets/civic_registry/collections/facilities/items/FAC-001?facility_type=clinic",
          "rel": "self",
          "type": "application/geo+json"
        },
        {
          "href": "/ogc/v1/datasets/civic_registry/collections/facilities",
          "rel": "collection",
          "type": "application/json"
        }
      ]
    }
  ]
}
```

`numberMatched` is omitted in Phase 1 because cursor pagination does not require an exact count. OGC API Features permits omitting it when the matching count is unknown or difficult to compute. If an exact count becomes cheap and policy-safe for a provider, it may be populated with an integer.

Single Feature:

```json
{
  "type": "Feature",
  "id": "PARCEL-8842",
  "geometry": {
    "type": "Polygon",
    "coordinates": [
      [
        [100.611, 13.755],
        [100.615, 13.755],
        [100.615, 13.758],
        [100.611, 13.758],
        [100.611, 13.755]
      ]
    ]
  },
  "properties": {
    "parcel_id": "PARCEL-8842",
    "land_use": "residential",
    "district": "Bang Rak",
    "area_sqm": 1320.5,
    "source_version": "01HX2Y9X9T8PZ5V4Y2E8JZK6M1"
  },
  "links": [
    {
      "href": "/ogc/v1/datasets/civic_registry/collections/parcels/items/PARCEL-8842",
      "rel": "self",
      "type": "application/geo+json"
    },
    {
      "href": "/ogc/v1/datasets/civic_registry/collections/parcels",
      "rel": "collection",
      "type": "application/json"
    }
  ]
}
```

Do not add a top-level `collection` member to GeoJSON Features. Use the `collection` link relation.

## Collection Detail

Collection detail returns the same collection object as the collections list, plus query discovery fields when available:

```json
{
  "id": "civic_registry.facilities",
  "title": "Public facilities",
  "itemType": "feature",
  "crs": [
    "http://www.opengis.net/def/crs/OGC/1.3/CRS84"
  ],
  "storageCrs": "http://www.opengis.net/def/crs/OGC/1.3/CRS84",
  "properties": {
    "dataset_id": "civic_registry",
    "collection_id": "facilities",
    "propertyNames": ["facility_id", "name", "facility_type", "operator", "updated_at"],
    "supportedQueryParameters": ["limit", "bbox", "bbox-crs", "datetime", "after", "facility_type"]
  },
  "links": [
    { "href": "/ogc/v1/datasets/civic_registry/collections/facilities", "rel": "self", "type": "application/json" },
    { "href": "/ogc/v1/datasets/civic_registry/collections/facilities/items", "rel": "items", "type": "application/geo+json" }
  ]
}
```

Formal OGC API Queryables can be deferred, but `propertyNames`, `supportedQueryParameters`, and `crs` should be present from Phase 1 for discoverability.

## Geometry Mapping

Feature `id` comes from the entity primary key.

Feature `properties` starts from the same visible field projection as the entity route, then removes geometry carrier fields:

- point `longitude_field`
- point `latitude_field`
- GeoJSON `field`
- WKT `field`
- WKB `field`
- bbox helper fields, unless explicitly exposed as normal properties by a future config

Geometry source behavior:

- Point fields convert to GeoJSON `Point`.
- `geojson` accepts either a JSON object or a string containing a GeoJSON Geometry.
- Null geometry returns a Feature with `"geometry": null` on both collection and item routes.
- Invalid geometry returns a structured `500` only if it passed startup validation but fails at runtime. Config and ingest validation should catch common invalid cases where practical.
- Oversized geometries return a stable error before response serialization.

Returning `geometry: null` is the Phase 1 policy because RFC 7946 permits it and it avoids a side channel where item reads reveal that a row exists but lacks geometry.

## Aggregates

Existing non-spatial aggregates stay on:

```text
GET /datasets/{dataset_id}/{entity}/aggregates
GET /datasets/{dataset_id}/{entity}/aggregates/{aggregate_id}
```

An aggregate may become an OGC collection only if it is materialized or modeled as an entity with geometry. The OGC surface should not invent geometry for non-spatial aggregate rows.

Rule:

- Registry rows with geometry become OGC Features.
- Spatial aggregates with geometry become derived OGC collections.
- Non-spatial aggregates remain in the Registry Relay aggregate API.

## Pagination

Use Registry Relay cursor pagination rather than offset pagination. `limit` maps to the existing entity limit rules. `after` carries an opaque signed cursor token, never a raw primary key.

Response links:

- `self` always present.
- `first` always present and points to the same query without `after`.
- `next` present when another page exists.
- `collection` link present on item routes.
- `prev` is deferred because opaque forward cursors do not make reverse traversal cheap.

The OGC `offset` parameter is deferred.

## Audit

OGC item routes must produce audit records equivalent to entity row reads.

Audit fields should include:

- endpoint kind: `ogc_collection_items` or `ogc_feature`
- underlying kind: `entity_collection` or `entity_record`
- dataset id
- entity name
- collection id
- primary key for item reads
- purpose header when required or supplied
- row count
- null geometry count
- invalid geometry count
- stable error code on failure

The `underlying_kind` field lets existing alerting rules that watch entity reads correlate OGC access with normal registry access. Do not overload existing disclosure-control fields such as `suppressed_groups` for null geometry counts.

Do not log raw geometry, row values, API keys, fingerprints, or full request bodies.

## Catalog And Metadata

The canonical `/metadata/*` surfaces stay route-neutral. OGC access services
for spatial entities are advertised by the OGC API routes and the Relay-native
dataset discovery surfaces, not by a legacy `/catalog` route.

This requires a dedicated catalog code path for OGC distributions. It is not just a hook in the current DCAT-AP extension shape.

For each exposed collection, add links or distributions pointing to:

```text
/ogc/v1/datasets/{dataset_id}/collections/{collection_id}
/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items
```

OpenAPI should include OGC routes when the feature is enabled. It must remain metadata-filtered by the authenticated principal.

If CORS `allowed_origins` is widened for OGC clients, ensure `application/geo+json` and `application/problem+json` responses are intentional cross-origin read surfaces. Do not widen CORS as a side effect of this feature.

## Error Handling

Use `application/problem+json` for OGC route errors. Include a stable Registry Relay code in an extension member named `code`.

Example:

```json
{
  "type": "https://registry-relay.local/problems/spatial-filter-unsupported",
  "title": "Spatial filter is not supported",
  "status": 400,
  "detail": "Collection parcels cannot evaluate bbox without bbox fields or spatial predicate support.",
  "code": "spatial.filter_unsupported",
  "parameter": "bbox"
}
```

Candidate stable codes:

| Code | Meaning |
| --- | --- |
| `ogc.collection_not_found` | Dataset or collection does not exist or is not visible |
| `ogc.feature_not_found` | Feature does not exist, is not visible, or does not match required filters |
| `spatial.geometry_invalid` | Geometry field is malformed |
| `spatial.geometry_too_large` | Geometry exceeds configured vertex limit |
| `spatial.bbox_invalid` | Bbox parameter is malformed or unsupported in shape |
| `spatial.filter_unsupported` | A supported parameter name cannot be evaluated for this collection |
| `spatial.crs_unsupported` | CRS is not supported |
| `query.cursor_invalid` | Cursor is malformed, expired, or bound to different query context |

Prefer `spatial.filter_unsupported` with a `parameter` member over one error code per filter parameter.

## Implementation Plan

### Phase 1: OGC Surface Without Spatial UDFs

- Add config model and validation for `spatial`.
- Add `ogcapi-features` feature flag and optional dependencies.
- Add serialization tests for `ogcapi-types` output shape before wiring handlers.
- Add OGC metadata builder.
- Add read-only OGC routes under `/ogc/v1`.
- Support dataset-scoped collection URLs.
- Support point geometry and existing GeoJSON geometry fields.
- Return `geometry: null` consistently for null geometry.
- Support `limit`, signed `after`, `bbox`, `bbox-crs`, and `datetime`.
- Support `bbox` for point and bbox-column entities.
- Preserve auth, required filters, purpose headers, field projection, and audit.
- Add catalog links for spatial entities through a dedicated OGC distribution path.
- Add focused integration tests.

### Phase 2: DataFusion Spatial Predicates

- Add optional `spatial-datafusion` feature flag.
- Register `geodatafusion` UDFs on the shared `SessionContext` when enabled.
- Add WKT/WKB geometry config.
- Support `bbox` through `ST_Intersects` only when bbox columns are absent and UDF support is enabled.
- Consider antimeridian OR-split support.
- Keep geometry output conversion in Registry Relay.

### Phase 3: Broader OGC Compatibility

- Evaluate OGC conformance tests.
- Add formal Queryables if needed.
- Add better collection extents.
- Consider CRS negotiation and reprojection only with a clear dataset requirement.
- Consider upstream `ST_AsGeoJSON` separately if it benefits `geodatafusion`, not as a Registry Relay blocker.

## Test Plan

Config tests:

- accepts point spatial config
- accepts GeoJSON spatial config with bbox fields
- accepts duplicate collection ids across different datasets
- rejects duplicate collection ids within one dataset
- rejects missing geometry source
- rejects multiple geometry source fields inside one tagged geometry variant
- rejects non-numeric point and bbox fields
- rejects unsupported CRS, including EPSG:4326 unless explicit migration normalization is added
- rejects unknown geometry and datetime fields
- rejects unknown spatial fields through `deny_unknown_fields`
- rejects invalid `max_bbox_degrees` and `max_geometry_vertices`

API tests:

- landing page includes visible links and `service-desc`
- conformance returns `conformsTo` with core and GeoJSON URIs
- collections list only spatial entities visible to caller
- collection detail includes `crs`, `storageCrs`, `propertyNames`, and `supportedQueryParameters`
- collection detail respects metadata scope
- items read requires read scope
- item read by id requires the same required filters as collection reads
- item links preserve required filter context
- point geometry maps to GeoJSON Point
- GeoJSON object and GeoJSON string inputs produce the same geometry output
- null geometry returns `geometry: null` in collection and item routes
- bbox filters point data
- bbox filters bbox-column data
- bbox on unsupported geometry returns `spatial.filter_unsupported` with `parameter: "bbox"`
- antimeridian bbox is rejected in Phase 1
- bbox-crs accepts CRS84 and rejects other CRS values
- broad bbox above `max_bbox_degrees` is rejected
- datetime requires configured datetime field
- open-open datetime interval is rejected
- datetime precision is stable for date and timestamp fields
- required filters are still enforced when only bbox is supplied
- purpose header is still enforced
- signed cursor is stable across inserts and invalidates when filters, bbox, datetime, or principal changes
- field projection matches the entity route for the same principal
- oversized GeoJSON geometries are rejected
- audit records include OGC endpoint kind, underlying kind, and row counts

Verification:

- focused integration tests for the new routes
- `just fmt-check`
- `just lint`
- `just test`
- `just build`
- `just deny` when dependencies change

## Open Questions

- Should any collection opt into treating `bbox` as an enumeration control, and if so what policy cap is enough?
- Should EPSG:4326 migration normalization be allowed with an explicit warning field, or should Phase 1 reject it everywhere?
- Should derived spatial aggregates be modeled as normal entities or as a separate aggregate-backed OGC collection type?
- What exact page traversal cap should be enforced for signed OGC cursors if global rate limiting is absent?

## Parallel Delivery Plan

Implement the feature in small waves with parallel workers only where ownership is disjoint. Each worker must know that others may be editing the repository at the same time, must avoid reverting unrelated edits, and must list changed files and verification results before handoff.

### Wave 0: Contract And Fixtures

Goal: lock the public contract before handler work starts.

Parallel workers:

- Worker A owns OGC fixture payloads and serialization tests for landing, conformance, collection, FeatureCollection, Feature, and problem responses.
- Worker B owns demo config updates and config validation tests for `spatial`, tagged geometry sources, CRS84 rejection rules, bbox caps, vertex caps, and dataset-scoped collection ids.

Definition of done:

- The example payloads in this spec are represented by tests.
- Config parsing works with `serde(deny_unknown_fields)`.
- Invalid spatial config fails at startup with stable errors.
- `cargo test` passes for the focused serialization and config tests.
- A review checkpoint confirms the code contract still matches this document.

### Wave 1: Read-Only OGC Metadata Surface

Goal: expose discovery endpoints without item reads.

Parallel workers:

- Worker A owns route mounting and handlers for `/ogc/v1`, `/ogc/v1/conformance`, `/ogc/v1/collections`, and dataset-scoped collection detail.
- Worker B owns metadata projection, per-principal collection visibility, OpenAPI registration, and catalog OGC distribution links.

Definition of done:

- All metadata routes are auth-gated and metadata-filtered.
- Collection ids are dataset-scoped in URLs and collision-safe across datasets.
- Landing page includes `service-desc` when OpenAPI is enabled.
- Collection detail includes `crs`, `storageCrs`, `propertyNames`, and `supportedQueryParameters`.
- Focused integration tests pass, then `just fmt-check`, `just lint`, and `just test` pass.
- Code review verifies no entity read path or catalog behavior regressed.

### Wave 2: Feature Reads And Geometry Mapping

Goal: return OGC Features from existing entity reads.

Parallel workers:

- Worker A owns item collection reads, item-by-id reads, signed OGC cursor context, `limit`, and `after`.
- Worker B owns point and GeoJSON geometry mapping, `geometry: null`, vertex limits, property projection, item links, and `application/geo+json` response headers.
- Worker C owns auth, required filters, purpose headers, and audit correlation fields for OGC item routes.

Definition of done:

- Item-by-id reads enforce the same required filter semantics as collection reads.
- FeatureCollection links preserve required filter context and never expose raw cursor state.
- OGC properties match the entity route projection for the same principal, minus configured geometry carrier fields.
- Null geometry is returned as `geometry: null` on collection and item routes.
- Audit records include OGC endpoint kind and underlying entity kind.
- Focused integration tests cover auth, projection, null geometry, point geometry, GeoJSON object and string parity, cursor integrity, and audit.
- A reviewer checks security-sensitive paths before the wave is merged.

### Wave 3: Spatial And Temporal Filters

Goal: add bounded `bbox`, `bbox-crs`, and `datetime` behavior.

Parallel workers:

- Worker A owns `bbox` parsing, CRS84-only `bbox-crs`, antimeridian rejection, point translation, bbox-column overlap translation, and `max_bbox_degrees`.
- Worker B owns `datetime` parsing, open-open rejection, date and timestamp precision behavior, and `spatial.filter_unsupported`.
- Worker C owns problem responses and error taxonomy tests for OGC failures.

Definition of done:

- World-size or over-cap bbox queries are rejected before data access.
- `bbox-crs` accepts only CRS84.
- Antimeridian bboxes are rejected with a stable error.
- `datetime` behavior is deterministic for date and timestamp fields.
- Unsupported filters return `application/problem+json` with `code` and `parameter`.
- Tests cover required filters when only `bbox` is supplied.
- `just fmt-check`, `just lint`, `just test`, and `just build` pass.

### Wave 4: Release Gate

Goal: validate the feature as a complete slice before enabling it in any deployment config.

Parallel workers:

- Worker A runs the full verification ladder and dependency checks, including `just deny` if dependencies changed.
- Worker B performs a code-review pass focused on OGC compliance, response shapes, link relations, and media types.
- Worker C performs a code-review pass focused on enumeration risk, cursor binding, auth, audit, CORS, and error side channels.

Definition of done:

- Every Phase 1 item in the implementation plan is implemented or explicitly removed from scope by updating this spec.
- No "partial" handler, silent fallback, or placeholder response remains.
- All tests named in the Test Plan either exist or have a documented blocker.
- The final review confirms the feature preserves dataset, principal, required-filter, purpose-header, and projection boundaries.
- The final report lists changed files, commands run, results, skipped checks, residual risks, and the exact feature flag or config needed to enable the surface.
