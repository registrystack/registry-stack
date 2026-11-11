# Spatial service sites acceptance fixture

This is a neutral synthetic Base Registry Engine source fixture for bounded CRS84 geometry reads.
It keeps the existing `service-site` Record type with a GeoJSON Point field named `location`,
public map attributes, an optional null geometry case, and a reviewed derived logical `map-label`
attribute.
It adds a separate `service-area` Record type whose required `boundary` field accepts a GeoJSON
Polygon or MultiPolygon.

The public map collection id is `service-site.map-reader`: Record type `service-site`, profile
`map-reader`, direct current-record list authority, and an explicit bounded bbox grant.
The quickstart calls the protected `service-site.installation-map-reader` collection with a
stock-issuer client to exercise the installation's `service_zones: central` row restriction.
That client registration supplies `registry_principal: synthetic-qgis-installation`,
`registry_purpose: service-site-map`, scope `service-sites:map:read`, and claim
`service_zones: central`.
No fabricated runtime claim is required.

The polygon collection id is `service-area.area-map-reader`.
Its caller sees only the polygon collection. The existing `map-reader` caller continues to see
only the point collection.
This separation lets GIS acceptance prove the point-only landing profile and the landing profile
used when at least one polygon collection is visible.

Every profile uses the verified `registry_principal` claim, matching the quickstart's one runtime
principal mapping. The token's `sub` remains its client identity. It is not substituted for the
declared fixture principal.

Profiles:

- `map-reader`: public map reader with `service-sites:public:read`, purpose
  `service-site-public-map`, `get` and `list` over every site, public `location`, count, scalar
  filters, and bbox with maximum spans of 0.25 longitude degrees and 0.20 latitude degrees.
- `area-map-reader`: public polygon map reader with `service-areas:public:read`, purpose
  `service-area-public-map`, `get` and `list` over every area, public `boundary`, count, scalar
  filters, and the same bbox spans.
- `installation-map-reader`: authenticated QGIS installation map reader with
  `service-sites:map:read`, purpose `service-site-map`, `zone` row boundary from the
  `service_zones` claim, and the same bbox spans.
- `directory-reader`: public directory reader with `service-sites:public:read`, purpose
  `service-site-public-directory`, nonspatial list/get over every site without the geometry field.
- `hidden-geometry-reader`: authenticated directory read where geometry is not readable and no
  spatial query is declared.
- `get-only-map-reader`: authenticated get-only geometry read with no bbox authority.
- `service-site-admin`: writable seed/admin profile with `service-sites:seed`, create and patch for
  both Record types, batch for service sites, and no data export. There is no QGIS editing profile.

The seed input in `fixtures/seed-service-sites.jsonl` contains 225 create operations with synthetic
UUID `native-id` values. The records include dense central points, exact edge points, just-inside
and just-outside bbox examples, and one null-geometry row. They are designed so normal page size
100 requires more than two pages.

The representative `tests/journeys.yaml` includes the existing Point bbox query and nonspatial
profile refusal.
It also creates one Polygon that intersects the representative query and a MultiPolygon whose
combined envelope overlaps that query although neither polygon intersects it.
The native create expectations preserve each GeoJSON geometry exactly, and the polygon bbox
expectation returns only the intersecting Record.
Use the [spatial quickstart](../../quickstart/README.md#spatial-service-site-quickstart) to bootstrap
PostGIS and run the protected Point GeoJSON journey with a stock-issuer client.
Its optional refresh exercise imports `fixtures/qgis-refresh-service-site.jsonl` through the
ordinary batch API.

Useful offline checks:

```bash
cargo run --locked -p registry-bregctl -- project lock products/breg/acceptance/spatial-service-sites --check
cargo run --locked -p registry-bregctl -- check products/breg/acceptance/spatial-service-sites --production
mkdir -p out
cargo run --locked -p registry-bregctl -- generate openapi products/breg/acceptance/spatial-service-sites --production --output out/spatial-service-sites-openapi
```

The offline commands validate authored source and generated contracts. They do not exercise token
acquisition or database execution. Use the quickstart and the product's PostgreSQL tests for those
paths.
