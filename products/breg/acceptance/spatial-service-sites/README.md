# Spatial Service Sites Acceptance Fixture

This is a neutral synthetic Base Registry Engine source fixture for the first BReg GIS increment. It models one `service-site` entity with a CRS84 GeoJSON Point field named `location`, public map attributes, an optional null geometry case and a reviewed derived logical `map-label` attribute.

The public collection id is `service-site.map-reader`: entity `service-site`, profile `map-reader`, direct current-record list authority and an explicit bounded bbox grant. The quickstart connects QGIS to the protected `service-site.installation-map-reader` collection to exercise Mint renewal and the installation's `service_zones: central` row restriction. That profile uses the existing Mint client authorization claim mechanism: configure `registry_principal: synthetic-qgis-installation`, `registry_purpose: service-site-map`, scope `service-sites:map.read` and claim `service_zones: central` or another declared zone. No issuer change or fabricated runtime claim is required.

All authenticated profiles use the verified `registry_principal` claim, matching the quickstart's one runtime principal mapping. Mint's `sub` remains its client identity; it is not substituted for the declared fixture principal.

Profiles:

- `map-reader`: anonymous public `get` and `list`, public `location`, count, scalar filters and bbox with maximum spans of 0.25 longitude degrees and 0.20 latitude degrees.
- `installation-map-reader`: authenticated QGIS installation map reader with `service-sites:map.read`, purpose `service-site-map`, `zone` row boundary from the `service_zones` claim and the same bbox spans.
- `directory-reader`: anonymous nonspatial public list/get without the geometry field.
- `hidden-geometry-reader`: authenticated directory read where geometry is not readable and no spatial query is declared.
- `get-only-map-reader`: authenticated get-only geometry read with no bbox authority.
- `service-site-admin`: writable seed/admin profile with `service-sites:seed`, create/patch/batch and no data export. There is no QGIS editing profile.

The seed input in `fixtures/seed-service-sites.jsonl` contains 225 create operations with synthetic UUID `native-id` values. The records include dense central points, exact edge points, just-inside and just-outside bbox examples, and one null-geometry row. They are designed so normal page size 100 requires more than two pages.

The representative `tests/journeys.yaml` includes a declared public bbox query and a nonspatial-profile bbox refusal. Use the [spatial quickstart](../../quickstart/README.md#spatial-service-site-quickstart) to bootstrap PostGIS, run these journeys and connect QGIS with a Mint installation credential. Its refresh exercise imports `fixtures/qgis-refresh-service-site.jsonl` through the ordinary batch API after connecting QGIS.

Useful offline checks:

```bash
cargo run --locked -p registry-bregctl -- project lock products/breg/acceptance/spatial-service-sites --check
cargo run --locked -p registry-bregctl -- check products/breg/acceptance/spatial-service-sites --production
mkdir -p out
cargo run --locked -p registry-bregctl -- generate openapi products/breg/acceptance/spatial-service-sites --production --output out/spatial-service-sites-openapi
```

`check` reports `access.profile.anonymous_collection` for `directory-reader` and `map-reader`. Both profiles grant `list` to unauthenticated callers on purpose, so every service site is public; `--deny-findings` would turn those two findings into failures.

The offline commands validate authored source and generated contracts. They do not exercise QGIS, Mint renewal or database execution; use the quickstart and the product's PostgreSQL tests for those paths.
