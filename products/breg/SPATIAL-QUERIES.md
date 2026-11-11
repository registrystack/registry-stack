# CRS84 geometry queries and QGIS

Base Registry Engine can expose a stored CRS84 Point, Polygon or MultiPolygon
as GeoJSON and grant bounded current-record bounding-box queries. PostGIS is
required for every spatial predicate. Polygon and MultiPolygon storage always
requires PostGIS. Ordinary Point storage, validation, history and GeoJSON reads
that do not use a spatial predicate work without it.

Start with the [spatial quickstart](quickstart/README.md#spatial-service-site-quickstart)
for a complete project, local database bootstrap, stock-issuer client, and protected
GeoJSON smoke. The [service-site fixture](acceptance/spatial-service-sites/README.md)
contains public and protected Point map profiles, a separate Polygon collection,
a hidden-geometry profile, a get-only profile and synthetic edge/null cases.

## Author stored geometries and an explicit query grant

Each Record type may declare multiple stored geometry fields. Choose one stored
`crs84-point` or `crs84-polygon` field as the primary GeoJSON geometry through
`geojson.geometryField`. A polygon field accepts both Polygon and MultiPolygon
values:

```yaml
fields:
  - id: boundary
    type: crs84-polygon
    precision: 9
    maximumPositions: 10000
    bbox:
      west: "100.450000000"
      south: "13.600000000"
      east: "100.700000000"
      north: "13.900000000"

geojson:
  geometryField: boundary
```

`precision` is required and ranges from 0 through 9. `maximumPositions` is
required and ranges from 4 through 10,000, counting every position in every
ring and Polygon part, including each closing position. The optional `bbox`
uses the same west, south, east and north bounds as a Point field.

The value is a closed two-dimensional GeoJSON object with only `type` and
`coordinates`. Its type is `Polygon` or `MultiPolygon`. Rings contain at least
four positions and must close exactly. Foreign members, a third coordinate,
invalid topology and a consecutive longitude change greater than 180 degrees
are refused. Split a shape at the antimeridian and represent its parts as a
MultiPolygon. BReg preserves the geometry, ring order and winding the caller
provided. It does not derive or store an area value.

On the existing access-profile grant for that Record type, add:

```yaml
spatialQueries:
  bbox:
    maximumLongitudeSpanDegrees: 0.25
    maximumLatitudeSpanDegrees: 0.20
```

The grant needs direct `list` authority and must allow reading the primary
geometry. Span limits must be positive finite numbers, at most 360 longitude
degrees and 180 latitude degrees. Fractional limits are supported. Geometry
selection belongs to the Record type. The bbox grant does not repeat a field
name.

Reading a geometry does not grant bbox access. Installing PostGIS does not grant
access either. Existing scope, purpose, row, field and count restrictions still
apply to the exact selected profile. Geometry fields cannot be declared as
scalar filter, sort, selector or row-boundary fields.

## Native requests and responses

For the public map profile in the fixture, request:

```http
GET /v1/records/service-sites?accessProfile=map-reader&bbox=100.54,13.74,100.56,13.76
Accept: application/geo+json
```

The order is west, south, east, north in longitude/latitude degrees. Edges are
inclusive. A zero-width or zero-height box is valid. Null geometries do not
match. A Polygon or MultiPolygon matches only when its actual geometry
intersects the box. An overlap between their bounding envelopes alone is not a
match.
The input accepts four finite decimal or exponent values with a leading digit.
Both the input and its canonical decimal form are bounded to 256 bytes, so an
extreme exponent can exceed the budget even when its input text is short.
Crossing the antimeridian, inverted bounds, a third dimension,
out-of-range coordinates and a span above the grant are refused. Bbox can be
combined with permitted scalar filters using AND. It is unavailable on
historical reads, lookups and relationship read paths.

`Accept: application/json` retains the native JSON representation. GeoJSON
`get` returns a Feature. A direct list returns a FeatureCollection. A feature's
`id` is the native record ID, `geometry` is the selected primary geometry and
`properties` contains the other selected logical fields, including authorized
derived fields. Revision metadata is in `registry.revision`.

If `$select` omits the readable primary geometry, GeoJSON emits `geometry: null`.
A profile that cannot read the primary geometry cannot request this representation
or use bbox. A GeoJSON get does not supply a mutation ETag.

Follow `registry.pageInfo.nextCursor` with the native `$skiptoken` option and
normal authorization on every request. A cursor binds the effective query,
selection, page size, profile, authority, package and representation. Do not
change those options on continuation. Pages read live data, not a frozen
snapshot. Concurrent writes can affect traversal. Count remains separately
authorized and opt-in.

GeoJSON responses and bbox query responses are limited to 2 MiB of canonical
JSON bytes. A response above that limit fails atomically through the read
service's `source.unavailable` refusal, without a partial feature collection.
Use a smaller page size or select fewer fields when records are large. The
limit bounds released response bytes, not total database or process memory.

## QGIS connection

The in-process `/v1/gis` adapter serves the QGIS OAPIF provider. Its collection
IDs are `entity-id.profile-id`, so changing a profile cannot silently select
another profile's authority. Only direct list permissions with readable primary
geometry and explicit bbox capability are advertised.

The landing document advertises `breg-gis-bounded-crs84-point-bbox-v1` when
the caller can see only Point collections. If any visible collection uses a
Polygon or MultiPolygon, it advertises
`breg-gis-bounded-crs84-geometry-bbox-v1`. A Point collection detail retains
the profile `bounded-crs84-point-bbox`. A Polygon collection detail uses
`bounded-crs84-polygon-bbox`.

GIS deployments require an operator-configured origin:

```yaml
listener:
  bind: 127.0.0.1:8080
  publicOrigin: http://127.0.0.1:8080
```

Use HTTPS outside loopback development. The value may include a deployment path
prefix, such as `https://registry.example.org/registry-a`, but not credentials,
a query string or a fragment. Discovery, paging and schema links preserve that
prefix and never use request Host or forwarded headers. QGIS requires absolute
links to retain authentication and follow every page.

The adapter accepts `bbox`, `limit`, `cursor` and `f=json`. An oversized `limit`
is clamped to the compiled page maximum, with an opaque cursor-only next link
when more rows remain. It returns flat authorized attributes and
`numberReturned`. It does not compute hidden extents or counts. The maintained
stock-issuer quickstart has no QGIS authentication recipe because that issuer
accepts private-key JWT clients only. To connect QGIS to a protected collection,
configure an institution-operated issuer flow that QGIS supports and keep its
credentials in the QGIS authentication store, not in URLs or project source.
Removing the client at its issuer prevents subsequent renewal but does not erase
data already cached by QGIS.

The six routes are landing, API description, conformance, collection listing,
collection detail and collection items. There is no adapter item-detail route,
editing, custom QGIS plugin, direct database access or full OGC conformance
claim. Unsupported formats, CRS options and filter languages are refused.

## Database and upgrades

Polygon storage and every bbox query require PostgreSQL 17 or later and PostGIS
3.5 or later. A Point-only package with no bbox grant does not require PostGIS.
The quickstart pins PostgreSQL 17 with PostGIS 3.5.2. An administrator installs
PostGIS into the admin-owned `registry_spatial_ext` schema. When the package
grants bbox, the administrator also provisions the non-login bbox role. Runtime
and migration roles cannot install or upgrade the extension.
The bbox role owns only generated views that return matching record IDs. It
cannot write data, own tables or bypass row security. The ordinary runtime has
no membership in that role. It joins the ID views to compute authorized
attributes, derived values, filters and pages through the normal read path.

Run `bregctl doctor --runtime-config /absolute/path/to/runtime.yaml`
to check the configured package and startup dependencies without opening a
listener. If a GIS package reports `startup.database.unready`, have the database
administrator verify the supported PostGIS version, extension schema, schema
USAGE grants and bbox-role privileges as well as the package's maintenance and
schema state. Do not give the runtime role extension-installation authority to
work around the refusal.

The package always generates a stored PostGIS geometry column and GiST index
for a Polygon field. It generates the equivalent column and partial GiST index
for a Point only when a profile grants bbox. JSONB remains the sole writable
source. Internal geometry columns do not become logical fields or appear in
history or exports. PostGIS types, functions and operators are schema-qualified.

Adding or changing the geometry binding or bbox grant requires the normal
reviewed successor lifecycle. The compiler derives the projection/index DDL.
an author does not write dummy SQL to enable spatial storage or bbox.
Missing prerequisites refuse before maintenance begins. An apply failure
after maintenance begins keeps records unavailable until the existing
reviewed recovery procedure completes. Removing the last bbox grant removes
the helper. It also removes a Point's generated projection and index when no
other bbox grant needs them. A Polygon keeps its generated projection and index.
Stored data, history and the administrator-owned extension and role remain.

Adding the stored projection can rewrite existing rows, and creating its index
takes locks and additional disk space. Plan a maintenance window and a tested
backup/restore path for an existing registry. The small quickstart does not
establish an online migration or a safe conversion time for production volumes.
