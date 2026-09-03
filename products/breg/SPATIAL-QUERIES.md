# Point queries and QGIS

Base Registry Engine can expose a stored CRS84 Point as GeoJSON and grant bounded
current-record bounding-box queries. PostGIS is required for every spatial
predicate. Ordinary Point storage, validation, history and GeoJSON reads that
do not use a spatial predicate work without PostGIS.

Start with the [spatial quickstart](quickstart/README.md#spatial-service-site-quickstart)
for a complete project, local database bootstrap, Mint installation credential
and QGIS connection. The [service-site fixture](acceptance/spatial-service-sites/README.md)
contains public and protected map profiles, a hidden-geometry profile, a
get-only profile and synthetic edge/null cases.

## Author one geometry and an explicit query grant

On an entity with a stored `crs84-point` field, declare its primary geometry:

```yaml
geojson:
  geometryField: location
```

On the existing access-profile grant for that entity, add:

```yaml
spatialQueries:
  bbox:
    maximumLongitudeSpanDegrees: 0.25
    maximumLatitudeSpanDegrees: 0.20
```

The grant needs direct `list` authority and must allow reading the primary
Point. Span limits must be positive finite numbers, at most 360 longitude
degrees and 180 latitude degrees. Fractional limits are supported. Geometry
selection belongs to the entity; the bbox grant does not repeat a field name.

Reading a Point does not grant bbox access. Installing PostGIS does not grant
access either. Existing scope, purpose, row, field and count restrictions still
apply to the exact selected profile. Points cannot be declared as scalar
filter, sort, selector or row-boundary fields.

## Native requests and responses

For the public map profile in the fixture, request:

```http
GET /v1/records/service-sites?accessProfile=map-reader&bbox=100.54,13.74,100.56,13.76
Accept: application/geo+json
```

The order is west, south, east, north in longitude/latitude degrees. Edges are
inclusive. A zero-width or zero-height box is valid; null Points do not match.
The input accepts four finite decimal or exponent values with a leading digit.
Both the input and its canonical decimal form are bounded to 256 bytes, so an
extreme exponent can exceed the budget even when its input text is short.
Crossing the antimeridian, inverted bounds, a third dimension,
out-of-range coordinates and a span above the grant are refused. Bbox can be
combined with permitted scalar filters using AND. It is unavailable on
historical reads, lookups and relationship read paths.

`Accept: application/json` retains the native JSON representation. GeoJSON
`get` returns a Feature; a direct list returns a FeatureCollection. A feature's
`id` is the native record ID, `geometry` is the selected Point and `properties`
contains the other selected logical fields, including authorized derived
fields. Revision metadata is in `registry.revision`.

If `$select` omits the readable primary Point, GeoJSON emits `geometry: null`.
A profile that cannot read the primary Point cannot request this representation
or use bbox. A GeoJSON get does not supply a mutation ETag.

Follow `registry.pageInfo.nextCursor` with the native `$skiptoken` option and
normal authorization on every request. A cursor binds the effective query, selection, page size,
profile, authority, package and representation. Do not change those options
on continuation. Pages read live data, not a frozen snapshot; concurrent writes
can affect traversal. Count remains separately authorized and opt-in.

GeoJSON responses and bbox query responses are limited to 2 MiB of canonical
JSON bytes. A response above that limit fails atomically through the read
service's `source.unavailable` refusal, without a partial feature collection.
Use a smaller page size or select fewer fields when records are large. The
limit bounds released response bytes, not total database or process memory.

## QGIS connection

The in-process `/v1/gis` adapter serves the QGIS OAPIF provider. Its collection
IDs are `entity-id.profile-id`, so changing a profile cannot silently select
another profile's authority. Only direct list grants with readable primary
geometry and explicit bbox capability are advertised.

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
`numberReturned`; it does not compute hidden extents or counts. Follow the
[quickstart's OAuth2 connection steps](quickstart/README.md#spatial-service-site-quickstart)
and keep credentials in the QGIS authentication store, not in URLs or project
source. Removing a Mint installation client prevents subsequent renewal but
does not erase data already cached by QGIS.

The six routes are landing, API description, conformance, collection listing,
collection detail and collection items. There is no adapter item-detail route,
editing, custom QGIS plugin, direct database access or full OGC conformance
claim. Unsupported formats, CRS options and filter languages are refused.

## Database and upgrades

GIS requires PostgreSQL 16 or later and PostGIS 3.5 or later. The quickstart
pins PostgreSQL 17 with PostGIS 3.5.2. An administrator installs PostGIS into
the admin-owned `registry_spatial_ext` schema and provisions the non-login bbox
role. Runtime and migration roles cannot install or upgrade the extension.
The bbox role owns only generated views that return matching record IDs. It
cannot write data, own tables or bypass row security. The ordinary runtime has
no membership in that role; it joins the ID views while computing authorized
attributes, derived values, filters and pages through the normal read path.

Run `bregctl doctor --runtime-config /absolute/path/to/runtime.yaml`
to check the configured package and startup dependencies without opening a
listener. If a GIS package reports `startup.database.unready`, have the database
administrator verify the supported PostGIS version, extension schema, schema
USAGE grants and bbox-role privileges as well as the package's maintenance and
schema state. Do not give the runtime role extension-installation authority to
work around the refusal.

The package generates one stored geometry projection and partial GiST index
for the queried primary Point. JSONB remains the sole writable source. Internal
geometry columns do not become logical fields or appear in history or exports.
PostGIS types, functions and operators are schema-qualified.

Adding or changing the geometry binding or bbox grant requires the normal
reviewed successor lifecycle. The compiler derives the projection/index DDL;
an author does not write dummy SQL to enable bbox on an existing Point.
Missing prerequisites refuse before maintenance begins. An apply failure
after maintenance begins keeps records unavailable until the existing
reviewed recovery procedure completes. Removing the last bbox grant removes
its generated projection/index and helper, while preserving Point data,
history and the administrator-owned extension and role.

Adding the stored projection can rewrite existing rows, and creating its index
takes locks and additional disk space. Plan a maintenance window and a tested
backup/restore path for an existing registry. The small quickstart does not
establish an online migration or a safe conversion time for production volumes.
