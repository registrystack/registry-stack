# Base Registry Engine Generic Quickstart

This is the shortest local adopter path for Base Registry Engine. It starts a
domain-neutral registry from `bregctl init`, checks it, runs
disposable PostgreSQL and Registry Mint on loopback, obtains a short-lived Mint
token, posts one record, and reads that record back from Base Registry Engine.

The launcher replaces only the initialized project's package identity, with a
local one, before `check`, `test`, and `package`. It adds no model, profile, or
catalogue metadata of its own; everything else the registry exposes comes from
the initialized project.

Prerequisites are Docker, OpenSSL, Python 3, and `uv`, plus Cargo unless you
pass `--installed`.

```bash
products/breg/quickstart/run.sh
```

The first run builds `breg`, `bregctl`, and `mint`, then
pulls the pinned PostgreSQL image if Docker does not already have it. With
`--installed`, the launcher skips the build and uses the `breg`, `bregctl`, and
`mint` found on `PATH`, which is how a released install runs it. When the
launcher prints `Base Registry Engine generic quickstart is ready`, leave that
terminal running.

In another terminal, read the created record:

```bash
products/breg/quickstart/query.sh get <record-id>
```

Or create and read another generic record:

```bash
products/breg/quickstart/query.sh all
```

The helper reads the bearer token from `quickstart/.run/secrets/operator-token`.
It does not put the token on the command line or print it. The launcher writes
the local runtime configuration it used to `.run/runtime.yaml`.

For a non-interactive check of the full local path, run:

```bash
products/breg/quickstart/run.sh --smoke
```

## Change-request examples

The configurable change-request examples use the same local quickstart model:
protected token files, generated runtime configuration, `bregctl`
checks, and HTTP calls against the compiled REST surface. Start with the
structural CLI journey in [`../CHANGE_REQUEST_EXAMPLES.md`](../CHANGE_REQUEST_EXAMPLES.md):
check both fixture directories, inspect `explain change-requests`, then run
`products/breg/scripts/test-change-request-examples.sh --env /path/to/test.env`.
The env file contains `BREG_TEST_DATABASE_URL` and
`BREG_TEST_TLS_CA_PEM_PATH`; the full guide shows the exact file
shape and disposable fixture override flags for local authoring edits. The
script uses the same owner-only runtime config and role token file pattern as
the quickstart and demo paths.

The request action flow is GET-driven. For submit, review, revise, cancel, and
apply, fetch the request record first and use the matching
`request.actions[].ifMatch` value as the action `If-Match` header. Do not reuse
the normal record `ETag` for request actions.

## Spatial service-site quickstart

Use `--spatial` to run the synthetic service-site fixture instead of the generic `bregctl init` project:

```bash
products/breg/quickstart/run.sh --spatial
```

The spatial mode keeps the same local Mint, package, apply, TLS-verified database, and Base Registry Engine path as the generic quickstart. It switches the project source to `products/breg/acceptance/spatial-service-sites`, gives that copied source local package identity, enables a PostGIS database image, seeds synthetic service-site records, and leaves the server running for QGIS.

Spatial mode uses the pinned image `postgis/postgis@sha256:01a6a70e41e6c4467c8f55f6063555ed72db2d6662cd0d571040d42eadaeb6f6`, which is the `17-3.5` image. On Apple Silicon the launcher passes `--platform linux/amd64`, so Docker Desktop may run it under emulation. The ordinary generic path still uses the plain pinned PostgreSQL image.

The database bootstrap keeps PostGIS admin-owned in `registry_spatial_ext`. The local admin step installs the extension, revokes `CREATE` from public, migration, and runtime roles, revokes all public access on the extension schema, and grants schema usage only to migration, runtime, and the non-login bbox helper role. The quickstart bbox role is `registry_quickstart_runtime__spatial_bbox`; it is `NOLOGIN`, owns only generated candidate-ID views, and has no permanent `CREATE` privilege. It is granted to the migration role only with `INHERIT FALSE`, `SET TRUE`, and `ADMIN FALSE` for governed view ownership transfer. Runtime does not receive bbox role membership. The bbox role does not receive its own database `CONNECT` grant.

For a non-interactive spatial smoke, run:

```bash
products/breg/quickstart/run.sh --spatial --smoke
```

That path runs the existing `test`, `package`, `apply`, and server startup flow, then uses synthetic API writes and bbox reads. It checks JSON record listing, GeoJSON output, and the OGC API Features items route for the protected QGIS collection.

The connection recipe targets QGIS 4.2.1 and GDAL 3.12.4. After `run.sh --spatial` prints ready:

Start an empty QGIS project and set its project CRS to **OGC:CRS84 (WGS 84 (CRS84))** using the bottom-right CRS control. In the Locator, enter `go 100.55,13.75` and choose the result in the current project CRS. Set the status-bar **Scale** to `1:5000`. Switch the coordinate display to **Extents** and leave a margin below the grant: keep the longitude span below `0.24` degrees and latitude span below `0.19` degrees before adding the layer. The BReg's exact limits remain `0.25` and `0.20`; QGIS coordinate serialization can put an apparently exact-limit extent slightly over its grant. Use `1:2500` if the window makes the extent too wide. A fresh world extent exceeds this fixture's query grant.

1. Open **Settings > Options > Authentication > Configurations** and **Add a new authentication configuration**. Set a master password if prompted. Give the configuration a recognizable name and set **Resource URL** to the printed **Base Registry Engine** value, without `/v1/gis`.
2. Select **OAuth2 authentication**, **Grant flow: Client Credentials**, and **Resource access token method: Header**. Set **Token URL** to `http://127.0.0.1:<mint-port>/token`, using the printed Mint port, and **Client ID** to `qgis-installation-central`.
3. Read **Client secret** from the printed owner-only file under `quickstart/.run/secrets/qgis-client-secret`. Leave **Scope** empty to use the configured Mint grant and leave **Persist between launches** off for the token session. Save the configuration. Never paste the secret into shell history, logs or project files.
4. Open **Layer > Data Source Manager > WFS / OGC API - Features > New...**. Name the connection and set **URL** to `http://127.0.0.1:<breg-port>/v1/gis`. Select the saved OAuth2 configuration under **Authentication**. Keep GET and feature paging enabled where shown; set **Page size** to `25` for this exercise, then select **OK**.
5. Choose that connection under **Server Connections**, select **Connect**, and select `service-site.installation-map-reader`. This protected collection exercises Mint renewal and the installation's `service_zones: central` restriction. The separate `service-site.map-reader` collection is anonymous.
6. Check **Only request features overlapping the view extent** and select **Add**. This is the provider option `restrictToRequestBBOX=1`; **Page size** maps to `pageSize`. Pan within the fixture's small declared bbox limits rather than requesting the entire world.

These controls are described in the [QGIS authentication guide](https://docs.qgis.org/4.2/en/docs/user_manual/auth_system/auth_overview.html) and [WFS / OGC API Features client guide](https://docs.qgis.org/4.2/en/docs/user_manual/working_with_ogc/ogc_client_support.html). A saved layer or project may contain an `authcfg` reference. That reference points to QGIS's authentication database; the client secret must remain in that database or the owner-only quickstart file, never in the layer URL or project content.

The QGIS principal is an installation client, not a human user. It is read-only and scoped to `service-sites:map.read`, purpose `service-site-map`, principal `synthetic-qgis-installation`, and claim `service_zones: central`. Spatial mode uses 60-second access tokens so the connection exercises Mint renewal. The operator client remains a separate private-key client used for local seed writes. Removing or rotating the QGIS client stops new token renewal, but it does not erase data QGIS has already cached locally.

The in-process adapter exposes six GIS routes and reuses BReg authorization, read plans and audited GeoJSON output. It advertises an empty OGC API conformance list because it does not implement the full standard. Collection paging reads live data. If a native record request omits the readable geometry with `$select`, GeoJSON represents it as `null`; a profile that cannot read the primary geometry cannot request GeoJSON or bbox.

To check refresh after a BReg write, leave the launcher running and open another terminal at the repository root. This imports one additional synthetic point through the ordinary authenticated batch API. Run it once per disposable quickstart; its checkpoint makes retries resumable. After a `--installed` run, use the `bregctl` and `mint` on `PATH` in place of the `target/debug/` paths.

```bash
spatial_run="$PWD/products/breg/quickstart/.run"
spatial_input="$PWD/products/breg/acceptance/spatial-service-sites/fixtures/qgis-refresh-service-site.jsonl"
target/debug/bregctl data validate \
  --package "$spatial_run/build/package" \
  --entity service-site --profile service-site-admin --operation create \
  --input "$spatial_input"

spatial_refresh_token="$spatial_run/secrets/refresh-token-$(openssl rand -hex 8)"
target/debug/mint token \
  --url "$(cat "$spatial_run/mint-origin")/token" \
  --client-id generic-quickstart \
  --key "$spatial_run/keys/operator/signing-p256-private-jwk" |
  python3 products/breg/quickstart/support/quickstart.py \
    store-token --out "$spatial_refresh_token"
target/debug/bregctl data import \
  --package "$spatial_run/build/package" \
  --breg-url "$(cat "$spatial_run/breg-origin")" \
  --access-token-file "$spatial_refresh_token" \
  --entity service-site --profile service-site-admin --operation create \
  --input "$spatial_input" \
  --checkpoint "$spatial_run/qgis-refresh-checkpoint.json"
```

Refresh the QGIS layer and its attribute table. Look for `SVC-QGIS-REFRESH` near longitude `100.550123456`, latitude `13.750123456`, with the derived `mapLabel` attribute. Pan within the allowed extent and refresh again after a minute to exercise token renewal. The operator token stays in an owner-only file and is never copied into QGIS.

For the offline structural self-test, which does not start Docker or use the
network, run:

```bash
products/breg/quickstart/self-test.sh
```

All generated configuration, keys, tokens, logs, package artifacts, and
database URLs live under `quickstart/.run/`, which is ignored by Git and created
owner-only. A new run replaces only that quickstart-owned directory after
checking that it is not a symbolic link.

This is deliberately a local-development route. It uses Mint's supervised
local-development profile, loopback HTTP, disposable PostgreSQL or PostGIS in spatial mode, and an unsigned
local package. Production pilots still require the separate package-signing,
database-role, migration, TLS, and operational lifecycle described in the
product README.
