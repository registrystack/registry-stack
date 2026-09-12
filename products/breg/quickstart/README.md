# Base Registry Engine quickstart

This launcher starts a local Registry project with the maintained `bregctl dev`
lifecycle. It uses the pinned stock ThunderID issuer, private-key JWT clients,
a retained PostgreSQL database, and Base Registry Engine on loopback. Credentials
stay in owner-only files.

Prerequisites are Docker and Python 3, plus Cargo unless released `breg` and
`bregctl` binaries are already installed.

```bash
products/breg/quickstart/run.sh
```

The source run builds `breg` and `bregctl`. Use `--installed` to select the two
commands from `PATH`. The launcher initializes the generic project, starts its
retained dev session, acquires a fresh operator header with `bregctl dev token`,
creates one record, and reads it back.

Leave the launcher running, then use the query helper in another terminal:

```bash
products/breg/quickstart/query.sh list
products/breg/quickstart/query.sh all
products/breg/quickstart/query.sh create QS-002 "Another synthetic record"
```

The helper reads `.run/headers/operator.header`. It does not put the bearer token
on the command line or print it. A non-interactive check starts the same services,
exercises the API, and removes the owned dev session:

```bash
products/breg/quickstart/run.sh --smoke
```

## Spatial service-site fixture

The spatial mode copies the maintained synthetic service-site project and adds
explicit stock-issuer clients for its protected profiles. The administrative
client can seed sites. The installation map reader is read-only, carries
`service_zones: central`, and is restricted by the authored bbox limits.

```bash
products/breg/quickstart/run.sh --spatial --smoke
```

This mode seeds the fixture through the authenticated record API, checks the
protected bbox list, and reads the same bounded collection as GeoJSON through
the OGC API Features route. The former QGIS OAuth recipe is retired because the maintained local issuer
accepts private-key JWT clients only. Applications
can copy the public HTTP calls demonstrated by the smoke, while a production
client must use its institution's private-key JWT token provider and keep the
resulting authorization header private.

To import the optional refresh record while a spatial run remains active, first
acquire a fresh operator header and pass that protected file to `bregctl`:

```bash
spatial_run="$PWD/products/breg/quickstart/.run"
target/debug/bregctl --format json dev token operator "$spatial_run/project" \
  >"$spatial_run/refresh-token-report.json"
header_file=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["headerFile"])' \
  "$spatial_run/refresh-token-report.json")
target/debug/bregctl data import \
  --package "$spatial_run/project/.breg/dev/package" \
  --breg-url "$(cat "$spatial_run/breg-origin")" \
  --header-file "$header_file" \
  --entity service-site --profile service-site-admin --operation create \
  --input products/breg/acceptance/spatial-service-sites/fixtures/qgis-refresh-service-site.jsonl \
  --checkpoint "$spatial_run/qgis-refresh-checkpoint.json"
```

Run the offline structural check with:

```bash
products/breg/quickstart/self-test.sh
```

All disposable files are under `quickstart/.run/`. The launcher removes its
owned dev session on exit. Production deployments require an operated issuer,
signer custody, signed packages, and an operated PostgreSQL service.
