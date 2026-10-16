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
commands from `PATH`. The launcher initializes the canonical local directory,
starts its retained dev session, and obtains short-lived client tokens. It
creates and reads a contact, then verifies that a client from another
jurisdiction receives a concealed refusal for the same record.

Leave the launcher running, then use the query helper in another terminal:

```bash
products/breg/quickstart/query.sh list
products/breg/quickstart/query.sh all
products/breg/quickstart/query.sh create "Example contact" contact@example.test
```

The helper reads `.run/headers/editor.header`. It does not put the bearer token
on the command line or print it. A non-interactive check starts the same services,
exercises the API, and removes the owned dev session:

```bash
products/breg/quickstart/run.sh --smoke
```

## Spatial service-site fixture

The spatial mode copies the maintained synthetic service-site project, including
its explicit local clients and journeys. The administrative
client can seed sites. The installation map reader is read-only, carries
`service_zones: central`, and is restricted by the authored bbox limits.

```bash
products/breg/quickstart/run.sh --spatial --smoke
```

This mode seeds the fixture through the authenticated record API, checks the
protected bbox list, and reads the same bounded collection as GeoJSON through
the OGC API Features route. Applications can use the public HTTP calls
demonstrated by the smoke. A production
client must use its institution's private-key JWT token provider and keep the
resulting authorization header private.

Run the offline structural check with:

```bash
products/breg/quickstart/self-test.sh
```

All disposable files are under `quickstart/.run/`. The launcher removes its
owned dev session after a successful run. It retains failed or interrupted state
for diagnosis; stop that owned session before removing `.run/` and retrying.
Production deployments require an operated issuer, reviewed packages, and an
operated PostgreSQL service.
