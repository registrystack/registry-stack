# Base Registry Engine demos

The demo launcher copies one maintained acceptance project into disposable local
state and runs it through `bregctl dev`. The retained lifecycle starts the
pinned stock ThunderID issuer, private-key JWT clients, PostgreSQL, and Base
Registry Engine. It then seeds synthetic records through the authenticated API
and exercises the selected fixture's reads.

Prerequisites are Docker and Python 3, plus Cargo unless released `breg` and
`bregctl` commands are installed.

```bash
products/breg/demo/run.sh
products/breg/demo/run.sh --installed
products/breg/demo/run.sh --smoke
```

The default fixture is `business-establishments`. Select another maintained
fixture with:

```bash
products/breg/demo/run.sh --fixture household
products/breg/demo/run.sh --fixture asset-site
products/breg/demo/run.sh --fixture asset-change-request
products/breg/demo/run.sh --fixture facility
products/breg/demo/run.sh --fixture inspection
```

Each persona is an explicit local private-key JWT client with the exact access
profile, scopes, purpose, and row claims needed for that fixture. The launcher
acquires a fresh token with `bregctl dev token` and copies only its owner-only
header file into `.run/headers/`. It does not put bearer tokens on command lines
or print them.

Leave a normal run active and use the query helper in another terminal:

```bash
products/breg/demo/query.sh all
products/breg/demo/query.sh --fixture facility operator
products/breg/demo/query.sh --fixture inspection inspector
products/breg/demo/query.sh --fixture asset-change-request planner
products/breg/demo/query.sh --fixture asset-change-request submitter
```

The business and household viewer profiles use their stable synthetic code as
the local row selector. This lets the immutable dev client registration exist
before records receive server-generated UUIDs while preserving the one-row
viewer boundary exercised by the demo.

`asset-change-request` creates an asset, sites, a placement, and one draft
correction request. Its separate submitter, reviewer, supervisor, applier, and
planner clients exercise the existing disclosure-limited profiles. A handoff
file contains persona metadata and an inert deep link, with no lifecycle
authority:

```bash
products/breg/demo/run.sh --fixture asset-change-request \
  --handoff /absolute/new/path/change-request-handoff.json
```

Use `--webhook` to add the fixture's local event destination. `bregctl dev`
owns the loopback receiver and its secret, and `bregctl dev events` writes a
value-redacted delivery report under `.run/webhook-events.json`.

```bash
products/breg/demo/run.sh --webhook --smoke
```

All generated project, service state, credentials, and reports live under
`demo/.run/` or the explicit `--state-dir`. A new run refuses an existing path.
Successful runs remove their owned state; failed or interrupted runs retain it
for diagnosis. Stop the owned dev session before removing that directory and retrying.
Production deployments require an operated issuer, signer custody, signed
packages, and an operated PostgreSQL service.
