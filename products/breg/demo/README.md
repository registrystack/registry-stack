# Base Registry Engine business demo

This local demo starts four real components:

- PostgreSQL 17 with TLS, separate migration and runtime roles, and disposable
  databases;
- Registry Mint as the OIDC token issuer;
- Base Registry Engine configured from one acceptance project;
- `bregctl` for schema testing, packaging, activation, and
  verification.

It defaults to the business-establishments project. The business path asks Mint
for short-lived operator and negative-test tokens and creates eight synthetic
establishments, three businesses, and eight effective-dated operator
assignments through Base Registry Engine's ordinary authenticated REST API. Once the
first business has a server UUID, the demo creates a separate viewer key and
Mint client whose verified claims bind it to that UUID and business code.

## Run it

Prerequisites are Docker, OpenSSL, Python 3, and `uv`, plus either released
`breg`, `bregctl`, and `mint` binaries on `PATH` or Cargo to build them from
this checkout. With the released binaries installed, run:

```bash
products/breg/demo/run.sh --installed
```

`--installed` takes `breg`, `bregctl`, and `mint` from `PATH`, skips the build,
and combines with every other option in this document. Without it, the first
run builds those three binaries from this checkout with Cargo:

```bash
products/breg/demo/run.sh
```

Either way, the first run may pull the pinned PostgreSQL image. When the demo
is ready, leave that terminal running. In a second terminal, execute all sample
reads:

```bash
products/breg/demo/query.sh all
```

Or focus on one access profile:

```bash
products/breg/demo/query.sh operator
products/breg/demo/query.sh viewer
```

These are the real requests against the running server. The operator suite
shows establishments belonging to one business, production-site and suspended-site
counts, combined stored and derived filters, and an exact request-value selector
lookup. The viewer suite proves that one claim-bound
business can be fetched by UUID or looked up from its verified business-code
claim, while list and business-to-establishments path requests return the concealed
`resource.not_found` response.

The helper reads bearer tokens from owner-only files inside `.run/`. It does
not put them in command-line arguments or print them. Press Ctrl-C in the first
terminal to stop Mint and Base Registry Engine and remove the PostgreSQL container.

Use `--smoke` to run the full setup, seed and query assertions, then stop
without waiting:

```bash
products/breg/demo/run.sh --smoke
```

Choose another maintained fixture with `--fixture`:

```bash
products/breg/demo/run.sh --fixture household
products/breg/demo/run.sh --fixture asset-site
products/breg/demo/run.sh --fixture asset-change-request
products/breg/demo/run.sh --fixture facility
products/breg/demo/run.sh --fixture inspection
```

The corresponding query helper uses the same fixture choice:

```bash
products/breg/demo/query.sh --fixture facility operator
products/breg/demo/query.sh --fixture inspection inspector
products/breg/demo/query.sh --fixture asset-change-request planner
products/breg/demo/query.sh --fixture asset-change-request submitter
```

`asset-change-request` uses the reviewed
`asset-site-placement-change-requests` acceptance project. It creates an asset,
an original and corrected site, the current placement, and one draft placement
correction request through the authenticated API. Its owner-only handoff exposes
five Workspace personas: the four lifecycle actors plus a site planner that can
browse assets, sites, and placements through the existing disclosure-limited
profile. The walkthrough order remains submitter, reviewer, supervisor, then
applier. The handoff contains an inert deep link to the synthetic request, but
no bearer token or lifecycle authority. Each actor must still obtain its
currently permitted action from a fresh request GET.

Generate a handoff for another local client with:

```bash
products/breg/demo/run.sh --fixture asset-change-request \
  --handoff /absolute/new/path/change-request-handoff.json
```

Use `--webhook` to add a local loopback receiver and exercise the configured
event lifecycle:

```bash
products/breg/demo/run.sh --webhook
products/breg/demo/run.sh --webhook --smoke
```

Webhook mode extends only the disposable project copy with a conditional
establishment event. It leaves the shared acceptance fixture unchanged, generates an
owner-only HMAC key, and uses Base Registry Engine's loopback-development outbound
policy. The receiver verifies the exact CloudEvents request and HMAC contract,
then deterministically proves immediate delivery, automatic retry,
dead-letter inspection with `bregctl webhook list`, and optimistic
replay with `bregctl webhook replay`.

The offline `webhook sample` report and final value-free status report are
written under `demo/.run/`. The script prints their paths, but never prints the
bearer token or HMAC key.

The exact paths, query parameters, selector bodies, and expected statuses live
in `support/demo.py`, which `query.sh` invokes. This keeps the examples
copyable without teaching readers to expand bearer tokens into process-visible
`curl` arguments. Public field names use their compiled lower-camel API names,
while selector IDs retain their configured kebab-case spelling. The operator
selector body uses the exact `values` property, while the viewer's
verified-claim selector correctly sends no caller-provided values.

## Disposable state

All generated configuration, keys, tokens, logs, package artifacts, and
database connection material live under `demo/.run/`, which is ignored by Git.
The directory and its secret subdirectories are owner-only. A new run replaces
the previous disposable directory after verifying that it is the demo-owned
path and not a symbolic link.

The demo deliberately uses Registry Mint's supervised local-development
profile and a local unsigned Registry package. Production deployments require
their normal issuer, signer custody, package signatures, and operated
PostgreSQL service.

## Demo data

North Quay Engineering has an office and a production branch. Central Fabrication
has a production site, a distribution branch, and a suspended storage depot.
South Harbour Logistics has three separate establishments used to test isolation.
All names and records are synthetic. Summary counts use currently effective
operator assignments; a suspended site still belongs to its operating business.
The `operating-created-v1` webhook selects only establishments created with
`operating-status: operating`, so the suspended depot produces no event.

Facility mode uses the `facility-operator` persona with purpose
`facility-registry` and an `administrative_boundaries` claim containing
`north-district`. It seeds "North District Water Treatment Facility" and a
separate south-district facility to prove row-boundary concealment, then creates
a current water-discharge permit, one installation with CRS84 point and decimal
area fields, and dated discharge reports.

Inspection mode uses the `inspection-inspector` persona with purpose
`facility-inspection`. It seeds inspection `INSPECTION-SYNTH-001`, a structured
air-domain observation, imported authority `AUTHORITY-SYNTH-001`, and two
create-only permit records where the second corrects the first.

The data is a small curated relational fixture rather than random names. This
makes the business assignments and expected query results stable and easy to
understand. The existing Evidence source-mock generator is not reused here
because it generates isolated HTTP responses from OpenAPI; it does not create
referentially coherent Registry records.

The seed still follows the real application boundary: Mint owns the authority
claims, Base Registry Engine validates every write, and assignments use the server
UUIDs returned for their establishment and business records.
