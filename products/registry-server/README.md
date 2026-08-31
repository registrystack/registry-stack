# Registry Server

Registry Server is a small PostgreSQL system of record whose data model and
REST surface are compiled from governed configuration. It is intended for
institutional registries that need reliable writes, history, access control,
and a safe way to evolve their schema without building a bespoke service.

The runtime has no built-in business, facility, authority, permit, or asset model.
An entity, relationship, route, field, access profile, and event exists only
when an active Registry package declares it. For example, an establishment's
assignment to its operating business is an ordinary configured relationship.

The product starts with two executables:

- `registry-server` loads one verified package and serves its configured REST
  API against PostgreSQL.
- `registry-serverctl` is deterministic tooling for authoring, checking,
  packaging, applying, and verifying Registry configuration.

AI-assisted authoring remains outside the production authority boundary. It
may propose configuration and run deterministic checks, but it cannot bypass
package review, signature policy, or the separate migration database role.

## First-hour local quickstart

The documentation site has three adopter pages:

- [Registry Server overview](../../docs/site/src/content/docs/explanation/configuration-defined-registry.mdx)
- [Create and query your first registry](../../docs/site/src/content/docs/tutorials/first-registry-server.mdx)
- [Configure your registry](../../docs/site/src/content/docs/configure/registry-server.mdx)

For a generic, domain-neutral local path, run:

```bash
products/registry-server/quickstart/run.sh
```

The quickstart uses `registry-serverctl init` to create a small generic
Registry project, adds only local package identity for the disposable package,
checks it, starts disposable PostgreSQL and Registry Mint on loopback, activates
an unsigned local package, obtains a short-lived Mint token, POSTs one record,
and GETs that record back. Generated configuration, keys, tokens, package
artifacts, logs, and database URLs stay under
`products/registry-server/quickstart/.run/`, which is ignored by Git and
created owner-only.

Leave the quickstart terminal running, then use the printed record id in a
second terminal:

```bash
products/registry-server/quickstart/query.sh get <record-id>
```

The query helper reads the bearer token from an owner-only token file. It does
not put the token on the command line or print it. For a non-interactive local
smoke, run:

```bash
products/registry-server/quickstart/run.sh --smoke
```

To verify only the checked quickstart structure without Docker or network, run:

```bash
products/registry-server/quickstart/self-test.sh
```

This route is intentionally local-only: Mint's supervised local-development
profile, loopback HTTP, disposable PostgreSQL, and an unsigned local package.
It is the first-hour learning path, not a shortcut around production package
signing, operated database roles, TLS, migration review, or secret custody.

## Pilot operator lifecycle

For an offline permissions exercise, use [Review access configuration](examples/access-review/README.md).
It includes a complete project, allowed and refused synthetic caller scenarios,
and an omitted-row-restriction exercise. `explain access` shows effective field
permissions; `check --deny-findings` makes review findings blocking for automation.
Entity `accessRequirements` are mandatory compiler checks, not additional grants.

The pilot lifecycle uses the published `registry-serverctl` and
`registry-server` executables. It does not require a Rust change for a new
configured domain or a compatible additive schema change.

1. An author runs `registry-serverctl check <project> --production`, generates
   review artifacts as needed, and uses `diff` against the active runtime
   configuration for a successor.
2. `registry-serverctl test` executes the declared journeys against a separate
   schema-test database. Its result binds the candidate source, database
   identity, exact catalog fingerprint, signature policy, and test receipt.
3. `registry-serverctl package` reproduces that tested candidate and stops at
   `awaiting_signatures`. An external signer reviews and signs the exact
   `signing-input.json`; rerunning `package` with the detached signature
   document publishes the verified package. The CLI accepts no private signing
   key.
4. An operator with the migration database credential runs
   `registry-serverctl apply --runtime-config <file> --package <directory>` and
   then `registry-serverctl verify --runtime-config <file>`. Initial activation
   also requires `--initial`.
5. `registry-server --config <file>` serves the active package. Authorized
   bulk operations use `registry-serverctl data validate`, `data import`, and
   `data export`, which reuse the packaged plans and normal authenticated API
   paths.

For a compatible successor, repeat test, package, external signing, and apply
with the active runtime configuration as the baseline, then restart the same
server executable on the successor package. A migration failure after
maintenance begins leaves the database durably in maintenance and readiness
fails until an operator resolves the cause and applies the exact successor
again or completes the reviewed restore path.

Authoring, signing, and migration authority are deliberately separate. An
author or coding agent can edit configuration, inspect a diff, and run checks.
Those commands cannot mint a package signature or obtain the production
migration credential. A runtime configuration without that credential is
refused before initial production control-plane state or DDL is created.

OIDC key resolution is deployment configuration, not governed package content.
If `authentication.oidc.jwksSource` is omitted, discovery is used. An operator
can instead pin a static document through a protected secret reference:

```yaml
authentication:
  oidc:
    jwksSource:
      kind: static
      documentRef: secret:file/oidc-jwks
```

The static document must be a bounded, duplicate-free set of public keys that
matches the configured algorithm, signature use, verification operation, key
identifier policy, and key shape. It is resolved once when the verifier is
constructed, so rotation requires a reviewed configuration change and process
restart.

Runtime files set `apiVersion` to
`registry.registrystack.org/server-runtime/v1alpha1` and `kind` to
`RegistryServerRuntimeConfig`. The generated JSON Schema at
`generated/runtime/runtime.schema.json` is suitable for editor validation. It
documents bounded defaults for operational tuning while keeping package,
database, authority, role, and secret-reference fields explicit.

## Scope

Registry Server owns typed configured storage, generated REST contracts,
authorization, record revisions, audit ordering, idempotency, outbox creation,
and governed migrations. It does not provide a UI, GraphQL, workflow,
eligibility, payment, identity matching, SQLite support, a multi-registry
control plane, or runtime code plugins.

The focused direction for hooks is documented in
[`EVENTS-AND-WEBHOOKS.md`](EVENTS-AND-WEBHOOKS.md). Version 1 uses explicit
transactional events and authenticated after-commit webhooks, with future Rhai
rules kept behind the same governed extension boundary.

PostgreSQL is the sole Version 1 database. The administrator installs
`btree_gist`; neither the runtime nor migration role installs extensions.

## Product contracts

The files in `contracts/` are the authoritative machine-readable delivery
catalog. They deliberately distinguish a `planned` invariant from an
`enforced` one. A planned row records a concrete threat and future refusal but
does not pretend that a test exists. The implementation change that enforces
it must add one resolving negative executable test in the same patch.

The projects under `acceptance/` are authored configuration inputs for the same
compiler and binary. The five baseline fixtures cover asset/site placement,
business establishments, facility inspections, environmental facilities, and
legal-entity registrations. Separate change-request fixtures exercise reviewed
asset corrections and household contact registration without changing those
baseline direct-write journeys. These are not generated output or implicit
runtime models. The real-PostgreSQL pilot test executes the baseline fixtures,
while the public-binary adopter workflow proves signed activation, authenticated
data access, an additive upgrade, failure recovery, and unchanged server bytes
for the asset project. See [change-request examples](CHANGE_REQUEST_EXAMPLES.md)
for the approval workflows.

Run the current deterministic contract checks with:

```bash
products/registry-server/scripts/check-contracts.sh
```

For an interactive local business example backed by disposable PostgreSQL,
Registry Mint, a real local package, and deterministic relational data, run:

```bash
products/registry-server/demo/run.sh
```

The launcher retains every key and token in an ignored owner-only directory
and prints a separate query helper rather than printing bearer credentials.

## Portable metadata and composition

Application clients consume the [caller-filtered metadata contract](metadata.md)
from `/v1/registry`, including exact route/profile fields, schemas, selectors,
reference bindings, and query capabilities.

Domain-semantic entries in `manifestProjection` are optional overlays on the
configured data model. They can declare localized catalogue text, dataset and
API metadata, entity concept URIs, identifiers, field concepts, relationship
roles, and codelist schemes. The compiler refuses overlay entries outside the
selected access profile and classification ceiling. It does not infer or
hardcode a domain model.

The business-establishments fixture defines businesses, establishments, and dated
operator assignments. Its local example concept URIs demonstrate semantic metadata
without claiming conformance to an external domain model. It also declares exact
selectors, a business-to-establishments read path, and a reviewed SQL module that
counts head offices, branches, production sites, and suspended establishments.
Two boolean fields indicate whether a business has a head office or production site.
The summary includes only assignments effective on the evaluation date.

Every emitted derived row must have a non-null canonical `id`, and one derived
relation may emit at most one row for that `id`. Registry Server refuses the
query atomically when reviewed SQL violates either rule.

```bash
registry-serverctl generate manifest \
  products/registry-server/acceptance/business-establishments \
  --output ./business-metadata
```

This produces the canonical Registry Manifest source and a DCAT JSON-LD
catalogue. Registry Manifest owns the standards rendering, so Registry Server
does not carry a second DCAT implementation.

The REST query profile uses the native `$select`, `$filter`, `$orderby`,
`$top`, `$count`, and `$skiptoken` keys. Selector values are exact lookup
inputs only; they do not create authority. Relationship read paths are
configured routes such as `/v1/records/businesses/{record_id}/establishments`, and the
path grant explicitly limits the target fields, filters, ordering, and count
support available through that traversal.

Evidence can consume an authenticated Registry Server REST route through its
existing bounded `http-json` source and an explicitly reviewed adapter. Relay
remains a separate publication boundary. A direct Relay source adapter should
be added only for a concrete publication journey, rather than coupling either
product to Registry Server internals.

## Relationship to Registry Stack

Registry Server is a writable source-of-truth product. Registry Relay remains
the separately deployed read-only publication product; Evidence remains the
minimum-disclosure assertion product; Manifest receives a safe one-way
metadata projection; Mint may issue configured OIDC tokens; and PublicSchema
is an authoring input rather than a runtime dependency.
