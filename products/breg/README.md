# Base Registry Engine

Base Registry Engine is a small PostgreSQL system of record whose data model and
REST surface are compiled from governed configuration. It is intended for
institutional registries that need reliable writes, history, access control,
and a safe way to evolve their schema without building a bespoke service.

Start with the [standalone examples](examples/README.md) for the current
Record type, Action, and Proposal model and its runnable PostgreSQL journeys.
The canonical projects include their local clients, journeys, and resumable scenarios.

The runtime has no built-in business, facility, authority, permit, or asset model.
A Record type, relationship, route, field, access profile, and event exists only
when an active Registry package declares it. For example, an establishment's
assignment to its operating business is an ordinary configured relationship.

BReg authoring uses `recordTypes` and `recordType`; `manifestProjection.entities`
keeps Registry Manifest vocabulary, and the record envelope
`entityTypeIdentifier` keeps the independent Registry Record contract.

The product starts with two executables:

- `breg` loads one verified package and serves its configured REST
  API against PostgreSQL.
- `bregctl` is deterministic tooling for authoring, checking,
  packaging, applying, and verifying Registry configuration.

AI-assisted authoring remains outside the production authority boundary. It
may propose configuration and run deterministic checks, but it cannot bypass
package review or the separate migration database role.

## First-hour local quickstart

Use the adopter guides for authoring, local evaluation, and operation.

- [Build a registry with Base Registry Engine](../../docs/site/src/content/docs/explanation/configuration-defined-registry.mdx)
- [Create and query your first registry](../../docs/site/src/content/docs/tutorials/first-breg.mdx)
- [Change a registry with an Action](../../docs/site/src/content/docs/tutorials/change-a-registry-with-an-action.mdx)
- [Query a spatial registry from QGIS](../../docs/site/src/content/docs/tutorials/query-a-spatial-registry-from-qgis.mdx)
- [Author a registry project](../../docs/site/src/content/docs/configure/breg.mdx)
- [Deploy and operate a registry](../../docs/site/src/content/docs/operate/breg.mdx)
- [Modeling patterns for registries](../../docs/site/src/content/docs/explanation/registry-modeling-patterns.mdx)
- [Base Registry Engine configuration reference](../../docs/site/src/content/docs/reference/breg-configuration.mdx)
- [Base Registry Engine API reference](../../docs/site/src/content/docs/reference/breg-api.mdx)

For a generic, domain-neutral local path, run:

```bash
products/breg/quickstart/run.sh
```

Pass `--installed` to use released `breg` and `bregctl` binaries from `PATH`
instead of building them from this checkout with Cargo.

The quickstart uses `bregctl init` to create a small generic
Registry project, replaces its package identity with a local one for the
disposable package, checks it, starts disposable PostgreSQL and the pinned stock
ThunderID issuer on loopback, activates an unsigned local package, obtains a
short-lived token, POSTs one record, and GETs that record back. Generated
configuration, keys, tokens, package artifacts, logs, and database URLs stay under
`products/breg/quickstart/.run/`, which is ignored by Git and
created owner-only.

Leave the quickstart terminal running, then use the printed record id in a
second terminal:

```bash
products/breg/quickstart/query.sh get <record-id>
```

The query helper reads the bearer token from an owner-only token file. It does
not put the token on the command line or print it. For a non-interactive local
smoke, run:

```bash
products/breg/quickstart/run.sh --smoke
```

To verify only the checked quickstart structure without Docker or network, run:

```bash
products/breg/quickstart/self-test.sh
```

This route is intentionally local-only: the supervised stock ThunderID issuer,
loopback HTTP, disposable PostgreSQL, and an unsigned local package.
It is the first-hour learning path, not a shortcut around production package
review, operated database roles, TLS, migration review, or secret custody.

For a retained local loop that needs no checkout, Python launcher, or shell
script, [Native local BReg lifecycle](DEV.md) documents `bregctl dev` against
installed binaries and Docker PostgreSQL.

`bregctl init <destination>` writes the complete [minimal directory](examples/minimal/README.md).
Use `--template facility-registry` for the complete [facility project](examples/facility/README.md).
Both are ordinary authored projects with fixed scenarios. `bregctl examples list` describes a starter's scenarios without
starting services or creating credentials, and `bregctl examples run
<scenario> <project>` runs or resumes one against the project's ready local
development instance. `bregctl init <destination> --from publicschema` derives
a new project from the PublicSchema reference model snapshot pinned in
`crates/registry-linkml`, either from the shipped `household` starter
selection (`--starter household`) or from an authored selection document
(`--selection <file>`); without either flag the command asks which concepts
and properties to select at the terminal. [Governed facility registration and
transfer](registry-extensibility.md), [Native persisted field
patterns](native-patterns.md), and [Current membership
access](membership-access.md) describe modeling patterns a derived or starter
project can build on. An action handler can also be a WebAssembly module:
[WASM action handlers](wasm-action-handlers.md) covers what ships, the
server-compatibility contract, operator configuration, and the upgrade and
rollback paths.
For institution-facing record numbers and codes, [Generated business
identifiers](generated-identifiers.md) explains sequences, random codes,
uniqueness scopes, and migration from retained values.

## Pilot operator lifecycle

Inspect the canonical projects' explicit access profiles and synthetic journey callers. `explain access` shows effective field
permissions; `check --deny-warnings` makes its access warnings blocking for automation.
Record type `accessRequirements` are mandatory compiler checks, not additional grants.

For configured atomic writes across records, see [Immediate actions](immediate-actions.md).

The [facility registration and transfer example](registry-extensibility.md)
combines those actions with a related-record acceptance condition, current
ownership and committed events. [Membership access](membership-access.md)
describes read permissions based on current governed membership records.
[Consent-gated reads](consent.md) describes read permissions that disclose a
row to a named recipient only while the subject's recorded consent is in
force.
The create-only asset example introduces typed inputs, fixed effects and an
action-only grant. The household example adds narrow target conditions and
recovery from stale input or a lost response. Mandatory reviewed change control
still applies to every targeted operation.

The pilot lifecycle uses matching `bregctl` and `breg` executables from the
same build, whether built from source or installed from a release. It does not
require a Rust change for a new
configured domain or a compatible additive schema change.

1. An author runs `bregctl check <project> --production`, generates
   review artifacts as needed, and uses `diff` against the active runtime
   configuration for a successor.
2. `bregctl test` executes the declared journeys against a separate
   schema-test database. Its result binds the candidate source, reviewed
   migrations, exact catalog fingerprint, and test receipt.
3. `bregctl package` reproduces that tested candidate and publishes the
   package with `SHA256SUMS` in one step, reporting its shared package digest.
   `--revision <text>` optionally records a source label in the hash-covered
   `REVISION` file.
4. An operator with the migration database credential runs
   `bregctl plan --runtime-config <file> --package <directory>`, which
   runs the activation's pre-maintenance checks in rolled-back transactions, then
   `bregctl apply --runtime-config <file> --package <directory>` and
   `bregctl status --runtime-config <file>`. Initial activation
   also requires `--initial`.
5. `breg --runtime-config <file>` verifies `SHA256SUMS`, the optional
   `package.expectedDigest` pin, the package closure, and the physical instance
   claim, then serves only when `identity.databaseId` and the package digest
   equal what the database's activation ledger records. Authorized
   bulk operations use `bregctl data validate`, `data import`, and
   `data export`, which reuse the packaged plans and normal authenticated API
   paths. `bregctl data runs list` and `data runs cancel` expose the maintained
   client's creator-scoped recovery operations for a Record type API route.

One package is the unit an operator promotes: the same package directory, with
the same package digest and `registryRevision`, is planned and applied in each
environment, and only the runtime file's `identity` and database values differ.

For a compatible successor, repeat test, package, and apply with the active
package directory as `--baseline-package`, then restart the same
server executable on the successor package.

Each database records its activations in the activation ledger,
`registry_internal.registry_migrations`: one row per activation, the initial
one included, keyed by a UUID activation id and ordered by apply order. A row
names the package digest, the predecessor package digest, the
`registryRevision`, the plan kind (`initial` or `successor`), the role mode,
any backups a destructive migration was bound to, and the keyed hash of
`--operator-reference`. `apply` accepts a successor only when its
predecessor digest is the active package, and refuses the active package again
and any older package. The migration credential authorizes an activation, and
every activation is audited as `breg-activation-audit/v1`. With separate
migration and runtime roles, the runtime role cannot write the ledger, so it
cannot change which package the runtime serves; with one role for both, the
ledger check catches mistakes but not someone holding that credential. Removing or narrowing an access
profile removes its obsolete compiled row-security policies during apply;
activation still requires the exact candidate catalog. Unexpected policies
remain catalog drift and are not silently deleted. A compiled policy whose
expression was altered in place while it kept its definition comment is also
refused as drift, and the activation fails: apply keeps a policy whose
comment matches, so it does not repair one. A database administrator recovers
by clearing that policy's comment (`COMMENT ON POLICY name ON table IS NULL`)
and applying the exact target package again, which replaces the policy with
its compiled definition. A migration failure after maintenance begins leaves
the database durably in maintenance and readiness fails. Inspect it with
`bregctl status --runtime-config <absolute-file>`. Retry
`bregctl apply --runtime-config <absolute-file> --package <absolute-target-directory>`
only with the exact pinned target package and its required `--backup` bindings;
a reviewed apply resumes its durable checkpoints rather than undoing them.
Assess a stuck activation without changing it with:

```bash
bregctl migration reconcile \
  --runtime-config <absolute-file> \
  --package <absolute-target-directory> \
  --operator-reference <reference>
```

When that assessment reports `completable` or `revertible`, repeat it with
`--execute` to perform the named safe transition. An `unresolvable` result
requires restoring the operator's own pre-activation backup and starting again
from the restored active package. Operators must not edit managed tables to make
a retry pass.

Authoring and migration authority are deliberately separate. An author or
coding agent can edit configuration, inspect a diff, and run checks. Those
commands cannot obtain the production migration credential. A runtime configuration without that credential is
refused before initial production control-plane state or DDL is created.

OIDC key resolution is deployment configuration, not governed package content.
If `authentication.oidc.jwksSource` is omitted, discovery is used. An operator
can name the key set location directly with `type: uri` and an `https` `uri`
(plain `http` only on an IPv4 loopback host), which the verifier fetches and
refreshes the same way it does a discovered key set, or pin a static document
through a protected secret reference:

```yaml
authentication:
  oidc:
    jwksSource:
      type: static
      documentRef: secret:file/oidc-jwks
```

The static document must be a bounded, duplicate-free set of public keys that
matches the configured algorithm, signature use, verification operation, key
identifier policy, and key shape. It is resolved once when the verifier is
constructed, so rotation requires a reviewed configuration change and process
restart.

Runtime files set `apiVersion` to
`id.registrystack.org/formats/breg/runtime/v1alpha1` and `kind` to
`BRegRuntimeConfig`. The generated JSON Schema at
`generated/runtime/runtime.schema.json` is suitable for editor validation. It
documents bounded defaults for operational tuning while keeping package,
database, authority, role, and secret-reference fields explicit.

The top-level `logLevel` accepts `error`, `warn`, or `info` and defaults to
`info`. `BREG_LOG` overrides the authored value for process-local operation.
An unknown value in either source refuses startup; neither source accepts
filter directives or enables dependency logging.

## Scope

### Record response contract

Authorized get, list, lookup, create, patch, tombstone, relationship, snapshot,
and revision routes use the shared Registry Record v1 single-record or
collection envelope. The envelope keeps opaque record and revision identifiers
separate from `domainData` and publishes the compiled registry, primary dataset,
and entity type in `meta`. Use `Accept: application/ld+json` for the scalar
shared context; ordinary `application/json` has no JSON-LD control members.
Successful profiled responses include profile and relative schema Link values.
See [History](HISTORY.md) for the breaking before-and-after shape and the exact
route mapping.

For atomic interval corrections, saved historical queries and their access and
retention boundaries, see [Corrections and historical queries](HISTORY.md).
For the opt-in log that lets a record subject see named reads of that record,
including retention, intermediary attribution, and delayed disclosure, see
[Subject-facing access logs](ACCESS-LOG.md).
See [Events and hooks](EVENTS-AND-WEBHOOKS.md) for committed record and Proposal events.

[Point queries and QGIS](SPATIAL-QUERIES.md) describes GeoJSON output and
explicitly granted PostGIS-backed bbox queries. The spatial quickstart uses
the same BReg, stock ThunderID issuer, and package lifecycle; ordinary
registries do not need PostGIS.

Base Registry Engine owns typed configured storage, generated REST contracts,
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

The compiler gives every reference column a btree index unless an authored
index or unique constraint already leads with it, and an authoring compile
reports `breg.entity.list-unindexed-filter` or `breg.entity.list-unindexed-sort` for a
granted list filter or sort that no index leads with. The compiler appends the
record id as the last column of every authored index: every list orders by
the record id last, so an index that ends with it returns a filtered, sorted
page in order and resumes a later page at its cursor. An authored index
declares the fields a list compares with `eq` first, then the field it sorts
by; the record id is never declared. A leading field filtered any other way,
such as by a range or `in`, still narrows the read, but the filtered set is
then ordered for each page. A database activated by
an engine that predates reference indexes gains them through an ordinary
successor package: `bregctl package` classifies each one as a compatible
additive index and the migration transaction creates it with a plain
`CREATE INDEX`, which blocks writes to that table until it commits.

## Reference lifecycle

An active Record can reference only an active target Record. Create and patch,
including batch and import writes, refuse a missing or tombstoned target.
Tombstoning a target refuses while another active Record references it, even
when that referencing Record is outside the caller's read permissions.
These refusals use the generic `409 mutation.conflict` response and disclose
no referencing Record IDs or values. Action and Proposal target admission
continues to require its independently granted current authority. A writer
authorized to submit a known target ID can still infer whether that target is
lifecycle-eligible from success versus conflict even without target read
authority. The conflict does not distinguish a missing target from a tombstoned
one or disclose target fields.

Clear an optional reference, point it at an active replacement, or tombstone
the referencing Record before tombstoning its target. Tombstoned Records and
retained history keep their original reference IDs. A self-reference does not
prevent tombstoning that same Record; active references from other Records do.
There is no automatic cascade or clearing of references.

Registries activated by an earlier compiler receive the lifecycle constraints
through a successor package built with the deployed package as
`--baseline-package`. Use `bregctl plan` to check the activation prerequisites.
Before live maintenance, apply the successor to a representative restored-data
copy to validate existing links. If that apply finds an active Record that
references a tombstoned target, repair its reference or tombstone that Record
through the current package, refresh the restored-data copy, and repeat the
validation before activating the successor in production.

Plan a maintenance window for this upgrade. Adding the stored generated
lifecycle column rewrites each reference source table. Adding the target's
unique lifecycle key and temporarily changing FORCE RLS on the source and target
take ACCESS EXCLUSIVE locks. The source and target locks acquired by the FORCE
changes are held while PostgreSQL validates existing links.
An additive activation runs its compiler DDL, runtime grants, and exact target
catalog verification in one transaction, so a validation or fingerprint refusal
rolls that DDL back. Maintenance still pins the exact target for recovery; this
check is performed during apply, not by a successor plan before maintenance.
A reviewed activation commits compiler and authored steps at durable checkpoints; a later reference validation refusal leaves those
earlier checkpoints in place and pins maintenance as failed. Follow the exact
target retry, reconciliation, or backup-restore procedure above.

## Live derived fields

A derived relation is a reviewed SQL asset, compiled into a read-only,
`security_invoker` view over the caller's `registry_source` rows. Its SQL must
be one `SELECT` with the declared key and field aliases. The compiler accepts
an explicit set of raw PostgreSQL grammar nodes, the aggregate functions
`count`, `bool_and`, and `every`, and `registry_context.evaluation_date()`.
`JSON_VALUE` and `JSON_EXISTS` may read scalars inside a structured field.
An explicit `RETURNING` type must be a supported built-in scalar type.
Ordinary casts are limited separately to reviewed built-in scalar targets;
arrays, catalog reference types, XML, money, and timestamp-with-time-zone casts
are refused. Column references resolve against the columns exposed by each
range in its own SELECT scope, so a range name cannot capture its whole row and
attribute notation cannot invoke an unlisted function.
`JSON_QUERY`, table functions, SQL/JSON aggregates and constructors, and XML
constructs are refused. Additions to this grammar require a concrete use case
and review; a parser upgrade does not automatically admit new syntax.
Joins use explicit `ON` conditions; source and join aliases cannot rename
columns through alias lists.

The generated view checks derived values before casting them to their declared
types. String length bounds, text maximum length, exact decimal scale and
precision, integer integrality and range, and vocabulary membership are
enforced without truncation or rounding. Null values retain their existing
nullable behavior. A violating value raises a stable database error identifying
the field without including its value; an API read fails through the ordinary
value-free source-unavailable response. Only derived relations reached by a
read are evaluated.

View definitions belong to the managed catalog fingerprint. When a compiler
release changes these wrappers, follow the package upgrade instructions in
[CHANGELOG.md](CHANGELOG.md), rebuilding from the authored project with the
deployed package as the baseline and applying the successor before switching
the runtime. An upgrade never rewrites the active catalog merely by starting
the runtime.

## Product contracts

The files in `contracts/` are the authoritative machine-readable delivery
catalog. They deliberately distinguish a `planned` invariant from an
`enforced` one. A planned row records a concrete threat and future refusal but
does not pretend that a test exists. The implementation change that enforces
it must add one resolving negative executable test in the same patch.

The projects under `acceptance/` are authored configuration inputs for the same
compiler and binary. The five baseline fixtures cover asset/site placement,
business establishments, facility inspections, environmental facilities, and
legal-entity registrations. The canonical [native projects](examples/README.md) exercise generated
CRUD, immediate multi-record Actions, and reviewed or no-review Proposals. These are not generated output or implicit
runtime models. The real-PostgreSQL pilot test executes the baseline fixtures,
while the public-binary adopter workflow proves activation, authenticated
data access, an additive upgrade, failure recovery, and unchanged server bytes
for the asset project. See [Proposal configuration](proposals.md)
for the approval workflows.
For bounded institutional-agent authority and current-status checks, see
[task grants for governed writes](TASK_GRANTS.md).
For a chat assistant that reads a citizen's own data and prepares a
Proposal draft the citizen submits themselves, see the
[citizen MCP gateway](MCP-GATEWAY.md).
The separate `household-history` fixture proves correction batches and retained
snapshot answers through the same compiler and runtime.
The additional `spatial-service-sites` project covers governed Point queries
and the QGIS installation-client path.
The [person-registration-rhai project](acceptance/person-registration-rhai/README.md)
combines a persisted native identifier pattern with an input-only immediate Rhai
handler, declared business refusal, coordinated creates and an optional patch.
See [native string patterns](native-patterns.md) for stored integrity rules.
Its synthetic CLI cases assert computed effects and its PostgreSQL journeys
verify stored values and existing action authority and concurrency contracts.
For current native Proposal context pairing and independent application authority,
use the [canonical Casework review](../casework/examples/canonical-review/README.md).
The status service and human context reader have separate purpose-specific grants.
The [committed product events](../coordinator/examples/product-events/README.md)
journey shows record and Action effects starting independently authorized
Coordinator work through the shared signed event contract.

Run the current deterministic contract checks with:

```bash
products/breg/scripts/check-contracts.sh
```

Run the durable receiver's independent behavioral tests with:

```bash
python3 products/breg/examples/webhook-receiver/test_receiver.py -v
```

The [receiver example](examples/webhook-receiver/README.md) provisions no registry
or issuer. It demonstrates durable acceptance independently of BReg deployment.

## Portable metadata and composition

Use [the Evidence lookup exporter](EVIDENCE.md) to select a compiled lookup,
its exact selector alternatives and readable facts for an Evidence project.
The generated files use Evidence's ordinary source contracts; connection
credentials and question authority remain separately configured.

Application clients consume the [caller-filtered metadata contract](metadata.md)
from `/v1/registry`, including exact route/profile fields, schemas, selectors,
reference bindings, and query capabilities.

Domain-semantic entries in `manifestProjection` are optional overlays on the
configured data model. One project declares one publisher authority, one public
service, one catalogue, one or more datasets, one or more data services, and
optional distributions. Every entity names exactly one `primaryDataset`, while
each data service explicitly lists its nonempty `servesDatasets`. Project-level
`accessProfile` and `classificationCeiling` values are defaults that a dataset
may narrow or replace. The compiler resolves every membership and reference
before generation, and refuses duplicates, missing memberships, and dangling
dataset, service, or distribution references.

Generated Manifest and DCAT bytes are one classified publication slice. A
dataset appears only when its effective access profile matches the governed
project publication profile and its effective classification ceiling does not
exceed the governed project ceiling. Services, distributions, public-service
references, entities, fields, and relationship edges are pruned with that
slice, so a public artifact cannot disclose a protected dataset by reference.

The projection can also declare localized catalogue and resource text, entity
concept URIs, identifiers, field concepts, relationship roles, and codelist
schemes. Registry Manifest remains the only portable metadata compiler and DCAT
renderer. Base Registry Engine does not infer or hardcode a domain model.
Operational references may cross datasets, but Registry Manifest v1 accepts
portable relationship targets only within the same dataset. Base Registry Engine
therefore keeps the operational reference valid while omitting that edge from
the lossy portable projection until Registry Manifest defines cross-dataset
relationship semantics.

The business-establishments fixture defines two datasets, one data service that
serves both, one distribution attached to the registered-businesses dataset,
and entities with explicit primary-dataset membership. Its local example concept URIs demonstrate semantic metadata
without claiming conformance to an external domain model. It also declares exact
selectors, a business-to-establishments read path, and a reviewed SQL module that
counts head offices, branches, production sites, and suspended establishments.
Two boolean fields indicate whether a business has a head office or production site.
The summary includes only assignments effective on the evaluation date.

Every emitted derived row must have a non-null canonical `id`, and one derived
relation may emit at most one row for that `id`. Base Registry Engine refuses the
query atomically when reviewed SQL violates either rule.

```bash
bregctl generate manifest \
  products/breg/acceptance/business-establishments \
  --output ./business-metadata
```

This produces the canonical Registry Manifest source and a DCAT JSON-LD
catalogue. Registry Manifest owns the standards rendering, so Base Registry Engine
does not carry a second DCAT implementation.

The REST query profile uses the native `$select`, `$filter`, `$orderby`,
`$top`, `$count`, and `$skiptoken` keys. Selector values are exact lookup
inputs only; they do not create authority. Relationship read paths are
configured routes such as `/v1/records/businesses/{record_id}/establishments`, and the
path grant explicitly limits the target fields, filters, ordering, and count
support available through that traversal.

Evidence can consume an authenticated Base Registry Engine REST route through its
existing bounded `http-json` source and an explicitly reviewed adapter.
Evidence keeps its own authorization and disclosure boundary; the integration
does not couple either runtime to the other's internals.

## Relationship to Registry Stack

Base Registry Engine is a writable source-of-truth product. Evidence remains the
minimum-disclosure assertion product; Manifest receives a safe one-way
metadata projection; an operated OIDC issuer supplies configured tokens; and
PublicSchema is an authoring input rather than a runtime dependency.

Registry Relay is retired from maintained Registry Stack. Base Registry Engine
does not replace Relay's publication of an institution's existing SQLite data.

## Statistical datasets

Declare bounded count datasets for live analysis under ordinary read profiles
and immutable, disclosure-controlled releases for separate dashboard readers.
See [Statistical datasets](STATISTICS.md) for the model, HTTP contract,
publication lifecycle, and accepted disclosure risks.

See the shared [per-resource access-token profile](../platform/ACCESS-TOKENS.md)
for OIDC interoperability. `registry_actor_kind` is profile-specific, including
when one OAuth client registration requests separate product tokens.
