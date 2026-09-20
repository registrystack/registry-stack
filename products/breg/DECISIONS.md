# Product decisions

- Version 1 supports PostgreSQL only. SQLite is not a deployment compatibility
  promise.
- Extension points begin with transactionally created outbox events and
  authenticated webhooks under `EVENTS-AND-WEBHOOKS.md`. Arbitrary synchronous
  code hooks are not part of the server.
- Packages contain governed model and generated artifacts. Runtime
  configuration binds deployment-specific values and secrets and is not part of
  the signed model.
- Runtime configuration is an explicitly versioned document. Authority,
  credentials, package identity, and database roles remain required; bounded
  operational tuning uses reviewed defaults so a safe starter file stays
  readable.
- A project authors reusable access profiles once at the project top level.
  Modules may contribute profiles while composing an entity, but root project
  entities do not carry a second access-profile vocabulary.
- Domain semantics are optional configuration overlays. Base Registry Engine does
  not hardcode Establishment, Business, OperatorAssignment, or any other domain model.
  An overlay may add localized labels, concept URIs, identifiers, relationship
  roles, and codelist metadata only for entities and fields visible through its
  selected access profile and classification ceiling.
- Selector profiles and relationship read paths are governed model entries,
  not runtime concepts. Selector values are exact inputs for a compiled lookup
  and never grant authority. A read-path permission is confined to one configured
  source, association entity, target, and target field capability set.
- Registry Manifest remains the owner of standards-oriented metadata and DCAT
  rendering. Base Registry Engine emits a one-way, lossy Manifest source plus its
  DCAT JSON-LD projection when `manifestProjection` is authored. The projection
  is optional, so a basic registry is not forced to invent catalogue metadata.
  The server does not maintain a second catalogue model or claim conformance
  that was not explicitly authored.
- One Registry project may contain several explicitly identified master
  datasets under one primary publisher authority, public service, and catalogue.
  Every entity belongs to exactly one primary dataset; data services and
  distributions carry resolved dataset membership. Dataset-specific access and
  classification values inherit from explicit project defaults. The compiled
  BReg model projects these resources once into Registry Manifest and owns no
  parallel DCAT model.
- A selected and authorized compiled record operation is the BReg's governed
  decision to publish the record's structural registry, primary-dataset, and
  entity-type identifiers. They are mandatory Registry Record metadata rather
  than caller-selectable domain fields, and the BReg does not add a second
  gate based on the optional Registry Manifest catalogue publication profile.
  Successful JSON and JSON-LD records use the shared Registry Record v1
  envelope. Batch, action, and GeoJSON products remain explicitly named
  separate shapes.
- An operational reference may cross dataset boundaries when the ordinary
  compiled model and access checks permit it. Registry Manifest v1 currently
  requires relationship targets to be entities in the same dataset, so the
  lossy portable projection intentionally omits cross-dataset relationship
  edges. First-class portable cross-dataset relationships are deferred until
  Registry Manifest defines and validates that representation; the omission
  does not weaken or invalidate the operational relationship.
- `bregctl init` emits a working example project rather than a blank
  one: package identity, a manifest projection, a closed vocabulary, two inline
  entities, three access profiles, one module extending an entity, and that
  module's lock computed as the project is written. Module locks are refreshed
  explicitly with `project lock`; lock digests still bind every module source
  and declared SQL asset before a production package is compiled.
- Evidence and Relay integrations use their published protocol surfaces and
  platform primitives. Base Registry Engine does not depend on their product crates
  or duplicate their policy, disclosure, credential, or publication engines.
- Base Registry Engine accepts one PostgreSQL client path: `tokio-postgres` 0.7.18,
  `deadpool-postgres` 0.14.2, and `tokio-postgres-rustls` 0.14.0. The real
  PostgreSQL kernel proves dynamic result handling, transactions, cancellation,
  pool recovery, role separation, RLS, advisory locks, and activation
  interlocking. There is no second production client behind an abstraction.
- Runtime connections use strict native-root or custom-CA TLS. Custom-CA mode
  accepts one DER root for the current connection scope and verifies both the
  chain and server hostname. Plaintext PostgreSQL is confined to the test
  harness; a required-TLS runtime does not downgrade against it.
- Generated RLS policies defend against application mistakes and pooled-context
  leakage. They do not constrain a party holding the runtime database
  credential, which can set the same custom transaction context; credential
  posture and rotation remain operator controls.
- OIDC verification can use issuer discovery or an operator-pinned static JWKS
  held behind a secret reference. Static documents accept only a bounded,
  duplicate-free set of public keys exactly compatible with the configured
  algorithm and key policy. They are loaded once per verifier construction and
  rotate only by configuration change and restart.
- `bregctl test` may use a dedicated schema-test database, but it
  grants no package-signing or production-migration authority. Package signing
  remains external to the CLI, and production activation requires the separate
  migration database credential. The clean adopter proof uses distinct schema
  test databases for the initial and successor candidates plus a third
  production database.
- `bregctl init --from <MODEL>` derives a project from a reference model
  snapshot embedded in the tooling, behind an explicit flag. The derivation is
  import only: nothing exports back from a derived project to the model.
  PublicSchema is the first model. The derived project is ordinary source; the
  model never becomes a runtime type, and the snapshot itself is a pinned
  external input recorded in `external/README.md`.
- `registry.action-handler/v1` runs a project-authored Rhai script inside
  `handle(ctx)` for typed input calculation and branching. The ABI accepts
  scalar inputs only and refuses `crs84-point` and `structured` inputs; every
  effect an action can produce is a declared write slot with a fixed target,
  operation, and field list, so the script cannot reach a target, field, or
  operation the compiler did not admit. Declared refusal codes are the only
  way a script can decline a call before an effect commits.
- A persisted `string` or `text` field may declare `pattern` using
  PostgreSQL's native advanced regular-expression syntax, on PostgreSQL 17 or
  newer. There is no second regular-expression engine in BReg; the database
  itself enforces the pattern.
- A read access profile may declare `membershipBoundaries`: a one-hop join
  predicate over a configured membership entity, its key field, its principal
  field, and its active flag. Boundaries are restricted to `get`, `lookup`,
  `list`, `revisions`, and `snapshot`, require an authenticated profile with a
  verified `principalClaim`, and are capped at eight per profile.
  `products/breg/scripts/check_source_neutrality.py` no longer forbids the
  bare words `membership` or `memberships`, since the mechanism is a generic,
  configured boundary and not domain-specific behavior; concrete fixture
  compounds such as `group-membership` remain forbidden. Changing this
  blocklist is a boundary decision, recorded here and in
  `products/breg/AGENTS.md`.
- `evidence::resolve(capability_id, subjects)` is available to
  `registry.action-handler/v2` handlers as a trial: a governed action may
  consume a signed Evidence assertion as an ordinary relying party, with the
  trusted provider, its endpoint, token, and trusted JWKS all declared by the
  operator in runtime configuration. BReg depends unconditionally on
  `registry-evidence-client` and `registry-evidence-verifier` for this
  release; gating that dependency behind a Cargo feature is deferred. The
  accepted assertion is retained for 24 hours after acceptance and erased by
  `bregctl evidence-retention erase-expired`, following the same operator-run
  erasure pattern already used for change-request retention and history.
- `products/breg/starters/` holds ready-made, versioned BReg projects with
  fixed scenarios and synthetic clients, pinned to the same PublicSchema
  draft vocabulary snapshot as `bregctl init --from publicschema`.
  `bregctl examples list` describes a starter's scenarios without starting
  services or creating credentials; `bregctl examples run <scenario>
  <project>` runs or resumes one, including a reviewed-change scenario
  advanced one stage at a time and a first-record scenario resumable by its
  captured attempt id.
- `evidencectl source add` is the documented local path for connecting a
  registry project to an Evidence project: it drives the matching-version
  `bregctl` binary found on `PATH` through `dev prepare-source` and `dev
  export-client`, never through a crate dependency. It reviews the connection
  by default and performs it only with `--apply`; there is no interactive
  confirmation. `bregctl dev
  prepare-source` is hidden from `--help` but remains a functional command of
  its own. `bregctl generate evidence-source`, `bregctl dev export-client` run
  directly, and `evidencectl source import` remain the manual path for a
  profile and client already prepared in the registry.
- A `restricted` string, text, date, decimal, or structured field may declare
  `encrypted: true`, optionally with a `lookup` block of closed-vocabulary
  normalization steps and a `unique` flag. Values are sealed in the engine with
  envelope encryption and stored as ciphertext plus an HMAC blind index;
  plaintext exists in memory only inside the serving process, and rows,
  journal revisions, and held response bodies carry the sealed form until one
  decrypt at an enumerated caller-authorized response edge. The guarantee
  covers direct database reads (DBA, replica, dump, backup); the serving
  process, holders of the key-transit credential, and backups retained from
  before a flip stay outside it and are documented operator risk.
- Field encryption runs on the AWS-LC FIPS build everywhere the workspace
  links it; there is no non-FIPS backend selection and no runtime mode switch.
  A local-file data-key provider exists for local assurance only and the
  runtime refuses it unless the database initialization environment is local.
- Change-request flows cannot target an encrypted field, feed one through a
  Rhai write ceiling, or source one through a declarative `fromField`: the
  compiler refuses each shape, and a runtime backstop refuses again before any
  proposal or target snapshot is materialized. Lifting this is future work,
  not a configuration option.
- Turning encryption on for a field with existing rows is a reviewed migration
  step that seals existing values and drops the plaintext column, with the
  history choice carried explicitly on the reviewed descriptor:
  `erase-and-rebaseline` destroys the full per-record history after the
  successor package activates, and `retain-plaintext-history` keeps serving
  pre-flip revisions as written, scoped by the flip boundary. A plan with no
  choice refuses, and `retain-plaintext-history` is an accepted-risk option
  that does not satisfy the database-read guarantee. Preflight and audit
  report records, revisions, and counts, never values. In Phase 1, a
  `retain-plaintext-history` apply refuses before sealing any row when its
  preflight reports retained request target or proposal copies for a covered
  field; operators must clear those copies through the request lifecycle and
  retention policy first. All simultaneous field-encryption flips for one
  entity share one backfill step so migration history never records a partial
  successor shape.
- Phase 1 does not support removing encryption, changing the lookup of an
  already-encrypted field, or adding a required encrypted field to an existing
  entity. Add a new encrypted field as optional, populate it through authorized
  Registry writes, then make it required in a later package.
