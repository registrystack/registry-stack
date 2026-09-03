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
  and never grant authority. A read-path grant is confined to one configured
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
  entities, two access profiles, one module extending an entity, and that
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
