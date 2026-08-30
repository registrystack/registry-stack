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
- Domain semantics are optional configuration overlays. Registry Server does
  not hardcode Person, Household, GroupMembership, or any other domain model.
  An overlay may add localized labels, concept URIs, identifiers, relationship
  roles, and codelist metadata only for entities and fields visible through its
  selected access profile and classification ceiling.
- Selector profiles and relationship read paths are governed model entries,
  not runtime concepts. Selector values are exact inputs for a compiled lookup
  and never grant authority. A read-path grant is confined to one configured
  source, association entity, target, and target field capability set.
- Registry Manifest remains the owner of standards-oriented metadata and DCAT
  rendering. Registry Server emits a one-way, lossy Manifest source plus its
  DCAT JSON-LD projection when `manifestProjection` is authored. The projection
  is optional, so a basic registry is not forced to invent catalogue metadata.
  The server does not maintain a second catalogue model or claim conformance
  that was not explicitly authored.
- `registry-serverctl init` emits one small inline entity and no empty module.
  Module locks are discovered and refreshed explicitly with `project lock`;
  lock digests still bind every module source and declared SQL asset before a
  production package is compiled.
- Evidence and Relay integrations use their published protocol surfaces and
  platform primitives. Registry Server does not depend on their product crates
  or duplicate their policy, disclosure, credential, or publication engines.
- Registry Server accepts one PostgreSQL client path: `tokio-postgres` 0.7.18,
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
- `registry-serverctl test` may use a dedicated schema-test database, but it
  grants no package-signing or production-migration authority. Package signing
  remains external to the CLI, and production activation requires the separate
  migration database credential. The clean adopter proof uses distinct schema
  test databases for the initial and successor candidates plus a third
  production database.
