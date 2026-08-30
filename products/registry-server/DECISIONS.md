# Product decisions

- Version 1 supports PostgreSQL only. SQLite is not a deployment compatibility
  promise.
- Extension points begin with transactionally created outbox events and
  authenticated webhooks. Arbitrary synchronous code hooks are not part of the
  server.
- Packages contain governed model and generated artifacts. Runtime
  configuration binds deployment-specific values and secrets and is not part of
  the signed model.
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
