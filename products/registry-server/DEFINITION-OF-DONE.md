# Definition of Done

Registry Server is not complete because one entity can be stored or because a
generated OpenAPI document exists. Completion requires the machine-readable
requirements in `contracts/definition-of-done.yaml` to pass on the same
revision using real PostgreSQL.

The delivery states are deliberately separate:

- **Architecture proof** proves the compiler, real router, PostgreSQL role and
  RLS boundary, atomic record transaction, audit ordering, and activation
  interlock. It is not a shippable partial writable API.
- **Pilot** adds the approved governed model, package and migration recovery,
  bounded REST and operational tooling, and all five coequal domain fixtures.
- **Release** uses the normal Registry Stack release process after the pilot
  surface is complete.

No required row may be satisfied by a mock database, disabled test, placeholder
artifact, or manual action claimed to be automated. A planned security row is
not implementation evidence. At the exit for its wave, it must be enforced and
have exactly one resolving negative executable test.

The pilot catalog is now enforced. Its closing proof combines the
real-PostgreSQL five-domain acceptance test with a clean public-binary lifecycle
that exercises production checking, isolated schema tests, external signing,
operator apply, authenticated serving, compatible additive upgrade, durable
failed maintenance, exact fix-forward recovery, and restart with unchanged
server bytes. The business pilot fixture also exercises configured selector,
derived-field, and relationship read-path surfaces without making business or
establishment a runtime type. This is a pilot exit claim, not a claim that a release
has been published.
