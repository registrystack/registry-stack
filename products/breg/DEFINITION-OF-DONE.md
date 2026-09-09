# Definition of Done

Base Registry Engine is not complete because one entity can be stored or because a
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
server bytes. A second migration recovery path, `migration reconcile`, assesses
and resolves a pinned migration without building a new package; it is proven
by its own CLI-authority test, not by this closing proof. The business pilot
fixture also exercises configured selector,
derived-field, and relationship read-path surfaces without making business or
establishment a runtime type. This is a pilot exit claim, not a claim that a release
has been published.

The pilot catalog also carries the governed surfaces that are added over the
same binaries as configuration. Action handlers under
`registry.action-handler/v1`, acceptance-time target requirements, native
persisted field patterns, current membership read boundaries, and
change-request submitter targets are enforced rows, and each one names the
real-PostgreSQL test that proves its refusals as well as its success path.
Adopter tooling rows carry the same rule:
`bregctl init --from publicschema`, the four published starters with
`bregctl examples`, and `bregctl dev` reading a project's `dev-clients.yaml`
are enforced by tests that write and compile a derived project, run every
starter's authored journey and security journey through the real router, and
start a session without a flag.

Two rows are deliberately not complete. The `registry.action-handler/v2` ABI
with its `evidence::resolve` helper is a trial in `immediate-actions.md` and
`EVIDENCE.md`, and so is the retained evidence-use scope that
`bregctl evidence-retention erase-expired` deletes. Their implementations and
negative tests pass, but their authoring contract is not frozen for Version 1.
The contract grammar has no trial state, so both rows are `partial` and their
`gap` names the trial. A trial row is not a Version 1 completion claim, and no
release claim rests on one.

The HTTP record contract is also explicit: caller-filtered and generated
OpenAPI artifacts assign every record-related route to the shared single or
collection Registry Record profile, or to a named BReg-specific shape.
Real-router PostgreSQL tests prove the exact JSON and JSON-LD bytes, structural
identifier disclosure after authorization, concealment before I/O, lookup
cardinality collapse, audit-gated release, and representation-bound replay.
