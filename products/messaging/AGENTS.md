# Registry Messaging product

This directory owns the Messaging product contract, generated API description,
examples, and product-local verification scripts. Read the workspace
`AGENTS.md`, this file, and `README.md` before changing the product.

- Treat `generated/registry-messaging.openapi.json` and
  `generated/runtime/runtime.schema.json` as generated output. Both come from
  `crates/registry-messaging/src/schema.rs`; the regeneration commands are in
  `README.md`, and the checkpoint fails when either drifts.
- Keep `contracts/security-invariant-matrix.yaml` listing all ten invariants
  of the product specification. A pending row names the slice that owes it
  and cites no test; it becomes partial or enforced only in the change that
  adds the negative test that earns it. A mapped test is not evidence that the
  test ran.
- Record a deliberate behaviour a reader could mistake for an oversight in
  `contracts/recorded-decisions.yaml`, with the tests that hold it.
- Preserve the product boundary: no Messaging crate, directly or through any
  shared dependency, reaches a Base Registry Engine, Casework, Scheduling,
  Evidence, or Relay crate, and none of those products reach the Messaging
  runtime or `messagingctl`. The core depends on no other Messaging crate and
  the client never reaches the runtime. Run
  `scripts/check_dependency_direction.py` after dependency changes.
- A credential is always a `secret:` reference in a member ending in `Ref`.
  Never accept an environment expression, an inline value, or a request field
  in its place.
- Changes to authentication, authorization, audit, data minimization, or
  retention are security-sensitive: update `SECURITY-REVIEW-NOTES.md` and the
  matrix in the same change.
- PostgreSQL verification requires a disposable database and the
  `postgres-test` feature. A test binary that skips because its database URL
  is absent is not database verification.
