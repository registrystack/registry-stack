# Registry Coordinator product

This directory owns the Coordinator deployment contract, generated schemas and
API description, authored examples, and product-local verification scripts.
Read the workspace `AGENTS.md`, this file, and `README.md` before changing the
product.

The Coordinator owns its finite, reviewed workflow packages, the durable run
state and prepared commands it keeps in its own PostgreSQL database, its
waits, and its audit journal. It never owns product authority, product data,
eligibility, or capacity: each external effect belongs to the product that
receives the call, which decides it under its own authorization.

- Reach a product only over its public HTTP contract, through its maintained
  Rust client. The runtime may depend on product clients, product cores,
  `registry-record`, and `registry-platform-*`; never on a product runtime,
  adopter tooling, a supporting service, or a language binding. Never write
  to another product's database. Tests compose with another product the same
  way, through its built executable and public HTTP contract, never through a
  runtime dev-dependency. Its combined CLI may use `registry-cli-api` for
  product-neutral HTTP and connection handling; that helper carries no
  product runtime or authority.
- The Coordinator inherits no authorization. A caller allowed to start a run
  is not thereby allowed the effects its workflow requests: every product decides
  each call it receives under its own policy, and a wait never renews an
  approval or creates downstream authority. A run belongs to the caller that
  started it, and status and inspection follow that ownership and operator
  policy. Status, inspection, and every run action also check the run's own
  workflow: a run of a workflow the caller's policy does not list reads as
  `run.not-visible`, and `list` leaves it out.
- A `wait-for` observes a named completion exposed by an accepted Operation, using
  `completion: {step, name}`. Casework results and bounded external reads share
  that contract. Wake-ups only advance an eligible
  authoritative read and start no run. Keep the durable observation floor, budget,
  correlation, and original deadline intact across recovery.
- Keep the canonical authoring separation: contracts, types, named pure Functions,
  local exact Operation aliases, and one Workflow graph. Functions take one typed
  object of named inputs and gain no I/O capability. Runtime uses one tagged
  connections map. Caller policies are keyed by exact verified client identity and
  scope run actions through workflows. Start requires the expected workflowRevision.
- BReg and its review authority decide a Proposal. Coordinator invokes immediate
  BReg Actions, reads, starts, submits and cancels Proposals of one pinned
  Proposal Action, follows a Proposal by its current Proposal Get, never
  approves, decides or applies one, and is not a Review provider.
- No product crate depends on a Coordinator crate. The only allowed dependent
  is `registry-cli-docs`, on `registry-coordinator` for the published CLI
  reference. Adding a dependent, or a Coordinator crate, means naming its rule
  in the gate in the same change. The Casework, Scheduling, and Messaging
  gates also refuse the Coordinator from their side.
- `registry-coordinator-client` reaches `registry-platform-*`, never the runtime,
  a Review client or a product core. Its Node.js and Python bindings add no Coordinator semantics;
  follow `crates/CLIENTS.md` when changing the client surface.
- `scripts/check_dependency_direction.py` enforces both directions on the
  whole forward closure with every feature enabled. A package's own
  dev-dependencies count; those of a crate it reaches do not, since Cargo never
  builds them into it. Run the gate and its tests after any dependency change.
- Treat everything under `generated/` as generated output. The schemas come
  from the generators `scripts/check-schemas.sh` runs, and the OpenAPI
  document from `coordinatorctl openapi`; that script fails when either
  drifts, and `README.md` gives the commands.
- Changes to authentication, authorization, audit, data minimization,
  retention, or recovery are security-sensitive and need explicit review
  notes in `SECURITY-REVIEW-NOTES.md`.
- PostgreSQL verification requires disposable databases and the
  `postgres-test` feature. A test binary that skips because its database URL
  is absent is not database verification.

## Verify your change

```bash
python3 -m unittest discover -s products/coordinator/scripts -p 'test_*.py'
python3 products/coordinator/scripts/check_dependency_direction.py
products/coordinator/scripts/check-schemas.sh
cargo test --locked -p registry-coordinator-client -p registry-stack-client
COORDINATOR_TEST_DATABASE_URL=<disposable database> \
COORDINATOR_MESSAGING_TEST_DATABASE_URL=<separate disposable database> \
COORDINATOR_SCHEDULING_TEST_DATABASE_URL=<separate Scheduling database> \
  products/coordinator/scripts/test-postgres.sh
```

`README.md` names the focused runtime test targets and the native-service
journeys. The client binding checks are in `crates/CLIENTS.md`.
