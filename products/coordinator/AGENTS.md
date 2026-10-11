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
  runtime dev-dependency.
- The Coordinator inherits no authorization. A caller allowed to start a run
  is not thereby allowed the effects its flow requests: every product decides
  each call it receives under its own policy, and a wait never renews an
  approval or creates downstream authority. A run belongs to the caller that
  started it, and status and inspection follow that ownership and operator
  policy. Status, inspection, and every run action also check the run's own
  flow: a run of a flow the caller's policy does not list reads as
  `run.not-visible`, and `list` leaves it out.
- A run waits either until an instant or for a Casework review result, and
  the completion event only brings the next result read forward. A run starts
  only from an explicit caller request, never from a product event. Describe
  the Coordinator as running reviewed sequences of product calls across those
  waits, never as the way products connect to one another, until event-started
  runs ship.
- No product crate depends on a Coordinator crate. The only allowed dependents
  are `registry-stack-client`, on `registry-coordinator-client`, and
  `registry-cli-docs`, on `registry-coordinator` for the published CLI
  reference. Adding a dependent, or a Coordinator crate, means naming its rule
  in the gate in the same change. The Casework, Scheduling, and Messaging
  gates also refuse the Coordinator from their side.
- `registry-coordinator-client` reaches only `registry-platform-*` and never
  the runtime. Its Node.js and Python bindings add no Coordinator semantics;
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
  notes.
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
  products/coordinator/scripts/test-postgres.sh
```

`README.md` names the focused runtime test targets and the native-service
journeys. The client binding checks are in `crates/CLIENTS.md`.
