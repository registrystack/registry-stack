# Standalone BReg examples

`minimal/registry.yaml` is a directory with one Record type and generated CRUD.
`facility/registry.yaml` adds reusable value types, one named Rhai function,
an immediate multi-record Action, and durable Proposals. Action execution mode
is governed configuration. Proposal lifecycle operations use promoted links.

From the repository root:

```sh
cargo run --locked -p registry-bregctl -- check products/breg/examples/refactor/minimal
cargo run --locked -p registry-bregctl -- check products/breg/examples/refactor/facility
cargo run --locked -p registry-bregctl -- --format json explain actions products/breg/examples/refactor/facility
cargo run --locked -p registry-bregctl -- --format json explain proposals products/breg/examples/refactor/facility
```

The executable journeys use an isolated database and the real BReg HTTP routes,
clients, PostgreSQL transactions, and row policies. Supply a PostgreSQL URL whose
role can create disposable test databases and roles, then run:

```sh
export BREG_TEST_DATABASE_URL='postgresql://USER:PASSWORD@HOST:PORT/DATABASE'
cargo test --locked -p registry-breg --features runtime,tooling,postgres-test \
  --test postgres_refactor --test postgres_facility_proposal -- --test-threads=1
```

The minimal journey proves CRUD, row concealment, revision conditions and exact
receipt recovery. The facility journey creates a facility and assignment atomically,
freezes its named-function correction, binds the exact review result, applies it
through the built-in executor, and resumes from promoted Proposal links. Its small
conforming review authority replaces an external Casework deployment. The policy
pin in this example is synthetic; bind your independently compiled policy before
using your own authority. Unavailable optional dependencies affect only operations
that require them.

Broader focused Proposal proofs cover manual and no-review automatic application,
current authority, refusal, concurrency, cancellation, recovery, retained attachments,
and activation:

```sh
cargo test --locked -p registry-breg --features runtime,tooling,postgres-test \
  --test postgres_proposal --test postgres_proposal_security \
  --test postgres_proposal_s3 --test postgres_native_retention -- --test-threads=1
```

`products/breg/generated/refactor-minimal/` and `products/breg/generated/refactor/`
contain the canonical contracts. The latter includes generated TypeScript and
Python project types used by `facility/console/`; the console tests use metadata
and generated clients rather than lifecycle URL construction.

For a locally deployed service, the maintained [development runbook](../../DEV.md)
owns PostgreSQL, authentication, package activation and the `bregctl dev` lifecycle.
