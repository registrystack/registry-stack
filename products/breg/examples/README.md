# Standalone BReg examples

`minimal/` is a directory project with one Record type and generated CRUD.
`reviewed-change/registry.yaml` adds one fixed-plan name correction to one Record
type. It requires an external review authority and uses the omitted automatic
application default. Its explicit profile grants record creation and reading,
Action Start, and caller-owned Proposal submission. A separate reviewer profile
can inspect the current and proposed name; direct Patch is unavailable.
`facility/registry.yaml` adds reusable value types, one named Rhai function,
an immediate multi-record Action, and durable Proposals. Action execution mode
is governed configuration. Proposal lifecycle operations use promoted links.

Both shipped starters include their own local clients and authored journeys.
The facility starter's `bregctl examples` scenarios cover registration,
no-review draft editing, ownership refusal, submission, manual application,
cancellation, and an independently reviewed correction. Their retained attempts
preserve exact commands through interruption and restart. See the portable
[facility instructions](facility/README.md) for the commands.

From the repository root:

```sh
cargo run --locked -p registry-bregctl -- check products/breg/examples/minimal
cargo run --locked -p registry-bregctl -- check products/breg/examples/reviewed-change
cargo run --locked -p registry-bregctl -- check products/breg/examples/facility
cargo run --locked -p registry-bregctl -- --format json explain actions products/breg/examples/facility
cargo run --locked -p registry-bregctl -- --format json explain proposals products/breg/examples/facility
```

The executable journeys use an isolated database and the real BReg HTTP routes,
clients, PostgreSQL transactions, and row policies. Supply a PostgreSQL URL whose
role can create disposable test databases and roles, then run:

```sh
export BREG_TEST_DATABASE_URL='postgresql://USER:PASSWORD@HOST:PORT/DATABASE'
cargo test --locked -p registry-breg --features runtime,tooling,postgres-test \
  --test postgres_refactor --test postgres_reviewed_change_example \
  --test postgres_facility_proposal -- --test-threads=1
```

The minimal journey proves CRUD, row concealment, revision conditions and exact
receipt recovery. The reviewed-change journey starts and submits a correction,
performs the authenticated external review handoff, obtains fresh approval before
automatic application, and recovers the original submission receipt. Its small
conforming test authority proves protocol binding, not a real policy decision.
The example's policy pin is synthetic and must be replaced with an independently
compiled policy for deployment. The facility journey creates a facility and
assignment atomically, freezes its named-function correction, binds the exact
review result, applies it
through the built-in executor, and resumes from promoted Proposal links. Its small
conforming review authority replaces an external Casework deployment. The facility
project selects a policy by ID. The provider freezes its concrete version and
digest when accepting each submission. Add an exact version and digest only when
the registry owner requires a strict pin. Unavailable optional dependencies affect only operations
that require them.

Broader focused Proposal proofs cover manual and no-review automatic application,
current authority, refusal, concurrency, cancellation, recovery, retained attachments,
and activation:

```sh
cargo test --locked -p registry-breg --features runtime,tooling,postgres-test \
  --test postgres_proposal --test postgres_proposal_security \
  --test postgres_proposal_human_recovery --test postgres_proposal_review_delivery \
  --test postgres_proposal_hooks --test postgres_proposal_s3 \
  --test postgres_native_retention -- --test-threads=1
```

For retained frozen submissions, ordinary authorized Proposal Get exposes
`actionId`, `actionRevision`, `submissionVersion`, `effectDigest`, and local
`applicationStatus`. Preserve that exact binding when observing progress; a later
revise/rebase does not satisfy a wait for the earlier submission. Applied work
includes retained application evidence. Recover an uncertain Start or Submit
with its original prepared command, rather than inferring execution from a later Get.
External Apply or Retry of automatic work requires a verified human and an explicit
operation grant. Manual-mode Apply keeps its independently configured authority.

`products/breg/generated/minimal/` and `products/breg/generated/facility/`
contain the canonical contracts. The latter includes generated TypeScript and
Python project types used by `facility/console/`; the console tests use metadata
and generated clients rather than lifecycle URL construction.

For a locally deployed service, the maintained [development runbook](../DEV.md)
owns PostgreSQL, authentication, package activation and the `bregctl dev` lifecycle.
