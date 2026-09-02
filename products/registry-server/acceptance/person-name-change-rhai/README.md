# Rhai person-name-change adopter fixture

This is a deliberately small, synthetic Registry Server adoption example for a
Rhai-backed change-request planner. It has one governed target, `person`, and
one request entity, `person-name-change-request`.

The request declares the planner's complete input surface: `person`,
`given-name`, `family-name`, and `handling`. The planner's write ceiling is
equally narrow: it can only patch the referenced `person` record's
`display-name`. It cannot introduce an entity, operation, field, target row, or
review decision.

`scripts/person-name-change.rhai` trims the supplied name parts and joins them
with a single space. Both handling values use the selected
`name-change-submitter` profile, which has `apply_request` plus the matching
`applyTargets` grant because the planner's disposition is not known until
submission. `handling: routine` returns `apply`, so submission freezes and
applies the plan in one transaction. `handling: assisted` returns `queue` with
the closed `assisted-review` reason. It freezes the complete proposal but does
not rerun the script; the separate `assisted-applier` later applies that frozen
proposal through the ordinary authorized action.

This distinction is why the name construction belongs in Rhai while the
authority remains YAML. YAML declares request fields, the ABI, target and field
ceiling, no-review policy, allowed planner outcomes, queue reason catalogue,
and grants. Rhai only chooses a bounded value and one of the declared outcomes.

Run the structural check from the repository root:

```bash
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-serverctl -- \
  check products/registry-server/acceptance/person-name-change-rhai
```

Run the captured planner locally with bounded synthetic request fields and no
database, credentials, or target read:

```bash
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-serverctl -- \
  project planner-test products/registry-server/acceptance/person-name-change-rhai \
  --entity person-name-change-request \
  --request products/registry-server/acceptance/person-name-change-rhai/examples/routine-request.json
```

The report contains only compiled planner identity, its disposition and declared
queue reason, ordinal effect aliases, target kinds, operations, field names,
dependencies, and counts. It deliberately omits request values, target record
identifiers, source text and paths, claims, and credentials. This command tests
the closed planner calculation. The PostgreSQL journey remains the authority for
base-revision checks, authorization, freezing, and application.

To try an implementation change, copy this project, edit only
`scripts/person-name-change.rhai`, give the copy a new `package.sourceRevision`,
then rerun `check` and `project planner-test`. For example, uppercasing the
trimmed family name changes both the reported script digest and the compiled
change-request contract fingerprint without changing the YAML-owned write or
authority ceiling. Run the copied project through the product fixture gate with
`test-change-request-examples.sh --rhai-project <copied-project>` to prove the
new routine and assisted target values through PostgreSQL. New submissions use
the new digest. A proposal already frozen by an earlier package keeps its
stored effects and digest; review, retry, and application do not rerun the
edited script.

The synthetic journey covers both planner outcomes. It verifies the routine
submit's applied target value and the later assisted apply target value. It
intentionally does not assert an invented review receipt, queue-only public
state, or planner rerun signal.
