# Rhai person-name-change adopter fixture

This is a deliberately small, synthetic Base Registry Engine adoption example for a
Rhai-backed change-request planner. It has one governed target, `person`, and
one request entity, `person-name-change-request`.

The request declares the planner's complete input surface: `person`,
`given-name`, `family-name`, and `handling`. The planner's write ceiling is
equally narrow: it can only patch the referenced `person` record's
`display-name`. It cannot introduce an entity, operation, field, target row, or
review decision.

`scripts/person-name-change.rhai` trims the supplied name parts and joins them
with a single space. Submission freezes the complete proposal. The selected
`name-change-submitter` profile has `apply_request` plus the matching
`applyTargets` grant, so a separate manual application can later apply those
frozen effects without rerunning the planner.

This distinction is why the name construction belongs in Rhai while the
authority remains YAML. YAML declares request fields, the ABI, target and field
ceiling, no-review policy, manual application mode, and grants. Rhai only
computes bounded frozen effects and never chooses review or execution authority.

Run the structural check from the repository root:

```bash
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  check products/breg/acceptance/person-name-change-rhai
```

Run the captured planner locally with bounded synthetic request fields and no
database, credentials, or target read:

```bash
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked -p registry-bregctl -- \
  project planner-test products/breg/acceptance/person-name-change-rhai \
  --entity person-name-change-request \
  --request products/breg/acceptance/person-name-change-rhai/examples/routine-request.json
```

The report contains only compiled planner identity, ordinal effect aliases,
target kinds, operations, field names, dependencies, and counts. It deliberately
omits request values, target record
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

The synthetic journey covers two planner inputs and verifies that both frozen
proposals are applied only through the later authorized apply action. It
intentionally does not assert an invented review receipt or planner rerun signal.
