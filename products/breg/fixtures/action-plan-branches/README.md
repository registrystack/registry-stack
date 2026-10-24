# Test an Action plan's branches

Use this offline diagnostic fixture to assert a computed effect, a declared
refusal, and a handler failure. `invalid-copy` deliberately copies an absent
optional input into a required field. Keep that Action as a negative fixture.

From the repository root, run:

```sh
bregctl check products/breg/fixtures/action-plan-branches
bregctl project action-test products/breg/fixtures/action-plan-branches --action create-entry --input products/breg/fixtures/action-plan-branches/examples/success.input.json --expect products/breg/fixtures/action-plan-branches/examples/success.expect.json
bregctl project action-test products/breg/fixtures/action-plan-branches --action create-entry --input products/breg/fixtures/action-plan-branches/examples/refusal.input.json --expect products/breg/fixtures/action-plan-branches/examples/refusal.expect.json
bregctl project action-test products/breg/fixtures/action-plan-branches --action invalid-copy --input products/breg/fixtures/action-plan-branches/examples/handler-failure.input.json --expect products/breg/fixtures/action-plan-branches/examples/handler-failure.expect.json
```

A matching expectation reports `assertionsPassed: true`. A changed effect or
failure code refuses the assertion at the differing expectation member, without
printing values. A malformed supplied input remains an input error.

`check` also checks literal refusal codes and effect IDs in direct returned ABI
maps and literal returned effect arrays. Variables, helper-returned outcomes,
computed identifiers, and dynamically built arrays need executable branch tests.
Literal checking does not prove which branch runs or that every branch is valid.
Neither offline check proves live target authority or commit conditions.
