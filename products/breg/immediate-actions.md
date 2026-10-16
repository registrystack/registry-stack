# Immediate Actions

Use an immediate Action for a typed operation whose effects must commit together.
Generated CRUD serves ordinary record maintenance; an Action groups configured
writes without adding domain-specific server code. A Proposal Action uses the
same plan model when application must happen later.

The [facility project](examples/facility/README.md) is the complete
multi-record example. `register-facility` creates a facility and its initial
assignment in one transaction. Its `operator` reference is checked for current
active status and jurisdiction. The authored `operator-editor` profile supplies
setup authority; tooling never injects a seeding grant.

## Author one plan

```yaml
actions:
  - id: register-facility
    execution:
      mode: immediate
    inputs:
      - id: name
        type: string
        required: true
        minimumLength: 1
        maximumLength: 200
        classification: internal
    plan:
      type: fixed
      effects:
        - id: facility
          target:
            recordType: facility
          operation: create
          set:
            name:
              fromInput: name
```

This fragment illustrates the syntax; use the complete project for required
fields, references, guards, datasets, and grants. HTTP input names come from
`apiName`. Plans address authored input IDs. A literal uses `value`; a reference
to an earlier created record uses `fromEffect`. Effect order is authored order,
with explicit dependencies. Forward references refuse compilation. Aliased
writes to one target fold into one revision; conflicting writes or cycles refuse
atomically.

For computed effects, declare a named Function and select `plan.type: function`
with its `function`, `inputs`, `writes`, and declared `refusals`. The write ceiling
remains governed configuration. Rhai uses `registry.action-plan/v1`, `ctx.inputs`,
and a bounded effects or refusal result. The
[person registration project](acceptance/person-registration-rhai/README.md)
shows normalization, coordinated creates, and omitted effect slots.
[WASM handlers](wasm-action-handlers.md) have their own admitted backend contract.

## Authorize and guard

An Action grant uses `permissions.actions`, the Action ID, `operations: [invoke]`,
explicit target row boundaries, and permitted result effects. It grants no
ordinary CRUD. Every existing reference target needs current target authority,
including link-only references and targets chosen by a function. `commitGuards`
checks required current facts inside the mutation transaction. A Record type's
`mutationPolicy` still prevents immediate writes to Proposal-required targets.

An invocation commits record effects, revisions, history, audit, idempotency
receipt, and outbox together. A refused effect leaves no partial record or event.
The response discloses only granted result effects. Events describe committed
work; an external webhook failure cannot roll back the registry transaction.
Use the [durable webhook receiver](examples/webhook-receiver/README.md) when an
adopting service needs durable acceptance and deduplication.

## Inspect and test the function

```sh
bregctl check ./registry
bregctl --format json explain actions ./registry
bregctl project action-test ./registry --action <action-id> --input /path/to/input.json
```

`action-test` runs a named plan function over bounded synthetic JSON using logical
input IDs, without a wire envelope. Add `--expect /path/to/expected.json` to check
exact effects or a declared refusal. This offline check reads no live targets and
does not prove runtime authority or commit guards.

## Invoke and recover

Select the Action from caller-filtered metadata. Its fixed execution mode and
advertised routes distinguish immediate Invoke from Proposal Start. Obtain any
required target conditions through the selected binding, retain the user's input
and conditions, and prepare one invocation with a caller-owned idempotency key.
The server rechecks package identity, current authority, guards, and concurrency.

Recover a lost response using the same prepared request and key. A replay returns
the retained receipt without replanning or reacquiring Evidence. A changed input
or binding conflicts; an expired or erased receipt refuses without executing
again. Refresh stale conditions only after reviewing current input and targets.

See [Proposal configuration](proposals.md) for durable work,
[metadata](metadata.md) for client selection, and the
[standalone examples](examples/README.md) for focused runtime proofs.
