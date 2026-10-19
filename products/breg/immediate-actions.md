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

### Check one target's advisory availability

An immediate Action with at least one reference input advertises one
`routes.availability` endpoint. `targetInput` selects one reference input for
that request. Send that reference and any other declared input values already
available to the application:

```json
{
  "targetInput": "itemId",
  "input": {
    "itemId": "00000000-0000-0000-0000-000000000001"
  }
}
```

The check evaluates field-based `commitGuards` for that one target under the
selected Action profile and its ordinary Get disclosure. It returns the
observed target revision with `available: true` or with `available: false` and
the reason `guard-not-satisfied`. If a declared input needed by a guard is
absent, `available` is `null`, the reason is `input-required`, and
`missingInputs` names only declared API input names. If the guard or row
boundary depends on a field the caller cannot read, or the profile lacks Get
authority for the target Record type, the answer is `available: null` with
`observedRevision: null`, `not-disclosed`, and no missing-input names. A target
denied by the ordinary Get boundary and a missing target both use the concealed
404. Query reference inputs separately when an Action has several targets. A
known failed guard takes precedence over missing guard input; correcting that
guard may expose an `input-required` result on the next check.
No availability response names a guard ID or a Record value.

```json
{
  "availability": {
    "available": null,
    "observedRevision": null,
    "reason": "not-disclosed",
    "recovery": "none"
  }
}
```

Availability is an observation. It does not run a Function, test SQL
uniqueness or Evidence, mint a condition token, grant mutation authority, or
reserve the observed revision. Invoke remains responsible for current authority,
concurrency, form completeness, every guard, Functions, and Evidence; all required
checks must succeed before effects commit. `available: true` means only that this target's field
guards are currently satisfied, including the case where it has no field
guards. A safely disclosed field guard that fails at commit answers
`412 action.guard_failed` after current-target admission checks pass. The code
confirms that blocker; effect application, proposed-value authorization, and database
constraints run only after guards pass. An earlier refusal retains its normal
response. Stale conditions and guard failures that cannot be disclosed remain
`412 precondition.failed`.

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
required target conditions through the selected binding, use advisory
availability to guide the form when the Action advertises it, retain the user's
input and conditions, and prepare one invocation with a caller-owned idempotency key.
The server rechecks package identity, current authority, guards, and concurrency.

Recover a lost response using the same prepared request and key. A replay returns
the retained receipt without replanning or reacquiring Evidence. A changed input
or binding conflicts; an expired or erased receipt refuses without executing
again. Refresh stale conditions only after reviewing current input and targets.

See [Proposal configuration](proposals.md) for durable work,
[metadata](metadata.md) for client selection, and the
[standalone examples](examples/README.md) for focused runtime proofs.
