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

An omitted optional Rhai input is the unit value `()`. Omit the corresponding
field from an effect's `set` map. Copying `()` or `null` into a required,
non-null field is a handler result failure; it does not clear the field.

The Action ABI supplies no trusted calendar date in `ctx`. When a command needs
a caller-selected business date, declare a typed input such as `asOfDate`; treat
it as caller data, not current server time. Plan logic runs only when that
Action is invoked and is not a Record field-validation boundary. If a rule must
not be bypassed, withhold the ordinary Create profile that could write the same
state without the Action.

`bregctl check` performs one narrow source check for literal catalogue mistakes:
it validates the string literal in a returned root map whose only key has the
shape `#{refusal: #{code: "..."}}`, and each string-literal `id` in a returned
root map whose only key has the shape
`#{effects: [#{id: "...", ...}]}` with a literal effects array. The walker checks
explicit `return` statements anywhere inside the one-argument entrypoint and its
final root-level map expression. It does not inspect an implicit map result
inside a nested `if` branch. Helper-returned, computed, or dynamically assembled
outcomes remain runtime behavior and need executable branch tests.

## Authorize and guard

An Action grant uses `permissions.actions`, the Action ID, `operations: [invoke]`,
explicit target row boundaries, and permitted result effects. It grants no
ordinary CRUD. Its target row boundaries are runtime-enforced Action authority
in addition to any ordinary Record grant held by the same profile. Every existing
reference target needs current target authority, including link-only references
and targets chosen by a function. `commitGuards` checks required current facts
inside the mutation transaction. A Record type's `mutationPolicy` still prevents
immediate writes to Proposal-required targets. `bregctl explain access` reports
this authority, whether any direct Record grant also exists, and the compiled
write or existing-target role of each Action target use. The direct-grant flag
does not compare that grant's operations or row boundaries, and Action target
authority does not grant ordinary CRUD. For a Proposal Action, a `write` use
under the Start grant describes an effect the proposal may apply after approval;
it does not grant the Start caller a direct Record write.

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
the reason `guard-not-satisfied`. A guard may declare an optional, stable LocalId
`reason` of at most 64 characters. The response exposes it as `guardReason` only
when every guard fact and every row-boundary fact for the selected target is
readable. The generic `reason` remains `guard-not-satisfied`. If a declared input
needed by a guard is absent, `available` is `null`, the reason is
`input-required`, and `missingInputs` names only declared API input names. If a
guard or row boundary depends on a fact the caller cannot read, or the profile
lacks Get authority for the target Record type, the answer is `available: null`
with `observedRevision: null`, `not-disclosed`, and no `guardReason` or
`missingInputs`. A target denied by the ordinary Get boundary and a missing target both
use the concealed 404. Query reference inputs separately when an Action has
several targets. A known failed guard takes precedence over missing guard input;
correcting that guard may expose an `input-required` result on the next check.
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
`412 precondition.failed`. Invoke rechecks the guard during commit. If it fails,
BReg rolls back and re-observes disclosure before returning `guardReason`;
advisory `guardReason` is neither authority nor a reservation.

## Inspect and test the function

```sh
bregctl check ./registry
bregctl --format json explain actions ./registry
bregctl project action-test ./registry --action <action-id> --input /path/to/input.json
```

`action-test` runs a named plan function over bounded synthetic JSON using logical
input IDs, without a wire envelope. Add `--expect /path/to/expected.json` to check
exact effects, a declared refusal, or a handler failure. The public
[`action-plan-branches` fixture](fixtures/action-plan-branches/README.md) carries
all three examples. A handler result error is asserted as
`{"failure":{"code":"action.handler.result"}}`; malformed supplied input remains
an input error. Runtime handler failures return the bounded value-free 500
problem and log the Action, plan, phase, slot, field, and failure identity, never
an input value. This offline check reads no live targets and does not prove
runtime authority or commit guards.

## Invoke and recover

Select the Action from caller-filtered metadata. Its fixed execution mode and
advertised routes distinguish immediate Invoke from Proposal Start. Obtain any
required target conditions through the selected binding, use advisory
availability to guide the form when the Action advertises it, retain the user's
input and conditions, and prepare one invocation with a caller-owned idempotency key.
The server rechecks package identity, current authority, guards, and concurrency.

An omitted `accessProfile` when the Action route has no default, an unknown
profile, and a profile the caller cannot use all return the same concealed 404.
The response does not list usable profiles. Select the profile and Action from
caller-filtered metadata, then prepare the invocation from that client binding
instead of probing Action URLs.

Recover a lost response using the same prepared request and key. A replay returns
the retained receipt without replanning or reacquiring Evidence. A changed input
or binding conflicts; an expired or erased receipt refuses without executing
again. Refresh stale conditions only after reviewing current input and targets.

See [Proposal configuration](proposals.md) for durable work,
[metadata](metadata.md) for client selection, and the
[standalone examples](examples/README.md) for focused runtime proofs.
