# Durable Proposal configuration

Use an Action with `execution.mode: proposal` when a change must remain as durable
work before application. BReg owns its draft, frozen plan, target authorization,
guards, local application, receipt, audit, and retention. An external review
authority owns review policy and decisions.

The [facility project](examples/facility/README.md) declares generated
CRUD for its directory, immediate registration of a facility and assignment,
and two Proposal Actions. The [smaller reviewed change](examples/reviewed-change/registry.yaml)
uses a fixed plan when a named function is unnecessary.

## Declare review and application

The Action owns its execution mode. Callers cannot turn an immediate Action into
a Proposal or choose an application mode at invocation.

```yaml
execution:
  mode: proposal
  proposal:
    review:
      type: required
      authority: casework
      source: facility-registry
      policy:
        id: facility-address-review
    retention:
      mode: retain
```

An ID-only policy delegates selection to the configured authority. The provider
atomically records its current concrete policy with the first acceptance. Later
retries use the original request and recover that acceptance, even if the active
policy has changed. BReg keeps the original selection in the frozen Proposal;
it stores the accepted policy separately and requires results to match it exactly.

This default lets the provider administrator evolve review policy for future
submissions, including choosing human review or automatic assessment. When the
registry owner must separately approve policy changes, supply both `version`
and `digest` alongside `id` from the provider's exported policy binding. Partial
pins are refused. An unavailable or mismatched policy never grants approval.

Use an exact pin when the policy version chosen at submission must decide the
review. With an ID-only selector, provider changes before first acceptance can
affect pending deliveries throughout the recovery window (30 days by default);
an operator resubmit restarts that window without replacing an existing acceptance.
A new submission after changes-requested selects the provider's current policy
again unless pinned.

Omitting `application` selects automatic application by the built-in executor.
It receives only the compiled system grant for the exact frozen submission,
never an author or reviewer identity or a general record grant.

For explicit application by a separately authorized caller:

```yaml
    application:
      mode: manual
```

For durable work without external review, declare `review.type: none`.
Review, application mode, and retention are separate choices.

## Govern targets and plans

A Record type can require Proposals independently of profile grants:

```yaml
mutationPolicy:
  patch: proposal-required
```

A direct Patch or immediate Action cannot bypass that rule. The Action's `plan`
is either `type: fixed` with ordered effects or `type: function` naming a
project-local function and its write ceiling. Effects use `fromInput`,
`fromEffect`, literal `value`, and explicit clear operations. Function code
computes effects within that ceiling; it cannot invent authority or a review
result. The facility function uses `registry.action-plan/v1` and `ctx.inputs`.

`commitGuards` checks frozen input and current target requirements at commit.
Submission freezes exact inputs, effects, target revisions, Action revision,
review selection, and effect digest. Apply never reruns a changed planner to alter
approved work. Any required Evidence is resolved under explicit operator trust
and the Action's declared capability; commit-time Evidence cannot change effects.

## Separate the grants

Profiles declare `permissions.records`, `permissions.actions`, and
`permissions.proposals` independently. Start authorizes creation of a draft;
Proposal Get, List, Edit, Submit, Revise, Rebase, Retry, Cancel, and Apply each
need their own grant. List requires List authority and conceals other owners'
and jurisdictions' work before filters or counts. Reading review context also
requires current record disclosure. A review-status service grant is restricted
to its named authority and returns no display values.

An external Apply or Retry of automatic work requires a verified human with an
explicit grant. Automatic execution never impersonates that human. Manual Apply
uses its separately configured current caller authority.

## Bind an optional review authority

Deployment `reviewAuthorities` maps the authored logical authority to its exact
endpoint, producer identity, profile, and credential. Use secret references and
a renewable `privateKeyJwt` credential where supported by your issuer. The
[development lifecycle](DEV.md#observe-local-events) shows the local client
binding. No executor credential or self-HTTP binding is needed.

With the binding absent, only operations requiring that authority are disabled.
Restore it to resume retained work. Approval must be freshly authenticated and
unexpired before any uncommitted manual or automatic application. Already
committed receipt recovery follows the local retention contract.

## Inspect and resume work

```sh
bregctl check ./registry
bregctl --format json explain actions ./registry
bregctl --format json explain proposals ./registry
```

These commands inspect configuration without a database or review decision.
At runtime, select the Action from caller-filtered metadata, Start a draft, then
use its promoted Proposal links. Refetch after each transition. Keep lifecycle
conditions separate from record ETags.

An authorized Proposal Get identifies `actionId`, `actionRevision`,
`submissionVersion`, `effectDigest`, current revision, and `applicationStatus`.
Preserve that exact frozen binding while observing progress. Revise or Rebase
makes the earlier binding stale; do not silently follow its successor. Applied
work carries retained application evidence. Blocked work carries a safe reason,
recovery hint, and currently authorized links. Observation cannot establish
whether an earlier uncertain Start or Submit executed; recover that command
with its original prepared request and idempotency key.

### Show the frozen changes

Declare the fields a reviewer may inspect in the Action's `reviewContext`:

```yaml
reviewContext:
  id: facility-address-context
  fields:
    changes:
      type: changes
      recordType: facility
      fields: [address-line, city, postal-code]
```

Each matching frozen effect exposes its record ID, operation, and selected
`before` and `after` values. A create has `before: null`. These values come from
the stored submission, including computed changes. Inspection does not run the
planner or apply the change. A `type: record` mapping selects a current field
through a reference input; a `type: input` mapping selects one frozen input.

The reviewer needs `get-review-context` with the named `readableContextFields`.
Record and changes projections also require an ordinary Record Get grant for
the selected fields. Current row boundaries, membership, and consent govern
those values, including subjects named by frozen before and after snapshots.
Use a separate profile for lifecycle operations when Record reads require consent.

Input projections disclose only the selected caller-supplied frozen inputs under
the context grant. They do not infer Record permissions or consent from an input's
meaning. Use a record or changes projection when displaying authoritative Record
values that must follow those current disclosure rules.

## Retain or erase detail

`retain` keeps detail. `operator-erase` makes eligible terminal detail removable
through the operator workflow. Inspect before erasing:

```sh
bregctl proposal-retention list --runtime-config /etc/breg/runtime.yaml
bregctl proposal-retention dry-run --runtime-config /etc/breg/runtime.yaml \
  --action-id correct-address --proposal-id <proposal-uuid> --submission-version <version>
```

Erasure removes retained payload detail and cannot be undone. Review the exact
dry-run result before running `proposal-retention erase` with the same binding.
History, Proposal detail, Evidence uses, attachments, and idempotency responses
have separate retention scopes. Expired or erased receipts cannot execute again.

The [standalone examples](examples/README.md) identify the focused
PostgreSQL proofs. The [metadata contract](metadata.md) owns client discovery
and promoted-link validation.
