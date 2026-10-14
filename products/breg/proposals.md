# Durable Proposal configuration

Use an Action with `execution.mode: proposal` when a change must remain as durable
work before application. BReg owns its draft, frozen plan, target authorization,
guards, local application, receipt, audit, and retention. An external review
authority owns review policy and decisions.

The [facility project](examples/refactor/facility/README.md) declares generated
CRUD for its directory, immediate registration of a facility and assignment,
and two Proposal Actions. The [smaller reviewed change](examples/refactor/reviewed-change/registry.yaml)
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
        version: '1'
        digest: 'sha256:<independently compiled policy digest>'
    retention:
      mode: retain
```

Supply the exact immutable policy binding from your authority. The canonical
example uses a synthetic pin for a conforming test authority, not a deployment
policy. Omitting `application` selects automatic application by the built-in
executor. It receives only the compiled system grant for the exact frozen
submission, never an author or reviewer identity or a general record grant.

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
review binding, and effect digest. Apply never reruns a changed planner to alter
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

The [standalone examples](examples/refactor/README.md) identify the focused
PostgreSQL proofs. The [metadata contract](metadata.md) owns client discovery
and promoted-link validation.
