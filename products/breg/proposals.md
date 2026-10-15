# Durable Proposal configuration

Use an Action with `execution.mode: proposal` when a change must remain as durable
work before application. Base Registry Engine (BReg) owns its draft, frozen plan, target authorization,
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
and jurisdictions' work before filters or counts. Record and changes projections
in review context also require current Record disclosure. Frozen input and
document projections use their declared review-context grants and current
applicable checks. A review-status service grant is restricted to its named
authority and returns no display values.

Ownership alone does not preserve access after a target leaves the caller's
current row boundary. Proposal Get then returns a concealed 404, List omits the
Proposal, and transitions such as Cancel return the generic precondition refusal.
The saved Proposal remains governed work, but that caller can no longer view,
cancel or recover it. An adopter should explain this loss of access and provide
its service contact path; it must not retain a private copy as substitute authority.

An authorized review-status read includes `requestId` after the Review provider
has accepted that exact submission. Before acceptance the member is absent.
Use this provider-issued ID to correlate independently authorized Casework
history, clocks or notes reads, including a changes-requested explanation.
The ID grants no Casework access and is absent from human review-context reads.
Refetch status for the intended submission after Revise or Rebase; do not use a
previous submission's request ID for new work.

For an audit investigation, correlate the exact Proposal, Action revision,
submission version and effect digest with the accepted `requestId` and retained
`resultId`. Read Casework's request history and Decisions under separate current
Casework authority. Automatic application records BReg's system executor, not
the human reviewer; an application receipt does not embed the officer's Decision.
Retain the needed evidence under each product's retention policy before detail
or receipts expire. This correlation does not bypass either product's disclosure
checks or recover erased history.

An external Apply or Retry of automatic work requires a verified human with an
explicit grant. Automatic execution never impersonates that human. Manual Apply
uses its separately configured current caller authority.

Automatic application is the default. Explicit manual mode has no apply-task
queue, assignee or due date, and an approval does not open a Casework task to
apply the change. The adopter owns follow-up: list submitted Proposals, inspect
their current Apply availability, and arrange who acts before approval expires.
Casework remains the review provider; BReg owns and authorizes application.

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

BReg submits every Proposal with `subjectType: proposal`. The Action identity
comes from the Proposal's `actionId`, not from the subject type. Treat
`context.reference` as opaque: preserve it for exact correlation and use the
declared context contract rather than parsing its current spelling.

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

`applicationStatus` reports application progress only. Under required Review it
reads `awaiting-review` until an approved result exists, then `pending`,
`applying`, `blocked`, `applied` or `cancelled`. Its `application-refused`
reason means an executor refused the frozen effects; a review outcome never
appears there. The `apply` link's availability reports Review instead:
`pending-review` with recovery `refresh` while no decision applies,
`review-rejected` or `review-changes-requested` after that decision, and
`review-ended` when the provider cancelled or superseded the review without a
withdrawal by BReg. Each of the last three carries recovery `revise`.

Mutation refusals intentionally share a generic 412 for unavailable authority
and failed preconditions. To show or test why Apply is unavailable, first read
the authorized Proposal and inspect `links.apply.availability.reason`, such as
`pending-review`. Check the expected Proposal revision as well. A 412 alone
does not prove that Review is pending, and availability is an observation, not
a promise that a later mutation will pass its current checks.

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

Review context and its document downloads require the active Action revision to
match the frozen submission. After an Action contract changes, BReg conceals the
old display rather than mapping its inputs or effects through the new definition.
Where Rebase is available, an authorized caller can explicitly Rebase and submit
new work under the current Action for fresh Review. Refetching alone does not
replace the frozen submission.
Display-free review status remains independently authorized for exact retained
submission correlation.

### Show a supporting document

An Action can project a declared document slot into its review context:

```yaml
reviewContext:
  id: facility-address-context
  fields:
    supportingDocument:
      type: document
      slot: supporting-document
```

Grant the reviewer `get-review-context` and include `supportingDocument` in
`readableContextFields`. The field is `null` when that optional slot was empty
at submission. Otherwise it contains the frozen document's slot ID, SHA-256,
media type, byte size and an exact source download link. Proposal `get` and
`readableAttachments` are separate grants and are unnecessary for this review.

Use the maintained client to select the review binding and download explicitly:

```js
const metadata = await client.registryContract('proposal-reviewer');
const binding = metadata.selectProposalReviewContext(
  'proposal-reviewer', 'correct-address',
);
const context = (await client.readProposalReviewById(binding, proposalId)).value;
const document = await client.downloadProposalReviewDocument(
  binding, context, 'supportingDocument',
);
// document.body contains the verified bytes; document.mediaType identifies them.
```

Each download requires the exact submission, effect and context schema and
rechecks current authorization and the complete context's Record/changes
disclosure before releasing bytes. Revise, Rebase, erased detail or unavailable
document verification can make a saved link unusable. Refetch the intended
context explicitly; the client never follows a successor or an external URL.

A document projection cannot infer the subjects described inside an opaque PDF.
For consent-sensitive review, also declare the authoritative Record or changes
projection whose current disclosure must hold. A document-only context grants
the selected frozen content without adding an inferred consent relationship.
The [facility example](examples/facility/README.md) combines supporting-document
display with current Record and frozen changes projections.

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
