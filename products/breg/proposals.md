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

Set `review.source` to the source namespace configured in the Review provider.
It may differ from the registry's `project.id`. BReg and the provider use that
namespace for the Review subject and delivery digest; the opaque BReg context
reference still identifies the registry. Retrying an unsettled request also
repairs the legacy registry-id digest without changing its request or idempotency key.
The first delivery and its accepted settlement are logged at `info`. Uncertain
deliveries warn with the SHA-256 of the Proposal id string, authority, attempt
count, and bounded outcome code; request values and credentials are not logged.

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
Such a Proposal has no review outcome: follow it to `applied` or `cancelled`.
A blocked application is a turn change, not an outcome. The caller corrects
the work with Retry, Revise or Rebase, or cancels it.

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
need their own grant. `get-application-actor` is a supplemental disclosure
grant and must appear with Get in the same Proposal grant. List requires List authority and conceals other owners'
and jurisdictions' work before filters or counts. Record and changes projections
in review context also require current Record disclosure. Frozen input and
document projections use their declared review-context grants and current
applicable checks. A review-status service grant is restricted to its named
authority and returns no display values.

A Proposal grant may name `writableInputs`, the Action inputs that profile may
set. Without it, every declared input stays writable. With it, Start refuses a
value for any other input, and Edit, Revise and Rebase must restate every other
input exactly as the current draft or submitted version holds it. An absent
input and `null` count as the same value. A refusal answers
`400 request.invalid` with `fieldPath` naming the first such input, for example
`/input/licenceNumber`; the draft stays unchanged and the refusal is audited
without the value. The list must name declared inputs and needs Start, Edit,
Revise or Rebase authority. When the grant holds Edit, Revise or Rebase, every
input outside the list must be in `readableInputs`, so the equality check never
reveals a value the caller cannot read. Attachments keep their own
`writableAttachments` grant. For an Action whose inputs are `holder`,
`statement` and `licence-number`, an applicant may write the first two while an
officer, under a grant without the list, records the licence number:

```yaml
proposals:
  - action: apply-for-licence
    operations: [get, list, edit, submit, revise, cancel]
    ownership: caller
    readableInputs: [holder, statement, licence-number]
    writableInputs: [holder, statement]
```

Ownership alone does not preserve access after a target leaves the caller's
current row boundary. Proposal Get then returns a concealed 404, List omits the
Proposal, and transitions such as Cancel return the generic precondition refusal.
The saved Proposal remains governed work, but that caller can no longer view,
cancel or recover it. An adopter should explain this loss of access and provide
its service contact path; it must not retain a private copy as substitute authority.

A Proposal offers its `reviewStatus` link in every state except `draft`,
including after it was rejected, applied or cancelled, so a client that
follows links can still reach a retained result. The link is absent once the
current submission's detail was erased.

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
bregctl --format json explain lifecycle
```

These commands inspect configuration without a database or review decision.
The lifecycle explanation needs no project. Each state lists every `turn` the
runtime can derive and the condition for it, using the same pure rule that
serves Proposal documents and lifecycle events. These turns describe whose
move the work waits on. They do not grant an operation; current links and
runtime checks continue to decide caller authority.
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
`applying`, `blocked`, `applied`, `cancelled` or `rejected`. Its
`application-refused` reason means an executor refused the frozen effects; a
review outcome never appears there.

A unique-constraint failure during manual Apply returns `409 mutation.conflict`
without retaining any Record effects. Subsequent reads report
`applicationStatus.state: blocked`, `reason: application-refused`, and
`recovery: correct-input`. Apply is unavailable; Rebase remains available to
correct the input and prepare a fresh submission. A stale Record revision
instead returns `412 precondition.failed` without creating that application
block. Read the current Proposal before choosing the next authorized operation.

The `apply` link's availability reports Review separately:

| Review of the current submission | Apply availability |
|---|---|
| Delivered and awaiting a decision | `pending-review`, recovery `refresh` |
| Delivery or result lookup failing | `dependency-outage`, recovery `retry`; Retry resumes it |
| `changes-requested` | `review-changes-requested`, recovery `revise` |
| Approval past its `availableUntil` | `review-ended`, recovery `revise` |
| Review submission failed for good | `review-ended`, recovery `revise` |
| `answered`, or cancelled or superseded by the provider | `review-ended`, recovery `revise` |

Withdrawal ends the current round immediately, including while remote cancellation
is pending or a late approval remains as historical evidence. Apply reads
`review-ended` and the turn returns to `party`; a package block still takes
precedence. When Revise is the recovery, the Retry link reports the same reason
instead of `invalid-input`.

### Whose turn it is

Every Proposal document and lifecycle event carries a derived `turn`:

- `party`: the caller who drives the Proposal acts next. A draft, a blocked
  application that needs corrected input, and a submission whose Review ended
  without an approval it can use (changes requested, an expired approval, a
  failed review submission, a provider end) are the party's turn.
- `official`: a reviewer or applier acts next. Review in progress or being
  retried, an approved or review-free manual submission awaiting Apply, and an
  automatic application blocked on a dependency outage are an official's turn.
- `nobody`: no one needs to act. The Proposal is `applied`, `cancelled` or
  `rejected`, or its automatic application is queued or running.

`turn` is derived from the lifecycle state, the current submission's review
progress and its application status when the Proposal is read; nothing stores
it. It says whose move the work waits on, not who is authorized to make it:
the links still decide what the current caller may do. List Proposals by turn
with `GET /v1/proposals?turn=party` (or `official`, `nobody`). A page may hold
fewer than `limit` items, so keep paging while `nextCursor` is present.

### After a Review result

A result settles only the submission version it was recorded for. A
rejection of the current submission ends the Proposal: it moves to `rejected`
in the transaction that records the result, with a `rejected` lifecycle event.
Any other result leaves the Proposal `submitted` until it is applied or
cancelled; a changes-requested result records a `review-returned` event.

| Result | What follows |
|---|---|
| `approved`, automatic application | The built-in executor applies the frozen effects. `applicationStatus` reads `applied`, or `blocked` with a recovery hint when an executor refuses them. |
| `approved`, manual application | The `apply` link becomes available. An authorized caller applies before the approval's `availableUntil`. |
| `rejected` | The Proposal is `rejected`, a terminal state. Every command link reads `review-rejected` with recovery `receipt-only`: Submit, Edit, Revise, Rebase, Apply, Retry and Cancel answer 409 `proposal.rejected`, also after a package activation changes the Action revision; an attachment upload or removal is an Edit and answers the same. Start a new Proposal to propose the work again. |
| `changes-requested` | The Proposal stays `submitted`. Apply reads `review-changes-requested` with recovery `revise`. Revise submits the corrected version. |
| `answered` | Apply reads `review-ended` with recovery `revise`. An answer is not a decision on a change. |
| `cancelled` or `superseded` by the provider | Apply reads `review-ended` with recovery `revise`. A round BReg withdrew also reads as ended; a late approval cannot restore Apply authority. |

### The decision

Proposal Get, each Proposal in a list, and the per-version submission read
carry `decision` once the reviewer decided the submission:

```json
"decision": {
  "status": "rejected",
  "decidedAt": "2026-10-16T09:12:44.000000Z",
  "publicReason": "The certificate on file expired."
}
```

`status` is `approved`, `rejected`, `changes-requested` or `answered`.
`publicReason` appears only when the reviewer wrote one for the subject; it is
the only reviewer text BReg serves. Notes, internal reasons and the reviewer's
identity stay with the review provider. A provider-side end (`cancelled`,
`superseded`) is not a decision and has no `decision`; neither has a result
whose content retention erased. A lifecycle command's response omits
`decision`: read the Proposal to see it. Each read that serves a public reason
records a fixed `proposal-review-public-reason` marker in its audit entry,
never the text.

Revise after an approved, not yet applied, manual submission discards the
approval. The approval binds the earlier version only, and the revised version
needs its own Review before it can be applied. Apply first if the approved
change must take effect.

Cancel, and Revise or Rebase of a submitted Proposal, close the Proposal's
queued, applying or blocked automatic application job in the same transaction.
The job reads `cancelled`; it never applies a superseded version.

### When activation blocks submitted work

A successful package activation that marks a submitted Proposal
`package-changed` closes its queued, applying or blocked application jobs and
withdraws its Review in the same transaction. A never-sent Review is cancelled
locally. An accepted Review uses the existing producer cancellation operation.
An already-sent request with an uncertain outcome recovers the same request and
idempotency key only to obtain its acceptance and cancel it. Cancellation may
remain pending while the authority is unavailable. Failed rounds are withdrawn
too: a retained acceptance can be cancelled, while an exhausted delivery without
an acceptance stays closed.

A late exact result is retained under the existing retention rules, but cannot
queue an application or advance the withdrawn round. Rebase and Submit create a
fresh version and Review. Rolling back to the frozen Action revision can clear
`blockedReason`; it never revives a cancelled round or a closed job, including
when no application job existed before withdrawal. A closed automatic application
remains observable as `blocked` with `contract-changed`, `correct-input`, and
`automaticRetry.scheduled: false`, including after rollback clears the package
block. The Proposal stays submitted and its authorized requester can still
Rebase or Cancel; observing it never requeues the old application. This includes
an approved result received after withdrawal when no application job exists:
Get, List and turn filtering keep the Proposal recoverable, while its retained
decision remains historical evidence. Manual rounds also return the turn to the
requester and refuse Apply after a restoring package clears the block.

`bregctl review-recovery resubmit` and `retry-application` refuse a currently
blocked, still-submitted Proposal with reason `package-changed` and direct its
requester to Rebase for fresh Review or Cancel. Once cancelled, it receives the
existing terminal or withdrawn refusal instead. The recovery operations keep their
authority and cannot reopen a withdrawn round after rollback.

The private metrics listener exposes `breg_proposal_application_blocked_jobs`:
the count of application jobs closed or held by a package change on the current
submitted Proposal. These jobs do not age the runnable application queue. The
count drops when that version is no longer current, its Proposal is cancelled,
or rollback clears the block. A failed database sample omits the series.
Database operators can list the same retained jobs without reading source values:

```sql
SELECT q.action_id, q.proposal_id, q.submission_version, q.state
FROM registry_internal.registry_proposal_application_jobs q
JOIN registry_internal.registry_proposal_state p USING (action_id, proposal_id)
WHERE p.state = 'submitted' AND p.submission_version = q.submission_version
  AND p.blocked_reason = 'package-changed'
  AND q.state IN ('queued', 'applying', 'blocked', 'cancelled');
```

A distinct handoff failure, `producer-identity-mismatch`, means a valid provider
acceptance explicitly named a different producer ID. The bounded warning names
BReg's configured `reviewAuthorities` `producerId` and the provider's admitted
producer ID. Align them with the provider's `trustedProducers` configuration
before submitting new work. The provider may retain the mismatched Review;
this diagnosis does not mean its mutation rolled back. Transport failures,
missing metadata with a wrong digest, and malformed acceptances retain uncertain
effect handling. Submission bodies and credentials are excluded from the warning.

### Read one submission

`GET /v1/proposals/{id}/submissions/{version}` reads one submitted version
under Proposal Get authority. It returns that version's frozen `effectDigest`,
its review result, its `decision` when one was made, and its application status
as separate members, and `current` says whether it is still the Proposal's
latest version. The Rust, Node.js and Python clients read it with
`read_proposal_submission` (`readProposalSubmission` in Node.js). An unknown
or non-canonical version is concealed like an unknown Proposal. Once neither
the review result nor the application receipt is retained, the read answers
410 `proposal.submission_expired`, and its audit entry records a result count of zero.

Settle a followed Proposal only from this per-version read, or from the
current Proposal Get for the current version. Never settle it from a Casework
result for the Proposal subject. Revise and Rebase are allowed while a review
submission is uncertain or cancelling, so a late Casework result for an
earlier version can still arrive after BReg has moved on.

### Who applied a Proposal

The application receipt records who applied the Proposal, as a keyed actor
pseudonym scoped to the database and issuer, and when. The audit journal
records the same pseudonym on the application request. A profile holding both
`get` and `get-application-actor` receives `appliedBy` and `appliedAt` in the
application member of Proposal Get and the per-version submission read. Both
members are absent without that supplemental operation, and Proposal List
omits them even for a holder. No response carries the raw issuer or subject.
The pseudonym lets a holder link Proposals applied by the same actor within
one database and issuer. A holder who knows the applier of one Proposal from
another source can associate that actor with other matching pseudonyms. An
audit hash-key holder can also recompute it for a known issuer and subject.

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
Either field is `null` when its optional input was omitted at preparation, and
a `type: record` field is also `null` when its optional Record field is empty.

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

### Bounded review-context reads

A caller with the existing `get-review-context` grant can request up to 100
distinct canonical Proposal UUIDs in one exchange:
`GET /v1/proposals/review-context?accessProfile=<profile>&ids=<uuid>,<uuid>`.
The ordered `items` contain the requested `id` and either `status: visible`
with the ordinary `context` document, or `status: concealed` with no document.
Unknown and currently unauthorized Proposals have the same concealed result.
Every item retains its own current Proposal and Record disclosure checks,
transaction, and paired audit entries. Batch transport adds no authority.
Operational failures refuse the entire batch; the aggregate response is bounded
at 8 MiB. Use smaller batches when contexts approach that bound.
The native Rust client validates cardinality, order, IDs, Action binding and
closed item shapes before releasing any document.
