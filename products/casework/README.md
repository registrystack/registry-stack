# Registry Casework

Registry Casework is a bounded human review service. A trusted producer asks for
review under a compiled `ReviewPolicy`; Casework admits a `ReviewRequest`,
assigns one or more `ReviewTask`s, records human `Decision`s, and returns an
immutable `ReviewResult`. The producer owns the subject and any later business
mutation. Casework has no source write or apply authority. PostgreSQL 17 or
newer is required for activation and runtime startup.

Start with the [standalone decision project](examples/standalone-decision/casework.yaml)
for a submitted snapshot. The [canonical review project](examples/canonical-review/README.md)
adds a BReg Proposal with current-source context. The [runtime configuration
guide](RUNTIME-CONFIG.md) and [current-source development guide](DEV-SOURCES.md)
cover deployment bindings. The [task grant guide](TASK_GRANTS.md) covers bounded
institutional agents. The generated [OpenAPI contract](generated/registry-casework.openapi.json)
and [CLI report contract](contracts/cli/README.md) own exact wire shapes.

## First submitted review

The starter needs no BReg service. It declares a `decision` policy with
`purpose: answer`, `context: {mode: submitted}`, a bounded `displaySchema`,
configured outcomes, a queue, access profiles, and a trusted requester.

```sh
caseworkctl init ./casework --template standalone-decision
caseworkctl check ./casework
caseworkctl explain ./casework
caseworkctl test ./casework
caseworkctl types ./casework --output ./casework-types
caseworkctl dev start ./casework
caseworkctl dev token requester ./casework
caseworkctl dev token staff ./casework
```

`check` compiles the policy and local schema closure offline. `explain` reports
the policy binding, context custody, stages, outcomes, routing, clocks,
staffing, refusals, and recovery. `test` exercises only local synthetic
fixtures; its `offline-synthetic` boundary does not prove a deployed service.
`types` writes TypeScript and Python types for policy bindings and review
contracts. `dev` owns a retained local Casework database and issuer; `dev token`
writes owner-only headers for a registered teaching client. Use
`caseworkctl dev events ./casework` for a bounded local runtime journal and
`caseworkctl dev stop ./casework` when finished. A stop preserves the database.
The dev database pulls `docker.io/library/postgres:17.11` at pinned digest
`sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675`.
Retained owned containers using the previous exact ECR Public reference at
that digest remain valid.

Each protected API call authenticates with `Authorization: Bearer ...` and selects
one declared profile. Shared producer Review routes use `Registry-Review-Profile`;
Casework policy inspection, human and administrative routes use
`Registry-Casework-Profile`. The development header file includes both so the same
registered caller can use its permitted routes. The producer's Requester profile is
separate from the human Staff or Supervisor profile. Bootstrap a team serving
the policy's queue through the authenticated Directory API before expecting
reviewers to see work.

The producer normally submits `policy: {"id":"decision"}`. Casework selects
and freezes its current compiled policy at first acceptance. This delegates
policy-version governance to the trusted Casework administrator. A producer
that must approve every policy change instead submits the exact
`{id, version, digest}` binding. Both pin fields are required together.
For strict mode, read `data.policyBindings[]` from the checked project:

```sh
caseworkctl --format json check ./casework
```

For a deployed service, the authenticated
`GET /v1/review-policies/decision` returns a policy closure whose `identity`
is the exact binding for strict mode. Use that identity, or the generated typed
client, rather than inventing a digest. A request to
`POST /v1/review-requests` carries `policy`, an immutable `subject` with
`source`, `type`, `id`, `version`, and a real content `digest`, an opaque
`requesterReference`, and `context: {"mode":"submitted","snapshot":{...}}`
that validates against the pinned display schema. An optional qualified
`initiator` supports reviewer exclusion. Send `Idempotency-Key`; a retry with
the same key and original body recovers the accepted request before consulting
current policy, even after policy updates. Acceptance, polling and results retain
the concrete accepted policy; never fill that binding into the original selector
or change its submission digest. New review work requires a new submission.
Current producer authority and context compatibility remain required. The admitted producer
identity, namespace, policy, subject binding, and submission digest govern
later cancellation and result access. Creation and recovery responses include
`Registry-Review-Producer`, naming the admitted producer explicitly so a source
can diagnose a producer-ID configuration mismatch without guessing from a digest.

The same admitted producer can cancel an open Review even when its current source
conceals the item. Cancellation uses the retained exact subject binding, settles
its tasks and clocks, and retains the terminal evidence without reading source
content. This does not expand reviewer or supervisor visibility or cancellation
authority. A source package activation can use this operation to close a round
that requires Rebase and fresh Review.

Human reviewers read `GET /v1/review-tasks`, then claim, assign, delegate,
release, draft privately, or decide a task under its current revision. Send
`If-Match` and `Idempotency-Key` on the documented mutations. The decision
vocabulary belongs to the policy: `approve`, `reject`, `changes-requested`,
or `answer`, each naming one of the policy's declared outcomes, with a reason
or structured result when the selected outcome requires them. An approval
names an outcome too; one without it is refused at `$.outcome`, and the
`Registry-Casework-Validation-Allowed` header lists the policy's approval
outcomes. Each outcome declares `publicReason: required`, `optional` or
`none`: a public reason of at most 2000 UTF-8 bytes reaches the producer on
the ReviewResult, while the private `reason` stays in the accountability
record and the audit journal records only that a public reason was given.
Stage thresholds count independent
eligible reviewers. Every approval in one stage names the same outcome: one
naming another outcome than the stage already chose is refused at
`$.outcome` with `approval-outcome-differs`, and the
`Registry-Casework-Validation-Allowed` header names the chosen outcome. The
final stage settles the request with that outcome and the public reason of
the approval that meets its threshold; earlier stages' outcomes and reasons,
and other approvers' public reasons, are kept for accountability and not
released. Decisions and task holdings are revision-fenced; an old
response cannot authorize a later state.

The same producer reads `GET /v1/review-requests/{requestId}/result` or its
resumable result feed. A `ReviewResult` repeats the subject, policy, and
submission digest and carries a terminal status such as `approved`,
`rejected`, `answered`, `cancelled`, or `superseded`. A decided result names
its `outcome` and any `publicReason`; a cancelled or superseded one carries
neither. A completion destination,
when configured, receives an authenticated payload-free wake. A wake carries
no decision payload; the producer fetches the result and authorizes any later
mutation independently.

## Refused older spellings

`caseworkctl check` and the runtime refuse the older project spellings below
at their path, name the replacement, and point at the row of the format table
in [CHANGELOG.md](CHANGELOG.md). Rewrite the project by hand; there is no
migration command. The identifier-keyed maps of row F4 are a configuration
shape only: the served policy lists those items as arrays in identifier order,
so reordering a map changes neither the served policy nor its digest.

| Row | Before | After |
| --- | --- | --- |
| F1 | subject clock `after: {elapsed: PT48H}` | `after: {hours: 48}`; exactly one of `minutes`, `hours` or `days` (24 hours) |
| F2 | `retention: {terminalDays, accountabilityDays}` on a review policy | `retention: {terminalRetentionDays, accountabilityRetentionDays}` |
| F3 | trusted producer `recoveryDays: N` | `retention: {receiptRetentionDays: N}`, at most 365 |
| F4 | `accessProfiles`, `queues`, `teams`, `trustedProducers`, `calendars`, `clocks`, `reviewPolicies`, `contextProviders`, `taskTemplates`, a policy's `outcomes` and a clock's `reminders` as lists of `{id: ..., ...}` | mappings from each id to the rest of its entry, `queues: {QUEUE_ID: {label: ...}}` |
| F5 | `type: activity` | `type: stage` |
| F6 | `anchor: request-accepted-at`, `anchor: stage-entered-at` | `anchor: {type: request-accepted}`, `anchor: {type: stage-entered}` |
| F7 | subject clock `completeOn: result-terminal` | removed; a subject clock completes when the result is terminal |
| F8 | `atRisk: {workingDaysBefore: N}`, reminder `workingDaysBefore: N` | `atRisk: {before: {workingDays: N}}`, `reminders: {REMINDER_ID: {before: {workingDays: N}}}` |
| F9 | routing `when: {activity: review}` | removed; a rule applies whenever a task is created, and one naming a `stage` matches only that stage's tasks |

## Distinct approvals and source versions

Each approval in a stage must come from a different eligible person.
A repeat claim after that person's decision returns `403 review.distinct-approver-required`.
The bounded `insufficient-distinct-approvers` task notice identifies a staffing shortfall without
listing team members. `caseworkctl doctor` warns when current serving-team membership cannot staff
a configured stage; offline `check` cannot inspect live Directory membership.

Deploy the BReg context provider and BReg at exactly the same Registry Stack version.
The provider checks `Registry-Engine-Version` before reading subjects, including when incompatible
metadata cannot decode. `source.version-mismatch` names an incompatible peer;
`source.version-unavailable` means the peer did not supply a usable version.
Neither refusal echoes the peer's header or source data.

## Current-source BReg review

The canonical project pins a BReg Proposal review-context export. Its
`facility-address-review` policy has `purpose: approval` and
`context.mode: current-source`, one provider and exact contract, and a vendored bounded
display schema. Casework keeps the request binding and derived task metadata,
not the current-source business projection. The provider exposes only the
capabilities a compiled policy uses: human display and service status here;
task-grant context and routing context are separate purpose-bound reads when
configured. An unsupported required capability is a compile refusal. BReg
serves human display and service status only: it does not serve task-grant
context yet
([#2062](https://github.com/registrystack/registry-stack/issues/2062)), so
`caseworkctl check` and the runtime refuse a task template with `subjects`
bound to this policy, naming the template and the capability. Remove
`subjects`, or bind the template to a source that serves task-grant context.

Build the matching BReg package, then pair and verify its native export:

```sh
caseworkctl provider pair products/casework/examples/canonical-review \
  --provider-id facility-proposal-context \
  --breg-package /absolute/path/to/breg-package \
  --action-id correct-address --apply
caseworkctl check products/casework/examples/canonical-review \
  --against-breg-package /absolute/path/to/breg-package
```

Pairing refusals retain `casework.provider-pair.contract-mismatch`,
`casework.provider-pair.unserved-capability`, or
`casework.provider-pair.version-mismatch`. The diagnostic names the review
policy's contract path, the provider's capabilities path, or `--bregctl`, with a
specific corrective action. Peer command output and secret values are excluded.

The offline check compares the export's exact source, action, context contract,
and schema bytes with the Casework package. The registry revision is diagnostic
metadata; unrelated package changes do not alter the accepted context binding. Set
`runtime.yaml` `contextProviders.facility-registry` to the BReg URL,
`statusProfile`, token endpoint, exact audience/resource/scopes, and status
reader secret references. The status reader needs only the BReg
`get-review-status` purpose. It never supplies fields displayed to a person.
The human caller sends the current bearer and selects an authorized
`Registry-Source-Profile` for open work, source context, lists, decisions, and
new notes. BReg applies that
profile's `get-review-context` disclosure and checks the exact Proposal
binding; Casework refuses or omits concealed or changed work. Open work must
also still be reviewable at the source: claim, decide, `next`, and reads of an
open task refuse or omit it once it is not. Decided tasks and settled requests
release their retained Casework-owned task, decision, history, and existing
notes under current Casework authority and retention. Their `/context` read
and new notes still require current source disclosure.
There is no generic Proposal read or source synchronization in this integration.

For local development, configure `dev-clients.yaml` `integrations` explicitly
and start the BReg dev session separately. Running `caseworkctl dev start`
with `--issuer-project ./breg-project` borrows a ready BReg issuer only after the
Casework clients and their precise grants have been registered there. See
[DEV-SOURCES.md](DEV-SOURCES.md) for provider and secret-file configuration.
The BReg producer owns Proposal submission, cancellation, and result
consumption. Applying the Proposal uses a separate BReg principal and BReg's
own fresh authority check.

## Staffing and accountability

All staffing operates on `ReviewTask`. Six supported outcomes share the same
current Directory, policy, task, and source-disclosure checks:

1. `GET /v1/review-tasks/next` returns the earliest due visible eligible task;
   it ignores `sort`, `limit`, and `cursor`.
2. `GET /v1/review-tasks/holdings` returns the caller's claimed or assigned tasks.
3. `POST /v1/directory/caseload/preview` and `/apply` move an exact,
   revision-fenced set atomically.
4. `GET /v1/review-tasks` filters by an exact five-part SubjectBinding or a
   visible reference and sorts by due date, subject, or reference. Selection
   never discovers arbitrary source records. Follow `nextCursor` unchanged;
   restart the walk when a live source change makes a cursor stale. The
   reference filter and sort match the exact reference the producer or
   provider supplies. A BReg producer supplies its machine string
   `breg:{registry}:{action}:{proposal}:{version}`, so staff cannot find a
   BReg review by a business number such as a licence number.
5. `POST /v1/directory/clocks/recompute/preview` and `/apply` recompute
   deadlines against the request's pinned policy closure. A subject clock
   covers one request, and a resubmission starts a new budget.
6. Authored routing evaluates only declared fields at task or stage creation.
   Submitted routing reads the admitted snapshot; current-source routing uses
   the provider's minimized routing capability and retains derived metadata.

`GET /v1/review-tasks/own-decisions` lets an eligible reviewer recover their
own retained decision receipts. Supervisors can inspect their serving queues
through `/v1/review-tasks/supervision` and independently authorized, audited
`/v1/review-accountability/{eventId}`. Own receipts omit private reasons and
producer results; accountability does not release review context. Directory
teams, absence cover, membership, and queue service remain current authority.
An opaque task reference or cursor grants no access. A decided row in either
list still asks the current source whether the caller can see the subject, with
the caller's bearer and source profile; a concealed subject is omitted and any
source error fails closed. A decided task read and the history, including notes,
of a settled request instead release retained Casework-owned records under
current Casework authority until terminal retention expires. They do not
release source context: `/v1/review-tasks/{taskId}/context` still asks the source
and answers not found when the source conceals the subject. Adding a new note
also retains the current source-visibility check.

List, next-task and holdings reads ordered by due date or subject select a
bounded SQL page before current-source reads. Their opaque continuation binds
the caller, profiles and query, and rechecks the anchor's current authority.
Live-reference filtering or sorting still completes a bounded scan before
returning globally ordered results; a smaller page cannot reduce that scan.
`inbox.maximumCandidateScan` defaults to 100, `maximumSourceReads` to 25 and
`pageDeadlineMilliseconds` to 2000. Source observations are shared by task
slots belonging to the same request for this invocation only. Continuation
anchor validation consumes the same source-observation budget as candidates.
Exceeding a scan or source-observation budget refuses the whole ordinary read
with `review.query-too-broad`; a provider timeout reports source unavailability.
Narrow the queue or exact subject, reduce an ordinary page size, or size the
budgets for the candidate page and measured source latency. These three reads
do not return partial budget-exhausted pages.

Caseload preview deliberately selects all of the source officer's claimed
tasks, optionally restricted to one queue, with a maximum of 100 tasks. It
has no subset, limit or continuation parameter. Apply moves that exact
revision-fenced set atomically. Use individual authorized task assignments
for a selected subset; those assignments are independent transactions.
Apply a caseload or clock recompute preview within 15 minutes. Once applied,
a retry with the same preview answers the same result for 24 hours, even if
the Directory changed since, so a lost response can be recovered.

Supervisory discovery deliberately omits holder identities and due dates.
It is an accountability view, not a team holdings board. Use the Directory
to choose the source officer and an authorized caseload preview to inspect
the proposed move. Reviewer eligibility is not a substitute for supervisor
authority.

An authorized ReviewTask read or supervisory row can include
`staffingDiagnostic: no-cover-available` when assignment or absence recompute
finds no eligible cover. This notice reveals no holder or source context.
Successful assignment, claim, caseload transfer, release or task closure clears
it; a closed task does not display an old staffing notice.

## Package, activate, and recover

Use a fresh Casework database for this pre-1.0 contract. It does not upgrade a
retired schema in place and never discards existing operator data to proceed.
The reviewed package contains `casework.yaml`, every referenced local schema,
provider description, and exact `SHA256SUMS`. Point `package.root` at that
package, and set `package.expectedDigest` to the printed package digest when
pinning a deployment. `runtime.yaml` also names a logical `databaseId`,
listener, OIDC verifier, access credentials, audit destination, and optional
context-provider bindings. Configure a distinct migration role for apply
where the database uses split roles.

```sh
caseworkctl check ./casework --runtime-config /etc/registry-casework/runtime.yaml
caseworkctl package ./casework --dry-run
caseworkctl package ./casework --output /srv/registry-casework/package
caseworkctl doctor --runtime-config /etc/registry-casework/runtime.yaml
caseworkctl plan --runtime-config /etc/registry-casework/runtime.yaml
caseworkctl apply --runtime-config /etc/registry-casework/runtime.yaml
caseworkctl status --runtime-config /etc/registry-casework/runtime.yaml
casework --runtime-config /etc/registry-casework/runtime.yaml serve
```

`check --runtime-config` checks authored configuration offline. `plan` reads
the configured database; `doctor` also checks the audit destination. `apply` alone
uses the migration credential and records package activation. A candidate
that removes a still-needed policy, producer, profile, team, provider, or
contract is refused until affected reviews finish. There is no orphan bypass.
The service verifies the activated package before it serves traffic. Review
results, idempotency receipts, cursors, and accountability have separate
bounded retention; a producer should retain its request ID and original
idempotency key, retry safely after a lost response, and fetch the immutable
result after a completion wake. Audit failure refuses sensitive operations;
restore the audit destination and use `status` to inspect activation.
The [logical backup/restore proof](scripts/test-backup-restore.sh) runs a
submitted review against an owned disposable Docker database. It checks the
backup-point activation and holding, fresh readiness, and append-only audit
after a restore. A logical database restore does not rewind the external audit
journal or inherit authority from a later result.

The runtime's [configuration reference](RUNTIME-CONFIG.md) owns every field and
recovery diagnostic. JSON CLI reports use one versioned typed envelope with
machine-readable codes and suggested actions. A domain refusal exits 1,
invalid usage 2, and unavailable local or remote resources 3.

## Verification database

The maintained review checks use disposable PostgreSQL databases and unique
test schemas. Never point them at retained operator data. The aggregate runner
uses `CASEWORK_REVIEW_TEST_DATABASE_URL`; it defaults
`CASEWORK_ACTIVATION_TEST_DATABASE_URL` and
`CASEWORK_ASSIGNMENT_TEST_DATABASE_URL` to that URL when omitted. The native
BReg journey additionally needs `BREG_TEST_DATABASE_URL`. The separate
`caseworkctl` retained split-role session test uses `CASEWORK_TEST_DATABASE_URL`
and creates its own schema and role.

```sh
CASEWORK_REVIEW_TEST_DATABASE_URL=postgresql://localhost/casework_review_test \
  products/casework/scripts/check-review-examples.sh
```

That runner checks authored examples, generated contracts, review and migration
transactions, HTTP, grants, and the installed local-client journey. Its final
journey needs a running Docker daemon, Node, Python, and the documented native
build prerequisites. Focused product contract checks run with
`python3 products/casework/scripts/test_product_contracts.py`.

The cross-product task-grant journey is an ignored Rust test owned by the Casework
maintainer and the `casework-postgres` CI job. CI builds the Scheduling probe and runs the
exact ignored test against its disposable database and stock ThunderID. The journey loads
Evidence through its runtime configuration and crosses into Scheduling through its maintained
probe. To reproduce it locally, build the probe, export the inputs named by the test's ignore
reason, then run:

```sh
cargo test --locked -p registry-casework --features postgres-test --lib \
  approved_casework_tasks_reach_evidence_breg_and_scheduling_through_stock_thunderid \
  -- --ignored
```
