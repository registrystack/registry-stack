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
reference](https://docs.registrystack.org/reference/casework-configuration/) and [current-source pairing guide](https://docs.registrystack.org/configure/casework/#pair-a-current-source-provider)
cover deployment bindings. The [task grant reference](https://docs.registrystack.org/reference/casework-task-grants/) covers bounded
institutional agents. The generated [OpenAPI contract](generated/registry-casework.openapi.json)
and [CLI report contract](contracts/cli/README.md) own exact wire shapes.
The [stage outcomes example](examples/stage-outcomes/README.md) keeps one review
history while offering different decisions at local and final review.

## Start a development run

The starter needs no BReg service. It declares a `decision` policy with
`purpose: answer`, `context: {mode: submitted}`, a bounded `displaySchema`,
configured outcomes, a queue, access profiles, and a trusted requester.

```sh
caseworkctl init ./casework --template standalone-decision
caseworkctl check ./casework
caseworkctl explain ./casework
caseworkctl test ./casework
caseworkctl types ./casework --output ./casework-types
rstack dev start ./casework
```

`check` compiles the policy and local schema closure offline. `explain` reports
the policy binding, context custody, stages, outcomes, routing, clocks,
staffing, refusals, and recovery. `test` exercises only local synthetic
fixtures; its `offline-synthetic` boundary does not prove a deployed service.
`types` writes TypeScript and Python types for policy bindings and review
contracts. `rstack dev` runs the project with its own PostgreSQL server and a local
issuer, from a plan file. The
[standalone decision example](examples/standalone-decision/dev.yaml) has the plan and a scenario
for this starter. `rstack dev token RUN --as staff` writes an owner-only header file for a person the
plan names. Managed development data survives a stop. Use `rstack dev stop RUN --clean` to remove it or `rstack dev start PROJECT --clean` to start fresh. See
[Run a project with rstack dev](https://docs.registrystack.org/configure/run-a-project-with-rstack-dev/#the-managed-postgresql-server) for the database image and recovery.

Policy, stage, routing-rule, queue, team, and outcome labels are presentation
text for people. They are single-line values: tabs, line feeds, carriage
returns, and other control characters are refused. Stable references continue
to use ids, and labels do not change a policy's behavioral binding digest.
`explain` reports the queues a policy uses, including clock reassignment
queues, the union of its deciding profiles, and every staff or supervisor
profile eligible to be selected.

A policy binding deliberately closes over every access profile, queue, team,
and the project inbox, even when one policy does not currently name them. It
also closes over that policy's referenced clocks and calendars, context
provider, task templates, and trusted producers. This whole-project staffing
closure means adding an otherwise unused queue or team changes every policy
binding. `explain` keeps that closure in `dependencies` and reports narrower
usage separately; it also lists all project clocks, calendars, and trusted
producers at project level.

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
For strict mode, read `policyBindings[]` from the checked project's flat report:

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

A stage may declare `publicProgressCode`, a lowercase local identifier such as
`identity-check`. The code is part of the frozen policy digest. The admitted
producer can request the current mapped code with
`GET /v1/review-requests/{requestId}?include=progress`.
Casework includes `progressCode` only when a reviewing request's active stage
declares one. Producers map the code to applicant-facing language and verify the exact accepted
request, subject, policy and submission digest before displaying it.
Upgrade clients that decode full policy or task-context closures before
activating a policy that sets progress codes. Older Casework clients may
reject the added stage field.
Policies that omit the field retain the earlier closure shape and digest.

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
`Registry-Casework-Validation-Allowed` header lists the current stage's approval
outcomes. Each outcome declares `publicReason: required`, `optional` or
`none`: a public reason of at most 2000 UTF-8 bytes reaches the producer on
the ReviewResult, while the private `reason` stays in the accountability
record and the audit journal records only that a public reason was given.
An approval carries no private `reason`: only `outcome` and `publicReason`. A
member the request type does not declare, such as `reason` on an approval, is
refused with 422 `request.unprocessable`, and the
`Registry-Casework-Validation-Path` header names it (`$.decision.reason`) with
reason `schema-mismatch`; the submitted value is never echoed.
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

Each stage may set `outcomes` to the non-empty subset of policy outcome ids it
offers. Omitting the field offers every policy outcome, preserving existing
projects. `caseworkctl check` refuses an unknown outcome id and a stage with no
available path to advance or settle the review: every stage must offer an
outcome whose settlement is `approved` (`answered` for an answer policy).
`caseworkctl explain` always
reports the effective outcomes for each stage, including the all-policy default.
A `changes-requested` result ends that review version. A resubmission is a new
version that starts at the policy's first stage; it does not resume the earlier
review in place.

The same producer reads `GET /v1/review-requests/{requestId}/result` or its
resumable result feed. A `ReviewResult` repeats the subject, policy, and
submission digest and carries a terminal status such as `approved`,
`rejected`, `answered`, `cancelled`, or `superseded`. A decided result names
its `outcome` and any `publicReason`; a cancelled or superseded one carries
neither. A configured completion destination receives a Standard Webhooks-signed
[completion wake](https://docs.registrystack.org/configure/casework-completion-receivers/)
with event, request and result identifiers. Delivery is at-least-once. A wake carries
no decision payload; the producer fetches the result and authorizes any later
mutation independently.

## Distinct approvals and source versions

Each approval in a stage must come from a different eligible person.
A development clients file may bind several clients to the same access profile.
Each client has its own identity and token. Two clients on a team's staff list
that resolve to the same principal are refused. Use two clients on one Staff
profile to exercise `requiredApprovals: 2` locally; separate profile names are
not a substitute for independent people.
A repeat claim after that person's decision returns `403 review.distinct-approver-required`.
The bounded `insufficient-distinct-approvers` task notice identifies a staffing shortfall without
listing team members. `caseworkctl doctor` warns when current serving-team membership cannot staff
a configured stage; offline `check` cannot inspect live Directory membership.

Deploy the BReg context provider and BReg at exactly the same Registry Stack version.
The provider checks `Registry-Engine-Version` before reading subjects, including when incompatible
metadata cannot decode. `source.version-mismatch` names an incompatible peer;
`source.version-unavailable` means the peer did not supply a usable version.
Neither refusal echoes the peer's header or source data.

## Approval patterns

Create a submitted-snapshot approval project with a shared pattern:

```sh
caseworkctl init ./review --template two-peer-approval
caseworkctl check ./review
caseworkctl explain ./review
caseworkctl test ./review
```

`single-reviewer-approval` requires one reviewer. `two-peer-approval` requires
two distinct people on one Staff profile and creates two synthetic local
clients for them. `technical-check-then-authorization` creates a technical
check followed by a separate authorizer. Every pattern excludes the initiator;
the authorization stage also excludes earlier reviewers. Inspect the generated
policy, staffing, retention, and producer bindings before using it for your
institution.

By default, `negativeDecisions: settle` lets a rejection or request for changes
settle the review immediately. Set `negativeDecisions: advise` on a non-final
stage to record the finding and continue. On that stage, `requiredApprovals`
counts completed decisions by distinct eligible people, including negative
ones. The next stage opens when the threshold is met even if every finding was
negative. The technical-check pattern uses this mode; only the authorizer can
settle its review. A final advisory stage is refused with
`casework.review-policy.advisory-final-stage` at its `negativeDecisions` field.

Later authorized reviewers serving an active-stage task's effective queue can
read earlier advisory decisions and private reasons through the existing
decision history. Routing determines that queue; membership in the stage's
default queue alone does not grant access. Each advisory decision is
audited. The producer receives only the settling outcome and that decision's
public reason; earlier findings and reasons remain in Casework. `explain`
reports each stage's effective mode. Omitting the field preserves existing
policy behavior and digests.

## Current-source BReg review

To generate one of the approval patterns for an existing Proposal-mode Action,
use `caseworkctl provider add`:

```sh
caseworkctl provider add ./review --posture development --breg-project ./facility \
  --action correct-address --pattern single-reviewer-approval \
  --breg-package ./facility-package
```

The command reads BReg through the matching `bregctl` public CLI. Missing
review requirements, context, or reader grants produce
`casework.provider-add.breg-changes-needed`, proposed YAML, and no project.
The flat JSON report names the command result in `outcome`, such as
`changes-needed`, `created`, or `in-agreement`; `status` remains the process
result class.
Review and apply those source changes, then rerun. Existing context, policy
IDs, and authority names are retained. The suggested context contains the
Plan's used inputs and changed fields; a changes projection needs ordinary
Record read authority over those fields and rows. An inputs-only alternative
is printed beside that grant. Bypass writes are warnings for an operator to
assess, and documents are never added to the proposed context.
If the Action writes encrypted fields, BReg cannot export their before/after
values. The command asks you to author a supported context explicitly, such as
an inputs-only context, then rerun. It never silently drops changed fields.
An automatic context exceeding 64 context fields or 64 selected fields in one
changes projection also requires an explicitly authored, minimized context.

If the Action's start profiles use different row boundaries, author the human
reviewer's Proposal and Record grants explicitly, then rerun. The command
preserves a complete reviewer grant bound to `actorKind: human` and explicit
`requesterClients`. Existing profiles without a human binding remain unchanged;
the proposed profile uses a separate ID. Bind its suggested reviewer client ID
to the intended UI clients before applying it. Its status service must have only the
selected Action's Review status authority, with no Record, Action, other
Proposal, or statistical dataset authority.

When BReg is ready, Casework writes the pattern with exact current-source
pins and the native exported schema. With `--breg-package`, its compiled registry
revision must match the inspected project before pairing and schema comparison.
The selected policy ID must fit Casework's local identifier format. An exact
BReg policy selection must match the compiled Casework policy's version and
digest; matching exact selections and ID-only selections are both supported.
`--package-output` writes a package when creating the project and sets the
runtime example's package root to that destination.
Without a package it checks the generated project and prints the pairing
step. A repeat invocation compares effective policy values and the source status
profile, accepts explicitly written defaults, and rechecks agreement without
rewriting files. When `runtime.example.yaml` is present, its status profile must
match and its scopes must include every scope currently required by BReg;
additional operator-configured scopes are preserved. To write
a package for an existing project, use `caseworkctl package --output`.
Generated producer identities use reserved `.test` placeholders; runtime
examples contain secret references only. The command never edits BReg or
creates credentials.

The canonical project pins a BReg Proposal review-context export. Its
`facility-address-review` policy has `purpose: approval` and
`context.mode: current-source`, one provider and exact contract, and a vendored bounded
display schema. Casework keeps the request binding and derived task metadata,
not the current-source business projection. The provider exposes only the
capabilities a compiled policy uses. Human display, service status, and
task-grant context are separate purpose-bound reads; routing context remains a
separate capability. A BReg provider can expose task-grant context only when
the paired package declares a distinct `get-task-grant-context` service
profile with the exact source fields. `caseworkctl check` and the runtime
refuse a task template with `subjects` when the provider or runtime binding
omits that capability. There is no fallback to human display or service status.

Build the matching BReg package, then pair and verify its native export:

```sh
caseworkctl provider pair products/casework/examples/canonical-review \
  --provider-id facility-proposal-context \
  --breg-package /absolute/path/to/breg-package \
  --action-id correct-address --apply
caseworkctl check products/casework/examples/canonical-review \
  --against-breg-package /absolute/path/to/breg-package
```

The source-built `registry-mcp` supporting service can use the default-off
`delegatedStaffReaders` contract for assigned-task listing and context reads at
`/v1/delegated-staff`. Each reader explicitly admits a trusted gateway,
represented staff profile, required scopes, short token lifetime and optional
source profiles, and names in `representedHuman` the claim that says the
represented person is human. Ordinary staff and producer routes retain their
own authentication. Current-source context additionally requires
`delegatedDisplayExchange` and an institution-approved source agent profile;
the Casework bearer is never forwarded to BReg. See
[the MCP gateway configuration](https://docs.registrystack.org/configure/breg-mcp/) and
[the staff runtime example](../platform/examples/mcp-runtime/casework.example.yaml).

Pairing refusals retain `casework.provider-pair.contract-mismatch`,
`casework.provider-pair.unserved-capability`, or
`casework.provider-pair.version-mismatch`. The diagnostic names the review
policy's contract path, the provider's capabilities path, or `--bregctl-bin`, with a
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
still requires current source disclosure. Once the request has left review
(it is terminal) and the exact source binding remains disclosed but is no
longer reviewable, the reviewer who recorded a task's retained decision may
read that task's context, and only that task's. Other eligible reviewers,
including the authors of other tasks on the same request, receive not found,
and an earlier stage's author receives not found while the request is still
in review. The author reads the source's current projection, still authorized
by the source with the caller's own token and source profile, until the
result's retention ends. Casework checks authorship and the reviewer's current
membership, profile and retention before the provider read and re-checks them
after it (defence in depth). New notes still require current source
disclosure.
There is no generic Proposal read or source synchronization in this integration.

For local development, list BReg and Casework in one `rstack dev` plan. See
[the pairing guide](https://docs.registrystack.org/configure/casework/#pair-a-current-source-provider) for provider and secret-file configuration.
The BReg producer owns Proposal submission, cancellation, and result
consumption. Applying the Proposal uses a separate BReg principal and BReg's
own fresh authority check.

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
caseworkctl check ./casework --production
caseworkctl package ./casework --dry-run
caseworkctl package ./casework --output /srv/registry-casework/package
caseworkctl doctor --runtime-config /etc/registry-casework/runtime.yaml
caseworkctl plan --runtime-config /etc/registry-casework/runtime.yaml
caseworkctl apply --runtime-config /etc/registry-casework/runtime.yaml
caseworkctl status --runtime-config /etc/registry-casework/runtime.yaml
casework --runtime-config /etc/registry-casework/runtime.yaml serve
```

`generate identity-facts` writes the identity facts Casework expects of its
token issuer, so the issuer's configuration is derived from this product and
never written twice:

```sh
caseworkctl generate identity-facts ./casework \
  --runtime-config /etc/registry-casework/runtime.yaml --output ./casework.identity-facts.yaml
```

The facts state the issuer, audience and admitted clients from the issuer
entry under `authentication.oidc.issuers`, the human-actor claim, each access profile's scopes
and whether it requires a human (as Casework does for a profile that does not
act as a requester, or that initiates reviews), and, when `taskAuthority` is configured, the task authority as an
assertion issuer, a status profile limited to its `statusClients`, and the
exchange profile for the clients that present its assertions. The assertion
issuer's key location is `<taskAuthority.issuer>/.well-known/jwks.json`, where
the Casework service publishes it. The command refuses a runtime file with
more than one issuer entry or a `scopeClaim` other than `scope`, refuses an
existing output file, opens no secret, and prints only the output path and counts.

`check --runtime-config` checks authored configuration offline. `check
--production` also reads the exact package input closure and points an unpaired
context provider back to its authored `description` with the `provider pair`
recovery command. It writes no package and contacts no runtime dependency. `plan` reads
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

The runtime's [configuration reference](https://docs.registrystack.org/reference/casework-configuration/) owns every field and
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

For an explicitly declared synthetic browser run, `rstack dev` binds the run
issuer itself. It checks that the existing producer's exact issuer, profile and
subject match the plan's declared development identity and grant, writes the
allocated loopback issuer into a private copy of the project, then runs the
public `caseworkctl check` and `package` on that copy. Subjects and grants never
change. Initiator opt-in acknowledges issuer trust under the existing producer,
not an enforced subject allowlist. See the
[run declaration](https://docs.registrystack.org/configure/run-a-project-with-rstack-dev/).
