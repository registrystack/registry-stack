# Registry Casework changelog

## Unreleased

- The BReg source adapter projects a request whose approval expired before it
  was applied (BReg application state `expired`) as a waiting application
  occurrence instead of refusing the source read. The professional-review
  journey follows the `rebase` value BReg's `revise_request` action carries
  after a send-back, and asserts that BReg records a revision.
- `caseworkctl source add` no longer refuses the whole pairing when the BReg
  registry declares another change-request entity, besides the ones being
  paired, that names one of this Casework project's review authorities with a
  `policyId` no `reviewKinds` entry matches. BReg's own compile check only
  validates that `review.authority` and `review.policyId` are well-formed
  identifiers, so such an entity previously passed unnoticed until something
  tried to submit a change request against it. Refusing the pairing over it
  blocked incremental authoring (pairing this entity before that other
  entity's review kind exists) and was wrong whenever several Casework
  projects share the same authority id, since the other entity's policy may
  legitimately live in one of them. The command now reports a finding
  instead, naming the entity, the declared `policyId`, and that no
  `reviewKinds[].id` matches it (a missing or non-string `policyId` still
  fails `bregctl check` first). Preview
  and apply report the same findings. The entities actually being paired
  are unaffected: an unresolved `policyId` on any of them is still refused. A `policyId`
  edited in the BReg project after pairing is not caught: nothing
  `source add` writes records the BReg project's location or content, and
  the existing pinned-description re-check is deliberately scoped to the
  casework.yaml on disk now, not a re-derived BReg source.
- `caseworkctl source add` no longer refuses the whole pairing when a
  selected request's review or apply access profile declares a `rowBoundaries`
  claim using operator `equals` over a string-shaped field. It writes the
  source description and runtime binding as before, and the local BReg
  dev-client export still grants the profile, since BReg's runtime keeps
  enforcing the boundary and refuses a token that lacks the claim. What
  changes is that the command now reports a finding naming the profile and
  the boundary claim(s), so an operator knows a local Casework reviewer
  client needs that claim added by hand, as a string equal to the field's
  stored value, to exercise the profile. Preview and apply report the same
  finding. A `rowBoundaries` claim using operator `in`, or `equals` over a
  non-string-shaped field (for example Boolean or Int64), still refuses the
  pairing: the local Casework dev-client claim model holds only strings, and
  neither pairing can be represented that way.
- The BReg source adapter refuses a source request reported as `superseded`,
  a state BReg no longer defines. A BReg draft still projects as a superseded
  application occurrence.
- Add `package.expectedPolicyDigest` to the Casework runtime configuration.
  When set, `casework` refuses to start unless the package under
  `package.root` is a package with exactly that policy digest. The refusal
  names the expected digest and the digest it found, or that it found no
  package. Set it to the digest `caseworkctl
  package` reported for the reviewed package. The field is optional; a runtime
  configuration without it starts as before.
- Add `caseworkctl attempt mark-uncertain` for a pending source attempt the
  actor who started it can no longer recover. Only that actor may call the
  recover route, so such an attempt used to stay pending and hold its work item
  in synchronizing with no way to settle it. The command connects with the
  migration database credential, previews by default, and refuses an attempt
  whose execution lease is still live or that is not pending. Apply moves the
  attempt to uncertain, fences the original executor with a fresh execution
  token, and records an `attempt_uncertain` history event naming the operator's
  `decidedBy`, `operatorReason`, and the attempt's `originalActor` and
  `originalProfileId`. Settle the attempt afterwards with `caseworkctl attempt
  settle`. Its JSON report kind is `AttemptUncertainMarkingReport`.
- BREAKING: fix credential rotation and transport tuning superseding
  in-flight human work. The BReg source binding generation hashed the base
  URL, reader profile, token authority, client credentials, trust reference,
  timeouts, and presentation settings, so changing any of them re-keyed every
  source-backed work item. The generation now covers only the source id, the
  binding's `eventSource`, and the imported source description digest.
  Upgrading from v0.33.0 or earlier supersedes open work items from BReg
  sources once, because their stored generation differs from the new formula;
  claims, drafts, and pending attempts on them do not carry over. Finish or
  settle source-backed work before upgrading.
- Fix inbox reference lookup missing a work item after the binding's
  `displayReference` changed. Changing it keeps the binding generation, so the
  item kept the reference stored when it was first observed and a lookup by
  the reference the source now discloses did not find it. Reconciliation now
  refreshes the stored reference of open work items even when the source
  revision is unchanged, without changing the item revision or history.
- Fix `casework migrate` silently dropping hosted work. Migration 15, which
  replaces the hosted work tables with unified reviews, dropped them even
  when they still held in-flight items or retained accountability records.
  `migrate` now refuses before applying anything, names each hosted table
  that holds rows with its row count, and writes nothing. Keep that database
  with the release that wrote it until its work is exported, then migrate a
  fresh Casework database. Empty hosted tables are still replaced.
- Fix reconciliation failing on every pass after a package or source binding
  was rolled back to a value the deployment had already used (A, then B, then
  A). The returned-to binding derives the occurrence key of the item it left
  behind, and that superseded item still held the key's uniqueness, so every
  pass stopped on a duplicate key. Migration
  `0016_occurrence_identity_excludes_superseded.sql` limits the occurrence
  identity index to items that are not superseded: the superseded item stays
  terminal and readable, and the observation opens a fresh item beside it. Two
  live items for one occurrence are still refused. A failed database operation
  now names the constraint it violated, and nothing from the row.
- Fix an older `casework` binary against a database a newer release migrated.
  `casework migrate` used to report success without changing anything, and
  `casework serve` refused to start with a corruption error. Both now refuse
  with `the Casework database schema version N is newer than this binary
  supports (M); run a casework release that supports it`, and `migrate` writes
  nothing.
- Fix `caseworkctl db migrate` reducing a migration refusal to `A Casework
  runtime dependency check failed.` The schema-newer-than-binary refusal and
  the refusal to drop retained hosted work now reach the operator with the
  message `casework migrate` prints, under the code
  `casework.migration.refused`, the path `database`, and exit status 1. A
  database that cannot be reached is still reported as an operational failure
  with exit status 3.
- `caseworkctl attempt settle` now names the recovery step when it refuses a
  pending attempt: once the execution lease expires, the actor who started the
  attempt calls `POST /v1/work-items/{itemId}/attempts/{attemptId}/recover`
  while the source is reachable, and the attempt is settled only if recovery
  leaves it uncertain. Who may recover or settle is unchanged.
- Pair several request entities of one BReg register with one Casework
  source. A source declares up to 32 request entities; `caseworkctl source add`
  pairs them in one pass, the imported description lists them under
  `casework-source-description/v1alpha2`, and discovery pages through each
  entity in declaration order. A source with one entity keeps its `v1alpha1`
  description and its binding generation, so existing bindings do not change.
- Fix the professional-review starter hiding every source-backed review task.
  Its `scope-correction` `displaySchema` described `record` as an object, but
  the professional-licences source discloses it as a UUID string, so every
  preflight failed and the inbox dropped the task. The schema now restates each
  projected field's schema as `bregctl explain change-requests` reports it. The
  kind also gains a `changes-requested` outcome, so a reviewer can send a
  request back for its submitter to revise and resubmit. The starter and the
  example project change together.
- Log a warning when a source-context review is refused for a configuration
  defect: the source's disclosure fails the kind's `displaySchema`
  (`display_schema_rejected`, with the validation reason and path) or the
  source no longer returns the pinned binding (`binding_mismatch`). The
  entry names the review kind and carries no subject data. The reviewer's
  response is unchanged, so the inbox still leaves the task out silently.
- `caseworkctl doctor` now checks the secret each review completion
  destination names (`bearerTokenRef` or `auth.secretRef`) alongside the
  database, audit, and source secrets, so an unreadable destination secret is
  reported before the runtime first tries to deliver a completion.
- Name the two initiator refusals. A person a stage excludes as the request's
  initiator is refused at claim and decision with
  `403 review.initiator-excluded` instead of `operation.not-authorized`, and
  a request for an `excludeInitiator` kind that names no initiator is refused
  with `422 review.initiator-required` instead of `request.invalid`. Assigning
  or delegating to the initiator still answers `operation.not-authorized`, so
  a supervisor learns nothing about who submitted the request.
- Admit a request from a producer without `trustedInitiatorIssuer` when it
  names an initiator, without recording that initiator. Such a producer only
  submits kinds that exclude nobody, and it was refused with
  `request.invalid`, which broke every human-submitted BReg request to it.
- Let a review completion destination present its secret in a named header.
  `reviewCompletionDestinations.<id>.auth: {header, secretRef}` sends the raw
  secret in that header with no `Authorization` header; without `header`, or
  with the existing `bearerTokenRef`, the secret is sent as
  `Authorization: Bearer` as before. Reserved header names are refused when the
  runtime configuration loads.
- Add `decidedByCaller` to `GET /v1/review-tasks/{taskId}` for a decided task.
  It is true only when the current caller recorded the decision, so a reviewer
  whose decide response was lost can confirm the outcome. It names no other
  reviewer.
- Fix initiator exclusion for BReg-sourced reviews. BReg now names a review's
  initiator by the value of its configured principal claim rather than `sub`,
  so a stage with `excludeInitiator` refuses the submitter when the Casework
  profiles read that same claim. The professional-review starter and example
  now exclude the submitter from the review stage and set
  `trustedInitiatorIssuer` on the BReg producer. The paired
  professional-licences BReg starter's `editor` client is now a human teaching
  client, because BReg names an initiator only for a human caller and Casework
  refuses a request for an `excludeInitiator` kind that names none.
- Add an optional `initiatorProfile` on a review producer. The person a request
  names as its initiator reads that request's requester-visible history through
  `GET /v1/review-requests/{requestId}/history`, and nothing else. The initiator
  profile authenticates a person as strictly as a reviewer profile: it refuses
  delegated (`act`), grant-bearing, and non-human tokens. Retention now
  keeps the initiator identity as a request-bound sha256 tombstone instead of clearing
  it, so the initiator receives the same `410` as the producer after expiry.
  A request erased by an earlier release kept no initiator identity, so its
  initiator receives `404`.

## v0.33.0 - 2026-09-22

- BREAKING: replace hosted decisions with unified reviews. Remove `hosted.rs`
  and its routes: `POST /v1/hosted-items` and the paired
  `GET /v1/hosted-items/terminal`, `GET /v1/hosted-items/{itemId}`,
  `GET`/`POST /v1/hosted-items/{itemId}/notes`,
  `POST /v1/hosted-items/{itemId}/cancel`,
  `GET /v1/hosted-accountability/{eventId}`,
  `POST /v1/work-items/{itemId}/hosted-decisions`, and
  `GET /v1/work-items/{itemId}/hosted-history`. Add `review.rs` and its routes:
  `POST /v1/review-requests`, `GET /v1/review-kinds` and
  `/v1/review-kinds/{kindId}`, `GET /v1/review-results`,
  `GET /v1/review-tasks` and `/v1/review-tasks/{taskId}` with `context`,
  `claim`, `assign`, `delegate`, `release`, `draft`, and `decisions`,
  `GET /v1/review-requests/{requestId}` with `result`, `cancel`, `history`,
  `clocks`, and `notes`, and `GET /v1/review-accountability/{eventId}`.
  Casework now owns approval for BReg change requests through the
  source-neutral producer contract (`registry-review-protocol`,
  `registry-review-client`) instead of BReg holding review state itself. A
  single `0015_unified_reviews.sql` migration creates the review schema and
  drops the experimental `casework_hosted_*` tables; no hosted data is carried
  over.
- Review decisions can carry a structured result. A review kind declares an optional closed
  `resultSchema` beside its display schema, and an outcome may set `resultRequired`. A Requester may
  narrow declared top-level fields per request with `resultConstraints` at create time; the constraints
  are stored verbatim, count in the create idempotency hash, and are refused unless every value they
  admit is already inside the kind schema. The deciding person submits a `result` with the outcome,
  which Casework validates against the schema and then the constraints, and the Requester reads it
  back on the terminal request. Results and their constraints erase with the display payload at
  `terminalDays`; the accountability record keeps only a sha256 digest of the result until its own
  `accountabilityDays` closes.
- Allow governed Casework task templates to approve exact Scheduling service,
  location, and commitment-action bounds. The existing generic ThunderID
  exchange carries them to Scheduling without a product crate dependency.
- The inbox, the next-item result, holdings, the item view, history, and clocks
  stay readable while a subject's source binding has moved within its source
  generation but reconciliation has not applied it yet. The retained occurrence
  is returned without actions. One such item no longer refuses the caller's
  inbox, next item, or holdings. Operations that act on the item or its tasks,
  including claims, drafts, decisions, assignment, and caseload moves, still
  refuse with `work-item.proposal-changed`, and a caseload move preview that
  reads such an item still refuses as a whole.
- The BReg source adapter logs the cause of a source reader failure, such as
  the refusal status and problem code or the token request failure, when it
  first appears or changes, and logs when a reader request next succeeds. A
  missing record is not logged. Caller-facing problem codes are unchanged.

## v0.32.0 - 2026-09-15

- Pair each Casework client with the assertion issuers it may present through
  `assertionIssuers`. A token exchanged through any other assertion authority
  is refused; without the setting no pairing rule applies.
- The Rust Casework client adds `CaseworkTaskAssertionSource` for
  task-grant-bound token exchange. The Node.js client exposes
  `taskAssertionEndpoint()` and the Python client `task_assertion_endpoint()`.
- Borrowed local development sessions admit only the clients they declare.
  `caseworkctl` no longer admits every client of a shared issuer when a session
  declares none.

## v0.31.0 - 2026-09-13

- Add institutional task grants. An officer approves a governed task template,
  and an agent exchanges a short-lived Casework assertion for access bounded to
  the approved client, resource, purpose, subjects, permissions, and deadline.
- Sign explicit requester context for Evidence reads and retain the approved
  source and deadline across restart and token re-exchange. Evidence and BReg
  continue to enforce their own local policy and current grant status.
- Expose task approval, exchange, status, and Evidence context through the
  maintained Rust, Node.js, and Python clients and local development commands.
- Add a source-backed development journey that reviews BReg changes through
  Casework, and preflight every configured source credential before starting a
  multi-source local project.
- BREAKING: remove `taskAuthority.id` and the
  `registry_grant_authority` claim. Task-grant source identity now comes from
  the verified assertion issuer. Reset local development databases containing
  pre-v0.31.0 task grants or drafts, then rebuild source configuration and
  generated clients.

## v0.30.0 - 2026-09-12

- Document the secret reference grammar, the owner-only file rules, and the
  requirement that every resolved secret value be non-empty NUL-free text of at
  most 64 KiB, with a command that generates the audit journal secret.
- Document the static `authentication.oidc.jwksSource` alternative to issuer
  discovery, when to prefer it, and that it performs no rotation of its own.
- Name `GET /v1/work-items/{itemId}/hosted-history` as the staff hosted
  lifecycle history read, and say that `GET /v1/work-items/{itemId}/history` is
  the source-scoped variant that requires a `Registry-Source-Profile` header.
- Name the failing secret reference and the rule it broke when the database
  connection, the audit journal, or a static OIDC JWKS document cannot resolve
  its secret at startup, and name the source whose binding was refused. The
  refusal never carries the resolved secret value.
- Version the runtime configuration as `casework-runtime/v1alpha1`, select the
  fixed `casework.yaml` through an absolute `package.root`, move listener fields
  under `listener` with port 8100, require explicit secret providers, adopt
  `audit.hashKeyRef`, and generate its JSON Schema from the owning Rust types.
- Remove the unused runtime OIDC `principalClaim` and direct operators to the
  enforced `accessProfiles[].principalClaim`; add field paths for invalid
  routing, queue, clock, and hosted-kind references.
- Add an explicit source-owned display reference for exact, case-sensitive
  inbox lookup, current-caller disclosure rechecks, and `due`, `age`, or `type`
  inbox ordering with cursor context bound to the selected lookup and sort.
- Return `/v1/work-items/next` as a bounded `WorkItemPage`, including empty
  successful pages and a continuation when caller-visible scanning exhausts
  its per-request budget.
- Persist source-reconciliation progress across bounded passes and apply the
  configured concurrency limit to caller-scoped source reads while preserving
  deterministic response order.
- Add directory-scoped absence cover, explicit assignment and delegation for
  hosted or source-backed work, and bounded review-then-apply caseload moves
  with per-item visibility, eligibility, attempt, and revision results. Add
  Administrator-managed team membership and served-queue replacement with
  immediate authority changes and bounded ineligible-holding release.
- Add bounded, source-validated routing projections and ordered queue rules,
  plus named subject and working-day activity clock policies with revisioned
  external holiday-set inputs, immutable Administrator-published holiday
  revisions, bounded occurrence reads, and reviewed atomic deadline
  recomputation.
- Add source-free hosted decisions with declared bounded display schemas and
  outcomes, Requester-owned create/read/notes/cancel/terminal polling, human
  decisions under a configured profile, pinned kind policy, opaque actor references,
  audited Supervisor accountability resolution, separate terminal and
  accountability retention, payload-free idempotency tombstones for
  expired-response recovery, and the `standalone-decision` starter.
- Add the first checkpoint runtime and `caseworkctl` authoring and local operator
  commands, with separate PostgreSQL storage for team membership, work items,
  private drafts, attempts, history and durable events.
- Connect one governed BReg request source through the maintained client.
  Signed event hints and periodic readback discover current work and repair
  missed events. Decisions retain the acting human's token and source profile.
- Add caller-visible inbox views, claim and release, officer-private drafts,
  correction requests, approval and separate application, supervisor holdings,
  per-item accountability and a passive elapsed queue target.
- Preserve original attempts through uncertain source responses and expose
  distinct refusal and recovery codes to the maintained Rust and Node clients.
- Add `caseworkctl attempt settle`, a preview-by-default operator command that
  settles an uncertain source attempt whose execution lease has expired as
  applied or not applied, and records the outcome, reason, and decider as an
  `attempt_settled` history event in the same transaction as the state change.
- Require an explicit trusted-issuer human identity assertion in addition to
  token verification, selected profile scopes and current directory membership.
- Publish per-operation OpenAPI responses from the maintained Rust problem
  contract, including bounded framework rejections, request tracing, recovery
  headers, and current DTO shapes.
- Require an explicit local-development or upstream-TLS mode, reject public
  listeners, and document the private server-to-server, no-CORS boundary.
- Add a reproducible combined demo with Registry App Kit and the existing-kit
  comparison.

This checkpoint does not include bulk decisions, consultation, automatic
outcomes, or outbound delivery. Clock policies compute due reminder and
escalation occurrences. When one falls due, the runtime confirms the item with a
fresh source read, then records the reminder in the item's history or, for a
due step, releases the holder and moves the item to the queue the step names,
under the `system:clock` actor. A clock decides no outcome, changes nothing at
the source, and sends nothing outward; an Administrator applies a reviewed
recompute after a policy change.

The unified Registry Stack Node.js and Python client packages include Casework
in this release. The demo builds a matching local candidate from the selected
source trees.
