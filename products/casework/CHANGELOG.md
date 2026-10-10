# Registry Casework changelog

## Unreleased

- A task template accepts `authorizationMode`. `immediate`, the default,
  keeps `lifetimeSeconds` at 900 or less; `deferred` allows up to 604800
  (seven days). A preview and a grant view carry `authorizationMode` when it
  is `deferred`. The project schema and the OpenAPI document state the
  member, and the Rust, Node.js, and Python clients export
  `TaskAuthorizationMode`. No project that omits the member changes meaning.
- Schema revision 26 (`0026_review_assignment_generation.sql`) adds the
  authorization-window constraints on `casework_task_grants` and
  `casework_review_task_grants`, and the column
  `casework_review_tasks.assignment_generation` with its trigger
  `casework_review_assignment_generation`.
- The Rust client adds `CaseworkTaskAssertionSource`, a task-assertion
  credential source for a product client: a 4xx answer from the exchange is
  an invalid credential with fixed text, and a 408, a 429, a 5xx, or a
  transport failure is transient.
- `caseworkctl dev` names five refusals of a local session's configuration
  and exits 1 for them, where it reported `caseworkctl.operational-failure`
  and exited 3: `caseworkctl.dev.integrations-invalid`,
  `caseworkctl.dev.shared-client-mismatch`,
  `caseworkctl.dev.shared-task-authority-mismatch`,
  `caseworkctl.dev.source-binding-invalid`, and
  `caseworkctl.dev.borrowed-principal-invalid`. Each names the file and
  member to fix and repeats no private cause. A script matching the earlier
  code or exit status for these failures sees the new ones.
- BREAKING: `caseworkctl simulate` takes its file as `--simulation FILE`
  (was `--fixture FILE`): the command reads a `CaseworkSimulation`, and a
  fixture is the other file kind `caseworkctl test` runs. There is no alias,
  so `--fixture` is a usage error. Migration: replace `--fixture` with
  `--simulation` in every script that runs `caseworkctl simulate`.
- BREAKING: the Node.js and Python clients write five error words in
  kebab-case (CFG-NAME-2): kind `invalid-request` (was `invalid_request`);
  the protocol failures `header-bounds`, `trace-context`, and `media-type`
  (were `header_bounds`, `trace_context`, `media_type`); and the transport
  kind `response-too-large` (was `response_too_large`). Migration: change
  what a consumer of a client error compares. No file an adopter writes
  changes.
- BREAKING: the lifecycle hook `caseworkctl source add` writes into a Base
  Registry Engine project tags its handler by `type`:
  `handler: {type: url, destinationId: casework}` (was `kind: url`), because
  the Base Registry Engine of this release refuses `kind` there by name. In a
  project an earlier release paired, rename `kind` to `type` in the handler
  of each `casework-lifecycle-v1-<entity>` hook, or repeat `caseworkctl
  source add --apply`, then build the registry package again.
- BREAKING: the source action that sends a subject back for correction is
  named `request-correction` where it was `request_correction`
  (CFG-NAME-2). It is the one action name Casework gives a meaning of its
  own: when it completes, the officer's reason and flagged fields are
  retained as the correction context of the work item. The name appears as
  `actions[].operation` of a work item, the `operation` of a decision and
  of its attempt, and `detail.operation` of an item history entry. There is
  no alias: `request_correction` is still a valid action name and is
  executed as an ordinary action that retains no correction context. The
  Base Registry Engine adapter does not offer the action, so a deployment
  that uses no other adapter is unaffected; another adapter names it with
  `OperationName::REQUEST_CORRECTION`. No schema migration rewrites a stored
  action name: v0.40.0 does not upgrade v0.39.0 state in place; apply to a
  new database. Audit records are not rewritten. Migration: update the
  adapter and its callers. See
  `release/notes/config-conventions/casework.md`.
- The name of a source action follows the local identifier grammar
  (CFG-ID-1): a lowercase letter, then at most 63 lowercase letters,
  digits, underscores, or hyphens. A hyphen is the one character newly
  admitted, so a source adapter may offer a kebab-case operation and a
  caller may send one as the `operation` of a decision. Every name that was
  accepted is still accepted, and a name outside the grammar is still
  refused as `request.unprocessable`. The `OperationName` pattern in the
  OpenAPI document is `^[a-z][a-z0-9_-]{0,63}$`.
- BREAKING: a registry operation a task template lists under
  `bounds.permissions[].operations` is a local identifier (CFG-ID-1): a
  lowercase letter, then at most 63 lowercase letters, digits, underscores,
  or hyphens, where it was any run of lowercase letters and underscores. A
  kebab-case operation such as `apply-request` is accepted, and so is every
  snake_case name that starts with a letter. A name that starts with an
  underscore or is longer than 64 characters, which was accepted, is refused
  as `casework.task-template.invalid-operation` at its own pointer, as every
  other value outside the grammar still is. Casework copies the listed
  operations into the task assertion unchanged; the registry still decides
  what each one permits. Migration: none for a template whose operations
  start with a letter and fit in 64 characters; otherwise write the name the
  registry declares. See `release/notes/config-conventions/casework.md`.
- BREAKING: the clock, staffing, inbox, paging, and caseload words are
  kebab-case (CFG-NAME-2). The `state` of a clock occurrence is
  `verification-pending` or `source-facts-missing` where it was
  `verification_pending` or `source_facts_missing`;
  `assignment.staffingDiagnostic` is `no-cover-available`; the
  `assignmentKind` of a review assignment entry is `absence-cover`; the
  `status` of a page is `budget-exhausted` or `source-unavailable`; the
  `result` of an item of a caseload move is `not-visible`, `not-eligible`,
  or `attempt-in-progress`; the `view` of `GET /v1/work-items` is
  `my-teams`, `team-holdings`, or `completed-by-me`; and the `purpose` of
  `GET /v1/directory/targets` is `absence-person` or `absence-cover`. A
  request naming a view or a purpose in the old spelling is refused. The
  OpenAPI document, the Rust client, and the Node.js and Python
  declarations carry the new values. Migration
  `0025_clock_staffing_inbox_spelling.sql` rewrites the stored clock
  occurrence states, staffing diagnostics, and review task assignment
  kinds, replaces the `CHECK` constraints and the two partial indexes that
  name them, and rewrites the same words inside stored review history
  details, retained work item idempotency responses, and stored inbox
  cursors; no row is removed, no request hash changes, and a reason a
  caller wrote is never touched. A directory target cursor issued before
  the upgrade for `absence_person` or `absence_cover` is refused after it:
  start that listing again. Migration: run `caseworkctl plan` then
  `caseworkctl apply` with the previous release's runtime stopped, and
  update a caller that sends or compares one of these values. See
  `release/notes/config-conventions/casework.md`, "Protocol words".
- BREAKING: the history, event, and audit words are kebab-case (CFG-NAME-2).
  The `kind` of a work item history entry (`caseload-moved`, `draft-saved`,
  `task-approved`, `task-revoked`, `task-invalidated`, `attempt-reserved`,
  `attempt-uncertain`, `action-completed`, `attempt-settled`,
  `clock-reminder`, `clock-step-applied`, `clock-recomputed`), the `kind` of
  a review history entry (`request-created`, `review-created`,
  `review-decided`, `review-settled`, `review-cancelled`,
  `review-superseded`, `stage-advanced`, `task-assigned`, `task-claimed`,
  `task-delegated`, `task-released`, `task-draft-saved`,
  `task-absence-reconciled`, `task-grant-approved`, `task-grant-revoked`,
  `task-grant-invalidated`), the directory event kinds
  (`directory-bootstrapped`, `team-updated`, `absence-created`,
  `absence-updated`, `absence-deleted`), and every audit event name built
  from one of them (`casework.review-decided`) were spelled with
  underscores, as were the audit events `casework.holiday-revision-created`,
  `casework.review-accountability-read`, `casework.review-note-added`,
  `casework.source-retention-erased`, and `casework.package-activated`. The
  `outcome` of a settled attempt is `not-applied` in its history entry and
  in the `caseworkctl attempt settle` report, and a release Casework records
  during reconciliation gives its `reason` as `source-observation` or
  `directory-membership-changed`. The OpenAPI document, the Rust client, and
  the Node.js and Python declarations carry the new values. Migration
  `0024_history_event_spelling.sql` rewrites the stored history, durable
  event, and directory event kinds, the two values above inside stored
  details, and the retained idempotency operation `item.caseload-moved`,
  and replaces the task invalidation function and its partial index; no row
  is removed, no request hash changes, and a reason a caller wrote is never
  touched. Audit records already written keep their spelling. Migration:
  run `caseworkctl plan` then `caseworkctl apply` with the previous
  release's runtime stopped, and update a caller that compares a history
  `kind` or selects audit records by event name. See
  `release/notes/config-conventions/casework.md`, "Protocol words".
- BREAKING: the validation reason of a refused review submission is
  kebab-case (CFG-NAME-2). The `Registry-Casework-Validation-Reason`
  response header, the `validation.reason` member the Rust, Node.js, and
  Python clients expose, and the reason `registry-review-client` reads carry
  `schema-mismatch` where they carried `schema_mismatch`, and the other
  thirteen reasons the same way. A client of the previous release does not
  know the new words and reports a refused submission as a protocol failure,
  so upgrade the client with the runtime. Nothing stored holds a reason, so
  nothing is migrated. See
  `release/notes/config-conventions/casework.md`, "Protocol words".
- BREAKING: the words `caseworkctl` prints in its JSON reports are
  kebab-case (CFG-NAME-2). `caseworkctl lifecycle` respells nine event ids
  (`attempt_reserved` is `attempt-reserved`, `observe_waiting_applicant` is
  `observe-waiting-applicant`, `record_decision` is `record-decision`,
  `advance_stage` is `advance-stage`, and the other five the same way) and
  the review state id `changes-requested`, in the transition table and in
  every layer's `events` list. `caseworkctl check` reports `queueMode` as
  `first-match` and `sourceDescription` as `pending-source-add`;
  `caseworkctl source add` reports a planned change's `operation` as
  `ensure-exact`; and a diagnostic about something that is not a document
  names its `artifact` as `runtime-dependency`, `runtime-configuration`,
  `authoring-input`, `operator-action`, `command-arguments`, or
  `dev-session`. No file, HTTP response, or stored row carries one of these
  words, so nothing is migrated: update a script that compares one. See
  `release/notes/config-conventions/casework.md`, "Protocol words".
- BREAKING: the review protocol words are kebab-case (CFG-NAME-2), in every
  place Casework writes one. `changes_requested` is `changes-requested` as
  the `lifecycle` of a review request, the `status` of a review result, and
  the `type` of a reviewer's decision; `already_terminal` is
  `already-terminal` as the `outcome` of a cancel response;
  `binding_changed` is `binding-changed` as the `bindingStatus` of a review
  task context; and the `transition` in the `detail` of a `review-decided`
  history entry is `changes-requested` or `stage-advanced`. A request that
  sends the decision type in the old spelling is refused as
  `request.unprocessable`: there is no alias. The OpenAPI document, the Rust
  clients, and the Node.js and Python declarations carry the new values.
  Migration `0023_review_outcome_spelling.sql` rewrites the stored request
  lifecycles, decisions, results, accountability records, history details,
  and retained replay responses, and replaces the five `CHECK` constraints
  that named the old value; no row is removed and no request hash changes.
  A `changes-requested` decision retried after the upgrade under the
  idempotency key of a decision sent before it is therefore refused as
  `idempotency.key-reused` and commits no second decision: the first
  decision stands.
  Audit records already written keep their spelling. Migration: run
  `caseworkctl plan` then `caseworkctl apply` with the previous release's
  runtime stopped, and update a caller that compares one of these values.
  See `release/notes/config-conventions/casework.md`, "Protocol words".
- BREAKING: `caseworkctl lifecycle` spells the `id` of every enforcement
  layer in lowercase kebab-case, as `bregctl explain lifecycle` spells its
  own: every underscore became a hyphen, so `caller_authentication` is
  `caller-authentication` and `lifecycle_transition` is
  `lifecycle-transition`. All 21 ids changed, 11 on the `occurrence`
  lifecycle and 11 on `review-request`, which share
  `caller-authentication`; the release note lists each one. The ids are
  printed by this command alone: no authored file, HTTP response, or stored
  row carries one. The event ids under `events` and the review state id
  `changes-requested` are respelled by the report words entry above.
- BREAKING: `caseworkctl check` and `caseworkctl init` no longer print every
  member of their report in the human format. A clean `check` prints its
  outcome line, `project:`, `runtime config:` when a runtime file was given,
  `profile:`, each warning, and the summary line `N errors, M warnings in K
  files`; the `status:`, `effective:`, `networkAccess:`, and
  `databaseAccess:` lines are gone. `init` prints `created:` with the
  project directory, one indented line for each entry it wrote, and a
  `next:` line; the `init succeeded.` line and the `template:`, `project:`,
  `created:` list, and `next:` list lines are gone. `--format json` is
  unchanged and carries every member. A script that read one of the removed
  lines reads the same member from `--format json`.
- `caseworkctl check` and `caseworkctl test` tell a file under `fixtures/`,
  `simulations/`, or `simulations/holiday-sets/` that lacks its envelope the
  header its directory holds: the suggested action of
  `config.missing-envelope` reads, for a simulation, "Start the file with
  `apiVersion: id.registrystack.org/formats/casework/simulation/v1alpha1` and
  `kind: CaseworkSimulation`." It named the three kinds and no `apiVersion`.
  The code, the pointer, and the exit status are unchanged.
- BREAKING: the source description `caseworkctl source add` writes under
  `sources/` carries `apiVersion:
  id.registrystack.org/formats/casework/breg-source-description/v1alpha1` and
  `kind: CaseworkBregSourceDescription` (CFG-ENV-2, CFG-ENV-3), and lists
  every paired entity in `requests`, one entry for a source with one entity.
  It carried `registry.registrystack.org/casework-source-description/v1alpha1`
  with a single `request` member, or `.../v1alpha2` with `requests`, under
  `kind: BRegCaseworkSourceDescription`. A description under either earlier
  `apiVersion` is refused: `caseworkctl check` and `caseworkctl package`
  report `config.retired-api-version` at the source's `description`, and the
  runtime refuses a package that carries one as
  `casework.package.source-description-mismatch`. No reader accepts the
  earlier shape. Import each source again: move `sources/SOURCE_ID.json`
  aside, run `caseworkctl source add BREG_PROJECT --project DIR --source-id
  SOURCE_ID --apply`, then `caseworkctl package`, `caseworkctl plan`, and
  `caseworkctl apply`. The description's digest is part of the source binding
  generation, so plan reports the source's generation as changed and apply
  rebinds its stored state; plan refuses while a source attempt is pending or
  uncertain under the previous generation. No HTTP response member changes.
  A related pointer into a one-entity description now reads `/requests/0/...`
  where it read `/request/...`.
- BREAKING: `accessProfiles[].id`, `queues[].id`, `reviewProducers[].id`, and
  `taskTemplates[].id` in `casework.yaml` are local identifiers (CFG-ID-1,
  `^[a-z][a-z0-9_-]{0,63}$`). An access profile id and a review producer id
  accepted letters, digits, `-`, `_`, `.`, and `:` up to 128 bytes; a queue
  id and a task template id accepted letters, digits, `-`, `_`, and `.` up to
  128 bytes. An id outside the grammar is refused by the reader as
  `config.invalid-value` at the id's own pointer. The HTTP bounds on the
  `Registry-Casework-Profile` header and on a queue id in a directory request
  are unchanged; a name outside the grammar now selects nothing. Stored rows
  keep the id they were written under and no migration respells them.
  Migration: an id inside the grammar needs no change. To rename one, let the
  work stored under it finish, rename it and every reference to it, then
  package, plan, and apply; `caseworkctl plan` refuses a package that would
  strand in-flight work under a queue, an access profile, or a review
  producer it no longer declares. See
  `release/notes/config-conventions/casework.md`.
- BREAKING: activation refuses a policy package that no longer declares the
  review producer of an in-flight review. A review request keeps the id of
  the producer that submitted it, and that producer reads, cancels, and
  receives the result of it only under that id, so a package that removed or
  renamed the producer left those reviews with no caller. `caseworkctl plan`
  and `caseworkctl apply` refuse it as `casework.activation.stranded-work`
  at `runtime.yaml:/package/acknowledgeStrandedWork`, naming the producer id
  and the number of in-flight reviews, never a subject; the runtime repeats
  the refusal before it listens and `caseworkctl doctor` reports it under its
  `pinnedWork` check. A review is in flight while it is under review; one
  that reached a result or was cancelled or superseded is not counted. The
  closed `reason` of a conflict in the `PlanReport`, `ApplyReport`, and
  `DoctorReport` contracts gains `producer-removed`, with the `producer` and
  `reviews` members. Migration: let the reviews the producer submitted reach
  a result under the earlier package before removing or renaming it, or set
  `package.acknowledgeStrandedWork` to the digest the refusal names.
- BREAKING: the settlement of a review outcome that asks for changes is
  `changes-requested` (CFG-NAME-2), where it was `changes_requested`. The
  old value under `reviewKinds[].outcomes[].settlement` in `casework.yaml` is
  refused as `config.unknown-variant`. The same spelling is the digest input
  of the review kind's policy and is returned in `outcomes[].settlement` by
  `GET /v1/review-kinds`, `GET /v1/review-kinds/{kind_id}`, and the
  `policySnapshot` of `GET /v1/review-tasks/{task_id}/context`; the client
  types follow. The policy digest of a review kind that declares such an
  outcome changes. A stored policy snapshot in the old spelling is not
  read: v0.40.0 does not upgrade v0.39.0 state in place; apply to a new
  database. The request lifecycle, the result status, and the
  decision type are respelled by the review protocol words entry above.
  Migration: respell the
  value in `casework.yaml` without changing the review kind's `version`,
  then package, plan, and apply. See
  `release/notes/config-conventions/casework.md`.
- BREAKING: the two waiting states of a work item are kebab-case
  (CFG-NAME-2): `waiting-applicant` (was `waiting_applicant`) and
  `waiting-application` (was `waiting_application`). An old value under
  `taskTemplates[].itemStates` in `casework.yaml` is refused as
  `config.unknown-variant`. The same spelling is stored and returned as the
  `state` of a work item in every response that carries one, printed as
  `itemState` by `caseworkctl attempt`, and listed by `caseworkctl
  lifecycle`; the client types follow. Schema migration 22 respells the
  stored work items, the stored task template documents, and the template in
  each task grant record, so a live grant stays valid; `caseworkctl apply`
  runs it. Migration: respell the two values in `casework.yaml` without
  changing a template's `version`, then package, plan, and apply. See
  `release/notes/config-conventions/casework.md`.
- BREAKING: a clock in `casework.yaml` is tagged by `type` (CFG-ID-7), where
  the member was `scope`, and its four values are kebab-case (CFG-NAME-2):
  `first-submitted-at` (was `firstSubmittedAt`), `review-completed` (was
  `reviewCompleted`), `awaiting-applicant` (was `awaitingApplicant`), and
  `stage-entered-at` (was `stageEnteredAt`). `scope` is refused as
  `config.removed-key` at `/clocks/N/scope`, naming `type`, and each old
  value as `config.unknown-variant`. The same spelling is stored, digested,
  and returned in the `clocks` member of `GET /v1/casework`; the client
  types follow. A stored clock in the old spelling is not read: v0.40.0
  does not upgrade v0.39.0 state in place; apply to a new database.
  Migration: rename `scope` to `type` and respell the four
  values in `casework.yaml`, then package, plan, and apply. See
  `release/notes/config-conventions/casework.md`.
- BREAKING: `authentication.oidc.allowedClients` in `runtime.yaml` is
  required (CFG-EMPTY-2) and takes `unrestricted` or a list of at least one
  client, none repeated (CFG-ID-6). On development loopback an omitted member
  or `[]` admitted every client; both are now refused when the file is read,
  as `config.missing-key` at `/authentication/oidc` and `config.invalid-value`
  at `/authentication/oidc/allowedClients`, and a repeated client is refused
  as `config.duplicate-item` at the repeated item.
  `casework.runtime.allowed-clients-required` now answers `unrestricted`
  outside development loopback or beside a `taskAuthority`. `caseworkctl
  init` and the maintained examples write `allowedClients: unrestricted`.
  Migration: list the clients that call the deployment, or write
  `allowedClients: unrestricted` on development loopback, and write a
  repeated client once. See `release/notes/config-conventions/casework.md`.
- BREAKING: `casework.yaml` names the project in a top-level `project`
  block (CFG-ENV-6), where the block was called `casework`, and `project.id`
  is a local identifier (CFG-ID-1), where it was any non-empty text. The old
  key is refused as `config.removed-key` at `/casework`, naming `project`.
  Migration: rename `casework` to `project`, rewrite `project.id` if it is
  not a lowercase letter followed by at most 63 lowercase letters, digits,
  underscores, or hyphens, then package, plan, and apply. See
  `release/notes/config-conventions/casework.md`.
- BREAKING: five `caseworkctl` reports respell values in kebab-case
  (CFG-NAME-2) and type their identifiers (CFG-ID-1). `plan` writes
  `databaseIdCheck: not-recorded` (was `notRecorded`); `lifecycle` names the
  review machine `review-request` (was `review_request`); `simulate` writes
  the source record identifier as `subject.recordId` (was `subject.id`);
  `source add` writes `activation: not-performed` (was `not_performed`);
  `test` writes `proofBoundary: offline-synthetic` (was `offline_synthetic`).
  `PlanReport.schema.json` has one refusal variant, which carries the plan
  when `status` is `refused` (CFG-ID-7); the report shape is unchanged.
  Migration: a script that reads one of these values or `.subject.id` reads
  the new spelling; no file an operator writes changes.
- BREAKING: `authentication.oidc.assertionIssuers` in the runtime file
  refuses a client written with an empty issuer list (CFG-EMPTY-2), as
  `config.invalid-value` at `/authentication/oidc/assertionIssuers/<client>`;
  the runtime schema declares `minItems: 1` on the list. Migration: remove
  the client from `assertionIssuers`, or list its issuers. A client that is
  not listed may exchange from no authority, which is what the empty list
  meant.
- BREAKING: `accessProfiles[].requiredScopes` in `casework.yaml` is a set
  (CFG-ID-6). A scope listed twice in one profile, which was accepted, is
  refused by the reader as `config.duplicate-item` at the second occurrence,
  and the project schema declares `uniqueItems`. Migration: delete the
  repeated scope.
- A repeated id in one of the eight named lists of `casework.yaml`
  (`accessProfiles`, `queues`, `sources`, `reviewKinds`, `reviewProducers`,
  `calendars`, `clocks`, `taskTemplates`) is refused by the reader as
  `config.duplicate-id` at the `id` of the second item (CFG-ID-5), before the
  semantic checks run. The product codes (`casework.queue.duplicate-id` and
  its seven siblings) no longer appear for a project read from a file.
  Migration: no file changes; a script that matches the product code must
  match `config.duplicate-id`.
- BREAKING: the identifiers `casework.yaml` declares are local identifiers
  (CFG-ID-1, `^[a-z][a-z0-9_-]{0,63}$`). The id of a calendar, a clock, a
  clock reminder, a clock step, a review kind, a review stage, a review
  outcome, and a routing rule, and a routing field name under
  `when.fields`, now also accept `_`. A source `id` and a request
  `target.id`, which accepted any non-empty string, are held to the same
  grammar, the one `runtime.yaml` holds a `sources` key to. A claim name
  under `taskTemplates[].subjects` is typed as an external identifier and
  keeps its bound of letters, digits, `-`, `_`, and `.` up to 128 bytes. A
  malformed id is refused by the reader as `config.invalid-value` at the
  id's own pointer. The published HTTP contract follows: the identifier
  pattern of the OpenAPI document accepts `_`. Migration: rewrite a source
  id or a target id that is not a local identifier, then package, plan, and
  apply; no other file changes. The step is in
  `release/notes/config-conventions/casework.md` under "Stable move".
- BREAKING: `casework.yaml` carries the format identifier as its
  `apiVersion` (CFG-ENV-2):
  `id.registrystack.org/formats/casework/project/v1alpha1`, where it was
  `registry.registrystack.org/casework/v1alpha1`. `kind` and every other
  member are unchanged. The old value is refused as
  `config.retired-api-version` at `/apiVersion`, and the diagnostic names
  the new one. Migration: write the new `apiVersion`, then run
  `caseworkctl package`, `caseworkctl plan`, and `caseworkctl apply`,
  because the header is part of the packaged policy. The step is in
  `release/notes/config-conventions/casework.md` under "Stable move".
- BREAKING: each `caseworkctl --format json` report names its own format
  (CFG-ENV-2, CFG-ENV-3). `apiVersion` is
  `id.registrystack.org/formats/casework/<report>/v1alpha3`, such as
  `.../casework/check-report/v1alpha3`, where every report carried
  `registry.registrystack.org/caseworkctl/v1alpha3`, and `kind` carries the
  product's name: `CheckReport` is `CaseworkCheckReport`, and so on for all
  21 reports. Every other member, the schema file names, and the schema
  `$id` values are unchanged. Migration: a script that selects a report by
  `kind` or checks `apiVersion` matches the new values; the table is in
  `release/notes/config-conventions/casework.md` under "Stable move".
- BREAKING: the keys of three id-keyed `runtime.yaml` maps are typed
  (CFG-ID-1, CFG-ID-2). A key under `sources` is a local identifier
  (`^[a-z][a-z0-9_-]{0,63}$`), the grammar `casework.yaml` already holds a
  source id to. A key under `reviewCompletionDestinations` or
  `taskAuthority.statusClients` is kept as written and is 1 to 512
  characters without control characters. A malformed key is refused as
  `config.invalid-value` at the key's own pointer. Migration: none for a
  file the runtime started with; rewrite an empty, over-long, or
  control-character key. The step is in
  `release/notes/config-conventions/casework.md` under "Stable move".
- BREAKING: four `runtime.yaml` keys take the names the conventions give a
  retention period, an attempt timeout, and a retry delay (CFG-NAME-5):
  `audit.retainDays` is `audit.retentionDays`,
  `sources.<id>.requestTimeoutMilliseconds` is
  `sources.<id>.attemptTimeoutMilliseconds`, and under
  `reviewCompletionDestinations.<id>`, `timeoutMilliseconds` is
  `attemptTimeoutMilliseconds` and `retrySeconds` is `retryDelaySeconds`.
  Values, units, defaults, and bounds are unchanged. Each old key is refused
  as `config.removed-key`, naming its replacement. Migration: rename the
  keys; the step is in `release/notes/config-conventions/casework.md` under
  "Stable move".
- BREAKING: `runtime.yaml` carries `apiVersion:
  id.registrystack.org/formats/casework/runtime/v1alpha1`, the format
  identifier every other Registry Stack file uses, where it carried
  `registry.registrystack.org/casework-runtime/v1alpha1`. The old value is
  refused as `config.retired-api-version` at `/apiVersion`, naming the new
  one; `kind: CaseworkRuntimeConfig` is unchanged. Migration: replace the
  `apiVersion` line; the step is in
  `release/notes/config-conventions/casework.md` under "Stable move".
- BREAKING: `authentication.oidc.jwksSource` in `runtime.yaml` is tagged by
  `type`, where it was tagged by `kind`: `jwksSource: {kind: static, ...}`
  becomes `jwksSource: {type: static, ...}`. The values `discovery`, `uri`,
  and `static` are unchanged. `kind` is refused as `config.removed-key` at
  `/authentication/oidc/jwksSource/kind`, naming `type`. Migration: rename the
  key and keep its value; the step is in
  `release/notes/config-conventions/casework.md` under "Stable move".
- `caseworkctl simulate --format json` carries `diagnostics`, the warnings the
  readers reported for `casework.yaml`, the simulation, and its holiday sets.
- `caseworkctl dev grant --format json` carries `diagnostics`, an empty list,
  like every other Casework report.
- BREAKING: `authentication.oidc.assertionIssuers: {}` is refused: delete the
  member to apply no assertion-issuer rule. The generated runtime schema types
  the client keys as `ExternalId` and requires at least one client.
- BREAKING: `caseworkctl` and the `casework` runtime read `casework.yaml`
  through the shared configuration reader. Every problem is reported at its
  line and column with its own code, `casework.project.invalid` is retired,
  and `null`, anchors, aliases, tags, and numbers or booleans written where
  text is expected are refused. Migration steps and the code table are in
  `release/notes/config-conventions/casework.md`.
- BREAKING: `casework.yaml` has a published JSON Schema, which
  `caseworkctl init` copies into the project and names in a modeline. The
  reader refuses an out-of-range number, a repeated item in a set, and an
  issuer that is not an `http` or `https` URL at its position, with
  `config.out-of-range`, `config.duplicate-item`, and `config.invalid-value`.
  Migration steps and the code table are in
  `release/notes/config-conventions/casework.md`.
- BREAKING: the `casework` runtime and `caseworkctl` refuse a `runtime.yaml`
  member written as `null`, `~`, or an empty value, where it read as absent;
  omit the key instead. A malformed secret reference, URL, or digest is
  refused by the reader at its position with `config.invalid-value`, and an
  out-of-range BReg binding timeout or reconciliation interval or audit
  rotation bound with `config.out-of-range`. `taskAuthority.issuer` must be an
  absolute `http` or `https` URL. Migration steps are in
  `release/notes/config-conventions/casework.md`.
- BREAKING: a refused `runtime.yaml` is reported in full: `casework serve`
  prints every problem in the file at its line and column after one
  sentence, and `caseworkctl plan`, `apply`, `status`, `doctor`, and `dev`
  report one positioned diagnostic per problem, each with its own code,
  where they reported `casework.runtime-configuration.invalid` for the first
  problem alone. A runtime file that cannot be read is
  `platform.runtime-config.unavailable`, where it was
  `caseworkctl.io-failure`. `caseworkctl check PROJECT --runtime-config FILE`
  checks a runtime file offline against the project, and `--environment`
  checks the values its `${NAME}` expressions take from the current
  environment. Migration steps and the code table are in
  `release/notes/config-conventions/casework.md`.
- BREAKING: `caseworkctl check` and `caseworkctl test` report a
  `diagnostics` list in the shared diagnostic shape, where they reported
  `findings`, and count the files they read in `filesChecked`. A missing
  imported source description is a `warning` at its line and column, with
  the JSON pointer `/sources/N/description`, and an `error` under
  `--production`. `--deny-warnings` replaces `--deny-findings`. Migration
  steps and the old-to-new table are in
  `release/notes/config-conventions/casework.md`.
- BREAKING: every refusal `caseworkctl check`, `explain`, `simulate`, and
  `package` make of a project against its imported source descriptions is
  its own diagnostic, placed at the line and column of `casework.yaml` it
  concerns, with its own `casework.<area>.<condition>` code, where each was
  the first problem alone under `caseworkctl.refused` at path `authoring`.
  The `--against-breg-package` refusals keep their codes and are placed at
  `/sources` or `/sources/N/description`; the stale pin no longer repeats
  either revision. Migration steps and the old-to-new table are in
  `release/notes/config-conventions/casework.md`.
- BREAKING: fixtures, simulations, and holiday sets are read through the
  shared configuration reader and have published JSON Schemas. A fixture
  declares `apiVersion: id.registrystack.org/formats/casework/fixture/v1alpha1`,
  names itself with `id`, writes its request as `request: {source, entity}`,
  and states its target as `target: {elapsedMinutes: N}` or `target: none`.
  A simulation declares `kind: CaseworkSimulation`, names its record
  `subject.recordId` and its rule `expect.rule` (or `rule: none`), writes
  `dueState: at-risk`, and omits a routing field the record does not carry,
  since `subject.fields` holds only a boolean, a number, or text; a holiday
  set declares `kind: CaseworkHolidaySet`. `caseworkctl check` reads every
  file under `fixtures/` and `simulations/` and refuses an undeclared
  reference or a review display its kind's display schema rejects,
  `caseworkctl test` also runs simulations, and each failure is its own
  positioned diagnostic.
  Migration steps and the code table are in
  `release/notes/config-conventions/casework.md`.
- BREAKING: a project declares at most 64 sources (`casework.source.too-many`
  at `/sources`), and `caseworkctl check` and `test` refuse a `fixtures/`,
  `simulations/`, or `simulations/holiday-sets/` directory holding more than
  1024 YAML files (`casework.project.too-many-files`), so `filesChecked`
  states its maximum. Migration steps are in
  `release/notes/config-conventions/casework.md`.
- BREAKING: `caseworkctl source add` reports its warnings in `diagnostics`,
  where it reported them in `findings`. Each is a `warning` placed at the
  JSON pointer of the BReg `registry.yaml` member it concerns, with that
  file's line and column under `source`; `artifact` is gone and the message
  names no value. `source add` reads `casework.yaml` through the project
  reader, so an invalid project is refused with positioned diagnostics.
  Migration steps are in `release/notes/config-conventions/casework.md`.
- BREAKING: `dev-clients.yaml` declares
  `apiVersion: id.registrystack.org/formats/casework/dev-clients/v1alpha1`
  and `kind: CaseworkDevClients` in place of `version: 1`, is read through
  the shared configuration reader, and has a published JSON Schema that
  `caseworkctl init` copies into the project and names in a modeline.
  `caseworkctl check` reads it beside `casework.yaml`, counts it in
  `filesChecked`, and reports each problem at its line
  and column with a `casework.dev-clients.*` code, where `caseworkctl dev`
  reported the first problem alone as one sentence. A `${...}` expression
  is refused, and `integrations.taskAuthority.jwksPort` must be 1 to 65535.
  Client and service client IDs and the keys of `integrations.sources`,
  `secretFiles`, and `taskAuthority.statusClients` are local identifiers (a
  leading digit is refused, `_` is accepted), claim names are external
  identifiers, a service client's claim values are text,
  `taskAuthority.issuer` is an absolute URL, and a source binding no longer
  takes its timeouts or reconciliation interval.
  Migration steps are in `release/notes/config-conventions/casework.md`.
- BREAKING: `.casework/dev/state.json`, the session state `caseworkctl dev`
  retains, declares
  `apiVersion: id.registrystack.org/formats/casework/dev-state/v1alpha1`
  and `kind: CaseworkDevState` in place of `version: 2`, and is read through
  the shared configuration reader. `caseworkctl dev` refuses a session an
  earlier `caseworkctl` started, without changing it. `caseworkctl check`
  reads the file when the project has one, counts it in `filesChecked` (now
  at most 3140), and reports a problem at its line and column, or with
  `casework.dev-state.invalid-ownership` for an owner, port, or container
  `caseworkctl` never writes. Migration: run `caseworkctl dev stop --remove`
  with the earlier `caseworkctl`, remove `.casework/dev`, and start again.
- BREAKING: the 21 `caseworkctl --format json` report schemas are published
  in the identifier catalog, `CheckReport` as
  `https://id.registrystack.org/schemas/casework/check-report/check-report.v1alpha3.schema.json`
  where it was `https://registrystack.org/caseworkctl/v1alpha3/CheckReport.schema.json`,
  and declare their `apiVersion` and `kind` beside their variants. The members
  they left open (attempt, retention, check, doctor, explain, package,
  simulation, source add, plan, and apply detail) are now typed and closed,
  and every count states its maximum. `ExplainReport` and `CheckReport` refer
  to the project schema for the policy they carry. The reports themselves are
  unchanged. Migration: load the schemas by their new identifiers, and give a
  validator the project schema beside those two; the table is in
  `release/notes/config-conventions/casework.md`.
- `registry-casework-client`, which never resent a mutation, now resends an
  idempotency-keyed mutation whose outcome is unknown (a timeout or broken
  exchange after the request was sent, or a 5xx answer) byte for byte under
  the same key, through the bounded loop the BReg, Messaging, and Scheduling
  clients share. It resends at most 2 times, only while the outcome is
  unknown, and never after any 4xx answer, waiting 250 ms then 500 ms, or a
  server `Retry-After` of at most 5 seconds; a longer one ends the retries.
  Opt out with `CaseworkClientConfig::with_max_mutation_retries(0)` (Node.js
  `maxMutationRetries`, Python `max_mutation_retries`; 0 to 2). Reads,
  unkeyed operations (task grant revocations, task assertions, decision
  recovery, and previews), and review request create and cancel are never
  resent. One keyed mutation can now take up to three request timeouts (30
  seconds each by default) plus the waits between attempts (#1913).
- `CaseworkClientError::is_outcome_unknown()` (Node.js `outcomeUnknown`,
  Python `outcome_unknown`) reports a failure after which the mutation may
  have taken effect, including an answer a binding cannot represent; recover
  it with the same request under the same key, never a new key.
  `CaseworkClientError::mutation_class()` now agrees with it: a connection
  that was never established, a connect timeout included, is
  `Deterministic`, where it was `Ambiguous`.
- The Node.js client reports a rejected constructor setting (an unsafe
  integer, an undefined member, or a value of the wrong type) as kind
  `configuration`, where it reported `invalid_request`. Code that branches on
  `kind` sees the change.

## v0.39.0 - 2026-10-06

- BREAKING: `caseworkctl dev` takes PostgreSQL loopback port 15433 on a first
  start, where it took 55433. On Linux an outgoing loopback connection could
  take 55433 as its own source port, and a first start then refused the port as
  occupied although nothing listened on it. A session that already started
  keeps the port it retained. Anything that connects to a new session's
  database by the old default needs the new port, or `--database-port 55433`
  (or `CASEWORKCTL_DEV_DATABASE_PORT`) on the first start.

- BREAKING: before 1.0, a release reads only the state its immediate
  predecessor wrote. This release reads state written by v0.38.0 and nothing
  older. If you run an older release, upgrade one release at a time and finish
  each release's upgrade steps before starting the next. The entries below
  remove what served only releases before v0.38.0.
  - `release/scripts/rehearse-upgrade.py` rehearses a Casework upgrade only
    from state v0.38.0 wrote. It no longer starts from a release without
    `caseworkctl plan` and `apply`, adopts a database that records no
    activation, repackages a package that carries no `SHA256SUMS`, or waits
    for the audit outbox table that v0.38.0 no longer has.
  - Building the Registry Casework release image fails when no `caseworkctl`
    is staged beside the runtime.
  - Recovery of a prepared BReg source action refuses saved attempt evidence
    that carries no `version`, before any source request, where it read such
    evidence as an earlier format. Every release has written `version` 1, so
    no retained attempt is affected.
  - `caseworkctl dev` refuses retained dev state from a Mint-era session as
    invalid retained state, without the Mint guidance, and leaves it
    untouched. Stop that session with the release that wrote it, or move
    `.casework/dev` aside, then start a fresh session.
  - Dev state that lacks `binaries`, `sources`, or `borrowedScopes` is refused
    as invalid. Start a fresh session.
  - `caseworkctl dev start --clients` is no longer accepted. Use
    `--clients-file`.
  - `caseworkctl source add` no longer refuses a BReg `registry.yaml` by name
    for carrying the bare `casework-lifecycle-v1` hook that releases before
    v0.34.0 wrote. v0.38.0 refused that hook, so no project it paired carries
    one. A project that still does keeps it as an authored hook beside the
    per-entity hook `source add` writes: `bregctl check` refuses it on a
    second entity, and Casework still refuses the events it emits. Remove it
    from `registry.yaml` by hand.

- Empty source-backed inbox views over a source reconciled within the larger
  of twice its `reconciliationIntervalMilliseconds` and 2 minutes return
  `complete` without requeueing subjects or clearing source completeness. A
  source reconciled less often than once a minute keeps that status for its
  whole window rather than for a fixed 2 minutes. Callers serving
  no queue receive `complete` regardless of discovery state. Pages waiting only
  for source discovery no longer issue a cursor that repeats the same position;
  retry those `budget_exhausted` pages without a cursor after reconciliation.
  The retried walk starts from the first position and can return items earlier
  pages already returned: deduplicate work items by `itemId`, and replace
  holdings totals instead of adding to them (#1838).

- `caseworkctl source add --casework-endpoint URL` sets the Casework endpoint
  of the local BReg review authority it writes, for a Casework session on a
  port other than the default 8092. Without the option the output is
  unchanged. The option accepts only an exact loopback HTTP URL and refuses
  anything else without repeating the value; an existing authority that
  differs only in its endpoint is refused with a message naming the option
  (#1435).

- `caseworkctl dev start` and `dev stop` name the cause of a local session
  failure instead of a generic filesystem or runtime dependency failure
  (`caseworkctl.io-failure` or `caseworkctl.operational-failure`), still
  exiting 3; scripts matching those codes for these failures see the
  `caseworkctl.dev.*` codes instead. The report names an occupied port
  (`caseworkctl.dev.port-occupied`), authored inputs that differ from a
  session retaining records (`caseworkctl.dev.inputs-changed`, with
  `caseworkctl dev stop --remove`), a retained `.casework/dev/audit` stream
  an earlier release wrote (`caseworkctl.dev.audit-format-unsupported`,
  refused before the supervisor starts), an audit directory the runtime
  cannot open (`caseworkctl.dev.audit-unavailable`), and a supervised start
  that failed, pointing at `.casework/dev/logs`
  (`caseworkctl.dev.start-failed`). Each message is fixed text with a port
  number or a project-relative path; no absolute path, credential, or
  supervisor cause is reported (#1433).
- `caseworkctl dev stop --remove` also empties the project's retained
  `.casework/dev/audit` directory, since the audit there describes the
  records the removal discards; a stream an earlier release wrote no longer
  outlives the session it described. Only an owner-only tree of ordinary
  files is removed, a symlink is refused rather than followed, and the audit
  hash key and other session state are kept. A plain `dev stop` keeps the
  audit directory.

## v0.38.0 - 2026-10-01

- BREAKING: package activation (`caseworkctl plan`, `apply`, and `status`) and
  `casework serve` startup refuse a PostgreSQL server older than 17 with an
  upgrade instruction, before any migration or activation write. Operators
  on PostgreSQL 16 or older must upgrade the database server before
  upgrading Casework.
- Share activation ledger and runtime privilege checks with Scheduling and
  Messaging. Activation now detects the loss of any required table DML
  privilege, including when other required privileges remain granted (#1731).

- `caseworkctl source add` keeps an automatic executor's service apply profile
  separate from human source-context profiles. Staff and supervisors receive
  no executor scopes. `check` and fixture `test` report each request's
  application mode from its imported source description, or `null` before
  that description exists.

## v0.37.0 - 2026-09-29

- BREAKING: the `Registry-Source-Profile` header is the only input that
  selects the source profile on `POST /v1/work-items/{itemId}/decisions` and
  both attempt recovery routes, as on every other source-backed route.
  `DecideRequest` no longer carries `sourceProfileId`, and
  `RecoverAttemptRequest` is a closed empty object (`{}`); a body that still
  sends `sourceProfileId` is refused with 422 `request.unprocessable`. The
  Rust client, the Node and Python bindings, and the unified clients follow.
  Callers, App Kit included, that send `sourceProfileId` in a decision or
  recovery body must drop it and send the value in `Registry-Source-Profile`
  (#1443).
- `GET /v1/review-tasks` sent without `Registry-Source-Profile` answers 400
  `source-profile.required` when the page would be empty, has no
  `nextCursor`, and at least one candidate was skipped only because that
  header is absent, instead of a silent empty page. A page that lists
  anything, such as submitted-context tasks, is unchanged, and an empty page
  cut short by the source-read budget, candidate scan, or page deadline
  keeps its `nextCursor` and `status` (#1443).
- `caseworkctl dev token` writes the client's `Registry-Casework-Profile`
  line beneath `Authorization` in `secrets/<client>.header` for a client
  bound to a Casework access profile, so the file is usable as-is with
  `curl --header @file`; an integration client's file keeps only
  `Authorization`. A caller that also passes that
  header itself sends it twice (#1443).
- New closed problem code `request.limit-out-of-range` (400) for a zero or
  over-maximum `limit` on a paged route. Its detail names the parameter and
  the accepted ranges, 1 to 100, and 1 to 1000 on the directory absence
  list. It was `request.invalid`. The review result feed and review history
  default to the inbox policy's `defaultPageSize` instead of 25 (#1467).
- `ReviewTaskPage` gains a required `status`, the `PageStatus` the work-item
  page already reports: `complete`; `budget_exhausted` when the source-read
  budget, candidate scan, or page deadline stopped the page before it
  filled; or `source_unavailable` when a bound source did not answer in
  time. Either of the last two comes with a `nextCursor`. Review cursors are
  unchanged (#1467).
- A plain `GET /v1/work-items/{itemId}`, its history, and its clocks return
  the retained item without actions or routing copy when the source's
  binding generation moved or the adapter refused the caller read as a moved
  binding; without a caller view the display reference is withheld too. They
  answered 409 `work-item.proposal-changed`. In those two cases a superseded
  item answers 409 `work-item.superseded`; a superseded item read within one
  binding generation still returns its historical record without actions.
  Mutations still refuse a moved binding.
  Current source visibility still gates every read (#1467).
- A runtime source binding that breaks an adapter rule is refused at load
  with the member's key path, `sources.<id>.<member>`, and a static reason
  naming the rule and its bound, instead of "the binding does not meet the
  source adapter's accepted range". The configured value is never repeated.
  The timeout-ordering refusal now names
  `sources.<id>.requestTimeoutMilliseconds` (#1467).
- `caseworkctl check`, `explain`, `simulate`, and `package` no longer tell you
  to repeat `source add` when `casework.yaml` names a `projection`,
  `contextProjection`, or `displayReference` field the source description
  does not publish; the refusal names the policy key path and the field. A
  description that drifted from the adapter contract keeps the existing
  refusal (#1467).
- BREAKING: every mutating route parses its JSON body with the workspace's
  strict parser, so a duplicate object member at any depth, including inside
  free-form members such as a review draft body or a decision result, is
  refused with 422 `request.unprocessable` instead of the last occurrence
  winning. The same parser refuses, with 422 `request.unprocessable`, a
  well-formed raw JSON integer that IEEE 754 binary64 cannot represent
  exactly, such as `9007199254740993` (above 2^53); send such a value as a
  string. Media-type parsing is stricter: the whole `Content-Type` value must
  parse as `application/json` or `application/*+json` with every parameter a
  `name=token` or `name="quoted-string"` pair, so a value such as
  `application/json; charset` is refused with 415
  `request.unsupported-media-type`. The rejection classes are otherwise
  those of the previous extractor: 413 over the body limit, 400
  `request.invalid` for malformed JSON, and 422 for a document that does not
  match the request type (#1209).
- Each review-producer operation lists only the problems it can return: the
  reads no longer list initiator or idempotency codes, and every producer
  operation lists `profile.not-human` (#1340).
- `caseworkctl attempt mark-uncertain` refuses an item that is not awaiting
  its source outcome with its own sentence instead of settle's, and the Node
  `AttemptUncertainHistoryEntry` detail types the operator marking and
  definitive-refusal keys (#1367).

## v0.36.0 - 2026-09-29

- BREAKING: a Casework package is activated in the database by
  `caseworkctl apply --runtime-config FILE`, and `casework serve` only reads
  that activation. `caseworkctl plan` reports, with the runtime credential and
  in a read-only transaction, what an apply would change: the pending schema
  versions, the source generations and task templates it would register or
  activate, work still pinned to a policy the candidate drops, the runtime
  role's mode, and `changesPending`. `caseworkctl apply` uses the migration
  credential and, in one transaction under the migration advisory lock,
  migrates the schema, registers source generations, activates task
  templates, refuses stranded pinned work, grants the runtime role its
  privileges when the two credentials name different roles, and records one
  row in a new activation ledger (schema migration 19). `--operator-reference`
  is recorded and audited only as a keyed hash scoped to the activation, and
  `--backup REF` may be given up to 16 times. Each apply writes a
  `casework-activation-audit/v1` request entry before any database work and a
  response entry after the commit; an audit destination that refuses the
  request entry leaves the database untouched. `caseworkctl status` shows the
  activation history and the role mode, and `caseworkctl doctor` gives the
  plan or apply next step. Exit codes are 0 for success, 1 for a refusal, 2
  for a usage error, and 3 for an operational failure, including an audit
  destination that refused an entry; an apply that committed but whose
  response entry was refused reports `casework.activation.applied-unaudited`
  and must not be repeated. Re-applying the active package with nothing to
  change is refused and names its digest.
- BREAKING: `runtime.yaml` requires `identity.databaseId`, an operator-chosen
  logical name for the deployment's database. The first apply records it, and
  every later apply and every startup refuses a database that recorded
  another one without naming either value.
- BREAKING: the runtime no longer migrates, registers source generations, or
  activates task templates at startup. It repeats the stranded pinned work
  comparison read-only, since a process on the earlier package can admit work
  after the apply, and it refuses a database with no activation, a schema
  other than its own, an active package other than the one it loaded, an
  unregistered source generation, a database identity other than its own, or
  a split-role activation whose runtime credential can now write the
  activation ledger, and each refusal names `caseworkctl plan` then
  `caseworkctl apply`.
- BREAKING: in split-role mode, `caseworkctl plan`, `caseworkctl apply`, and
  startup refuse a runtime role that owns a Casework object, holds CREATE on
  the schema, or holds TRIGGER on a Casework table, and a database where a
  trigger no Casework migration creates is attached to a Casework table. The
  refusal names the `REASSIGN OWNED BY`, `REVOKE CREATE ON SCHEMA`, `REVOKE
  TRIGGER`, or `DROP TRIGGER` statement to run, `FROM PUBLIC` when that is how
  the runtime role holds the privilege, then the command to run next. Apply
  never revokes TRIGGER or drops a trigger itself: before any migration it
  refuses a default privilege of the migration role that would grant the
  runtime role TRIGGER on the tables it creates, naming `ALTER DEFAULT
  PRIVILEGES ... REVOKE TRIGGER ON TABLES FROM <grantee>`.
- BREAKING: startup refuses a BReg source whose imported description pins a
  `sourceRevision` other than the registry revision the source serves, naming
  `caseworkctl check PROJECT --against-breg-package DIR --source-id ID`, the
  `caseworkctl source add BREG_PROJECT --project PROJECT --source-id ID
  --apply` repin, then package, plan, and apply. A source that cannot be read
  at startup is not refused there; its reads refuse the same drift.
- `caseworkctl check PROJECT --against-breg-package DIR [--source-id ID]
  [--bregctl-bin PATH]` verifies a closed BReg package through the `bregctl` of
  the same release, compares the registry revision it rederives with the
  source's pinned `sourceRevision`, and adds `bregPackage` to the check report
  on a match. A mismatch is refused with `casework.source-revision.stale`;
  a project with several BReg sources needs `--source-id`
  (`casework.source.ambiguous`), and an unknown or missing source or source
  description is refused with `casework.source.none`,
  `casework.source.unknown`, or `casework.source-description.missing`.
- `caseworkctl plan` refuses a runtime role that cannot read an existing
  activation ledger with `casework.activation.ledger-unreadable`, naming
  `caseworkctl apply --runtime-config FILE` with the migration credential to
  grant it, then `caseworkctl plan --runtime-config FILE`.
- `caseworkctl plan` names `casework.activation.hosted-work-would-be-dropped`
  and `casework.activation.unpublished-audit-would-be-dropped` when schema
  migration 15 or 17 is pending and the table it drops still holds rows,
  counted without a lock; apply counts them again under an exclusive lock and
  refuses the same.
- `caseworkctl package --help` says that its package is the unit `caseworkctl
  plan` and `apply` activate, and that `bregctl package` is a different verb
  that builds a BReg registry package.
- BREAKING: `casework migrate` and `caseworkctl db migrate` are removed. Each
  still parses only to refuse with exit 2 and name `caseworkctl plan
  --runtime-config FILE` then `caseworkctl apply --runtime-config FILE`; the
  `DatabaseMigrationReport` kind is gone, and the `caseworkctl/v1alpha3` wire
  contract adds `PlanReport`, `ApplyReport`, and `StatusReport` and the
  `DoctorReport` `roleMode` and `singleRoleStatement` fields.
- BREAKING: every `caseworkctl --format json` report opens with `ok`,
  `command`, and `status`, in that order, as `evidencectl` and
  `schedulingctl` reports do, under `caseworkctl/v1alpha3`. `ok` is true
  exactly when the exit code is 0, and `command` is present on every report,
  failures included. `status` keeps a report's own status where it has one,
  and is otherwise `passed` for a successful `test`, `complete` for another
  success, `refused` for a plan that names its refusals, and `domain-refusal`,
  `usage-error`, or `operational-failure` by exit class for a failure without
  a report of its own.
- Upgrade: add `identity.databaseId` to `runtime.yaml`, then run
  `caseworkctl plan` and `caseworkctl apply` once with the new binaries
  before starting the runtime. The first apply on a database an earlier
  release migrated adopts it: it applies the pending migrations and records
  the first activation. With split roles, a trigger an operator added to a
  Casework table blocks apply and startup until it is dropped. A BReg source
  description imported from an earlier release pins a registry revision this
  release's BReg no longer serves: after upgrading BReg, run `caseworkctl
  check --against-breg-package`, repin with `caseworkctl source add --apply`,
  and package the project again before plan and apply.
  Stop every runtime serving the earlier package before `caseworkctl apply`
  of a package that changes a source's binding generation. A runtime left
  running can reserve a source attempt under the earlier binding while or
  after apply rebinds the source, and the new runtime cannot execute or
  recover it (#1723). No `status` or `doctor` report lists such an attempt:
  its work item stays fenced, the holder's next call receives the recovery
  problem naming it, and the operator clears it with `caseworkctl attempt
  mark-uncertain` then `caseworkctl attempt settle` once the source owner
  confirms the outcome.
  `caseworkctl dev` applies in-process on every start, after it rewrites the
  session's operator configuration, so a session retained from an earlier
  release starts with its database in place. Ctrl+C stops a start whose
  apply waits on a database lock.
  A session it creates connects the runtime and apply with one database role;
  a session retained from an earlier release keeps its split runtime and
  migration roles, and apply alone grants that runtime role, so both
  activation ledgers stay read-only to it.
- A command line `caseworkctl` refuses is described by the kind of error and
  the argument name, such as `unexpected argument --operator-reference`, or
  by the argument's own validation reason, such as `--backup must not be
  empty`, and names `caseworkctl --help` as the next step. The refused value
  is never repeated on standard output or standard error.
- The Casework image carries `caseworkctl` at `/usr/local/bin/caseworkctl`
  beside the runtime. The entrypoint stays `casework`; run `plan`, `apply`,
  and `status` from the image by overriding the entrypoint.

## v0.35.0 - 2026-09-28

- BREAKING: Casework reads `runtime.yaml` through the shared Registry Stack
  runtime configuration loader and declares its secret providers, database,
  listener bind, OpenID Connect issuer and clients, and audit key through the
  shared blocks. The runtime file may not pass through a symbolic link and is
  at most 1 MiB. `${VAR}`, `${VAR:-default}`, and `${VAR:?message}` are
  substituted in string values after parsing, so a substituted value is
  always text; an expression in a field ending in `Ref` or under
  `secretProviders` is refused, and one in `casework.yaml` is refused by the
  runtime and by `caseworkctl check` with the path of the field that holds it.
- BREAKING: `listener.bind` is required; the `127.0.0.1:8100` default is
  removed.
- BREAKING: `authentication.oidc.issuer` must be an absolute `https` URL
  without credentials, query, or fragment, or IPv4-loopback `http` under
  `development-loopback`, and `authentication.oidc.audience` is at most 512
  characters.
- BREAKING: under `operator-controlled-upstream`,
  `authentication.oidc.allowedClients` must name at least one client; an
  empty list admitted every client the issuer verifies and is now refused at
  that field. `development-loopback` still accepts an empty list, and a
  configured `taskAuthority` still requires a non-empty list in either mode.
- BREAKING: `authentication.oidc.jwksUri` is removed. Declare
  `jwksSource` with `kind: uri` and the same `https` URL as `uri`; that
  source fetches the key set from the fixed address without reading the
  discovery document. The removed key is refused with the replacement named,
  and `caseworkctl` reports it at `runtime.yaml:/authentication/oidc/jwksUri`.
- BREAKING: `audit.hashKeyRef` must be an exact secret reference when the
  document is read. A refused `authentication.oidc.assertionIssuers` map is
  reported at that field; its bounds are unchanged.
- BREAKING: a Casework package is the shared Registry Stack package format.
  `caseworkctl package` writes `SHA256SUMS`, one `sha256sum` line per file
  sorted by path, in place of `casework.package.json`, and reports
  `packageDigest`, the SHA-256 digest of `SHA256SUMS`, in place of
  `policyDigest`. `--revision TEXT` records one free-text line in a
  `REVISION` file the digest covers. At startup the runtime refuses a changed,
  missing, or extra file by name, and refuses a `package.root` that still
  holds `casework.package.json`, naming `caseworkctl package`; rebuild every
  deployed package with it.
- BREAKING: `package.expectedPolicyDigest` is renamed `package.expectedDigest`
  and pins the package digest. The retired key is refused with its
  replacement named, and a mismatch is refused in the shape every Registry
  Stack runtime shares:
  `package.expectedDigest is <pin> but the package at package.root is <found>`.
- BREAKING: the runtime verifies `package.root` as a package in every listener
  mode, with or without `package.expectedDigest`. A local
  `development-loopback` runtime no longer serves an authored project: a
  directory without `SHA256SUMS` is refused naming `caseworkctl package`.
  `caseworkctl dev` packages the authored project under `.casework/dev/package`
  on every start and serves that package, and the `runtime.example.yaml`
  `caseworkctl init` writes serves `.casework/package`. The doctor
  `pinnedWork` verdict `development` is removed, and `/version` and doctor
  always report `packageDigest` as a digest, never `null`.
- The metrics listener no longer lets the scrape rate set the database load.
  Scrapes within five seconds of a database reading reuse it, concurrent
  scrapes wait for the one reading in flight, and a reading that takes longer
  than five seconds reports `casework_database_up 0`.

- Casework database connections now use `connect_timeout=5`,
  `keepalives_idle=15`, `keepalives_interval=5`, `keepalives_retries=3`, and
  `tcp_user_timeout=30`, all in seconds, unless the database URL sets them,
  so a connection to a server that stopped answering fails within seconds
  instead of the operating system's hours.

- Answer every audited request entry. An operation whose change is not
  known to have committed (a refusal, a failure, a canceled request, or a
  commit whose acknowledgment was lost and whose outcome could not be read
  back) writes `{event, outcome: "unfinished"}` as its response under the
  same correlation. A commit whose acknowledgment was lost is read back
  first, and one that took effect is answered and recorded like any other.
  A committed operation writes all of its response entries even when its
  caller disconnects while they are written. Adding a review note is audited
  as `casework.review_note_added`, naming the review request by its keyed
  pseudonym and the note's history event, but never the note's text or
  audience.

- BREAKING: write audit through the shared platform audit writer instead of
  a hash-chained journal published from a PostgreSQL outbox.
  - The `audit` block takes `hashKeyRef`, `destination` (`file`, the
    default, or `stdout`), and, for `file` only, the absolute `path`,
    `rotateBytes` (default 104857600, at least 1048576), and `retainDays`
    (default 90, at most 36500). An existing `{path, hashKeyRef}` block keeps
    working as a `file` destination.
  - Every entry carries the schema `registry-casework-audit/v1`, a `request`
    or `response` phase, and a correlation shared by an operation's request
    and response entries. The runtime writes the request entry before it
    opens the operation's transaction and the response entries after that
    transaction commits. A destination that refuses either fails the call
    with `service.unavailable`; a refused response leaves the committed
    change in place. An accountability read returns protected fields only
    after its response entry is accepted. A requested operation that records
    no domain event, such as an idempotent replay or a request whose state
    already held, writes one response entry whose `outcome` is `replayed` or
    `unchanged` and returns its result only after that entry is accepted.
  - Entries are no longer hash-chained, and the runtime keeps no audit state
    in PostgreSQL. Schema version 17 drops `casework_audit_outbox`; `migrate`
    refuses with `casework.migration.refused` while the outbox still holds
    unpublished records, so run the previous release until its publisher has
    drained the outbox, then migrate.
  - The review database trigger no longer writes audit; the runtime writes
    the invalidation entries it caused after the transaction commits.
  - Before starting the upgraded runtime, archive the old active audit file
    and every numbered sibling separately, then use a fresh `audit.path`.
    Retention now deletes aged sealed files under that path. Update log
    consumers to the new envelope and ship entries to append-only storage
    when tamper evidence is required.
  - `/ready` reports ready only while the audit writer is ready, and
    `caseworkctl doctor` reports an `audit` check.
  - A `caseworkctl` command that writes audit, such as an applied erasure or
    settlement, writes to a sibling file named for its role beside
    `audit.path` (`audit.caseworkctl.ndjson` beside `audit.ndjson`).
  - The retention report no longer carries an `auditRecords` count.

- The optional `metricsListener.bind` runtime setting serves `/metrics`
  (Prometheus text: build and package digest, database reachability, and
  per-source reconciliation failures and last-success age) and `/version` (running version and package digest) on a second,
  operator-private address. It must be loopback or private, never a wildcard,
  and never the API listener's address and port. Without it no telemetry
  socket opens, and the API listener is unchanged.
- BREAKING: Casework and its BReg sources run in lock-step. BReg now names its
  release in a `Registry-Engine-Version` header on `GET /v1/registry`, and the
  Casework BReg adapter refuses a source whose engine reports another release,
  or no release, as a source outage. One trailing `-dev`, which a build
  without the release marker appends, is set aside on each side, so a release
  build matches a development build of the same version (with a warning);
  every other part of the version, a prerelease tag included, must match. The runtime log names the source and both
  versions, and `caseworkctl doctor` refuses at `sourceConnections` with the
  same message and the upgrade step. Upgrade each BReg source first, then
  Casework, to the same release; reads resume on the next matching contract
  read. The adapter logs the engine version once when it first reads it, and
  a caller's read of a registry contract that does not decode is now logged
  with its route and metadata error kind instead of passing silently.
- BREAKING: the runtime refuses to activate a policy package that would strand
  in-flight work pinned under an earlier package, and names each conflict with
  its counts: a queue or access profile that pinned reviews or open work items
  still need, a pinned review kind version declared with different content, a
  removed source that source-context reviews or open work items still need,
  or a source read the pinned display schema would refuse. Let that work finish, or set the new
  `package.acknowledgeStrandedWork` to the exact package digest the refusal
  names. `caseworkctl doctor` runs the same comparison as its `pinnedWork`
  check and reports the conflicts under `pinnedWork`, so it previews the
  refusal against the next package before a restart.
- BREAKING: `caseworkctl doctor` names the check that failed instead of
  reporting every dependency failure as "A Casework runtime dependency check
  failed." A refusal carries the code `casework.doctor.check-failed`, names the
  check in its `path` (`doctor:/checks/database`, `sourceConnections`,
  `directory`, `reconciliation`, `audit`, and so on), says what failed
  without echoing a connection string or a source response, and suggests the
  next step. `doctor` also checks each source's reconciliation health, and
  its report adds `packageDigest`, the `reconciliation` readiness key, and
  each source's reconciliation health. Because pinned
  objects gained fields, the `caseworkctl --format json` wire contract moves
  from `caseworkctl/v1alpha1` to `caseworkctl/v1alpha2`; a consumer that
  matches the version must accept the new one.
- BREAKING: `GET /ready` answers `503` once a source's reconciliation has
  failed five consecutive passes, and until one pass for that source succeeds.
  Schema migration 18 records each pass's outcome, so every replica and
  `doctor` see the same health; `caseworkctl apply` applies it. A database
  whose schema is not the runtime's own is refused at startup with the
  `caseworkctl plan` then `caseworkctl apply` instruction, instead of as
  invalid stored data.
- One item a reconciliation or event-synchronization pass cannot apply no
  longer stops the rest of the pass. The pass applies every other claimed
  item, logs how many it could not apply, and retries each after its claim
  lapses.

## v0.34.0 - 2026-09-25

- BREAKING: give each paired BReg request entity its own lifecycle hook, so
  a pairing of several request entities in one registry passes `bregctl
  check`. BReg requires a hook id to be unique across the registry, and
  `caseworkctl source add --apply` used to write `casework-lifecycle-v1` on
  every paired entity, which BReg refused as `event.id.registry_duplicate`.
  - The hook on request entity `<entity>` is now
    `casework-lifecycle-v1-<entity>`, for one paired entity or several.
    `source add` refuses, before writing, an entity whose id would push the
    hook id past BReg's 64-byte identifier limit (entity ids of at most 42
    bytes fit), naming the entity and the limit.
  - The BReg source binding no longer accepts `eventType`. The adapter
    derives the expected `ce-type` from each paired request entity, refuses
    an event whose type no paired entity derives before verifying its
    signature, and refuses an event whose type is not the one derived from
    the request entity its body names.
  - To migrate, remove `eventType` from each `*.breg-runtime.yaml` binding,
    which is otherwise refused at startup. Remove every
    `casework-lifecycle-v1` hook from the BReg `registry.yaml` (and the
    `hooks` key where it was the only hook), then repeat `caseworkctl source
    add --apply` to write the per-entity hooks. `source add` refuses a
    `registry.yaml` that still carries the bare hook and names each entity
    that carries it. Deliveries BReg queued under the bare hook id before the
    change are refused by the updated adapter; the runtime's reconciliation
    readback observes the same work from the source.
- `caseworkctl source add --apply` compares the source description and the
  runtime binding before refusing either, and the refusal now says how to
  recover. It names each file that differs from what the run would write and
  why:
  - the description pins another `sourceRevision`;
  - `casework.yaml` pairs a different set of request entities, for example
    one becoming two, which moves `v1alpha1` to `v1alpha2`;
  - the binding was hand edited.

  It prints the exact recovery commands: move each file to a `.previous`
  copy, then repeat the same `source add --apply`. A lifecycle hook or
  `casework-reader` permission in the BReg `registry.yaml` that differs from
  the regenerated one is refused with the entity named. The refusal says to
  remove that fragment and repeat `source add --apply`. Nothing is replaced
  automatically. When `casework.yaml` drops a request entity from the paired
  set, the same conflict message now also names that entity's
  `casework-lifecycle-v1-<entity>` hook and `casework-reader` permission as fragments
  to remove from `registry.yaml`, since `source add` never removes a
  generated fragment on its own. `source add` also refuses, before preview or
  apply, whenever `registry.yaml` still carries a lifecycle hook or
  `casework-reader` permission for a request entity the current pairing does
  not include, whatever left it there, naming the entity and the exact
  fragment to remove; leaving it in place would keep BReg emitting that
  entity's lifecycle events and keep the reader credential's read access to
  it after Casework stopped coordinating it.
- `caseworkctl check` and `caseworkctl source add` refuse a source-context
  review kind whose `displaySchema` the imported source description proves
  would reject what the source discloses, which hides the review task from
  every reviewer at runtime. They refuse three cases:
  - A projected field the closed schema does not declare.
  - A declared property whose `type` shares no JSON type with the source
    field.
  - A value the source schema itself names that the property rejects. That
    value is an `enum` or `const` member, `null`, or a Boolean, alone or as
    an array item.

  The refusal names the review kind, the property, and each rejected value.
  A property a root `allOf` branch declares, instead of the root
  `properties` map, is checked against the same first two cases, since
  `allOf` requires every branch to validate the whole disclosure; the
  refusal names the branch (`allOf branch 1`, and so on). `anyOf`, `oneOf`,
  `not`, `if`/`then`/`else`, and `$ref` are not provable this way and are
  left to the runtime check.
  `source add` refuses before preview, so nothing is written. Constraints
  that only an invented value could violate, and properties that use `$ref`,
  are left to the runtime check. The professional-review template now marks
  its display properties and `licensedActivities` enum as the starter
  registry's vocabulary, to be replaced from `bregctl explain
  change-requests`.
- The review retention pass deletes a review's clock occurrences at
  `terminalDays` instead of at `accountabilityDays`. Each occurrence carries
  the subject source, type, and identifier, the pinned clock policy, and its
  evaluated effects, so a review kind with `terminalDays` shorter than
  `accountabilityDays` kept that source-linked data long after the request
  context it came from was erased. Every clock occurrence now expires with
  the request context of the round it is bound to, including a subject clock
  a changes-requested round paused. A later round of the same review kind
  continues that clock only inside the result window; a resubmission after
  it starts a fresh subject clock with a full deadline. A request whose result
  an earlier pass already erased is picked up again while a clock occurrence
  remains, so existing rows are removed too. The same expiry check now also
  runs atomically when the next round is created, so a paused or running
  subject clock still bound to an already-expired round is erased and
  restarted there too, rather than depending on the asynchronous retention
  pass to catch up first.
- Casework keeps every sealed audit file instead of rotating and deleting the
  oldest. Before the first `serve` of v0.34.0, stop every earlier `casework`
  process, and if a numbered file such as `casework.ndjson.1` sits beside the
  audit file, move the audit file and its numbered siblings to an archive
  directory, as the Casework operate guide describes. The audit directory must
  be mode `0700`. Casework refuses to start until both hold.
- Casework reads its log level from `CASEWORK_LOG` (`error`, `warn`, or `info`,
  default `info`) and writes structured JSON. `RUST_LOG` no longer has any
  effect on the `casework` process.
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
