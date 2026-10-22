# Base Registry Engine changelog

## Unreleased

- BREAKING: `breg` and `bregctl doctor` refuse a database that still carries
  the attachment verification shape v0.43.0 and earlier installed (a
  `registry_internal.registry_attachment_verification` table with a
  `lease_id` column, or without the
  `registry_internal.registry_attachment_verification_jobs` table), with
  `startup.database.pre-1-0-schema`, before the role and catalog checks that
  reported it as missing grants or as catalog drift to restore from a backup
  carrying the same shape. `bregctl plan` and `bregctl apply` refuse it with
  `apply.database.pre-1-0-schema` before any other database outcome, where
  they reported an active package as ready or already active, and the
  commands that bind the active registry refuse it as
  `<command>.active-registry.pre-1-0-schema`. Migration: create a fresh
  database, rebuild the package with the v0.44.0 `bregctl test` and
  `bregctl package`, because a package an earlier release built records
  that release's schema fingerprint, and run
  `bregctl apply --package DIR --initial`.

- `registry_internal.registry_attachment_verification_jobs` and the hook
  delivery state refuse a `leased` row without a `lease_expires_at`, through
  the corrected shared dispatch job and delivery state shapes, and the managed
  schema fingerprint changes with them. Install the release on a fresh
  database.

- BREAKING: attachment verification audit entries use the schema
  `breg-attachment-verification-audit/v3`, with the same record fields as
  `/v2`. The keyed verification reference is derived under the
  `breg-attachment-verification-v2` domain from the verification id and the
  attempt's lease token, in place of the `breg-attachment-verification-v1`
  domain over the content digest, content type, and lease id, so a reference
  under one domain never matches one under the other for the same
  verification. Migration: a reader joining verification entries across the
  change branches on the schema.
- BREAKING: one 60 second attachment verification attempt covers both the
  storage read and the verifier call, so `breg` refuses at configuration load
  an `attachmentStorage.attemptTimeoutMilliseconds` (S3 storage only) plus
  `attachmentVerification.attemptTimeoutMilliseconds` above 55,000, with
  `breg.runtime.attachment-attempt-budget-exceeded`; the remaining five
  seconds are kept for recording the outcome. Migration: lower either timeout
  so the two add up to at most 55,000.
- BREAKING: attachment verification runs on the shared
  `registry-platform-dispatch` job core. Each pending verdict has one job in
  the `registry_internal.registry_attachment_verification_jobs` table, and
  `registry_internal.registry_attachment_verification` loses its
  `next_attempt_at`, `lease_id`, `lease_expires_at`, and `attempts` columns
  and the `registry_attachment_verification_pending` index, and gains a
  `verification_id` column. A failed attempt is retried after a delay
  drawn with equal jitter, 15 to 30 seconds for the first retry and doubling
  to at most one hour with jitter included, in place of a fixed 30 seconds; an attempt has 60 seconds in place of 180; and a lease a
  stopped worker left behind is retried after that delay and audited as
  `unfinished` by the worker that recovers it. Migration: the tables are not
  converted in place, so install the release on a fresh database. Operator
  queries that read the attempt count or lease from the verdict table read
  `attempt`, `state`, and `lease_expires_at` from the job table, joined on
  `verification_id`. A pending verdict whose job is missing or dead-lettered
  holds back the worker's last success, so
  `breg_worker_last_success_age_seconds` grows while one waits.
- BREAKING: hook destinations move from `eventDestinations` to
  `destinations.hooks` in `runtime.yaml` and in the `bregctl dev` clients file
  `dev-clients.yaml` (CFG-NAME-5). Migration: add a `destinations:` block,
  put a `hooks:` key under it, and move each `eventDestinations` entry under
  `hooks:` unchanged. A file that still writes `eventDestinations` is refused
  with `config.removed-key` naming `destinations.hooks`, and `breg` refuses to
  start on it. The destination binding digest a retained delivery was captured
  under is unchanged, so retained deliveries stay deliverable. `bregctl
  doctor` reports the check as `destinations.hooks`; its diagnostic codes are
  renamed in the hook vocabulary entry below.
- BREAKING: hook delivery audit entries use the schema `breg-hook-audit/v1`
  in place of `breg-webhook-audit/v3`, carry `"event": "breg.hook-delivery"`,
  and derive their keyed event and delivery references under the
  `breg-hook-event-v1` and `breg-hook-delivery-v1` domains. Migration: select
  hook delivery entries by the new schema or event name, and branch on the
  schema when joining references across the upgrade; a reference written
  before the upgrade does not match one written after it for the same
  delivery.
- BREAKING: local Rhai and WASM hook handlers run on the shared
  `registry-platform-hooks` executor, which uses the bare
  `registry-platform-script` engine. Hook programs lose the `join` helper the
  action planner engine carries. Migration: build the string in the program
  itself. A package whose hook calls `join` still compiles and activates,
  because the engine resolves functions when the program runs, and then
  dead-letters every delivery of that hook with the reason
  `handler-execution`. After upgrading, run `bregctl hook list` and look for
  `handler-execution` dead letters; fix the program, then replay them with
  `bregctl hook replay`.
  Action handlers keep `join`. The WASM hook entry point no longer shares the
  action handler module cache.
- BREAKING: the Rust module `registry_breg::webhook` is `registry_breg::hooks`,
  its `Webhook*` types are `Hook*`, and `registry_breg::hook_handler` is
  removed in favour of the executor in `registry-platform-hooks`. Migration:
  rename the imports. Hook declarations are checked against the full hook
  capability set at compile time and refused outside it with
  `hook.capability.unsupported`; every declaration BReg accepted before is
  still accepted.
- BREAKING: the sending side of event delivery is named hooks throughout,
  with no aliases. Migration: update every script, alert, dashboard, and
  receiver that names the old words:
  - the operator verb `bregctl webhook` is `bregctl hook` (`sample`, `list`,
    `drain`, `replay`, `discard`), and its diagnostics name the artifacts
    `hook-sample` and `hook-operations` and the suggested actions
    `select-hook-event` and `verify-hook-operation`; the offline sample
    request target placeholder is `<configured-hook-request-target>`;
  - the codes `webhook.sample.event-refused`, `webhook.sample.render-refused`,
    `webhook.package.refused`, `webhook.operation.refused`,
    `webhook.claim.*`, and `webhook.worker.*` are `hook.*` with the same
    suffix;
  - `startup.webhook.retained-bindings` is `startup.hook.retained-bindings`,
    and `startup.event-destinations.refused`,
    `apply.event-destinations.refused`,
    `test.event-destinations.inventory-mismatch`, and
    `test.event-destinations.activation-failed` name `hook-destinations` in
    place of `event-destinations`;
  - `breg.event.webhook-projection-too-large`,
    `breg.event.webhook-destination-invalid`,
    `breg.runtime.invalid-event-destination`, and
    `breg.runtime.event-destination-id-collision` are
    `breg.event.hook-projection-too-large`,
    `breg.event.hook-destination-invalid`,
    `breg.runtime.invalid-hook-destination`, and
    `breg.runtime.hook-destination-id-collision`;
  - the operational events `WebhookWorkerIterationFailed` and
    `WebhookStateTransitionFailed` are `HookWorkerIterationFailed` and
    `HookStateTransitionFailed`, and every hook worker log uses the target
    `registry_breg::hooks` in place of `registry_breg::webhook`;
  - the metrics labels `worker="webhook"` and `queue="webhook-delivery"` are
    `worker="hook"` and `queue="hook-delivery"`, and the `bregctl plan`
    and `apply` check `webhook-bindings` is `hook-bindings`;
  - the Rust constants `WEBHOOK_*`, `MAX_WEBHOOK_*`, `MIN_WEBHOOK_*`, and
    `DEFAULT_WEBHOOK_*` are `HOOK_*`, `MAX_HOOK_*`, `MIN_HOOK_*`, and
    `DEFAULT_HOOK_*`;
  - in `registry-breg-client`, `verify_webhook_delivery`,
    `BRegWebhookDelivery`, `BRegVerifiedWebhookDelivery`, and
    `BRegWebhookVerificationError` are `verify_hook_delivery`,
    `BRegHookDelivery`, `BRegVerifiedHookDelivery`, and
    `BRegHookVerificationError`; the Node.js client exports
    `verifyHookDelivery`, `HookDeliveryInput`, `VerifiedHookDelivery`, and
    `HookVerificationRefusalCode`, the Python client exports
    `verify_hook_delivery`, and both report a refused delivery with the error
    kind `hook-verification` in place of `webhook-verification`.
  The signature and idempotency domains (`breg-webhook-signature-v1`,
  `breg-webhook-idempotency-v1`), the delivery tables, the compiled delivery
  identifiers, the destination binding digests, and the CloudEvents request a
  receiver gets are unchanged, so retained deliveries stay deliverable and
  receivers keep verifying.
- BREAKING: `attachmentStorage` and `attachmentVerification` in `runtime.yaml`
  name their destination `url`, not `endpoint` (CFG-VAL-7). Migration: rename
  `endpoint:` to `url:` in both blocks and keep the value. A file that still
  writes `endpoint` under `type: s3` or `type: http` is refused with
  `config.removed-key` at that member, and `breg` refuses to start on it;
  under `type: database` or `type: disabled`, which take no `url` either, it
  is refused as an unknown key. The value is kept exactly as written: no
  whitespace is trimmed, no host is mapped through IDNA, and no backslash is
  rewritten; a value holding whitespace, a control character, or a
  backslash, or a host the URL parser would rewrite, is refused instead. User
  information and a scheme other than `http` or `https` are refused when the
  file is decoded, with `config.invalid-value` at the member and the shared
  URL sentence. The S3 adapter and the verifier transport now
  come from `registry-platform-objectstore`; moving them changes no object
  key, no storage or verification binding digest a registry has pinned, and
  no request. The attempt timeouts, the attempt budget refusal, and the fresh
  database the attachment verification jobs need are the separate entries
  above.

- `bregctl plan` and `bregctl apply` name a refusal that happens before
  maintenance begins instead of reporting `apply.migration.failed` with advice
  to reconcile a migration that never started. A wrong migration role reports
  `apply.database.migration-role-refused`, a missing administrator-installed
  prerequisite `apply.database.prerequisite-missing` naming it, a refused
  catalog `apply.database.catalog-refused`, a refused database setting
  `apply.database-configuration.refused`, and a package id that derives no
  lock key `apply.package.lock-key-refused`. Each says nothing was changed.

## 0.43.0 - 2026-10-21

- BREAKING: authored display fields reject prohibited Unicode controls and
  checked definition namespaces reject identifiers differing only by `-` versus
  `_`. Equivalent peer labels produce warnings. Run product checks and repair
  the reported locations; see [the upgrade notes](../../release/notes/v0.43.0.md#authored-text-and-identifier-checks).

- Preserve authored display on access profiles, statistical datasets, record and
  Proposal hooks, and derived fields. Model inspection includes native datasets,
  all project access-profile labels, field display, and module origins.
  Workspace metadata for the caller includes authored labels and descriptions
  for readable derived fields. Labels never select an identity or grant authority.
- BREAKING: the model, access, and actions explanation formats advance to
  `v1alpha6`, proposals to `v1alpha2`, and lifecycle to `v1alpha7`. Select the
  matching schemas. Action inputs retain optional authored `display` separately
  from the existing `label` fallback. Lifecycle states report their possible `turns`,
  including the ordered conditions for submitted work, from the runtime rule.
- Model explanation lists each source document's authored JSON Pointers before
  defaults and module composition. Consumers can distinguish a source member
  from a compiled default after resolving the object's source document and ID.
  Index-field, profile read-path, and target-permission diagnostics now retain
  the exact owning item, including its module extension block.
- Rebuild governed packages after upgrading. Dataset and access-profile
  presentation metadata now contributes to the compiled revision and artifact
  bytes.
- Activate display-only successor packages as metadata updates while retaining
  compatible frozen Proposal submissions. Unchanged rebuilds remain empty plans.

- Extend `bregctl explain access` with each Action target's runtime-enforced
  authority, whether the profile also has a direct Record grant, and the
  compiled write or existing-target role of each use. The report identifies
  Action target authority as additional to Record grants.

- BREAKING: enforce active reference integrity in PostgreSQL: active Records cannot
  reference tombstoned targets, and a target cannot be tombstoned while another
  active Record references it. Tombstoned Records and history retain their
  reference IDs. Conflicts remain value-free `409 mutation.conflict` responses.
  Existing deployments must build and apply a successor package against their
  deployed baseline before switching runtimes. `bregctl plan` checks activation
  prerequisites but does not validate live rows. Before live maintenance, apply
  the successor to a representative restored-data copy; repair any active
  references to tombstoned targets through the current package, refresh the
  copy, and repeat that validation before production activation.

## 0.42.0 - 2026-10-20

- Advertise a per-target availability route for immediate Actions with
  reference inputs. The route evaluates disclosed field guards without
  granting mutation authority and returns a closed unknown result when the
  required target facts cannot be disclosed.
- BREAKING: an immediate Action whose declared field guard fails at commit now
  answers `412 action.guard_failed` instead of `412 precondition.failed` when
  current-target admission checks pass and the selected profile can read the
  failed guard's target fields. The code confirms that blocker; it does not
  promise the Action would otherwise succeed. Effect application, proposed-value
  authorization, and database constraints run only after guards pass. An
  earlier refusal retains its normal response, while a stale condition or a
  guard that cannot be disclosed remains `412 precondition.failed`. Clients
  that match `precondition.failed`, for example to offer reload and retry, must
  accept the new code; older Rust clients report it as an unrecognized problem.
- BREAKING: the routes explanation format advances from `v1alpha5` to
  `v1alpha6` and includes the `availability` Action route kind. Consumers must
  select the `v1alpha6` schema.
- Correct generated Action response contracts: Proposal Start advertises its
  `201` Proposal response with `ETag` and `Location`, without immediate guard,
  handler, or Evidence failures. Immediate Invoke includes Evidence failures
  when Evidence is declared only in commit guards.
- Distinguish an explicit Review producer-ID mismatch from uncertain transport
  outcomes, with bounded diagnostics naming both configured IDs.
- BREAKING: when activation blocks submitted work, atomically withdraw its Review
  and close its application jobs. Before activating an incompatible package, check
  affected submitted Proposals and arrange requester recovery. A restoring package
  cannot revive those rounds or jobs; the requester must Cancel, or Rebase and
  Submit for fresh Review. Late results remain evidence, and authorized Get and
  List stay available even when approval arrives before any job exists. Recovery
  names the package-change block, and private metrics count its closed jobs.
- A `409 mutation.conflict` from a direct record create, patch or batch that
  violates a compare, int-range or vocabulary constraint now carries the
  members `recordType`, `constraintId` and `constraintKind` (`compare`,
  `int-range` or `vocabulary`), plus `left` and `right` for a compare
  constraint or `field` otherwise. The server omits all of them when the
  caller cannot read every field the constraint references; unique and
  temporal non-overlap conflicts stay generic. Clients that hold this problem
  to a closed member set must accept these members. The maintained clients
  expose them as the conflict's constraint, and a fixture journey's generic
  `mutation.conflict` expectation accepts them only when they match a declared
  constraint the step's access profile can read.
- Automatically erase expired Action and Proposal Evidence uses under the runtime
  role after their fixed 24-hour window, in bounded, audited batches. Manual
  `bregctl evidence-retention erase-expired` remains available to operators.
- Prune terminal webhook metadata after both the receipt and payload retention
  horizons permit it, preserving active and uncertain work, replay protection,
  and audit records. Dead letters also require completed payload expiry.
  Nonempty ticks report committed deletion counts; failures report a closed,
  value-free reason and any prior committed progress. Idle ticks stay silent.
- Include a closed `refusalReason` in read audit records where the refusal has a
  defined reason, without recording caller selectors or record values.

- BREAKING: request, operator, access-log and webhook audit records now name activation UUIDs
  `activationId`, reserving `packageRevision` for package digests. The affected
  audit schemas advance as documented in [audit identity](contracts/audit-identity.md).
  Import authority records preserve their original binding as `authorityActivationId`.
  Reference-hash inputs and domains are unchanged.
- Expire and audit every webhook delivery after its shared payload expires,
  including siblings whose payload was already erased.
- BREAKING: activation refuses before maintenance with
  `apply.hooks.local-retained` when local hook work still needs the active
  package. `bregctl webhook drain` attempts due local work under that package
  with attempt and time bounds. Apply audits this retained-local guard refusal
  in `breg-activation-audit/v1` with the outcome `refused`, which audit
  consumers have not seen before; an incomplete refusal audit returns
  `apply.audit.refusal-incomplete` with ready state unchanged. Other activation
  failure classifications retain their contracts.
- Let settled URL proposal decisions finish delivery after activation.
  Uncommitted proposals classified under a successor become non-replayable
  `hook.proposal.package_unavailable` dead letters, while committed answers
  retain receipt recovery without applying twice. An interrupted final attempt
  with no recoverable receipt instead becomes `worker-interrupted` without a
  proposal code and may remain eligible for explicit replay to the receiver.
  `webhook list` exposes `proposalCode` and a bounded `proposalSummary` for
  the superseded-activation refusal; it does not expose other handler-authored
  summaries.
- BREAKING: `webhook list` reports `replayEligible` only when the captured
  operator permission and the product proposal policy both allow a replay,
  alongside the state, payload, and binding checks. A dead letter that replay
  would refuse now reads `false`; it read `true` before.
- Classify added events as disclosure widening and removed events as narrowing.
  Changed projections and destinations require disclosure review in diff output;
  event changes remain applicable without reviewed migration SQL.

- BREAKING: this release carries no state migration from 0.41; apply it to a
  fresh database and keep the 0.41 database for reconciliation and rollback.
- Native adopter tests can capture several disclosed Action results from one
  resumable `bregctl examples` invocation and assert an exact unordered set of
  collection member identities plus selected domain field values in journeys.
  Existing single-result examples and count-only journey assertions remain
  valid.
- `bregctl init --from publicschema` derives a bounded `structured` list for
  a multivalued class property when its range class explicitly declares
  `inline_only: true`. Each generated field is a closed object with a required
  `values` array of at most 50 complete flat scalar or enumerated objects and
  a 16384-byte field bound; required value members stay required. Existing
  scalar and enumeration lists retain their 4096-byte bound. This supports
  `ProfessionalLicense.profession_code` as `CodedValue` objects and
  `WaterUseAuthorization.authorized_water_quantity` as `QuantityValue`
  objects. Relationship-valued lists, identifiers, nested class shapes,
  polymorphic ranges, cycles, explicit targets and selected target entities
  remain refused. Existing single-valued projections, Actions, access grants
  and runtime behavior are unchanged.
- BREAKING: generated text columns and indexes use PostgreSQL's built-in
  `pg_catalog.pg_c_utf8` collation, and the managed-catalog fingerprint is
  stable across PostgreSQL 17 and 18. PostgreSQL 17 is now the minimum for
  runtime, spatial provisioning, migration receipts, and schema-test receipts.
  A non-UTF8 database, an unvalidated PostgreSQL 18 NOT NULL constraint, or a
  managed text collation that differs is refused with recovery guidance.
- Immediate Action row policies grow linearly with the number of effects, and
  each distinct target row is loaded and locked once during execution and
  replay authorization. Unchanged policy definitions retain their PostgreSQL
  catalog identity; exact catalog verification still refuses a policy changed
  without updating its compiler marker.
- BREAKING: a Review result from Registry Casework names the policy outcome
  it settled on, and BReg reads it. Upgrade Casework and every review
  producer, including BReg, in the same release. A 0.41 BReg refuses an
  approved result that names an outcome, and this BReg refuses a 0.41
  approved result that names none; either way an approved Proposal stays
  `submitted` until both sides are upgraded.
- BREAKING: an event with no compiled delivery is bounded at 1 MiB, the
  Version 1 signable bound, instead of 2 MiB, and a larger one is refused
  when it is recorded. The runtime logs the envelope size and bound with the
  fix: project fewer or smaller fields into the event.
- The Rust client's `verify_webhook` delegates to the shared hooks receiver.
  Invalid delivery time, duplicate signed header, oversized body, and
  undersized key failures now have distinct codes and messages that name the
  input to fix without rendering it. A signed header that is not visible ASCII
  is refused as `malformed-signature`.
- A Proposal prepared without an optional input serves its review context:
  an `input` field whose input was omitted reads `null`, and so does a
  `record` field whose optional reference input was omitted or whose
  optional Record field is empty, as the published context schema already
  declared. The review-context read refused such a Proposal before.
- The Rust, Node.js and Python clients refuse a Proposal transition whose
  link is unavailable with a message naming the link's `reason` and
  `recovery`, for example `reason pending-review, recovery refresh` for an
  Apply prepared before the Review is decided. The refusal kind stays
  `invalid-request`; only the message changed from the generic "contract or
  attempt is invalid".
- The runtime logs one warning when the review authority refuses a review
  handoff for good and BReg records it `remote-refused`. The warning names
  the authority, the HTTP status and the Problem code, never the Proposal or
  its values, and tells the operator to check the review producer
  configuration and its grant; the Proposal reads `review-ended` with
  recovery `revise`.
- A rejected or applied Proposal keeps its `reviewStatus` link, so a client
  that follows links can still read the retained review result. The link was
  offered only while the Proposal was `submitted`, although the read itself
  served the result after a decision.

- BREAKING: retention windows other than the audit journal's live in a
  top-level `retention` block, the shape Scheduling and Messaging use.
  `idempotency.receiptRetentionDays` becomes `retention.receiptRetentionDays`
  and `eventDelivery.payloadRetentionDays` becomes
  `retention.hookPayloadRetentionDays`, the name Scheduling uses for the same
  hook payload window; defaults and bounds are unchanged, and
  `audit.retentionDays` stays where it is. Each old key, and each old
  `idempotency` or `eventDelivery` block, is refused with `config.removed-key`
  naming the new path. Before:

  ```yaml
  idempotency:
    receiptRetentionDays: 7
  eventDelivery:
    payloadRetentionDays: 7
  ```

  After:

  ```yaml
  retention:
    receiptRetentionDays: 7
    hookPayloadRetentionDays: 7
  ```

  Migration: move both keys into one `retention` block and delete the old
  blocks; the values stay as they are.

- BREAKING: a `taskGrantStatus` entry names its status resource
  `statusResource` (was `caseworkResource`), since any task authority, not
  only Casework, can answer grant status. The old key is refused with
  `config.removed-key` naming `statusResource`. Migration: rename the key;
  the value stays as it is.

- `GET /v1/proposals/{id}/submissions/{version}` reads one submitted
  version of a Proposal under Proposal Get authority: its frozen effect
  digest, its review result, and its application status as separate members,
  with `current` marking the latest version. A profile holding the supplemental
  `get-application-actor` Proposal operation receives the stored keyed
  `appliedBy` pseudonym and `appliedAt` on this read and Proposal Get. Both
  remain absent from Proposal List and from reads without the operation. No
  response carries the raw issuer or subject. Once neither the review result nor the application
  receipt is retained, the read answers 410 `proposal.submission_expired`.
  A non-canonical or unknown version is concealed like an unknown Proposal.
- Published Proposal schemas now reject a decision `publicReason` that is
  whitespace-only or contains control characters, matching the client
  contract for reviewer text.
- BREAKING: the Proposal list takes `limit` (1 to 100, default 50) for its
  page size and refuses `top` with `query.invalid` naming `limit`. An
  ingestion run listing takes `cursor` and answers `nextCursor`, and refuses
  `after` with `query.invalid` naming `cursor`. Both refusals come after the
  caller's authority is checked, so an unauthorized caller still sees
  concealment. Record, metadata, statistics and GIS lists keep `$top` and
  `$skiptoken`. The Rust `BRegProposalQuery.top` field is `limit`;
  `BRegIngestionRunListQuery::after` is `cursor` and
  `BRegIngestionRunPage::next_after` is `next_cursor`; the Node.js and Python
  clients take `cursor` and return `nextCursor`.
- `bregctl dev` pulls the same pinned PostgreSQL image from Docker Hub after
  ECR Public throttled hosted development journeys. Existing owned containers
  at the prior exact ECR reference remain valid.
- BREAKING: projects declare `recordTypes` and Actions. Immediate Actions
  commit their plan in one transaction; durable Proposals freeze the same plan
  for inspection, optional Review, and independently authorized application.
  The old entity-backed change-request model and its routes are removed.
  Build packages from the current project format and apply them to a fresh
  database. This baseline provides no compatibility layer or state migration
  for the removed contracts.
- BREAKING: Rust, Node.js and Python clients use standalone Proposal methods.
  In Node, `immediateActions` and `selectImmediateAction` become `actions` (with
  a declared mode) and `selectAction`; Action `contractFingerprint` becomes
  `revision`, and BReg-owned `Entity` identifiers become `RecordType` identifiers.
  Replace lifecycle methods with `startProposal`, `prepareProposal`,
  `executeProposal` and `recoverProposal`; replace request attachments with
  `uploadProposalAttachment`, `downloadProposalAttachment` and
  `deleteProposalAttachment`. Request history is replaced by explicit
  `getProposal` and `listProposals` observations. Rust and Python expose the
  corresponding snake-case methods. Recovery requires a fresh authorized
  Proposal read. See the [Node client](../../crates/registry-breg-client-node/README.md#standalone-proposals)
  and [Python client](../../crates/registry-breg-client-py/README.md#standalone-proposals)
  for the replacement flows.
- BReg metadata uses version 2 and describes each profile's Proposal operations,
  readable inputs and governed document-slot requirements. The client refuses
  older metadata versions; regenerate packages and update clients together.
- Review context can project a declared supporting document without granting
  ordinary Proposal Get. Downloads use the frozen submission's bytes and
  recheck current context disclosure, verification and retention. Review status
  exposes the accepted provider `requestId` for independently authorized
  history and notes reads; human context does not expose that ID.
- `bregctl dev` seeds and retained example results use `recordType`. Removed
  authoring keys name their replacements, and model inspection includes each
  field's compiled `fieldType`, including fields absent from query projections.
- Review policies select the provider's current policy by ID by default. An
  optional complete version and digest pin requires an exact policy. Once
  accepted, a Review keeps its exact policy and frozen submission identity
  across retries and recovery.
- Filtered, sorted lists use declared indexes under `recordTypes[].indexes`.
  The compiler appends the record ID to each index, so an index accepts at
  most 31 authored fields. Source views allow the PostgreSQL planner to reach
  those indexes while row-level security continues to enforce disclosure.
  Index fields matching equality filters followed by the sort field support
  indexed continuation; a range or `in` filter on a leading field can still
  require a sort for each page.
- `bregctl dev` requests local client tokens for the resource that
  `issuer.clientResources` assigns to that client. Previously, startup requested
  every token for the owner BReg audience, so an owner that registered a client
  for another local product refused its token and could not start.
- `bregctl dev` accepts a development issuer's RS256 verification key only
  when the published key declares `use: sig`, lists `verify` alone if it lists
  `key_ops`, and carries no private member. The pinned ThunderID 1.0.1 issuer
  publishes such keys, so an existing local session starts as before.
- BREAKING: a Proposal lifecycle event's `subject.recordReference` is the
  Proposal's resource path, `/v1/proposals/{id}`, instead of a hashed
  reference. Record events keep their hashed reference. A receiver that
  matched Proposal events by the hashed value matches the path instead.
- BREAKING: `applicationStatus.recovery` is `retry` or `correct-input`.
  The never-emitted `refresh` and `receipt-only` values are removed from the
  schema and from the Rust `BRegApplicationRecoveryHint` and Node.js types;
  a document carrying either is refused as malformed. Apply, Retry and Revise
  link availability keeps both values.
- BREAKING: under required Review, `applicationStatus.state` reads
  `awaiting-review` until an approved result exists, in both application
  modes. `application-refused` now means only that an executor refused the
  frozen effects. A changes-requested or provider-ended Review is reported by
  the `apply` link's availability as `review-changes-requested` or
  `review-ended`, each with the new recovery `revise`. `applicationStatus.recovery` no longer lists the never-emitted
  `terminal`. The Rust, Node.js and Python clients and the generated project
  SDKs accept the new values; update clients with the server.
- BREAKING: a Review that rejects a Proposal's current submission ends the
  Proposal. It moves to the terminal state `rejected` in the transaction that
  records the result, with a `rejected` lifecycle event whose `authorityKind`
  is `review`. Submit, Edit, Revise, Rebase, Apply, Retry and Cancel answer
  409 `proposal.rejected`, including after a package activation changes the
  Action revision, and each command link reads `review-rejected` with
  recovery `receipt-only`. An attachment upload or removal is an Edit and
  answers the same with either attachment storage. The OpenAPI documents
  declare 409 on every Proposal command and attachment write.
  `applicationStatus.state` reads `rejected`. A changes-requested result keeps
  the Proposal `submitted` and revisable and records a `review-returned`
  event. Proposal `state`, event `transition` and `authorityKind`, and the
  Rust, Node.js and Python client types accept the new values. Migration: a
  client that waited for Revise after a rejection starts a new Proposal
  instead; a receiver that switches on `transition` or `authorityKind` adds
  the new values.
- BREAKING: every Proposal document and lifecycle event carries `turn`:
  `party`, `official` or `nobody`, whose move the Proposal waits on, derived
  when it is read and never stored. `turn` is required in the Proposal
  document and Proposal event schemas. `GET /v1/proposals?turn=party` (or `official`, `nobody`) lists only
  Proposals with that turn, and `state=rejected` lists rejected ones; any
  other value is concealed like every malformed list query. A page may hold
  fewer than `limit` items, so keep paging while `nextCursor` is present.
  The Rust `BRegProposalQuery` gains `turn`. Migration: a receiver that
  validates Proposal events against a pinned copy of the schema refreshes it.
- Proposal Get, each Proposal in a list, and the per-version submission read
  carry `decision` once the reviewer decided the submission: `status`,
  `decidedAt` and, when the reviewer wrote one for the subject,
  `publicReason`. It is read through the review protocol's result type, and
  the public reason is the only reviewer text BReg serves. A read that serves
  a public reason records a fixed `proposal-review-public-reason` marker in
  its audit entry, never the text. Lifecycle command responses omit
  `decision`.
- The `apply` link's availability tells the truth about Reviews that cannot
  approve the current submission: an approval past its `availableUntil`, an
  `answered` result, and a review submission that failed for good read
  `review-ended` with recovery `revise` instead of `pending-review` with
  `refresh`. While delivery or result lookup is failing it reads
  `dependency-outage` with recovery `retry`. When Revise is the recovery, the
  Retry link reports the same reason instead of `invalid-input`.
- BREAKING: Apply, Retry and Revise link availability no longer lists the
  never-emitted recovery `terminal`. It is removed from the schema, the Rust
  `BRegRecoveryHint`, and the Node.js and Python types; a document carrying it
  is refused as malformed. Migration: drop any `terminal` branch; a rejected
  Proposal reads `receipt-only`.
- The Rust, Node.js and Python clients read one submitted version with
  `read_proposal_submission` (`readProposalSubmission` in Node.js), which
  follows the Proposal's self link and decodes `decision`, and a lapsed
  version's 410 `proposal.submission_expired` as a Problem. The client
  capability inventory names it and the `limit` and `turn` list options.
- The per-version submission read's 410 audits a result count of zero, not a
  one-record read.
- BREAKING: `bregctl explain lifecycle` answers
  `breg/lifecycle-explanation/v1alpha6`, which adds the `rejected` state, the
  `reject` transition from `submitted`, and its `review-authority-result`
  enforcement. `bregctl explain events` answers
  `breg/events-explanation/v1alpha6`, whose Proposal transition selection adds
  `rejected` and `review-returned`; a Proposal hook may select either.
  Migration: select the `v1alpha6` schema for both formats.
- `bregctl dev` verifies the webhook deliveries it receives with the shared
  hooks receiver, the verifier the clients use, and keeps only its local
  checks of content type, event id, time, generation and attempt.
- Cancel, and Revise or Rebase of a submitted Proposal, close the Proposal's
  queued, applying or blocked automatic application job in the same
  transaction, so the job reads `cancelled` instead of remaining inert queued
  work the worker can never claim. Installation widens the job state check on
  an existing database.
- The Python client exposes `verify_webhook_delivery`, the shared Rust webhook
  verifier the Node client already offers, with keyword-only `method`, `path`,
  `headers`, `body` and `key`. Refusal raises `BaseRegistryClientError` with
  kind `webhook-verification`. The durable receiver example verifies with it
  instead of its own HMAC code.
- BREAKING: `bregctl doctor` names why a database connection was refused:
  `startup.database.unreachable`, `startup.database.capacity-exhausted`,
  `startup.database.tls-refused`,
  `startup.database.authentication-refused`, `startup.database.missing`,
  `startup.database.timeout`, `startup.database.configuration-refused`, or
  `startup.database.secret-refused`, replacing `startup.database.connection-refused`.
  Missing or extra managed schemas, tables, views, sequences, functions, and indexes, and a
  removed unique constraint, required column, or required column's `NOT NULL`
  marker, report `startup.database.catalog-drift` and name up to 64 affected
  identifiers instead of `startup.database.unready`. After each repair, rerun `doctor` to find any
  remaining drift. Automation that matches the earlier codes must match these.
- BREAKING: `bregctl package` and `bregctl check --production` refuse a
  `canonicalBaseIri` in the reserved `.invalid` namespace, such as the one
  `bregctl init --from` writes, as `breg.registry.canonical-base-iri-reserved`
  at `project.project.canonicalBaseIri`. `breg` and `bregctl apply` refuse a
  package that carries one unless its database was initialized for the
  `local` environment, as `bregctl dev` initializes it: `apply` reports
  `apply.package.deployment-identity-refused` and `doctor` reports
  `startup.package.refused`. Point `canonicalBaseIri` at a hostname you
  control, rerun `schema-test`, and rebuild the package.

- `authentication.oidc.allowInsecureHttp: true` permits plain HTTP beyond
  loopback to the configured issuer and to a JWKS URI declared in
  `jwksSource`. Without it, an HTTP issuer or key URI outside loopback is
  refused. While it is set, `breg` logs a startup warning and `bregctl doctor`
  reports the `authentication.insecure-http` warning advisory, in its JSON
  `advisories` too. The doctor report heads its advisories `Advisories:`
  (was `PostgreSQL advisories:`), since they are no longer only PostgreSQL's.

- Unlike the token-verifying runtimes, `breg-review` gains no
  `allowInsecureHttp` setting: it sends its client credentials to the
  issuer's token endpoint, so it signs people in only with an HTTPS issuer,
  or a loopback one under `listener.tlsTermination: development-loopback`.
  `signIn.allowInsecureHttp` is refused as an unknown key, and a plain HTTP
  issuer beyond loopback is refused at `breg-review check` with
  `breg.review-runtime.plain-http-endpoint`.

## 0.41.0 - 2026-10-13

- BREAKING: the published `registry-stack-client` Python package, which carries
  the Base Registry Engine client, requires Python 3.11 or later: its
  `Requires-Python` is `>=3.11` (was `>=3.10`), and its wheels are built
  against the Python 3.11 stable ABI and named `cp311-abi3` (was `cp310-abi3`).
  Python 3.10 is no longer supported. Migration: run Python 3.11 or later.

- BREAKING: the published `@registrystack/client` Node.js package, which
  carries the Base Registry Engine client, requires Node.js 24.11.0 or later:
  its `engines.node` is `>=24.11.0` (was `>=22.12.0`). Node.js 22 is no longer
  supported. Migration: run Node.js 24.11.0 or later.
- BREAKING: revision history no longer reads a revision journaled under an
  immediate action's effect identifier. The detail read of such a revision,
  and any list page that includes it, answer `503 source.unavailable`, whether
  or not the active package still declares that effect. Only v0.38.0 and
  earlier journaled an action's revision this way; every release since
  journals it under the entity's canonical operation identifier, such as
  `records.person.create`, and v0.40.0 serves only a database a v0.40.0 apply
  created. A database v0.40.0 created needs no action. Rows an earlier release
  wrote are not read in place: apply to a new database, as v0.40.0 already
  required.
- BREAKING: a database without the subject access-log storage is no longer
  verified or served. v0.38.0 introduced the storage, and every apply since
  installs it whether or not the package declares `accessLog`; a database
  last applied by an earlier release was served without it, until its next
  apply, as long as its package declared no `accessLog`. Startup now refuses
  such a database before binding a listener and writes nothing: with separate
  roles it answers `the Registry runtime role is missing grants the active
  package gives it`, and with one role `the Registry database is not ready
  for this package`. A database v0.40.0 created holds the storage and needs
  no action. A database last applied before v0.38.0 is not upgraded in place:
  apply to a new database, as v0.40.0 already required.
- Fixed actions accept omitted optional reference inputs on create and patch,
  consistently with optional scalar inputs. Supplied references still require
  an existing authorized target; explicit null and missing required inputs
  remain invalid. Handler reference restrictions are unchanged.
- Rust, Node.js, and Python metadata readers ignore unknown object members
  while retaining duplicate, type, required-member, and resource checks.
  Unsupported `requiredCapabilities` disable the affected executable binding
  without blocking supported operations. Immediate-action descriptors also
  recognize an optional must-understand capability list. Tombstone, batch,
  and lifecycle selection now report `required-capability`, where they
  reported `contract-mismatch`, when no selected operation carries
  capabilities the client understands.
- Well-formed unsupported metadata vocabulary now omits only the affected
  statistical dataset, descriptive change-request capability, selector, or
  spatial capability. An unsupported temporal mode keeps its `temporal`
  descriptor as served, because null already means the collection is not
  temporal. Supported siblings remain usable; malformed known fields,
  bindings, disclosure grants, and execution gates stay strict.
- Rust, Node.js, and Python clients handle valid unknown Problem codes by HTTP
  status and trace ID, with no inferred code or extension semantics. Known
  codes keep their exact validation; additive object members are ignored after
  duplicate checks. Malformed envelopes still refuse as protocol errors.
- The `immutable-identity-corrections` fixture demonstrates a required subject
  reference on creation and later description corrections using separate
  existing access profiles, with no subject-retargeting patch authority.
- `bregctl dev` compiles the captured project whenever it generates the local
  runtime and writes the compiled registry's one principal claim to
  `authentication.authorityClaims.principal`, where it always wrote
  `registry_principal`. A project whose entity profiles and action grants all
  name another claim, such as `principalClaim: sub`, now gets a local runtime
  that agrees with it; before, the engine refused that runtime because the
  configured principal claim was not the one the profiles require. A local
  client's token must carry the claim the project names; for `sub` that is the
  issuer's verified subject. A project with no authenticated grant keeps
  `registry_principal`, and a project whose grants all name
  `registry_principal` gets the same principal claim as before: no action is
  needed. An operated runtime is unchanged and still sets
  `authentication.authorityClaims.principal` itself.
- `bregctl dev` writes `authentication.authorityClaims.purpose`, as
  `registry_purpose`, only when a compiled access profile requires a purpose,
  where it wrote the member for every project. The engine accepts a purpose
  claim exactly when a profile requires one, so a project that requires no
  purpose now gets a local runtime the engine accepts. No action is needed.
- `bregctl dev` checks the generated runtime's authentication against the
  compiled registry before a first start retains the project's `.breg/dev`
  state, and refuses a project it cannot serve under one claim mapping:
  grants that name more than one `principalClaim` (the refusal lists them), a
  `principalClaim` of `scope`, and a `principalClaim` of `registry_purpose` in
  a project that requires a purpose. Each of these projects already failed
  later in the start, when the engine refused the generated runtime's claim
  mapping, so no project that started before is refused now. If affected, give
  every entity profile and action grant, including those a module contributes,
  one `principalClaim` that is neither the scope claim nor the purpose claim.
- BREAKING: the task-grant status check before a governed write, a later
  approval, or an application reports a 401 or 403 from the Casework status
  endpoint as an outage, so the request answers `service.unavailable` (503)
  where it answered `precondition.failed` (412): such an answer refuses the
  engine's own status credential, not the grant. A 404 still refuses the
  grant with `precondition.failed`. The check runs through the shared
  platform transport, which identifies itself with the user agent
  `registry-task-status` (was `registry-breg-task-status`) and bounds the
  whole attempt at ten seconds; the engine's own five-second bound on the
  check still ends it first. Migration: alert on `service.unavailable` for a
  misconfigured or revoked status client, and match the new user agent in
  Casework access logs.
- BREAKING: the runtime checks each `taskGrantStatus` entry when it reads
  the file, and refuses an invalid one as
  `breg.runtime.invalid-task-grant-status` at `/taskGrantStatus`, where only
  activation refused it, as `breg.runtime.invalid-binding`. The members are
  typed: `tokenEndpoint` is a URL; `clientId`, `clientAssertionAudience`,
  and `caseworkResource` are external identifiers (1 to 512 characters, no
  control characters), and `caseworkResource` is an absolute resource URI.
  `sourceIssuer` accepts an absolute URN issuer as well as a URL, since it
  is compared and never fetched. Migration: none for an entry the runtime
  already activated; a script that matched `breg.runtime.invalid-binding`
  for a malformed entry matches the new code.
- A `taskGrantStatus` entry takes the optional members `statusScope` and
  `statusPath`. Omitted, the engine requests the `casework:grants:status`
  scope and calls `/v1/task-grants/{grantId}/status` under `baseUrl`, as
  before. Set them only for a task authority that answers under another
  scope or route: `statusScope` is one scope token, and `statusPath` starts
  with `/` and holds exactly one whole `{grantId}` segment.
- A native `bregctl dev` fixture journey under a `sub` access profile may
  write `claims: {principal: "$localClientSubject"}`. The marker resolves to
  the selected local client's registered subject in the private captured
  project only; the authored journey file is unchanged. The marker is refused
  under any other principal claim and anywhere else in a journey.
- `bregctl dev` binds the Casework task-grant status services a
  `dev-clients.yaml` declares under `taskGrantStatus`, at most eight, each
  with its own status-only client on a numeric loopback endpoint, into the
  generated runtime. A machine client may declare `grants`, at most seven
  audiences each with 1 to 32 scopes that resource declares, to request
  ordinary tokens at other issuer resources; the grants change neither its
  primary scopes, its exported resource, nor its BReg admission. See
  `products/breg/DEV.md`.
- `bregctl dev start` pulls its PostgreSQL image from the Docker Official
  Images mirror `public.ecr.aws/docker/library/postgres` at the same
  digest, and its help names that reference. A session whose schema
  requires PostGIS still pulls `postgis/postgis` from Docker Hub. An egress
  allowlist for local development must admit `public.ecr.aws`. A retained
  session container on the Docker Hub `postgres:17.11` reference at that
  digest is still accepted.

## v0.40.0 - 2026-10-11

- The reviewed migration descriptor schema lists only the three change classes
  its semantic checker accepts. It refuses `compatible-additive` and
  `unsupported`, matching the existing `breg.migration.change-class` refusal;
  compiled package classifications remain unchanged.

v0.40.0 does not upgrade v0.39.0 state in place; apply to a new database.
Fresh installation creates the current schema directly, without conversion
or discard of earlier rows.

- The Rust, Node.js, and Python clients decode the caller-filtered
  `statisticalDatasets` metadata the runtime already publishes. Rust exposes
  `BRegMetadata::statistical_datasets()`, Node.js exposes
  `BRegMetadata.statisticalDatasets`, and Python exposes
  `BRegMetadata.statistical_datasets`. The decoder requires the closed
  dataset, dimension, calendar-period, digest, and operation shapes and
  retains accepted descriptions as inert metadata. It accepts `read-live`,
  `list-releases`, `read-released-series`, `read-latest-release`,
  `read-release-version`, `publish-release`, and `withdraw-release`. A
  release-only reader may receive the metadata with no entity or
  entity-operation authority. Upgrade a client that reads this metadata;
  no configuration or database migration is required.
- Record and GeoJSON continuation requests, responses, clients, and generated
  OpenAPI use the authenticated cursor codec's exact 10,978-byte ceiling. The
  previously shared 4,096-byte opaque-value bound could reject a valid
  server-issued cursor, including the observed 4,720-byte regression.
  Snapshot tokens retain their separate 4,096-byte limit, and a cursor of
  10,979 bytes is refused. Authenticated encryption, expiry, query binding,
  caller binding, and cursor encoding are unchanged. Rebuild and repin
  v0.40.0 packages because the generated OpenAPI change moves their revisions;
  DDL hashes and action and change-request fingerprints do not move.

- BREAKING: `bregctl` report `artifact`, `suggestedAction`, and baseline
  assurance words use kebab-case, such as `registry-project`,
  `correct-authoring-source`, and `runtime-bound`. Update report consumers;
  the selected artifact, corrective action, and assurance level are unchanged.
- BREAKING: `bregctl` operation and usage diagnostic codes use kebab-case
  segments, including closed codes copied from clients or planners. For
  example, `verify.runtime_config.path_invalid` becomes
  `verify.runtime-config.path-invalid`. Update code comparisons. HTTP Problem
  codes and decoded error classifications are unchanged.
- BREAKING: the migration ledger and `bregctl` status/reconcile reports write
  `compiled-additive` and `metadata-only`, where they wrote
  `compiled_additive` and `metadata_only`. The fresh ledger's constraints use
  these words; stored rows are not converted. Use a fresh database.
- BREAKING: the seven statistical operation names use kebab-case in generated
  OpenAPI, registry metadata, `/v1/registry`, and audit `operationId` values.
  For example, `read_live` becomes `read-live` and `publish_release` becomes
  `publish-release`. Rebuild packages and update metadata and audit consumers.
- BREAKING: a standing agent profile, one with `actorKind: agent` and no
  `taskGrant`, is refused when it holds `publish` on a statistical dataset,
  with `breg.access-profile.standing-agent-publish-forbidden`. Publishing and
  withdrawing a release commit at once, with no draft for a person to
  confirm. The unit entity profile of the publisher's id, which both
  operations are authorized through, meets the same rule when a module
  contributes it. Move `publish` to a profile a person or a service uses
  directly and rebuild the package: the runtime refuses to load one built
  with a standing agent publisher. `read-live` and `read-releases` stay
  available to a standing agent. No alias is provided.
- BREAKING: a governed action handler declares one ABI,
  `registry.action-handler/v1`. `registry.action-handler/v2` is no longer an
  accepted value. The action's own `evidence` declaration, and no longer the
  ABI identifier, is what lets a Rhai handler call `evidence::resolve` and
  what selects Evidence evaluation outside PostgreSQL, provider activation,
  the Evidence deadline, and the `503 action.evidence_failed` response in
  generated OpenAPI. To migrate, replace `abi: registry.action-handler/v2`
  with `abi: registry.action-handler/v1` in each action `handler`, keep the
  action's `evidence` block as written, and rebuild the package. A file that
  still declares `registry.action-handler/v2` is refused with
  `breg.action.handler-abi-invalid` at `actions[<id>].handler.abi`, and the
  message names the accepted identifier.
  `breg.action.handler-wasm-abi-unsupported` is removed, because a WASM
  handler has no second ABI to declare. `breg.action.handler-helper-contract`
  now reports an `evidence::` call in a handler whose action declares no
  `evidence`, and `breg.action.evidence-ceiling-invalid` now reports
  `evidence` on an action whose handler is not Rhai. A
  `registry.action-handler/v2` handler on an action with no `evidence` ran as
  an Evidence action with a zero-call ceiling; it is now an ordinary
  input-only action. Consuming Evidence from an action remains a trial.

- Runtime file flags use the help text "Runtime configuration file" and
  show `ABSOLUTE_FILE` wherever an absolute input path is required.

- BREAKING: the Rust, Node.js, and Python clients write eight error words in
  kebab-case (CFG-NAME-2): kind `invalid-request` (was `invalid_request`);
  the `protocol` codes `header-bounds`, `trace-context`, and `media-type`
  (were `header_bounds`, `trace_context`, `media_type`); the transport kind
  `response-too-large`; the token kinds `invalid-credential` and
  `scope-narrowed`; and the refused-token code `unregistered-error-code`.
  The codes RFC 6749 section 5.2 registers keep the specification's
  spelling. Migration: change what a consumer of a client error compares.
  No file an adopter writes changes.
- BREAKING: the Rust, Node.js, and Python clients write their own remaining
  eighteen words in kebab-case (CFG-NAME-2): the kinds `not-found`,
  `metadata-selection`, `lifecycle-promotion`, and `webhook-verification`;
  the `protocol` codes `entity-tag`, `profile-link`, `cache-policy`, and
  `representation-digest`; the `metadata-selection` codes `not-found`,
  `unbound-source`, `profile-mismatch`, `unsupported-operation`,
  `required-capability`, and `contract-mismatch`; the webhook verification
  codes `missing-header`, `malformed-signature`, `signature-mismatch`, and
  `unsupported-version`; and the attachment slot value kind `not-selected`.
  Each was the same word with an underscore. The Problem `code` the registry
  answers (`resource.not_found` among them) is unchanged. Migration: change
  what a consumer of a client error, a webhook verification refusal, or an
  attachment slot value compares. No file an adopter writes changes.
- BREAKING: `registry.yaml` opens with
  `apiVersion: id.registrystack.org/formats/breg/project/v1alpha1` and
  `kind: BRegProject`, and names the registry in a top-level `project` block
  (was `registry.registrystack.org/v1alpha1`, `RegistryProject`, and the
  `registry` block). The earlier header and block are refused by name.
  Migration steps are in `release/notes/config-conventions/breg.md` under
  "Stable move".
- BREAKING: `module.yaml` opens with
  `apiVersion: id.registrystack.org/formats/breg/module/v1alpha1` and
  `kind: BRegModule` (it had no header). A module without them is refused with
  `config.missing-envelope`. Module digests are unchanged. Migration steps are
  in `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: `runtime.yaml` writes
  `apiVersion: id.registrystack.org/formats/breg/runtime/v1alpha1` (was
  `registry.registrystack.org/breg-runtime/v1alpha1`). The earlier value is
  refused with `config.retired-api-version`. Migration steps are in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: each `bregctl explain` payload carries its own `apiVersion`,
  `id.registrystack.org/formats/breg/<format>/v1alpha4`, and a kind that opens
  with `BReg`, such as `BRegAccessExplanation` (all nine shared
  `registry.registrystack.org/breg-explain/v1alpha4` and wrote kinds such as
  `AccessExplanation`). The table of values is in
  `release/notes/config-conventions/breg.md` under "Stable move".
- Every `bregctl --format json` report opens with
  `apiVersion: id.registrystack.org/formats/breg/ctl-report/v1alpha1` and
  `kind: BRegCtlReport`, ahead of `ok` and `command`. The change is additive:
  the members a command already wrote are unchanged.
- BREAKING: a consent record states the longest a give lasts as
  `consentRecord.validity.maximumDurationDays`, a whole number of days from 1
  to 3652 (was `maxDuration`, an ISO 8601 duration text such as `P365D`), in
  `registry.yaml`, in `module.yaml`, in the compiled package, and in
  `bregctl explain access`. `maxDuration` is refused with
  `config.removed-key`. A duration in years, months, or weeks is written as
  the days it stands for, and the smallest duration is one day. Lock the
  project and rebuild the package after the edit. A package the previous
  release built states `maxDuration` and is refused, as a current package and
  as a predecessor. No stored row is rewritten. Migration steps are in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: a vocabulary under `manifestProjection.vocabularies` names the
  page that publishes it as `externalReference` (was `externalRef`), in
  `registry.yaml` and in the compiled package. `externalRef` is refused with
  `config.removed-key`. The rendered Registry Manifest keeps its own
  `external_ref`. Rebuild the package after the edit; no stored row changes.
  Migration steps are in `release/notes/config-conventions/breg.md` under
  "Stable move".
- BREAKING: a client listed under `authentication.oidc.assertionIssuers` in
  `runtime.yaml` names at least one issuer. `assertionIssuers: {kiosk: []}`
  is refused with `config.invalid-value` at
  `/authentication/oidc/assertionIssuers/kiosk`: remove the client, which
  then may exchange from no authority as before, or list its issuers.
  Migration steps are in `release/notes/config-conventions/breg.md` under
  "Stable move".
- BREAKING: `authentication.oidc.deniedKids` in `runtime.yaml` names at
  least one key or is left out. `deniedKids: []` is refused with
  `config.invalid-value`, and the refusal says to delete the member. A file
  with no `deniedKids` denies no key, as `[]` did. `bregctl init` and
  `bregctl dev` no longer write the empty list. Migration steps are in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: `attachmentStorage`, `attachmentVerification`, and
  `fieldEncryption.provider` in `runtime.yaml` name their variant in `type`
  (was `kind`), and the field encryption variant `localFile` is written
  `local-file`. The `kind` member is refused with `config.removed-key`, and
  `type: localFile` with `config.unknown-variant`. The other variant words
  are unchanged. Nothing stored changes.
  Migration steps are in `release/notes/config-conventions/breg.md` under
  "Stable move".
- BREAKING: the issuer key source names its variant in `type` (was `kind`):
  `authentication.oidc.jwksSource.type` in the engine's `runtime.yaml` and
  `resourceServer.jwksSource.type` in the `breg-mcp` runtime file. The words
  `discovery`, `uri`, and `static` are unchanged. The `kind` member is
  refused with `config.removed-key`, naming `type`. Nothing stored changes.
  Migration steps are in `release/notes/config-conventions/breg.md` under
  "Stable move".
- BREAKING: `runtime.yaml` reads the keys of `eventDestinations` as local
  identifiers and the client keys of `assertionIssuers` and `trustedActors`
  as external identifiers, and refuses a key that is not one with
  `config.invalid-value` at the key. No event destination key that was read
  before is refused. A client key that carries a control character is newly
  refused; an OAuth client identifier never does. Nothing stored changes.
  Details are in `release/notes/config-conventions/breg.md` under "Stable
  move".
- BREAKING: an access profile that writes no `principalClaim` is refused
  with `config.missing-key` when `registry.yaml` or `module.yaml` is read.
  The compiler already refused it, so no accepted project changes. The
  compiler keeps `breg.access-profile.principal-claim-required` for a claim
  written empty and no longer reports `breg.import.principal-required` or
  `breg.access.membership-authentication`. The published project schema
  lists `principalClaim` as required. Details are in
  `release/notes/config-conventions/breg.md` under "Stable move".
- An `entities` list that writes one `id` twice in a `registry.yaml` or a
  `module.yaml` is refused when the file is read, with `config.duplicate-id`
  at the `id` of the second item (was `breg.entity.id-duplicate` at the list,
  from the compiler). `breg.entity.id-duplicate` stays for an entity that
  more than one file contributes. No accepted project changes.
- `bregctl init` opens `registry.yaml`, `modules/record-notes/module.yaml`,
  and `runtime.example.yaml` with a `# yaml-language-server: $schema=` line
  naming the published schema of the file, so an editor checks the file with
  no setup. The line is a comment: the reader, module digests, and package
  digests do not see it, and an existing project needs no edit.
- BREAKING: `bregctl test --baseline-package`, `bregctl package
  --baseline-package`, and `bregctl diff` do not read a deployed package the
  previous release built as a baseline. It carries the retired package
  `apiVersion` and the retired spellings, and is refused before its sources
  are read, with `package.baseline.retired-api-version` or
  `diff.baseline.retired-api-version`, and `bregctl plan` and `bregctl
  apply` refuse the package as a predecessor. A history descriptor a database
  retained under the earlier bound names is refused when it is read. Build
  the package with this release and apply it to a new database.
- BREAKING: a field type writes its bounds as `minimumLength`,
  `maximumLength`, and `maximumBytes` (were `minLength`, `maxLength`, and
  `maxBytes`) in `registry.yaml`, in `module.yaml`, in the compiled package,
  in the registry metadata document, and in `bregctl explain` output. An
  earlier name in a project or module is refused with `config.removed-key`.
  JSON Schema keywords inside a structured field's `schema` and in the
  generated OpenAPI document are unchanged. Lock the project and rebuild the
  package after the edit. Action and change-request contract fingerprints,
  statistical dataset definition digests, and the Evidence export
  `behaviorRevision` hash the bounds under the names a project writes, and a
  fingerprint no longer hashes the `anonymous` member a permission once
  carried: every action and change-request fingerprint changes, with the row
  policies in the generated DDL that state it, and a consumer that pinned a
  `behaviorRevision` generates its Evidence source export again. No SQL
  migration runs. Migration steps are in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: `runtime.yaml` writes the event destination profile words in
  kebab-case: `networkProfile` is `production-https` or
  `loopback-development-http`, and `dnsFamily` is `dual-stack-strict` or
  `ipv4-only`. An earlier word is refused with `config.unknown-variant`. The
  stored binding digest of a destination is unchanged. Migration steps are in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: `runtime.yaml` renames eleven members to the shared spellings:
  `database.pool.maxSize` to `maximumConnections`,
  `authentication.oidc.maxTokenLifetimeSeconds` to
  `maximumTokenLifetimeSeconds`, `jwksCache.maxDocumentBytes` to
  `maximumDocumentBytes`, `jwksCache.requestTimeoutMilliseconds` to
  `attemptTimeoutMilliseconds`, `audit.retainDays` to `retentionDays`,
  `cursor.maxAgeSeconds` to `maximumAgeSeconds`, `wasmExecution.maxModuleBytes`
  and `maxGuestMemoryBytes` to `maximumModuleBytes` and
  `maximumGuestMemoryBytes`, and `timeoutMilliseconds` to
  `attemptTimeoutMilliseconds` under `fieldEncryption.provider`,
  `attachmentStorage`, and `attachmentVerification`. Values are unchanged. An
  earlier key is refused with `config.removed-key`. Migration steps are in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: `bregctl --format json explain lifecycle` spells the `id` of each
  of its twenty-one enforcement layers in lowercase kebab-case, such as
  `caller-authentication` (was `caller_authentication`). The table of values
  is in `release/notes/config-conventions/breg.md` under "Stable move".
- The `bregctl explain` contract schemas type the module, action, effect,
  consent organization, consent group, and lifecycle `id` members as
  `$defs/LocalId`. The registry project already holds these identifiers to that
  grammar, so no output changes.
- BREAKING: `bregctl --format json explain actions` and `explain routes` tag
  every union with `type` (was `kind`): a target `source`, an effect target
  `binding`, an effect field mutation and its `value`, and each entry of
  `routes[]`. An effect field value reads `from-input` or `from-effect` (was
  `from_input`, `from_effect`). The table is in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: `bregctl --format json explain actions` spells what it states
  about a handler, its evidence, and a requirement in lowercase kebab-case,
  such as `reads: supplied-inputs-only` (was `supplied_inputs_only`). The
  eleven values are in `release/notes/config-conventions/breg.md` under
  "Stable move".
- BREAKING: `bregctl --format json explain queries` names each of the eight
  members of `operations[].bounds` `maximum<Thing>`, such as `maximumPageSize`
  (was `maxPageSize`). The table is in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: `bregctl --format json explain actions` reports how long an
  accepted Evidence assertion is retained as `evidence.retentionDays: 1` (was
  `retentionSeconds: 86400`). The retention itself is unchanged.
- BREAKING: `bregctl --format json explain access` spells its own constants
  in lowercase kebab-case: each of the seven `claimContractError` values, such
  as `principal-claim-missing` (was `principal_claim_missing`), and, with
  `--scenario`, `mode: offline-synthetic` and `recordAccess: not-evaluated`
  (were `offline_synthetic`, `not_evaluated`). The table is in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: `bregctl --format json explain change-requests` tags six unions
  with `type` (was `kind`): a `planner`, its `declaringOrigin`, the `target`
  of each of its `possibleWrites`, an effect target `binding`, an effect field
  mutation, and its `value`. It writes `reserved-create`, `from-field`, and
  `from-effect` (were `reserved_create`, `from_field`, `from_effect`).
  `requests[].review` is unchanged. A Casework source imported from this
  output is imported again with the same release's `caseworkctl source add`.
  The table is in `release/notes/config-conventions/breg.md` under "Stable
  move".
- BREAKING: the access profiles a module writes on an entity
  (`module.yaml` `/entities/*/accessProfiles` and
  `/extendEntities/*/accessProfiles`) are read with the same rules as a
  project profile: `requiredScopes` is required (`unrestricted` or a list of
  at least one scope), `rowBoundaries`, `applyTargets`, and `requestPresence`
  take `unrestricted` or a non-empty list, and `[]` is refused. The published
  module schema states the member, and the project access findings
  `breg.access.profile-subsumes-narrower` and
  `breg.access.wildcard-spelled-item` also report a module profile. Migration
  steps are in `release/notes/config-conventions/breg.md`.
- BREAKING: an action permission in an access profile no longer accepts
  `rowBoundaries` (an action has no rows; the row reach of its targets is
  written on each target), and a statistical dataset permission must name its
  `dataset` as an identifier. Migration steps are in
  `release/notes/config-conventions/breg.md`.
- `bregctl check --format json` reports `status` (`complete`, `domain-refusal`,
  or `operational-failure`) beside `ok` and `command`, and `bregctl dev grant`
  JSON carries an empty `diagnostics` list. Both are additive.
- `runtime.yaml` `database` embeds the shared database block, so it accepts
  `trustedRootCertificateRef` (a secret reference to PEM root certificates that
  both the runtime and the migration connection trust in place of the platform
  roots) and `testOnlyPlaintext` (refused outside test builds as
  `breg.runtime.plaintext-database`, with the fix named). A malformed secret
  reference in `database` is now refused as `breg.runtime.invalid-database` at
  `/database` rather than as `config.invalid-value` at the member.
- BREAKING: `dev-clients.yaml` has a published JSON Schema, and `bregctl dev`
  decodes its identifiers, issuer and Evidence provider URLs, and mapping keys
  through the shared types. `issuer.exchangeIssuers[].mapping` is spelled
  `institutional-grant` or `first-party` (was `institutional_grant` and
  `first_party`), an identifier that starts with a digit is refused, and an
  issuer or `baseUrl` must be an absolute `http` or `https` URL. Migration
  steps are in `release/notes/config-conventions/breg.md`.
- `editors/configure.py` maps the JSON formats `*-binding.json` and
  `examples/scenarios.json` beside the YAML formats for VS Code and Zed.
- A reviewed migration descriptor has a published JSON Schema generated from
  the types its reader decodes,
  `products/breg/generated/tools/migration-descriptor.v1alpha1.schema.json`,
  and `editors/configure.py` maps `modules/*/migrations/*/descriptor.json`
  anywhere below the project directory to it for VS Code and Zed.
- BREAKING: `registry.yaml` and `module.yaml` are read by the shared
  configuration reader. A file that writes null, an unquoted number where text
  is expected (`version: 1`), an ambiguous number, or a YAML anchor, alias,
  merge key, or tag is refused, and source refusals carry the reader's codes
  in place of `source.yaml.invalid` and `source.environment_expression`. A
  package whose sealed sources carry such a shape must be rebuilt from a
  corrected source. A comparison literal (`equals`, `afterEquals`,
  `beforeEquals`) still accepts `null` as a record value; a list or a mapping
  there is refused by the reader as `config.invalid-type` rather than at
  compile time. Migration steps and the code table are in
  `release/notes/config-conventions/breg.md`.
- BREAKING: `runtime.yaml` is decoded by the shared reader. `breg` and every
  `bregctl` command that reads it report every problem in the file with the
  reader's code, path, line, column, and fix, and `breg` prints those
  diagnostics on stderr when it refuses to start. Runtime refusal codes the
  reader now decides (`runtime_config.document`,
  `runtime_config.governed_member`, `runtime_config.env_expansion`, and the
  file, envelope, and substitution codes) become reader codes, and
  `database.url`, `database.password`, and `database.plaintext` are refused as
  `config.removed-key`. The runtime file may be up to 1 MiB. The code table
  and migration steps are in `release/notes/config-conventions/breg.md`.
- BREAKING: `runtime.yaml` secret references and URLs are typed by the shared
  reader. A `*Ref` member that is not `secret:file/NAME` or `secret:env/NAME`,
  and a `publicOrigin`, Evidence provider `baseUrl`, or task-grant status
  `baseUrl` or `sourceIssuer` that is not an absolute `http` or `https` URL,
  is refused as `config.invalid-value` at the member. A task-grant status
  `sourceIssuer` written as a `urn:` was accepted and is refused, and
  `authentication.oidc.assertionIssuers: {}` is refused: delete the member to
  apply no assertion-issuer rule. Migration steps are in
  `release/notes/config-conventions/breg.md`.
- BREAKING: every integer member of `runtime.yaml` is refused outside the
  minimum and maximum the runtime schema states when the file is read, as
  `config.out-of-range` at the member, rather than after decoding as
  `runtime_config.invalid_bounds`, `invalid_oidc`, `invalid_oidc_leeway`,
  `invalid_audit`, `invalid_wasm_execution`, `invalid_binding`,
  `invalid_event_destination`, `invalid_attachment_storage`,
  `invalid_attachment_verification`, or `invalid_field_encryption` at the
  enclosing block. No value that was accepted is refused. A problem inside an
  `attachmentStorage`, `attachmentVerification`, or `fieldEncryption.provider`
  form is reported at its own member. The code table is in
  `release/notes/config-conventions/breg.md`.
- BREAKING: `registry.yaml` URLs and module digests are typed by the shared
  reader. A module lock `digest` that is not `sha256:` and 64 lowercase hex
  digits, and a `taskGrant.sourceIssuer` that is not an absolute URL, are
  refused at read as `config.invalid-value` rather than at compile as
  `module.lock.digest_invalid` and `access_profile.task_grant.invalid`. A
  Manifest projection `baseUrl`, `endpointUrl`, `accessUrl`, or `downloadUrl`
  that is not an absolute `http` or `https` URL without user information, or
  that is empty, is refused as `config.invalid-value`. The code table is in
  `release/notes/config-conventions/breg.md`.
- BREAKING: every integer member of `registry.yaml` and `module.yaml` states
  its minimum and maximum in the published schemas, and a value outside them
  is refused at read as `config.out-of-range` (or `config.invalid-value` at
  the field, for a string `maxLength` above 1000000, a decimal `precision` of
  0, and a CRS84 `precision` above 9) rather than at compile under a field,
  batch, attachment, statistical disclosure, or action evidence code. No
  value that compiled before is refused. The code table is in
  `release/notes/config-conventions/breg.md`.
- BREAKING: a list member of `registry.yaml` and `module.yaml` that is a set
  (access profile scopes, purposes, clients, operations, and field lists,
  read paths, access requirements, trusted intermediaries, change-control
  operations, effect `clear` lists, and hook projections and conditions)
  refuses a repeated item as `config.duplicate-item` instead of collapsing
  it. Delete the repeat to migrate. The member list is in
  `release/notes/config-conventions/breg.md`.
- BREAKING: `provenanceFields` on a permission or an entity access profile is
  read as a set: a repeated item is refused with `config.duplicate-item`
  where the file is read (was `breg.access-profile.provenance-fields-invalid`
  at compile). Delete the repeat to migrate. Its words are unchanged, the
  published schemas mark them as member names, and the project schema now
  lists the member on an entity permission. A module profile's
  `taskGrant.sourceIssuer` is read as a URL, as a project profile's is.
- BREAKING: every configuration diagnostic code is named
  `breg.<area>.<condition>` in kebab segments, such as
  `breg.access.profile-unrestricted-collection` for
  `access.profile.unrestricted_collection`. A runtime rule decided after
  `runtime.yaml` is read is reported as `breg.runtime.<condition>` by every
  command, with no `startup.`, `verify.`, or other command prefix, and
  `bregctl check` reports a refused package as `breg.package.<cause>` rather
  than `check.package.<cause>`. Codes that name a `bregctl` operation, HTTP
  problem codes, and the reader's `config.*` and `yaml.*` codes are
  unchanged. Replace each code a script or alert matches; the old-to-new
  table is in `release/notes/config-conventions/breg.md`.
- BREAKING: `bregctl check` reports in the diagnostic shape every Registry
  Stack check command shares. Its JSON report lists every error and warning
  under `diagnostics[]`, each with `severity`, a JSON Pointer `path`, a
  `source` naming the file, line, and column, and a `suggestedAction`
  sentence, in place of `findings[]` and `entities[id=...]` paths, and its
  human report prints `severity[code] file:line:column path` lines. A finding
  is a `warning`, `--deny-findings` is `--deny-warnings`, and a project,
  package, or runtime file the command cannot read exits 3 instead of 1.
  `bregctl check --runtime-config FILE` also checks a `runtime.yaml` offline.
  Migration steps are in `release/notes/config-conventions/breg.md`.
- BREAKING: a package's `package.json` declares `apiVersion:
  id.registrystack.org/formats/breg/package/v2` and `kind: BRegPackage`.
  `breg` and every `bregctl` command refuse a package with the retired
  `registry.registrystack.org/package/v2` header, as a current package and as
  the predecessor `--baseline-package` or a runtime file names, and the
  refusal names the current apiVersion. Rebuild the package from the migrated
  project with this release and apply it to a new database with `bregctl
  apply --initial`. Migration steps are in
  `release/notes/config-conventions/breg.md`.
- BREAKING: experimental statistical datasets in `registry.yaml` tag their
  period with `type: flow` or `type: stock` in place of `kind`, and a
  dataset `id` outside the local identifier grammar is refused when the
  project is read, as `config.invalid-value`, rather than by the compiler.
  Rename `period.kind` to `period.type`. Migration steps are in
  `release/notes/config-conventions/breg.md`.
- The project, module, and runtime JSON Schemas admit `null` only in a
  comparison literal, as the reader does, and declare no `default: null`. The
  project schema states its `apiVersion` and `kind` as constants, an embedded
  `schema` member carries `x-registry-foreign: json-schema-2020-12`, and the
  project and module schemas are published as
  `https://id.registrystack.org/schemas/breg/project/project.v1alpha1.schema.json`
  and `https://id.registrystack.org/schemas/breg/module/module.v1alpha1.schema.json`.
- BREAKING: the files `bregctl` reads and writes beside a registry project
  (fixture journeys, reviewed migration documents, backup bindings, and the
  other tool formats) follow the Registry Stack configuration conventions: a
  current header, kebab-case values, and the shared reader's refusals. A
  package carrying a reviewed migration that an earlier release built no
  longer loads; migrate its documents and rebuild it. An Evidence source
  export an earlier release generated is refused by `evidencectl source`;
  generate it again. Every change and its migration step is in the "BReg
  tool and output formats" section of
  `release/notes/config-conventions/breg.md`.
- BREAKING: the words that name a change between two compiled registries are
  written in kebab-case (CFG-NAME-2) in a reviewed migration `descriptor.json`
  (`changeClass`, `covers[].code`, `covers[].target.kind`, `recovery`), in a
  compiled package's `migrationPlan.changes`, and in the JSON and human
  output of `bregctl diff`, `plan`, `apply`, and `migration explain`:
  `data-backfill-required`, `access-or-disclosure-change`,
  `field-added-required`, `access-profile`, `exact-target-resume`,
  `lock-or-rewrite-risk`, `review-required`, `compatible-additive`,
  `role-change`, and the others, with the `checks` of `bregctl plan`
  (`migration-role`, `history-coverage`, and eight more). A descriptor in
  snake_case is refused with `config.unknown-variant` at the word, naming the
  kebab-case word. Rewrite the words in each descriptor, recompute the
  `planDigest` of its `rehearsal.json`, build the package again, and update
  what reads the commands' output. No stored word changes. The tables of
  every word are in the "BReg tool and output formats" section of
  `release/notes/config-conventions/breg.md`.
- BREAKING: a `${...}` substitution expression in a file `bregctl` reads as
  written (fixture journeys, schema-test credentials, model selection,
  development clients, example scenarios, migration descriptors, backup
  bindings) is refused with `config.substitution-not-allowed`; an earlier
  release kept it as literal text. Write the value, or in the credentials
  and development clients a secret reference, in its place. The same
  fragment section has the details.
- BREAKING: the nine `bregctl explain` output schemas take identifiers from
  the Registry Stack identifier catalog in place of their
  `registrystack.org/breg-explain/v1alpha3/<Kind>.schema.json` identifiers; a
  consumer that resolves them by `$id` replaces each old identifier with the
  new one the same fragment section lists. The schemas also state bounds,
  set uniqueness, and the digest pattern for what `bregctl` already writes;
  the output and its `apiVersion` are unchanged.
- `bregctl check --file <FILE>` checks one BReg tool file offline, chosen by
  its `kind`, without reading a secret, database, or network. It exits 1 on
  a refusal, or on a warning under `--deny-warnings`, 2 on a usage error, and
  3 when the file cannot be read.
- BREAKING: governed read routes refuse `HEAD` (#1902). axum answered `HEAD`
  on every `GET` route by running the whole read, writing a subject access log
  row, and journaling a `GET` the caller did not send. A `HEAD` now receives
  the concealed 404 a method the route does not accept already receives; under
  `/v1/statistics/` an authenticated caller's `HEAD` is journaled as a `HEAD`
  refusal. `/health`, `/healthz`, and `/ready` still answer `HEAD`. A client
  that sent `HEAD` to a record, history, statistics, attachment, GIS,
  ingestion-run, or discovery route must send `GET`.
- BREAKING: idempotency keys are per caller (#1912). A spent key is found by
  the configured OIDC issuer, the verified principal, and the key, in one
  scope every ordinary write shares, not per operation: a caller reusing a
  key on a different write route answers `409 idempotency.conflict`. Its
  request binding is an unkeyed SHA-256 digest, so rotating
  `audit.hashKeyRef` changes audit pseudonyms only: an exact retry after a
  rotation still replays and never executes again. The same key sent by
  another principal is that principal's own fresh request. A replay with an
  identical body but a different package, access profile, or claims still
  answers `409 idempotency.conflict`. Only successful responses are held, for
  the new `idempotency.receiptRetentionDays` (default 7, at most 365). An
  exact retry past that horizon answers the new `410 idempotency.expired` and
  is never executed. The new `bregctl idempotency-retention erase-expired
  --runtime-config PATH --before RFC3339` drops held responses past their
  horizon, with the raw issuer, principal, and key the spent-key table stores
  until then, and keeps each key spent by its digest: the same caller's exact
  retry still answers `410 idempotency.expired` and a changed retry `409
  idempotency.conflict`. The spent rows themselves are kept indefinitely; see
  `SECURITY-REVIEW-NOTES.md`.
- BREAKING: the caller-keyed idempotency store is a new engine capability, so
  a package an earlier release built no longer loads. Rebuild it with this
  release and apply it to a new database with `bregctl apply --initial`.
- The new database holds no idempotency record: a request the earlier
  release committed and a caller retries against this one executes again.
- Ingestion runs belong to the verified caller that created them, not to its
  audit pseudonym (#1930). A run stores the configured OIDC issuer and the
  verified principal, and listing, reading, chunk submission, receipt
  recovery, and cancellation compare those; the run's bound claim context is
  an unkeyed SHA-256 digest. Rotating `audit.hashKeyRef` no longer hides an
  open run from its creator, and another principal still finds none of it.
- BREAKING: no stored ingestion run is carried across, since a run the
  earlier release stored names no verified creator and this release starts
  on a new database. A `bregctl data import` checkpoint written against the
  earlier registry refuses to resume; import the data again under a fresh
  checkpoint path.
- BREAKING: `breg-mcp` and `breg-review` read `runtime.yaml` through the
  shared configuration reader, as
  `id.registrystack.org/formats/breg/mcp-runtime/v1alpha1` and
  `id.registrystack.org/formats/breg/review-runtime/v1alpha1`; the previous
  `apiVersion` is refused with its replacement named. In `breg-mcp`,
  `maxTokenLifetimeSeconds` becomes `maximumTokenLifetimeSeconds` (now at
  most 86400), `registry.requestTimeoutMilliseconds` becomes
  `attemptTimeoutMilliseconds`, `limits.maxRequestBodyBytes` becomes
  `maximumRequestBytes`, and `audit.retainDays` becomes `retentionDays`; in
  `breg-review`, `limits` becomes `rateLimits` and `audit.retainDays` becomes
  `retentionDays`. Each old key is refused naming its replacement. `check`
  reads no secret, takes `--format json` and `--deny-warnings`, and exits 0,
  1, 2, or 3. Migration steps and the code table are in
  `release/notes/config-conventions/breg.md`, section "BReg citizen services".
- BREAKING: a registry serves authenticated callers only. `anonymous` on an
  access profile in `registry.yaml` or `module.yaml` is refused when the file
  is read as `config.removed-key`, naming the fix, and every route except the
  probes and the review completion receiver refuses a request without a
  verified bearer token with `401 authentication.refused` before any profile,
  query, or record is read; such a request used to reach the route and could
  be served by an anonymous profile or answered `404`. The OpenAPI document
  lists `bearerAuth` only, the `breg_anonymous_refusals_total` metric is
  removed, the schema-test credentials file refuses `type: anonymous`,
  `bregctl explain` reports `breg-explain/v1alpha4` without the anonymous
  members, fifteen anonymous-only diagnostic codes are no longer reported,
  and a baseline package that granted unauthenticated access is refused.
  Migration steps are in `release/notes/config-conventions/breg.md`, section
  "BReg access".
- BREAKING: an access profile in `registry.yaml` says `unrestricted` or names
  what it restricts, and an empty list is refused when the file is read.
  `requiredScopes` is required on every profile and takes `unrestricted` or a
  list of at least one scope; `rowBoundaries` on an entity permission, an
  action target, an `applyTargets` entry, and a `requestPresence` entry takes
  `unrestricted` or a list of at least one row boundary. `requiredPurposes`,
  `requesterClients`, and the members of `accessRequirements` only narrow:
  omit one to apply no restriction, and `[]` or `unrestricted` there is
  refused naming that fix. Enforcement does not change and a rewritten
  project keeps its compiled revision. The findings
  `breg.access.profile-no-required-scope` and
  `breg.access.action-no-required-scope` are removed;
  `breg.access.profile-subsumes-narrower` and
  `breg.access.wildcard-spelled-item` are added. A module that declares
  `accessRequirements` without all three members gets a new digest. Migration
  steps are in `release/notes/config-conventions/breg.md`, section "BReg
  access".
- BREAKING: `authentication.oidc.allowedClients` in `runtime.yaml` is
  required and takes `unrestricted` or a list of at least one OAuth client.
  A runtime file that omits the member is refused at startup as
  `config.missing-key`, and `allowedClients: []` is refused as
  `config.invalid-value`; both used to accept a token from every client of
  the issuer, which is now written `allowedClients: unrestricted`. Token
  verification does not change. Migration steps are in
  `release/notes/config-conventions/breg.md`, section "BReg access".
- BREAKING: access to a statistical dataset is granted in each access
  profile's `permissions`, as `{dataset, operations}` with the operations
  `read-live`, `publish`, and `read-releases`. `live` and `releases` on a
  `statisticalDatasets` entry are refused when the file is read as
  `config.removed-key`, naming the new home. Exactly one profile may hold
  `publish` on a dataset, and the publisher and every `read-live` profile of
  a published dataset also write `read-releases`, which the release routes
  already served them. `breg.access-profile.permission-dataset-unknown`,
  `breg.statistical-dataset.publisher-multiple`,
  `breg.statistical-dataset.publisher-missing`, and
  `breg.statistical-dataset.read-releases-required` are added;
  `breg.statistical-dataset.profile-unknown` and
  `breg.statistical-dataset.releases-readers-empty` are removed. Enforcement
  does not change and a rewritten project keeps its compiled revision.
  `bregctl explain access` gains `statisticalDatasets`, the profiles holding
  each operation per dataset, in `breg-explain/v1alpha4`. Migration steps are
  in `release/notes/config-conventions/breg.md`, section "BReg access".

- `registry-breg-client` resends an idempotency-keyed mutation whose outcome
  is unknown, a timeout or broken exchange after sending or a 5xx answer, up
  to 2 times by default, with the same key, headers, and body. A caller that
  must not resend sets `with_max_mutation_retries(0)`. A call can now take up
  to three request timeouts plus the waits between them (250 ms, then 500 ms,
  or a `Retry-After` of at most 5 seconds). `is_outcome_unknown()` tells a
  caller whether a returned error may still have taken effect, in which case
  the recovery is the same request under the same key. The engine's
  `action.handler_failed` and `statistical_dataset.domain_violation` answers
  are rolled back before commit, so they are known outcomes and are not
  resent; neither is any answer with a 4xx status line.
- BREAKING: the hook delivery, review result, and attachment verification
  words the engine stores, audits, and reports are written in kebab-case:
  `bregctl webhook list` reports `dead-lettered` (was `dead_lettered`) and
  kebab-case dead letter reasons, the audit journal writes webhook outcomes
  such as `http-non-success` and dispositions `retry-pending`,
  `dead-lettered`, and `replay-pending`, and stored rows hold
  `hmac-sha256-v1`, `after-commit`, `dead-lettered`, and `changes-requested`.
  A database written by an earlier release is not migrated in place; start on
  a new database. The table is in `release/notes/config-conventions/breg.md`
  under "Stable move".
- BREAKING: every enumerated word is written in kebab-case, in `registry.yaml`
  and module files and in everything the engine writes: `submit-request`,
  `revise-request`, `cancel-request`, `apply-request`, `create-only`,
  `operator-erase`, `on-or-after`, `less-than`, `int-range`,
  `request-lifecycle`, `verified-claim`, `field-is-null`, `valid-from`,
  `as-of`, `is-null`, `from-field`, `reserved-create`, and the others. A
  snake_case or camelCase word is refused where the file is read. The HTTP
  metadata document and `x-registry-queryProfile` name the query bounds
  `maximumPageSize`, `maximumFilterClauses`, and `maximumInValues`, and the
  Rust client fields follow. `bregctl access preview` writes its refusal
  reasons in kebab-case. Rewrite the words, run `bregctl project lock`, build
  the package again, and apply it to a new database: a package or a database
  written by an earlier release is refused. Both tables of words are in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: an `id` outside `^[a-z][a-z0-9_-]{0,63}$`, and a mapping key
  outside the grammar of its position, is refused when `registry.yaml`, a
  module file, or `runtime.yaml` is read, as `config.invalid-value` at the
  line of the identifier (was `breg.identifier.invalid` from the compiler).
  The grammar is unchanged, so a project that passed `bregctl check` still
  passes. The published schemas type each `id` as `LocalId` and name the keys
  of each mapping. The table is in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: a union of `registry.yaml` and of a module file is tagged by
  `type`: a constraint, a predicate of a unique constraint, and an event
  condition (were tagged by `kind`), a selector of a change request Evidence
  subject (was tagged by `source`), and the review of a change request, which
  is `{type: required, authority, policyId}` or `{type: none}` (was
  `{authority, policyId}` or `{mode: none}`). The earlier form is refused with
  `config.missing-key` naming `type`. The review is written the same way in
  the package, the `x-registry-changeRequest` extension, the metadata
  document, a change request record, `bregctl explain change-requests`, and
  the Node.js and Python clients. Module digests and proposal digests change:
  run `bregctl project lock`, build the package again, and apply it to a new
  database. The table is in `release/notes/config-conventions/breg.md` under
  "Stable move".
- BREAKING: an access profile in `registry.yaml` groups its `permissions` by
  what each names (CFG-ID-7, CFG-SCHEMA-8): `permissions` is a mapping of
  three lists, `entities`, `actions`, and `datasets`, where it was one list
  whose entries were told apart by the member each carried. The members of a
  permission are unchanged. A list at `permissions`, `[]` among them, is
  refused when the file is read, with `config.invalid-value` naming the three
  groups, and a member that belongs to another kind of permission is refused
  with `config.unknown-key` where it is written. Five compiler diagnostics
  that refused a permission naming both an entity and an action, or neither,
  are removed with the shape they refused. The compiled model does not
  change: the registry revision, every `bregctl explain` report, and every
  generated output are the ones the list compiled to. A module file is not
  affected. Move each permission under its group, and build the package
  again: its digest changes. The tables are in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: the handler of an entity hook and of a governed action is tagged
  by `type` (CFG-ID-7), where it was tagged by `kind`:
  `handler: {type: url, destinationId: <id>}`, `type: rhai`, `type: wasm`, in
  `registry.yaml` and in a module file. A handler written with `kind` is
  refused when the file is read, with `config.removed-key` naming `type`, and
  the compiler refusals that pointed at `handler.kind` point at
  `handler.type` under their unchanged codes. The planner of a change
  request, the compiled handler in the package and in `bregctl explain
  actions`, and the stored `handler_kind` of a hook delivery keep `kind`.
  Rename the member, run `bregctl project lock` for a module you changed, and
  build the package again: its digest changes. The table is in
  `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: `null` is no longer a comparison value in `registry.yaml` or a
  module file. A change request precondition predicate and an action
  requirement state an unset value with `isNull: true` (was `equals: null`),
  and an event condition lists the field in `beforeIsNull` or `afterIsNull`
  (was `beforeEquals: {field: null}` or `afterEquals: {field: null}`). A
  `null` comparison is refused when the file is read, with
  `config.null-value`; `isNull: false` is refused with `config.invalid-value`.
  The compiled predicate is the one `equals: null` compiled to, and a module
  that never compared with `null` keeps its digest. Replace each `null`
  comparison, run `bregctl project lock` for a module you changed, and build
  the package again.
- BREAKING: the metric label values the registry defines are spelled in
  kebab-case. The `status` label of `breg_http_requests_total` and
  `breg_http_request_duration_seconds` is `client-error` or `server-error`
  in place of `client_error` or `server_error`, and so is the `status` field
  of the structured request log. The `state` label of
  `breg_pool_connections` reports `maximum-size` (was `max_size`), the `worker`
  label of `breg_worker_last_success_age_seconds` reports
  `attachment-verification` and `subject-access-log-retention`, and the
  `queue` label of `breg_queue_oldest_pending_age_seconds` reports
  `webhook-delivery`, `review-submission`, and `review-application`. Metric
  names and label names are unchanged. Migration: respell the label values
  in every dashboard query, recording rule, alert rule, and log filter. The
  table is in `release/notes/config-conventions/breg.md` under "Stable move".
- BREAKING: the thirteen webhook audit words that still carried an
  underscore are written in kebab-case. In a webhook delivery record of the
  audit journal, the `outcome` words `attempt_started`,
  `destination_resolution_refused`, `destination_transport_unavailable`,
  `payload_expired`, `replay_requested`, `replay_committed`,
  `replay_refused`, `replay_unfinished`, `discard_requested`,
  `discard_committed`, `discard_refused`, and `discard_unfinished`, and the
  `disposition` word `discard_pending`, are now spelled with hyphens
  (`attempt-started`, `discard-pending`). Records already written keep their
  spelling and nothing stored changes. Migration: a query, alert, or report
  that matches one of these words matches the new spelling for records
  written from this release on.

## v0.39.0 - 2026-10-06

- BREAKING: `bregctl dev` takes PostgreSQL loopback port 15432 on a first
  start, where it took 55432. On Linux an outgoing loopback connection could
  take 55432 as its own source port, and a first start then refused the port as
  occupied although nothing listened on it (#1870). A session that already
  started keeps the port it retained. Anything that connects to a new session's
  database by the old default needs the new port, or `--database-port 55432` on
  the first start.

- BREAKING: before 1.0, a release reads only the state its immediate
  predecessor wrote. This release reads state written by v0.38.0 and nothing
  older. If you run an older release, upgrade one release at a time and finish
  each release's upgrade steps before starting the next. The entries below
  remove what served only releases before v0.38.0.
  - `release/scripts/rehearse-upgrade.py` refuses to start from any release
    before v0.38.0.
  - Building the Base Registry Engine release image fails when no `bregctl` is
    staged beside the runtime.
  - Installing the webhook delivery tables (`registry_outbox`,
    `registry_webhook_deliveries`, `registry_webhook_delivery_state`) no
    longer upgrades tables written by builds older than v0.38.0. It no longer
    backfills `payload_expires_at`, `handler_kind`, `data_schema`, or the
    proposal columns, no longer replaces the legacy answer constraint, and no
    longer refuses pre-Version 1 webhook history with `pre-V1 webhook history
    requires explicit operator migration`. It still adds the dead-letter
    reason column and its constraint to a delivery-state table created without
    them. Registry Scheduling installs these tables once, on an empty schema,
    and is not affected.
  - Schema install no longer refuses or drops legacy review data
    (`registry_request_decisions`, and the request states `approved`,
    `needs_changes`, `rejected`, `canceled`). A database still holding such a
    state fails reads with the generic unavailable problem.
  - Schema install no longer upgrades review submissions that have no
    producer, or text feed-checkpoint cursors.
  - Schema install no longer upgrades revision, idempotency, request, review,
    attachment, ingestion-run, or field-encryption flip tables created before
    v0.38.0.
  - `bregctl project migrate` is removed. Declare the projection by hand as
    `manifestProjection.datasets[]` and `manifestProjection.dataServices[]`,
    each with an `id`, and point every entity's `primaryDataset` at one of
    them.
  - The retired package flags `--database-id`, `--baseline-runtime-config`,
    `--signature-threshold`, `--signature-key-id`, and `--signatures` are
    refused as unknown arguments (exit status 2) instead of with a removal
    message. Remove them from scripts.
  - `bregctl field-encryption keygen --out` is no longer accepted. Use
    `--output`.
  - `bregctl dev start --clients` is no longer accepted. Use `--clients-file`.
  - `bregctl dev start --mint-port` and `--mint-bin` are unknown arguments.
    Dev state version 1 is refused as invalid retained dev state and kept for
    inspection. Stop it with the release that wrote it, or move it aside, then
    start a fresh session.
  - Dev state that lacks `requiresPostgis`, `seedImportAuthorities`,
    `seedImportIntents`, or `binaries` is refused as invalid. Start a fresh
    session.
  - A `bregctl-data/v1` import sidecar is reported as
    `data.import.checkpoint.refused`, where it was
    `data.import.checkpoint.legacy`. Start the import again with a fresh
    checkpoint path.
  - A database that holds registry tables but no activation ledger is no
    longer adopted. Startup, `bregctl status`, `bregctl plan`, and `bregctl
    apply` refuse it with one generic refusal and change nothing. The codes
    are `startup.database.unrecognized`, `status.database.unrecognized`, and
    `apply.database.unrecognized`. The maintenance commands that bind the
    active registry refuse it as `<prefix>.active_registry.unrecognized`,
    where the suffix was `pre_ledger`. The codes
    `startup.database.pre_ledger`, `status.database.pre_ledger`,
    `apply.database.pre_ledger`, `apply.adoption.not_ready`, and
    `apply.adoption.fingerprint_mismatch` are removed, and `plan` and `apply`
    no longer report `adopted` as an `activation`. Upgrade the database one
    release at a time through v0.38.0 first. A database that v0.38.0 or an
    earlier release already adopted is unaffected.
  - `bregctl apply --acknowledge-retired-audit-discard` and the refusal code
    `apply.audit.retired_rows_present` are removed. Schema install has dropped
    the retired audit tables since v0.35.0, so a v0.38.0 database no longer
    holds them.
  - A `package/v1` package is refused like any other package this release
    cannot read: `plan` and `apply` report `apply.package.refused`, and the
    commands that inspect a package report `*.package.integrity_refused`. The
    dedicated `legacy_format` refusal that named `bregctl package` is gone.
    So is the physical-column catalog fingerprint that only those packages
    carried: catalog verification computes the named-column fingerprint
    only. Rebuild the package with a current `bregctl package`.
  - The removed project keys no longer have dedicated `*.removed`
    diagnostics. They are refused as `source.shape.invalid` (JSON) or
    `source.yaml.invalid` (YAML), naming the unknown field. The keys are
    `package.environment`, `package.instanceId`, `package.sequence`,
    `manifestProjection.dataset`, `manifestProjection.dataService`,
    `accessProfiles[].grants`, `entities[].events`, and
    `extendEntities[].events`.
  - The removed runtime configuration keys `package.trustAnchorPath`,
    `activeRevision`, `activeSequence`, and `compilerSourceRevision` are
    refused as `runtime_config.document`, naming the unknown field, where they
    were `runtime_config.package_key_removed`. A `${VAR}` reference in one of
    them is substituted before the refusal, so a reference to an unset
    variable is refused first as `runtime_config.env_expansion`, which names
    neither the key nor the variable.
  - `breg --config FILE` fails with the standard unexpected-argument error
    (exit status 2). Use `--runtime-config`.
  - `breg-mcp` refuses `resourceServer.jwks` and `audit.maximumFileBytes` with
    the generic unknown-field error and no longer names their replacements.
  - A package whose compiled action permission target lacks `operation` or
    `source` is refused when it is read. v0.38.0 writes both on every target.
  - `BRegPreparedLifecycle::from_slice` refuses version 1 prepared lifecycle
    evidence. Prepare the lifecycle again with a current client.
  - The Base Registry Engine client refuses served metadata whose operation
    omits `readableRequestFields`, where it treated that as an empty grant.
  - A package whose compiled model or query inventory serializes a temporal
    `scopeFields` is refused on a strict load. No release since v0.36.0 writes
    one. The authored `temporal.scopeFields` key stays accepted and deprecated
    in this release.
  - A predecessor package whose query temporal bindings lack `valueKind`, or
    whose compiled model or query inventory carries a temporal `scopeFields`,
    is refused with a derivation error. Rebuild and activate it with v0.38.0
    before you upgrade.
- BREAKING: statistical datasets add engine-owned immutable release storage
  to every package, changing every schema fingerprint. Rebuild the package
  with the active baseline and apply it once before starting the upgraded
  runtime. Root projects may declare count datasets with live read profiles,
  one publisher, and separate released-data readers. The API serves exact live
  counts and disclosure-controlled immutable JSON/CSV releases, with
  idempotent publication and atomic withdrawal. A withdrawn version's header
  omits `contentDigest`. Publication remains available after history erasure
  with an explicitly null snapshot bookmark until history is rebaselined. See
  `STATISTICS.md` for disclosure risks, definition series, and the seven HTTP
  operations.
- Derived SQL now accepts only explicitly reviewed raw PostgreSQL grammar
  nodes (#1841). `JSON_VALUE` and `JSON_EXISTS` remain available for scalar
  structured-field access; `JSON_QUERY`, `JSON_TABLE`, `XMLTABLE`, SQL/JSON
  aggregates and constructors, and XML functions are refused. Expressions
  inside accepted SQL/JSON functions receive the same relation, function, and
  encrypted-column checks as other derived SQL.
  Implicit `NATURAL`/`USING` joins and source/join column alias lists are refused
  because they can evade explicit column-reference checks.
  Cast targets are limited to reviewed built-in scalar types, and column names
  resolve against the compiler-known output of the exact source, CTE, or
  subquery range in each SELECT scope. Whole-row references, row constructors,
  attribute-notation function calls, arrays, catalog reference types, XML,
  money, and timestamp-with-time-zone casts are refused (#1855).
- Derived strings, decimals, and integers no longer silently truncate or round
  to their declared type (#1842). Generated views enforce string minimum and
  maximum length, text maximum length, decimal scale, precision and range,
  integer integrality and range, and vocabulary membership before casting.
  An invalid value raises a stable, value-free database error identifying its
  entity and field; API reads return the existing `503 source.unavailable`.
- BREAKING: derived-view wrappers are compiled DDL and belong to the managed
  catalog fingerprint. A project with these derived fields compiles to a new
  `registryRevision`; its earlier package fails artifact rederivation with the
  upgraded runtime. Starting the runtime changes no catalog or activation
  binding. Before switching the runtime, rebuild and test the authored project
  with the deployed package as `--baseline-package`, then package, plan, and
  apply its successor with the matching `bregctl`. Rehearsal may report
  `migration.rehearsal.baseline_fingerprint_drift` when reconstructing the
  predecessor with the new compiler. Successor activation replaces every
  retained compatible derived view, even when its authored SQL is unchanged,
  verifies the exact target fingerprint, and records the successor binding
  atomically. Existing import/export continuations keep their earlier package
  and fingerprint binding and must not resume under the successor. A project
  whose SQL uses newly refused constructs must revise that SQL before rebuilding.

- Immediate actions now advance the shared history commit head in the same
  transaction as their effects (#1856). Each distinct changed record joins
  one commit, including aliased patch effects. Latest snapshots and coverage
  rebaselines can therefore observe action writes. Replays and rolled-back
  actions allocate no commit. Existing unindexed action revisions are not backfilled by this fix and
  still cause coverage rebaselining to refuse. Rebuild affected pre-1.0
  development databases before using history snapshots or coverage rebaselining.

- Review-completion callback authentication refusals now return the registered
  `401 authentication.refused` problem and its catalogue type, title, and
  detail instead of the undocumented
  `review_completion.authentication_refused` code.
- BREAKING: a reviewed migration's `rehearsal.json` no longer carries
  `proofs`. Its `lockTimeout`, `chunkResume`, and `destructiveResume`
  booleans were written by the author and accepted only when they equalled
  values the descriptor already fixed, so they proved no lock-timeout or
  resume behavior. `test` and `package` refuse a receipt that still carries
  the member with `migration.review.receipt_proofs_retired`; remove it and
  regenerate the receipt. A package the previous release built with such a
  receipt is still read as the predecessor of the upgrade apply, and its
  `proofs` values are ignored; like every package the previous release built,
  it no longer loads as the active package. That acceptance is removed in the
  next release.
- `test` rehearses a reviewed migration's assertions and transactional steps
  under the lock and statement timeouts its descriptor declares, and a
  backfill step under its own, as activation does. The rehearsal used a
  fixed 5 second lock and 300 second statement timeout for every reviewed
  statement, so a migration activation would cancel could pass it.
- `bregctl test --fingerprint-only --runtime-config <file>` measures the
  schema fingerprint a fresh install of the candidate produces, the value a
  reviewed migration's `finalSchemaFingerprint` declares, and rolls back
  without running fixtures or writing a receipt, so `--credentials` and
  `--output` are not needed for it. Measuring the target used to take a full
  schema test on a separate disposable database. The
  `migration.review.fingerprint_mismatch` refusal names both the declared and
  the measured fingerprint.
- BREAKING: a background worker (webhook delivery, attachment verification,
  review, or subject access log retention) or the metrics listener that
  panics or returns before shutdown is requested ends `breg`: the process
  stops serving, drains within the shutdown grace, logs
  `Base Registry Engine stopped` with a closed
  `<task>.panicked` or `<task>.returned` code, and exits with status 1.
  Earlier releases kept serving without the task. `GET /ready` still does
  not reflect the workers. Run `breg` under a supervisor that restarts it on
  failure, such as an orchestrator's restart policy, systemd
  `Restart=on-failure`, or Docker `--restart on-failure`.
- A failed review worker iteration writes a warning with the closed code
  `review.worker.iteration_failed` instead of being discarded as an idle
  pass. The review result lookup outage warning carries the closed code
  `review.result_lookups.unavailable` and no longer carries an unavailable
  count.
- The attachment verification worker claims the next due job as soon as it
  finishes one, rather than waiting a second after every job, so a backlog
  drains at the verifier's pace. It still waits a second after a pass that
  found no due job or failed.
- The metrics listener publishes `breg_worker_last_success_age_seconds` by
  `worker`, `breg_queue_oldest_pending_age_seconds` by `queue` for webhook
  deliveries, review submissions, and application jobs, and
  `breg_active_package_info` with the `package_digest` this process verified
  at startup. A webhook delivery or review submission whose lease expired
  counts as waiting from the moment its lease expired. The attachment verification worker's age
  keeps growing while a job whose content read or verifier request failed
  waits for its retry. A scrape that cannot read the queues omits every
  queue sample and writes `metrics.queue_sample.failed`. Anyone who reaches the metrics
  listener can read the package digest.
- A migration lock another session holds is reported as an activation in
  progress, never as an unreachable database. `migration reconcile` reads the
  active identity without the lock, so its assessment reports `in_progress`
  where it refused with `migration.reconcile.active_registry.unavailable`, and
  `--execute` refuses with `migration.reconcile.outcome.in_progress`. `apply`
  and `plan` name the held lock instead of `database.migrationUrlRef`, under
  the code the next entry gives. `history erase`,
  `history rebaseline`, `field-encryption preflight`, and
  `field-encryption erase-history` report a lock held while they read the
  active identity as `<prefix>.active_registry.in_progress`, for example
  `history.erase.active_registry.in_progress`, with the suggested action
  `retry_after_migration_lock_releases`. An assessment opens no audit
  writer, so it answers when the audit destination cannot be written;
  `--execute` still refuses with `migration.reconcile.audit.unavailable`.
- BREAKING: `apply` and `plan` report a migration lock another session held
  past the lock timeout as `apply.database.in_progress`, with the suggested
  action `retry_after_migration_lock_releases`, where they reported
  `apply.database.unavailable`. Automation that matches
  `apply.database.unavailable` to detect contention must match
  `apply.database.in_progress`. A database that cannot be reached keeps
  `apply.database.unavailable`. `history erase`, `history rebaseline`, and
  `field-encryption erase-history` report a lock held when their maintenance
  transaction takes it as `history.erase.in_progress`,
  `history.rebaseline.in_progress`, and
  `field_encryption.erase_history.in_progress`, with the same suggested
  action, where they reported `history.erase.unavailable`,
  `history.rebaseline.unavailable`, and
  `field_encryption.erase_history.unavailable`. `evidence-retention
  erase-expired`, the `request-retention` commands, `import-authority open`,
  `close`, and `close-expired`, and `instance-claim adopt` report the same
  held lock as `evidence_retention.in_progress`,
  `request_retention.in_progress`, `import_authority.in_progress`, and
  `instance_claim.in_progress`, where they reported
  `evidence_retention.unavailable`, `request_retention.operation.refused`,
  `import_authority.unavailable`, and `instance_claim.unavailable`.
  Automation that retries those unavailable codes on contention must match
  the `in_progress` codes.
- `bregctl apply` and `bregctl plan` take `--expected-digest`, the
  `sha256:` package digest `plan` and `package` print. A package at
  `--package` with another digest is refused with
  `apply.package.digest_mismatch`, naming both digests, before any database
  contact, and nothing changes. A malformed value is a usage error. Without
  the flag, both commands behave as before.
- A configured active package that `package.expectedDigest` does not pin is
  refused with the sentence `verify` already gives, naming the pinned and the
  found package digests, by `apply`, `plan`, `migration reconcile`,
  `history erase`, `history rebaseline`, `field-encryption preflight`, and
  `field-encryption erase-history`. Each keeps its code, for example
  `apply.package.refused` at `package.root`; the message named neither
  digest before.
- BREAKING: `webhook list`, `replay`, and `discard`, the `request-retention`
  commands, the `import-authority` commands, and `evidence-retention
  erase-expired` refuse that package with the same sentence under
  `webhook.package.refused`, `request_retention.package.refused`,
  `import_authority.package.refused`, and
  `evidence_retention.package.refused` at `package`, where they reported
  `webhook.operation.refused`, `request_retention.operation.refused`,
  `import_authority.unavailable`, and `evidence_retention.unavailable` and
  named neither digest.

- An immediate action whose selected effects write fields that a locale
  collation orders differently from byte order, such as `award-number` and
  `awarded-by` under `en_US.utf8`, no longer answers
  `503 service.unavailable` (#1820). The generated row policy orders the
  written-field set with the `"C"` collation, so it matches the set the
  runtime binds on every database collation. The set of fields an action may
  write is unchanged.
- BREAKING: the policy is part of the compiled DDL, so a project that declares
  immediate actions compiles to a new `registryRevision`, and a package an
  earlier release built for it no longer loads. Action contract fingerprints
  are unchanged, so retained idempotent retries still match. Rebuild the
  package unchanged with this `bregctl package --baseline-package <deployed
  package>` and apply it; activation replaces the policy. A Registry Casework
  BReg source pins the old `registryRevision` and Casework startup refuses
  it: repin with `caseworkctl source add BREG_PROJECT --project PROJECT
  --source-id ID --apply`, then package, plan, and apply the Casework project
  once.
- A Registry that declares immediate actions indexes its stored action
  results by target entity, record, and revision, so revision history finds
  the action that wrote a revision without scanning every result under the
  2-second history statement timeout. The index is part of the managed
  catalog, so such a project's package records a new schema fingerprint. The
  rebuild with `bregctl package --baseline-package <deployed package>` that
  the `"C"`-collation entry above already requires picks it up: `bregctl
  test` reports the advisory `migration.rehearsal.baseline_fingerprint_drift`
  finding for it, and the apply installs the index. No extra step is
  needed. Until that apply, an upgraded runtime keeps verifying and serving
  the earlier catalog. A project that declares no immediate actions is unchanged, and
  removing a project's last immediate action removes the index.

- A hook proposal whose action commits effects at different revisions, such
  as a create beside a patch, records the same resulting revision on its
  delivery row on every database collation (#1836). The revision comes from the
  effect whose identifier sorts first under the `"C"` collation, so effect
  identifiers that a locale collation orders differently from byte order,
  such as `followup` and `follow-up-tally` under `en_US.utf8`, no longer
  change it, on the first application or on receipt recovery. Stored action
  results, the compiled DDL, and the managed catalog are unchanged, so no
  package rebuild is needed.

- `manifestProjection.vocabularies[].concepts` may label every code that any
  visible field of the vocabulary admits. Previously the compiler checked
  labels against only the last visible field it visited, so a field narrowed
  to fewer codes, such as a change-request field, refused labels for the
  vocabulary's other codes with
  `manifest_projection.vocabulary.concept_invalid`. The generated Registry
  Manifest codelist likewise carries the union of the codes its projected
  fields admit, in first-seen order, instead of the last field's codes. A
  label for a code that no visible field admits is still refused.
- BREAKING: when projected fields of one vocabulary admit different codes,
  the generated `generated/manifest/registry-manifest.json` changes, so the
  project compiles to a new `registryRevision` and a package an earlier
  release built for it no longer loads. Rebuild the package unchanged with
  this `bregctl package --baseline-package <deployed package>` and apply it. A Registry Casework BReg source pins the
  old `registryRevision` and Casework startup refuses it: repin with
  `caseworkctl source add BREG_PROJECT --project PROJECT --source-id ID
  --apply`, then package, plan, and apply the Casework project once.

- Authorized revision-history list and detail reads no longer answer
  `503 source.unavailable` for a record an immediate action created or
  changed. An action's revision is journaled under the entity's canonical
  operation identifier, such as `records.person.create`. A revision an earlier
  release journaled under the action's effect identifier stays readable, and
  keeps reporting that identifier, while the action that wrote it, as its
  stored action result records, still declares that effect against the same
  entity with the same operation. Another action declaring the same effect
  identifier does not keep it readable.
  Such revisions are not backfilled to the canonical identifier and no
  migration rewrites them: once a later package removes or renames that
  action or effect, or changes the effect's operation, that revision's detail
  read and any list page that includes it answer `503 source.unavailable`.
- BREAKING: `bregctl dev` pins a session on what it runs, not on how its
  files are spelled: the compiled registry revision, the package
  `sourceRevision`, and the canonical JSON form of `tests/journeys.yaml` and
  the clients file. A comment, blank line or key-order edit to a YAML file
  no longer counts as a changed input, so `dev start`, `dev examples run` and
  `dev prepare-source` accept it while the session holds records. Any edit
  to a Rhai script or WASM module, a comment included, still counts, because
  the compiled revision carries the digest of the exact bytes it ships. A
  `.breg/dev` session started by an earlier release holds the earlier pin and
  reads as changed inputs: with records retained, `dev start`,
  `dev examples run` and `dev prepare-source` refuse it, and `dev start` names
  `dev stop --remove`; after `--remove`, `dev start` replaces the session as
  for any edited project. Run `bregctl dev stop --remove` on such a session
  before starting it with this release; no command carries its records
  across.

- A record, list, lookup, relationship, attachment, access-log, revision, or
  snapshot read abandoned at the request deadline (`504 request.timeout`) now
  cancels its in-flight PostgreSQL statement and discards its session, as
  governed request actions already did. Previously the abandoned backend kept
  running while the pool opened a replacement, so under overload the number of
  runtime sessions rose past the pool's `maxSize`. The cancelled session now
  keeps its pool slot until PostgreSQL has stopped the statement, so the
  session count stays within `maxSize`. The read's audit attempt is still
  answered by exactly one `unfinished` response, and nothing the read
  collected is released.
- The review worker backs off a review authority's result feed after a failed
  fetch, waiting 1 second and doubling up to 60 seconds, and fetches it on
  every pass again after the first successful page. It warns once when a feed
  becomes unavailable and once when it recovers, and logs repeated failures at
  debug. Previously an unavailable authority was asked for its feed, and
  `BReg review result feeds are temporarily unavailable` was logged, about
  once a second.

- Correction to the v0.36.0 notes: `bregctl dev` does keep a package
  sequence, in that release and since. Its state starts the sequence at 1 for
  the first package and advances it by one each time
  `bregctl dev prepare-source` prepares a successor, and its reports carry it
  as `packageSequence` beside `packageDigest`.
- BREAKING: the WebAssembly executor builds Wasmtime without its default
  features, so a WASM action or hook handler module that uses GC types,
  exception handling, or `externref` is refused at compile time with
  `action.handler.module_invalid` or `hook.handler.module_invalid`. Modules
  that use linear memory, funcref tables, and indirect calls are admitted as
  before. Rebuild a guest that needs one of those proposals without it.
  Release binaries no longer link `wasmtime-internal-cache`, whose build
  script embedded the source commit.
- BREAKING: a build without the `wasm` feature refuses a WASM hook handler
  at compile time with `hook.handler.wasm_build_unsupported` at
  `entities[].hooks[].handler.kind`, as it already refuses a WASM action
  handler. Such a build compiled the hook and loaded its package, and the
  hook failed each time it fired. Package loading rederives through the
  compiler, so the build now refuses that package at load. Deploy a package
  with WASM hooks only on a build with the `wasm` feature, which default
  builds carry.
- A package whose project declares a change-request `planner` is accepted as
  a predecessor (#1814). Its packaged effective model records where the
  planner was declared as `declaringOrigin`, and the predecessor reader
  refused that member, so `bregctl test` and `bregctl package` refused the
  package under `--baseline-package` with
  `package.baseline.integrity_refused`, and `bregctl plan` and
  `bregctl apply` refused a database it was active on with
  `apply.package.refused`. No successor of such a package could be built or
  applied. The package format is unchanged, so packages already published
  need no rebuild.
- BREAKING: the `contains` and `prefix` text-search operators (`contains` and
  `startswith` in `$filter`) match without regard to case on string, text,
  and vocabulary-code fields, on current and snapshot reads (#1849). They
  matched case-sensitively. Matching follows PostgreSQL's locale rules,
  treats `%`, `_`, and backslash literally, and does not fold accents or rank
  results. An operand may be shorter than a string's `minLength` or name only
  part of a vocabulary code; it keeps the query literal size bound and the
  string or text `maxLength`, and a control character is refused. An empty
  term matches every non-null value the caller's read profile permits.
  `equals` and `in` keep exact, case-sensitive matching. A caller that relied
  on case-sensitive `contains` or `prefix` results must filter them itself.
- `bregctl check` names each unresolved field with its entity and its profile
  or constraint under `access_profile.field.unknown`, and reports the finding
  `access.profile.create_required_field_not_writable` at
  `entities[id=..].accessProfiles[id=..].writableFields[field=..]` when a
  direct `create` or `import` grant omits a required writable stored field,
  which no request through that grant can supply. Add the field to
  `writableFields` or remove the operation from the permission. The finding
  fails a check only under `--deny-findings` (#1849).
- A missing or malformed `Idempotency-Key` on an immediate action answers
  `400 request.invalid` naming the header in `fieldPath`, where it carried no
  `fieldPath`. The Rust, Node.js, and Python BReg clients expose the
  validated `fieldPath` of an accepted problem (`field_path` in Rust and
  Python), so a caller can identify the field or header that needs attention
  (#1850).
- The WebAssembly executor runs Wasmtime 48.0.5, which carries the fixes for
  RUSTSEC-2026-0325, RUSTSEC-2026-0326, and RUSTSEC-2026-0327 (#1853).
  Handler capabilities and the fuel and memory limits are unchanged.

## v0.38.0 - 2026-10-01

- Automatic review executors can renew credentials with `privateKeyJwt`.
  `bregctl review-recovery retry-application` requeues an `executor-denied`
  job after credentials or grants are corrected, while retaining its exact
  current approved proposal and idempotency key. Application conflicts and
  precondition refusals retry with a delay of 5 seconds up to 5 minutes.
- `bregctl dev` accepts explicit service-client `reviewExecutors` bindings for
  automatically applied requests and uses renewing local issuer credentials.
- Webhook destination validation refuses `localhost` and `*.localhost` under
  production and private-service profiles before startup. Dead letters retain
  a closed, value-free failure reason for operator inspection.
- `bregctl webhook list` remains available when retained work names a
  superseded binding. Operators can restore the exact binding or use the new
  audited, generation-bound `webhook discard` command to close eligible work
  without replaying it under the replacement binding.

- An entity may declare `accessLog` to keep a subject-facing log of reads of
  its records, stored apart from the operational audit. The record subject
  reads it at `GET /v1/records/{route}/{id}/access-log` under a profile that
  currently grants `get` for the record and whose verified principal equals
  the stored `subjectField`. `retentionDays` defaults to 90 and accepts 1
  through 3650. `trustedIntermediaries`, at most 64 verified client IDs, may
  forward the original requester and purpose in the
  `Registry-Access-Requester` and `Registry-Access-Purpose` headers, and
  `exemptions` delay a documented entry for a named profile without omitting
  it. A failed log insert refuses the read, and an access-logged entity
  cannot grant an anonymous profile any read. `bregctl generate
  evidence-source` writes protocol `breg-evidence-lookup-v2`, which changes
  the `behaviorRevision` of a regenerated source, and enables forwarded
  attribution for an access-logged entity. See
  [subject-facing access logs](ACCESS-LOG.md).
- An upgraded runtime and `bregctl` keep verifying and serving a database a
  release before subject access-log storage activated, without an apply. The
  next successor apply installs the storage.

- Publish `breg-mcp` and its paired `breg-review` service as release binaries
  and Docker images from v0.38.0.

- BREAKING: a direct create, patch, or batch item whose resulting row falls
  outside the caller's row boundary answers `412 precondition.failed` before
  any write, where it answered `503 service.unavailable` (#1771). The body is
  the same value-free problem a stale `If-Match` answers, retrying the
  unchanged request cannot succeed, and the refusal is audited as a refusal.
  A batch carrying one such item commits none of them, and an import item is
  refused as an item. A genuine PostgreSQL privilege failure still answers
  `503`. Handle a `412` on a create as a boundary refusal, not a retryable
  outage.
- BREAKING: the generated OpenAPI document lists `412 precondition.failed`
  on every create and batch operation reachable through a profile with
  `rowBoundaries`. The document is a packaged, byte-bound artifact that feeds
  `registryRevision`, so such a project compiles to a new `registryRevision`
  and a package an earlier release built for it no longer loads. Rebuild it
  unchanged with this `bregctl`: run `bregctl test PROJECT --baseline-package
  DEPLOYED --runtime-config FILE --credentials FILE --output RECEIPT`, then
  `bregctl package PROJECT --baseline-package DEPLOYED --test-receipt RECEIPT
  --output BUILD`, where `DEPLOYED` is the absolute directory of the deployed
  package, and apply `BUILD/package` with `bregctl plan` and `bregctl apply`.
  A Registry Casework BReg source pins the old
  `registryRevision` and Casework startup refuses it: repin with `caseworkctl
  source add BREG_PROJECT --project PROJECT --source-id ID --apply`, then
  package, plan, and apply the Casework project once.
- `bregctl dev` clients may declare `registry_purpose` as a list of the
  purposes that one client may use; the first stays the purpose of its
  ordinary dev token. Each authenticated journey step names an exact scope
  subset and, for a multi-purpose client, one declared `purpose`, and gets
  its own short-lived token under the same OAuth client. An undeclared scope
  or purpose is refused before `schema test`. When the clients file is read,
  dev refuses multi-purpose clients whose distinct token claims together,
  counting `registry_actor_kind`, `registry_purpose`, and `scope`, exceed
  16, and a multi-purpose client also listed on any authored exchange
  connection, `first_party` or `institutional_grant` (#1772).
- `bregctl dev` seeds and `schema test` journeys can load rows through an
  Import route with `operation: import`. Dev opens an exact one-item import
  authority bound to the item's digest, drives the production ingestion run,
  and closes the authority. An interrupted start resumes the same run, and
  one interrupted before it journaled the authority it opened recovers that
  exact one-item, zero-progress authority only when it opened no earlier
  than the intent dev saved before asking; any other open authority on the
  entity is refused by name and left to `bregctl import-authority close`
  (#1772).

## v0.37.0 - 2026-09-29

- BREAKING: a record or query `400` names the member or parameter at fault
  in `fieldPath`, where it carried none before. `detail` and `code` are
  unchanged. A create body names `/data` for a field the grant does not let
  the caller write, known or not, and `/data/<apiName>` for a missing
  required field or a wrong value of a writable one; a JSON Patch document
  names `/<n>`, `/<n>/op`, `/<n>/path`, or `/<n>/value`; a batch body names
  `/items`, `/changeContext`, `/items/<n>` and its fixed members, and the
  create and patch forms under them; a malformed `Idempotency-Key` names the
  header, and so does an `If-Match` header sent on a batch; and a
  `query.invalid` refusal names the parameter, such as `$select`, including
  the first read query option sent to a revision route, which takes none.
  An unknown and a withheld name answer the same problem and are
  never echoed. A client that rejects an unfamiliar problem member accepts
  `fieldPath` on `request.invalid` and `query.invalid`; the Rust, Node.js,
  and Python BReg clients do in this release, and a client that pins exact
  problem bodies drops `fieldPath` before comparing.
- BREAKING: a JSON Patch `test` of a field the grant does not let the caller
  read answers `400 request.invalid` at `/<n>/path` before the record is
  read, exactly like a `test` of an unknown field. It was refused only after
  the record was read, so a missing record answered
  `404 resource.not_found` and a stale `If-Match` answered
  `412 precondition.failed` first. Test only fields the grant lists in
  `readableFields` (`GET /v1/registry?accessProfile=<id>`), and handle a
  `400` on such a patch as a malformed document, not as a missing record or
  a stale revision.
- BREAKING: BReg refuses to compile a standing agent profile, one with
  `actorKind: agent` and no `taskGrant`, that holds `submit_request`,
  `revise_request`, `cancel_request`, or `apply_request`, with
  `access_profile.standing_agent.operation_forbidden`, or that holds
  `create` or `patch` on an entity without a `changeRequest`, or
  `import`, `tombstone`, or `batch` on any entity, with
  `access_profile.standing_agent.direct_mutation_forbidden`. A standing
  agent carries no human approval, so it may read and author
  change-request drafts while a human submits them; move the lifecycle
  operations to a profile the person uses directly.
- BREAKING: BReg refuses to compile a standing agent profile that holds an
  immediate-action permission, with
  `access_profile.standing_agent.action_forbidden`. An immediate action
  commits its effects at once, with no draft for the person to confirm, so
  a token carrying a trusted `act` no longer reaches any immediate action.
  Move the action permission to a profile the person uses directly.
- BREAKING: BReg refuses to compile a module that contributes an access
  profile declaring a `taskGrant`, whether on an entity it adds or on one it
  extends, with `access_profile.task_grant.module_forbidden`. Task-grant
  ceilings are checked only where grants are authored, in project
  `accessProfiles`; declare the task-grant profile there.
- BREAKING: BReg accepts an `act` claim of exactly `{sub, iss}` when `iss`
  equals the verified token issuer, as a token exchange writes it, beside
  exactly `{sub}`. A token whose `act.sub` is the trusted actor for its
  client is an agent token whatever its `registry_actor_kind` claim says,
  so it no longer satisfies a profile that declares `actorKind: human`.
- BREAKING: BReg admits a token carrying a trusted `act` only on an access
  profile that declares `actorKind: agent`. A profile that declares no
  `actorKind` refuses such a token, so a delegated caller cannot borrow the
  operations of a profile written for people using BReg directly. Tokens
  without `act` are admitted as before.

- A read path answers when the caller's profile holds no permission entry
  for the path's target entity. It returns the records the path grant and
  the generated target policy authorize, the same answer as a target
  permission without `get` or `list`, where it answered
  `503 source.unavailable` before. A profile that does not declare the path
  is still refused as `404 resource.not_found`, like an unknown path.
- The audit journal records the agent behind a delegated request. A
  request carrying a trusted `act` writes the shared `authorization` object
  on its refusal, mutation, and request lifecycle records, with actor kind
  `agent` and a keyed `actorPseudonym` scoped to the package revision beside
  the principal and client pseudonyms. The raw actor identifier is never
  stored, and task-grant records without `act` are unchanged.
- The audit journal records delegated authority on reads. A read's
  terminal record, for records, lists, lookups, revisions, history, and
  snapshots, now carries the `authorization` object for a task-grant or
  delegated token. Direct tokens record no such object, as before.

- Align the citizen MCP gateway and review page with the shared runtime
  configuration and audit primitives before their first release. Listener
  binds are explicit; configuration uses the bounded shared YAML loader,
  secret providers, and audit key block. Gateway key sets use `jwksSource`.
  File audit streams rotate at 100 MiB and retain sealed files for 90 days
  by default; archive draft chained files and start on a fresh path.
  Admitted operations record a request before protected I/O and a response
  before result release. That includes every refused callback for a pending
  sign-in whose state and issuer match, and every sign-out a live session
  confirms with its CSRF token. A callback refused for its sign-in cookie,
  query, state, issuer, or rate limit opens no operation and is not
  journaled, and neither is a sign-out without a live session.
  A lost submit response can be retried from the same live review session
  with its retained action and idempotency key; gateway stale-update retries
  remain refused. Import is included in the standing-agent direct-write
  ceiling.

## v0.36.0 - 2026-09-29

- BREAKING: package signing is removed. Upgrade to v0.35.0 before this
  release: a deployment on v0.34.0 or earlier must pass through v0.35.0,
  because this release no longer reads a predecessor package that has no
  `SHA256SUMS` envelope.
  - A package is unsigned and named by its package digest, the SHA-256 of
    its `SHA256SUMS`. `bregctl package` seals and publishes it in one step
    into `<output>/package`, with no signing input, signature document, or
    `awaiting_signatures` state, and refuses an output directory that
    already holds a published package.
  - `bregctl test` and `package` refuse `--signature-threshold`,
    `--signature-key-id`, and `--database-id`, `package` refuses
    `--signatures`, and both take the active package directory as
    `--baseline-package` instead of `--baseline-runtime-config`. Each
    refusal says what to do instead.
  - The runtime `package` block holds `root` and an optional
    `expectedDigest`. `trustAnchorPath`, `activeRevision`, and
    `activeSequence` are refused, and the trust anchor file is gone.
  - The project `package` block holds only `sourceRevision`.
    `environment`, `instanceId`, and `sequence` are refused as
    `package.environment.removed`, `package.instance_id.removed`, and
    `package.sequence.removed`; the environment and instance belong in the
    runtime file's `identity`.
  - The legacy-predecessor fallback v0.35.0 added is gone: `diff`, `test`,
    `package`, `apply`, and the field-encryption preflight no longer read a
    predecessor without `SHA256SUMS` through its BReg signature, and
    `package.digest_pin_unverifiable` is gone. The migration rehearsal still
    reports `migration.rehearsal.baseline_fingerprint_drift` as a finding.
  - With no signature to check, the database decides what follows what.
    `bregctl apply` refuses a package whose package id differs from the
    active one or whose `migrationPlan.fromPackageDigest` is not the active
    package digest as `apply.package.refused`, which covers the previous or
    an older package; the active package itself as
    `apply.package.already_active`, naming `bregctl status`; and a runtime
    file whose `identity.databaseId` is not the one the database recorded as
    `apply.database.identity_mismatch`. `bregctl plan` reports the same
    refusals without changing anything.
  - Rebuild every package an earlier release built with this release's
    `bregctl package`: its `package/v1` manifest is refused and its schema
    fingerprint has changed. For the upgrade, rebuild the deployed project
    unchanged, then build each successor from that package.
  - The first `bregctl apply --package DIR` on a database an earlier release
    installed, without `--initial`, adopts it into the activation ledger;
    `bregctl plan` reports that activation as `adopted`. The ledger history
    that release kept is dropped, and the adoption becomes ledger row 1.
    Every ingestion run the earlier release opened against the running
    package is rebound to the adopted package and stays writable; a run
    bound to any other package stays retired. Adoption records its own
    activation id on every import authority a pre-ledger release had already
    closed, because the revision each was opened under has no activation in
    the ledger, so those authorities' activation id names the adoption rather
    than the activation they were opened under.
  - An apply that resumes an unfinished activation must use the database
    roles that activation started with. A runtime file whose
    `database.roles` now name other roles, such as one edited for one role
    while the upgrade's first apply was unfinished, is refused as
    `apply.resume.roles_differ`, naming the role mode and runtime role the
    activation started with, and nothing changes. Rerun the apply with those
    roles, or, for a new package, assess the activation with
    `bregctl migration reconcile`. A role change is not assessed by
    reconciliation: fix the cause of its failure and rerun the same apply,
    which resumes it.
  - A successor package activates with the database roles the active
    activation serves with. A runtime file whose `database.roles` name other
    roles is refused as `apply.successor.roles_differ` before maintenance,
    naming the role mode and runtime role the active activation records, and
    nothing changes. Apply the active package under the new roles first,
    which records a `role_change` activation, then apply the successor.
  - A Casework deployment repins each BReg source whose project declares a
    `package` block: that project's `registryRevision` changes (see below),
    so Casework treats the source's records as moved until the source
    description pins the upgraded value. Repeat `caseworkctl source add
    --apply` against the upgraded registry and follow the recovery its
    refusal prints.
  - An Evidence deployment re-imports each BReg source once: the export names
    `provenance.registryRevision` instead of `provenance.packageRevision`, so
    `evidencectl` reports changed provenance on the first import after the
    upgrade.
  - With separate migration and runtime roles, a trigger an operator added to
    a registry table, such as a local audit trigger, blocks startup:
    `breg` refuses as `startup.runtime_role.can_write` and `bregctl apply`
    and `bregctl plan` as `apply.runtime_role.can_write`, naming the exact
    `DROP TRIGGER` to run. Drop it, then rerun the refused command.
  - An import authority's `activationRevision` is `activationId` in its audit
    record and in the `bregctl import-authority` report.

- BREAKING: the database records every activation, the initial one included,
  as one row of `registry_internal.registry_migrations`, keyed by a UUID
  activation id and ordered by `apply_order`. Each row names the package
  digest, its predecessor digest, the `registryRevision`, the plan and
  migration kinds, the role mode, and the runtime role.
  - `registry_internal.registry_state` records the active package digest
    and the active activation id instead of a package revision, an
    environment, an instance id, and a package sequence, and holds the
    instance claim. The `registry_internal.registry_instance_claim` table is
    gone.
  - Records, the revision journal, captured outbox and delivery rows, audit
    entries, and import authorities name the activation that wrote them by
    its activation id wherever they named a package revision. Webhook event
    data and ingestion runs keep naming the active package by its digest as
    `packageRevision`, since a client knows the package it holds, not the
    activation the database recorded for it.
  - `bregctl apply` reports `activationId` instead of `packageSequence`.
  - A destructive activation records each backup it was bound to in the
    row's `backup_references`: the binding path, the backup file, its SHA-256
    digest, its byte length, and when it was taken. The ledger keeps the
    reference, never the backup.
  - An import authority records the activation it was opened under as the
    UUID `activation_id` instead of the text `activation_revision`. Its
    `breg-import-authority-audit/v1` record and the `bregctl
    import-authority` JSON report name it as `activationId` instead of
    `activationRevision`. A successful activation supersedes every open
    import authority in the transaction that makes it active and records
    each supersession once that transaction commits; a failed activation
    supersedes none. Open a new authority after the activation.
  - Reconciliation audits under `breg-migration-reconcile-audit/v3`, naming
    `packageDigest`, `targetPackageDigest`, and `activationId` instead of
    `packageRevision`, `targetPackageRevision`, and `packageSequence`.
  - `bregctl migration reconcile` reports `maintenanceTargetPackageDigest`,
    `activePackageDigest`, and `targetPackageDigest` instead of
    `maintenanceTargetRevision`, `activePackageRevision`, and
    `targetPackageRevision`.
  - Webhook events take their `source` from the runtime `identity.instanceId`.
    Startup refuses a changed `identity.instanceId` while pending or leased
    deliveries were captured under the previous one, naming the stored source
    and the configured instance id, because the delivery worker would
    dead-letter each of them. Keep the previous `identity.instanceId` until
    they drain, then change it. Delivered and dead-lettered work does not
    hold the change back.
  - `breg` refuses to start on a database that records no activated package,
    naming `bregctl apply --package DIR --initial`, and on a database that
    predates the activation ledger, naming `bregctl apply --package DIR`. It
    checks the package pin and the physical instance claim before it reads the
    recorded identity, and `bregctl instance-claim` refuses a package root the
    runtime `package.expectedDigest` does not pin before it connects.

- BREAKING: a database a release before the activation ledger installed is
  adopted into the ledger once, by `bregctl apply --package DIR` without
  `--initial`, where DIR and `package.root` both name the deployed project
  packaged with this release's `bregctl package`. Under the apply lock and in
  one transaction the kernel tables take this release's shapes, the live
  managed schema fingerprint must equal the package's `schemaFingerprint`,
  and the adoption becomes ledger row 1 with plan kind `adopted`; no model
  DDL runs, and `bregctl apply` reports the activation `adopted`. The ledger
  history of the release that installed the database is dropped. The
  instance claim that release recorded is kept, and every open import
  authority is superseded. A fingerprint mismatch is refused as
  `apply.adoption.fingerprint_mismatch`, naming both fingerprints, and a
  database that release left in maintenance as `apply.adoption.not_ready`;
  either refusal changes nothing. Any other apply of a pre-ledger database is
  refused as `apply.database.pre_ledger`, naming `bregctl apply --package
  DIR`.

- `bregctl plan --runtime-config FILE --package DIR` makes the checks
  `bregctl apply` makes before it changes anything, under the same apply lock
  and in transactions it rolls back, and changes nothing. It reports whether
  an activation is pending and its kind (`initial`, `successor`,
  `role_change`, `adopted`, or `none`), the package and active package
  digests, the `registryRevision`, the role mode, the activation a retry
  would resume, and the backup bindings apply requires. It refuses what apply
  would refuse, with the same `apply.*` codes, and runs no migration
  statement; `bregctl test` rehearsed those. With `--backup
  BINDING_PATH=BINDING_FILE` it checks each binding as apply would.

- `bregctl status --runtime-config FILE` reads the activation ledger under the
  migration credential and reports the package id, the database id, the
  active package digest and activation id, the `registryRevision`, the role
  mode, the schema fingerprint, the maintenance status and target, and every
  ledger row with its package and predecessor digests, plan and migration
  kinds, outcome, and times.

- `bregctl apply` of the active package under other configured database
  roles, such as a separate runtime role in place of one role for both, is its
  own activation: it records a ledger row with the same package digest and the
  role mode and runtime role it serves with, grants the runtime role, revokes
  what the retired runtime role held as the runtime, and reports the
  activation `role_change`. Under the roles the database already serves with,
  it is refused as `apply.package.already_active`, naming `bregctl status`.

- BREAKING: the role mode is `single` when `database.roles.migration` and
  `database.roles.runtime` name one role and `split` otherwise, and each mode's
  privileges are asserted. In split mode `breg` and `bregctl apply` refuse a
  runtime role that can write the activation ledger or the registry state: a
  superuser, a member of the migration role, an owner of any registry schema,
  table, sequence, view, or function or a member of its owner, a holder of
  CREATE on a registry schema, of TRIGGER on a registry table or view, or of a
  write privilege on the ledger or state tables, directly or through PUBLIC,
  and a table carrying a trigger the migrations never created. `bregctl
  apply` refuses as `apply.runtime_role.can_write`, naming the object and the
  fix: `REASSIGN OWNED BY` then `bregctl apply --package DIR`, or the exact
  `REVOKE` or `DROP TRIGGER` then rerunning the refused command. `breg`
  refuses as `startup.runtime_role.can_write`, naming `bregctl apply
  --package DIR`, and refuses a runtime role missing the grants the active
  package gives it as `startup.runtime_role.grants_missing`; the apply of the
  active package reissues them. A one-role runtime file over a database
  activated for a separate runtime role is refused as
  `startup.role_mode.changed` until `bregctl apply --package DIR` activates it
  for one role. `breg` logs the role mode at startup, and `bregctl doctor`
  reports it as `roleMode`; in single mode both say the activation ledger
  check catches mistakes but not someone holding that credential.

- `bregctl dev` and the quickstart serve the local registry with one database
  role, the migration role; the schema-test rehearsal keeps a separate runtime
  role. A local session retained from an earlier release keeps its split
  runtime file, which `bregctl dev stop --remove` does not replace; remove the
  project's `.breg/dev` directory to start one that serves with one role.

- `bregctl apply --operator-reference TEXT` binds an operator's change
  reference to the activation. The text must be 1 to 512 bytes without control
  characters, and the audit profile must be keyed: the ledger row records only
  its keyed hash, scoped to the activation id, never the text.

- Every activation, adoption included, is audited as
  `breg-activation-audit/v1`, correlated by its activation id. The request
  entry is written before the activation changes any state and names the
  activation and prior activation ids, the package and predecessor digests,
  the `registryRevision`, the plan kind, the database id, environment,
  instance id, role mode, and the operator reference's keyed hash. The
  response follows the commit as `applied`, or durable state that shows the
  target did not become active as `failed`; an attempt whose end that state
  cannot show is answered `unfinished`. An audit destination that refuses
  the request entry refuses the apply as `apply.audit.unavailable`, and
  nothing changes.

- An activation records the instance claim when the database has never
  recorded one, as a registry upgraded from a release before the claim, so an
  in-place upgrade starts after `bregctl apply` without `bregctl
  instance-claim adopt --acknowledge-original-retired`. A recorded claim is
  kept, so a restored copy still refuses to serve until it is adopted.

- `bregctl instance-claim adopt` also runs on a database the instance claim
  already names, as after a point-in-time recovery, a snapshot, or a base
  backup, which keep the claim matching and reopen every import authority
  closed after the backup point. It claims the database again with a raised
  epoch and supersedes every open import authority in one transaction,
  audited under `breg-instance-claim-audit/v1` with the event `reclaimed`.
  Run it once after any restore, before the database serves. The
  `instance_claim.already_current` refusal is gone.

- A runtime file refused as `runtime_config.document` says which field is
  wrong and why, such as an unknown `audit.destination` and the destinations
  it accepts, without repeating the refused value, in `bregctl doctor`,
  `bregctl verify`, and every other command that reports it. A
  removed package key is refused before any environment expression in its
  value is substituted, and the runtime file is read through the shared
  runtime configuration loader.

- BREAKING: an Evidence source export names the compiled model it came from
  as `provenance.registryRevision` instead of `provenance.packageRevision`,
  so `evidencectl` reports changed provenance for every BReg source on its
  next import.

- A runtime file may name one role as both `database.roles.migration` and
  `database.roles.runtime`, and then one reference as both
  `database.runtimeUrlRef` and `database.migrationUrlRef`. Two distinct roles
  still need two distinct references. With one role, `bregctl apply` grants
  that role nothing beyond the ownership it already holds and revokes only
  from `PUBLIC`, and `breg` serves as the owner of the registry schema.

- BREAKING: the schema fingerprint no longer measures the runtime role's
  grants, so one package fits a database served with one role or with two.
  Every package's schema fingerprint changes; rebuild each package with this
  `bregctl package`.

- BREAKING: `registryRevision` is a function of the compiled model only. The
  project's `package` block no longer appears in
  `compiled/effective-model.json`, so a project that declares a package
  identity compiles to a different `registryRevision` than it did before, and
  two projects that differ only in their package identity compile to the same
  one.

- BREAKING: a Registry Casework BReg source pins the `registryRevision` it
  was imported from, and Casework startup refuses a pin the registry no
  longer serves. After upgrading BReg, run `caseworkctl check PROJECT
  --against-breg-package DIR --source-id ID`, repin with `caseworkctl source
  add BREG_PROJECT --project PROJECT --source-id ID --apply`, then package,
  plan, and apply the Casework project once. See
  `products/casework/CHANGELOG.md`.

- BREAKING: a package is environment neutral and unsigned. One package built
  by `bregctl package` is the unit an operator promotes through every
  environment, and its identity is its package digest, the SHA-256 of its
  `SHA256SUMS`.
  - A project's `package.environment`, `package.instanceId`, and
    `package.sequence` are refused with `package.environment.removed`,
    `package.instance_id.removed`, and `package.sequence.removed`. Move the
    environment and the instance id to the runtime file's `identity`, and
    delete the sequence: a package names its predecessor through
    `migrationPlan.fromPackageDigest`. `package.sourceRevision` stays.
  - The manifest is `package/v2`. It no longer carries `packageRevision`,
    `environment`, `instanceId`, `databaseId`, `sequence`, `priorRevision`,
    `signaturePolicy`, or signatures, and `migrationPlan.fromRevision` is
    `fromPackageDigest`. A `package/v1` package is refused; rebuild it with
    `bregctl package`.
  - Trust anchors, package signatures, and the signing input are gone. A
    runtime file's `package.trustAnchorPath`, `package.activeRevision`,
    `package.activeSequence`, and `package.compilerSourceRevision` are refused
    with `runtime_config.package_key_removed`, naming what to do instead.
    `package.root` and `package.expectedDigest` stay.
  - A runtime file's `identity.instanceId` follows the grammar the project's
    `package.instanceId` had, a lowercase letter then at most 63 lowercase
    letters, digits, `-`, or `_`, and is refused otherwise with
    `runtime_config.invalid_instance_id`. `identity.environment` must equal
    `identity.databaseInitializationEnvironment`, or the file is refused with
    `runtime_config.environment_identity_conflict`.
  - A package without `SHA256SUMS`, built by an earlier `bregctl`, is no
    longer read as a predecessor through its signature. Rebuild it with this
    `bregctl`.
  - `bregctl package` and `bregctl test` drop `--database-id`,
    `--signature-threshold`, `--signature-key-id`, and `--signatures`, and
    `--baseline-runtime-config` is `--baseline-package DIR`, the predecessor
    package directory. Each retired flag exits 2 and names its replacement.
    `bregctl package` writes the package with its sum file and prints the
    package digest.
  - The schema-test receipt is `breg-schema-test-receipt/v2`. It drops the
    environment, instance id, database id, sequence, candidate revision, and
    signing input digest, and names the predecessor by `priorPackageDigest`.
    Its source closure also binds each reviewed migration file by path and
    digest, so a changed descriptor, statement, or rehearsal file makes the
    receipt stale. `bregctl test` no longer compares the runtime identity
    with the candidate.
  - A reviewed migration file outside the package layout, such as a backup
    binding, is refused when the package is built. The backup binding is an
    apply input only (`bregctl apply --backup`).
  - Reports name packages by `packageDigest` instead of a package revision,
    including `bregctl dev status`. `bregctl dev` keeps no package sequence,
    writes no trust anchor or active-package keys, and takes its event source
    from the runtime `identity.instanceId`.
  - The database records the active package digest. An initial apply accepts
    a package that names a predecessor. Applying a package that does not
    follow the active one is refused as `apply.package.refused`, which also
    covers a package older than the active one. An empty migration plan is
    refused before database authority, and `migration reconcile` refuses the
    active package as its target before database authority.
- The BReg image carries `bregctl` at `/usr/local/bin/bregctl` beside the
  runtime. The entrypoint stays `breg`; run `plan`, `apply`, and `status` from
  the image by overriding the entrypoint.

- A `bregctl` usage error, in human and JSON output, names the refused
  argument and its error kind but never repeats a rejected token, so a
  mistyped `--operator-reference` value no longer reaches the terminal or a
  captured log in clear. A reason one of the value parsers gives is kept
  while it does not repeat the value. The diagnostic code stays
  `usage.invalid` and the exit status 2.

## v0.35.0 - 2026-09-28

- Upgrade a registry whose active package the previous `bregctl` release
  built. A package without the shared `SHA256SUMS` envelope is read as the
  predecessor by `diff --runtime-config`, `test --baseline-runtime-config`,
  `package --baseline-runtime-config`, `apply`, and the field-encryption
  preflight,
  verified from its signed manifest: the BReg signature against the trust
  anchor, every file's digest, and a closure that refuses any file the
  manifest does not list, including a stray `SHA256SUMS` or `REVISION`. Test,
  package, and apply a successor with this `bregctl`; do not rebuild the
  active package, which changes its revision and schema fingerprint.
  - `breg` startup, `verify`, and `migration explain` still refuse a
    package without `SHA256SUMS`, and say to apply a successor with this
    `bregctl`.
  - A runtime configuration that pins `package.expectedDigest` on such a
    predecessor is refused with `package.digest_pin_unverifiable`; remove the
    pin until the successor is active.
  - The migration rehearsal in `test` no longer refuses when the predecessor
    schema this compiler installs measures differently from its signed
    fingerprint, which a predecessor built by an earlier release always does.
    The test report carries the finding
    `migration.rehearsal.baseline_fingerprint_drift` with both fingerprints.
    A predecessor schema that cannot be installed is still refused with
    `migration.rehearsal.baseline_not_reproducible`, and the rehearsed
    migration must still reach the candidate fingerprint.
  - The migration rehearsal installs the predecessor schema the successor
    plan was computed from, so a successor of a package built before
    compiler-owned reference indexes no longer fails its rehearsal with
    `migration.rehearsal.compiler_statement_failed` on the index it adds.
  - `diff --runtime-config` classifies changes against the running package's
    signed migration baseline, so it reports an index the successor plan
    creates, such as a compiler-owned reference index, as a lock risk.
  - A registry activated by an earlier release records no instance claim, so
    `breg` refuses to serve it after the first successor apply on this
    release until the operator runs `bregctl instance-claim adopt
    --acknowledge-original-retired` once against its runtime configuration.

- Answer every audited request entry. A read, mutation, action, or request
  action that ends after its attempt without a terminal or refusal entry,
  because it failed, timed out, or its caller went away, writes a response
  with the phase `unfinished` under the same correlation. A read that fails
  after its rows were read writes the Refused terminal, and a terminal the
  destination refuses is logged instead of discarded.
  - A reviewed change-request apply records its attempt before the receipt
    preflight's reads and the review authority, and holds it through the
    action.
  - `migration reconcile` answers a transition that fails after its request
    entry with a `failed` response.
  - `request-retention erase` answers a refused or failed erasure with a
    `refused` or `failed` response, deletes the external attachment objects
    before it records a committed erasure, and records how many objects still
    wait for deletion. An erasure that committed without its response entry
    reports `request_retention.erasure.unaudited`. `request-retention
    cleanup-attachments` answers a failed cleanup with a `failed` response.
  - `history rebaseline`, a standalone `history erase`, and a
    field-encryption erase-and-rebaseline run answer their request entry with
    an `unfinished` response when they are refused or fail before their
    terminal entry, as does an attachment verification job that stops early.
  - `evidence-retention erase-expired` is audited under
    `breg-evidence-retention-audit/v1`: a request entry naming the cutoff
    before the erasure, and a response with the erased count or `failed`.
  - An ingestion run creation, cancellation, chunk replay, or receipt
    recovery refused after its `breg-ingestion-audit/v1` request entry is
    answered in that schema with a `refused` response, and not recorded again
    as a general refusal. A transition whose commit returned an error is
    answered `unfinished`, since that error does not prove a rollback.
  - Event delivery records a terminal outcome and a payload expiry only after
    the delivery state commits. An attempt whose lease commit fails is
    answered with `worker_interrupted`. A terminal outcome whose commit
    failed and cannot be read back is answered `worker_interrupted` with
    disposition `unknown`, which claims no delivery state. An operator replay writes a
    `replay_requested` request before the reset and a `replay_committed` or
    `replay_refused` response after it, or `replay_unfinished` when the
    reset's commit failed and its fate cannot be read back.

- BREAKING: write audit through the platform audit writer instead of a
  hash-chained journal in PostgreSQL. Each process opens one writer at
  startup and writes JSON Lines entries `{schema, correlation, phase, time,
  record}` to a file or to standard output. Nothing audit-related is stored
  in PostgreSQL any more.
  - The runtime configuration's `audit` section gains `destination` (`file`,
    the default, or `stdout`), `path` (required for `file`, absolute),
    `rotateBytes` (default 100 MiB) and `retainDays` (default 90).
    `hashKeyRef` still names the key that derives keyed references, and
    reference derivation is unchanged. A runtime configuration without
    `audit.path` is refused at startup.
  - A request writes a `request` entry before protected I/O and a `response`
    entry sharing its correlation before any disclosure. A mutation writes its
    response entry after its transaction commits; if the writer refuses it,
    the effect stays committed, the caller receives the audit-unavailable
    refusal, and a retry with the same idempotency key replays the stored
    result as an audited replay.
  - Audit schemas move to `breg-audit/v2`, `breg-webhook-audit/v2`,
    `breg-history-erasure-audit/v2`, `breg-history-rebaseline-audit/v2`,
    `breg-migration-reconcile-audit/v2` and
    `breg-field-encryption-audit/v2`. Attachment verification, attachment
    cleanup and ingestion-run records, which had no schema of their own, are
    `breg-attachment-verification-audit/v1`,
    `breg-attachment-cleanup-audit/v1` and `breg-ingestion-audit/v1`.
  - `bregctl` lifecycle commands that audit (`history erase`, `history
    rebaseline`, `field-encryption erase-history` and `migration reconcile`)
    write to their own sibling file beside the runtime's `path`, named
    `<stem>.bregctl.<extension>` (`audit.bregctl.jsonl` for `audit.jsonl`),
    and report `*.audit.unavailable` when it cannot be opened.
  - `bregctl audit verify`, `audit export` and `audit prune` are removed,
    with their `audit.*` diagnostics. Rotation and retention of the audit
    files replace pruning; ship or verify them with the log tooling that
    already reads your other JSON Lines files.
  - The `registry_internal.registry_audit` and `registry_audit_head` tables
    leave the managed catalog. The next `bregctl apply` against an existing
    database refuses while either table still holds rows, naming them and
    asking the operator to archive the rows first; passing
    `--acknowledge-retired-audit-discard` acknowledges discarding them and lets
    the apply drop the tables. The history-erasure coverage a successor
    package relies on, and field-encryption erase progress, are recorded in
    `registry_internal` state tables instead of being read back from audit.
    The managed catalog fingerprint changes, so every package must be rebuilt
    and signed again.
  - `bregctl doctor` checks that the audit destination is writable without
    opening it, so it runs beside a serving process. Two processes cannot
    share one audit file: a second runtime needs its own `path`.
  - To migrate, export the old journal with the previous release's `bregctl
    audit export` if you must retain it, add `audit.path` to each runtime
    configuration, then rebuild, sign and `bregctl apply` the package. If the
    database still carries rows in `registry_audit` or `registry_audit_head`,
    archive them first (for example with `psql` or `pg_dump --table`), then
    apply with `--acknowledge-retired-audit-discard`.
