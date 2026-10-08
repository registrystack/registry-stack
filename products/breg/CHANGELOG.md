# Base Registry Engine changelog

## Unreleased

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
  `breg` refuses a package with the retired
  `registry.registrystack.org/package/v2` header; `bregctl` still reads one as
  the deployed predecessor named by `--baseline-package`. Rebuild the deployed
  package with this release against it, then `plan` and `apply` the rebuild,
  which is recorded as a metadata-only activation. Migration steps are in
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
  longer loads; migrate its documents and rebuild it. Every change and its
  migration step is in the "BReg tool and output formats" section of
  `release/notes/config-conventions/breg.md`.
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
  a package an earlier release built no longer loads. Rebuild it unchanged
  with this `bregctl package --baseline-package <deployed package>` and apply
  it once before starting the upgraded runtime.
- The upgrade keeps existing idempotency records as tombstones no caller can
  find: each carries no raw caller or key and loses its held response and
  receipt, while the immediate action results, immediate action
  applications, and request idempotency links that reference it stay, so a
  revision an earlier release's immediate action wrote keeps its history
  provenance. A request committed before the upgrade and retried after it
  executes again.
- Ingestion runs belong to the verified caller that created them, not to its
  audit pseudonym (#1930). A run stores the configured OIDC issuer and the
  verified principal, and listing, reading, chunk submission, receipt
  recovery, and cancellation compare those; the run's bound claim context is
  an unkeyed SHA-256 digest. Rotating `audit.hashKeyRef` no longer hides an
  open run from its creator, and another principal still finds none of it.
- BREAKING: the upgrade discards every stored ingestion run with its chunks
  and receipts, since a run stored before it names no verified creator. The
  records committed chunks wrote stay, and an import authority keeps the
  volume they consumed. Finish or cancel open runs before upgrading. A
  `bregctl data import` whose run was discarded refuses to resume; import
  only the uncommitted lines under a fresh checkpoint path.
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
  `release/notes/config-conventions/breg-services.md`.

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
