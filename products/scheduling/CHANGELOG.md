# Registry Scheduling changelog

## Unreleased

- A refused `schedulingctl check` opens with
  `schedulingctl check refused the input.` and closes with the summary line,
  as the other check commands print it.
- BREAKING: `authentication.oidc.allowedClients` is required in every file. An
  omitted member and `[]` are refused with
  `scheduling.runtime.allowed-clients-required`, development loopback
  included; before, only `operator-controlled-upstream` refused them. The
  generated runtime schema requires the member with at least one item.
  Migration: list the clients the deployment admits.
- BREAKING: a repeated `id` in a project, records, or fixture-facts list is
  refused with `config.duplicate-id` at the second item's `id`, where the
  finding was `scheduling.project.duplicate-identifier`,
  `scheduling.records.duplicate-identifier`, or
  `scheduling.fixture.duplicate-identifier`. Migration steps are in
  `release/notes/config-conventions/scheduling.md`.
- BREAKING: `authentication.oidc.assertionIssuers: {}` is refused: delete the
  member to apply no assertion-issuer rule. The generated runtime schema types
  the client keys as `ExternalId` and requires at least one client.
- BREAKING: the authored files follow the Registry Stack configuration
  conventions and are read by the shared configuration reader, which reports
  every problem at its line and column with a JSON Pointer and a next step.
  `scheduling.yaml` is `kind: SchedulingProject` at
  `id.registrystack.org/formats/scheduling/project/v1alpha1`, names itself
  under `project` with a text `version`, and requires `channels`;
  `maxRecipients`, `minutesBefore`, and `maxPerCaller` are `maximumRecipients`,
  `offsetMinutes`, and `maximumPerCaller`. `records.yaml` carries a
  `SchedulingRecords` envelope, fixtures move to
  `id.registrystack.org/formats/scheduling/fixture/v1alpha1`, a units policy
  and a fixture expectation are tagged by `type` with kebab-case values, and
  an empty restricting list is refused. Each old spelling is refused with
  its replacement. The HTTP contract and the clients are unchanged.
  Migration steps are in `release/notes/config-conventions/scheduling.md`.
- BREAKING: the runtime file's `apiVersion` is
  `id.registrystack.org/formats/scheduling/runtime/v1alpha1`, the retention
  periods are `attemptReceiptRetentionDays` and `hookPayloadRetentionDays`,
  and `audit.retainDays` is `audit.retentionDays`. `scheduling serve` and
  `schedulingctl` report every rule the file breaks at its line and column
  with its own `scheduling.runtime.<condition>` or shared `config.*` code,
  where `schedulingctl` reported `schedulingctl.runtime-configuration.invalid`
  at `runtime.yaml`. `RuntimeConfigError::path` is replaced by
  `RuntimeConfigError::pointer` and `RuntimeConfigError::code`. Migration
  steps and the old-to-new code table are in
  `release/notes/config-conventions/scheduling.md`.
- BREAKING: `schedulingctl check` exits 1 on any finding, reports
  `diagnostics` and `filesChecked` in place of `findings`, takes
  `--deny-warnings` in place of `--deny-findings`, and checks a runtime file
  offline with `--runtime-config FILE` and `--environment`. Every JSON
  report names its format as `SchedulingCtlReport` at
  `id.registrystack.org/formats/scheduling/ctl-report/v1alpha1`, and `test`
  with no fixture exits 1. A database an earlier release wrote is not read;
  start from a new one. Migration steps are in
  `release/notes/config-conventions/scheduling.md`.
- A hold or an appointment is owned by the verified token issuer and subject
  that booked it, stored on the claim, rather than by the audit-keyed
  pseudonym of that pair. Listing by external reference, reading,
  rescheduling, cancelling, releasing a hold, and the per-caller hold ceiling
  all decide on the stored pair, so rotating `audit.hashKeyRef` no longer
  detaches any claim from its owner. History and audit still carry the
  pseudonym. Migration 12 adds the owner; a hold or appointment written before
  it recorded only the pseudonym, keeps its capacity and history, and is
  owned by no caller, so its booker can no longer list, read, confirm,
  reschedule, cancel, or release it. Run `schedulingctl plan` and
  `schedulingctl apply` with this release before starting the runtime.
- The retention sweep that erases an idempotency receipt also clears the
  attempt's raw token issuer, subject, and key. The attempt is identified by a
  SHA-256 digest of those three and the command and is never deleted, so the
  key stays spent for that caller: an exact retry still answers
  `idempotency.expired`, a changed one `idempotency.key-reused`, and another
  caller's identical key is fresh. Migration 11 re-keys every existing attempt
  and clears the raw values from receipts already erased; run
  `schedulingctl plan` and `schedulingctl apply` with this release before
  starting the runtime.
- The Rust client resends a keyed command (hold create, appointment create,
  reschedule, cancel) whose outcome is unknown, identically and under the same
  idempotency key: after a timeout or broken exchange once the request was
  sent, or after a 5xx answer. It resends at most twice by default,
  `with_max_mutation_retries(0)` turns the resend off, and reads and the
  unkeyed hold release are never resent. `is_outcome_unknown()` reports an
  error after which the command may have taken effect; the Node.js
  `outcomeUnknown` and Python `outcome_unknown` fields carry the same answer.
- Scheduling joins the unified clients beginning with v0.40.0: the
  `scheduling` namespace of `@registrystack/client` and the
  `registry_client.scheduling` module of `registry-stack-client`.
- The `idempotency.expired` detail now names the recovery for each command:
  for an appointment command, read the appointment by its external reference
  or its identifier before choosing a new key; a hold cannot be read and
  expires on its own, so start a new request. The OpenAPI document and the
  published problem table carry the new text.
- The runtime configuration schema publishes the hook destination bounds
  startup enforces: `destinations.hooks` holds at most 128 bindings whose ids
  follow the logical destination id grammar, `attemptTimeoutMilliseconds` is
  from 100 through 10000, and `maximumAttempts` from 1 through 20, where the
  schema accepted any map, any timeout, and 0 through 255 attempts.
  Configuration that started before is unaffected, since startup already
  refused values outside them.
- The runtime configuration schema publishes the retention bounds startup
  enforces: `retention.attemptReceiptDays` is at least 1, and
  `retention.hookPayloadDays` is from 1 through 30. Configuration that started
  before is unaffected, since startup already refused values outside them.
- Document the read that observes an outcome after its task grant expired: an
  expired grant refuses its whole token on every `/v1` route, so the caller
  reads with a token for the same issuer and subject that carries the read
  scope and no grant, listing by external reference or reading by identifier.
- The Node.js client reports a rejected constructor setting (an unsafe
  integer, an undefined member, or a value of the wrong type) as kind
  `configuration`, where it reported `invalid_request`. Code that branches on
  `kind` sees the change.

## v0.39.0 - 2026-10-06

- BREAKING: before 1.0, a release reads only the state its immediate
  predecessor wrote. This release reads state written by v0.38.0 and nothing
  older. If you run an older release, upgrade one release at a time and finish
  each release's upgrade steps before starting the next. The entries below
  remove what served only releases before v0.38.0.
  - Building the Registry Scheduling release image fails when no
    `schedulingctl` is staged beside the runtime.

## v0.38.0 - 2026-10-01

- BREAKING: package activation (`schedulingctl plan`, `apply`, and `status`) and
  `scheduling serve` startup refuse a PostgreSQL server older than 17 with an
  upgrade instruction, before any migration or activation write. Operators
  on PostgreSQL 16 or older must upgrade the database server before
  upgrading Scheduling.
- BREAKING: publish the `v1alpha2` HTTP contract with typed opaque
  `externalReferences` on hold and appointment
  documents and to hold or direct-booking admissions. Hold confirmation,
  reschedule, cancellation, reads, and idempotent replays retain the reference
  set. Add the owner-scoped `GET /v1/appointments` filter over one exact
  product, record type, and record identifier tuple, with bounded paging whose
  cursor is bound to both the caller and filter.
- Migration 10 stores external references. The runtime refuses to start
  until `schedulingctl plan` and `apply` run it, and existing holds and
  appointments receive an empty reference set.

- Add a standalone Linux amd64 runtime binary from v0.38.0, alongside the
  existing Docker image and operator binary.
- Share activation ledger and runtime privilege checks with Casework and
  Messaging. Activation now detects the loss of any required table DML
  privilege, including when other required privileges remain granted (#1731).

## v0.37.0 - 2026-09-29

- Read each request's `now`, and the hold-expiry, retention, and reminder
  dispatch passes' `now`, from the same clock the capacity transaction
  re-checks grants against. Production still reads the system clock, so
  deployments see no change.
- Start a hold's time to live when its capacity transaction decides, after
  the supply and per-caller locks, instead of when the request arrived. A
  hold created under lock contention now carries the whole configured
  `holdPolicy.ttlMinutes` in its `expiresAt`, its stored expiry, and its
  `held` history event, and the task grant is re-checked at that same
  instant.
- Answer availability for an offering whose `horizonDays` reaches past the
  last representable instant instead of panicking the request: such a horizon
  bounds nothing. A caller-supplied availability or explain `start` at the
  edge of the calendar is answered the same way.

## v0.36.0 - 2026-09-29

- Write operational logs to standard error instead of standard output, so a
  `stdout` audit destination carries audit entries alone. A collector that read
  `scheduling` logs from standard output reads standard error instead.
- Log at `info` when `RUST_LOG` is unset or invalid. The runtime previously
  logged errors only by default, so a deployment without `RUST_LOG` lost every
  info and warn record.
- BREAKING: activate a package with `schedulingctl plan`, `schedulingctl
  apply`, and `schedulingctl status`, recorded in a database activation
  ledger, instead of `scheduling migrate` and a startup that adopts the
  database and publishes the policy.
  - `identity.databaseId` is required in `runtime.yaml`: an operator-chosen
    logical id for the database, recorded by the first apply. An apply,
    `records apply`, or startup under another id is refused, naming only the
    key.
  - `schedulingctl plan --runtime-config FILE` reads with the runtime
    credential and writes nothing, on an empty database too. It reports the
    active and candidate package digests, the database identity check, the
    pending schema versions, the policy revision the apply would publish,
    whether retained hook deliveries stay deliverable, and `changesPending`.
  - `schedulingctl apply --runtime-config FILE [--operator-reference TEXT]
    [--backup REF]...` connects with the migration credential and, in one
    transaction under the migration advisory lock, applies the pending schema
    versions, binds the scheduling id, publishes the policy, grants the
    runtime role when the credentials are two roles, and records one ledger
    row. Any valid package applies, an earlier one included, each as a new
    row; the active package refuses with `nothing needs applying` unless a
    schema version is pending or the runtime role or its role mode changed,
    so a rotated runtime role or a move to split mode re-applies it. The
    operator reference is kept only as a keyed hash scoped by the activation
    id. Apply writes a `scheduling-activation-audit/v1` request entry to the
    `schedulingctl` sibling of `audit.path` (`audit.schedulingctl.ndjson`
    beside `audit.ndjson`) before the transaction and a response entry after
    it, and applies nothing when the request entry is refused. An
    activation whose commit was not acknowledged is read back, and one whose
    outcome cannot be read is answered `unfinished` with reason
    `schedulingctl.activation.unacknowledged`, naming `schedulingctl status`,
    since it may have taken effect. A response entry refused after the
    commit exits 3 with `schedulingctl.activation.applied-unaudited`, naming
    `schedulingctl status`; an audit destination that cannot be written
    exits 3 with `schedulingctl.audit-unavailable`.
  - `schedulingctl plan` refuses a runtime role that cannot read an existing
    activation ledger with `schedulingctl.activation.ledger-unreadable`, exit
    1, naming `schedulingctl apply --runtime-config FILE` with the migration
    credential to grant it, then `schedulingctl plan --runtime-config FILE`.
  - `schedulingctl plan` names `schedulingctl.activation.unpublished-audit`
    when schema migration 8 is pending and the audit outbox still holds
    unpublished records, counted without a lock; apply counts them again
    under an exclusive lock and refuses the same.
  - `schedulingctl plan` names `schedulingctl.activation.hook-destinations`,
    with `changesPending` false, when a destination the policy hooks name is
    not bound under `destinations.hooks` or its `hmacSha256KeyRef` does not
    resolve to a key of at least 32 bytes. Apply refuses the same before it
    writes anything, exit 1, with the same code. Plan resolves the key only
    to learn its presence and size; no report carries it.
  - `schedulingctl status --runtime-config FILE` reads the full activation
    history, the schema version, and the role mode.
  - In split role mode the runtime role reads the ledger and the schema
    history but cannot write either; it keeps ordinary write access to the
    product tables. Apply grants it only the `scheduling_*` objects and the
    platform hook delivery tables Scheduling installs, never another
    application's objects in a shared schema. Single role mode is reported by `plan`, `apply`, and
    `status`. Each ledger row records the runtime role and the role mode it
    holds after the grants, read from its privileges and memberships.
  - `scheduling serve` writes no activation state. It refuses a database with
    no active package, a verified package the ledger does not name, and a
    ledger recorded for another `identity.databaseId`, naming `schedulingctl
    plan` then `schedulingctl apply`; `package.expectedDigest` still pins the
    package at `package.root`. It refuses a ledger that recorded split role
    mode for a runtime credential that can now write it, naming
    `schedulingctl apply`.
  - In split role mode, `plan`, `apply`, and `scheduling serve` refuse with
    `schedulingctl.activation.split-role-weakened` a runtime role that owns,
    or is a member of an owner of, the Scheduling schema or a `scheduling_*`
    table, sequence, view, or function, that holds TRIGGER on a
    `scheduling_*` table or view, or that holds CREATE on the schema, and a
    database where a trigger is attached to a `scheduling_*` table. The
    refusal names `REASSIGN OWNED BY` then `schedulingctl apply`, or `REVOKE
    TRIGGER`, `REVOKE CREATE ON SCHEMA` (from PUBLIC when that is how the
    runtime role holds it), or `DROP TRIGGER` for each attached trigger, then
    a rerun of the refused command. Split-mode apply never revokes TRIGGER
    itself: before any migration it refuses a default privilege of the
    migration role that would grant the runtime role TRIGGER on the tables
    it creates, naming `ALTER DEFAULT PRIVILEGES ... REVOKE TRIGGER ON TABLES
    FROM <grantee>` then a rerun. It re-applies the active package when the
    runtime role no longer holds every grant apply issues; `scheduling serve` refuses that
    runtime role, naming `schedulingctl apply`.
  - `scheduling migrate` is removed; it exits 2 naming `schedulingctl plan
    --runtime-config FILE` then `schedulingctl apply --runtime-config FILE`.
  - The operator commands exit 0 on success, 1 on a refusal, 2 on a usage
    error, and 3 on an operational failure.
  - `schedulingctl records apply` refuses a database no `schedulingctl apply`
    has activated, and one where another package is active, checked again
    under the swap's locks so a concurrent apply cannot slip between the
    check and the swap.
  - Upgrade: add `identity.databaseId`, then run `schedulingctl apply` once
    after upgrading, before starting the upgraded runtime; a database an
    earlier release migrated is adopted by that first apply, which also
    backfills the retained policy document. With split roles, a trigger an
    operator added to a `scheduling_*` table blocks `plan`, `apply`, and
    startup until it is dropped. Apply checks that retained hook deliveries
    stay deliverable before it takes the publication locks, so a delivery an
    earlier runtime appends to a destination the upgrade rebinds, while the
    apply runs, is refused at startup instead; stop the earlier runtime, or
    keep its destination bindings until its deliveries drain, before
    `schedulingctl apply`.
- BREAKING: every `schedulingctl --format json` report opens with `ok`,
  `command`, and `status`, in that order, the envelope `evidencectl` writes.
  - `ok` is true exactly when the command exits 0. `status` is the command's
    own (`check` keeps `complete`, `incomplete`, or `invalid`), `passed`,
    `failed`, or `refused` for `test`, `refused` for a `plan` that names a
    refusal, and `complete` otherwise.
  - A refused report carries a non-empty `diagnostics` array whose entries
    each name a `suggestedAction`: a refused `check`, `test`, or `plan`
    points at its `findings`, `fixtures`, or `refusals` member, which it
    keeps.
  - A failure without a report of its own names the command and reports
    `usage-error`, `domain-refusal`, or `operational-failure` by exit class.
  - `records apply` reports `command: "records apply"` instead of
    `records-apply`.
- A command line `schedulingctl` refuses is described by the kind of error
  and the argument name, such as `unexpected argument --operator-reference`,
  or by the argument's own validation reason, such as `--backup must be
  between 1 and 256 bytes`, and names `schedulingctl --help` as the next
  step. The refused value is never repeated on standard output or standard
  error.
- `schedulingctl` is published as a release binary for `linux-amd64`,
  `linux-arm64`, and `macos-arm64`, and the Scheduling image carries it at
  `/usr/local/bin/schedulingctl` beside the runtime. The entrypoint stays
  `scheduling`; run `plan`, `apply`, and `status` from the image by
  overriding the entrypoint. The Scheduling runtime remains an image-only
  artifact.

## v0.35.0 - 2026-09-28

- BREAKING: write audit through the shared platform audit writer instead of
  a hash-chained journal published from a PostgreSQL outbox.
  - The `audit` block takes `hashKeyRef`, `destination` (`file`, the
    default, or `stdout`), and, for `file` only, the absolute `path`,
    `rotateBytes` (default 104857600, at least 1048576), and `retainDays`
    (default 90, at most 36500). An existing `{path, hashKeyRef}` block keeps
    working as a `file` destination.
  - Every entry carries the schema `registry-scheduling-audit/v1`, a
    `request` or `response` phase, and a correlation shared by a decision's
    request and response entries; a response names that correlation as its
    `eventId`. The runtime writes a commitment's request entry before it
    opens the capacity transaction and its response entry after that
    transaction commits or rolls back. A refused request entry opens no
    transaction and answers `service.unavailable`; a refused response entry
    for a committed commitment answers `service.unavailable` with the
    commitment in place. A replayed receipt is answered only after its own
    response entry, recording the decision the receipt carries, is accepted;
    a refused one answers `service.unavailable` without the receipt. A
    permission refused before the transaction is one response entry.
  - Every commitment request entry is answered. A refusal, decided by the
    ledger or by the permission check, is answered only once its response
    entry is accepted, and `service.unavailable` otherwise, where it was
    previously answered with the write failure only logged. A transaction
    rolled back on a failure, records replaced under a commitment, and a
    reused or expired idempotency key now write a response with the outcome
    `unfinished` and a closed reason, and a commitment that returns or is
    canceled before answering writes `commitment.unfinished`.
  - A capacity commit that is not acknowledged is read back by its
    transaction identifier before it is recorded: one that took effect is
    answered and recorded as committed, one that rolled back writes
    `commitment.failed`, and one whose status cannot be read writes
    `commitment.unfinished` and answers `service.unavailable`, never
    `commitment.failed`.
  - Hook delivery writes an attempt's request entry before egress and its
    terminal response entry with the same correlation; a refused entry leaves
    the delivery pending and sends nothing.
  - Entries are no longer hash-chained, and the runtime keeps no audit state
    in PostgreSQL. Schema version 8 drops `scheduling_audit_outbox`;
    `migrate` refuses while the outbox still holds unpublished records, so
    run the previous release until its publisher has drained the outbox,
    then migrate.
  - Before starting the upgraded runtime, archive the old active audit file
    and every numbered sibling separately, then use a fresh `audit.path`.
    Retention now deletes aged sealed files under that path. Update log
    consumers to the new envelope and ship entries to append-only storage
    when tamper evidence is required.
  - `/readyz` reports ready only while the audit writer is ready.
  - `schedulingctl records apply` writes its request entry before it
    replaces the records and its response entry after, to a sibling file
    named for its role beside `audit.path` (`audit.schedulingctl.ndjson`
    beside `audit.ndjson`), and refuses to replace anything when that file
    cannot be opened. A replacement whose commit was not acknowledged is
    read back, and one whose outcome cannot be read is answered
    `unfinished` with reason `records.replace-unacknowledged`, since it may
    have taken effect.

- BREAKING: read `runtime.yaml` through the shared Registry Stack runtime
  configuration loader. The file is capped at 1 MiB, and the runtime
  configuration path and every configured path are refused when they pass
  through a symbolic link.
- BREAKING: remove `authentication.oidc.jwksUri`. Declare
  `authentication.oidc.jwksSource` with `kind: uri` and `uri` instead; the
  removed key is refused with a diagnostic naming its replacement.
- BREAKING: `listener.bind` is required; it no longer defaults to
  `127.0.0.1:8105`.
- BREAKING: an environment expression such as `${VAR}` in the authored
  `scheduling.yaml`, or in a records or fixture document the authoring tooling
  reads, is refused with the path of the field that holds it.
- Accept `${VAR}`, `${VAR:-default}`, and `${VAR:?message}` in string values of
  `runtime.yaml`, never in a `*Ref` field or beneath one, nor under
  `secretProviders`.
- BREAKING: a Scheduling package is the shared Registry Stack package format.
  `schedulingctl package PROJECT --output DIRECTORY` writes `scheduling.yaml`
  and `SHA256SUMS`, one `sha256sum` line per file sorted by path, into a new
  directory, in place of `scheduling.package.json` beside the project;
  `--dry-run` reports the digest without writing, and `--revision TEXT`
  records one free-text line in a `REVISION` file the digest covers. The
  report names `packageDigest`, the SHA-256 digest of `SHA256SUMS`, and no
  longer carries the manifest's `policyDigest`; the semantic policy digest
  `explain` reports, the store records, and hooks carry is unchanged.
- BREAKING: the runtime verifies `package.root` as a package at every start,
  in every listener mode, with or without `package.expectedDigest`. A
  changed, missing, or extra file, a directory without `SHA256SUMS` such as an
  authored project, and a directory that still holds `scheduling.package.json`
  are each refused by name, naming `schedulingctl package`. A
  `development-loopback` runtime no longer serves an authored project; the
  demo packages its project copy before it starts the runtime.
- Add the optional `package.expectedDigest` pin, compared with the package
  digest at startup. A mismatch is refused in the shape every Registry Stack
  runtime shares:
  `package.expectedDigest is <pin> but the package at package.root is <found>`.
- BREAKING: `authentication.oidc.issuer` must be an absolute `https` URL
  without credentials, query, or fragment, or a loopback `http` URL under
  `development-loopback`, and `authentication.oidc.audience` is at most 512
  characters without control characters. Both are checked by the shared OIDC
  issuer block, the same one the other runtimes use.
- A refused `authentication.oidc.assertionIssuers` map is now reported at that
  field rather than at `authentication.oidc`. Its bounds are unchanged.
- `audit.hashKeyRef` must be an exact secret reference when the document is
  read, not only when its provider is checked.

## v0.34.0 - 2026-09-25

- Registry Scheduling has no user-visible changes in this release.

## v0.33.0 - 2026-09-22

- Publish the scheduling MVP: published openings, exact-time offerings over
  interchangeable resource pools, published arrival windows with channel
  subquotas, holds, and accountable appointments, over PostgreSQL. The
  contract is pre-1.0 and may change in a later minor release.
- Keep the capacity ledger inside the runtime's own transaction. A hold or
  appointment is created, moved, or released only inside that transaction, and
  no other product may write the ledger; eligibility stays with the source
  system.
- Validate a policy against the published window records it governs, which
  refuses a window whose staffing pool also backs an exact-time offering.
  The authoring tooling reports it against the files on disk, and policy
  publication and records replacement re-run the same check at the database
  under the locks they already hold, so a deployment that bypasses the
  authoring tooling cannot publish the combination it refuses.
- Keep one supply identifier to one kind of supply. A resource pool and a
  published window anchor their capacity transactions on the same row keyed by
  that identifier, so authoring refuses the collision from either side and both
  anchor writes name the standing supply rather than aborting one publish path
  and silently skipping the anchor on the other.
- Authorize every commitment with a task grant whose scheduling bounds name
  the offering's service, its location, and the action, bounded to 64
  permissions of 32 actions with no wildcard. Only the grant's expiry is
  re-checked inside the capacity transaction.
- Write one pseudonymized authorization audit record for every commitment
  decision: the allowed case, the permission mismatches refused before the
  capacity transaction opens, and the commitments that transaction refuses,
  including an admission refusal, the hold ceiling, a lapsed grant, a stale
  observed revision, and a cancellation past its cutoff. A failed transaction
  and a replaced environment decided nothing and are not audited; an
  idempotency key refusal is carried by the attempt receipt instead.
- Document the maintained Casework approval and stock ThunderID exchange path,
  and feed its exact exchanged bearer through Scheduling's real authenticator
  before the adopter uses it for an appointment.
- Emit each committed scheduling change as a CloudEvents 1.0 event through the
  outbox to a configured reminder destination, and keep intents readable in
  place when no destination is configured.
- Retain idempotency attempt receipts for the configured period and forget
  listing cursors after fifteen minutes. Appointment, history, outbox, and
  audit retention are deferred.
- Answer a release or cancellation retry from the policy revision that
  governed the claim. Publication may retire an offering, or keep its
  identifier and sell it under a different service or location, once no claim
  on it is live, and the retry each receipt exists to serve is still
  authorized against the offering as it stood when the claim was committed.
- Bound the offering-wide duplicate guard to the bookings it decides on. The
  ledger closes no booking when its time passes, so the active claims carrying
  one party's key accumulate for the life of the deployment; the guard now
  reads an index over the key, the offering, and the booking's end rather than
  over the key alone.
- Provide `schedulingctl init`, `check`, `test`, `explain`, and `package`, and
  write complete `runtime.example.yaml` and `records.yaml` documents beside
  every initialized project.
- Carry the product's own contract checks, security-invariant matrix, and
  offline authoring journey under this folder.
- Deliver declared `after` URL observers for confirmed, rescheduled, and
  cancelled appointments from a transactionally captured, bounded projection;
  refuse conditions, principals, local handlers, and observer proposals.
- Re-check hold expiry after locking its supply during confirmation, so a
  delayed confirmation cannot claim capacity that became bookable and was
  committed elsewhere after the hold expired.
- Keep arrival offerings as policy references while operators publish their
  concrete window capacity through atomic runtime records. Apply location
  openings and closures to live window availability and admission, and refuse
  a request whose start differs from the selected window.
- Close the beta review races and contract gaps: include exact-time buffers in
  locked snapshots, scope duplicate keys to their offering, enforce requested
  capabilities, reject cross-offering reschedules, keep cancellations
  available during rolling policy changes, prevent occupied resources moving
  between pools, replay the winning idempotency receipt, and refuse policy
  publications that strand standing commitments. Keep explanation probes,
  multi-pattern reopenings, long-range availability, deployment-bound records
  updates, ownership checks, and replayed response fields aligned with those
  same runtime contracts.
