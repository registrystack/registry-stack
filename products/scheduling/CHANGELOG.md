# Registry Scheduling changelog

## Unreleased

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
    id. Apply writes a `scheduling-activation-audit/v1` request entry to
    `audit.schedulingctl.ndjson` before the transaction and a response entry
    after it, and applies nothing when the request entry is refused. An
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
  - `schedulingctl status --runtime-config FILE` reads the full activation
    history, the schema version, and the role mode.
  - In split role mode the runtime role reads the ledger and the schema
    history but cannot write either; it keeps ordinary write access to the
    product tables. Single role mode is reported by `plan`, `apply`, and
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
    has activated, and one where another package is active.
  - Upgrade: add `identity.databaseId`, then run `schedulingctl apply` once
    after upgrading, before starting the upgraded runtime; a database an
    earlier release migrated is adopted by that first apply, which also
    backfills the retained policy document. With split roles, a trigger an
    operator added to a `scheduling_*` table blocks `plan`, `apply`, and
    startup until it is dropped.

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
