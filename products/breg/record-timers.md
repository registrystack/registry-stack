# Record timers

A Record timer lets a governed Record schedule one bounded immediate Action
from stored control fields. The timer is part of the reviewed Registry package:
it is not a caller route, a queue payload, or a general scheduler.

Use a timer when the due instant and scheduling controls belong to the anchor
Record, and the Action can decide and shape its effect from current governed
facts within its declared local read scope. Keep external calendar
coordination, capacity scheduling, and cross-system orchestration outside the
Base Registry Engine (BReg).

## Author one future activation

The Record type declares the timer. The root project separately grants the
exact `recordType` and timer pair:

```yaml
recordTypes:
  - id: service
    fields:
      - {id: status, type: vocabulary-code, vocabulary: service-status, classification: internal}
      - {id: activates-at, type: timestamp, classification: internal}
      - {id: activation-not-after, type: timestamp, classification: internal}
      - {id: activation-revision, type: uuid, classification: internal}
    timers:
      - id: activate
        at: activates-at
        notAfter: activation-not-after
        rearmOn: activation-revision
        when:
          type: fields
          equals: {status: scheduled}
        invoke: activate-service
        input:
          service: {fromRecordId: true}
          planned-at: {fromField: activates-at}
          occurrence: {fromTimer: occurrence-id}

timerGrants:
  - {recordType: service, timer: activate}
```

The invoked Action is an ordinary immediate Action. Its inputs must be
completely mapped by the timer. The compiler refuses a timer that invokes a
Proposal Action, a publicly invokable Action, or an Action with remote
Function, Evidence, commit-Evidence, or consent-issuance capability. A local
bounded handler remains available when it needs none of those capabilities.
The plan may Patch only the exact anchor Record and may Create bounded new
Records. Timer Actions cannot Tombstone a Record. Its declared guards and
linked reads remain bounded by the compiled system grant; that read scope does
not grant mutation of another existing Record. Ordinary authorized tombstoning
of the anchor cancels its timer work.

`timerGrants` is root-project authority. A module may contribute a timer
definition, but it cannot enable autonomous work. A project that imports the
module must name the exact contributed timer in its root `timerGrants`; without
that grant compilation fails. Removing a timer means activating a reviewed
successor that removes both its declaration and matching grant. A false
`when` predicate or a global pause is not permanent disablement.

## Control fields, predicates, and inputs

`at` and `notAfter` name timestamp fields. `rearmOn` names a UUID or integer
field whose changed value distinguishes a new occurrence even when its due
time is unchanged. `notAfter`, `rearmOn`, and `when` are optional. Control
fields cannot be encrypted because their admitted types are not encryptable.

The material control tuple is the current value of `at`, `notAfter`, and
`rearmOn`. Any change to that tuple creates a new occurrence, including a
change from A to B and later back to A. Changing only fields named by `when`
does not create an occurrence: a false predicate holds the current unfinished
occurrence, and a later true predicate releases that same unfinished
occurrence. Settled work stays settled. A new or materially changed control
tuple whose `notAfter` is not later than `at` is refused.

One compatibility case does not turn that refusal into a general editing
block. If an existing current occurrence is already configuration-blocked by
an invalid window inherited across a package change, an unrelated Record edit
may preserve the unchanged controls. It keeps that exact configuration block
and creates no timer work. This exception does not create a configuration
block for a Record with no current occurrence or for settled work, and it does
not replace a preserved technical block or exhausted attempt history.

`when.type: fields` is a bounded conjunction of equality checks over current
stored fields. Every named field and literal must agree with the field's
declared type. The predicate is checked from the locked current Record, not
from a payload captured when the timer was armed.

Each Action input selects exactly one source:

- `fromRecordId: true` maps the anchor Record UUID to a reference input that
  targets that Record type.
- `fromField: FIELD` maps the field's current locked value to an input of the
  same type.
- `fromTimer: occurrence-id` maps the durable occurrence UUID.
- `fromTimer: due-at` maps the occurrence's intended timestamp.
- `value: VALUE` maps a typed non-null literal.

`fromField` may name an optional field even when the Action input is required.
If the current Record omits that field, ordinary live Action input validation
refuses the occurrence. It does not substitute a value or bypass the input's
required constraint.

Encrypted predicate and `fromField` values remain supported by the authored
contract. Runtime execution reads only the exact grant-covered fields from the
locked anchor. Field-at-rest encryption protects the stored Record value, not
the policy itself: authored `when.equals` and `input.value` literals remain
visible in the project and in compiled or effective package inspection. Do not
put secrets in those literals.

The maintained PostgreSQL test
`encrypted_predicate_write_opens_the_same_occurrence_and_maps_current_plaintext`
opens the same unfinished occurrence through an encrypted predicate update and
proves the mapped current plaintext reaches the authorized Action effect. For
that successful worker path, its plaintext canary is absent from JSON rendered
from every timer table, the real admitted operator projection, captured audit
entries, and scoped worker tracing. The tracing capture includes a positive
control. This test does not exercise actual `bregctl` process logging or every
possible failure path.

## Inspect the effective authority

Run the normal authoring checks and inspect the compiled access report:

```sh
bregctl check ./registry --production
bregctl --format json explain access ./registry
```

The access explanation lists each timer's control, predicate, and
effect-shaping input fields, the profiles and operations that can write those
fields, and the exact product-owned future-effect grant. That system grant is
not an access profile or token-selectable identity. Its target `operation`
member reuses the shared Operation representation, which is a superset of
timer authority. A realizable timer grant contains only `get` for exact reads,
`create` for bounded new Records, and `patch` for the exact anchor. Other
Operation values in the shared schema do not grant a timer those capabilities.

A timer-only Action remains in governed compiled inspection, but it has no
public Action route, access entry, default profile, generated invoke method,
portable Action contract, or public Registry metadata entry. Do not add a
synthetic profile to make it callable.

## Milestone 1 boundaries

Milestone 1 does not backfill historical Records when a timer is introduced.
A newly created Record can arm its timer from its initial control values. A
Record that already existed before the timer was activated needs a later
material write to `at`, `notAfter`, or `rearmOn`. The milestone also does not
provide a force-run command, successful timer-initiated rearming, payment
observation, Messaging delivery, Proposal timing, membership scheduling, a
per-Record timer projection, Studio or App Kit authoring, or a large-backlog
capacity claim.

The operator surface is separate from ordinary Record APIs. Its list and show
reports contain bounded operational metadata and keyed Record references, not
mapped input values, participants, result payloads, or claim tokens. A
technical retry can add one attempt allowance to the exact eligible occurrence;
it does not bypass current package, control, instance, or Action authority.

## Inspect and control timer work

Use the runtime configuration for the Registry deployment you are operating.
The path must be absolute. JSON output is suitable for scripts and keeps the
closed state, block, outcome, and technical-code vocabularies explicit:

```sh
runtime_config=/absolute/path/to/runtime.yaml

bregctl --format json timer status --runtime-config "$runtime_config"
bregctl --format json timer list --runtime-config "$runtime_config" --limit 50
bregctl --format json timer show --runtime-config "$runtime_config" \
  --occurrence-id 00000000-0000-0000-0000-000000000000
```

List pages use an opaque cursor returned by the preceding page. Status scans
each occurrence state and each block kind independently, with a 10,000-row
ceiling for every category. It reports each capped count and sets
`countsTruncated` when any category or the separate live-lease sample exceeds
its ceiling. `staleRevisionCount` is a separate sum over capped samples of up
to 10,000 pending, leased, and blocked rows per state. Prometheus
current-occurrence and block gauges also use independent category caps, while
current executed-attempt and stale-current gauges are sums over a separate
sample of at most 10,000 current rows. Those gauges need not reconcile with the
category counts after truncation. Show returns at most the latest 100 retained
attempts, in chronological order, and `attemptsTruncated` reports either
pagination or expired attempt detail that is no longer retained. `attemptCount`
remains the cumulative count even after attempt detail expires.
`detailAvailable` and `detailExpiresAt` describe retained occurrence-level
diagnostic detail, not whether the Action executed.

Status is a bounded live observation assembled from several database reads,
not a transactionally coherent snapshot. Its category counts, stale-revision
count, lease owners, and lag can therefore reflect slightly different moments.
Each mutating command rechecks the exact current control epoch and occurrence
state.
List pagination is also a live diagnostic view, not a durable event feed or a
snapshot: work committed after a page can sort behind its cursor and be absent
from the remainder of that scan. Start a new scan when completeness matters.

These commands use the runtime database credential and the keyed companion
audit journal from the named runtime configuration. There is no separate timer
operator database role. Protect that configuration and credential as operator
capability: the database cannot distinguish `bregctl timer` from another holder
of the same credential, which could use the runtime role's database grants to
write timer tables and control columns without `bregctl`'s reason, audit, and
compare-and-set checks. Migration-owned protocol and instance-binding state
remains outside those runtime writes.

Pause and resume use the control epoch returned by status. Re-read status after
an epoch mismatch. Supply a bounded change reference and reason that are useful
to your institutional audit process, but do not put secrets or personal data in
either value:

```sh
bregctl --format json timer pause --runtime-config "$runtime_config" \
  --expected-control-epoch 42 \
  --operator-reference CHG-1234 \
  --reason 'Pause while the downstream service is unavailable'

bregctl --format json timer resume --runtime-config "$runtime_config" \
  --expected-control-epoch 43 \
  --operator-reference CHG-1235 \
  --reason 'Resume after downstream recovery was verified'
```

Retry is limited to the exact current technically blocked occurrence and its
observed cumulative attempt count. It grants one additional attempt; it does
not run the Action synchronously or reset the count. Retry is refused unless
the global timer control is `running`; after reconciling the block, resume a
paused or adoption-held control before retrying:

```sh
bregctl --format json timer retry --runtime-config "$runtime_config" \
  --occurrence-id 00000000-0000-0000-0000-000000000000 \
  --expected-attempt-count 5 \
  --operator-reference INC-5678 \
  --reason 'Retry after the transient runtime failure was resolved'
```

Status, list, and show remain available while timer claims are paused or in
adoption hold. An expired valid `notAfter` window makes retry ineligible. The
worker eventually materializes unfinished work as missed; status is not a
promise that this asynchronous transition is visible at the exact deadline.
An invalid or unknown current window remains a configuration block until a
corrective governed Record write or a reviewed successor timer configuration
makes the window valid. A preserved technical block remains technical across
those successor changes. An invalid window is never inferred as missed from a
stale predecessor deadline.

Pause, resume, and retry commit the database transition before writing the
final companion-audit response. A `timer.audit.unavailable` result can therefore
mean the transition committed but was not confirmed to the operator. Do not
assume rollback or repeat the command blindly. Re-read status and the exact
occurrence, compare the control epoch, occurrence state, and `attemptCount`,
then reconcile the unfinished audit request before choosing a follow-up.

## Upgrade an existing Registry

Every package built with this release declares Record timer store support,
including a project that defines no timers. A package built by an earlier
release is predecessor-only for this engine feature. Starting the new runtime
with that older package does not add tables or rewrite the active catalog. Keep
the exact active package directory, build a governed successor from it with
this release, plan and apply that successor, and only then restart the runtime
on the successor package:

```sh
bregctl test PROJECT --baseline-package ACTIVE_PACKAGE --runtime-config RUNTIME --credentials CREDENTIALS --output RECEIPT
bregctl package PROJECT --baseline-package ACTIVE_PACKAGE --test-receipt RECEIPT --output BUILD
bregctl plan --runtime-config RUNTIME --package BUILD/package
bregctl apply --runtime-config RUNTIME --package BUILD/package
```

This is the ordinary successor-package workflow, not a separate timer migration
command. The package records the engine-owned timer store transition; operators
do not supply timer schema SQL.

For a successor, `bregctl plan` reports each added, changed, removed, or
effect-input-migration timer without Record values. It includes predecessor and
successor policy revisions plus a bounded observation of current unfinished
markers. `observedUnfinishedCount` may be partial when `truncated` is true;
`hasStaleRevisions` says the observed cache spans older policy revisions.
Changed-policy outcomes remain unknown until refresh. A removed timer is known
to be fenced from execution, and a newly added timer leaves historical Records
unarmed. The plan does not scan business Records or offer backfill.

## Run more than one replica

All replicas of one Registry deployment use the same active package,
authoritative database, and logical `identity.instanceId`. They also need the
same relevant runtime key and provider configuration. Keep
`identity.instanceId` stable across replicas: it identifies the deployment and
derives durable hook event identity, not the individual process or timer
worker.

Configure a distinct durable audit sink for each process. Replica processes
must connect directly to PostgreSQL or through session-mode pooling. Do not use
transaction-mode PgBouncer: BReg's registry interlocks use session-level
PostgreSQL advisory locks that must remain on the same connection.

Use process IDs, logs, and the database connection's application name to
distinguish worker processes operationally. Worker concurrency and database
pool limits apply to each process. The number of lease owners visible in timer
status is an observation of current ledger work, not a count of deployed
replicas.

## Restore boundary

Fence the original primary before a restored or promoted copy can serve. Run
the existing instance-claim adoption against the restored database, then keep
timer work in adoption hold while reconciling the recovery window. Inspect the
timer status and resume only with the expected control epoch and an audited
operator reference and reason. Resume is the only transition that releases an
adoption hold.

A database restore carries the timer ledger and retained attempt history only
up to the restore point. It cannot establish whether an external downstream
effect completed after that point. Reconcile those downstream systems and any
logical outbox delivery separately before resume. The milestone does not claim
a full backup-and-restore or downstream-reconciliation exercise.

`retention.receiptRetentionDays` bounds terminal diagnostic detail and attempt
history. Finished attempt detail may expire even while a current occurrence
remains blocked; the cumulative attempt count and current failure metadata stay
available. After detail expires, restore cannot recover it. Retention may also
remove expired non-current terminal occurrences. The current settled generation
marker and binding-removal incarnation fences survive indefinitely, so do not
infer missing execution from absent expired detail or older terminal rows.
