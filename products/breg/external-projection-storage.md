# External projection storage and recovery

When you operate indexed external views, keep the projection cache separate from the registry's own records and backups. An external value becomes readable only under the current package, deployment binding, source grant, local profile, and expiry. Refreshing the cache does not create a Record revision.

## Provisioning and binding

Indexed projections require separate migration and runtime PostgreSQL roles. Activation and startup refuse a shared role; packages without indexed projections can keep their existing role layout. The migration role installs the projection store when the compiled project contains an indexed projection. A project with live projections only, or without external projections, does not install this store. The runtime role can read the four tables and execute their bounded functions. It cannot insert, update, or delete their rows directly.

The migration-installed binding function contains the compiled projection allowlist. Its definition is part of the managed catalog fingerprint. At startup, each configured deployment binding binds its allowlisted slot under the exact active package and activation, one projection at a time. A restart with the same binding, source grant, and cache lifetime reuses the stored epoch, so the cache stays warm.

The binding and source grant fingerprints cover only what grants authority over cached rows: the reviewed pack contract, the operation, and the allowed fields. Renewing the grant cutoff, replacing a CA bundle, moving an endpoint, or changing acquisition limits keeps the stored epoch. A changed contract, operation, allowed field list, or effective cache lifetime starts a fresh epoch at the next start. A withdrawn slot whose binding is still configured also starts a fresh epoch. Rows under every older epoch are left for purge, and a withdrawn or replaced epoch never becomes readable again.

Each projection's scope covers its own declaration and its external record type. Editing a view, an access profile, or another projection keeps its cache. Changing the projection's own declaration resets its scope during package activation and requires fresh acquisition.

If you already run an indexed projection, activate a successor package with the release that adds managed refresh before starting that release against the database. The migration installs the queue and the compiler-owned lookup indexes. Activation refuses removal of the final indexed projection once the queue schema has been installed, so it cannot erase pending work or replay state. To stop acquisition, keep that declaration and remove its source binding and refresh plans from every BReg instance. Removing the remaining schema requires a separate reviewed retirement migration.

A projection that cannot bind leaves only its own views unavailable. Its binding may fail its own checks, its source grant may have expired, or the database may refuse its scope. Those views answer `503` with the `source.unavailable` Problem, whose `fieldPath` is `/externalProjections/{id}`. Other views keep serving. Startup logs each unavailable projection with the reason, and `bregctl doctor` reports each one as an `external-projection.unavailable` warning. A doctor check binds and rolls back, so it never moves a serving scope to a new epoch.

The current link requires the local reference scheme to match the source selector scheme.
The named link reserves `identifierBinding` for a future versioned resolver contract.
That resolver would take the authorised local reference and return a source-scoped handle
before Adapter acquisition. The current checker refuses unknown binding configuration.

Write access to a link's `fromField` chooses which outside subject BReg fetches. Whoever can set that field on a root decides which subject the source is asked for under the deployment's source grant, and which subject's values readers of that root then see. Grant write access to a link field only to identities trusted to assert that link, and review changes to it as you would review a disclosure.

A source states a decimal field as a JSON number, and BReg serves it as a string. An integer keeps its exact digits. Any other number is read as a double, so a value with more than about 15 significant digits is rounded before BReg serves it. A source that needs exact decimals beyond that cannot send them as JSON numbers; BReg does not accept decimal strings from a source.

## Freshness and purge

`cacheTtlSeconds` is the one cache lifetime of a source result. A deployment binding may set its own `cacheTtlSeconds` to shorten, but never extend, the authored value. The lifetime is measured from the original source observation time, not from refresh completion. The effective expiry is the earlier of that lifetime and the deployment binding's source grant cutoff, `grantValidUntil`. From a successful source response, BReg honours only `no-store`; it reads no other expiry or storage permission there, so set `grantValidUntil` no later than the source permits storage. There is no retention period after expiry: an expired value is purged.

A captured snapshot stores the observation time and a keyed revision reference when the source supplies a revision. The reference is scoped to the bound source.

Replaying an accepted result keeps its original expiry. A refresh that fails because the source is unavailable, returns an incomplete result, or cannot be acquired under the current binding keeps the previous snapshot of either kind until its own expiry, without extending its lifetime. Explicit grant denial, or a successful source response marked `no-store`, removes the previous snapshot, making coverage unproven, fenced against newer publications. A `no-store` on an error, a redirect or the authentication challenge that starts a credential refresh changes nothing: that refresh fails as unavailable and keeps the previous snapshot. A successful source response marked `no-store` cannot enter the indexed store, even when a later step of the same acquisition fails. If it supersedes an earlier retained result for the same subject, the guarded retention-refusal path removes that result; an older refresh cannot erase a newer publication.

Reads check expiry independently of the refresh job. Indexed predicates and counts refuse incomplete coverage before selecting matching rows. Each page reads coverage, rows and any count from one statement snapshot, so a count always matches complete coverage at that moment. A refresh records each key in its own short transaction, so a read waits for at most one key's publication and can show new values for some keys of a page in flight and previous values for the rest. A `nextCursor` stays valid while refreshes publish or fail individual keys; the next page reads the values current when it runs. A row whose ordering value changed between pages can appear twice or not at all. A cursor is encrypted and authenticated with the deployment's cursor key and bound to its caller, query and projection generation, so its contents (including the sort value it resumes from) cannot be altered or read by the client. A sort value resumes from up to 6144 bytes. When the last row of a page carries a longer sort value, or its cursor (key, query and sort value, with quotes, backslashes and control characters counted as their JSON escapes) would exceed the 8 KiB cursor payload, that page's request is answered `source.unavailable` and no `nextCursor` is issued; the earlier pages were served, and the listing stops there. Every cursor the server issues is one the next page accepts. Rotating, withdrawing or resetting the projection invalidates outstanding cursors. A complete empty related collection is covered; a partial collection, source failure, or protected-existence response is not evidence of emptiness or absence.

A read of one record looks only at that record. Every other indexed page, including each continuation page, computes coverage, root presence, expiry and any count over every root the caller is authorized to read before it selects its rows, so its cost grows with the caller's whole authorized population, not with the page size. Grant indexed views only to access profiles whose row boundaries are narrowed to the records their callers need, and rate-limit the callers of indexed queries and of refresh at the gateway.

A root whose link field is empty or unset names no outside subject. It counts as covered, reads with its external fields absent, or as an empty related collection, and its refresh sends no source request. A root whose link key the store or the source contract would refuse is never sent to the source. The store refuses a key over 1024 bytes or with a control character; the source contract also refuses a key over 512 bytes or with leading or trailing white space. Such a root reads as having no outside value, like a root with an empty link field, for that record alone: it is covered, its external fields are absent, and lists, predicates, sorts and counts over its view keep serving the other records. The refresh still logs and counts the key as `invalid-key` and as unavailable in its report, so an operator can find and correct it. A write of such a key to a field an external view links from is refused as `request.invalid` on create, patch, action, proposal, batch and import writes, and writes nothing. Two paths differ: a mutation returned in an action hook's answer is refused as `hook.proposal.mutation_refused`, and the SQL steps of a history migration write current rows without this check, so reads guard those rows. The same value in a field no view links from is accepted. A key stored before the view was configured is read under the rule above until it is corrected. A label sweep applies the same rules to each related row's label key, so one invalid label key leaves only that row without its label.

The purge worker runs every five seconds. Each pass deletes expired snapshots, refresh receipts whose lease has ended, and everything under withdrawn or replaced epochs, in at most eight batches of a thousand rows of each kind. Freshness enforcement keeps expired values out of responses even when refresh or purge is delayed, but an expired value stays stored until a pass deletes it. That happens while the database is down, while the server is stopped, and while a backlog larger than one pass drains. Size database capacity for the backlog. Where a storage obligation is strict, choose a cache lifetime shorter than that obligation by more than the worker interval and the time you need to recover from those conditions, and watch the signals in the next section. Database WAL and physical snapshots need their own retention policy.

## Monitor refresh and purge

Each signal names the projection and a fixed reason category. None carries a source key, a selector, a value or a secret.

- A purge pass that deletes rows logs one `info` line per projection and reason, with `snapshots` and `receipts` counts. The reason is `expired`, `replaced` for a rotated epoch, or `withdrawn`.
- A purge pass that fails logs `external projection retention tick failed` at `error`, with a `reason` of `registry-not-ready`, `lock-timeout`, `query-cancelled`, `database` or `deadline`. It names no projection, because one pass covers them all.
- A purge pass that reaches its batch bound logs a `warn` line. The rest of the backlog waits for the next pass.
- On the metrics listener, `breg_worker_last_success_age_seconds{worker="external-projection-retention"}` reports the seconds since the last completed pass. It is absent until the first pass completes. Alert when it grows well past the five-second interval.
- A refresh page that acquired keys logs one `info` line with its `published` count, and one `warn` line per failure reason with a `keys` count. The reason is `denied`, `retention-refused`, `unavailable`, `incomplete`, `invalid-binding`, or `abandoned` when a newer result, a changed root or a changed collection superseded the result before publication.
- A refresh page that holds link keys or label keys the store or the source contract would refuse logs a `warn` line with the reason `invalid-key` and a `keys` count. Those keys are never sent to the source, and the records that hold them read as having no outside value until the keys are corrected.
- A live read whose root holds a link key the store or the source contract would refuse logs one `warn` line with the `view`, the reason `invalid-key` and `keys` of 1. The key is never sent to the source and the record reads as having no outside value.
- A refresh request that fails as a whole logs a `warn` line with a `reason` of `concealed`, `invalid-cursor`, `incomplete`, `unavailable`, `projection-unavailable` or `deadline`.
- A live read whose source acquisition fails logs a `warn` line with the same reasons as a refresh key, other than `abandoned`. The view answers unavailable.
- `bregctl doctor` reports each projection a server would serve as an `external-projection.status` advisory. It gives the time the source grant expires and, for an indexed projection, when the newest snapshot it holds was observed. Renew a grant before that time. An old or missing newest snapshot means the refresh sweep is not running.
- `bregctl external-projection inspect` reports the expired snapshots that purge has not yet deleted.

## Schedule refresh and inspect coverage

Add an optional top-level `externalRefresh` block in your BReg runtime file, alongside `externalSources`. A plan targets one indexed view link. Reuse a worker binding when two plans use the same machine identity and row scope.

The following example uses the service profile and a 300-second source lifetime from the [external views example](examples/external-views/README.md). The service access token must have the named principal, requester client, required scope and purpose, and the expected claim for each root List boundary. The reviewed project gives that profile List permission and `refreshExternalProjections`. BReg uses the separate credentials under `externalSources` to contact the authority.

```yaml
externalRefresh:
  workers:
    licensing-zone-a:
      accessProfile: projection-refresh
      requesterClient: licensing-refresh
      principal: synthetic-licensing-refresh
      rowClaims: {jurisdiction: zone-a}
  plans:
    licensing-holders:
      worker: licensing-zone-a
      target: {view: licence-holder-indexed, link: holder}
      intervalSeconds: 120
    licensing-holdings:
      worker: licensing-zone-a
      target: {view: business-holdings-indexed, link: holdings}
      intervalSeconds: 120
      refreshLabels: true
      sourceChanges:
        holdings-indexed:
          requesterClient: business-change-notifier
          requiredScope: registry:licensing:holdings-change-hint
```

Check the complete file with `bregctl check PROJECT --runtime-config FILE`. `intervalSeconds` is measured from the start of one completed sweep to the start of the next. A sweep that runs past its interval is immediately due again. A failed traversal, expired target, exhausted retry, or reconciliation obligation discovered after the sweep started waits at least 60 seconds before the follow-up, so a persistent failure cannot create a tight loop. Keep the interval, the time to finish a sweep, and a margin for retries and timer delay inside the effective source lifetime. Measure them with your number of distinct subjects and the source's request budget. `pageSize` defaults to 50 and accepts 1 to 100. Collections use a smaller root page and every call observes the bound Adapter operation's own limits. `refreshLabels` defaults to false. Enable it only when the worker has the separate label projection grant and its source binding is available. A plan with an unavailable binding does not prevent unrelated views and plans from serving.

Run the following from your existing scheduler using the worker's current BReg access token. A newly registered or restored plan is immediately due. The command stops when ready work runs out, another worker holds the lease, or its run budget ends. Use `--start-sweep` for an immediate reconciliation request, which coalesces with one that is already due or in progress.

```bash
bregctl external-projection refresh \
  --breg-url https://licences.example.org \
  --plan licensing-holders \
  --access-token-file /run/secrets/licensing-refresh.jwt
```

Each `POST /v1/external-refresh-plans/{plan}/step` accepts `{}` or `{"startSweep":true}` and advances one bounded sweep page or ready target batch. PostgreSQL holds the lease and the sealed continuation, so another invocation can resume after interruption. Steps alternate between ready targets and a due sweep. An ordinary Record write queues a local root when it changes a link or a field used by the worker's row boundary. The worker rechecks the current root and may reuse a fresh snapshot. A source hint instead asks for a new observation. A transient failure retries the affected key while the previous value keeps its original expiry.

Removing a plan, changing its activation, authority or projection epoch, or disabling its indexed projection fences the previous generation immediately. Its pending selectors remain sensitive managed database state until their original expiry, but no worker can claim or publish them. The purge removes them after that bound; re-enabling a plan starts a current-generation reconciliation instead of reviving the retained work.

For source notifications, configure `sourceChanges` for a primary or enabled label projection. The notifier uses its own verified BReg service client. It posts `hintId`, `projection`, `selectorScheme` and `selector` to `POST /v1/external-refresh-plans/{plan}/hints`. A `202` acknowledges a committed queue entry, including replay of the same hint. It does not report whether an eligible local root exists. Reuse the same hint ID on delivery retry. See the [signed webhook bridge example](examples/webhook-receiver/README.md) for admission, retry, and holdings moves. A holdings notice fetches the complete current collection for the named parent. To pick up a move immediately, notify for both parents. A scheduled sweep reconciles missed notifications.

Use `bregctl doctor` to see the plan's due and lease state, last attempt and completed sweep, and queue age. The step report counts processed items, published and reused keys, failures and retries. A completed sweep can have acquisition failures. An authorised indexed query checks current coverage for the scope that query serves. The operator's grant horizon and queue status cannot establish coverage on their own.

Manual refresh remains available at `POST /v1/external-views/{view}/{link}/refresh`. Continue with `nextCursor` until it ends. For related labels, run `POST /v1/external-views/{view}/{link}/refresh-labels` after the collection refresh. Both modes check the same machine grants, row policy, scope and publication rules. Label acquisition uses only current eligible roots and fresh complete parent snapshots.

In a manual sweep, a root without a link key counts only as processed. An invalid key counts as unavailable. `bregctl external-projection inspect` reports projection receipt counts by outcome and fresh, expired and invalidated snapshot counts.

## Stop acquisition, withdraw, and renew

Deployment configuration is the only cutoff for acquisition. To stop acquiring a projection, remove its binding from the deployment configuration and restart. Its views then answer `source.unavailable`. A binding that stays in the configuration binds again at the next start and acquires fresh data, even after a withdrawal. Record a source withdrawal in deployment configuration or at the source authority so that it also holds after a backup restore.

Use `bregctl external-projection` with the runtime configuration. It connects with the configured migration role, reads no source values, and takes the registry lock. Runtime cannot execute its maintenance function. Withdraw and rotate check the active package, activation, and managed catalog in the same transaction that changes the scope, and record an audit request and response under `breg-external-projection-audit/v1`. While another session holds the migration lock, they answer `external-projection.in-progress` and change nothing.

1. Remove or update the deployment binding first, then restart.
2. Run `bregctl external-projection inspect --runtime-config ABSOLUTE_FILE --projection PROJECTION`. It reports the scope epoch, whether it is active, its binding and grant digests, its cache lifetime, the active package and activation, and the counts above. A null epoch means the projection has not bound yet.
3. Withdraw with `bregctl external-projection withdraw --runtime-config ABSOLUTE_FILE --projection PROJECTION`. This disables the scope and erases its retained values and refresh receipts. Withdrawal purges data; it does not stop acquisition. If the binding is still configured, the next start binds a fresh epoch and acquires again.
4. A renewed binding or grant needs no maintenance. When its contract, operation, allowed fields, or cache lifetime changed, the next start moves the projection to a fresh epoch and leaves the old rows for purge. Otherwise the stored epoch and its cache stay in place. To discard the cache under an unchanged binding, run `bregctl external-projection rotate --runtime-config ABSOLUTE_FILE --projection PROJECTION`. It computes the binding and grant digests and the effective cache lifetime from the configured binding, as startup does, without acquiring source data. It then allocates a fresh epoch and removes previous cache contents. A projection whose binding is missing or fails its own checks is refused with the reason.
5. Acquire fresh authorized data. Neither a fresh epoch nor rotation asserts coverage.

These operations do not change the governed schema or package digest. They mutate only the rebuildable projection cache. A database-only withdrawal cannot be durable across a backup that excludes those rows; the current deployment/source authority is the durable cutoff.

## Logical backups

Exclude data from all seven projection and managed-refresh tables. Keep their schema and functions so a restore retains the package-installed allowlist but starts with no source values, old bindings, refresh work, selectors, or receipts. For example, with PostgreSQL service profiles supplying your connections and credentials:

```bash
pg_dump --dbname='service=breg-backup' --format=custom \
  --exclude-table-data=registry_internal.registry_external_projection_scopes \
  --exclude-table-data=registry_internal.registry_external_projection_refreshes \
  --exclude-table-data=registry_internal.registry_external_projection_snapshots \
  --exclude-table-data=registry_internal.registry_external_projection_values \
  --exclude-table-data=registry_internal.registry_external_refresh_plans \
  --exclude-table-data=registry_internal.registry_external_refresh_work \
  --exclude-table-data=registry_internal.registry_external_refresh_receipts \
  --file=registry.backup
```

The seven exclusions do not remove the local identifiers that your own Records hold. Those identifiers remain part of the registry backup according to its ordinary policy. Do not use `--exclude-table`: the projection and refresh table definitions, privileges, and functions belong to the governed database schema. After restore, register the current plans and start their reconciliation sweeps under current source authority.

Use a PostgreSQL dump client compatible with the server version. Protect the backup according to the sensitivity of the registry's own records. Physical backups and storage snapshots do not provide these table-data exclusions, so they need a separately approved erasure and restore procedure before they can be used for an indexed grant.

## Restore

Restore with the registry's ordinary PostgreSQL and instance-claim procedure. Fence the original instance and complete explicit instance adoption before serving the restored database. Preserve the exact package and verify the restored managed catalog and runtime privileges.

Before startup, check the current source grant and deployment binding. A withdrawal stored only in excluded database rows does not survive the restore. Reflect withdrawn source authority in the current deployment configuration or at the source before allowing reacquisition. The absence of cached values prevents old bytes from being served, but it is not permission for a new acquisition.

Startup binds each configured projection using the current reviewed deployment configuration. Indexed queries remain incomplete until authorized refresh covers their eligible roots. Restore does not mark a projection ready or extend any source lifetime. Live reads continue to use their own current source contract and retain no projection copy.

## Implementation references

- [Guarded projection storage and binding](../../crates/registry-breg/src/postgres/external_projection.rs)
- [Managed PostgreSQL refresh queue](../../crates/registry-breg/src/postgres/external_refresh_queue.rs)
- [Scheduled and targeted refresh steps](../../crates/registry-breg/src/postgres/external_runtime/managed.rs)
- [Indexed coverage and query kernel](../../crates/registry-breg/src/postgres/external_view_query.rs)
- [Managed schema installation](../../crates/registry-breg/src/postgres/schema.rs)
- [Exact catalog and runtime privilege checks](../../crates/registry-breg/src/postgres/catalog.rs)
- [Instance adoption contract](../../crates/registry-breg/src/instance_claim.rs)

The focused PostgreSQL tests exercise publication fencing, replay, expiry, collection replacement, empty-cache restore provisioning, binding refusal, and runtime ACLs. The query tests exercise the compiled root read policy, coverage, filtering, counts, and paging. Full package activation, source-adapter, HTTP, and backup/restore acceptance remain separate integration checks.
