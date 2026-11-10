# External projection storage and recovery

When you operate indexed external views, keep the projection cache separate from the registry's own records and backups. An external value becomes readable only under the current package, deployment binding, source grant, local profile, and expiry. Refreshing the cache does not create a Record revision.

## Provisioning and binding

Indexed projections require separate migration and runtime PostgreSQL roles. Activation and startup refuse a shared role; packages without indexed projections can keep their existing role layout. The migration role installs the projection store when the compiled project contains an indexed projection. A project with live projections only, or without external projections, does not install this store. The runtime role can read the four tables and execute their bounded functions. It cannot insert, update, or delete their rows directly.

The migration-installed binding function contains the compiled projection allowlist. Its definition is part of the managed catalog fingerprint. At startup, each configured deployment binding binds its allowlisted slot under the exact active package and activation, one projection at a time. A restart with the same binding, source grant, and cache lifetime reuses the stored epoch, so the cache stays warm.

The binding and source grant fingerprints cover only what grants authority over cached rows: the reviewed pack contract, the operation, and the allowed fields. Renewing the grant cutoff, replacing a CA bundle, moving an endpoint, or changing acquisition limits keeps the stored epoch. A changed contract, operation, allowed field list, or effective cache lifetime starts a fresh epoch at the next start. A withdrawn slot whose binding is still configured also starts a fresh epoch. Rows under every older epoch are left for purge, and a withdrawn or replaced epoch never becomes readable again.

Each projection's scope covers its own declaration and its external record type. Editing a view, an access profile, or another projection keeps its cache. Changing the projection's own declaration resets its scope during package activation and requires fresh acquisition. Removing the final indexed projection removes its rebuildable store during package activation.

A projection that cannot bind leaves only its own views unavailable. Its binding may fail its own checks, its source grant may have expired, or the database may refuse its scope. Those views answer `503` with the `source.unavailable` Problem, whose `fieldPath` is `/externalProjections/{id}`. Other views keep serving. Startup logs each unavailable projection with the reason, and `bregctl doctor` reports each one as an `external-projection.unavailable` warning. A doctor check binds and rolls back, so it never moves a serving scope to a new epoch.

The current link requires the local reference scheme to match the source selector scheme.
The named link reserves `identifierBinding` for a future versioned resolver contract.
That resolver would take the authorised local reference and return a source-scoped handle
before Adapter acquisition. The current checker refuses unknown binding configuration.

## Freshness and purge

`cacheTtlSeconds` is the one cache lifetime of a source result. A deployment binding may set its own `cacheTtlSeconds` to shorten, but never extend, the authored value. The lifetime is measured from the original source observation time, not from refresh completion. The effective expiry is the earlier of that lifetime and the source result's own expiry, and the source must permit storage until then. There is no retention period after expiry: an expired value is purged.

A captured snapshot stores the observation time and a keyed revision reference when the source supplies a revision. The reference is scoped to the bound source.

Replaying an accepted result keeps its original expiry. A refresh that fails because the source is unavailable, returns an incomplete result, or cannot be acquired under the current binding keeps the previous snapshot of either kind until its own expiry, without extending its lifetime. Explicit grant denial or no-store removes the previous snapshot, making coverage unproven, fenced against newer publications. A source response marked `no-store` cannot enter the indexed store. If it supersedes an earlier retained result for the same subject, the guarded retention-refusal path removes that result; an older refresh cannot erase a newer publication.

Reads check expiry independently of the refresh job. Indexed predicates and counts refuse incomplete coverage before selecting matching rows. A complete empty related collection is covered; a partial collection, source failure, or protected-existence response is not evidence of emptiness or absence.

The bounded purge worker runs every few seconds and deletes snapshots once they expire. It also removes data from withdrawn or replaced epochs. Size database capacity for the backlog. Where a storage obligation is strict, choose a cache lifetime shorter than that obligation by more than the worker interval and the expected recovery delay. Freshness enforcement keeps expired values out of responses even when refresh or purge is delayed, but a delayed purge can still breach a storage obligation. Monitor purge failures, expiry backlog, and database downtime separately. No physical erasure guarantee holds during a database outage or when backlog exceeds that margin. Database WAL and physical snapshots need their own retention policy.

## Schedule refresh and inspect coverage

Run the named view’s `POST /v1/external-views/{view}/{link}/refresh` with the approved machine profile. Continue with the returned `nextCursor` until the sweep ends. For independent related labels, run `POST /v1/external-views/{view}/{link}/refresh-labels` after the related collection refresh. That machine profile needs explicit refresh grants on both projections under the same purpose. The label sweep selects keys only from authorised roots with fresh complete collections. A changed collection generation requires a fresh sweep.

The refresh report counts processed roots or related rows, published values, reused keys and unavailable results. `bregctl external-projection inspect` reports receipt counts by outcome and fresh, expired and invalidated snapshot counts. Use an authorised indexed query to test readiness for its local root scope.

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

Exclude data from all four projection tables. Keep their schema and functions so a restore retains the package-installed allowlist but starts with no source values, old bindings, or refresh receipts. For example, with PostgreSQL service profiles supplying your connections and credentials:

```bash
pg_dump --dbname='service=breg-backup' --format=custom \
  --exclude-table-data=registry_internal.registry_external_projection_scopes \
  --exclude-table-data=registry_internal.registry_external_projection_refreshes \
  --exclude-table-data=registry_internal.registry_external_projection_snapshots \
  --exclude-table-data=registry_internal.registry_external_projection_values \
  --file=registry.backup
```

The four exclusions do not remove the local identifiers that your own Records hold. Those identifiers remain part of the registry backup according to its ordinary policy. Do not use `--exclude-table`: the projection table definitions, privileges, and functions belong to the governed database schema.

Use a PostgreSQL dump client compatible with the server version. Protect the backup according to the sensitivity of the registry's own records. Physical backups and storage snapshots do not provide these table-data exclusions, so they need a separately approved erasure and restore procedure before they can be used for an indexed grant.

## Restore

Restore with the registry's ordinary PostgreSQL and instance-claim procedure. Fence the original instance and complete explicit instance adoption before serving the restored database. Preserve the exact package and verify the restored managed catalog and runtime privileges.

Before startup, check the current source grant and deployment binding. A withdrawal stored only in excluded database rows does not survive the restore. Reflect withdrawn source authority in the current deployment configuration or at the source before allowing reacquisition. The absence of cached values prevents old bytes from being served, but it is not permission for a new acquisition.

Startup binds each configured projection using the current reviewed deployment configuration. Indexed queries remain incomplete until authorized refresh covers their eligible roots. Restore does not mark a projection ready or extend any source lifetime. Live reads continue to use their own current source contract and retain no projection copy.

## Implementation references

- [Guarded projection storage and binding](../../crates/registry-breg/src/postgres/external_projection.rs)
- [Indexed coverage and query kernel](../../crates/registry-breg/src/postgres/external_view_query.rs)
- [Managed schema installation](../../crates/registry-breg/src/postgres/schema.rs)
- [Exact catalog and runtime privilege checks](../../crates/registry-breg/src/postgres/catalog.rs)
- [Instance adoption contract](../../crates/registry-breg/src/instance_claim.rs)

The focused PostgreSQL tests exercise publication fencing, replay, expiry, collection replacement, empty-cache restore provisioning, binding refusal, and runtime ACLs. The query tests exercise the compiled root read policy, coverage, filtering, counts, and paging. Full package activation, source-adapter, HTTP, and backup/restore acceptance remain separate integration checks.
