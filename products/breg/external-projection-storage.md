# External projection storage and recovery

When you operate indexed external views, keep the projection cache separate from the registry's own records and backups. An external value becomes readable only under the current package, deployment binding, source grant, local profile, and expiry. Refreshing the cache does not create a Record revision.

## Provisioning and binding

Indexed projections require separate migration and runtime PostgreSQL roles. Activation and startup refuse a shared role; packages without indexed projections can keep their existing role layout. The migration role installs the projection store when the compiled project contains an indexed projection. A project with live projections only, or without external projections, does not install this store. The runtime role can read the four tables and execute their bounded functions. It cannot insert, update, or delete their rows directly.

The migration-installed binding function contains the compiled projection allowlist. Its definition is part of the managed catalog fingerprint. At startup, a current reviewed deployment binding can fill an empty allowlisted slot under the exact active package and activation. A restart with the same binding and source grant reuses the stored epoch.

A different binding, source grant, or retention policy cannot replace an already bound slot through runtime startup. A withdrawn slot also stays withdrawn. These changes require operator maintenance under migration authority. Changing the compiled external contract invalidates its previous associations and requires a fresh binding and acquisition. Removing the final indexed projection removes its rebuildable store during package activation.

The current link requires the local reference scheme to match the source selector scheme.
The named link reserves `identifierBinding` for a future versioned resolver contract.
That resolver would take the authorised local reference and return a source-scoped handle
before Adapter acquisition. The current checker refuses unknown binding configuration.

## Freshness and retention

`cacheTtlSeconds` bounds the age of a usable source result. The effective deployment TTL may shorten, but never exceed, the authored TTL. The effective read expiry is the earlier of that lifetime and the source result's expiry. The retention bound is measured from the original source observation time, not from refresh completion and not as an extra grace period after expiry. Source retention permission can shorten that bound.

A captured snapshot stores the observation time and a keyed revision reference when the source supplies a revision. The reference is scoped to the bound source.

Replaying an accepted result keeps its original expiry. A failed exact-key refresh removes the previous one/absent snapshot, making coverage unproven. An interrupted related-collection refresh preserves its previous verified complete snapshot without extending its lifetime. Explicit grant denial or no-store removes either kind, fenced against newer publications. A source response marked `no-store` cannot enter the indexed store. If it supersedes an earlier retained result for the same subject, the guarded retention-refusal path removes that result; an older refresh cannot erase a newer publication.

Reads check expiry independently of the refresh job. Indexed predicates and counts refuse incomplete coverage before selecting matching rows. A complete empty related collection is covered; a partial collection, source failure, or protected-existence response is not evidence of emptiness or absence.

The bounded purge selects snapshots at freshness expiry, before their maximum retention deadline where that deadline allows headroom. Run it regularly, size capacity for the backlog, and configure an erasure margin greater than the worker interval and expected recovery delay. Purge also removes data from withdrawn or replaced epochs. Freshness enforcement keeps expired values out of responses even when refresh or purge is delayed, but a delayed purge can still breach a storage obligation. Monitor purge failures, expiry backlog, and database downtime separately. No physical erasure guarantee holds during a database outage or when backlog exceeds the configured margin. Database WAL and physical snapshots need their own retention policy.

## Schedule refresh and inspect coverage

Run the named view’s `POST /v1/external-views/{view}/{link}/refresh` with the approved machine profile. Continue with the returned `nextCursor` until the sweep ends. For independent related labels, run `POST /v1/external-views/{view}/{link}/refresh-labels` after the related collection refresh. That machine profile needs explicit refresh grants on both projections under the same purpose. The label sweep selects keys only from authorised roots with fresh complete collections. A changed collection generation requires a fresh sweep.

The refresh report counts processed roots or related rows, published values, reused keys and unavailable results. The migration role’s scope inspection reports receipt counts by outcome and fresh, expired and invalidated snapshot counts. Use an authorised indexed query to test readiness for its local root scope.

## Operator withdrawal and grant renewal

Use [external-projection-scope.sh](../../scripts/external-projection-scope.sh) with a PostgreSQL service profile for the migration role. The script never requests source values. Runtime cannot execute its maintenance function. It takes the package advisory lock and checks the exact inspected package, activation, and scope epoch before mutation.

1. Stop dependent acquisition and update or disable the deployment binding first. Record the source withdrawal in deployment configuration or the source authority so it remains effective after a backup restore.
2. Run `bash scripts/external-projection-scope.sh inspect breg-migration PROJECTION`. Preserve the returned epoch, packageDigest, and activationId for the next command. A null epoch is passed as `unbound`.
3. Withdraw with `bash scripts/external-projection-scope.sh withdraw breg-migration PROJECTION EPOCH PACKAGE_DIGEST ACTIVATION_UUID`. This disables the scope and erases its retained values and refresh receipts. Runtime startup cannot reactivate it.
4. After reviewing a renewed binding and grant, obtain its validated fingerprints and effective limits with `bregctl generate external-source-facts --runtime-config ABSOLUTE_FILE --output NEW_FILE PROJECT`. This reads deployment configuration without acquiring source data. Use the chosen projection entry's `bindingDigest`, `grantDigest`, `cacheTtlSeconds`, and `maximumRetentionSeconds`; do not calculate the digests by hand. Inspect again, then run `bash scripts/external-projection-scope.sh rotate breg-migration PROJECTION EPOCH PACKAGE_DIGEST ACTIVATION_UUID BINDING_DIGEST GRANT_DIGEST TTL_SECONDS RETENTION_SECONDS`. Use the exact digests and effective bounds from the reviewed deployment configuration. Rotation allocates a fresh epoch and removes previous cache contents. A changed package or epoch refuses the operation; inspect and review again instead of retrying old values.
5. Start with the matching reviewed configuration and acquire fresh authorized data. Rotation does not assert coverage.

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

Startup can bind empty slots using the current reviewed deployment configuration. Indexed queries remain incomplete until authorized refresh covers their eligible roots. Restore does not mark a projection ready or extend any source lifetime. Live reads continue to use their own current source contract and retain no projection copy.

## Implementation references

- [Guarded projection storage and binding](../../crates/registry-breg/src/postgres/external_projection.rs)
- [Indexed coverage and query kernel](../../crates/registry-breg/src/postgres/external_view_query.rs)
- [Managed schema installation](../../crates/registry-breg/src/postgres/schema.rs)
- [Exact catalog and runtime privilege checks](../../crates/registry-breg/src/postgres/catalog.rs)
- [Instance adoption contract](../../crates/registry-breg/src/instance_claim.rs)

The focused PostgreSQL tests exercise publication fencing, replay, expiry, collection replacement, empty-cache restore provisioning, binding refusal, and runtime ACLs. The query tests exercise the compiled root read policy, coverage, filtering, counts, and paging. Full package activation, source-adapter, HTTP, and backup/restore acceptance remain separate integration checks.
