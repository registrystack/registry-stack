# Upgrade and rollback: v0.9.0 -> v0.10.0 -> v0.9.0

Status: release-gate procedure prepared on 2026-07-16. No successful execution
is claimed by this prepare change. A source-build run may be recorded against
the finalized source ref before tagging. The complete gate uses the immutable
published assets after the tag workflow and must pass before release acceptance
and closeout.

## Purpose

Prove that an operator can apply the intentional pre-1.0 compatibility breaks,
move Notary correctness state from Redis to Notary-owned PostgreSQL, bootstrap
Relay consultation state separately, verify restart and multi-instance
semantics, and restore the complete v0.9.0 deployment when rollback is required.

This procedure does not promise an in-place rollback of a v0.10.0 database.
Rollback restores the version-matched v0.9.0 configuration, images, Redis data,
and other state from the pre-upgrade backup.

## Fixed inputs

- Baseline source and images: annotated tag `v0.9.0`.
- Candidate source: the finalized beta-12 manifest source ref.
- Candidate images: source-built before tagging, then the immutable digests
  published by the `v0.10.0` tag workflow for the post-tag verification pass.
- Crosswalk: `1d44ec735fdc8a7c719264b339574371e8330337`.
- Database servers: PostgreSQL 16 for the upgrade proof, followed by the
  release-gated PostgreSQL 17 and 18 conformance jobs.
- Topology: one Registry Relay, one paired Registry Notary, one Relay-owned
  PostgreSQL database, and one separate Notary-owned PostgreSQL database. A
  second identical Notary replica is added for the concurrency proof. Do not
  share Relay tables, roles, schemas, or migrations with Notary.

Record exact source refs, image ids or digests, PostgreSQL versions, Compose or
orchestrator versions, host architecture, and timestamps. Do not use `latest`
or another mutable tag.

## Back up before upgrade

1. Remove the v0.9.0 Relay and Notary instances from traffic, then stop every
   writer.
2. Back up Relay and Notary configuration, signed bundles and trust anchors,
   secret references, audit files and shipping cursors, anti-rollback state,
   signing-key references, source files, and operator deployment definitions.
3. Back up the complete v0.9.0 Redis state and record whether credential status
   contains any unexpired suspension or revocation record. The PostgreSQL
   cutover has no Redis importer or dual-write mode. Any required credential
   status record blocks this exercise until a reviewed typed migration exists.
4. Record SHA-256 hashes, ownership, and permissions for the backup without
   printing secrets or state values. Keep v0.9.0 and v0.10.0 restore sets
   separate.
5. Record baseline health and readiness, one authorized and one denied Relay
   request, one Notary evaluation, and one duplicate replay rejection.

Keep the stopped Redis data inaccessible throughout candidate validation. Do
not delete it until the release is accepted and the rollback window closes.

## Drain the retired Redis state

From the last v0.9.0 writer acknowledgement, wait the longest applicable
interval. Use longer configured protocol lifetimes when present.

| State | Minimum drain |
| --- | --- |
| Machine quota | 1 minute |
| OID4VCI nonce and preauthorization state | 10 minutes |
| Evaluation and batch idempotency | 15 minutes |
| Self-attestation quota | 1 hour |
| Replay identifiers | Longest configured token or request lifetime |
| Credential status | No timed drain; required records must be absent or migrated |

The wait is the maximum applicable interval, not the sum. A timed drain does
not make a lost suspension or revocation safe.

## Migrate configuration

Apply the v0.10.0 changelogs and release notes as a complete reauthoring guide:

- Replace the retired Notary Redis settings with the typed `state.postgresql`
  block. Supply the runtime URL, migration URL, TLS root, and sensitive-state
  key through named environment variables.
- Provision a dedicated Notary database, migration login, `NOLOGIN` owner, and
  runtime login. Run `registry-notary state install`, then `state doctor`.
- Use one Notary authority per Relay trust domain. Replicas may share a Notary
  database only when they serve the same authority configuration.
- Bootstrap Relay consultation state with its separately owned PostgreSQL
  database, roles, schemas, audit-pseudonym keyring, and retention settings.
  Do not grant Relay roles access to Notary state or the reverse.
- Replace removed Notary authentication modes and legacy federation or source
  configuration with the paired authority, internal workload, and current
  federation naming documented by v0.10.0.
- Run the CEL adapter as the released standalone Notary worker where the
  selected profile requires it. Run the Relay Rhai worker separately for Relay
  source adaptation. Neither worker is a generic shared state service.
- Regenerate manifests and derived artifacts. RFC 8785 canonical JSON can
  change digests for numeric or non-ASCII values, so do not copy a v0.9.0
  digest into the new project file.
- Reauthorize any `registryctl` workflow that used a removed command. Install
  `registryctl` v0.10.0 together with
  `registryctl-v0.10.0-image-lock.json`, then regenerate and review the project.

Run both products' `doctor` commands before starting a listener. Any
unclassified install, doctor, startup, or readiness failure stops the exercise.

## Candidate upgrade proof

Start one candidate Relay and one candidate Notary replica without public
traffic, then record all of the following:

- Both products report `0.10.0`; liveness succeeds; readiness attests the
  configured state, schema, roles, and selected deployment posture.
- An unauthorized Relay read is denied and an authorized purpose-bound read
  succeeds.
- A native Notary consultation uses the paired Relay contract and returns only
  the declared result envelope.
- A replay or nonce decision created before a Notary process restart remains
  enforced after restart.
- A retained evaluation remains available until its expiry after restart.
- Relay consultation idempotency and audit-pseudonym state survive a Relay
  restart.
- Audit-chain verification succeeds and logs contain no raw secret, token,
  subject identifier, database URL, state value, or pseudonym key.

Add a second identical Notary replica sharing the Notary database. Race the
same replay, nonce consumption, batch idempotency key, and preauthorization
redemption through both replicas. Exactly one state transition may win, and an
idempotent batch must charge quota once. Stop PostgreSQL and prove both replicas
become not ready. Restore PostgreSQL and require a fresh complete attestation
before readiness recovers.

Run equivalent PostgreSQL restart and multi-instance consultation checks for
Relay where the deployed profile enables native consultation.

## Backup and restore proof

1. Quiesce candidate writers and take complete, encrypted logical backups of
   the Relay and Notary databases. Preserve the corresponding role
   provisioning, application release, migration set, and Notary sensitive-state
   key version.
2. Restore each dump into its own empty, isolated database with freshly
   provisioned roles. Never restore individual correctness tables.
3. Reattest Relay consultation bootstrap state. For Notary, run `state install`
   to bind the restored role identities, then run `state doctor`.
4. Start one replica without traffic and repeat the restart, duplicate
   rejection, retained-evaluation, keyring, and readiness checks.
5. Treat any snapshot that may predate acknowledged traffic as stale. Keep it
   quarantined for the maximum applicable drain and reconcile credential
   status before admission.

Successful database restore alone is not permission to serve. An unreconciled
revocation, suspension, replay marker, nonce tombstone, idempotency result, or
quota debit remains a release blocker.

## Rollback proof

1. Stop every v0.10.0 Relay and Notary writer. Retain the v0.10.0 databases and
   backup evidence; do not point v0.9.0 binaries at them.
2. Restore the complete v0.9.0 configuration, secret references, audit and
   anti-rollback files, signing references, and Redis backup.
3. Restore the exact v0.9.0 image ids or digests and start the baseline
   topology.
4. Repeat baseline health, readiness, authorized and denied Relay reads,
   Notary evaluation, and duplicate replay rejection.
5. Verify backup hashes and prove that operator-owned sources, audit evidence,
   Redis data, and the retained v0.10.0 databases were not silently rewritten.

Rollback succeeds only when the restored v0.9.0 topology reaches the baseline
recorded before the upgrade. A failed rollback, missing correctness record, or
secret leak blocks the release.

## Published-asset acceptance

After `v0.10.0` publishes, run this complete procedure using downloaded release
assets and immutable image digests, including registryctl installation,
generated-project, upgrade, restart, multi-instance, backup, restore, and
rollback checks. Verify `SHA256SUMS`, the image lock's source and digest lineage,
representative cosign signatures, SLSA provenance, and final GHCR digests. Do
not mark the release manifest `released` until this acceptance run passes or a
specific held gate is recorded without overstating the evidence.
