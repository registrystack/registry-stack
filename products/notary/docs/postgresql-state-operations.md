# PostgreSQL state operations

Registry Notary uses one PostgreSQL database for correctness state that must
survive restart or be shared by identical instances. This includes replay and
nonce decisions, retained evaluations, batch idempotency, credential status,
quotas, and OID4VCI preauthorization state. Notary does not use Relay schemas,
roles, tables, or migrations.

Give each independently configured Notary authority its own database and role
pair. Only replicas serving the same Notary configuration and trust domain may
share that database. The fixed functions deliberately do not add a generic
tenant layer, so pointing unrelated Notary services at one database would mix
their idempotency, quota, and identifier namespaces.

Use this guide for a first installation, the pre-1.0 Redis cutover, forward
upgrades, backup, restore, and recovery. Keep the Notary audit sink,
governed-config state, and signing-key backups in their separately owned
procedures.

## Prerequisites

Before installation, provide:

- PostgreSQL major 16, 17, or 18 on a writable primary;
- a dedicated Notary database with encrypted storage and encrypted backups;
- TLS between every Notary instance and PostgreSQL, including local
  PostgreSQL testing;
- a restricted migration login, a distinct `NOLOGIN` owner role conventionally
  named `registry_notary_owner`, and a restricted login role conventionally
  named `registry_notary_runtime`;
- migration and runtime database URLs delivered through the deployment secret
  manager, never command-line values;
- a mounted root certificate when the database certificate is not rooted in
  the host trust store; and
- when preauthorization is enabled, one base64url-encoded 32-byte
  sensitive-state key shared by all replicas.

Use the same released `registry-notary` binary and migration set for install,
doctor, and runtime admission. PostgreSQL tools used for logical backup must
support the source server major. Keep Notary clocks synchronized for audit and
token handling, although database expiry and quota decisions use PostgreSQL
time.

Configure the runtime connection by environment-variable name:

```yaml
state:
  storage: postgresql
  postgresql:
    url_env: REGISTRY_NOTARY_POSTGRES_URL
    root_certificate_path: /run/secrets/notary-postgres-ca.pem
    connect_timeout_ms: 5000
    operation_timeout_ms: 2000
    max_connections: 16
    sensitive_state_key_env: REGISTRY_NOTARY_SENSITIVE_STATE_KEY
```

`postgresql` is the only deployable storage value. `in_memory` is limited to
`deployment.profile: local` with `deployment.multi_instance: false`.

`max_connections` is the hard physical-connection cap for one Notary replica,
not the whole deployment. Reserve at least `replica count × max_connections`,
then add separate capacity for migrations, doctor, backup, monitoring, and
platform administration. Start with the default 16 only when that budget is
available. Smaller authority services can set a lower positive cap. A caller
waiting for a pooled session fails within `operation_timeout_ms`; opening a new
physical connection uses `connect_timeout_ms` and completes full runtime
attestation before serving state. Values above 256 are rejected to prevent a
configuration typo from preallocating an unsafe per-process resource bound.

Healthy physical connections are reused. A query timeout, query or driver
failure, failed readiness attestation, or changed database URL generation
evicts the connection. The next checkout reloads the URL from the named
environment variable and fully attests the replacement. The generation marker
is a process-keyed HMAC; URL and credential material are not retained in pool
metadata or emitted in diagnostics.

## Role separation

The `NOLOGIN` owner role owns `registry_notary_private`,
`registry_notary_api`, their objects, and the fixed transaction functions. Do
not grant it direct login. The separate migration login may assume the owner
role but has no superuser, role-creation, database-creation, replication, or
`BYPASSRLS` capability. Do not put its URL in a Notary runtime container.

The runtime role receives only schema usage and execution on the exact
`registry_notary_api` function signatures. It must not:

- own either Notary schema or any private table or sequence;
- have direct privileges on private tables or sequences;
- create schemas, objects, roles, or databases;
- be superuser or have `BYPASSRLS`;
- inherit the owner role; or
- receive Relay roles or privileges.

Every runtime function is security-definer code owned by the owner, uses a
pinned search path, schema-qualifies object references, and is not executable
by `PUBLIC`. `state doctor` verifies both required and forbidden privileges.
Do not fix a role failure by granting table access to the runtime role.

Provision role passwords and connection policy with the database platform or
infrastructure-as-code system. Preserve the provisioning definition with the
backup evidence. A database dump alone is not a complete role backup.

For a direct PostgreSQL installation, a database administrator can provision
the roles and database with the following `psql` input. Supply the two generated
passwords through the process environment, not as command-line arguments, and
then remove them from the administrator session:

```sh
NOTARY_MIGRATOR_PASSWORD="$(openssl rand -hex 32)" \
NOTARY_RUNTIME_PASSWORD="$(openssl rand -hex 32)" \
psql --set=ON_ERROR_STOP=1 --dbname=postgres <<'SQL'
\getenv migrator_password NOTARY_MIGRATOR_PASSWORD
\getenv runtime_password NOTARY_RUNTIME_PASSWORD
CREATE ROLE registry_notary_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  NOREPLICATION NOBYPASSRLS;
CREATE ROLE registry_notary_migrator
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  NOREPLICATION NOBYPASSRLS PASSWORD :'migrator_password';
CREATE ROLE registry_notary_runtime
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  NOREPLICATION NOBYPASSRLS PASSWORD :'runtime_password';
GRANT registry_notary_owner TO registry_notary_migrator;
CREATE DATABASE registry_notary OWNER registry_notary_owner;
REVOKE ALL ON DATABASE registry_notary FROM PUBLIC;
GRANT CONNECT ON DATABASE registry_notary
  TO registry_notary_migrator, registry_notary_runtime;
\connect registry_notary
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
```

In managed PostgreSQL, express the same role attributes, membership, ownership,
and revocations through the platform's supported provisioning mechanism. The
installer rejects unsafe owner, migration, or runtime role attributes.

## State commands

Run schema installation and forward migrations with the owner connection:

```sh
registry-notary --config /etc/registry-notary/notary.yaml state install \
  --migration-url-env REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL \
  --owner-role registry_notary_owner \
  --runtime-role registry_notary_runtime
```

`state install` reads runtime connection settings from the Notary config. It
uses the separately named migration URL, verifies that login may assume the
named `NOLOGIN` owner, and explicitly assumes the owner for DDL and grants. It
applies only the released, forward migration path and records the schema
version, capability, deterministic fingerprint, and owner/runtime role
identities. It does not start a listener or process application requests.

Attest the installed contract through the runtime connection:

```sh
registry-notary --config /etc/registry-notary/notary.yaml state doctor
```

`state doctor` connects only with the URL named by
`state.postgresql.url_env`. It verifies the supported server major, writable
primary, schema metadata and fingerprint, role identity, required execution
privileges, forbidden privileges, and a bounded runtime transaction call. A
nonzero exit blocks startup or rollout.

Both commands keep URLs, credentials, certificate paths, role identifiers,
SQL, table names, and stored identifiers out of diagnostics. Check that an
environment variable is present without printing its value.

## First installation

1. Provision the database, migration login, `NOLOGIN` owner, and runtime login.
2. Inject `REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL` only into the operator job.
   Inject `REGISTRY_NOTARY_POSTGRES_URL` and, when required,
   `REGISTRY_NOTARY_SENSITIVE_STATE_KEY` into each Notary replica.
3. Mount the root certificate read-only when one is configured.
4. Run `state install` with the released binary.
5. Run `state doctor`. Stop if it reports any incompatible schema, role,
   version, TLS, durability, or read-only condition.
6. Start one Notary replica with no public traffic. Confirm its readiness
   endpoint succeeds.
7. Run the restart and state smoke checks below. When preauthorization is
   enabled, complete a full offer-to-credential canary so the configured
   sensitive-state key is proven against encrypted state.
8. Start the remaining replicas from the same image and configuration. Confirm
   every replica reports ready before admitting traffic.

Do not let the runtime apply DDL automatically. A missing or partially applied
schema must fail before any listener binds.

## Clean Redis cutover

This pre-1.0 transition is a stopped-writer cutover. There is no Redis importer
or dual-write mode.

Before scheduling the cutover, inspect credential-status use. Proceed only
when credential status is disabled or the old store has no suspension or
revocation record that must survive. If any such record exists, the cutover is
blocked until a separately reviewed typed migration is available. Never
discard the store or recreate those credentials as valid.

At the maintenance window:

1. Remove Notary from traffic and stop every Notary writer.
2. Record the time at which the last writer stopped.
3. Wait the longest applicable drain interval from that time. Use configured
   token and request lifetimes when they are longer than the standard periods
   below.
4. Provision PostgreSQL, run `state install`, and run `state doctor`.
5. Start one PostgreSQL-backed replica without traffic and complete the smoke
   checks, including a process restart.
6. Start the remaining identical replicas, repeat readiness and
   multi-instance checks, then admit traffic.
7. Only after those checks pass, remove the Notary Redis service, volume,
   credentials, monitoring, and Redis backup job.

Use these minimum drain periods:

| State | Minimum drain from the last writer |
| --- | --- |
| Machine quota | 1 minute |
| OID4VCI nonce and preauthorization state | 10 minutes |
| Evaluation and batch idempotency | 15 minutes |
| Self-attestation quota | 1 hour |
| Replay identifiers | Longest configured token or request lifetime |
| Credential status | No timed drain; required records must be absent or migrated |

The cutover wait is the maximum of the applicable periods, not their sum. Keep
the old Redis data inaccessible during validation and delete it only at the
final removal step. Redis used by a separately deployed eSignet service is
eSignet-owned and is not part of this removal.

## Forward upgrades and replica admission

Database upgrades are forward-only and use a stopped-writer boundary:

1. Confirm the target release supports the PostgreSQL server major.
2. Remove traffic and stop every Notary writer.
3. Take and verify a database backup, role provisioning record, migration set,
   application release, and sensitive-state key version.
4. Run the target release's `state install` command as the owner.
5. Run the target release's `state doctor` command as the runtime role.
6. Start one target-release replica without traffic and confirm readiness and
   the smoke checks.
7. Start the remaining target-release replicas and admit traffic only after
   all instances attest the same schema fingerprint.

Do not run old and new binaries concurrently across an incompatible schema
change. A runtime admits only its exact compiled schema version, capability,
and fingerprint. A partially upgraded, older, or newer schema remains
unavailable.

Rolling admission applies only to replicas after the schema migration has
completed and every old writer is stopped. If the target application must be
rolled back, restore the matching database backup, role provisioning, and
sensitive-state key together, then follow stale-restore quarantine. Never run
an older binary against the forward schema.

For a PostgreSQL server major upgrade, keep every Notary writer stopped and use
the complete logical `pg_dump` and `pg_restore` procedure below for one
adjacent supported-major hop. Registry Stack CI exercises 16 to 17 and 17 to
18 with fresh target roles, changed role OIDs, full catalog reattestation, and
post-restore behavior for every correctness-state domain. Run `state install`
to rebind the target roles, run `state doctor`, then use the same one-replica
admission sequence. Do not skip a major or use the old major's physical data
directory with a new server binary.

## Retention and maintenance

Notary writes an absolute expiry when each record is created. Lowering a
future retention setting does not shorten existing rows.

| Domain | Retention |
| --- | --- |
| Replay identifier | Protocol token or request expiry |
| Reserved nonce | Configured nonce expiry |
| Consumed nonce | 60 seconds after consumption |
| Stored evaluation | Its absolute expiry, normally 15 minutes or a stricter self-attestation expiry |
| Completed or failed batch idempotency | 15 minutes |
| In-flight batch idempotency | Bounded owner lease, then takeover eligibility |
| Credential status | Credential expiry plus `credential_status.retention_seconds` |
| Machine quota | One-minute fixed window |
| Self-attestation quota | One-minute or one-hour fixed window by bucket |
| Preauthorization login state | Configured lifetime, at most 600 seconds |
| Preauthorization transaction code | Code lifetime, at most 600 seconds, or successful redemption |

Each serving replica begins expiry maintenance every 60 seconds. One
transaction deletes at most 1,000 expired rows from each typed state table and
reports whether any table filled that bound. A full per-table batch causes the
replica to release its pooled session, wait with a short bounded internal
backoff, and run another bounded transaction until every table returns a short
batch. The catch-up policy has no operator-facing tuning setting. Multiple
replicas may run these transactions concurrently because candidates are locked
with skip-locked semantics.

Logical expiry checks on reads and writes remain authoritative between
transactions, so a transient cleanup failure does not reopen expired state. A
failed catch-up transaction is retried by the next scheduled maintenance cycle.
Transient cleanup contention is not a reason to delete rows manually. Never
remove an unexpired replay row, nonce tombstone, idempotency completion,
credential-status record, quota window, or preauthorization row to recover
capacity.

Monitor database size, transaction latency, pool wait failures, the configured
per-replica connection cap, database connection saturation, dead tuples,
autovacuum, backup age, replication or archive lag, and doctor status.
Do not include row values or identifiers in monitoring labels.

## Logical backup with pg_dump

Stop writers for a simple quiesced backup, or use the database platform's
transactionally consistent snapshot workflow. Use a restricted PostgreSQL
service definition and password file so credentials do not appear in process
arguments. The password file must be owned by the backup operator and have
mode `0600`:

```ini
# /run/registry-notary/pg_service.conf
[registry_notary_migrator]
host=postgres.example.internal
port=5432
dbname=registry_notary
user=registry_notary_migrator
sslmode=verify-full
sslrootcert=/run/secrets/notary-postgres-ca.pem
```

`registry_notary_migrator` is an operator-defined libpq service name, not a
built-in Registry Notary setting. Point `PGSERVICEFILE` at its file when it is
not installed in a standard libpq location:

```sh
install -d -m 0700 /var/backups/registry-notary
PGSERVICEFILE=/run/registry-notary/pg_service.conf \
PGSERVICE=registry_notary_migrator \
PGPASSFILE=/run/secrets/registry-notary-migrator.pgpass \
pg_dump --format=custom --no-owner --no-acl \
  --role=registry_notary_owner \
  --file=/var/backups/registry-notary/notary-state.dump \
  --dbname=registry_notary
sha256sum /var/backups/registry-notary/notary-state.dump \
  > /var/backups/registry-notary/notary-state.dump.sha256
```

Encrypt the dump and checksum in the approved backup system. Preserve with
it:

- the application release and exact migration set;
- the source PostgreSQL major and backup tool version;
- reproducible owner/runtime role provisioning;
- the recovery timestamp and whether writers were quiesced; and
- the sensitive-state key version through the secret manager, outside the
  dump.

The database backup must include the whole Notary database at one consistent
point. Do not back up or restore individual correctness tables.

Restore into an empty, isolated database with no Notary network path:

```sh
sha256sum -c /var/backups/registry-notary/notary-state.dump.sha256
PGSERVICEFILE=/run/registry-notary/pg_service.conf \
PGSERVICE=registry_notary_migrator \
PGPASSFILE=/run/secrets/registry-notary-migrator.pgpass \
pg_restore --exit-on-error --single-transaction --no-owner --no-acl \
  --role=registry_notary_owner \
  --dbname=registry_notary \
  /var/backups/registry-notary/notary-state.dump
registry-notary --config /etc/registry-notary/notary.yaml state install \
  --migration-url-env REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL \
  --owner-role registry_notary_owner \
  --runtime-role registry_notary_runtime
registry-notary --config /etc/registry-notary/notary.yaml state doctor
```

Provision the migration, owner, and runtime roles before `pg_restore`. The
migration login must be able to assume the owner. Restoring with the owner role
makes every schema object owner explicit while omitting source-cluster ACLs.
The post-restore `state install` rebinds only the metadata role identities,
reapplies the complete compiled ACL baseline, and requires the complete
released schema catalog to attest in the same transaction. It never replaces
correctness rows, changes object ownership, or repairs schema drift. Do not
admit traffic until doctor, an applicable preauthorization canary, and the
quarantine decision all pass.

## WAL archiving and point-in-time recovery

Use physical base backups plus continuous WAL archiving when the recovery
point objective requires point-in-time recovery. Protect the base backup, WAL
archive, tablespace mapping, encryption material, and PostgreSQL configuration
as one recovery set. Test WAL restore through the database platform, not on the
production primary.

For recovery:

1. Keep every Notary replica stopped and network-blocked from the recovery
   database.
2. Restore the complete cluster or Notary database to the selected recovery
   target and promote it to a writable primary.
3. Provision or restore the owner/runtime roles. A full physical cluster
   restore preserves their identities; a logical or cross-cluster restore
   requires `state install` to reattest them.
4. Restore the sensitive-state key version corresponding to the recovery
   point.
5. Run `state install`, then `state doctor`.
6. Classify the recovery point as known quiesced or potentially stale.
7. Complete the required quarantine and smoke checks before traffic admission.

Choosing a WAL target before an acknowledged one-time consume, status update,
or quota debit can reopen a correctness decision. Successful PostgreSQL
recovery is not by itself permission to serve.

## Stale-restore quarantine

A backup is potentially stale when writers were not quiesced or when its
recovery point may predate acknowledged traffic. Keep Notary offline in that
case.

Before release from quarantine:

1. Determine the latest time at which the old deployment could have
   acknowledged a write.
2. Wait until every token, request, nonce, evaluation, idempotency key, and
   preauthorization value that could be missing from the restore has expired.
3. Wait through the maximum one-hour self-attestation quota window. Treat
   uncertain quota state conservatively.
4. Reconcile credential status against retained issuance and status evidence.
   If a suspension or revocation could be missing, keep status and issuance
   unavailable. Time does not repair a lost revocation.
5. Run `state doctor` again and complete restart and multi-instance smoke
   checks.

Use the later of the recovery point and the last possible acknowledged-writer
time as the start of the maximum applicable drain interval. If that time
cannot be established, begin the full configured drain at quarantine entry and
rotate or revoke affected credentials as required by incident policy. Never
mark unknown status records valid to finish recovery.

A known quiesced and transactionally consistent backup may skip the timed
quarantine only after schema, role, key, credential-status, and semantic checks
all pass.

## Sensitive-state key backup and rotation

The sensitive-state key is not stored in PostgreSQL and is not included in
`pg_dump`, a physical base backup, or WAL. Store it as a versioned secret with
access restricted to Notary workloads and recovery operators. Record the
secret version with each database backup without recording key material.
Every replica must use the same key version while any preauthorization row is
live. Activation, `state doctor`, and every readiness probe compare the
configured key id with every live row in both preauthorization tables. A wrong
backup-matched secret or live mixed-key state therefore remains unavailable.
Both sensitive reservation transactions also serialize key-generation
admission and reject a different key while either table has a live row.
Unexpired replay markers use the verified Notary issuer and stable Notary
replay hashes rather than this sensitive key or mutable service configuration,
so an already redeemed pre-authorized code remains spent across the rotation.

Rotate it with a stopped-issuance drain:

1. Stop admission of new OID4VCI preauthorization flows on every replica.
2. Keep the old key available and wait 600 seconds from the last admitted
   preauthorization flow.
3. Confirm expired preauthorization rows have been pruned by normal bounded
   maintenance.
4. Stop all replicas. Replace the secret with one new base64url-encoded
   32-byte key and update every replica atomically.
5. Start one replica, run `state doctor`, and exercise one complete
   preauthorization flow.
6. Start the remaining replicas and resume preauthorization only after all use
   the same key version.

Do not overlap replicas using different sensitive-state keys. Do not retain
old keys in application configuration after the drain.

If the recovery key is unavailable, keep Notary unavailable until every
restored preauthorization row has passed its absolute expiry, with 600 seconds
as the maximum configured lifetime. Prune the expired rows, provision a new
key, then use the one-replica admission sequence. Never bypass decryption,
weaken PIN verification, or expose ciphertext to make startup succeed.

## Restart and multi-instance smoke checks

Run these checks without production traffic and retain only redacted outcomes:

1. Confirm `state doctor` and readiness succeed on replica A.
2. Create a short-lived replay or nonce decision through replica A, restart A,
   and verify the duplicate is still rejected.
3. Create an evaluation through A and retrieve or render it through replica B.
   Restart both and confirm it remains available only until its expiry.
4. Race the same replay identifier or nonce consume through A and B. Exactly
   one request may win.
5. Race the same idempotent batch through A and B. Both callers must observe
   one completed response, and quota must be charged once.
6. When credential status is enabled, update a credential to revoked through A
   and verify B cannot reverse it before or after restart. Also verify a valid
   or suspended credential becomes effectively expired at its stored expiry on
   both replicas; application clock skew must not change that result.
7. When preauthorization is enabled, redeem one code concurrently through A
   and B. Exactly one token request may win.
8. Stop PostgreSQL and confirm every replica becomes not ready. Restore the
   database and confirm readiness recovers only after a fresh full attestation.

Do not retain tokens, nonces, PINs, identifiers, claim values, database URLs,
or credentials in smoke-test logs.

## Failure diagnostics

| Symptom or component code | Operator action |
| --- | --- |
| `database_unavailable` | Check primary availability, network policy, TLS handshake, connection limits, and the configured connect timeout. Do not print the URL. |
| `schema_incompatible` | Stop all replicas. Use the matching released binary to run `state install`, or restore the matching application and database backup together. |
| `role_incompatible` | Compare role provisioning with the role-separation contract and rerun install and doctor. Do not grant runtime table access. |
| Unsupported database version | Move the database to PostgreSQL 16, 17, or 18, then run install and doctor before admission. |
| Database is read-only or in recovery | Promote the intended recovery target to a writable primary or correct routing. Never serve correctness state from a read-only replica. |
| TLS or root-certificate failure | Verify the mounted certificate, trust chain, permissions, and configured TLS policy without logging its path or contents. |
| Missing URL environment variable | Correct secret injection for the variable name in config. Do not substitute a URL on the command line. |
| Missing or wrong sensitive-state key | Stop preauthorization, restore the backup-matched secret version, or follow the 600-second key-loss drain. |
| Fingerprint or role-identity mismatch after restore | Keep the database isolated, run the matching `state install`, then rerun doctor and stale-restore checks. |
| Cleanup contention | Check transaction latency, locks, autovacuum, and connection pressure. Do not manually delete unexpired rows. |
| Readiness remains unavailable after recovery | Confirm the database accepts a new TLS connection and has the expected role and schema. The pool evicts failed sessions automatically; if the platform still presents the old endpoint or secret generation, correct that injection and restart the canary before requiring doctor and readiness. |

Diagnostics are intentionally value-free. Use redacted database-platform logs
and the stable component code to investigate. Do not add SQL, row values,
identifiers, secrets, paths, URLs, or role names to application diagnostics.

## Supported PostgreSQL versions

Registry Notary supports PostgreSQL server majors 16, 17, and 18. Each release
tests the full state conformance suite on all three majors. An unlisted major
is unsupported even when the wire protocol appears compatible, and startup
must refuse it until that major has dedicated conformance evidence.

After any PostgreSQL minor update, run `state doctor`, readiness, restart, and
the representative replay, nonce, idempotency, status, quota, and
preauthorization checks. After a major upgrade, follow the stopped-writer
forward-upgrade procedure in full.
