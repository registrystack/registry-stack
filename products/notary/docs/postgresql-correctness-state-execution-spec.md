# Registry Notary PostgreSQL correctness-state execution specification

**Status:** implementation contract for registry-stack issue #356

**Date:** 2026-07-14
**Stacked base:** `agent/relay-notary-country-authoring` at `94b378320bff397aa0ca32f7d0d696c6fd4b26c5`
**Implementation branch:** `agent/notary-postgresql`

## 1. Outcome and boundary

Registry Notary will have one production correctness-state topology: typed,
Notary-owned PostgreSQL schemas accessed by a restricted Notary runtime role.
PostgreSQL owns every decision that must survive process restart or be shared
between identical Notary instances. In-memory implementations remain only for
focused tests and an explicit single-process local development mode.

One database belongs to one independently configured Notary authority. Only
replicas of that same Notary trust domain share it. Independent Notary
services use separate databases and role pairs rather than a generic tenant
column or caller-selectable namespace.

This change will:

- move replay, nonce, evaluation, idempotency, credential-status, quota, and
  preauthorization state to PostgreSQL;
- preserve domain-specific transaction and retention semantics;
- fail startup and readiness when the database, schema, supported PostgreSQL
  major, or runtime role is unavailable or incompatible;
- document installation, forward upgrade, backup, restore, retention, and
  recovery;
- make the production path usable by implementers through one configuration
  block, deterministic install and doctor commands, actionable value-free
  diagnostics, and a realistic local-to-production journey;
- remove Notary Redis configuration, code, dependencies, images, services,
  checks, and current documentation in the same delivery; and
- prove PostgreSQL 16, 17, and 18 behavior, process restart, multi-instance
  races, and takeover.

The implementation must not reuse Relay tables, schemas, roles, migrations,
advisory-lock identifiers, or state semantics. It may reproduce the proven
mechanics for PostgreSQL URL loading, TLS, bounded certificate reads,
connection timeouts, driver ownership, role attestation, schema fingerprints,
and value-free diagnostics.

The implementation must not introduce a reusable state framework, an opaque
key-value table, a dual Redis/PostgreSQL mode, or unrelated hardening.

### 1.1 Implementer experience contract

Security and implementer usability are joint release requirements. A secure
state plane that an implementer cannot reliably install, inspect, and recover
does not produce a usable deployment.

The 1.0-facing path therefore has these acceptance criteria:

- one top-level `state` block configures all Notary correctness domains;
- configuration rejects removed Redis and per-domain storage selectors with a
  precise field-level error rather than accepting aliases or silent defaults;
- `registry-notary state install` applies the product-owned schema with a
  separately provisioned owner connection, and never grants the runtime role
  table access;
- `registry-notary state doctor` exercises the same role, schema, version,
  fingerprint, read-write, and transaction-function contract used at startup
  and readiness;
- diagnostics name the failed invariant and the operator action without
  exposing database URLs, role names, paths, identifiers, ciphertext, or SQL;
- the documented journey starts with explicit single-process `in_memory`
  local development, then changes only the `state` block and secrets to reach
  the supported PostgreSQL deployment;
- PostgreSQL 16, 17, and 18 use the same migration artifact and public
  commands; and
- adding a future correctness domain requires a typed private table, fixed
  transaction function, migration, retention rule, recovery rule, focused
  tests, and an update to this inventory. It does not require a new backend
  selector or generic storage framework.

An implementer proof must run the documented install, doctor, startup,
readiness, restart, and multi-instance flow without private SQL or
repository-internal setup knowledge beyond database and role provisioning.

## 2. State authority inventory

The following table is exhaustive for process-local or Redis-backed Notary
correctness state at the stacked base.

| Domain | Current implementation | Production authority after this change | Transaction and concurrency requirement | Retention and recovery requirement | Sensitivity |
| --- | --- | --- | --- | --- | --- |
| Replay identifiers | `registry-platform-replay` through `ReplayStores`; Redis or in-memory | `registry_notary_private.replay_identifier` | Insert a scoped identifier exactly once. Concurrent inserts across instances produce one winner. An unexpired row always rejects. An expired row may be replaced atomically. | Absolute token or request expiry. Expired rows are pruned in bounded batches. Backup and restore must retain all unexpired rows or the service must remain offline until every token valid at the restore point has expired. | Store only domain-separated hashes of scope and identifier, never raw JWTs, nonces, tenants, issuers, holders, or subjects. |
| Consumable OID4VCI nonces | `ConsumableNonceStore`; Redis or in-memory | `registry_notary_private.consumable_nonce` | Reserve only when no live reservation or consumed tombstone exists. Every replacement increments a stored generation. Consumption first reads one live generation, then atomically compares that generation while changing the row to consumed. Missing, expired, consumed, or replaced generations fail. A successful consume retains a consumed tombstone for 60 seconds so stale operations and immediate re-reservation cannot reopen the nonce. | Reservation expiry is the configured nonce expiry. A consumed tombstone expires 60 seconds after consumption. Generation, reservation, and tombstone survive restart and restore. | Store only domain-separated hashes plus generation, state, and timestamps. |
| Evaluation retention | `EvidenceStore.evaluations`, process-local `HashMap` | `registry_notary_private.evaluation` | Insert one complete stored evaluation after evaluation succeeds. Reads return the exact stored record only while unexpired. No partial result is published. | The record's absolute `expires_at`, currently normally 15 minutes or the stricter self-attestation expiry. Expired rows are deleted in bounded batches. Restore preserves unexpired records and their access-binding metadata. | Results may contain minimized claim values. Use typed identity/time columns plus a versioned JSON record, expose access only through fixed functions, and require encrypted database storage and backups operationally. |
| Batch idempotency | `EvidenceStore.idempotency`, process-local map plus watch channels | `registry_notary_private.batch_idempotency` | Atomically bind one idempotency-key hash to one request hash and one owner lease. The first owner reservation and its machine-quota debit commit together and set an immutable `quota_charged` marker. Same-hash callers wait and replay the completed response without another debit. A different hash conflicts. Failed or expired ownership can be taken over with a new unguessable owner token without another debit. Only the current owner can complete or fail. Evaluation rows and the completed response publish in one transaction, and a completed response cannot be replaced. | Completed and failed rows remain for 15 minutes. In-flight rows carry a bounded lease and become takeover-eligible after owner loss. Restore retains completed responses and never turns completion into new ownership. | Hash the client idempotency key. The stored response can contain claim values and receives the same controls as evaluations. |
| Credential status | `CredentialStatusStore`; Redis or in-memory with process-local striped transition locks | `registry_notary_private.credential_status` | Issuance is insert-only and fails on an existing credential id. Status update locks the row and enforces valid, suspended, and terminal revoked transitions in the database transaction. PostgreSQL derives the effective status from database time: revoked remains terminal, expiry supersedes valid or suspended, and replica clocks cannot reopen an expired credential. Concurrent instances cannot reverse revocation, disagree on expiry, or lose a winning transition. | Retain until credential expiry plus `credential_status.retention_seconds`. Restore must preserve revoked and suspended state before issuance resumes. | Credential ids and profile/issuer metadata are restricted operational data. They are never written to logs or diagnostics. |
| Machine evaluation quota | `MachineQuotaLimiter`, process-local fixed-window map | `registry_notary_private.machine_quota` | Atomically check and debit the whole request cost for one keyed principal. A rejected batch consumes nothing. Concurrent instances share the same fixed one-minute window and limit. | Delete after the one-minute window. Restore preserves a conservative debit or the service waits for the restored window to expire. | Store a keyed audit pseudonym for the principal, not the raw principal id. |
| Self-attestation rate limits | `SelfAttestationRateLimiter`, process-local fixed-window map | `registry_notary_private.subject_access_quota` | Check every applicable bucket and debit all applicable buckets in one transaction. If any bucket is exhausted, debit none. Check-only operations do not mutate. Concurrent instances share counters. | Delete when each one-minute or one-hour window ends. Restore preserves a conservative debit or waits for the maximum one-hour window. | Keys are already keyed audit pseudonyms. Store the pseudonym, bucket kind, window, and count only. |
| Preauthorization login state | `SingleUseStore<LoginState>`, process-local | `registry_notary_private.preauthorization_login_state` | Reserve an opaque state once, subject to the existing 4,096-row abuse bound. Callback atomically deletes and returns one unexpired record. Unknown, duplicate, expired, and already-consumed state fails closed across instances. Capacity check and insertion are one transaction. Login and transaction-code reservations take one fixed Notary-specific advisory lock and reject a different live key id, so competing replicas cannot create mixed live key generations. | Absolute `login_state_ttl_seconds`, at most 600 seconds. Expired rows are deleted. Restore never makes expired rows usable. Activation, doctor, and every readiness probe attest that every live sensitive row matches the configured key id. | PKCE verifier and eSignet nonce are application-encrypted with an operator-supplied 256-bit sensitive-state key before storage. Associated data binds schema version, row kind, key hash, key id, and expiry. Plaintext is zeroized after use. |
| Preauthorization transaction-code session | `SingleUseStore<TxCodeSession>`, process-local | `registry_notary_private.preauthorization_tx_code` | Reserve by pre-authorized-code JTI hash. The signed pre-authorized code binds whether its exact offer requires a transaction code, so restart or reconfiguration cannot weaken or add the PIN requirement for a live offer. Wrong PIN may read without consuming. Correct PIN redemption atomically inserts the pre-authorized-code replay marker and deletes the verifier, producing exactly one winner across instances. Reservation shares the sensitive-key generation lock and rejects a different live key id in either preauthorization table. | Absolute pre-authorized-code expiry, at most 600 seconds. Delete on successful code use and on expiry. Restore and every readiness probe preserve the same live-key attestation as login state. | Store only a keyed PIN verifier made with a domain-separated MAC subkey, never reversible PIN ciphertext. Raw code, JTI, and PIN are not stored as table keys or logged. |

The six self-attestation bucket kinds remain distinct and closed:

| Bucket | Window | Atomic grouping |
| --- | --- | --- |
| Invalid token per client address | 1 minute | Denial debit |
| Authenticated request per principal | 1 minute | Request, mismatch, and issuance groups as currently defined |
| Subject mismatch per principal | 1 hour | Principal check plus mismatch denial debit |
| Credential issuance per holder | 1 hour | Principal and credential-issuance buckets |
| Credential issuance per principal | 1 hour | Principal and optional holder buckets |
| Transaction-code attempts per code | 1 minute | One attempt debit |

## 3. Explicitly classified non-authorities

The following process-local values do not decide durable correctness and will
not move to PostgreSQL:

- signed status-list JWT cache entries, because every request first reads the
  authoritative credential-status record and the cache key includes its exact
  status and `updated_at` value;
- OIDC and JWKS transport caches;
- Relay readiness results and singleflight caches;
- signer sessions and file-watch observations;
- request-local evaluation dependency maps and coalesced Relay calls;
- metrics counters, semaphores, HTTP client caches, and offline fixture maps.

The following durable authorities already have separate ownership and remain
outside issue #356:

- the Notary audit chain and shipping acknowledgement cursor remain owned by
  the configured audit sink and audit policy;
- governed-config antirollback state and break-glass approval files remain
  owned by the signed-config workflow; and
- signing keys remain owned by their configured provider.

These exclusions do not authorize memory-backed alternatives for any domain in
the state authority inventory.

## 4. PostgreSQL ownership and schema contract

The database contract is product-owned and typed:

```text
PostgreSQL cluster
└── Notary database
    ├── registry_notary_private schema
    │   ├── schema_metadata
    │   ├── replay_identifier
    │   ├── consumable_nonce
    │   ├── evaluation
    │   ├── batch_idempotency
    │   ├── credential_status
    │   ├── machine_quota
    │   ├── subject_access_quota
    │   ├── preauthorization_login_state
    │   └── preauthorization_tx_code
    └── registry_notary_api schema
        └── fixed, typed transaction functions
```

There are two database roles:

- the owner role applies forward-only migrations and owns the schema; and
- the runtime role connects from Notary and has schema usage plus execution on
  the fixed transaction functions in `registry_notary_api`.

The runtime role has no direct privileges on private tables or sequences. It
must not own either schema, create objects in them, be a
superuser, bypass row security, create roles or databases, or use Relay roles.
The owner defines every runtime function as `SECURITY DEFINER`, pins an empty
or explicit `search_path`, schema-qualifies every object reference, and revokes
default `PUBLIC` execution before granting the runtime role the exact function
signatures it needs.
The metadata row binds schema version, capability id, deterministic schema
fingerprint, owner role OID, and runtime role OID. Runtime startup verifies
that metadata and the required positive and negative privileges.

The initial capability is `registry.notary.postgresql-state/v1`. Runtime code
accepts exactly the compiled schema version and fingerprint. It never applies
DDL automatically and never serves against a partially upgraded schema.

PostgreSQL server majors 16, 17, and 18 are supported. Other majors fail
startup with a value-free compatibility diagnostic until explicitly tested.

## 5. Runtime configuration and activation

One top-level state configuration replaces per-domain storage selection:

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

Rules:

- `postgresql` is the only deployable storage value.
- `in_memory` is accepted only with `deployment.profile: local` and
  `deployment.multi_instance: false`.
- A production, evidence-grade, hosted-lab, or multi-instance configuration
  with `in_memory` fails validation. There is no waiver.
- `replay.storage`, `replay.redis`, `credential_status.storage`, and
  `credential_status.redis` are removed rather than aliased.
- The database URL is loaded only from the named environment variable, held in
  zeroizing memory, never emitted through `Debug`, posture, doctor, or errors,
  and parsed with the PostgreSQL client parser.
- TLS is required for every PostgreSQL connection, including local PostgreSQL
  testing. The optional root certificate is size-bounded and read without
  disclosing its path on failure.
- Each replica owns a Notary-specific pool capped by `max_connections`; values
  outside 1 through 256 are rejected before allocation. Pool admission waits
  at most `operation_timeout_ms`. Physical
  connection establishment remains bounded by `connect_timeout_ms`.
- A physical connection enters the pool only after complete session setup and
  schema, role, catalog, server, writeability, and durability attestation. It
  is reused across typed state operations, then discarded after an operation
  timeout, query or driver failure, failed readiness attestation, or database
  URL generation change.
- The database URL generation is a process-keyed HMAC tag. The pool does not
  retain or log the URL to detect a generation change. A replacement physical
  connection reloads the named environment variable and completes full
  attestation before use.
- The sensitive-state key is base64url-encoded 32-byte key material. It is
  required whenever preauthorization is enabled with PostgreSQL. Identical
  replicas use the same key for the lifetime of any unexpired row. Activation,
  doctor, and every readiness probe fail closed when any live login or
  transaction-code row has a different derived key id.
- Domain-separated subkeys are derived for login-state AEAD, transaction-code
  PIN verification, and stored identifier hashing. The key id is stored with
  ciphertext but key material is never stored. Rotation stops new
  preauthorization issuance, drains or prunes all rows for at most the
  600-second maximum lifetime, then replaces the key before issuance resumes.

Runtime compilation remains side-effect free. Async activation connects to
PostgreSQL, validates the database contract, installs the state backend, then
activates Relay where applicable. No listener binds before both state and
Relay activation succeed.

## 6. Transaction contract

All time comparisons use PostgreSQL `clock_timestamp()` so identical replicas
share one authority. Application wall clocks do not decide expiry or quota
windows.

### 6.1 Replay and nonce

- Replay insert is one statement or transaction that inserts when absent or
  replaces only an expired row. It returns inserted or already seen.
- Nonce reserve inserts reserved state when absent or expired, but not while a
  consumed tombstone is live.
- Nonce consume locks or conditionally updates exactly one reserved,
  unexpired row to consumed with a 60-second tombstone. No success path deletes
  the tombstone.

### 6.2 Evaluation and idempotency

- Evaluation publication inserts the complete versioned record and its typed
  identity and expiry columns together. For a batch, all evaluation rows and
  the completed idempotency response commit in the same transaction.
- Idempotency reservation serializes on the key hash. It returns owner, wait,
  replay, or conflict. Initial ownership and machine-quota debit commit in the
  same transaction with a permanent `quota_charged` marker. Ownership uses a
  random token and bounded lease.
- Waiters poll with a bounded interval and the request deadline. They do not
  evaluate while a live owner exists.
- Completion and failure compare key hash, request hash, and owner token.
  Completion writes the response and terminal status atomically. Owner loss
  leaves a lease that another instance can take over after expiry without
  charging quota again.

### 6.3 Credential status

- Issuance inserts the complete initial valid record and rejects any existing
  credential id instead of overwriting it.
- Update locks the credential row, validates the transition, changes status
  and `updated_at`, and returns the committed record in one transaction.
- Revoked is terminal. Expiry is derived from the stored credential expiry and
  does not rewrite the explicit status.

### 6.4 Quotas

- Machine quota locks one principal bucket, resets only after its fixed window,
  and applies the complete subject cost or no cost.
- Self-attestation quota locks all applicable bucket rows in deterministic
  bucket/key order, checks them all, then debits them all. Any denial rolls the
  whole transaction back.
- Database or transaction uncertainty fails closed. It is never treated as an
  unused quota.

### 6.5 Preauthorization

- Login state reserve and consume are one-winner operations.
- Transaction-code peek returns one unexpired encrypted value without mutation
  so a wrong PIN does not burn the offer.
- The token path verifies scope and authorization details and verifies the PIN
  before mutation. It then atomically inserts the pre-authorized-code replay
  identifier and deletes the matching PIN verifier in one database
  transaction. No second token can win.
- PIN verification uses a constant-time keyed MAC comparison with a dedicated
  derived subkey. The PIN is not decryptable from database state.
- Ciphertext includes a fresh random AEAD nonce. Associated-data mismatch,
  decryption failure, missing key material, or unknown format fails closed and
  does not reveal which field failed.

## 7. Retention maintenance

Every table has an indexed absolute expiry column where applicable. Every
serving Notary instance begins maintenance once per minute. One transaction
deletes at most 1,000 expired rows from each typed table in deterministic,
skip-locked batches and returns both the aggregate deletion count and whether
any individual table filled its batch. A filled per-table batch starts another
bounded transaction after an internal, bounded backoff. The worker releases
its pooled session between transactions and repeats until every table returns
a short batch. This catch-up behavior is fixed runtime policy, not an operator
configuration surface, and concurrent maintenance remains safe.

Logical expiry checks remain authoritative between transactions and scheduled
passes. A transient maintenance failure ends the current catch-up sequence and
the next scheduled pass retries. Maintenance failure makes readiness fail only
when it also proves the database contract or runtime operation is unavailable;
ordinary transient cleanup contention does not stop serving valid state.

No retention operation deletes an unexpired replay row, nonce tombstone,
idempotency completion, revocation record, quota window, or preauthorization
row. Operators may lower future retention settings, but existing rows keep the
absolute expiry assigned when they were written.

## 8. Migration and upgrade

This pre-1.0 cutover is a clean PostgreSQL installation, not an online Redis
adapter migration. The old Redis records do not have a complete typed schema
or an authenticated export contract, and retaining an importer would preserve
the prohibited compatibility dependency.

The cutover procedure is therefore:

1. stop all Notary writers;
2. confirm credential status is disabled or the existing store contains no
   records that must survive, because revocation or suspension state must not
   be discarded;
3. wait for the maximum configured lifetime of outstanding replay, nonce,
   evaluation, idempotency, quota, and preauthorization records, up to the
   one-hour self-attestation window;
4. install the PostgreSQL owner/runtime roles and schema with the owner role;
5. start one Notary replica, confirm startup and readiness attestation, then
   start the remaining identical replicas; and
6. remove the Redis service, volume, secret, monitoring, and backup job only
   after the PostgreSQL-backed smoke and restart checks pass.

If step 2 finds credential-status data that must survive, the upgrade is
blocked. Do not reinitialize or silently mark credentials valid. This clean
cutover policy is acceptable only while Registry Stack remains pre-1.0 with no
production status data. Once that assumption changes, a separately reviewed
typed export/import migration is mandatory before cutover.

Future PostgreSQL upgrades are forward-only owner migrations. The documented
sequence is backup, stop writers, apply the next migration, attest the new
fingerprint and role, start one replica, verify readiness, then roll out
identical replicas. Runtime binaries refuse old, new, or partially applied
schemas, so application rollback also requires restoring the matching database
backup and preauthorization key material.

After a logical restore into a fresh cluster, role OIDs can legitimately
change. `state install` may rebind only the metadata owner/runtime OIDs and
reapply the fixed runtime grants when the capability, schema version, semantic
fingerprint, complete catalog, and object ownership already match the released
contract. The rebind and full attestation are one transaction. Any other drift
rolls the transaction back; the installer does not repair it.

## 9. Backup, restore, and recovery

A recoverable backup set contains:

- the complete Notary database at one consistent PostgreSQL recovery point;
- owner and runtime role definitions or reproducible role provisioning;
- the exact schema migration set and application version;
- the sensitive-state key through the deployment secret manager,
  never inside the database backup; and
- the audit sink and governed-config state through their separate documented
  backup procedures.

Backup and restore evidence must prove that replay decisions, nonce tombstones,
completed idempotency responses, credential status, quotas, evaluation expiry,
and encrypted preauthorization rows retain their semantics after restart.

A restore from a point that might predate an acknowledged one-time consume or
quota debit must not serve immediately. Keep Notary offline until every token
and preauthorization value that could have been valid at the recovery point
has expired and the maximum one-hour quota window has elapsed. Restore of a
known quiesced, transactionally consistent backup may serve after schema,
role, key, and semantic conformance checks pass.

If the sensitive-state key is unavailable, keep Notary unavailable until all
restored preauthorization rows expire, delete those expired rows, provision a
new key, and then resume. Never weaken decryption or expose ciphertext to make
the service start.

## 10. Readiness and diagnostics

Startup fails before listener bind for:

- missing or empty URL/key environment variables;
- invalid URL or forbidden insecure TLS mode;
- connection timeout or unavailable database;
- unsupported PostgreSQL major;
- read-only or recovery-mode database;
- missing, extra, or incompatible schema metadata;
- any live preauthorization row whose key id differs from the configured
  sensitive-state key;
- schema fingerprint mismatch;
- connected-role OID mismatch; or
- missing required or present forbidden privileges.

Every readiness probe performs the complete server, writeability, durability,
schema, catalog, and role attestation on a bounded pooled session. Startup
performs the same attestation before listener bind. It reports a stable
component code such as `database_unavailable`, `schema_incompatible`, or
`role_incompatible` without table names, role names, paths, URLs, credentials,
SQL, or stored identifiers. Detailed logs remain value-free and name the
operator action.

Readiness recovers after database availability is restored and a fresh
connection passes complete attestation. Failed or closed sessions are evicted,
so a stale connection is never reported ready.

## 11. Atomic Redis deletion boundary

The final PostgreSQL checkpoint removes current Notary Redis surfaces from:

- root and crate Cargo manifests and `Cargo.lock`;
- `registry-platform-cache` and `registry-platform-replay` Redis features and
  implementations, while preserving focused in-memory test stores;
- Notary configuration, validation, posture, doctor, explain-config, examples,
  tests, OpenAPI, and generated fixtures;
- the standalone Solmara Lab repository's Compose topology, secrets,
  provisioning, validation, smoke, volumes, and Notary backup guidance;
- release checks, current product docs, public docs, and current architecture
  diagrams.

Redis used internally by the separately deployed eSignet examples remains
because it is eSignet-owned state, not Notary state. Historical release notes,
archived specifications, and completed upgrade exercises remain accurate
historical evidence and are not rewritten.

## 12. Verification matrix

Focused and PostgreSQL-backed tests must cover:

- exact replay insert races, expiry, restart, and restored state;
- nonce reserve/consume races, expiry rejection, retained tombstones, stale
  generation resistance, restart, and takeover;
- evaluation insert/read/expiry across two instances and restart;
- idempotency same-hash wait/replay, different-hash conflict, owner failure,
  lost acknowledgement, lease takeover, completed-response durability, and
  restore;
- valid credential transitions, terminal revocation, concurrent updates,
  expiry, retention, restart, and restore;
- machine-quota exact boundary, whole-batch rejection, concurrent debit,
  restart, and clock behavior;
- every self-attestation bucket, multi-bucket all-or-nothing debit,
  check-only behavior, concurrent instances, restart, and expiry;
- encrypted login-state and transaction-code reserve, peek, consume, delete,
  expiry, wrong key, tampering, restart, and secret-absence assertions;
- sequential physical-connection reuse, the configured per-replica cap,
  bounded pool admission, failed-session eviction, and same-process recovery
  after PostgreSQL stop and restart;
- startup and readiness failures for availability, TLS, server major, schema,
  fingerprint, role, and permission errors; and
- a clean backup and restore preserving every domain invariant.

The same conformance test runs against disposable PostgreSQL 16, 17, and 18 in
local verification and a dedicated read-only GitHub Actions matrix. The final
gate also runs Notary focused suites, locked workspace check/tests, Clippy with
warnings denied, cargo-deny, both product OpenAPI checks, Solmara Lab
PostgreSQL and topology smoke, docs tests/build, release-source checks, image
builds, DCO, and an independent security and operability review of the final
diff.

## 13. Required delivery checkpoints

1. This execution specification, committed before implementation.
2. PostgreSQL schema, role contract, configuration, activation, readiness, and
   conformance foundation.
3. Replay, nonce, evaluation, idempotency, status, quota, and preauthorization
   cutover with focused tests.
4. Atomic Redis deletion plus standalone Solmara Lab, documentation, recovery,
   and upgrade guidance.
5. PostgreSQL 16, 17, and 18, multi-instance, restart, backup/restore, full
   verification, and independent review.
6. Rebase onto the latest `origin/main` only after PR #355 merges, followed by
   complete focused and full verification.
