# Registry Document Store

The Document Store holds document bytes in custody for an owning system and
releases an exact, verified document version to a recipient a document grant
names. An owning system places a document in custody under a document policy;
content verification decides whether a version may ever be released; a
document grant names one recipient, one version, and an expiry.

The product is pre-1.0 and held out of releases. The configuration formats,
schemas, problem vocabulary, tooling, CI gates, and release hold-out exist.
Custody, PostgreSQL and S3 storage, upload with digest and length checks,
content verification on dispatch, document grants, and release of a verified
version are implemented and served behind OAuth access-token verification,
with removal from custody and erasure by a cleanup sweep, and document events
are delivered to after-commit URL observers.

## Routes

Every route but `GET /health` takes a bearer access token the configured
issuer signed. The token's client, scopes, and actor kind select one access
profile in `documents.yaml`; the profile and the document policy decide what
the caller may do. `generated/registry-documents.openapi.json` is the full
contract.

| Route | Does |
|---|---|
| `POST /documents` | Reserve a document under a policy; needs an `Idempotency-Key` |
| `PUT /uploads/{uploadId}/content` | Send the reserved bytes once; the same bytes again answer the same view |
| `GET /documents` | List the documents the caller holds in custody or reserved |
| `GET /documents/{documentId}` | Read metadata and the actions the caller may take |
| `GET /documents/{documentId}/versions/{versionId}/content` | Download a releasable version, as its custodian or a grant holder |
| `POST /documents/{documentId}/grants` | Grant one named recipient one exact version until a fixed expiry; needs an `Idempotency-Key` |
| `GET /documents/{documentId}/grants` | List every grant on a document |
| `GET /document-grants` | List the active grants naming the caller |
| `DELETE /document-grants/{grantId}` | Revoke a grant |
| `POST /documents/{documentId}/erasure` | Remove a document from custody; only its custodian may. Takes no `Idempotency-Key`: a repeat moves nothing and answers the same view |
| `GET /document-policies` | List the policies the caller may reserve under, with their bounds |

A document the caller may not see answers `resource.not-found`, the same as
one that does not exist. Lists page by `cursor` and `limit` (at most 100) in a
stable order.

## Retention and erasure

A document is kept until its custodian removes it or the verifier rejects
it. Nothing expires on a timer: a grant that expires or is revoked erases
nothing held in custody, and there is no sliding expiry. A citizen-held
document is kept until the citizen removes it.

`POST /documents/{documentId}/erasure` starts the custody clock. In one
transaction it suspends release, revokes every active grant on the document,
cancels any pending verification, and marks the version `erasure-pending` with
a due time of now plus the policy's `cleanupGraceHours`, which is at least one
hour, so the operator always has a window to restore from a mistaken request
(a project that sets it to 0 is refused). No grant, download, or verdict that
starts after the request commits releases the version. A download admitted
before the commit is not interrupted and may finish after it, bounded by its
transfer deadline.

A rejection schedules the erasure of the rejected bytes the same way, due
`cleanupGraceHours` after the verdict. The version reads `rejected` until its
bytes are erased and `erased` after; the record stays. A verification that
dead-letters is not a verdict, so its bytes are kept until an operator replays
it or the custodian removes the document. A rejection revokes no grant;
removing a rejected document revokes them and keeps the rejection's due time.

A cleanup sweep runs every minute. Each pass:

- expires uploads whose upload window lapsed, so a lapsed reservation takes
  no more bytes. The window is the reservation time plus the policy's
  `cleanupGraceHours`;
- arms an erasure job on `registry-platform-dispatch` for each version past
  its due time;
- on S3, deletes objects an upload staged but never committed once they are
  older than the longest transfer deadline plus ten minutes.

An erasure job retries for about seven days before it dead-letters; a
dead-lettered erasure stays `erasure-pending` until an operator replays it.
The version moves to `erased` only once erasure is confirmed:

- PostgreSQL `bytea`: the content row is deleted in the same transaction that
  records `erased`. No query reaches the bytes after that commit, but they
  stay on disk: vacuum only marks the space reusable, so the bytes remain
  until PostgreSQL overwrites those pages or `VACUUM FULL` rewrites the
  table, and WAL archives and replicas keep their own copies.
- S3: the object is deleted and a following read must answer 404. A delete
  the store accepts but does not honour leaves the version pending and is
  retried.

"Erased" means the Store can no longer serve the bytes. It does not reach
backups, WAL archives, replicas, database pages not yet overwritten, or
object-store versions the bucket keeps outside the Store's key. Records are
kept: documents, versions, grants, verification history, and the audit file
survive erasure, and every foreign key between them is `ON DELETE RESTRICT`.

Set `cleanup.erasure: paused` in the runtime configuration to halt erasure
without halting the rest of the runtime. A paused deployment still serves,
still takes removal requests, and still expires lapsed uploads; it arms no
erasure job, runs no erasure worker, and sweeps no orphan, and it logs a
warning at startup. Due versions wait and are erased on the first pass after
erasure is set back to `active` and the runtime restarts.

### Restore drill

Rehearse a restore before relying on one:

1. Set `cleanup.erasure: paused` and stop serving traffic at the edge.
2. Restore the database backup, and restore the audit file from the same
   point if you have it.
3. Start the runtime. It serves no request you have not let through, and the
   sweep erases nothing while paused.
4. Compare the restored state with the audit file. Revocations and erasure
   requests newer than the backup are lost unless the audit file was
   restored too: the database no longer knows about them, so a grant revoked
   after the backup is active again and a document removed after the backup
   is in custody again. Repeat them from the audit file before serving. A
   removal repeated here gets a fresh due time, so its bytes stay for
   another full `cleanupGraceHours` after the repeat, not after the
   original request.
5. On S3, if the database was restored and the bucket was not, remove the
   objects uploaded after the backup: no row names them, so no sweep ever
   reaches them. Each object key is `documents/<scope>/<sha256>`, where
   `<scope>` is the lowercase hex SHA-256 of `<identity.databaseId>/<objectId>`
   with the object id in lowercase hyphenated form. Compute the scope of
   every `object_id` in `documents_staged_objects`,
   list the keys under `documents/`, and delete every key whose scope none
   of them produces. Run this only on a bucket the deployment uses alone:
   another deployment's keys under the same prefix are indistinguishable.
6. Set `cleanup.erasure: active` and restart. The next pass handles every
   version that became due after the backup was taken; the drill needs no
   step for them. Bytes erased after the backup are back in the restored
   database or bucket until their version is erased again. An S3 object
   erased after the backup stays gone if the bucket was not restored, and
   its restored version refuses download until it is removed again.

`restore_drill` rehearses these steps once on database storage, with
`pg_dump` and `pg_restore` on `PATH`:

```bash
DOCUMENTS_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-documents --features postgres-test --test restore_drill \
  -- --ignored --nocapture
```

It takes a custom-format dump of its schema, then revokes a grant, removes
and erases a document, and uploads a new one. It pauses erasure, drops the
schema, and restores the dump while keeping the audit file, as when the
journal is backed up apart from the database. On 2026-10-21 against
PostgreSQL 17.10, the rehearsal found what step 4 says:

- the revoked grant was active again and its recipient could download;
- the document removed after the backup was `ready` in custody, its bytes
  back;
- the document uploaded after the backup was unknown (404); on database
  storage its bytes went with its row, so nothing was left for step 5;
- a version whose removal predated the backup stayed `erasure-pending`,
  and a paused sweep armed nothing even after it was made due;
- the audit file still recorded the lost revocation, removal, and erasure.

Repeating the revocation and the removal from the audit file worked. The
repeated removal was due 24 hours after the repeat, the starter policy's
full `cleanupGraceHours`, not after the original request. After erasure was
set back to `active` and the runtime restarted, the first sweep erased the
due version and kept the repeated removal's bytes. Step 5 is not rehearsed:
the rehearsal does not restore an S3 bucket.

## Crates

| Crate | Owns |
|---|---|
| `registry-documents-core` | Source-neutral naming, the problem vocabulary, wire DTOs, and the `DocumentsProject` model |
| `registry-documents` | PostgreSQL-backed runtime and the `documents` binary |
| `registry-documentsctl` | Configuration checks, packaging, activation, dead-letter replay, and the `documentsctl` binary |
| `registry-documents-client` | Bounded Rust client over the runtime's HTTP contract |

## Configuration

Two operator documents configure a deployment:

- `documents.yaml`, a `DocumentsProject`: document policies, the access
  profiles they reference, and after-commit URL observers. See
  `examples/starter/documents.yaml`.
- the runtime configuration, a `DocumentsRuntimeConfig`: listener, database,
  authentication, audit, storage, content verification, cleanup, hook
  destinations, and retention. See `RUNTIME-CONFIG.md` and
  `examples/starter/runtime.example.yaml`.

Check them offline, with no database, network, or secret:

```bash
cargo run --locked -p registry-documentsctl -- check \
  --project products/documents/examples/starter \
  --runtime-config "$PWD/products/documents/examples/starter/runtime.example.yaml"
```

`documentsctl` exits 0 when every document is accepted, 1 when one is
refused, 2 for a usage error, and 3 when a file cannot be read. `--format
json` prints the `DocumentsCtlReport` envelope.

## Operate

`documentsctl init DIRECTORY` writes the starter project and runtime
configuration into a new directory and never overwrites one. A deployment
then runs in this order:

```bash
documentsctl package PROJECT --output PACKAGE_DIRECTORY
documentsctl plan --runtime-config ABSOLUTE_FILE
documentsctl apply --runtime-config ABSOLUTE_FILE \
  --operator-reference CHANGE --backup SNAPSHOT
documents --runtime-config ABSOLUTE_FILE serve
```

`package` checks the project and writes the deployable package `package.root`
names; `--dry-run` reports its digest without writing it, for
`package.expectedDigest`. `plan` reports what `apply` would change and writes
nothing. `apply` connects with `database.migrationUrlRef`, applies the schema,
records the verified package digest in the activation ledger, and grants the
runtime role what serving needs. Applying the active package again records
nothing. `status` reports the active package and the activation history.

`serve` refuses a database with no active package, one recorded for another
`identity.databaseId`, and one whose active package is not the configured
one; apply the package first. The runtime listens on `127.0.0.1:8116` in the
starter.

A verification job that dead-letters leaves its version pending and
suspended. `documentsctl verification list --runtime-config ABSOLUTE_FILE`
shows each such job with its generation, and

```bash
documentsctl verification replay --runtime-config ABSOLUTE_FILE \
  --version-id VERSION --expected-generation GENERATION
```

returns it to pending under the next generation, to be verified like any
other. A generation other than the current one is refused, and so is a
version whose erasure is pending or done or whose document has a removal
requested. The replay is written to the `documentsctl` companion audit
journal. No HTTP route lists or replays a job.

`documentsctl erasure status --runtime-config ABSOLUTE_FILE` reports whether
erasure is active or paused and counts the versions awaiting their grace, the
ones due, and the dead-lettered erasure jobs. A dead-lettered erasure is never
re-armed by the sweep: `documentsctl erasure list` shows each one with its
generation, and `documentsctl erasure replay`, with the same `--version-id`
and `--expected-generation` options, returns it to pending, audited the same
way. While erasure is paused a replayed job waits.

## Volume fit

`products/documents/scripts/measure-volume-fit.sh COUNT BYTES` measures what
`bytea` storage costs at a stated count and size. It creates two databases
with libpq's environment (`PGHOST`, `PGPORT`, `PGUSER`, and `PGPASSWORD` or
`PGPASSFILE`; no credential on the command line), fills one through the
runtime's own routes with `COUNT` verified documents of `BYTES` pseudo-random
bytes each, dumps it with `pg_dump --format=custom`, restores the dump into
the other, checks that both hold the same content, prints the sizes and
times as JSON, and drops both databases. Random bytes do not compress, which
is close to real PDFs, whose streams are already compressed.

Indicative results, 2026-10-21, PostgreSQL 17.10 in an OrbStack container on
an Apple M5 Max (18 cores, 128 GiB) shared with many other workloads (load
average between 6.7 and 27.5 during the runs), `pg_dump` and `pg_restore` 18.4 over
loopback TCP:

| Documents | Size | Payload | Database | Dump file | Dump | Restore |
|---|---|---|---|---|---|---|
| 1,000 | 1 MiB | 1.05 GB | 1.10 GB | 1.20 GB | 41.6 s | 7.8 s |
| 10,000 | 64 KiB | 655 MB | 718 MB | 751 MB | 25.8 s | 7.1 s |

The sizes do not depend on the machine. The database is the payload plus
about 44 KB a document at 1 MiB and about 5.4 KB at 64 KiB (1.04 and 1.08
times the payload). TOAST stores incompressible content as is. The
custom-format dump is larger than the payload, about 1.14 times in both
runs: `pg_dump` writes `bytea` as hex text and its compression wins back
less than the hex encoding added. Plan backup space at more than the
database size. Each restored database held the same content as its source, by count,
total length, and a digest over every version's content.

The times are indicative only: the machine was contended and the database
ran in a VM. An authoritative run on a dedicated host is still owed before
the times are quoted for sizing.

## Events and observers

A project may declare `hooks`: after-commit URL observers of three event
families. Each hook names a trigger, the document policies whose
documents it hears about, the fields it projects, and a destination id; the
runtime configuration binds that id under `destinations.hooks` to a URL and
an HMAC signing key. The project file never carries an endpoint or a secret.

`policies` is required and lists at least one policy the project declares,
each once. A hook hears only about documents held under a policy it names,
so a hook for one owning system never reports another system's documents.
The list is a plain declaration the operator reviews with the package, not a
condition evaluated at run time; routing by custodian is not offered.

| Trigger | Emitted when | Fields a hook may project |
|---|---|---|
| `document-version.ready` | A verdict makes a version ready that was not ready, including a version approved again after a verifier binding change suspended it. | `documentId`, `versionId`, `versionDigest`, `policyId`, `policyVersion` |
| `document-version.rejected` | A verdict rejects a version. | the same five |
| `document-grant.changed` | A grant is issued or revoked, including each grant a removal request revokes. | the same five, plus `grantId`, `change` (`issued` or `revoked`), `actorKind`, and `expiresAt` |

`actorKind` is `service` or `human`: the kind of caller that issued or
revoked the grant, or that requested the removal which revoked it. A version
event carries no `actorKind`, because the verdict it reports is the
verifier's, not a caller's. `expiresAt` is the grant's expiry, as the API
reports it. No event carries content, a label, a media type, a name, a
subject, or anything else about the person a document describes.

The envelope's subject names the version or grant and its revision. Every
recorded change of a version or a grant, a verdict, a suspension, a
revocation, a removal, raises its revision by one, so two events about one
record arrive with strictly increasing revisions, and a receiver can drop
one older than what it already holds.

An event is captured in the same transaction as the transition it reports,
so a rolled-back verdict or grant change reports nothing, and a capture that
cannot be written fails the transition. A repeated verdict, an issue replayed
under its `Idempotency-Key`, a repeated revocation, and a repeated removal
request report nothing.
Delivery runs after commit: each attempt is a signed Version 1 hook envelope
whose `source` is `urn:registrystack:documents:<project id>`, whose `type`
is the hook id, and whose `dataschema` names the family's published schema
under `generated/events/`. A failed attempt is retried with backoff from 30
seconds to an hour until the destination's `maximumAttempts` are spent, then
dead-lettered; delivery never delays or undoes a transition. An observer may
not answer with a proposal: every proposal is refused and recorded as
`documents.hook.proposal-unsupported`, and nothing in the Store changes.

Hooks accept only `phase: after` and a `url` handler. A Rhai or Wasm handler,
a `when` condition, a `principal`, and any other phase are refused when the
project is read.

A grant reaching its expiry emits nothing. Expiry is not a recorded
transition: the grant stops releasing at its `expiresAt`, which the
`issued` event already carried, and no sweep records it as expired. A
receiver that needs to know when a grant lapses reads `expiresAt` from the
`issued` event. A removal request reports each grant it revokes; the
version's own erasure steps emit nothing.

Hooks are part of the package. Adding, removing, or changing a hook changes
the package digest, so run `documentsctl package` and `documentsctl apply`
before restarting; `serve` refuses a package that is not the active one.

Every captured delivery records the binding of its destination: the
destination id, URL, signing key reference, timeout, and attempt budget.
Startup refuses to serve while a pending or leased delivery records a
binding the runtime configuration no longer holds, so changing any of those
values in place, or removing the entry, fails the next start until that
work is gone. To move a hook to a new URL or key:

1. Add a destination under a new id in `destinations.hooks` and leave the
   old entry exactly as it is.
2. Point the hook's `destinationId` at the new id, then run
   `documentsctl package` and `documentsctl apply`, and restart. New events
   go to the new destination; deliveries already captured keep their old
   one.
3. Remove the old entry only once its pending deliveries have drained,
   delivered or dead-lettered, or expired at the end of
   `retention.hookPayloadRetentionDays`.

There is no command that abandons pending deliveries.

## Generated files

Everything under `generated/` is reproduced by its generator and never
hand-edited:

```bash
cargo run -p registry-documents --features schema --example runtime-schema -- \
  --output products/documents/generated/runtime
cargo run -p registry-documents --features schema --example project-schema -- \
  --output products/documents/generated/project
cargo run -p registry-documents --features schema --example event-schemas -- \
  --output products/documents/generated/events
cargo run -p registry-documents --features schema --example openapi -- \
  --output products/documents/generated
```

The problem catalog published under
`https://id.registrystack.org/problems/registry-documents/` is exported by
`cargo run -p registry-documents-core --example problem-catalog` through
`products/identifiers/scripts/generate.py`.

## Verify

```bash
products/documents/scripts/check-checkpoint.sh
products/documents/scripts/check-contracts.sh
DOCUMENTS_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-documents --features postgres-test \
  --test postgres_startup --test postgres_operator --test postgres_documents \
  --test postgres_s3
DOCUMENTS_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-documentsctl --features postgres-test --test postgres_cli
cargo build --locked -p registry-render
DOCUMENTS_TEST_DATABASE_URL=<disposable database> \
  REGISTRY_RENDER_BIN="$PWD/target/debug/registry-render" cargo test --locked \
  -p registry-documents --features postgres-test --test postgres_journey
```

The checkpoint runs the dependency-direction and database-isolation gates,
the script tests, the contract validator, the schema drift test, and the
offline `documentsctl` refusal cases. The PostgreSQL suites need a disposable
database and fail, rather than skip, without `DOCUMENTS_TEST_DATABASE_URL`.
Each test runs in its own schema. `postgres_s3` runs the S3 storage branch
against a loopback fake object store and HTTP verifier it starts itself.
`postgres_journey` is the golden journey over a real socket: a letter
rendered by the `registry-render` binary is reserved under the digest Registry
Render reported, uploaded into a citizen's custody, shared by the citizen with
one named recipient, downloaded byte for byte, and kept after the share
expires and the sweep runs. It fails, rather than skips, without
`REGISTRY_RENDER_BIN`. The database-isolation gate also refuses a suite that
reads its database variable without failing when it is absent, or that
ignores a test.
