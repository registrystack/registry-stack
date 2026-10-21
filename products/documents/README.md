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
with removal from custody and erasure by a cleanup sweep. Hooks arrive in a
later change.

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
other. A generation other than the current one is refused. The replay is
written to the `documentsctl` companion audit journal. No HTTP route lists or
replays a job.

## Generated files

Everything under `generated/` is reproduced by its generator and never
hand-edited:

```bash
cargo run -p registry-documents --features schema --example runtime-schema -- \
  --output products/documents/generated/runtime
cargo run -p registry-documents --features schema --example project-schema -- \
  --output products/documents/generated/project
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
```

The checkpoint runs the dependency-direction and database-isolation gates,
the script tests, the contract validator, the schema drift test, and the
offline `documentsctl` refusal cases. The PostgreSQL suites need a disposable
database and fail, rather than skip, without `DOCUMENTS_TEST_DATABASE_URL`.
Each test runs in its own schema. `postgres_s3` runs the S3 storage branch
against a loopback fake object store and HTTP verifier it starts itself.
