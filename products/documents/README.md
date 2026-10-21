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
version are implemented and served behind OAuth access-token verification.
Retention, erasure, and hooks arrive in later changes.

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
| `GET /document-policies` | List the policies the caller may reserve under, with their bounds |

A document the caller may not see answers `resource.not-found`, the same as
one that does not exist. Lists page by `cursor` and `limit` (at most 100) in a
stable order.

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
