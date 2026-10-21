# Registry Document Store

The Document Store holds document bytes in custody for an owning system and
releases an exact, verified document version to a recipient a document grant
names. An owning system places a document in custody under a document policy;
content verification decides whether a version may ever be released; a
document grant names one recipient, one version, and an expiry.

The product is pre-1.0 and held out of releases. This directory and its four
crates are a wired skeleton: the configuration formats, schemas, problem
vocabulary, tooling, CI gates, and release hold-out exist, and the runtime
serves only its health route. Document custody, storage, content
verification, document grants, retention, and hooks arrive in later changes.

## Crates

| Crate | Owns |
|---|---|
| `registry-documents-core` | Source-neutral naming, the problem vocabulary, wire DTOs, and the `DocumentsProject` model |
| `registry-documents` | PostgreSQL-backed runtime and the `documents` binary |
| `registry-documentsctl` | Offline configuration checks and the `documentsctl` binary |
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

Serve with `documents --runtime-config ABSOLUTE_FILE serve`. The runtime
listens on `127.0.0.1:8116` in the starter.

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
  -p registry-documents --features postgres-test --test postgres_startup
```

The checkpoint runs the dependency-direction and database-isolation gates,
the script tests, the contract validator, the schema drift test, and the
offline `documentsctl` refusal cases. The PostgreSQL suite needs a disposable
database and fails, rather than skips, without `DOCUMENTS_TEST_DATABASE_URL`.
