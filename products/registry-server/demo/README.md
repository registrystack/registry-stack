# Registry Server household demo

This local demo starts four real components:

- PostgreSQL 17 with TLS, separate migration and runtime roles, and disposable
  databases;
- Registry Mint as the OIDC token issuer;
- Registry Server configured from the PublicSchema-shaped household project;
- `registry-serverctl` for schema testing, packaging, activation, and
  verification.

It then asks Mint for short-lived operator and negative-test tokens and creates
eight synthetic people, three households, and eight effective-dated memberships
through Registry Server's ordinary authenticated REST API.

## Run it

Prerequisites are Docker, Cargo, OpenSSL, Python 3, and `uv`. Run:

```bash
products/registry-server/demo/run.sh
```

The first run builds the four required Registry Stack binaries and may pull the
pinned PostgreSQL image. When the demo is ready, leave that terminal running.
In a second terminal, execute the sample reads:

```bash
products/registry-server/demo/query.sh
```

The query helper reads the bearer token from its owner-only file without
placing the token in a command-line argument or printing it. Press Ctrl-C in
the first terminal to stop Mint and Registry Server and remove the PostgreSQL
container.

Use `--smoke` to run the full setup, seed and query assertions, then stop
without waiting:

```bash
products/registry-server/demo/run.sh --smoke
```

## Copyable requests

The query helper runs the GET shapes against the local server. The examples
below also show the selector lookup and viewer-denial requests with synthetic
bearer placeholders and deterministic logical IDs; when using the demo
directly, read the generated household UUID from
`demo/.run/seed-record-ids.json`.

```bash
curl -sS -H 'Authorization: Bearer <operator-token>' \
  'http://127.0.0.1:18080/v1/records/households/<household-id>/people?accessProfile=household-operator&$select=person-code,legal-name,person-sex,residency-status&$orderby=person-code&$top=20&$count=true'

curl -sS -H 'Authorization: Bearer <operator-token>' \
  'http://127.0.0.1:18080/v1/records/households?accessProfile=household-operator&$select=household-code,administrative-area,local-household-number,child-count&$filter=administrative-area%20eq%20%27north-demo%27%20and%20child-count%20eq%201&$orderby=local-household-number&$top=20&$count=true'

curl -sS -H 'Authorization: Bearer <operator-token>' \
  'http://127.0.0.1:18080/v1/records/households?accessProfile=household-operator&$select=household-code,child-under-5-count,single-headed&$filter=single-headed%20eq%20true%20and%20child-under-5-count%20eq%201&$top=20&$count=true'

curl -sS -H 'Authorization: Bearer <operator-token>' \
  'http://127.0.0.1:18080/v1/records/households?accessProfile=household-operator&$select=household-code,woman-headed,child-count,elderly-count&$filter=woman-headed%20eq%20true%20and%20child-count%20eq%201%20and%20elderly-count%20eq%201&$top=20&$count=true'

curl -sS -X POST -H 'Authorization: Bearer <operator-token>' \
  -H 'Content-Type: application/json' \
  --data '{"selector":"by-local-reference","value":{"administrative-area":"north-demo","local-household-number":1001}}' \
  'http://127.0.0.1:18080/v1/records/households:lookup?accessProfile=household-operator'

curl -sS -H 'Authorization: Bearer <viewer-token-bound-to-one-household>' \
  'http://127.0.0.1:18080/v1/records/households?accessProfile=household-viewer'

curl -sS -H 'Authorization: Bearer <operator-token>' \
  'http://127.0.0.1:18080/v1/records/households?accessProfile=household-operator&$skiptoken=<nextCursor>'
```

The `household-viewer` profile is intentionally get and lookup only. A list
attempt is expected to return the same concealed absence class as an
unauthorized resource.

## Disposable state

All generated configuration, keys, tokens, logs, package artifacts, and
database connection material live under `demo/.run/`, which is ignored by Git.
The directory and its secret subdirectories are owner-only. A new run replaces
the previous disposable directory after verifying that it is the demo-owned
path and not a symbolic link.

The demo deliberately uses Registry Mint's supervised local-development
profile and a local unsigned Registry package. Production deployments require
their normal issuer, signer custody, package signatures, and operated
PostgreSQL service.

## Demo data

The data is a small curated relational fixture rather than random names. This
makes the household memberships and expected query results stable and easy to
understand. The existing Evidence source-mock generator is not reused here
because it generates isolated HTTP responses from OpenAPI; it does not create
referentially coherent Registry records.

The seed still follows the real application boundary: Mint owns the authority
claims, Registry Server validates every write, and memberships use the server
UUIDs returned for their person and household records.
