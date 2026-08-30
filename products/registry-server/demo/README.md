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
through Registry Server's ordinary authenticated REST API. Once the first
household has a server UUID, the demo creates a separate viewer key and Mint
client whose verified claims bind it to that UUID and household code.

## Run it

Prerequisites are Docker, Cargo, OpenSSL, Python 3, and `uv`. Run:

```bash
products/registry-server/demo/run.sh
```

The first run builds the four required Registry Stack binaries and may pull the
pinned PostgreSQL image. When the demo is ready, leave that terminal running.
In a second terminal, execute all sample reads:

```bash
products/registry-server/demo/query.sh all
```

Or focus on one access profile:

```bash
products/registry-server/demo/query.sh operator
products/registry-server/demo/query.sh viewer
```

These are the real requests against the running server. The operator suite
shows relationship traversal, composable derived-field filters, and an exact
request-value selector lookup. The viewer suite proves that one claim-bound
household can be fetched by UUID or looked up from its verified household-code
claim, while list and household-to-people path requests return the concealed
`resource.not_found` response.

The helper reads bearer tokens from owner-only files inside `.run/`. It does
not put them in command-line arguments or print them. Press Ctrl-C in the first
terminal to stop Mint and Registry Server and remove the PostgreSQL container.

Use `--smoke` to run the full setup, seed and query assertions, then stop
without waiting:

```bash
products/registry-server/demo/run.sh --smoke
```

The exact paths, query parameters, selector bodies, and expected statuses live
in `support/demo.py`, which `query.sh` invokes. This keeps the examples
copyable without teaching people to expand bearer tokens into process-visible
`curl` arguments. Field and selector IDs intentionally retain their configured
kebab-case spelling. The operator selector body uses the exact `values`
property, while the viewer's verified-claim selector correctly sends no
caller-provided values.

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
