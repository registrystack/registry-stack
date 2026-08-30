# Registry Server Generic Quickstart

This is the shortest local adopter path for Registry Server. It starts a
domain-neutral registry from `registry-serverctl init`, checks it, runs
disposable PostgreSQL and Registry Mint on loopback, obtains a short-lived Mint
token, posts one record, and reads that record back from Registry Server.

The launcher adds only local package identity to the initialized project before
`check`, `test`, and `package`. It does not add a manifest projection or a
domain model.

Prerequisites are Docker, Cargo, OpenSSL, Python 3, and `uv`.

```bash
products/registry-server/quickstart/run.sh
```

The first run builds `registry-server`, `registry-serverctl`, and `mint`, then
pulls the pinned PostgreSQL image if Docker does not already have it. When the
launcher prints `Registry Server generic quickstart is ready`, leave that
terminal running.

In another terminal, read the created record:

```bash
products/registry-server/quickstart/query.sh get <record-id>
```

Or create and read another generic record:

```bash
products/registry-server/quickstart/query.sh all
```

The helper reads the bearer token from `quickstart/.run/secrets/operator-token`.
It does not put the token on the command line or print it. The launcher writes
the local runtime configuration it used to `.run/runtime.yaml`.

For a non-interactive check of the full local path, run:

```bash
products/registry-server/quickstart/run.sh --smoke
```

For the offline structural self-test, which does not start Docker or use the
network, run:

```bash
products/registry-server/quickstart/self-test.sh
```

All generated configuration, keys, tokens, logs, package artifacts, and
database URLs live under `quickstart/.run/`, which is ignored by Git and created
owner-only. A new run replaces only that quickstart-owned directory after
checking that it is not a symbolic link.

This is deliberately a local-development route. It uses Mint's supervised
local-development profile, loopback HTTP, disposable PostgreSQL, and an unsigned
local package. Production pilots still require the separate package-signing,
database-role, migration, TLS, and operational lifecycle described in the
product README.
