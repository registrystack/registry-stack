# MCP configuration and golden workspace

Check the citizen example from the source workspace without resolving a credential:

```sh
cargo run --locked -p registry-mcp -- --runtime-config "$PWD/products/platform/examples/mcp-runtime/runtime.example.yaml" check
```

The example selects the existing BReg citizen tools explicitly.
Its issuer, registry and review origins are placeholders; an offline pass establishes configuration validity, not access to a running service.
Use the institution's independently operated issuer and task authority for protected BReg operations.

The staff example selects the separate delegated-read contract explicitly:

```sh
cargo run --locked -p registry-mcp -- --runtime-config "$PWD/products/platform/examples/mcp-runtime/casework.example.yaml" check
```

Its `readerPolicy` must name an enabled Casework `delegatedStaffReaders` policy,
with the exact trusted gateway client/actor, represented Staff profile, read
scopes and short lifetime. Casework admits only assigned-task listing and context
reads through dedicated routes. An offline pass validates the gateway file; the
backend independently checks that authority on every call. Current-source reads
also require a separate source-resource exchange and source-owned agent
disclosure profile. The example uses a distinct staff audience, client, scope and
credential namespace.

The historical `casework-held.example.yaml` is retained as a migration refusal
fixture. It lacks the explicit authority selector and is refused offline with
`config.missing-key`. Use the staff example above for the delegated-read shape.

## Run the synthetic external-read workspace

The native integration test creates a complete temporary workspace: a synthetic issuer, a controlled external source, a real Adapter process with PostgreSQL journal, and the configurable MCP router with a real MCP client.
It obtains the contract through the Adapter's public CLI and authenticated endpoint rather than a hand-written manifest.
It exercises GET, read-only POST, input/output validation, digest drift, unavailable journal and other negative cases.
The fixture data is synthetic and no production service is contacted.

Build the matching Adapter sources separately.
They must support `effective-contract/v1alpha1`, authenticated contract/readiness readback and the operation's `x-registry-adapter-contract` precondition.
Use the fixtures from that same source tree and an explicitly disposable PostgreSQL database.
Then run from the gateway source workspace:

```sh
ADAPTER_BIN=/absolute/path/to/adapter \
ADAPTER_FIXTURES_ROOT=/absolute/path/to/matching/products/adapter \
ADAPTER_TEST_DATABASE_URL=postgresql://test-user:test-password@127.0.0.1:5432/owned-test-database \
cargo test --locked -p registry-mcp --test native_adapter -- --ignored --test-threads=1
```

The test writes its temporary runtime files and synthetic credentials under `TMPDIR`; set that to an owned scratch directory where required by your environment.
It owns its test schema and process cleanup.
Read the command's test count and results; an ignored test or zero selected tests is not a successful golden-workspace run.

For the separate native citizen proof, follow the BReg `postgres` lane's `native_citizen` instructions and matching binary prerequisites.
Synthetic authority and loopback sources prove the local composition boundaries; live institution access remains a separate deployment exercise.

## Run the native staff-read proof

Build matching `breg`, `bregctl`, `casework` and `caseworkctl` binaries. Set
`BREG_BIN`, `BREGCTL_BIN`, `CASEWORK_BIN` and `CASEWORKCTL_BIN` to their absolute
paths, `REGISTRY_STACK_FIXTURES_ROOT` to this matching source tree, and
`CASEWORK_MCP_TEST_DATABASE_URL` to an explicitly owned disposable PostgreSQL
administrator connection. The test creates isolated product databases/roles;
never select an institutional or retained database. Set `TMPDIR` to a private
task-owned directory.

```sh
cargo test --locked -p registry-mcp --test native_casework -- --ignored --nocapture
```

This executes the MCP client/router, token exchange and real product/database
boundaries. The issuer and test records are synthetic. It does not establish
a production issuer integration or live institutional authorization.
