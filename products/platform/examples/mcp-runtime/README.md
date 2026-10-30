# MCP configuration and golden workspace

Check the citizen example from the source workspace without resolving a credential:

```sh
cargo run --locked -p registry-mcp -- --runtime-config "$PWD/products/platform/examples/mcp-runtime/runtime.example.yaml" check
```

The example selects the existing BReg citizen tools explicitly.
Its issuer, registry and review origins are placeholders; an offline pass establishes configuration validity, not access to a running service.
Use the institution's independently operated issuer and task authority for protected BReg operations.

The staff template demonstrates an authority dependency with a precise refusal:

```sh
cargo run --locked -p registry-mcp -- --runtime-config "$PWD/products/platform/examples/mcp-runtime/casework-held.example.yaml" check
```

Expect exit 1 and `casework.mcp.delegation-unsupported`.
Current Casework human profiles reject delegated actor tokens.
The template uses a distinct staff audience, client, scope and credential namespace; it does not make that missing authority available.

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
