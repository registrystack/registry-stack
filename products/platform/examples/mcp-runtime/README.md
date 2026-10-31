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

The missing-authority negative configuration lives under
`crates/registry-mcp/tests/fixtures/`; it is a test fixture, not a prior released
operator format. Use the staff example above for the delegated-read shape.

The [Adapter example](adapter.example.yaml) is experimental. Set its absolute
contract file and exported digest, reviewed operation names/descriptions,
audience and secret references for a separately built compatible producer.
`dataClass: non-personal` is an unchecked classification; review the fields and
source authority rather than treating the label as enforcement.

## Run the synthetic external-read workspace

The native integration test creates a complete temporary workspace: a synthetic issuer, a controlled external source, a real Adapter process with PostgreSQL journal, and the configurable MCP router with a real MCP client.
It obtains the contract through the Adapter's public CLI and authenticated endpoint rather than a hand-written manifest.
It exercises GET, read-only POST, input/output validation, digest drift, unavailable journal and other negative cases.
The fixture data is synthetic and no production service is contacted.

The producer is a separate in-progress source dependency and is not shipped by
this gateway tree. The committed producer-generated golden export gives a
non-ignored compatibility check without that binary. Native proof additionally
requires the matching producer and fixtures described below. The binding remains
experimental until that producer is available and its combined CI drill is wired.

Build the matching Adapter sources separately. For the explicitly owned plaintext
PostgreSQL fixture, run from that Adapter source tree:

```sh
cargo build --locked -p registry-adapter --features postgres-test --bin adapter
```

The binary must support the versioned/domain-bound `effective-contract/v1alpha1`
digest, trusted-machine authority, authenticated contract/readiness readback and
the operation's `x-registry-adapter-contract` precondition.
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

## Match the staff authorization settings

| Gateway setting | Owning service setting |
| --- | --- |
| `authorization.audience` | Casework token verifier audience |
| `authorization.exchange.clientId` | Reader policy's admitted gateway client |
| `readerPolicy` | Enabled Casework `delegatedStaffReaders` map key |
| `authorization.scopes` | Staff profile scopes plus reader `requiredScope` |
| Optional `sourceProfile` | Reader's admitted source profile and BReg agent profile |
| Source delegated exchange audience/client | Independently admitted BReg source audience and trusted actor |

The issuer must support client-authenticated RFC 8693 exchange, preserve the
represented staff subject, bind the gateway in `act`, and issue the configured
Casework read scopes within the reader's lifetime limit. Current-source reads
need a second exchange to the source audience under the independently admitted
source gateway, including the required BReg review scope. This is an issuer
capability requirement. The native drill uses a synthetic issuer and does not
prove that the stock issuer or an institution's IdP supports these exchanges.

For source disclosure, the institution explicitly grants the BReg agent profile
its reviewer population and permitted fields/rows. That profile does not
automatically intersect with each represented person's human BReg permissions.

Configure Casework's `authentication.oidc.humanIdentity` against an issuer-verified
claim about the represented person, and preserve that claim through both
exchanges. The native fixture uses a separate subject-human claim: the gateway's
current actor category can correctly be `service` while its represented subject
is human. Preserve the principal, purpose and jurisdiction claims selected by
the source profile as well. Tokens must derive these claims from the verified
subject; tool arguments cannot supply them.
