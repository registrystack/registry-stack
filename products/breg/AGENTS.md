# Base Registry Engine agent guidance

Read the repository-root `AGENTS.md` first, then `products/breg/README.md` for
orientation. This entry owns `crates/registry-breg`, `crates/registry-bregctl`,
`crates/registry-breg-client` with its Node and Python bindings, and the product
material under `products/breg/`.

## Product boundary

Base Registry Engine is the writable system of record. It owns configured
writes, record revisions and history, the generated REST contract,
authorization, audit ordering, idempotency, outbox creation, and governed
migrations against PostgreSQL. It carries no built-in domain model: an entity,
relationship, route, field, access profile, or event exists only when an active
Registry package declares it. PostgreSQL is the sole Version 1 database.

Its read routes are governed configuration as well: a route, its selectors, its
readable fields, and its query capabilities all come from the compiled package,
and a caller value never creates authority.

The Evidence export described at
https://docs.registrystack.org/configure/breg-evidence/ is a governed
lookup export, never Evidence authority. `bregctl generate evidence-source`
writes ordinary Evidence source, selector, schema, and adapter files from a
compiled registry, changing no registry and creating no access grant. Evidence
keeps the questions those facts answer, caller authorization, minimization,
signing, and deployment configuration.

At the other edges, Registry Manifest owns portable metadata and DCAT rendering
and receives a one-way projection, and an operated OAuth issuer issues tokens
while a BReg
runtime stays an independent OAuth resource server. Authoring and migration
authority stay separate: tooling can edit, diff, and check configuration, and
cannot hold the production migration credential. Registry Relay is retired;
BReg does not inherit its publication contract or serve as a generic replacement.

## Source neutrality

`products/breg/scripts/check_source_neutrality.py` forbids fixture-specific
compound identifiers, concrete entity, route, and Rust-type names such as
`group-membership` or `GroupMembership`, from `registry-breg`,
`registry-bregctl`, and `registry-breg-client` production source. It does not
forbid the bare words `membership` or `memberships`: `membershipBoundaries` is
a generic, configured read-boundary mechanism, a one-hop join predicate over a
configured entity, key field, principal field, and active flag, restricted to
`get`, `lookup`, `list`, `revisions`, and `snapshot`, with at most eight
boundaries per access profile (`crates/registry-breg/src/membership.rs`,
`crates/registry-breg/src/contract.rs`).
Domain-specific compounds such as `group-membership` remain forbidden.
Changing the blocklist is a boundary decision: record it in this file.

## Where the owning material lives

- Delivery catalog: `products/breg/contracts/`, including
  `definition-of-done.yaml`, `security-invariant-matrix.yaml`, and
  `security-test-traceability.yaml`. A `planned` row records a threat and a
  future refusal; the change that enforces it adds the resolving negative test
  in the same patch. Read the exact row and resolving tests before making an
  enforcement claim; a schedule or an offline compiler result does not
  establish runtime behavior.
- Behavior guides: the docs site owns them, under `docs/site/src/content/docs/`.
  The adopter guides are `configure/breg.mdx` and `operate/breg.mdx`, and the
  published references are `reference/breg-configuration.mdx` and
  `reference/breg-api.mdx`. Focused guides sit beside them as `configure/breg-*.mdx`,
  `operate/breg-*.mdx`, and `reference/breg-*.mdx`.
- Local loops: `rstack dev` runs a project from its `dev.yaml` plan and
  scenario file (`configure/run-a-project-with-rstack-dev.mdx`),
  `products/breg/quickstart/` for the scripted first hour, and
  `products/breg/examples/` for the canonical projects and their scenario
  files. `reference/bregctl-dev.mdx` documents the older `bregctl dev` lifecycle.
- Canonical projects: `products/breg/examples/`, `products/breg/acceptance/`,
  and `products/breg/fixtures/`. `products/breg/examples/README.md` indexes the
  examples; acceptance and fixture projects carry a README where one exists.
- Model-derived projects: the embedded PublicSchema snapshot in
  `crates/registry-linkml`, the reference model behind `bregctl init --from
  publicschema`.
- Composition: `configure/breg-evidence.mdx` for the lookup export, and
  `products/breg/evidence/` for the reviewed registry, starter project, and
  proof it is tested with.

## Where code lives

All paths are under `crates/registry-breg/src/` unless named otherwise.

| Surface | Owning source |
| --- | --- |
| Authoring, normalized model, diagnostics | `contract.rs`, `compiler.rs`, and `schema.rs` |
| Generated CRUD, Record reads and mutations | `api/`, `postgres/`, and `mutation/` |
| Immediate atomic plans | `immediate_actions.rs` and `action_handler.rs` |
| Durable plans and application | `proposal_prepare.rs`, `proposal_store.rs`, `proposal_workflow.rs`, and `api/proposals.rs` |
| Review integration and deployment trust | `review_store.rs`, `review_integration.rs`, and `runtime_config.rs` |
| Restricted automatic application | Compiled system apply grants and the native Proposal worker, without an executor OAuth client or self-HTTP route |
| Record and Proposal events | `event_destination.rs` and `proposal_hooks.rs` |
| Application contracts and clients | `api/metadata.rs`, `crates/registry-breg-client`, and generated project types |
| Local authoring and operator lifecycle | `crates/registry-bregctl` |

Production code carries no fixture-specific domain types. Record types, Actions,
and Proposals are the public model; canonical projects live under `examples/`,
`acceptance/`, and `fixtures/`.

## Checks per change kind

Run these from the repository root. In managed worktrees set
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`, and
`CARGO_PROFILE_TEST_DEBUG=0`, as the root guidance requires.

Any Rust change. CI builds this shard in the default dev and test profiles
without `--all-features`, per `.github/scripts/run_cargo_packages.py`:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -p registry-breg -p registry-bregctl -- -D warnings
cargo test --locked -p registry-breg -p registry-bregctl
```

Add the `registry-breg-client*` packages when the change reaches the clients.

Compiler, contract, fixture, or generated-artifact change:

```sh
products/breg/scripts/check-contracts.sh
products/breg/scripts/check-client-contract.sh
```

`check-contracts.sh` runs `validate_product.py` over the delivery catalog, the
source-neutrality checker, `check-generated.sh` for the committed generated
trees, and the Python unit suites. Run
`python3 products/breg/scripts/validate_product.py` alone when only the catalog
changed.

Anything reaching SQL, migrations, revisions, or authorization needs a real
database. CI starts a PostGIS container and exports its URL first:

```sh
BREG_TEST_DATABASE_URL=postgresql://breg:breg_test@localhost:5432/breg \
  products/breg/scripts/test-postgres.sh
```

CI integration events run the same journeys as parallel `--lane postgres:I/N`
shard jobs that split the owned target lists; a plain local run keeps the full
suite.

`products/breg/scripts/test-postgres-tls.sh` proves the TLS behavior and needs
the `BREG_TEST_TLS_*` variables the `breg-contracts` job exports. The adopter
workflow needs the same TLS PostgreSQL: without it `bregctl test` refuses with
only `test.database.unavailable`. Locally, one command starts a disposable
TLS-only PostGIS container for the checkout and prints the exports both scripts
read:

```sh
exports=$(products/breg/scripts/local-postgres-tls.sh) && eval "$exports"
products/breg/scripts/test-postgres-tls.sh
products/breg/scripts/test-adopter-workflow.sh
products/breg/scripts/local-postgres-tls.sh --stop
```

The container accepts TLS connections only, so run `test-postgres.sh` against a
separate plain container. Doing the setup by hand trips the same four details
each time: the container ID must be the full hex ID, the CA copy cannot sit
directly in `/tmp`, the URL host must be `localhost` (the certificate's name),
and the PostGIS image starts PostgreSQL twice before it is really ready.

Native development lifecycle change. The test owns a PostgreSQL container, so
it needs Docker:

```sh
cargo test --locked -p registry-bregctl --test dev_lifecycle -- --ignored --test-threads=1
```

Evidence export change. The proof drives the three native binaries over
`products/breg/evidence/` offline and starts no container:

```sh
cargo build --locked \
  -p registry-bregctl -p registry-evidence -p registry-evidencectl --bins
uv run --no-project --with PyYAML==6.0.2 python \
  products/breg/evidence/tests/verify-composition.py \
  --bregctl target/debug/bregctl \
  --evidencectl target/debug/evidencectl \
  --evidence target/debug/evidence
```

CLI surface or configuration schema change. The docs generators read public
Clap definitions and committed schemas. Regenerate for local validation; commit
the source changes while the generated site copies stay ignored:

```sh
cd docs/site && npm run generate
```

Quickstart or tutorial change:

```sh
products/breg/quickstart/run.sh --smoke
products/breg/quickstart/run.sh --spatial --smoke
node docs/site/scripts/run-tutorial.mjs --gate breg
```

## Generated outputs

Reproduce each with its generator. Commit the product-owned schema and fixture
outputs beside the source change. The `docs/site` outputs below are ignored build
artifacts, regenerated by the normal docs commands. Do not hand-edit any of them.

| Output | Generator |
|---|---|
| `products/breg/generated/authoring/` | `cargo run -p registry-breg --features schema --example authoring-schema -- --output products/breg/generated/authoring` |
| `products/breg/generated/runtime/` | `cargo run -p registry-breg --features runtime,schema --example runtime-schema -- --output products/breg/generated/runtime` |
| `products/breg/generated/event-schemas/proposal-lifecycle.schema.json` | `cargo run -p registry-breg --example proposal-event-schema -- --output products/breg/generated/event-schemas/proposal-lifecycle.schema.json` |
| `products/breg/generated/mcp-runtime/` | `cargo run -p registry-breg-mcp --features schema --example mcp-runtime-schema -- --output products/breg/generated/mcp-runtime` |
| `products/breg/generated/review-runtime/` | `cargo run -p registry-breg-review --features schema --example review-runtime-schema -- --output products/breg/generated/review-runtime` |
| `products/breg/generated/tools/` | `cargo run -p registry-bregctl --features schema --example tool-schema -- --output products/breg/generated/tools`, compared by `products/breg/scripts/check-tool-schemas.sh` |
| `products/breg/generated/<fixture>/` | `bregctl generate <selector> <fixture> --output <directory>`, compared by `products/breg/scripts/check-generated.sh` |
| `docs/site/src/data/generated/breg-configuration.json` | `docs/site/scripts/generate-breg-configuration.mjs` |
| `docs/site/src/content/docs/reference/cli/breg.mdx`, `docs/site/src/content/docs/reference/cli/bregctl.mdx` | `docs/site/scripts/generate-cli-reference.mjs` |

## Security-sensitive changes

`CONTRIBUTING.md` treats changes to authentication, authorization, assertion
evaluation or signing, audit integrity, release provenance, deployment defaults,
or data minimization as security-sensitive. For BReg that covers
package verification, the separate migration database role,
access profiles and field permissions, selector validation, audit ordering, and
any change to what a configured read route can return. Name the threat, the Rust
enforcement point, and the focused negative test that pins it. Do not weaken a
pinning test to make a gate pass.

Update the security model page (`docs/site/src/content/docs/security/breg.mdx`) in the same change when a trust
boundary, an operator obligation, or an accepted residual changes. The
change-by-change review narrative belongs in the pull request description, not
in the repository.
