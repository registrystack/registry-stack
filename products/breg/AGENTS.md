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

The Evidence export described in `products/breg/EVIDENCE.md` is a governed
lookup export, never Evidence authority. `bregctl generate evidence-source`
writes ordinary Evidence source, selector, schema, and adapter files from a
compiled registry, changing no registry and creating no access grant. Evidence
keeps the questions those facts answer, caller authorization, minimization,
signing, and deployment configuration.

At the other edges, Registry Manifest owns portable metadata and DCAT rendering
and receives a one-way projection, Registry Relay is a separate read-only
publication boundary, and Registry Mint issues tokens while an operated BReg
runtime stays an independent OAuth resource server. Authoring, signing, and
migration authority stay separate: tooling can edit, diff, and check
configuration, and cannot mint a package signature or hold the production
migration credential.

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
`crates/registry-breg/src/contract.rs`, `products/breg/membership-access.md`).
Domain-specific compounds such as `group-membership` remain forbidden.
Changing the blocklist is a boundary decision: record it in this file.

## Where the owning material lives

- Delivery catalog: `products/breg/contracts/`, including
  `definition-of-done.yaml`, `security-invariant-matrix.yaml`, and
  `security-test-traceability.yaml`. A `planned` row records a threat and a
  future refusal; the change that enforces it adds the resolving negative test
  in the same patch.
- Design and behavior: `products/breg/IMPLEMENTATION.md` first, then the
  focused document beside it that owns the changed area, among
  `products/breg/HISTORY.md`, `products/breg/SPATIAL-QUERIES.md`,
  `products/breg/EVENTS-AND-WEBHOOKS.md`, `products/breg/metadata.md`,
  `products/breg/immediate-actions.md`, `products/breg/registry-extensibility.md`,
  `products/breg/native-patterns.md`, and `products/breg/membership-access.md`.
- Local loops: `products/breg/DEV.md` for the native `bregctl dev` lifecycle,
  `products/breg/quickstart/` for the scripted first hour, and
  `products/breg/starters/` for the resumable starter journeys `bregctl
  examples` lists and runs.
- Model-derived projects: the embedded PublicSchema snapshot in
  `crates/registry-linkml`, the reference model behind `bregctl init --from
  publicschema`.
- Composition: `products/breg/EVIDENCE.md` for the lookup export, and
  `products/breg/evidence/` for the reviewed registry, starter project, and
  proof it is tested with.
- Published configuration references:
  `docs/site/src/content/docs/reference/breg-configuration.mdx` and
  `docs/site/src/content/docs/reference/breg-api.mdx`; the adopter guides are
  `docs/site/src/content/docs/configure/breg.mdx` and
  `docs/site/src/content/docs/operate/breg.mdx`.

## Checks per change kind

Run these from the repository root. In managed worktrees set
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`, and
`CARGO_PROFILE_TEST_DEBUG=0`, as the root guidance requires.

Any Rust change. CI builds this shard without `--all-features`, per
`.github/scripts/run_cargo_packages.py`:

```sh
cargo fmt --check
cargo clippy --locked --profile ci --all-targets -p registry-breg -p registry-bregctl -- -D warnings
cargo test --locked --profile ci -p registry-breg -p registry-bregctl
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

`products/breg/scripts/test-postgres-tls.sh` proves the TLS behavior and needs
the `BREG_TEST_TLS_*` variables the `breg-contracts` job exports.

Native development lifecycle change. The test owns a PostgreSQL container, so
it needs Docker:

```sh
cargo test --locked --profile ci -p registry-bregctl --test dev_lifecycle -- --ignored
```

Evidence export change. The proof drives the three native binaries over
`products/breg/evidence/` offline and starts no container:

```sh
CARGO_TARGET_DIR=target/breg-evidence-composition cargo build --locked --profile ci \
  -p registry-bregctl -p registry-evidence -p registry-evidencectl --bins
uv run --no-project --with PyYAML==6.0.2 python \
  products/breg/evidence/tests/verify-composition.py \
  --bregctl target/breg-evidence-composition/ci/bregctl \
  --evidencectl target/breg-evidence-composition/ci/evidencectl \
  --evidence target/breg-evidence-composition/ci/evidence
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
bash docs/site/scripts/check-breg-tutorial.sh
```

## Generated outputs

Reproduce each with its generator. Commit the product-owned schema and fixture
outputs beside the source change. The `docs/site` outputs below are ignored build
artifacts, regenerated by the normal docs commands. Do not hand-edit any of them.

| Output | Generator |
|---|---|
| `products/breg/generated/authoring/` | `cargo run -p registry-breg --features schema --example authoring-schema -- --output products/breg/generated/authoring` |
| `products/breg/generated/runtime/` | `cargo run -p registry-breg --features runtime,schema --example runtime-schema -- --output products/breg/generated/runtime` |
| `products/breg/generated/<fixture>/` | `bregctl generate <selector> <fixture> --output <directory>`, compared by `products/breg/scripts/check-generated.sh` |
| `docs/site/src/data/generated/breg-configuration.json` | `docs/site/scripts/generate-breg-configuration.mjs` |
| `docs/site/src/content/docs/reference/cli/breg.mdx`, `docs/site/src/content/docs/reference/cli/bregctl.mdx` | `docs/site/scripts/generate-cli-reference.mjs` |

## Security review notes

`CONTRIBUTING.md` treats changes to authentication, authorization, assertion
evaluation or signing, audit integrity, release provenance, deployment defaults,
or data minimization as security-sensitive, and requires explicit maintainer
review notes even when the maintainer is the author. For BReg that covers
package verification and signature policy, the separate migration database role,
access profiles and field permissions, selector validation, audit ordering, and
any change to what a configured read route can return. Name the threat, the Rust
enforcement point, and the focused negative test that pins it. Do not weaken a
pinning test to make a gate pass.
