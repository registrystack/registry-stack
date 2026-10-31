# Registry Adapter product

This directory owns the Adapter product contract and the product-local
verification scripts. Read the workspace `AGENTS.md`, this file,
`README.md`, and `CONCEPT.md` before changing the product or any
`registry-adapter*` crate.

- `CONCEPT.md` is the product contract: the artifact model, the engine
  (a bounded Rust port of Apache Camel, with its port table in section
  8.10), writes and failure semantics, authorization,
  audit, configuration formats, and the quality verification every gate
  implements. On any conflict, `CONCEPT.md` wins over every other
  document in this directory.

## Area ownership

| Area | Owns |
|---|---|
| `crates/registry-adapter-core` | Source-neutral Adapter model, wire DTOs, `adapter.*` problem codes, and pure authoring checks; no I/O (it depends on `registry-platform-httputil` only for its pure header predicates and bounds) |
| `crates/registry-adapter` | Adapter runtime: the governed facade, the Camel-port engine (exchange, routes, EIP processors, components), the security surface, the audit journal, and the idempotency store |
| `crates/registry-adapterctl` | Adapter authoring and operator tooling and the `adapterctl` binary |
| `crates/registry-adapter-connectors` | Native product connectors over the maintained clients (`registry-breg-client`, `registry-scheduling-client`, `registry-documents-client`), each behind an off-by-default cargo feature; no facade binary links it (`CONCEPT.md` sections 17.3 and 17.5) |
| `products/adapter/` | `README.md`, `CONCEPT.md`, schemas, profiles, packs, examples, fixtures (including the source-shape fixtures and the bad-authoring corpus), and product scripts |

`CONCEPT.md` section 8.1 fixes the platform reuse: the runtime reaches
`registry-platform-script`, `-oidc`, `-httputil`, `-ratelimit`,
`-config`, `-yaml`, `-authcommon`, `-crypto`, and `-canonical-json`, and never another
product's runtime, tooling, or protocol types. Product logic (routes, EIP
processors, mapping, disclosure) never moves into a platform crate. The
generic primitives under `throttle`, `circuitBreaker`, and redelivery live in
`registry-platform-ratelimit` and `registry-platform-resilience` (D13); the
processors and the redelivery loop stay here. This program changes no
Evidence crate; its other platform edits are format registration in
`products/platform/` and additive constructors accepted in review.
`[ingestion]` The one exception to "never another product's protocol
types" is the connector crate above: it reaches the maintained product
clients only, never a product runtime, CLI, or database crate, and
`products/adapter/scripts/check_dependency_direction.py` enforces that
boundary mechanically (`CONCEPT.md` section 17.5). No facade binary and
neither engine crate links the connector crate or any product client.

## Gates

Run from the worktree root; every cargo invocation carries
`CARGO_TARGET_DIR=<target-dir> PATH="$HOME/.cargo/bin:$PATH"`, your own
target directory for `<target-dir>`.

```bash
products/adapter/scripts/check-contracts.sh
products/adapter/scripts/check_dependency_direction.py
products/adapter/scripts/test-postgres.sh
```

`check-contracts.sh` runs the verification floor: `cargo fmt --check`
over the workspace plus clippy and tests over the adapter crates
(`-p registry-adapter -p registry-adapter-core -p registry-adapterctl`),
the `adapterctl verify --live` synthetic TLS proof under the `tls-test`
feature, the generated schemas held to their generator, the platform
configuration-format lint, `check-port-table.py`, the example checks and
fixture replays, the source-shape contracts and fixture replays, and the
bad-authoring corpus. `test-postgres.sh` runs the adapter crates'
`postgres-test` suites: without `ADAPTER_TEST_DATABASE_URL` it starts and
removes its own loopback PostgreSQL 17 container; with the variable set it
uses that server as given.

## Verify commands

```bash
CARGO_TARGET_DIR=<target-dir> PATH="$HOME/.cargo/bin:$PATH" cargo fmt --check
CARGO_TARGET_DIR=<target-dir> PATH="$HOME/.cargo/bin:$PATH" cargo clippy -p registry-adapter -p registry-adapter-core -p registry-adapterctl --all-targets -- -D warnings
CARGO_TARGET_DIR=<target-dir> PATH="$HOME/.cargo/bin:$PATH" cargo test -p registry-adapter -p registry-adapter-core -p registry-adapterctl --locked
```

Every adapter diagnostic is value-free under an `adapter.*` code
(CONCEPT.md section 11, CFG-SEC-3): a report names the artifact, the
JSON Pointer, and the code, never a value that could carry secret or
environment material. Configuration formats follow
`products/platform/CONFIG-CONVENTIONS.md`; the `Adapter` envelope prefix
and the five v1alpha1 format kinds are registered in
`products/platform/config-formats.yaml`.
