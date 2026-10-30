# Registry Adapter product

This directory owns the Adapter product contract, the execution plan that
decomposes it, and the product-local verification scripts. Read the
workspace `AGENTS.md`, this file, and the two documents below before
changing the product or any `registry-adapter*` crate.

- `CONCEPT.md` is the product contract: the artifact model, the engine
  (a bounded Rust port of Apache Camel, with its port table in section
  8.10), writes and failure semantics, authorization,
  audit, configuration formats, and the quality verification every gate
  implements. On any conflict, `CONCEPT.md` wins over every other
  document in this directory.
- `DELIVERY-PLAN.md` is the execution plan: the wave model, stream
  ownership, the eleven rules every agent works under, the review protocol, and each increment's
  definition of done and acceptance commands. It never widens the
  contract.

## Area ownership

| Area | Owns |
|---|---|
| `crates/registry-adapter-core` | Source-neutral Adapter model, wire DTOs, `adapter.*` problem codes, and pure authoring checks; no I/O |
| `crates/registry-adapter` | Adapter runtime: the governed facade, the Camel-port engine (exchange, routes, EIP processors, components), the security surface, the audit journal, and the idempotency store |
| `crates/registry-adapterctl` | Adapter authoring and operator tooling and the `adapterctl` binary |
| `products/adapter/` | `CONCEPT.md`, `DELIVERY-PLAN.md`, schemas, profiles, packs, examples, fixtures, and product scripts |

`CONCEPT.md` section 8.1 fixes the platform reuse: the runtime reaches
`registry-platform-script`, `-oidc`, `-httputil`, `-httpsec`,
`-ratelimit`, `-audit`, `-config`, and `-yaml`, and never another
product's runtime, tooling, or protocol types. Product logic (routes, EIP
processors, mapping, disclosure) never moves into a platform crate; the
redelivery, circuit breaker, and throttle processors stay adapter-local
under the two-system rule (D13). This program changes no Evidence crate
and no platform crate; its only platform edits are format registration in
`products/platform/`.

## Gates

Run from the worktree root; every cargo invocation carries
`CARGO_TARGET_DIR=<target-dir> PATH="$HOME/.cargo/bin:$PATH"`, your own
target directory for `<target-dir>`.

```bash
products/adapter/scripts/check-contracts.sh
products/adapter/scripts/test-postgres.sh
```

`check-contracts.sh` runs the verification floor from `DELIVERY-PLAN.md`:
`cargo fmt --check` over the workspace plus clippy and tests over the
adapter crates (`-p registry-adapter -p registry-adapter-core
-p registry-adapterctl`), the generated schemas held to their generator,
and the platform configuration-format lint. `test-postgres.sh` runs the
adapter crates' `postgres-test` suites: without
`ADAPTER_TEST_DATABASE_URL` it starts and removes its own loopback
PostgreSQL 17 container; with the variable set it uses that server as
given. The PostgreSQL suites themselves land with the journal in
Increment 1 wave 1. Schema drift, `check-port-table.py`, and fixture
checks join at the integration waves, as `DELIVERY-PLAN.md` assigns
them.

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
and the five v1alpha1 format kinds are registered through the platform
change Increment 0 wave 1 (stream A2) makes in
`products/platform/config-formats.yaml`.
