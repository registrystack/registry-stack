# Registry Adapter product

This directory owns the Adapter product contract, the execution plan that
decomposes it, and the product-local verification scripts. Read the
workspace `AGENTS.md`, this file, and the two documents below before
changing the product or any `registry-adapter*` crate.

- `CONCEPT.md` is the product contract: the artifact model, the engine,
  the call-plan vocabulary, writes and failure semantics, authorization,
  audit, configuration formats, and the quality verification every gate
  implements. On any conflict, `CONCEPT.md` wins over every other
  document in this directory.
- `DELIVERY-PLAN.md` is the execution plan: the wave model, stream
  ownership, the ten rules every agent works under, and each increment's
  definition of done and acceptance commands. It never widens the
  contract.

## Area ownership

| Area | Owns |
|---|---|
| `crates/registry-adapter-core` | Source-neutral Adapter model, wire DTOs, `adapter.*` problem codes, and pure authoring checks; no I/O |
| `crates/registry-adapter` | Adapter runtime: the governed facade, the call-plan interpreter, the security surface, and the audit journal |
| `crates/registry-adapterctl` | Adapter authoring and operator tooling and the `adapterctl` binary |
| `products/adapter/` | `CONCEPT.md`, `DELIVERY-PLAN.md`, schemas, profiles, packs, examples, fixtures, and product scripts |

`CONCEPT.md` section 8.1 fixes the platform reuse: the runtime reaches
`registry-platform-script`, `-oidc`, `-httputil`, `-httpsec`,
`-ratelimit`, `-audit`, `-config`, and `-yaml`, and never another
product's runtime, tooling, or protocol types. Product logic (call plans,
mapping, disclosure) never moves into a platform crate; where the adapter
needs more than the platform has, the addition lands in the platform
crate as mechanism, additively, under the two-system rule. This program
changes no Evidence crate.

## Gates

Run from the worktree root; every cargo invocation carries
`CARGO_TARGET_DIR=/Volumes/CodexWorktrees/target/live-adapter PATH="$HOME/.cargo/bin:$PATH"`.

```bash
products/adapter/scripts/check-contracts.sh
```

The gate is `cargo fmt --check` over the workspace plus clippy and tests
over the adapter crates (`-p registry-adapter -p registry-adapter-core
-p registry-adapterctl`). It is the only gate today; the standalone
`products/adapter/scripts/test-postgres.sh` arrives with Increment 2,
when the journal lands, and schema drift and fixture replay join at the
Increment 0 integration wave.

## Verify commands

```bash
CARGO_TARGET_DIR=/Volumes/CodexWorktrees/target/live-adapter PATH="$HOME/.cargo/bin:$PATH" cargo fmt --check
CARGO_TARGET_DIR=/Volumes/CodexWorktrees/target/live-adapter PATH="$HOME/.cargo/bin:$PATH" cargo clippy -p registry-adapter -p registry-adapter-core -p registry-adapterctl --all-targets -- -D warnings
CARGO_TARGET_DIR=/Volumes/CodexWorktrees/target/live-adapter PATH="$HOME/.cargo/bin:$PATH" cargo test -p registry-adapter -p registry-adapter-core -p registry-adapterctl --locked
```

Every adapter diagnostic is value-free under an `adapter.*` code
(CONCEPT.md section 11, CFG-SEC-3): a report names the artifact, the
JSON Pointer, and the code, never a value that could carry secret or
environment material. Configuration formats follow
`products/platform/CONFIG-CONVENTIONS.md`; the `Adapter` envelope prefix
and the five v1alpha1 format kinds are registered through the platform
change Increment 0 wave 1 (stream A2) makes in
`products/platform/config-formats.yaml`.
