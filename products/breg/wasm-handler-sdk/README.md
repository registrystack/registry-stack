# BREG WASM Handler SDK

The Rust SDK for writing a Base Registry Engine (BREG) action handler as a function, compiling it
to a WebAssembly module, and packaging it into a registry project. The authoring guide, the
packaging declaration, the runtime configuration and the upgrade and rollback paths are on the
documentation site: <https://docs.registrystack.org/configure/breg-wasm-action-handlers/>.

This directory is its own cargo workspace, excluded from the registry-stack workspace. Guest-only
dependencies stay out of the registry-stack dependency tree, and the SDK's byte-ABI shim uses the
raw-pointer code the registry workspace forbids.

## Layout

| Path | What it is |
|---|---|
| `sdk/` | `registry-breg-wasm-sdk`, imported as `breg_wasm_sdk`. The crate that hides the byte ABI. |
| `template/` | `breg-wasm-handler-template`. The reference handler (phone normalization). Copy it to start. |
| `preinit/` | `breg-wasm-preinit`. Build-time tool that pre-initializes a module. |
| `admission/` | `breg-wasm-admission-proof`. Compiles the built module into a registry project and runs every fixture outcome. |
| `scripts/build.sh` | Builds the module, records sizes and hashes, enforces the size ceilings, runs the proof. |
| `fixtures/` | The fixture corpus shared by the template's host tests and the admission proof. |

## Test and build

You need Rust 1.95 or later with the `wasm32-unknown-unknown` target
(`rustup target add wasm32-unknown-unknown`).

```sh
cargo test -p breg-wasm-handler-template
scripts/build.sh             # build, record sizes, enforce ceilings, run the proof
scripts/build.sh --preinit   # also produce the pre-initialized variant
scripts/build.sh --skip-proof
```

The build writes modules to `artifacts/` and records each module's bytes, ceiling, verdict and
sha256 in `artifacts/module-sizes.tsv`. It fails over the 2 MiB ceiling, or 5 MiB for a
pre-initialized module.
