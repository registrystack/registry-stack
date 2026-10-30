# WASM action handlers

A BReg immediate Action can use a named WebAssembly Function instead of Rhai.
This guide covers what ships today, the server-compatibility contract, operator
configuration, and the upgrade and rollback paths. Authoring help lives in
[`wasm-handler-sdk/`](wasm-handler-sdk/README.md).

## What ships

- A named Function (`runtime: wasm` with a project-local `source` path,
  `entrypoint: plan`, and `abi: registry.action-plan/v1`), a backend-tagged
  compiled representation, an optional
  operator configuration section, and a cargo feature (`wasm`) gating
  admission and execution. Maintained `registry-breg` and `registry-bregctl`
  builds enable the feature by default. A custom `--no-default-features` build
  omits WASM support and the Wasmtime dependency.
- A WASM handler is input-only and resolver-free. Proposal-mode WASM
  plans are refused typed at admission, and so is an action that declares
  `evidence` with a WASM handler.
- The execution backend is Pulley by default (no runtime code generation) with
  native as an operator opt-in; see the configuration table below.
- The guest contract is a closed byte ABI: zero imports, five required exports
  (`alloc`, `handle`, `result_ptr`, `result_len`, `memory`), the request is
  exactly the `{"inputs": ...}` JSON document, and the response is exactly one
  JSON document through the same shared outcome validator the Rhai path uses.
  The Rust SDK hides all of this behind a plain function.

## Build support

Maintained binaries enable WASM support. A custom build without the `wasm`
feature refuses a WASM-bearing package during compiler admission or package
rederivation before activation. Check the Action's compiled explanation and
operator execution budgets before deploying it. Hook handlers retain their
separate `registry.hook-handler/v1` ABI.

## Enabling the feature

Default builds of `registry-breg` and `registry-bregctl` already include the
`wasm` feature. A custom feature selection must include `--features wasm` to
admit and run wasm-handler packages. The feature gates authoring and admission
(script/module pairing, module budgets, structural validation of module bytes
through the same executor the runtime uses), execution (dispatch routes WASM
handlers to the WASM runtime before the Rhai path), and the feature-gated
PostgreSQL journey suite. The `breg-wasm` CI lane runs the executor suite and
outcome-parity corpus under both backends, breg admission, the explicit
no-default-features refusal suite, and the PostgreSQL journeys against the
pinned PostGIS image.

## Operator configuration

Optional `wasmExecution` section in the runtime configuration:

| Field | Range | Default | Enforcement |
|---|---|---|---|
| `maximumModuleBytes` | 1 KiB..=5 MiB | 2 MiB | Package load into the runtime, and prepare |
| `maximumGuestMemoryBytes` | 1 MiB..=1 GiB | 32 MiB | Per-invocation guest memory |
| `backend` | `pulley` or `native` | `pulley` | One resolved value feeds execution, admission validation, and the prepared-module cache key |

- Typed refusals carry a code and a path; unknown members are refused. The
  section installs at startup and clears at shutdown, graceful and aborted both
  covered.
- A structural 5 MiB ceiling sits above the operator range: compiler
  admission, the package closure, and bregctl capture enforce it whatever the
  configuration, so configuration can never admit what authoring refused.
  Raise `maximumModuleBytes` above 2 MiB only for pre-initialized library modules.
- The backend is single-sourced: one resolver feeds execution, admission
  validation, and the prepared-module cache key, which is
  (module content hash, backend). A module admitted under one backend cannot
  execute under another by configuration drift. Pure authoring compilation has
  no operator configuration in scope, so admission validates under the default
  (pulley); the ABI check is target-independent, so admission cannot accept a
  module the configured backend rejects.
- Runtime shape: one engine and one 1 ms epoch ticker per process; prepared
  modules cached by (content hash, backend) with LRU move-to-front, hard cap
  32; a fresh store and instance per call; budgets and backend fixed at
  construction, so a configuration change replaces the runtime and cache
  together. Evaluation before any install is refused typed (a wiring fault),
  and a failed epoch-ticker spawn surfaces at install rather than leaving
  deadlines inert.
- Fuel is deliberately absent from the section: the compiled-in fuel budget is
  a far backstop the epoch deadline reaches first, and the two map to different
  public categories (resource exhaustion versus deadline), so exposing fuel
  without pinning which limit wins would let one wall-clock overrun surface as
  either category.

## Authoring and building

The SDK workspace at [`wasm-handler-sdk/`](wasm-handler-sdk/) contains the
`registry-breg-wasm-sdk` crate (hides the byte ABI and memory management;
preserves exact values including 64-bit integers, decimal strings, and the
absent/null distinction), a reference template implementing phone
normalization with success and declared-refusal fixtures, the build-time
pre-initializer for library handlers, and `scripts/build.sh`.

The build script is the size gate on the authoring side: it records every
produced module's byte size and sha256 to `artifacts/module-sizes.tsv` and
fails the build over the ceiling (2 MiB default, 5 MiB when pre-initializing),
complementing admission-time enforcement.

## Upgrade

1. Existing Rhai and declarative packages need no change, no re-publication,
   and no migration.
2. Use the maintained default build, or include `--features wasm` in a custom
   feature selection, and redeploy; existing packages load unchanged.
3. Add the `wasmExecution` section only if non-default budgets or the native
   backend are needed; defaults apply otherwise.
4. Author wasm-handler packages with the SDK; record the minimum server
   requirement (the `compatibility` member states it). Older and feature-off
   servers refuse the package during load, before an invocation or attempt
   audit can exist.
5. Calibrate budgets on the deployment's own architecture. Fuel is not a
   cross-host invariant, and worst single calls can exceed the budgeted p99 on
   both backends.
6. For library-backed handlers, always pre-initialize: a naive library module
   costs hundreds of milliseconds per call natively and seconds on Pulley;
   pre-initialization is what makes the default backend viable.

## Rollback

1. Deactivate or replace wasm-handler packages through the ordinary activation
   procedures; plugin execution and failed activation introduce no schema
   mutation and no late guest effects.
2. Remove the `wasmExecution` section; the install clears at shutdown.
3. Before deploying a custom build without the feature, deactivate or replace
   every wasm-handler package. Such a build cannot rederive and load those
   packages. Build with `--no-default-features` and the other required features;
   the resulting dependency tree omits Wasmtime.
4. Verify package loading before serving traffic. A feature-off build refuses
   wasm-handler packages during rederivation and refuses authoring them with
   `breg.action.handler-wasm-build-unsupported` or, for a WASM hook handler,
   `breg.hook.handler-wasm-build-unsupported`.

## Operational notes

- The wasmtime pin is an LTS line (`=48.0.8`, EOL 2028-08-20). Advisory
  detection runs in CI (cargo-deny's RustSec check), dependabot is constrained
  to LTS patch proposals against the pin, and each release cut checks the
  remaining support window, promoting the next-LTS migration to a release
  blocker once under six months remain.
- Aggregate deployment budgets (host RSS, preparation peaks) should be frozen
  per deployment; cold preparation compiles one module in roughly 100 ms.
- A module whose exported memory declares a minimum above the guest-memory
  budget is refused at validation; a negative guest-reported outcome length or
  pointer is a bounded ABI violation, never an empty success.
