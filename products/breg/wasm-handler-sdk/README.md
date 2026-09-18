# BREG WASM Handler SDK

Author a Base Registry Engine (BREG) action handler as a Rust function,
compile it to a WebAssembly module, and package it into a registry project.
This directory holds the SDK, a copyable template handler, the build-time
pre-initializer, and the admission-proof harness that ties them together.

Audience: a Rust developer writing a first BREG WASM action handler. You
need Rust (1.95 or later) with the `wasm32-unknown-unknown` target
installed (`rustup target add wasm32-unknown-unknown`). No WASI, no
JavaScript, no server: a handler is a function from request inputs to one
outcome document.

## Layout

| Path | What it is |
|---|---|
| `sdk/` | `registry-breg-wasm-sdk`, imported as `breg_wasm_sdk`. The crate that hides the byte ABI: request decoding, outcome types, and the module export macros. |
| `template/` | `breg-wasm-handler-template`. The reference handler (phone normalization), written entirely against the SDK. Copy it to start. |
| `preinit/` | `breg-wasm-preinit`. Build-time tool that pre-initializes a module by running its `init` once and snapshotting the warmed memory. |
| `admission/` | `breg-wasm-admission-proof`. The proof harness: compiles the built module into a registry project and runs every fixture outcome. |
| `scripts/build.sh` | Builds the module, records sizes and hashes, enforces the size ceilings, runs the proof. |
| `fixtures/` | The fixture corpus shared by the template's host tests and the admission proof. |

This directory is its own cargo workspace, excluded from the
registry-stack workspace (like the fuzz directories under
`products/platform` and `products/manifest`). Guest-only dependencies stay
out of the registry-stack dependency tree, and the SDK's byte-ABI shim uses
the raw-pointer code the registry workspace forbids.

## Write a handler

1. Copy `template/` to a new crate and rename it. Keep
   `crate-type = ["lib", "cdylib"]`: the `lib` half lets your tests run on
   your machine, the `cdylib` half is the module.

2. Write your decision logic as a pure function, then read the declared
   inputs around it:

   ```rust
   use breg_wasm_sdk::{Effect, HandlerFailure, Outcome, Refusal, Request, Value};

   pub fn my_handler(request: &Request) -> Result<Outcome, HandlerFailure> {
       let raw = required_string(request, "raw-phone")?;
       // ... your logic ...
       Ok(Outcome::effects(vec![Effect::new("phone").set("phone", "+22222123456")]))
       // or: Ok(Outcome::refusal(Refusal::new("invalid-phone").field("raw-phone")))
   }

   fn required_string<'a>(request: &'a Request, id: &str) -> Result<&'a str, HandlerFailure> {
       match request.input(id) {
           Some(Value::String(text)) => Ok(text),
           _ => Err(HandlerFailure::MalformedRequest),
       }
   }
   ```

3. Declare the module's entry once, at the crate root:

   ```rust
   fn handle(request: Request) -> Result<Outcome, HandlerFailure> {
       my_handler(&request)
   }

   breg_wasm_sdk::handler!(handle);
   ```

   If your handler warms lazily initialized library statics (metadata
   tables, compiled regexes), add a `warm()` function and use
   `breg_wasm_sdk::handler_with_init!(handle, warm);` instead. The
   pre-initializer runs `warm` once at build time and snapshots the result.

One handler per module. The registry packages one module path per action
handler, and the export macros define the module's ABI surface, so a second
invocation in one crate is a compile error.

### What your function receives

The platform sends exactly the `{"inputs": {...}}` JSON document as bytes;
`Request` decodes it. Inputs are keyed by authored input id, and values
keep their exact kinds: integers stay exact (an i64 beyond f64 precision
survives the round trip), decimals stay strings, a reference envelope stays
a JSON object. An absent input and an explicit `null` are different:
`request.input("x")` returns `None` for the first and
`Some(Value::Null)` for the second. `request.input_str("x")` collapses
both to `None`, which matches the usual "absent means empty" reading.

### What your function returns

One `Outcome` (see `sdk/src/outcome.rs`): effects against the handler's
declared write slots, or one declared refusal. The serialized document is
exactly what the BREG shared outcome validator accepts:

- `{"effects": [{"id": "<slot>", "set": {<field>: <value>}}]}` with an
  optional `"clear": [<field>, ...]` for patch slots;
- `{"refusal": {"code": "<code>", "field": "<input id>"}}` with `field`
  optional.

The codes come from the refusal catalogue you declare in the project, and
the `field` must be a declared input id; the shared validator refuses the
outcome otherwise. A set value of `null` is also refused: use `clear` on an
optional patch field instead.

Do not confuse a business rejection with a failure. A declared refusal is a
normal outcome the registry records and audits. `HandlerFailure` (for
example, when the request violates the input contract the registry already
admitted) is a handler fault with a static message, not a business
decision; reaching it means the module and the project disagree about the
inputs.

## Run the fixtures

The template's host tests drive the generated exports directly (allocate,
handle, read the result window), so they run the same decision code the
module runs:

```sh
cargo test -p breg-wasm-handler-template
```

Fixtures live in `fixtures/normalize-phone-cases.json`: each case is the
request inputs and the exact outcome document expected. Add your cases
there (or point your crate at its own corpus); the admission proof reads
the same file, so one corpus serves both levels.

## Build the module

```sh
scripts/build.sh             # build, record sizes, enforce ceilings, run the proof
scripts/build.sh --preinit   # also produce the pre-initialized variant
scripts/build.sh --skip-proof
```

The build compiles the template for `wasm32-unknown-unknown` in the
`release-wasm` size profile (opt-level "z", LTO, one codegen unit, no
unwinding), writes the module to `artifacts/`, and records every produced
artifact's bytes, ceiling, verdict, and sha256 in
`artifacts/module-sizes.tsv`.

Module-size ceilings, enforced with a failing build:

- 2 MiB for an ordinary module. This is also the default execution ceiling
  a deployment runs with no operator configuration, so an ordinary module
  that fits here runs anywhere.
- 5 MiB for a pre-initialized library module (the `--preinit` variant).
  A module this size needs an operator who configures
  `wasmExecution.maxModuleBytes` accordingly; the default-budget runtime
  refuses it typed at execution while admission still accepts it, which the
  admission proof demonstrates.
- Above both sits the 5 MiB structural ceiling the compiler enforces at
  admission. Nothing over it compiles into a package at all.

(The ceiling-enforced size record is a product requirement recorded
2026-09-18: the build records the produced module's size as a build
artifact and fails over the configured ceiling, complementing
admission-time enforcement.)

## Package it into a BREG project

The registry project's action handler declares the module instead of a
script:

```json
"handler": {
  "kind": "wasm",
  "module": "wasm/handler.wasm",
  "abi": "registry.action-handler/v1",
  "refusals": [
    {"code": "invalid-phone", "label": "The phone number is not a valid phone number."},
    {"code": "invalid-region", "label": "The region is not a usable phone region."}
  ],
  "writes": [
    {"id": "phone", "target": {"entity": "person"}, "operation": "create", "fields": ["phone"]}
  ]
}
```

The `module` path is project-local, relative, ending in `.wasm`. The
declared input ids, write-slot ids, fields, and refusal codes must match
what the module reads and emits; the admission proof's project
(`admission/src/lib.rs`) is a complete working example. At compile time the
registry reads the module bytes, checks the ceilings, hashes them, and
validates the module against the platform guest ABI (zero imports, exactly
the `alloc`/`handle`/`result_ptr`/`result_len`/`memory` exports), so a
package either carries a module the runtime could run or the compiler
refuses it with a diagnostic naming the violation.

## What the SDK guarantees

- Exact values end to end: integers serialize as integers, decimal strings
  and reference envelopes pass through untouched, and absent versus null
  stays distinguishable on the request side.
- No pointer code in your crate: allocation, the handle boundary, and the
  result window are generated, and a panic in your handler never crosses
  the boundary uncaught.
- Exactly one JSON document per outcome, in the shape the shared validator
  accepts; the refusal builder cannot construct a document the validator
  would reject on shape.
- Zero imports: the generated module imports nothing (std only, no WASI),
  which is what module admission requires.

## What is out of scope

- Handler ABI v2 (`registry.action-handler/v2`, the Evidence resolver
  contract) is not authorable as WASM in this release; the SDK targets
  input-only v1 action handlers.
- Change-request planners stay Rhai-only; a WASM planner is refused at
  admission.
- Everything a handler cannot do by construction: no I/O, no clock, no
  randomness, no network, no threads. The module runs under fuel, epoch,
  memory, and stack budgets, inside the request's transaction.
