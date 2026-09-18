// SPDX-License-Identifier: Apache-2.0

//! Footprint probe for the platform WASM executor behind the non-default
//! `wasm` feature.
//!
//! This example exists only to measure the binary, image, and dependency
//! footprint of the platform executor (`registry-platform-script`'s `wasm`
//! feature, pinned Wasmtime `=48.0.2`). It constructs the real executor for
//! both backends through the platform API and does nothing else: it is not
//! part of the `registry-breg` library, no request path, CLI command, or
//! runtime code links against it, and the `wasm` feature stays off in every
//! default build.
//!
//! The executor constructors below are pinned through a static of function
//! pointers so the linked binary retains the runtime they reach. The
//! measurement compares linked binaries; a binary the linker optimized the
//! runtime out of would measure nothing.

use registry_platform_script::wasm::{Backend, Budgets, Executor, InvokeError};

/// Executor construction for Cranelift lowering to host machine code.
fn native_executor() -> Result<Executor, InvokeError> {
    Executor::new(Backend::Native, Budgets::default())
}

/// Executor construction for Cranelift lowering to Pulley bytecode, run by
/// the interpreter; requires the runtime's `pulley` cargo feature.
fn pulley_executor() -> Result<Executor, InvokeError> {
    Executor::new(Backend::Pulley, Budgets::default())
}

#[used]
static WASM_EXECUTOR_PROTOTYPE_BUILDERS: [fn() -> Result<Executor, InvokeError>; 2] =
    [native_executor, pulley_executor];

fn main() {
    // Reading the static keeps the linker-retention trick intact while
    // giving this probe an entry point; the count itself is not the
    // measurement, the linked binary is.
    println!(
        "pinned {} wasm executor constructor(s) for footprint measurement",
        WASM_EXECUTOR_PROTOTYPE_BUILDERS.len()
    );
}
