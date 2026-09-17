// SPDX-License-Identifier: Apache-2.0

//! Footprint probe for the pinned WASM runtime behind the non-default
//! `wasm-executor-prototype` feature.
//!
//! This module exists only to measure the binary, image, and dependency
//! footprint of the pinned Wasmtime release (`=48.0.2`, Phase 1 of the
//! platform script and BREG WASM plan). It builds the deterministic engine
//! configuration the prototype executor uses and exposes nothing: the module
//! is crate-private, no request path, CLI command, or runtime code calls it,
//! and the feature stays off in every default build.
//!
//! The engine builders below are pinned through a static of function pointers
//! so the linked binary retains the runtime they reach. The measurement
//! compares linked binaries; a binary the linker optimized the runtime out of
//! would measure nothing.

use wasmtime::{Config, Engine};

/// Per-call wasm stack budget of the prototype configuration: wasmtime's
/// documented 512 KiB default, recorded explicitly because stack overflow
/// traps identically across backends under it.
const PROTOTYPE_MAX_WASM_STACK_BYTES: usize = 512 * 1024;

/// The deterministic engine configuration shared by both backends: threads,
/// relaxed SIMD, and memory64 off (threads defaults to on, so its call is
/// load-bearing), NaN canonicalization on, and fuel plus epoch interruption
/// armed.
fn prototype_config() -> Config {
    let mut config = Config::new();
    config.wasm_threads(false);
    config.wasm_relaxed_simd(false);
    config.wasm_memory64(false);
    config.cranelift_nan_canonicalization(true);
    config.max_wasm_stack(PROTOTYPE_MAX_WASM_STACK_BYTES);
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config
}

/// Engine construction for Cranelift lowering to host machine code.
fn native_engine() -> wasmtime::Result<Engine> {
    Engine::new(&prototype_config())
}

/// Engine construction for Cranelift lowering to Pulley bytecode, run by the
/// interpreter; requires the runtime's `pulley` cargo feature.
fn pulley_engine() -> wasmtime::Result<Engine> {
    let mut config = prototype_config();
    config.target("pulley64")?;
    Engine::new(&config)
}

#[allow(dead_code)]
#[used]
static WASM_EXECUTOR_PROTOTYPE_ENGINE_BUILDERS: [fn() -> wasmtime::Result<Engine>; 2] =
    [native_engine, pulley_engine];
