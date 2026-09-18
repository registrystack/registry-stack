// SPDX-License-Identifier: Apache-2.0
//! Build-time pre-initializer for BREG WASM handler modules: runs the
//! module's `init` export (the handler's warm-up) under wasmtime-wizer and
//! rewrites the module with the initialized memory snapshotted into data
//! segments. Every later instantiation, including the platform executor's
//! fresh store-per-call instances, then starts with warm statics.
//!
//! Used by `scripts/build.sh --preinit` only; the registry never runs it.

use std::process::ExitCode;

use wasmtime::{Config, Engine, Instance, Store};
use wasmtime_wizer::Wizer;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (Some(input_path), Some(output_path), None) = (args.next(), args.next(), args.next())
    else {
        eprintln!("usage: breg-wasm-preinit <input.wasm> <output.wasm>");
        return ExitCode::from(2);
    };
    match run(&input_path, &output_path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Authoring-time tool: the operator sees the full error chain.
            eprintln!("preinit failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(
    input_path: &std::ffi::OsStr,
    output_path: &std::ffi::OsStr,
) -> Result<(), Box<dyn std::error::Error>> {
    let wasm = std::fs::read(input_path)?;
    let engine = Engine::new(&Config::new())?;
    let mut store = Store::new(&engine, ());
    // The default feature set of the wasmtime config governs the rewrite; a
    // BREG handler module imports nothing, so instantiation links nothing.
    let rewritten = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            Wizer::new()
                .init_func("init")
                .run(&mut store, &wasm, async |store, module| {
                    Instance::new(store, module, &[])
                })
                .await
        })?;
    std::fs::write(output_path, &rewritten)?;
    println!(
        "preinit: {} -> {} bytes (+{})",
        wasm.len(),
        rewritten.len(),
        rewritten.len().saturating_sub(wasm.len())
    );
    Ok(())
}
