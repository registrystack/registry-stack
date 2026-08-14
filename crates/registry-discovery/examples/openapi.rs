// SPDX-License-Identifier: Apache-2.0
//! Regenerate or check the committed Discovery OpenAPI document.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use registry_discovery::openapi::{generated_bytes, OPENAPI_BYTES};

fn main() -> ExitCode {
    let mut arguments = env::args().skip(1);
    let mode = arguments.next();
    if arguments.next().is_some() {
        return usage();
    }
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("openapi.json");
    let generated = match generated_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to serialize the Discovery OpenAPI contract: {error}");
            return ExitCode::FAILURE;
        }
    };
    match mode.as_deref() {
        Some("--check") => {
            if generated == OPENAPI_BYTES {
                println!("Discovery OpenAPI is current: {}", path.display());
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "Discovery OpenAPI drifted: run `cargo run --locked -p registry-discovery --example openapi -- --write`"
                );
                ExitCode::FAILURE
            }
        }
        Some("--write") => match fs::write(&path, generated) {
            Ok(()) => {
                println!("wrote {}", path.display());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("failed to write {}: {error}", path.display());
                ExitCode::FAILURE
            }
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: openapi (--check|--write)");
    ExitCode::FAILURE
}
