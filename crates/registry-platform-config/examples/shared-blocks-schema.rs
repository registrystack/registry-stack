// SPDX-License-Identifier: Apache-2.0

//! Write the canonical JSON Schema of the shared runtime configuration blocks.
//!
//! The configuration conformance gate compares every runtime's generated
//! schema against this document, so a product that re-declares a shared block
//! instead of embedding it fails the gate.
//!
//! ```bash
//! cargo run -p registry-platform-config --features schema \
//!   --example shared-blocks-schema -- --output products/platform/generated
//! ```

fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let usage = || {
        eprintln!("usage: shared-blocks-schema --output <directory>");
        std::process::ExitCode::from(2)
    };
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        return usage();
    }
    let Some(output) = arguments.next().map(std::path::PathBuf::from) else {
        return usage();
    };
    if arguments.next().is_some() {
        return usage();
    }
    let rendered = match registry_platform_config::schema::shared_blocks_document() {
        Ok(rendered) => rendered,
        Err(error) => {
            eprintln!("shared blocks schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let written = std::fs::create_dir_all(&output).and_then(|()| {
        std::fs::write(
            output.join(registry_platform_config::schema::SHARED_BLOCKS_SCHEMA_FILE),
            rendered,
        )
    });
    if let Err(error) = written {
        eprintln!("shared blocks schema generation failed: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}
