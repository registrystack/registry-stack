// SPDX-License-Identifier: Apache-2.0
//! Write the generated JSON Schemas (task connection, identity facts, identity deployment):
//!
//! ```bash
//! cargo run -p registry-thunderid-tooling --features schema \
//!   --example tooling-schemas -- --output products/platform/schemas
//! ```

fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        eprintln!("usage: tooling-schemas --output <directory>");
        return std::process::ExitCode::from(2);
    }
    let Some(output) = arguments.next().map(std::path::PathBuf::from) else {
        eprintln!("usage: tooling-schemas --output <directory>");
        return std::process::ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("usage: tooling-schemas --output <directory>");
        return std::process::ExitCode::from(2);
    }
    let documents = match registry_thunderid_tooling::schema::schema_documents() {
        Ok(documents) => documents,
        Err(error) => {
            eprintln!("schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if let Err(error) = std::fs::create_dir_all(&output) {
        eprintln!("schema generation failed: {error}");
        return std::process::ExitCode::FAILURE;
    }
    for (name, contents) in documents {
        if let Err(error) = std::fs::write(output.join(name), contents) {
            eprintln!("schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    }
    std::process::ExitCode::SUCCESS
}
