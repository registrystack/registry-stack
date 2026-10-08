// SPDX-License-Identifier: Apache-2.0

//! Writes the gateway runtime configuration JSON Schema into `--output`.

#[cfg(feature = "schema")]
fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        eprintln!("usage: mcp-runtime-schema --output <directory>");
        return std::process::ExitCode::from(2);
    }
    let Some(output) = arguments.next().map(std::path::PathBuf::from) else {
        eprintln!("usage: mcp-runtime-schema --output <directory>");
        return std::process::ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("usage: mcp-runtime-schema --output <directory>");
        return std::process::ExitCode::from(2);
    }
    let documents = match registry_breg_mcp::schema::schema_documents() {
        Ok(documents) => documents,
        Err(error) => {
            eprintln!("MCP runtime schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if let Err(error) = std::fs::create_dir_all(&output) {
        eprintln!("MCP runtime schema generation failed: {error}");
        return std::process::ExitCode::FAILURE;
    }
    for (name, contents) in documents {
        if let Err(error) = std::fs::write(output.join(name), contents) {
            eprintln!("MCP runtime schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(feature = "schema"))]
fn main() -> std::process::ExitCode {
    eprintln!("mcp-runtime-schema requires the schema feature");
    std::process::ExitCode::from(2)
}
