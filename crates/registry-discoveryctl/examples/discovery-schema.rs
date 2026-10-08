// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "schema")]
fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        eprintln!("usage: discovery-schema --output <directory>");
        return std::process::ExitCode::from(2);
    }
    let Some(output) = arguments.next().map(std::path::PathBuf::from) else {
        eprintln!("usage: discovery-schema --output <directory>");
        return std::process::ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("usage: discovery-schema --output <directory>");
        return std::process::ExitCode::from(2);
    }
    let documents = match registry_discoveryctl::schema::schema_documents() {
        Ok(documents) => documents,
        Err(error) => {
            eprintln!("Discovery schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if let Err(error) = std::fs::create_dir_all(&output) {
        eprintln!("Discovery schema generation failed: {error}");
        return std::process::ExitCode::FAILURE;
    }
    for (name, contents) in documents {
        if let Err(error) = std::fs::write(output.join(name), contents) {
            eprintln!("Discovery schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(feature = "schema"))]
fn main() -> std::process::ExitCode {
    eprintln!("discovery-schema requires the schema feature");
    std::process::ExitCode::from(2)
}
