//! Generate the deterministic Evidence authoring-form JSON Schemas.
//!
//! The library holds the schemas as text and never touches a file, which is the
//! crate's own invariant. Writing them is this example's whole job, so the
//! committed artifact has exactly one producer and the drift gate can rerun it.

use std::{env, fs, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("authoring schema generation failed: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        return Err("usage: authoring-schema --output <directory>".to_string());
    }
    let output = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "usage: authoring-schema --output <directory>".to_string())?;
    if arguments.next().is_some() {
        return Err("usage: authoring-schema --output <directory>".to_string());
    }

    let documents = registry_evidence_authoring::schema::documents().map_err(|error| {
        format!("the authoring form could not be described as JSON Schema: {error}")
    })?;
    fs::create_dir_all(&output)
        .map_err(|error| format!("failed to create {}: {error}", output.display()))?;
    for (name, contents) in documents {
        let path = output.join(name);
        fs::write(&path, contents)
            .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    }
    Ok(())
}
