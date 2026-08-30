// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "schema")]
use std::{env, fs, path::PathBuf, process::ExitCode};

#[cfg(feature = "schema")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("authoring schema generation failed: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "schema")]
fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        return Err("usage: authoring-schema --output <directory>".to_owned());
    }
    let output = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "usage: authoring-schema --output <directory>".to_owned())?;
    if arguments.next().is_some() {
        return Err("usage: authoring-schema --output <directory>".to_owned());
    }

    let documents = registry_server::schema::documents()
        .map_err(|error| format!("the authoring schema could not be generated: {error}"))?;
    fs::create_dir_all(&output)
        .map_err(|error| format!("failed to create {}: {error}", output.display()))?;
    for (name, contents) in documents {
        let path = output.join(name);
        fs::write(&path, contents)
            .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    }
    Ok(())
}

#[cfg(not(feature = "schema"))]
fn main() -> std::process::ExitCode {
    eprintln!("authoring-schema requires the registry-server schema feature");
    std::process::ExitCode::from(2)
}
