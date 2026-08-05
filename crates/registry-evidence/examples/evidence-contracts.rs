//! Generate deterministic Evidence Version 1 public contract artifacts.

use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("evidence contract generation failed: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        return Err("usage: evidence-contracts --output <directory>".to_string());
    }
    let output = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "usage: evidence-contracts --output <directory>".to_string())?;
    if arguments.next().is_some() {
        return Err("usage: evidence-contracts --output <directory>".to_string());
    }
    registry_evidence::contracts::write_documents(&output).map_err(|error| error.to_string())
}
