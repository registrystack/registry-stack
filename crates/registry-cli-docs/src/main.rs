// SPDX-License-Identifier: Apache-2.0
//! Regenerate the committed CLI catalog snapshot the docs site renders.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    if arguments.next().as_deref() != Some("--write") || arguments.next().is_some() {
        eprintln!("usage: registry-cli-docs --write");
        return ExitCode::FAILURE;
    }
    let path = registry_cli_docs::snapshot_path();
    let snapshot = match registry_cli_docs::catalog_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("failed to serialize the CLI catalog: {error}");
            return ExitCode::FAILURE;
        }
    };
    match std::fs::write(&path, snapshot) {
        Ok(()) => {
            println!("wrote {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to write {}: {error}", path.display());
            ExitCode::FAILURE
        }
    }
}
