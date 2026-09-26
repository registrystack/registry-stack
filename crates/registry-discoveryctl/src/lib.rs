// SPDX-License-Identifier: Apache-2.0
//! Finite Registry Discovery authoring and immutable index packages.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod build;
mod project;

pub use build::{package_project, package_project_at, BuildError, PackagedDiscovery};
pub use project::{
    check_project, ApprovedOrigin, AuthoredEvidenceMapping, AuthoredEvidenceTypeAlternative,
    CheckedProject, OriginsFile, ProjectError, MAPPING_SCHEMA, MAX_MAPPING_FILE_BYTES,
    ORIGINS_SCHEMA,
};

#[derive(Debug, Parser)]
#[command(
    name = "discoveryctl",
    about = "Check and package one immutable Registry Discovery index",
    version = registry_platform_buildinfo::DISPLAY_VERSION
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate an authoring project without network I/O.
    Check {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        allow_loopback: bool,
    },
    /// Fetch every enabled approved origin once and write one immutable package.
    Package {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        allow_loopback: bool,
        /// Optional operator revision recorded in the package envelope.
        #[arg(long)]
        revision: Option<String>,
    },
    /// Removed. Use `discoveryctl package`.
    #[command(hide = true, trailing_var_arg = true)]
    Build {
        #[arg(allow_hyphen_values = true)]
        _legacy_arguments: Vec<OsString>,
    },
}

const RETIRED_BUILD_ERROR: &str =
    "discoveryctl build was removed; use discoveryctl package with a new output directory";

#[must_use]
pub fn main_entry() -> ExitCode {
    let arguments = Arguments::parse();
    match run(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn run(arguments: Arguments) -> Result<(), String> {
    match arguments.command {
        Command::Check {
            project,
            allow_loopback,
        } => check_project(&project, allow_loopback)
            .map(|checked| {
                println!(
                    "valid origins={} mappings={}",
                    checked.origins.len(),
                    checked.mappings.len()
                );
            })
            .map_err(|error| error.to_string()),
        Command::Package {
            project,
            output,
            allow_loopback,
            revision,
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "the Discovery package runtime could not start".to_owned())
            .and_then(|runtime| {
                runtime
                    .block_on(package_project(
                        &project,
                        &output,
                        allow_loopback,
                        revision.as_deref(),
                    ))
                    .map(|package| {
                        println!(
                            "packaged packageDigest={} catalogRevision={} mappingRevision={}",
                            package.package_digest,
                            package.index.catalog_revision,
                            package.index.mapping_revision
                        );
                    })
                    .map_err(|error| error.to_string())
            }),
        Command::Build { .. } => Err(RETIRED_BUILD_ERROR.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_build_refusal_names_discoveryctl_package() {
        let arguments = Arguments::try_parse_from([
            "discoveryctl",
            "build",
            "--project",
            "project",
            "--output",
            "discovery-index.json",
        ])
        .expect("the retired command reaches its migration refusal");
        let message = run(arguments).unwrap_err();
        assert!(message.contains("discoveryctl package"), "{message}");

        assert!(Arguments::try_parse_from([
            "discoveryctl",
            "package",
            "--project",
            "project",
            "--output",
            "package",
        ])
        .is_ok());
    }
}
