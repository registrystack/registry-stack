// SPDX-License-Identifier: Apache-2.0
//! Finite Registry Discovery authoring and immutable index builds.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod build;
mod project;

pub use build::{build_project, build_project_at, BuildError};
pub use project::{
    check_project, ApprovedOrigin, AuthoredEvidenceMapping, AuthoredEvidenceTypeAlternative,
    CheckedProject, OriginsFile, ProjectError, MAPPING_SCHEMA, ORIGINS_SCHEMA,
};

#[derive(Debug, Parser)]
#[command(
    name = "discoveryctl",
    about = "Check and build one immutable Registry Discovery index",
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
    /// Fetch every enabled approved origin once and atomically build one index.
    Build {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        allow_loopback: bool,
    },
}

#[must_use]
pub fn main_entry() -> ExitCode {
    let arguments = Arguments::parse();
    let result = match arguments.command {
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
        Command::Build {
            project,
            output,
            allow_loopback,
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "the Discovery build runtime could not start".to_owned())
            .and_then(|runtime| {
                runtime
                    .block_on(build_project(&project, &output, allow_loopback))
                    .map(|index| {
                        println!(
                            "built catalogRevision={} mappingRevision={}",
                            index.catalog_revision, index.mapping_revision
                        );
                    })
                    .map_err(|error| error.to_string())
            }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}
