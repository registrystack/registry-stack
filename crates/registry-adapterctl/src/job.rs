// SPDX-License-Identifier: Apache-2.0

//! `adapterctl job check`: the offline validation of one ingestion job
//! over the same compile the page run uses
//! (`products/adapter/CONCEPT.md` sections 17.1 and 17.2).
//!
//! The command compiles the job exactly as the engine's page entry
//! would: the pinned pack, the `AdapterJob` definition, the operator
//! runtime config through the shared loader, the authoring checks the
//! runtime stands on, the source endpoints, the scripts and routes the
//! source route reaches. It is validation only: no listener, no
//! database, no OIDC issuer, no send, no read. A refusal carries its
//! closed code, the same diagnostics a page run's compile raises.

use clap::{Args, Subcommand};
use std::path::PathBuf;

/// The `job` command group.
#[derive(Debug, Args)]
pub struct JobArgs {
    #[command(subcommand)]
    pub command: JobCommand,
}

/// The subcommands of `job`.
#[derive(Debug, Subcommand)]
pub enum JobCommand {
    /// Compile one ingestion job offline, exactly as the page run
    /// would, and print the findings.
    Check(JobCheckArgs),
}

/// The arguments of `job check`.
#[derive(Debug, Args)]
pub struct JobCheckArgs {
    /// The pack document the job pins.
    #[arg(value_name = "PACK")]
    pub pack: PathBuf,

    /// The job definition.
    #[arg(value_name = "JOB")]
    pub job: PathBuf,

    /// The operator runtime config; defaults to `runtime.yaml` beside
    /// the pack.
    #[arg(long, value_name = "FILE")]
    pub runtime: Option<PathBuf>,
    /// The facade profile the workspace checks run over; defaults to
    /// `profile.yaml` beside the pack.
    #[arg(long, value_name = "FILE")]
    pub profile: Option<PathBuf>,
    /// The project whose workspace checks the runtime stands on;
    /// defaults to `project.yaml` beside the pack.
    #[arg(long, value_name = "FILE")]
    pub project: Option<PathBuf>,
}

/// One completed job check: the artifacts as written.
pub(crate) struct JobCheckRun {
    pub(crate) pack: String,
    pub(crate) job: String,
    pub(crate) runtime: String,
    pub(crate) files_checked: usize,
}

/// Why the job check could not run to a verdict.
#[derive(Debug)]
pub(crate) enum JobCheckFailure {
    /// A required file could not be read: the environment is broken,
    /// not the authoring.
    Io {
        path: String,
        source: std::io::Error,
    },
    /// The compile refused the job: the diagnostics carry their closed
    /// codes.
    Refused {
        diagnostics: Vec<registry_platform_yaml::Diagnostic>,
    },
}

/// Count the artifacts the check itself opened, for the report: the
/// pack, the runtime config, and the profile and project the compile
/// reads beside the pack. The scripts and query files the pack
/// inventories are the compile's own accounting.
fn files_checked() -> usize {
    4
}

/// Run the job check: compile the job offline, or refuse with the
/// compile's own diagnostics.
pub(crate) fn run(args: &JobCheckArgs) -> Result<JobCheckRun, JobCheckFailure> {
    let pack_directory = args
        .pack
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_default();
    let runtime = match &args.runtime {
        Some(runtime) => runtime.clone(),
        None => pack_directory.join("runtime.yaml"),
    };
    if !runtime.is_file() {
        return Err(JobCheckFailure::Io {
            path: runtime.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no runtime config was given and none sits beside the pack",
            ),
        });
    }
    let outcome = match (&args.profile, &args.project) {
        (Some(profile), Some(project)) => registry_adapter::engine::job::compile_job_with(
            &args.pack, &args.job, &runtime, profile, project,
        ),
        (None, None) => registry_adapter::engine::job::compile_job(&args.pack, &args.job, &runtime),
        _ => {
            return Err(JobCheckFailure::Io {
                path: "--profile --project".to_owned(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "--profile and --project stand together; pass both or neither",
                ),
            })
        }
    };
    match outcome {
        Ok(_program) => Ok(JobCheckRun {
            pack: args.pack.display().to_string(),
            job: args.job.display().to_string(),
            runtime: runtime.display().to_string(),
            files_checked: files_checked(),
        }),
        Err(error) => Err(JobCheckFailure::Refused {
            diagnostics: error.diagnostics,
        }),
    }
}
