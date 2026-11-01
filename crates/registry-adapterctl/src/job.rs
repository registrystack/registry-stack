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

    /// The operator runtime config; defaults to `job-runtime.yaml` beside
    /// the pack.
    #[arg(long, value_name = "FILE")]
    pub runtime: Option<PathBuf>,
    /// The facade profile the workspace checks run over; defaults to
    /// `profile.yaml` beside the pack.
    #[arg(long, value_name = "FILE", requires = "project")]
    pub profile: Option<PathBuf>,
    /// The project whose workspace checks the runtime stands on;
    /// defaults to `project.yaml` beside the pack.
    #[arg(long, value_name = "FILE", requires = "profile")]
    pub project: Option<PathBuf>,

    /// Exit 1 when a warning is reported.
    #[arg(long)]
    pub deny_warnings: bool,
}

/// One completed job check: the artifacts as written.
pub(crate) struct JobCheckRun {
    pub(crate) pack: String,
    pub(crate) job: String,
    pub(crate) runtime: String,
    pub(crate) files_checked: usize,
    /// The reader's warnings over the authored artifacts.
    pub(crate) warnings: Vec<registry_platform_yaml::Diagnostic>,
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
/// pack, the job, the runtime config, and the profile and project the
/// compile reads (beside the pack unless passed). The scripts and query
/// files the pack inventories are the compile's own accounting.
fn files_checked() -> usize {
    5
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
        None => pack_directory.join("job-runtime.yaml"),
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
        // The parser requires the two together; a caller that builds the
        // arguments by hand still gets a refusal, never a guess.
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
        Ok(program) => Ok(JobCheckRun {
            pack: args.pack.display().to_string(),
            job: args.job.display().to_string(),
            runtime: runtime.display().to_string(),
            files_checked: files_checked(),
            warnings: program.warnings,
        }),
        Err(error) => Err(JobCheckFailure::Refused {
            diagnostics: error.diagnostics,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct Harness {
        #[command(flatten)]
        args: JobCheckArgs,
    }

    fn parse(extra: &[&str]) -> Result<Harness, clap::Error> {
        let mut argv = vec!["job-check", "pack.yaml", "job.yaml"];
        argv.extend_from_slice(extra);
        Harness::try_parse_from(argv)
    }

    /// The profile and the project stand together: one without the other
    /// is a usage error at the parser, never a missing-file failure.
    #[test]
    fn the_profile_and_the_project_are_passed_together() {
        assert!(parse(&[]).is_ok(), "neither reads both beside the pack");
        assert!(parse(&["--profile", "p.yaml", "--project", "q.yaml"]).is_ok());
        let alone = parse(&["--profile", "p.yaml"]).expect_err("a profile alone refuses");
        assert_eq!(
            alone.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        let alone = parse(&["--project", "q.yaml"]).expect_err("a project alone refuses");
        assert_eq!(
            alone.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    /// The report counts every file the check opened: the pack, the job,
    /// the runtime config, the profile, and the project.
    #[test]
    fn the_report_counts_the_five_files_the_check_opens() {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/fixtures/corpus/base-job");
        let args = JobCheckArgs {
            pack: base.join("pack.yaml"),
            job: base.join("job.yaml"),
            runtime: Some(base.join("job-runtime.yaml")),
            profile: Some(base.join("profile.yaml")),
            project: Some(base.join("project.yaml")),
            deny_warnings: false,
        };
        let run = match run(&args) {
            Ok(run) => run,
            Err(JobCheckFailure::Io { path, source }) => panic!("{path}: {source}"),
            Err(JobCheckFailure::Refused { diagnostics }) => panic!("{diagnostics:?}"),
        };
        assert_eq!(run.files_checked, 5);
    }
}
