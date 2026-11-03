// SPDX-License-Identifier: Apache-2.0

//! The operator command line of the governed-ingestion job, in the
//! crate's library so the published command reference reads the same
//! tree the binary runs (`registry-cli-docs`).

use clap::{Args, CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

/// The operator surface of the governed-ingestion job.
#[derive(Parser)]
#[command(
    name = "adapter-job",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Run a governed-ingestion job: initialize its store, check, bounded pass, status, inspect, rescan.",
    after_help = "Output is value-free by default. Pass --show-values to include the projected values a dry-run pass would hand off; status, inspect, and check never carry item values."
)]
pub struct Cli {
    /// Include the projected values a dry-run pass would deliver. The
    /// default omits every item value.
    #[arg(long, global = true)]
    pub show_values: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Optional workspace artifacts when they live separately from the pack.
#[derive(Args)]
pub struct WorkspaceArgs {
    /// The profile document; defaults to profile.yaml beside the pack.
    #[arg(long)]
    pub profile: Option<PathBuf>,
    /// The project document; defaults to project.yaml beside the pack.
    #[arg(long)]
    pub project: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize or migrate the job store without running a job.
    InitStore {
        /// The operator runtime config file, whose store block alone is
        /// resolved. Source and destination credentials are not activated.
        #[arg(long)]
        runtime: PathBuf,
    },
    /// Compile a job the way a pass would, with the value-free findings.
    Check {
        /// The job definition file.
        job_yaml: PathBuf,
        /// The pinned adapter pack file.
        #[arg(long)]
        pack: PathBuf,
        /// The operator runtime config file.
        #[arg(long)]
        runtime: PathBuf,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
    /// Run one bounded pass (the default, the shape a CronJob drives),
    /// or loop on the job's interval trigger.
    Pass {
        /// The job definition file.
        job_yaml: PathBuf,
        /// The pinned adapter pack file.
        #[arg(long)]
        pack: PathBuf,
        /// The operator runtime config file, whose store block names
        /// the job store's connection reference.
        #[arg(long)]
        runtime: PathBuf,
        #[command(flatten)]
        workspace: WorkspaceArgs,
        /// Hand off to the built-in fixture destination, which posts
        /// each deliverable to the receiver at --fixture-url. Loopback
        /// URLs only; a real destination is its own brief.
        #[arg(long, group = "handoff", requires = "fixture_url")]
        fixture: bool,
        /// The loopback URL of the fixture receiver.
        #[arg(long)]
        fixture_url: Option<String>,
        /// Run the pass against the preview destination, which delivers
        /// nothing, acknowledges nothing, and records what a real
        /// destination would have received. Nothing is written. Preview
        /// passes run once because they do not advance the stored schedule.
        #[arg(long, group = "handoff", conflicts_with = "loop")]
        dry_run: bool,
        /// Loop: sleep until the job's interval trigger is due, run the
        /// pass, and repeat, running a rescan pass when the source's
        /// declared delay says one is due. The default runs one pass.
        #[arg(long)]
        r#loop: bool,
        /// The consecutive item-scoped refusals with one code that stop
        /// a pass with the position unchanged.
        #[arg(long, default_value_t = crate::pass::DEFAULT_REFUSAL_LIMIT)]
        refusal_limit: u32,
    },
    /// Count what the item table holds: statuses, refusal codes, the
    /// schedule, and why the last pass stopped. Value-free.
    Status {
        /// The job definition file.
        job_yaml: PathBuf,
        /// The operator runtime config file, whose store block names
        /// the job store's connection reference.
        #[arg(long)]
        runtime: PathBuf,
    },
    /// Read one item's row: its statuses, sequence, and references.
    /// Value-free: the row holds no payload to print.
    Inspect {
        /// The job definition file.
        job_yaml: PathBuf,
        /// The operator runtime config file, whose store block names
        /// the job store's connection reference.
        #[arg(long)]
        runtime: PathBuf,
        /// The source item's key.
        #[arg(long)]
        key: String,
    },
    /// Mark a rescan due now, then run one rescan pass from the first
    /// page: unchanged items skip by digest, refused items retry.
    Rescan {
        /// The job definition file.
        job_yaml: PathBuf,
        /// The pinned adapter pack file.
        #[arg(long)]
        pack: PathBuf,
        /// The operator runtime config file, whose store block names
        /// the job store's connection reference.
        #[arg(long)]
        runtime: PathBuf,
        #[command(flatten)]
        workspace: WorkspaceArgs,
        /// Hand off to the built-in fixture destination at --fixture-url.
        #[arg(long, group = "handoff", requires = "fixture_url")]
        fixture: bool,
        /// The loopback URL of the fixture receiver.
        #[arg(long)]
        fixture_url: Option<String>,
        /// Run the pass against the preview destination; nothing is
        /// written.
        #[arg(long, group = "handoff")]
        dry_run: bool,
        /// The consecutive item-scoped refusals with one code that stop
        /// a pass with the position unchanged.
        #[arg(long, default_value_t = crate::pass::DEFAULT_REFUSAL_LIMIT)]
        refusal_limit: u32,
    },
    /// Accept an intended item-identity change (a new keyPointer or CSV
    /// option) after a pass stopped with identity-migration-required. Moves
    /// the stored identity to the job as authored now, keeps every item row,
    /// and prints an audit receipt; items the new identity reads as new are
    /// delivered again.
    RebindIdentity {
        /// The job definition file.
        job_yaml: PathBuf,
        /// The pinned adapter pack file.
        #[arg(long)]
        pack: PathBuf,
        /// The operator runtime config file, whose store block names
        /// the job store's connection reference.
        #[arg(long)]
        runtime: PathBuf,
        #[command(flatten)]
        workspace: WorkspaceArgs,
    },
}

/// The command tree the binary parses.
#[must_use]
pub fn command() -> clap::Command {
    Cli::command()
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser as _;

    #[test]
    fn the_version_is_the_display_version_the_ctl_tools_report() {
        assert_eq!(
            <Cli as clap::CommandFactory>::command().get_version(),
            Some(registry_platform_buildinfo::DISPLAY_VERSION)
        );
    }

    #[test]
    fn init_store_requires_an_explicit_runtime() {
        let error = match Cli::try_parse_from(["adapter-job", "init-store"]) {
            Ok(_) => panic!("initialization requires an explicit store runtime"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn rebind_identity_takes_the_job_pack_and_runtime_and_no_delivery_options() {
        let base = [
            "adapter-job",
            "rebind-identity",
            "job.yaml",
            "--pack",
            "pack.yaml",
            "--runtime",
            "runtime.yaml",
        ];
        assert!(Cli::try_parse_from(base).is_ok());
        assert!(
            Cli::try_parse_from(base.iter().copied().chain(["--dry-run"])).is_err(),
            "rebinding is never a preview"
        );
    }

    #[test]
    fn init_store_refuses_job_and_delivery_arguments() {
        for extra in [
            vec!["job.yaml"],
            vec!["--pack", "pack.yaml"],
            vec!["--dry-run"],
            vec![
                "--fixture",
                "--fixture-url",
                "http://127.0.0.1:9000/deliver",
            ],
        ] {
            let mut arguments = vec!["adapter-job", "init-store", "--runtime", "runtime.yaml"];
            arguments.extend(extra);
            assert!(
                Cli::try_parse_from(arguments).is_err(),
                "store initialization accepts no job or delivery options"
            );
        }
    }
}
