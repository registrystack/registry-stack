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
    version,
    about = "Run a governed-ingestion job: check, bounded pass, status, inspect, rescan.",
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
}

/// The command tree the binary parses.
#[must_use]
pub fn command() -> clap::Command {
    Cli::command()
}
