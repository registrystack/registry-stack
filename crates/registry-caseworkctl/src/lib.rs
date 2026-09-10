// SPDX-License-Identifier: Apache-2.0

mod policy;
mod project;
mod source_add;

use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "caseworkctl",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Registry Casework project and local operator tooling"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a complete Casework authoring project in a new directory.
    Init(InitArgs),
    /// Connect an authored source through its owning public tooling.
    Source(SourceArgs),
    /// Validate authored inputs offline and print effective defaults.
    Check(ProjectArgs),
    /// Explain the running policy from validated local inputs.
    Explain(ProjectArgs),
    /// Evaluate a fixture using its controlled clock and source facts.
    Simulate(SimulateArgs),
    /// Package validated policy and exact imported descriptions for deployment.
    Package(PackageArgs),
    /// Run the project's bounded synthetic fixtures offline.
    Test(ProjectArgs),
    /// Check live database, issuer, source and directory readiness.
    Doctor(OperatorArgs),
    /// Manage Casework's own database.
    Db(DbArgs),
    /// Manage a retained local Casework process.
    Dev(DevArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// New directory for the authored Casework project.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// Project template: professional-review or standalone-decision.
    #[arg(long, value_name = "NAME")]
    template: String,
}

#[derive(Debug, Args)]
struct SourceArgs {
    #[command(subcommand)]
    command: SourceCommand,
}

#[derive(Debug, Subcommand)]
enum SourceCommand {
    /// Preview or apply one local BReg connection.
    Add(SourceAddArgs),
}

#[derive(Clone, Debug, Args)]
struct SourceAddArgs {
    /// Authored Base Registry Engine project.
    #[arg(value_name = "BREG_PROJECT")]
    registry: PathBuf,
    /// Authored Casework project.
    #[arg(long, value_name = "CASEWORK_PROJECT")]
    project: PathBuf,
    /// Stable Casework source identifier.
    #[arg(long)]
    source_id: String,
    /// Apply the exact reported local authoring changes.
    #[arg(long)]
    apply: bool,
    /// Public bregctl binary of the same Registry Stack version.
    #[arg(long, env = "BREGCTL_BIN", default_value = "bregctl")]
    bregctl_bin: PathBuf,
}

#[derive(Debug, Args)]
struct ProjectArgs {
    /// Authored Casework project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
}

#[derive(Debug, Args)]
struct SimulateArgs {
    /// Authored Casework project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// Synthetic fixture with source facts and a controlled clock.
    #[arg(long, value_name = "FILE")]
    fixture: PathBuf,
}

#[derive(Debug, Args)]
struct PackageArgs {
    /// Authored Casework project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// New directory for the verified policy package.
    #[arg(long, value_name = "DIRECTORY")]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct OperatorArgs {
    /// Authored Casework project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// Operator configuration file; defaults to operator.yaml in the project.
    #[arg(long, value_name = "FILE")]
    operator: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DbArgs {
    #[command(subcommand)]
    command: DbCommand,
}

#[derive(Debug, Subcommand)]
enum DbCommand {
    /// Apply Casework's embedded migrations with migration authority.
    Migrate(OperatorArgs),
}

#[derive(Debug, Args)]
struct DevArgs {
    #[command(subcommand)]
    command: DevCommand,
}

#[derive(Debug, Subcommand)]
enum DevCommand {
    /// Start a retained local Casework runtime.
    Start(OperatorArgs),
    /// Stop this project's retained local Casework runtime.
    Stop(ProjectArgs),
    /// Print the bounded retained runtime journal.
    Events(ProjectArgs),
}

pub fn main_entry() -> ExitCode {
    match run(Cli::parse()) {
        Ok(report) => {
            if serde_json::to_writer_pretty(std::io::stdout().lock(), &report).is_err() {
                return ExitCode::from(3);
            }
            println!();
            ExitCode::SUCCESS
        }
        Err(error) => {
            let report = json!({
                "ok": false,
                "diagnostics": [{"code": "caseworkctl.refused", "message": format!("{error:#}")}]
            });
            let _ = serde_json::to_writer_pretty(std::io::stderr().lock(), &report);
            eprintln!();
            ExitCode::from(1)
        }
    }
}

/// Command tree available to command-reference tooling.
#[must_use]
pub fn command() -> clap::Command {
    Cli::command()
}

fn run(cli: Cli) -> Result<Value> {
    match cli.command {
        Command::Init(args) => project::init(&args.project, &args.template),
        Command::Source(args) => match args.command {
            SourceCommand::Add(args) => source_add::run(&args),
        },
        Command::Check(args) => project::check(&args.project),
        Command::Explain(args) => project::explain(&args.project),
        Command::Package(args) => project::package(&args.project, &args.output),
        Command::Simulate(args) => project::simulate(&args.project, &args.fixture),
        Command::Test(args) => project::test(&args.project),
        Command::Doctor(args) => project::doctor(&args.project, args.operator.as_deref()),
        Command::Db(args) => match args.command {
            DbCommand::Migrate(args) => {
                project::db_migrate(&args.project, args.operator.as_deref())
            }
        },
        Command::Dev(args) => match args.command {
            DevCommand::Start(args) => project::dev_start(&args.project, args.operator.as_deref()),
            DevCommand::Stop(args) => project::dev_stop(&args.project),
            DevCommand::Events(args) => project::dev_events(&args.project),
        },
    }
    .context("casework command refused")
}
