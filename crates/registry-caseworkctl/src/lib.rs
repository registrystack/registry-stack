// SPDX-License-Identifier: Apache-2.0

mod policy;
mod project;
mod source_add;

use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_casework_core::{AttemptSettlement, AttemptSettlementOutcome};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::ExitCode;
use uuid::Uuid;

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
    /// Preview or erase retained local payload copies for one source request.
    Retention(RetentionArgs),
    /// Preview or record an operator settlement of one uncertain source attempt.
    Attempt(AttemptArgs),
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
    /// Preview or apply one local Base Registry Engine (BReg) connection.
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
struct RetentionArgs {
    #[command(subcommand)]
    command: RetentionCommand,
}

#[derive(Debug, Subcommand)]
enum RetentionCommand {
    /// Preview or erase retained local payload copies for one exact source request.
    Erase(RetentionEraseArgs),
}

#[derive(Debug, Args)]
struct RetentionEraseArgs {
    #[command(flatten)]
    operator: OperatorArgs,
    /// Stable Casework source identifier.
    #[arg(long)]
    source_id: String,
    /// Source-owned request kind.
    #[arg(long)]
    request_kind: String,
    /// Source-owned request identifier.
    #[arg(long)]
    request_id: String,
    /// Apply the reviewed local erasure. Omit to preview.
    #[arg(long)]
    apply: bool,
}

#[derive(Debug, Args)]
struct AttemptArgs {
    #[command(subcommand)]
    command: AttemptCommand,
}

#[derive(Debug, Subcommand)]
enum AttemptCommand {
    /// Preview or record an operator settlement of one uncertain source attempt.
    ///
    /// Only an uncertain attempt whose execution lease has expired can be
    /// settled. Apply changes the attempt and its work item and records the
    /// decision in the work item's history in one transaction.
    Settle(AttemptSettleArgs),
}

#[derive(Debug, Args)]
struct AttemptSettleArgs {
    #[command(flatten)]
    operator: OperatorArgs,
    /// Uncertain source attempt to settle.
    #[arg(long, value_name = "UUID")]
    attempt_id: Uuid,
    /// What the source owner confirmed about the attempt.
    #[arg(long, value_enum)]
    outcome: SettleOutcome,
    /// Why the attempt is settled this way; recorded in the work item's history.
    #[arg(long)]
    reason: String,
    /// Who made the decision; recorded in the work item's history.
    #[arg(long)]
    decided_by: String,
    /// Apply the reviewed settlement. Omit to preview.
    #[arg(long)]
    apply: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SettleOutcome {
    /// The source applied the attempt; the work item awaits its next source observation.
    Applied,
    /// The source did not apply the attempt; the work item returns to its holder.
    NotApplied,
}

impl From<SettleOutcome> for AttemptSettlementOutcome {
    fn from(outcome: SettleOutcome) -> Self {
        match outcome {
            SettleOutcome::Applied => Self::Applied,
            SettleOutcome::NotApplied => Self::NotApplied,
        }
    }
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
        Command::Retention(args) => match args.command {
            RetentionCommand::Erase(args) => project::retention_erase(
                &args.operator.project,
                args.operator.operator.as_deref(),
                args.source_id,
                args.request_kind,
                args.request_id,
                args.apply,
            ),
        },
        Command::Attempt(args) => match args.command {
            AttemptCommand::Settle(args) => project::attempt_settle(
                &args.operator.project,
                args.operator.operator.as_deref(),
                AttemptSettlement {
                    attempt_id: args.attempt_id,
                    outcome: args.outcome.into(),
                    reason: args.reason,
                    decided_by: args.decided_by,
                },
                args.apply,
            ),
        },
        Command::Dev(args) => match args.command {
            DevCommand::Start(args) => project::dev_start(&args.project, args.operator.as_deref()),
            DevCommand::Stop(args) => project::dev_stop(&args.project),
            DevCommand::Events(args) => project::dev_events(&args.project),
        },
    }
    .context("casework command refused")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_erase_previews_unless_apply_is_explicit() {
        let parse = |extra: &[&str]| {
            let mut arguments = vec![
                "caseworkctl",
                "retention",
                "erase",
                "/tmp/casework-project",
                "--source-id",
                "registry",
                "--request-kind",
                "correction",
                "--request-id",
                "request-1",
            ];
            arguments.extend_from_slice(extra);
            Cli::try_parse_from(arguments).unwrap()
        };

        let Command::Retention(RetentionArgs {
            command: RetentionCommand::Erase(preview),
        }) = parse(&[]).command
        else {
            panic!("expected retention erase");
        };
        assert!(!preview.apply);

        let Command::Retention(RetentionArgs {
            command: RetentionCommand::Erase(apply),
        }) = parse(&["--apply"]).command
        else {
            panic!("expected retention erase");
        };
        assert!(apply.apply);
    }

    const ATTEMPT_ID: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

    fn attempt_settle_arguments() -> Vec<&'static str> {
        vec![
            "caseworkctl",
            "attempt",
            "settle",
            "/tmp/casework-project",
            "--attempt-id",
            ATTEMPT_ID,
            "--outcome",
            "not-applied",
            "--reason",
            "The source refused the saved evidence version.",
            "--decided-by",
            "Registrar duty officer",
        ]
    }

    fn replace_argument(
        mut arguments: Vec<&'static str>,
        flag: &str,
        value: &'static str,
    ) -> Vec<&'static str> {
        let position = arguments.iter().position(|value| *value == flag).unwrap();
        arguments[position + 1] = value;
        arguments
    }

    fn parse_attempt_settle(arguments: Vec<&str>) -> AttemptSettleArgs {
        let Command::Attempt(AttemptArgs {
            command: AttemptCommand::Settle(args),
        }) = Cli::try_parse_from(arguments).unwrap().command
        else {
            panic!("expected attempt settle");
        };
        args
    }

    #[test]
    fn attempt_settle_previews_unless_apply_is_explicit() {
        let preview = parse_attempt_settle(attempt_settle_arguments());
        assert!(!preview.apply);
        assert_eq!(preview.attempt_id.to_string(), ATTEMPT_ID);
        assert_eq!(preview.outcome, SettleOutcome::NotApplied);
        assert_eq!(
            preview.reason,
            "The source refused the saved evidence version."
        );
        assert_eq!(preview.decided_by, "Registrar duty officer");
        assert_eq!(
            preview.operator.project,
            PathBuf::from("/tmp/casework-project")
        );
        assert_eq!(preview.operator.operator, None);

        let mut arguments = replace_argument(attempt_settle_arguments(), "--outcome", "applied");
        arguments.push("--apply");
        let apply = parse_attempt_settle(arguments);
        assert!(apply.apply);
        assert_eq!(apply.outcome, SettleOutcome::Applied);
    }

    #[test]
    fn attempt_settle_requires_every_decision_argument() {
        for flag in ["--attempt-id", "--outcome", "--reason", "--decided-by"] {
            let mut arguments = attempt_settle_arguments();
            let position = arguments.iter().position(|value| *value == flag).unwrap();
            arguments.drain(position..=position + 1);
            let error = Cli::try_parse_from(arguments).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "{flag} must be required"
            );
        }
    }

    #[test]
    fn attempt_settle_refuses_unknown_outcomes_and_malformed_attempt_ids() {
        let unknown_outcome =
            replace_argument(attempt_settle_arguments(), "--outcome", "uncertain");
        assert_eq!(
            Cli::try_parse_from(unknown_outcome).unwrap_err().kind(),
            clap::error::ErrorKind::InvalidValue
        );
        let malformed_id =
            replace_argument(attempt_settle_arguments(), "--attempt-id", "attempt-1");
        assert_eq!(
            Cli::try_parse_from(malformed_id).unwrap_err().kind(),
            clap::error::ErrorKind::ValueValidation
        );
    }

    #[test]
    fn attempt_settle_help_explains_outcomes_and_explicit_apply() {
        let error =
            Cli::try_parse_from(["caseworkctl", "attempt", "settle", "--help"]).unwrap_err();
        let help = error.to_string();
        for expected in [
            "--attempt-id",
            "--outcome",
            "applied",
            "not-applied",
            "--reason",
            "--decided-by",
            "--apply",
            "Omit to preview",
            "lease has expired",
        ] {
            assert!(help.contains(expected), "missing help text: {expected}");
        }
    }

    #[test]
    fn retention_erase_help_explains_exact_selection_and_explicit_apply() {
        let error =
            Cli::try_parse_from(["caseworkctl", "retention", "erase", "--help"]).unwrap_err();
        let help = error.to_string();
        for expected in [
            "--source-id",
            "--request-kind",
            "--request-id",
            "--apply",
            "Omit to preview",
        ] {
            assert!(help.contains(expected), "missing help text: {expected}");
        }
    }
}
