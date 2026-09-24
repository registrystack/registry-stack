// SPDX-License-Identifier: Apache-2.0

mod dev;
mod display_schema;
mod lifecycle;
mod policy;
mod project;
mod source_add;

use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_casework::{AttemptSettlementError, RuntimeConfigError, StoreError};
use registry_casework_core::{
    AttemptSettlement, AttemptSettlementOutcome, AttemptUncertainMarking, ConfigError,
    ConfigLoadError,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::ffi::{OsStr, OsString};
use std::io;
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
    /// Emit the selected command's report in this format.
    #[arg(long, value_enum, global = true, default_value_t)]
    format: OutputFormat,

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
    Check(CheckArgs),
    /// Explain the running policy from validated local inputs.
    Explain(ProjectArgs),
    /// Report the occurrence and review state machines the runtime enforces.
    Lifecycle,
    /// Evaluate a fixture using its controlled clock and source facts.
    Simulate(SimulateArgs),
    /// Package validated policy and exact imported descriptions for deployment.
    Package(PackageArgs),
    /// Run the project's bounded synthetic fixtures offline.
    Test(ProjectArgs),
    /// Check live database, issuer, source and directory readiness.
    Doctor(DoctorArgs),
    /// Manage Casework's own database.
    Db(DbArgs),
    /// Preview or erase retained local payload copies for one source request.
    Retention(RetentionArgs),
    /// Preview or record an operator decision about one source attempt whose lease has expired.
    Attempt(AttemptArgs),
    /// Start, stop and inspect this project's retained local Casework runtime.
    Dev(Box<dev::DevArgs>),
    /// Supervise one project's owned local services. Not for direct use.
    #[command(name = "__dev-supervisor", hide = true)]
    DevSupervisor(dev::SupervisorArgs),
    /// Own one native service until it exits or its supervisor is lost.
    #[command(name = "__dev-service-guard", hide = true)]
    DevServiceGuard(dev::ServiceGuardArgs),
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
struct CheckArgs {
    /// Authored Casework project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// Require every declared source import and all deployment policy inputs.
    #[arg(long)]
    production: bool,
    /// Exit unsuccessfully when the authoring check reports any finding.
    #[arg(long)]
    deny_findings: bool,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Absolute runtime configuration selecting the package and startup bindings.
    #[arg(long, value_name = "FILE")]
    runtime_config: PathBuf,
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
    /// New directory for the verified policy package. Required unless --dry-run.
    #[arg(long, value_name = "DIRECTORY", required_unless_present = "dry_run")]
    output: Option<PathBuf>,
    /// Report the same policyDigest and files a package would produce, without writing one.
    #[arg(long, conflicts_with = "output", required_unless_present = "output")]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct OperatorArgs {
    /// Authored Casework project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// Runtime configuration file; defaults to runtime.yaml in the project.
    #[arg(long, value_name = "FILE")]
    runtime_config: Option<PathBuf>,
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
    /// Preview or record an operator marking of one pending source attempt as uncertain.
    ///
    /// Only a pending attempt whose execution lease has expired can be marked,
    /// for an attempt the actor who started it cannot recover. The command
    /// connects with the migration database credential. Apply changes the
    /// attempt and its work item and records the decision, naming the decider
    /// and the attempt's original actor, in the work item's history in one
    /// transaction; settle the attempt afterwards.
    MarkUncertain(AttemptMarkUncertainArgs),
}

#[derive(Debug, Args)]
struct AttemptMarkUncertainArgs {
    #[command(flatten)]
    operator: OperatorArgs,
    /// Pending source attempt to mark uncertain.
    #[arg(long, value_name = "UUID")]
    attempt_id: Uuid,
    /// Why the attempt is marked uncertain; recorded in the work item's history.
    #[arg(long)]
    reason: String,
    /// Who made the decision; recorded in the work item's history.
    #[arg(long)]
    decided_by: String,
    /// Apply the reviewed marking. Omit to preview.
    #[arg(long)]
    apply: bool,
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

const DOMAIN_REFUSAL_EXIT: u8 = 1;
const OPERATIONAL_FAILURE_EXIT: u8 = 3;
const CLI_API_VERSION: &str = "registry.registrystack.org/caseworkctl/v1alpha1";

pub fn main_entry() -> ExitCode {
    main_entry_from(
        std::env::args_os(),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
}

fn main_entry_from<I, T>(
    args: I,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let machine_mode = args
        .windows(2)
        .any(|pair| pair[0] == OsStr::new("--format") && pair[1] == OsStr::new("json"))
        || args.iter().any(|arg| arg == OsStr::new("--format=json"));
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = write!(stdout, "{error}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            if machine_mode {
                write_failure(
                    &cli_report_envelope(
                        "UsageReport",
                        json!({"ok":false,"command":"usage","diagnostics":[diagnostic(
                            "usage.invalid", "arguments", error.to_string(), "Correct the command arguments and retry."
                        )]}),
                    ),
                    OutputFormat::Json,
                    stdout,
                    stderr,
                );
            } else {
                let _ = write!(stderr, "{error}");
            }
            return ExitCode::from(2);
        }
    };
    let cli = match cli.command {
        Command::DevServiceGuard(args) => {
            return match dev::run_service_guard(args) {
                Ok(false) => ExitCode::SUCCESS,
                Ok(true) => ExitCode::from(dev::SERVICE_GUARD_FORCED_EXIT),
                Err(error) => {
                    let _ = writeln!(stderr, "{error:#}");
                    ExitCode::from(DOMAIN_REFUSAL_EXIT)
                }
            };
        }
        Command::DevSupervisor(args) => {
            return match dev::run_supervisor(args) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    let _ = writeln!(stderr, "{error:#}");
                    ExitCode::from(DOMAIN_REFUSAL_EXIT)
                }
            };
        }
        command => Cli {
            format: cli.format,
            command,
        },
    };
    let format = cli.format;
    let command_kind = command_kind(&cli.command);
    let report_kind = cli_report_kind(&cli.command);
    match run(cli) {
        Ok(report) => write_success(
            &machine_report(format, report_kind, report),
            format,
            stdout,
            stderr,
        ),
        Err(error) => {
            if let Some(denied) = error.downcast_ref::<project::DeniedFindings>() {
                write_failure(
                    &machine_report(
                        format,
                        report_kind,
                        json!({"ok":false,"command":"check","diagnostics":denied.0}),
                    ),
                    format,
                    stdout,
                    stderr,
                );
                return ExitCode::from(DOMAIN_REFUSAL_EXIT);
            }
            let (exit, diagnostic) = classify_failure(command_kind, &error);
            write_failure(
                &machine_report(
                    format,
                    report_kind,
                    json!({"ok":false,"diagnostics":[diagnostic]}),
                ),
                format,
                stdout,
                stderr,
            );
            ExitCode::from(exit)
        }
    }
}

/// Every public JSON report carries one top-level envelope. The version covers
/// all report kinds as one contract: a breaking change to any pinned field
/// requires a version bump for the complete `caseworkctl` surface.
fn cli_report_envelope(kind: &'static str, mut report: Value) -> Value {
    report
        .as_object_mut()
        .expect("every caseworkctl report serializes as an object")
        .extend([
            ("apiVersion".to_owned(), Value::from(CLI_API_VERSION)),
            ("kind".to_owned(), Value::from(kind)),
        ]);
    report
}

fn machine_report(format: OutputFormat, kind: &'static str, report: Value) -> Value {
    if format == OutputFormat::Json {
        cli_report_envelope(kind, report)
    } else {
        report
    }
}

fn cli_report_kind(command: &Command) -> &'static str {
    match command {
        Command::Attempt(args) => match args.command {
            AttemptCommand::Settle(_) => "AttemptSettlementReport",
            AttemptCommand::MarkUncertain(_) => "AttemptUncertainMarkingReport",
        },
        Command::Check(_) => "CheckReport",
        Command::Db(_) => "DatabaseMigrationReport",
        Command::Doctor(_) => "DoctorReport",
        Command::Explain(_) => "ExplainReport",
        Command::Init(_) => "InitReport",
        Command::Lifecycle => "LifecycleReport",
        Command::Package(_) => "PackageReport",
        Command::Retention(_) => "RetentionEraseReport",
        Command::Simulate(_) => "SimulationReport",
        Command::Source(_) => "SourceAddReport",
        Command::Test(_) => "TestReport",
        Command::Dev(args) => args.report_kind(),
        Command::DevSupervisor(_) | Command::DevServiceGuard(_) => "DevReport",
    }
}

#[derive(Clone, Copy)]
enum CommandKind {
    Authoring,
    Operational,
    Retention,
    AttemptSettlement,
    AttemptUncertainMarking,
    Migration,
}

fn command_kind(command: &Command) -> CommandKind {
    if matches!(command, Command::Retention(_)) {
        return CommandKind::Retention;
    }
    if matches!(command, Command::Db(_)) {
        return CommandKind::Migration;
    }
    if let Command::Attempt(args) = command {
        return match args.command {
            AttemptCommand::Settle(_) => CommandKind::AttemptSettlement,
            AttemptCommand::MarkUncertain(_) => CommandKind::AttemptUncertainMarking,
        };
    }
    if matches!(command, Command::Doctor(_) | Command::Dev(_)) {
        CommandKind::Operational
    } else {
        CommandKind::Authoring
    }
}

fn classify_failure(kind: CommandKind, error: &anyhow::Error) -> (u8, Value) {
    if let Some(diagnostic) = operator_refusal(kind, error) {
        return (DOMAIN_REFUSAL_EXIT, diagnostic);
    }
    let io_failure = error.chain().any(|cause| cause.is::<std::io::Error>());
    let runtime_error = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<RuntimeConfigError>());
    let project_error = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ConfigLoadError>());
    let semantic_error = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ConfigError>());
    let runtime_project_error =
        matches!(runtime_error, Some(RuntimeConfigError::Project(_))) && project_error.is_some();
    let runtime_dependency_unavailable = matches!(runtime_error, Some(RuntimeConfigError::Oidc));
    let domain = !io_failure
        && !runtime_dependency_unavailable
        && (runtime_error.is_some()
            || project_error.is_some()
            || semantic_error.is_some()
            || matches!(kind, CommandKind::Authoring));
    let (artifact, path, action) = if io_failure {
        (
            "filesystem",
            "filesystem".to_owned(),
            "Correct the path or permissions, then retry.",
        )
    } else if runtime_dependency_unavailable {
        (
            "runtime_dependency",
            "runtime.yaml:/authentication/oidc".to_owned(),
            "Restore access to the configured OIDC issuer or mounted JWKS, then retry.",
        )
    } else if runtime_project_error {
        project_diagnostic_location(project_error.expect("runtime project error has source"))
    } else if let Some(runtime) = runtime_error {
        runtime_diagnostic_location(runtime)
    } else if let Some(project) = project_error {
        project_diagnostic_location(project)
    } else if let Some(semantic) = semantic_error {
        semantic_diagnostic_location(semantic)
    } else if matches!(kind, CommandKind::Authoring) {
        (
            "authoring_input",
            "authoring".to_owned(),
            "Correct the authored input named by the refusal, then retry.",
        )
    } else {
        (
            "runtime_dependency",
            "runtime".to_owned(),
            "Correct the unavailable runtime dependency, then retry.",
        )
    };
    let code = if io_failure {
        "caseworkctl.io-failure"
    } else if runtime_dependency_unavailable {
        "casework.runtime-dependency.unavailable"
    } else if runtime_project_error || project_error.is_some() || semantic_error.is_some() {
        "casework.project.invalid"
    } else if runtime_error.is_some() {
        "casework.runtime-configuration.invalid"
    } else if domain {
        "caseworkctl.refused"
    } else {
        "caseworkctl.operational-failure"
    };
    let message = if io_failure {
        "A required filesystem operation failed.".to_owned()
    } else if runtime_dependency_unavailable {
        "The configured OIDC runtime dependency is unavailable.".to_owned()
    } else if runtime_project_error {
        project_error
            .expect("runtime project error has source")
            .to_string()
    } else if let Some(runtime) = runtime_error {
        runtime.to_string()
    } else if let Some(project) = project_error {
        project.to_string()
    } else if let Some(semantic) = semantic_error {
        semantic.to_string()
    } else if domain {
        format!("{error:#}")
    } else {
        "A Casework runtime dependency check failed.".to_owned()
    };
    (
        if domain {
            DOMAIN_REFUSAL_EXIT
        } else {
            OPERATIONAL_FAILURE_EXIT
        },
        json!({
            "severity":"error", "code":code, "artifact":artifact, "path":path,
            "message":message, "suggestedAction":action
        }),
    )
}

fn operator_refusal(kind: CommandKind, error: &anyhow::Error) -> Option<Value> {
    let (code, path, message, action) = match kind {
        CommandKind::Retention => {
            let store = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<StoreError>())?;
            if !matches!(
                store,
                StoreError::NotFound | StoreError::AttemptPending | StoreError::Invalid
            ) {
                return None;
            }
            (
                "casework.retention.refused",
                "retention",
                store.to_string(),
                "Correct the exact source selection or recover the pending attempt, then preview again.",
            )
        }
        CommandKind::AttemptSettlement => {
            let settlement = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<AttemptSettlementError>())?;
            if !matches!(
                settlement,
                AttemptSettlementError::NotFound
                    | AttemptSettlementError::NotUncertain(_)
                    | AttemptSettlementError::LeaseLive
                    | AttemptSettlementError::ItemNotSynchronizing(_)
                    | AttemptSettlementError::Invalid { .. }
            ) {
                return None;
            }
            // A pending attempt is moved to uncertain only by the recover route,
            // which the actor who started it calls once the lease expires.
            let action = if matches!(settlement, AttemptSettlementError::NotUncertain("pending")) {
                "After the attempt's execution lease expires, the actor who started it calls \
                 POST /v1/work-items/{itemId}/attempts/{attemptId}/recover while the source is \
                 reachable; settle the attempt only if recovery leaves it uncertain. If that actor \
                 cannot recover it, mark it uncertain with caseworkctl attempt mark-uncertain."
            } else {
                "Confirm the attempt and source outcome, then preview the settlement again."
            };
            (
                "casework.attempt-settlement.refused",
                "attempt",
                settlement.to_string(),
                action,
            )
        }
        CommandKind::AttemptUncertainMarking => {
            let marking = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<AttemptSettlementError>())?;
            if !matches!(
                marking,
                AttemptSettlementError::NotFound
                    | AttemptSettlementError::NotPending(_)
                    | AttemptSettlementError::LeaseLive
                    | AttemptSettlementError::ItemNotSynchronizing(_)
                    | AttemptSettlementError::Invalid { .. }
            ) {
                return None;
            }
            let action = if matches!(marking, AttemptSettlementError::NotPending("uncertain")) {
                "The attempt is already uncertain; settle it with caseworkctl attempt settle once \
                 the source owner confirms its outcome."
            } else {
                "Confirm the attempt, then preview the marking again."
            };
            (
                "casework.attempt-mark-uncertain.refused",
                "attempt",
                marking.to_string(),
                action,
            )
        }
        CommandKind::Migration => {
            // Only the refusals `casework migrate` names are passed through; a
            // database that cannot be reached stays an operational failure.
            let store = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<StoreError>())?;
            let action = match store {
                StoreError::SchemaNewer { .. } => {
                    "Run the casework release that migrated this database or a later one; \
                     Casework does not migrate a schema down."
                }
                StoreError::HostedWorkWouldBeDropped { .. } => {
                    "Keep this database with the release that wrote it until its hosted work \
                     is exported, then migrate a fresh Casework database."
                }
                _ => return None,
            };
            (
                "casework.migration.refused",
                "database",
                store.to_string(),
                action,
            )
        }
        CommandKind::Authoring | CommandKind::Operational => return None,
    };
    Some(json!({
        "severity": "error",
        "code": code,
        "artifact": "operator_action",
        "path": path,
        "message": message,
        "suggestedAction": action,
    }))
}

fn runtime_diagnostic_location(error: &RuntimeConfigError) -> (&'static str, String, &'static str) {
    let path = if matches!(error, RuntimeConfigError::RemovedPrincipalClaim) {
        "runtime.yaml:/authentication/oidc/principalClaim".to_owned()
    } else if error.path() == "/" {
        "runtime.yaml".to_owned()
    } else {
        format!("runtime.yaml:/{}", error.path().trim_start_matches('/'))
    };
    let action = if matches!(error, RuntimeConfigError::RemovedPrincipalClaim) {
        "Remove authentication.oidc.principalClaim and configure accessProfiles[].principalClaim in casework.yaml."
    } else {
        "Correct the named runtime configuration field, then retry."
    };
    ("runtime_configuration", path, action)
}

fn project_diagnostic_location(error: &ConfigLoadError) -> (&'static str, String, &'static str) {
    let path = if error.path() == "/" {
        "casework.yaml".to_owned()
    } else {
        format!("casework.yaml:/{}", error.path().trim_start_matches('/'))
    };
    (
        "casework_project",
        path,
        "Correct the named Casework project member, then retry.",
    )
}

fn semantic_diagnostic_location(error: &ConfigError) -> (&'static str, String, &'static str) {
    if let ConfigError::Reference { path, .. } | ConfigError::Semantic { path, .. } = error {
        return (
            "casework_project",
            format!("casework.yaml:{path}"),
            "Correct the named project member and its reference, then retry.",
        );
    }
    let (artifact, path, action) = match error {
        ConfigError::TaskTemplate => (
            "casework_project",
            "casework.yaml:/taskTemplates",
            "Use unique task templates with eligible teams and human profiles, valid source fields, exact bounds, and a lifetime of at most 900 seconds.",
        ),
        ConfigError::Envelope => (
            "casework_project",
            "casework.yaml:/apiVersion",
            "Use the supported Casework project envelope.",
        ),
        ConfigError::Identifier => (
            "casework_project",
            "casework.yaml",
            "Correct the invalid identifier named by the project member.",
        ),
        ConfigError::DefaultQueue => (
            "casework_project",
            "casework.yaml:/queues",
            "Declare unique queues and valid queue references.",
        ),
        ConfigError::AccessProfiles | ConfigError::AccessProfileScopes => (
            "casework_project",
            "casework.yaml:/accessProfiles",
            "Correct the access profile roles, claims, and distinct scopes.",
        ),
        ConfigError::ReviewKinds => (
            "casework_project",
            "casework.yaml:/reviewKinds",
            "Correct the unified review kind, stage, schema, outcome, retention, clock, or access-profile reference.",
        ),
        ConfigError::ReviewProducers => (
            "casework_project",
            "casework.yaml:/reviewProducers",
            "Correct the producer identity, requester profile, source namespace, kind grant, recovery, or completion binding.",
        ),
        ConfigError::NoConfiguredWork => (
            "casework_project",
            "casework.yaml:/sources",
            "Declare a source or unified review kind.",
        ),
        ConfigError::Routing => (
            "casework_project",
            "casework.yaml:/sources",
            "Correct the routing rule, field, or queue reference.",
        ),
        ConfigError::Clocks => (
            "casework_project",
            "casework.yaml:/clocks",
            "Correct the clock, calendar, holiday, or queue reference.",
        ),
        ConfigError::InboxBounds => (
            "casework_project",
            "casework.yaml:/inbox",
            "Correct the inbox limits.",
        ),
        ConfigError::Reference { .. } | ConfigError::Semantic { .. } => unreachable!(),
    };
    (artifact, path.to_owned(), action)
}

fn diagnostic(code: &str, path: &str, message: String, suggested_action: &str) -> Value {
    json!({
        "severity": "error",
        "code": code,
        "artifact": "command_arguments",
        "path": path,
        "message": message,
        "suggestedAction": suggested_action,
    })
}

fn write_success(
    report: &Value,
    format: OutputFormat,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    let result = match format {
        OutputFormat::Json => serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout)),
        OutputFormat::Human => render_human(report, stdout),
    };
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        let _ = writeln!(stderr, "caseworkctl: output could not be written");
        ExitCode::from(OPERATIONAL_FAILURE_EXIT)
    }
}

fn write_failure(
    report: &Value,
    format: OutputFormat,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) {
    if format == OutputFormat::Json {
        let _ = serde_json::to_writer_pretty(&mut *stdout, report);
        let _ = writeln!(stdout);
        return;
    }
    if let Some(diagnostics) = report["diagnostics"].as_array() {
        for finding in diagnostics {
            let _ = writeln!(
                stderr,
                "{}[{}] {}: {}",
                finding["severity"].as_str().unwrap_or("error"),
                finding["code"].as_str().unwrap_or("caseworkctl.refused"),
                finding["path"].as_str().unwrap_or("command"),
                finding["message"].as_str().unwrap_or("command refused")
            );
            if let Some(action) = finding["suggestedAction"].as_str() {
                let _ = writeln!(stderr, "  next: {action}");
            }
        }
    }
}

fn render_human(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    let command = report["command"].as_str().unwrap_or("command");
    let lead = match (
        command,
        report["status"].as_str(),
        report["authoringStatus"].as_str(),
    ) {
        ("check", Some("incomplete"), _) => "Authoring check completed with incomplete inputs.",
        ("check", Some("complete"), _) => "Authoring check passed with complete inputs.",
        ("test", _, Some("incomplete")) => {
            "Offline synthetic fixtures passed with incomplete authored inputs."
        }
        ("test", _, _) => "Offline synthetic fixtures passed.",
        _ => "",
    };
    if lead.is_empty() {
        writeln!(stdout, "{} succeeded.", command)?;
    } else {
        writeln!(stdout, "{lead}")?;
    }
    if let Some(fields) = report.as_object() {
        for (key, value) in fields {
            if matches!(key.as_str(), "ok" | "command" | "findings" | "diagnostics")
                || value.is_null()
            {
                continue;
            }
            let rendered = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            writeln!(stdout, "{key}: {rendered}")?;
        }
    }
    if let Some(findings) = report["findings"].as_array() {
        for finding in findings {
            writeln!(
                stdout,
                "finding[{}] {}: {}",
                finding["code"].as_str().unwrap_or("casework.finding"),
                finding["path"].as_str().unwrap_or("casework.yaml"),
                finding["message"].as_str().unwrap_or("review required")
            )?;
            if let Some(action) = finding["suggestedAction"].as_str() {
                writeln!(stdout, "  next: {action}")?;
            }
        }
    }
    Ok(())
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
        Command::Check(args) => project::check(&args.project, args.production, args.deny_findings),
        Command::Explain(args) => project::explain(&args.project),
        Command::Lifecycle => lifecycle::lifecycle(),
        Command::Package(args) => match args.output {
            Some(output) => project::package(&args.project, &output),
            None => project::package_dry_run(&args.project),
        },
        Command::Simulate(args) => project::simulate(&args.project, &args.fixture),
        Command::Test(args) => project::test(&args.project),
        Command::Doctor(args) => project::doctor(&args.runtime_config),
        Command::Db(args) => match args.command {
            DbCommand::Migrate(args) => {
                project::db_migrate(&args.project, args.runtime_config.as_deref())
            }
        },
        Command::Retention(args) => match args.command {
            RetentionCommand::Erase(args) => project::retention_erase(
                &args.operator.project,
                args.operator.runtime_config.as_deref(),
                args.source_id,
                args.request_kind,
                args.request_id,
                args.apply,
            ),
        },
        Command::Attempt(args) => match args.command {
            AttemptCommand::Settle(args) => project::attempt_settle(
                &args.operator.project,
                args.operator.runtime_config.as_deref(),
                AttemptSettlement {
                    attempt_id: args.attempt_id,
                    outcome: args.outcome.into(),
                    reason: args.reason,
                    decided_by: args.decided_by,
                },
                args.apply,
            ),
            AttemptCommand::MarkUncertain(args) => project::attempt_mark_uncertain(
                &args.operator.project,
                args.operator.runtime_config.as_deref(),
                AttemptUncertainMarking {
                    attempt_id: args.attempt_id,
                    reason: args.reason,
                    decided_by: args.decided_by,
                },
                args.apply,
            ),
        },
        Command::Dev(args) => dev::run(*args),
        Command::DevSupervisor(_) => unreachable!("the supervisor is dispatched before run"),
        Command::DevServiceGuard(_) => unreachable!("the service guard is dispatched before run"),
    }
    .context("casework command refused")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_service_guard_preserves_hyphenated_service_arguments() {
        let cli = Cli::try_parse_from([
            "caseworkctl",
            "__dev-service-guard",
            "--",
            "/bin/echo",
            "--config",
            "/tmp/service.yaml",
        ])
        .unwrap();
        let Command::DevServiceGuard(args) = cli.command else {
            panic!("internal guard command not parsed");
        };
        assert_eq!(args.binary, PathBuf::from("/bin/echo"));
        assert_eq!(
            args.arguments,
            [
                std::ffi::OsString::from("--config"),
                std::ffi::OsString::from("/tmp/service.yaml"),
            ]
        );
    }

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

    #[test]
    fn canonical_command_shapes_and_default_format_are_stable() {
        let cli = Cli::try_parse_from([
            "caseworkctl",
            "check",
            "/tmp/project",
            "--production",
            "--deny-findings",
        ])
        .unwrap();
        assert_eq!(cli.format, OutputFormat::Human);
        let Command::Check(args) = cli.command else {
            panic!("expected check")
        };
        assert!(args.production);
        assert!(args.deny_findings);

        let cli = Cli::try_parse_from([
            "caseworkctl",
            "--format",
            "json",
            "doctor",
            "--runtime-config",
            "/tmp/runtime.yaml",
        ])
        .unwrap();
        assert_eq!(cli.format, OutputFormat::Json);
        let Command::Doctor(args) = cli.command else {
            panic!("expected doctor")
        };
        assert_eq!(args.runtime_config, PathBuf::from("/tmp/runtime.yaml"));

        assert!(Cli::try_parse_from([
            "caseworkctl",
            "doctor",
            "/tmp/project",
            "--runtime-config",
            "/tmp/runtime.yaml"
        ])
        .is_err());
        assert!(
            Cli::try_parse_from(["caseworkctl", "init", "--template", "standalone-decision"])
                .is_err()
        );
    }

    #[test]
    fn package_requires_exactly_one_of_output_or_dry_run() {
        assert!(Cli::try_parse_from(["caseworkctl", "package", "/tmp/project"]).is_err());
        assert!(Cli::try_parse_from([
            "caseworkctl",
            "package",
            "/tmp/project",
            "--output",
            "/tmp/out",
            "--dry-run",
        ])
        .is_err());

        let Command::Package(args) = Cli::try_parse_from([
            "caseworkctl",
            "package",
            "/tmp/project",
            "--output",
            "/tmp/out",
        ])
        .unwrap()
        .command
        else {
            panic!("expected package")
        };
        assert_eq!(args.output, Some(PathBuf::from("/tmp/out")));
        assert!(!args.dry_run);

        let Command::Package(args) =
            Cli::try_parse_from(["caseworkctl", "package", "/tmp/project", "--dry-run"])
                .unwrap()
                .command
        else {
            panic!("expected package")
        };
        assert_eq!(args.output, None);
        assert!(args.dry_run);
    }

    #[test]
    fn usage_json_has_the_common_diagnostic_fields_and_exit_two() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(
            ["caseworkctl", "--format", "json", "doctor"],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::from(2));
        assert!(stderr.is_empty());
        let report: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(report["apiVersion"], CLI_API_VERSION);
        assert_eq!(report["kind"], "UsageReport");
        let diagnostic = &report["diagnostics"][0];
        for field in [
            "severity",
            "code",
            "artifact",
            "path",
            "message",
            "suggestedAction",
        ] {
            assert!(diagnostic.get(field).is_some(), "missing {field}");
        }
        assert_eq!(diagnostic["artifact"], "command_arguments");

        stdout.clear();
        let exit = main_entry_from(["caseworkctl", "doctor"], &mut stdout, &mut stderr);
        assert_eq!(exit, ExitCode::from(2));
        assert!(stdout.is_empty());
        assert!(!stderr.is_empty());
    }

    #[test]
    fn help_and_version_remain_clap_text_when_json_format_is_selected() {
        for arguments in [
            vec!["caseworkctl", "--format", "json", "--help"],
            vec!["caseworkctl", "--format=json", "--version"],
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let exit = main_entry_from(arguments, &mut stdout, &mut stderr);

            assert_eq!(exit, ExitCode::SUCCESS);
            assert!(stderr.is_empty());
            assert!(!stdout.is_empty());
            assert!(serde_json::from_slice::<Value>(&stdout).is_err());
        }
    }

    #[test]
    fn authoring_refusal_preserves_its_message_and_names_authored_input() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("casework");
        project::init(&project, "standalone-decision").unwrap();
        for entry in std::fs::read_dir(project.join("fixtures")).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }

        let arguments = [
            OsString::from("caseworkctl"),
            OsString::from("--format=json"),
            OsString::from("test"),
            project.clone().into_os_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(arguments, &mut stdout, &mut stderr);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
        let report: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(report["apiVersion"], CLI_API_VERSION);
        assert_eq!(report["kind"], "TestReport");
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(diagnostic["artifact"], "authoring_input");
        assert_eq!(diagnostic["path"], "authoring");
        assert!(diagnostic["message"]
            .as_str()
            .is_some_and(|message| message.contains("test requires at least one YAML fixture")));
        assert_eq!(
            diagnostic["suggestedAction"],
            "Correct the authored input named by the refusal, then retry."
        );

        stdout.clear();
        let mut stderr = Vec::new();
        let exit = main_entry_from(
            [
                OsString::from("caseworkctl"),
                OsString::from("test"),
                project.into_os_string(),
            ],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stdout.is_empty());
        let rendered = String::from_utf8(stderr).unwrap();
        assert!(rendered.contains("test requires at least one YAML fixture"));
        assert!(!rendered.contains("runtime dependency"));
    }

    #[test]
    fn check_reports_the_exact_broken_review_policy_binding() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("casework");
        let example = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/examples/multi-stage-routing-clocks");
        std::fs::create_dir_all(project.join("sources")).unwrap();
        std::fs::copy(example.join("casework.yaml"), project.join("casework.yaml")).unwrap();
        for source in ["regional-register.json", "response-register.json"] {
            std::fs::copy(
                example.join("sources").join(source),
                project.join("sources").join(source),
            )
            .unwrap();
        }
        let regional_path = project.join("sources/regional-register.json");
        let mut regional: Value =
            serde_json::from_slice(&std::fs::read(&regional_path).unwrap()).unwrap();
        regional["request"]["review"]["policyId"] = json!("missing-review-kind");
        std::fs::write(&regional_path, serde_json::to_vec(&regional).unwrap()).unwrap();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(
            [
                OsString::from("caseworkctl"),
                OsString::from("--format=json"),
                OsString::from("check"),
                project.into_os_string(),
            ],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
        let report: Value = serde_json::from_slice(&stdout).unwrap();
        let diagnostic = &report["diagnostics"][0];
        let message = diagnostic["message"].as_str().unwrap();
        assert!(message.contains("regional-register"), "{message}");
        assert!(message.contains("missing-review-kind"), "{message}");
        assert!(
            message.contains("sha256:regional-source-revision"),
            "{message}"
        );
        assert_eq!(diagnostic["artifact"], "authoring_input");
        assert_eq!(diagnostic["path"], "authoring");
    }

    #[test]
    fn denied_authoring_findings_use_exit_one_and_the_same_diagnostics() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("casework");
        project::init(&project, "professional-review").unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(
            [
                OsString::from("caseworkctl"),
                OsString::from("--format=json"),
                OsString::from("check"),
                project.clone().into_os_string(),
                OsString::from("--deny-findings"),
            ],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::from(1));
        assert!(stderr.is_empty());
        let report: Value = serde_json::from_slice(&stdout).unwrap();
        let diagnostic = &report["diagnostics"][0];
        for field in [
            "severity",
            "code",
            "artifact",
            "path",
            "message",
            "suggestedAction",
        ] {
            assert!(diagnostic.get(field).is_some(), "missing {field}");
        }
        assert_eq!(diagnostic["code"], "casework.source-description.missing");
        assert_eq!(diagnostic["path"], "casework.yaml:/sources/0/description");

        stdout.clear();
        let exit = main_entry_from(
            [
                OsString::from("caseworkctl"),
                OsString::from("check"),
                project.into_os_string(),
                OsString::from("--deny-findings"),
            ],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::from(1));
        assert!(stdout.is_empty());
        assert!(String::from_utf8_lossy(&stderr)
            .starts_with("finding[casework.source-description.missing]"));
    }

    #[test]
    fn review_connection_retention_diagnostic_names_the_incompatible_pair() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("standalone");
        project::init(&project, "standalone-decision").unwrap();
        let policy_path = project.join("casework.yaml");
        let mut policy: Value =
            serde_norway::from_slice(&std::fs::read(&policy_path).unwrap()).unwrap();
        policy["reviewProducers"][0]["recoveryDays"] = json!(91);
        std::fs::write(&policy_path, serde_norway::to_string(&policy).unwrap()).unwrap();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(
            [
                OsString::from("caseworkctl"),
                OsString::from("--format=json"),
                OsString::from("check"),
                project.into_os_string(),
            ],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::from(1));
        assert!(stderr.is_empty());
        let report: Value = serde_json::from_slice(&stdout).unwrap();
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(diagnostic["code"], "casework.project.invalid");
        assert_eq!(
            diagnostic["path"],
            "casework.yaml:/reviewProducers[0].recoveryDays"
        );
        assert!(diagnostic["message"].as_str().is_some_and(
            |message| message.contains("recovery window no longer than result retention")
        ));
        assert_eq!(
            diagnostic["suggestedAction"],
            "Correct the named Casework project member, then retry."
        );
    }

    #[test]
    fn operational_failures_follow_the_selected_output_channel() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing-runtime.yaml");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(
            [
                OsString::from("caseworkctl"),
                OsString::from("--format=json"),
                OsString::from("doctor"),
                OsString::from("--runtime-config"),
                missing.clone().into_os_string(),
            ],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::from(3));
        assert!(stderr.is_empty());
        let report: Value = serde_json::from_slice(&stdout).unwrap();
        let diagnostic = &report["diagnostics"][0];
        for field in [
            "severity",
            "code",
            "artifact",
            "path",
            "message",
            "suggestedAction",
        ] {
            assert!(diagnostic.get(field).is_some(), "missing {field}");
        }

        stdout.clear();
        let exit = main_entry_from(
            [
                OsString::from("caseworkctl"),
                OsString::from("doctor"),
                OsString::from("--runtime-config"),
                missing.into_os_string(),
            ],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::from(3));
        assert!(stdout.is_empty());
        assert!(String::from_utf8_lossy(&stderr).starts_with("error[caseworkctl.io-failure]"));
    }

    #[test]
    fn runtime_and_project_parse_diagnostics_never_echo_rejected_values() {
        const REJECTED_VALUE: &str = "value-that-must-not-be-echoed";
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("runtime.yaml");
        std::fs::write(
            &runtime,
            format!("apiVersion: registry.registrystack.org/casework-runtime/v1alpha1\nkind: CaseworkRuntimeConfig\ndatabase:\n  testOnlyPlaintext: {REJECTED_VALUE}\n"),
        )
        .unwrap();
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("casework.yaml"),
            format!("apiVersion: registry.registrystack.org/casework/v1alpha1\nkind: CaseworkProject\nsources: {REJECTED_VALUE}\n"),
        )
        .unwrap();

        for format in ["human", "json"] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let exit = main_entry_from(
                [
                    OsString::from("caseworkctl"),
                    OsString::from(format!("--format={format}")),
                    OsString::from("doctor"),
                    OsString::from("--runtime-config"),
                    runtime.clone().into_os_string(),
                ],
                &mut stdout,
                &mut stderr,
            );
            assert_eq!(exit, ExitCode::from(1));
            assert!(!String::from_utf8_lossy(&stdout).contains(REJECTED_VALUE));
            assert!(!String::from_utf8_lossy(&stderr).contains(REJECTED_VALUE));

            stdout.clear();
            stderr.clear();
            let exit = main_entry_from(
                [
                    OsString::from("caseworkctl"),
                    OsString::from(format!("--format={format}")),
                    OsString::from("check"),
                    project.clone().into_os_string(),
                ],
                &mut stdout,
                &mut stderr,
            );
            assert_eq!(exit, ExitCode::from(1));
            assert!(!String::from_utf8_lossy(&stdout).contains(REJECTED_VALUE));
            assert!(!String::from_utf8_lossy(&stderr).contains(REJECTED_VALUE));
        }
    }

    #[test]
    fn removed_principal_claim_diagnostic_names_the_replacement_path_and_action() {
        let error = anyhow::Error::new(RuntimeConfigError::RemovedPrincipalClaim);
        let (exit, diagnostic) = classify_failure(CommandKind::Operational, &error);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(
            diagnostic["path"],
            "runtime.yaml:/authentication/oidc/principalClaim"
        );
        assert!(diagnostic["suggestedAction"]
            .as_str()
            .unwrap()
            .contains("accessProfiles[].principalClaim"));
    }

    #[test]
    fn unavailable_oidc_dependency_uses_operational_exit_and_safe_diagnostic() {
        let error = anyhow::Error::new(RuntimeConfigError::Oidc);
        let (exit, diagnostic) = classify_failure(CommandKind::Operational, &error);

        assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
        assert_eq!(
            diagnostic["code"],
            "casework.runtime-dependency.unavailable"
        );
        assert_eq!(diagnostic["artifact"], "runtime_dependency");
        assert_eq!(diagnostic["path"], "runtime.yaml:/authentication/oidc");
        assert_eq!(
            diagnostic["message"],
            "The configured OIDC runtime dependency is unavailable."
        );
        assert_eq!(
            diagnostic["suggestedAction"],
            "Restore access to the configured OIDC issuer or mounted JWKS, then retry."
        );
    }

    #[test]
    fn operator_refusals_keep_safe_recovery_reasons_without_exposing_store_failures() {
        let pending = anyhow::Error::new(StoreError::AttemptPending)
            .context("processing Casework source retention");
        let (exit, diagnostic) = classify_failure(CommandKind::Retention, &pending);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(diagnostic["code"], "casework.retention.refused");
        assert_eq!(
            diagnostic["message"],
            "a source attempt is still pending recovery"
        );

        let lease = anyhow::Error::new(AttemptSettlementError::LeaseLive)
            .context("settling the Casework source attempt");
        let (exit, diagnostic) = classify_failure(CommandKind::AttemptSettlement, &lease);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(diagnostic["code"], "casework.attempt-settlement.refused");
        assert_eq!(
            diagnostic["message"],
            "the source attempt still holds a live execution lease; wait for it to expire"
        );

        let corrupt =
            anyhow::Error::new(StoreError::Corrupt).context("processing Casework source retention");
        let (exit, diagnostic) = classify_failure(CommandKind::Retention, &corrupt);
        assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
        assert_eq!(diagnostic["code"], "caseworkctl.operational-failure");
        assert_eq!(diagnostic["artifact"], "runtime_dependency");
        assert_eq!(diagnostic["path"], "runtime");
        assert_eq!(
            diagnostic["message"],
            "A Casework runtime dependency check failed."
        );
        assert_eq!(
            diagnostic["suggestedAction"],
            "Correct the unavailable runtime dependency, then retry."
        );
    }

    #[test]
    fn db_migrate_passes_migration_refusals_through_and_keeps_database_failures_generic() {
        let kind = command_kind(
            &Cli::try_parse_from(["caseworkctl", "db", "migrate", "."])
                .unwrap()
                .command,
        );

        let newer = anyhow::Error::new(StoreError::SchemaNewer {
            found: 17,
            supported: 16,
        })
        .context("applying Casework database migrations");
        let (exit, diagnostic) = classify_failure(kind, &newer);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(diagnostic["code"], "casework.migration.refused");
        assert_eq!(diagnostic["artifact"], "operator_action");
        assert_eq!(diagnostic["path"], "database");
        assert_eq!(
            diagnostic["message"],
            "the Casework database schema version 17 is newer than this binary supports (16); run a casework release that supports it"
        );
        assert_eq!(
            diagnostic["suggestedAction"],
            "Run the casework release that migrated this database or a later one; Casework does not migrate a schema down."
        );

        let hosted = anyhow::Error::new(StoreError::HostedWorkWouldBeDropped {
            version: 15,
            tables: vec![("casework_hosted_items", 1)],
        })
        .context("applying Casework database migrations");
        let (exit, diagnostic) = classify_failure(kind, &hosted);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(diagnostic["code"], "casework.migration.refused");
        assert_eq!(
            diagnostic["message"],
            StoreError::HostedWorkWouldBeDropped {
                version: 15,
                tables: vec![("casework_hosted_items", 1)],
            }
            .to_string()
        );
        assert!(
            diagnostic["message"]
                .as_str()
                .unwrap()
                .contains("casework_hosted_items (1 row)"),
            "{diagnostic:#}"
        );
        assert_eq!(
            diagnostic["suggestedAction"],
            "Keep this database with the release that wrote it until its hosted work is exported, then migrate a fresh Casework database."
        );

        for failure in [StoreError::Unavailable, StoreError::Corrupt] {
            let failure =
                anyhow::Error::new(failure).context("applying Casework database migrations");
            let (exit, diagnostic) = classify_failure(kind, &failure);
            assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
            assert_eq!(diagnostic["code"], "caseworkctl.operational-failure");
            assert_eq!(
                diagnostic["message"],
                "A Casework runtime dependency check failed."
            );
        }
    }

    #[test]
    fn a_pending_attempt_settlement_refusal_names_the_recovery_step() {
        let pending = anyhow::Error::new(AttemptSettlementError::NotUncertain("pending"))
            .context("settling the Casework source attempt");
        let (exit, diagnostic) = classify_failure(CommandKind::AttemptSettlement, &pending);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(diagnostic["code"], "casework.attempt-settlement.refused");
        assert_eq!(
            diagnostic["message"],
            "the source attempt is pending; only an uncertain attempt can be settled"
        );
        assert_eq!(
            diagnostic["suggestedAction"],
            "After the attempt's execution lease expires, the actor who started it calls \
             POST /v1/work-items/{itemId}/attempts/{attemptId}/recover while the source is \
             reachable; settle the attempt only if recovery leaves it uncertain. If that actor \
             cannot recover it, mark it uncertain with caseworkctl attempt mark-uncertain."
        );

        let completed = anyhow::Error::new(AttemptSettlementError::NotUncertain("completed"))
            .context("settling the Casework source attempt");
        let (_, diagnostic) = classify_failure(CommandKind::AttemptSettlement, &completed);
        assert_eq!(
            diagnostic["suggestedAction"],
            "Confirm the attempt and source outcome, then preview the settlement again."
        );
    }

    #[test]
    fn human_reports_distinguish_incomplete_authoring_from_offline_fixture_proof() {
        let finding = json!({
            "severity":"finding",
            "code":"casework.source-description.missing",
            "artifact":"casework_project",
            "path":"casework.yaml:/sources/0/description",
            "message":"a declared source import is missing",
            "suggestedAction":"Import the declared source description."
        });
        let mut check_output = Vec::new();
        render_human(
            &json!({"ok":true,"command":"check","status":"incomplete","findings":[finding.clone()]}),
            &mut check_output,
        )
        .unwrap();
        assert!(String::from_utf8(check_output)
            .unwrap()
            .starts_with("Authoring check completed with incomplete inputs."));

        let mut test_output = Vec::new();
        render_human(
            &json!({
                "ok":true,
                "command":"test",
                "authoringStatus":"incomplete",
                "findings":[finding],
                "proofBoundary":"offline_synthetic",
                "productionClosure":false
            }),
            &mut test_output,
        )
        .unwrap();
        let test_output = String::from_utf8(test_output).unwrap();
        assert!(test_output
            .starts_with("Offline synthetic fixtures passed with incomplete authored inputs."));
        assert!(test_output.contains("proofBoundary: offline_synthetic"));
        assert!(test_output.contains("productionClosure: false"));
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
        assert_eq!(preview.operator.runtime_config, None);

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

    fn attempt_mark_uncertain_arguments() -> Vec<&'static str> {
        vec![
            "caseworkctl",
            "attempt",
            "mark-uncertain",
            "/tmp/casework-project",
            "--attempt-id",
            ATTEMPT_ID,
            "--reason",
            "The officer who started the attempt has left.",
            "--decided-by",
            "Registrar duty officer",
        ]
    }

    fn parse_attempt_mark_uncertain(arguments: Vec<&str>) -> AttemptMarkUncertainArgs {
        let Command::Attempt(AttemptArgs {
            command: AttemptCommand::MarkUncertain(args),
        }) = Cli::try_parse_from(arguments).unwrap().command
        else {
            panic!("expected attempt mark-uncertain");
        };
        args
    }

    #[test]
    fn attempt_mark_uncertain_previews_unless_apply_is_explicit() {
        let preview = parse_attempt_mark_uncertain(attempt_mark_uncertain_arguments());
        assert!(!preview.apply);
        assert_eq!(preview.attempt_id.to_string(), ATTEMPT_ID);
        assert_eq!(
            preview.reason,
            "The officer who started the attempt has left."
        );
        assert_eq!(preview.decided_by, "Registrar duty officer");
        assert_eq!(
            preview.operator.project,
            PathBuf::from("/tmp/casework-project")
        );

        let mut arguments = attempt_mark_uncertain_arguments();
        arguments.push("--apply");
        assert!(parse_attempt_mark_uncertain(arguments).apply);
    }

    #[test]
    fn attempt_mark_uncertain_requires_every_decision_argument() {
        for flag in ["--attempt-id", "--reason", "--decided-by"] {
            let mut arguments = attempt_mark_uncertain_arguments();
            let position = arguments.iter().position(|value| *value == flag).unwrap();
            arguments.drain(position..=position + 1);
            let error = Cli::try_parse_from(arguments).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "{flag} must be required"
            );
        }
        let malformed_id =
            replace_argument(attempt_mark_uncertain_arguments(), "--attempt-id", "a-1");
        assert_eq!(
            Cli::try_parse_from(malformed_id).unwrap_err().kind(),
            clap::error::ErrorKind::ValueValidation
        );
    }

    #[test]
    fn attempt_mark_uncertain_help_names_expired_leases_and_explicit_apply() {
        let error = Cli::try_parse_from(["caseworkctl", "attempt", "mark-uncertain", "--help"])
            .unwrap_err();
        let help = error.to_string();
        for expected in [
            "--attempt-id",
            "--reason",
            "--decided-by",
            "--apply",
            "Omit to preview",
            "pending",
            "lease has expired",
            "migration database",
        ] {
            assert!(help.contains(expected), "missing help text: {expected}");
        }
    }

    #[test]
    fn attempt_mark_uncertain_reports_its_own_kind() {
        let cli = Cli::try_parse_from(attempt_mark_uncertain_arguments()).unwrap();
        assert_eq!(
            cli_report_kind(&cli.command),
            "AttemptUncertainMarkingReport"
        );
        let cli = Cli::try_parse_from(attempt_settle_arguments()).unwrap();
        assert_eq!(cli_report_kind(&cli.command), "AttemptSettlementReport");
    }

    #[test]
    fn an_uncertainty_marking_refusal_names_the_next_step() {
        let uncertain = anyhow::Error::new(AttemptSettlementError::NotPending("uncertain"))
            .context("marking the Casework source attempt uncertain");
        let (exit, diagnostic) = classify_failure(CommandKind::AttemptUncertainMarking, &uncertain);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(
            diagnostic["code"],
            "casework.attempt-mark-uncertain.refused"
        );
        assert_eq!(diagnostic["path"], "attempt");
        assert_eq!(
            diagnostic["message"],
            "the source attempt is uncertain; only a pending attempt can be marked uncertain"
        );
        assert_eq!(
            diagnostic["suggestedAction"],
            "The attempt is already uncertain; settle it with caseworkctl attempt settle once \
             the source owner confirms its outcome."
        );

        let lease = anyhow::Error::new(AttemptSettlementError::LeaseLive)
            .context("marking the Casework source attempt uncertain");
        let (exit, diagnostic) = classify_failure(CommandKind::AttemptUncertainMarking, &lease);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(
            diagnostic["code"],
            "casework.attempt-mark-uncertain.refused"
        );
        assert_eq!(
            diagnostic["suggestedAction"],
            "Confirm the attempt, then preview the marking again."
        );
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

#[cfg(test)]
mod cli_contract_tests;
