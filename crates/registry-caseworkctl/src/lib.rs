// SPDX-License-Identifier: Apache-2.0

mod breg_package;
mod dev;
mod display_schema;
mod lifecycle;
mod policy;
mod project;
mod report;
mod source_add;

use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_casework::{AttemptSettlementError, RuntimeConfigError, StoreError};
use registry_casework_core::{
    AttemptSettlement, AttemptSettlementOutcome, AttemptUncertainMarking, ConfigLoadError,
};
use registry_platform_config::RuntimeConfigErrorKind;
use registry_platform_yaml::Report;
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
    ///
    /// The package is the unit caseworkctl plan and apply activate: a new directory holding the checked policy and the source descriptions it pins, named by the runtime configuration. bregctl package is a different verb that builds a Base Registry Engine (BReg) registry package from a tested BReg project.
    Package(PackageArgs),
    /// Run the project's bounded synthetic fixtures offline.
    Test(ProjectArgs),
    /// Check live database, issuer, source and directory readiness.
    Doctor(DoctorArgs),
    /// Report what applying the configured package would change, without writing.
    Plan(ActivationArgs),
    /// Apply the configured package with migration authority and record it as active.
    Apply(ApplyArgs),
    /// Report the active package, every activation, and the runtime role mode.
    Status(ActivationArgs),
    /// Removed: refuses and names `caseworkctl plan` then `caseworkctl apply`.
    #[command(hide = true)]
    Db(RemovedCommandArgs),
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
    /// Loopback URL of the local Casework session that the generated BReg
    /// review authority calls; match the session's --casework-port.
    #[arg(long, value_name = "URL", default_value = source_add::DEFAULT_CASEWORK_ENDPOINT)]
    casework_endpoint: String,
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
    /// Closed Base Registry Engine (BReg) package whose rederived registry
    /// revision must equal the pinned sourceRevision of a BReg source; verified
    /// by bregctl.
    #[arg(long, value_name = "DIRECTORY")]
    against_breg_package: Option<PathBuf>,
    /// BReg source to compare with the package; required when the project
    /// declares more than one.
    #[arg(long, value_name = "ID", requires = "against_breg_package")]
    source_id: Option<String>,
    /// bregctl binary of the same release that verifies the package.
    #[arg(long, env = "BREGCTL_BIN", default_value = "bregctl")]
    bregctl_bin: PathBuf,
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
    /// Report the same packageDigest and files a package would produce, without writing one.
    #[arg(long, conflicts_with = "output", required_unless_present = "output")]
    dry_run: bool,
    /// Free-text revision recorded in the package's REVISION file and covered by its digest.
    #[arg(long, value_name = "TEXT")]
    revision: Option<String>,
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
struct ActivationArgs {
    /// Absolute runtime configuration selecting the package and the database.
    #[arg(long, value_name = "FILE")]
    runtime_config: PathBuf,
}

#[derive(Debug, Args)]
struct ApplyArgs {
    #[command(flatten)]
    activation: ActivationArgs,
    /// Change or ticket reference for this activation; recorded and audited
    /// only as a keyed hash, never as the text given.
    #[arg(long, value_name = "TEXT", value_parser = parse_operator_reference)]
    operator_reference: Option<String>,
    /// Backup or snapshot reference recorded with this activation. Repeatable.
    #[arg(long = "backup", value_name = "REF", value_parser = parse_backup_reference)]
    backups: Vec<String>,
}

fn parse_operator_reference(value: &str) -> Result<String, String> {
    registry_casework::validate_operator_reference(value).map(|()| value.to_owned())
}

fn parse_backup_reference(value: &str) -> Result<String, String> {
    registry_casework::validate_backup_reference(value).map(|()| value.to_owned())
}

/// The uuid parser's own error quotes part of the rejected text, and a usage
/// error repeats the reason, so this one names only the flag.
fn parse_attempt_id(value: &str) -> Result<Uuid, String> {
    Uuid::parse_str(value).map_err(|_| "--attempt-id must be a UUID".to_owned())
}

/// A removed command keeps its name only to refuse it and name the
/// replacement; whatever followed it is ignored.
#[derive(Debug, Args)]
struct RemovedCommandArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    arguments: Vec<OsString>,
}

const REMOVED_DB_MIGRATE_MESSAGE: &str = "caseworkctl db migrate was removed; database changes \
     are applied with a package activation: run `caseworkctl plan --runtime-config FILE` then \
     `caseworkctl apply --runtime-config FILE`";

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
    #[arg(long, value_name = "UUID", value_parser = parse_attempt_id)]
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
    #[arg(long, value_name = "UUID", value_parser = parse_attempt_id)]
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
use report::{OPERATIONAL_FAILURE_EXIT, USAGE_EXIT};
/// The next step for a command line clap refused.
const USAGE_ACTION: &str =
    "Run caseworkctl --help, or the command with --help, and retry with the documented arguments.";
const CLI_API_VERSION: &str = "registry.registrystack.org/caseworkctl/v1alpha3";

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
            let message = report::usage_message(&error);
            if machine_mode {
                write_usage_report("usage.invalid", message, USAGE_ACTION, stdout, stderr);
            } else {
                let _ = writeln!(stderr, "error: {message}\n  next: {USAGE_ACTION}");
            }
            return ExitCode::from(USAGE_EXIT);
        }
    };
    if let Some((code, message, action)) = usage_refusal(&cli.command) {
        if machine_mode {
            write_usage_report(code, message, action, stdout, stderr);
        } else {
            let _ = writeln!(stderr, "error: {message}");
        }
        return ExitCode::from(2);
    }
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
        Ok(report) if report_kind == "PlanReport" && report["ok"] == false => {
            // A plan that names a refusal is the evidence and the refusal at
            // once: the report goes to stdout and the exit code signals it.
            let report = machine_report(format, report_kind, report, DOMAIN_REFUSAL_EXIT);
            if format == OutputFormat::Human {
                let _ = render_human(&report, stdout);
            }
            write_failure(&report, format, stdout, stderr);
            ExitCode::from(DOMAIN_REFUSAL_EXIT)
        }
        Ok(report) => write_success(
            &machine_report(format, report_kind, report, 0),
            format,
            stdout,
            stderr,
        ),
        Err(error) => {
            if let Some(report) = configuration_report(&error) {
                write_configuration_report(report, format, report_kind, stdout, stderr);
                return ExitCode::from(DOMAIN_REFUSAL_EXIT);
            }
            if let Some((exit, diagnostics)) = activation_failure(&error) {
                write_failure(
                    &machine_report(
                        format,
                        report_kind,
                        json!({"ok":false,"diagnostics":diagnostics}),
                        exit,
                    ),
                    format,
                    stdout,
                    stderr,
                );
                return ExitCode::from(exit);
            }
            if let Some(denied) = error.downcast_ref::<project::DeniedFindings>() {
                write_failure(
                    &machine_report(
                        format,
                        report_kind,
                        json!({"ok":false,"command":"check","diagnostics":denied.0}),
                        DOMAIN_REFUSAL_EXIT,
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
                    exit,
                ),
                format,
                stdout,
                stderr,
            );
            ExitCode::from(exit)
        }
    }
}

fn write_usage_report(
    code: &str,
    message: String,
    action: &str,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) {
    write_failure(
        &json_report(
            "UsageReport",
            json!({"ok":false,"command":"usage","diagnostics":[diagnostic(
                code, "arguments", message, action
            )]}),
            USAGE_EXIT,
        ),
        OutputFormat::Json,
        stdout,
        stderr,
    );
}

/// A usage refusal clap cannot express: a removed command, or a repeatable
/// flag given more often than its bound.
fn usage_refusal(command: &Command) -> Option<(&'static str, String, &'static str)> {
    match command {
        Command::Db(_) => Some((
            "usage.removed-command",
            REMOVED_DB_MIGRATE_MESSAGE.to_owned(),
            "Run caseworkctl plan --runtime-config FILE, then caseworkctl apply --runtime-config FILE.",
        )),
        Command::Apply(args) if args.backups.len() > registry_casework::MAX_BACKUP_REFERENCES => {
            Some((
                "usage.invalid",
                format!(
                    "--backup may be given at most {} times",
                    registry_casework::MAX_BACKUP_REFERENCES
                ),
                "Correct the command arguments and retry.",
            ))
        }
        _ => None,
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

fn machine_report(format: OutputFormat, kind: &'static str, report: Value, exit: u8) -> Value {
    if format == OutputFormat::Json {
        json_report(kind, report, exit)
    } else {
        report
    }
}

/// Complete a command's report into the shared envelope: `ok` agrees with
/// the exit code, `command` names the command path, and `status` names what
/// happened. A report that carries its own status keeps it; a plan that
/// names a refusal is `refused`; a failure without a report of its own is
/// named by its exit class.
fn json_report(kind: &'static str, mut report: Value, exit: u8) -> Value {
    report["ok"] = json!(exit == 0);
    if report.get("command").is_none() {
        report["command"] = json!(report_command(kind));
    }
    if report.get("status").is_none() {
        let status = match exit {
            0 if kind == "TestReport" => "passed",
            0 => "complete",
            _ if kind == "PlanReport" && report.get("refusals").is_some() => "refused",
            exit => report::failure_status(exit),
        };
        report["status"] = json!(status);
    }
    cli_report_envelope(kind, report)
}

/// The command path each report kind names, as its schema pins it.
fn report_command(kind: &str) -> &'static str {
    match kind {
        "AttemptSettlementReport" => "attempt settle",
        "AttemptUncertainMarkingReport" => "attempt mark-uncertain",
        "CheckReport" => "check",
        "PlanReport" => "plan",
        "ApplyReport" => "apply",
        "StatusReport" => "status",
        "DoctorReport" => "doctor",
        "ExplainReport" => "explain",
        "InitReport" => "init",
        "LifecycleReport" => "lifecycle",
        "PackageReport" => "package",
        "RetentionEraseReport" => "retention erase",
        "SimulationReport" => "simulate",
        "SourceAddReport" => "source add",
        "TestReport" => "test",
        "DevReport" => "dev",
        "DevEventsReport" => "dev events",
        "DevGrantReport" => "dev grant",
        "DevIdentityReport" => "dev identity",
        "DevTokenReport" => "dev token",
        "UsageReport" => "usage",
        other => unreachable!("{other} is not a caseworkctl report kind"),
    }
}

fn cli_report_kind(command: &Command) -> &'static str {
    match command {
        Command::Attempt(args) => match args.command {
            AttemptCommand::Settle(_) => "AttemptSettlementReport",
            AttemptCommand::MarkUncertain(_) => "AttemptUncertainMarkingReport",
        },
        Command::Check(_) => "CheckReport",
        Command::Plan(_) => "PlanReport",
        Command::Apply(_) => "ApplyReport",
        Command::Status(_) => "StatusReport",
        Command::Db(_) => "UsageReport",
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
    Activation,
}

fn command_kind(command: &Command) -> CommandKind {
    if matches!(command, Command::Retention(_)) {
        return CommandKind::Retention;
    }
    if matches!(
        command,
        Command::Plan(_) | Command::Apply(_) | Command::Status(_)
    ) {
        return CommandKind::Activation;
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
    if let Some(check) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<project::DoctorCheckFailure>())
    {
        return (
            OPERATIONAL_FAILURE_EXIT,
            json!({
                "severity":"error", "code":"casework.doctor.check-failed",
                "artifact":"runtime_dependency", "path":format!("doctor:/checks/{}", check.check),
                "message":check.message, "suggestedAction":check.action
            }),
        );
    }
    // A development-session cause is named only from its allowlisted class;
    // the chain text beside it may carry absolute paths or a supervisor cause.
    if let Some(failure) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<dev::DevFailure>())
    {
        let (code, path, message, action) = failure.diagnostic();
        return (
            OPERATIONAL_FAILURE_EXIT,
            json!({
                "severity":"error", "code":code, "artifact":"dev_session", "path":path,
                "message":message, "suggestedAction":action
            }),
        );
    }
    let runtime_error = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<RuntimeConfigError>());
    let io_failure = error.chain().any(|cause| cause.is::<std::io::Error>())
        || matches!(
            runtime_error,
            Some(RuntimeConfigError::Load(load))
                if load.kind() == RuntimeConfigErrorKind::Unavailable
        );
    let runtime_dependency_unavailable = matches!(runtime_error, Some(RuntimeConfigError::Oidc));
    let domain = !io_failure
        && !runtime_dependency_unavailable
        && (runtime_error.is_some() || matches!(kind, CommandKind::Authoring));
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
    } else if let Some(runtime) = runtime_error {
        runtime_diagnostic_location(runtime)
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
    } else if let Some(runtime) = runtime_error {
        runtime.to_string()
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
                "retention".to_owned(),
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
                "attempt".to_owned(),
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
                    | AttemptSettlementError::ItemCannotBecomeUncertain(_)
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
                "attempt".to_owned(),
                marking.to_string(),
                action,
            )
        }
        CommandKind::Activation => {
            // An activation refusal carries its own diagnostics; this arm
            // names only a runtime role that cannot read the activation
            // ledger and a source binding the adapters could not be built
            // from. A database that cannot be reached stays an operational
            // failure.
            if let Some(store @ StoreError::LedgerUnreadable { .. }) = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<StoreError>())
            {
                return Some(json!({
                    "severity": "error",
                    "code": "casework.activation.ledger-unreadable",
                    "artifact": "operator_action",
                    "path": "runtime.yaml:/database/runtimeUrlRef",
                    "message": store.to_string(),
                    "suggestedAction": "Run caseworkctl apply --runtime-config FILE with the \
                        migration credential so it grants the runtime role its privileges, then \
                        run caseworkctl plan --runtime-config FILE again.",
                }));
            }
            let runtime = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<registry_casework::RuntimeError>())?;
            let registry_casework::RuntimeError::SourceConfiguration(source_id) = runtime else {
                return None;
            };
            (
                "casework.activation.source-binding-invalid",
                format!("runtime.yaml:/sources/{source_id}"),
                runtime.to_string(),
                "Correct the operator source binding named by the refusal so it matches casework.yaml, then plan again.",
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

/// The diagnostics for an activation `apply` refused: one per refusal, each
/// with the fix for its code. An audit destination that refused an entry is
/// an operational failure, and so is an activation that committed while its
/// response entry was refused; that one says the package is active.
fn activation_failure(error: &anyhow::Error) -> Option<(u8, Value)> {
    let activation = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<registry_casework::ActivationError>())?;
    let (code, message, action) = match activation {
        registry_casework::ActivationError::Refused(refusals) => {
            return Some((
                DOMAIN_REFUSAL_EXIT,
                Value::from(activation_refusal_diagnostics(refusals)),
            ));
        }
        registry_casework::ActivationError::Store(StoreError::AuditUnavailable) => (
            "casework.activation.audit-unavailable",
            "The Casework audit destination did not accept an activation entry, so the \
             package was not applied."
                .to_owned(),
            "Restore the audit destination named at runtime.yaml:/audit, then apply again.",
        ),
        registry_casework::ActivationError::Store(_) => return None,
        registry_casework::ActivationError::AppliedUnaudited { .. } => (
            "casework.activation.applied-unaudited",
            activation.to_string(),
            "The package is active, so do not apply it again. Restore the audit destination \
             and record the activation named by caseworkctl status in the audit trail.",
        ),
    };
    Some((
        OPERATIONAL_FAILURE_EXIT,
        json!([{
            "severity": "error",
            "code": code,
            "artifact": "runtime_dependency",
            "path": "runtime.yaml:/audit",
            "message": message,
            "suggestedAction": action,
        }]),
    ))
}

/// A plan is a refusal when it names anything apply would refuse, except
/// that the candidate is already the active package: that plan reports
/// `changesPending: false` and exits successfully.
fn plan_is_refusal(refusals: &[registry_casework::ActivationRefusal]) -> bool {
    refusals
        .iter()
        .any(|refusal| refusal.code != "casework.activation.already-active")
}

fn activation_refusal_diagnostics(refusals: &[registry_casework::ActivationRefusal]) -> Vec<Value> {
    refusals
        .iter()
        .map(|refusal| {
            let action = match refusal
                .code
                .strip_prefix("casework.activation.")
                .unwrap_or_default()
            {
                "already-active" => {
                    "Nothing needs applying; change the package or its runtime bindings \
                     before applying again."
                }
                "attempt-pending" => {
                    "Recover or settle the named source's pending attempts, then plan again."
                }
                "database-id-mismatch" => {
                    "Point database.runtimeUrlRef and database.migrationUrlRef at the database \
                     this configuration belongs to, or correct identity.databaseId, then plan \
                     again."
                }
                "hosted-work-would-be-dropped" => {
                    "Keep this database with the release that wrote it until its hosted work \
                     is exported, then apply this release to a fresh Casework database."
                }
                "role-mode-weakened" => {
                    "Run the statements the refusal names as the migration role so the \
                     runtime role owns no Casework object, cannot create one or attach a \
                     trigger, and no trigger outside the Casework migrations remains, then \
                     run caseworkctl apply --runtime-config FILE after a REASSIGN, or rerun \
                     the refused command otherwise."
                }
                "schema-newer" => {
                    "Run the casework release that migrated this database or a later one; \
                     Casework does not migrate a schema down."
                }
                "stranded-work" => {
                    "Keep the earlier package active until the named work finishes, or, once \
                     you accept that it stays hidden or orphaned, set \
                     package.acknowledgeStrandedWork to the digest the refusal names, then \
                     plan again."
                }
                "template-changed" => {
                    "Give the changed task template a new version in casework.yaml, then \
                     package and plan again."
                }
                "template-too-large" => {
                    "Shrink the named task template below the size bound, then package and \
                     plan again."
                }
                "unpublished-audit-would-be-dropped" => {
                    "Run the casework release that wrote these audit records until its audit \
                     publisher has published every one, then apply again."
                }
                _ => "Correct what the refusal names, then plan again.",
            };
            json!({
                "severity": "error",
                "code": refusal.code,
                "artifact": "operator_action",
                "path": refusal.path,
                "message": refusal.message,
                "suggestedAction": action,
            })
        })
        .collect()
}

fn runtime_diagnostic_location(error: &RuntimeConfigError) -> (&'static str, String, &'static str) {
    let removed_key = match error {
        RuntimeConfigError::Load(load) if load.kind() == RuntimeConfigErrorKind::RemovedKey => {
            Some(load.field())
        }
        _ => None,
    };
    let path = if let Some(field) = removed_key {
        format!("runtime.yaml:/{}", field.replace('.', "/"))
    } else if error.path() == "/" {
        "runtime.yaml".to_owned()
    } else {
        format!("runtime.yaml:/{}", error.path().trim_start_matches('/'))
    };
    if matches!(error, RuntimeConfigError::AllowedClientsRequired) {
        return (
            "runtime_configuration",
            path,
            "List every client identifier this deployment admits in authentication.oidc.allowedClients, then retry.",
        );
    }
    let action = match removed_key {
        Some("authentication.oidc.principalClaim") => {
            "Remove authentication.oidc.principalClaim and configure accessProfiles[].principalClaim in casework.yaml."
        }
        Some("authentication.oidc.jwksUri") => {
            "Replace authentication.oidc.jwksUri with authentication.oidc.jwksSource, kind: uri, and the same https URL as uri."
        }
        _ => "Correct the named runtime configuration field, then retry.",
    };
    ("runtime_configuration", path, action)
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
        OutputFormat::Json => report::write(report, stdout),
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
        let _ = report::write(report, stdout);
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

/// The reader's report when a command refused a configuration file.
fn configuration_report(error: &anyhow::Error) -> Option<&Report> {
    error
        .chain()
        .find_map(|cause| match cause.downcast_ref::<ConfigLoadError>() {
            Some(ConfigLoadError::Refused(report)) => Some(report),
            _ => cause.downcast_ref::<Report>(),
        })
}

/// Print a configuration refusal unchanged: the CFG-DIAG-2 lines on stderr,
/// or, with `--format json`, the CFG-DIAG-1 diagnostics in the report
/// envelope on stdout.
fn write_configuration_report(
    report: &Report,
    format: OutputFormat,
    report_kind: &'static str,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) {
    if format == OutputFormat::Json {
        let envelope = json_report(
            report_kind,
            json!({"ok": false, "diagnostics": report.to_json_value()}),
            DOMAIN_REFUSAL_EXIT,
        );
        let _ = report::write(&envelope, stdout);
    } else {
        let _ = write!(stderr, "{}", report.render_human());
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
    if report["ok"] == false {
        writeln!(stdout, "{command} refused.")?;
    } else if lead.is_empty() {
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
        Command::Check(args) => project::check(&args.project, args.production, args.deny_findings)
            .and_then(|report| match &args.against_breg_package {
                Some(package) => breg_package::compare(
                    &args.project,
                    package,
                    args.source_id.as_deref(),
                    &args.bregctl_bin,
                    report,
                ),
                None => Ok(report),
            }),
        Command::Explain(args) => project::explain(&args.project),
        Command::Lifecycle => lifecycle::lifecycle(),
        Command::Package(args) => match args.output {
            Some(output) => project::package(&args.project, &output, args.revision.as_deref()),
            None => project::package_dry_run(&args.project, args.revision.as_deref()),
        },
        Command::Simulate(args) => project::simulate(&args.project, &args.fixture),
        Command::Test(args) => project::test(&args.project),
        Command::Doctor(args) => project::doctor(&args.runtime_config),
        Command::Plan(args) => project::plan(&args.runtime_config),
        Command::Apply(args) => project::apply(
            &args.activation.runtime_config,
            args.operator_reference,
            args.backups,
        ),
        Command::Status(args) => project::status(&args.runtime_config),
        Command::Db(_) => unreachable!("the removed command is refused before run"),
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
    use registry_casework::RuntimeConfig;
    use std::fs;

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
        let root = crate::canonical_tempdir();
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
        let root = crate::canonical_tempdir();
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
        let root = crate::canonical_tempdir();
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

    /// Run `caseworkctl check PROJECT`, in JSON when `json` is set, and
    /// return the exit code, stdout, and stderr.
    fn check_project(project: &std::path::Path, json: bool) -> (ExitCode, String, String) {
        let mut arguments = vec![OsString::from("caseworkctl")];
        if json {
            arguments.push(OsString::from("--format=json"));
        }
        arguments.extend([OsString::from("check"), project.as_os_str().to_owned()]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(arguments, &mut stdout, &mut stderr);
        (
            exit,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    /// Write the standalone template with `edit` applied and return the
    /// project, its casework.yaml, and the edited text.
    fn edited_standalone(
        root: &std::path::Path,
        edit: impl FnOnce(&str) -> String,
    ) -> (PathBuf, PathBuf, String) {
        let project = root.join("standalone");
        project::init(&project, "standalone-decision").unwrap();
        let policy_path = project.join("casework.yaml");
        let original = std::fs::read_to_string(&policy_path).unwrap();
        let edited = edit(&original);
        assert_ne!(edited, original);
        std::fs::write(&policy_path, &edited).unwrap();
        (project, policy_path, edited)
    }

    fn line_of(text: &str, line: &str) -> u64 {
        u64::try_from(
            text.lines()
                .position(|candidate| candidate == line)
                .unwrap()
                + 1,
        )
        .unwrap()
    }

    #[test]
    fn check_refuses_an_environment_expression_in_the_authored_project() {
        let root = crate::canonical_tempdir();
        let (project, policy_path, edited) = edited_standalone(root.path(), |text| {
            text.replace(
                "    label: Decisions awaiting review\n",
                "    label: \"${QUEUE_LABEL}\"\n",
            )
        });
        let line = line_of(&edited, "    label: \"${QUEUE_LABEL}\"");

        let (exit, stdout, stderr) = check_project(&project, true);
        assert_eq!(exit, ExitCode::from(1));
        assert!(stderr.is_empty());
        let report: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(report["ok"], false);
        assert_eq!(report["command"], "check");
        let diagnostics = report["diagnostics"].as_array().unwrap();
        assert_eq!(diagnostics.len(), 1, "{report:#}");
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic["code"], "config.substitution-not-allowed");
        assert_eq!(diagnostic["artifact"], "CaseworkProject");
        assert_eq!(diagnostic["path"], "/queues/0/label");
        assert_eq!(
            diagnostic["source"],
            json!({"file": policy_path.display().to_string(), "line": line, "column": 12})
        );
        assert!(diagnostic["suggestedAction"]
            .as_str()
            .is_some_and(|action| action.contains("in casework.yaml directly")));
        assert!(!stdout.contains("QUEUE_LABEL"), "{stdout}");

        let (exit, stdout, stderr) = check_project(&project, false);
        assert_eq!(exit, ExitCode::from(1));
        assert!(stdout.is_empty());
        assert!(
            stderr.starts_with(&format!(
                "error[config.substitution-not-allowed] {}:{line}:12 /queues/0/label\n",
                policy_path.display()
            )),
            "{stderr}"
        );
        assert!(
            stderr.ends_with("1 error, 0 warnings in 1 file\n"),
            "{stderr}"
        );
        assert!(!stderr.contains("QUEUE_LABEL"), "{stderr}");
    }

    /// The check prints the reader's report unchanged: every semantic
    /// finding at its position, with the place it relates to.
    #[test]
    fn review_connection_retention_diagnostic_names_the_incompatible_pair() {
        let root = crate::canonical_tempdir();
        let (project, policy_path, edited) = edited_standalone(root.path(), |text| {
            text.replace("    recoveryDays: 30\n", "    recoveryDays: 91\n")
        });
        let file = policy_path.display().to_string();
        let line = line_of(&edited, "    recoveryDays: 91");
        let related_line = line_of(&edited, "      terminalDays: 90");

        let (exit, stdout, stderr) = check_project(&project, true);
        assert_eq!(exit, ExitCode::from(1));
        assert!(stderr.is_empty());
        let report: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(
            report["diagnostics"],
            json!([{
                "severity": "error",
                "code": "casework.review-producer.recovery-exceeds-retention",
                "artifact": "CaseworkProject",
                "path": "/reviewProducers/0/recoveryDays",
                "message": "recoveryDays is longer than the result retention of a review kind this producer submits",
                "suggestedAction": "Make recoveryDays no longer than that review kind's retention.terminalDays.",
                "source": {"file": file, "line": line, "column": 19},
                "related": [{
                    "file": file,
                    "line": related_line,
                    "column": 21,
                    "path": "/reviewKinds/0/retention/terminalDays",
                    "message": "terminalDays is written here"
                }]
            }])
        );

        let (exit, stdout, stderr) = check_project(&project, false);
        assert_eq!(exit, ExitCode::from(1));
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            format!(
                "error[casework.review-producer.recovery-exceeds-retention] {file}:{line}:19 /reviewProducers/0/recoveryDays
  recoveryDays is longer than the result retention of a review kind this producer submits
  next: Make recoveryDays no longer than that review kind's retention.terminalDays.
  note: {file}:{related_line}:21 /reviewKinds/0/retention/terminalDays terminalDays is written here
1 error, 0 warnings in 1 file
"
            )
        );
    }

    #[test]
    fn operational_failures_follow_the_selected_output_channel() {
        let root = crate::canonical_tempdir();
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
        let root = crate::canonical_tempdir();
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
    fn removed_runtime_keys_name_the_replacement_path_and_action() {
        let root = crate::canonical_tempdir();
        let runtime_config = root.path().join("runtime.yaml");
        for (removed, path, replacement) in [
            (
                "principalClaim: sub",
                "runtime.yaml:/authentication/oidc/principalClaim",
                "accessProfiles[].principalClaim",
            ),
            (
                "jwksUri: https://issuer.example/jwks",
                "runtime.yaml:/authentication/oidc/jwksUri",
                "authentication.oidc.jwksSource",
            ),
        ] {
            fs::write(
                &runtime_config,
                format!(
                    "apiVersion: {}\nkind: {}\nauthentication:\n  oidc:\n    {removed}\n",
                    registry_casework::RUNTIME_CONFIG_API_VERSION,
                    registry_casework::RUNTIME_CONFIG_KIND,
                ),
            )
            .unwrap();
            let error = anyhow::Error::new(RuntimeConfig::load(&runtime_config).unwrap_err());
            let (exit, diagnostic) = classify_failure(CommandKind::Operational, &error);
            assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
            assert_eq!(diagnostic["code"], "casework.runtime-configuration.invalid");
            assert_eq!(diagnostic["path"], path);
            assert!(
                diagnostic["suggestedAction"]
                    .as_str()
                    .unwrap()
                    .contains(replacement),
                "{diagnostic}"
            );
        }
    }

    #[test]
    fn a_production_runtime_without_allowed_clients_names_the_field_to_fill() {
        let error = anyhow::Error::new(RuntimeConfigError::AllowedClientsRequired);
        let (exit, diagnostic) = classify_failure(CommandKind::Operational, &error);

        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(diagnostic["code"], "casework.runtime-configuration.invalid");
        assert_eq!(
            diagnostic["path"],
            "runtime.yaml:/authentication.oidc.allowedClients"
        );
        assert!(
            diagnostic["suggestedAction"]
                .as_str()
                .unwrap()
                .contains("List every client identifier"),
            "{diagnostic}"
        );
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

    fn run_args(arguments: &[&str]) -> (ExitCode, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(
            std::iter::once("caseworkctl").chain(arguments.iter().copied()),
            &mut stdout,
            &mut stderr,
        );
        (
            exit,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    #[test]
    fn the_removed_db_migrate_command_refuses_as_usage_naming_plan_then_apply() {
        for arguments in [
            &["db", "migrate", "."][..],
            &["db", "migrate", ".", "--runtime-config", "runtime.yaml"][..],
            &["db"][..],
        ] {
            let (exit, stdout, stderr) = run_args(arguments);
            assert_eq!(exit, ExitCode::from(2), "{arguments:?}: {stderr}");
            assert!(stdout.is_empty(), "{stdout}");
            assert!(
                stderr.contains(
                    "run `caseworkctl plan --runtime-config FILE` then \
                     `caseworkctl apply --runtime-config FILE`"
                ),
                "{stderr}"
            );
        }

        let (exit, stdout, stderr) = run_args(&["--format", "json", "db", "migrate", "."]);
        assert_eq!(exit, ExitCode::from(2));
        assert!(stderr.is_empty(), "{stderr}");
        let report: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(report["kind"], "UsageReport");
        assert_eq!(report["ok"], false);
        assert_eq!(report["diagnostics"][0]["code"], "usage.removed-command");
        assert_eq!(report["diagnostics"][0]["path"], "arguments");
        assert!(report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .starts_with("caseworkctl db migrate was removed"));
    }

    #[test]
    fn the_removed_db_command_is_hidden_from_help() {
        let help = Cli::command().render_help().to_string();
        assert!(!help.contains("\n  db "), "{help}");
        for command in ["plan", "apply", "status"] {
            assert!(help.contains(&format!("\n  {command} ")), "{help}");
        }
    }

    #[test]
    fn a_usage_error_never_repeats_a_rejected_argument_value() {
        let sentinel = "sentinel-7f3a9c";
        let rejected = format!("{sentinel}\n");
        let unknown = format!("--operator-reference={sentinel}");
        let refusals: [&[&str]; 2] = [
            &[
                "apply",
                "--runtime-config",
                "runtime.yaml",
                "--operator-reference",
                &rejected,
            ],
            &["check", "project", &unknown],
        ];
        for arguments in refusals {
            for format in ["human", "json"] {
                let mut all = vec!["--format", format];
                all.extend_from_slice(arguments);
                let (exit, stdout, stderr) = run_args(&all);
                assert_eq!(exit, ExitCode::from(2), "{stdout}{stderr}");
                assert!(
                    !stdout.contains(sentinel) && !stderr.contains(sentinel),
                    "{stdout}{stderr}"
                );
                assert!(
                    stdout.contains("--operator-reference")
                        || stderr.contains("--operator-reference"),
                    "{stdout}{stderr}"
                );
                assert!(
                    stdout.contains("--help") || stderr.contains("--help"),
                    "{stdout}{stderr}"
                );
            }
        }
    }

    #[test]
    fn a_validator_reason_survives_as_the_usage_message() {
        let sentinel = "sentinel-7f3a9c";
        let mut settle = attempt_settle_arguments();
        settle.remove(0);
        let settle = replace_argument(settle, "--attempt-id", sentinel);
        let refusals: [(&[&str], &str); 2] = [
            (
                &["apply", "--runtime-config", "runtime.yaml", "--backup", ""],
                "--backup must not be empty",
            ),
            (&settle, "--attempt-id must be a UUID"),
        ];
        for (arguments, reason) in refusals {
            for format in ["human", "json"] {
                let mut all = vec!["--format", format];
                all.extend_from_slice(arguments);
                let (exit, stdout, stderr) = run_args(&all);
                assert_eq!(exit, ExitCode::from(2), "{stdout}{stderr}");
                assert!(
                    stdout.contains(reason) || stderr.contains(reason),
                    "{reason}: {stdout}{stderr}"
                );
                assert!(
                    !stdout.contains(sentinel) && !stderr.contains(sentinel),
                    "{stdout}{stderr}"
                );
            }
        }
    }

    #[test]
    fn apply_bounds_its_operator_references_as_usage_errors() {
        let long = "r".repeat(registry_casework::MAX_OPERATOR_REFERENCE_BYTES + 1);
        for reference in ["", "change\n42", long.as_str()] {
            let (exit, _, stderr) = run_args(&[
                "apply",
                "--runtime-config",
                "runtime.yaml",
                "--operator-reference",
                reference,
            ]);
            assert_eq!(exit, ExitCode::from(2), "{reference:?}: {stderr}");
            assert!(stderr.contains("--operator-reference"), "{stderr}");
        }
        let (exit, _, stderr) =
            run_args(&["apply", "--runtime-config", "runtime.yaml", "--backup", ""]);
        assert_eq!(exit, ExitCode::from(2), "{stderr}");
        assert!(stderr.contains("--backup must not be empty"), "{stderr}");

        let mut arguments = vec!["apply", "--runtime-config", "runtime.yaml"];
        for _ in 0..=registry_casework::MAX_BACKUP_REFERENCES {
            arguments.extend(["--backup", "snapshot"]);
        }
        let (exit, _, stderr) = run_args(&arguments);
        assert_eq!(exit, ExitCode::from(2), "{stderr}");
        assert!(
            stderr.contains("--backup may be given at most 16 times"),
            "{stderr}"
        );
    }

    fn refusal(code: &str) -> registry_casework::ActivationRefusal {
        registry_casework::ActivationRefusal {
            code: format!("casework.activation.{code}"),
            path: "database".to_owned(),
            message: format!("{code} message"),
        }
    }

    #[test]
    fn every_activation_refusal_is_its_own_diagnostic_with_a_next_action() {
        let codes = [
            "already-active",
            "attempt-pending",
            "database-id-mismatch",
            "hosted-work-would-be-dropped",
            "role-mode-weakened",
            "schema-newer",
            "stranded-work",
            "template-changed",
            "template-too-large",
            "unpublished-audit-would-be-dropped",
        ];
        let refusals: Vec<_> = codes.iter().map(|code| refusal(code)).collect();
        let diagnostics = activation_refusal_diagnostics(&refusals);
        assert_eq!(diagnostics.len(), codes.len());
        let mut actions = std::collections::BTreeSet::new();
        for (diagnostic, code) in diagnostics.iter().zip(codes) {
            assert_eq!(diagnostic["code"], format!("casework.activation.{code}"));
            assert_eq!(diagnostic["artifact"], "operator_action");
            assert_eq!(diagnostic["path"], "database");
            assert_eq!(diagnostic["message"], format!("{code} message"));
            let action = diagnostic["suggestedAction"].as_str().unwrap();
            assert!(!action.is_empty(), "{code}");
            actions.insert(action.to_owned());
        }
        assert_eq!(actions.len(), codes.len(), "each refusal names its own fix");

        let error = anyhow::Error::new(registry_casework::ActivationError::Refused(vec![
            refusal("database-id-mismatch"),
            refusal("stranded-work"),
        ]))
        .context("applying the Casework package");
        let (exit, report) = activation_failure(&error).expect("an activation refusal");
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(report.as_array().unwrap().len(), 2);

        let failed = anyhow::Error::new(registry_casework::ActivationError::Store(
            StoreError::Unavailable,
        ));
        assert!(activation_failure(&failed).is_none());
        let (exit, diagnostic) = classify_failure(CommandKind::Activation, &failed);
        assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
        assert_eq!(
            diagnostic["message"],
            "A Casework runtime dependency check failed."
        );
    }

    #[test]
    fn an_activation_audit_failure_is_operational_and_an_unaudited_commit_says_it_applied() {
        let refused = anyhow::Error::new(registry_casework::ActivationError::Store(
            StoreError::AuditUnavailable,
        ))
        .context("applying the Casework package");
        let (exit, report) = activation_failure(&refused).expect("an audit failure");
        assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
        assert_eq!(report[0]["code"], "casework.activation.audit-unavailable");
        assert_eq!(report[0]["path"], "runtime.yaml:/audit");
        assert!(report[0]["message"]
            .as_str()
            .unwrap()
            .contains("the package was not applied"));

        let digest = format!("sha256:{}", "a".repeat(64));
        let unaudited = anyhow::Error::new(registry_casework::ActivationError::AppliedUnaudited {
            activation_id: uuid::Uuid::nil(),
            package_digest: digest.clone(),
        })
        .context("applying the Casework package");
        let (exit, report) = activation_failure(&unaudited).expect("an unaudited activation");
        assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
        assert_eq!(report[0]["code"], "casework.activation.applied-unaudited");
        let message = report[0]["message"].as_str().unwrap();
        assert!(
            message.contains(&digest) && message.contains("is active"),
            "{message}"
        );
        assert!(report[0]["suggestedAction"]
            .as_str()
            .unwrap()
            .contains("do not apply it again"));
    }

    #[test]
    fn a_plan_naming_a_refusal_is_a_refusal_unless_the_package_is_already_active() {
        assert!(!plan_is_refusal(&[]));
        assert!(!plan_is_refusal(&[refusal("already-active")]));
        assert!(plan_is_refusal(&[refusal("database-id-mismatch")]));
        assert!(plan_is_refusal(&[
            refusal("already-active"),
            refusal("stranded-work")
        ]));
    }

    #[test]
    fn a_plan_whose_runtime_role_cannot_read_the_ledger_is_a_refusal_naming_apply() {
        let error = anyhow::Error::new(StoreError::LedgerUnreadable {
            schema: "casework".to_owned(),
        })
        .context("planning the Casework package activation");
        let (exit, diagnostic) = classify_failure(CommandKind::Activation, &error);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(diagnostic["code"], "casework.activation.ledger-unreadable");
        assert_eq!(diagnostic["path"], "runtime.yaml:/database/runtimeUrlRef");
        assert_eq!(
            diagnostic["message"],
            "the Casework runtime role cannot read the activation ledger in schema casework; run `caseworkctl apply --runtime-config FILE` to grant the runtime role its privileges, then rerun `caseworkctl plan --runtime-config FILE`"
        );
        assert_eq!(
            diagnostic["suggestedAction"],
            "Run caseworkctl apply --runtime-config FILE with the migration credential so it grants the runtime role its privileges, then run caseworkctl plan --runtime-config FILE again."
        );
    }

    #[test]
    fn an_invalid_source_binding_is_a_domain_refusal_naming_the_source() {
        let error = anyhow::Error::new(registry_casework::RuntimeError::SourceConfiguration(
            "registry".to_owned(),
        ))
        .context("building the Casework source adapters");
        let (exit, diagnostic) = classify_failure(CommandKind::Activation, &error);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(
            diagnostic["code"],
            "casework.activation.source-binding-invalid"
        );
        assert_eq!(diagnostic["path"], "runtime.yaml:/sources/registry");
        assert_eq!(
            diagnostic["message"],
            "the Casework source binding for source registry is invalid"
        );
    }

    #[test]
    fn doctor_names_the_check_that_failed_instead_of_a_generic_dependency_failure() {
        let doctor = command_kind(
            &Cli::try_parse_from(["caseworkctl", "doctor", "--runtime-config", "runtime.yaml"])
                .unwrap()
                .command,
        );
        let unmigrated = project::doctor_dependency_failure(
            "database",
            "the Casework runtime database is not ready".to_owned(),
            "Run caseworkctl plan --runtime-config FILE, then caseworkctl apply --runtime-config FILE, then retry.",
            anyhow::Error::new(StoreError::SchemaNotCurrent {
                applied: None,
                required: 17,
            })
            .context("checking the database"),
        );
        let (exit, diagnostic) = classify_failure(doctor, &unmigrated);
        assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
        assert_eq!(diagnostic["code"], "casework.doctor.check-failed");
        assert_eq!(diagnostic["artifact"], "runtime_dependency");
        assert_eq!(diagnostic["path"], "doctor:/checks/database");
        assert_eq!(
            diagnostic["message"],
            "the Casework runtime database is not ready: the Casework database schema is not current: no migration has been applied, and this binary requires version 17; run `caseworkctl plan --runtime-config FILE` then `caseworkctl apply --runtime-config FILE`"
        );
        assert_eq!(
            diagnostic["suggestedAction"],
            "Run caseworkctl plan --runtime-config FILE, then caseworkctl apply --runtime-config FILE, then retry."
        );

        // A cause outside the closed set of Casework errors is never echoed:
        // it may carry a connection string or a response body.
        let opaque = project::doctor_dependency_failure(
            "sourceConnections",
            "source registry did not answer the reader readiness check".to_owned(),
            "Check the source binding, then retry.",
            anyhow::anyhow!("postgresql://user:do-not-echo@db.example.test/casework"),
        );
        let (_, diagnostic) = classify_failure(doctor, &opaque);
        assert_eq!(diagnostic["path"], "doctor:/checks/sourceConnections");
        assert_eq!(
            diagnostic["message"],
            "source registry did not answer the reader readiness check"
        );

        // A BReg engine from another release is named with the lock-step
        // action instead of the generic connection advice.
        let mismatch = project::source_readiness_failure(
            "registry",
            Some("BReg source registry runs engine version 0.0.1 and this Casework runs 0.0.2. Casework and BReg run in lock-step, so upgrade both to the same release".to_owned()),
            anyhow::Error::new(registry_casework_core::SourceAdapterError::Unavailable),
        );
        let (exit, diagnostic) = classify_failure(doctor, &mismatch);
        assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
        assert_eq!(diagnostic["path"], "doctor:/checks/sourceConnections");
        assert!(diagnostic["message"]
            .as_str()
            .is_some_and(|message| message.contains("0.0.1") && message.contains("0.0.2")));
        assert!(diagnostic["suggestedAction"]
            .as_str()
            .is_some_and(|action| action.contains("same release")));
        let unmatched = project::source_readiness_failure(
            "registry",
            None,
            anyhow::Error::new(registry_casework_core::SourceAdapterError::Unavailable),
        );
        let (_, diagnostic) = classify_failure(doctor, &unmatched);
        assert_eq!(
            diagnostic["message"],
            "source registry did not pass the reader readiness check: the source is temporarily unavailable"
        );

        // A typed configuration refusal keeps its precise location.
        let typed = project::doctor_dependency_failure(
            "configuration",
            "the Casework runtime configuration is invalid".to_owned(),
            "Correct the configuration, then retry.",
            anyhow::Error::new(RuntimeConfigError::Oidc),
        );
        let (_, diagnostic) = classify_failure(doctor, &typed);
        assert_eq!(
            diagnostic["code"],
            "casework.runtime-dependency.unavailable"
        );
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
    fn settling_and_marking_uncertain_name_their_own_action_for_an_item_in_the_wrong_state() {
        let settle = anyhow::Error::new(AttemptSettlementError::ItemNotSynchronizing("open"))
            .context("settling the Casework source attempt");
        let (exit, diagnostic) = classify_failure(CommandKind::AttemptSettlement, &settle);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(diagnostic["code"], "casework.attempt-settlement.refused");
        assert_eq!(
            diagnostic["message"],
            "the work item is open; only a work item awaiting its source outcome can be settled"
        );

        let mark = anyhow::Error::new(AttemptSettlementError::ItemCannotBecomeUncertain("open"))
            .context("marking the Casework source attempt uncertain");
        let (exit, diagnostic) = classify_failure(CommandKind::AttemptUncertainMarking, &mark);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(
            diagnostic["code"],
            "casework.attempt-mark-uncertain.refused"
        );
        assert_eq!(
            diagnostic["message"],
            "the work item is open; only a work item awaiting its source outcome can have its \
             attempt marked uncertain"
        );
        assert_eq!(
            diagnostic["suggestedAction"],
            "Confirm the attempt, then preview the marking again."
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
    fn package_help_says_what_the_verb_means_beside_bregctl_package() {
        let error = Cli::try_parse_from(["caseworkctl", "package", "--help"]).unwrap_err();
        let help = error.to_string();
        for expected in [
            "caseworkctl plan and apply activate",
            "bregctl package is a different verb",
        ] {
            assert!(help.contains(expected), "missing help text: {expected}");
        }
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

/// A temporary directory under the canonical system temporary root. The
/// runtime configuration loader refuses a path through a symbolic link, and
/// the system temporary root is one on some hosts.
#[cfg(test)]
pub(crate) fn canonical_tempdir() -> tempfile::TempDir {
    let root = std::fs::canonicalize(std::env::temp_dir()).expect("canonical temporary root");
    tempfile::tempdir_in(root).expect("temporary directory")
}
