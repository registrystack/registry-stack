// SPDX-License-Identifier: Apache-2.0

mod policy;
mod project;
mod source_add;

use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_casework::RuntimeConfigError;
use registry_casework_core::{
    AttemptSettlement, AttemptSettlementOutcome, ConfigError, ConfigLoadError,
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
    /// New directory for the verified policy package.
    #[arg(long, value_name = "DIRECTORY")]
    output: PathBuf,
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

const DOMAIN_REFUSAL_EXIT: u8 = 1;
const OPERATIONAL_FAILURE_EXIT: u8 = 3;

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
                    &json!({"ok":false,"command":"usage","diagnostics":[diagnostic(
                        "usage.invalid", "arguments", error.to_string(), "Correct the command arguments and retry."
                    )]}),
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
    let format = cli.format;
    let command_kind = command_kind(&cli.command);
    match run(cli) {
        Ok(report) => write_success(&report, format, stdout, stderr),
        Err(error) => {
            if let Some(denied) = error.downcast_ref::<project::DeniedFindings>() {
                write_failure(
                    &json!({"ok":false,"command":"check","diagnostics":denied.0}),
                    format,
                    stdout,
                    stderr,
                );
                return ExitCode::from(DOMAIN_REFUSAL_EXIT);
            }
            let (exit, diagnostic) = classify_failure(command_kind, &error);
            write_failure(
                &json!({"ok":false,"diagnostics":[diagnostic]}),
                format,
                stdout,
                stderr,
            );
            ExitCode::from(exit)
        }
    }
}

#[derive(Clone, Copy)]
enum CommandKind {
    Authoring,
    Operational,
}

fn command_kind(command: &Command) -> CommandKind {
    if matches!(
        command,
        Command::Doctor(_)
            | Command::Db(_)
            | Command::Retention(_)
            | Command::Attempt(_)
            | Command::Dev(_)
    ) {
        CommandKind::Operational
    } else {
        CommandKind::Authoring
    }
}

fn classify_failure(kind: CommandKind, error: &anyhow::Error) -> (u8, Value) {
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
        "The Casework command was refused because an authored input did not satisfy its contract."
            .to_owned()
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
        ConfigError::HostedKinds => (
            "casework_project",
            "casework.yaml:/hostedKinds",
            "Correct the hosted kind or its access-profile references.",
        ),
        ConfigError::NoConfiguredWork => (
            "casework_project",
            "casework.yaml:/sources",
            "Declare a source or hosted kind.",
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
        Command::Package(args) => project::package(&args.project, &args.output),
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
        },
        Command::Dev(args) => match args.command {
            DevCommand::Start(args) => {
                project::dev_start(&args.project, args.runtime_config.as_deref())
            }
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
