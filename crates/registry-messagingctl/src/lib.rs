// SPDX-License-Identifier: Apache-2.0

//! `messagingctl`, the Registry Messaging adopter and local operator
//! tooling.
//!
//! - `init` writes a starter authoring project and runtime example.
//! - `check` loads a package, or a runtime configuration and the package it
//!   names, exactly as `messaging serve` would, offline: no secret is
//!   resolved, no database is reached, and no signing key is fetched. It
//!   reports the package digest and renders every template's sample.
//! - `preview` renders one template version with given data, offline, and
//!   in JSON prints the exact bytes the runtime's preview route answers.
//! - `plan` reads the configured package, activation ledger, schema, and
//!   runtime role without writing; `apply` performs that activation with
//!   migration authority; `status` reads the resulting history with the
//!   runtime credential.
//! - `messages list` and `messages show` read accepted messages with the
//!   recipient masked; `messages retry`, `settle`, and `cancel` report what
//!   the action would do to one message, and with `--apply` do it. Each
//!   applied action writes its audit request and outcome directly to the
//!   `messagingctl` companion stream beside the runtime's audit
//!   destination.
//! - `retention erase-expired` reports what the configured retention
//!   periods say had expired by `--before`, and with `--apply` erases it,
//!   with the migration credential. A cutoff in the future is refused.
//! - `dev` runs the package in the foreground against PostgreSQL and Mailpit
//!   in Docker and a mock HTTP gateway, with the runtime in this process,
//!   and removes its containers on Ctrl-C; `dev token` writes a bearer
//!   header file for a client an access profile names.
//!
//! Exit codes: 0 when the command succeeds, 1 when the configuration,
//! package, preview, message action, or retention cutoff is refused, 2 for a usage error, and
//! 3 when a file, secret, database, or audit destination could not be
//! reached, a change's commit or audit outcome could not be confirmed, or
//! the report could not be written.
//!
//! With `--format json` every report opens with `ok`, `command`, and
//! `status`, in that order. `status` is `complete` for a success unless the
//! report names its own, such as `ready` for a development session, and
//! `domain-refusal`, `usage-error`, or `operational-failure` by exit class
//! for a failure, whose `diagnostics` each name a `suggestedAction`. A
//! successful `preview` is the one exception: it prints the exact bytes the
//! runtime's preview route answers.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_messaging::activation::{ActivationError, ActivationRefusal, ApplyRequest};
use registry_messaging::config::{
    check_runtime_file, startup_report, CheckedAgainst, RuntimeCheck, RuntimeConfig,
    RuntimeConfigError,
};
use registry_messaging::http::preview_json;
use registry_messaging::messages::{
    MessageReader, MessageStoreError, OperatorAction, OperatorActionReport, SettleOutcome,
};
use registry_messaging::package::{
    load_package, load_project, package_inputs, plan_package_inputs, write_package_inputs,
    LoadedPackage, PackageLoadError,
};
use registry_messaging::retention::RetentionError;
use registry_messaging::runtime::{
    activation_plan, activation_status, apply_activation, erase_expired_as_operator,
    message_reader, message_store, RuntimeError,
};
use registry_messaging_core::{
    ContentRefusal, MessageDispatch, MessageStatus, ProblemCode, TemplatePreviewRequest,
    MESSAGING_PROJECT_KIND, MESSAGING_RUNTIME_KIND,
};
use registry_platform_yaml::{Diagnostic, Report, Source};
use serde_json::{json, Value};
use uuid::Uuid;

#[cfg(test)]
mod cli_contract_tests;
mod dev;
mod report;
mod starter;

use report::{DOMAIN_REFUSAL_EXIT, OPERATIONAL_FAILURE_EXIT, USAGE_EXIT};

#[derive(Debug, Parser)]
#[command(
    name = "messagingctl",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Registry Messaging adopter and local operator tooling"
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
    /// Write a starter authoring project and runtime example.
    Init(InitArgs),
    /// Build an immutable runtime package from an editable project.
    Package(PackageArgs),
    /// Check an authoring project, installed package, or runtime configuration.
    Check(CheckArgs),
    /// Render one template version with the given data, offline.
    Preview(PreviewArgs),
    /// Report what activating the configured package would change, without writing.
    Plan(ActivationArgs),
    /// Apply schema changes and record the configured package as active.
    Apply(ApplyArgs),
    /// Report the active package, activation history, schema, and role mode.
    Status(ActivationArgs),
    /// Read accepted messages, and retry, settle, or cancel one.
    #[command(subcommand)]
    Messages(MessagesCommand),
    /// Erase what the retention periods say has expired.
    #[command(subcommand)]
    Retention(RetentionCommand),
    /// Run an authoring project locally with PostgreSQL, Mailpit, and a mock HTTP
    /// gateway in Docker, until Ctrl-C.
    Dev(dev::DevArgs),
}

#[derive(Debug, Subcommand)]
enum RetentionCommand {
    /// Report what had expired by --before, and erase it with --apply.
    EraseExpired(EraseExpiredArgs),
}

#[derive(Debug, Args)]
struct EraseExpiredArgs {
    /// Absolute path to the runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
    /// The RFC 3339 instant every retention period is counted back from. It
    /// must not be in the future.
    #[arg(long, value_name = "RFC3339", value_parser = parse_cutoff)]
    before: chrono::DateTime<chrono::Utc>,
    /// Erase. Without it, only report what would be erased.
    #[arg(long)]
    apply: bool,
}

fn parse_cutoff(value: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|instant| instant.with_timezone(&chrono::Utc))
        .map_err(|_| "expected an RFC 3339 instant such as 2026-09-01T00:00:00Z".to_owned())
}

#[derive(Debug, Subcommand)]
enum MessagesCommand {
    /// List messages, newest first, with the recipient never shown.
    List(ListArgs),
    /// Show one message with its recipient masked, and its attempts.
    Show(MessageArgs),
    /// Queue a failed message again under a new generation, with --apply.
    Retry(ActionArgs),
    /// Settle a message whose outcome is unknown, with --apply.
    Settle(SettleArgs),
    /// Cancel a queued message, with --apply.
    Cancel(ActionArgs),
}

#[derive(Debug, Args)]
struct ListArgs {
    /// Absolute path to the runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
    /// Only messages with this status.
    #[arg(long, value_enum, value_name = "STATUS")]
    status: Option<StatusFilter>,
    /// The most messages to list.
    #[arg(long, value_name = "COUNT", default_value_t = 50,
          value_parser = clap::value_parser!(i64).range(1..=MAXIMUM_LIST_LIMIT))]
    limit: i64,
}

#[derive(Debug, Args)]
struct MessageArgs {
    /// Absolute path to the runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
    /// The message id the runtime returned on acceptance.
    #[arg(value_name = "MESSAGE_ID", value_parser = parse_message_id)]
    message: Uuid,
}

/// Parse a message id without repeating the refused value in the reason.
fn parse_message_id(value: &str) -> Result<Uuid, String> {
    Uuid::parse_str(value).map_err(|_| "expected a UUID".to_owned())
}

#[derive(Debug, Args)]
struct ActionArgs {
    #[command(flatten)]
    target: MessageArgs,
    /// Change the message. Without it, only report what would change.
    #[arg(long)]
    apply: bool,
}

#[derive(Debug, Args)]
struct SettleArgs {
    #[command(flatten)]
    action: ActionArgs,
    /// Whether the provider took the message: sent makes it submitted,
    /// not-sent queues it again under a new generation.
    #[arg(long, value_enum, value_name = "OUTCOME")]
    outcome: SettleArg,
}

/// A message status `messages list` filters on.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum StatusFilter {
    Queued,
    Sending,
    Submitted,
    Delivered,
    Failed,
    Expired,
    Cancelled,
    Unknown,
}

impl From<StatusFilter> for MessageStatus {
    fn from(filter: StatusFilter) -> Self {
        match filter {
            StatusFilter::Queued => Self::Queued,
            StatusFilter::Sending => Self::Sending,
            StatusFilter::Submitted => Self::Submitted,
            StatusFilter::Delivered => Self::Delivered,
            StatusFilter::Failed => Self::Failed,
            StatusFilter::Expired => Self::Expired,
            StatusFilter::Cancelled => Self::Cancelled,
            StatusFilter::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SettleArg {
    Sent,
    NotSent,
}

#[derive(Debug, Args)]
struct InitArgs {
    /// The directory to create. It must not exist.
    #[arg(value_name = "DIRECTORY")]
    directory: PathBuf,
}

#[derive(Debug, Args)]
struct PackageArgs {
    /// Editable Messaging project to package.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// New directory to create for the installed package.
    #[arg(long, value_name = "DIRECTORY")]
    output: PathBuf,
    /// Optional source revision recorded in the package envelope.
    #[arg(long, value_name = "REVISION")]
    revision: Option<String>,
    /// Validate and report the digest without writing the package.
    #[arg(long)]
    dry_run: bool,
}

/// Where a command reads the package from: a package directory, or the
/// runtime configuration that names one and may pin its digest.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("source").required(true).multiple(false)))]
struct PackageSource {
    /// Absolute path to the runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE", group = "source")]
    runtime_config: Option<PathBuf>,
    /// The package directory holding messaging.yaml.
    #[arg(long, value_name = "DIRECTORY", group = "source")]
    package: Option<PathBuf>,
    /// Editable authoring project holding messaging.yaml.
    #[arg(long, value_name = "DIRECTORY", group = "source")]
    project: Option<PathBuf>,
}

/// What `check` reads: a runtime configuration, a package or authoring
/// project, or a runtime configuration together with the package or
/// project it is checked against.
#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("checked")
        .required(true)
        .multiple(true)
        .args(["runtime_config", "package", "project"])
))]
struct CheckArgs {
    /// The runtime configuration file, checked offline against the package
    /// --package or --project names, or else the one its package.root names.
    #[arg(long, value_name = "FILE")]
    runtime_config: Option<PathBuf>,
    /// The package directory holding messaging.yaml.
    #[arg(long, value_name = "DIRECTORY", conflicts_with = "project")]
    package: Option<PathBuf>,
    /// Editable authoring project holding messaging.yaml.
    #[arg(long, value_name = "DIRECTORY")]
    project: Option<PathBuf>,
    /// Fill ${NAME} expressions in the runtime configuration from the
    /// environment and check every value; without it each expression is
    /// checked by its syntax and position only.
    #[arg(long, requires = "runtime_config")]
    environment: bool,
    /// Refuse the check when it reports a warning.
    #[arg(long)]
    deny_warnings: bool,
}

#[derive(Debug, Args)]
struct PreviewArgs {
    #[command(flatten)]
    source: PackageSource,
    /// The template id.
    #[arg(value_name = "TEMPLATE")]
    template: String,
    /// The template version.
    #[arg(value_name = "VERSION")]
    version: String,
    /// A locale the template version declares.
    #[arg(long, value_name = "LOCALE")]
    locale: String,
    /// A JSON file holding the template data.
    #[arg(long, value_name = "FILE")]
    data: PathBuf,
}

#[derive(Debug, Args)]
struct ApplyArgs {
    #[command(flatten)]
    activation: ActivationArgs,
    /// Change or ticket reference; stored only as an activation-scoped keyed hash.
    #[arg(long, value_name = "TEXT")]
    operator_reference: Option<String>,
    /// Backup or snapshot reference recorded with this activation. Repeatable.
    #[arg(long = "backup", value_name = "REF")]
    backups: Vec<String>,
}

#[derive(Debug, Args)]
struct ActivationArgs {
    /// Absolute path to the runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

/// The largest template data file `preview` reads.
const MAXIMUM_DATA_BYTES: u64 = 1024 * 1024;

/// The most messages one `messages list` reports.
const MAXIMUM_LIST_LIMIT: i64 = 500;

/// The clap command tree, for the generated CLI reference.
#[must_use]
pub fn command() -> clap::Command {
    Cli::command()
}

pub fn main_entry() -> ExitCode {
    main_entry_from(
        std::env::args_os(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}

/// One command's result: the report, its exit code, and how a person reads
/// it. `raw_json`, when set, is printed in JSON mode instead of the report.
struct Outcome {
    report: Value,
    exit: u8,
    view: View,
    raw_json: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
enum View {
    Init,
    Package,
    Check,
    /// A refusal whose diagnostics carry their positions, printed as the
    /// shared human report (CFG-DIAG-2).
    Diagnostics,
    Preview,
    Activation,
    MessageList,
    MessageShow,
    MessageAction,
    Retention,
    Dev,
    DevToken,
}

impl Outcome {
    fn new(report: Value, view: View) -> Self {
        Self {
            report,
            exit: 0,
            view,
            raw_json: None,
        }
    }

    fn refused(exit: u8, code: &str, path: &str, message: String) -> Self {
        let (artifact, action) = guidance(code, exit);
        Self {
            report: json!({
                "ok": false,
                "diagnostics": [{
                    "severity": "error",
                    "code": code,
                    "artifact": artifact,
                    "path": path,
                    "message": message,
                    "suggestedAction": action,
                }]
            }),
            exit,
            view: View::Check,
            raw_json: None,
        }
    }

    /// A refusal reporting every diagnostic in `report`. A diagnostic that
    /// names no artifact is about the runtime configuration.
    fn diagnosed(exit: u8, report: &Report) -> Self {
        let mut diagnostics = report.to_json_value();
        for diagnostic in diagnostics.as_array_mut().into_iter().flatten() {
            if diagnostic.get("artifact").is_none() {
                diagnostic["artifact"] = json!(MESSAGING_RUNTIME_KIND);
            }
        }
        let mut refused = json!({"ok": false, "diagnostics": diagnostics});
        if let Some(files) = report.files_checked() {
            refused["filesChecked"] = json!(files);
        }
        Self {
            report: refused,
            exit,
            view: View::Diagnostics,
            raw_json: None,
        }
    }
}

/// The next step for a command line clap refused.
const USAGE_ACTION: &str =
    "Run messagingctl --help, or the command with --help, and retry with the documented arguments.";

/// The artifact a refusal is about and the next step it suggests, by its
/// problem code, and by its exit class for a code without its own.
fn guidance(code: &str, exit: u8) -> (&'static str, &'static str) {
    match code {
        "usage.invalid" => ("command_arguments", USAGE_ACTION),
        "init.exists" => (
            "filesystem",
            "Name a directory that does not exist yet, then rerun messagingctl init.",
        ),
        "init.write-failed" => (
            "filesystem",
            "Make the parent directory writable, then rerun messagingctl init.",
        ),
        "package.refused" => (
            "package_output",
            "Correct the --output directory as the message names, then rerun messagingctl package.",
        ),
        "config.refused" if exit == OPERATIONAL_FAILURE_EXIT => (
            "runtime_configuration",
            "Restore the file or secret the message names, then retry.",
        ),
        "config.refused" => (
            "runtime_configuration",
            "Correct the member the path names, then rerun messagingctl check.",
        ),
        "data.unreadable" => (
            "template_data",
            "Make the --data file readable, then rerun messagingctl preview.",
        ),
        "data.invalid" => (
            "template_data",
            "Correct the --data file as the message names, then rerun messagingctl preview.",
        ),
        "runtime.unavailable" | "output.failed" => (
            "runtime_dependency",
            "Retry the command; if it fails again, report the message.",
        ),
        "package.outcome-unknown" => (
            "database",
            "Run messagingctl status to see which activation the ledger records before applying again.",
        ),
        "audit.unconfirmed" => (
            "audit",
            "Do not apply the change again; restore the audit destination.",
        ),
        "audit.unavailable" => (
            "audit",
            "Restore the audit destination, then retry; nothing was changed.",
        ),
        "messagingctl.activation.not-activated"
        | "messagingctl.activation.package-not-active"
        | "messagingctl.activation.grants-stale" => (
            "database_activation",
            "Run messagingctl plan with the runtime configuration, then apply with the migration credential.",
        ),
        "messagingctl.activation.database-id-mismatch" => (
            "database_activation",
            "Use the database belonging to this deployment, or restore the configured deployment identity.",
        ),
        "messagingctl.activation.role-mode-weakened" => (
            "database_activation",
            "Restore the split-role ownership and grants, then rerun messagingctl plan.",
        ),
        "messagingctl.activation.ledger-unreadable" => (
            "database_activation",
            "Restore the runtime credential's read access to the activation ledger, then retry.",
        ),
        "messagingctl.activation.schema-newer" => (
            "database_activation",
            "Use the Messaging release that owns the recorded schema version.",
        ),
        "messagingctl.activation.schema-invalid" => (
            "database_activation",
            "Restore a database whose migration history is an ordered prefix of this Messaging release.",
        ),
        "messagingctl.activation.invalid-reference" => (
            "command_arguments",
            "Correct the operator or backup reference bounds, then retry.",
        ),
        "database.unavailable" => (
            "database",
            "Restore the database or the credential the message names, then retry.",
        ),
        "retention.future-cutoff" => (
            "command_arguments",
            "Pass a --before instant that is not in the future.",
        ),
        "retention.outcome-unknown" => (
            "database",
            "Run the same command without --apply to preview what is still due.",
        ),
        "message.not-found" => (
            "message",
            "Find the message id with messagingctl messages list.",
        ),
        "message.not-eligible" | "message.dispatch-started" => (
            "message",
            "Run messagingctl messages show MESSAGE_ID and take the action its dispatch state \
             allows.",
        ),
        "message.changed" | "message.outcome-unknown" => (
            "message",
            "Run messagingctl messages show MESSAGE_ID before acting again.",
        ),
        "dev.refused" => (
            "dev_session",
            "Correct the project or request the message names, then retry.",
        ),
        "dev.failed" | "dev.interrupted" => (
            "dev_session",
            "Restore Docker or the file the message names, then rerun messagingctl dev.",
        ),
        _ if exit == OPERATIONAL_FAILURE_EXIT => (
            "runtime_dependency",
            "Restore the file, secret, database, or service the message names, then retry.",
        ),
        _ => (
            "messaging_package",
            "Correct the template, locale, or data the message names, then retry.",
        ),
    }
}

/// Complete a command's own report into the shared envelope: `ok` agrees
/// with the exit code, `command` names the subcommand path, and `status`
/// keeps a report's own status or names what happened by exit class.
fn completed(report: &Value, command: &str, exit: u8) -> Value {
    assert!(
        exit == 0
            || report["diagnostics"]
                .as_array()
                .is_some_and(|diagnostics| !diagnostics.is_empty()),
        "a failed {command} report carries diagnostics"
    );
    let mut report = report.clone();
    report["ok"] = json!(exit == 0);
    report["command"] = json!(command);
    if report.get("status").is_none() {
        report["status"] = json!(if exit == 0 {
            "complete"
        } else {
            report::failure_status(exit)
        });
    }
    report
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
            return match write!(stdout, "{error}") {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::from(OPERATIONAL_FAILURE_EXIT),
            };
        }
        Err(error) => {
            let message = report::usage_message(&error);
            if machine_mode {
                let outcome = Outcome::refused(USAGE_EXIT, "usage.invalid", "arguments", message);
                return finish(&outcome, "usage", OutputFormat::Json, stdout, stderr);
            }
            // The exit code carries the refusal even when this line cannot
            // be written.
            let _ = writeln!(stderr, "error: {message}\n  next: {USAGE_ACTION}");
            return ExitCode::from(USAGE_EXIT);
        }
    };
    let command = command_path(&cli.command);
    let outcome = match cli.command {
        Command::Dev(args) => return dev::run(args, cli.format, stdout, stderr),
        Command::Init(args) => init(&args.directory),
        Command::Package(args) => package(&args),
        Command::Check(args) => check(&args),
        Command::Preview(args) => preview(&args),
        Command::Plan(args) => plan(&args.runtime_config),
        Command::Apply(args) => apply(&args),
        Command::Status(args) => status(&args.runtime_config),
        Command::Messages(command) => messages(&command),
        Command::Retention(RetentionCommand::EraseExpired(args)) => erase_expired(&args),
    };
    finish(&outcome, command, cli.format, stdout, stderr)
}

/// The subcommand path a parsed invocation selected, as its report names it.
fn command_path(command: &Command) -> &'static str {
    match command {
        Command::Init(_) => "init",
        Command::Package(_) => "package",
        Command::Check(_) => "check",
        Command::Preview(_) => "preview",
        Command::Plan(_) => "plan",
        Command::Apply(_) => "apply",
        Command::Status(_) => "status",
        Command::Messages(MessagesCommand::List(_)) => "messages list",
        Command::Messages(MessagesCommand::Show(_)) => "messages show",
        Command::Messages(MessagesCommand::Retry(_)) => "messages retry",
        Command::Messages(MessagesCommand::Settle(_)) => "messages settle",
        Command::Messages(MessagesCommand::Cancel(_)) => "messages cancel",
        Command::Retention(RetentionCommand::EraseExpired(_)) => "retention erase-expired",
        Command::Dev(args) => dev::command_path(args),
    }
}

fn package(args: &PackageArgs) -> Outcome {
    let inputs = match package_inputs(&args.project) {
        Ok(inputs) => inputs,
        Err(error) => return package_refusal(&args.project, &error),
    };
    let digest = if args.dry_run {
        match plan_package_inputs(&args.project, &inputs, args.revision.as_deref()) {
            Ok(digest) => digest,
            Err(error) => {
                return Outcome::refused(
                    DOMAIN_REFUSAL_EXIT,
                    "package.refused",
                    "--output",
                    error.to_string(),
                )
            }
        }
    } else {
        match write_package_inputs(&args.output, &inputs, args.revision.as_deref()) {
            Ok(package) => package.digest().to_owned(),
            Err(error) => {
                return Outcome::refused(
                    DOMAIN_REFUSAL_EXIT,
                    "package.refused",
                    "--output",
                    error.to_string(),
                )
            }
        }
    };
    Outcome::new(
        json!({
            "ok": true,
            "project": args.project,
            "output": args.output,
            "dryRun": args.dry_run,
            "revision": args.revision,
            "projectDigest": digest,
            "projectFiles": inputs.len(),
        }),
        View::Package,
    )
}

fn init(directory: &Path) -> Outcome {
    match starter::write(directory) {
        Ok(created) => Outcome::new(
            json!({
                "ok": true,
                "directory": directory,
                "created": created,
                "next": [
                    "Run messagingctl check --project DIRECTORY, then messagingctl dev DIRECTORY to run it locally against PostgreSQL and Mailpit containers.",
                    "Run messagingctl package DIRECTORY --output PACKAGE, point runtime.yaml at PACKAGE, run messagingctl plan, then messagingctl apply, then messaging serve.",
                ],
            }),
            View::Init,
        ),
        Err(starter::InitError::Exists) => Outcome::refused(
            DOMAIN_REFUSAL_EXIT,
            "init.exists",
            "/",
            "the directory already exists; init never overwrites".to_owned(),
        ),
        Err(starter::InitError::Io(error)) => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "init.write-failed",
            "/",
            format!("the starter could not be written: {error}"),
        ),
    }
}

/// Load the package as `messaging serve` does: from the runtime
/// configuration, which also verifies a pinned digest and the admitted
/// clients, or from a bare package directory.
fn load(source: &PackageSource) -> Result<(Option<RuntimeConfig>, LoadedPackage), Outcome> {
    match (&source.runtime_config, &source.package, &source.project) {
        (Some(path), _, _) => {
            let config = load_runtime(path)?;
            let package = config
                .load_package()
                .map_err(|error| config_refusal(&error))?;
            Ok((Some(config), package))
        }
        (None, Some(root), _) => load_package(root)
            .map(|package| (None, package))
            .map_err(|error| package_refusal(root, &error)),
        (None, None, Some(root)) => load_project(root)
            .map(|package| (None, package))
            .map_err(|error| package_refusal(root, &error)),
        (None, None, None) => Err(Outcome::refused(
            USAGE_EXIT,
            "usage.invalid",
            "/",
            "name --runtime-config, --package, or --project".to_owned(),
        )),
    }
}

/// The refusal of a package or authoring project under `root` that could
/// not be read, or was read and refused: every diagnostic its files hold,
/// or the one file it could not read as a package.
fn package_refusal(root: &Path, error: &PackageLoadError) -> Outcome {
    let exit = if error.is_read_failure() {
        OPERATIONAL_FAILURE_EXIT
    } else {
        DOMAIN_REFUSAL_EXIT
    };
    Outcome::diagnosed(exit, &package_load_report(root, error))
}

/// The diagnostics of a package load refusal. A file the loader refused as
/// a package, rather than for what it holds, is named with no position.
fn package_load_report(root: &Path, error: &PackageLoadError) -> Report {
    if let Some(report) = error.report() {
        return report.clone();
    }
    let exit = if error.is_read_failure() {
        OPERATIONAL_FAILURE_EXIT
    } else {
        DOMAIN_REFUSAL_EXIT
    };
    let (_, action) = guidance("config.refused", exit);
    let mut diagnostic = Diagnostic::error("config.refused", "", error.to_string(), action);
    diagnostic.artifact = Some(MESSAGING_PROJECT_KIND.to_owned());
    diagnostic.source = Some(Source {
        file: root.join(error.path()).display().to_string(),
        line: None,
        column: None,
    });
    Report::new(vec![diagnostic])
}

/// Read the runtime file at `path` as `messaging serve` does. A refusal of
/// the file itself reports every rule it breaks, each at its position.
fn load_runtime(path: &Path) -> Result<RuntimeConfig, Outcome> {
    RuntimeConfig::load(path).map_err(|error| match startup_report(path, &error) {
        Some(report) => Outcome::diagnosed(refusal_exit(&error), &report),
        None => config_refusal(&error),
    })
}

/// The exit class of a refused runtime configuration: an operational
/// failure when a file it needs could not be read at all.
fn refusal_exit(error: &RuntimeConfigError) -> u8 {
    match error {
        RuntimeConfigError::Load(error)
            if error.diagnostics().iter().any(|diagnostic| {
                diagnostic.code == registry_messaging::config::RUNTIME_CONFIG_UNAVAILABLE_CODE
            }) =>
        {
            OPERATIONAL_FAILURE_EXIT
        }
        RuntimeConfigError::Package(error) if error.is_read_failure() => OPERATIONAL_FAILURE_EXIT,
        _ => DOMAIN_REFUSAL_EXIT,
    }
}

/// The refusal of a runtime configuration, or of the package or dependency
/// it names, by its own code at the member it concerns.
fn config_refusal(error: &RuntimeConfigError) -> Outcome {
    let report = match error {
        RuntimeConfigError::Load(error) => Report::new(error.diagnostics().to_vec()),
        RuntimeConfigError::Package(package) if package.report().is_some() => {
            package.report().cloned().unwrap_or_default()
        }
        _ => Report::new(vec![Diagnostic::error(
            error.code(),
            error.pointer(),
            error.to_string(),
            error.suggested_action(),
        )]),
    };
    Outcome::diagnosed(refusal_exit(error), &report)
}

/// Check a runtime configuration offline (CFG-CHECK-1), a package, or an
/// authoring project, and report what the runtime would serve, rendering
/// each template's sample in every locale it declares.
fn check(args: &CheckArgs) -> Outcome {
    let given = match (&args.package, &args.project) {
        (Some(root), _) => Some((root, load_package(root))),
        (None, Some(root)) => Some((root, load_project(root))),
        (None, None) => None,
    };
    let Some(path) = &args.runtime_config else {
        return match given {
            Some((root, Ok(loaded))) => {
                let warnings = loaded.warnings();
                if args.deny_warnings && warnings.warning_count() > 0 {
                    return Outcome::diagnosed(DOMAIN_REFUSAL_EXIT, warnings);
                }
                match package_report(&loaded) {
                    Ok(mut report) => {
                        report["project"] = json!(root);
                        report["filesChecked"] = json!(warnings.files_checked());
                        report["diagnostics"] = warnings.to_json_value();
                        Outcome::new(report, View::Check)
                    }
                    Err(refused) => refused,
                }
            }
            Some((root, Err(error))) => package_refusal(root, &error),
            None => Outcome::refused(
                USAGE_EXIT,
                "usage.invalid",
                "arguments",
                "name --runtime-config, --package, or --project".to_owned(),
            ),
        };
    };
    let (given, mut refused) = match given {
        Some((root, Ok(loaded))) => (Some((root, loaded)), None),
        Some((root, Err(error))) => (None, Some(package_refusal(root, &error))),
        None => (None, None),
    };
    let absolute = match std::path::absolute(path) {
        Ok(absolute) => absolute,
        Err(_) => {
            return Outcome::refused(
                OPERATIONAL_FAILURE_EXIT,
                "config.refused",
                "arguments",
                "the --runtime-config path could not be resolved against the working directory"
                    .to_owned(),
            )
        }
    };
    let against = match (&given, &refused) {
        (Some((_, loaded)), _) => CheckedAgainst::Package(loaded),
        (None, Some(_)) => CheckedAgainst::Nothing,
        (None, None) => CheckedAgainst::NamedPackage,
    };
    let runtime = check_runtime_file(&absolute, against, args.environment);
    let report = runtime_report(path, &absolute, &runtime);
    let denied = report.has_errors() || (args.deny_warnings && report.warning_count() > 0);
    if let Some(mut refused) = refused.take() {
        let exit = if runtime.unavailable {
            OPERATIONAL_FAILURE_EXIT
        } else {
            refused.exit
        };
        if let (Some(diagnostics), Value::Array(more)) = (
            refused.report["diagnostics"].as_array_mut(),
            Outcome::diagnosed(exit, &report).report["diagnostics"].take(),
        ) {
            diagnostics.extend(more);
        }
        let package_files = refused.report["filesChecked"].as_u64().unwrap_or(0);
        refused.report["filesChecked"] =
            json!(package_files + report.files_checked().map_or(0, |files| files as u64));
        refused.exit = exit;
        refused.view = View::Diagnostics;
        return refused;
    }
    if denied {
        let exit = if runtime.unavailable {
            OPERATIONAL_FAILURE_EXIT
        } else {
            DOMAIN_REFUSAL_EXIT
        };
        return Outcome::diagnosed(exit, &report);
    }
    let package = given
        .as_ref()
        .map(|(_, loaded)| loaded)
        .or(runtime.package.as_ref());
    let mut checked = match package.map(package_report).transpose() {
        Ok(checked) => checked.unwrap_or_else(|| json!({"ok": true})),
        Err(refused) => return refused,
    };
    if let Some((root, _)) = &given {
        checked["project"] = json!(root);
    }
    checked["runtimeConfig"] = json!(path);
    checked["filesChecked"] = json!(report.files_checked());
    checked["diagnostics"] = report.to_json_value();
    if let Some(config) = runtime.config() {
        if !runtime.defers_within("/listener") {
            checked["listener"] = json!(config.listener.bind.socket_addr().to_string());
        }
        if !runtime.defers_within("/metricsListener") {
            checked["metricsListener"] = json!(config
                .metrics_listener
                .as_ref()
                .map(|metrics| metrics.bind.socket_addr().to_string()));
        }
        if !runtime.defers_within("/retention") {
            checked["retention"] = config.retention.report();
        }
    }
    Outcome::new(checked, View::Check)
}

/// The findings of an offline runtime check, each naming the file as its
/// path was given rather than as it was resolved.
fn runtime_report(given: &Path, absolute: &Path, runtime: &RuntimeCheck) -> Report {
    let given = given.display().to_string();
    let absolute = absolute.display().to_string();
    let named = |diagnostic: &Diagnostic| {
        let mut diagnostic = diagnostic.clone();
        if let Some(source) = &mut diagnostic.source {
            if source.file == absolute {
                source.file.clone_from(&given);
            }
        }
        for related in &mut diagnostic.related {
            if related.file == absolute {
                related.file.clone_from(&given);
            }
        }
        diagnostic
    };
    let mut report = Report::new(runtime.diagnostics.iter().map(named).collect());
    report.set_files_checked(runtime.files_checked);
    report
}

/// The package part of a `check` report: its digest, its templates with
/// each sample rendered in every locale, and its access profiles.
fn package_report(loaded: &LoadedPackage) -> Result<Value, Outcome> {
    let package = &loaded.package;
    let profiles: Vec<Value> = package
        .access_profiles()
        .iter()
        .map(|profile| json!({"id": profile.id, "role": profile.role}))
        .collect();
    let mut templates = Vec::new();
    for template in package.templates() {
        let mut samples = Vec::new();
        if let Some(sample) = template.sample() {
            for locale in template.locales() {
                // The package check rendered every sample in every locale, so
                // a sample that stopped rendering here is a defect to report,
                // never one to hide.
                let request = TemplatePreviewRequest {
                    locale: locale.to_owned(),
                    data: sample.clone(),
                };
                match package.preview(template.id(), template.version(), &request) {
                    Ok(preview) => samples.push(json!({"locale": locale, "sms": preview.sms})),
                    Err(refusal) => return Err(preview_refusal(&refusal)),
                }
            }
        }
        templates.push(json!({
            "id": template.id(),
            "version": template.version(),
            "channel": template.channel(),
            "locales": template.locales().collect::<Vec<_>>(),
            "samples": samples,
        }));
    }
    Ok(json!({
        "ok": true,
        "projectDigest": package.digest(),
        "projectFiles": loaded.files.len(),
        "templates": templates,
        "accessProfiles": profiles,
    }))
}

fn preview(args: &PreviewArgs) -> Outcome {
    let (_, loaded) = match load(&args.source) {
        Ok(loaded) => loaded,
        Err(refused) => return refused,
    };
    let data = match read_data(&args.data) {
        Ok(data) => data,
        Err(refused) => return refused,
    };
    let request = TemplatePreviewRequest {
        locale: args.locale.clone(),
        data,
    };
    let preview = match loaded
        .package
        .preview(&args.template, &args.version, &request)
    {
        Ok(preview) => preview,
        Err(refusal) => return preview_refusal(&refusal),
    };
    let mut bytes = match preview_json(&preview) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Outcome::refused(
                OPERATIONAL_FAILURE_EXIT,
                "output.failed",
                "/",
                format!("the preview could not be serialized: {error}"),
            )
        }
    };
    bytes.push(b'\n');
    let report = match serde_json::to_value(&preview) {
        Ok(report) => report,
        Err(error) => {
            return Outcome::refused(
                OPERATIONAL_FAILURE_EXIT,
                "output.failed",
                "/",
                format!("the preview could not be serialized: {error}"),
            )
        }
    };
    Outcome {
        report,
        exit: 0,
        view: View::Preview,
        raw_json: Some(bytes),
    }
}

fn read_data(path: &Path) -> Result<Value, Outcome> {
    let unreadable = |error: io::Error| {
        Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "data.unreadable",
            "--data",
            format!("the data file could not be read: {error}"),
        )
    };
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let mut bytes = Vec::new();
    file.take(MAXIMUM_DATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() as u64 > MAXIMUM_DATA_BYTES {
        return Err(Outcome::refused(
            DOMAIN_REFUSAL_EXIT,
            "data.invalid",
            "--data",
            format!("the data file exceeds {MAXIMUM_DATA_BYTES} bytes"),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        Outcome::refused(
            DOMAIN_REFUSAL_EXIT,
            "data.invalid",
            "--data",
            format!("the data file is not JSON: {error}"),
        )
    })
}

/// A refused render, named by its problem code. Data diagnostics carry the
/// pointer and keyword of each refused member, never a value.
fn preview_refusal(refusal: &ContentRefusal) -> Outcome {
    let mut outcome = Outcome::refused(
        DOMAIN_REFUSAL_EXIT,
        refusal.problem().code(),
        "/",
        refusal.to_string(),
    );
    if let ContentRefusal::DataInvalid {
        diagnostics,
        truncated,
    } = refusal
    {
        outcome.report["diagnostics"][0]["data"] = json!(diagnostics);
        outcome.report["diagnostics"][0]["truncated"] = json!(truncated);
    }
    outcome
}

/// A single-threaded async runtime for one database command.
fn async_runtime() -> Result<tokio::runtime::Runtime, Outcome> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            Outcome::refused(
                OPERATIONAL_FAILURE_EXIT,
                "runtime.unavailable",
                "/",
                format!("the async runtime could not start: {error}"),
            )
        })
}

fn plan(path: &Path) -> Outcome {
    let config = match load_runtime(path) {
        Ok(config) => config,
        Err(refused) => return refused,
    };
    let runtime = match async_runtime() {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    match runtime.block_on(activation_plan(&config)) {
        Ok(plan) => {
            let refused = !plan.refusals.is_empty();
            let diagnostics = activation_diagnostics(&plan.refusals);
            let report = json!({
                "ok": !refused,
                "runtimeConfig": path,
                "packageDigest": plan.package_digest,
                "activeDigest": plan.active_digest,
                "change": plan.change,
                "databaseId": plan.database_id,
                "planKind": plan.plan_kind,
                "pendingSchemaVersions": plan.pending_schema_versions,
                "runtimeRoleMode": plan.runtime_role_mode,
                "grantsCurrent": plan.grants_current,
                "refusals": plan.refusals,
                "diagnostics": diagnostics,
            });
            if refused {
                Outcome {
                    report,
                    exit: DOMAIN_REFUSAL_EXIT,
                    view: View::Activation,
                    raw_json: None,
                }
            } else {
                Outcome::new(report, View::Activation)
            }
        }
        Err(error) => apply_failure(error),
    }
}

fn apply(args: &ApplyArgs) -> Outcome {
    let path = &args.activation.runtime_config;
    let config = match load_runtime(path) {
        Ok(config) => config,
        Err(refused) => return refused,
    };
    let runtime = match async_runtime() {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    let request = ApplyRequest {
        operator_reference: args.operator_reference.clone(),
        backup_references: args.backups.clone(),
    };
    match runtime.block_on(apply_activation(&config, &request)) {
        Ok(applied) => {
            let change = if applied.recorded { "activate" } else { "none" };
            let active_digest = if applied.recorded {
                applied.activation.predecessor_package_digest.clone()
            } else {
                Some(applied.activation.package_digest.clone())
            };
            Outcome::new(
                json!({
                "ok": true,
                "runtimeConfig": path,
                "packageDigest": applied.activation.package_digest,
                "activeDigest": active_digest,
                "change": change,
                "applied": applied.recorded,
                "restartRequired": applied.recorded,
                "activation": applied.activation,
                "schemaVersionsApplied": applied.schema_versions_applied,
                }),
                View::Activation,
            )
        }
        Err(error) => apply_failure(error),
    }
}

fn status(path: &Path) -> Outcome {
    let config = match load_runtime(path) {
        Ok(config) => config,
        Err(refused) => return refused,
    };
    let runtime = match async_runtime() {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    match runtime.block_on(activation_status(&config)) {
        Ok(status) => Outcome::new(
            json!({
                "ok": true,
                "runtimeConfig": path,
                "active": status.active,
                "history": status.history,
                "schemaVersion": status.schema_version,
                "runtimeRoleMode": status.runtime_role_mode,
                "grantsCurrent": status.grants_current,
            }),
            View::Activation,
        ),
        Err(error) => apply_failure(error),
    }
}

/// The report of an `apply` that did not finish.
fn apply_failure(error: RuntimeError) -> Outcome {
    match error {
        RuntimeError::Config(error) => config_refusal(&error),
        RuntimeError::Activation(ActivationError::Refused(refusals)) => {
            activation_refused(refusals)
        }
        RuntimeError::Activation(ActivationError::NotActivated) => Outcome::refused(
            DOMAIN_REFUSAL_EXIT,
            "messagingctl.activation.not-activated",
            "database",
            error.to_string(),
        ),
        RuntimeError::Activation(ActivationError::DatabaseIdMismatch) => Outcome::refused(
            DOMAIN_REFUSAL_EXIT,
            "messagingctl.activation.database-id-mismatch",
            "identity.databaseId",
            error.to_string(),
        ),
        RuntimeError::Activation(ActivationError::PackageNotActive) => Outcome::refused(
            DOMAIN_REFUSAL_EXIT,
            "messagingctl.activation.package-not-active",
            "package",
            error.to_string(),
        ),
        RuntimeError::Activation(ActivationError::RoleModeWeakened) => Outcome::refused(
            DOMAIN_REFUSAL_EXIT,
            "messagingctl.activation.role-mode-weakened",
            "database.runtimeUrlRef",
            error.to_string(),
        ),
        RuntimeError::Activation(ActivationError::GrantsStale) => Outcome::refused(
            DOMAIN_REFUSAL_EXIT,
            "messagingctl.activation.grants-stale",
            "database.runtimeUrlRef",
            error.to_string(),
        ),
        RuntimeError::Activation(ActivationError::AppliedUnaudited { .. }) => {
            audit_unconfirmed(&error)
        }
        RuntimeError::Activation(ActivationError::OutcomeUnknown { .. }) => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "package.outcome-unknown",
            "database",
            error.to_string(),
        ),
        RuntimeError::Activation(ActivationError::Audit(_)) => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "audit.unavailable",
            "audit",
            error.to_string(),
        ),
        RuntimeError::AuditUnconfirmed { .. } => audit_unconfirmed(&error),
        RuntimeError::OutcomeUnknown { .. } => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "package.outcome-unknown",
            "database",
            format!(
                "{error}; run messagingctl status to see which activation the ledger records \
                 before applying again"
            ),
        ),
        error => database_unavailable(&error),
    }
}

fn activation_refused(refusals: Vec<ActivationRefusal>) -> Outcome {
    Outcome {
        report: json!({
            "ok": false,
            "diagnostics": activation_diagnostics(&refusals),
            "refusals": refusals,
        }),
        exit: DOMAIN_REFUSAL_EXIT,
        view: View::Activation,
        raw_json: None,
    }
}

fn activation_diagnostics(refusals: &[ActivationRefusal]) -> Vec<Value> {
    refusals
        .iter()
        .map(|refusal| {
            let (artifact, suggested_action) = guidance(refusal.code, DOMAIN_REFUSAL_EXIT);
            json!({
                "severity": "error",
                "code": refusal.code,
                "artifact": artifact,
                "path": refusal.path,
                "message": refusal.message,
                "suggestedAction": suggested_action,
            })
        })
        .collect()
}

/// A change was committed, and its audit outcome record was not written.
fn audit_unconfirmed(error: &RuntimeError) -> Outcome {
    Outcome::refused(
        OPERATIONAL_FAILURE_EXIT,
        "audit.unconfirmed",
        "audit",
        format!("{error}; do not apply it again, and restore the audit destination"),
    )
}

fn messages(command: &MessagesCommand) -> Outcome {
    let path = match command {
        MessagesCommand::List(args) => &args.runtime_config,
        MessagesCommand::Show(args) => &args.runtime_config,
        MessagesCommand::Retry(args) | MessagesCommand::Cancel(args) => &args.target.runtime_config,
        MessagesCommand::Settle(args) => &args.action.target.runtime_config,
    };
    let config = match load_runtime(path) {
        Ok(config) => config,
        Err(refused) => return refused,
    };
    let runtime = match async_runtime() {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    runtime.block_on(async {
        match command {
            MessagesCommand::List(args) => match open_message_reader(&config).await {
                Ok(reader) => list(&reader, args).await,
                Err(outcome) => outcome,
            },
            MessagesCommand::Show(args) => match open_message_reader(&config).await {
                Ok(reader) => show(&config, &reader, args.message).await,
                Err(outcome) => outcome,
            },
            MessagesCommand::Retry(args) => {
                act(&config, &args.target, OperatorAction::Retry, args.apply).await
            }
            MessagesCommand::Cancel(args) => {
                act(&config, &args.target, OperatorAction::Cancel, args.apply).await
            }
            MessagesCommand::Settle(args) => {
                let outcome = match args.outcome {
                    SettleArg::Sent => SettleOutcome::Sent,
                    SettleArg::NotSent => SettleOutcome::NotSent,
                };
                act(
                    &config,
                    &args.action.target,
                    OperatorAction::Settle(outcome),
                    args.action.apply,
                )
                .await
            }
        }
    })
}

async fn open_message_reader(config: &RuntimeConfig) -> Result<MessageReader, Outcome> {
    match message_reader(config).await {
        Ok(reader) => Ok(reader),
        Err(RuntimeError::Config(error)) => Err(config_refusal(&error)),
        Err(error) => Err(database_unavailable(&error)),
    }
}

fn future_cutoff() -> Outcome {
    Outcome::refused(
        DOMAIN_REFUSAL_EXIT,
        "retention.future-cutoff",
        "--before",
        "the cutoff is in the future; retention erases only what has already expired".to_owned(),
    )
}

/// Report, and with `--apply` erase, what had expired by the cutoff. A
/// future cutoff is refused before the configuration is read, and again
/// against the database's clock.
fn erase_expired(args: &EraseExpiredArgs) -> Outcome {
    if args.before > chrono::Utc::now() {
        return future_cutoff();
    }
    let config = match load_runtime(&args.runtime_config) {
        Ok(config) => config,
        Err(refused) => return refused,
    };
    let runtime = match async_runtime() {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    match runtime.block_on(erase_expired_as_operator(
        &config,
        args.before.into(),
        args.apply,
    )) {
        Ok(report) => Outcome::new(
            json!({
                "ok": true,
                "runtimeConfig": args.runtime_config,
                "before": report.before,
                "applied": report.applied,
                "payloads": report.payloads,
                "records": report.records,
                "submissionReceipts": report.submission_receipts,
                "retention": config.retention.report(),
            }),
            View::Retention,
        ),
        Err(error) => retention_failure(error, args.apply),
    }
}

/// The report of a retention run that did not finish. An applied run
/// erases in batches, and the batches committed before a failure stay
/// erased and journaled.
fn retention_failure(error: RuntimeError, applied: bool) -> Outcome {
    match error {
        RuntimeError::Config(error) => config_refusal(&error),
        RuntimeError::Retention(RetentionError::FutureCutoff) => future_cutoff(),
        RuntimeError::AuditUnconfirmed { .. } => audit_unconfirmed(&error),
        RuntimeError::OutcomeUnknown { .. } => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "retention.outcome-unknown",
            "database",
            format!("{error}; run the same command without --apply to preview what is still due"),
        ),
        error if applied => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "database.unavailable",
            "database",
            format!(
                "{error}; batches committed before the failure stay erased and journaled, and \
                 the next run continues from there"
            ),
        ),
        error => database_unavailable(&error),
    }
}

fn database_unavailable(error: &dyn std::fmt::Display) -> Outcome {
    Outcome::refused(
        OPERATIONAL_FAILURE_EXIT,
        "database.unavailable",
        "database",
        error.to_string(),
    )
}

fn message_not_found(message: Uuid) -> Outcome {
    Outcome::refused(
        DOMAIN_REFUSAL_EXIT,
        "message.not-found",
        "MESSAGE_ID",
        format!("no message {message} exists"),
    )
}

async fn list(reader: &MessageReader, args: &ListArgs) -> Outcome {
    match reader.list(args.status.map(Into::into), args.limit).await {
        Ok(messages) => Outcome::new(json!({"ok": true, "messages": messages}), View::MessageList),
        Err(error) => database_unavailable(&error),
    }
}

/// Show one message as the runtime serves it: the configured package decides
/// whether a message still without a report is one whose provider records
/// none.
async fn show(config: &RuntimeConfig, reader: &MessageReader, message: Uuid) -> Outcome {
    let receipt_providers = match config.load_package() {
        Ok(loaded) => loaded.receipt_providers(),
        Err(error) => return config_refusal(&error),
    };
    match reader.read(message).await {
        Ok(Some(mut stored)) => {
            stored.settle_report_capability(&receipt_providers);
            Outcome::new(
                json!({
                "ok": true,
                "message": stored.view,
                "accessProfile": stored.access_profile,
                "generation": stored.generation,
                "attempt": stored.attempt,
                }),
                View::MessageShow,
            )
        }
        Ok(None) => message_not_found(message),
        Err(error) => database_unavailable(&error),
    }
}

/// Report, and with `apply` do, one operator action. An action the message
/// is not in the state for is refused, applied or not, so a preview that
/// exits 0 is one `--apply` would carry out.
async fn act(
    config: &RuntimeConfig,
    target: &MessageArgs,
    action: OperatorAction,
    apply: bool,
) -> Outcome {
    let result = if apply {
        let store = match message_store(config).await {
            Ok(store) => store,
            Err(RuntimeError::Config(error)) => return config_refusal(&error),
            Err(error) => return database_unavailable(&error),
        };
        store.operate(target.message, action, true).await
    } else {
        let reader = match open_message_reader(config).await {
            Ok(reader) => reader,
            Err(outcome) => return outcome,
        };
        reader.operate(target.message, action).await
    };
    let report = match result {
        Ok(Some(report)) => report,
        Ok(None) => return message_not_found(target.message),
        Err(error) => return action_failure(target.message, action, error),
    };
    if !report.eligible
        && action == OperatorAction::Cancel
        && report.dispatch == MessageDispatch::Queued
    {
        return dispatch_started(target.message);
    }
    if !report.eligible {
        return Outcome::refused(
            DOMAIN_REFUSAL_EXIT,
            "message.not-eligible",
            "MESSAGE_ID",
            format!(
                "message {} has dispatch state {}; {} applies only to a message whose \
                 dispatch state is {}",
                target.message,
                report.dispatch.as_str(),
                action.as_str(),
                eligible_dispatch(action).as_str()
            ),
        );
    }
    action_outcome(&report)
}

/// The refusal of a cancellation of a message that is being sent or whose
/// current generation has an attempt that may have reached its provider,
/// under the code the HTTP API answers it with.
fn dispatch_started(message: Uuid) -> Outcome {
    Outcome::refused(
        DOMAIN_REFUSAL_EXIT,
        ProblemCode::MessageDispatchStarted.code(),
        "MESSAGE_ID",
        format!(
            "message {message} is being sent or may have been handed to its provider, so it \
             can no longer be cancelled"
        ),
    )
}

/// The report of an operator action the store could not answer, naming
/// whether the message changed.
fn action_failure(message: Uuid, action: OperatorAction, error: MessageStoreError) -> Outcome {
    let action = action.as_str();
    match error {
        MessageStoreError::DispatchStarted => dispatch_started(message),
        MessageStoreError::Refused => Outcome::refused(
            DOMAIN_REFUSAL_EXIT,
            "message.changed",
            "MESSAGE_ID",
            format!(
                "message {message} changed before the {action} could be applied; show it and \
                 try again"
            ),
        ),
        MessageStoreError::OutcomeUnknown => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "message.outcome-unknown",
            "MESSAGE_ID",
            format!(
                "the {action} of message {message} may have been applied; run messages show \
                 before acting again"
            ),
        ),
        MessageStoreError::AuditUnconfirmed => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "audit.unconfirmed",
            "audit",
            format!(
                "the {action} of message {message} was applied, and its audit outcome could \
                 not be recorded; do not apply it again, and restore the audit destination"
            ),
        ),
        MessageStoreError::AuditUnavailable => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "audit.unavailable",
            "audit",
            format!(
                "the audit destination refused the {action} request for message {message}; \
                 nothing was changed"
            ),
        ),
        MessageStoreError::Store(error) => database_unavailable(&error),
    }
}

/// The one dispatch state an action applies to, as `messages show` reports
/// it. The derived status is not enough: a submitted message the provider
/// reported undelivered is failed, and retrying it would send it again.
const fn eligible_dispatch(action: OperatorAction) -> MessageDispatch {
    match action {
        OperatorAction::Retry => MessageDispatch::Failed,
        OperatorAction::Settle(_) => MessageDispatch::Unknown,
        OperatorAction::Cancel => MessageDispatch::Queued,
    }
}

fn action_outcome(report: &OperatorActionReport) -> Outcome {
    match serde_json::to_value(report) {
        Ok(mut value) => {
            value["ok"] = json!(true);
            // The envelope's `status` names what the command did; the
            // message's own status is `messageStatus`.
            if let Some(status) = value
                .as_object_mut()
                .and_then(|report| report.remove("status"))
            {
                value["messageStatus"] = status;
            }
            Outcome::new(value, View::MessageAction)
        }
        Err(error) => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "output.failed",
            "/",
            format!("the report could not be serialized: {error}"),
        ),
    }
}

/// Write the report and return the exit code, or the operational failure
/// code when the report itself could not be written.
fn finish(
    outcome: &Outcome,
    command: &str,
    format: OutputFormat,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    let written = match (format, &outcome.raw_json) {
        (OutputFormat::Json, Some(bytes)) => stdout.write_all(bytes),
        (OutputFormat::Json, None) => {
            report::write(&completed(&outcome.report, command, outcome.exit), stdout)
        }
        (OutputFormat::Human, _) => render_human(outcome, stdout, stderr),
    };
    match written {
        Ok(()) => ExitCode::from(outcome.exit),
        Err(_) => {
            // The report could not be written; this line may not land either,
            // and the exit code carries the failure regardless.
            let _ = writeln!(stderr, "messagingctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}

fn render_human(
    outcome: &Outcome,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> io::Result<()> {
    let report = &outcome.report;
    let failed = report["ok"] == json!(false);
    // A refusal with positions, and the warnings of a check that passed,
    // print as the shared human report.
    let warned = matches!(outcome.view, View::Check)
        && !failed
        && report["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| !diagnostics.is_empty());
    if matches!(outcome.view, View::Diagnostics) || warned {
        write!(stderr, "{}", shared_report(report).render_human())?;
        if failed {
            return Ok(());
        }
    }
    if failed {
        for diagnostic in report["diagnostics"].as_array().into_iter().flatten() {
            writeln!(
                stderr,
                "{}[{}] {}: {}",
                diagnostic["severity"].as_str().unwrap_or("error"),
                text(&diagnostic["code"]),
                diagnostic["path"].as_str().unwrap_or("/"),
                text(&diagnostic["message"]),
            )?;
            for data in diagnostic["data"].as_array().into_iter().flatten() {
                writeln!(
                    stderr,
                    "  data {}: {}",
                    if text(&data["pointer"]).is_empty() {
                        "/"
                    } else {
                        text(&data["pointer"])
                    },
                    text(&data["keyword"])
                )?;
            }
            if let Some(action) = diagnostic["suggestedAction"].as_str() {
                writeln!(stderr, "  next: {action}")?;
            }
        }
        return Ok(());
    }
    match outcome.view {
        View::Init => render_init(report, stdout),
        View::Package => render_package(report, stdout),
        View::Check | View::Diagnostics => render_check(report, stdout),
        View::Preview => render_preview(report, stdout),
        View::Activation => render_activation(report, stdout),
        View::MessageList => render_message_list(report, stdout),
        View::MessageShow => render_message_show(report, stdout),
        View::MessageAction => render_message_action(report, stdout),
        View::Retention => render_retention(report, stdout),
        View::Dev => render_dev(report, stdout),
        View::DevToken => render_dev_token(report, stdout),
    }
}

/// The diagnostics of a report as the shared human report prints them.
fn shared_report(report: &Value) -> Report {
    let diagnostics: Vec<Diagnostic> =
        serde_json::from_value(report["diagnostics"].clone()).unwrap_or_default();
    let mut shared = Report::new(diagnostics);
    if let Some(files) = report["filesChecked"].as_u64() {
        shared.set_files_checked(usize::try_from(files).unwrap_or(usize::MAX));
    }
    shared
}

fn render_package(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    let verb = if report["dryRun"] == json!(true) {
        "would create"
    } else {
        "created"
    };
    writeln!(stdout, "{verb}: {}", text(&report["output"]))?;
    writeln!(stdout, "package digest: {}", text(&report["projectDigest"]))?;
    writeln!(stdout, "package files: {}", report["projectFiles"])
}

fn render_dev(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    if report["state"] == json!("stopped") {
        writeln!(stdout, "stopped; the session's containers are removed")?;
        return writeln!(
            stdout,
            "session directory: {}",
            text(&report["sessionDirectory"])
        );
    }
    writeln!(stdout, "ready")?;
    for (label, key) in [
        ("api", "api"),
        ("metrics", "metrics"),
        ("mailpit", "mailpit"),
        ("mock gateway", "mockGateway"),
        ("runtime config", "runtimeConfig"),
        ("log", "log"),
    ] {
        writeln!(stdout, "  {label}: {}", text(&report[key]))?;
    }
    writeln!(
        stdout,
        "next: messagingctl dev token CLIENT, then send with curl -H @HEADER_FILE; Ctrl-C stops the session"
    )
}

fn render_dev_token(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    writeln!(stdout, "header file: {}", text(&report["headerFile"]))?;
    writeln!(
        stdout,
        "valid for {} seconds; send with curl -H @{}",
        report["expiresInSeconds"],
        text(&report["headerFile"])
    )
}

fn render_init(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    writeln!(stdout, "created: {}", text(&report["directory"]))?;
    for file in report["created"].as_array().into_iter().flatten() {
        writeln!(stdout, "  {}", text(file))?;
    }
    for next in report["next"].as_array().into_iter().flatten() {
        writeln!(stdout, "next: {}", text(next))?;
    }
    Ok(())
}

fn render_check(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    match report["runtimeConfig"].as_str() {
        Some(path) => writeln!(stdout, "ok: {path}")?,
        None => writeln!(stdout, "ok: {}", text(&report["project"]))?,
    }
    if let Some(digest) = report["projectDigest"].as_str() {
        writeln!(stdout, "package digest: {digest}")?;
    }
    if report.get("listener").is_some() {
        writeln!(stdout, "listener: {}", text(&report["listener"]))?;
    }
    if let Some(metrics) = report.get("metricsListener") {
        match metrics.as_str() {
            Some(bind) => writeln!(stdout, "metrics listener: {bind}")?,
            None => writeln!(stdout, "metrics listener: none")?,
        }
    }
    for template in report["templates"].as_array().into_iter().flatten() {
        writeln!(
            stdout,
            "template: {} {} ({})",
            text(&template["id"]),
            text(&template["version"]),
            text(&template["channel"])
        )?;
        for sample in template["samples"].as_array().into_iter().flatten() {
            let sms = &sample["sms"];
            if sms.is_object() {
                writeln!(
                    stdout,
                    "  sample {}: {} segment(s), {} {} units",
                    text(&sample["locale"]),
                    sms["segments"],
                    text(&sms["encoding"]),
                    sms["units"]
                )?;
            } else {
                writeln!(stdout, "  sample {}: renders", text(&sample["locale"]))?;
            }
        }
    }
    for profile in report["accessProfiles"].as_array().into_iter().flatten() {
        writeln!(
            stdout,
            "access profile: {} ({})",
            text(&profile["id"]),
            text(&profile["role"])
        )?;
    }
    if let Some(retention) = report.get("retention") {
        writeln!(
            stdout,
            "retention: payload {} days, record {} days, submission receipt {} days",
            retention["payloadRetentionDays"],
            retention["recordRetentionDays"],
            retention["submissionReceiptRetentionDays"]
        )?;
    }
    Ok(())
}

fn render_preview(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    writeln!(
        stdout,
        "template: {} {} ({}, {})",
        text(&report["template"]["id"]),
        text(&report["template"]["version"]),
        text(&report["channel"]),
        text(&report["locale"])
    )?;
    writeln!(stdout, "package digest: {}", text(&report["packageDigest"]))?;
    for part in ["subject", "text", "html"] {
        if let Some(rendered) = report["parts"][part].as_str() {
            writeln!(stdout, "--- {part}")?;
            writeln!(stdout, "{}", rendered.trim_end_matches('\n'))?;
        }
    }
    let sms = &report["sms"];
    if sms.is_object() {
        writeln!(
            stdout,
            "--- sms: {} segment(s), {} {} units",
            sms["segments"],
            text(&sms["encoding"]),
            sms["units"]
        )?;
    }
    Ok(())
}

fn render_activation(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    if let Some(digest) = report.get("packageDigest").and_then(Value::as_str) {
        writeln!(stdout, "package digest: {digest}")?;
    }
    if let Some(change) = report.get("change").and_then(Value::as_str) {
        writeln!(stdout, "change: {change}")?;
    }
    if let Some(active) = report.get("active") {
        writeln!(
            stdout,
            "active: {}",
            active
                .get("packageDigest")
                .and_then(Value::as_str)
                .unwrap_or("none")
        )?;
    }
    if let Some(version) = report.get("schemaVersion") {
        writeln!(stdout, "schema version: {}", text(version))?;
    }
    if let Some(mode) = report.get("runtimeRoleMode").and_then(Value::as_str) {
        writeln!(stdout, "runtime role mode: {mode}")?;
    }
    Ok(())
}

fn render_retention(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    writeln!(stdout, "before: {}", text(&report["before"]))?;
    let verb = if report["applied"] == json!(true) {
        "erased"
    } else {
        "due"
    };
    writeln!(stdout, "payloads {verb}: {}", report["payloads"])?;
    writeln!(stdout, "records {verb}: {}", report["records"])?;
    writeln!(
        stdout,
        "submission receipts {verb}: {}",
        report["submissionReceipts"]
    )?;
    if report["applied"] != json!(true) {
        writeln!(stdout, "run again with --apply to erase")?;
    }
    Ok(())
}

fn render_message_list(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    let messages = report["messages"].as_array().map_or(&[][..], Vec::as_slice);
    if messages.is_empty() {
        return writeln!(stdout, "no messages");
    }
    for message in messages {
        writeln!(
            stdout,
            "{} {} (dispatch {}) {} {} generation {} attempt {} accepted {} updated {}",
            text(&message["id"]),
            text(&message["status"]),
            text(&message["dispatch"]),
            text(&message["channel"]),
            text(&message["senderProfile"]),
            message["generation"],
            message["attempt"],
            text(&message["acceptedAt"]),
            text(&message["updatedAt"])
        )?;
    }
    Ok(())
}

fn render_message_show(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    let message = &report["message"];
    writeln!(stdout, "message: {}", text(&message["id"]))?;
    writeln!(
        stdout,
        "status: {} (dispatch {}, report {})",
        text(&message["status"]),
        text(&message["dispatch"]),
        text(&message["report"])
    )?;
    if let Some(reported) = message["reportedAt"].as_str() {
        writeln!(stdout, "reported: {reported}")?;
    }
    writeln!(
        stdout,
        "channel: {} via {}",
        text(&message["channel"]),
        text(&message["senderProfile"])
    )?;
    // The view masks the contact; only its kind is printed.
    for kind in message["to"]
        .as_object()
        .into_iter()
        .flat_map(|to| to.keys())
    {
        writeln!(stdout, "to: {kind} (redacted)")?;
    }
    if let Some(template) = message["template"].as_object() {
        writeln!(
            stdout,
            "template: {} {}",
            template.get("id").map_or("", text),
            template.get("version").map_or("", text)
        )?;
    }
    if let Some(correlation) = message["correlationId"].as_str() {
        writeln!(stdout, "correlation id: {correlation}")?;
    }
    writeln!(stdout, "access profile: {}", text(&report["accessProfile"]))?;
    writeln!(
        stdout,
        "generation: {} attempt: {}",
        report["generation"], report["attempt"]
    )?;
    writeln!(stdout, "accepted: {}", text(&message["acceptedAt"]))?;
    if let Some(not_before) = message["notBefore"].as_str() {
        writeln!(stdout, "not before: {not_before}")?;
    }
    writeln!(stdout, "expires: {}", text(&message["expiresAt"]))?;
    writeln!(stdout, "updated: {}", text(&message["updatedAt"]))?;
    for attempt in message["attempts"].as_array().into_iter().flatten() {
        writeln!(
            stdout,
            "attempt {}.{}: {} started {}{}",
            attempt["generation"],
            attempt["attempt"],
            text(&attempt["outcome"]),
            text(&attempt["startedAt"]),
            attempt["finishedAt"]
                .as_str()
                .map_or_else(String::new, |finished| format!(" finished {finished}"))
        )?;
    }
    Ok(())
}

fn render_message_action(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    let action = match report["outcome"].as_str() {
        Some(outcome) => format!("{} {outcome}", text(&report["action"])),
        None => text(&report["action"]).to_owned(),
    };
    writeln!(
        stdout,
        "{action} {}: {} -> {}",
        text(&report["id"]),
        text(&report["messageStatus"]),
        text(&report["nextStatus"])
    )?;
    if report["applied"] == json!(true) {
        match report["nextGeneration"].as_i64() {
            Some(generation) => writeln!(stdout, "applied: queued as generation {generation}"),
            None => writeln!(stdout, "applied"),
        }
    } else {
        writeln!(
            stdout,
            "preview: run again with --apply to change the message"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_messaging::store::StoreError;
    use std::path::Path;

    const PACKAGE: &str = r"apiVersion: id.registrystack.org/formats/messaging/project/v1alpha1
kind: MessagingProject
project:
  id: operations
  version: '1'
accessProfiles:
  - id: operations
    principalClaim: sub
    requiredScopes: [messaging:operate]
    requesterClients: [operations-console]
    role: operator
    requestsPerMinute: 60
    burst: 10
";

    fn runtime(root: &Path, extra: &str) -> String {
        format!(
            r"apiVersion: id.registrystack.org/formats/messaging/runtime/v1alpha1
kind: MessagingRuntimeConfig
identity:
  databaseId: messaging-test
package:
  root: {root}/package
listener:
  bind: 127.0.0.1:8107
  tlsTermination: development-loopback
metricsListener:
  bind: 127.0.0.1:9107
secretProviders:
  environment: {{}}
database:
  runtimeUrlRef: secret:env/MESSAGING_RUNTIME_URL
  migrationUrlRef: secret:env/MESSAGING_MIGRATION_URL
authentication:
  oidc:
    issuer: https://identity.example.test
    audience: urn:example:messaging
    allowedClients: [operations-console]
audit:
  path: {root}/audit/messaging.jsonl
  hashKeyRef: secret:env/MESSAGING_AUDIT_KEY
{extra}",
            root = root.display()
        )
    }

    fn project(extra: &str) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let safe_root = std::fs::canonicalize(root.path()).unwrap();
        let authoring = safe_root.join("project");
        std::fs::create_dir_all(&authoring).unwrap();
        std::fs::write(authoring.join("messaging.yaml"), PACKAGE).unwrap();
        let inputs = package_inputs(&authoring).unwrap();
        write_package_inputs(&safe_root.join("package"), &inputs, None).unwrap();
        let path = safe_root.join("runtime.yaml");
        std::fs::write(&path, runtime(&safe_root, extra)).unwrap();
        (root, path)
    }

    fn run(arguments: &[&OsStr]) -> (ExitCode, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut args = vec![OsStr::new("messagingctl")];
        args.extend_from_slice(arguments);
        let exit = main_entry_from(args, &mut stdout, &mut stderr);
        (
            exit,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    fn check_json(path: &Path) -> (ExitCode, Value) {
        let (exit, stdout, _) = run(&[
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("check"),
            OsStr::new("--runtime-config"),
            path.as_os_str(),
        ]);
        (exit, serde_json::from_str(&stdout).unwrap())
    }

    #[test]
    fn the_package_formats_are_the_ones_the_runtime_reads() {
        assert!(PACKAGE.contains(registry_messaging_core::MESSAGING_PROJECT_API_VERSION));
        assert!(PACKAGE.contains(registry_messaging_core::MESSAGING_PROJECT_KIND));
        let (root, _) = project("");
        let runtime = runtime(root.path(), "");
        assert!(runtime.contains(registry_messaging_core::MESSAGING_RUNTIME_API_VERSION));
        assert!(runtime.contains(registry_messaging_core::MESSAGING_RUNTIME_KIND));
    }

    #[test]
    fn a_valid_configuration_passes_and_reports_what_would_be_served() {
        let (_root, path) = project("");
        let (exit, report) = check_json(&path);
        assert_eq!(exit, ExitCode::SUCCESS, "{report}");
        assert_eq!(report["ok"], true);
        assert_eq!(report["metricsListener"], "127.0.0.1:9107");
        assert_eq!(report["accessProfiles"][0]["id"], "operations");
        assert_eq!(report["accessProfiles"][0]["role"], "operator");
        assert_eq!(report["retention"]["payloadRetentionDays"], 7);

        let (exit, stdout, stderr) = run(&[
            OsStr::new("check"),
            OsStr::new("--runtime-config"),
            path.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(
            stdout.contains("access profile: operations (operator)"),
            "{stdout}"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn an_unknown_key_is_refused_with_its_path() {
        let (_root, path) = project("surprise: true\n");
        let (exit, report) = check_json(&path);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert_eq!(report["ok"], false);
        assert_eq!(report["diagnostics"][0]["code"], "config.unknown-key");
        assert_eq!(report["diagnostics"][0]["path"], "/surprise");
        let source = &report["diagnostics"][0]["source"];
        assert_eq!(source["file"], json!(path));
        assert!(source["line"].is_u64() && source["column"].is_u64());
    }

    #[test]
    fn an_environment_expression_in_a_secret_reference_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let safe_root = std::fs::canonicalize(root.path()).unwrap();
        let authoring = safe_root.join("project");
        std::fs::create_dir_all(&authoring).unwrap();
        std::fs::write(authoring.join("messaging.yaml"), PACKAGE).unwrap();
        let inputs = package_inputs(&authoring).unwrap();
        write_package_inputs(&safe_root.join("package"), &inputs, None).unwrap();
        let document = runtime(&safe_root, "").replace(
            "secret:env/MESSAGING_AUDIT_KEY",
            "secret:env/${AUDIT_KEY_NAME:-MESSAGING_AUDIT_KEY}",
        );
        let path = safe_root.join("runtime.yaml");
        std::fs::write(&path, document).unwrap();
        let (exit, report) = check_json(&path);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert_eq!(report["diagnostics"][0]["path"], "/audit/hashKeyRef");
    }

    #[test]
    fn a_human_refusal_goes_to_standard_error() {
        let (_root, path) = project("retention:\n  payloadRetentionDays: 31\n");
        let (exit, stdout, stderr) = run(&[
            OsStr::new("check"),
            OsStr::new("--runtime-config"),
            path.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stdout.is_empty());
        // Position first, then the message, the next step, and the summary
        // (CFG-DIAG-2), with the file named as it was given.
        let mut lines = stderr.lines();
        let head = lines.next().unwrap();
        assert!(
            head.starts_with(&format!("error[config.out-of-range] {}:", path.display())),
            "{stderr}"
        );
        assert!(
            head.ends_with(" /retention/payloadRetentionDays"),
            "{stderr}"
        );
        assert!(lines
            .next()
            .unwrap()
            .starts_with("  the value is outside its bounds"));
        assert!(lines.next().unwrap().starts_with("  next: "), "{stderr}");
        assert_eq!(lines.next(), Some("1 error, 0 warnings in 1 file"));
    }

    #[test]
    #[should_panic(expected = "carries diagnostics")]
    fn a_failure_without_diagnostics_is_a_programming_error() {
        let _ = completed(&json!({"ok": false}), "check", DOMAIN_REFUSAL_EXIT);
    }

    #[test]
    fn a_missing_file_is_an_operational_failure() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let (exit, report) = check_json(&root.join("absent.yaml"));
        assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT));
        assert_eq!(report["ok"], false);
    }

    #[test]
    fn usage_errors_exit_two_and_answer_json_in_machine_mode() {
        let (exit, stdout, _) = run(&[
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("check"),
        ]);
        assert_eq!(exit, ExitCode::from(USAGE_EXIT));
        let report: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
        assert_eq!(report["command"], "usage");
        assert_eq!(report["status"], "usage-error");
        let (exit, _, stderr) = run(&[OsStr::new("send")]);
        assert_eq!(exit, ExitCode::from(USAGE_EXIT));
        assert_eq!(
            stderr,
            format!("error: unrecognized subcommand\n  next: {USAGE_ACTION}\n")
        );
    }

    #[test]
    fn the_format_values_match_every_sibling_ctl() {
        for format in ["human", "json"] {
            assert!(Cli::try_parse_from([
                "messagingctl",
                "--format",
                format,
                "check",
                "--runtime-config",
                "/etc/messaging/runtime.yaml"
            ])
            .is_ok());
        }
        assert!(Cli::try_parse_from([
            "messagingctl",
            "--format",
            "yaml",
            "check",
            "--runtime-config",
            "/etc/messaging/runtime.yaml"
        ])
        .is_err());
    }

    /// A project whose package declares one SMTP provider and whose runtime
    /// connects it in plaintext to a loopback relay, behind a listener
    /// terminating TLS as `tls_termination` says.
    fn loopback_relay_project(tls_termination: &str) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let safe_root = std::fs::canonicalize(root.path()).unwrap();
        let authoring = safe_root.join("project");
        std::fs::create_dir_all(&authoring).unwrap();
        std::fs::write(
            authoring.join("messaging.yaml"),
            format!("{PACKAGE}providers:\n  - id: mail-relay\n    type: smtp\n"),
        )
        .unwrap();
        let inputs = package_inputs(&authoring).unwrap();
        write_package_inputs(&safe_root.join("package"), &inputs, None).unwrap();
        let document = runtime(
            &safe_root,
            "providers:\n  mail-relay:\n    type: smtp\n    host: 127.0.0.1\n    \
             port: 1025\n    tls: development-loopback\n",
        )
        .replace(
            "tlsTermination: development-loopback",
            &format!("tlsTermination: {tls_termination}"),
        );
        let path = safe_root.join("runtime.yaml");
        std::fs::write(&path, document).unwrap();
        (root, path)
    }

    #[test]
    fn a_development_listener_admits_a_plaintext_loopback_relay() {
        let (_root, path) = loopback_relay_project("development-loopback");
        let (exit, report) = check_json(&path);
        assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    }

    // A test feature admits the plaintext relay whatever the listener, so
    // only a build without one can observe the refusal.
    #[cfg(not(feature = "postgres-test"))]
    #[test]
    fn a_plaintext_loopback_relay_is_refused_behind_a_production_listener() {
        let (_root, path) = loopback_relay_project("operator-controlled-upstream");
        let (exit, report) = check_json(&path);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report}");
        let message = report["diagnostics"][0]["message"].as_str().unwrap();
        assert!(
            message.contains("development-loopback listener"),
            "{message}"
        );
    }

    fn starter(root: &Path) -> PathBuf {
        let directory = root.join("starter");
        let (exit, stdout, stderr) = run(&[OsStr::new("init"), directory.as_os_str()]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stderr}");
        assert!(stdout.contains("created:"), "{stdout}");
        directory
    }

    fn data_file(root: &Path, data: &Value) -> PathBuf {
        let path = root.join("data.json");
        std::fs::write(&path, serde_json::to_vec(data).unwrap()).unwrap();
        path
    }

    fn preview_args<'a>(
        package: &'a Path,
        template: &'a str,
        locale: &'a str,
        data: &'a Path,
    ) -> Vec<&'a OsStr> {
        vec![
            OsStr::new("preview"),
            OsStr::new("--project"),
            package.as_os_str(),
            OsStr::new(template),
            OsStr::new("1"),
            OsStr::new("--locale"),
            OsStr::new(locale),
            OsStr::new("--data"),
            data.as_os_str(),
        ]
    }

    fn json_run(arguments: &[&OsStr]) -> (ExitCode, Value) {
        let mut args = vec![OsStr::new("--format"), OsStr::new("json")];
        args.extend_from_slice(arguments);
        let (exit, stdout, _) = run(&args);
        (exit, serde_json::from_str(&stdout).unwrap())
    }

    #[test]
    fn init_points_at_the_local_dev_session() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("starter");
        let (exit, report) = json_run(&[OsStr::new("init"), directory.as_os_str()]);
        assert_eq!(exit, ExitCode::SUCCESS);
        let next: Vec<&str> = report["next"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| step.as_str().unwrap())
            .collect();
        assert!(
            next.iter()
                .any(|step| step.contains("messagingctl dev DIRECTORY")),
            "{next:?}"
        );

        let directory = root.path().join("human");
        let (exit, stdout, _) = run(&[OsStr::new("init"), directory.as_os_str()]);
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(
            stdout
                .lines()
                .any(|line| line.starts_with("next: ")
                    && line.contains("messagingctl dev DIRECTORY")),
            "{stdout}"
        );
    }

    #[test]
    fn init_writes_the_published_starter_byte_for_byte_and_never_overwrites() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let published =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/messaging/examples/starter");
        let mut expected = Vec::new();
        let mut pending = vec![published.clone()];
        while let Some(folder) = pending.pop() {
            for entry in std::fs::read_dir(folder).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    expected.push(
                        path.strip_prefix(&published)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
        }
        expected.sort();
        let mut embedded: Vec<String> = starter::FILES
            .iter()
            .map(|(path, _)| (*path).to_owned())
            .collect();
        embedded.sort();
        assert_eq!(embedded, expected);
        for (relative, _) in starter::FILES {
            assert_eq!(
                std::fs::read(directory.join(relative)).unwrap(),
                std::fs::read(published.join(relative)).unwrap(),
                "{relative}"
            );
        }

        let (exit, report) = json_run(&[OsStr::new("init"), directory.as_os_str()]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert_eq!(report["diagnostics"][0]["code"], "init.exists");
        let leftovers: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![OsString::from("starter")]);
    }

    /// The committed report example is what `messagingctl --format json check
    /// --project products/messaging/examples/starter` writes from the
    /// repository root, byte for byte.
    #[test]
    fn the_committed_report_example_is_check_output() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let relative = "products/messaging/examples/starter";
        let project = root.join(relative);
        let (exit, mut report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--project"),
            project.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{report}");
        report["project"] = json!(relative);
        let mut written = Vec::new();
        report::write(&report, &mut written).unwrap();
        let committed =
            std::fs::read(root.join("products/messaging/examples/formats/ctl-report.json"))
                .unwrap();
        assert!(
            written == committed,
            "products/messaging/examples/formats/ctl-report.json drifted; rerun \
             `messagingctl --format json check --project {relative}` from the repository \
             root and commit its output"
        );
    }

    #[test]
    fn check_reports_the_package_digest_templates_and_sample_segments() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let expected = load_project(&directory).unwrap();
        let (exit, report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--project"),
            directory.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{report}");
        assert_eq!(report["projectDigest"], expected.package.digest());
        assert_eq!(report["projectFiles"], expected.files.len());
        assert_eq!(report["filesChecked"], expected.files.len());
        assert_eq!(report["diagnostics"], json!([]));
        let templates = report["templates"].as_array().unwrap();
        assert_eq!(templates.len(), 2);
        assert_eq!(templates[0]["id"], "appointment-reminder");
        assert_eq!(templates[0]["locales"], json!(["en", "fr"]));
        assert_eq!(
            templates[0]["samples"][1],
            json!({"locale": "fr", "sms": null})
        );
        assert_eq!(templates[1]["channel"], "sms");
        assert_eq!(templates[1]["samples"][0]["sms"]["segments"], 1);
        assert_eq!(templates[1]["samples"][0]["sms"]["encoding"], "gsm7");
        assert!(report.get("listener").is_none());

        let (exit, stdout, _) = run(&[
            OsStr::new("check"),
            OsStr::new("--project"),
            directory.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(
            stdout.contains("template: appointment-reminder-sms 1 (sms)"),
            "{stdout}"
        );
        assert!(stdout.contains("sample en: 1 segment(s), gsm7"), "{stdout}");
    }

    #[test]
    fn check_refuses_a_project_file_at_its_member_and_file() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let provider = directory.join("providers/sms-gateway/provider.yaml");
        let text = std::fs::read_to_string(&provider).unwrap();
        assert!(text.contains("maximumConcurrentRequests: "), "{text}");
        let broken = text
            .lines()
            .map(|line| {
                if line.trim_start().starts_with("maximumConcurrentRequests: ") {
                    "  maximumConcurrentRequests: 0".to_owned()
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&provider, broken).unwrap();

        let (exit, report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--project"),
            directory.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report}");
        let diagnostics = report["diagnostics"].as_array().unwrap();
        assert_eq!(diagnostics.len(), 1, "{report}");
        assert_eq!(diagnostics[0]["code"], "config.out-of-range");
        assert_eq!(
            diagnostics[0]["path"],
            "/capabilities/maximumConcurrentRequests"
        );
        assert_eq!(
            diagnostics[0]["source"]["file"],
            provider.display().to_string()
        );
        assert!(diagnostics[0]["source"]["line"].as_u64().is_some());
        assert!(report["filesChecked"].as_u64().unwrap() >= 2, "{report}");
    }

    #[test]
    fn check_lists_project_warnings_and_deny_warnings_refuses_them() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let project = directory.join("messaging.yaml");
        let text = std::fs::read_to_string(&project).unwrap();
        std::fs::write(
            &project,
            text.replace(
                "requesterClients: [operations-console]",
                "requesterClients: [unrestricted]",
            ),
        )
        .unwrap();

        let (exit, report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--project"),
            directory.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{report}");
        let diagnostics = report["diagnostics"].as_array().unwrap();
        assert_eq!(diagnostics.len(), 1, "{report}");
        assert_eq!(diagnostics[0]["severity"], "warning");
        assert_eq!(
            diagnostics[0]["code"],
            "messaging.project.wildcard-spelled-item"
        );
        assert_eq!(
            diagnostics[0]["path"],
            "/accessProfiles/1/requesterClients/0"
        );

        let (exit, report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--project"),
            directory.as_os_str(),
            OsStr::new("--deny-warnings"),
        ]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report}");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "messaging.project.wildcard-spelled-item"
        );
    }

    #[test]
    fn package_builds_an_installed_directory_that_check_accepts() {
        let root = tempfile::tempdir().unwrap();
        let project = starter(root.path());
        let output = root.path().join("installed");
        let (exit, report) = json_run(&[
            OsStr::new("package"),
            project.as_os_str(),
            OsStr::new("--output"),
            output.as_os_str(),
            OsStr::new("--revision"),
            OsStr::new("test-revision"),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{report}");
        assert_eq!(report["revision"], "test-revision");
        assert!(output.join("SHA256SUMS").is_file());
        assert_eq!(
            std::fs::read_to_string(output.join("REVISION")).unwrap(),
            "test-revision\n"
        );

        let (exit, checked) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--package"),
            output.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{checked}");
        assert_eq!(checked["projectDigest"], report["projectDigest"]);

        let dry_output = root.path().join("dry-output");
        let (exit, dry) = json_run(&[
            OsStr::new("package"),
            project.as_os_str(),
            OsStr::new("--output"),
            dry_output.as_os_str(),
            OsStr::new("--revision"),
            OsStr::new("test-revision"),
            OsStr::new("--dry-run"),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{dry}");
        assert_eq!(dry["projectDigest"], report["projectDigest"]);
        assert!(!dry_output.exists());
    }

    #[test]
    fn check_takes_one_package_at_most_and_the_environment_only_with_a_runtime_file() {
        for refused in [
            ["check", "--project", "/a", "--package", "/b"].as_slice(),
            ["check", "--project", "/a", "--environment"].as_slice(),
        ] {
            let arguments: Vec<&OsStr> = refused.iter().map(OsStr::new).collect();
            let (exit, report) = json_run(&arguments);
            assert_eq!(exit, ExitCode::from(USAGE_EXIT), "{refused:?}");
            assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
        }
        assert!(Cli::try_parse_from([
            "messagingctl",
            "check",
            "--project",
            "/a",
            "--runtime-config",
            "/b",
            "--environment",
            "--deny-warnings",
        ])
        .is_ok());
    }

    #[test]
    fn a_runtime_file_is_checked_against_a_project_with_no_built_package() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(&std::fs::canonicalize(root.path()).unwrap());
        let runtime_config = directory.join("runtime.example.yaml");
        let (exit, report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--project"),
            directory.as_os_str(),
            OsStr::new("--runtime-config"),
            runtime_config.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{report}");
        assert_eq!(report["runtimeConfig"], json!(runtime_config));
        assert_eq!(report["diagnostics"], json!([]));
        assert!(report["projectDigest"].is_string());
        // The runtime file and every project file the check read.
        assert_eq!(
            report["filesChecked"],
            1 + load_project(&directory).unwrap().files.len()
        );

        // Alone, the file is checked against the package its package.root
        // names, which this machine does not hold.
        let (exit, report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--runtime-config"),
            runtime_config.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT), "{report}");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "messaging.package.invalid"
        );
        assert_eq!(report["diagnostics"][0]["path"], "/package/root");
        assert!(report["diagnostics"][0]["source"]["line"].is_u64());
    }

    #[test]
    fn a_refused_package_names_the_refused_file() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        std::fs::write(
            directory.join("templates/appointment-reminder/1/en/text.j2"),
            "{% if %}",
        )
        .unwrap();
        let (exit, report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--project"),
            directory.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("does not parse"));
    }

    #[test]
    fn preview_json_is_the_exact_body_the_route_answers() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let data = json!({"name": "Ada <Lovelace>", "day": "2026-10-01", "office": "Central"});
        let path = data_file(root.path(), &data);
        let mut args = vec![OsStr::new("--format"), OsStr::new("json")];
        args.extend(preview_args(
            &directory,
            "appointment-reminder",
            "fr",
            &path,
        ));
        let (exit, stdout, stderr) = run(&args);
        assert_eq!(exit, ExitCode::SUCCESS, "{stderr}");
        let loaded = load_project(&directory).unwrap();
        let preview = loaded
            .package
            .preview(
                "appointment-reminder",
                "1",
                &TemplatePreviewRequest {
                    locale: "fr".to_owned(),
                    data,
                },
            )
            .unwrap();
        let mut expected = preview_json(&preview).unwrap();
        expected.push(b'\n');
        assert_eq!(stdout.as_bytes(), expected.as_slice());
        assert!(stdout.contains("Ada &lt;Lovelace&gt;"), "{stdout}");
    }

    #[test]
    fn preview_in_human_form_prints_each_part_and_the_segment_count() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let data = json!({"name": "Ada", "day": "2026-10-01", "office": "Central"});
        let path = data_file(root.path(), &data);
        let (exit, stdout, _) = run(&preview_args(
            &directory,
            "appointment-reminder-sms",
            "en",
            &path,
        ));
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(stdout.contains("--- text\n"), "{stdout}");
        assert!(stdout.contains("--- sms: 1 segment(s), gsm7"), "{stdout}");
        assert!(!stdout.contains("--- subject"), "{stdout}");
    }

    #[test]
    fn preview_refusals_name_their_problem_code_and_never_a_value() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let valid = json!({"name": "Ada", "day": "2026-10-01", "office": "Central"});
        let cases = [
            (
                "appointment-reminder",
                "de",
                valid.clone(),
                "template.locale-unavailable",
            ),
            ("absent", "en", valid.clone(), "template.not-found"),
            (
                "appointment-reminder",
                "en",
                json!({"name": "secret-value-7", "day": 3}),
                "template.data-invalid",
            ),
        ];
        for (template, locale, data, code) in cases {
            let path = data_file(root.path(), &data);
            let mut args = vec![OsStr::new("--format"), OsStr::new("json")];
            args.extend(preview_args(&directory, template, locale, &path));
            let (exit, stdout, _) = run(&args);
            assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{code}");
            let report: Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(report["diagnostics"][0]["code"], code);
            assert!(!stdout.contains("secret-value-7"), "{stdout}");
        }
        let path = data_file(root.path(), &json!({"name": "Ada", "day": 3}));
        let (exit, _, stderr) = run(&preview_args(
            &directory,
            "appointment-reminder",
            "en",
            &path,
        ));
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.contains("data /day"), "{stderr}");

        let path = root.path().join("broken.json");
        std::fs::write(&path, "{").unwrap();
        let mut args = vec![OsStr::new("--format"), OsStr::new("json")];
        args.extend(preview_args(
            &directory,
            "appointment-reminder",
            "en",
            &path,
        ));
        let (exit, stdout, _) = run(&args);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stdout.contains("data.invalid"), "{stdout}");
    }

    #[test]
    fn apply_refuses_before_any_database_when_the_package_is_refused() {
        let (root, path) = project("");
        let pinned = runtime(root.path(), "").replace(
            &format!("  root: {}/package\n", root.path().display()),
            &format!(
                "  root: {}/package\n  expectedDigest: sha256:{}\n",
                root.path().display(),
                "0".repeat(64)
            ),
        );
        std::fs::write(&path, pinned).unwrap();
        let (exit, report) = json_run(&[
            OsStr::new("apply"),
            OsStr::new("--runtime-config"),
            path.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert_eq!(
            report["diagnostics"][0]["code"],
            "messaging.package.digest-mismatch"
        );
        assert_eq!(report["diagnostics"][0]["path"], "/package/expectedDigest");
    }

    #[test]
    fn apply_without_a_database_credential_is_an_operational_failure() {
        let (root, path) = project("");
        let document = runtime(root.path(), "").replace(
            "secret:env/MESSAGING_MIGRATION_URL",
            "secret:env/MESSAGINGCTL_TEST_UNSET_MIGRATION_URL",
        );
        std::fs::write(&path, document).unwrap();
        let (exit, report) = json_run(&[
            OsStr::new("apply"),
            OsStr::new("--runtime-config"),
            path.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT), "{report}");
        assert_eq!(report["diagnostics"][0]["code"], "database.unavailable");
    }

    #[test]
    fn messages_arguments_are_checked_before_any_database() {
        let id = "0b0b8f1c-7a7e-4c43-9d7e-0f3c5d9a1e2b";
        let cases: [&[&str]; 5] = [
            &["messages", "show", "not-a-uuid"],
            &["messages", "settle", id],
            &["messages", "settle", id, "--outcome", "maybe"],
            &["messages", "list", "--limit", "0"],
            &["messages", "list", "--status", "lost"],
        ];
        for case in cases {
            let mut args: Vec<&OsStr> = case.iter().map(OsStr::new).collect();
            args.extend([
                OsStr::new("--runtime-config"),
                OsStr::new("/etc/messaging/runtime.yaml"),
            ]);
            let (exit, report) = json_run(&args);
            assert_eq!(exit, ExitCode::from(USAGE_EXIT), "{case:?}");
            assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
            assert_eq!(report["status"], "usage-error");
        }
    }

    #[test]
    fn a_malformed_or_future_cutoff_is_refused_before_any_file_or_database() {
        let missing = OsStr::new("/nonexistent/messaging/runtime.yaml");
        let (exit, report) = json_run(&[
            OsStr::new("retention"),
            OsStr::new("erase-expired"),
            OsStr::new("--runtime-config"),
            missing,
            OsStr::new("--before"),
            OsStr::new("last-tuesday"),
        ]);
        assert_eq!(exit, ExitCode::from(USAGE_EXIT), "{report}");
        assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
        let (exit, report) = json_run(&[
            OsStr::new("retention"),
            OsStr::new("erase-expired"),
            OsStr::new("--runtime-config"),
            missing,
            OsStr::new("--before"),
            OsStr::new("9999-01-01T00:00:00Z"),
            OsStr::new("--apply"),
        ]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report}");
        assert_eq!(report["diagnostics"][0]["code"], "retention.future-cutoff");
        // A past cutoff reaches the configuration, which is missing here.
        let (exit, report) = json_run(&[
            OsStr::new("retention"),
            OsStr::new("erase-expired"),
            OsStr::new("--runtime-config"),
            missing,
            OsStr::new("--before"),
            OsStr::new("2026-01-01T00:00:00Z"),
        ]);
        assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT), "{report}");
    }

    #[test]
    fn messages_without_a_database_credential_is_an_operational_failure() {
        let (root, path) = project("");
        let document = runtime(root.path(), "").replace(
            "secret:env/MESSAGING_RUNTIME_URL",
            "secret:env/MESSAGINGCTL_TEST_UNSET_RUNTIME_URL",
        );
        std::fs::write(&path, document).unwrap();
        for command in [
            vec!["messages", "list"],
            vec!["messages", "cancel", "0b0b8f1c-7a7e-4c43-9d7e-0f3c5d9a1e2b"],
        ] {
            let mut args: Vec<&OsStr> = command.iter().map(OsStr::new).collect();
            args.extend([OsStr::new("--runtime-config"), path.as_os_str()]);
            let (exit, report) = json_run(&args);
            assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT), "{report}");
            assert_eq!(report["diagnostics"][0]["code"], "database.unavailable");
        }
    }

    fn diagnostic(outcome: &Outcome) -> (u8, String, String) {
        let diagnostic = &outcome.report["diagnostics"][0];
        (
            outcome.exit,
            diagnostic["code"].as_str().unwrap().to_owned(),
            diagnostic["message"].as_str().unwrap().to_owned(),
        )
    }

    #[test]
    fn each_message_action_failure_names_whether_the_message_changed() {
        let message = Uuid::nil();
        let cases = [
            (
                MessageStoreError::Refused,
                DOMAIN_REFUSAL_EXIT,
                "message.changed",
                "show it and try again",
            ),
            (
                MessageStoreError::DispatchStarted,
                DOMAIN_REFUSAL_EXIT,
                "message.dispatch-started",
                "can no longer be cancelled",
            ),
            (
                MessageStoreError::OutcomeUnknown,
                OPERATIONAL_FAILURE_EXIT,
                "message.outcome-unknown",
                "may have been applied; run messages show before acting again",
            ),
            (
                MessageStoreError::AuditUnconfirmed,
                OPERATIONAL_FAILURE_EXIT,
                "audit.unconfirmed",
                "was applied",
            ),
            (
                MessageStoreError::AuditUnavailable,
                OPERATIONAL_FAILURE_EXIT,
                "audit.unavailable",
                "nothing was changed",
            ),
            (
                MessageStoreError::Store(StoreError::Configuration),
                OPERATIONAL_FAILURE_EXIT,
                "database.unavailable",
                "database configuration",
            ),
        ];
        for (error, exit, code, says) in cases {
            let (got_exit, got_code, got_message) =
                diagnostic(&action_failure(message, OperatorAction::Retry, error));
            assert_eq!((got_exit, got_code.as_str()), (exit, code), "{got_message}");
            assert!(got_message.contains(says), "{code}: {got_message}");
        }
    }

    #[test]
    fn a_post_commit_apply_or_retention_failure_is_not_reported_as_database_unavailable() {
        let unavailable = RuntimeError::Activation(ActivationError::Audit("refused".to_owned()));
        let (exit, code, message) = diagnostic(&apply_failure(unavailable));
        assert_eq!(
            (exit, code.as_str()),
            (OPERATIONAL_FAILURE_EXIT, "audit.unavailable")
        );
        assert!(message.contains("activation audit failed"), "{message}");

        let unconfirmed = RuntimeError::AuditUnconfirmed {
            action: "package activation",
            detail: "refused".to_owned(),
        };
        let (exit, code, message) = diagnostic(&apply_failure(unconfirmed));
        assert_eq!(
            (exit, code.as_str()),
            (OPERATIONAL_FAILURE_EXIT, "audit.unconfirmed")
        );
        assert!(message.contains("was applied"), "{message}");

        let unknown = RuntimeError::OutcomeUnknown {
            stage: "package ledger write",
            source: StoreError::Configuration,
        };
        let (exit, code, message) = diagnostic(&apply_failure(unknown));
        assert_eq!(
            (exit, code.as_str()),
            (OPERATIONAL_FAILURE_EXIT, "package.outcome-unknown")
        );
        assert!(message.contains("run messagingctl status"), "{message}");

        let unconfirmed = RuntimeError::AuditUnconfirmed {
            action: "retention batch",
            detail: "refused".to_owned(),
        };
        let (exit, code, _) = diagnostic(&retention_failure(unconfirmed, true));
        assert_eq!(
            (exit, code.as_str()),
            (OPERATIONAL_FAILURE_EXIT, "audit.unconfirmed")
        );

        let unknown = RuntimeError::OutcomeUnknown {
            stage: "retention batch",
            source: StoreError::Configuration,
        };
        let (exit, code, message) = diagnostic(&retention_failure(unknown, true));
        assert_eq!(
            (exit, code.as_str()),
            (OPERATIONAL_FAILURE_EXIT, "retention.outcome-unknown")
        );
        assert!(message.contains("preview"), "{message}");

        let database = RuntimeError::Database {
            stage: "retention run",
            source: StoreError::Configuration,
        };
        let (exit, code, message) = diagnostic(&retention_failure(database, true));
        assert_eq!(
            (exit, code.as_str()),
            (OPERATIONAL_FAILURE_EXIT, "database.unavailable")
        );
        assert!(message.contains("batches committed before"), "{message}");
    }

    #[test]
    fn activation_boundary_failures_are_actionable_domain_refusals() {
        let cases = [
            (
                ActivationError::NotActivated,
                "messagingctl.activation.not-activated",
                "database",
            ),
            (
                ActivationError::DatabaseIdMismatch,
                "messagingctl.activation.database-id-mismatch",
                "identity.databaseId",
            ),
            (
                ActivationError::PackageNotActive,
                "messagingctl.activation.package-not-active",
                "package",
            ),
            (
                ActivationError::RoleModeWeakened,
                "messagingctl.activation.role-mode-weakened",
                "database.runtimeUrlRef",
            ),
            (
                ActivationError::GrantsStale,
                "messagingctl.activation.grants-stale",
                "database.runtimeUrlRef",
            ),
        ];
        for (error, expected_code, expected_path) in cases {
            let outcome = apply_failure(RuntimeError::Activation(error));
            let (exit, code, _) = diagnostic(&outcome);
            assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
            assert_eq!(code, expected_code);
            assert_eq!(outcome.report["diagnostics"][0]["path"], expected_path);
        }
    }
}
