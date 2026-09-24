// SPDX-License-Identifier: Apache-2.0

//! `messagingctl`, the Registry Messaging adopter and local operator
//! tooling.
//!
//! - `init` writes the starter package and runtime example.
//! - `check` loads a package, or a runtime configuration and the package it
//!   names, exactly as `messaging serve` would, offline: no secret is
//!   resolved, no database is reached, and no signing key is fetched. It
//!   reports the package digest and renders every template's sample.
//! - `preview` renders one template version with given data, offline, and
//!   in JSON prints the exact bytes the runtime's preview route answers.
//! - `apply` compares the package with the database's package ledger, and
//!   with `--apply` records it as the package the runtime serves after its
//!   next restart.
//! - `messages list` and `messages show` read accepted messages with the
//!   recipient masked; `messages retry`, `settle`, and `cancel` report what
//!   the action would do to one message, and with `--apply` do it. Each
//!   applied action writes its audit record into the outbox the running
//!   runtime publishes.
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
//! 3 when a file, secret, or database could not be reached or the report
//! could not be written.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_messaging::config::{RuntimeConfig, RuntimeConfigError};
use registry_messaging::http::preview_json;
use registry_messaging::messages::{
    MessageStore, MessageStoreError, OperatorAction, OperatorActionReport, SettleOutcome,
};
use registry_messaging::package::{load_package, LoadedPackage};
use registry_messaging::retention::RetentionError;
use registry_messaging::runtime::{
    apply_package, erase_expired_as_operator, message_store, PackageChange, RuntimeError,
};
use registry_messaging_core::{
    ContentRefusal, MessageDispatch, MessageStatus, TemplatePreviewRequest,
};
use serde_json::{json, Value};
use uuid::Uuid;

mod dev;
mod starter;

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
    /// Write the starter package and runtime example into a new directory.
    Init(InitArgs),
    /// Check a package, or a runtime configuration and its package, offline.
    Check(CheckArgs),
    /// Render one template version with the given data, offline.
    Preview(PreviewArgs),
    /// Compare the package with the package ledger, and record it with
    /// --apply.
    Apply(ApplyArgs),
    /// Read accepted messages, and retry, settle, or cancel one.
    #[command(subcommand)]
    Messages(MessagesCommand),
    /// Erase what the retention periods say has expired.
    #[command(subcommand)]
    Retention(RetentionCommand),
    /// Run the package locally with PostgreSQL, Mailpit, and a mock HTTP
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
    #[arg(value_name = "MESSAGE_ID")]
    message: Uuid,
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
}

#[derive(Debug, Args)]
struct CheckArgs {
    #[command(flatten)]
    source: PackageSource,
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
    /// Absolute path to the runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
    /// Record the package in the ledger. Without it, only report the change.
    #[arg(long)]
    apply: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

const REFUSAL_EXIT: u8 = 1;
const USAGE_EXIT: u8 = 2;
const OPERATIONAL_FAILURE_EXIT: u8 = 3;

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
    Check,
    Preview,
    Apply,
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
        Self {
            report: json!({
                "ok": false,
                "diagnostics": [{"code": code, "path": path, "message": message}]
            }),
            exit,
            view: View::Check,
            raw_json: None,
        }
    }
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
            let report = json!({
                "ok": false,
                "diagnostics": [{"code": "usage.invalid", "path": "/", "message": error.to_string()}]
            });
            let format = if machine_mode {
                OutputFormat::Json
            } else {
                OutputFormat::Human
            };
            let outcome = Outcome {
                report,
                exit: USAGE_EXIT,
                view: View::Check,
                raw_json: None,
            };
            return finish(&outcome, format, stdout, stderr);
        }
    };
    let outcome = match cli.command {
        Command::Dev(args) => return dev::run(args, cli.format, stdout, stderr),
        Command::Init(args) => init(&args.directory),
        Command::Check(args) => check(&args.source),
        Command::Preview(args) => preview(&args),
        Command::Apply(args) => apply(&args.runtime_config, args.apply),
        Command::Messages(command) => messages(&command),
        Command::Retention(RetentionCommand::EraseExpired(args)) => erase_expired(&args),
    };
    finish(&outcome, cli.format, stdout, stderr)
}

fn init(directory: &Path) -> Outcome {
    match starter::write(directory) {
        Ok(created) => Outcome::new(
            json!({
                "ok": true,
                "directory": directory,
                "created": created,
                "next": [
                    "Run messagingctl check --package DIRECTORY.",
                    "Copy runtime.example.yaml to runtime.yaml, set its absolute paths and secret references, run messaging migrate, then messagingctl apply --apply, then messaging serve.",
                ],
            }),
            View::Init,
        ),
        Err(starter::InitError::Exists) => Outcome::refused(
            REFUSAL_EXIT,
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
    match (&source.runtime_config, &source.package) {
        (Some(path), _) => {
            let loaded = RuntimeConfig::load(path).and_then(|config| {
                let package = config.load_package()?;
                Ok((config, package))
            });
            loaded
                .map(|(config, package)| (Some(config), package))
                .map_err(|error| config_refusal(&error))
        }
        (None, Some(root)) => load_package(root)
            .map(|package| (None, package))
            .map_err(|error| {
                let exit = if error.is_read_failure() {
                    OPERATIONAL_FAILURE_EXIT
                } else {
                    REFUSAL_EXIT
                };
                Outcome::refused(exit, "config.refused", error.path(), error.to_string())
            }),
        (None, None) => Err(Outcome::refused(
            USAGE_EXIT,
            "usage.invalid",
            "/",
            "name --runtime-config or --package".to_owned(),
        )),
    }
}

fn config_refusal(error: &RuntimeConfigError) -> Outcome {
    let exit = match error {
        RuntimeConfigError::Read(_) => OPERATIONAL_FAILURE_EXIT,
        RuntimeConfigError::Package(error) if error.is_read_failure() => OPERATIONAL_FAILURE_EXIT,
        _ => REFUSAL_EXIT,
    };
    Outcome::refused(exit, "config.refused", error.path(), error.to_string())
}

/// Report what the runtime would serve, rendering each template's sample
/// in every locale it declares.
fn check(source: &PackageSource) -> Outcome {
    let (config, loaded) = match load(source) {
        Ok(loaded) => loaded,
        Err(refused) => return refused,
    };
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
                    Err(refusal) => {
                        return preview_refusal(&refusal);
                    }
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
    let mut report = json!({
        "ok": true,
        "packageDigest": package.digest(),
        "packageFiles": loaded.files.len(),
        "templates": templates,
        "accessProfiles": profiles,
    });
    if let Some(config) = config {
        report["runtimeConfig"] = json!(source.runtime_config);
        report["listener"] = json!(config.listener.bind.to_string());
        report["metricsListener"] = json!(config
            .metrics_listener
            .as_ref()
            .map(|metrics| metrics.bind.to_string()));
        report["retention"] = json!(config.retention);
    } else {
        report["package"] = json!(source.package);
    }
    Outcome::new(report, View::Check)
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
            REFUSAL_EXIT,
            "data.invalid",
            "--data",
            format!("the data file exceeds {MAXIMUM_DATA_BYTES} bytes"),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        Outcome::refused(
            REFUSAL_EXIT,
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
        REFUSAL_EXIT,
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

fn apply(path: &Path, record: bool) -> Outcome {
    let config = match RuntimeConfig::load(path) {
        Ok(config) => config,
        Err(error) => return config_refusal(&error),
    };
    let runtime = match async_runtime() {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    match runtime.block_on(apply_package(&config, record)) {
        Ok(applied) => Outcome::new(
            json!({
                "ok": true,
                "runtimeConfig": path,
                "packageDigest": applied.package_digest,
                "activeDigest": applied.active_digest,
                "change": applied.change,
                "applied": applied.applied,
                "restartRequired": applied.applied,
            }),
            View::Apply,
        ),
        Err(RuntimeError::Config(error)) => config_refusal(&error),
        Err(error) => database_unavailable(&error),
    }
}

fn messages(command: &MessagesCommand) -> Outcome {
    let path = match command {
        MessagesCommand::List(args) => &args.runtime_config,
        MessagesCommand::Show(args) => &args.runtime_config,
        MessagesCommand::Retry(args) | MessagesCommand::Cancel(args) => &args.target.runtime_config,
        MessagesCommand::Settle(args) => &args.action.target.runtime_config,
    };
    let config = match RuntimeConfig::load(path) {
        Ok(config) => config,
        Err(error) => return config_refusal(&error),
    };
    let runtime = match async_runtime() {
        Ok(runtime) => runtime,
        Err(refused) => return refused,
    };
    runtime.block_on(async {
        let store = match message_store(&config).await {
            Ok(store) => store,
            Err(RuntimeError::Config(error)) => return config_refusal(&error),
            Err(error) => return database_unavailable(&error),
        };
        match command {
            MessagesCommand::List(args) => list(&store, args).await,
            MessagesCommand::Show(args) => show(&config, &store, args.message).await,
            MessagesCommand::Retry(args) => {
                act(&store, &args.target, OperatorAction::Retry, args.apply).await
            }
            MessagesCommand::Cancel(args) => {
                act(&store, &args.target, OperatorAction::Cancel, args.apply).await
            }
            MessagesCommand::Settle(args) => {
                let outcome = match args.outcome {
                    SettleArg::Sent => SettleOutcome::Sent,
                    SettleArg::NotSent => SettleOutcome::NotSent,
                };
                act(
                    &store,
                    &args.action.target,
                    OperatorAction::Settle(outcome),
                    args.action.apply,
                )
                .await
            }
        }
    })
}

fn future_cutoff() -> Outcome {
    Outcome::refused(
        REFUSAL_EXIT,
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
    let config = match RuntimeConfig::load(&args.runtime_config) {
        Ok(config) => config,
        Err(error) => return config_refusal(&error),
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
                "retention": config.retention,
            }),
            View::Retention,
        ),
        Err(RuntimeError::Config(error)) => config_refusal(&error),
        Err(RuntimeError::Retention(RetentionError::FutureCutoff)) => future_cutoff(),
        Err(error) => database_unavailable(&error),
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
        REFUSAL_EXIT,
        "message.not-found",
        "MESSAGE_ID",
        format!("no message {message} exists"),
    )
}

async fn list(store: &MessageStore, args: &ListArgs) -> Outcome {
    match store.list(args.status.map(Into::into), args.limit).await {
        Ok(messages) => Outcome::new(json!({"ok": true, "messages": messages}), View::MessageList),
        Err(error) => database_unavailable(&error),
    }
}

/// Show one message as the runtime serves it: the configured package decides
/// whether a message still without a report is one whose provider records
/// none.
async fn show(config: &RuntimeConfig, store: &MessageStore, message: Uuid) -> Outcome {
    let receipt_providers = match config.load_package() {
        Ok(loaded) => loaded.receipt_providers(),
        Err(error) => return config_refusal(&error),
    };
    match store.read(message).await {
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
    store: &MessageStore,
    target: &MessageArgs,
    action: OperatorAction,
    apply: bool,
) -> Outcome {
    let report = match store.operate(target.message, action, apply).await {
        Ok(Some(report)) => report,
        Ok(None) => return message_not_found(target.message),
        Err(MessageStoreError::Refused) => {
            return Outcome::refused(
                REFUSAL_EXIT,
                "message.changed",
                "MESSAGE_ID",
                format!(
                    "message {} changed before the {} could be applied; show it and try again",
                    target.message,
                    action.as_str()
                ),
            )
        }
        Err(error) => return database_unavailable(&error),
    };
    if !report.eligible {
        return Outcome::refused(
            REFUSAL_EXIT,
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
    format: OutputFormat,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    let written = match (format, &outcome.raw_json) {
        (OutputFormat::Json, Some(bytes)) => stdout.write_all(bytes),
        (OutputFormat::Json, None) => serde_json::to_writer_pretty(&mut *stdout, &outcome.report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout)),
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
    if report["ok"] == json!(false) {
        for diagnostic in report["diagnostics"].as_array().into_iter().flatten() {
            writeln!(
                stderr,
                "messagingctl: {} ({})",
                text(&diagnostic["message"]),
                diagnostic["path"].as_str().unwrap_or("/")
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
        }
        return Ok(());
    }
    match outcome.view {
        View::Init => render_init(report, stdout),
        View::Check => render_check(report, stdout),
        View::Preview => render_preview(report, stdout),
        View::Apply => render_apply(report, stdout),
        View::MessageList => render_message_list(report, stdout),
        View::MessageShow => render_message_show(report, stdout),
        View::MessageAction => render_message_action(report, stdout),
        View::Retention => render_retention(report, stdout),
        View::Dev => render_dev(report, stdout),
        View::DevToken => render_dev_token(report, stdout),
    }
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
        None => writeln!(stdout, "ok: {}", text(&report["package"]))?,
    }
    writeln!(stdout, "package digest: {}", text(&report["packageDigest"]))?;
    if report.get("listener").is_some() {
        writeln!(stdout, "listener: {}", text(&report["listener"]))?;
        match report["metricsListener"].as_str() {
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
            retention["payloadDays"], retention["recordDays"], retention["submissionReceiptDays"]
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

fn render_apply(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    writeln!(stdout, "package digest: {}", text(&report["packageDigest"]))?;
    writeln!(
        stdout,
        "active digest: {}",
        report["activeDigest"].as_str().unwrap_or("none")
    )?;
    let change = if report["change"] == json!(PackageChange::None) {
        "none: the ledger already names this package active"
    } else if report["applied"] == json!(true) {
        "recorded: restart the runtime to serve this package"
    } else {
        "activate: run again with --apply to record this package"
    };
    writeln!(stdout, "change: {change}")
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
        text(&report["status"]),
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
    use std::path::Path;

    const PACKAGE: &str = r"apiVersion: registry.registrystack.org/messaging-package/v1alpha1
kind: MessagingPackage
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
            r"apiVersion: registry.registrystack.org/messaging-runtime/v1alpha1
kind: MessagingRuntimeConfig
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
        std::fs::create_dir_all(root.path().join("package")).unwrap();
        std::fs::write(root.path().join("package/messaging.yaml"), PACKAGE).unwrap();
        let path = root.path().join("runtime.yaml");
        std::fs::write(&path, runtime(root.path(), extra)).unwrap();
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
        assert!(PACKAGE.contains(registry_messaging_core::MESSAGING_PACKAGE_API_VERSION));
        assert!(PACKAGE.contains(registry_messaging_core::MESSAGING_PACKAGE_KIND));
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
        assert_eq!(report["retention"]["payloadDays"], 7);

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
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert_eq!(report["ok"], false);
        assert_eq!(report["diagnostics"][0]["code"], "config.refused");
        assert!(report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("surprise"));
    }

    #[test]
    fn an_environment_expression_in_a_secret_reference_is_refused() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("package")).unwrap();
        std::fs::write(root.path().join("package/messaging.yaml"), PACKAGE).unwrap();
        let document = runtime(root.path(), "").replace(
            "secret:env/MESSAGING_AUDIT_KEY",
            "secret:env/${AUDIT_KEY_NAME:-MESSAGING_AUDIT_KEY}",
        );
        let path = root.path().join("runtime.yaml");
        std::fs::write(&path, document).unwrap();
        let (exit, report) = check_json(&path);
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert_eq!(report["diagnostics"][0]["path"], "audit.hashKeyRef");
    }

    #[test]
    fn a_human_refusal_goes_to_standard_error() {
        let (_root, path) = project("retention:\n  payloadDays: 31\n");
        let (exit, stdout, stderr) = run(&[
            OsStr::new("check"),
            OsStr::new("--runtime-config"),
            path.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert!(stdout.is_empty());
        assert!(stderr.contains("retention is out of bounds"), "{stderr}");
    }

    #[test]
    fn a_missing_file_is_an_operational_failure() {
        let root = tempfile::tempdir().unwrap();
        let (exit, report) = check_json(&root.path().join("absent.yaml"));
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
        let (exit, _, stderr) = run(&[OsStr::new("send")]);
        assert_eq!(exit, ExitCode::from(USAGE_EXIT));
        assert!(!stderr.is_empty());
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
        std::fs::create_dir_all(root.path().join("package")).unwrap();
        std::fs::write(
            root.path().join("package/messaging.yaml"),
            format!("{PACKAGE}providers:\n  - id: mail-relay\n    kind: smtp\n"),
        )
        .unwrap();
        let document = runtime(
            root.path(),
            "providers:\n  mail-relay:\n    kind: smtp\n    host: 127.0.0.1\n    \
             port: 1025\n    tls: development-loopback\n",
        )
        .replace(
            "tlsTermination: development-loopback",
            &format!("tlsTermination: {tls_termination}"),
        );
        let path = root.path().join("runtime.yaml");
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
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT), "{report}");
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
            OsStr::new("--package"),
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
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert_eq!(report["diagnostics"][0]["code"], "init.exists");
        let leftovers: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![OsString::from("starter")]);
    }

    #[test]
    fn check_reports_the_package_digest_templates_and_sample_segments() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let expected = load_package(&directory).unwrap();
        let (exit, report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--package"),
            directory.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{report}");
        assert_eq!(report["packageDigest"], expected.package.digest());
        assert_eq!(report["packageFiles"], expected.files.len());
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
            OsStr::new("--package"),
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
    fn check_takes_exactly_one_package_source() {
        let (exit, report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--package"),
            OsStr::new("/a"),
            OsStr::new("--runtime-config"),
            OsStr::new("/b"),
        ]);
        assert_eq!(exit, ExitCode::from(USAGE_EXIT));
        assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
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
            OsStr::new("--package"),
            directory.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
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
        let loaded = load_package(&directory).unwrap();
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
            assert_eq!(exit, ExitCode::from(REFUSAL_EXIT), "{code}");
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
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
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
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
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
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert_eq!(report["diagnostics"][0]["path"], "package.expectedDigest");
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
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT), "{report}");
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
}
