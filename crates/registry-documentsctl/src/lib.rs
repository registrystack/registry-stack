// SPDX-License-Identifier: Apache-2.0

//! `documentsctl`, the Document Store adopter and local operator tooling.
//!
//! - `init` writes the maintained starter project into a new directory.
//! - `check` reads a project's `documents.yaml`, a runtime configuration,
//!   or both, exactly as the runtime's reader does, offline: no secret is
//!   resolved and no database is reached.
//! - `package` builds the deployable package from a checked project.
//! - `plan`, `apply`, and `status` read and change the database's package
//!   activation ledger through the runtime configuration. Only `apply`
//!   writes, over the migration credential.
//! - `verification list` and `verification replay` read the dead-lettered
//!   content verification jobs and return one to pending under a new
//!   generation. No HTTP route replays a job.
//!
//! Exit codes: 0 when the command succeeds, 1 when the input or the
//! database state is refused, 2 for a usage error, and 3 when a file,
//! secret, database, or audit destination was unavailable or the report
//! could not be written.
//!
//! With `--format json` every report opens with `ok`, `command`, and
//! `status`, in that order, then names its format with `apiVersion` and
//! `kind`. `status` is `complete` for a success and `domain-refusal`,
//! `usage-error`, or `operational-failure` by exit class for a failure,
//! whose `diagnostics` each name a `suggestedAction`.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_documents::config::check_runtime_file;
use registry_documents::package::{package_limits, PACKAGE_COMMAND};
use registry_documents::verification::MAXIMUM_DEAD_LETTER_LISTING;
use registry_documents_core::{
    DocumentsProject, DOCUMENTS_PROJECT_KIND, DOCUMENTS_RUNTIME_KIND, PROJECT_FILE,
};
use registry_platform_config::{plan_package, write_package, PackageErrorKind};
use registry_platform_yaml::{Diagnostic, Report, Source};
use serde_json::{json, Value};
use uuid::Uuid;

mod operate;
mod report;
mod starter;

use report::{DOMAIN_REFUSAL_EXIT, OPERATIONAL_FAILURE_EXIT, USAGE_EXIT};

/// The largest `documents.yaml` file `check` and `package` read.
const MAXIMUM_PROJECT_BYTES: u64 = 1024 * 1024;

/// How many dead letters `verification list` reports when `--limit` is not
/// given.
const DEFAULT_DEAD_LETTER_LISTING: u16 = 50;

/// The next step for a command line clap refused.
const USAGE_ACTION: &str =
    "Run documentsctl --help, or the command with --help, and retry with the documented arguments.";

#[derive(Debug, Parser)]
#[command(
    name = "documentsctl",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Registry Stack Document Store adopter and local operator tooling"
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
    /// Write the starter project into a new directory.
    Init(InitArgs),
    /// Check a project, a runtime configuration, or both, offline.
    Check(CheckArgs),
    /// Build the deployable package from a checked project.
    Package(PackageArgs),
    /// Report what apply would change in the database, writing nothing.
    Plan(ActivationArgs),
    /// Apply the schema and record the configured package as active.
    Apply(ApplyArgs),
    /// Report the active package and the activation history.
    Status(ActivationArgs),
    /// Inspect and replay dead-lettered content verification jobs.
    #[command(subcommand)]
    Verification(VerificationCommand),
}

#[derive(Debug, Subcommand)]
enum VerificationCommand {
    /// List the oldest dead-lettered content verification jobs.
    List(ListArgs),
    /// Return one dead-lettered content verification job to pending.
    Replay(ReplayArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// The directory to create. It must not exist.
    #[arg(value_name = "DIRECTORY")]
    directory: PathBuf,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("input")
        .args(["project", "runtime_config"])
        .required(true)
        .multiple(true)
))]
struct CheckArgs {
    /// The project directory holding documents.yaml.
    #[arg(long, value_name = "DIRECTORY")]
    project: Option<PathBuf>,

    /// Runtime configuration file.
    #[arg(long, value_name = "FILE")]
    runtime_config: Option<PathBuf>,

    /// Substitute `${VAR}` references in the runtime configuration from the
    /// environment instead of checking them as stand-ins.
    #[arg(long, requires = "runtime_config")]
    environment: bool,

    /// Refuse the check when it finds a warning.
    #[arg(long)]
    deny_warnings: bool,
}

#[derive(Debug, Args)]
struct PackageArgs {
    /// The project directory holding documents.yaml.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// New directory to create for the package.
    #[arg(long, value_name = "DIRECTORY")]
    output: PathBuf,
    /// Optional source revision recorded in the package envelope.
    #[arg(long, value_name = "REVISION")]
    revision: Option<String>,
    /// Validate and report the digest without writing the package.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct ActivationArgs {
    /// Runtime configuration file.
    #[arg(long, value_name = "FILE")]
    runtime_config: PathBuf,
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
struct ListArgs {
    #[command(flatten)]
    activation: ActivationArgs,
    /// The most dead letters to report, oldest first.
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = DEFAULT_DEAD_LETTER_LISTING,
        value_parser = clap::value_parser!(u16).range(1..=i64::from(MAXIMUM_DEAD_LETTER_LISTING)),
    )]
    limit: u16,
}

#[derive(Debug, Args)]
struct ReplayArgs {
    #[command(flatten)]
    activation: ActivationArgs,
    /// The document version whose verification job is replayed.
    #[arg(long, value_name = "UUID")]
    version_id: Uuid,
    /// The generation `verification list` reported for the job.
    #[arg(
        long,
        value_name = "GENERATION",
        value_parser = clap::value_parser!(i64).range(1..),
    )]
    expected_generation: i64,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

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
/// it.
struct Outcome {
    report: Value,
    exit: u8,
    view: View,
}

#[derive(Clone, Copy)]
enum View {
    Check,
    /// A refusal whose diagnostics carry their positions, printed as the
    /// shared human report.
    Diagnostics,
    Init,
    Package,
    Activation,
    DeadLetters,
    Replayed,
}

impl Outcome {
    fn new(report: Value, view: View) -> Self {
        Self {
            report,
            exit: 0,
            view,
        }
    }

    /// A refusal carrying one diagnostic about something other than a
    /// position in a file the command read.
    fn refused(exit: u8, code: &str, path: &str, message: String) -> Self {
        let (artifact, action) = guidance(code, exit);
        Self {
            report: json!({
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
        }
    }

    /// A refusal reporting every diagnostic in `report`. A diagnostic that
    /// names no artifact is about the runtime configuration.
    fn diagnosed(exit: u8, report: &Report) -> Self {
        let mut diagnostics = report.to_json_value();
        for diagnostic in diagnostics.as_array_mut().into_iter().flatten() {
            if diagnostic.get("artifact").is_none() {
                diagnostic["artifact"] = json!(DOCUMENTS_RUNTIME_KIND);
            }
        }
        let mut refused = json!({"diagnostics": diagnostics});
        if let Some(files) = report.files_checked() {
            refused["filesChecked"] = json!(files);
        }
        Self {
            report: refused,
            exit,
            view: View::Diagnostics,
        }
    }
}

/// The artifact a refusal is about and the next step it suggests, by its
/// code, and by its exit class for a code without its own.
fn guidance(code: &str, exit: u8) -> (&'static str, &'static str) {
    match code {
        "usage.invalid" => ("command-arguments", USAGE_ACTION),
        "config.unresolvable" => (
            "command-arguments",
            "Name a runtime configuration path that resolves from the working directory, then retry.",
        ),
        "init.exists" => (
            "filesystem",
            "Name a directory that does not exist yet, then rerun documentsctl init.",
        ),
        "init.write-failed" => (
            "filesystem",
            "Make the parent directory writable, then rerun documentsctl init.",
        ),
        "package.refused" if exit == OPERATIONAL_FAILURE_EXIT => (
            "package-output",
            "Make the --output parent directory writable, then rerun documentsctl package.",
        ),
        "package.refused" => (
            "package-output",
            "Correct the --output directory or --revision as the message names, then rerun documentsctl package.",
        ),
        "config.refused" if exit == OPERATIONAL_FAILURE_EXIT => (
            "runtime-configuration",
            "Restore the file or secret the message names, then retry.",
        ),
        "config.refused" => (
            "runtime-configuration",
            "Correct the member the path names, then rerun documentsctl check.",
        ),
        "documents.package.digest-mismatch"
        | "documents.package.invalid"
        | "documents.package.unexpected-contents"
        | "documents.package.file-changed"
        | "documents.package.project-refused"
        | "documents.package.policy-above-ceiling" => (
            "documents-package",
            "Rebuild the package with documentsctl package, deploy it at package.root, and pin its digest in package.expectedDigest.",
        ),
        "runtime.unavailable" => (
            "runtime-dependency",
            "Retry the command; if it fails again, report the message.",
        ),
        "package.outcome-unknown" => (
            "database",
            "Run documentsctl status to see which activation the ledger records before applying again.",
        ),
        "audit.unconfirmed" => (
            "audit",
            "Do not apply the change again; restore the audit destination and confirm with documentsctl status.",
        ),
        "audit.unavailable" => (
            "audit",
            "Restore the audit destination or its key, then retry; nothing was changed.",
        ),
        "documentsctl.activation.not-activated"
        | "documentsctl.activation.package-not-active"
        | "documentsctl.activation.grants-stale" => (
            "database-activation",
            "Run documentsctl plan with the runtime configuration, then apply with the migration credential.",
        ),
        "documentsctl.activation.database-id-mismatch" => (
            "database-activation",
            "Use the database belonging to this deployment, or restore the configured deployment identity.",
        ),
        "documentsctl.activation.role-mode-weakened" => (
            "database-activation",
            "Restore the split-role ownership and grants, then rerun documentsctl plan.",
        ),
        "documentsctl.activation.ledger-unreadable" => (
            "database-activation",
            "Restore the runtime credential's read access to the activation ledger, then retry.",
        ),
        "documentsctl.activation.schema-newer" => (
            "database-activation",
            "Use the Document Store release that owns the recorded schema version.",
        ),
        "documentsctl.activation.schema-invalid" => (
            "database-activation",
            "Restore a database whose migration history is an ordered prefix of this Document Store release.",
        ),
        "documentsctl.activation.invalid-reference" => (
            "command-arguments",
            "Correct the operator or backup reference bounds, then retry.",
        ),
        "database.unavailable" => (
            "database",
            "Restore the database or the credential the message names, then retry.",
        ),
        "verification.not-found" => (
            "verification-job",
            "Find the version id with documentsctl verification list.",
        ),
        "verification.not-dead-lettered" | "verification.changed" => (
            "verification-job",
            "Run documentsctl verification list and replay only a job it reports.",
        ),
        "verification.stale-generation" => (
            "verification-job",
            "Run documentsctl verification list and pass the generation it reports as --expected-generation.",
        ),
        _ if exit == OPERATIONAL_FAILURE_EXIT => (
            "runtime-dependency",
            "Restore the file, secret, database, or service the message names, then retry.",
        ),
        _ => (
            "documents-project",
            "Correct the input the message names, then retry.",
        ),
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
    let outcome = match &cli.command {
        Command::Init(args) => init(&args.directory),
        Command::Check(args) => check(args),
        Command::Package(args) => package(args),
        Command::Plan(args) => operate::plan(&args.runtime_config),
        Command::Apply(args) => operate::apply(
            &args.activation.runtime_config,
            args.operator_reference.as_deref(),
            &args.backups,
        ),
        Command::Status(args) => operate::status(&args.runtime_config),
        Command::Verification(VerificationCommand::List(args)) => {
            operate::dead_letters(&args.activation.runtime_config, args.limit)
        }
        Command::Verification(VerificationCommand::Replay(args)) => operate::replay(
            &args.activation.runtime_config,
            args.version_id,
            args.expected_generation,
        ),
    };
    finish(&outcome, command, cli.format, stdout, stderr)
}

/// The subcommand path a parsed invocation selected, as its report names it.
fn command_path(command: &Command) -> &'static str {
    match command {
        Command::Init(_) => "init",
        Command::Check(_) => "check",
        Command::Package(_) => "package",
        Command::Plan(_) => "plan",
        Command::Apply(_) => "apply",
        Command::Status(_) => "status",
        Command::Verification(VerificationCommand::List(_)) => "verification list",
        Command::Verification(VerificationCommand::Replay(_)) => "verification replay",
    }
}

fn init(directory: &Path) -> Outcome {
    match starter::write(directory) {
        Ok(created) => Outcome::new(
            json!({
                "directory": directory,
                "created": created,
                "next": [
                    "Run documentsctl check --project DIRECTORY --runtime-config DIRECTORY/runtime.example.yaml.",
                    "Run documentsctl package DIRECTORY --output PACKAGE, point runtime.yaml at PACKAGE and pin its digest, run documentsctl plan, then documentsctl apply, then documents serve.",
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
            format!("the starter could not be written: {}", error.kind()),
        ),
    }
}

/// Build the package from the project's `documents.yaml`, refusing a
/// project its reader refuses. The package holds that one file, which is
/// what `documents serve` accepts.
fn package(args: &PackageArgs) -> Outcome {
    let bytes = match read_project(&args.project) {
        Ok(bytes) => bytes,
        Err(report) => return Outcome::diagnosed(OPERATIONAL_FAILURE_EXIT, &report),
    };
    let file = args.project.join(PROJECT_FILE).display().to_string();
    let warnings = match DocumentsProject::decode(&file, &bytes) {
        Ok(decoded) => decoded.document.warnings(),
        Err(mut report) => {
            report.set_files_checked(1);
            return Outcome::diagnosed(DOMAIN_REFUSAL_EXIT, &report);
        }
    };
    let files = BTreeMap::from([(PROJECT_FILE.to_owned(), bytes)]);
    let revision = args.revision.as_deref();
    let built = if args.dry_run {
        plan_package(
            &args.output,
            &files,
            revision,
            &package_limits(),
            PACKAGE_COMMAND,
        )
    } else {
        write_package(
            &args.output,
            &files,
            revision,
            &package_limits(),
            PACKAGE_COMMAND,
        )
        .map(|package| package.digest().to_owned())
    };
    match built {
        Ok(digest) => Outcome::new(
            json!({
                "project": args.project,
                "output": args.output,
                "dryRun": args.dry_run,
                "revision": args.revision,
                "packageDigest": digest,
                "files": [PROJECT_FILE],
                "diagnostics": warnings.to_json_value(),
            }),
            View::Package,
        ),
        Err(error) => {
            let exit = if matches!(error.kind(), PackageErrorKind::Io { .. }) {
                OPERATIONAL_FAILURE_EXIT
            } else {
                DOMAIN_REFUSAL_EXIT
            };
            Outcome::refused(exit, "package.refused", "--output", error.to_string())
        }
    }
}

fn check(args: &CheckArgs) -> Outcome {
    let mut combined = Report::new(Vec::new());
    combined.set_files_checked(0);
    let mut unavailable = false;
    let mut report = json!({});
    if let Some(root) = &args.project {
        let (project, project_unavailable) = check_project(root);
        unavailable |= project_unavailable;
        combined.extend(project);
        report["project"] = json!(root);
    }
    if let Some(path) = &args.runtime_config {
        // The runtime reads only an absolute path; a relative one is
        // resolved against the working directory, as an operator means it.
        let Ok(absolute) = std::path::absolute(path) else {
            return Outcome::refused(
                OPERATIONAL_FAILURE_EXIT,
                "config.unresolvable",
                "arguments",
                "the --runtime-config path could not be resolved against the working directory"
                    .to_owned(),
            );
        };
        let runtime = check_runtime_file(&absolute, args.environment);
        unavailable |= runtime.unavailable;
        combined.extend(runtime.report);
        report["runtimeConfig"] = json!(path);
    }
    report["filesChecked"] = json!(combined.files_checked().unwrap_or(0));
    report["diagnostics"] = combined.to_json_value();
    let exit = check_exit(&combined, args.deny_warnings, unavailable);
    Outcome {
        report,
        exit,
        view: View::Check,
    }
}

/// The exit code of a check: an unreadable file outranks a refusal, and a
/// warning refuses only under `--deny-warnings`.
fn check_exit(report: &Report, deny_warnings: bool, unavailable: bool) -> u8 {
    if unavailable {
        OPERATIONAL_FAILURE_EXIT
    } else if report.has_errors() || (deny_warnings && report.warning_count() > 0) {
        DOMAIN_REFUSAL_EXIT
    } else {
        0
    }
}

/// Read and decode one project's `documents.yaml`. The flag is set when the
/// file could not be read at all, as opposed to read and refused.
fn check_project(root: &Path) -> (Report, bool) {
    let file = root.join(PROJECT_FILE).display().to_string();
    let bytes = match read_project(root) {
        Ok(bytes) => bytes,
        Err(report) => return (report, true),
    };
    let mut report = match DocumentsProject::decode(&file, &bytes) {
        Ok(decoded) => decoded.document.warnings(),
        Err(report) => report,
    };
    report.set_files_checked(1);
    (report, false)
}

/// The bytes of the project's `documents.yaml`, or the one diagnostic that
/// says it could not be read.
fn read_project(root: &Path) -> Result<Vec<u8>, Report> {
    let path = root.join(PROJECT_FILE);
    read_bounded(&path).map_err(|reason| {
        let mut diagnostic = Diagnostic::error(
            "project.unreadable",
            "",
            format!("the project file could not be read: {reason}"),
            "Name a project directory that holds a readable documents.yaml, then retry.",
        );
        diagnostic.artifact = Some(DOCUMENTS_PROJECT_KIND.to_owned());
        diagnostic.source = Some(Source {
            file: path.display().to_string(),
            line: None,
            column: None,
        });
        let mut report = Report::new(vec![diagnostic]);
        report.set_files_checked(0);
        report
    })
}

/// Read at most one byte past [`MAXIMUM_PROJECT_BYTES`], which is enough
/// for the shared reader to refuse a larger file as `yaml.too-large`. The
/// reason names the failure class and never the file's content.
fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| error.kind().to_string())?;
    let mut bytes = Vec::new();
    file.take(MAXIMUM_PROJECT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.kind().to_string())?;
    Ok(bytes)
}

/// Complete a command's own report into the shared envelope: `ok` agrees
/// with the exit code, `command` names the subcommand, and `status` names
/// what happened by exit class.
fn completed(report: &Value, command: &str, exit: u8) -> Value {
    let mut report = report.clone();
    report["ok"] = json!(exit == 0);
    report["command"] = json!(command);
    report["status"] = json!(if exit == 0 {
        "complete"
    } else {
        report::failure_status(exit)
    });
    report
}

fn finish(
    outcome: &Outcome,
    command: &str,
    format: OutputFormat,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    let written = match format {
        OutputFormat::Json => {
            report::write(&completed(&outcome.report, command, outcome.exit), stdout)
        }
        OutputFormat::Human => render_human(outcome, command, stdout, stderr),
    };
    match written {
        Ok(()) => ExitCode::from(outcome.exit),
        Err(_) => {
            // The report could not be written; this line may not land either,
            // and the exit code carries the failure regardless.
            let _ = writeln!(stderr, "documentsctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}

/// Human output: diagnostics on standard error, in the shared rendering
/// when they carry positions, and the command's result on standard output.
fn render_human(
    outcome: &Outcome,
    command: &str,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> io::Result<()> {
    let report = &outcome.report;
    let shared = shared_report(report);
    if outcome.exit != 0 {
        writeln!(stderr, "documentsctl {command} refused the input.")?;
        if matches!(outcome.view, View::Diagnostics) || command == "check" {
            return write!(stderr, "{}", shared.render_human());
        }
        for diagnostic in report["diagnostics"].as_array().into_iter().flatten() {
            writeln!(
                stderr,
                "{}[{}] {}: {}",
                diagnostic["severity"].as_str().unwrap_or("error"),
                text(&diagnostic["code"]),
                diagnostic["path"].as_str().unwrap_or("/"),
                text(&diagnostic["message"]),
            )?;
            if let Some(action) = diagnostic["suggestedAction"].as_str() {
                writeln!(stderr, "  next: {action}")?;
            }
        }
        return Ok(());
    }
    if !shared.is_empty() {
        write!(stderr, "{}", shared.render_human())?;
    }
    match outcome.view {
        View::Check | View::Diagnostics => writeln!(stdout, "checked: {}", shared.summary()),
        View::Init => {
            writeln!(stdout, "created: {}", text(&report["directory"]))?;
            for file in report["created"].as_array().into_iter().flatten() {
                writeln!(stdout, "  {}", text(file))?;
            }
            for next in report["next"].as_array().into_iter().flatten() {
                writeln!(stdout, "next: {}", text(next))?;
            }
            Ok(())
        }
        View::Package => {
            let verb = if report["dryRun"] == json!(true) {
                "would create"
            } else {
                "created"
            };
            writeln!(stdout, "{verb}: {}", text(&report["output"]))?;
            writeln!(stdout, "package digest: {}", text(&report["packageDigest"]))
        }
        View::Activation => render_activation(report, stdout),
        View::DeadLetters => {
            let letters = report["deadLetters"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if letters.is_empty() {
                return writeln!(stdout, "no dead-lettered content verification jobs");
            }
            for letter in &letters {
                writeln!(
                    stdout,
                    "{}  generation {}  attempt {}  dead-lettered {}",
                    text(&letter["versionId"]),
                    letter["generation"],
                    letter["attempt"],
                    text(&letter["deadLetteredAt"]),
                )?;
            }
            Ok(())
        }
        View::Replayed => writeln!(
            stdout,
            "replayed: {} is pending at generation {}",
            text(&report["versionId"]),
            report["generation"],
        ),
    }
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
    if let Some(version) = report.get("schemaVersion").filter(|value| !value.is_null()) {
        writeln!(stdout, "schema version: {version}")?;
    }
    if let Some(mode) = report.get("runtimeRoleMode").and_then(Value::as_str) {
        writeln!(stdout, "runtime role mode: {mode}")?;
    }
    if report["restartRequired"] == json!(true) {
        writeln!(
            stdout,
            "restart documents serve to load the activated package"
        )?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn starter() -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/documents/examples/starter")
            .canonicalize()
            .unwrap()
            .display()
            .to_string()
    }

    fn run(arguments: &[&OsStr]) -> (ExitCode, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut all = vec![OsStr::new("documentsctl")];
        all.extend_from_slice(arguments);
        let code = main_entry_from(all, &mut stdout, &mut stderr);
        (
            code,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    fn json_report(arguments: &[&str]) -> (ExitCode, Value) {
        let mut all = vec![OsStr::new("--format"), OsStr::new("json")];
        all.extend(arguments.iter().map(OsStr::new));
        let (code, stdout, stderr) = run(&all);
        assert!(stderr.is_empty(), "{stderr}");
        (code, serde_json::from_str(&stdout).unwrap())
    }

    fn starter_runtime() -> String {
        format!("{}/runtime.example.yaml", starter())
    }

    #[test]
    fn the_starter_project_and_runtime_check_clean() {
        let (project, runtime) = (starter(), starter_runtime());
        let (code, report) =
            json_report(&["check", "--project", &project, "--runtime-config", &runtime]);
        assert_eq!(code, ExitCode::SUCCESS, "{report:#}");
        assert_eq!(report["ok"], true);
        assert_eq!(report["command"], "check");
        assert_eq!(report["status"], "complete");
        assert_eq!(report["kind"], "DocumentsCtlReport");
        assert_eq!(report["filesChecked"], 2);
        assert_eq!(report["diagnostics"], json!([]));
    }

    #[test]
    fn a_human_check_that_passes_prints_one_summary_line() {
        let project = starter();
        let (code, stdout, stderr) = run(&[
            OsStr::new("check"),
            OsStr::new("--project"),
            OsStr::new(&project),
        ]);
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(stdout, "checked: 0 errors, 0 warnings in 1 file\n");
        assert!(stderr.is_empty(), "{stderr}");
    }

    #[test]
    fn a_refused_project_is_reported_at_its_member_and_exits_one() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let starter = std::fs::read_to_string(format!("{}/{PROJECT_FILE}", starter())).unwrap();
        let broken = starter.replacen(
            "kind: DocumentsProject",
            "kind: DocumentsProject\nunexpected: true",
            1,
        );
        assert_ne!(starter, broken);
        std::fs::write(directory.path().join(PROJECT_FILE), broken).unwrap();
        let root = directory.path().to_str().unwrap();
        let (code, report) = json_report(&["check", "--project", root]);
        assert_eq!(code, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert_eq!(report["ok"], false);
        assert_eq!(report["status"], "domain-refusal");
        let diagnostics = report["diagnostics"].as_array().unwrap();
        assert!(!diagnostics.is_empty());
        assert!(diagnostics
            .iter()
            .all(|diagnostic| diagnostic["suggestedAction"].is_string()));
        assert!(diagnostics
            .iter()
            .any(|diagnostic| diagnostic["path"] == "/unexpected"));
    }

    #[test]
    fn a_refused_runtime_configuration_names_the_finding_without_the_value() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let starter = std::fs::read_to_string(starter_runtime()).unwrap();
        let broken = starter.replacen(
            "https://scanner.example.test/v1/verify",
            "http://scanner.example.test/v1/verify",
            1,
        );
        assert_ne!(starter, broken);
        let path = directory.path().join("runtime.yaml");
        std::fs::write(&path, broken).unwrap();
        let (code, report) = json_report(&["check", "--runtime-config", path.to_str().unwrap()]);
        assert_eq!(code, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report:#}");
        let text = report.to_string();
        assert!(!text.contains("scanner.example.test"), "{text}");
        assert_eq!(report["diagnostics"][0]["path"], "/contentVerification/url");
    }

    #[test]
    fn a_missing_project_file_is_an_operational_failure() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let root = directory.path().to_str().unwrap();
        let (code, report) = json_report(&["check", "--project", root]);
        assert_eq!(code, ExitCode::from(OPERATIONAL_FAILURE_EXIT));
        assert_eq!(report["status"], "operational-failure");
        assert_eq!(report["diagnostics"][0]["code"], "project.unreadable");
    }

    #[test]
    fn check_needs_a_project_or_a_runtime_configuration() {
        let (code, report) = json_report(&["check"]);
        assert_eq!(code, ExitCode::from(USAGE_EXIT));
        assert_eq!(report["command"], "usage");
        assert_eq!(report["status"], "usage-error");
        let (code, _, stderr) = run(&[OsStr::new("check")]);
        assert_eq!(code, ExitCode::from(USAGE_EXIT));
        assert!(
            stderr.starts_with("error: missing required argument"),
            "{stderr}"
        );
    }

    #[test]
    fn the_environment_flag_needs_a_runtime_configuration() {
        let (code, _) = json_report(&["check", "--project", &starter(), "--environment"]);
        assert_eq!(code, ExitCode::from(USAGE_EXIT));
    }

    #[test]
    fn a_clean_check_passes_with_deny_warnings() {
        let (code, report) = json_report(&[
            "check",
            "--project",
            &starter(),
            "--runtime-config",
            &starter_runtime(),
            "--deny-warnings",
        ]);
        assert_eq!(code, ExitCode::SUCCESS, "{report:#}");
        assert_eq!(report["diagnostics"], json!([]));
    }

    #[test]
    fn deny_warnings_turns_a_warning_into_a_refusal() {
        let mut warning =
            Diagnostic::error("config.deprecated-api-version", "/apiVersion", "m", "a");
        warning.severity = registry_platform_yaml::Severity::Warning;
        let report = Report::new(vec![warning]);
        assert_eq!(check_exit(&report, false, false), 0);
        assert_eq!(check_exit(&report, true, false), DOMAIN_REFUSAL_EXIT);
        assert_eq!(check_exit(&report, true, true), OPERATIONAL_FAILURE_EXIT);
    }

    #[test]
    fn an_oversized_project_is_refused_by_the_reader_before_parsing() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let oversized = format!("#{}\n", "x".repeat(1024 * 1024));
        std::fs::write(directory.path().join(PROJECT_FILE), oversized).unwrap();
        let root = directory.path().to_str().unwrap();
        let (code, report) = json_report(&["check", "--project", root]);
        assert_eq!(code, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report:#}");
        assert_eq!(report["diagnostics"][0]["code"], "yaml.too-large");
        assert_eq!(report["diagnostics"][0]["path"], "");
    }

    #[test]
    fn the_command_tree_is_well_formed() {
        command().debug_assert();
    }

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
    }

    #[test]
    fn init_reports_the_files_it_wrote_and_refuses_an_existing_directory() {
        let parent = scratch();
        let directory = parent.path().join("project");
        let target = directory.to_str().unwrap();
        let (code, report) = json_report(&["init", target]);
        assert_eq!(code, ExitCode::SUCCESS, "{report:#}");
        assert_eq!(report["command"], "init");
        assert_eq!(report["status"], "complete");
        assert_eq!(
            report["created"],
            json!(["documents.yaml", "runtime.example.yaml"])
        );
        let (code, _) = json_report(&["check", "--project", target]);
        assert_eq!(code, ExitCode::SUCCESS, "the starter checks clean");
        let (code, report) = json_report(&["init", target]);
        assert_eq!(code, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert_eq!(report["status"], "domain-refusal");
        assert_eq!(report["diagnostics"][0]["code"], "init.exists");
        assert_eq!(report["diagnostics"][0]["artifact"], "filesystem");
    }

    #[test]
    fn package_writes_the_package_serve_verifies_and_dry_run_writes_nothing() {
        let parent = scratch();
        let output = parent.path().join("package");
        let target = output.to_str().unwrap();
        let (code, planned) = json_report(&[
            "package",
            &starter(),
            "--output",
            target,
            "--revision",
            "r1",
            "--dry-run",
        ]);
        assert_eq!(code, ExitCode::SUCCESS, "{planned:#}");
        assert!(!output.exists(), "a dry run writes nothing");
        let (code, report) = json_report(&[
            "package",
            &starter(),
            "--output",
            target,
            "--revision",
            "r1",
        ]);
        assert_eq!(code, ExitCode::SUCCESS, "{report:#}");
        assert_eq!(report["command"], "package");
        assert_eq!(report["files"], json!([PROJECT_FILE]));
        assert_eq!(report["packageDigest"], planned["packageDigest"]);
        let verified =
            registry_platform_config::verify_package(&output, &package_limits(), PACKAGE_COMMAND)
                .unwrap();
        assert_eq!(verified.digest(), report["packageDigest"]);
        assert_eq!(
            std::fs::read(output.join(PROJECT_FILE)).unwrap(),
            std::fs::read(format!("{}/{PROJECT_FILE}", starter())).unwrap()
        );
        assert!(
            !output.join("runtime.example.yaml").exists(),
            "the package holds only the project file"
        );
        let (code, report) = json_report(&["package", &starter(), "--output", target]);
        assert_eq!(code, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert_eq!(report["diagnostics"][0]["code"], "package.refused");
        assert_eq!(report["diagnostics"][0]["path"], "--output");
    }

    #[test]
    fn package_refuses_a_project_its_reader_refuses() {
        let project = scratch();
        let starter = std::fs::read_to_string(format!("{}/{PROJECT_FILE}", starter())).unwrap();
        std::fs::write(
            project.path().join(PROJECT_FILE),
            starter.replacen(
                "kind: DocumentsProject",
                "kind: DocumentsProject\nunexpected: true",
                1,
            ),
        )
        .unwrap();
        let output = project.path().join("package");
        let (code, report) = json_report(&[
            "package",
            project.path().to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
        assert_eq!(code, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{report:#}");
        assert!(report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["path"] == "/unexpected"));
        assert!(!output.exists());
        let missing = scratch();
        let (code, report) = json_report(&[
            "package",
            missing.path().to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
        assert_eq!(code, ExitCode::from(OPERATIONAL_FAILURE_EXIT));
        assert_eq!(report["diagnostics"][0]["code"], "project.unreadable");
    }

    #[test]
    fn a_database_command_refuses_the_package_before_reaching_the_database() {
        // The starter runtime names a package root that does not exist on
        // this machine, so each command stops at the package, as serve does.
        for command in [
            vec!["plan"],
            vec!["apply"],
            vec!["status"],
            vec!["verification", "list"],
            vec![
                "verification",
                "replay",
                "--version-id",
                "00000000-0000-4000-8000-000000000001",
                "--expected-generation",
                "1",
            ],
        ] {
            let runtime = starter_runtime();
            let mut arguments = command.clone();
            arguments.extend(["--runtime-config", runtime.as_str()]);
            let (code, report) = json_report(&arguments);
            assert_ne!(code, ExitCode::SUCCESS, "{command:?}: {report:#}");
            assert_eq!(
                report["command"],
                if command[0] == "verification" {
                    command[..2].join(" ")
                } else {
                    command[0].to_owned()
                }
            );
            assert_eq!(report["ok"], false);
            let diagnostics = report["diagnostics"].as_array().unwrap();
            assert!(!diagnostics.is_empty(), "{command:?}");
            assert!(diagnostics
                .iter()
                .all(|diagnostic| diagnostic["suggestedAction"].is_string()));
        }
    }

    #[test]
    fn a_missing_runtime_configuration_is_an_operational_failure() {
        let directory = scratch();
        let missing = directory.path().join("runtime.yaml");
        let (code, report) = json_report(&["plan", "--runtime-config", missing.to_str().unwrap()]);
        assert_eq!(code, ExitCode::from(OPERATIONAL_FAILURE_EXIT), "{report:#}");
        assert_eq!(report["command"], "plan");
        assert_eq!(report["status"], "operational-failure");
    }

    #[test]
    fn database_commands_need_a_runtime_configuration() {
        for command in [
            &["plan"][..],
            &["apply"],
            &["status"],
            &["verification", "list"],
        ] {
            let (code, report) = json_report(command);
            assert_eq!(code, ExitCode::from(USAGE_EXIT), "{command:?}");
            assert_eq!(report["status"], "usage-error");
            assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
        }
    }

    #[test]
    fn the_dead_letter_listing_is_bounded() {
        let runtime = starter_runtime();
        for limit in ["0", "501", "x"] {
            let (code, report) = json_report(&[
                "verification",
                "list",
                "--runtime-config",
                &runtime,
                "--limit",
                limit,
            ]);
            assert_eq!(code, ExitCode::from(USAGE_EXIT), "{limit}: {report:#}");
            assert!(
                report["diagnostics"][0]["message"]
                    .as_str()
                    .unwrap()
                    .contains("--limit"),
                "{report:#}"
            );
        }
        let parsed = Cli::try_parse_from([
            "documentsctl",
            "verification",
            "list",
            "--runtime-config",
            "r.yaml",
        ])
        .unwrap();
        let Command::Verification(VerificationCommand::List(args)) = parsed.command else {
            panic!("a listing");
        };
        assert_eq!(args.limit, DEFAULT_DEAD_LETTER_LISTING);
        assert!(Cli::try_parse_from([
            "documentsctl",
            "verification",
            "list",
            "--runtime-config",
            "r.yaml",
            "--limit",
            "500",
        ])
        .is_ok());
    }

    #[test]
    fn a_replay_names_one_version_and_the_generation_it_expects() {
        let runtime = starter_runtime();
        let version = "00000000-0000-4000-8000-000000000001";
        for arguments in [
            vec![
                "verification",
                "replay",
                "--runtime-config",
                &runtime,
                "--expected-generation",
                "1",
            ],
            vec![
                "verification",
                "replay",
                "--runtime-config",
                &runtime,
                "--version-id",
                version,
            ],
            vec![
                "verification",
                "replay",
                "--runtime-config",
                &runtime,
                "--version-id",
                "not-a-uuid",
                "--expected-generation",
                "1",
            ],
            vec![
                "verification",
                "replay",
                "--runtime-config",
                &runtime,
                "--version-id",
                version,
                "--expected-generation",
                "0",
            ],
        ] {
            let (code, report) = json_report(&arguments);
            assert_eq!(
                code,
                ExitCode::from(USAGE_EXIT),
                "{arguments:?}: {report:#}"
            );
            assert!(
                !report.to_string().contains("not-a-uuid"),
                "a refused value is not repeated"
            );
        }
    }

    #[test]
    fn every_refusal_code_names_its_own_next_step() {
        for code in [
            "documentsctl.activation.not-activated",
            "documentsctl.activation.package-not-active",
            "documentsctl.activation.database-id-mismatch",
            "documentsctl.activation.role-mode-weakened",
            "documentsctl.activation.grants-stale",
            "documentsctl.activation.ledger-unreadable",
            "documentsctl.activation.schema-newer",
            "documentsctl.activation.schema-invalid",
            "documentsctl.activation.invalid-reference",
            "verification.not-found",
            "verification.not-dead-lettered",
            "verification.stale-generation",
            "verification.changed",
            "audit.unconfirmed",
            "audit.unavailable",
            "package.outcome-unknown",
            "database.unavailable",
        ] {
            let fallback = guidance("unlisted.code", DOMAIN_REFUSAL_EXIT);
            assert_ne!(guidance(code, DOMAIN_REFUSAL_EXIT), fallback, "{code}");
        }
    }

    #[test]
    fn human_output_prints_the_result_and_each_refusal_with_its_next_step() {
        let parent = scratch();
        let directory = parent.path().join("project");
        let target = directory.as_os_str();
        let (code, stdout, stderr) = run(&[OsStr::new("init"), target]);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(stdout.starts_with("created: "), "{stdout}");
        assert!(stdout.contains("\n  documents.yaml\n"), "{stdout}");
        assert!(stderr.is_empty(), "{stderr}");
        let (code, stdout, stderr) = run(&[OsStr::new("init"), target]);
        assert_eq!(code, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stdout.is_empty(), "{stdout}");
        assert_eq!(
            stderr,
            "documentsctl init refused the input.\n\
             error[init.exists] /: the directory already exists; init never overwrites\n  \
             next: Name a directory that does not exist yet, then rerun documentsctl init.\n"
        );
    }
}
