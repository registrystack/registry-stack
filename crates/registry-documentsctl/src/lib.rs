// SPDX-License-Identifier: Apache-2.0

//! `documentsctl`, the Document Store adopter and local operator tooling.
//!
//! - `check` reads a project's `documents.yaml`, a runtime configuration,
//!   or both, exactly as the runtime's reader does, offline: no secret is
//!   resolved and no database is reached.
//!
//! Exit codes: 0 when the command succeeds, 1 when the project or runtime
//! configuration is refused, 2 for a usage error, and 3 when a file could
//! not be read or the report could not be written.
//!
//! With `--format json` every report opens with `ok`, `command`, and
//! `status`, in that order, then names its format with `apiVersion` and
//! `kind`. `status` is `complete` for a success and `domain-refusal`,
//! `usage-error`, or `operational-failure` by exit class for a failure,
//! whose `diagnostics` each name a `suggestedAction`.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_documents::config::check_runtime_file;
use registry_documents_core::{DocumentsProject, DOCUMENTS_PROJECT_KIND, PROJECT_FILE};
use registry_platform_yaml::{Diagnostic, Report, Source};
use serde_json::{json, Value};

mod report;

use report::{DOMAIN_REFUSAL_EXIT, OPERATIONAL_FAILURE_EXIT, USAGE_EXIT};

/// The largest `documents.yaml` file `check` reads.
const MAXIMUM_PROJECT_BYTES: u64 = 1024 * 1024;

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
    /// Check a project, a runtime configuration, or both, offline.
    Check(CheckArgs),
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

/// One command's result: the report and its exit code.
struct Outcome {
    report: Value,
    exit: u8,
}

impl Outcome {
    /// A refusal carrying one diagnostic about something other than a file
    /// the command read.
    fn refused(exit: u8, code: &str, artifact: &str, path: &str, message: String) -> Self {
        let action = if exit == USAGE_EXIT {
            USAGE_ACTION
        } else {
            "Correct the input the message names, then retry."
        };
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
            let message = report::usage_message(&error);
            if machine_mode {
                let outcome = Outcome::refused(
                    USAGE_EXIT,
                    "usage.invalid",
                    "command-arguments",
                    "arguments",
                    message,
                );
                return finish(&outcome, "usage", OutputFormat::Json, stdout, stderr);
            }
            // The exit code carries the refusal even when this line cannot
            // be written.
            let _ = writeln!(stderr, "error: {message}\n  next: {USAGE_ACTION}");
            return ExitCode::from(USAGE_EXIT);
        }
    };
    let outcome = match &cli.command {
        Command::Check(args) => check(args),
    };
    finish(&outcome, "check", cli.format, stdout, stderr)
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
                "runtime-configuration",
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
    Outcome { report, exit }
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
    let path = root.join(PROJECT_FILE);
    let file = path.display().to_string();
    let bytes = match read_bounded(&path) {
        Ok(bytes) => bytes,
        Err(reason) => {
            let mut diagnostic = Diagnostic::error(
                "project.unreadable",
                "",
                format!("the project file could not be read: {reason}"),
                "Name a project directory that holds a readable documents.yaml, then retry.",
            );
            diagnostic.artifact = Some(DOCUMENTS_PROJECT_KIND.to_owned());
            diagnostic.source = Some(Source {
                file,
                line: None,
                column: None,
            });
            let mut report = Report::new(vec![diagnostic]);
            report.set_files_checked(0);
            return (report, true);
        }
    };
    let mut report = match DocumentsProject::decode(&file, &bytes) {
        Ok(decoded) => decoded.document.warnings(),
        Err(report) => report,
    };
    report.set_files_checked(1);
    (report, false)
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
        OutputFormat::Human => render_human(outcome, stdout, stderr),
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

/// Human output: diagnostics in the shared rendering on standard error, and
/// a one-line confirmation on standard output for a check that passed.
fn render_human(
    outcome: &Outcome,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> io::Result<()> {
    let diagnostics: Vec<Diagnostic> =
        serde_json::from_value(outcome.report["diagnostics"].clone()).unwrap_or_default();
    let mut shared = Report::new(diagnostics);
    if let Some(files) = outcome.report["filesChecked"].as_u64() {
        shared.set_files_checked(usize::try_from(files).unwrap_or(usize::MAX));
    }
    if outcome.exit != 0 {
        writeln!(stderr, "documentsctl check refused the input.")?;
        return write!(stderr, "{}", shared.render_human());
    }
    if !shared.is_empty() {
        write!(stderr, "{}", shared.render_human())?;
    }
    writeln!(stdout, "checked: {}", shared.summary())
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
}
