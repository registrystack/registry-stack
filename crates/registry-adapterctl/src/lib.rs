// SPDX-License-Identifier: Apache-2.0

//! `adapterctl`, the Registry Stack Adapter authoring and operator tooling.
//!
//! This crate owns the `adapterctl` binary. Its commands: `check`, the
//! offline check over authored artifacts (project, profile, pack, fixtures,
//! and with `--runtime` the runtime config); `project lock`, the pin
//! rewriter; `schemas`, the generator and drift gate of the five format
//! JSON Schemas; `compile`, the per-deployment contract compiler;
//! `fixtures replay`, the offline replay of a project's fixture suites
//! against its compiled contract; and `verify --live`, the probe that
//! drives one constant-determined send per binding against the
//! destination the runtime names. It reads the same
//! source-neutral model the runtime serves, so an artifact `adapterctl
//! check` accepts is one the runtime can interpret.

mod check;
mod compile;
mod fixtures;
mod project;
mod report;
mod schemas;
mod verify;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use registry_platform_yaml::Report;
use serde_json::{json, Value};
use std::ffi::{OsStr, OsString};
use std::io;
use std::process::ExitCode;

use report::{
    failure, failure_status, usage_message, DOMAIN_REFUSAL_EXIT, OPERATIONAL_FAILURE_EXIT,
    USAGE_EXIT,
};

#[derive(Debug, Parser)]
#[command(
    name = "adapterctl",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Registry Stack Adapter authoring and operator tooling"
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
    /// Check an authored adapter project, its pinned profile and pack, and
    /// its fixtures, offline, and print the findings.
    Check(check::CheckArgs),
    /// Operate one authored adapter project.
    Project(project::ProjectArgs),
    /// Write the generated JSON Schemas of the five Adapter formats, or
    /// check the committed ones for drift.
    Schemas(schemas::SchemasArgs),
    /// Compile the deployment's concrete OpenAPI contract beside the
    /// project, or check the written one for drift.
    Compile(compile::CompileArgs),
    /// Replay the project's fixture suites, offline.
    Fixtures(fixtures::FixturesArgs),
    /// Drive one constant-determined send per binding against the
    /// destination the runtime names, live.
    Verify(verify::VerifyArgs),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

/// Entry point behind the thin `main.rs`, so tests can run it in process.
pub fn main_entry() -> ExitCode {
    main_entry_from(
        std::env::args_os(),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
}

/// The next step for a command line clap refused.
const USAGE_ACTION: &str =
    "Run adapterctl --help, or the command with --help, and retry with the documented arguments.";

/// Run one invocation against the given streams.
pub fn main_entry_from<I, T>(
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
    let cli = match Cli::try_parse_from(&args) {
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
            let message = usage_message(&error);
            if machine_mode {
                if write_failure(&usage_failure(message), OutputFormat::Json, stdout, stderr)
                    .is_err()
                {
                    return output_failed(stderr);
                }
            } else {
                let _ = writeln!(stderr, "error: {message}\n  next: {USAGE_ACTION}");
            }
            return ExitCode::from(USAGE_EXIT);
        }
    };
    let Cli { format, command } = cli;
    let command_name = match &command {
        Command::Check(_) => "check",
        Command::Project(project) => match project.command {
            project::ProjectCommand::Lock(_) => "project lock",
        },
        Command::Schemas(_) => "schemas",
        Command::Compile(_) => "compile",
        Command::Fixtures(fixtures) => match fixtures.command {
            fixtures::FixturesCommand::Replay(_) => "fixtures replay",
        },
        Command::Verify(_) => "verify",
    };
    let outcome = match command {
        Command::Check(args) => check_command(args, format, command_name, stdout, stderr),
        Command::Project(args) => project_command(args, format, command_name, stdout, stderr),
        Command::Schemas(args) => schemas_command(args, format, command_name, stdout, stderr),
        Command::Compile(args) => compile_command(args, format, command_name, stdout, stderr),
        Command::Fixtures(args) => fixtures_command(args, format, command_name, stdout, stderr),
        Command::Verify(args) => verify_command(args, format, command_name, stdout, stderr),
    };
    match outcome {
        Ok(exit) => exit,
        Err(()) => output_failed(stderr),
    }
}

fn usage_failure(message: String) -> Value {
    failure(
        "usage",
        USAGE_EXIT,
        vec![json!({
            "severity": "error",
            "code": "adapterctl.usage-invalid",
            "artifact": "command-arguments",
            "path": "arguments",
            "message": message,
            "suggestedAction": USAGE_ACTION,
        })],
    )
}

/// Whether the check verdict refuses: any error always refuses, and with
/// `--deny-warnings` a warning refuses too.
fn refused(diagnostics: &[registry_platform_yaml::Diagnostic], deny_warnings: bool) -> bool {
    diagnostics
        .iter()
        .any(|diagnostic| match diagnostic.severity {
            registry_platform_yaml::Severity::Error => true,
            registry_platform_yaml::Severity::Warning => deny_warnings,
        })
}

/// Run `check` and write its verdict: a complete report, a refusal carrying
/// the findings, or a failure naming the broken environment.
fn check_command(
    args: check::CheckArgs,
    format: OutputFormat,
    command_name: &'static str,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<ExitCode, ()> {
    let run = match check::run(&args) {
        Ok(run) => run,
        Err(check::CheckFailure::Io { path, source }) => {
            let exit = OPERATIONAL_FAILURE_EXIT;
            let report = failure(
                command_name,
                exit,
                vec![json!({
                    "severity": "error",
                    "code": "adapterctl.io-failure",
                    "artifact": "filesystem",
                    "path": path,
                    "message": format!("the file could not be read: {source}"),
                    "suggestedAction": "Correct the path or permissions, then retry.",
                })],
            );
            return write_failure(&report, format, stdout, stderr).map(|()| ExitCode::from(exit));
        }
    };
    let errors = refused(&run.diagnostics, args.deny_warnings);
    if errors {
        let mut checked = Report::new(run.diagnostics);
        checked.set_files_checked(run.files_checked);
        let exit = DOMAIN_REFUSAL_EXIT;
        let envelope = json!({
            "ok": false,
            "command": command_name,
            "status": failure_status(exit),
            "diagnostics": checked.to_json_value(),
            "filesChecked": run.files_checked,
        });
        return write_configuration_report(
            &checked,
            command_name,
            format,
            envelope,
            stdout,
            stderr,
        )
        .map(|()| ExitCode::from(exit));
    }
    let mut checked = Report::new(run.diagnostics);
    checked.set_files_checked(run.files_checked);
    let mut envelope = json!({
        "ok": true,
        "command": command_name,
        "status": "complete",
        "project": run.project,
        "filesChecked": run.files_checked,
        "diagnostics": checked.to_json_value(),
    });
    if run.fixtures_checked > 0 {
        // The fixture pass checked the contracts only; the send-by-send
        // replay activates with the route engine (CONCEPT 13.3). The
        // field says so, so a green pass is not read as a route test.
        envelope["fixtures"] = json!("contracts only, replay not run");
    }
    write_success(&envelope, &checked, format, stdout)
}

/// Run `project lock` and write its verdict: the rewritten pins, a refusal
/// carrying the reader's findings, or a failure naming the broken
/// environment.
fn project_command(
    args: project::ProjectArgs,
    format: OutputFormat,
    command_name: &'static str,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<ExitCode, ()> {
    let project::ProjectCommand::Lock(args) = args.command;
    let run = match project::run_lock(&args) {
        Ok(run) => run,
        Err(project::LockFailure::Io { path, source }) => {
            let exit = OPERATIONAL_FAILURE_EXIT;
            let report = failure(
                command_name,
                exit,
                vec![json!({
                    "severity": "error",
                    "code": "adapterctl.io-failure",
                    "artifact": "filesystem",
                    "path": path,
                    "message": format!("the file could not be read: {source}"),
                    "suggestedAction": "Correct the path or permissions, then retry.",
                })],
            );
            return write_failure(&report, format, stdout, stderr).map(|()| ExitCode::from(exit));
        }
    };
    let errors = refused(&run.diagnostics, false);
    let mut checked = Report::new(run.diagnostics);
    checked.set_files_checked(run.files_checked);
    if errors {
        let exit = DOMAIN_REFUSAL_EXIT;
        let envelope = json!({
            "ok": false,
            "command": command_name,
            "status": failure_status(exit),
            "diagnostics": checked.to_json_value(),
            "filesChecked": run.files_checked,
        });
        return write_configuration_report(
            &checked,
            command_name,
            format,
            envelope,
            stdout,
            stderr,
        )
        .map(|()| ExitCode::from(exit));
    }
    let envelope = json!({
        "ok": true,
        "command": command_name,
        "status": "complete",
        "project": run.project,
        "filesChecked": run.files_checked,
        "diagnostics": checked.to_json_value(),
        "profile": run.profile.as_str(),
        "pack": run.pack.as_str(),
        "inventory": run.inventory.as_str(),
    });
    write_success(&envelope, &checked, format, stdout)
}

/// Run `schemas` and write its verdict.
fn schemas_command(
    args: schemas::SchemasArgs,
    format: OutputFormat,
    command_name: &'static str,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<ExitCode, ()> {
    match schemas::run(&args) {
        Ok(mut report) => {
            report["ok"] = json!(true);
            report["status"] = json!("complete");
            let mut out = Vec::new();
            report::write(&report, &mut out).map_err(|_| ())?;
            if format == OutputFormat::Json {
                let _ = stdout.write_all(&out);
            } else {
                let _ = writeln!(stdout, "{}", human_lead(&report));
                if let Some(files) = report["files"].as_array() {
                    for file in files {
                        let _ = writeln!(stdout, "{}", file.as_str().unwrap_or_default());
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            let (exit, diagnostics) = schemas::failure(&error);
            let report = failure(command_name, exit, diagnostics);
            write_failure(&report, format, stdout, stderr).map(|()| ExitCode::from(exit))
        }
    }
}

/// Run `compile` and write its verdict.
fn compile_command(
    args: compile::CompileArgs,
    format: OutputFormat,
    command_name: &'static str,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<ExitCode, ()> {
    match compile::run(&args) {
        Ok(run) => {
            let mut report = json!({
                "command": command_name,
                "check": run.check,
                "project": run.project,
                "output": run.output,
                "operations": run.operations,
            });
            report["ok"] = json!(true);
            report["status"] = json!("complete");
            let mut out = Vec::new();
            report::write(&report, &mut out).map_err(|_| ())?;
            if format == OutputFormat::Json {
                let _ = stdout.write_all(&out);
            } else {
                let _ = writeln!(stdout, "{}", human_lead(&report));
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            let (exit, diagnostics) = compile::failure(&error);
            let report = failure(command_name, exit, diagnostics);
            write_failure(&report, format, stdout, stderr).map(|()| ExitCode::from(exit))
        }
    }
}

/// Run `fixtures replay` and write its verdict: the replayed counts, a
/// refusal carrying the findings, or a failure naming the broken
/// environment.
fn fixtures_command(
    args: fixtures::FixturesArgs,
    format: OutputFormat,
    command_name: &'static str,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<ExitCode, ()> {
    let fixtures::FixturesCommand::Replay(args) = args.command;
    match fixtures::run(&args) {
        Ok(run) => {
            let mut report = json!({
                "command": command_name,
                "project": run.project,
                "drive": "completed",
                "fixtures": run.fixtures,
                "entries": run.entries,
                "upstreamExchanges": run.exchanges,
                "writesSimulated": run.writes_simulated,
                "journalDurability": "not-run",
            });
            report["ok"] = json!(true);
            report["status"] = json!("complete");
            let mut out = Vec::new();
            report::write(&report, &mut out).map_err(|_| ())?;
            if format == OutputFormat::Json {
                let _ = stdout.write_all(&out);
            } else {
                let _ = writeln!(stdout, "{}", human_lead(&report));
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            let (exit, diagnostics) = fixtures::failure(&error);
            let report = failure(command_name, exit, diagnostics);
            write_failure(&report, format, stdout, stderr).map(|()| ExitCode::from(exit))
        }
    }
}

/// Run `verify --live` and write its verdict: the drove and waited
/// counts with the wait reasons, a refusal carrying the findings, or a
/// failure naming the broken environment or the step that stopped.
fn verify_command(
    args: verify::VerifyArgs,
    format: OutputFormat,
    command_name: &'static str,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<ExitCode, ()> {
    match verify::run(&args) {
        Ok(run) => {
            let mut checked = Report::new(run.warnings);
            checked.set_files_checked(run.files_checked);
            let mut report = json!({
                "command": command_name,
                "project": run.project,
                "runtime": run.runtime,
                "drove": run.drove,
                "waited": run.waited,
                "waits": run.waits,
                "filesChecked": run.files_checked,
                "diagnostics": checked.to_json_value(),
            });
            report["ok"] = json!(true);
            report["status"] = json!("complete");
            write_success(&report, &checked, format, stdout)
        }
        Err(verify::VerifyFailure::Io { path, source }) => {
            let exit = OPERATIONAL_FAILURE_EXIT;
            let report = failure(
                command_name,
                exit,
                vec![json!({
                    "severity": "error",
                    "code": "adapterctl.io-failure",
                    "artifact": "filesystem",
                    "path": path,
                    "message": format!("the file could not be read: {source}"),
                    "suggestedAction": "Correct the path or permissions, then retry.",
                })],
            );
            write_failure(&report, format, stdout, stderr).map(|()| ExitCode::from(exit))
        }
        Err(verify::VerifyFailure::Refused {
            diagnostics,
            files_checked,
        }) => {
            let mut checked = Report::new(diagnostics);
            checked.set_files_checked(files_checked);
            let exit = DOMAIN_REFUSAL_EXIT;
            let envelope = json!({
                "ok": false,
                "command": command_name,
                "status": failure_status(exit),
                "diagnostics": checked.to_json_value(),
                "filesChecked": files_checked,
            });
            write_configuration_report(&checked, command_name, format, envelope, stdout, stderr)
                .map(|()| ExitCode::from(exit))
        }
        Err(verify::VerifyFailure::Stopped { exit, diagnostics }) => {
            let report = failure(command_name, exit, diagnostics);
            write_failure(&report, format, stdout, stderr).map(|()| ExitCode::from(exit))
        }
    }
}

/// Print a configuration refusal unchanged: the CFG-DIAG-2 lines on stderr,
/// or, with `--format json`, the CFG-DIAG-1 diagnostics in the report
/// envelope on stdout.
fn write_configuration_report(
    report: &Report,
    command: &str,
    format: OutputFormat,
    envelope: Value,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<(), ()> {
    if format == OutputFormat::Json {
        report::write(&envelope, stdout).map_err(|_| ())?;
    } else {
        let _ = writeln!(stderr, "adapterctl {command} refused the input.");
        let _ = write!(stderr, "{}", report.render_human());
    }
    Ok(())
}

fn write_success(
    report: &Value,
    checked: &Report,
    format: OutputFormat,
    stdout: &mut dyn io::Write,
) -> Result<ExitCode, ()> {
    let result = match format {
        OutputFormat::Json => report::write(report, stdout),
        OutputFormat::Human => render_human(report, checked, stdout),
    };
    result.map(|()| ExitCode::SUCCESS).map_err(|_| ())
}

/// The human form of a completed command: the lead line, the report's own
/// members, and the reader's summary of the files it checked.
fn render_human(report: &Value, checked: &Report, stdout: &mut dyn io::Write) -> io::Result<()> {
    writeln!(stdout, "{}", human_lead(report))?;
    if let Some(fields) = report.as_object() {
        for (key, value) in fields {
            if matches!(
                key.as_str(),
                "ok" | "command"
                    | "status"
                    | "diagnostics"
                    | "apiVersion"
                    | "kind"
                    | "filesChecked"
            ) || value.is_null()
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
    write!(stdout, "{}", checked.render_human())
}

fn human_lead(report: &Value) -> String {
    match report["command"].as_str().unwrap_or("command") {
        "check" => "Authoring check passed.".to_owned(),
        "schemas" if report["check"] == json!(true) => "Schema drift check passed.".to_owned(),
        "schemas" => "Generated schemas written; nothing drifted.".to_owned(),
        "compile" if report["check"] == json!(true) => "Compile drift check passed.".to_owned(),
        "compile" => "Compiled contract written.".to_owned(),
        "fixtures replay" => {
            "Fixture replay completed through the runtime engine; upstream sends were intercepted offline."
                .to_owned()
        }
        "verify" => match report["drove"].as_u64().unwrap_or_default() {
            0 => {
                "Live verify drove no upstream send; every binding waits for the engine data path."
                    .to_owned()
            }
            1 => "Live verify drove 1 upstream send within its declared range.".to_owned(),
            drove => {
                format!("Live verify drove {drove} upstream sends within their declared range.")
            }
        },
        other => format!("{other} completed."),
    }
}

fn write_failure(
    report: &Value,
    format: OutputFormat,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<(), ()> {
    if format == OutputFormat::Json {
        return report::write(report, stdout).map_err(|_| ());
    }
    if matches!(
        report["command"].as_str(),
        Some("check") | Some("compile") | Some("project lock")
    ) {
        let command = report["command"].as_str().unwrap_or_default();
        let _ = writeln!(stderr, "adapterctl {command} refused the input.");
    }
    if let Some(diagnostics) = report["diagnostics"].as_array() {
        for finding in diagnostics {
            let _ = writeln!(
                stderr,
                "{}[{}] {}: {}",
                finding["severity"].as_str().unwrap_or("error"),
                finding["code"].as_str().unwrap_or("adapterctl.refused"),
                finding["path"].as_str().unwrap_or("command"),
                finding["message"].as_str().unwrap_or("command refused"),
            );
            if let Some(action) = finding["suggestedAction"].as_str() {
                let _ = writeln!(stderr, "  next: {action}");
            }
        }
    }
    Ok(())
}

/// The exit for a report that could not be written to standard output.
fn output_failed(stderr: &mut dyn io::Write) -> ExitCode {
    let _ = writeln!(stderr, "adapterctl: output could not be written");
    ExitCode::from(OPERATIONAL_FAILURE_EXIT)
}

/// Command tree available to command-reference tooling.
#[must_use]
pub fn command() -> clap::Command {
    Cli::command()
}

#[cfg(test)]
mod tests {
    use super::refused;
    use registry_platform_yaml::Diagnostic;

    #[test]
    fn deny_warnings_refuses_a_warning_only_when_asked() {
        let warning = Diagnostic::warning(
            "config.deprecated-api-version",
            "/apiVersion",
            "the apiVersion is deprecated",
            "Write the current apiVersion.",
        );
        assert!(!refused(&[], true));
        assert!(!refused(std::slice::from_ref(&warning), false));
        assert!(refused(std::slice::from_ref(&warning), true));
        let error = Diagnostic::error(
            "config.unknown-key",
            "/stray",
            "the key is not part of the format",
            "Remove the key.",
        );
        assert!(refused(&[warning, error], false));
    }
}
