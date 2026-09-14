// SPDX-License-Identifier: Apache-2.0

//! `schedulingctl`, the Registry Scheduling authoring and local operator
//! tooling: `init` writes a complete starter project, `check` validates the
//! authored policy offline, `test` replays every fixture offline, and
//! `explain` publishes what the runtime would serve.

mod project;
mod templates;

use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "schedulingctl",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Registry Scheduling authoring and local operator tooling"
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
    /// Create a complete Registry Scheduling authoring project in a new directory.
    Init(InitArgs),
    /// Validate the authored policy offline and print effective defaults.
    Check(CheckArgs),
    /// Run every fixture's replay cases offline.
    Test(ProjectArgs),
    /// Explain the checked policy offline: what the runtime would publish.
    Explain(ProjectArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// New directory for the authored scheduling project.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// Project template: standalone-exact-time or standalone-arrival-window.
    #[arg(long, value_name = "NAME")]
    template: String,
}

#[derive(Debug, Args)]
struct CheckArgs {
    /// Authored scheduling project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// Exit unsuccessfully when the authoring check reports any finding.
    #[arg(long)]
    deny_findings: bool,
}

#[derive(Debug, Args)]
struct ProjectArgs {
    /// Authored scheduling project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    #[default]
    Text,
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
                    &usage_failure(error.to_string()),
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
    let deny_findings = matches!(&cli.command, Command::Check(args) if args.deny_findings);
    match run(cli) {
        Ok(report) => {
            let outcome = write_success(&report, format, stdout, stderr);
            if outcome != ExitCode::SUCCESS {
                return outcome;
            }
            if report_is_refusal(&report, deny_findings) {
                ExitCode::from(DOMAIN_REFUSAL_EXIT)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            let (exit, diagnostic) = classify_failure(&error);
            write_failure(
                &json!({"ok": false, "diagnostics": [diagnostic]}),
                format,
                stdout,
                stderr,
            );
            ExitCode::from(exit)
        }
    }
}

fn run(cli: Cli) -> Result<Value> {
    match cli.command {
        Command::Init(args) => project::init(&args.project, &args.template),
        Command::Check(args) => project::check(&args.project),
        Command::Test(args) => project::test(&args.project),
        Command::Explain(args) => project::explain(&args.project),
    }
}

/// A completed report may still describe a refusal: an authoring check that
/// found something when the caller passed `--deny-findings`, or a fixture run
/// with failing cases, which always fails the build. The report is the
/// evidence; the exit code is the signal.
fn report_is_refusal(report: &Value, deny_findings: bool) -> bool {
    if report["command"] == "check" {
        return deny_findings && report["status"] == "incomplete";
    }
    report["fixtures"]
        .as_array()
        .is_some_and(|fixtures| fixtures.iter().any(|fixture| fixture["status"] == "failed"))
}

fn usage_failure(message: String) -> Value {
    json!({
        "ok": false,
        "command": "usage",
        "diagnostics": [{
            "severity": "error",
            "code": "schedulingctl.usage-invalid",
            "artifact": "command_arguments",
            "path": "arguments",
            "message": message,
            "suggestedAction": "Correct the command arguments and retry.",
        }],
    })
}

fn classify_failure(error: &anyhow::Error) -> (u8, Value) {
    let io_failure = error.chain().any(|cause| cause.is::<std::io::Error>());
    if io_failure {
        (
            OPERATIONAL_FAILURE_EXIT,
            json!({
                "severity": "error",
                "code": "schedulingctl.io-failure",
                "artifact": "filesystem",
                "path": "filesystem",
                "message": "A required filesystem operation failed.",
                "suggestedAction": "Correct the path or permissions, then retry.",
            }),
        )
    } else {
        (
            DOMAIN_REFUSAL_EXIT,
            json!({
                "severity": "error",
                "code": "schedulingctl.refused",
                "artifact": "scheduling_project",
                "path": "scheduling.yaml",
                "message": format!("{error:#}"),
                "suggestedAction": "Correct the authored input the message names, then retry.",
            }),
        )
    }
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
        OutputFormat::Text => render_human(report, stdout),
    };
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        let _ = writeln!(stderr, "schedulingctl: output could not be written");
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
                finding["code"].as_str().unwrap_or("schedulingctl.refused"),
                finding["path"].as_str().unwrap_or("command"),
                finding["message"].as_str().unwrap_or("command refused"),
            );
            if let Some(action) = finding["suggestedAction"].as_str() {
                let _ = writeln!(stderr, "  next: {action}");
            }
        }
    }
}

fn human_lead(report: &Value) -> String {
    let command = report["command"].as_str().unwrap_or("command");
    let failed_fixtures = report["fixtures"]
        .as_array()
        .is_some_and(|fixtures| fixtures.iter().any(|fixture| fixture["status"] == "failed"));
    match (
        command,
        report["status"].as_str(),
        report["authoringStatus"].as_str(),
    ) {
        ("check", Some("incomplete"), _) => {
            "Authoring check completed with incomplete inputs.".to_owned()
        }
        ("check", Some("complete"), _) => "Authoring check passed with complete inputs.".to_owned(),
        ("test", _, _) if failed_fixtures => {
            "Offline synthetic fixtures reported failures.".to_owned()
        }
        ("test", _, Some("incomplete")) => {
            "Offline synthetic fixtures passed with incomplete authored inputs.".to_owned()
        }
        ("test", _, _) => "Offline synthetic fixtures passed.".to_owned(),
        _ => format!("{command} succeeded."),
    }
}

fn render_human(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    writeln!(stdout, "{}", human_lead(report))?;
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
                "finding {}: {}",
                finding["path"].as_str().unwrap_or("scheduling.yaml"),
                finding["reason"].as_str().unwrap_or("review required"),
            )?;
        }
    }
    Ok(())
}

/// Command tree available to command-reference tooling.
#[must_use]
pub fn command() -> clap::Command {
    Cli::command()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run one invocation in JSON mode and return its exit code, its report
    /// (null when stdout carried no report), and its stderr.
    fn run_json(arguments: &[&str]) -> (ExitCode, Value, Vec<u8>) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut all = vec![
            OsString::from("schedulingctl"),
            OsString::from("--format=json"),
        ];
        all.extend(arguments.iter().map(OsString::from));
        let exit = main_entry_from(all, &mut stdout, &mut stderr);
        let report = serde_json::from_slice(&stdout).unwrap_or(Value::Null);
        (exit, report, stderr)
    }

    fn initialized(template: &str) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        project::init(&project, template).unwrap();
        (root, project)
    }

    #[test]
    fn canonical_command_shapes_and_default_format_are_stable() {
        let cli = Cli::try_parse_from(["schedulingctl", "check", "/tmp/project"]).unwrap();
        assert_eq!(cli.format, OutputFormat::Text);
        let Command::Check(args) = cli.command else {
            panic!("expected check")
        };
        assert_eq!(args.project, PathBuf::from("/tmp/project"));
        assert!(!args.deny_findings);

        let cli =
            Cli::try_parse_from(["schedulingctl", "check", "/tmp/project", "--deny-findings"])
                .unwrap();
        let Command::Check(args) = cli.command else {
            panic!("expected check")
        };
        assert!(args.deny_findings);

        let cli =
            Cli::try_parse_from(["schedulingctl", "--format", "json", "test", "/tmp/project"])
                .unwrap();
        assert_eq!(cli.format, OutputFormat::Json);

        let cli = Cli::try_parse_from([
            "schedulingctl",
            "init",
            "/tmp/project",
            "--template",
            "standalone-exact-time",
        ])
        .unwrap();
        let Command::Init(args) = cli.command else {
            panic!("expected init")
        };
        assert_eq!(args.template, "standalone-exact-time");

        for command in ["test", "explain"] {
            let cli = Cli::try_parse_from(["schedulingctl", command, "/tmp/project"]).unwrap();
            match command {
                "test" => assert!(matches!(cli.command, Command::Test(_))),
                _ => assert!(matches!(cli.command, Command::Explain(_))),
            }
        }

        assert!(Cli::try_parse_from([
            "schedulingctl",
            "init",
            "--template",
            "standalone-exact-time"
        ])
        .is_err());
        assert!(Cli::try_parse_from(["schedulingctl", "check"]).is_err());
    }

    #[test]
    fn every_template_initializes_checks_tests_and_explains_green() {
        for template in ["standalone-exact-time", "standalone-arrival-window"] {
            let root = tempfile::tempdir().unwrap();
            let project = root.path().join("project");
            let project_string = project.to_str().unwrap().to_owned();

            let (exit, report, stderr) =
                run_json(&["init", &project_string, &format!("--template={template}")]);
            assert_eq!(exit, ExitCode::SUCCESS, "{template}");
            assert!(stderr.is_empty());
            assert_eq!(report["command"], "init");

            let (exit, check, stderr) = run_json(&["check", &project_string]);
            assert_eq!(exit, ExitCode::SUCCESS, "{template}");
            assert!(stderr.is_empty());
            assert_eq!(check["status"], "complete", "{check}");

            let (exit, test, stderr) = run_json(&["test", &project_string]);
            assert_eq!(exit, ExitCode::SUCCESS, "{template}");
            assert!(stderr.is_empty());
            assert!(
                test["fixtures"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|fixture| fixture["status"] == "passed"),
                "{test}"
            );

            let (exit, explain, stderr) = run_json(&["explain", &project_string]);
            assert_eq!(exit, ExitCode::SUCCESS, "{template}");
            assert!(stderr.is_empty());
            assert!(explain["policyDigest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:"));
        }
    }

    /// A check that completes reports its findings and exits zero, so a human
    /// reads the report without parsing an exit code; `--deny-findings` is the
    /// CI switch that makes the same finding fail the build. A complete check
    /// passes either way.
    #[test]
    fn an_incomplete_check_exits_zero_unless_findings_are_denied() {
        let (_root, project) = initialized("standalone-exact-time");
        let policy_path = project.join("scheduling.yaml");
        let broken = std::fs::read_to_string(&policy_path).unwrap().replacen(
            "version: 1\n",
            "version: 0\n",
            1,
        );
        std::fs::write(&policy_path, broken).unwrap();
        let (exit, report, stderr) = run_json(&["check", project.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert_eq!(report["status"], "incomplete");
        assert!(report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["path"] == "scheduling.version" && finding["reason"] == "invalid-bound"
            }));

        let (exit, report, stderr) =
            run_json(&["check", "--deny-findings", project.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
        assert_eq!(report["status"], "incomplete");

        let (_root, clean) = initialized("standalone-exact-time");
        let (exit, report, stderr) =
            run_json(&["check", "--deny-findings", clean.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert_eq!(report["status"], "complete");
    }

    #[test]
    fn a_failing_fixture_case_is_reported_and_exits_nonzero() {
        let (_root, project) = initialized("standalone-exact-time");
        let fixture_path = project.join("fixtures/counter-stations.yaml");
        let broken = std::fs::read_to_string(&fixture_path).unwrap().replacen(
            "code: booking.duplicate-active",
            "code: capacity.exhausted",
            1,
        );
        std::fs::write(&fixture_path, broken).unwrap();
        let (exit, report, stderr) = run_json(&["test", project.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
        let fixtures = report["fixtures"].as_array().unwrap();
        let counter = fixtures
            .iter()
            .find(|fixture| fixture["name"] == "counter-stations")
            .unwrap();
        assert_eq!(counter["status"], "failed");
        let case = counter["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "same-key-retry-is-refused")
            .unwrap();
        assert_eq!(case["status"], "fail");
        // The detail reports what actually happened: the duplicate-active
        // refusal the broken expectation no longer matches.
        assert!(case["detail"]
            .as_str()
            .unwrap()
            .contains("booking.duplicate-active"));
    }

    #[test]
    fn a_fixture_that_cannot_replay_is_a_domain_refusal_with_a_diagnostic() {
        let (_root, project) = initialized("standalone-exact-time");
        let fixture_path = project.join("fixtures/counter-stations.yaml");
        let broken = std::fs::read_to_string(&fixture_path).unwrap().replacen(
            "code: booking.duplicate-active",
            "code: not-a-problem-code",
            1,
        );
        std::fs::write(&fixture_path, broken).unwrap();
        let (exit, report, stderr) = run_json(&["test", project.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
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
        assert_eq!(diagnostic["code"], "schedulingctl.refused");
        assert!(diagnostic["message"]
            .as_str()
            .unwrap()
            .contains("not-a-problem-code"));
    }

    #[test]
    fn usage_json_has_the_common_diagnostic_fields_and_exit_two() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(
            ["schedulingctl", "--format", "json", "check"],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::from(2));
        assert!(stderr.is_empty());
        let report: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(report["command"], "usage");
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
        let exit = main_entry_from(["schedulingctl", "check"], &mut stdout, &mut stderr);
        assert_eq!(exit, ExitCode::from(2));
        assert!(stdout.is_empty());
        assert!(!stderr.is_empty());
    }

    #[test]
    fn a_missing_project_is_an_operational_failure_on_the_selected_channel() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing").to_str().unwrap().to_owned();
        let (exit, report, stderr) = run_json(&["check", &missing]);
        assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT));
        assert!(stderr.is_empty());
        assert_eq!(report["diagnostics"][0]["code"], "schedulingctl.io-failure");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(
            ["schedulingctl", "check", missing.as_str()],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT));
        assert!(stdout.is_empty());
        assert!(String::from_utf8_lossy(&stderr).starts_with("error[schedulingctl.io-failure]"));
    }

    #[test]
    fn text_reports_render_the_lead_the_proof_boundary_and_findings() {
        let (_root, project) = initialized("standalone-exact-time");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(
            ["schedulingctl", "test", project.to_str().unwrap()],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        let text = String::from_utf8(stdout).unwrap();
        assert!(text.starts_with("Offline synthetic fixtures passed."));
        assert!(text.contains("proofBoundary: offline_synthetic"));
        assert!(text.contains("productionClosure: false"));
        assert!(text.contains("networkAccess: false"));

        let mut stdout = Vec::new();
        let exit = main_entry_from(
            ["schedulingctl", "check", project.to_str().unwrap()],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::SUCCESS);
        let text = String::from_utf8(stdout).unwrap();
        assert!(text.starts_with("Authoring check passed with complete inputs."));
        // Nested report objects render as compact JSON.
        assert!(text.contains("\"schedulingId\":\"registry-updates\""));

        // An incomplete check renders its findings in text mode too, and
        // exits zero unless findings were denied.
        let policy_path = project.join("scheduling.yaml");
        let broken = std::fs::read_to_string(&policy_path).unwrap().replacen(
            "version: 1\n",
            "version: 0\n",
            1,
        );
        std::fs::write(&policy_path, broken).unwrap();
        let mut stdout = Vec::new();
        let exit = main_entry_from(
            ["schedulingctl", "check", project.to_str().unwrap()],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, ExitCode::SUCCESS);
        let text = String::from_utf8(stdout).unwrap();
        assert!(text.starts_with("Authoring check completed with incomplete inputs."));
        assert!(text.contains("finding scheduling.version: invalid-bound"));
    }
}
