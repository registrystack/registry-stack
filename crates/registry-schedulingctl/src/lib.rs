// SPDX-License-Identifier: Apache-2.0

//! `schedulingctl`, the Registry Scheduling authoring and local operator
//! tooling: `init` writes a complete starter project, `check` validates the
//! authored policy offline, `test` replays every fixture offline, `explain`
//! publishes what the runtime would serve, `package` writes the deployment
//! identity the runtime verifies, `records apply` performs the one
//! attributable operator write of a deployment's live environment records,
//! and `intents` reads the delivery intents a deployment's sweep has stopped
//! carrying.

pub mod intents;
mod project;
pub mod records;
mod templates;

use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_scheduling::config::RuntimeConfigError;
use registry_scheduling::store::StoreError;
use registry_scheduling_core::AUTHORED_POLICY_FILE;
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
    /// Write the verified policy package manifest beside the authored policy.
    Package(ProjectArgs),
    /// Apply the live environment records of a deployment.
    Records(RecordsArgs),
    /// List delivery intents a deployment's sweep has stopped carrying.
    Intents(IntentsArgs),
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

#[derive(Debug, Args)]
struct RecordsArgs {
    #[command(subcommand)]
    command: RecordsCommand,
}

#[derive(Debug, Subcommand)]
enum RecordsCommand {
    /// Replace the deployment's environment records in one attributable write.
    Apply(RecordsApplyArgs),
}

#[derive(Debug, Args)]
struct RecordsApplyArgs {
    /// Runtime configuration document of the deployment to write.
    #[arg(value_name = "RUNTIME_CONFIG")]
    config: PathBuf,
    /// Environment records document: locations, pools, and exceptions.
    #[arg(value_name = "RECORDS")]
    records: PathBuf,
}

#[derive(Debug, Args)]
struct IntentsArgs {
    /// Runtime configuration document of the deployment to read.
    #[arg(value_name = "RUNTIME_CONFIG")]
    config: PathBuf,
    /// Most intents to list.
    #[arg(long, default_value_t = 50)]
    limit: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
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
        Ok(mut report) => {
            // The exit code already tells the caller whether this refused;
            // the JSON must agree instead of reporting "ok": true underneath
            // a nonzero exit.
            let refusal = report_is_refusal(&report, deny_findings);
            if refusal {
                report["ok"] = json!(false);
            }
            let outcome = write_success(&report, format, stdout, stderr);
            if outcome != ExitCode::SUCCESS {
                return outcome;
            }
            if refusal {
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
        Command::Package(args) => project::package(&args.project),
        Command::Records(args) => match args.command {
            RecordsCommand::Apply(apply) => records::apply(&apply.config, &apply.records),
        },
        Command::Intents(args) => intents::undelivered(&args.config, args.limit),
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
    // A runtime configuration that will not load is a defect in an authored
    // document; a store that cannot be reached is a defect in the deployment
    // environment. Both name their own artifact instead of hiding behind the
    // generic authoring refusal.
    if error
        .chain()
        .any(|cause| cause.downcast_ref::<RuntimeConfigError>().is_some())
    {
        return (
            DOMAIN_REFUSAL_EXIT,
            json!({
                "severity": "error",
                "code": "schedulingctl.runtime-configuration.invalid",
                "artifact": "runtime_configuration",
                "path": "runtime.yaml",
                "message": format!("{error:#}"),
                "suggestedAction": "Correct the runtime configuration the message names, then retry.",
            }),
        );
    }
    if error
        .chain()
        .any(|cause| cause.downcast_ref::<StoreError>().is_some())
    {
        return (
            OPERATIONAL_FAILURE_EXIT,
            json!({
                "severity": "error",
                "code": "schedulingctl.store-unavailable",
                "artifact": "database",
                "path": "database",
                "message": format!("{error:#}"),
                "suggestedAction": "Restore the Scheduling database or its credentials, then retry.",
            }),
        );
    }
    if io_failure {
        (
            OPERATIONAL_FAILURE_EXIT,
            json!({
                "severity": "error",
                "code": "schedulingctl.io-failure",
                "artifact": "filesystem",
                "path": "filesystem",
                "message": format!("{error:#}"),
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
                "path": AUTHORED_POLICY_FILE,
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
        OutputFormat::Human => render_human(report, stdout),
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
        ("package", _, _) => {
            "Policy package manifest written beside the authored policy.".to_owned()
        }
        ("records-apply", _, _) => "Environment records applied.".to_owned(),
        ("intents", _, _) => "Undelivered delivery intents listed.".to_owned(),
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
                finding["path"].as_str().unwrap_or(AUTHORED_POLICY_FILE),
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
        assert_eq!(cli.format, OutputFormat::Human);
        let Command::Check(args) = cli.command else {
            panic!("expected check")
        };
        assert_eq!(args.project, PathBuf::from("/tmp/project"));
        assert!(!args.deny_findings);

        // `--format` matches every sibling ctl's value names: `human` and
        // `json`, never `text`.
        let cli = Cli::try_parse_from([
            "schedulingctl",
            "--format",
            "human",
            "check",
            "/tmp/project",
        ])
        .unwrap();
        assert_eq!(cli.format, OutputFormat::Human);
        assert!(Cli::try_parse_from([
            "schedulingctl",
            "--format",
            "text",
            "check",
            "/tmp/project"
        ])
        .is_err());

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

        for command in ["test", "explain", "package"] {
            let cli = Cli::try_parse_from(["schedulingctl", command, "/tmp/project"]).unwrap();
            match command {
                "test" => assert!(matches!(cli.command, Command::Test(_))),
                "explain" => assert!(matches!(cli.command, Command::Explain(_))),
                _ => assert!(matches!(cli.command, Command::Package(_))),
            }
        }

        let cli = Cli::try_parse_from([
            "schedulingctl",
            "records",
            "apply",
            "/runtime.yaml",
            "/records.yaml",
        ])
        .unwrap();
        let Command::Records(RecordsArgs {
            command: RecordsCommand::Apply(args),
        }) = cli.command
        else {
            panic!("expected records apply")
        };
        assert_eq!(args.config, PathBuf::from("/runtime.yaml"));
        assert_eq!(args.records, PathBuf::from("/records.yaml"));

        assert!(Cli::try_parse_from(["schedulingctl", "records"]).is_err());
        assert!(
            Cli::try_parse_from(["schedulingctl", "records", "apply", "/runtime.yaml"]).is_err()
        );

        let cli = Cli::try_parse_from(["schedulingctl", "intents", "/runtime.yaml"]).unwrap();
        let Command::Intents(args) = cli.command else {
            panic!("expected intents")
        };
        assert_eq!(args.config, PathBuf::from("/runtime.yaml"));
        assert_eq!(args.limit, 50);

        let cli =
            Cli::try_parse_from(["schedulingctl", "intents", "/runtime.yaml", "--limit", "10"])
                .unwrap();
        let Command::Intents(args) = cli.command else {
            panic!("expected intents")
        };
        assert_eq!(args.limit, 10);

        assert!(Cli::try_parse_from(["schedulingctl", "intents"]).is_err());

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
        // Findings alone, without --deny-findings, are not a refusal.
        assert_eq!(report["ok"], true);
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
        // The exit code already says this refused; the JSON must agree.
        assert_eq!(report["ok"], false);

        let (_root, clean) = initialized("standalone-exact-time");
        let (exit, report, stderr) =
            run_json(&["check", "--deny-findings", clean.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert_eq!(report["status"], "complete");
        assert_eq!(report["ok"], true);
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
        // The exit code already says this refused; the JSON must agree.
        assert_eq!(report["ok"], false);
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
        // A failing case prints what the fixture expected and what actually
        // happened side by side, so a mismatch is legible without opening
        // the fixture file.
        let detail = case["detail"].as_str().unwrap();
        assert!(detail.contains("expected"), "{detail}");
        assert!(detail.contains("capacity.exhausted"), "{detail}");
        assert!(detail.contains("booking.duplicate-active"), "{detail}");
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
        // The path names the authored policy file by the crate's own
        // constant, not a literal that could drift from it.
        assert_eq!(diagnostic["path"], AUTHORED_POLICY_FILE);
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
        // The failure names the path and the operating system's reason
        // instead of a generic placeholder that could be any I/O failure.
        let message = report["diagnostics"][0]["message"].as_str().unwrap();
        assert!(message.contains(&missing), "{message}");
        assert!(
            message.to_lowercase().contains("no such file or directory"),
            "{message}"
        );

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

    #[test]
    fn package_writes_a_verifiable_manifest_and_refuses_replacement() {
        let (_root, project) = initialized("standalone-exact-time");
        let (exit, report, stderr) = run_json(&["package", project.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert_eq!(report["command"], "package");
        assert!(report["packageDigest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert!(report["policyDigest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        // The package identity and the policy's own digest are different
        // documents and must never be conflated.
        assert_ne!(report["packageDigest"], report["policyDigest"]);
        assert_eq!(report["files"][0]["path"], "scheduling.yaml");
        assert_eq!(report["runtimeConfigurationIncluded"], false);
        assert_eq!(report["secretsIncluded"], false);

        let manifest_path = project.join("scheduling.package.json");
        assert!(manifest_path.is_file());
        // The written manifest is exactly the one the runtime's own verifier
        // accepts against the same policy text.
        let policy_path = project.join("scheduling.yaml");
        let policy_text = std::fs::read_to_string(&policy_path).unwrap();
        let verified =
            registry_scheduling::config::verify_policy_package(&policy_path, &policy_text)
                .unwrap()
                .expect("the written manifest verifies");
        // `verify_policy_package` returns the manifest's own byte-exact
        // digest, which the on-disk manifest calls `policyDigest`; the
        // report must mirror that naming, not the policy's semantic digest.
        assert_eq!(verified, report["policyDigest"].as_str().unwrap());
        // Pretty-printed, newline-terminated: a text document an operator
        // diffs.
        let bytes = std::fs::read(&manifest_path).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));

        // Repackaging is a deliberate act: the existing manifest is refused,
        // never silently replaced.
        let (exit, report, stderr) = run_json(&["package", project.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
        let message = report["diagnostics"][0]["message"].as_str().unwrap();
        assert!(message.contains("already exists"), "{message}");
    }

    #[test]
    fn package_refuses_incomplete_authoring_and_writes_nothing() {
        let (_root, project) = initialized("standalone-exact-time");
        let policy_path = project.join("scheduling.yaml");
        let broken = std::fs::read_to_string(&policy_path).unwrap().replacen(
            "version: 1\n",
            "version: 0\n",
            1,
        );
        std::fs::write(&policy_path, broken).unwrap();
        let (exit, report, stderr) = run_json(&["package", project.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
        assert!(report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("finding"));
        assert!(!project.join("scheduling.package.json").exists());
    }

    #[test]
    fn runtime_configuration_and_store_failures_map_to_their_own_diagnostics() {
        let config_error = anyhow::Error::new(RuntimeConfigError::RelativeRuntimePath);
        let (exit, diagnostic) = classify_failure(&config_error);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(
            diagnostic["code"],
            "schedulingctl.runtime-configuration.invalid"
        );
        assert_eq!(diagnostic["artifact"], "runtime_configuration");

        let store_error = anyhow::Error::new(StoreError::Configuration).context("connecting");
        let (exit, diagnostic) = classify_failure(&store_error);
        assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
        assert_eq!(diagnostic["code"], "schedulingctl.store-unavailable");
        assert_eq!(diagnostic["artifact"], "database");
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
    }

    /// A records document that does not hold together is refused in its own
    /// terms before any connection is opened: the write path never reaches
    /// the database with a document the store would reject mid-swap.
    #[test]
    fn records_apply_refuses_an_invalid_document_before_touching_a_database() {
        let (root, project) = initialized("standalone-exact-time");
        let config_path = root.path().join("runtime.yaml");
        std::fs::write(
            &config_path,
            format!(
                "apiVersion: registry.registrystack.org/scheduling-runtime/v1alpha1\n\
                 kind: SchedulingRuntimeConfig\n\
                 package:\n  root: {}\n\
                 listener:\n  bind: 127.0.0.1:8105\n  tlsTermination: development-loopback\n\
                 secretProviders:\n  environment: {{}}\n\
                 authentication:\n  oidc:\n    issuer: https://issuer.example.test\n\
                 \x20   audience: scheduling-api\n\
                 database:\n  runtimeUrlRef: secret:env/SCHEDULINGCTL_TEST_DATABASE\n\
                 \x20 migrationUrlRef: secret:env/SCHEDULINGCTL_TEST_DATABASE\n\
                 audit:\n  path: {}/audit.jsonl\n\
                 \x20 hashKeyRef: secret:env/SCHEDULINGCTL_TEST_AUDIT\n\
                 retention:\n  attemptReceiptDays: 2\n",
                project.display(),
                root.path().display()
            ),
        )
        .unwrap();
        let records_path = root.path().join("records.yaml");
        std::fs::write(
            &records_path,
            "locations:\n  - id: bangkok-counter\n    timezone: Asia/Nowhere\n",
        )
        .unwrap();
        let (exit, report, stderr) = run_json(&[
            "records",
            "apply",
            config_path.to_str().unwrap(),
            records_path.to_str().unwrap(),
        ]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
        let message = report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            message.contains("unknown timezone Asia/Nowhere"),
            "{message}"
        );
    }
}
