// SPDX-License-Identifier: Apache-2.0

//! `schedulingctl`, the Registry Scheduling authoring and local operator
//! tooling: `init` writes a complete starter project, `check` validates the
//! authored policy offline, `test` replays every fixture offline, `explain`
//! publishes what the runtime would serve, `package` writes the deployment
//! identity the runtime verifies, `plan`, `apply`, and `status` activate a
//! verified package on a deployment's database and report its activation
//! ledger, `records apply` performs the one attributable operator write of a
//! deployment's live environment records, and `intents` reads the delivery
//! intents a deployment's sweep has stopped carrying.

pub mod activation;
pub mod intents;
mod project;
pub mod records;
mod report;
mod templates;

use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_platform_audit::AuditUnavailable;
use registry_scheduling::config::RuntimeConfigError;
use registry_scheduling::runtime::RuntimeError;
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
    /// Write the checked policy into a new package directory the runtime verifies.
    Package(PackageArgs),
    /// Report what `apply` would do to a deployment's database, writing nothing.
    Plan(ActivationArgs),
    /// Activate the verified package on a deployment's database.
    Apply(ApplyArgs),
    /// Report the active package and the activation ledger of a deployment's database.
    Status(ActivationArgs),
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
struct PackageArgs {
    /// Authored scheduling project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// New directory for the verified package. Required unless --dry-run.
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
struct ActivationArgs {
    /// Runtime configuration document of the deployment.
    #[arg(long, value_name = "FILE")]
    runtime_config: PathBuf,
}

#[derive(Debug, Args)]
struct ApplyArgs {
    /// Runtime configuration document of the deployment to activate.
    #[arg(long, value_name = "FILE")]
    runtime_config: PathBuf,
    /// Change or ticket reference; recorded only as a keyed hash.
    #[arg(long, value_name = "TEXT", value_parser = activation::bounded_operator_text)]
    operator_reference: Option<String>,
    /// Reference to a backup taken before this apply; repeatable.
    #[arg(long = "backup", value_name = "REFERENCE", value_parser = activation::bounded_operator_text)]
    backups: Vec<String>,
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

use report::{DOMAIN_REFUSAL_EXIT, OPERATIONAL_FAILURE_EXIT, USAGE_EXIT};

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
            return ExitCode::from(USAGE_EXIT);
        }
    };
    if let Command::Apply(args) = &cli.command {
        if args.backups.len() > activation::MAX_BACKUP_REFERENCES {
            let message = format!(
                "--backup may be given at most {} times",
                activation::MAX_BACKUP_REFERENCES
            );
            if machine_mode {
                write_failure(&usage_failure(message), OutputFormat::Json, stdout, stderr);
            } else {
                let _ = writeln!(stderr, "error: {message}");
            }
            return ExitCode::from(USAGE_EXIT);
        }
    }
    let format = cli.format;
    let command = command_path(&cli.command);
    let deny_findings = matches!(&cli.command, Command::Check(args) if args.deny_findings);
    match run(cli) {
        Ok(mut report) => {
            // The exit code already tells the caller whether this refused;
            // the JSON must agree instead of reporting "ok": true underneath
            // a nonzero exit.
            let refusal = report_is_refusal(&report, deny_findings);
            if format == OutputFormat::Json {
                report = completed_report(report, command, refusal);
            } else if refusal {
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
                &report::failure(command, exit, vec![diagnostic]),
                format,
                stdout,
                stderr,
            );
            ExitCode::from(exit)
        }
    }
}

/// The subcommand path a parsed invocation selected, as its report names it.
fn command_path(command: &Command) -> &'static str {
    match command {
        Command::Init(_) => "init",
        Command::Check(_) => "check",
        Command::Test(_) => "test",
        Command::Explain(_) => "explain",
        Command::Package(_) => "package",
        Command::Plan(_) => "plan",
        Command::Apply(_) => "apply",
        Command::Status(_) => "status",
        Command::Records(RecordsArgs {
            command: RecordsCommand::Apply(_),
        }) => "records apply",
        Command::Intents(_) => "intents",
    }
}

fn run(cli: Cli) -> Result<Value> {
    match cli.command {
        Command::Init(args) => project::init(&args.project, &args.template),
        Command::Check(args) => project::check(&args.project),
        Command::Test(args) => project::test(&args.project),
        Command::Explain(args) => project::explain(&args.project),
        Command::Package(args) => match args.output {
            Some(output) => project::package(&args.project, &output, args.revision.as_deref()),
            None => project::package_dry_run(&args.project, args.revision.as_deref()),
        },
        Command::Plan(args) => activation::plan(&args.runtime_config),
        Command::Apply(args) => activation::apply(
            &args.runtime_config,
            args.operator_reference.as_deref(),
            &args.backups,
        ),
        Command::Status(args) => activation::status(&args.runtime_config),
        Command::Records(args) => match args.command {
            RecordsCommand::Apply(apply) => records::apply(&apply.config, &apply.records),
        },
        Command::Intents(args) => intents::undelivered(&args.config, args.limit),
    }
}

/// A completed report may still describe a refusal: an authoring check that
/// found something when the caller passed `--deny-findings`, a value whose
/// text is outside its grammar (never gated behind `--deny-findings`, because
/// there is nothing to opt into), or a fixture run with failing cases, which
/// always fails the build. An activation plan that names a refusal apply
/// would raise is a refusal too, except that the candidate is already the
/// active package: that plan reports `changesPending: false` and nothing
/// else. The report is the evidence; the exit code is the signal.
fn report_is_refusal(report: &Value, deny_findings: bool) -> bool {
    if report["command"] == "plan" {
        return report["refusals"].as_array().is_some_and(|refusals| {
            refusals
                .iter()
                .any(|refusal| refusal["code"] != "schedulingctl.activation.package-already-active")
        });
    }
    if report["command"] == "check" {
        return report["status"] == "invalid"
            || (deny_findings && report["status"] == "incomplete");
    }
    report["authoringStatus"] == "invalid"
        || report["fixtures"]
            .as_array()
            .is_some_and(|fixtures| fixtures.iter().any(|fixture| fixture["status"] == "failed"))
}

/// Complete a command's own report into the shared envelope: `ok` agrees
/// with the exit code, `status` names what happened, and a refusal points at
/// the member that says what to correct. A check keeps its own status
/// (`complete`, `incomplete`, or `invalid`), and a plan keeps its own
/// `refusals` list.
fn completed_report(mut report: Value, command: &str, refusal: bool) -> Value {
    report["ok"] = json!(!refusal);
    report["command"] = json!(command);
    let failed_fixtures = report["fixtures"]
        .as_array()
        .is_some_and(|fixtures| fixtures.iter().any(|fixture| fixture["status"] == "failed"));
    if report.get("status").is_none() {
        let status = match (command, refusal) {
            ("test", true) if failed_fixtures => "failed",
            (_, true) => "refused",
            ("test", false) => "passed",
            (_, false) => "complete",
        };
        report["status"] = json!(status);
    }
    if refusal && report.get("diagnostics").is_none() {
        let (code, artifact, path, message, action) = match command {
            "plan" => (
                "schedulingctl.plan.refused",
                "database",
                "$.refusals",
                "The activation plan names a refusal apply would raise.",
                "Resolve each entry under refusals as its message names, then rerun schedulingctl plan --runtime-config FILE.",
            ),
            "test" if failed_fixtures => (
                "schedulingctl.test.fixtures-failed",
                "scheduling_project",
                "$.fixtures",
                "One or more offline synthetic fixture cases failed.",
                "Correct each failing case under fixtures, or the policy it exercises, then rerun schedulingctl test PROJECT.",
            ),
            "test" => (
                "schedulingctl.test.refused",
                "scheduling_project",
                "$.findings",
                "The authored policy has a value outside its grammar, so no fixture ran.",
                "Correct each entry under findings, then rerun schedulingctl test PROJECT.",
            ),
            _ => (
                "schedulingctl.check.refused",
                "scheduling_project",
                "$.findings",
                "The authoring check refused the project.",
                "Correct each entry under findings, then rerun schedulingctl check PROJECT.",
            ),
        };
        report["diagnostics"] = json!([{
            "severity": "error",
            "code": code,
            "artifact": artifact,
            "path": path,
            "message": message,
            "suggestedAction": action,
        }]);
    }
    report
}

fn usage_failure(message: String) -> Value {
    report::failure(
        "usage",
        USAGE_EXIT,
        vec![json!({
            "severity": "error",
            "code": "schedulingctl.usage-invalid",
            "artifact": "command_arguments",
            "path": "arguments",
            "message": message,
            "suggestedAction": "Correct the command arguments and retry.",
        })],
    )
}

fn classify_failure(error: &anyhow::Error) -> (u8, Value) {
    let io_failure = error.chain().any(|cause| cause.is::<std::io::Error>());
    // An apply that committed and then lost its response audit entry is not
    // a refusal: the activation stands, and the operator restores the audit
    // destination and confirms the ledger.
    if let Some(applied) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<activation::AppliedUnaudited>())
    {
        return (
            OPERATIONAL_FAILURE_EXIT,
            json!({
                "severity": "error",
                "code": "schedulingctl.activation.applied-unaudited",
                "artifact": "audit",
                "path": "audit.path",
                "message": applied.to_string(),
                "suggestedAction": "Restore the schedulingctl audit destination, then run `schedulingctl status --runtime-config FILE` to confirm the active package.",
            }),
        );
    }
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
    if error.chain().any(|cause| {
        cause.is::<AuditUnavailable>()
            || matches!(
                cause.downcast_ref::<RuntimeError>(),
                Some(RuntimeError::AuditDestination(_))
            )
    }) {
        return (
            OPERATIONAL_FAILURE_EXIT,
            json!({
                "severity": "error",
                "code": "schedulingctl.audit-unavailable",
                "artifact": "audit",
                "path": "audit.path",
                "message": format!("{error:#}"),
                "suggestedAction": "Restore the schedulingctl audit destination beside audit.path, then retry.",
            }),
        );
    }
    if let Some(activation::Refusal(refusal)) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<activation::Refusal>())
    {
        return (
            DOMAIN_REFUSAL_EXIT,
            json!({
                "severity": "error",
                "code": activation::refusal_code(refusal),
                "artifact": "database",
                "path": "database",
                "message": format!("{error:#}"),
                "suggestedAction": "Run the command the message names, or correct what it names, then retry.",
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
        OutputFormat::Json => report::write(report, stdout),
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
        let _ = report::write(report, stdout);
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
        ("check", Some("invalid"), _) => {
            "Authoring check refused: a value's text is outside the grammar its field requires."
                .to_owned()
        }
        ("check", Some("incomplete"), _) => {
            "Authoring check completed with incomplete inputs.".to_owned()
        }
        ("check", Some("complete"), _) => "Authoring check passed with complete inputs.".to_owned(),
        ("test", _, _) if failed_fixtures => {
            "Offline synthetic fixtures reported failures.".to_owned()
        }
        ("test", _, Some("invalid")) => {
            "Offline synthetic fixtures were not run: a value's text is outside the grammar its field requires."
                .to_owned()
        }
        ("test", _, Some("incomplete")) => {
            "Offline synthetic fixtures passed with incomplete authored inputs.".to_owned()
        }
        ("test", _, _) => "Offline synthetic fixtures passed.".to_owned(),
        ("package", _, _) if report["dryRun"] == true => {
            "Package planned; nothing was written.".to_owned()
        }
        ("package", _, _) => "Package written.".to_owned(),
        ("plan", _, _) if report["changesPending"] == false => {
            "Activation planned: the package is already active; nothing needs applying.".to_owned()
        }
        ("plan", _, _) => "Activation planned; nothing was written.".to_owned(),
        ("apply", _, _) => "Package activated.".to_owned(),
        ("status", _, _) => "Activation status read.".to_owned(),
        ("records apply", _, _) => "Environment records applied.".to_owned(),
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
        assert_envelope(&stdout, &report, exit);
        (exit, report, stderr)
    }

    /// Every JSON report opens with `ok`, `command`, and `status` in that
    /// order; `ok` is true exactly when the process exits zero, and a report
    /// that is not ok carries at least one diagnostic naming the next step.
    fn assert_envelope(stdout: &[u8], report: &Value, exit: ExitCode) {
        let text = String::from_utf8_lossy(stdout);
        let head = text
            .lines()
            .filter_map(|line| line.strip_prefix("  \""))
            .filter_map(|line| line.split_once('"').map(|(key, _)| key))
            .take(3)
            .collect::<Vec<_>>();
        assert_eq!(head, ["ok", "command", "status"], "{text}");
        assert!(report["command"].as_str().is_some_and(|c| !c.is_empty()));
        assert!(report["status"].as_str().is_some_and(|s| !s.is_empty()));
        assert_eq!(report["ok"], json!(exit == ExitCode::SUCCESS), "{text}");
        if exit != ExitCode::SUCCESS {
            let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
            assert!(!diagnostics.is_empty(), "{text}");
            for diagnostic in diagnostics {
                assert!(
                    diagnostic["suggestedAction"]
                        .as_str()
                        .is_some_and(|action| !action.is_empty()),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn a_successful_report_names_its_status() {
        let (_root, project) = initialized("standalone-exact-time");
        let project = project.to_str().unwrap();
        let (_, report, _) = run_json(&["check", project]);
        assert_eq!(report["status"], "complete");
        let (_, report, _) = run_json(&["test", project]);
        assert_eq!(report["status"], "passed");
        let (_, report, _) = run_json(&["explain", project]);
        assert_eq!(report["status"], "complete");
        let (_, report, _) = run_json(&["package", project, "--dry-run"]);
        assert_eq!(report["status"], "complete");
    }

    #[test]
    fn a_failure_without_its_own_report_is_named_by_its_exit_class() {
        let (exit, report, _) = run_json(&["check"]);
        assert_eq!(exit, ExitCode::from(USAGE_EXIT));
        assert_eq!(report["command"], "usage");
        assert_eq!(report["status"], "usage-error");

        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let (exit, report, _) = run_json(&["check", missing.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT));
        assert_eq!(report["command"], "check");
        assert_eq!(report["status"], "operational-failure");

        let (exit, report, _) = run_json(&["explain", missing.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT));
        assert_eq!(report["command"], "explain");

        let (_root, project) = initialized("standalone-exact-time");
        let (exit, report, _) = run_json(&[
            "package",
            project.to_str().unwrap(),
            "--output",
            project.to_str().unwrap(),
        ]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert_eq!(report["command"], "package");
        assert_eq!(report["status"], "domain-refusal");
    }

    /// A plan that names a refusal keeps its own `refusals` member and
    /// points at it, so a caller reading only the envelope finds the next
    /// step; a plan that refuses nothing is complete.
    #[test]
    fn a_refused_plan_points_at_its_refusals() {
        let plan = json!({
            "ok": true,
            "command": "plan",
            "refusals": [{"code": "schedulingctl.activation.database-id-mismatch", "message": "m"}],
        });
        let report = completed_report(plan, "plan", true);
        assert_eq!(report["ok"], false);
        assert_eq!(report["status"], "refused");
        assert_eq!(report["refusals"][0]["message"], "m");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "schedulingctl.plan.refused"
        );
        assert_eq!(report["diagnostics"][0]["path"], "$.refusals");

        let report = completed_report(
            json!({"ok": true, "command": "plan", "refusals": []}),
            "plan",
            false,
        );
        assert_eq!(report["ok"], true);
        assert_eq!(report["status"], "complete");
        assert!(report.get("diagnostics").is_none());
    }

    #[test]
    fn activation_operator_text_outside_its_bounds_is_a_usage_error() {
        let (exit, report, _) = run_json(&[
            "apply",
            "--runtime-config",
            "runtime.yaml",
            "--operator-reference",
            "change\n42",
        ]);
        assert_eq!(exit, ExitCode::from(2));
        assert_eq!(report["command"], "usage");

        let long = "x".repeat(activation::MAX_OPERATOR_TEXT_BYTES + 1);
        let (exit, _, _) = run_json(&[
            "apply",
            "--runtime-config",
            "runtime.yaml",
            "--backup",
            &long,
        ]);
        assert_eq!(exit, ExitCode::from(2));

        let mut arguments = vec!["apply", "--runtime-config", "runtime.yaml"];
        for _ in 0..=activation::MAX_BACKUP_REFERENCES {
            arguments.extend(["--backup", "snapshot"]);
        }
        let (exit, report, _) = run_json(&arguments);
        assert_eq!(exit, ExitCode::from(2));
        assert!(report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("--backup may be given at most 16 times"));
    }

    #[test]
    fn a_plan_naming_a_refusal_is_a_refusal_unless_the_package_is_already_active() {
        let plan = |codes: &[&str]| {
            json!({
                "command": "plan",
                "refusals": codes
                    .iter()
                    .map(|code| json!({"code": code, "message": "m"}))
                    .collect::<Vec<_>>(),
            })
        };
        assert!(!report_is_refusal(&plan(&[]), false));
        assert!(!report_is_refusal(
            &plan(&["schedulingctl.activation.package-already-active"]),
            false
        ));
        assert!(report_is_refusal(
            &plan(&["schedulingctl.activation.database-id-mismatch"]),
            false
        ));
        assert!(report_is_refusal(
            &plan(&[
                "schedulingctl.activation.package-already-active",
                "schedulingctl.activation.database-id-mismatch"
            ]),
            false
        ));
    }

    #[test]
    fn an_activation_refusal_is_a_domain_refusal_and_a_store_failure_is_operational() {
        let refusal = activation::refusal_or_failure(StoreError::NotActivated)
            .context("reading the Scheduling activation ledger");
        let (exit, diagnostic) = classify_failure(&refusal);
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(diagnostic["code"], "schedulingctl.activation.not-activated");
        assert!(diagnostic["message"]
            .as_str()
            .unwrap()
            .contains("run `schedulingctl plan --runtime-config FILE` then `schedulingctl apply --runtime-config FILE`"));

        let (exit, diagnostic) =
            classify_failure(&activation::refusal_or_failure(StoreError::Corrupt));
        assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
        assert_eq!(diagnostic["code"], "schedulingctl.store-unavailable");
    }

    #[test]
    fn an_unavailable_audit_is_an_operational_failure_and_an_unaudited_apply_says_it_applied() {
        let destination = anyhow::Error::new(
            registry_scheduling::runtime::RuntimeError::AuditDestination("closed".to_owned()),
        )
        .context("opening the schedulingctl audit destination");
        let (exit, diagnostic) = classify_failure(&destination);
        assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
        assert_eq!(diagnostic["code"], "schedulingctl.audit-unavailable");

        struct Refusing;
        impl io::Write for Refusing {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("refused"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let audit = registry_scheduling::audit::SchedulingAudit::new(
            registry_platform_audit::AuditWriter::from_line_sink(Box::new(Refusing)),
        );
        let unavailable = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(audit.activation_request(uuid::Uuid::new_v4(), json!({})))
            .expect_err("the refusing sink refuses the append");
        let request = anyhow::Error::new(unavailable)
            .context("writing the activation.apply request audit entry; nothing was applied");
        let (exit, diagnostic) = classify_failure(&request);
        assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
        assert_eq!(diagnostic["code"], "schedulingctl.audit-unavailable");

        let applied = anyhow::Error::new(activation::AppliedUnaudited {
            package_digest: "sha256:00".to_owned(),
            activation_id: uuid::Uuid::nil(),
            cause: "audit destination is unavailable".to_owned(),
        });
        let (exit, diagnostic) = classify_failure(&applied);
        assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
        assert_eq!(
            diagnostic["code"],
            "schedulingctl.activation.applied-unaudited"
        );
        assert!(diagnostic["message"]
            .as_str()
            .unwrap()
            .contains("`schedulingctl status --runtime-config FILE`"));
    }

    fn initialized(template: &str) -> (tempfile::TempDir, PathBuf) {
        // Canonical, because the runtime configuration loader refuses a path
        // reached through a symbolic link and the system temporary
        // directory is one on some platforms.
        let root =
            tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
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

        for command in ["test", "explain"] {
            let cli = Cli::try_parse_from(["schedulingctl", command, "/tmp/project"]).unwrap();
            match command {
                "test" => assert!(matches!(cli.command, Command::Test(_))),
                _ => assert!(matches!(cli.command, Command::Explain(_))),
            }
        }
        // `package` writes a new directory or plans one, never both and
        // never beside the project.
        assert!(Cli::try_parse_from(["schedulingctl", "package", "/tmp/project"]).is_err());
        assert!(Cli::try_parse_from([
            "schedulingctl",
            "package",
            "/tmp/project",
            "--output",
            "/tmp/package",
            "--dry-run",
        ])
        .is_err());
        let Command::Package(args) = Cli::try_parse_from([
            "schedulingctl",
            "package",
            "/tmp/project",
            "--output",
            "/tmp/package",
            "--revision",
            "change 42",
        ])
        .unwrap()
        .command
        else {
            panic!("expected package")
        };
        assert_eq!(args.output, Some(PathBuf::from("/tmp/package")));
        assert_eq!(args.revision.as_deref(), Some("change 42"));
        let Command::Package(args) =
            Cli::try_parse_from(["schedulingctl", "package", "/tmp/project", "--dry-run"])
                .unwrap()
                .command
        else {
            panic!("expected package")
        };
        assert!(args.dry_run && args.output.is_none());

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
        assert_eq!(
            report["diagnostics"][0]["code"],
            "schedulingctl.check.refused"
        );
        assert_eq!(report["diagnostics"][0]["path"], "$.findings");

        let (_root, clean) = initialized("standalone-exact-time");
        let (exit, report, stderr) =
            run_json(&["check", "--deny-findings", clean.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert_eq!(report["status"], "complete");
        assert_eq!(report["ok"], true);
    }

    /// A value whose text is outside its grammar (a clock that is not
    /// `HH:MM`) is not unfinished authoring: no `--deny-findings` switch
    /// governs it, because there is nothing to opt into. `check` refuses it
    /// unconditionally, and the `version: 0` case above must keep exiting
    /// zero without `--deny-findings` so the two families stay separated.
    #[test]
    fn a_malformed_value_refuses_check_regardless_of_deny_findings() {
        let (_root, project) = initialized("standalone-exact-time");
        let policy_path = project.join("scheduling.yaml");
        let broken = std::fs::read_to_string(&policy_path).unwrap().replacen(
            "startTime: \"09:00\"",
            "startTime: \"9:00\"",
            1,
        );
        std::fs::write(&policy_path, broken).unwrap();

        let (exit, report, stderr) = run_json(&["check", project.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
        assert_eq!(report["status"], "invalid");
        assert_eq!(report["ok"], false);
        assert!(report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["path"] == "openings[0].startTime" && finding["reason"] == "malformed-value"
            }));

        // --deny-findings changes nothing here: the refusal does not depend
        // on it.
        let (exit, report, stderr) =
            run_json(&["check", "--deny-findings", project.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
        assert_eq!(report["status"], "invalid");
        assert_eq!(report["ok"], false);
    }

    /// A malformed policy has no business running fixtures against it:
    /// `test` refuses the same way `check` does, before it ever reads the
    /// fixtures directory.
    #[test]
    fn a_malformed_value_refuses_test_without_running_fixtures() {
        let (_root, project) = initialized("standalone-exact-time");
        let policy_path = project.join("scheduling.yaml");
        let broken = std::fs::read_to_string(&policy_path).unwrap().replacen(
            "startTime: \"09:00\"",
            "startTime: \"9:00\"",
            1,
        );
        std::fs::write(&policy_path, broken).unwrap();

        let (exit, report, stderr) = run_json(&["test", project.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
        assert_eq!(report["authoringStatus"], "invalid");
        assert_eq!(report["ok"], false);
        assert_eq!(report["fixtures"].as_array().unwrap().len(), 0);
        assert_eq!(report["status"], "refused");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "schedulingctl.test.refused"
        );
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
        assert_eq!(report["status"], "failed");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "schedulingctl.test.fixtures-failed"
        );
        assert_eq!(report["diagnostics"][0]["path"], "$.fixtures");
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
    fn package_writes_a_package_the_runtime_verifies_and_refuses_replacement() {
        let (root, project) = initialized("standalone-exact-time");
        let output = root.path().join("package");
        let (exit, report, stderr) = run_json(&[
            "package",
            project.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{report}");
        assert!(stderr.is_empty());
        assert_eq!(report["command"], "package");
        assert_eq!(report["dryRun"], false);
        assert_eq!(report["revision"], Value::Null);
        assert_eq!(report["files"][0]["path"], "scheduling.yaml");
        assert_eq!(report["files"].as_array().unwrap().len(), 1);
        assert_eq!(report["runtimeConfigurationIncluded"], false);
        assert_eq!(report["secretsIncluded"], false);
        assert!(report.get("policyDigest").is_none(), "{report}");
        // The package digest is the digest of SHA256SUMS, the file the
        // runtime verifies the package against.
        let sums = std::fs::read(output.join("SHA256SUMS")).unwrap();
        assert_eq!(
            report["packageDigest"],
            registry_platform_config::sha256_uri(&sums)
        );
        let verified = registry_scheduling::config::verify_scheduling_package(
            &registry_platform_config::PackageConfig {
                root: output.clone(),
                expected_digest: None,
            },
        )
        .expect("the runtime verifies the written package");
        assert_eq!(verified.digest(), report["packageDigest"]);
        assert_eq!(
            std::fs::read(output.join("scheduling.yaml")).unwrap(),
            std::fs::read(project.join("scheduling.yaml")).unwrap()
        );
        assert!(!project.join("SHA256SUMS").exists());

        // A dry run reports the digest the written package carries.
        let (exit, planned, _) = run_json(&["package", project.to_str().unwrap(), "--dry-run"]);
        assert_eq!(exit, ExitCode::SUCCESS);
        assert_eq!(planned["dryRun"], true);
        assert_eq!(planned["packageDigest"], report["packageDigest"]);

        // Packaging the same project twice gives the same digest; a revision
        // is covered by it.
        let again = root.path().join("again");
        let (_, repeated, _) = run_json(&[
            "package",
            project.to_str().unwrap(),
            "--output",
            again.to_str().unwrap(),
        ]);
        assert_eq!(repeated["packageDigest"], report["packageDigest"]);
        let revised = root.path().join("revised");
        let (_, revised_report, _) = run_json(&[
            "package",
            project.to_str().unwrap(),
            "--output",
            revised.to_str().unwrap(),
            "--revision",
            "change 42",
        ]);
        assert_eq!(revised_report["revision"], "change 42");
        assert_ne!(revised_report["packageDigest"], report["packageDigest"]);

        // A package is written once: an existing output is refused.
        let (exit, report, stderr) = run_json(&[
            "package",
            project.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
        let message = report["diagnostics"][0]["message"].as_str().unwrap();
        assert!(message.contains("schedulingctl package"), "{message}");
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
        let output = project.with_file_name("package");
        let (exit, report, stderr) = run_json(&[
            "package",
            project.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(stderr.is_empty());
        assert!(report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("finding"));
        assert!(!output.exists());
    }

    #[test]
    fn an_authored_policy_carrying_an_environment_expression_is_refused() {
        let (_root, project) = initialized("standalone-exact-time");
        let policy_path = project.join(AUTHORED_POLICY_FILE);
        let policy = std::fs::read_to_string(&policy_path).unwrap();
        let (line, _) = policy
            .lines()
            .find_map(|line| {
                line.trim_start()
                    .strip_prefix("because: ")
                    .map(|v| (line, v))
            })
            .expect("the template states a reason");
        let indent = &line[..line.len() - line.trim_start().len()];
        std::fs::write(
            &policy_path,
            policy.replacen(line, &format!("{indent}because: ${{REASON}}"), 1),
        )
        .unwrap();
        let (exit, report, _) = run_json(&["check", project.to_str().unwrap()]);
        assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT));
        let message = report["diagnostics"][0]["message"].as_str().unwrap();
        assert!(message.contains("runtime.yaml only"), "{message}");
    }

    #[test]
    fn runtime_configuration_and_store_failures_map_to_their_own_diagnostics() {
        let config_error = anyhow::Error::new(RuntimeConfigError::InvalidEnvelope);
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
        let package = root.path().join("package");
        project::package(&project, &package, None).unwrap();
        let config_path = root.path().join("runtime.yaml");
        std::fs::write(
            &config_path,
            format!(
                "apiVersion: registry.registrystack.org/scheduling-runtime/v1alpha1\n\
                 kind: SchedulingRuntimeConfig\n\
                 package:\n  root: {}\n\
                 listener:\n  bind: 127.0.0.1:8105\n  tlsTermination: development-loopback\n\
                 secretProviders:\n  environment: {{}}\n\
                 identity:\n  databaseId: scheduling-ctl-test\n\
                 authentication:\n  oidc:\n    issuer: https://issuer.example.test\n\
                 \x20   audience: scheduling-api\n\
                 database:\n  runtimeUrlRef: secret:env/SCHEDULINGCTL_TEST_DATABASE\n\
                 \x20 migrationUrlRef: secret:env/SCHEDULINGCTL_TEST_DATABASE\n\
                 audit:\n  path: {}/audit.jsonl\n\
                 \x20 hashKeyRef: secret:env/SCHEDULINGCTL_TEST_AUDIT\n\
                 retention:\n  attemptReceiptDays: 2\n",
                package.display(),
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
        assert_eq!(report["command"], "records apply");
        assert_eq!(report["status"], "domain-refusal");
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
