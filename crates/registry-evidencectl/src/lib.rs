//! Evidence adopter tooling: key generation, source authoring, and fixture
//! runs. Companion to the frozen `evidence` runtime CLI; it never
//! implements Evidence semantics itself and shells out to the runtime binary
//! for them.

use std::{ffi::OsString, io::Write as _, path::PathBuf, process::ExitCode};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

mod access;
mod audit_view;
mod authoring;
mod build;
mod check;
mod client;
mod dev;
mod doctor;
mod evidence_binary;
mod fixtures;
mod jwks;
mod keygen;
mod request;
mod runtime;
mod scaffold;
mod source_add;
mod source_cli;
mod source_import;
mod source_mock;
mod suggest;
mod target;
mod tooling;
mod tooling_editor;
mod verify;

#[derive(Debug, Parser)]
#[command(
    name = "evidencectl",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Evidence adopter tooling: keys, source authoring, fixture runs"
)]
struct Cli {
    /// Select human-readable or machine-readable output.
    #[arg(
        id = "output_format",
        long = "format",
        global = true,
        value_enum,
        default_value_t = OutputFormat::Human
    )]
    output_format: OutputFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new editable Evidence project.
    Init(scaffold::NewArgs),
    /// Validate authored policy and, when selected, deployment closure offline.
    Check(CheckArgs),
    /// Explain the authored inventory and optional target-owned governance.
    Explain(ExplainArgs),
    /// Run the project's synthetic Evidence fixtures.
    Test(TestArgs),
    /// Compile an editable project into a reviewed deployment candidate.
    Package(PackageArgs),
    /// Configure progressive relying-party clients and fetch contract candidates.
    #[command(subcommand)]
    Client(client::ClientCommand),
    /// Manage local caller access policies and clients.
    #[command(subcommand)]
    Access(access::AccessCommand),
    /// Generate Evidence Gateway deployment key material as owner-only files.
    #[command(subcommand)]
    Keygen(keygen::KeygenCommand),
    /// Assemble a public JWKS document from public JWK files.
    Jwks(jwks::JwksArgs),
    /// Start an editable Evidence Gateway project from OpenAPI, a starter, or a SQLite extract.
    New(scaffold::NewArgs),
    /// Compile an editable project into a reviewed deployment candidate.
    Build(build::BuildArgs),
    /// Drive the evidence binary across a project's bundle fixtures.
    #[command(subcommand)]
    Fixtures(fixtures::FixturesCommand),
    /// Work with a project's sources, starting from their own API documents.
    #[command(subcommand)]
    Source(source_cli::SourceCommand),
    /// Create and inspect complete deployment targets.
    #[command(subcommand)]
    Target(target::TargetCommand),
    /// Check one runtime configuration and its startup dependencies.
    Doctor(runtime::DoctorArgs),
    /// Compatibility operations over deployment artifacts.
    #[command(subcommand)]
    Artifact(ArtifactCommand),
    /// Run the private local Registry Mint and Evidence Gateway pair.
    Dev(dev::DevArgs),
    /// Prepare a closed request for the active local project.
    #[command(subcommand)]
    Request(request::RequestCommand),
    /// Verify one retained Evidence Gateway response offline.
    Verify(verify::VerifyArgs),
    /// Inspect stopped local audit history.
    #[command(subcommand)]
    Audit(audit_view::AuditCommand),
    /// Advanced: editor and tooling integration surfaces.
    #[command(subcommand)]
    Tooling(tooling::ToolingCommand),
    #[command(name = "__dev-supervisor", hide = true)]
    DevSupervisor(dev::SupervisorArgs),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(Debug, Args)]
struct CheckArgs {
    /// Editable Evidence project directory.
    project: PathBuf,
    /// Explicit deployment target whose governance and runtime structure are checked.
    #[arg(long)]
    target: Option<PathBuf>,
    /// Require a production or evidence-grade target and complete deployment closure.
    #[arg(long)]
    production: bool,
    /// Refuse an otherwise valid but incomplete authoring project.
    #[arg(long)]
    deny_findings: bool,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// Editable Evidence project directory.
    project: PathBuf,
    /// Include this deployment target's effective governance.
    #[arg(long)]
    target: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct TestArgs {
    /// Editable or deployment Evidence project directory.
    project: PathBuf,
    /// Complete deployment target to use when compiling an editable project.
    #[arg(long)]
    target: Option<PathBuf>,
    /// Generate local caller governance while retaining the target's source connections.
    #[arg(long, requires = "target")]
    local: bool,
    /// Run only the exact bundle-relative fixture path named here.
    #[arg(long)]
    fixture: Option<String>,
    /// Run only the exact case identifier in the selected fixture.
    #[arg(long, requires = "fixture")]
    case: Option<String>,
    /// Include the runtime's structured value-free evaluation trace.
    #[arg(long)]
    explain: bool,
    #[arg(long, hide = true)]
    evidence_bin: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct PackageArgs {
    /// Editable Evidence project directory.
    project: PathBuf,
    /// Explicit deployment target.
    #[arg(long)]
    target: PathBuf,
    /// New candidate directory to create.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Subcommand)]
enum ArtifactCommand {
    /// Inspect deployment artifact custody without contacting dependencies.
    Inspect(ArtifactInspectArgs),
}

#[derive(Debug)]
struct SafeCliFailure {
    operational: bool,
    code: &'static str,
    artifact: String,
    path: &'static str,
    message: String,
    suggested_action: String,
}

impl std::fmt::Display for SafeCliFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SafeCliFailure {}

#[derive(Debug, Args)]
struct ArtifactInspectArgs {
    /// Deployment project containing runtime.yaml beside bundle/.
    project: PathBuf,
    /// Mechanically compare this Registry Mint configuration with Evidence authentication.
    #[arg(long)]
    mint_config: Option<PathBuf>,
}

/// Return the complete command tree without running Evidence adopter tooling.
pub fn command() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    command
}

/// Parse process arguments and run one adopter-tooling operation.
pub fn main_entry() -> ExitCode {
    let arguments = normalized_process_args();
    let requested_format = requested_output_format(&arguments);
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
        Err(_) => {
            write_usage_failure(requested_format);
            return ExitCode::from(2);
        }
    };
    let format = cli.output_format;
    let result = match cli.command {
        Command::Init(args) => {
            let artifact = args.directory.display().to_string();
            safe_command(
                scaffold::run_with_format(args, format),
                "evidence.init.refused",
                artifact,
                "Evidence could not create the requested project destination.",
                "Use a new destination and correct the starter or import input named by the command.",
            )
        }
        Command::Check(args) => {
            let artifact = args.project.display().to_string();
            safe_command(
                run_check_command(args, format),
                "evidence.check.failed",
                artifact,
                "Evidence could not inspect the selected authoring project.",
                "Correct the selected project or target artifact and rerun check.",
            )
        }
        Command::Explain(args) => {
            let artifact = args.project.display().to_string();
            safe_command(
                run_explain_command(args, format),
                "evidence.explain.failed",
                artifact,
                "Evidence could not explain the selected authoring project.",
                "Correct the selected project or target artifact and rerun explain.",
            )
        }
        Command::Test(args) => {
            let artifact = args.project.display().to_string();
            safe_command(
                fixtures::run(fixtures::FixturesCommand::Run(fixtures::RunArgs {
                    project: args.project,
                    evidence_bin: args.evidence_bin,
                    target: args.target,
                    local: args.local,
                    fixture: args.fixture,
                    case: args.case,
                    json: format == OutputFormat::Json,
                    explain: args.explain,
                })),
                "evidence.test.failed",
                artifact,
                "Evidence could not complete the selected offline fixture run.",
                "Correct the selected project, target, or fixture artifact and rerun test.",
            )
        }
        Command::Package(args) => {
            let artifact = args.project.display().to_string();
            safe_command(
                build::run_with_format(
                    build::BuildArgs {
                        project: args.project,
                        target: args.target,
                        output: args.output,
                    },
                    format,
                ),
                "evidence.package.failed",
                artifact,
                "Evidence could not compile the selected deployment candidate.",
                "Correct the selected project or target findings and rerun package with a new output directory.",
            )
        }
        Command::Client(command) => client::run(command),
        Command::Access(command) => access::run(command),
        Command::Keygen(command) => keygen::run(command),
        Command::Jwks(args) => jwks::run(args),
        Command::New(args) => scaffold::run_with_format(args, format),
        Command::Build(args) => build::run_with_format(args, format),
        Command::Fixtures(fixtures::FixturesCommand::Run(mut args)) => {
            args.json |= format == OutputFormat::Json;
            fixtures::run(fixtures::FixturesCommand::Run(args))
        }
        Command::Source(command) => source_cli::run(command, format),
        Command::Target(command) => target::run(command),
        Command::Doctor(args) => safe_command(
            runtime::run(args, format),
            "evidence.doctor.failed",
            "runtime configuration".to_owned(),
            "Evidence could not inspect the selected runtime configuration.",
            "Correct the runtime configuration or unavailable startup dependency and rerun doctor.",
        ),
        Command::Artifact(ArtifactCommand::Inspect(args)) => doctor::run(doctor::DoctorArgs {
            project: args.project,
            mint_config: args.mint_config,
            json: format == OutputFormat::Json,
        }),
        Command::Dev(args) => safe_dev_command(dev::run_with_format(args, format)),
        Command::Request(command) => request::run(command),
        Command::Verify(args) => verify::run(args),
        Command::Audit(command) => audit_view::run(command),
        Command::Tooling(command) => tooling::run(command),
        Command::DevSupervisor(args) => dev::run_supervisor(args),
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            if let Some(failure) = error.downcast_ref::<SafeCliFailure>() {
                write_safe_failure(failure, format);
                return ExitCode::from(if failure.operational { 3 } else { 1 });
            }
            let operational = error
                .chain()
                .any(|cause| cause.downcast_ref::<std::io::Error>().is_some());
            let (status, code, exit) = if operational {
                ("operational-failure", "evidencectl.operational-failure", 3)
            } else {
                ("domain-refusal", "evidencectl.domain-refusal", 1)
            };
            let detail = format!("{error:#}");
            let safe_message = if operational {
                "Evidence adopter tooling could not complete the requested operation."
            } else {
                "Evidence adopter tooling refused the requested authored or configuration input."
            };
            match format {
                OutputFormat::Human => eprintln!("evidencectl: {detail}"),
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::json!({
                        "status": status,
                        "diagnostics": [{
                            "severity": "error",
                            "code": code,
                            "artifact": "evidencectl",
                            "path": "$",
                            "message": safe_message,
                            "suggestedAction": "Correct the reported problem and retry the command."
                        }]
                    })
                ),
            }
            ExitCode::from(exit)
        }
    }
}

fn requested_output_format(arguments: &[OsString]) -> OutputFormat {
    if arguments.iter().enumerate().any(|(index, argument)| {
        argument == "--format=json"
            || (argument == "--format"
                && arguments
                    .get(index + 1)
                    .is_some_and(|value| value == "json"))
    }) {
        OutputFormat::Json
    } else {
        OutputFormat::Human
    }
}

fn usage_failure_json() -> serde_json::Value {
    serde_json::json!({
        "status": "usage-error",
        "diagnostics": [{
            "severity": "error",
            "code": "evidencectl.usage",
            "artifact": "command line",
            "path": "$",
            "message": "The Evidence command line is incomplete or contains conflicting or unsupported arguments.",
            "suggestedAction": "Run evidencectl --help or the selected command with --help, then retry using the documented arguments."
        }]
    })
}

fn usage_failure_human() -> String {
    let diagnostic = &usage_failure_json()["diagnostics"][0];
    format!(
        "{}[{}] {} {}: {}\n  next: {}\n",
        diagnostic["severity"].as_str().unwrap_or("error"),
        diagnostic["code"].as_str().unwrap_or("evidencectl.usage"),
        diagnostic["artifact"].as_str().unwrap_or("command line"),
        diagnostic["path"].as_str().unwrap_or("$"),
        diagnostic["message"]
            .as_str()
            .unwrap_or("invalid arguments"),
        diagnostic["suggestedAction"]
            .as_str()
            .unwrap_or("Run evidencectl --help."),
    )
}

fn write_usage_failure(format: OutputFormat) {
    match format {
        OutputFormat::Human => eprint!("{}", usage_failure_human()),
        OutputFormat::Json => println!("{}", usage_failure_json()),
    }
}

fn safe_command(
    result: anyhow::Result<ExitCode>,
    code: &'static str,
    artifact: String,
    message: &'static str,
    suggested_action: &'static str,
) -> anyhow::Result<ExitCode> {
    result.map_err(|error| {
        let operational = error
            .chain()
            .any(|cause| cause.downcast_ref::<std::io::Error>().is_some());
        SafeCliFailure {
            operational,
            code,
            artifact,
            path: "$",
            message: message.to_owned(),
            suggested_action: if operational {
                "Verify required files and services, and select the matching Evidence binary, then retry the command.".to_owned()
            } else {
                suggested_action.to_owned()
            },
        }
        .into()
    })
}

fn safe_dev_command(result: anyhow::Result<ExitCode>) -> anyhow::Result<ExitCode> {
    match result {
        Err(error) => {
            if let Some(conflict) = error.downcast_ref::<dev::PortConflict>() {
                return Err(SafeCliFailure {
                    operational: true,
                    code: "evidence.dev.port-unavailable",
                    artifact: format!("127.0.0.1:{}", conflict.port),
                    path: "$",
                    message: format!(
                        "Local port {} is already in use, so the local {} cannot start.",
                        conflict.port, conflict.service
                    ),
                    suggested_action: format!(
                        "Free 127.0.0.1:{}, or rerun dev start with {} <port>.",
                        conflict.port, conflict.flag
                    ),
                }
                .into());
            }
            safe_command(
                Err(error),
                "evidence.dev.failed",
                "local development project".to_owned(),
                "Evidence could not complete the requested local lifecycle operation.",
                "Correct the local project or service dependency and retry the lifecycle operation.",
            )
        }
        Ok(code) => Ok(code),
    }
}

fn write_safe_failure(failure: &SafeCliFailure, format: OutputFormat) {
    match format {
        OutputFormat::Human => eprint!("{}", safe_failure_human(failure)),
        OutputFormat::Json => println!("{}", safe_failure_json(failure)),
    }
}

fn safe_failure_human(failure: &SafeCliFailure) -> String {
    format!(
        "error[{}] {} {}: {}\n  next: {}\n",
        failure.code, failure.artifact, failure.path, failure.message, failure.suggested_action
    )
}

fn safe_failure_json(failure: &SafeCliFailure) -> serde_json::Value {
    serde_json::json!({
        "status": if failure.operational { "operational-failure" } else { "domain-refusal" },
        "diagnostics": [{
            "severity": "error",
            "code": failure.code,
            "artifact": failure.artifact,
            "path": failure.path,
            "message": failure.message,
            "suggestedAction": failure.suggested_action,
        }]
    })
}

/// Preserve the released request-response `--format` spelling now that the
/// top-level flag owns output rendering. Its two closed values are
/// unambiguous; new help uses `--response-format`.
fn normalized_process_args() -> Vec<OsString> {
    normalize_arguments(std::env::args_os().collect())
}

fn normalize_arguments(mut arguments: Vec<OsString>) -> Vec<OsString> {
    let in_request_prepare = arguments
        .windows(2)
        .any(|pair| pair[0] == "request" && pair[1] == "prepare");
    if !in_request_prepare {
        return arguments;
    }
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--format"
            && arguments
                .get(index + 1)
                .is_some_and(|value| value == "signed-jws" || value == "sd-jwt-vc")
        {
            arguments[index] = OsString::from("--response-format");
            index += 2;
            continue;
        }
        if arguments[index] == "--format=signed-jws" {
            arguments[index] = OsString::from("--response-format=signed-jws");
        } else if arguments[index] == "--format=sd-jwt-vc" {
            arguments[index] = OsString::from("--response-format=sd-jwt-vc");
        }
        index += 1;
    }
    arguments
}

fn run_check_command(args: CheckArgs, format: OutputFormat) -> anyhow::Result<ExitCode> {
    let project = args.project.display().to_string();
    match check::check(
        &args.project,
        args.target.as_deref(),
        args.production,
        args.deny_findings,
    ) {
        Ok(report) => {
            write_check_report(&report, format)?;
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => match error.downcast::<check::DeniedFindings>() {
            Ok(denied) => {
                let report = serde_json::json!({
                    "command": "check",
                    "status": "refused",
                    "proof": "none",
                    "project": project,
                    "findings": denied.0,
                });
                write_check_report(&report, format)?;
                Ok(ExitCode::from(1))
            }
            Err(error) => Err(error),
        },
    }
}

fn run_explain_command(args: ExplainArgs, format: OutputFormat) -> anyhow::Result<ExitCode> {
    let project = args.project.display().to_string();
    match check::explain(&args.project, args.target.as_deref()) {
        Ok(report) => {
            write_check_report(&report, format)?;
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => match error.downcast::<check::DeniedFindings>() {
            Ok(denied) => {
                let report = serde_json::json!({
                    "command": "explain",
                    "status": "refused",
                    "proof": "none",
                    "project": project,
                    "findings": denied.0,
                });
                write_check_report(&report, format)?;
                Ok(ExitCode::from(1))
            }
            Err(error) => Err(error),
        },
    }
}

fn write_check_report(report: &serde_json::Value, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Human => check::render_human(report, &mut std::io::stdout())?,
        OutputFormat::Json => writeln!(std::io::stdout(), "{}", serde_json::to_string(report)?)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn public_reference_excludes_the_dev_supervisor() {
        let command = command();
        assert!(command
            .find_subcommand("__dev-supervisor")
            .is_some_and(clap::Command::is_hide_set));
    }

    #[test]
    fn dev_syntax_separates_start_options_from_lifecycle_subcommands() {
        assert!(Cli::try_parse_from(["evidencectl", "dev", "start"]).is_ok());
        assert!(Cli::try_parse_from(["evidencectl", "dev", "start", "project"]).is_ok());
        assert!(Cli::try_parse_from([
            "evidencectl",
            "dev",
            "start",
            "project",
            "--evidence-port",
            "18080",
            "--mint-port",
            "18081",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["evidencectl", "dev", "--detach"]).is_ok());
        assert!(Cli::try_parse_from(["evidencectl", "dev", "stop"]).is_ok());
        assert!(
            Cli::try_parse_from(["evidencectl", "dev", "stop", "--project", "project",]).is_ok()
        );

        let mixed_mode = Cli::try_parse_from(["evidencectl", "dev", "--detach", "stop"])
            .expect_err("start options must not combine with a lifecycle subcommand");
        assert_eq!(mixed_mode.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn canonical_commands_require_positional_projects_and_explicit_targets() {
        assert!(Cli::try_parse_from([
            "evidencectl",
            "init",
            "project",
            "--starter",
            "starter",
            "--profile",
            "local"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["evidencectl", "check", "project"]).is_ok());
        assert!(
            Cli::try_parse_from(["evidencectl", "explain", "project", "--target", "target"])
                .is_ok()
        );
        assert!(Cli::try_parse_from([
            "evidencectl",
            "test",
            "project",
            "--target",
            "target",
            "--local"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "evidencectl",
            "package",
            "project",
            "--target",
            "target",
            "--output",
            "candidate"
        ])
        .is_ok());

        for arguments in [
            vec!["evidencectl", "check"],
            vec!["evidencectl", "explain"],
            vec!["evidencectl", "test"],
            vec![
                "evidencectl",
                "package",
                "--target",
                "target",
                "--output",
                "candidate",
            ],
        ] {
            let error = Cli::try_parse_from(arguments).expect_err("PROJECT is required");
            assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
        }
    }

    #[test]
    fn production_check_and_runtime_doctor_require_explicit_inputs() {
        assert!(Cli::try_parse_from(["evidencectl", "check", "project", "--production"]).is_ok());

        assert!(Cli::try_parse_from([
            "evidencectl",
            "doctor",
            "--runtime-config",
            "/srv/evidence/runtime.yaml",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(
            ["evidencectl", "doctor", "--project", "candidate", "--json",]
        )
        .is_ok());
        assert!(Cli::try_parse_from(["evidencectl", "artifact", "inspect", "candidate",]).is_ok());
    }

    #[test]
    fn request_prepare_keeps_subject_input_forms_mutually_exclusive() {
        let base = [
            "evidencectl",
            "request",
            "prepare",
            "question",
            "--purpose",
            "eligibility",
            "--name",
            "retained-request",
        ];

        assert!(Cli::try_parse_from(base).is_ok());

        assert!(
            Cli::try_parse_from(base.into_iter().chain(["--subject", "person:id=123"]),).is_ok()
        );
        assert!(
            Cli::try_parse_from(base.into_iter().chain(["--subjects-file", "subjects.json"]),)
                .is_ok()
        );

        let duplicate_subject = Cli::try_parse_from(base.into_iter().chain([
            "--subject",
            "person:id=123",
            "--subjects-file",
            "subjects.json",
        ]))
        .expect_err("subject input forms are mutually exclusive");
        assert_eq!(duplicate_subject.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn request_response_format_compatibility_preserves_both_format_meanings() {
        let base = [
            "evidencectl",
            "request",
            "prepare",
            "question",
            "--purpose",
            "eligibility",
            "--name",
            "retained-request",
        ];
        for arguments in [
            base.into_iter()
                .chain(["--response-format", "signed-jws", "--format", "json"])
                .map(OsString::from)
                .collect::<Vec<_>>(),
            ["evidencectl", "--format", "json"]
                .into_iter()
                .chain(base.into_iter().skip(1))
                .chain(["--response-format", "signed-jws"])
                .map(OsString::from)
                .collect::<Vec<_>>(),
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }

        let equals = normalize_arguments(
            base.into_iter()
                .chain(["--format=sd-jwt-vc"])
                .map(OsString::from)
                .collect(),
        );
        assert!(equals
            .iter()
            .any(|value| value == "--response-format=sd-jwt-vc"));
        assert!(Cli::try_parse_from(equals).is_ok());

        let duplicate = normalize_arguments(
            base.into_iter()
                .chain(["--format", "sd-jwt-vc", "--response-format", "signed-jws"])
                .map(OsString::from)
                .collect(),
        );
        assert_eq!(
            Cli::try_parse_from(duplicate)
                .expect_err("old and new response-format spellings conflict")
                .kind(),
            ErrorKind::ArgumentConflict
        );

        let unrelated = vec![
            OsString::from("evidencectl"),
            OsString::from("verify"),
            OsString::from("--format=sd-jwt-vc"),
        ];
        assert_eq!(normalize_arguments(unrelated.clone()), unrelated);
    }

    #[test]
    fn canonical_failure_renderers_exclude_rejected_values_in_both_formats() {
        const CANARY: &str = "selector-value-never-render";
        let error = safe_command(
            Err(anyhow::anyhow!(CANARY)),
            "evidence.check.failed",
            "project/evidence-project.yaml".to_owned(),
            "Evidence could not inspect the selected authoring project.",
            "Correct the selected project or target artifact and rerun check.",
        )
        .expect_err("refusal");
        let failure = error
            .downcast_ref::<SafeCliFailure>()
            .expect("safe failure");
        let human = safe_failure_human(failure);
        let json = safe_failure_json(failure).to_string();
        assert!(!human.contains(CANARY));
        assert!(!json.contains(CANARY));
        for expected in [failure.message.as_str(), failure.suggested_action.as_str()] {
            assert!(human.contains(expected));
            assert!(json.contains(expected));
        }
    }

    #[test]
    fn busy_dev_port_keeps_the_safe_numeric_recovery_in_both_formats() {
        let error = safe_dev_command(Err(dev::PortConflict {
            port: 48123,
            service: "Evidence Gateway",
            flag: "--evidence-port",
        }
        .into()))
        .expect_err("busy port");
        let failure = error
            .downcast_ref::<SafeCliFailure>()
            .expect("safe failure");
        assert!(failure.operational);
        assert_eq!(failure.code, "evidence.dev.port-unavailable");
        for report in [
            safe_failure_human(failure),
            safe_failure_json(failure).to_string(),
        ] {
            assert!(report.contains("48123"), "{report}");
            assert!(report.contains("already in use"), "{report}");
            assert!(report.contains("--evidence-port"), "{report}");
        }
    }

    #[test]
    fn usage_failure_renderers_are_value_free_and_preserve_six_fields() {
        const CANARY: &str = "unknown-selector-value-never-render";
        let arguments = normalize_arguments(
            [
                "evidencectl",
                "--format",
                "json",
                "check",
                "project",
                CANARY,
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
        );
        assert_eq!(requested_output_format(&arguments), OutputFormat::Json);
        assert!(Cli::try_parse_from(arguments).is_err());
        let json = usage_failure_json();
        let human = usage_failure_human();
        assert!(!json.to_string().contains(CANARY));
        assert!(!human.contains(CANARY));
        let diagnostic = &json["diagnostics"][0];
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
        for field in ["message", "suggestedAction"] {
            assert!(human.contains(diagnostic[field].as_str().unwrap()));
        }
    }

    #[test]
    fn materialized_source_mock_serve_rejects_ephemeral_generation_options() {
        for option in [
            ["--operation", "GET /records"],
            ["--seed", "1"],
            ["--as-of", "2026-08-13"],
        ] {
            let error = Cli::try_parse_from(
                [
                    "evidencectl",
                    "source",
                    "mock",
                    "serve",
                    "--config",
                    "source.yaml",
                ]
                .into_iter()
                .chain(option),
            )
            .expect_err("materialized serving must reject ephemeral generation options");
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }

        let explain = Cli::try_parse_from([
            "evidencectl",
            "source",
            "mock",
            "serve",
            "--config",
            "source.yaml",
            "--explain",
        ])
        .expect_err("materialized serving must reject generator explanations");
        assert_eq!(explain.kind(), ErrorKind::ArgumentConflict);

        assert!(Cli::try_parse_from([
            "evidencectl",
            "source",
            "mock",
            "serve",
            "--config",
            "source.yaml",
            "--http-addr",
            "127.0.0.1:4010",
        ])
        .is_ok());
    }

    #[test]
    fn stored_source_mock_generation_reuses_settings_and_can_append_cases() {
        for option in [["--seed", "1"], ["--as-of", "2026-08-13"]] {
            let error = Cli::try_parse_from(
                [
                    "evidencectl",
                    "source",
                    "mock",
                    "generate",
                    "--config",
                    "source.yaml",
                ]
                .into_iter()
                .chain(option),
            )
            .expect_err("stored generation must reject new generation inputs");
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }

        assert!(Cli::try_parse_from([
            "evidencectl",
            "source",
            "mock",
            "generate",
            "--config",
            "source.yaml",
            "--operation",
            "GET /records/{id}",
            "--case",
            "second-record",
            "--path-parameter",
            "id=123",
        ])
        .is_ok());

        assert!(Cli::try_parse_from([
            "evidencectl",
            "source",
            "mock",
            "generate",
            "--config",
            "source.yaml",
            "--explain",
        ])
        .is_ok());
    }

    /// Every argument in the built command tree, with the command path that
    /// owns it, so a rule can be asserted across the whole binary at once.
    fn tree_arguments(command: &clap::Command, path: &str) -> Vec<(String, clap::Arg)> {
        let mut arguments: Vec<(String, clap::Arg)> = command
            .get_arguments()
            .map(|argument| (path.to_owned(), argument.clone()))
            .collect();
        for subcommand in command.get_subcommands() {
            let child = format!("{path} {}", subcommand.get_name());
            arguments.extend(tree_arguments(subcommand, &child));
        }
        arguments
    }

    #[test]
    fn project_names_one_project_directory_across_every_subcommand() {
        let command = command();
        let arguments = tree_arguments(&command, command.get_name());
        let projects: Vec<_> = arguments
            .iter()
            .filter(|(_, argument)| argument.get_long() == Some("project"))
            .collect();
        assert!(
            projects.len() >= 18,
            "the whole tree must be walked, saw {:?}",
            projects.iter().map(|(path, _)| path).collect::<Vec<_>>()
        );

        let documented: Vec<_> = projects
            .iter()
            .filter(|(_, argument)| !argument.is_hide_set())
            .collect();
        assert_eq!(
            documented
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                "evidencectl build",
                "evidencectl fixtures run",
                "evidencectl source add",
                "evidencectl source suggest",
                "evidencectl source mock serve",
                "evidencectl source mock generate",
                "evidencectl source mock check",
                "evidencectl source diff",
                "evidencectl source import",
                "evidencectl source update",
                "evidencectl source detach",
                "evidencectl target new",
                "evidencectl target explain",
                "evidencectl doctor",
                "evidencectl tooling editor",
            ]),
            "every documented --project must be covered by this rule"
        );

        for (path, argument) in &projects {
            assert!(
                !argument.is_required_set(),
                "{path} --project must be optional so the current directory is always a valid answer"
            );
        }

        for (path, argument) in documented {
            let help = argument
                .get_help()
                .expect("every documented --project carries help")
                .to_string();
            assert!(
                help.starts_with("Evidence project directory"),
                "{path} --project help must open with the shared phrase, saw {help:?}"
            );
            let long_help = argument
                .get_long_help()
                .expect("every documented --project states the project shape it needs")
                .to_string();
            assert!(
                long_help.contains("editable project") || long_help.contains("deployment project"),
                "{path} --project must name the project shape it needs, saw {long_help:?}"
            );
            if *path == "evidencectl source suggest" {
                assert!(
                    help.contains("printed when this is absent"),
                    "{path} --project stays absent to keep the draft print-only, saw {help:?}"
                );
            } else {
                assert!(
                    help.contains("defaults to the current directory"),
                    "{path} --project must say the current directory is the default, saw {help:?}"
                );
            }
        }
    }

    #[test]
    fn the_project_commands_a_newcomer_reaches_for_run_without_the_flag() {
        for arguments in [
            vec!["evidencectl", "doctor"],
            vec!["evidencectl", "fixtures", "run"],
            vec![
                "evidencectl",
                "build",
                "--target",
                "deployment/local",
                "--output",
                "candidate",
            ],
            vec!["evidencectl", "source", "add", "registry"],
            vec!["evidencectl", "source", "diff", "exports/registry"],
            vec!["evidencectl", "source", "import", "exports/registry"],
            vec!["evidencectl", "source", "update", "exports/registry"],
            vec!["evidencectl", "source", "detach", "registry"],
            vec!["evidencectl", "target", "new", "targets/local", "--local"],
            vec!["evidencectl", "tooling", "editor"],
        ] {
            assert!(
                Cli::try_parse_from(&arguments).is_ok(),
                "{arguments:?} must work from inside the project directory"
            );
        }
    }

    #[test]
    fn target_project_context_is_optional_and_only_used_for_local_creation() {
        for (options, local) in [
            (vec!["--local"], true),
            (vec!["--settings", "settings.yaml"], false),
        ] {
            let mut arguments = vec!["evidencectl", "target", "new", "target"];
            arguments.extend(options);
            let cli = Cli::try_parse_from(arguments).expect("project context is optional");
            let Command::Target(target::TargetCommand::New(args)) = cli.command else {
                panic!("target new parsed");
            };
            assert_eq!(args.local, local);
            assert!(args.project.is_none());
            assert_eq!(args.settings.is_some(), !local);
        }
        assert!(Cli::try_parse_from([
            "evidencectl",
            "target",
            "new",
            "target",
            "--settings",
            "settings.yaml",
            "--project",
            ".",
        ])
        .is_err());
    }

    #[test]
    fn output_paths_are_spelled_one_way_in_help() {
        let command = command();
        for (path, argument) in tree_arguments(&command, command.get_name()) {
            let Some(long) = argument.get_long() else {
                continue;
            };
            assert!(
                !matches!(long, "out" | "out-dir" | "public-out"),
                "{path} still offers --{long} as a documented spelling"
            );
        }
    }

    #[test]
    fn retired_output_spellings_keep_parsing() {
        for arguments in [
            vec!["evidencectl", "keygen", "secret", "--out", "audit-hmac-key"],
            vec!["evidencectl", "keygen", "token", "--out", "source-token"],
            vec!["evidencectl", "keygen", "signing", "--out-dir", "secrets"],
            vec![
                "evidencectl",
                "keygen",
                "signing",
                "--out-dir",
                "secrets",
                "--public-out",
                "signing.jwk.json",
            ],
            vec!["evidencectl", "keygen", "holder", "--out-dir", "keys"],
            vec![
                "evidencectl",
                "keygen",
                "client-assertion",
                "--out-dir",
                "secrets",
                "--public-out",
                "assertion.jwk.json",
            ],
            vec![
                "evidencectl",
                "jwks",
                "--out",
                "trusted-issuer-keys.json",
                "signing-p256-public.jwk.json",
            ],
            vec![
                "evidencectl",
                "client",
                "contracts",
                "fetch",
                "--profile",
                "client-profile.json",
                "--out",
                "contracts.json",
            ],
            vec![
                "evidencectl",
                "client",
                "profile",
                "create",
                "--base-url",
                "https://evidence.example.test",
                "--client-id",
                "reporting",
                "--private-key-file",
                "client-private-jwk",
                "--out",
                "client-profile.json",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&arguments).is_ok(),
                "{arguments:?} must keep working as already published"
            );
        }
    }

    #[test]
    fn current_output_spellings_parse() {
        for arguments in [
            vec![
                "evidencectl",
                "keygen",
                "secret",
                "--output",
                "audit-hmac-key",
            ],
            vec!["evidencectl", "keygen", "token", "--output", "source-token"],
            vec![
                "evidencectl",
                "keygen",
                "signing",
                "--output-dir",
                "secrets",
                "--public-output",
                "signing.jwk.json",
            ],
            vec!["evidencectl", "keygen", "holder", "--output-dir", "keys"],
            vec![
                "evidencectl",
                "keygen",
                "client-assertion",
                "--output-dir",
                "secrets",
                "--public-output",
                "assertion.jwk.json",
            ],
            vec![
                "evidencectl",
                "jwks",
                "--output",
                "trusted-issuer-keys.json",
                "signing-p256-public.jwk.json",
            ],
            vec![
                "evidencectl",
                "client",
                "contracts",
                "fetch",
                "--profile",
                "client-profile.json",
                "--output",
                "contracts.json",
            ],
            vec![
                "evidencectl",
                "client",
                "profile",
                "create",
                "--base-url",
                "https://evidence.example.test",
                "--client-id",
                "reporting",
                "--private-key-file",
                "client-private-jwk",
                "--output",
                "client-profile.json",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&arguments).is_ok(),
                "{arguments:?} must parse"
            );
        }
    }

    #[test]
    fn native_source_target_and_starter_commands_parse_without_displacing_existing_paths() {
        for arguments in [
            vec![
                "evidencectl",
                "new",
                "starter-project",
                "--starter",
                "starters/local",
                "--profile",
                "local",
            ],
            vec![
                "evidencectl",
                "new",
                "openapi-project",
                "--openapi",
                "source.openapi.yaml",
                "--profile",
                "local",
            ],
            vec![
                "evidencectl",
                "new",
                "sqlite-project",
                "--transport",
                "sqlite-extract",
                "--profile",
                "local",
            ],
            vec![
                "evidencectl",
                "source",
                "import",
                "exports/registry",
                "--project",
                "project",
                "--target",
                "targets/local",
            ],
            vec![
                "evidencectl",
                "source",
                "update",
                "exports/registry",
                "--resolutions",
                "resolutions.json",
            ],
            vec!["evidencectl", "source", "diff", "exports/registry"],
            vec!["evidencectl", "source", "detach", "registry"],
            vec![
                "evidencectl",
                "target",
                "new",
                "targets/local-created",
                "--settings",
                "targets/local/settings.yaml",
            ],
            vec![
                "evidencectl",
                "target",
                "explain",
                "targets/local-created",
                "--json",
            ],
            vec![
                "evidencectl",
                "fixtures",
                "run",
                "--target",
                "targets/local-created",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&arguments).is_ok(),
                "{arguments:?} must parse"
            );
        }
    }

    #[test]
    fn request_verify_is_a_deprecated_alias_of_verify() {
        let command = command();
        let request = command
            .find_subcommand("request")
            .expect("request is published");
        let aliased = request
            .find_subcommand("verify")
            .expect("request verify stays available");
        let about = aliased
            .get_about()
            .expect("request verify carries help")
            .to_string();
        assert!(
            about.to_lowercase().contains("deprecated"),
            "request verify must announce itself as deprecated, saw {about:?}"
        );
        let long_about = aliased
            .get_long_about()
            .expect("request verify explains what replaces it")
            .to_string();
        assert!(
            long_about.contains("evidencectl verify"),
            "request verify must name the command that replaces it, saw {long_about:?}"
        );

        for arguments in [
            vec![
                "evidencectl",
                "verify",
                "response.jws",
                "--context",
                "context.json",
                "--output",
                "verified.json",
            ],
            vec![
                "evidencectl",
                "request",
                "verify",
                "response.jws",
                "--context",
                "context.json",
                "--output",
                "verified.json",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&arguments).is_ok(),
                "{arguments:?} must keep working"
            );
        }
    }
}
