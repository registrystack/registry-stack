// SPDX-License-Identifier: Apache-2.0
mod dev;
#[cfg(test)]
mod fixture_tests;
mod project;
mod project_types;
mod provider_add;
mod provider_pair;
mod report;
#[cfg(feature = "schema")]
pub mod schema;
mod templates;
use anyhow::Result;
use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};
#[derive(Debug, Parser)]
#[command(name="caseworkctl",version=registry_platform_buildinfo::DISPLAY_VERSION,about="Compile and operate bounded review policies")]
struct Cli {
    /// Write human diagnostics and reports, or one typed JSON report.
    #[arg(long, value_enum, global = true, default_value_t)]
    format: OutputFormat,
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum OutputFormat {
    #[default]
    Human,
    Json,
}
#[derive(Debug, Subcommand)]
enum Command {
    /// Create a standalone or source-backed ReviewPolicy project.
    Init {
        /// New project directory; existing destinations are never overwritten.
        #[arg(value_name = "DIRECTORY")]
        project: PathBuf,
        /// Starter to create.
        #[arg(long, default_value = "standalone-decision", value_parser = templates::TEMPLATE_NAMES)]
        template: String,
    },
    /// Validate policy, closed context schemas and required provider capabilities offline.
    Check(CheckArgs),
    /// Explain pinned policy, context custody, staffing, refusals and recovery.
    Explain(ProjectArgs),
    /// Exercise bounded review context fixtures offline.
    Test(TestArgs),
    /// Generate policy bindings and context/request/task/result TypeScript and Python types.
    Types {
        /// Existing authored Casework project directory.
        #[arg(value_name = "PROJECT")]
        project: PathBuf,
        /// Directory for generated TypeScript and Python contracts.
        #[arg(long, value_name = "DIRECTORY")]
        output: PathBuf,
    },
    /// Create approval projects and pair context providers with native producer exports.
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    /// Report the one review lifecycle.
    Lifecycle,
    /// Package the policy and its exact local schema and provider dependency closure.
    #[command(group(ArgGroup::new("package_output").required(true).multiple(false).args(["output", "dry_run"])))]
    Package {
        /// Existing authored Casework project directory.
        #[arg(value_name = "PROJECT")]
        project: PathBuf,
        /// New directory for the exact package closure; required unless --dry-run.
        #[arg(long, value_name = "DIRECTORY")]
        output: Option<PathBuf>,
        /// One printable source revision recorded in the package.
        #[arg(long)]
        revision: Option<String>,
        /// Inspect the file closure and digest without writing a package.
        #[arg(long)]
        dry_run: bool,
    },
    /// Inspect database, active package and audit readiness without applying changes.
    Doctor(OperatorArgs),
    /// Read and explain the candidate activation plan without changing the database.
    Plan(OperatorArgs),
    /// Read the active package identity and database activation ledger.
    Status(OperatorArgs),
    /// Apply the reviewed package and fresh-schema activation with the migration credential.
    Apply {
        /// Runtime configuration file
        #[arg(long, value_name = "FILE")]
        runtime_config: PathBuf,
        /// Operator change or approval reference recorded with activation.
        #[arg(long)]
        operator_reference: Option<String>,
        /// Backup reference recorded with activation; repeat for additional references.
        #[arg(long)]
        backup_reference: Vec<String>,
    },
    /// Start, stop and inspect a retained standalone local session.
    Dev(Box<dev::DevArgs>),
    #[command(name = "__dev-supervisor", hide = true)]
    DevSupervisor(dev::SupervisorArgs),
    #[command(name = "__dev-service-guard", hide = true)]
    DevServiceGuard(dev::ServiceGuardArgs),
}
#[derive(Debug, Subcommand)]
enum ProviderCommand {
    /// Create an approval project from a Base Registry Engine (BReg) Action and print missing configuration.
    Add {
        /// New Casework directory, or a previously generated project to check without rewriting.
        #[arg(value_name = "DIRECTORY")]
        project: PathBuf,
        /// Authored BReg project inspected through its matching bregctl executable.
        #[arg(long, value_name = "PROJECT")]
        breg_project: PathBuf,
        /// Proposal-mode BReg Action to review.
        #[arg(long)]
        action: String,
        /// Approval stages and outcomes shared with caseworkctl init.
        #[arg(long, value_parser = templates::PATTERN_NAMES)]
        pattern: String,
        /// Sealed BReg package to pair and compare before packaging Casework.
        #[arg(long, value_name = "DIRECTORY")]
        breg_package: Option<PathBuf>,
        /// Package directory written with a new project; omit to inspect the package without writing it.
        #[arg(long, value_name = "DIRECTORY", requires = "breg_package")]
        package_output: Option<PathBuf>,
        /// Matching bregctl executable used for public project and package inspection.
        #[arg(long, default_value = "bregctl", value_name = "BINARY")]
        bregctl_bin: PathBuf,
    },
    /// Verify native context and reader authority, then optionally retain its provider export.
    Pair {
        /// Existing Casework project with the exact vendored schema and context pin.
        #[arg(value_name = "PROJECT")]
        project: PathBuf,
        /// Declared Casework context provider to pair.
        #[arg(long)]
        provider_id: String,
        /// Sealed native Base Registry Engine (BReg) package containing the action's context export.
        #[arg(long, value_name = "DIRECTORY")]
        breg_package: PathBuf,
        /// Base Registry Engine (BReg) action that declares the required review context.
        #[arg(long)]
        action_id: String,
        /// Matching bregctl executable used to verify the producer package.
        #[arg(long, default_value = "bregctl", value_name = "BINARY")]
        bregctl_bin: PathBuf,
        /// Write the verified provider export and description reference after validation.
        #[arg(long)]
        apply: bool,
    },
}
#[derive(Debug, Args)]
struct ProjectArgs {
    /// Existing authored Casework project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
}
#[derive(Debug, Args)]
struct TestArgs {
    /// Existing authored Casework project and its offline fixtures.
    project: PathBuf,
    /// Refuse authored warnings as well as errors.
    #[arg(long)]
    deny_warnings: bool,
}
#[derive(Debug, Args)]
struct OperatorArgs {
    /// Runtime configuration file
    #[arg(long, value_name = "FILE")]
    runtime_config: PathBuf,
}
#[derive(Debug, Args)]
struct CheckArgs {
    /// Existing authored Casework project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// Check the exact package closure required for production.
    #[arg(long)]
    production: bool,
    /// Refuse authored warnings as well as errors.
    #[arg(long)]
    deny_warnings: bool,
    /// Compare imported provider contracts with this sealed native Base Registry Engine (BReg) package.
    #[arg(long, value_name = "DIRECTORY")]
    against_breg_package: Option<PathBuf>,
    /// Limit native package comparison to this declared provider.
    #[arg(long, requires = "against_breg_package")]
    provider_id: Option<String>,
    /// Matching bregctl executable used for native package verification.
    #[arg(long, default_value = "bregctl", value_name = "BINARY")]
    bregctl_bin: PathBuf,
    /// Runtime configuration file
    #[arg(long, value_name = "FILE")]
    runtime_config: Option<PathBuf>,
    /// Resolve configured environment substitutions while checking the runtime file.
    #[arg(long, requires = "runtime_config")]
    environment: bool,
}
pub fn command() -> clap::Command {
    Cli::command()
}
pub fn main_entry() -> ExitCode {
    main_entry_from(std::env::args_os(), &mut io::stdout(), &mut io::stderr())
}
pub fn main_entry_from(
    args: impl IntoIterator<Item = OsString>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> ExitCode {
    let args: Vec<_> = args.into_iter().collect();
    let json_output = args.iter().enumerate().any(|(index, arg)| {
        arg == "--format=json"
            || (arg == "--format" && args.get(index + 1).is_some_and(|value| value == "json"))
    });
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            if !error.use_stderr() {
                let _ = write!(stdout, "{error}");
                return ExitCode::SUCCESS;
            }
            let diagnostic = registry_platform_yaml::Diagnostic::error(
                "casework.usage.invalid",
                "",
                report::usage_message(&error),
                "Run caseworkctl --help for supported commands and arguments.",
            );
            if json_output {
                if let Ok(value) = report::CliReport::failure(
                    "usage",
                    report::ReportStatus::UsageError,
                    vec![diagnostic],
                ) {
                    let _ = report::write(&serde_json::to_value(value).unwrap_or_default(), stdout);
                }
            } else {
                let _ = writeln!(stderr, "{}", diagnostic.message);
            }
            return ExitCode::from(report::USAGE_EXIT);
        }
    };
    let kind = command_kind(&cli.command);
    let command = cli.command.report_command();
    if command == "internal" {
        return match run(cli.command) {
            Ok(_) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        };
    }
    let result = run(cli.command).and_then(|value| report::CliReport::from_value(command, value));
    let (value, exit) = match result {
        Ok(value) => {
            let value = serde_json::to_value(value).unwrap_or_default();
            let failed = value["ok"] != true;
            (value, if failed { DOMAIN_REFUSAL_EXIT } else { 0 })
        }
        Err(error) => {
            let (exit, diagnostic) = classify_failure(kind, &error);
            let (exit, diagnostics) = if let Some(activation) = activation_failure(&error) {
                activation
            } else {
                (
                    exit,
                    configuration_report(&error)
                        .map(|report| report.diagnostics().to_vec())
                        .unwrap_or_else(|| {
                            vec![registry_platform_yaml::Diagnostic::error(
                                diagnostic["code"].as_str().unwrap_or("caseworkctl.refused"),
                                diagnostic["path"].as_str().unwrap_or(""),
                                diagnostic["message"]
                                    .as_str()
                                    .unwrap_or("operation refused"),
                                diagnostic["suggestedAction"]
                                    .as_str()
                                    .unwrap_or("Correct the named input and retry."),
                            )]
                        }),
                )
            };
            let status = if exit == OPERATIONAL_FAILURE_EXIT {
                report::ReportStatus::OperationalFailure
            } else {
                report::ReportStatus::DomainRefusal
            };
            let value = report::CliReport::failure(command, status, diagnostics)
                .and_then(|value| serde_json::to_value(value).map_err(Into::into))
                .unwrap_or_default();
            (value, exit)
        }
    };
    let output = if matches!(cli.format, OutputFormat::Human) && exit != 0 {
        stderr as &mut dyn Write
    } else {
        stdout as &mut dyn Write
    };
    let _ = match cli.format {
        OutputFormat::Json => report::write(&value, output),
        OutputFormat::Human => render_human(&value, output),
    };
    ExitCode::from(exit)
}

const DOMAIN_REFUSAL_EXIT: u8 = 1;
use report::OPERATIONAL_FAILURE_EXIT;
#[derive(Clone, Copy)]
enum CommandKind {
    Authoring,
    Operational,
}
fn command_kind(command: &Command) -> CommandKind {
    if matches!(
        command,
        Command::Doctor(_)
            | Command::Plan(_)
            | Command::Apply { .. }
            | Command::Status(_)
            | Command::Dev(_)
    ) {
        CommandKind::Operational
    } else {
        CommandKind::Authoring
    }
}
fn classify_failure(kind: CommandKind, error: &anyhow::Error) -> (u8, Value) {
    if let Some(failure) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<provider_add::ProviderAddFailure>())
    {
        let (code, path, message, action) = failure.diagnostic();
        return (
            DOMAIN_REFUSAL_EXIT,
            json!({"severity":"error","code":code,"path":path,"message":message,"suggestedAction":action}),
        );
    }
    if let Some(failure) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<provider_pair::PairingFailure>())
    {
        let (code, path, message, action) = failure.diagnostic();
        return (
            DOMAIN_REFUSAL_EXIT,
            json!({"severity":"error","code":code,"artifact":"provider-pair","path":path,"message":message,"suggestedAction":action}),
        );
    }
    if let Some(failure) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<dev::DevFailure>())
    {
        let (code, path, message, action) = failure.diagnostic();
        return (
            if failure.is_configuration_refusal() {
                DOMAIN_REFUSAL_EXIT
            } else {
                OPERATIONAL_FAILURE_EXIT
            },
            json!({"severity":"error","code":code,"artifact":"dev-session","path":path,"message":message,"suggestedAction":action}),
        );
    }
    if let Some(runtime) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<registry_casework::RuntimeConfigError>())
    {
        let unavailable = matches!(runtime, registry_casework::RuntimeConfigError::Oidc)
            || error.chain().any(|cause| cause.is::<std::io::Error>());
        return (
            if unavailable {
                OPERATIONAL_FAILURE_EXIT
            } else {
                DOMAIN_REFUSAL_EXIT
            },
            json!({"severity":"error","code":runtime.code(),"path":format!("runtime.yaml:{}",runtime.pointer()),"message":if unavailable{"The configured runtime dependency is unavailable."}else{"The runtime configuration was refused."},"suggestedAction":runtime.suggested_action()}),
        );
    }
    let io_failure = error.chain().any(|cause| cause.is::<std::io::Error>());
    let domain = !io_failure
        && (configuration_report(error).is_some() || matches!(kind, CommandKind::Authoring));
    (
        if domain {
            DOMAIN_REFUSAL_EXIT
        } else {
            OPERATIONAL_FAILURE_EXIT
        },
        json!({"severity":"error","code":if io_failure{"caseworkctl.io-failure"}else if domain{"caseworkctl.refused"}else{"caseworkctl.operational-failure"},"path":if io_failure{"filesystem"}else{"runtime"},"message":if io_failure{"A required filesystem operation failed."}else if domain{"The authored input was refused."}else{"A Casework runtime dependency check failed."},"suggestedAction":if io_failure{"Correct the path or permissions, then retry."}else{"Correct the named input or runtime dependency, then retry."}}),
    )
}

fn activation_failure(
    error: &anyhow::Error,
) -> Option<(u8, Vec<registry_platform_yaml::Diagnostic>)> {
    use registry_casework::{ActivationError, StoreError};
    use registry_platform_yaml::Diagnostic;
    if let Some(activation) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ActivationError>())
    {
        let classified = match activation {
            ActivationError::Refused(refusals)=>Some((DOMAIN_REFUSAL_EXIT,refusals.iter().map(|refusal|report::operator_refusal_diagnostic(&refusal.code,&refusal.path,&refusal.message)).collect())),
            ActivationError::Store(StoreError::AuditUnavailable)=>Some((OPERATIONAL_FAILURE_EXIT,vec![Diagnostic::error("casework.activation.audit-unavailable","runtime.yaml:/audit","The audit destination refused the activation request; the package was not applied.","Restore the audit destination, then apply again.")])),
            ActivationError::AppliedUnaudited{..}=>Some((OPERATIONAL_FAILURE_EXIT,vec![Diagnostic::error("casework.activation.applied-unaudited","runtime.yaml:/audit",activation.to_string(),"The package is active. Restore audit and confirm the activation with caseworkctl status --runtime-config FILE before taking another action.")])),
            ActivationError::Store(_)=>None,
        };
        if classified.is_some() {
            return classified;
        }
    }
    if error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<StoreError>(),
            Some(StoreError::LedgerUnreadable { .. })
        ) || matches!(
            cause.downcast_ref::<ActivationError>(),
            Some(ActivationError::Store(StoreError::LedgerUnreadable { .. }))
        )
    }) {
        return Some((DOMAIN_REFUSAL_EXIT,vec![Diagnostic::error("casework.activation.ledger-unreadable","runtime.yaml:/database/runtimeUrlRef","The runtime role cannot read the activation ledger.","Run caseworkctl apply --runtime-config FILE using the migration credential to restore runtime grants, then plan again.")]));
    }
    None
}
#[cfg(test)]
mod operator_tests;

impl Command {
    fn report_command(&self) -> &'static str {
        match self {
            Self::Init { .. } => "init",
            Self::Check(_) => "check",
            Self::Explain(_) => "explain",
            Self::Test(_) => "test",
            Self::Types { .. } => "types",
            Self::Provider { command } => match command {
                ProviderCommand::Add { .. } => "provider-add",
                ProviderCommand::Pair { .. } => "provider-pair",
            },
            Self::Lifecycle => "lifecycle",
            Self::Package { .. } => "package",
            Self::Doctor(_) => "doctor",
            Self::Plan(_) => "plan",
            Self::Status(_) => "status",
            Self::Apply { .. } => "apply",
            Self::Dev(args) => match args.report_kind() {
                "CaseworkDevEventsReport" => "dev-events",
                "CaseworkDevGrantReport" => "dev-grant",
                "CaseworkDevIdentityReport" => "dev-identity",
                "CaseworkDevTokenReport" => "dev-token",
                _ => "dev",
            },
            Self::DevSupervisor(_) | Self::DevServiceGuard(_) => "internal",
        }
    }
}

fn run(command: Command) -> Result<Value> {
    match command {
        Command::Init { project, template } => project::init(&project, &template),
        Command::Check(args) => {
            let mut result = project::check(&args.project, args.production, args.deny_warnings);
            if let Some(runtime) = args.runtime_config {
                result = project::check_runtime_config(
                    &args.project,
                    &runtime,
                    args.environment,
                    result,
                );
            }
            let mut report = result?;
            if let Some(package) = args.against_breg_package {
                report["bregPackage"] = provider_pair::compare(
                    &args.project,
                    &package,
                    args.provider_id.as_deref(),
                    &args.bregctl_bin,
                )?;
            }
            Ok(report)
        }
        Command::Explain(args) => project::explain(&args.project),
        Command::Test(args) => project::test(&args.project, args.deny_warnings),
        Command::Types { project, output } => project_types::generate(&project, &output),
        Command::Provider {
            command:
                ProviderCommand::Add {
                    project,
                    breg_project,
                    action,
                    pattern,
                    breg_package,
                    package_output,
                    bregctl_bin,
                },
        } => provider_add::add(
            &project,
            &breg_project,
            &action,
            &pattern,
            breg_package.as_deref(),
            package_output.as_deref(),
            &bregctl_bin,
        ),
        Command::Provider {
            command:
                ProviderCommand::Pair {
                    project,
                    provider_id,
                    breg_package,
                    action_id,
                    bregctl_bin,
                    apply,
                },
        } => provider_pair::pair(
            &project,
            &provider_id,
            &breg_package,
            &action_id,
            &bregctl_bin,
            apply,
        ),
        Command::Lifecycle => Ok(
            json!({"ok":true,"command":"lifecycle","lifecycles":[registry_casework_core::review_lifecycle()]}),
        ),
        Command::Package {
            project,
            output,
            revision,
            dry_run,
        } => {
            if dry_run {
                project::package_dry_run(&project, revision.as_deref())
            } else {
                project::package(
                    &project,
                    &output.ok_or_else(|| anyhow::anyhow!("--output is required"))?,
                    revision.as_deref(),
                )
            }
        }
        Command::Doctor(args) => project::doctor(&args.runtime_config),
        Command::Plan(args) => project::plan(&args.runtime_config),
        Command::Status(args) => project::status(&args.runtime_config),
        Command::Apply {
            runtime_config,
            operator_reference,
            backup_reference,
        } => project::apply(&runtime_config, operator_reference, backup_reference),
        Command::Dev(args) => dev::run(*args),
        Command::DevSupervisor(args) => {
            dev::run_supervisor(args)?;
            Ok(json!({"ok":true}))
        }
        Command::DevServiceGuard(args) => Ok(json!({"ok":dev::run_service_guard(args)?})),
    }
}
fn render_human(value: &Value, out: &mut (impl Write + ?Sized)) -> io::Result<()> {
    let diagnostics: Vec<registry_platform_yaml::Diagnostic> =
        serde_json::from_value(value["diagnostics"].clone()).map_err(io::Error::other)?;
    if !diagnostics.is_empty() {
        write!(
            out,
            "{}",
            registry_platform_yaml::Report::new(diagnostics).render_human()
        )?;
        if value["ok"] == false && value["command"] != "provider-add" {
            return Ok(());
        }
    }
    if value["command"] == "provider-add" {
        if let Some(data) = value.get("data") {
            return render_provider_add(data, out);
        }
        return Ok(());
    }
    writeln!(
        out,
        "{}",
        serde_json::to_string_pretty(value).map_err(io::Error::other)?
    )
}

fn render_provider_add(data: &Value, out: &mut (impl Write + ?Sized)) -> io::Result<()> {
    for field in ["changes", "deployment"] {
        if let Some(changes) = data[field].as_array() {
            for change in changes {
                writeln!(
                    out,
                    "{}: {}",
                    change["path"].as_str().unwrap_or_default(),
                    change["explanation"].as_str().unwrap_or_default()
                )?;
                write_yaml(&change["yaml"], out)?;
            }
        }
    }
    for notice in ["readGrant", "inputsOnlyAlternative"] {
        if let Some(notice) = data.get(notice) {
            writeln!(
                out,
                "{}",
                notice["explanation"].as_str().unwrap_or_default()
            )?;
            write_yaml(&notice["yaml"], out)?;
        }
    }
    if let Some(bypasses) = data["bypassPaths"].as_array() {
        for bypass in bypasses {
            writeln!(
                out,
                "Bypass: profile {} can {} {}. Review this mutationPolicy change:",
                bypass["profile"].as_str().unwrap_or_default(),
                bypass["operation"].as_str().unwrap_or_default(),
                bypass["recordType"].as_str().unwrap_or_default()
            )?;
            write_yaml(&bypass["mutationPolicy"], out)?;
        }
    }
    writeln!(
        out,
        "{}: {}",
        data["state"].as_str().unwrap_or_default(),
        data["next"].as_str().unwrap_or_default()
    )
}

fn write_yaml(value: &Value, out: &mut (impl Write + ?Sized)) -> io::Result<()> {
    writeln!(
        out,
        "{}",
        serde_norway::to_string(value).map_err(io::Error::other)?
    )
}
pub(crate) fn configuration_report(
    error: &anyhow::Error,
) -> Option<&registry_platform_yaml::Report> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<registry_platform_yaml::Report>()
            .or_else(
                || match cause.downcast_ref::<registry_casework_core::ConfigLoadError>() {
                    Some(registry_casework_core::ConfigLoadError::Refused(report)) => Some(report),
                    _ => None,
                },
            )
    })
}
#[cfg(test)]
pub(crate) fn canonical_tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removed_commands_are_not_exposed() {
        for name in ["source", "attempt", "retention", "simulate"] {
            assert!(Cli::try_parse_from(["caseworkctl", name]).is_err());
        }
    }
    #[test]
    fn package_requires_one_output_mode_before_project_io() {
        use clap::error::ErrorKind;
        for (arguments, expected) in [
            (
                vec!["caseworkctl", "package", "missing-project"],
                ErrorKind::MissingRequiredArgument,
            ),
            (
                vec![
                    "caseworkctl",
                    "package",
                    "missing-project",
                    "--output",
                    "package",
                    "--dry-run",
                ],
                ErrorKind::ArgumentConflict,
            ),
        ] {
            assert_eq!(Cli::try_parse_from(arguments).unwrap_err().kind(), expected);
        }
        for arguments in [
            vec![
                "caseworkctl",
                "package",
                "missing-project",
                "--output",
                "package",
            ],
            vec!["caseworkctl", "package", "missing-project", "--dry-run"],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }
    }
    #[test]
    fn human_configuration_refusal_includes_positions_notes_and_summary() {
        let temp = canonical_tempdir();
        let project = temp.path().join("duplicate");
        project::init(&project, "standalone-decision").unwrap();
        std::fs::write(
            project.join("casework.yaml"),
            format!("{}\nduplicate: 1\nduplicate: 2\n", project::STANDALONE_YAML),
        )
        .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = main_entry_from(
            [
                OsString::from("caseworkctl"),
                OsString::from("check"),
                project.into_os_string(),
            ],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(result, ExitCode::from(1));
        assert!(stdout.is_empty());
        let human = String::from_utf8(stderr).unwrap();
        assert!(human.contains("error[yaml.duplicate-key]"), "{human}");
        assert!(human.contains(" /duplicate\n"), "{human}");
        assert!(human.contains("  next:"), "{human}");
        assert!(human.contains("  note:"), "{human}");
        assert!(human.contains("1 error, 0 warnings in 1 file"), "{human}");
        assert!(!human.contains("\"diagnostics\":"), "{human}");
    }
    #[test]
    fn canonical_review_template_embeds_the_owner_project_and_context_schema() {
        let temp = canonical_tempdir();
        let project = temp.path().join("canonical");
        project::init(&project, "canonical-review").unwrap();
        for (name, bytes) in [
            ("casework.yaml", include_bytes!("../../../products/casework/examples/canonical-review/casework.yaml").as_slice()),
            ("schemas/correct-address.schema.json", include_bytes!("../../../products/casework/examples/canonical-review/schemas/correct-address.schema.json").as_slice()),
            ("dev-clients.yaml", include_bytes!("../../../products/casework/examples/canonical-review/dev-clients.yaml").as_slice()),
        ] {
            assert_eq!(std::fs::read(project.join(name)).unwrap(), bytes, "{name}");
        }
        project::load_and_check_policy(&project).unwrap();
        for name in ["casework.yaml", "runtime.example.yaml", "dev-clients.yaml"] {
            let text = std::fs::read_to_string(project.join(name)).unwrap();
            let schema = text
                .lines()
                .next()
                .unwrap()
                .strip_prefix("# yaml-language-server: $schema=")
                .unwrap();
            assert!(project.join(schema).is_file(), "{name}");
        }
    }

    /// The canonical BReg-bound project with one task template whose
    /// `subjects` need task-grant context.
    fn canonical_with_subject_template(declare_on_provider: bool) -> (tempfile::TempDir, PathBuf) {
        let temp = canonical_tempdir();
        let project = temp.path().join("canonical");
        project::init(&project, "canonical-review").unwrap();
        let path = project.join("casework.yaml");
        let mut yaml = std::fs::read_to_string(&path).unwrap();
        if declare_on_provider {
            yaml = yaml
                .replace(
                    "    capabilities: [human-display, service-status]\n",
                    "    capabilities: [human-display, service-status, task-grant-context]\n",
                )
                .replace(
                    "      service-status: casework-review-status\n",
                    "      service-status: casework-review-status\n      task-grant-context: casework-task-context\n",
                );
        }
        yaml.push_str(
            "teams:
  facility-reviewers:
    label: Facility reviewers
    serves: [facility-addresses]
    memberProfiles: [staff]
    supervisorProfiles: [supervisor]
taskTemplates:
  address-summary:
    version: \"1\"
    label: Prepare an address summary
    eligibleTeams: [facility-reviewers]
    eligibleProfiles: [staff]
    source: facility-registry
    reviewPolicies: [facility-address-review]
    agent: {issuer: https://agent.example.test, subject: summary-agent}
    client: summary-client
    resource: urn:breg:facility-registry
    scopes: [registry:facility:read]
    purpose: prepare-summary
    bounds: {type: breg, permissions: [{collection: facilities, operations: [get]}]}
    subjects: {facility: facilityId}
    lifetimeSeconds: 900
",
        );
        std::fs::write(&path, yaml).unwrap();
        // Local callers are optional; without them the policy refusal is
        // the only one left to report.
        std::fs::remove_file(project.join("dev-clients.yaml")).unwrap();
        (temp, project)
    }

    fn json_check(project: &std::path::Path) -> (ExitCode, Value) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let exit = main_entry_from(
            [
                OsString::from("caseworkctl"),
                OsString::from("--format"),
                OsString::from("json"),
                OsString::from("check"),
                project.as_os_str().to_owned(),
            ],
            &mut out,
            &mut err,
        );
        assert!(err.is_empty(), "{}", String::from_utf8_lossy(&err));
        (exit, serde_json::from_slice(&out).unwrap())
    }

    #[test]
    fn check_refuses_task_grant_subjects_a_breg_source_does_not_serve() {
        let (_temp, project) = canonical_with_subject_template(true);
        let (exit, report) = json_check(&project);
        assert_eq!(exit, ExitCode::from(1), "{report}");
        let diagnostics = report["diagnostics"].as_array().unwrap();
        let template = diagnostics
            .iter()
            .find(|diagnostic| diagnostic["path"] == "/taskTemplates/address-summary/subjects")
            .unwrap_or_else(|| panic!("the template is named at its subjects: {report}"));
        assert_eq!(
            template["code"],
            "casework.task-template.unserved-capability"
        );
        assert_eq!(
            template["message"],
            "task template address-summary declares subjects, which need the \
             task-grant-context capability, and BReg, the source behind context provider \
             facility-proposal-context, does not serve task-grant context yet; see \
             https://github.com/registrystack/registry-stack/issues/2062"
        );
        assert_eq!(
            template["suggestedAction"],
            "Remove `subjects` from task template address-summary, or bind the template \
             to review policies whose source serves task-grant context."
        );
        assert_eq!(
            template["source"]["file"],
            project.join("casework.yaml").display().to_string()
        );
        let provider = diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic["path"] == "/contextProviders/facility-proposal-context/capabilities"
            })
            .unwrap_or_else(|| panic!("the provider declaration is named too: {report}"));
        assert_eq!(
            provider["code"],
            "casework.context-provider.unserved-capability"
        );
        assert_eq!(
            provider["suggestedAction"],
            "Remove task-grant-context from the capabilities and serviceProfiles of context \
             provider facility-proposal-context."
        );
        assert_eq!(diagnostics.len(), 2, "{report}");
    }

    #[test]
    fn check_names_the_template_when_its_provider_does_not_declare_task_grant_context() {
        let (_temp, project) = canonical_with_subject_template(false);
        let (exit, report) = json_check(&project);
        assert_eq!(exit, ExitCode::from(1), "{report}");
        let diagnostics = report["diagnostics"].as_array().unwrap();
        assert_eq!(diagnostics.len(), 1, "{report}");
        assert_eq!(
            diagnostics[0]["code"],
            "casework.task-template.provider-capability"
        );
        assert_eq!(
            diagnostics[0]["path"],
            "/taskTemplates/address-summary/subjects"
        );
    }

    #[test]
    fn init_files_select_existing_local_editor_schemas() {
        let temp = canonical_tempdir();
        let project = temp.path().join("editor");
        project::init(&project, "standalone-decision").unwrap();
        for name in ["casework.yaml", "runtime.example.yaml", "dev-clients.yaml"] {
            let text = std::fs::read_to_string(project.join(name)).unwrap();
            let schema = text
                .lines()
                .next()
                .unwrap()
                .strip_prefix("# yaml-language-server: $schema=")
                .unwrap();
            assert!(
                project.join(schema).is_file(),
                "{name} selects absent schema {schema}"
            );
            let document: Value =
                serde_json::from_slice(&std::fs::read(project.join(schema)).unwrap()).unwrap();
            assert!(
                document["$id"].as_str().is_some(),
                "{name} schema has no identity"
            );
        }
    }
    #[test]
    fn starter_compiles_and_generates_bindings() {
        let temp = canonical_tempdir();
        let project = temp.path().join("standalone");
        project::init(&project, "standalone-decision").unwrap();
        project::check(&project, false, false).unwrap();
        project::test(&project, false).unwrap();
        project_types::generate(&project, &temp.path().join("types")).unwrap();
    }
}
