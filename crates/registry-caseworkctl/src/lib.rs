// SPDX-License-Identifier: Apache-2.0
mod dev;
mod project;
mod project_types;
mod provider_pair;
mod report;
#[cfg(feature = "schema")]
pub mod schema;
use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
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
    /// Create a complete standalone ReviewPolicy project.
    Init {
        project: PathBuf,
        #[arg(long, default_value = "standalone-decision")]
        template: String,
    },
    /// Validate policy, closed context schemas and required provider capabilities offline.
    Check(CheckArgs),
    /// Explain pinned policy, context custody, staffing, refusals and recovery.
    Explain(ProjectArgs),
    /// Exercise bounded review context fixtures offline.
    Test(ProjectArgs),
    /// Generate policy bindings and context/request/task/result TypeScript and Python types.
    Types {
        project: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Pair a context provider with an existing native producer export and reader authority.
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    /// Report the one review lifecycle.
    Lifecycle,
    /// Package the policy and its exact local schema and provider dependency closure.
    Package {
        project: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        revision: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    Doctor(OperatorArgs),
    Plan(OperatorArgs),
    Status(OperatorArgs),
    Apply {
        #[arg(long)]
        runtime_config: PathBuf,
        #[arg(long)]
        operator_reference: Option<String>,
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
    Pair {
        project: PathBuf,
        #[arg(long)]
        provider_id: String,
        #[arg(long)]
        breg_package: PathBuf,
        #[arg(long)]
        action_id: String,
        #[arg(long, default_value = "bregctl")]
        bregctl_bin: PathBuf,
        #[arg(long)]
        apply: bool,
    },
}
#[derive(Debug, Args)]
struct ProjectArgs {
    project: PathBuf,
}
#[derive(Debug, Args)]
struct OperatorArgs {
    #[arg(long)]
    runtime_config: PathBuf,
}
#[derive(Debug, Args)]
struct CheckArgs {
    project: PathBuf,
    #[arg(long)]
    production: bool,
    #[arg(long)]
    deny_warnings: bool,
    #[arg(long)]
    against_breg_package: Option<PathBuf>,
    #[arg(long, requires = "against_breg_package")]
    provider_id: Option<String>,
    #[arg(long, default_value = "bregctl")]
    bregctl_bin: PathBuf,
    #[arg(long)]
    runtime_config: Option<PathBuf>,
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
            Self::Provider { .. } => "provider-pair",
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
        Command::Test(args) => project::test(&args.project),
        Command::Types { project, output } => project_types::generate(&project, &output),
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
    if let Some(diagnostics) = value["diagnostics"].as_array() {
        for diagnostic in diagnostics {
            writeln!(
                out,
                "{}: {}",
                diagnostic["code"].as_str().unwrap_or("casework.refused"),
                diagnostic["message"]
                    .as_str()
                    .unwrap_or("operation refused")
            )?;
        }
    }
    writeln!(
        out,
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_default()
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
    fn starter_compiles_and_generates_bindings() {
        let temp = canonical_tempdir();
        let project = temp.path().join("standalone");
        project::init(&project, "standalone-decision").unwrap();
        project::check(&project, false, false).unwrap();
        project::test(&project).unwrap();
        project_types::generate(&project, &temp.path().join("types")).unwrap();
    }
}
