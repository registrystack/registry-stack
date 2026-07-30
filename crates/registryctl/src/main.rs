use std::ffi::OsStr;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Error, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use serde::Serialize;

use registryctl::{
    ApprovedLaneV1, ApprovedSetAssembleOptions, DeploymentProfile, DevFailureCategory,
    ProductBundleSignOptions, ProjectCheckOptions, ProjectEditorSetupOptions,
    ProjectExecutionContext, ProjectInitOptions, ProjectSchemaKind, ProjectStarter,
    ProjectTestOptions, ProjectTestSelection, ReviewCompareOptions, ReviewedProjectBuildOptions,
    TrustAnchorCreateOptions, TrustAnchorRotateOptions,
};

const EXIT_DOMAIN: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_OPERATIONAL: u8 = 3;
const PROJECT_FILE: &str = "registry-stack.yaml";

fn main() -> ExitCode {
    if registry_relay::rhai_worker::is_worker_invocation(std::env::args_os()) {
        return registry_relay::rhai_worker::run_worker_stdio();
    }
    if is_exact_internal_mode("__registryctl-cel-worker-v1") {
        registry_notary_server::cel_worker::run_stdio_worker();
        return ExitCode::SUCCESS;
    }

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return ExitCode::from(u8::try_from(code).unwrap_or(EXIT_USAGE));
        }
    };
    match run(cli) {
        Ok(status) => status,
        Err(failure) => {
            eprintln!("registryctl: {}", failure.error);
            ExitCode::from(failure.status)
        }
    }
}

#[derive(Debug)]
struct CliFailure {
    status: u8,
    error: Error,
}

impl CliFailure {
    fn domain(error: impl Into<Error>) -> Self {
        Self {
            status: EXIT_DOMAIN,
            error: error.into(),
        }
    }

    fn usage(error: impl Into<Error>) -> Self {
        Self {
            status: EXIT_USAGE,
            error: error.into(),
        }
    }

    fn operational(error: impl Into<Error>) -> Self {
        Self {
            status: EXIT_OPERATIONAL,
            error: error.into(),
        }
    }
}

type CliResult<T = ExitCode> = std::result::Result<T, CliFailure>;

#[derive(Debug, Parser)]
#[command(name = "registryctl")]
#[command(version)]
#[command(disable_help_subcommand = true)]
#[command(
    about = "Create, test, run, and prepare a Registry Stack project",
    long_about = "Create, test, run, and prepare a Registry Stack project.\n\n\
Start here: registryctl init my-registry --template http\n\
Then run:  cd my-registry && registryctl test && registryctl dev",
    after_help = "Newcomer workflow:\n  init -> test -> dev -> check -> build\n\n\
Governed handoff:\n  review -> build -> trust -> deploy\n\n\
Run `registryctl <command> --help` for command ownership and next actions."
)]
struct Cli {
    /// Select a project directory before project discovery.
    #[arg(
        short = 'C',
        long = "project-dir",
        global = true,
        value_name = "DIRECTORY"
    )]
    project_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create a project from a tested local template.
    Init {
        /// Absent or empty real directory in which to create the project.
        #[arg(value_name = "PROJECT_DIRECTORY")]
        destination: PathBuf,
        /// Tested template embedded in this Registryctl release.
        #[arg(long, value_enum)]
        template: InitTemplate,
        /// Output for a person or one strict versioned JSON document.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },

    /// Execute authored fixtures offline through production semantics.
    Test {
        /// Select one declared project environment.
        #[arg(long)]
        environment: Option<String>,
        /// Run fixtures for one integration id.
        #[arg(long)]
        integration: Option<String>,
        /// Run one fixture within the selected integration.
        #[arg(long, requires = "integration")]
        fixture: Option<String>,
        /// Include the safe synthetic interaction trace.
        #[arg(long)]
        trace: bool,
        /// Rerun when authored project files change.
        #[arg(long)]
        watch: bool,
        /// Output for a person or one strict versioned JSON document.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },

    /// Build and run an isolated disposable development environment.
    Dev {
        /// Select one declared project environment.
        #[arg(long)]
        environment: Option<String>,
        /// Leave the development environment running.
        #[arg(long)]
        detach: bool,
        #[command(subcommand)]
        command: Option<DevCommand>,
    },

    /// Validate and explain authored intent without writing build state.
    Check {
        /// Select one declared project environment.
        #[arg(long)]
        environment: Option<String>,
        /// Include the complete redacted effective plan.
        #[arg(long)]
        explain: bool,
        /// Show directly authored non-secret values in trusted local human output.
        #[arg(long, requires = "explain")]
        show_authored_values: bool,
        /// Output for a person or one strict versioned JSON document.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },

    /// Emit deterministic unsigned product-lane signing inputs.
    #[command(
        after_help = "Governed handoff:\n  Input owner: country implementer and reviewer\n  Output owner: independent product-lane trust owners\n  Mutation: replaces only generated build output for the selected environment\n  Next command: registryctl trust bundle sign --help"
    )]
    Build {
        /// Select one declared project environment.
        #[arg(long)]
        environment: Option<String>,
        /// Current approved baseline set for an update.
        #[arg(long)]
        against: Option<PathBuf>,
        /// Output for a person or one strict versioned JSON document.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },

    /// Generate or verify a governed deployment package.
    ///
    /// Bare `registryctl deploy` prints help and performs no action.
    Deploy {
        #[command(subcommand)]
        command: Option<DeployCommand>,
    },

    /// Diagnose host, released-artifact, and product prerequisites.
    Doctor {
        /// Select one declared project environment.
        #[arg(long)]
        environment: Option<String>,
        /// Select a diagnostic profile, not an operating contract.
        #[arg(long, value_enum)]
        profile: Option<DeploymentProfile>,
        /// Output for a person or one strict versioned JSON document.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },

    /// Advanced: compare authored state with an approved baseline.
    Review {
        #[command(subcommand)]
        command: ReviewCommand,
    },

    /// Advanced: inspect and create independently owned trust artifacts.
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },

    /// Advanced: inspect static schemas, references, and editor support.
    Tooling {
        #[command(subcommand)]
        command: ToolingCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DevCommand {
    /// Report the bound development workload state.
    Status {
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Report bounded, value-free product log availability.
    Logs {
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Run the selected denial and authorized scenarios.
    Smoke {
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Stop the bound runtime and remove disposable development state.
    Down,
}

#[derive(Debug, Subcommand)]
enum DeployCommand {
    /// Generate a complete governed package without activating it.
    #[command(
        after_help = "Governed handoff:\n  Input owner: approved-set owner and installed Registry Stack release\n  Output owner: deployment operator\n  Mutation: creates or safely regenerates only the selected managed package directory; does not activate it\n  Next command: registryctl deploy verify --package <directory>"
    )]
    Generate {
        /// Verified three-lane approved baseline set.
        #[arg(long)]
        approved_set: PathBuf,
        /// Absent, empty, or verified managed package directory.
        #[arg(long)]
        output_dir: PathBuf,
        /// Optional closed deployment binding. Omit for safe loopback defaults.
        #[arg(long)]
        binding: Option<PathBuf>,
        /// Output for a person or one strict versioned JSON document.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Verify package ownership, freshness, and hard invariants.
    #[command(
        after_help = "Governed handoff:\n  Input owner: deployment operator\n  Output owner: deployment operator\n  Mutation: none\n  Next command: docker compose --env-file generated/compose.empty.env -f generated/compose.yaml config --no-interpolate --no-env-resolution --quiet"
    )]
    Verify {
        /// Deployment package to verify.
        #[arg(long)]
        package: PathBuf,
        /// Optional expected approved baseline set.
        #[arg(long)]
        approved_set: Option<PathBuf>,
        /// Generated closure digest recorded outside the package.
        #[arg(long)]
        expected_closure_sha256: Option<String>,
        /// Check operator-file existence, isolation, mode, and owner without reading values.
        #[arg(long)]
        check_operator_files: bool,
        /// Output for a person or one strict versioned JSON document.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum ReviewCommand {
    /// Compare authored intent with an optional current approved set.
    #[command(
        after_help = "Governed handoff:\n  Input owner: country implementer\n  Output owner: independent reviewer\n  Mutation: none\n  Next command: registryctl build"
    )]
    Compare {
        /// Select one declared project environment.
        #[arg(long)]
        environment: Option<String>,
        /// Current approved baseline set. Omit for initial review.
        #[arg(long)]
        against: Option<PathBuf>,
        /// Return status 1 when the report detects a change.
        #[arg(long)]
        fail_on_change: bool,
        /// Output for a person or one strict versioned JSON document.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum TrustCommand {
    /// Work with immutable operator trust anchors.
    Anchor {
        #[command(subcommand)]
        command: TrustAnchorCommand,
    },
    /// Inspect, verify, or sign one product-lane bundle.
    Bundle {
        #[command(subcommand)]
        command: TrustBundleCommand,
    },
    /// Assemble the exact three independently verified product lanes.
    ApprovedSet {
        #[command(subcommand)]
        command: ApprovedSetCommand,
    },
}

#[derive(Debug, Subcommand)]
enum TrustAnchorCommand {
    /// Create an immutable version-1 lane anchor.
    #[command(
        after_help = "Governed handoff:\n  Input owner: product-lane trust owner\n  Output owner: the same product-lane trust owner\n  Mutation: creates one new immutable anchor file; never edits an existing anchor\n  Next command: registryctl trust bundle sign --help"
    )]
    Create {
        #[arg(long, value_enum)]
        lane: Lane,
        #[arg(long)]
        input: PathBuf,
        #[arg(long = "public-key", required = true, action = clap::ArgAction::Append)]
        public_keys: Vec<PathBuf>,
        #[arg(long)]
        threshold: u32,
        #[arg(long)]
        output_file: PathBuf,
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Create a next anchor and transition without editing the current anchor.
    #[command(
        after_help = "Governed handoff:\n  Input owner: current product-lane trust owners\n  Output owner: next product-lane trust owners\n  Mutation: creates a next anchor and authenticated transition in a fresh directory\n  Next command: registryctl trust bundle sign --help"
    )]
    Rotate {
        #[arg(long)]
        current_anchor: PathBuf,
        #[arg(long = "next-public-key", required = true, action = clap::ArgAction::Append)]
        next_public_keys: Vec<PathBuf>,
        #[arg(long)]
        next_threshold: u32,
        #[arg(long = "key", required = true, action = clap::ArgAction::Append)]
        keys: Vec<String>,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum TrustBundleCommand {
    /// Inspect signed-manifest metadata without granting trust.
    #[command(
        after_help = "Governed handoff:\n  Input owner: product-lane trust owner\n  Output owner: reviewer\n  Mutation: none\n  Next command: registryctl trust bundle verify --bundle-dir <directory> --anchor <file>"
    )]
    Inspect {
        #[arg(long)]
        bundle_dir: PathBuf,
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Verify a bundle against its lane anchor.
    #[command(
        after_help = "Governed handoff:\n  Input owner: product-lane signer and anchor owner\n  Output owner: approved-set assembler\n  Mutation: none\n  Next command: registryctl trust approved-set assemble --help"
    )]
    Verify {
        #[arg(long)]
        bundle_dir: PathBuf,
        #[arg(long)]
        anchor: PathBuf,
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Sign one generated lane input into a fresh closed directory.
    #[command(
        after_help = "Governed handoff:\n  Input owner: country implementer for the signing input; product-lane trust owner for anchor and key locator\n  Output owner: product-lane trust owner\n  Mutation: creates one fresh signed bundle directory; never edits the input or anchor\n  Next command: registryctl trust bundle verify --bundle-dir <directory> --anchor <file>"
    )]
    Sign {
        #[arg(long, value_enum)]
        lane: Lane,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        anchor: PathBuf,
        /// Current approved set for an update.
        #[arg(long)]
        against: Option<PathBuf>,
        /// Explicit file: or op:// key locator.
        #[arg(long = "key", required = true, action = clap::ArgAction::Append)]
        keys: Vec<String>,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum ApprovedSetCommand {
    /// Assemble an initial or updated approved baseline set.
    #[command(
        after_help = "Governed handoff:\n  Input owner: independent product-lane trust owners\n  Output owner: approved-set owner\n  Mutation: creates one approved-set file; never edits signed lane inputs\n  Next command: registryctl deploy generate --approved-set <file> --output-dir <directory>"
    )]
    Assemble {
        /// Select one declared project environment.
        #[arg(long)]
        environment: Option<String>,
        /// Preceding approved set for an update.
        #[arg(long = "from")]
        preceding_set: Option<PathBuf>,
        #[arg(long)]
        relay_public: Option<PathBuf>,
        #[arg(long)]
        relay_consultation: Option<PathBuf>,
        #[arg(long)]
        notary: Option<PathBuf>,
        #[arg(long)]
        output_file: PathBuf,
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum ToolingCommand {
    /// Print one strict project-authoring JSON Schema.
    Schema {
        #[arg(long, value_enum)]
        kind: ProjectSchemaKind,
    },
    /// Print a generated configuration or xw.v1 reference.
    Reference {
        #[command(subcommand)]
        command: ReferenceCommand,
    },
    /// Install deterministic project-local schema mappings.
    Editor {
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Run cross-file navigation over the Language Server Protocol.
    LanguageServer,
    /// Print one static diagnostic catalog.
    Diagnostics {
        #[arg(long, value_enum)]
        catalog: DiagnosticCatalog,
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum ReferenceCommand {
    /// Print the deterministic project configuration reference.
    Configuration {
        /// Audit reviewed human-intent coverage instead of printing the reference.
        #[arg(long)]
        coverage: bool,
    },
    /// Print the generated xw.v1 function or editor reference.
    Xw {
        #[arg(long, value_enum, default_value = "reference")]
        format: XwFormat,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum InitTemplate {
    Http,
}

impl From<InitTemplate> for ProjectStarter {
    fn from(value: InitTemplate) -> Self {
        match value {
            InitTemplate::Http => Self::Http,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum DiagnosticCatalog {
    Authoring,
    Fixture,
    Operator,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum XwFormat {
    Reference,
    Editor,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum Lane {
    RelayPublic,
    RelayConsultation,
    Notary,
}

impl From<Lane> for registry_platform_config::ProductAcceptanceLaneV1 {
    fn from(value: Lane) -> Self {
        match value {
            Lane::RelayPublic => Self::RelayPublic,
            Lane::RelayConsultation => Self::RelayConsultation,
            Lane::Notary => Self::Notary,
        }
    }
}

impl From<Lane> for ApprovedLaneV1 {
    fn from(value: Lane) -> Self {
        match value {
            Lane::RelayPublic => Self::RelayPublic,
            Lane::RelayConsultation => Self::RelayConsultation,
            Lane::Notary => Self::Notary,
        }
    }
}

fn run(cli: Cli) -> CliResult {
    let Cli {
        project_dir,
        command,
    } = cli;
    match command {
        Commands::Init {
            destination,
            template,
            format,
        } => {
            if project_dir.is_some() {
                return Err(CliFailure::usage(anyhow!(
                    "global --project-dir does not select the init destination; use the positional PROJECT_DIRECTORY"
                )));
            }
            let report = registryctl::init_registry_project(&ProjectInitOptions {
                starter: template.into(),
                directory: destination,
            })
            .map_err(CliFailure::operational)?;
            match format {
                OutputFormat::Json => print_json(&report)?,
                OutputFormat::Human => {
                    println!(
                        "Created Registry Stack project {} in {}.",
                        report.project,
                        report.output.display()
                    );
                    println!("Next: cd {} && registryctl test", report.output.display());
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Test {
            environment,
            integration,
            fixture,
            trace,
            watch,
            format,
        } => {
            let project = discover_project(project_dir.as_deref())?;
            let environment = resolve_environment(&project, environment)?;
            if watch && format == OutputFormat::Json {
                return Err(CliFailure::usage(anyhow!(
                    "test --watch supports only human output"
                )));
            }
            let options = ProjectTestOptions {
                project_directory: project,
                environment: Some(environment),
            };
            let selection = ProjectTestSelection {
                integration,
                fixture,
                trace,
            };
            if watch {
                watch_project_tests(options, selection)?;
            } else {
                let report = registryctl::test_registry_project_selected(&options, &selection)
                    .map_err(CliFailure::domain)?;
                print_project_report(format, "test", &report, false)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Check {
            environment,
            explain,
            show_authored_values,
            format,
        } => {
            if show_authored_values && format == OutputFormat::Json {
                return Err(CliFailure::usage(anyhow!(
                    "--show-authored-values requires human output"
                )));
            }
            let project = discover_project(project_dir.as_deref())?;
            let environment = resolve_environment(&project, environment)?;
            let options = ProjectCheckOptions {
                project_directory: project,
                environment,
                explain: explain || format == OutputFormat::Human,
                against: None,
                anchor: None,
            };
            if show_authored_values {
                let checked =
                    registryctl::check_registry_project_with_trusted_local_authored_values(
                        &options,
                    )
                    .map_err(CliFailure::domain)?;
                print_project_report(OutputFormat::Human, "check", &checked.report, explain)?;
                println!("Directly authored non-secret values:");
                for value in checked.authored_values {
                    println!("  {}", value.terminal_line().map_err(CliFailure::domain)?);
                }
            } else {
                match registryctl::check_registry_project(&options) {
                    Ok(report) => print_project_report(format, "check", &report, explain)?,
                    Err(error) => {
                        if let Some(diagnostics) =
                            error.downcast_ref::<registryctl::ProjectAuthoringDiagnostics>()
                        {
                            match format {
                                OutputFormat::Human => println!(
                                    "{}",
                                    registryctl::render_project_authoring_diagnostics(diagnostics)
                                ),
                                OutputFormat::Json => print_json(diagnostics)?,
                            }
                            return Ok(ExitCode::from(EXIT_DOMAIN));
                        }
                        return Err(CliFailure::domain(error));
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Build {
            environment,
            against,
            format,
        } => {
            let project = discover_project(project_dir.as_deref())?;
            let environment = resolve_environment(&project, environment)?;
            let report = registryctl::build_reviewed_project(&ReviewedProjectBuildOptions {
                project_directory: project,
                environment,
                against,
            })
            .map_err(CliFailure::domain)?;
            match format {
                OutputFormat::Json => print_json(&report)?,
                OutputFormat::Human => {
                    println!(
                        "Built unsigned signing inputs for {}.",
                        render_lanes(&report.affected_lanes)
                    );
                    println!(
                        "Build output: {}",
                        report
                            .build
                            .output
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "<none>".to_string())
                    );
                    println!("Next: {}", report.next_action);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Dev {
            environment,
            detach,
            command,
        } => {
            if detach && command.is_some() {
                return Err(CliFailure::usage(anyhow!(
                    "--detach applies only when starting with bare registryctl dev"
                )));
            }
            let project = discover_project(project_dir.as_deref())?;
            let environment = resolve_environment(&project, environment)?;
            run_dev(&project, &environment, detach, command)
        }
        Commands::Deploy { command } => match command {
            None => {
                print_subcommand_help("deploy")?;
                Ok(ExitCode::SUCCESS)
            }
            Some(command) => run_deploy(command),
        },
        Commands::Doctor {
            environment,
            profile,
            format,
        } => {
            let project = discover_project(project_dir.as_deref())?;
            let environment = resolve_environment(&project, environment)?;
            run_doctor(&project, &environment, profile, format)
        }
        Commands::Review { command } => match command {
            ReviewCommand::Compare {
                environment,
                against,
                fail_on_change,
                format,
            } => {
                let project = discover_project(project_dir.as_deref())?;
                let environment = resolve_environment(&project, environment)?;
                let report = registryctl::compare_reviewed_project(&ReviewCompareOptions {
                    project_directory: project,
                    environment,
                    against,
                })
                .map_err(CliFailure::domain)?;
                match format {
                    OutputFormat::Json => print_json(&report)?,
                    OutputFormat::Human => {
                        println!(
                            "Review comparison: {}.",
                            if report.changed {
                                "changed"
                            } else {
                                "unchanged"
                            }
                        );
                        println!("Affected lanes: {}.", render_lanes(&report.affected_lanes));
                        println!("Mutation: {}.", report.mutation);
                        println!("Next: {}", report.next_action);
                    }
                }
                Ok(if fail_on_change && report.changed {
                    ExitCode::from(EXIT_DOMAIN)
                } else {
                    ExitCode::SUCCESS
                })
            }
        },
        Commands::Trust { command } => run_trust(project_dir.as_deref(), command),
        Commands::Tooling { command } => run_tooling(project_dir.as_deref(), command),
    }
}

fn run_dev(
    project: &Path,
    environment: &str,
    detach: bool,
    command: Option<DevCommand>,
) -> CliResult {
    let plan = if command.is_none() {
        registryctl::prepare_dev_runtime_plan(project, environment).map_err(dev_failure)?
    } else {
        registryctl::load_bound_dev_runtime_plan(project, environment).map_err(dev_failure)?
    };
    let mut controller = registryctl::DevRuntimeController::new(registryctl::DockerComposeBackend);
    match command {
        None => {
            let report = controller.start(&plan, detach).map_err(dev_failure)?;
            println!(
                "Started disposable development runtime for {}.",
                environment
            );
            for endpoint_url in &report.endpoint_urls {
                println!("{}", dev_endpoint_line(endpoint_url)?);
            }
            println!("Source mode: {}", json_enum(&report.source_mode)?);
            println!("Request: {}", report.request_command);
            println!("Smoke: {}", report.smoke_command);
            println!("Logs: {}", report.logs_command);
            println!("Down: {}", report.down_command);
            println!("{}", report.disposable_notice);
            std::io::stdout()
                .flush()
                .map_err(|error| CliFailure::operational(anyhow!(error)))?;
            if !detach {
                controller.attach(&plan).map_err(dev_failure)?;
            }
        }
        Some(DevCommand::Status { format }) => {
            let report = controller.status(&plan).map_err(dev_failure)?;
            match format {
                OutputFormat::Json => print_json(&report)?,
                OutputFormat::Human => {
                    println!("Development runtime: {} workloads.", report.workloads.len());
                    for workload in &report.workloads {
                        println!(
                            "  {}: {}",
                            json_enum(&workload.workload)?,
                            json_enum(&workload.state)?
                        );
                    }
                    println!("Request: {}", report.request_command);
                }
            }
        }
        Some(DevCommand::Logs { format }) => {
            let report = controller.logs(&plan).map_err(dev_failure)?;
            match format {
                OutputFormat::Json => print_json(&report)?,
                OutputFormat::Human => {
                    println!("Development product log availability:");
                    for product in &report.products {
                        println!(
                            "  {}: {}",
                            json_enum(&product.workload)?,
                            if product.available {
                                "available"
                            } else {
                                "unavailable"
                            }
                        );
                    }
                }
            }
        }
        Some(DevCommand::Smoke { format }) => {
            let report = controller.smoke(&plan).map_err(dev_failure)?;
            match format {
                OutputFormat::Json => print_json(&report)?,
                OutputFormat::Human => {
                    for line in dev_smoke_human_lines(&report)? {
                        println!("{line}");
                    }
                }
            }
            if !report.passed {
                return Ok(ExitCode::from(EXIT_DOMAIN));
            }
        }
        Some(DevCommand::Down) => {
            controller.down(&plan).map_err(dev_failure)?;
            println!("Stopped and removed the bound disposable development runtime.");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn dev_endpoint_line(endpoint_url: &str) -> CliResult<String> {
    let authority = endpoint_url.strip_prefix("https://").ok_or_else(|| {
        CliFailure::operational(anyhow!(
            "development runtime returned a non-HTTPS public endpoint"
        ))
    })?;
    if authority.is_empty() || endpoint_url.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(CliFailure::operational(anyhow!(
            "development runtime returned an invalid public endpoint"
        )));
    }
    Ok(format!("Endpoint: {endpoint_url}"))
}

fn dev_failure(error: registryctl::DevRuntimeError) -> CliFailure {
    let status = match error.category {
        DevFailureCategory::DockerMissing
        | DevFailureCategory::DockerUnavailable
        | DevFailureCategory::ComposeUnsupported
        | DevFailureCategory::ImageUnavailable
        | DevFailureCategory::PortCollision
        | DevFailureCategory::Startup
        | DevFailureCategory::BackendContract
        | DevFailureCategory::Io => EXIT_OPERATIONAL,
        DevFailureCategory::InvalidPlan
        | DevFailureCategory::MissingDefaultScenario
        | DevFailureCategory::UnsafeEnvironment
        | DevFailureCategory::ProjectBinding
        | DevFailureCategory::AmbiguousRuntime
        | DevFailureCategory::StaleBuild
        | DevFailureCategory::InvalidImageLock
        | DevFailureCategory::SmokeFailed => EXIT_DOMAIN,
    };
    CliFailure {
        status,
        error: anyhow!(error),
    }
}

fn json_enum<T: Serialize>(value: &T) -> CliResult<String> {
    serde_json::to_value(value)
        .map_err(|error| CliFailure::operational(anyhow!("cannot render report: {error}")))?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| CliFailure::operational(anyhow!("report enum is not a JSON string")))
}

fn dev_smoke_human_lines(report: &registryctl::DevSmokeReportV1) -> CliResult<Vec<String>> {
    let mut lines = vec![format!(
        "Development smoke: {}.",
        if report.passed { "passed" } else { "failed" }
    )];
    for result in &report.results {
        let token_delta = result
            .token_counter_delta
            .map_or_else(|| "unobserved".to_string(), |value| value.to_string());
        let source_delta = result
            .source_counter_delta
            .map_or_else(|| "unobserved".to_string(), |value| value.to_string());
        let claims = if result.minimized_claim_ids.is_empty() {
            "none".to_string()
        } else {
            result.minimized_claim_ids.join(",")
        };
        lines.push(format!(
            "  {}: status={}; passed={}; token_counter_delta={token_delta}; source_counter_delta={source_delta}; minimized_claim_ids={claims}",
            result.scenario_id,
            json_enum(&result.status)?,
            result.passed,
        ));
    }
    Ok(lines)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Ready,
    NotReady,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct DoctorCheckV1 {
    id: &'static str,
    status: DoctorStatus,
    category: &'static str,
    remediation: Option<&'static str>,
}

impl DoctorCheckV1 {
    const fn ready(id: &'static str) -> Self {
        Self {
            id,
            status: DoctorStatus::Ready,
            category: "ready",
            remediation: None,
        }
    }

    const fn not_ready(
        id: &'static str,
        category: &'static str,
        remediation: &'static str,
    ) -> Self {
        Self {
            id,
            status: DoctorStatus::NotReady,
            category,
            remediation: Some(remediation),
        }
    }
}

#[derive(Debug, Serialize)]
struct DoctorReportV1 {
    schema_version: &'static str,
    status: DoctorStatus,
    environment: String,
    profile: DeploymentProfile,
    checks: Vec<DoctorCheckV1>,
}

fn run_doctor(
    project: &Path,
    environment: &str,
    profile: Option<DeploymentProfile>,
    format: OutputFormat,
) -> CliResult {
    let profile = profile.unwrap_or(DeploymentProfile::Local);
    let mut checks = Vec::new();

    let authoring = registryctl::check_registry_project(&ProjectCheckOptions {
        project_directory: project.to_path_buf(),
        environment: environment.to_string(),
        explain: false,
        against: None,
        anchor: None,
    });
    checks.push(if authoring.is_ok() {
        DoctorCheckV1::ready("authored_environment")
    } else {
        DoctorCheckV1::not_ready(
            "authored_environment",
            "authored_environment_invalid",
            "correct the selected authored environment and rerun registryctl check",
        )
    });

    let release_lock = std::env::current_exe()
        .ok()
        .and_then(|executable| {
            executable
                .parent()
                .map(|parent| parent.join("registry-release-lock.v1.json"))
        })
        .and_then(|path| registryctl::verify_installed_release_lock(&path).ok());
    checks.push(if release_lock.is_some() {
        DoctorCheckV1::ready("installed_release_lock")
    } else {
        DoctorCheckV1::not_ready(
            "installed_release_lock",
            "release_lock_missing_or_invalid",
            "reinstall Registryctl from a verified Registry Stack release payload",
        )
    });

    let docker_installed = Command::new("docker")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    checks.push(if docker_installed {
        DoctorCheckV1::ready("docker_cli")
    } else {
        DoctorCheckV1::not_ready(
            "docker_cli",
            "docker_missing",
            "install Docker using the documented host prerequisite",
        )
    });

    let daemon_available = docker_installed
        && Command::new("docker")
            .args(["info", "--format", "{{json .ServerVersion}}"])
            .output()
            .is_ok_and(|output| output.status.success());
    checks.push(if daemon_available {
        DoctorCheckV1::ready("docker_daemon")
    } else {
        DoctorCheckV1::not_ready(
            "docker_daemon",
            "docker_daemon_unavailable",
            "start the Docker service and rerun registryctl doctor",
        )
    });

    let compose_supported = docker_installed
        && Command::new("docker")
            .args(["compose", "version", "--short"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|version| parse_compose_version(&version))
            .is_some_and(|version| version >= (2, 35, 0));
    checks.push(if compose_supported {
        DoctorCheckV1::ready("docker_compose")
    } else {
        DoctorCheckV1::not_ready(
            "docker_compose",
            "compose_version_unsupported",
            "install Docker Compose 2.35.0 or later",
        )
    });

    if let Some(lock) = release_lock.as_ref() {
        let images = lock.managed_images();
        let available = daemon_available
            && [
                images.relay(),
                images.notary(),
                images.postgresql_state_plane(),
            ]
            .into_iter()
            .all(|image| {
                Command::new("docker")
                    .args(["image", "inspect", "--format", "{{.Id}}", image])
                    .output()
                    .is_ok_and(|output| output.status.success())
            });
        checks.push(if available {
            DoctorCheckV1::ready("locked_images")
        } else {
            DoctorCheckV1::not_ready(
                "locked_images",
                "locked_images_unavailable",
                "load every exact digest-locked image from the verified release payload",
            )
        });
    } else {
        checks.push(DoctorCheckV1::not_ready(
            "locked_images",
            "release_lock_unavailable",
            "verify the installed release lock before checking local image availability",
        ));
    }

    let status = if checks
        .iter()
        .all(|check| check.status == DoctorStatus::Ready)
    {
        DoctorStatus::Ready
    } else {
        DoctorStatus::NotReady
    };
    let report = DoctorReportV1 {
        schema_version: "registryctl.doctor.v1",
        status,
        environment: environment.to_string(),
        profile,
        checks,
    };
    match format {
        OutputFormat::Json => print_json(&report)?,
        OutputFormat::Human => {
            println!(
                "Registry Stack doctor: {}.",
                match report.status {
                    DoctorStatus::Ready => "ready",
                    DoctorStatus::NotReady => "not ready",
                }
            );
            println!("Environment: {}", report.environment);
            println!("Profile: {}", json_enum(&report.profile)?);
            for check in &report.checks {
                println!(
                    "  {}: {} ({})",
                    check.id,
                    match check.status {
                        DoctorStatus::Ready => "ready",
                        DoctorStatus::NotReady => "not ready",
                    },
                    check.category
                );
                if let Some(remediation) = check.remediation {
                    println!("    Remediation: {remediation}");
                }
            }
        }
    }
    Ok(if status == DoctorStatus::Ready {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_DOMAIN)
    })
}

fn parse_compose_version(value: &str) -> Option<(u64, u64, u64)> {
    let value = value.trim().strip_prefix('v').unwrap_or(value.trim());
    let mut parts = value.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts
        .next()?
        .bytes()
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    let patch = std::str::from_utf8(&patch).ok()?.parse().ok()?;
    Some((major, minor, patch))
}

fn run_deploy(command: DeployCommand) -> CliResult {
    match command {
        DeployCommand::Generate {
            approved_set,
            output_dir,
            binding,
            format,
        } => {
            let report = registryctl::generate_deployment_package(
                registryctl::DeploymentGenerateRequestV1 {
                    approved_set_file: approved_set,
                    output_dir,
                    binding_file: binding,
                },
            )
            .map_err(CliFailure::domain)?;
            match format {
                OutputFormat::Human => {
                    println!(
                        "Generated governed deployment package at {}.",
                        report.output_dir.display()
                    );
                    println!(
                        "Approved-set digest: {}",
                        report.source_approved_baseline_set_sha256
                    );
                    println!(
                        "Generated closure: {}",
                        report.externally_recorded_closure_sha256
                    );
                    println!(
                        "Next: registryctl deploy verify --package {} --expected-closure-sha256 {}",
                        report.output_dir.display(),
                        report.externally_recorded_closure_sha256
                    );
                    println!(
                        "Operator Compose check: cd {} && docker compose --env-file generated/compose.empty.env -f generated/compose.yaml config --no-interpolate --no-env-resolution --quiet",
                        report.output_dir.display()
                    );
                }
                OutputFormat::Json => {
                    print_json(&serde_json::json!({
                        "schema_version": "registryctl.deployment_generate.v1",
                        "output_dir": report.output_dir,
                        "source_approved_baseline_set_sha256": report.source_approved_baseline_set_sha256,
                        "externally_recorded_closure_sha256": report.externally_recorded_closure_sha256,
                        "manifest": report.manifest,
                        "next_action": "registryctl deploy verify --package <directory> --expected-closure-sha256 <recorded-sha256>"
                    }))?;
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        DeployCommand::Verify {
            package,
            approved_set,
            expected_closure_sha256,
            check_operator_files,
            format,
        } => {
            let report =
                registryctl::verify_generated_deployment(registryctl::DeploymentVerifyRequestV1 {
                    package_dir: &package,
                    expected_approved_set_file: approved_set.as_deref(),
                    externally_recorded_closure_sha256: expected_closure_sha256,
                    check_operator_files,
                })
                .map_err(CliFailure::domain)?;
            let report_value = serde_json::to_value(&report).map_err(|error| {
                CliFailure::operational(anyhow!(
                    "cannot render deployment ownership report: {error}"
                ))
            })?;
            let invalid = report_value
                .get("ownership")
                .and_then(serde_json::Value::as_str)
                == Some("invalid");
            match format {
                OutputFormat::Json => print_json(&report)?,
                OutputFormat::Human => {
                    println!(
                        "Deployment ownership: {}.",
                        report_value["ownership"].as_str().unwrap_or("invalid")
                    );
                    println!(
                        "Package freshness: {}.",
                        report_value["package_freshness"]
                            .as_str()
                            .unwrap_or("not_applicable")
                    );
                    println!(
                        "Verification scope: {}.",
                        report_value["verification_scope"]
                            .as_str()
                            .unwrap_or("package")
                    );
                    println!(
                        "In-place regeneration safe: {}.",
                        report.in_place_regeneration_safe
                    );
                    if invalid {
                        println!("Hard-invariant failures: {}.", report.violations.len());
                    } else {
                        println!(
                            "Next operator Compose check: cd {} && docker compose --env-file generated/compose.empty.env -f generated/compose.yaml config --no-interpolate --no-env-resolution --quiet",
                            package.display()
                        );
                    }
                }
            }
            Ok(if invalid {
                ExitCode::from(EXIT_DOMAIN)
            } else {
                ExitCode::SUCCESS
            })
        }
    }
}

fn run_trust(project_dir: Option<&Path>, command: TrustCommand) -> CliResult {
    match command {
        TrustCommand::Anchor { command } => match command {
            TrustAnchorCommand::Create {
                lane,
                input,
                public_keys,
                threshold,
                output_file,
                format,
            } => {
                let report = registryctl::create_trust_anchor(&TrustAnchorCreateOptions {
                    lane: lane.into(),
                    input,
                    public_keys,
                    threshold,
                    output_file,
                })
                .map_err(CliFailure::domain)?;
                match format {
                    OutputFormat::Json => print_json(&report)?,
                    OutputFormat::Human => {
                        println!(
                            "Created immutable {} anchor version {} at {}.",
                            render_acceptance_lane(report.lane),
                            report.anchor_version,
                            report.output_file.display()
                        );
                        println!("Anchor digest: {}", report.anchor_digest);
                        println!("Next: {}", report.next_action);
                    }
                }
            }
            TrustAnchorCommand::Rotate {
                current_anchor,
                next_public_keys,
                next_threshold,
                keys,
                output_dir,
                format,
            } => {
                let report = registryctl::rotate_trust_anchor(&TrustAnchorRotateOptions {
                    current_anchor,
                    next_public_keys,
                    next_threshold,
                    keys,
                    output_dir,
                })
                .map_err(CliFailure::domain)?;
                match format {
                    OutputFormat::Json => print_json(&report)?,
                    OutputFormat::Human => {
                        println!(
                            "Created {} anchor version {} and its authenticated transition in {}.",
                            render_acceptance_lane(report.lane),
                            report.next_anchor_version,
                            report.output_dir.display()
                        );
                        println!("Anchor digest: {}", report.anchor_digest);
                        println!("Next: {}", report.next_action);
                    }
                }
            }
        },
        TrustCommand::Bundle { command } => match command {
            TrustBundleCommand::Inspect { bundle_dir, format } => {
                let report =
                    registryctl::inspect_config_bundle(&bundle_dir).map_err(CliFailure::domain)?;
                print_serialized_or_debug(format, "Bundle inspection", &report)?;
            }
            TrustBundleCommand::Verify {
                bundle_dir,
                anchor,
                format,
            } => {
                let report = registryctl::verify_config_bundle_cli(&bundle_dir, &anchor)
                    .map_err(CliFailure::domain)?;
                print_serialized_or_debug(format, "Bundle verification", &report)?;
            }
            TrustBundleCommand::Sign {
                lane,
                input,
                anchor,
                against,
                keys,
                output_dir,
                format,
            } => {
                let report = registryctl::sign_product_bundle(&ProductBundleSignOptions {
                    lane: lane.into(),
                    input,
                    anchor,
                    preceding_approved_set: against,
                    keys,
                    output_dir,
                })
                .map_err(CliFailure::domain)?;
                match format {
                    OutputFormat::Json => print_json(&report)?,
                    OutputFormat::Human => {
                        println!(
                            "Signed {} sequence {} into {}.",
                            render_acceptance_lane(report.lane),
                            report.sequence,
                            report.output_dir.display()
                        );
                        println!("Configuration digest: {}", report.config_hash);
                        println!("Next: {}", report.next_action);
                    }
                }
            }
        },
        TrustCommand::ApprovedSet { command } => match command {
            ApprovedSetCommand::Assemble {
                environment,
                preceding_set,
                relay_public,
                relay_consultation,
                notary,
                output_file,
                format,
            } => {
                let project = discover_project(project_dir)?;
                let environment = resolve_environment(&project, environment)?;
                let report = registryctl::assemble_approved_set(&ApprovedSetAssembleOptions {
                    project_directory: project,
                    environment,
                    preceding_set,
                    relay_public,
                    relay_consultation,
                    notary,
                    output_file,
                })
                .map_err(CliFailure::domain)?;
                match format {
                    OutputFormat::Human => {
                        println!(
                            "Assembled approved baseline set at {}.",
                            report.output_file.display()
                        );
                        println!("Approved-set digest: {}", report.approved_set_digest);
                        println!("Affected lanes: {}.", render_lanes(&report.affected_lanes));
                        println!(
                            "Next: registryctl deploy generate --approved-set {} --output-dir <directory>",
                            report.output_file.display()
                        );
                    }
                    OutputFormat::Json => {
                        #[derive(Serialize)]
                        struct ApprovedSetCliReport<'a> {
                            schema_version: &'static str,
                            approved_set_digest: &'a str,
                            affected_lanes: &'a [ApprovedLaneV1],
                            output_file: &'a Path,
                            next_action: &'static str,
                        }
                        print_json(&ApprovedSetCliReport {
                            schema_version: "registryctl.approved_set_assembly.v1",
                            approved_set_digest: &report.approved_set_digest,
                            affected_lanes: &report.affected_lanes,
                            output_file: &report.output_file,
                            next_action: "registryctl deploy generate --approved-set <file> --output-dir <directory>",
                        })?;
                    }
                }
            }
        },
    }
    Ok(ExitCode::SUCCESS)
}

fn run_tooling(project_dir: Option<&Path>, command: ToolingCommand) -> CliResult {
    match command {
        ToolingCommand::Schema { kind } => print!("{}", kind.document()),
        ToolingCommand::Reference { command } => match command {
            ReferenceCommand::Configuration { coverage } => {
                if coverage {
                    let report = registryctl::embedded_configuration_reference_coverage()
                        .map_err(|error| CliFailure::domain(anyhow!("{error}")))?;
                    let complete = report.status == registryctl::CoverageStatus::Complete;
                    print_json(&report)?;
                    if !complete {
                        return Ok(ExitCode::from(EXIT_DOMAIN));
                    }
                } else {
                    let reference = registryctl::embedded_configuration_reference()
                        .map_err(|error| CliFailure::domain(anyhow!("{error}")))?;
                    print_json(&reference)?;
                }
            }
            ReferenceCommand::Xw { format } => match format {
                XwFormat::Reference => print!(
                    "{}",
                    registry_relay::rhai_worker::xw::generated_function_reference()
                ),
                XwFormat::Editor => print!(
                    "{}",
                    registry_relay::rhai_worker::xw::generated_editor_metadata()
                ),
            },
        },
        ToolingCommand::Editor { format } => {
            let project = discover_project(project_dir)?;
            let report = registryctl::setup_registry_project_editor(&ProjectEditorSetupOptions {
                project_directory: project,
            })
            .map_err(CliFailure::domain)?;
            match format {
                OutputFormat::Json => print_json(&report)?,
                OutputFormat::Human => {
                    println!(
                        "Editor schema mappings are {} for {}.",
                        report.status, report.project_directory
                    );
                    println!("Managed files: {}.", report.files.len());
                }
            }
        }
        ToolingCommand::LanguageServer => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| CliFailure::operational(anyhow!(error)))?
                .block_on(registry_language_server::run_stdio());
        }
        ToolingCommand::Diagnostics { catalog, format } => match catalog {
            DiagnosticCatalog::Authoring => {
                let reference = registryctl::authoring_error_reference();
                registryctl::validate_authoring_error_reference(&reference)
                    .map_err(|error| CliFailure::domain(anyhow!("{error:?}")))?;
                print_catalog(format, "authoring", &reference)?;
            }
            DiagnosticCatalog::Fixture => {
                let reference = registryctl::fixture_error_reference();
                registryctl::validate_fixture_error_reference(&reference)
                    .map_err(|error| CliFailure::domain(anyhow!("{error:?}")))?;
                print_catalog(format, "fixture", &reference)?;
            }
            DiagnosticCatalog::Operator => {
                let reference = registryctl::operator_error_reference();
                registryctl::validate_operator_error_reference(&reference)
                    .map_err(|error| CliFailure::domain(anyhow!("{error:?}")))?;
                print_catalog(format, "operator", &reference)?;
            }
        },
    }
    Ok(ExitCode::SUCCESS)
}

fn discover_project(explicit: Option<&Path>) -> CliResult<PathBuf> {
    if let Some(explicit) = explicit {
        let metadata = fs::symlink_metadata(explicit).map_err(|error| {
            CliFailure::operational(anyhow!(
                "cannot inspect project directory {}: {error}",
                explicit.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CliFailure::domain(anyhow!(
                "project directory must be a non-symlink directory: {}",
                explicit.display()
            )));
        }
        if !explicit.join(PROJECT_FILE).is_file() {
            return Err(CliFailure::domain(anyhow!(
                "{} does not contain {PROJECT_FILE}",
                explicit.display()
            )));
        }
        return Ok(explicit.to_path_buf());
    }

    let current = std::env::current_dir().map_err(|error| {
        CliFailure::operational(anyhow!("cannot inspect the current directory: {error}"))
    })?;
    for candidate in current.ancestors() {
        if candidate.join(PROJECT_FILE).is_file() {
            return Ok(candidate.to_path_buf());
        }
    }
    Err(CliFailure::domain(anyhow!(
        "no Registry Stack project was found; run registryctl init or select one with -C"
    )))
}

fn resolve_environment(project: &Path, explicit: Option<String>) -> CliResult<String> {
    if let Some(environment) = explicit {
        return validate_environment_id(environment);
    }
    if let Some(environment) = std::env::var_os("REGISTRYCTL_ENVIRONMENT") {
        let environment = environment.into_string().map_err(|_| {
            CliFailure::usage(anyhow!("REGISTRYCTL_ENVIRONMENT must contain Unicode"))
        })?;
        return validate_environment_id(environment);
    }

    let project_bytes = fs::read(project.join(PROJECT_FILE))
        .map_err(|error| CliFailure::operational(anyhow!("cannot read {PROJECT_FILE}: {error}")))?;
    let project_document: serde_json::Value =
        serde_norway::from_slice(&project_bytes).map_err(|error| {
            CliFailure::domain(anyhow!("{PROJECT_FILE} is not valid YAML: {error}"))
        })?;
    if let Some(default) = project_document
        .get("default_environment")
        .and_then(serde_json::Value::as_str)
    {
        return validate_environment_id(default.to_string());
    }

    let directory = project.join("environments");
    let entries = fs::read_dir(&directory).map_err(|error| {
        CliFailure::operational(anyhow!(
            "cannot inspect declared environments in {}: {error}",
            directory.display()
        ))
    })?;
    let mut environments = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliFailure::operational(anyhow!("cannot inspect a declared environment: {error}"))
        })?;
        let metadata = entry.metadata().map_err(|error| {
            CliFailure::operational(anyhow!("cannot inspect a declared environment: {error}"))
        })?;
        if metadata.is_file() && entry.path().extension() == Some(OsStr::new("yaml")) {
            if let Some(id) = entry.path().file_stem().and_then(OsStr::to_str) {
                environments.push(id.to_string());
            }
        }
    }
    environments.sort();
    environments.dedup();
    match environments.as_slice() {
        [only] => Ok(only.clone()),
        [] => Err(CliFailure::domain(anyhow!(
            "the project declares no environments"
        ))),
        _ => Err(CliFailure::domain(anyhow!(
            "select an environment with --environment; declared environment ids: {}",
            environments.join(", ")
        ))),
    }
}

fn validate_environment_id(environment: String) -> CliResult<String> {
    let valid = !environment.is_empty()
        && environment.len() <= 64
        && environment
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && environment
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase());
    if valid {
        Ok(environment)
    } else {
        Err(CliFailure::usage(anyhow!(
            "environment id must begin with a lowercase letter and contain only lowercase letters, digits, and hyphens"
        )))
    }
}

fn watch_project_tests(
    options: ProjectTestOptions,
    selection: ProjectTestSelection,
) -> CliResult<()> {
    let context =
        ProjectExecutionContext::for_current_executable().map_err(CliFailure::operational)?;
    loop {
        let report = registryctl::test_registry_project_selected_with_context(
            &options, &selection, &context,
        )
        .map_err(CliFailure::domain)?;
        println!(
            "Registry Stack test: {} ({} fixtures).",
            report.status,
            report.fixtures.len()
        );
        let observed = project_watch_fingerprint(&options.project_directory)
            .map_err(CliFailure::operational)?;
        loop {
            std::thread::sleep(Duration::from_millis(250));
            if project_watch_fingerprint(&options.project_directory)
                .map_err(CliFailure::operational)?
                != observed
            {
                break;
            }
        }
    }
}

fn project_watch_fingerprint(root: &Path) -> Result<Vec<(PathBuf, u64, Option<SystemTime>)>> {
    fn visit(
        root: &Path,
        directory: &Path,
        values: &mut Vec<(PathBuf, u64, Option<SystemTime>)>,
    ) -> Result<()> {
        for entry in fs::read_dir(directory)
            .with_context(|| format!("failed to watch project directory {}", directory.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap_or(&path);
            if relative
                .components()
                .next()
                .is_some_and(|component| component.as_os_str() == ".registry-stack")
            {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                visit(root, &path, values)?;
            } else if metadata.is_file() {
                values.push((
                    relative.to_path_buf(),
                    metadata.len(),
                    metadata.modified().ok(),
                ));
            }
        }
        Ok(())
    }

    let mut values = Vec::new();
    visit(root, root, &mut values)?;
    values.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(values)
}

fn print_project_report(
    format: OutputFormat,
    operation: &str,
    report: &registryctl::ProjectCommandReport,
    show_explanation: bool,
) -> CliResult<()> {
    match format {
        OutputFormat::Json => print_json(report),
        OutputFormat::Human => {
            println!(
                "Registry Stack {operation}: {} for {}.",
                report.status, report.project
            );
            println!("Fixtures: {}.", report.fixtures.len());
            if show_explanation {
                let explanation = report.explanation.as_ref().ok_or_else(|| {
                    CliFailure::operational(anyhow!(
                        "check explanation was requested but not generated"
                    ))
                })?;
                print_project_explanation(explanation)?;
            }
            match operation {
                "test" => println!("Next: registryctl dev"),
                "check" => println!("Next: registryctl build"),
                _ => {}
            }
            Ok(())
        }
    }
}

fn print_project_explanation(
    explanation: &registryctl::ProjectExplanationReportV1,
) -> CliResult<()> {
    println!(
        "Explanation: registry.project.explanation.v1 for {} in {} ({} classifier-safe fields).",
        explanation.project,
        explanation.environment,
        explanation.fields.len()
    );
    for field in &explanation.fields {
        let address = match &field.address {
            registryctl::ProjectFieldAddress::Project { path } => {
                format!("project {path}")
            }
            registryctl::ProjectFieldAddress::Integration { integration, path } => {
                format!("integration {integration} {path}")
            }
            registryctl::ProjectFieldAddress::Entity { entity, path } => {
                format!("entity {entity} {path}")
            }
            registryctl::ProjectFieldAddress::Environment { environment, path } => {
                format!("environment {environment} {path}")
            }
            registryctl::ProjectFieldAddress::Fixture {
                integration,
                fixture,
                path,
            } => format!("fixture {integration}.{fixture} {path}"),
        };
        let reported = match &field.reported_value {
            registryctl::ClassifierSafeReportedValue::Public { value } => {
                serde_json::to_string(value.as_value()).map_err(|error| {
                    CliFailure::operational(anyhow!(
                        "cannot render classifier-safe project value: {error}"
                    ))
                })?
            }
            registryctl::ClassifierSafeReportedValue::Redacted { classification, .. } => {
                format!("<redacted:{}>", serialized_enum_name(classification)?)
            }
            registryctl::ClassifierSafeReportedValue::Absent => "<absent>".to_string(),
        };
        println!(
            "  {address} = {reported} [{}, {}]",
            serialized_enum_name(&field.state.presence)?,
            serialized_enum_name(&field.state.effect)?
        );
    }
    println!("Full provenance and constraint metadata: rerun with --format json.");
    Ok(())
}

fn serialized_enum_name(value: &impl Serialize) -> CliResult<String> {
    serde_json::to_value(value)
        .map_err(|error| {
            CliFailure::operational(anyhow!(
                "cannot render classifier-safe project metadata: {error}"
            ))
        })?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| {
            CliFailure::operational(anyhow!("classifier-safe project metadata is not a string"))
        })
}

fn print_serialized_or_debug<T: Serialize + std::fmt::Debug>(
    format: OutputFormat,
    label: &str,
    value: &T,
) -> CliResult<()> {
    match format {
        OutputFormat::Json => print_json(value),
        OutputFormat::Human => {
            println!("{label}: {value:#?}");
            Ok(())
        }
    }
}

fn print_catalog<T: Serialize>(format: OutputFormat, label: &str, value: &T) -> CliResult<()> {
    match format {
        OutputFormat::Json => print_json(value),
        OutputFormat::Human => {
            let document = serde_json::to_value(value).map_err(|error| {
                CliFailure::operational(anyhow!("cannot render {label} diagnostics: {error}"))
            })?;
            let count = document
                .get("entries")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            println!("Registryctl {label} diagnostic catalog: {count} entries.");
            Ok(())
        }
    }
}

fn print_json<T: Serialize>(value: &T) -> CliResult<()> {
    let json = serde_json::to_string_pretty(value).map_err(|error| {
        CliFailure::operational(anyhow!("cannot render machine-readable output: {error}"))
    })?;
    println!("{json}");
    Ok(())
}

fn print_subcommand_help(name: &str) -> CliResult<()> {
    let mut command = Cli::command();
    let subcommand = command
        .find_subcommand_mut(name)
        .ok_or_else(|| CliFailure::operational(anyhow!("missing {name} help contract")))?;
    subcommand
        .write_long_help(&mut std::io::stdout())
        .map_err(|error| CliFailure::operational(anyhow!("cannot print {name} help: {error}")))?;
    std::io::stdout()
        .write_all(b"\n")
        .map_err(|error| CliFailure::operational(anyhow!("cannot finish {name} help: {error}")))
}

fn render_lanes(lanes: &[ApprovedLaneV1]) -> String {
    if lanes.is_empty() {
        "none".to_string()
    } else {
        lanes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn render_acceptance_lane(lane: registry_platform_config::ProductAcceptanceLaneV1) -> &'static str {
    match lane {
        registry_platform_config::ProductAcceptanceLaneV1::RelayPublic => "relay-public",
        registry_platform_config::ProductAcceptanceLaneV1::RelayConsultation => {
            "relay-consultation"
        }
        registry_platform_config::ProductAcceptanceLaneV1::Notary => "notary",
    }
}

fn is_exact_internal_mode(expected: &str) -> bool {
    let mut args = std::env::args_os();
    let _program = args.next();
    args.next().as_deref() == Some(OsStr::new(expected)) && args.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_smoke_human_output_reports_safe_observed_and_unobserved_evidence() {
        let report = registryctl::DevSmokeReportV1 {
            schema_version: registryctl::DEV_SMOKE_REPORT_SCHEMA_V1.to_string(),
            project: "example".to_string(),
            environment: "local".to_string(),
            results: vec![
                registryctl::DevSmokeScenarioResult {
                    scenario_id: "denied".to_string(),
                    status: registryctl::DevSmokeStatus::Denied,
                    token_counter_delta: Some(0),
                    source_counter_delta: Some(0),
                    minimized_claim_ids: Vec::new(),
                    passed: true,
                },
                registryctl::DevSmokeScenarioResult {
                    scenario_id: "authorized".to_string(),
                    status: registryctl::DevSmokeStatus::Authorized,
                    token_counter_delta: None,
                    source_counter_delta: None,
                    minimized_claim_ids: vec!["claim-a".to_string(), "claim-b".to_string()],
                    passed: true,
                },
            ],
            passed: true,
        };

        assert_eq!(
            dev_smoke_human_lines(&report).expect("smoke report renders"),
            [
                "Development smoke: passed.",
                "  denied: status=denied; passed=true; token_counter_delta=0; source_counter_delta=0; minimized_claim_ids=none",
                "  authorized: status=authorized; passed=true; token_counter_delta=unobserved; source_counter_delta=unobserved; minimized_claim_ids=claim-a,claim-b",
            ]
        );
    }

    #[test]
    fn development_success_endpoints_are_scheme_bearing_https_urls() {
        assert_eq!(
            dev_endpoint_line("https://127.0.0.1:4255").expect("HTTPS endpoint renders"),
            "Endpoint: https://127.0.0.1:4255"
        );
        let error =
            dev_endpoint_line("http://127.0.0.1:4255").expect_err("HTTP endpoint must fail closed");
        assert_eq!(error.status, EXIT_OPERATIONAL);
        assert!(error.error.to_string().contains("non-HTTPS"));
    }
}
