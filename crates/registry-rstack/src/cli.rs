// SPDX-License-Identifier: Apache-2.0

use crate::identity::{self, DrivenTool, Failure, GenerateOptions, Input, ProductSpec};
use crate::install::{self, BootstrapOptions};
use crate::store::{GenerationStore, InvocationLease};
use crate::ReleaseManifest;
use clap::{
    value_parser, Arg, ArgAction, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum,
};
use registry_platform_config::{
    declared, DeclaredPosture, Posture, PostureSource, DEVELOPMENT, POSTURE_ENV,
};
use registry_platform_yaml::{Diagnostic, Report};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

const PRODUCTS: [&str; 10] = [
    "breg",
    "casework",
    "discovery",
    "evidence",
    "manifest",
    "messaging",
    "render",
    "scheduling",
    "coordinator",
    "adapter",
];

macro_rules! reportln {
    ($($argument:tt)*) => {
        write_stdout(format_args!($($argument)*))?
    };
}

fn write_stdout(arguments: std::fmt::Arguments<'_>) -> Result<(), CliFailure> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_fmt(arguments)
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .map_err(|error| CliFailure::operational(format!("cannot write report: {error}")))
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReportFormat {
    Human,
    Json,
}

#[derive(Clone, Copy)]
enum RequestedReportFormat {
    Human,
    Json,
    Junit,
    Invalid,
}

#[derive(Parser)]
#[command(
    name = "rstack",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    disable_help_subcommand = true,
    about = "Registry Stack command and component manager"
)]
struct Cli {
    /// Report encoding. Defaults to human even when stdout is piped. Evidence
    /// test and fixtures run also accept junit.
    #[arg(long, global = true, value_enum, action = ArgAction::Append, default_value = "human")]
    format: Vec<ReportFormat>,

    /// Installation generation storage directory.
    #[arg(long, global = true)]
    install_root: Option<PathBuf>,

    /// Directory for the single public rstack executable link.
    #[arg(long, global = true)]
    bin_dir: Option<PathBuf>,

    /// Directory of already downloaded, verified release assets.
    #[arg(long, global = true)]
    asset_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Activate a release-pinned launcher and optional components.
    #[command(hide = true)]
    Bootstrap {
        #[arg(long)]
        release_manifest: PathBuf,
        #[arg(long)]
        checksum_file: PathBuf,
        #[arg(long)]
        launcher_asset: PathBuf,
        #[arg(long)]
        all: bool,
        #[arg(value_name = "COMPONENT")]
        components: Vec<String>,
    },
    /// List the selected release and component availability.
    Components {
        #[command(subcommand)]
        command: ComponentCommand,
    },
    /// Install one or more components at the selected release.
    Install {
        /// Install every product available for the selected platform.
        #[arg(long)]
        all: bool,
        /// Product to install.
        #[arg(value_name = "COMPONENT")]
        components: Vec<String>,
    },
    /// Update the launcher and installed components to one exact release.
    Update {
        /// Exact release tag to activate.
        #[arg(long)]
        release: String,
        /// Check the target release and report changes without activation.
        #[arg(long)]
        preview: bool,
    },
    /// Remove one or more installed components.
    Uninstall {
        /// Remove the complete managed installation.
        #[arg(long)]
        all: bool,
        /// Product to remove.
        #[arg(value_name = "COMPONENT")]
        components: Vec<String>,
    },
    /// Remove inactive, unused installation generations.
    Cleanup,
    /// Check selected binaries, paths, and component availability.
    Doctor,
    /// Show offline product help.
    Help {
        /// Product whose offline command reference to show.
        #[arg(value_name = "PRODUCT")]
        product: Option<String>,
    },
    /// Generate shell completion script.
    Completions {
        /// Shell whose completion script to generate.
        #[arg(value_name = "SHELL")]
        shell: String,
    },
    /// Generate and check hosted identity configuration.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Run and inspect a local Registry Stack development environment.
    #[command(
        long_about = "Run and inspect a local Registry Stack development environment.\n\nFor a walk-through from a project checkout to a running registry and review service, see `https://docs.registrystack.org/configure/run-a-project-with-rstack-dev/`"
    )]
    Dev {
        #[command(subcommand)]
        command: DevCommand,
    },
    /// Generate application clients from registry projects.
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
    #[command(external_subcommand)]
    Product(Vec<OsString>),
}

#[derive(Subcommand)]
enum ClientCommand {
    /// Run the registry-generate bin installed in the application project.
    #[command(
        after_help = "When an installed release is selected, rstack sets RSTACK_BREGCTL_BIN to that release's bregctl."
    )]
    Generate(ClientGenerate),
}

#[derive(clap::Args)]
struct ClientGenerate {
    /// Register member and project path, as member=path. Repeat for each register.
    #[arg(long, required = true)]
    register: Vec<OsString>,
    /// Comma-separated product names.
    #[arg(long)]
    products: Option<OsString>,
    /// Proposal author profile, as member=profile. Repeat to add profiles.
    #[arg(long)]
    author_profile: Vec<OsString>,
    /// Register route prefix, as member=/prefix. Repeat for each register.
    #[arg(long)]
    route_prefix: Vec<OsString>,
    /// TypeScript service file to generate.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Subcommand)]
enum DevCommand {
    /// Validate a development plan without starting services.
    #[command(after_help = "Example:\n  rstack dev check ./my-registry-project")]
    Check {
        /// Project directory containing dev.yaml.
        #[arg(value_name = "PROJECT")]
        project: PathBuf,
        /// Refuse an unaccepted warning.
        #[arg(long)]
        deny_warnings: bool,
    },
    /// Start a development environment for a registry project.
    #[command(after_help = "Example:\n  rstack dev start ./my-registry-project --ttl 1h")]
    Start {
        /// Project directory containing dev.yaml.
        #[arg(value_name = "PROJECT")]
        project: PathBuf,
        /// Root of an already-built local application when dev.yaml declares one.
        #[arg(long, value_name = "DIRECTORY")]
        application_root: Option<PathBuf>,
        /// TLS PostgreSQL administrator URL. Defaults to RSTACK_DEV_DATABASE_URL;
        /// without either, the run starts its own PostgreSQL server in Docker.
        #[arg(long, value_name = "URL")]
        database_url: Option<String>,
        /// Lifetime after readiness, from 1s to 24h. Defaults to 8h.
        #[arg(long, value_name = "DURATION")]
        ttl: Option<String>,
    },
    /// Report the state of a development environment.
    #[command(after_help = "Example:\n  rstack dev status 0123456789abcdef0123456789abcdef")]
    Status {
        /// Run ID returned by rstack dev start.
        #[arg(value_name = "RUN_ID")]
        run_id: String,
    },
    /// Issue a development token for one named synthetic person.
    #[command(
        after_help = "Example:\n  rstack dev token 0123456789abcdef0123456789abcdef --as operator"
    )]
    Token {
        /// Run ID returned by rstack dev start.
        #[arg(value_name = "RUN_ID")]
        run_id: String,
        /// Synthetic person configured by the project.
        #[arg(long = "as", value_name = "NAME")]
        person: String,
    },
    /// Stop a development environment.
    #[command(after_help = "Example:\n  rstack dev stop 0123456789abcdef0123456789abcdef")]
    Stop {
        /// Run ID returned by rstack dev start.
        #[arg(value_name = "RUN_ID")]
        run_id: String,
        /// Release the processes, databases and roles of a run whose supervisor
        /// was lost.
        #[arg(long)]
        recover: bool,
        /// TLS PostgreSQL administrator URL for --recover. Defaults to
        /// RSTACK_DEV_DATABASE_URL; a run that started its own server needs none.
        #[arg(long, value_name = "URL", requires = "recover")]
        database_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Generate identity-provider configuration from product identity facts.
    Generate {
        #[command(subcommand)]
        target: IdentityTarget,
    },
    /// Check an identity facts document or deployment file offline.
    Check {
        /// Identity facts document or identity deployment file.
        file: PathBuf,
        /// Product facts file to check a deployment against; repeat per product.
        #[arg(long = "facts", value_name = "FILE")]
        facts: Vec<PathBuf>,
        /// Exit 1 when any unaccepted warning is reported.
        #[arg(long)]
        deny_warnings: bool,
    },
}

#[derive(Subcommand)]
enum IdentityTarget {
    /// Generate ThunderID configuration into a new directory.
    ///
    /// Runs each selected product's own `generate identity-facts` command and
    /// merges the facts with the deployment file. Select every product that
    /// admits tokens from the issuer with its flags; the deployment file never
    /// states the issuer.
    Thunderid(ThunderidArguments),
}

#[derive(clap::Args)]
struct ThunderidArguments {
    /// Operator identity deployment file.
    #[arg(long, value_name = "FILE")]
    deployment: PathBuf,
    /// New directory to write; an existing path is refused.
    #[arg(long, value_name = "DIR")]
    output: PathBuf,
    /// Base Registry Engine project directory.
    #[arg(long, value_name = "DIR", requires = "breg_runtime_config")]
    breg_project: Option<PathBuf>,
    /// Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "FILE", requires = "breg_project")]
    breg_runtime_config: Option<PathBuf>,
    /// Check the Base Registry Engine runtime as a production runtime.
    #[arg(long, requires = "breg_runtime_config")]
    breg_production: bool,
    /// Casework project directory.
    #[arg(long, value_name = "DIR", requires = "casework_runtime_config")]
    casework_project: Option<PathBuf>,
    /// Casework runtime configuration file.
    #[arg(long, value_name = "FILE", requires = "casework_project")]
    casework_runtime_config: Option<PathBuf>,
    /// Evidence project directory.
    #[arg(long, value_name = "DIR", requires = "evidence_target")]
    evidence_project: Option<PathBuf>,
    /// Evidence target file.
    #[arg(long, value_name = "FILE", requires = "evidence_project")]
    evidence_target: Option<PathBuf>,
    /// Messaging runtime configuration file.
    #[arg(long, value_name = "FILE")]
    messaging_runtime_config: Option<PathBuf>,
}

impl ThunderidArguments {
    fn inputs(&self) -> Vec<Input> {
        let by_name = |name: &str| {
            identity::PRODUCTS
                .iter()
                .find(|product| product.name == name)
                .expect("a driven product is listed")
        };
        let mut inputs = Vec::new();
        let mut push =
            |name: &str, project: &Option<PathBuf>, config: &Option<PathBuf>, production| {
                if let Some(config) = config {
                    inputs.push(Input {
                        product: by_name(name),
                        project: project.clone(),
                        config: config.clone(),
                        production,
                    });
                }
            };
        push(
            "breg",
            &self.breg_project,
            &self.breg_runtime_config,
            self.breg_production,
        );
        push(
            "casework",
            &self.casework_project,
            &self.casework_runtime_config,
            false,
        );
        push(
            "evidence",
            &self.evidence_project,
            &self.evidence_target,
            false,
        );
        push("messaging", &None, &self.messaging_runtime_config, false);
        inputs
    }
}

impl From<Failure> for CliFailure {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Domain(message) => CliFailure::domain(message),
            Failure::Operational(message) => CliFailure::operational(message),
        }
    }
}

#[derive(Subcommand)]
enum ComponentCommand {
    /// List every known product and its selected-release status.
    List,
}

/// The installer's global path flags mean nothing to a development run, so
/// `dev` and its subcommands carry hidden copies that keep them out of their
/// help while still accepting them.
pub fn command() -> clap::Command {
    Cli::command().mut_subcommand("dev", |dev| {
        [
            ("install_root", "install-root"),
            ("bin_dir", "bin-dir"),
            ("asset_dir", "asset-dir"),
        ]
        .into_iter()
        .fold(dev, |dev, (id, flag)| {
            dev.arg(
                Arg::new(id)
                    .long(flag)
                    .global(true)
                    .hide(true)
                    .value_parser(value_parser!(PathBuf)),
            )
        })
    })
}

fn parse(arguments: Vec<OsString>) -> Result<Cli, clap::Error> {
    Cli::from_arg_matches(&command().try_get_matches_from(arguments)?)
}

pub fn run() -> i32 {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    let (duplicate_format, json_requested, format_supplied, requested_format) =
        report_arguments(&arguments);
    if duplicate_format {
        return emit_failure(2, "--format may be supplied only once", json_requested);
    }
    let evidence_junit = match requested_format {
        Some(RequestedReportFormat::Junit) if evidence_supports_junit(&arguments) => true,
        Some(RequestedReportFormat::Junit) => {
            return emit_failure(
                2,
                "--format junit is supported only by evidence test and evidence fixtures run",
                json_requested,
            );
        }
        Some(RequestedReportFormat::Invalid) => {
            return emit_failure(2, "--format must be human or json", json_requested);
        }
        _ => false,
    };
    let arguments = if evidence_junit {
        remove_report_format(arguments)
    } else {
        arguments
    };
    let cli = match parse(arguments) {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            if code != 0 && json_requested {
                return emit_failure(code, &error.to_string(), true);
            }
            let _ = error.print();
            return code;
        }
    };
    if let Err(error) = execute(cli, format_supplied, evidence_junit) {
        if error.reported {
            return error.code;
        }
        return emit_failure(error.code, &error.message, json_requested);
    }
    0
}

fn report_arguments(arguments: &[OsString]) -> (bool, bool, bool, Option<RequestedReportFormat>) {
    let mut occurrences = 0;
    let mut json = false;
    let mut requested = None;
    let mut values = arguments.iter().skip(1);
    while let Some(argument) = values.next() {
        if argument == "--" {
            break;
        }
        if argument == "--format" {
            occurrences += 1;
            if let Some(value) = values.next() {
                requested = Some(requested_report_format(value));
                json |= matches!(requested, Some(RequestedReportFormat::Json));
            }
        } else if let Some(value) = argument
            .to_str()
            .and_then(|text| text.strip_prefix("--format="))
        {
            occurrences += 1;
            requested = Some(requested_report_format(&OsString::from(value)));
            json |= matches!(requested, Some(RequestedReportFormat::Json));
        }
    }
    (occurrences > 1, json, occurrences > 0, requested)
}

fn requested_report_format(value: &OsString) -> RequestedReportFormat {
    match value.to_str() {
        Some("human") => RequestedReportFormat::Human,
        Some("json") => RequestedReportFormat::Json,
        Some("junit") => RequestedReportFormat::Junit,
        _ => RequestedReportFormat::Invalid,
    }
}

fn evidence_supports_junit(arguments: &[OsString]) -> bool {
    let command = command_tokens(arguments);
    matches!(
        command.as_slice(),
        ["evidence", "test", ..] | ["evidence", "fixtures", "run", ..]
    )
}

fn command_tokens(arguments: &[OsString]) -> Vec<&str> {
    let mut command = Vec::new();
    let mut index = 1;
    while index < arguments.len() {
        let Some(argument) = arguments[index].to_str() else {
            return Vec::new();
        };
        if argument == "--" {
            break;
        }
        if matches!(
            argument,
            "--format" | "--install-root" | "--bin-dir" | "--asset-dir"
        ) {
            index += 2;
            continue;
        }
        if argument.starts_with("--format=")
            || argument.starts_with("--install-root=")
            || argument.starts_with("--bin-dir=")
            || argument.starts_with("--asset-dir=")
        {
            index += 1;
            continue;
        }
        if !argument.starts_with('-') {
            command.push(argument);
        }
        index += 1;
    }
    command
}

fn remove_report_format(mut arguments: Vec<OsString>) -> Vec<OsString> {
    let mut index = 1;
    while index < arguments.len() {
        if arguments[index] == "--" {
            break;
        }
        if arguments[index] == "--format" {
            let end = usize::min(index + 2, arguments.len());
            arguments.drain(index..end);
            break;
        }
        if arguments[index]
            .to_str()
            .is_some_and(|argument| argument.starts_with("--format="))
        {
            arguments.remove(index);
            break;
        }
        index += 1;
    }
    arguments
}

fn emit_failure(code: i32, message: &str, json: bool) -> i32 {
    if json {
        let category = match code {
            1 => "domain",
            2 => "usage",
            _ => "operational",
        };
        let report = json!({
            "schema_version":"registry.rstack.error.v1",
            "status":"refused",
            "error":{"class":category,"message":message}
        });
        if write_stdout(format_args!("{report}")).is_err() {
            let _ = writeln!(io::stderr().lock(), "rstack: cannot write JSON report");
            return 3;
        }
    } else {
        let _ = writeln!(io::stderr().lock(), "rstack: {message}");
    }
    code
}

struct CliFailure {
    code: i32,
    message: String,
    reported: bool,
}

impl CliFailure {
    fn domain(message: String) -> Self {
        Self {
            code: 1,
            message,
            reported: false,
        }
    }

    fn operational(message: String) -> Self {
        Self {
            code: 3,
            message,
            reported: false,
        }
    }

    fn reported(code: i32) -> Self {
        Self {
            code,
            message: String::new(),
            reported: true,
        }
    }
}

impl From<String> for CliFailure {
    fn from(message: String) -> Self {
        Self {
            code: 2,
            message,
            reported: false,
        }
    }
}

impl From<&str> for CliFailure {
    fn from(message: &str) -> Self {
        Self::from(message.to_owned())
    }
}

fn execute(cli: Cli, format_supplied: bool, evidence_junit: bool) -> Result<(), CliFailure> {
    if cli.format.len() > 1 {
        return Err("--format may be supplied only once".into());
    }
    let format = cli.format.first().copied().unwrap_or(ReportFormat::Human);
    match &cli.command {
        Some(Command::Bootstrap {
            release_manifest,
            checksum_file,
            launcher_asset,
            all,
            components,
        }) => {
            let report = install::bootstrap(BootstrapOptions {
                release_manifest: release_manifest.clone(),
                checksum_file: checksum_file.clone(),
                launcher_asset: launcher_asset.clone(),
                asset_dir: cli.asset_dir.clone(),
                install_root: match &cli.install_root {
                    Some(path) => path.clone(),
                    None => default_install_root()?,
                },
                bin_dir: match &cli.bin_dir {
                    Some(path) => path.clone(),
                    None => default_bin_dir()?,
                },
                components: components.clone(),
                all: *all,
            })
            .map_err(CliFailure::operational)?;
            match format {
                ReportFormat::Human => reportln!(
                    "Activated {} with {} component(s) in {}",
                    report.release,
                    report.components.len(),
                    report.generation
                ),
                ReportFormat::Json => reportln!(
                    "{}",
                    serde_json::to_string(&report)
                        .map_err(|error| CliFailure::operational(error.to_string()))?
                ),
            }
        }
        None | Some(Command::Help { product: None }) => match format {
            ReportFormat::Human => {
                reportln!("rstack <product> <action> [options]");
                reportln!("Use rstack help <product> for offline product help.");
                reportln!("Use rstack dev --help for local development commands.");
                reportln!("Use rstack client generate --help to generate an application client.");
                reportln!("Use rstack components list to inspect installation availability.");
                reportln!("Products: {}", PRODUCTS.join(", "));
            }
            ReportFormat::Json => reportln!(
                "{}",
                json!({"schema_version":"registry.rstack.help.v1","command":{"name":"rstack","invocation":"rstack","products":PRODUCTS}})
            ),
        },
        Some(Command::Help {
            product: Some(product),
        }) => {
            if product == "dev" {
                dev_help(format)?;
            } else {
                known_product(product)?;
                product_help(product, format, &[])?;
            }
        }
        Some(Command::Components {
            command: ComponentCommand::List,
        }) => list_components(&cli, format)?,
        Some(Command::Install { all, components }) => {
            if (*all && !components.is_empty()) || (!*all && components.is_empty()) {
                return Err("select component names or --all, but not both".into());
            }
            for component in components {
                known_product(component)?;
            }
            let report = install::install(manager_options(&cli)?, components.clone(), *all)
                .map_err(manager_failure)?;
            match format {
                ReportFormat::Human => reportln!(
                    "Activated {} with components: {}",
                    report.release,
                    report.components.join(", ")
                ),
                ReportFormat::Json => reportln!(
                    "{}",
                    serde_json::to_string(&report)
                        .map_err(|error| CliFailure::operational(error.to_string()))?
                ),
            }
        }
        Some(Command::Uninstall { all, components }) => {
            if (*all && !components.is_empty()) || (!*all && components.is_empty()) {
                return Err("select component names or --all, but not both".into());
            }
            for component in components {
                known_product(component)?;
            }
            if *all {
                let report =
                    install::uninstall_all(manager_options(&cli)?).map_err(manager_failure)?;
                match format {
                    ReportFormat::Human => reportln!("Removed Registry Stack installation"),
                    ReportFormat::Json => reportln!(
                        "{}",
                        serde_json::to_string(&report)
                            .map_err(|error| CliFailure::operational(error.to_string()))?
                    ),
                }
            } else {
                let report = install::uninstall(manager_options(&cli)?, components.clone())
                    .map_err(manager_failure)?;
                match format {
                    ReportFormat::Human => reportln!(
                        "Activated {} without: {}",
                        report.release,
                        report.removed.join(", ")
                    ),
                    ReportFormat::Json => reportln!(
                        "{}",
                        serde_json::to_string(&report)
                            .map_err(|error| CliFailure::operational(error.to_string()))?
                    ),
                }
            }
        }
        Some(Command::Cleanup) => {
            let (install_root, bin_dir) = installation_paths(&cli)?;
            let store = GenerationStore::new(install_root, bin_dir);
            if !store.has_installation().map_err(CliFailure::operational)? {
                return Err(CliFailure::domain(
                    "no Registry Stack installation is selected".into(),
                ));
            }
            let mutation = store.lock_mutation().map_err(CliFailure::operational)?;
            let report = mutation.cleanup().map_err(CliFailure::operational)?;
            match format {
                ReportFormat::Human => reportln!(
                    "Removed {} inactive generation(s); preserved {}",
                    report.removed.len(),
                    report.preserved.len()
                ),
                ReportFormat::Json => reportln!(
                    "{}",
                    json!({
                        "schema_version":"registry.rstack.cleanup.v1",
                        "removed":report.removed,
                        "preserved":report.preserved.iter().map(|item| json!({"generation":item.name,"reason":format!("{:?}",item.reason).to_ascii_lowercase()})).collect::<Vec<_>>()
                    })
                ),
            }
        }
        Some(Command::Doctor) => doctor(&cli, format)?,
        Some(Command::Update { release, preview }) => {
            let report = install::update(&manager_options(&cli)?, release, *preview)
                .map_err(manager_failure)?;
            match format {
                ReportFormat::Human => reportln!(
                    "{} {} to {} with {} component(s), {} bytes to download{}",
                    if report.preview {
                        "Preview update from"
                    } else if report.activated {
                        "Updated from"
                    } else {
                        "Already at"
                    },
                    report.current_release,
                    report.target_release,
                    report.components.len(),
                    report.download_bytes,
                    if report.added_components.is_empty() {
                        String::new()
                    } else {
                        format!("; added: {}", report.added_components.join(", "))
                    }
                ),
                ReportFormat::Json => reportln!(
                    "{}",
                    serde_json::to_string(&report)
                        .map_err(|error| CliFailure::operational(error.to_string()))?
                ),
            }
        }
        Some(Command::Completions { shell }) => {
            if format_supplied {
                return Err("--format is not supported with completions".into());
            }
            if shell != "zsh" {
                return Err(format!("unsupported shell {shell}; supported: zsh").into());
            }
            reportln!(
                "#compdef rstack\n_arguments '1:product:({})'",
                PRODUCTS.join(" ")
            );
        }
        Some(Command::Dev { command }) => dispatch_dev(&cli, command, format)?,
        Some(Command::Client {
            command: ClientCommand::Generate(arguments),
        }) => generate_client(&cli, arguments)?,
        Some(Command::Identity { command }) => match command {
            IdentityCommand::Generate {
                target: IdentityTarget::Thunderid(arguments),
            } => {
                let inputs = arguments.inputs();
                if inputs.is_empty() {
                    return Err("select at least one product with its project and configuration flags, for example --breg-project and --breg-runtime-config".into());
                }
                let options = GenerateOptions {
                    deployment: arguments.deployment.clone(),
                    output: arguments.output.clone(),
                    inputs,
                };
                let summary =
                    identity::generate_thunderid(&options, &|product| driven_tool(&cli, product))?;
                match format {
                    ReportFormat::Human => {
                        reportln!(
                            "{}",
                            identity::generate_report_human(&summary, &options.output)
                        )
                    }
                    ReportFormat::Json => reportln!(
                        "{}",
                        identity::generate_report_json(&summary, &options.output)
                    ),
                }
            }
            IdentityCommand::Check {
                file,
                facts,
                deny_warnings,
            } => {
                let outcome = identity::check(
                    file,
                    facts,
                    *deny_warnings,
                    matches!(format, ReportFormat::Json),
                );
                reportln!("{}", outcome.text);
                if outcome.code != 0 {
                    return Err(CliFailure::reported(outcome.code));
                }
            }
        },
        Some(Command::Product(arguments)) => {
            let product = arguments
                .first()
                .and_then(|value| value.to_str())
                .ok_or("product name must be UTF-8")?;
            known_product(product)?;
            if let Some((help_format, path)) = product_help_request(arguments, format)? {
                product_help(product, help_format, &path)?;
            } else {
                dispatch_product(
                    &cli,
                    product,
                    &arguments[1..],
                    format_supplied,
                    evidence_junit,
                )?;
            }
        }
    }
    Ok(())
}

fn generate_client(cli: &Cli, arguments: &ClientGenerate) -> Result<(), CliFailure> {
    let node_missing = || {
        CliFailure::domain(
            "rstack.client.node-missing: install Node.js 24 or later, then run npm install @registrystack/client in the application project".into(),
        )
    };
    if first_path_binary("node").is_none() {
        return Err(node_missing());
    }
    let output = std::path::absolute(&arguments.output)
        .map_err(|error| CliFailure::operational(format!("cannot resolve output path: {error}")))?;
    let output_directory = output
        .ancestors()
        .skip(1)
        .find_map(|candidate| candidate.canonicalize().ok().filter(|path| path.is_dir()));
    let generator = output_directory
        .as_deref()
        .and_then(installed_client_generator)
        .ok_or_else(|| {
            CliFailure::domain(
                "rstack.client.generator-missing: run npm install @registrystack/client in the application project".into(),
            )
        })?;

    let mut command = ProcessCommand::new("node");
    let selected = selected_state(cli)?;
    if let Some((lease, selection, manifest)) = &selected {
        set_selected_generation_environment(&mut command, lease.path(), selection, manifest)?;
        if !command.get_envs().any(|(name, value)| {
            name == BREG_DEV_HOST.tool_variable
                && value.is_some_and(|path| std::path::Path::new(path).is_file())
        }) {
            return Err(CliFailure::domain(
                "rstack.client.bregctl-missing: component breg is missing; run rstack install breg"
                    .into(),
            ));
        }
        inherit_invocation_lease(lease)?;
    } else if source_dev_binary(BREG_DEV_HOST.tool_variable).is_none() {
        return Err(CliFailure::domain(
            "rstack.client.bregctl-missing: run rstack install breg or set RSTACK_BREGCTL_BIN to an existing bregctl binary"
                .into(),
        ));
    }

    command.arg(generator);
    for (flag, values) in [
        ("--register", arguments.register.as_slice()),
        ("--author-profile", arguments.author_profile.as_slice()),
        ("--route-prefix", arguments.route_prefix.as_slice()),
        ("--products", arguments.products.as_slice()),
    ] {
        for value in values {
            command.arg(flag).arg(value);
        }
    }
    let error = command.arg("--output").arg(&arguments.output).exec();
    if error.kind() == io::ErrorKind::NotFound {
        return Err(node_missing());
    }
    Err(CliFailure::operational(format!(
        "cannot launch registry-generate: {error}"
    )))
}

fn installed_client_generator(output_directory: &std::path::Path) -> Option<PathBuf> {
    #[derive(serde::Deserialize)]
    struct ClientPackage {
        name: String,
        bin: std::collections::BTreeMap<String, PathBuf>,
    }

    let mut manifests = output_directory
        .ancestors()
        .map(|directory| directory.join("node_modules/@registrystack/client/package.json"));
    // Stop at the first manifest, including an invalid one.
    let manifest = manifests.find(|path| {
        !matches!(fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound)
    })?;
    let package_directory = manifest.parent()?.canonicalize().ok()?;
    let manifest = manifest.canonicalize().ok()?;
    if !manifest.starts_with(&package_directory) || !manifest.is_file() {
        return None;
    }
    let package: ClientPackage = serde_json::from_slice(&fs::read(manifest).ok()?).ok()?;
    let bin = package.bin.get("registry-generate")?;
    if package.name != "@registrystack/client" || bin.is_absolute() {
        return None;
    }
    let generator = package_directory.join(bin).canonicalize().ok()?;
    (generator.starts_with(&package_directory) && generator.is_file()).then_some(generator)
}

/// The tool of the selected release that writes a product's identity facts:
/// the product's `RSTACK_<PRODUCT>CTL_BIN` override when set, otherwise the
/// installed component.
fn driven_tool(cli: &Cli, product: &ProductSpec) -> Result<DrivenTool, Failure> {
    if let Some(path) = std::env::var_os(product.variable) {
        return Ok(DrivenTool {
            path: PathBuf::from(path),
            _lease: None,
        });
    }
    let missing = || {
        Failure::Domain(format!(
            "component {} is missing; run rstack install {}",
            product.name, product.name
        ))
    };
    let Some((lease, selection, _)) = selected_state(cli).map_err(|failure| {
        if failure.code == 1 {
            Failure::Domain(failure.message)
        } else {
            Failure::Operational(failure.message)
        }
    })?
    else {
        return Err(missing());
    };
    if !selection.components.iter().any(|name| name == product.name) {
        return Err(missing());
    }
    let tool = lease
        .path()
        .join("components")
        .join(product.name)
        .join(product.binary)
        .join(product.binary);
    if tool.is_file() {
        Ok(DrivenTool {
            path: tool,
            _lease: Some(lease),
        })
    } else {
        Err(missing())
    }
}

fn product_help_request(
    arguments: &[OsString],
    default_format: ReportFormat,
) -> Result<Option<(ReportFormat, Vec<String>)>, CliFailure> {
    let mut format = default_format;
    let mut path = Vec::new();
    let mut help = false;
    let mut values = arguments.iter().skip(1);
    while let Some(value) = values.next() {
        if value == "--" {
            if help {
                path.push("--".to_owned());
                path.extend(values.filter_map(|value| value.to_str().map(str::to_owned)));
            }
            break;
        }
        if value == "--help" {
            help = true;
        } else if value == "--format" {
            let value = values.next().ok_or("--format needs human or json")?;
            format = parse_report_format(value)?;
        } else if let Some(value) = value
            .to_str()
            .and_then(|text| text.strip_prefix("--format="))
        {
            format = parse_report_format(&OsString::from(value))?;
        } else if let Some(value) = value.to_str() {
            path.push(value.to_owned());
        }
    }
    if help
        && arguments
            .first()
            .is_some_and(|product| product == "evidence")
        && path.first().is_some_and(|command| command == "runtime")
        && path.len() > 1
    {
        return Ok(None);
    }
    Ok(help.then_some((format, path)))
}

fn parse_report_format(value: &OsString) -> Result<ReportFormat, CliFailure> {
    match value.to_str() {
        Some("human") => Ok(ReportFormat::Human),
        Some("json") => Ok(ReportFormat::Json),
        _ => Err("--format must be human or json".into()),
    }
}

fn product_help(product: &str, format: ReportFormat, path: &[String]) -> Result<(), CliFailure> {
    let entrypoint = match product {
        "breg" => "bregctl",
        "casework" => "caseworkctl",
        "discovery" => "discoveryctl",
        "evidence" => "evidencectl",
        "manifest" => "manifest",
        "messaging" => "messagingctl",
        "render" => "registry-render",
        "scheduling" => "schedulingctl",
        "coordinator" => "coordinatorctl",
        "adapter" => "adapterctl",
        _ => return Err(format!("unknown component {product}").into()),
    };
    let catalog: Value = serde_json::from_str(include_str!("../../registry-cli-docs/catalog.json"))
        .map_err(|error| format!("offline command catalogue is invalid: {error}"))?;
    let mut reference = catalog["binaries"]
        .as_array()
        .and_then(|commands| {
            commands
                .iter()
                .find(|command| command["name"] == entrypoint)
        })
        .cloned()
        .ok_or_else(|| format!("offline command catalogue lacks {product}"))?;
    rewrite_reference(&mut reference, entrypoint, &format!("rstack {product}"));
    reference["name"] = Value::String(product.to_owned());
    for token in path {
        if token.starts_with('-') {
            return Err(format!("unknown offline help option {token}").into());
        }
        let Some(child) = reference["subcommands"]
            .as_array()
            .and_then(|commands| {
                commands
                    .iter()
                    .find(|command| command["name"].as_str() == Some(token.as_str()))
            })
            .cloned()
        else {
            return Err(
                format!("unknown or surplus action {token} for offline {product} help").into(),
            );
        };
        reference = child;
    }
    match format {
        ReportFormat::Human => {
            reportln!(
                "{}: {}",
                reference["invocation"].as_str().unwrap_or("rstack"),
                reference["about"].as_str().unwrap_or("")
            );
            if let Some(actions) = reference["subcommands"].as_array() {
                for action in actions {
                    if let Some(name) = action["name"].as_str() {
                        reportln!("  {name}");
                    }
                }
            }
            if let Some(options) = reference["options"].as_array() {
                for option in options {
                    if let Some(display) = option["display"].as_str() {
                        reportln!("  {display}");
                    }
                }
            }
        }
        ReportFormat::Json => reportln!(
            "{}",
            json!({"schema_version":"registry.rstack.help.v1","command":reference})
        ),
    }
    Ok(())
}

fn rewrite_reference(value: &mut Value, private: &str, public: &str) {
    match value {
        Value::String(text) if private != "manifest" && text.contains(private) => {
            *text = text.replace(private, public);
        }
        Value::Array(items) => {
            for item in items {
                rewrite_reference(item, private, public);
            }
        }
        Value::Object(fields) => {
            for (name, item) in fields.iter_mut() {
                if private == "manifest" && matches!(name.as_str(), "invocation" | "usage") {
                    if let Value::String(text) = item {
                        if name == "invocation" {
                            if let Some(rest) = text.strip_prefix("manifest") {
                                if rest.is_empty() || rest.starts_with(' ') {
                                    *text = format!("{public}{rest}");
                                }
                            }
                        } else {
                            *text = text.replace("Usage: manifest", &format!("Usage: {public}"));
                        }
                    }
                }
                rewrite_reference(item, private, public);
            }
        }
        _ => {}
    }
}

fn known_product(product: &str) -> Result<(), String> {
    if PRODUCTS.contains(&product) {
        Ok(())
    } else {
        Err(format!("unknown component {product}"))
    }
}

fn home_directory() -> Result<PathBuf, CliFailure> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            CliFailure::operational("HOME is required for the default installation paths".into())
        })
}

fn default_install_root() -> Result<PathBuf, CliFailure> {
    Ok(home_directory()?.join(".local/lib/registrystack"))
}

fn default_bin_dir() -> Result<PathBuf, CliFailure> {
    Ok(home_directory()?.join(".local/bin"))
}

fn installation_paths(cli: &Cli) -> Result<(PathBuf, PathBuf), CliFailure> {
    let install_root = match &cli.install_root {
        Some(path) => path.clone(),
        None => default_install_root()?,
    };
    let bin_dir = match &cli.bin_dir {
        Some(path) => path.clone(),
        None => default_bin_dir()?,
    };
    Ok((install_root, bin_dir))
}

fn manager_options(cli: &Cli) -> Result<install::ManagerOptions, CliFailure> {
    let (install_root, bin_dir) = installation_paths(cli)?;
    Ok(install::ManagerOptions {
        install_root,
        bin_dir,
        asset_dir: cli.asset_dir.clone(),
    })
}

fn manager_failure(error: install::ManagerError) -> CliFailure {
    match error.class {
        install::ManagerErrorClass::Domain => CliFailure::domain(error.message),
        install::ManagerErrorClass::Operational => CliFailure::operational(error.message),
    }
}

fn selected_state(
    cli: &Cli,
) -> Result<
    Option<(
        InvocationLease,
        install::InstalledSelection,
        ReleaseManifest,
    )>,
    CliFailure,
> {
    let (install_root, bin_dir) = installation_paths(cli)?;
    let store = GenerationStore::new(install_root, bin_dir);
    if !store.has_installation().map_err(CliFailure::operational)? {
        return Ok(None);
    }
    let lease = store.acquire_current().map_err(CliFailure::operational)?;
    let selection = install::read_selection(lease.path()).map_err(CliFailure::operational)?;
    let manifest_path = lease.path().join("manifest.json");
    let metadata = fs::metadata(&manifest_path).map_err(|error| {
        CliFailure::operational(format!("cannot inspect selected release: {error}"))
    })?;
    if metadata.len() > 16 * 1024 * 1024 {
        return Err(CliFailure::operational(
            "selected release manifest exceeds 16 MiB".into(),
        ));
    }
    let raw = fs::read(&manifest_path).map_err(|error| {
        CliFailure::operational(format!("cannot read selected release: {error}"))
    })?;
    let manifest = ReleaseManifest::parse(&raw).map_err(CliFailure::operational)?;
    if manifest.release.tag != selection.release || manifest.components.release != selection.release
    {
        return Err(CliFailure::operational(
            "selected release identity differs from installed component selection".into(),
        ));
    }
    Ok(Some((lease, selection, manifest)))
}

fn list_components(cli: &Cli, format: ReportFormat) -> Result<(), CliFailure> {
    let selected = selected_state(cli)?;
    let Some((lease, selection, manifest)) = selected else {
        let components: Vec<Value> = PRODUCTS
            .iter()
            .map(|name| {
                json!({
                    "name":name,
                    "installed":false,
                    "available":null,
                    "version":null,
                    "entrypoint":null,
                    "path":null,
                    "capabilities":null
                })
            })
            .collect();
        match format {
            ReportFormat::Human => {
                reportln!("No installation selected.");
                for name in PRODUCTS {
                    reportln!("  {name}: availability unknown, version unavailable, path none");
                }
            }
            ReportFormat::Json => reportln!(
                "{}",
                json!({"schema_version":"registry.rstack.components.v1","release":null,"generation":null,"components":components})
            ),
        }
        return Ok(());
    };
    let components: Vec<Value> = PRODUCTS
        .iter()
        .map(|name| {
            let component = manifest.components.components.get(*name);
            let payload =
                component.and_then(|component| component.platforms.get(&selection.platform));
            let available = payload.is_some();
            let installed = available
                && selection
                    .components
                    .iter()
                    .any(|selected| selected.as_str() == *name);
            let path = installed.then(|| {
                let entrypoint = &component.expect("available component exists").entrypoint;
                lease
                    .path()
                    .join("components")
                    .join(*name)
                    .join(entrypoint)
                    .join(entrypoint)
            });
            json!({
                "name":name,
                "installed":installed,
                "available":available,
                "version":available.then_some(&manifest.release.version),
                "entrypoint":component.map(|component| &component.entrypoint),
                "path":path,
                "capabilities":payload.map(|payload| &payload.capabilities)
            })
        })
        .collect();
    match format {
        ReportFormat::Human => {
            reportln!(
                "Selected release: {} ({})",
                selection.release,
                lease.generation().name()
            );
            for item in &components {
                let name = item["name"].as_str().unwrap_or("unknown");
                let state = if item["installed"] == true {
                    "installed"
                } else if item["available"] == true {
                    "available"
                } else {
                    "unavailable"
                };
                let version = item["version"].as_str().unwrap_or("unavailable");
                let path = item["path"].as_str().unwrap_or("none");
                reportln!("  {name}: {state}, version {version}, path {path}");
            }
        }
        ReportFormat::Json => reportln!(
            "{}",
            json!({"schema_version":"registry.rstack.components.v1","release":selection.release,"generation":lease.generation().name(),"platform":selection.platform,"components":components})
        ),
    }
    Ok(())
}

fn doctor(cli: &Cli, format: ReportFormat) -> Result<(), CliFailure> {
    let (install_root, bin_dir) = installation_paths(cli)?;
    let store = GenerationStore::new(&install_root, &bin_dir);
    let mut problems = Vec::new();
    let selected = match selected_state(cli) {
        Ok(selected) => selected,
        Err(error) => {
            problems.push(error.message);
            None
        }
    };
    if selected.is_none() && problems.is_empty() {
        problems.push("no Registry Stack installation is selected".into());
    }
    let expected_link = store
        .public_link_target()
        .map_err(CliFailure::operational)?;
    let public_link = store.public_link();
    match fs::symlink_metadata(&public_link) {
        Ok(metadata) if metadata.file_type().is_symlink() => match fs::read_link(&public_link) {
            Ok(target) if target == expected_link => {}
            Ok(_) => problems.push("public rstack path is not owned by this installation".into()),
            Err(error) => problems.push(format!("cannot read public rstack link: {error}")),
        },
        Ok(_) => problems.push("public rstack path is occupied by another file".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            problems.push("public rstack link is missing".into())
        }
        Err(error) => problems.push(format!("cannot inspect public rstack path: {error}")),
    }
    if let Some(first) = first_path_binary("rstack") {
        if fs::canonicalize(&first).ok() != fs::canonicalize(&public_link).ok() {
            problems.push(format!(
                "another rstack shadows the selected launcher at {}",
                first.display()
            ));
        }
    }
    let release = selected
        .as_ref()
        .map(|(_, selection, _)| &selection.release);
    let generation = selected
        .as_ref()
        .map(|(lease, _, _)| lease.generation().name());
    let components = selected
        .as_ref()
        .map(|(_, selection, _)| &selection.components);
    let ok = problems.is_empty();
    let report = json!({
        "schema_version":"registry.rstack.doctor.v1",
        "status":if ok {"ok"} else {"refused"},
        "release":release,
        "generation":generation,
        "paths":{"install_root":install_root,"bin_dir":bin_dir,"public_link":public_link},
        "components":components,
        "problems":problems,
    });
    match format {
        ReportFormat::Human => {
            if ok {
                reportln!(
                    "Registry Stack installation is healthy: {}",
                    release.unwrap()
                );
            } else {
                for problem in &problems {
                    writeln!(io::stderr().lock(), "rstack: {problem}").map_err(|error| {
                        CliFailure::operational(format!("cannot write diagnosis: {error}"))
                    })?;
                }
            }
        }
        ReportFormat::Json => {
            write_stdout(format_args!("{report}"))?;
        }
    }
    if ok {
        Ok(())
    } else {
        Err(CliFailure::reported(1))
    }
}

fn first_path_binary(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// The hidden subcommand under which a hosting product CLI runs the
/// development runner; `registry_rstack_dev::COMMAND` names the same one.
const DEV_RUNNER_COMMAND: &str = "rstack-dev";

/// A product whose CLI hosts the development runner.
struct DevHost {
    component: &'static str,
    tool: &'static str,
    tool_variable: &'static str,
    runtime_variable: &'static str,
}

const BREG_DEV_HOST: DevHost = DevHost {
    component: "breg",
    tool: "bregctl",
    tool_variable: "RSTACK_BREGCTL_BIN",
    runtime_variable: "RSTACK_BREG_BIN",
};

/// The hosting products in the order that picks the host. The first one a
/// plan lists hosts `check` and `start`, because the plan needs that CLI
/// anyway. The first one available hosts `status`, `token` and `stop`: a run
/// keeps its state in its run directory, so any host of the same release
/// serves a run another host started.
const DEV_HOSTS: [DevHost; 10] = [
    BREG_DEV_HOST,
    DevHost {
        component: "casework",
        tool: "caseworkctl",
        tool_variable: "RSTACK_CASEWORKCTL_BIN",
        runtime_variable: "RSTACK_CASEWORK_BIN",
    },
    DevHost {
        component: "evidence",
        tool: "evidencectl",
        tool_variable: "RSTACK_EVIDENCECTL_BIN",
        runtime_variable: "RSTACK_EVIDENCE_BIN",
    },
    DevHost {
        component: "messaging",
        tool: "messagingctl",
        tool_variable: "RSTACK_MESSAGINGCTL_BIN",
        runtime_variable: "RSTACK_MESSAGING_BIN",
    },
    DevHost {
        component: "scheduling",
        tool: "schedulingctl",
        tool_variable: "RSTACK_SCHEDULINGCTL_BIN",
        runtime_variable: "RSTACK_SCHEDULING_BIN",
    },
    DevHost {
        component: "documents",
        tool: "documentsctl",
        tool_variable: "RSTACK_DOCUMENTSCTL_BIN",
        runtime_variable: "RSTACK_DOCUMENTS_BIN",
    },
    DevHost {
        component: "coordinator",
        tool: "coordinatorctl",
        tool_variable: "RSTACK_COORDINATORCTL_BIN",
        runtime_variable: "RSTACK_COORDINATOR_BIN",
    },
    DevHost {
        component: "adapter",
        tool: "adapterctl",
        tool_variable: "RSTACK_ADAPTERCTL_BIN",
        runtime_variable: "RSTACK_ADAPTER_BIN",
    },
    DevHost {
        component: "render",
        tool: "registry-render",
        tool_variable: "RSTACK_RENDER_BIN",
        runtime_variable: "RSTACK_RENDER_BIN",
    },
    DevHost {
        component: "discovery",
        tool: "discoveryctl",
        tool_variable: "RSTACK_DISCOVERYCTL_BIN",
        runtime_variable: "RSTACK_DISCOVERY_BIN",
    },
];

/// The binaries a development action needs before the launcher runs its host.
struct DevNeeds {
    /// The products whose binaries the action needs, the host first. Empty
    /// when the first available host serves the action.
    products: Vec<&'static DevHost>,
    /// `start` runs services, so it needs each product's runtime as well.
    services: bool,
}

impl DevNeeds {
    /// The run-ID actions need any host and no other binary.
    fn any_host() -> Self {
        Self {
            products: Vec::new(),
            services: false,
        }
    }

    /// `check` needs only its host; the runner reports another listed
    /// product whose tool is unavailable at that product's plan entry.
    fn check(project: &std::path::Path) -> Self {
        let mut products = plan_dev_products(project);
        products.truncate(1);
        Self {
            products,
            services: false,
        }
    }

    /// `start` needs the tool and runtime of every product the plan lists.
    fn start(project: &std::path::Path) -> Self {
        Self {
            products: plan_dev_products(project),
            services: true,
        }
    }

    /// The source binary overrides the action needs, the host's tool first.
    fn variables(&self) -> Vec<&'static str> {
        self.products
            .iter()
            .flat_map(|product| {
                std::iter::once(product.tool_variable).chain(
                    (self.services && product.runtime_variable != product.tool_variable)
                        .then_some(product.runtime_variable),
                )
            })
            .collect()
    }
}

/// The hosting products the project's dev.yaml lists under
/// `/products/*/product`, in hosting order. A missing, unreadable, oversized
/// or unparsable plan, or one without a products list, lists none: the first
/// available host then reports the real plan error, with the positioned
/// diagnostics every product gives for a malformed configuration file.
fn plan_dev_products(project: &std::path::Path) -> Vec<&'static DevHost> {
    use registry_platform_yaml::{NodeValue, Reader, MAXIMUM_DOCUMENT_BYTES};
    use std::io::Read;
    let limit = MAXIMUM_DOCUMENT_BYTES as u64;
    let file = project.join("dev.yaml");
    let mut bytes = Vec::new();
    let read = std::fs::File::open(&file)
        .and_then(|handle| handle.take(limit + 1).read_to_end(&mut bytes));
    if read.is_err() || bytes.len() as u64 > limit {
        return Vec::new();
    }
    let Ok(Some(root)) = Reader::new(file.display().to_string()).scan(&bytes) else {
        return Vec::new();
    };
    let Some(NodeValue::Sequence(entries)) = root.pointer("/products").map(|node| &node.value)
    else {
        return Vec::new();
    };
    DEV_HOSTS
        .iter()
        .filter(|host| {
            entries.iter().any(|entry| {
                matches!(
                    entry.pointer("/product").map(|node| &node.value),
                    Some(NodeValue::String(text)) if text.text == host.component
                )
            })
        })
        .collect()
}

/// The refusal when no host is available for an action that any host serves.
fn no_dev_host(managed: bool) -> CliFailure {
    let installs = DEV_HOSTS
        .iter()
        .map(|host| format!("rstack install {}", host.component))
        .collect::<Vec<_>>()
        .join(" or ");
    if managed {
        return CliFailure::domain(format!(
            "no installed component can run rstack dev; run {installs}"
        ));
    }
    let overrides = DEV_HOSTS
        .iter()
        .map(|host| host.tool_variable)
        .collect::<Vec<_>>()
        .join(" or ");
    CliFailure::domain(format!(
        "without a managed installation, run {installs}, or set an existing source binary override: {overrides}"
    ))
}

/// `rstack help dev`: the development commands' help, offline.
fn dev_help(format: ReportFormat) -> Result<(), CliFailure> {
    let mut root = command();
    root.build();
    let dev = root.find_subcommand_mut("dev").expect("the dev command");
    match format {
        ReportFormat::Human => reportln!("{}", dev.render_long_help()),
        ReportFormat::Json => {
            let subcommands: Vec<_> = dev
                .get_subcommands()
                .map(|sub| {
                    json!({
                        "name": sub.get_name(),
                        "invocation": format!("rstack dev {}", sub.get_name()),
                        "about": sub.get_about().map(ToString::to_string),
                    })
                })
                .collect();
            reportln!(
                "{}",
                json!({"schema_version":"registry.rstack.help.v1","command":{
                    "name":"dev","invocation":"rstack dev",
                    "about":dev.get_about().map(ToString::to_string),
                    "subcommands":subcommands}})
            );
        }
    }
    Ok(())
}

fn admit_dev(action: &DevCommand, format: ReportFormat) -> Result<(), CliFailure> {
    if !matches!(action, DevCommand::Check { .. } | DevCommand::Start { .. }) {
        return Ok(());
    }
    // The hosted commands also enforce this when called directly.
    let (code, message, fix) = match declared(None) {
        Err(error) => (
            error.code(),
            error.message(),
            "Unset REGISTRY_STACK_POSTURE, or set it to development.",
        ),
        Ok(DeclaredPosture {
            posture: Posture::Production,
            source: PostureSource::Environment,
        }) => (
            "platform.posture.conflict",
            "rstack dev runs development processes",
            "Unset REGISTRY_STACK_POSTURE, or set it to development.",
        ),
        Ok(_) => return Ok(()),
    };

    if matches!(action, DevCommand::Start { .. }) {
        return Err(format!("{code}: {message}. {fix}").into());
    }

    let report = Report::new(vec![Diagnostic::error(code, "", message, fix)]);
    match format {
        ReportFormat::Json => {
            // Keep the hosted dev-check report shape without loading a product host.
            let envelope = json!({
                "ok": false,
                "command": "dev-check",
                "status": "usage-error",
                "apiVersion": "id.registrystack.org/formats/breg/ctl-report/v1alpha1",
                "kind": "BRegCtlReport",
                "version": registry_platform_buildinfo::DISPLAY_VERSION,
                "diagnostics": report.to_json_value(),
            });
            reportln!("{envelope}");
        }
        ReportFormat::Human => {
            write!(io::stderr().lock(), "{}", report.render_human()).map_err(|error| {
                CliFailure::operational(format!("cannot write report: {error}"))
            })?;
        }
    }
    Err(CliFailure::reported(2))
}

fn source_dev_binary(variable: &str) -> Option<PathBuf> {
    std::env::var_os(variable)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_file())
}

fn dispatch_dev(cli: &Cli, action: &DevCommand, format: ReportFormat) -> Result<(), CliFailure> {
    admit_dev(action, format)?;
    let option = |name: &str, value: &std::ffi::OsStr| {
        let mut option = OsString::from(format!("--{name}="));
        option.push(value);
        option
    };
    let (name, mut options, target, database_url, needs) = match action {
        DevCommand::Check {
            project,
            deny_warnings,
        } => (
            "check",
            deny_warnings
                .then(|| OsString::from("--deny-warnings"))
                .into_iter()
                .collect::<Vec<_>>(),
            project.as_os_str(),
            None,
            DevNeeds::check(project),
        ),
        DevCommand::Start {
            project,
            application_root,
            database_url,
            ttl,
        } => (
            "start",
            application_root
                .iter()
                .map(|root| option("application-root", root.as_os_str()))
                .chain(ttl.iter().map(|ttl| option("ttl", ttl.as_ref())))
                .collect(),
            project.as_os_str(),
            database_url.as_deref(),
            DevNeeds::start(project),
        ),
        DevCommand::Status { run_id } => (
            "status",
            Vec::new(),
            run_id.as_ref(),
            None,
            DevNeeds::any_host(),
        ),
        DevCommand::Token { run_id, person } => (
            "token",
            vec![option("as", person.as_ref())],
            run_id.as_ref(),
            None,
            DevNeeds::any_host(),
        ),
        DevCommand::Stop {
            run_id,
            recover,
            database_url,
        } => (
            "stop",
            recover
                .then(|| OsString::from("--recover"))
                .into_iter()
                .collect(),
            run_id.as_ref(),
            database_url.as_deref(),
            DevNeeds::any_host(),
        ),
    };
    if matches!(format, ReportFormat::Json) {
        options.push(OsString::from("--json"));
    }

    let selected = selected_state(cli)?;
    let (mut command, lease) = if let Some((lease, selection, manifest)) = selected {
        let installed = |component: &str| selection.components.iter().any(|name| name == component);
        let host_path = |host: &DevHost| {
            lease
                .path()
                .join("components")
                .join(host.component)
                .join(host.tool)
                .join(host.tool)
        };
        let host = if let Some(first) = needs.products.first() {
            for product in &needs.products {
                if !installed(product.component) {
                    return Err(CliFailure::domain(format!(
                        "component {component} is missing; run rstack install {component}",
                        component = product.component
                    )));
                }
            }
            let host = host_path(first);
            if !host.is_file() {
                return Err(CliFailure::operational(format!(
                    "selected {} component lacks its {} binary",
                    first.component, first.tool
                )));
            }
            host
        } else {
            DEV_HOSTS
                .iter()
                .filter(|host| installed(host.component))
                .map(host_path)
                .find(|path| path.is_file())
                .ok_or_else(|| no_dev_host(true))?
        };
        let mut command = ProcessCommand::new(host);
        set_selected_generation_environment(&mut command, lease.path(), &selection, &manifest)?;
        let missing: Vec<_> = needs
            .variables()
            .into_iter()
            .filter(|variable| {
                !command
                    .get_envs()
                    .any(|(name, value)| name == std::ffi::OsStr::new(variable) && value.is_some())
            })
            .collect();
        if !missing.is_empty() {
            return Err(CliFailure::operational(format!(
                "selected release lacks development binaries for {}",
                missing.join(", ")
            )));
        }
        (command, Some(lease))
    } else {
        let missing: Vec<_> = needs
            .variables()
            .into_iter()
            .filter(|variable| source_dev_binary(variable).is_none())
            .collect();
        if !missing.is_empty() {
            return Err(CliFailure::domain(format!(
                "without a managed installation, run rstack install {}, or set existing source binary overrides: {}",
                needs
                    .products
                    .iter()
                    .filter(|product| missing.iter().any(|variable| {
                        *variable == product.tool_variable || *variable == product.runtime_variable
                    }))
                    .map(|product| product.component)
                    .collect::<Vec<_>>()
                    .join(" "),
                missing.join(", ")
            )));
        }
        let host = match needs.products.first() {
            Some(first) => source_dev_binary(first.tool_variable),
            None => DEV_HOSTS
                .iter()
                .find_map(|host| source_dev_binary(host.tool_variable)),
        }
        .ok_or_else(|| no_dev_host(false))?;
        (ProcessCommand::new(host), None)
    };

    command
        .env(POSTURE_ENV, DEVELOPMENT)
        .arg(DEV_RUNNER_COMMAND)
        .arg(name)
        .args(options)
        .arg("--")
        .arg(target);
    if let Some(database_url) = database_url {
        command.env("RSTACK_DEV_DATABASE_URL", database_url);
    }
    if let Some(lease) = &lease {
        inherit_invocation_lease(lease)?;
    }
    let host = PathBuf::from(command.get_program());
    let error = command.exec();
    Err(CliFailure::operational(format!(
        "cannot launch development host {}: {error}",
        host.display()
    )))
}

fn dispatch_product(
    cli: &Cli,
    product: &str,
    arguments: &[OsString],
    format_supplied: bool,
    evidence_junit: bool,
) -> Result<(), CliFailure> {
    let Some((lease, selection, manifest)) = selected_state(cli)? else {
        return Err(CliFailure::domain(format!(
            "component {product} is missing; run rstack install {product}"
        )));
    };
    if !selection.components.iter().any(|name| name == product) {
        return Err(CliFailure::domain(format!(
            "component {product} is missing; run rstack install {product}"
        )));
    }
    let component = manifest.components.components.get(product).ok_or_else(|| {
        CliFailure::operational(format!("selected release lacks component {product}"))
    })?;
    let executable = lease
        .path()
        .join("components")
        .join(product)
        .join(&component.entrypoint)
        .join(&component.entrypoint);
    let mut command = ProcessCommand::new(&executable);
    set_selected_generation_environment(&mut command, lease.path(), &selection, &manifest)?;
    let delimiter = arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(arguments.len());
    let product_has_format = arguments.iter().take(delimiter).any(|argument| {
        argument == "--format"
            || argument
                .to_str()
                .is_some_and(|value| value.starts_with("--format="))
    });
    let format = cli.format.first().copied().unwrap_or(ReportFormat::Human);
    let inherited_format = (format_supplied && !product_has_format).then_some(match format {
        ReportFormat::Human => "human",
        ReportFormat::Json => "json",
    });
    let normalized_runtime_arguments = (product == "evidence")
        .then(|| normalize_evidence_runtime_format(arguments, inherited_format))
        .flatten();
    let arguments = normalized_runtime_arguments.as_deref().unwrap_or(arguments);
    let delimiter = arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(arguments.len());
    let product_has_format = arguments.iter().take(delimiter).any(|argument| {
        argument == "--format"
            || argument
                .to_str()
                .is_some_and(|value| value.starts_with("--format="))
    });
    if evidence_junit {
        debug_assert_eq!(product, "evidence");
        command.args(&arguments[..delimiter]);
        command.args(["--format", "junit"]);
        command.args(&arguments[delimiter..]);
    } else if format_supplied && !product_has_format {
        let format = match format {
            ReportFormat::Human => "human",
            ReportFormat::Json => "json",
        };
        command.args(&arguments[..delimiter]);
        command.args(["--format", format]);
        command.args(&arguments[delimiter..]);
    } else {
        command.args(arguments);
    }
    inherit_invocation_lease(&lease)?;
    Err(CliFailure::operational(format!(
        "cannot launch {product}: {}",
        command.exec()
    )))
}

fn inherit_invocation_lease(lease: &InvocationLease) -> Result<(), CliFailure> {
    let mut flags = rustix::io::fcntl_getfd(lease.lease_file()).map_err(|error| {
        CliFailure::operational(format!("cannot inspect invocation lease: {error}"))
    })?;
    flags.remove(rustix::io::FdFlags::CLOEXEC);
    rustix::io::fcntl_setfd(lease.lease_file(), flags).map_err(|error| {
        CliFailure::operational(format!("cannot inherit invocation lease: {error}"))
    })?;
    Ok(())
}

/// Put a launcher report format before the first native Evidence runtime token
/// immediately after that token. Arguments after the native token, including a
/// delimiter and runtime-owned flags, retain their order and spelling.
fn normalize_evidence_runtime_format(
    arguments: &[OsString],
    inherited_format: Option<&str>,
) -> Option<Vec<OsString>> {
    let delimiter = arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(arguments.len());
    let mut index = 0;
    let mut format = take_report_format(arguments, &mut index, delimiter);
    if arguments
        .get(index)
        .is_none_or(|argument| argument != "runtime")
    {
        return None;
    }
    let runtime = arguments[index].clone();
    index += 1;
    if format.is_none() {
        format = take_report_format(arguments, &mut index, delimiter);
    }
    if index >= delimiter {
        return None;
    }
    let native_command = arguments[index].clone();
    index += 1;
    let format = format.or_else(|| inherited_format.map(OsString::from))?;

    let mut normalized = Vec::with_capacity(arguments.len() + 2);
    normalized.push(runtime);
    normalized.push(native_command);
    normalized.push(OsString::from("--format"));
    normalized.push(format);
    normalized.extend_from_slice(&arguments[index..]);
    Some(normalized)
}

fn take_report_format(
    arguments: &[OsString],
    index: &mut usize,
    delimiter: usize,
) -> Option<OsString> {
    let argument = arguments.get(*index)?;
    if argument == "--format" {
        let value = arguments
            .get(*index + 1)
            .filter(|_| *index + 1 < delimiter)?;
        *index += 2;
        return Some(value.clone());
    }
    let value = argument
        .to_str()
        .and_then(|argument| argument.strip_prefix("--format="))?;
    *index += 1;
    Some(OsString::from(value))
}

fn set_selected_generation_environment(
    command: &mut ProcessCommand,
    generation: &std::path::Path,
    selection: &install::InstalledSelection,
    manifest: &ReleaseManifest,
) -> Result<(), CliFailure> {
    let generation = generation.canonicalize().map_err(|error| {
        CliFailure::operational(format!("cannot resolve selected generation: {error}"))
    })?;
    let platform = install::platform().map_err(CliFailure::operational)?;
    command.env("RSTACK_GENERATION_DIR", &generation);
    command.env("RSTACK_RELEASE_TAG", &manifest.release.tag);
    for (component_name, binary, variable) in [
        ("breg", "bregctl", "RSTACK_BREGCTL_BIN"),
        ("breg", "breg", "RSTACK_BREG_BIN"),
        ("breg", "breg-mcp", "RSTACK_BREG_MCP_BIN"),
        ("breg", "breg-review", "RSTACK_BREG_REVIEW_BIN"),
        ("casework", "caseworkctl", "RSTACK_CASEWORKCTL_BIN"),
        ("casework", "casework", "RSTACK_CASEWORK_BIN"),
        ("evidence", "evidencectl", "RSTACK_EVIDENCECTL_BIN"),
        ("evidence", "evidence", "RSTACK_EVIDENCE_BIN"),
        (
            "evidence",
            "evidence-oid4vci",
            "RSTACK_EVIDENCE_OID4VCI_BIN",
        ),
        ("discovery", "discoveryctl", "RSTACK_DISCOVERYCTL_BIN"),
        ("discovery", "discovery", "RSTACK_DISCOVERY_BIN"),
        ("messaging", "messagingctl", "RSTACK_MESSAGINGCTL_BIN"),
        ("messaging", "messaging", "RSTACK_MESSAGING_BIN"),
        ("scheduling", "schedulingctl", "RSTACK_SCHEDULINGCTL_BIN"),
        ("scheduling", "scheduling", "RSTACK_SCHEDULING_BIN"),
        ("coordinator", "coordinatorctl", "RSTACK_COORDINATORCTL_BIN"),
        ("coordinator", "coordinator", "RSTACK_COORDINATOR_BIN"),
        ("documents", "documentsctl", "RSTACK_DOCUMENTSCTL_BIN"),
        ("documents", "documents", "RSTACK_DOCUMENTS_BIN"),
        ("adapter", "adapterctl", "RSTACK_ADAPTERCTL_BIN"),
        ("adapter", "adapter", "RSTACK_ADAPTER_BIN"),
        ("render", "registry-render", "RSTACK_RENDER_BIN"),
    ] {
        if !selection
            .components
            .iter()
            .any(|name| name == component_name)
        {
            command.env_remove(variable);
            continue;
        }
        let Some(component) = manifest.components.components.get(component_name) else {
            continue;
        };
        let Some(payload) = component.platforms.get(platform) else {
            continue;
        };
        let suffix = if platform == "macos-arm64" {
            ".tar.gz"
        } else {
            ""
        };
        let asset = format!("{binary}-{}-{platform}{suffix}", manifest.release.tag);
        if payload.assets.iter().any(|item| item.name == asset) {
            command.env(
                variable,
                generation
                    .join("components")
                    .join(component_name)
                    .join(binary)
                    .join(binary),
            );
        } else {
            command.env_remove(variable);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_generation_projects_optional_service_binaries() {
        let generation = tempfile::tempdir().unwrap();
        let platform = install::platform().unwrap();
        let suffix = if platform == "macos-arm64" {
            ".tar.gz"
        } else {
            ""
        };
        let manifest: ReleaseManifest = serde_json::from_value(json!({
            "schema_version": "registry-stack.release-candidate.v2",
            "repository": "registrystack/registry-stack",
            "release": {"tag":"v0.44.0","version":"0.44.0","source_sha":"a".repeat(40),"release_id":"test"},
            "payloads": [],
            "components": {
                "schema_version": "registry-stack.components.v1",
                "release": "v0.44.0",
                "launcher": {},
                "components": {
                    "breg": {"entrypoint":"bregctl","dependencies":[],"platforms":{
                        (platform): {"assets":[
                            {"name":format!("breg-mcp-v0.44.0-{platform}{suffix}"),"size":1,"sha256":"a".repeat(64)},
                            {"name":format!("breg-review-v0.44.0-{platform}{suffix}"),"size":1,"sha256":"a".repeat(64)}
                        ],"capabilities":{}}
                    }},
                    "evidence": {"entrypoint":"evidencectl","dependencies":[],"platforms":{
                        (platform): {"assets":[
                            {"name":format!("evidence-oid4vci-v0.44.0-{platform}{suffix}"),"size":1,"sha256":"a".repeat(64)}
                        ],"capabilities":{}}
                    }}
                }
            }
        })).unwrap();
        let selection = install::InstalledSelection {
            schema_version: "registry.rstack.selection.v1".to_owned(),
            release: "v0.44.0".to_owned(),
            platform: platform.to_owned(),
            components: vec!["breg".to_owned(), "evidence".to_owned()],
        };
        let mut command = ProcessCommand::new("true");
        assert!(set_selected_generation_environment(
            &mut command,
            generation.path(),
            &selection,
            &manifest
        )
        .is_ok());
        let projected: std::collections::BTreeMap<_, _> = command
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
            .collect();
        let canonical_generation = generation.path().canonicalize().unwrap();
        for (variable, component, binary) in [
            ("RSTACK_BREG_MCP_BIN", "breg", "breg-mcp"),
            ("RSTACK_BREG_REVIEW_BIN", "breg", "breg-review"),
            (
                "RSTACK_EVIDENCE_OID4VCI_BIN",
                "evidence",
                "evidence-oid4vci",
            ),
        ] {
            assert_eq!(
                projected.get(std::ffi::OsStr::new(variable)),
                Some(
                    &canonical_generation
                        .join("components")
                        .join(component)
                        .join(binary)
                        .join(binary)
                        .into_os_string()
                )
            );
        }
    }
}
