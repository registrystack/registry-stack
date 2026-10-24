// SPDX-License-Identifier: Apache-2.0

use crate::install::{self, BootstrapOptions};
use crate::store::{GenerationStore, InvocationLease};
use crate::ReleaseManifest;
use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

const PRODUCTS: [&str; 9] = [
    "breg",
    "casework",
    "discovery",
    "evidence",
    "manifest",
    "messaging",
    "render",
    "scheduling",
    "coordinator",
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
    #[command(external_subcommand)]
    Product(Vec<OsString>),
}

#[derive(Subcommand)]
enum ComponentCommand {
    /// List every known product and its selected-release status.
    List,
}

pub fn command() -> clap::Command {
    Cli::command()
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
    let cli = match Cli::try_parse_from(arguments) {
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
            known_product(product)?;
            product_help(product, format, &[])?;
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
    if let Some(first) = first_path_rstack() {
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

fn first_path_rstack() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join("rstack");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
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
    let mut flags = rustix::io::fcntl_getfd(lease.lease_file()).map_err(|error| {
        CliFailure::operational(format!("cannot inspect invocation lease: {error}"))
    })?;
    flags.remove(rustix::io::FdFlags::CLOEXEC);
    rustix::io::fcntl_setfd(lease.lease_file(), flags).map_err(|error| {
        CliFailure::operational(format!("cannot inherit invocation lease: {error}"))
    })?;
    Err(CliFailure::operational(format!(
        "cannot launch {product}: {}",
        command.exec()
    )))
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
