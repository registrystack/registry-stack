use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use registryctl::{
    BundleSignOptions, DeploymentProfile, DoctorFormat, InitProjectKind, InitReport, InitSource,
    ProjectBuildOptions, ProjectCheckOptions, ProjectCommandReport, ProjectEditorSetupOptions,
    ProjectInitOptions, ProjectSchemaKind, ProjectStarter, ProjectTestOptions,
    ProjectTestSelection, Sample,
};

fn main() -> Result<()> {
    if registry_relay::rhai_worker::is_worker_invocation(std::env::args_os()) {
        let status = registry_relay::rhai_worker::run_worker_stdio();
        if status == std::process::ExitCode::SUCCESS {
            return Ok(());
        }
        std::process::exit(1);
    }
    if is_exact_internal_mode("__registryctl-cel-worker-v1") {
        registry_notary_server::cel_worker::run_stdio_worker();
        return Ok(());
    }

    let cli = Cli::parse();
    if cli.command.should_check_for_updates() {
        registryctl::maybe_warn_about_update(env!("CARGO_PKG_VERSION"));
    }
    match cli.command {
        Commands::UpdateCheck => registryctl::update_check(env!("CARGO_PKG_VERSION"))?,
        Commands::UpdateCheckRefresh => registryctl::refresh_update_check_cache()?,
        Commands::Init {
            from,
            project_dir,
            format,
            command,
        } => {
            let report = match (from, command) {
                (Some(starter), None) => registryctl::init_registry_project(&ProjectInitOptions {
                    starter,
                    directory: project_dir,
                })?,
                (None, Some(command)) => {
                    let image_lock = registryctl::load_registryctl_image_lock()?;
                    match *command {
                        InitCommand::Relay { dir, sample } => {
                            registryctl::init_spreadsheet_api(&dir, sample, &image_lock)?
                        }
                        InitCommand::SpreadsheetApi { dir, sample } => {
                            registryctl::init_spreadsheet_api(&dir, sample, &image_lock)?
                        }
                    }
                }
                _ => anyhow::bail!(
                    "init requires exactly one of --from or a legacy product subcommand"
                ),
            };
            match format {
                OutputFormat::Human => println!("{}", render_init_report(&report)?),
                OutputFormat::Json => print_json(&report)?,
            }
        }
        Commands::Add { command } => match command {
            AddCommand::Notary => {
                let image_lock = registryctl::load_registryctl_image_lock()?;
                print_json(&registryctl::add_notary_to_project(
                    &std::env::current_dir()?,
                    &image_lock,
                )?)?;
            }
        },
        Commands::Test {
            project_dir,
            environment,
            live,
            integration,
            fixture,
            trace,
            watch,
        } => {
            if watch {
                return watch_project_tests(
                    ProjectTestOptions {
                        project_directory: project_dir,
                        environment,
                        live,
                    },
                    ProjectTestSelection {
                        integration,
                        fixture,
                        trace,
                    },
                );
            }
            print_json(&registryctl::test_registry_project_selected(
                &ProjectTestOptions {
                    project_directory: project_dir,
                    environment,
                    live,
                },
                &ProjectTestSelection {
                    integration,
                    fixture,
                    trace,
                },
            )?)?
        }
        Commands::Check {
            project_dir,
            environment,
            explain,
            format,
            against,
            anchor,
        } => {
            let report = registryctl::check_registry_project(&ProjectCheckOptions {
                project_directory: project_dir,
                environment,
                explain: explain || format == OutputFormat::Human,
                against,
                anchor,
            });
            let report = match report {
                Ok(report) => report,
                Err(error) => {
                    if let Some(report) =
                        error.downcast_ref::<registryctl::ProjectAuthoringDiagnostics>()
                    {
                        match format {
                            OutputFormat::Human => println!(
                                "{}",
                                registryctl::render_project_authoring_diagnostics(report)
                            ),
                            OutputFormat::Json => print_json(report)?,
                        }
                        std::process::exit(1);
                    }
                    return Err(error);
                }
            };
            match format {
                OutputFormat::Human => {
                    println!("{}", render_check_report(&report, explain)?)
                }
                OutputFormat::Json => print_json(&report)?,
            }
        }
        Commands::Authoring { command } => match command {
            AuthoringCommand::Xw { format } => match format {
                XwFormat::Reference => print!(
                    "{}",
                    registry_relay::rhai_worker::xw::generated_function_reference()
                ),
                XwFormat::Editor => print!(
                    "{}",
                    registry_relay::rhai_worker::xw::generated_editor_metadata()
                ),
            },
            AuthoringCommand::Schema { kind } => print!("{}", kind.document()),
            AuthoringCommand::Editor { project_dir } => print_json(
                &registryctl::setup_registry_project_editor(&ProjectEditorSetupOptions {
                    project_directory: project_dir,
                })?,
            )?,
        },
        Commands::Build {
            project_dir,
            environment,
            against,
            anchor,
        } => print_json(&registryctl::build_registry_project(
            &ProjectBuildOptions {
                project_directory: project_dir,
                environment,
                against,
                anchor,
            },
        )?)?,
        Commands::Start => registryctl::start_project(&std::env::current_dir()?)?,
        Commands::Stop => registryctl::stop_project(&std::env::current_dir()?)?,
        Commands::Restart => registryctl::restart_project(&std::env::current_dir()?)?,
        Commands::Status => registryctl::status_project(&std::env::current_dir()?)?,
        Commands::Open => registryctl::open_project(&std::env::current_dir()?)?,
        Commands::Smoke => registryctl::smoke_project(&std::env::current_dir()?)?,
        Commands::Doctor { format, profile } => {
            registryctl::doctor_project(&std::env::current_dir()?, format, profile)?
        }
        Commands::Logs => registryctl::logs_project(&std::env::current_dir()?)?,
        Commands::Bundle { command } => match command {
            BundleCommand::Inspect { bundle_dir } => {
                print_json(&registryctl::inspect_config_bundle(&bundle_dir)?)?;
            }
            BundleCommand::Verify {
                bundle_dir,
                anchor_path,
            } => {
                print_json(&registryctl::verify_config_bundle_cli(
                    &bundle_dir,
                    &anchor_path,
                )?)?;
            }
            BundleCommand::Sign {
                input,
                key,
                product,
                environment,
                stream_id,
                instance_id,
                sequence,
                bundle_id,
                out,
            } => {
                print_json(&registryctl::sign_config_bundle(BundleSignOptions {
                    input,
                    key,
                    product,
                    environment,
                    stream_id,
                    instance_id,
                    sequence,
                    bundle_id,
                    out,
                })?)?;
            }
        },
        Commands::Anchor { command } => match command {
            AnchorCommand::Init {
                anchor_path,
                product,
                environment,
                stream_id,
                instance_id,
            } => {
                print_json(&registryctl::init_config_anchor(
                    &anchor_path,
                    product,
                    environment,
                    stream_id,
                    instance_id,
                )?)?;
            }
            AnchorCommand::AddKey {
                anchor_path,
                jwk_path,
                disabled,
            } => {
                print_json(&registryctl::add_config_anchor_key(
                    &anchor_path,
                    &jwk_path,
                    !disabled,
                )?)?;
            }
            AnchorCommand::RemoveKey { anchor_path, kid } => {
                print_json(&registryctl::remove_config_anchor_key(&anchor_path, &kid)?)?;
            }
        },
        Commands::Bruno { command } => match command {
            BrunoCommand::Generate { force } => {
                let collection =
                    registryctl::bruno_generate_project(&std::env::current_dir()?, force)?;
                println!("Bruno collection: {}", human_path(&collection));
            }
            BrunoCommand::Open => registryctl::bruno_open_project(&std::env::current_dir()?)?,
            BrunoCommand::Run => registryctl::bruno_run_project(&std::env::current_dir()?)?,
        },
    }
    Ok(())
}

fn watch_project_tests(options: ProjectTestOptions, selection: ProjectTestSelection) -> Result<()> {
    watch_project_tests_until(options, selection, |_, _| Ok(false))
}

fn watch_project_tests_until(
    options: ProjectTestOptions,
    selection: ProjectTestSelection,
    mut should_stop_after_observation: impl FnMut(usize, &std::path::Path) -> Result<bool>,
) -> Result<()> {
    let mut completed_runs = 0;
    loop {
        let report = registryctl::test_registry_project_selected(&options, &selection)?;
        println!("{}", render_test_summary(&report));
        let observed = project_watch_fingerprint(&options.project_directory)?;
        completed_runs += 1;
        if should_stop_after_observation(completed_runs, &options.project_directory)? {
            return Ok(());
        }
        loop {
            std::thread::sleep(std::time::Duration::from_millis(250));
            if project_watch_fingerprint(&options.project_directory)? != observed {
                break;
            }
        }
    }
}

fn project_watch_fingerprint(
    root: &std::path::Path,
) -> Result<Vec<(PathBuf, u64, Option<std::time::SystemTime>)>> {
    fn visit(
        root: &std::path::Path,
        directory: &std::path::Path,
        values: &mut Vec<(PathBuf, u64, Option<std::time::SystemTime>)>,
    ) -> Result<()> {
        for entry in std::fs::read_dir(directory)
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
            let metadata = std::fs::symlink_metadata(&path)?;
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

fn is_exact_internal_mode(expected: &str) -> bool {
    let mut args = std::env::args_os();
    let _program = args.next();
    args.next().as_deref() == Some(std::ffi::OsStr::new(expected)) && args.next().is_none()
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).context("failed to render JSON output")?
    );
    Ok(())
}

fn render_init_report(report: &InitReport) -> Result<String> {
    use std::fmt::Write as _;

    let project_kind = match report.project_kind {
        InitProjectKind::RegistryProject => "Registry Stack project",
        InitProjectKind::RelaySpreadsheetApi => "Relay spreadsheet API",
    };
    let mut output = String::new();
    writeln!(output, "Initialized {project_kind} {:?}.", report.project)?;
    writeln!(output, "  Directory: {}", human_path(&report.output))?;
    match &report.source {
        InitSource::Starter {
            id,
            release,
            content_state,
            ..
        } => {
            writeln!(output, "  Starter: {id} (Registry Stack {release})")?;
            writeln!(output, "  Starter content: {content_state} bundled digest")?;
        }
        InitSource::Sample { id } => writeln!(output, "  Sample: {id}")?,
    }
    if let Some(collection) = &report.artifacts.bruno_collection {
        writeln!(output, "  Bruno collection: {}", human_path(collection))?;
    }
    if let Some(manifest) = &report.artifacts.editor_manifest {
        writeln!(
            output,
            "  Editor support: VS Code and Zed ({})",
            human_path(manifest)
        )?;
    }

    writeln!(output, "\nNext:")?;
    if report.output != std::path::Path::new(".") {
        writeln!(output, "  cd {}", human_path(&report.output))?;
    }
    match report.project_kind {
        InitProjectKind::RegistryProject => {
            writeln!(output, "  registryctl test --project-dir .")?;
        }
        InitProjectKind::RelaySpreadsheetApi => {
            writeln!(output, "  registryctl doctor --profile local --format json")?;
            writeln!(output, "  registryctl start")?;
        }
    }
    Ok(output.trim_end().to_string())
}

fn human_path(path: &std::path::Path) -> String {
    let mut value = path.display().to_string();
    if path.is_relative() && value.starts_with('-') {
        value.insert_str(0, "./");
    }
    if !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/._-".contains(character))
    {
        value
    } else {
        let mut escaped = String::with_capacity(value.len());
        for character in value.chars() {
            match character {
                '\\' => escaped.push_str("\\\\"),
                '\'' => escaped.push_str("\\'"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                character if character.is_control() => {
                    use std::fmt::Write as _;
                    write!(escaped, "\\u{:04x}", character as u32)
                        .expect("writing to a String cannot fail");
                }
                character => escaped.push(character),
            }
        }
        format!("$'{escaped}'")
    }
}

fn render_test_summary(report: &ProjectCommandReport) -> String {
    let passed = report
        .fixtures
        .iter()
        .filter(|fixture| fixture.passed)
        .count();
    let failed = report.fixtures.len().saturating_sub(passed);
    let mut output = format!(
        "{}: {passed}/{} fixtures passed",
        if failed == 0 { "PASS" } else { "FAIL" },
        report.fixtures.len()
    );
    for fixture in report.fixtures.iter().filter(|fixture| !fixture.passed) {
        output.push_str(&format!(
            "\n  {}.{}: {}",
            fixture.integration,
            fixture.fixture,
            fixture.failure.as_deref().unwrap_or("failed")
        ));
    }
    output
}

fn render_limit(value: &serde_json::Value, unit: &str) -> String {
    let value = value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string());
    match unit {
        "" | "duration" => value,
        "calls" if value == "1" => "1 call".to_string(),
        _ => format!("{value} {unit}"),
    }
}

fn render_count(count: u64, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

fn render_check_report(report: &ProjectCommandReport, expanded: bool) -> Result<String> {
    use std::fmt::Write as _;

    let explanation = report
        .explanation
        .as_ref()
        .context("human check output requires the redacted project explanation")?;
    let mut output = String::new();
    writeln!(
        output,
        "Registry Stack project: {} ({})",
        report.project, report.status
    )?;
    writeln!(
        output,
        "Environment: {}",
        report.environment.as_deref().unwrap_or("none")
    )?;
    writeln!(output, "Baseline: {}", report.baseline)?;
    if report.semantic_changes.is_empty() {
        writeln!(
            output,
            "Semantic changes: {}",
            if report.baseline == "initial_without_baseline" {
                "not compared (initial review)"
            } else {
                "none"
            }
        )?;
    } else {
        writeln!(
            output,
            "Semantic changes: {}",
            report
                .semantic_changes
                .iter()
                .map(|change| change.dimension)
                .collect::<Vec<_>>()
                .join(", ")
        )?;
    }

    let passed = report
        .fixtures
        .iter()
        .filter(|fixture| fixture.passed)
        .count();
    writeln!(
        output,
        "Fixtures: {passed}/{} passed",
        report.fixtures.len()
    )?;
    let mut by_integration = std::collections::BTreeMap::<&str, (usize, usize)>::new();
    for fixture in &report.fixtures {
        let totals = by_integration
            .entry(fixture.integration.as_str())
            .or_default();
        totals.1 += 1;
        totals.0 += usize::from(fixture.passed);
    }
    for (integration, (passed, total)) in by_integration {
        writeln!(output, "  {integration}: {passed}/{total} passed")?;
    }

    writeln!(output, "Effective authority and limits:")?;
    if let Some(topology) = explanation
        .get("topology")
        .and_then(serde_json::Value::as_object)
    {
        let deployment = topology
            .get("deployment")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let topology_label = match deployment {
            "relay_only" => "Relay-only",
            "notary_only" => "Notary-only",
            "combined" => "Relay + Notary",
            _ => "unknown",
        };
        writeln!(output, "  topology: {topology_label}")?;
        if let Some(relay) = topology.get("relay").and_then(serde_json::Value::as_object) {
            if relay
                .get("required")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                let integrations = relay
                    .get("source_integrations")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let records_services = relay
                    .get("records_api_services")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let entities = relay
                    .get("materialized_entities")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                writeln!(
                    output,
                    "  Relay authority: {}, {}, {}",
                    render_count(integrations, "source integration", "source integrations"),
                    render_count(
                        records_services,
                        "records API service",
                        "records API services"
                    ),
                    render_count(
                        entities,
                        "materialized entity definition",
                        "materialized entity definitions"
                    ),
                )?;
            } else {
                writeln!(output, "  Relay source authority: not applicable")?;
            }
        }
        if let Some(notary) = topology
            .get("notary")
            .and_then(serde_json::Value::as_object)
        {
            if notary
                .get("required")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                let source_free_evaluation = notary
                    .get("source_free_evaluation_services")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let relay_backed = notary
                    .get("relay_backed_services")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                writeln!(
                    output,
                    "  Notary authority: {}, {}",
                    render_count(
                        source_free_evaluation,
                        "source-free evaluation service",
                        "source-free evaluation services"
                    ),
                    render_count(
                        relay_backed,
                        "compiler-pinned Relay-backed service",
                        "compiler-pinned Relay-backed services"
                    ),
                )?;
            }
        }
    }
    if let Some(integrations) = explanation
        .get("integrations")
        .and_then(serde_json::Value::as_object)
    {
        for (name, integration) in integrations {
            let capability = integration
                .get("capability")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            writeln!(output, "  {name}: capability={capability}")?;
            if let Some(bounds) = integration
                .get("bounds")
                .and_then(serde_json::Value::as_object)
            {
                let rendered = bounds
                    .iter()
                    .map(|(name, bound)| {
                        let value = bound.get("value").unwrap_or(&serde_json::Value::Null);
                        let unit = bound
                            .get("unit")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("");
                        let source = bound
                            .get("source")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("intrinsic");
                        format!("{name}={} ({source})", render_limit(value, unit))
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(output, "    limits: {rendered}")?;
            }
            if let Some(operations) = integration
                .get("operations")
                .and_then(serde_json::Value::as_array)
            {
                writeln!(
                    output,
                    "    authority: {} bounded operation(s)",
                    operations.len()
                )?;
                if expanded {
                    for operation in operations {
                        writeln!(
                            output,
                            "      {} {} {}",
                            operation
                                .get("method")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("READ"),
                            operation
                                .get("destination")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("source"),
                            operation
                                .get("path")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("/")
                        )?;
                    }
                }
            } else if let Some(authority) = integration.get("script_authority") {
                let rules = authority
                    .get("allow")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, Vec::len);
                writeln!(
                    output,
                    "    authority: reviewed script with {rules} source allow rule(s)"
                )?;
            } else if capability == "snapshot" {
                writeln!(
                    output,
                    "    authority: exact local materialized snapshot read"
                )?;
            }
            for (field, label) in [
                ("ambiguity", "ambiguity"),
                ("subject_mismatch", "subject mismatch"),
            ] {
                let Some(reason) = integration
                    .pointer(&format!("/not_applicable/{field}"))
                    .and_then(serde_json::Value::as_object)
                else {
                    continue;
                };
                writeln!(
                    output,
                    "    {label} not applicable: {} [request fixture: {}]",
                    reason
                        .get("rationale")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("missing rationale"),
                    reason
                        .get("request_fixture")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("missing")
                )?;
            }
            if expanded {
                let outputs = integration
                    .get("outputs")
                    .and_then(serde_json::Value::as_object)
                    .map(|values| values.keys().cloned().collect::<Vec<_>>().join(", "))
                    .unwrap_or_else(|| "none".to_string());
                writeln!(output, "    outputs: {outputs}")?;
            }
        }
    }
    if expanded {
        writeln!(output, "Claims and disclosure:")?;
        if let Some(services) = explanation
            .get("services")
            .and_then(serde_json::Value::as_object)
        {
            for (service, declaration) in services {
                writeln!(output, "  {service}:")?;
                if let Some(claims) = declaration
                    .get("claims")
                    .and_then(serde_json::Value::as_object)
                {
                    for (claim, value) in claims {
                        writeln!(
                            output,
                            "    {claim}: disclosure={}",
                            value
                                .get("disclosure")
                                .map(serde_json::Value::to_string)
                                .unwrap_or_else(|| "null".to_string())
                        )?;
                    }
                }
            }
        }
    }
    writeln!(
        output,
        "Rhai xw.v1 reference: registryctl authoring xw --format reference"
    )?;
    Ok(output.trim_end().to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum XwFormat {
    Reference,
    Editor,
}

#[derive(Debug, Subcommand)]
enum AuthoringCommand {
    /// Print the generated xw.v1 function reference or editor metadata.
    Xw {
        #[arg(long, value_enum, default_value = "reference")]
        format: XwFormat,
    },
    /// Print one strict project-authoring JSON Schema for editor integration.
    Schema {
        #[arg(long, value_enum)]
        kind: ProjectSchemaKind,
    },
    /// Install deterministic local schema mappings for VS Code and Zed.
    Editor {
        /// Project workspace root containing registry-stack.yaml.
        #[arg(long, default_value = ".")]
        project_dir: PathBuf,
    },
}

#[derive(Debug, Parser)]
#[command(name = "registryctl")]
#[command(version)]
#[command(about = "Create and run local Registry Stack projects")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Check whether a newer registryctl release is available.
    UpdateCheck,
    /// Refresh the update-check cache in a detached child process.
    #[command(name = "__update-check-refresh", hide = true)]
    UpdateCheckRefresh,
    /// Create a local Registry Stack project.
    Init {
        /// Copy a tested project integration starter into a local workspace.
        #[arg(long, value_enum)]
        from: Option<ProjectStarter>,
        /// Destination for a project workspace initialized with --from.
        #[arg(long, default_value = ".")]
        project_dir: PathBuf,
        /// Human-readable result, or machine-readable JSON.
        #[arg(long, value_enum, default_value = "human", global = true)]
        format: OutputFormat,
        #[command(subcommand)]
        command: Option<Box<InitCommand>>,
    },
    /// Add another local Registry Stack product to the current project.
    Add {
        #[command(subcommand)]
        command: AddCommand,
    },
    /// Run every project integration fixture offline.
    Test {
        /// Project workspace root.
        #[arg(long, default_value = ".")]
        project_dir: PathBuf,
        /// Optional environment for environment-sensitive validation.
        #[arg(long)]
        environment: Option<String>,
        /// Use the deployed governed path. Direct registry access is never performed.
        #[arg(long)]
        live: bool,
        /// Run fixtures for one integration id.
        #[arg(long)]
        integration: Option<String>,
        /// Run one named fixture within the selected integration.
        #[arg(long, requires = "integration")]
        fixture: Option<String>,
        /// Include the safe synthetic interaction trace in the report.
        #[arg(long)]
        trace: bool,
        /// Rerun the selected offline scope when authored files change.
        #[arg(long, conflicts_with_all = ["live", "trace"])]
        watch: bool,
    },
    /// Validate and explain generated Relay and Notary configuration.
    Check {
        /// Project workspace root.
        #[arg(long, default_value = ".")]
        project_dir: PathBuf,
        /// Explicit environment binding.
        #[arg(long)]
        environment: String,
        /// Print the complete redacted acquisition and disclosure plan.
        #[arg(long)]
        explain: bool,
        /// Human-readable review report, or deliberate machine-readable JSON.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
        /// Previously signed product Config Bundle with review and internal approval state.
        #[arg(long)]
        against: Option<PathBuf>,
        /// Trust anchor for --against.
        #[arg(long)]
        anchor: Option<PathBuf>,
    },
    /// Inspect project-authoring references and schemas.
    Authoring {
        #[command(subcommand)]
        command: AuthoringCommand,
    },
    /// Emit deterministic unsigned Relay and Notary Config Bundle inputs.
    Build {
        /// Project workspace root.
        #[arg(long, default_value = ".")]
        project_dir: PathBuf,
        /// Explicit environment binding.
        #[arg(long)]
        environment: String,
        /// Previously signed product Config Bundle with review and internal approval state.
        #[arg(long)]
        against: Option<PathBuf>,
        /// Trust anchor for --against.
        #[arg(long)]
        anchor: Option<PathBuf>,
    },
    /// Start the local Registry Stack project.
    Start,
    /// Stop the local Registry Stack project.
    Stop,
    /// Restart the local Registry Stack project so config edits take effect.
    Restart,
    /// Print local runtime status.
    Status,
    /// Open or print the local API docs URL.
    Open,
    /// Run built-in local smoke checks.
    Smoke,
    /// Run product doctor validation and print a JSON report.
    Doctor {
        /// Deployment profile override to pass through to product doctor commands.
        #[arg(long, value_enum)]
        profile: Option<DeploymentProfile>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = DoctorFormat::Json)]
        format: DoctorFormat,
    },
    /// Stream Compose logs for the local project.
    Logs,
    /// Work with Registry Config Bundle directories.
    Bundle {
        #[command(subcommand)]
        command: BundleCommand,
    },
    /// Work with Registry Config Bundle trust anchors.
    Anchor {
        #[command(subcommand)]
        command: AnchorCommand,
    },
    /// Work with the optional generated Bruno API collection.
    Bruno {
        #[command(subcommand)]
        command: BrunoCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AddCommand {
    /// Add a local Notary and private consultation Relay over the benefits workbook.
    Notary,
}

impl Commands {
    fn should_check_for_updates(&self) -> bool {
        !matches!(
            self,
            Self::Doctor { .. }
                | Self::Authoring { .. }
                | Self::Bundle { .. }
                | Self::Anchor { .. }
                | Self::UpdateCheck
                | Self::UpdateCheckRefresh
        )
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    #[test]
    fn project_authoring_cli_accepts_the_documented_commands() {
        let init = Cli::try_parse_from([
            "registryctl",
            "init",
            "--from",
            "http",
            "--project-dir",
            "registry-project",
        ])
        .unwrap();
        assert!(matches!(
            init.command,
            Commands::Init {
                from: Some(ProjectStarter::Http),
                project_dir,
                format: OutputFormat::Human,
                command: None,
            } if project_dir == std::path::Path::new("registry-project")
        ));

        let relay_init = Cli::try_parse_from([
            "registryctl",
            "init",
            "relay",
            "my-first-api",
            "--format",
            "json",
        ])
        .unwrap();
        assert!(matches!(
            relay_init.command,
            Commands::Init {
                from: None,
                format: OutputFormat::Json,
                command: Some(command),
                ..
            } if matches!(command.as_ref(), InitCommand::Relay { dir, .. }
                if dir == std::path::Path::new("my-first-api"))
        ));

        let test = Cli::try_parse_from([
            "registryctl",
            "test",
            "--project-dir",
            "registry-project",
            "--environment",
            "staging",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            test.command,
            Commands::Test {
                project_dir,
                environment: Some(environment),
                live: true,
                integration: None,
                fixture: None,
                trace: false,
                watch: false,
            } if project_dir == std::path::Path::new("registry-project") && environment == "staging"
        ));

        let watch = Cli::try_parse_from([
            "registryctl",
            "test",
            "--project-dir",
            "registry-project",
            "--integration",
            "person-record",
            "--fixture",
            "active-person",
            "--watch",
        ])
        .unwrap();
        assert!(matches!(
            watch.command,
            Commands::Test {
                project_dir,
                environment: None,
                live: false,
                integration: Some(integration),
                fixture: Some(fixture),
                trace: false,
                watch: true,
            } if project_dir == std::path::Path::new("registry-project")
                && integration == "person-record"
                && fixture == "active-person"
        ));

        assert!(Cli::try_parse_from([
            "registryctl",
            "test",
            "--project-dir",
            "registry-project",
            "--trace",
            "--watch",
        ])
        .is_err());

        let check = Cli::try_parse_from([
            "registryctl",
            "check",
            "--project-dir",
            "registry-project",
            "--environment",
            "staging",
            "--explain",
            "--against",
            "baseline",
            "--anchor",
            "anchor.json",
        ])
        .unwrap();
        assert!(matches!(
            check.command,
            Commands::Check {
                project_dir,
                environment,
                explain: true,
                format: OutputFormat::Human,
                against: Some(against),
                anchor: Some(anchor),
            } if project_dir == std::path::Path::new("registry-project")
                && environment == "staging"
                && against == std::path::Path::new("baseline")
                && anchor == std::path::Path::new("anchor.json")
        ));

        let json_check = Cli::try_parse_from([
            "registryctl",
            "check",
            "--project-dir",
            "registry-project",
            "--environment",
            "staging",
            "--format",
            "json",
        ])
        .unwrap();
        assert!(matches!(
            json_check.command,
            Commands::Check {
                format: OutputFormat::Json,
                explain: false,
                ..
            }
        ));

        assert!(Cli::try_parse_from([
            "registryctl",
            "test",
            "--integration",
            "person-record",
            "--trace",
            "--watch",
        ])
        .is_err());

        let xw =
            Cli::try_parse_from(["registryctl", "authoring", "xw", "--format", "editor"]).unwrap();
        assert!(matches!(
            xw.command,
            Commands::Authoring {
                command: AuthoringCommand::Xw {
                    format: XwFormat::Editor
                }
            }
        ));

        let schema = Cli::try_parse_from([
            "registryctl",
            "authoring",
            "schema",
            "--kind",
            "integration",
        ])
        .unwrap();
        assert!(matches!(
            schema.command,
            Commands::Authoring {
                command: AuthoringCommand::Schema {
                    kind: ProjectSchemaKind::Integration
                }
            }
        ));
        let schema_document: serde_json::Value =
            serde_json::from_str(ProjectSchemaKind::Integration.document()).unwrap();
        assert_eq!(
            schema_document["title"],
            "Registry Stack project integration v1"
        );

        let editor = Cli::try_parse_from([
            "registryctl",
            "authoring",
            "editor",
            "--project-dir",
            "registry-project",
        ])
        .unwrap();
        assert!(matches!(
            editor.command,
            Commands::Authoring {
                command: AuthoringCommand::Editor { project_dir }
            } if project_dir == std::path::Path::new("registry-project")
        ));
        let default_editor = Cli::try_parse_from(["registryctl", "authoring", "editor"]).unwrap();
        assert!(matches!(
            default_editor.command,
            Commands::Authoring {
                command: AuthoringCommand::Editor { project_dir }
            } if project_dir == std::path::Path::new(".")
        ));

        let build = Cli::try_parse_from([
            "registryctl",
            "build",
            "--project-dir",
            "registry-project",
            "--environment",
            "staging",
        ])
        .unwrap();
        assert!(matches!(
            build.command,
            Commands::Build {
                project_dir,
                environment,
                against: None,
                anchor: None,
            } if project_dir == std::path::Path::new("registry-project") && environment == "staging"
        ));
    }

    #[test]
    fn project_authoring_cli_has_no_country_compatibility_alias() {
        assert!(Cli::try_parse_from([
            "registryctl",
            "init",
            "--from",
            "http",
            "--country-dir",
            "registry-project",
        ])
        .is_err());
    }

    #[test]
    fn project_authoring_cli_has_no_pre_freeze_project_path_alias() {
        assert!(
            Cli::try_parse_from(["registryctl", "test", "--project", "registry-project",]).is_err()
        );
    }

    #[test]
    fn human_check_report_is_concise_and_explain_adds_review_detail() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project_directory = temporary.path().join("registry-project");
        registryctl::init_registry_project(&ProjectInitOptions {
            starter: ProjectStarter::Http,
            directory: project_directory.clone(),
        })
        .expect("starter initializes");
        let report = registryctl::check_registry_project(&ProjectCheckOptions {
            project_directory,
            environment: "local".to_string(),
            explain: true,
            against: None,
            anchor: None,
        })
        .expect("starter checks");
        let concise = render_check_report(&report, false).expect("concise report renders");
        for heading in [
            "Baseline:",
            "Semantic changes:",
            "Fixtures:",
            "Effective authority and limits:",
            "Rhai xw.v1 reference:",
        ] {
            assert!(concise.contains(heading), "missing {heading}: {concise}");
        }
        assert!(!concise.contains("Claims and disclosure:"));
        assert!(concise.contains("topology: Relay + Notary"));
        assert!(concise.contains("calls=1 call"));
        assert!(concise.contains("deadline=15s"));
        assert!(!concise.contains("1calls"));
        assert!(!concise.contains("\"15s\"duration"));
        assert!(concise.contains("subject mismatch not applicable:"));
        assert!(!concise.contains("ambiguity not applicable: missing rationale"));
        let expanded = render_check_report(&report, true).expect("expanded report renders");
        assert!(expanded.contains("outputs:"));
        assert!(expanded.contains("Claims and disclosure:"));
    }

    #[test]
    fn human_check_report_identifies_single_product_topologies_and_authority() {
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/project-authoring");
        let relay_report = registryctl::check_registry_project(&ProjectCheckOptions {
            project_directory: fixtures.join("relay-only-records"),
            environment: "local".to_string(),
            explain: true,
            against: None,
            anchor: None,
        })
        .expect("Relay-only project checks");
        let relay_rendered = render_check_report(&relay_report, false).expect("report renders");
        assert!(relay_rendered.contains("topology: Relay-only"));
        assert!(relay_rendered.contains(
            "Relay authority: 0 source integrations, 1 records API service, 1 materialized entity definition"
        ));

        let notary_report = registryctl::check_registry_project(&ProjectCheckOptions {
            project_directory: fixtures.join("notary-only-evaluation"),
            environment: "local".to_string(),
            explain: true,
            against: None,
            anchor: None,
        })
        .expect("Notary-only evaluation project checks");
        let notary_rendered = render_check_report(&notary_report, false).expect("report renders");
        assert!(notary_rendered.contains("topology: Notary-only"));
        assert!(notary_rendered.contains(
            "Notary authority: 1 source-free evaluation service, 0 compiler-pinned Relay-backed services"
        ));
        assert!(notary_rendered.contains("Relay source authority: not applicable"));
    }

    #[test]
    fn project_test_watch_reruns_each_maintained_fixture_journey_after_an_authored_change() {
        fn copy_directory(source: &std::path::Path, destination: &std::path::Path) -> Result<()> {
            std::fs::create_dir_all(destination)?;
            for entry in std::fs::read_dir(source)? {
                let entry = entry?;
                let target = destination.join(entry.file_name());
                if entry.file_type()?.is_dir() {
                    copy_directory(&entry.path(), &target)?;
                } else {
                    std::fs::copy(entry.path(), target)?;
                }
            }
            Ok(())
        }

        let manifest_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let repository_root = manifest_root.join("../..");
        let catalog: serde_yaml::Value = serde_yaml::from_slice(
            &std::fs::read(manifest_root.join("tests/fixtures/project-authoring-journeys.yaml"))
                .expect("project-authoring journey catalog reads"),
        )
        .expect("project-authoring journey catalog parses");
        let mut journeys = Vec::new();
        for workspace in catalog["workspaces"]
            .as_sequence()
            .expect("catalog workspaces")
        {
            if !workspace["steps"]
                .as_sequence()
                .expect("catalog steps")
                .iter()
                .any(|step| step.as_str() == Some("watch"))
            {
                continue;
            }
            assert_eq!(
                workspace["classification"].as_str(),
                Some("maintained"),
                "watch is a maintained authoring journey"
            );
            let starter = workspace["starter"].as_str().map(|starter| match starter {
                "http" => ProjectStarter::Http,
                "dhis2-tracker" => ProjectStarter::Dhis2Tracker,
                "opencrvs-dci" => ProjectStarter::OpencrvsDci,
                "fhir-r4" => ProjectStarter::FhirR4,
                "snapshot" => ProjectStarter::Snapshot,
                other => panic!("unknown catalog starter {other}"),
            });
            let id = workspace["id"].as_str().expect("watch id").to_string();
            let project_dir = workspace["project_dir"]
                .as_str()
                .expect("watch project directory")
                .to_string();
            let source = repository_root.join(
                workspace["source"]
                    .as_str()
                    .expect("catalog workspace source"),
            );
            let project: serde_yaml::Value = serde_yaml::from_slice(
                &std::fs::read(source.join("registry-stack.yaml")).expect("catalog project reads"),
            )
            .expect("catalog project parses");
            let integrations = project["integrations"]
                .as_mapping()
                .expect("watch journey integrations");
            assert_eq!(integrations.len(), 1, "watch journey integration");
            let (integration, reference) = integrations.iter().next().expect("watch integration");
            let integration = integration.as_str().expect("integration id").to_string();
            let integration_file = reference["file"].as_str().expect("integration file");
            let fixture_file = workspace["focused_fixture_file"]
                .as_str()
                .expect("focused fixture file");
            let fixture_path = source
                .join(integration_file)
                .parent()
                .expect("integration directory")
                .join("fixtures")
                .join(fixture_file);
            let fixture: serde_yaml::Value =
                serde_yaml::from_slice(&std::fs::read(fixture_path).expect("watch fixture reads"))
                    .expect("watch fixture parses");
            journeys.push((
                id,
                starter,
                source,
                project_dir,
                integration,
                fixture["name"]
                    .as_str()
                    .expect("watch fixture name")
                    .to_string(),
            ));
        }
        assert_eq!(
            journeys.len(),
            9,
            "every maintained fixture journey watches"
        );

        for (id, starter, source, project_dir, integration, fixture) in journeys {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let project_directory = temporary.path().join(project_dir);
            if let Some(starter) = starter {
                registryctl::init_registry_project(&ProjectInitOptions {
                    starter,
                    directory: project_directory.clone(),
                })
                .expect("maintained starter initializes");
            } else {
                copy_directory(&source, &project_directory).expect("maintained non-starter copies");
            }

            let mut observed_runs = 0;
            watch_project_tests_until(
                ProjectTestOptions {
                    project_directory: project_directory.clone(),
                    environment: None,
                    live: false,
                },
                ProjectTestSelection {
                    integration: Some(integration),
                    fixture: Some(fixture),
                    trace: false,
                },
                |completed_runs, root| {
                    observed_runs = completed_runs;
                    if completed_runs == 1 {
                        use std::io::Write as _;

                        writeln!(
                            std::fs::OpenOptions::new()
                                .append(true)
                                .open(root.join("registry-stack.yaml"))?,
                            "# deterministic watch smoke"
                        )?;
                        Ok(false)
                    } else {
                        Ok(true)
                    }
                },
            )
            .expect("offline watch reruns after an authored project file changes");
            assert_eq!(observed_runs, 2, "{id}");
        }
    }

    #[test]
    fn project_init_rejects_removed_mixed_mode_and_preserves_missing_dispatch_check() {
        assert!(Cli::try_parse_from([
            "registryctl",
            "init",
            "--from",
            "opencrvs",
            "notary",
            "legacy",
        ])
        .is_err());

        let missing = Cli::try_parse_from(["registryctl", "init"]).unwrap();
        assert!(matches!(
            missing.command,
            Commands::Init {
                from: None,
                command: None,
                ..
            }
        ));
    }

    #[test]
    fn doctor_cli_accepts_profile_and_json_format() {
        let cli = Cli::try_parse_from([
            "registryctl",
            "doctor",
            "--profile",
            "local",
            "--format",
            "json",
        ])
        .unwrap();

        let Commands::Doctor { format, profile } = cli.command else {
            panic!("expected doctor command");
        };
        assert_eq!(format, DoctorFormat::Json);
        assert_eq!(profile, Some(DeploymentProfile::Local));
    }

    #[test]
    fn update_check_cli_parses() {
        let cli = Cli::try_parse_from(["registryctl", "update-check"]).unwrap();

        assert!(matches!(cli.command, Commands::UpdateCheck));
    }

    #[test]
    fn restart_cli_parses() {
        let cli = Cli::try_parse_from(["registryctl", "restart"]).unwrap();

        assert!(matches!(cli.command, Commands::Restart));
    }

    #[test]
    fn add_notary_cli_parses() {
        let cli = Cli::try_parse_from(["registryctl", "add", "notary"]).unwrap();

        assert!(matches!(
            cli.command,
            Commands::Add {
                command: AddCommand::Notary
            }
        ));
    }

    #[test]
    fn legacy_notary_authoring_commands_are_removed() {
        assert!(Cli::try_parse_from(["registryctl", "init", "notary", "project"]).is_err());
        assert!(
            Cli::try_parse_from(["registryctl", "add", "notary", "--from", "local-relay",])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["registryctl", "openfn", "convert", "workflow.yaml"]).is_err()
        );
    }

    #[test]
    fn doctor_skips_automatic_update_check() {
        let cli = Cli::try_parse_from(["registryctl", "doctor"]).unwrap();

        assert!(!cli.command.should_check_for_updates());
    }

    #[test]
    fn hidden_update_refresh_skips_automatic_update_check() {
        let cli = Cli::try_parse_from(["registryctl", "__update-check-refresh"]).unwrap();

        assert!(matches!(cli.command, Commands::UpdateCheckRefresh));
        assert!(!cli.command.should_check_for_updates());
    }

    #[test]
    fn bundle_cli_accepts_inspect_verify_and_sign() {
        let inspect =
            Cli::try_parse_from(["registryctl", "bundle", "inspect", "--bundle-dir", "bundle"])
                .unwrap();
        assert!(matches!(
            inspect.command,
            Commands::Bundle {
                command: BundleCommand::Inspect { .. }
            }
        ));
        assert!(!inspect.command.should_check_for_updates());

        let verify = Cli::try_parse_from([
            "registryctl",
            "bundle",
            "verify",
            "--bundle-dir",
            "bundle",
            "--anchor-path",
            "trust_anchor.json",
        ])
        .unwrap();
        assert!(matches!(
            verify.command,
            Commands::Bundle {
                command: BundleCommand::Verify { .. }
            }
        ));

        let sign = Cli::try_parse_from([
            "registryctl",
            "bundle",
            "sign",
            "--input",
            "input",
            "--key",
            "private.jwk",
            "--product",
            "registry-notary",
            "--environment",
            "production",
            "--stream-id",
            "civil-registry",
            "--sequence",
            "42",
            "--bundle-id",
            "2026-07-07-rollout-3",
            "--out",
            "bundle",
        ])
        .unwrap();
        assert!(matches!(
            sign.command,
            Commands::Bundle {
                command: BundleCommand::Sign { .. }
            }
        ));
    }

    #[test]
    fn anchor_cli_accepts_init_add_key_and_remove_key() {
        let init = Cli::try_parse_from([
            "registryctl",
            "anchor",
            "init",
            "--anchor-path",
            "trust_anchor.json",
            "--product",
            "registry-notary",
            "--environment",
            "production",
            "--stream-id",
            "civil-registry",
            "--instance-id",
            "notary-011",
        ])
        .unwrap();
        assert!(matches!(
            init.command,
            Commands::Anchor {
                command: AnchorCommand::Init { .. }
            }
        ));
        assert!(!init.command.should_check_for_updates());

        let add = Cli::try_parse_from([
            "registryctl",
            "anchor",
            "add-key",
            "--anchor-path",
            "trust_anchor.json",
            "--jwk-path",
            "public.jwk",
            "--disabled",
        ])
        .unwrap();
        assert!(matches!(
            add.command,
            Commands::Anchor {
                command: AnchorCommand::AddKey { disabled: true, .. }
            }
        ));

        let remove = Cli::try_parse_from([
            "registryctl",
            "anchor",
            "remove-key",
            "--anchor-path",
            "trust_anchor.json",
            "--kid",
            "kid-1",
        ])
        .unwrap();
        assert!(matches!(
            remove.command,
            Commands::Anchor {
                command: AnchorCommand::RemoveKey { .. }
            }
        ));
    }
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum InitCommand {
    /// Create a local Relay-backed spreadsheet API project.
    Relay {
        /// Directory to create.
        dir: PathBuf,
        /// Sample project to generate.
        #[arg(long, value_enum, default_value_t = Sample::Benefits)]
        sample: Sample,
    },
    /// Create a local Relay-backed spreadsheet API project.
    #[command(name = "spreadsheet-api", hide = true)]
    SpreadsheetApi {
        /// Directory to create.
        dir: PathBuf,
        /// Sample project to generate.
        #[arg(long, value_enum, default_value_t = Sample::Benefits)]
        sample: Sample,
    },
}

#[derive(Debug, Subcommand)]
enum BundleCommand {
    /// Inspect a Registry Config Bundle manifest and signature metadata.
    Inspect {
        /// Bundle directory containing manifest.json and config files.
        #[arg(long)]
        bundle_dir: PathBuf,
    },
    /// Verify a Registry Config Bundle against a trust anchor.
    Verify {
        /// Bundle directory containing manifest.json, manifest.sig.json, and config files.
        #[arg(long)]
        bundle_dir: PathBuf,
        /// Trust anchor JSON path.
        #[arg(long)]
        anchor_path: PathBuf,
    },
    /// Build and sign a Registry Config Bundle from an input directory.
    Sign {
        /// Directory containing config files to package.
        #[arg(long)]
        input: PathBuf,
        /// Private JWK path or op:// reference.
        #[arg(long)]
        key: String,
        /// Product binding, for example registry-notary.
        #[arg(long)]
        product: String,
        /// Environment binding, for example production.
        #[arg(long)]
        environment: String,
        /// Stream binding.
        #[arg(long = "stream-id")]
        stream_id: String,
        /// Optional instance binding.
        #[arg(long = "instance-id")]
        instance_id: Option<String>,
        /// Monotonic bundle sequence.
        #[arg(long)]
        sequence: u64,
        /// Bundle identifier.
        #[arg(long = "bundle-id")]
        bundle_id: String,
        /// Output bundle directory to create.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AnchorCommand {
    /// Initialize a Registry Config Bundle trust anchor file.
    Init {
        /// Trust anchor JSON path to write.
        #[arg(long)]
        anchor_path: PathBuf,
        /// Product binding, for example registry-notary.
        #[arg(long)]
        product: String,
        /// Environment binding, for example production.
        #[arg(long)]
        environment: String,
        /// Stream binding.
        #[arg(long)]
        stream_id: String,
        /// Instance binding for this node.
        #[arg(long)]
        instance_id: String,
    },
    /// Add a public JWK signer to a trust anchor.
    AddKey {
        /// Trust anchor JSON path to update.
        #[arg(long)]
        anchor_path: PathBuf,
        /// Public JWK JSON path.
        #[arg(long)]
        jwk_path: PathBuf,
        /// Add the signer as disabled.
        #[arg(long)]
        disabled: bool,
    },
    /// Remove a signer from a trust anchor by key id.
    RemoveKey {
        /// Trust anchor JSON path to update.
        #[arg(long)]
        anchor_path: PathBuf,
        /// Signer key id to remove.
        #[arg(long)]
        kid: String,
    },
}

#[derive(Debug, Subcommand)]
enum BrunoCommand {
    /// Generate or refresh the optional Bruno API collection.
    Generate {
        /// Overwrite existing Bruno files even if registryctl did not generate them.
        #[arg(long)]
        force: bool,
    },
    /// Open the generated Bruno collection when Bruno is installed.
    Open,
    /// Run the generated Bruno collection when the Bruno CLI is installed.
    Run,
}
