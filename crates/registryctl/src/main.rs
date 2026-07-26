use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand, ValueEnum};

use registryctl::{
    AddNotaryReport, AnchorReport, BundleInspectReport, BundleSignOptions, BundleSignReport,
    BundleVerifyReport, ClassifierSafeReportedValue, DeploymentProfile, DoctorFormat,
    FieldSourceKind, InitProjectKind, InitReport, InitSource, MigrationDisposition,
    ProjectBuildBaselineSetOptions, ProjectBuildOptions, ProjectCapabilityInventoryReportV1,
    ProjectCapabilityOptions, ProjectCheckOptions, ProjectCommandReport, ProjectEditorSetupOptions,
    ProjectEditorSetupReport, ProjectEnvironmentSemanticComparisonOptions, ProjectExecutionContext,
    ProjectFieldAddress, ProjectFieldExplanation, ProjectInitOptions, ProjectMigrationOptions,
    ProjectMigrationReportV1, ProjectPreflightOptions, ProjectPreflightReportV1,
    ProjectPromotionOptions, ProjectPromotionReportV1, ProjectSchemaKind,
    ProjectSemanticComparisonOptions, ProjectSemanticComparisonReportV1, ProjectStarter,
    ProjectStarterSemanticComparisonOptions, ProjectTestOptions, ProjectTestSelection,
    ProjectTrustedLocalAuthoredValue, PromotionDisposition, RedactionReason, Sample,
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
            let destination = match (&from, command.as_deref()) {
                (Some(_), None) => Some(project_dir.as_path()),
                (None, Some(InitCommand::Relay { dir, .. })) => Some(dir.as_path()),
                _ => None,
            };
            if format == OutputFormat::Json
                && destination.is_some_and(|destination| destination.to_str().is_none())
            {
                anyhow::bail!("init --format json requires a UTF-8 destination path; no project files were written");
            }
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
                    }
                }
                (None, None) => Cli::command()
                    .error(
                        ErrorKind::MissingRequiredArgument,
                        "init requires exactly one of --from or the relay subcommand",
                    )
                    .exit(),
                (Some(_), Some(_)) => Cli::command()
                    .error(
                        ErrorKind::ArgumentConflict,
                        "init accepts only one of --from or the relay subcommand",
                    )
                    .exit(),
            };
            match format {
                OutputFormat::Human => println!("{}", render_init_report(&report)?),
                OutputFormat::Json => print_json(&report)?,
            }
        }
        Commands::Add { format, command } => match command {
            AddCommand::Notary => {
                let image_lock = registryctl::load_registryctl_image_lock()?;
                let report =
                    registryctl::add_notary_to_project(&std::env::current_dir()?, &image_lock)?;
                print_formatted_report(format, &report, render_add_notary_report)?;
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
            format,
        } => {
            if watch {
                if format == OutputFormat::Json {
                    anyhow::bail!("test --watch supports only human output");
                }
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
            let report = registryctl::test_registry_project_selected(
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
            )?;
            print_formatted_report(format, &report, |report| render_test_report(report, trace))?;
        }
        Commands::Check {
            project_dir,
            environment,
            explain,
            show_authored_values,
            format,
            against,
            anchor,
        } => {
            if show_authored_values && format != OutputFormat::Human {
                anyhow::bail!("--show-authored-values requires --format human");
            }
            let options = ProjectCheckOptions {
                project_directory: project_dir,
                environment,
                explain: explain || format == OutputFormat::Human,
                against,
                anchor,
            };
            let checked = if show_authored_values {
                registryctl::check_registry_project_with_trusted_local_authored_values(&options)
                    .map(|trusted| (trusted.report, Some(trusted.authored_values)))
            } else {
                registryctl::check_registry_project(&options).map(|report| (report, None))
            };
            let (report, authored_values) = match checked {
                Ok(checked) => checked,
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
                OutputFormat::Human => println!(
                    "{}",
                    render_check_report(&report, explain, authored_values.as_deref())?
                ),
                OutputFormat::Json => print_json(&report)?,
            }
        }
        Commands::Preflight {
            project_dir,
            environment,
            format,
        } => {
            let report = registryctl::preflight_registry_project(&ProjectPreflightOptions {
                project_directory: project_dir,
                environment,
            })?;
            let ready = report.status == registryctl::PreflightStatus::Ready;
            match format {
                OutputFormat::Human => println!("{}", render_preflight_report(&report)?),
                OutputFormat::Json => print_json(&report)?,
            }
            if !ready {
                std::process::exit(1);
            }
        }
        Commands::Project { command } => match command {
            ProjectCommand::Diagnostics { catalog, format } => match catalog {
                DiagnosticCatalog::Authoring => {
                    let reference = registryctl::authoring_error_reference();
                    registryctl::validate_authoring_error_reference(&reference).map_err(
                        |error| {
                            anyhow::anyhow!(
                                "authoring diagnostic reference failed closed validation: {error:?}"
                            )
                        },
                    )?;
                    match format {
                        OutputFormat::Human => println!(
                            "{}",
                            render_diagnostic_reference(
                                catalog,
                                &reference.schema_version,
                                &reference.entries,
                                &[],
                            )?
                        ),
                        OutputFormat::Json => print_json(&reference)?,
                    }
                }
                DiagnosticCatalog::Fixture => {
                    let reference = registryctl::fixture_error_reference();
                    registryctl::validate_fixture_error_reference(&reference).map_err(|error| {
                        anyhow::anyhow!(
                            "fixture diagnostic reference failed closed validation: {error:?}"
                        )
                    })?;
                    match format {
                        OutputFormat::Human => println!(
                            "{}",
                            render_diagnostic_reference(
                                catalog,
                                &reference.schema_version,
                                &reference.entries,
                                &[],
                            )?
                        ),
                        OutputFormat::Json => print_json(&reference)?,
                    }
                }
                DiagnosticCatalog::Operator => {
                    let reference = registryctl::operator_error_reference();
                    registryctl::validate_operator_error_reference(&reference).map_err(
                        |error| {
                            anyhow::anyhow!(
                                "operator diagnostic reference failed closed validation: {error:?}"
                            )
                        },
                    )?;
                    match format {
                        OutputFormat::Human => println!(
                            "{}",
                            render_diagnostic_reference(
                                catalog,
                                &reference.schema_version,
                                &reference.entries,
                                &reference.omissions,
                            )?
                        ),
                        OutputFormat::Json => print_json(&reference)?,
                    }
                }
            },
        },
        Commands::Capabilities {
            project_dir,
            environment,
            format,
        } => {
            let report = registryctl::inspect_project_capabilities(&ProjectCapabilityOptions {
                project_directory: project_dir,
                environment,
            })?;
            print_formatted_report(format, &report, render_capability_inventory)?;
        }
        Commands::Compare {
            project_dir,
            environment,
            from_project_dir,
            from_environment,
            from_starter,
            format,
        } => {
            let report = if let Some(starter) = from_starter {
                registryctl::compare_registry_project_to_embedded_starter_semantically(
                    &ProjectStarterSemanticComparisonOptions {
                        project_directory: project_dir,
                        environment,
                        starter,
                    },
                )?
            } else if let Some(baseline_environment) = from_environment {
                if let Some(baseline_project_directory) = from_project_dir {
                    registryctl::compare_registry_projects_semantically(
                        &ProjectSemanticComparisonOptions {
                            current_project_directory: project_dir,
                            current_environment: environment,
                            baseline_project_directory,
                            baseline_environment,
                        },
                    )?
                } else {
                    registryctl::compare_registry_project_environments_semantically(
                        &ProjectEnvironmentSemanticComparisonOptions {
                            project_directory: project_dir,
                            current_environment: environment,
                            baseline_environment,
                        },
                    )?
                }
            } else {
                unreachable!("clap requires exactly one semantic comparison baseline")
            };
            print_formatted_report(format, &report, render_semantic_comparison_report)?;
        }
        Commands::Promote {
            project_dir,
            environment,
            against,
            anchor,
            relay_against,
            relay_anchor,
            notary_against,
            notary_anchor,
            format,
        } => {
            let report = registryctl::promote_registry_project(&ProjectPromotionOptions {
                project_directory: project_dir,
                environment,
                against,
                anchor,
                relay_against,
                relay_anchor,
                notary_against,
                notary_anchor,
            })?;
            let ready = !matches!(report.disposition, PromotionDisposition::Blocked);
            print_formatted_report(format, &report, render_promotion_report)?;
            if !ready {
                std::process::exit(1);
            }
        }
        Commands::Migrate {
            project_dir,
            target_version,
            output,
            write_candidate,
            format,
        } => {
            let report = registryctl::migrate_registry_project(&ProjectMigrationOptions {
                project_directory: project_dir,
                target_version,
                output_directory: output,
                write_candidate,
            })?;
            let supported = !matches!(report.disposition, MigrationDisposition::Blocked);
            print_formatted_report(format, &report, render_migration_report)?;
            if !supported {
                std::process::exit(1);
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
            AuthoringCommand::Reference { coverage } => {
                if coverage {
                    let report = registryctl::embedded_configuration_reference_coverage()?;
                    let complete = report.status == registryctl::CoverageStatus::Complete;
                    print_json(&report)?;
                    if !complete {
                        std::process::exit(1);
                    }
                } else {
                    print_json(&registryctl::embedded_configuration_reference()?)?;
                }
            }
            AuthoringCommand::Editor {
                project_dir,
                format,
            } => {
                let report =
                    registryctl::setup_registry_project_editor(&ProjectEditorSetupOptions {
                        project_directory: project_dir,
                    })?;
                print_formatted_report(format, &report, render_editor_setup_report)?;
            }
            AuthoringCommand::LanguageServer => {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(registry_language_server::run_stdio());
            }
        },
        Commands::Build {
            project_dir,
            environment,
            against,
            anchor,
            relay_against,
            relay_anchor,
            notary_against,
            notary_anchor,
            format,
        } => {
            let report = registryctl::build_registry_project_with_baselines(
                &ProjectBuildOptions {
                    project_directory: project_dir,
                    environment,
                    against,
                    anchor,
                },
                &ProjectBuildBaselineSetOptions {
                    relay_against,
                    relay_anchor,
                    notary_against,
                    notary_anchor,
                },
            )?;
            print_formatted_report(format, &report, render_build_report)?;
        }
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
        Commands::Bundle { format, command } => match command {
            BundleCommand::Inspect { bundle_dir } => {
                let report = registryctl::inspect_config_bundle(&bundle_dir)?;
                print_formatted_report(format, &report, render_bundle_inspect_report)?;
            }
            BundleCommand::Verify {
                bundle_dir,
                anchor_path,
            } => {
                let report = registryctl::verify_config_bundle_cli(&bundle_dir, &anchor_path)?;
                print_formatted_report(format, &report, render_bundle_verify_report)?;
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
                let report = registryctl::sign_config_bundle(BundleSignOptions {
                    input,
                    key,
                    product,
                    environment,
                    stream_id,
                    instance_id,
                    sequence,
                    bundle_id,
                    out,
                })?;
                print_formatted_report(format, &report, render_bundle_sign_report)?;
            }
        },
        Commands::Anchor { format, command } => match command {
            AnchorCommand::Init {
                anchor_path,
                product,
                environment,
                stream_id,
                instance_id,
            } => {
                let report = registryctl::init_config_anchor(
                    &anchor_path,
                    product,
                    environment,
                    stream_id,
                    instance_id,
                )?;
                print_formatted_report(format, &report, |report| {
                    render_anchor_report(report, "Initialized")
                })?;
            }
            AnchorCommand::AddKey {
                anchor_path,
                jwk_path,
                disabled,
            } => {
                let report =
                    registryctl::add_config_anchor_key(&anchor_path, &jwk_path, !disabled)?;
                print_formatted_report(format, &report, |report| {
                    render_anchor_report(report, "Updated")
                })?;
            }
            AnchorCommand::RemoveKey { anchor_path, kid } => {
                let report = registryctl::remove_config_anchor_key(&anchor_path, &kid)?;
                print_formatted_report(format, &report, |report| {
                    render_anchor_report(report, "Updated")
                })?;
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
    should_stop_after_observation: impl FnMut(usize, &std::path::Path) -> Result<bool>,
) -> Result<()> {
    let execution_context = ProjectExecutionContext::for_current_executable()?;
    watch_project_tests_until_with_context(
        options,
        selection,
        &execution_context,
        should_stop_after_observation,
    )
}

fn watch_project_tests_until_with_context(
    options: ProjectTestOptions,
    selection: ProjectTestSelection,
    execution_context: &ProjectExecutionContext,
    mut should_stop_after_observation: impl FnMut(usize, &std::path::Path) -> Result<bool>,
) -> Result<()> {
    let mut completed_runs = 0;
    loop {
        let report = registryctl::test_registry_project_selected_with_context(
            &options,
            &selection,
            execution_context,
        )?;
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

fn print_formatted_report<T: serde::Serialize>(
    format: OutputFormat,
    report: &T,
    render_human: impl FnOnce(&T) -> Result<String>,
) -> Result<()> {
    match format {
        OutputFormat::Human => println!("{}", render_human(report)?),
        OutputFormat::Json => print_json(report)?,
    }
    Ok(())
}

fn render_semantic_comparison_report(report: &ProjectSemanticComparisonReportV1) -> Result<String> {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(output, "{}", report.human_safe_summary())?;
    if !report.changes.is_empty() {
        writeln!(output, "Changes:")?;
        for change in &report.changes {
            writeln!(
                output,
                "  - {:?} {:?} {:?} {} ({} occurrence{})",
                change.dimension,
                change.direction,
                change.address.schema_family,
                change.address.field,
                change.occurrences,
                if change.occurrences == 1 { "" } else { "s" },
            )?;
        }
    }
    if !report.required_actions.is_empty() {
        writeln!(output, "Required actions:")?;
        for action in &report.required_actions {
            writeln!(output, "  - {action:?}")?;
        }
    }
    writeln!(
        output,
        "External approval: not evaluated; runtime behavior: not observed."
    )?;
    Ok(output.trim_end().to_owned())
}

fn render_add_notary_report(report: &AddNotaryReport) -> Result<String> {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(output, "Added Registry Notary to {:?}.", report.project)?;
    writeln!(
        output,
        "  Claim: {}",
        human_path(std::path::Path::new(report.claim_file))
    )?;
    writeln!(
        output,
        "  Notary API after start: {}",
        human_line(report.notary_url)
    )?;
    writeln!(output, "\nNext:")?;
    writeln!(output, "  registryctl start")?;
    Ok(output.trim_end().to_string())
}

fn render_test_report(report: &ProjectCommandReport, trace: bool) -> Result<String> {
    use std::fmt::Write as _;

    let mut output = render_test_summary(report);
    if trace {
        for fixture in &report.fixtures {
            write!(
                output,
                "\n  {} {}.{}",
                if fixture.passed { "PASS" } else { "FAIL" },
                human_line(&fixture.integration),
                human_line(&fixture.fixture)
            )?;
            for (label, values) in [
                ("inputs", &fixture.inputs),
                ("calls", &fixture.calls),
                ("outputs", &fixture.outputs),
                ("claims", &fixture.claims),
            ] {
                if !values.is_empty() {
                    write!(output, "\n    {label}: {}", human_list(values))?;
                }
            }
            if let Some(outcome) = &fixture.outcome {
                write!(output, "\n    outcome: {}", human_line(outcome))?;
            }
            if let Some(expected_error) = &fixture.expected_error {
                write!(
                    output,
                    "\n    expected error: {}",
                    human_line(expected_error)
                )?;
            }
            if let Some(source_access) = fixture.source_access {
                write!(output, "\n    source access: {source_access}")?;
            }
        }
    }
    Ok(output)
}

fn render_build_report(report: &ProjectCommandReport) -> Result<String> {
    use std::fmt::Write as _;

    let passed = report
        .fixtures
        .iter()
        .filter(|fixture| fixture.passed)
        .count();
    let mut output = String::new();
    writeln!(output, "Built Registry Stack project {:?}.", report.project)?;
    writeln!(
        output,
        "  Environment: {}",
        report
            .environment
            .as_deref()
            .map_or_else(|| "none".to_string(), human_line)
    )?;
    if let Some(path) = &report.output {
        writeln!(
            output,
            "  Output: {}",
            human_path(std::path::Path::new(path))
        )?;
    }
    writeln!(
        output,
        "  Fixtures: {passed}/{} passed",
        report.fixtures.len()
    )?;
    writeln!(output, "  Baseline: {}", human_line(report.baseline))?;
    writeln!(
        output,
        "  Semantic changes: {}",
        if report.semantic_changes.is_empty() {
            if report.baseline == "initial_without_baseline" {
                "not compared (initial review)".to_string()
            } else {
                "none".to_string()
            }
        } else {
            report
                .semantic_changes
                .iter()
                .map(|change| human_line(change.dimension))
                .collect::<Vec<_>>()
                .join(", ")
        }
    )?;
    Ok(output.trim_end().to_string())
}

fn render_editor_setup_report(report: &ProjectEditorSetupReport) -> Result<String> {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(
        output,
        "Configured Registry Stack editor support for {}.",
        human_path(std::path::Path::new(&report.project_directory))
    )?;
    writeln!(output, "  Generated files: {}", report.files.len())?;
    for file in &report.files {
        let path = std::path::Path::new(&report.project_directory).join(file);
        writeln!(output, "    {}", human_path(&path))?;
    }
    Ok(output.trim_end().to_string())
}

fn render_preflight_report(report: &ProjectPreflightReportV1) -> Result<String> {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(
        output,
        "Registry Stack project {:?} is {} for environment {:?}.",
        report.project,
        if report.status == registryctl::PreflightStatus::Ready {
            "locally ready"
        } else {
            "not locally ready"
        },
        report.environment
    )?;
    writeln!(
        output,
        "  Offline boundary: no network, source contact, fixture execution, external process, or build output."
    )?;
    writeln!(
        output,
        "  Checks: {} static, {} product, {} secret, {} runtime file.",
        report.static_checks.len(),
        report.product_validators.len(),
        report.secret_checks.len(),
        report.runtime_files.len(),
    )?;
    for diagnostic in &report.diagnostics {
        let code = serde_json::to_value(diagnostic.code)?
            .as_str()
            .unwrap_or("registryctl.preflight.unknown")
            .to_owned();
        writeln!(output, "  [{code}] {:?}", diagnostic.message)?;
        for address in &diagnostic.addresses {
            writeln!(
                output,
                "    {}#{}",
                address.file.as_str(),
                address.pointer.as_str()
            )?;
        }
        writeln!(output, "    Fix: {:?}", diagnostic.remediation)?;
    }
    Ok(output.trim_end().to_owned())
}

fn render_diagnostic_reference(
    catalog: DiagnosticCatalog,
    schema_version: &str,
    entries: &[registryctl::ErrorReferenceEntry],
    omissions: &[registryctl::OperatorErrorOmission],
) -> Result<String> {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(
        output,
        "Registry Stack {} diagnostic reference.",
        catalog.as_str()
    )?;
    writeln!(output, "  Schema: {}", human_line(schema_version))?;
    writeln!(output, "  Entries: {}", entries.len())?;
    for entry in entries {
        writeln!(
            output,
            "  [{}/{}/{}]",
            entry.family.as_str(),
            entry.product.as_str(),
            human_line(&entry.code)
        )?;
        writeln!(output, "    Meaning: {}", human_line(&entry.safe_meaning))?;
        writeln!(output, "    Rule: {}", human_line(&entry.rule))?;
        writeln!(
            output,
            "    Remediation: {}",
            human_line(&entry.safe_remediation)
        )?;
        writeln!(
            output,
            "    Lifecycle: {:?}; introduced: {}",
            entry.lifecycle,
            entry
                .introduced_in
                .as_deref()
                .map_or_else(|| "not released".to_string(), human_line)
        )?;
        writeln!(
            output,
            "    Evidence limitation: {}",
            human_line(&entry.evidence_limitation)
        )?;
        writeln!(
            output,
            "    Documentation: {}",
            human_line(&entry.docs_anchor)
        )?;
    }
    writeln!(output, "  Omissions: {}", omissions.len())?;
    for omission in omissions {
        writeln!(
            output,
            "  [omission/{:?}/{}] {}",
            omission.family,
            omission.product.as_str(),
            human_line(&omission.evidence)
        )?;
        writeln!(
            output,
            "    Required action: {}",
            human_line(&omission.required_action)
        )?;
    }
    Ok(output.trim_end().to_string())
}

fn render_promotion_report(report: &ProjectPromotionReportV1) -> Result<String> {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(output, "Promotion: {:?}", report.disposition)?;
    writeln!(output, "  Evidence: offline static comparison")?;
    writeln!(output, "  Classified changes: {}", report.changes.len())?;
    for change in &report.changes {
        writeln!(
            output,
            "  - {:?}: {:?} ({:?})",
            change.kind, change.effect, change.boundary
        )?;
    }
    if report.blocking_reasons.is_empty() {
        writeln!(output, "  Blocking reasons: none")?;
    } else {
        writeln!(output, "  Blocking reasons:")?;
        for reason in &report.blocking_reasons {
            writeln!(output, "  - {reason:?}")?;
        }
    }
    if report.required_actions.review_classes.is_empty() {
        writeln!(output, "  Required reviews: none")?;
    } else {
        writeln!(
            output,
            "  Required reviews: {}",
            report
                .required_actions
                .review_classes
                .iter()
                .map(|review| format!("{review:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )?;
    }
    writeln!(
        output,
        "  Re-sign: {:?}; restart: {:?}; reactivate: {:?}",
        report.required_actions.re_sign,
        report.required_actions.restart,
        report.required_actions.reactivate
    )?;
    Ok(output.trim_end().to_owned())
}

fn render_migration_report(report: &ProjectMigrationReportV1) -> Result<String> {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(output, "Project migration: {:?}", report.disposition)?;
    writeln!(output, "  Evidence: offline static validation")?;
    if report.disposition == MigrationDisposition::ReviewRequired {
        writeln!(
            output,
            "  Result: candidate/check succeeded; pending reviews are not approval or completion"
        )?;
    }
    writeln!(
        output,
        "  Changes: {} compatible normalizations, {} semantic",
        report.compatible_normalizations.len(),
        report.semantic_changes.len()
    )?;
    writeln!(
        output,
        "  Candidate: {:?}; emission: {:?}",
        report.output.candidate_artifact, report.output.candidate_emission
    )?;
    writeln!(output, "  Authored files overwritten: no")?;
    if report.blocking_reasons.is_empty() {
        writeln!(output, "  Blocking reasons: none")?;
    } else {
        writeln!(output, "  Blocking reasons:")?;
        for reason in &report.blocking_reasons {
            writeln!(output, "  - {reason:?}")?;
        }
    }
    let pending = report
        .reviews
        .iter()
        .filter(|review| review.status == registryctl::MigrationReviewStatus::RequiredPending)
        .map(|review| format!("{:?}", review.class))
        .collect::<Vec<_>>();
    writeln!(
        output,
        "  Required reviews: {}",
        if pending.is_empty() {
            "none".to_owned()
        } else {
            pending.join(", ")
        }
    )?;
    for gate in &report.rerun_gates {
        writeln!(output, "  Gate {:?}: {:?}", gate.gate, gate.status)?;
    }
    for diagnostic in &report.diagnostics {
        writeln!(
            output,
            "  Diagnostic {:?}/{:?}: {:?}",
            diagnostic.code, diagnostic.phase, diagnostic.remediation
        )?;
    }
    Ok(output.trim_end().to_owned())
}

fn render_capability_inventory(report: &ProjectCapabilityInventoryReportV1) -> Result<String> {
    use std::fmt::Write as _;

    let mut output = String::from("Registry Stack offline capability inventory.");
    writeln!(output, "\n  Runtime activation: not evaluated")?;
    for capability in &report.capabilities {
        writeln!(
            output,
            "  {:?}: installed={:?}, project={:?}, environment={:?}, disposition={:?}",
            capability.capability,
            capability.installed_release,
            capability.project_declaration,
            capability.environment_enablement,
            capability.disposition,
        )?;
    }
    if report.missing_support.is_empty() {
        writeln!(
            output,
            "  Missing support: none in evaluated local components"
        )?;
    } else {
        writeln!(
            output,
            "  Missing support: {} component(s)",
            report.missing_support.len()
        )?;
    }
    writeln!(output, "  Image availability: not evaluated")?;
    Ok(output.trim_end().to_owned())
}

fn render_bundle_inspect_report(report: &BundleInspectReport) -> Result<String> {
    use std::fmt::Write as _;

    let manifest = &report.manifest;
    let mut output = String::new();
    writeln!(output, "Config Bundle {:?}.", manifest.bundle_id)?;
    writeln!(output, "  Product: {}", human_line(&manifest.product))?;
    writeln!(
        output,
        "  Environment: {}",
        human_line(&manifest.environment)
    )?;
    writeln!(output, "  Stream: {}", human_line(&manifest.stream_id))?;
    if let Some(instance_id) = &manifest.instance_id {
        writeln!(output, "  Instance: {}", human_line(instance_id))?;
    }
    writeln!(output, "  Sequence: {}", manifest.sequence)?;
    writeln!(
        output,
        "  Config hash: {}",
        human_line(&manifest.config_hash)
    )?;
    writeln!(output, "  Files: {}", manifest.files.len())?;
    writeln!(output, "  Signatures: {}", report.signature_count)?;
    if !report.signature_kids.is_empty() {
        writeln!(output, "  Signers: {}", human_list(&report.signature_kids))?;
    }
    Ok(output.trim_end().to_string())
}

fn render_bundle_verify_report(report: &BundleVerifyReport) -> Result<String> {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(output, "Verified Config Bundle {:?}.", report.bundle_id)?;
    writeln!(output, "  Product: {}", human_line(&report.product))?;
    writeln!(output, "  Environment: {}", human_line(&report.environment))?;
    writeln!(output, "  Stream: {}", human_line(&report.stream_id))?;
    if let Some(instance_id) = &report.instance_id {
        writeln!(output, "  Instance: {}", human_line(instance_id))?;
    }
    writeln!(output, "  Sequence: {}", report.sequence)?;
    writeln!(output, "  Config: {}", human_path(&report.config_path))?;
    writeln!(output, "  Config hash: {}", human_line(&report.config_hash))?;
    writeln!(output, "  Signers: {}", human_list(&report.signer_kids))?;
    Ok(output.trim_end().to_string())
}

fn render_bundle_sign_report(report: &BundleSignReport) -> Result<String> {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(
        output,
        "Signed Config Bundle at {}.",
        human_path(&report.bundle_dir)
    )?;
    writeln!(output, "  Manifest: {}", human_path(&report.manifest_path))?;
    writeln!(
        output,
        "  Signature: {}",
        human_path(&report.signature_path)
    )?;
    writeln!(
        output,
        "  Config: {}",
        human_path(std::path::Path::new(&report.config_path))
    )?;
    writeln!(output, "  Config hash: {}", human_line(&report.config_hash))?;
    writeln!(
        output,
        "  Signer: {} ({})",
        human_line(&report.kid),
        human_line(&report.alg)
    )?;
    writeln!(output, "  Signatures: {}", report.signature_count)?;
    Ok(output.trim_end().to_string())
}

fn render_anchor_report(report: &AnchorReport, action: &str) -> Result<String> {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(
        output,
        "{action} Config Bundle trust anchor at {}.",
        human_path(&report.anchor_path)
    )?;
    writeln!(output, "  Product: {}", human_line(&report.product))?;
    writeln!(output, "  Environment: {}", human_line(&report.environment))?;
    writeln!(output, "  Stream: {}", human_line(&report.stream_id))?;
    writeln!(output, "  Instance: {}", human_line(&report.instance_id))?;
    writeln!(
        output,
        "  Signers: {} enabled, {} total",
        report.enabled_signer_count, report.signer_count
    )?;
    Ok(output.trim_end().to_string())
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
            writeln!(output, "  registryctl doctor --profile local")?;
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

fn human_line(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
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
    escaped
}

fn human_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values
            .iter()
            .map(|value| human_line(value))
            .collect::<Vec<_>>()
            .join(", ")
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

fn classifier_public_value(field: &ProjectFieldExplanation) -> Option<&serde_json::Value> {
    match &field.reported_value {
        ClassifierSafeReportedValue::Public { value } => Some(value.as_value()),
        ClassifierSafeReportedValue::Redacted { .. } | ClassifierSafeReportedValue::Absent => None,
    }
}

fn classifier_public_text(field: &ProjectFieldExplanation) -> Option<&str> {
    classifier_public_value(field)?.as_str()
}

fn classifier_public_count(field: &ProjectFieldExplanation) -> Option<u64> {
    classifier_public_value(field)?.as_u64()
}

fn render_field_source(source: FieldSourceKind) -> &'static str {
    match source {
        FieldSourceKind::Authored => "authored",
        FieldSourceKind::Defaulted => "defaulted",
        FieldSourceKind::Detected => "detected",
        FieldSourceKind::Derived => "derived",
        FieldSourceKind::EnvironmentBound => "environment-bound",
        FieldSourceKind::Generated => "generated",
        FieldSourceKind::Runtime => "runtime",
        FieldSourceKind::Absent => "absent",
    }
}

fn render_limit(field: &ProjectFieldExplanation, unit: &str) -> Option<String> {
    let value = classifier_public_value(field)?;
    let value = match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        _ => return None,
    };
    Some(match unit {
        "" | "duration" => value,
        "calls" if value == "1" => "1 call".to_string(),
        _ => format!("{value} {unit}"),
    })
}

fn render_count(count: u64, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

fn explanation_pointer_segments(path: &str) -> Option<Vec<String>> {
    if !path.starts_with('/') {
        return None;
    }
    path[1..]
        .split('/')
        .map(|segment| {
            let mut decoded = String::with_capacity(segment.len());
            let mut chars = segment.chars();
            while let Some(character) = chars.next() {
                if character != '~' {
                    decoded.push(character);
                    continue;
                }
                match chars.next()? {
                    '0' => decoded.push('~'),
                    '1' => decoded.push('/'),
                    _ => return None,
                }
            }
            Some(decoded)
        })
        .collect()
}

fn rendered_claim_class(
    has_direct_consultation_output: bool,
    authoritative_evidence: Option<&str>,
) -> Option<&'static str> {
    if has_direct_consultation_output {
        return Some("consultation_output");
    }
    match authoritative_evidence {
        Some("registry_backed") => Some("registry_backed_evaluation"),
        Some("self_attested") => Some("source_free_evaluation"),
        _ => None,
    }
}

fn render_check_report(
    report: &ProjectCommandReport,
    expanded: bool,
    trusted_local_values: Option<&[ProjectTrustedLocalAuthoredValue]>,
) -> Result<String> {
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

    let mut project_fields = std::collections::BTreeMap::new();
    let mut integration_fields =
        std::collections::BTreeMap::<&str, std::collections::BTreeMap<&str, _>>::new();
    let mut environment_fields = std::collections::BTreeMap::new();
    let mut redacted_sensitive_metadata = 0usize;
    let mut redacted_secret_material = 0usize;
    let mut redacted_by_policy = 0usize;
    for field in &explanation.fields {
        if let ClassifierSafeReportedValue::Redacted { reason, .. } = &field.reported_value {
            match reason {
                RedactionReason::SensitiveMetadata => redacted_sensitive_metadata += 1,
                RedactionReason::SecretMaterial => redacted_secret_material += 1,
                RedactionReason::Policy => redacted_by_policy += 1,
            }
        }
        match &field.address {
            ProjectFieldAddress::Project { path } => {
                project_fields.insert(path.as_str(), field);
            }
            ProjectFieldAddress::Integration { integration, path } => {
                integration_fields
                    .entry(integration)
                    .or_default()
                    .insert(path.as_str(), field);
            }
            ProjectFieldAddress::Environment { path, .. } => {
                environment_fields.insert(path.as_str(), field);
            }
            ProjectFieldAddress::Entity { .. } | ProjectFieldAddress::Fixture { .. } => {}
        }
    }

    writeln!(output, "Effective authority and limits:")?;
    let deployment = project_fields
        .get("/topology/deployment")
        .and_then(|field| classifier_public_text(field));
    if let Some(deployment) = deployment {
        let topology_label = match deployment {
            "relay_only" => "Relay-only",
            "notary_only" => "Notary-only",
            "combined" => "Relay + Notary",
            _ => "unknown",
        };
        writeln!(output, "  topology: {topology_label}")?;
        if matches!(deployment, "relay_only" | "combined") {
            let relay_counts = [
                (
                    "/topology/source_integration_count",
                    "source integration",
                    "source integrations",
                ),
                (
                    "/topology/records_api_service_count",
                    "records API service",
                    "records API services",
                ),
                (
                    "/topology/materialized_entity_count",
                    "materialized entity definition",
                    "materialized entity definitions",
                ),
            ]
            .into_iter()
            .filter_map(|(path, singular, plural)| {
                project_fields
                    .get(path)
                    .and_then(|field| classifier_public_count(field))
                    .map(|count| render_count(count, singular, plural))
            })
            .collect::<Vec<_>>();
            if !relay_counts.is_empty() {
                writeln!(output, "  Relay authority: {}", relay_counts.join(", "),)?;
            }
        } else {
            writeln!(output, "  Relay source authority: not applicable")?;
        }

        if matches!(deployment, "notary_only" | "combined") {
            let mut service_ids = std::collections::BTreeSet::new();
            for (path, field) in &project_fields {
                if classifier_public_value(field).is_none() {
                    continue;
                }
                let Some(parts) = explanation_pointer_segments(path) else {
                    continue;
                };
                if parts.len() >= 3 && parts[0] == "services" {
                    service_ids.insert(parts[1].clone());
                }
            }
            let mut source_free_evaluation = 0u64;
            let mut relay_backed = 0u64;
            for service_id in service_ids {
                let kind_path = format!("/services/{service_id}/kind");
                let consultation_count_path = format!("/services/{service_id}/consultation_count");
                if project_fields
                    .get(kind_path.as_str())
                    .and_then(|field| classifier_public_text(field))
                    != Some("evidence")
                {
                    continue;
                }
                match project_fields
                    .get(consultation_count_path.as_str())
                    .and_then(|field| classifier_public_count(field))
                {
                    Some(0) => source_free_evaluation += 1,
                    Some(_) => relay_backed += 1,
                    None => {}
                }
            }
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

    for (name, fields) in integration_fields {
        let Some(capability) = fields
            .get("/capability/type")
            .and_then(|field| classifier_public_text(field))
        else {
            continue;
        };
        writeln!(output, "  {name}: capability={capability}")?;
        let mut limits = Vec::new();
        for (path, label, unit) in [
            ("/limits/calls", "calls", "calls"),
            ("/limits/deadline", "deadline", ""),
            ("/limits/request_bytes", "request_bytes", "bytes"),
            ("/limits/source_bytes", "source_bytes", "bytes"),
            ("/source/response/max_bytes", "response_max_bytes", "bytes"),
        ] {
            let Some(field) = fields.get(path) else {
                continue;
            };
            let Some(value) = render_limit(field, unit) else {
                continue;
            };
            limits.push(format!(
                "{label}={value} ({})",
                render_field_source(field.source.kind)
            ));
        }
        if !limits.is_empty() {
            writeln!(output, "    limits: {}", limits.join(", "))?;
        }
        match capability {
            "http" => {
                let operation_count = fields
                    .get("/capability/http/operation_count")
                    .and_then(|field| classifier_public_count(field));
                if let Some(operation_count) = operation_count {
                    writeln!(
                        output,
                        "    authority: {} bounded operation(s)",
                        operation_count
                    )?;
                }
                if expanded {
                    let mut roles = std::collections::BTreeMap::new();
                    for (path, field) in &fields {
                        let Some(parts) = explanation_pointer_segments(path) else {
                            continue;
                        };
                        if parts.len() == 5
                            && parts[0] == "capability"
                            && parts[1] == "http"
                            && parts[2] == "operations"
                            && parts[4] == "role"
                        {
                            if let (Ok(index), Some(role)) =
                                (parts[3].parse::<usize>(), classifier_public_text(field))
                            {
                                roles.insert(index, role);
                            }
                        }
                    }
                    for (index, role) in roles {
                        writeln!(output, "      operation {}: class={role}", index + 1)?;
                    }
                }
            }
            "script" => {
                writeln!(
                    output,
                    "    authority: reviewed script with bounded source access"
                )?;
            }
            "snapshot" => {
                writeln!(
                    output,
                    "    authority: exact local materialized snapshot read"
                )?;
            }
            _ => {}
        }
        if expanded {
            let credential_path = format!(
                "/integrations/{}/source/credential_class",
                name.replace('~', "~0").replace('/', "~1")
            );
            if let Some(credential_class) = environment_fields
                .get(credential_path.as_str())
                .and_then(|field| classifier_public_text(field))
            {
                writeln!(output, "    credential class: {credential_class}")?;
            }
        }
    }

    if expanded {
        writeln!(output, "Services, claims, and disclosure:")?;
        let mut service_ids = std::collections::BTreeSet::new();
        for (path, field) in &project_fields {
            if classifier_public_value(field).is_none() {
                continue;
            }
            let Some(parts) = explanation_pointer_segments(path) else {
                continue;
            };
            if parts.len() >= 3 && parts[0] == "services" {
                service_ids.insert(parts[1].clone());
            }
        }
        for service_id in service_ids {
            let prefix = format!("/services/{service_id}");
            let public_text = |suffix: &str| {
                project_fields
                    .get(format!("{prefix}/{suffix}").as_str())
                    .and_then(|field| classifier_public_text(field))
            };
            let kind = public_text("kind");
            writeln!(
                output,
                "  {service_id}:{}",
                kind.map_or_else(String::new, |kind| format!(" kind={kind}"))
            )?;
            for (path, label) in [
                ("purpose", "purpose"),
                ("legal_basis", "legal basis"),
                ("consent", "consent"),
            ] {
                if let Some(value) = public_text(path) {
                    writeln!(output, "    {label}: {value}")?;
                }
            }
            let mut scopes = std::collections::BTreeMap::new();
            let mut claim_ids = std::collections::BTreeSet::new();
            for (path, field) in &project_fields {
                let Some(parts) = explanation_pointer_segments(path) else {
                    continue;
                };
                if parts.len() == 5
                    && parts[0] == "services"
                    && parts[1] == service_id
                    && parts[2] == "access"
                    && parts[3] == "scopes"
                {
                    if let (Ok(index), Some(scope)) =
                        (parts[4].parse::<usize>(), classifier_public_text(field))
                    {
                        scopes.insert(index, scope);
                    }
                }
                if parts.len() >= 5
                    && parts[0] == "services"
                    && parts[1] == service_id
                    && parts[2] == "claims"
                    && classifier_public_value(field).is_some()
                {
                    claim_ids.insert(parts[3].clone());
                }
            }
            if !scopes.is_empty() {
                writeln!(
                    output,
                    "    scopes: {}",
                    scopes.into_values().collect::<Vec<_>>().join(", ")
                )?;
            }
            for claim_id in claim_ids {
                let claim_prefix = format!("{prefix}/claims/{claim_id}");
                let disclosure = project_fields
                    .get(format!("{claim_prefix}/disclosure").as_str())
                    .or_else(|| {
                        project_fields.get(format!("{claim_prefix}/disclosure/default").as_str())
                    })
                    .and_then(|field| classifier_public_text(field));
                let evidence = project_fields
                    .get(format!("{claim_prefix}/evidence").as_str())
                    .and_then(|field| classifier_public_text(field));
                let claim_class = rendered_claim_class(
                    project_fields.contains_key(format!("{claim_prefix}/output").as_str()),
                    evidence,
                );
                let mut classes = Vec::new();
                if let Some(claim_class) = claim_class {
                    classes.push(format!("class={claim_class}"));
                }
                if let Some(disclosure) = disclosure {
                    classes.push(format!("disclosure={disclosure}"));
                }
                if !classes.is_empty() {
                    writeln!(output, "    claim {claim_id}: {}", classes.join(", "))?;
                }
            }
        }
        let mut redactions = Vec::new();
        if redacted_sensitive_metadata > 0 {
            redactions.push(render_count(
                redacted_sensitive_metadata as u64,
                "redacted sensitive metadata field",
                "redacted sensitive metadata fields",
            ));
        }
        if redacted_secret_material > 0 {
            redactions.push(render_count(
                redacted_secret_material as u64,
                "redacted secret material field",
                "redacted secret material fields",
            ));
        }
        if redacted_by_policy > 0 {
            redactions.push(render_count(
                redacted_by_policy as u64,
                "policy-redacted field",
                "policy-redacted fields",
            ));
        }
        if !redactions.is_empty() {
            writeln!(output, "Redactions: {}", redactions.join(", "))?;
        }
    }
    if let Some(values) = trusted_local_values {
        writeln!(
            output,
            "WARNING: trusted-local authored values follow. This output includes project-sensitive metadata and must not be shared."
        )?;
        writeln!(
            output,
            "Secret values, secret references and runtime secret-file locators, fixture data, raw parser text, defaulted values, and derived values remain hidden."
        )?;
        writeln!(output, "Trusted-local authored values:")?;
        if values.is_empty() {
            writeln!(output, "  none")?;
        }
        for field in values {
            writeln!(output, "  {}", field.terminal_line()?)?;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DiagnosticCatalog {
    Authoring,
    Fixture,
    Operator,
}

impl DiagnosticCatalog {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Authoring => "authoring",
            Self::Fixture => "fixture",
            Self::Operator => "operator",
        }
    }
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
    /// Print the deterministic project-configuration reference or its coverage audit.
    Reference {
        /// Print reviewed human-intent coverage and fail when any field is uncovered.
        #[arg(long)]
        coverage: bool,
    },
    /// Install deterministic local schema mappings for VS Code and Zed.
    Editor {
        /// Project workspace root containing registry-stack.yaml.
        #[arg(long, default_value = ".")]
        project_dir: PathBuf,
        /// Human-readable result, or machine-readable JSON.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Run cross-file Registry Stack navigation over the Language Server Protocol.
    LanguageServer,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    /// Print a static diagnostic catalog without reading a project or runtime.
    Diagnostics {
        /// Authoring, offline-fixture, or operator diagnostic reference.
        #[arg(long, value_enum)]
        catalog: DiagnosticCatalog,
        /// Human-readable reference, or machine-readable JSON.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
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
        /// Human-readable result, or machine-readable JSON.
        #[arg(long, value_enum, default_value = "human", global = true)]
        format: OutputFormat,
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
        /// Human-readable result, or machine-readable JSON.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
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
        /// Show directly authored non-secret values for trusted-local terminal review.
        ///
        /// This may expose project-sensitive metadata. Secret references,
        /// secret values and runtime secret-file locators, fixture data, raw
        /// parser text, defaulted values, and derived values remain hidden.
        #[arg(long, requires = "explain")]
        show_authored_values: bool,
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
    /// Inspect pure Registry Stack project metadata without reading a workspace.
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// Verify local environment, secret-reference, and runtime-file readiness without network access.
    Preflight {
        /// Project workspace root.
        #[arg(long, default_value = ".")]
        project_dir: PathBuf,
        /// Explicit environment binding.
        #[arg(long)]
        environment: String,
        /// Human-readable result, or machine-readable JSON.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Inspect compiled, declared, enabled, used, and missing local capabilities.
    Capabilities {
        /// Project workspace root.
        #[arg(long, default_value = ".")]
        project_dir: PathBuf,
        /// Explicit environment binding.
        #[arg(long)]
        environment: String,
        /// Human-readable result, or machine-readable JSON.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Compare normalized local project state without reading runtime or signed approval state.
    Compare {
        /// Current project workspace root.
        #[arg(long, default_value = ".")]
        project_dir: PathBuf,
        /// Current project environment binding.
        #[arg(long)]
        environment: String,
        /// Baseline project workspace root. Omit to compare two environments of this project.
        #[arg(long, requires = "from_environment", conflicts_with = "from_starter")]
        from_project_dir: Option<PathBuf>,
        /// Baseline environment binding for local project comparison.
        #[arg(
            long,
            required_unless_present = "from_starter",
            conflicts_with = "from_starter"
        )]
        from_environment: Option<String>,
        /// Compare against the recorded, exact starter embedded in this registryctl release.
        ///
        /// Optionally name a starter kind to assert that it matches the
        /// project's recorded provenance.
        #[arg(
            long,
            num_args = 0..=1,
            required_unless_present = "from_environment",
            conflicts_with_all = ["from_project_dir", "from_environment"]
        )]
        from_starter: Option<Option<ProjectStarter>>,
        /// Human-readable value-free review plan, or strict machine-readable JSON.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Compare normalized authored state with a verified reviewed baseline without deployment.
    Promote {
        /// Project workspace root.
        #[arg(long, default_value = ".")]
        project_dir: PathBuf,
        /// Explicit environment binding.
        #[arg(long)]
        environment: String,
        /// Previously signed product Config Bundle with review and internal approval state.
        #[arg(
            long,
            conflicts_with_all = ["relay_against", "relay_anchor", "notary_against", "notary_anchor"]
        )]
        against: Option<PathBuf>,
        /// Trust anchor for --against.
        #[arg(
            long,
            conflicts_with_all = ["relay_against", "relay_anchor", "notary_against", "notary_anchor"]
        )]
        anchor: Option<PathBuf>,
        /// Relay Config Bundle baseline for a combined Relay and Notary project.
        #[arg(long, requires = "relay_anchor")]
        relay_against: Option<PathBuf>,
        /// Relay trust anchor for --relay-against.
        #[arg(long, requires = "relay_against")]
        relay_anchor: Option<PathBuf>,
        /// Notary Config Bundle baseline for a combined Relay and Notary project.
        #[arg(long, requires = "notary_anchor")]
        notary_against: Option<PathBuf>,
        /// Notary trust anchor for --notary-against.
        #[arg(long, requires = "notary_against")]
        notary_anchor: Option<PathBuf>,
        /// Human-readable result, or machine-readable JSON.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Check a reviewed authoring migration and optionally emit a separate candidate.
    Migrate {
        /// Project workspace root.
        #[arg(long, default_value = ".")]
        project_dir: PathBuf,
        /// Target authoring contract version.
        #[arg(long, default_value_t = 1)]
        target_version: u32,
        /// Separate, absent destination for a reviewable candidate.
        #[arg(long, requires = "write_candidate")]
        output: Option<PathBuf>,
        /// Grant authority to write only the separate migration candidate.
        #[arg(long, requires = "output")]
        write_candidate: bool,
        /// Human-readable result, or machine-readable JSON.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
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
        #[arg(
            long,
            requires = "anchor",
            conflicts_with_all = ["relay_against", "relay_anchor", "notary_against", "notary_anchor"]
        )]
        against: Option<PathBuf>,
        /// Trust anchor for --against.
        #[arg(
            long,
            requires = "against",
            conflicts_with_all = ["relay_against", "relay_anchor", "notary_against", "notary_anchor"]
        )]
        anchor: Option<PathBuf>,
        /// Relay Config Bundle approved baseline for a combined project comparison.
        #[arg(long, requires = "relay_anchor")]
        relay_against: Option<PathBuf>,
        /// Relay trust anchor for --relay-against.
        #[arg(long, requires = "relay_against")]
        relay_anchor: Option<PathBuf>,
        /// Notary Config Bundle approved baseline for a combined project comparison.
        #[arg(long, requires = "notary_anchor")]
        notary_against: Option<PathBuf>,
        /// Notary trust anchor for --notary-against.
        #[arg(long, requires = "notary_against")]
        notary_anchor: Option<PathBuf>,
        /// Human-readable result, or machine-readable JSON.
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
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
    /// Run product doctor validation.
    Doctor {
        /// Deployment profile override to pass through to product doctor commands.
        #[arg(long, value_enum)]
        profile: Option<DeploymentProfile>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = DoctorFormat::Human)]
        format: DoctorFormat,
    },
    /// Stream Compose logs for the local project.
    Logs,
    /// Work with Registry Config Bundle directories.
    Bundle {
        /// Human-readable result, or machine-readable JSON.
        #[arg(long, value_enum, default_value = "human", global = true)]
        format: OutputFormat,
        #[command(subcommand)]
        command: BundleCommand,
    },
    /// Work with Registry Config Bundle trust anchors.
    Anchor {
        /// Human-readable result, or machine-readable JSON.
        #[arg(long, value_enum, default_value = "human", global = true)]
        format: OutputFormat,
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
                | Self::Project { .. }
                | Self::Preflight { .. }
                | Self::Capabilities { .. }
                | Self::Compare { .. }
                | Self::Promote { .. }
                | Self::Migrate { .. }
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
    fn pure_project_diagnostic_catalog_cli_accepts_all_catalogs_and_formats() {
        for catalog in ["authoring", "fixture", "operator"] {
            for format in ["human", "json"] {
                let parsed = Cli::try_parse_from([
                    "registryctl",
                    "project",
                    "diagnostics",
                    "--catalog",
                    catalog,
                    "--format",
                    format,
                ])
                .expect("pure diagnostic catalog command parses");
                assert!(matches!(
                    parsed.command,
                    Commands::Project {
                        command: ProjectCommand::Diagnostics { .. }
                    }
                ));
            }
        }
    }

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
                format: OutputFormat::Human,
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
                format: OutputFormat::Human,
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
                show_authored_values: false,
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
                show_authored_values: false,
                ..
            }
        ));
        let trusted_local = Cli::try_parse_from([
            "registryctl",
            "check",
            "--environment",
            "staging",
            "--explain",
            "--show-authored-values",
        ])
        .expect("trusted-local explanation parses");
        assert!(matches!(
            trusted_local.command,
            Commands::Check {
                explain: true,
                show_authored_values: true,
                format: OutputFormat::Human,
                ..
            }
        ));
        assert!(Cli::try_parse_from([
            "registryctl",
            "check",
            "--environment",
            "staging",
            "--show-authored-values",
        ])
        .is_err());

        let preflight = Cli::try_parse_from([
            "registryctl",
            "preflight",
            "--project-dir",
            "registry-project",
            "--environment",
            "staging",
            "--format",
            "json",
        ])
        .unwrap();
        assert!(matches!(
            preflight.command,
            Commands::Preflight {
                project_dir,
                environment,
                format: OutputFormat::Json,
            } if project_dir == std::path::Path::new("registry-project")
                && environment == "staging"
        ));

        let capabilities = Cli::try_parse_from([
            "registryctl",
            "capabilities",
            "--project-dir",
            "registry-project",
            "--environment",
            "staging",
            "--format",
            "json",
        ])
        .unwrap();
        assert!(matches!(
            capabilities.command,
            Commands::Capabilities {
                project_dir,
                environment,
                format: OutputFormat::Json,
            } if project_dir == std::path::Path::new("registry-project")
                && environment == "staging"
        ));

        let promote = Cli::try_parse_from([
            "registryctl",
            "promote",
            "--project-dir",
            "registry-project",
            "--environment",
            "staging",
            "--relay-against",
            "relay-bundle",
            "--relay-anchor",
            "relay-anchor.json",
            "--notary-against",
            "notary-bundle",
            "--notary-anchor",
            "notary-anchor.json",
            "--format",
            "json",
        ])
        .unwrap();
        assert!(matches!(
            promote.command,
            Commands::Promote {
                relay_against: Some(relay),
                relay_anchor: Some(relay_anchor),
                notary_against: Some(notary),
                notary_anchor: Some(notary_anchor),
                format: OutputFormat::Json,
                ..
            } if relay == std::path::Path::new("relay-bundle")
                && relay_anchor == std::path::Path::new("relay-anchor.json")
                && notary == std::path::Path::new("notary-bundle")
                && notary_anchor == std::path::Path::new("notary-anchor.json")
        ));
        assert!(Cli::try_parse_from([
            "registryctl",
            "promote",
            "--environment",
            "staging",
            "--against",
            "legacy-bundle",
            "--anchor",
            "legacy-anchor.json",
            "--relay-against",
            "relay-bundle",
            "--relay-anchor",
            "relay-anchor.json",
        ])
        .is_err());

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

        let reference =
            Cli::try_parse_from(["registryctl", "authoring", "reference", "--coverage"]).unwrap();
        assert!(matches!(
            reference.command,
            Commands::Authoring {
                command: AuthoringCommand::Reference { coverage: true }
            }
        ));

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
                command: AuthoringCommand::Editor {
                    project_dir,
                    format: OutputFormat::Human
                }
            } if project_dir == std::path::Path::new("registry-project")
        ));
        let default_editor = Cli::try_parse_from(["registryctl", "authoring", "editor"]).unwrap();
        assert!(matches!(
            default_editor.command,
            Commands::Authoring {
                command: AuthoringCommand::Editor {
                    project_dir,
                    format: OutputFormat::Human
                }
            } if project_dir == std::path::Path::new(".")
        ));

        let language_server =
            Cli::try_parse_from(["registryctl", "authoring", "language-server"]).unwrap();
        assert!(matches!(
            language_server.command,
            Commands::Authoring {
                command: AuthoringCommand::LanguageServer
            }
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
                relay_against: None,
                relay_anchor: None,
                notary_against: None,
                notary_anchor: None,
                format: OutputFormat::Human,
            } if project_dir == std::path::Path::new("registry-project") && environment == "staging"
        ));
        let build_with_product_baselines = Cli::try_parse_from([
            "registryctl",
            "build",
            "--environment",
            "staging",
            "--relay-against",
            "relay-bundle",
            "--relay-anchor",
            "relay-anchor.json",
            "--notary-against",
            "notary-bundle",
            "--notary-anchor",
            "notary-anchor.json",
        ])
        .unwrap();
        assert!(matches!(
            build_with_product_baselines.command,
            Commands::Build {
                relay_against: Some(relay),
                relay_anchor: Some(relay_anchor),
                notary_against: Some(notary),
                notary_anchor: Some(notary_anchor),
                ..
            } if relay == std::path::Path::new("relay-bundle")
                && relay_anchor == std::path::Path::new("relay-anchor.json")
                && notary == std::path::Path::new("notary-bundle")
                && notary_anchor == std::path::Path::new("notary-anchor.json")
        ));
        assert!(Cli::try_parse_from([
            "registryctl",
            "build",
            "--environment",
            "staging",
            "--relay-against",
            "relay-bundle",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "registryctl",
            "build",
            "--environment",
            "staging",
            "--against",
            "legacy-bundle",
            "--anchor",
            "legacy-anchor.json",
            "--relay-against",
            "relay-bundle",
            "--relay-anchor",
            "relay-anchor.json",
        ])
        .is_err());
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
    fn human_claim_class_uses_authoritative_evidence_dependency() {
        assert_eq!(
            rendered_claim_class(true, Some("registry_backed")),
            Some("consultation_output")
        );
        assert_eq!(
            rendered_claim_class(false, Some("registry_backed")),
            Some("registry_backed_evaluation")
        );
        assert_eq!(
            rendered_claim_class(false, Some("self_attested")),
            Some("source_free_evaluation")
        );
        assert_eq!(rendered_claim_class(false, None), None);
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
        let relay_rendered =
            render_check_report(&relay_report, false, None).expect("report renders");
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
        let notary_rendered =
            render_check_report(&notary_report, true, None).expect("report renders");
        assert!(notary_rendered.contains("topology: Notary-only"));
        assert!(notary_rendered.contains(
            "Notary authority: 1 source-free evaluation service, 0 compiler-pinned Relay-backed services"
        ));
        assert!(notary_rendered.contains(
            "claim application-complete: class=source_free_evaluation, disclosure=predicate"
        ));
        assert!(!notary_rendered.contains("class=registry_backed_evaluation"));
        assert!(notary_rendered.contains("Relay source authority: not applicable"));
    }

    #[test]
    fn human_bundle_and_anchor_reports_surface_operator_decisions() {
        let manifest = registry_platform_config::ConfigBundleManifest {
            schema: "registry.platform.config_bundle.v1".to_string(),
            product: "registry-notary".to_string(),
            environment: "production".to_string(),
            stream_id: "civil-registry".to_string(),
            instance_id: Some("notary-011".to_string()),
            bundle_id: "rollout-3".to_string(),
            sequence: 42,
            previous_config_hash: None,
            config_hash: "sha256:config".to_string(),
            files: vec![registry_platform_config::ConfigBundleFile {
                path: "config/notary.yaml".to_string(),
                sha256: "sha256:file".to_string(),
            }],
            created_at: "2026-07-19T00:00:00Z".to_string(),
        };
        let inspect = render_bundle_inspect_report(&BundleInspectReport {
            schema_version: "registryctl.config_bundle.inspect.v1".to_string(),
            manifest,
            signature_count: 1,
            signature_kids: vec!["signer-1".to_string()],
        })
        .expect("inspect report renders");
        for expected in [
            "Config Bundle \"rollout-3\".",
            "Product: registry-notary",
            "Sequence: 42",
            "Signatures: 1",
            "Signers: signer-1",
        ] {
            assert!(inspect.contains(expected), "missing {expected}: {inspect}");
        }

        let verify = render_bundle_verify_report(&BundleVerifyReport {
            schema_version: "registryctl.config_bundle.verify.v1".to_string(),
            product: "registry-notary".to_string(),
            environment: "production".to_string(),
            stream_id: "civil-registry".to_string(),
            instance_id: Some("notary-011".to_string()),
            bundle_id: "rollout-3".to_string(),
            sequence: 42,
            config_path: PathBuf::from("bundle/config/notary.yaml"),
            config_hash: "sha256:config".to_string(),
            signer_kids: vec!["signer-1".to_string()],
        })
        .expect("verify report renders");
        assert!(verify.starts_with("Verified Config Bundle \"rollout-3\"."));
        assert!(verify.contains("Config: bundle/config/notary.yaml"));

        let sign = render_bundle_sign_report(&BundleSignReport {
            schema_version: "registryctl.config_bundle.sign.v1".to_string(),
            bundle_dir: PathBuf::from("bundle"),
            manifest_path: PathBuf::from("bundle/manifest.json"),
            signature_path: PathBuf::from("bundle/manifest.sig.json"),
            config_path: "config/notary.yaml".to_string(),
            config_hash: "sha256:config".to_string(),
            kid: "signer-1".to_string(),
            alg: "EdDSA".to_string(),
            signature_count: 1,
        })
        .expect("sign report renders");
        assert!(sign.starts_with("Signed Config Bundle at bundle."));
        assert!(sign.contains("Signer: signer-1 (EdDSA)"));

        let anchor = render_anchor_report(
            &AnchorReport {
                schema_version: "registryctl.config_anchor.v1".to_string(),
                anchor_path: PathBuf::from("trust-anchor.json"),
                product: "registry-notary".to_string(),
                environment: "production".to_string(),
                stream_id: "civil-registry".to_string(),
                instance_id: "notary-011".to_string(),
                signer_count: 2,
                enabled_signer_count: 1,
            },
            "Updated",
        )
        .expect("anchor report renders");
        assert!(anchor.starts_with("Updated Config Bundle trust anchor at trust-anchor.json."));
        assert!(anchor.contains("Signers: 1 enabled, 2 total"));
    }

    #[test]
    fn human_report_values_cannot_inject_terminal_lines() {
        assert_eq!(
            human_line("line\nreturn\r tab\t escape\u{1b}"),
            "line\\nreturn\\r tab\\t escape\\u001b"
        );
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
        let catalog: serde_norway::Value = serde_norway::from_slice(
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
            let project: serde_norway::Value = serde_norway::from_slice(
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
            let fixture: serde_norway::Value = serde_norway::from_slice(
                &std::fs::read(fixture_path).expect("watch fixture reads"),
            )
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

            let current = std::env::current_exe().expect("test executable path");
            let mut worker = current
                .parent()
                .and_then(std::path::Path::parent)
                .expect("Cargo target directory")
                .join("registryctl");
            worker.set_extension(std::env::consts::EXE_EXTENSION);
            let execution_context = ProjectExecutionContext::new(worker)
                .expect("Cargo-built registryctl worker is available");
            let mut observed_runs = 0;
            watch_project_tests_until_with_context(
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
                &execution_context,
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
        let default = Cli::try_parse_from(["registryctl", "doctor"]).unwrap();
        assert!(matches!(
            default.command,
            Commands::Doctor {
                format: DoctorFormat::Human,
                profile: None
            }
        ));

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
                format: OutputFormat::Human,
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
                format: OutputFormat::Human,
                command: BundleCommand::Inspect { .. }
            }
        ));
        assert!(!inspect.command.should_check_for_updates());

        let json_inspect = Cli::try_parse_from([
            "registryctl",
            "bundle",
            "inspect",
            "--bundle-dir",
            "bundle",
            "--format",
            "json",
        ])
        .unwrap();
        assert!(matches!(
            json_inspect.command,
            Commands::Bundle {
                format: OutputFormat::Json,
                command: BundleCommand::Inspect { .. }
            }
        ));

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
                format: OutputFormat::Human,
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
                format: OutputFormat::Human,
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
                format: OutputFormat::Human,
                command: AnchorCommand::Init { .. }
            }
        ));
        assert!(!init.command.should_check_for_updates());

        let json_init = Cli::try_parse_from([
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
            "--format",
            "json",
        ])
        .unwrap();
        assert!(matches!(
            json_init.command,
            Commands::Anchor {
                format: OutputFormat::Json,
                command: AnchorCommand::Init { .. }
            }
        ));

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
                format: OutputFormat::Human,
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
                format: OutputFormat::Human,
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

#[cfg(test)]
mod migration_cli_tests {
    use clap::Parser as _;

    use super::{Cli, Commands, OutputFormat};

    #[test]
    fn migration_cli_requires_explicit_separate_candidate_authority() {
        let check = Cli::try_parse_from([
            "registryctl",
            "migrate",
            "--project-dir",
            "registry-project",
            "--target-version",
            "1",
            "--format",
            "json",
        ])
        .expect("check-only migration parses");
        assert!(matches!(
            check.command,
            Commands::Migrate {
                output: None,
                write_candidate: false,
                format: OutputFormat::Json,
                ..
            }
        ));

        let candidate = Cli::try_parse_from([
            "registryctl",
            "migrate",
            "--project-dir",
            "registry-project",
            "--output",
            "registry-project-v1",
            "--write-candidate",
        ])
        .expect("explicit candidate migration parses");
        assert!(matches!(
            candidate.command,
            Commands::Migrate {
                output: Some(path),
                write_candidate: true,
                ..
            } if path == std::path::Path::new("registry-project-v1")
        ));

        assert!(
            Cli::try_parse_from(["registryctl", "migrate", "--output", "registry-project-v1"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["registryctl", "migrate", "--write-candidate"]).is_err());
    }
}

#[cfg(test)]
mod semantic_comparison_cli_tests {
    use clap::Parser as _;

    use super::{Cli, Commands, OutputFormat};
    use registryctl::ProjectStarter;

    #[test]
    fn compare_cli_requires_exactly_one_local_or_embedded_baseline() {
        let starter = Cli::try_parse_from([
            "registryctl",
            "compare",
            "--project-dir",
            "candidate",
            "--environment",
            "local",
            "--from-starter",
            "--format",
            "json",
        ])
        .expect("embedded starter comparison parses");
        assert!(matches!(
            starter.command,
            Commands::Compare {
                project_dir,
                environment,
                from_starter: Some(None),
                from_project_dir: None,
                from_environment: None,
                format: OutputFormat::Json,
            } if project_dir == std::path::Path::new("candidate") && environment == "local"
        ));

        for (value, expected) in [
            ("http", ProjectStarter::Http),
            ("dhis2-tracker", ProjectStarter::Dhis2Tracker),
            ("opencrvs-dci", ProjectStarter::OpencrvsDci),
            ("fhir-r4", ProjectStarter::FhirR4),
            ("snapshot", ProjectStarter::Snapshot),
        ] {
            let selected = Cli::try_parse_from([
                "registryctl",
                "compare",
                "--environment",
                "local",
                "--from-starter",
                value,
            ])
            .unwrap_or_else(|error| panic!("{value} starter selection parses: {error}"));
            assert!(matches!(
                selected.command,
                Commands::Compare {
                    from_starter: Some(Some(actual)),
                    from_project_dir: None,
                    from_environment: None,
                    ..
                } if actual == expected
            ));
        }

        let same_project = Cli::try_parse_from([
            "registryctl",
            "compare",
            "--project-dir",
            "candidate",
            "--environment",
            "candidate",
            "--from-environment",
            "local",
        ])
        .expect("same-project environment comparison parses");
        assert!(matches!(
            same_project.command,
            Commands::Compare {
                from_project_dir: None,
                from_environment: Some(environment),
                from_starter: None,
                ..
            } if environment == "local"
        ));

        let local_projects = Cli::try_parse_from([
            "registryctl",
            "compare",
            "--project-dir",
            "candidate",
            "--environment",
            "candidate",
            "--from-project-dir",
            "reviewed",
            "--from-environment",
            "production",
        ])
        .expect("project-to-project comparison parses");
        assert!(matches!(
            local_projects.command,
            Commands::Compare {
                from_project_dir: Some(project),
                from_environment: Some(environment),
                from_starter: None,
                ..
            } if project == std::path::Path::new("reviewed") && environment == "production"
        ));

        assert!(
            Cli::try_parse_from(["registryctl", "compare", "--environment", "local",]).is_err()
        );
        assert!(Cli::try_parse_from([
            "registryctl",
            "compare",
            "--environment",
            "local",
            "--from-project-dir",
            "reviewed",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "registryctl",
            "compare",
            "--environment",
            "local",
            "--from-starter",
            "--from-environment",
            "reviewed",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "registryctl",
            "compare",
            "--environment",
            "local",
            "--from-starter",
            "unknown",
        ])
        .is_err());
    }
}
