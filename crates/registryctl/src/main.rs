use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use registryctl::{
    BundleSignOptions, DeploymentProfile, DoctorFormat, ProjectBuildOptions, ProjectCheckOptions,
    ProjectInitOptions, ProjectStarter, ProjectTestOptions, ProjectTestSelection, Sample,
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
            command,
        } => match (from, command) {
            (Some(starter), None) => {
                print_json(&registryctl::init_registry_project(&ProjectInitOptions {
                    starter,
                    directory: project_dir,
                })?)?
            }
            (None, Some(command)) => {
                let image_lock = registryctl::load_registryctl_image_lock()?;
                match *command {
                    InitCommand::Relay { dir, sample } => {
                        registryctl::init_spreadsheet_api(&dir, sample, &image_lock)?;
                    }
                    InitCommand::SpreadsheetApi { dir, sample } => {
                        registryctl::init_spreadsheet_api(&dir, sample, &image_lock)?;
                    }
                }
            }
            _ => {
                anyhow::bail!("init requires exactly one of --from or a legacy product subcommand")
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
            against,
            anchor,
        } => print_json(&registryctl::check_registry_project(
            &ProjectCheckOptions {
                project_directory: project_dir,
                environment,
                explain,
                against,
                anchor,
            },
        )?)?,
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
                registryctl::bruno_generate_project(&std::env::current_dir()?, force)?;
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
        print_json(&registryctl::test_registry_project_selected(
            &options, &selection,
        )?)?;
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
        #[command(subcommand)]
        command: Option<Box<InitCommand>>,
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
        #[arg(long, conflicts_with = "live")]
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
        /// Previously signed product Config Bundle with review and internal approval state.
        #[arg(long)]
        against: Option<PathBuf>,
        /// Trust anchor for --against.
        #[arg(long)]
        anchor: Option<PathBuf>,
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

impl Commands {
    fn should_check_for_updates(&self) -> bool {
        !matches!(
            self,
            Self::Doctor { .. }
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
                command: None,
            } if project_dir == std::path::Path::new("registry-project")
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
            "--trace",
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
                trace: true,
                watch: true,
            } if project_dir == std::path::Path::new("registry-project")
                && integration == "person-record"
                && fixture == "active-person"
        ));

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
                against: Some(against),
                anchor: Some(anchor),
            } if project_dir == std::path::Path::new("registry-project")
                && environment == "staging"
                && against == std::path::Path::new("baseline")
                && anchor == std::path::Path::new("anchor.json")
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
    fn project_test_watch_reruns_each_maintained_starter_after_an_authored_change() {
        let starters = [
            (ProjectStarter::Http, "person-record", "active-person"),
            (
                ProjectStarter::Dhis2Tracker,
                "health-record",
                "complete-health-match",
            ),
            (
                ProjectStarter::OpencrvsDci,
                "birth-record",
                "birth-record-match",
            ),
            (ProjectStarter::FhirR4, "coverage", "coverage-active"),
            (
                ProjectStarter::Snapshot,
                "person-snapshot",
                "snapshot-match",
            ),
        ];

        for (starter, integration, fixture) in starters {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let project_directory = temporary.path().join("registry-project");
            registryctl::init_registry_project(&ProjectInitOptions {
                starter,
                directory: project_directory.clone(),
            })
            .expect("maintained starter initializes");

            let mut observed_runs = 0;
            watch_project_tests_until(
                ProjectTestOptions {
                    project_directory: project_directory.clone(),
                    environment: None,
                    live: false,
                },
                ProjectTestSelection {
                    integration: Some(integration.to_string()),
                    fixture: Some(fixture.to_string()),
                    trace: true,
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
            assert_eq!(observed_runs, 2, "{starter:?}");
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
