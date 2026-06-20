use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use registryctl::{
    ConfigProduct, DeploymentProfile, DoctorFormat, LabEnvFormat, NotaryInitOptions,
    NotaryInitSourceKind, NotarySource, OpenFnBatchMode, OpenFnConvertOptions, OpenFnImportOptions,
    Sample,
};

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.should_check_for_updates() {
        registryctl::maybe_warn_about_update(env!("CARGO_PKG_VERSION"));
    }
    match cli.command {
        Commands::UpdateCheck => registryctl::update_check(env!("CARGO_PKG_VERSION"))?,
        Commands::UpdateCheckRefresh => registryctl::refresh_update_check_cache()?,
        Commands::Init { command } => match *command {
            InitCommand::Relay { dir, sample } => {
                registryctl::init_spreadsheet_api(&dir, sample)?;
            }
            InitCommand::SpreadsheetApi { dir, sample } => {
                registryctl::init_spreadsheet_api(&dir, sample)?;
            }
            InitCommand::Notary {
                dir,
                source_kind,
                source_url,
                source_token_from_env,
                source_token_env,
                source_dataset,
                source_entity,
                source_lookup_field,
                source_network,
                source_claim,
                source_claim_title,
                smoke_target_id,
            } => {
                registryctl::init_notary_project(
                    &dir,
                    NotaryInitOptions {
                        source_kind,
                        source_url: source_url
                            .unwrap_or_else(|| source_kind.default_source_url().to_string()),
                        source_token_from_env,
                        source_token_env: source_token_env
                            .unwrap_or_else(|| source_kind.default_source_token_env().to_string()),
                        source_dataset: source_dataset
                            .unwrap_or_else(|| source_kind.default_source_dataset().to_string()),
                        source_entity: source_entity
                            .unwrap_or_else(|| source_kind.default_source_entity().to_string()),
                        source_lookup_field: source_lookup_field.unwrap_or_else(|| {
                            source_kind.default_source_lookup_field().to_string()
                        }),
                        source_network,
                        source_claim: source_claim
                            .unwrap_or_else(|| source_kind.default_source_claim().to_string()),
                        source_claim_title: source_claim_title.unwrap_or_else(|| {
                            source_kind.default_source_claim_title().to_string()
                        }),
                        smoke_target_id: smoke_target_id
                            .unwrap_or_else(|| source_kind.default_smoke_target_id().to_string()),
                    },
                )?;
            }
        },
        Commands::Add { command } => match command {
            AddCommand::Notary { from, force } => {
                registryctl::add_notary(&std::env::current_dir()?, from, force)?;
            }
        },
        Commands::Start => registryctl::start_project(&std::env::current_dir()?)?,
        Commands::Stop => registryctl::stop_project(&std::env::current_dir()?)?,
        Commands::Status => registryctl::status_project(&std::env::current_dir()?)?,
        Commands::Open => registryctl::open_project(&std::env::current_dir()?)?,
        Commands::Smoke => registryctl::smoke_project(&std::env::current_dir()?)?,
        Commands::Doctor { format, profile } => {
            registryctl::doctor_project(&std::env::current_dir()?, format, profile)?
        }
        Commands::Config { command } => match command {
            ConfigCommand::Explain { product, format } => {
                registryctl::config_explain_project(&std::env::current_dir()?, product, format)?
            }
            ConfigCommand::Diff { product, format } => {
                registryctl::config_diff_project(&std::env::current_dir()?, product, format)?
            }
            ConfigCommand::Package { output, force } => registryctl::config_package_project(
                &std::env::current_dir()?,
                output.as_deref(),
                force,
            )?,
        },
        Commands::Logs => registryctl::logs_project(&std::env::current_dir()?)?,
        Commands::Notary { command } => match command {
            NotaryCommand::Smoke => registryctl::notary_smoke_project(&std::env::current_dir()?)?,
            NotaryCommand::Open => registryctl::notary_open_project(&std::env::current_dir()?)?,
        },
        Commands::Openfn { command } => match *command {
            OpenFnCommand::Import {
                input,
                openfn_token_env,
                workflow,
                output,
                jobs_dir,
                expression_prefix,
                source_id,
                dataset,
                entity,
                credential_env,
                allowed_base_url,
                smoke,
                smoke_fields,
                smoke_purpose,
                auth_hash_env,
                server_bind,
                cli_build_tool,
                runtime,
                worker_command,
                worker_script,
                max_workers,
                worker_timeout_ms,
                max_worker_memory_mb,
                max_output_bytes,
                max_request_bytes,
                max_query_parameter_bytes,
                max_batch_items,
                batch_mode,
                notary_snippet_output,
                no_notary_snippet,
                sidecar_base_url,
                sidecar_token_env,
                allow_latest_adaptors,
                allow_empty_job_bodies,
            } => registryctl::import_openfn_project(OpenFnImportOptions {
                input,
                openfn_token_env,
                workflow,
                output,
                jobs_dir,
                expression_prefix,
                source_id,
                dataset,
                entity,
                credential_env,
                allowed_base_urls: allowed_base_url,
                smoke,
                smoke_fields,
                smoke_purpose,
                auth_hash_env,
                server_bind,
                cli_build_tool,
                runtime,
                worker_command,
                worker_script,
                max_workers,
                worker_timeout_ms,
                max_worker_memory_mb,
                max_output_bytes,
                max_request_bytes,
                max_query_parameter_bytes,
                max_batch_items,
                batch_mode,
                notary_snippet_output: if no_notary_snippet {
                    None
                } else {
                    notary_snippet_output
                },
                sidecar_base_url,
                sidecar_token_env,
                allow_latest_adaptors,
                allow_empty_job_bodies,
            })?,
            OpenFnCommand::Convert {
                input,
                workflow,
                output,
                jobs_dir,
                expression_prefix,
                source_id,
                dataset,
                entity,
                credential_env,
                allowed_base_url,
                smoke_field,
                smoke_value,
                smoke_fields,
                smoke_purpose,
                auth_hash_env,
                server_bind,
                cli_build_tool,
                runtime,
                worker_command,
                worker_script,
                max_workers,
                worker_timeout_ms,
                max_worker_memory_mb,
                max_output_bytes,
                max_request_bytes,
                max_query_parameter_bytes,
                max_batch_items,
                batch_mode,
                notary_snippet_output,
                sidecar_base_url,
                sidecar_token_env,
                allow_latest_adaptors,
                allow_empty_job_bodies,
            } => registryctl::convert_openfn_project(OpenFnConvertOptions {
                input,
                workflow,
                output,
                jobs_dir,
                expression_prefix,
                source_id,
                dataset,
                entity,
                credential_env,
                allowed_base_urls: allowed_base_url,
                smoke_field,
                smoke_value,
                smoke_fields,
                smoke_purpose,
                auth_hash_env,
                server_bind,
                cli_build_tool,
                runtime,
                worker_command,
                worker_script,
                max_workers,
                worker_timeout_ms,
                max_worker_memory_mb,
                max_output_bytes,
                max_request_bytes,
                max_query_parameter_bytes,
                max_batch_items,
                batch_mode,
                notary_snippet_output,
                sidecar_base_url,
                sidecar_token_env,
                allow_latest_adaptors,
                allow_empty_job_bodies,
            })?,
        },
        Commands::Lab { command } => match command {
            LabCommand::Env { credential, format } => registryctl::lab_env(&credential, format)?,
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

#[derive(Debug, Parser)]
#[command(name = "registryctl")]
#[command(version)]
#[command(about = "Create and run local Registry Commons projects")]
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
    /// Create a local Registry Commons project.
    Init {
        #[command(subcommand)]
        command: Box<InitCommand>,
    },
    /// Add a Registry Commons product to the current project.
    Add {
        #[command(subcommand)]
        command: AddCommand,
    },
    /// Start the local Registry Commons project.
    Start,
    /// Stop the local Registry Commons project.
    Stop,
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
    /// Inspect, diff, and package generated product config files.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Stream Compose logs for the local project.
    Logs,
    /// Work with the local Registry Notary product.
    Notary {
        #[command(subcommand)]
        command: NotaryCommand,
    },
    /// Work with OpenFn workflow exports.
    Openfn {
        #[command(subcommand)]
        command: Box<OpenFnCommand>,
    },
    /// Work with public hosted-lab quickstart helpers.
    Lab {
        #[command(subcommand)]
        command: LabCommand,
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
                | Self::Config { .. }
                | Self::Lab { .. }
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
    fn notary_init_cli_accepts_fhir_source_kind() {
        let cli = Cli::try_parse_from([
            "registryctl",
            "init",
            "notary",
            "my-fhir-notary",
            "--source-kind",
            "fhir-sidecar",
        ])
        .unwrap();

        let Commands::Init { command } = cli.command else {
            panic!("expected init command");
        };
        let InitCommand::Notary {
            source_kind,
            source_url,
            source_token_env,
            smoke_target_id,
            ..
        } = *command
        else {
            panic!("expected init notary command");
        };
        assert_eq!(source_kind, NotaryInitSourceKind::FhirSidecar);
        assert_eq!(source_url, None);
        assert_eq!(source_token_env, None);
        assert_eq!(smoke_target_id, None);
    }

    #[test]
    fn doctor_skips_automatic_update_check() {
        let cli = Cli::try_parse_from(["registryctl", "doctor"]).unwrap();

        assert!(!cli.command.should_check_for_updates());
    }

    #[test]
    fn config_cli_accepts_explain_diff_and_package() {
        let explain = Cli::try_parse_from([
            "registryctl",
            "config",
            "explain",
            "--product",
            "relay",
            "--format",
            "json",
        ])
        .unwrap();
        let Commands::Config { command } = explain.command else {
            panic!("expected config command");
        };
        assert!(matches!(
            command,
            ConfigCommand::Explain {
                product: ConfigProduct::Relay,
                format: DoctorFormat::Json
            }
        ));

        let diff =
            Cli::try_parse_from(["registryctl", "config", "diff", "--product", "notary"]).unwrap();
        let Commands::Config { command } = diff.command else {
            panic!("expected config command");
        };
        assert!(matches!(
            command,
            ConfigCommand::Diff {
                product: ConfigProduct::Notary,
                format: DoctorFormat::Json
            }
        ));

        let package = Cli::try_parse_from([
            "registryctl",
            "config",
            "package",
            "--output",
            "registry-config.zip",
            "--force",
        ])
        .unwrap();
        let Commands::Config { command } = package.command else {
            panic!("expected config command");
        };
        assert!(matches!(
            command,
            ConfigCommand::Package {
                output: Some(_),
                force: true
            }
        ));
    }

    #[test]
    fn hidden_update_refresh_skips_automatic_update_check() {
        let cli = Cli::try_parse_from(["registryctl", "__update-check-refresh"]).unwrap();

        assert!(matches!(cli.command, Commands::UpdateCheckRefresh));
        assert!(!cli.command.should_check_for_updates());
    }

    #[test]
    fn lab_env_cli_parses_credential_and_format() {
        let cli = Cli::try_parse_from([
            "registryctl",
            "lab",
            "env",
            "--credential",
            "agri-evidence",
            "--format",
            "json",
        ])
        .unwrap();

        let Commands::Lab { command } = cli.command else {
            panic!("expected lab command");
        };
        let LabCommand::Env { credential, format } = command;
        assert_eq!(credential, "agri-evidence");
        assert_eq!(format, LabEnvFormat::Json);
    }

    #[test]
    fn lab_env_skips_automatic_update_check() {
        let cli =
            Cli::try_parse_from(["registryctl", "lab", "env", "--credential", "agri-evidence"])
                .unwrap();

        assert!(!cli.command.should_check_for_updates());
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
    /// Create a standalone local Notary project for an existing API.
    Notary {
        /// Directory to create.
        dir: PathBuf,
        /// Source kind to use for the starter Notary project.
        #[arg(long, value_enum, default_value_t = NotaryInitSourceKind::RegistryDataApi)]
        source_kind: NotaryInitSourceKind,
        /// Source API base URL as seen from the Notary container.
        #[arg(long)]
        source_url: Option<String>,
        /// Read the source API bearer token from this process environment variable.
        #[arg(long)]
        source_token_from_env: Option<String>,
        /// Env var name Notary should read for the source API bearer token.
        #[arg(long)]
        source_token_env: Option<String>,
        /// Source dataset used by the starter claim.
        #[arg(long)]
        source_dataset: Option<String>,
        /// Source entity used by the starter claim.
        #[arg(long)]
        source_entity: Option<String>,
        /// Source field used by the starter claim lookup.
        #[arg(long)]
        source_lookup_field: Option<String>,
        /// Docker Compose network to join when the source API runs in another local Compose project.
        #[arg(long)]
        source_network: Option<String>,
        /// Starter claim id to generate.
        #[arg(long)]
        source_claim: Option<String>,
        /// Starter claim title to generate.
        #[arg(long)]
        source_claim_title: Option<String>,
        /// Target id used by generated smoke and Bruno evaluation requests.
        #[arg(long)]
        smoke_target_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AddCommand {
    /// Add a local Notary backed by the generated Relay project.
    Notary {
        /// Source to use for the Notary evidence connection.
        #[arg(long, value_enum)]
        from: NotarySource,
        /// Replace existing Notary generated files.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum NotaryCommand {
    /// Run built-in local Notary smoke checks.
    Smoke,
    /// Open or print the local Notary API docs URL.
    Open,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Delegate to the product explain-config command for a generated config.
    Explain {
        /// Product config to explain.
        #[arg(long, value_enum)]
        product: ConfigProduct,
        /// Output format.
        #[arg(long, value_enum, default_value_t = DoctorFormat::Json)]
        format: DoctorFormat,
    },
    /// Compare committed product config with registryctl's generated validation view.
    Diff {
        /// Product config to diff.
        #[arg(long, value_enum)]
        product: ConfigProduct,
        /// Output format.
        #[arg(long, value_enum, default_value_t = DoctorFormat::Json)]
        format: DoctorFormat,
    },
    /// Package inspectable generated config files without local secrets or outputs.
    Package {
        /// Zip file to write. Defaults to output/registry-config-package.zip.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Replace an existing package file.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum OpenFnCommand {
    /// Import an OpenFn workflow URL or exported YAML into a sidecar manifest.
    #[command(
        after_help = "Examples:\n  registryctl openfn import 'https://app.openfn.org/projects/<project-id>/w/<workflow-id>' --source person_lookup --dataset civil_registry --entity civil_person --credential-env REGISTRY_SOURCE_CREDENTIAL_JSON --smoke national_id=smoke-person\n  registryctl openfn import ./openfn.yaml --workflow person-lookup --source person_lookup --dataset civil_registry --entity civil_person --credential-env REGISTRY_SOURCE_CREDENTIAL_JSON --smoke national_id=smoke-person\n  registryctl openfn import ./openfn.yaml --workflow native-batch-person-lookup --source person_lookup --dataset civil_registry --entity civil_person --credential-env REGISTRY_SOURCE_CREDENTIAL_JSON --smoke national_id=smoke-person --batch-mode native"
    )]
    Import {
        /// OpenFn workflow URL or exported OpenFn YAML file.
        input: String,
        /// Env var containing an OpenFn API token for URL imports.
        #[arg(long, default_value = "OPENFN_TOKEN")]
        openfn_token_env: String,
        /// Workflow key to import. For URLs, omitted value is inferred from the workflow name when the API allows it.
        #[arg(long)]
        workflow: Option<String>,
        /// Sidecar manifest path to write.
        #[arg(long, default_value = "openfn/openfn-sidecar.yaml")]
        output: PathBuf,
        /// Local directory where OpenFn job expression files will be written.
        #[arg(long, default_value = "openfn/jobs")]
        jobs_dir: PathBuf,
        /// Path prefix written into the manifest for expression files.
        #[arg(long, default_value = "/opt/openfn/jobs")]
        expression_prefix: PathBuf,
        /// Sidecar source id to create.
        #[arg(long = "source", alias = "source-id")]
        source_id: String,
        /// Registry Data API dataset served by this source.
        #[arg(long)]
        dataset: String,
        /// Registry Data API entity served by this source.
        #[arg(long)]
        entity: String,
        /// Env var containing the sidecar credential JSON for this source.
        #[arg(long)]
        credential_env: String,
        /// Allowed base URL for credential baseUrl validation. Can be repeated.
        #[arg(long = "allowed-base-url")]
        allowed_base_url: Vec<String>,
        /// Smoke lookup as field=value.
        #[arg(long)]
        smoke: String,
        /// Comma-separated smoke response fields. Defaults to the smoke lookup field.
        #[arg(long)]
        smoke_fields: Option<String>,
        /// Smoke lookup purpose.
        #[arg(long, default_value = "startup-readiness-smoke")]
        smoke_purpose: String,
        /// Env var containing the notary-to-sidecar bearer token hash.
        #[arg(long, default_value = "DEV_SIDECAR_TOKEN_HASH")]
        auth_hash_env: String,
        /// Sidecar bind address.
        #[arg(long, default_value = "127.0.0.1:9191")]
        server_bind: String,
        /// Pinned OpenFn compiler/build tool version.
        #[arg(long, default_value = "1.2.5")]
        cli_build_tool: String,
        /// Pinned OpenFn runtime version.
        #[arg(long, default_value = "1.9.3")]
        runtime: String,
        /// Worker command.
        #[arg(long, default_value = "node")]
        worker_command: PathBuf,
        /// Worker script path as seen by the sidecar process.
        #[arg(long, default_value = "/opt/openfn/openfn_worker.mjs")]
        worker_script: PathBuf,
        /// Maximum worker processes.
        #[arg(long, default_value_t = 2)]
        max_workers: usize,
        /// Worker timeout in milliseconds.
        #[arg(long, default_value_t = 10000)]
        worker_timeout_ms: u64,
        /// Maximum worker memory in MiB.
        #[arg(long, default_value_t = 512)]
        max_worker_memory_mb: u64,
        /// Maximum worker output bytes.
        #[arg(long, default_value_t = 1048576)]
        max_output_bytes: usize,
        /// Maximum request body bytes.
        #[arg(long, default_value_t = 16384)]
        max_request_bytes: usize,
        /// Maximum query parameter bytes.
        #[arg(long, default_value_t = 1024)]
        max_query_parameter_bytes: usize,
        /// Maximum items accepted by sidecar records:batchMatch.
        #[arg(long, default_value_t = 100)]
        max_batch_items: usize,
        /// How the sidecar invokes this workflow for records:batchMatch.
        #[arg(long, value_enum, default_value = "per-item")]
        batch_mode: OpenFnBatchMode,
        /// Notary config snippet path to write. Use --no-notary-snippet to skip.
        #[arg(long, default_value = "openfn/notary-source-snippet.yaml")]
        notary_snippet_output: Option<PathBuf>,
        /// Do not write the generated Notary config snippet.
        #[arg(long = "no-notary-snippet", action = clap::ArgAction::SetTrue)]
        no_notary_snippet: bool,
        /// Base URL Notary should use for the sidecar in the generated snippet.
        #[arg(long)]
        sidecar_base_url: Option<String>,
        /// Env var containing the raw notary-to-sidecar bearer token.
        #[arg(long, default_value = "OPENFN_SIDECAR_TOKEN")]
        sidecar_token_env: String,
        /// Permit @latest adaptor specs in the generated sidecar manifest.
        #[arg(long)]
        allow_latest_adaptors: bool,
        /// Permit empty OpenFn job bodies.
        #[arg(long)]
        allow_empty_job_bodies: bool,
    },
    /// Convert an exported OpenFn project YAML into an OpenFn sidecar manifest.
    Convert {
        /// OpenFn project YAML exported from Lightning.
        #[arg(long)]
        input: PathBuf,
        /// Workflow key to convert. Required when the export has multiple workflows.
        #[arg(long)]
        workflow: Option<String>,
        /// Sidecar manifest path to write.
        #[arg(long, default_value = "openfn-sidecar.yaml")]
        output: PathBuf,
        /// Local directory where OpenFn job expression files will be written.
        #[arg(long, default_value = "openfn/jobs")]
        jobs_dir: PathBuf,
        /// Path prefix written into the manifest for expression files.
        #[arg(long)]
        expression_prefix: Option<PathBuf>,
        /// Sidecar source id to create.
        #[arg(long)]
        source_id: String,
        /// Registry Data API dataset served by this source.
        #[arg(long)]
        dataset: String,
        /// Registry Data API entity served by this source.
        #[arg(long)]
        entity: String,
        /// Env var containing the sidecar credential JSON for this source.
        #[arg(long)]
        credential_env: String,
        /// Allowed base URL for credential baseUrl validation. Can be repeated.
        #[arg(long = "allowed-base-url")]
        allowed_base_url: Vec<String>,
        /// Smoke lookup field.
        #[arg(long)]
        smoke_field: String,
        /// Smoke lookup value.
        #[arg(long)]
        smoke_value: String,
        /// Comma-separated smoke response fields. Defaults to smoke-field.
        #[arg(long)]
        smoke_fields: Option<String>,
        /// Smoke lookup purpose.
        #[arg(long, default_value = "startup-readiness-smoke")]
        smoke_purpose: String,
        /// Env var containing the notary-to-sidecar bearer token hash.
        #[arg(long, default_value = "DEV_SIDECAR_TOKEN_HASH")]
        auth_hash_env: String,
        /// Sidecar bind address.
        #[arg(long, default_value = "127.0.0.1:9191")]
        server_bind: String,
        /// Pinned OpenFn compiler/build tool version.
        #[arg(long, default_value = "1.2.5")]
        cli_build_tool: String,
        /// Pinned OpenFn runtime version.
        #[arg(long, default_value = "1.9.3")]
        runtime: String,
        /// Worker command.
        #[arg(long, default_value = "node")]
        worker_command: PathBuf,
        /// Worker script path as seen by the sidecar process.
        #[arg(long, default_value = "/opt/openfn/openfn_worker.mjs")]
        worker_script: PathBuf,
        /// Maximum worker processes.
        #[arg(long, default_value_t = 2)]
        max_workers: usize,
        /// Worker timeout in milliseconds.
        #[arg(long, default_value_t = 10000)]
        worker_timeout_ms: u64,
        /// Maximum worker memory in MiB.
        #[arg(long, default_value_t = 512)]
        max_worker_memory_mb: u64,
        /// Maximum worker output bytes.
        #[arg(long, default_value_t = 1048576)]
        max_output_bytes: usize,
        /// Maximum request body bytes.
        #[arg(long, default_value_t = 16384)]
        max_request_bytes: usize,
        /// Maximum query parameter bytes.
        #[arg(long, default_value_t = 1024)]
        max_query_parameter_bytes: usize,
        /// Maximum items accepted by sidecar records:batchMatch.
        #[arg(long, default_value_t = 100)]
        max_batch_items: usize,
        /// How the sidecar invokes this workflow for records:batchMatch.
        #[arg(long, value_enum, default_value = "per-item")]
        batch_mode: OpenFnBatchMode,
        /// Notary config snippet path to write.
        #[arg(long)]
        notary_snippet_output: Option<PathBuf>,
        /// Base URL Notary should use for the sidecar in the generated snippet.
        #[arg(long)]
        sidecar_base_url: Option<String>,
        /// Env var containing the raw notary-to-sidecar bearer token.
        #[arg(long, default_value = "OPENFN_SIDECAR_TOKEN")]
        sidecar_token_env: String,
        /// Permit @latest adaptor specs in the generated sidecar manifest.
        #[arg(long)]
        allow_latest_adaptors: bool,
        /// Permit empty OpenFn job bodies.
        #[arg(long)]
        allow_empty_job_bodies: bool,
    },
}

#[derive(Debug, Subcommand)]
enum LabCommand {
    /// Emit SDK-ready environment values from the public hosted lab manifest.
    Env {
        /// Hosted lab credential id to export.
        #[arg(long)]
        credential: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = LabEnvFormat::Shell)]
        format: LabEnvFormat,
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
