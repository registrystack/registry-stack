use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use registryctl::{
    BundleSignOptions, ConsentKeygenOptions, ConsentSignOptions, DeploymentProfile, DoctorFormat,
    NotaryInitOptions, NotaryInitSourceKind, NotarySource, OpenFnBatchMode, OpenFnConvertOptions,
    OpenFnImportOptions, Sample,
};

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.should_check_for_updates() {
        registryctl::maybe_warn_about_update(env!("CARGO_PKG_VERSION"));
    }
    match cli.command {
        Commands::UpdateCheck => registryctl::update_check(env!("CARGO_PKG_VERSION"))?,
        Commands::UpdateCheckRefresh => registryctl::refresh_update_check_cache()?,
        Commands::Init { command } => {
            let image_lock = registryctl::load_registryctl_image_lock()?;
            match *command {
                InitCommand::Relay { dir, sample } => {
                    registryctl::init_spreadsheet_api(&dir, sample, &image_lock)?;
                }
                InitCommand::SpreadsheetApi { dir, sample } => {
                    registryctl::init_spreadsheet_api(&dir, sample, &image_lock)?;
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
                            source_token_env: source_token_env.unwrap_or_else(|| {
                                source_kind.default_source_token_env().to_string()
                            }),
                            source_dataset: source_dataset.unwrap_or_else(|| {
                                source_kind.default_source_dataset().to_string()
                            }),
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
                            smoke_target_id: smoke_target_id.unwrap_or_else(|| {
                                source_kind.default_smoke_target_id().to_string()
                            }),
                        },
                        &image_lock,
                    )?;
                }
            }
        }
        Commands::Add { command } => {
            let image_lock = registryctl::load_registryctl_image_lock()?;
            match command {
                AddCommand::Notary { from, force } => {
                    registryctl::add_notary(&std::env::current_dir()?, from, force, &image_lock)?;
                }
            }
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
        Commands::Notary { command } => match command {
            NotaryCommand::Smoke => registryctl::notary_smoke_project(&std::env::current_dir()?)?,
            NotaryCommand::Open => registryctl::notary_open_project(&std::env::current_dir()?)?,
        },
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
        Commands::Consent { command } => match command {
            ConsentCommand::Keygen { out_dir } => {
                print_json(&registryctl::generate_consent_keypair(
                    ConsentKeygenOptions { out_dir },
                )?)?;
            }
            ConsentCommand::Sign { payload, key, out } => {
                print_json(&registryctl::sign_consent_evidence(ConsentSignOptions {
                    payload,
                    key,
                    out,
                })?)?;
            }
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
    /// Restart the local Registry Commons project so config edits take effect.
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
    /// Work with the local Registry Notary product.
    Notary {
        #[command(subcommand)]
        command: NotaryCommand,
    },
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
    /// Generate keys and sign verified consent evidence.
    Consent {
        #[command(subcommand)]
        command: ConsentCommand,
    },
    /// Work with OpenFn workflow exports.
    Openfn {
        #[command(subcommand)]
        command: Box<OpenFnCommand>,
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
                | Self::Consent { .. }
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
    fn restart_cli_parses() {
        let cli = Cli::try_parse_from(["registryctl", "restart"]).unwrap();

        assert!(matches!(cli.command, Commands::Restart));
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
    fn notary_init_cli_accepts_opencrvs_dci_source_kind() {
        let cli = Cli::try_parse_from([
            "registryctl",
            "init",
            "notary",
            "my-opencrvs-notary",
            "--source-kind",
            "opencrvs-dci",
        ])
        .unwrap();

        let Commands::Init { command } = cli.command else {
            panic!("expected init command");
        };
        let InitCommand::Notary { source_kind, .. } = *command else {
            panic!("expected init notary command");
        };
        assert_eq!(source_kind, NotaryInitSourceKind::OpencrvsDci);
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

    #[test]
    fn consent_cli_accepts_keygen_and_sign() {
        let keygen = Cli::try_parse_from([
            "registryctl",
            "consent",
            "keygen",
            "--out-dir",
            "consent-keys",
        ])
        .unwrap();
        assert!(matches!(
            keygen.command,
            Commands::Consent {
                command: ConsentCommand::Keygen { .. }
            }
        ));
        assert!(!keygen.command.should_check_for_updates());

        let sign = Cli::try_parse_from([
            "registryctl",
            "consent",
            "sign",
            "--payload",
            "consent.json",
            "--key",
            "consent-keys/private.jwk",
            "--out",
            "consent.jws",
        ])
        .unwrap();
        assert!(matches!(
            sign.command,
            Commands::Consent {
                command: ConsentCommand::Sign { .. }
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
enum ConsentCommand {
    /// Generate an Ed25519 consent signing keypair in a new directory.
    Keygen {
        /// New directory that will receive private.jwk and public.jwk.
        #[arg(long, default_value = "consent-keys")]
        out_dir: PathBuf,
    },
    /// Validate and sign a ConsentEvidenceV1 JSON payload as compact JWS.
    Sign {
        /// ConsentEvidenceV1 payload JSON file.
        #[arg(long)]
        payload: PathBuf,
        /// Ed25519 private JWK file created by consent keygen.
        #[arg(long)]
        key: PathBuf,
        /// New compact-JWS output file.
        #[arg(long)]
        out: PathBuf,
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
