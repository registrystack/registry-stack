// SPDX-License-Identifier: Apache-2.0
//! Synchronous adaptor source sidecar entrypoint.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use registry_notary_openfn_sidecar::{
    create_local_tuf_demo_repo_report_json, load_startup_config_with_options,
    print_expression_hashes_report_json, render_governed_runtime_target_json, run,
    verify_governed_bundle_report_json, CreateLocalTufRepoOptions, LocalTufBundleVerifyOptions,
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(author, version, about = "Run the Registry Notary OpenFn sidecar")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// YAML sidecar config path.
    #[arg(short, long, env = "REGISTRY_NOTARY_OPENFN_SIDECAR_CONFIG")]
    config: Option<PathBuf>,
    /// Permit legacy unsigned manifests for local development only.
    #[arg(long, env = "REGISTRY_NOTARY_OPENFN_SIDECAR_ALLOW_UNSIGNED_DEV_CONFIG")]
    allow_unsigned_dev_config: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the sidecar HTTP server.
    Serve {
        /// YAML sidecar config path.
        #[arg(short, long, env = "REGISTRY_NOTARY_OPENFN_SIDECAR_CONFIG")]
        config: PathBuf,
        /// Permit legacy unsigned manifests for local development only.
        #[arg(long, env = "REGISTRY_NOTARY_OPENFN_SIDECAR_ALLOW_UNSIGNED_DEV_CONFIG")]
        allow_unsigned_dev_config: bool,
    },
    /// Build and verify governed runtime target material.
    Config {
        #[command(subcommand)]
        command: Box<ConfigCommand>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Render a governed runtime target from a sidecar manifest and jobs root.
    RenderTarget(RenderTargetArgs),
    /// Print exact SHA-256 hashes for every workflow expression in a target.
    PrintExpressionHashes(TargetFileArgs),
    /// Create a signed local TUF repository for demo and local verification.
    CreateLocalTufRepo(Box<CreateLocalTufRepoArgs>),
    /// Verify a target JSON file, or a local TUF target when TUF paths are supplied.
    VerifyBundle(Box<VerifyBundleArgs>),
}

#[derive(Debug, clap::Args)]
struct RenderTargetArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    jobs_root: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct TargetFileArgs {
    #[arg(long)]
    target: PathBuf,
}

#[derive(Debug, clap::Args)]
struct CreateLocalTufRepoArgs {
    #[arg(long)]
    target: PathBuf,
    #[arg(long)]
    target_name: String,
    #[arg(long)]
    root_path: PathBuf,
    #[arg(long)]
    signing_key_path: PathBuf,
    #[arg(long)]
    metadata_dir: PathBuf,
    #[arg(long)]
    targets_dir: PathBuf,
    #[arg(long)]
    product: String,
    #[arg(long)]
    instance_id: String,
    #[arg(long)]
    environment: String,
    #[arg(long)]
    stream_id: String,
    #[arg(long)]
    bundle_id: String,
    #[arg(long)]
    sequence: u64,
    #[arg(long)]
    previous_config_hash: String,
    #[arg(long = "change-class", required = true)]
    change_classes: Vec<String>,
    #[arg(long = "declared-signer-kid")]
    declared_signer_kids: Vec<String>,
    #[arg(long, default_value = "restart_required")]
    apply_policy: String,
    #[arg(long, default_value_t = 30)]
    targets_expiration_days: i64,
    #[arg(long, default_value_t = 30)]
    snapshot_expiration_days: i64,
    #[arg(long, default_value_t = 30)]
    timestamp_expiration_days: i64,
}

#[derive(Debug, clap::Args)]
struct VerifyBundleArgs {
    #[arg(long)]
    target: Option<PathBuf>,
    #[arg(long)]
    product: Option<String>,
    #[arg(long)]
    instance_id: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    stream_id: Option<String>,
    #[arg(long)]
    root_path: Option<PathBuf>,
    #[arg(long)]
    metadata_dir: Option<PathBuf>,
    #[arg(long)]
    targets_dir: Option<PathBuf>,
    #[arg(long)]
    datastore_dir: Option<PathBuf>,
    #[arg(long)]
    target_name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,registry_notary_openfn_sidecar=debug")),
        )
        .init();
    match args.command {
        Some(Command::Serve {
            config,
            allow_unsigned_dev_config,
        }) => serve(config, allow_unsigned_dev_config).await,
        Some(Command::Config { command }) => config_command(*command).await,
        None => {
            let config = args.config.ok_or("missing --config or subcommand")?;
            serve(config, args.allow_unsigned_dev_config).await
        }
    }
}

async fn serve(
    config: PathBuf,
    allow_unsigned_dev_config: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = tokio::fs::read_to_string(config).await?;
    let config = load_startup_config_with_options(&raw, allow_unsigned_dev_config).await?;
    run(config).await
}

async fn config_command(command: ConfigCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        ConfigCommand::RenderTarget(RenderTargetArgs {
            manifest,
            jobs_root,
            output,
        }) => {
            let raw = tokio::fs::read_to_string(manifest).await?;
            let target = render_governed_runtime_target_json(&raw, &jobs_root)?;
            write_or_print(output, &target).await?;
        }
        ConfigCommand::PrintExpressionHashes(TargetFileArgs { target }) => {
            let target = tokio::fs::read(target).await?;
            let report = print_expression_hashes_report_json(&target)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ConfigCommand::CreateLocalTufRepo(args) => {
            let report = create_local_tuf_demo_repo_report_json(CreateLocalTufRepoOptions {
                target_path: args.target,
                target_name: args.target_name,
                root_path: args.root_path,
                signing_key_path: args.signing_key_path,
                metadata_dir: args.metadata_dir,
                targets_dir: args.targets_dir,
                product: args.product,
                instance_id: args.instance_id,
                environment: args.environment,
                stream_id: args.stream_id,
                bundle_id: args.bundle_id,
                sequence: args.sequence,
                previous_config_hash: args.previous_config_hash,
                change_classes: args.change_classes,
                declared_signer_kids: args.declared_signer_kids,
                apply_policy: args.apply_policy,
                targets_expiration_days: args.targets_expiration_days,
                snapshot_expiration_days: args.snapshot_expiration_days,
                timestamp_expiration_days: args.timestamp_expiration_days,
            })
            .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ConfigCommand::VerifyBundle(args) => {
            let local_tuf = local_tuf_options(&args)?;
            let target_bytes = match (&args.target, &local_tuf) {
                (Some(path), None) => Some(tokio::fs::read(path).await?),
                (Some(_), Some(_)) => {
                    return Err(
                        "--target cannot be combined with local TUF verification options".into(),
                    )
                }
                (None, None) => {
                    return Err("--target or local TUF verification options are required".into())
                }
                (None, Some(_)) => None,
            };
            let report =
                verify_governed_bundle_report_json(target_bytes.as_deref(), local_tuf).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

fn local_tuf_options(
    args: &VerifyBundleArgs,
) -> Result<Option<LocalTufBundleVerifyOptions>, Box<dyn std::error::Error>> {
    let provided = [
        args.product.is_some(),
        args.instance_id.is_some(),
        args.environment.is_some(),
        args.stream_id.is_some(),
        args.root_path.is_some(),
        args.metadata_dir.is_some(),
        args.targets_dir.is_some(),
        args.datastore_dir.is_some(),
        args.target_name.is_some(),
    ];
    if provided.iter().all(|present| !present) {
        return Ok(None);
    }
    if !provided.iter().all(|present| *present) {
        return Err("local TUF verification requires product, instance-id, environment, stream-id, root-path, metadata-dir, targets-dir, datastore-dir, and target-name".into());
    }
    Ok(Some(LocalTufBundleVerifyOptions {
        product: args.product.clone().expect("checked above"),
        instance_id: args.instance_id.clone().expect("checked above"),
        environment: args.environment.clone().expect("checked above"),
        stream_id: args.stream_id.clone().expect("checked above"),
        root_path: args.root_path.clone().expect("checked above"),
        metadata_dir: args.metadata_dir.clone().expect("checked above"),
        targets_dir: args.targets_dir.clone().expect("checked above"),
        datastore_dir: args.datastore_dir.clone().expect("checked above"),
        target_name: args.target_name.clone().expect("checked above"),
    }))
}

async fn write_or_print(
    output: Option<PathBuf>,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(output) = output {
        tokio::fs::write(output, bytes).await?;
    } else {
        use std::io::Write;

        std::io::stdout().write_all(bytes)?;
    }
    Ok(())
}
