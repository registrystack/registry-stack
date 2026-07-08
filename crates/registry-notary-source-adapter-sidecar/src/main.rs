// SPDX-License-Identifier: Apache-2.0
// Registry Notary source adapter sidecar entrypoint.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use registry_notary_source_adapter_sidecar::{
    load_startup_config_with_options, render_governed_runtime_target_json, run,
    verify_governed_bundle_report_json,
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Run the Registry Notary source adapter sidecar"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// YAML sidecar config path.
    #[arg(short, long, env = "REGISTRY_NOTARY_SOURCE_ADAPTER_SIDECAR_CONFIG")]
    config: Option<PathBuf>,
    /// Permit legacy unsigned manifests for local development only.
    #[arg(
        long,
        env = "REGISTRY_NOTARY_SOURCE_ADAPTER_SIDECAR_ALLOW_UNSIGNED_DEV_CONFIG"
    )]
    allow_unsigned_dev_config: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the sidecar HTTP server.
    Serve {
        /// YAML sidecar config path.
        #[arg(short, long, env = "REGISTRY_NOTARY_SOURCE_ADAPTER_SIDECAR_CONFIG")]
        config: Option<PathBuf>,
        /// Permit legacy unsigned manifests for local development only.
        #[arg(
            long,
            env = "REGISTRY_NOTARY_SOURCE_ADAPTER_SIDECAR_ALLOW_UNSIGNED_DEV_CONFIG"
        )]
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
    /// Render a governed runtime target from a sidecar manifest.
    RenderTarget(RenderTargetArgs),
    /// Verify a governed runtime target JSON file.
    VerifyBundle(Box<VerifyBundleArgs>),
}

#[derive(Debug, clap::Args)]
struct RenderTargetArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct VerifyBundleArgs {
    #[arg(long)]
    target: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("info,registry_notary_source_adapter_sidecar=debug")
        }))
        .init();
    match args.command {
        Some(Command::Serve {
            config,
            allow_unsigned_dev_config,
        }) => {
            let config = resolve_config(config)?;
            serve(config, allow_unsigned_dev_config).await
        }
        Some(Command::Config { command }) => config_command(*command).await,
        None => {
            let config = resolve_config(args.config)?;
            serve(config, args.allow_unsigned_dev_config).await
        }
    }
}

fn resolve_config(config: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    config.ok_or_else(|| "missing --config or subcommand".into())
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
        ConfigCommand::RenderTarget(RenderTargetArgs { manifest, output }) => {
            let raw = tokio::fs::read_to_string(manifest).await?;
            let target = render_governed_runtime_target_json(&raw)?;
            write_or_print(output, &target).await?;
        }
        ConfigCommand::VerifyBundle(args) => {
            let target_bytes = tokio::fs::read(args.target).await?;
            let report = verify_governed_bundle_report_json(&target_bytes).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
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
