// SPDX-License-Identifier: Apache-2.0
//! Synchronous adaptor source sidecar entrypoint.

use std::path::PathBuf;

use clap::Parser;
use registry_notary_openfn_sidecar::{run, SidecarConfig};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(author, version, about = "Run the Registry Notary OpenFn sidecar")]
struct Args {
    /// YAML sidecar config path.
    #[arg(short, long, env = "REGISTRY_NOTARY_OPENFN_SIDECAR_CONFIG")]
    config: PathBuf,
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
    let raw = tokio::fs::read_to_string(args.config).await?;
    let config: SidecarConfig = serde_norway::from_str(&raw)?;
    run(config).await
}
