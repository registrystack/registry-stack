// SPDX-License-Identifier: Apache-2.0

//! The `scheduling` binary entry point.

#[tokio::main]
async fn main() {
    // Operational logs go to stderr whatever the audit destination is, so a
    // `stdout` audit destination carries audit entries alone.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let matches = registry_scheduling::runtime::command().get_matches();
    if let Err(error) = registry_scheduling::runtime::run(&matches).await {
        eprintln!("scheduling: {error}");
        std::process::exit(1);
    }
}
