// SPDX-License-Identifier: Apache-2.0

//! The `scheduling` binary entry point.

#[tokio::main]
async fn main() {
    // Operational logs go to stderr whatever the audit destination is, so a
    // `stdout` audit destination carries audit entries alone. `RUST_LOG`
    // selects verbosity and defaults to `info` when it is unset or invalid.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    if let Some(error) =
        registry_scheduling::runtime::removed_command_refusal(std::env::args_os().skip(1))
    {
        eprintln!("scheduling: {error}");
        std::process::exit(error.exit_code());
    }
    let matches = registry_scheduling::runtime::command().get_matches();
    if let Err(error) = registry_scheduling::runtime::run(&matches).await {
        eprintln!("scheduling: {error}");
        if let Some(report) = error.configuration_report() {
            eprint!("{}", report.render_human());
        }
        std::process::exit(error.exit_code());
    }
}
