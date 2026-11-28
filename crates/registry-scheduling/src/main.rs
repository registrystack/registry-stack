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
    let matches = registry_scheduling::runtime::command().get_matches();
    if registry_platform_config::has_repeated_posture_flag() {
        eprintln!("scheduling: [platform.posture.conflict] Declare --posture only once.");
        std::process::exit(2);
    }
    let flag = matches.get_one::<String>("posture").map(String::as_str);
    let posture = match registry_platform_config::declared(flag) {
        Ok(posture) => posture,
        Err(error) => {
            eprintln!(
                "scheduling: {}: {}\n  next: {}",
                error.code(),
                error.message(),
                error.suggested_action()
            );
            std::process::exit(2);
        }
    };
    if let Err(error) = registry_scheduling::runtime::run(&matches, posture).await {
        eprintln!("scheduling: {error}");
        if let Some(report) = error.configuration_report() {
            eprint!("{}", report.render_human());
        }
        std::process::exit(1);
    }
}
