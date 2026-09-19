// SPDX-License-Identifier: Apache-2.0

//! The `scheduling` binary entry point.

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let matches = registry_scheduling::runtime::command().get_matches();
    if let Err(error) = registry_scheduling::runtime::run(&matches).await {
        eprintln!("scheduling: {error}");
        std::process::exit(1);
    }
}
