use registry_casework::operational_log_level;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() {
    let level = match operational_log_level(std::env::var("CASEWORK_LOG").ok().as_deref()) {
        Ok(level) => level,
        Err(error) => {
            eprintln!("casework: {error}");
            std::process::exit(2);
        }
    };
    initialize_logging(level);

    let matches = registry_casework::command().get_matches();
    if let Err(error) = registry_casework::run(&matches).await {
        eprintln!("casework: {error}");
        std::process::exit(1);
    }
}

fn initialize_logging(level: LevelFilter) {
    let filter = Targets::new()
        .with_target("registry_casework", level)
        .with_target("registry_casework_breg", level);
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_current_span(false)
                .with_span_list(false),
        )
        .init();
}
