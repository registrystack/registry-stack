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
    if registry_platform_config::has_repeated_posture_flag() {
        eprintln!("casework: [platform.posture.conflict] Declare --posture only once.");
        std::process::exit(2);
    }
    let declared = match registry_platform_config::declared(
        matches.get_one::<String>("posture").map(String::as_str),
    ) {
        Ok(declared) => declared,
        Err(error) => {
            eprintln!(
                "casework: [{}] {}\n  next: {}",
                error.code(),
                error.message(),
                error.suggested_action()
            );
            std::process::exit(2);
        }
    };
    if let Err(error) = registry_casework::run(&matches, declared).await {
        eprintln!("casework: {error}");
        if let Some(report) = error.configuration_report() {
            eprint!("{}", report.render_human());
        }
        std::process::exit(1);
    }
}

fn initialize_logging(level: LevelFilter) {
    let filter = Targets::new()
        .with_target("registry_casework", level)
        .with_target("registry_casework_breg", level)
        .with_target("registry_platform_config::posture", level);
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
