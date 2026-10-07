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

    if let Some(refusal) = registry_casework::removed_command_refusal(std::env::args_os().skip(1)) {
        eprintln!("casework: {refusal}");
        std::process::exit(2);
    }
    let matches = registry_casework::command().get_matches();
    if let Err(error) = registry_casework::run(&matches).await {
        eprintln!("casework: {error}");
        if let Some(report) = error.configuration_report() {
            eprint!("{}", report.render_human());
        }
        let code = match error {
            registry_casework::RuntimeError::RemovedCommand(_) => 2,
            _ => 1,
        };
        std::process::exit(code);
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
