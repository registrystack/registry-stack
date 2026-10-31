// SPDX-License-Identifier: Apache-2.0
use clap::Parser;
use registry_mcp::{
    cli::{Cli, Command, Format},
    config::RuntimeConfig,
    runtime,
};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Command::Check(arguments) = cli.command {
        let (report, unavailable) =
            RuntimeConfig::check_status(&cli.runtime_config, arguments.environment);
        let failed = unavailable
            || report.has_errors()
            || (arguments.deny_warnings && report.warning_count() > 0);
        match arguments.format {
            Format::Human => print!("{}", report.render_human()),
            Format::Json => match serde_json::to_string_pretty(
                &serde_json::json!({"ok":!failed,"command":"check","status":if unavailable {"operational-failure"} else if failed {"domain-refusal"} else {"complete"},"apiVersion":"id.registrystack.org/formats/platform/mcp-ctl-report/v1alpha1","kind":"PlatformMcpCtlReport","version":env!("CARGO_PKG_VERSION"),"filesChecked":1,"errors":report.error_count(),"warnings":report.warning_count(),"diagnostics":report.to_json_value()}),
            ) {
                Ok(json) => println!("{json}"),
                Err(_) => {
                    eprintln!("registry-mcp: configuration report could not be encoded");
                    return ExitCode::from(3);
                }
            },
        }
        return if unavailable {
            ExitCode::from(3)
        } else if failed {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        };
    }
    let config = match RuntimeConfig::load(&cli.runtime_config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    // Restrict logging to the gateway's operational namespace.
    use tracing_subscriber::prelude::*;
    let level = match config.log_level {
        registry_breg_mcp::config::LogLevel::Error => tracing::Level::ERROR,
        registry_breg_mcp::config::LogLevel::Warn => tracing::Level::WARN,
        registry_breg_mcp::config::LogLevel::Info => tracing::Level::INFO,
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::filter::Targets::new()
                .with_target("registry_mcp", level)
                .with_target("registry_mcp_edge", level),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();
    let shutdown = async {
        if tokio::signal::ctrl_c().await.is_err() {
            tracing::error!("interrupt observation failed");
            std::future::pending::<()>().await;
        }
    };
    match runtime::serve(&config, shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
