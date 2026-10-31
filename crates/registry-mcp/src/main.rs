// SPDX-License-Identifier: Apache-2.0
use clap::Parser;
use registry_mcp::{
    cli::{Cli, Command, Format},
    config::RuntimeConfig,
    runtime,
};
use std::process::ExitCode;
use tracing::Level;
use tracing_subscriber::filter::Targets;

fn operational_targets(level: Level) -> Targets {
    Targets::new()
        .with_target("registry_mcp", level)
        .with_target("registry_mcp_edge", level)
        .with_target("registry_breg_mcp", level)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Command::Check(arguments) = cli.command {
        let check_path =
            std::path::absolute(&cli.runtime_config).unwrap_or_else(|_| cli.runtime_config.clone());
        let (report, unavailable) = RuntimeConfig::check_status(&check_path, arguments.environment);
        let failed = unavailable
            || report.has_errors()
            || (arguments.deny_warnings && report.warning_count() > 0);
        match arguments.format {
            Format::Human if failed => {
                let headline = if unavailable {
                    "registry-mcp check could not read all of its input."
                } else {
                    "registry-mcp check refused the input."
                };
                eprintln!("{headline}\n{}", report.render_human());
            }
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
        registry_mcp_edge::config::LogLevel::Error => Level::ERROR,
        registry_mcp_edge::config::LogLevel::Warn => Level::WARN,
        registry_mcp_edge::config::LogLevel::Info => Level::INFO,
    };
    tracing_subscriber::registry()
        .with(operational_targets(level))
        .with(tracing_subscriber::fmt::layer().json())
        .init();
    if config.resource_server.allow_insecure_http {
        tracing::warn!(
            "resourceServer.allowInsecureHttp permits plain HTTP to the configured issuer and to a JWKS URI declared in configuration"
        );
    }
    match runtime::serve(&config, shutdown_signal()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "the interrupt signal cannot be observed");
            std::future::pending::<()>().await;
        }
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                terminate.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "the terminate signal cannot be observed");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::IssuerNetworkPolicy;

    #[test]
    fn operational_logs_include_the_runtime_edge_and_breg_provider_only() {
        let targets = operational_targets(tracing::Level::INFO);
        assert!(targets.would_enable("registry_mcp", &tracing::Level::INFO));
        assert!(targets.would_enable("registry_mcp_edge::core", &tracing::Level::INFO));
        assert!(targets.would_enable("registry_breg_mcp::client", &tracing::Level::INFO));
        assert!(!targets.would_enable("registry_mcp", &tracing::Level::DEBUG));
        assert!(!targets.would_enable("reqwest", &tracing::Level::ERROR));
    }

    #[test]
    fn declared_jwks_fetch_policy_keeps_operator_declared_private_endpoints_bounded() {
        let production = IssuerNetworkPolicy::new("https://issuer.example.test", false)
            .expect("production issuer");
        assert_eq!(
            production.declared_jwks_fetch_policy(),
            FetchUrlPolicy {
                allowed_schemes: vec!["http".to_owned(), "https".to_owned()],
                allow_localhost: true,
                allow_http_private_network: false,
                allow_http_non_loopback: false,
                deny_private_ranges: false,
                deny_cloud_metadata: true,
            }
        );
        let insecure = IssuerNetworkPolicy::new("http://issuer.example.test", true)
            .expect("insecure issuer opt-in")
            .declared_jwks_fetch_policy();
        assert!(insecure.allow_http_non_loopback);
        assert!(insecure.deny_cloud_metadata);
        assert!(!insecure.allow_http_private_network);
    }
}
