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
        .with_target("registry_platform_config::posture", Level::INFO)
        .with_target("registry_breg_mcp", level)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let flag = cli.posture.as_deref();
    let production = matches!(&cli.command, Command::Check(arguments) if arguments.production);
    let usage_error = |code: &str, message: &str, action: &str| {
        if matches!(&cli.command, Command::Check(arguments) if matches!(arguments.format, Format::Json))
        {
            println!(
                "{}",
                serde_json::json!({
                    "apiVersion": "id.registrystack.org/formats/platform/mcp-ctl-report/v1alpha1",
                    "kind": "PlatformMcpCtlReport",
                    "version": env!("CARGO_PKG_VERSION"),
                    "command": "check",
                    "status": "usage-error",
                    "ok": false,
                    "filesChecked": 0,
                    "errors": 1,
                    "warnings": 0,
                    "diagnostics": [{"severity": "error", "code": code, "path": "", "message": message, "suggestedAction": action}],
                })
            );
        } else {
            eprintln!("{code}: {message}. {action}");
        }
        ExitCode::from(2)
    };
    if production && flag == Some("development") {
        return usage_error(
            "platform.posture.conflict",
            "--production and --posture development contradict each other",
            "Use one of them.",
        );
    }
    let flag = if production {
        flag.or(Some("production"))
    } else {
        flag
    };
    let declared = match registry_platform_config::declared(flag) {
        Ok(declared) => declared,
        Err(error) => return usage_error(error.code(), error.message(), error.suggested_action()),
    };

    if let Command::Check(arguments) = cli.command {
        let check_path =
            std::path::absolute(&cli.runtime_config).unwrap_or_else(|_| cli.runtime_config.clone());
        let (report, unavailable) =
            RuntimeConfig::check_status_with_posture(&check_path, arguments.environment, declared);
        let failed = unavailable
            || report.has_errors()
            || (arguments.deny_warnings
                && registry_platform_config::has_denied_warnings(report.diagnostics()));
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
                &serde_json::json!({"ok":!failed,"command":"check","status":if unavailable {"operational-failure"} else if failed {"domain-refusal"} else {"complete"},"apiVersion":"id.registrystack.org/formats/platform/mcp-ctl-report/v1alpha1","kind":"PlatformMcpCtlReport","version":env!("CARGO_PKG_VERSION"),"filesChecked":1,"errors":report.error_count(),"warnings":report.warning_count(),"diagnostics":report.to_json_value(),"posture":{"value":declared.posture.as_str(),"source":declared.source.as_str()}}),
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
    let loaded = match RuntimeConfig::load_with_posture(&cli.runtime_config, declared) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    // Restrict logging to the gateway's operational namespace.
    use tracing_subscriber::prelude::*;
    let config = &loaded.config;
    let level = match config.log_level {
        registry_mcp_edge::config::LogLevel::Error => Level::ERROR,
        registry_mcp_edge::config::LogLevel::Warn => Level::WARN,
        registry_mcp_edge::config::LogLevel::Info => Level::INFO,
    };
    tracing_subscriber::registry()
        .with(operational_targets(level))
        .with(tracing_subscriber::fmt::layer().json())
        .init();
    loaded.posture.log_startup();
    let shutdown = match shutdown_after(registry_platform_httpsec::shutdown_signal) {
        Ok(shutdown) => shutdown,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime::serve(&loaded, shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Installs the stop-signal handlers before the gateway starts serving. An
/// install failure refuses startup, so the process is never left with no way
/// to be stopped by a signal.
fn shutdown_after<I, S>(
    install: I,
) -> Result<impl std::future::Future<Output = ()> + Send + 'static, String>
where
    I: FnOnce() -> std::io::Result<S>,
    S: std::future::Future<Output = ()> + Send + 'static,
{
    let signal =
        install().map_err(|error| format!("the stop signals cannot be observed: {error}"))?;
    Ok(async move {
        signal.await;
        tracing::info!("shutting down");
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::IssuerNetworkPolicy;

    #[test]
    fn a_stop_signal_install_failure_refuses_startup() {
        let error = shutdown_after(|| -> std::io::Result<std::future::Pending<()>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "install refused",
            ))
        })
        .err()
        .expect("an install failure is an error, never a silent wait");
        assert!(error.contains("stop signals cannot be observed"), "{error}");
        assert!(error.contains("install refused"), "{error}");
    }

    #[tokio::test]
    async fn the_shutdown_future_resolves_when_the_signal_fires() {
        let shutdown = shutdown_after(|| Ok(std::future::ready(()))).expect("installs");
        tokio::time::timeout(std::time::Duration::from_secs(5), shutdown)
            .await
            .expect("a fired signal resolves the shutdown future");
    }

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
