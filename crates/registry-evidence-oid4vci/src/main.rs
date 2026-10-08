//! The `evidence-oid4vci` binary.
//!
//! Four subcommands. `check` validates a deployment offline, without opening a
//! socket or reading secret material, `inspect` prints its derived metadata,
//! `openapi` renders the public contract, and `serve` runs the delivery service
//! until it is terminated.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use clap::Parser;
use registry_evidence_oid4vci::{
    cli::{Cli, Command, OutputFormat},
    config::{check_file, DeliveryConfig},
    service::{serve, DeliveryService},
};
use registry_platform_yaml::{Diagnostic, Report};

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Command::Check {
        config,
        format,
        deny_warnings,
        environment,
    } = &cli.command
    {
        return check(config, *format, *deny_warnings, *environment);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Startup failures name the failing stage, never the key material
            // or the file contents that produced them.
            tracing::error!(target: "registry_evidence_oid4vci", "{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Check {
            config,
            format,
            deny_warnings,
            environment,
        } => {
            if check(&config, format, deny_warnings, environment) == ExitCode::SUCCESS {
                Ok(())
            } else {
                Err("the configuration check did not pass".to_owned())
            }
        }
        Command::Inspect { config } => {
            let config = load_config(&config)?;
            let runtime = runtime()?;
            let document = runtime.block_on(async move {
                let service = DeliveryService::load(config)
                    .map_err(|error| format!("the service cannot be inspected: {error}"))?;
                service
                    .inspect()
                    .await
                    .map_err(|error| format!("the service metadata is unavailable: {error}"))
            })?;
            let rendered = serde_json::to_string_pretty(&document)
                .map_err(|_| "the service metadata could not be rendered".to_owned())?;
            println!("{rendered}");
            Ok(())
        }
        Command::Openapi { output } => {
            let mut rendered = serde_json::to_string_pretty(
                &registry_evidence_oid4vci::contracts::openapi_document(),
            )
            .map_err(|_| "the OpenAPI contract could not be rendered".to_owned())?;
            rendered.push('\n');
            if let Some(output) = output {
                std::fs::write(output, rendered).map_err(|error| {
                    format!("the OpenAPI contract could not be written: {error}")
                })?;
            } else {
                print!("{rendered}");
            }
            Ok(())
        }
        Command::Serve { config } => {
            let config = load_config(&config)?;
            let runtime = runtime()?;
            runtime.block_on(async move {
                let service = Arc::new(
                    DeliveryService::load(config)
                        .map_err(|error| format!("the service could not start: {error}"))?,
                );
                serve(service, shutdown_signal())
                    .await
                    .map_err(|error| format!("the listener failed: {error}"))
            })
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("the async runtime could not start: {error}"))
}

/// Load the runtime file as `serve` and `inspect` read it.
///
/// A refusal prints the same position-first lines `check` prints to standard
/// error before the startup failure is logged, and a warning the file carries
/// is printed the same way without stopping startup.
fn load_config(path: &Path) -> Result<DeliveryConfig, String> {
    let absolute = absolute_lexical(path)
        .map_err(|_| "the configuration path cannot be resolved".to_owned())?;
    match DeliveryConfig::load_reporting(&absolute) {
        Ok((config, warnings)) => {
            if !warnings.is_empty() {
                eprint!(
                    "{}",
                    Report::new(as_given(warnings, &absolute, path)).render_human()
                );
            }
            Ok(config)
        }
        Err(error) => {
            eprint!(
                "{}",
                Report::new(as_given(error.diagnostics().to_vec(), &absolute, path)).render_human()
            );
            Err(format!("the configuration could not be loaded: {error}"))
        }
    }
}

/// Check the runtime file at `path` offline (CFG-CHECK-1) and report it.
///
/// Exits 0 when the file passes, 1 when it breaks a rule or, under
/// `deny_warnings`, carries a warning, and 3 when it cannot be read. clap
/// exits 2 for an invalid command line before this runs.
fn check(path: &Path, format: OutputFormat, deny_warnings: bool, environment: bool) -> ExitCode {
    let (diagnostics, unavailable) = match absolute_lexical(path) {
        Ok(absolute) => {
            let check = check_file(&absolute, environment);
            (
                as_given(check.diagnostics, &absolute, path),
                check.unavailable,
            )
        }
        Err(_) => (
            vec![Diagnostic::error(
                "evidence.oid4vci.config-path",
                "",
                "the configuration path cannot be resolved against the working directory",
                "Pass an absolute path, or run the command from a directory that exists.",
            )],
            true,
        ),
    };
    let mut report = Report::new(diagnostics);
    report.set_files_checked(usize::from(!unavailable));
    let (status, code) = if unavailable {
        ("operational-failure", 3)
    } else if report.has_errors() || (deny_warnings && report.warning_count() > 0) {
        ("domain-refusal", 1)
    } else {
        ("complete", 0)
    };
    match format {
        OutputFormat::Human => eprint!("{}", report.render_human()),
        OutputFormat::Json => println!(
            "{}",
            serde_json::json!({
                "ok": code == 0,
                "command": "check",
                "status": status,
                "filesChecked": usize::from(!unavailable),
                "diagnostics": report.to_json_value(),
            })
        ),
    }
    ExitCode::from(code)
}

/// `path` made absolute against the working directory, with `.` and `..`
/// resolved by name, as the runtime loader requires.
fn absolute_lexical(path: &Path) -> std::io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut normal = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    Ok(normal)
}

/// `diagnostics` naming the file as the operator wrote its path rather than
/// as the loader was given it.
fn as_given(mut diagnostics: Vec<Diagnostic>, absolute: &Path, given: &Path) -> Vec<Diagnostic> {
    let absolute = absolute.display().to_string();
    let given = given.display().to_string();
    for diagnostic in &mut diagnostics {
        if let Some(source) = diagnostic.source.as_mut() {
            if source.file == absolute {
                source.file.clone_from(&given);
            }
        }
    }
    diagnostics
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                terminate.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_openapi_write_failure_keeps_the_operating_system_cause() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing_parent = directory.path().join("missing").join("contract.json");
        let error = run(Cli {
            command: Command::Openapi {
                output: Some(missing_parent),
            },
        })
        .expect_err("writing below a missing directory fails");

        assert!(
            error.starts_with("the OpenAPI contract could not be written: "),
            "error: {error}"
        );
        assert_ne!(error, "the OpenAPI contract could not be written");
    }
}
