//! The `evidence-oid4vp` binary.
//!
//! Three subcommands. `check` validates a deployment offline, without opening
//! a socket or reading secret material, `openapi` renders the HTTP contract,
//! and `serve` runs the verifier service until it is terminated.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use clap::Parser;
use registry_evidence_oid4vp::{
    cli::{Cli, Command, OutputFormat},
    config::{check_file, Oid4vpConfig},
    service::{serve, VerifierService},
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
            tracing::error!(target: "registry_evidence_oid4vp", "{message}");
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
        Command::Openapi { output } => {
            let mut rendered = serde_json::to_string_pretty(
                &registry_evidence_oid4vp::contracts::openapi_document(),
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
            // Install the stop handlers before binding, so a service that
            // cannot observe a stop request does not start. The handlers
            // register with the runtime's reactor, so they are installed
            // inside it.
            let shutdown = {
                let _entered = runtime.enter();
                registry_platform_httpsec::shutdown_signal().map_err(|error| {
                    format!("the stop signal handlers could not be installed: {error}")
                })?
            };
            runtime.block_on(async move {
                let service = Arc::new(VerifierService::load(config).await.map_err(|error| {
                    eprint!(
                        "{}",
                        Report::new(vec![error.diagnostic().clone()]).render_human()
                    );
                    format!("the service could not start: {error}")
                })?);
                serve(service, shutdown)
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

/// Load the runtime file as `serve` reads it.
///
/// A refusal prints the same position-first lines `check` prints to standard
/// error before the startup failure is logged, and a warning the file carries
/// is printed the same way without stopping startup.
fn load_config(path: &Path) -> Result<Oid4vpConfig, String> {
    let absolute = absolute_lexical(path)
        .map_err(|_| "the configuration path cannot be resolved".to_owned())?;
    match Oid4vpConfig::load_reporting(&absolute) {
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

/// The envelope of the JSON report, shared with the `evidence` binary.
const CHECK_REPORT_API_VERSION: &str = "id.registrystack.org/formats/evidence/ctl-report/v1alpha1";
const CHECK_REPORT_KIND: &str = "EvidenceCtlReport";

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
                "evidence.oid4vp.config-path",
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
                "apiVersion": CHECK_REPORT_API_VERSION,
                "kind": CHECK_REPORT_KIND,
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
