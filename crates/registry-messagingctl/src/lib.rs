// SPDX-License-Identifier: Apache-2.0

//! `messagingctl`, the Registry Messaging adopter and local operator
//! tooling. `check` loads a runtime configuration and the package it names
//! exactly as `messaging serve` would, offline: no secret is resolved, no
//! database is reached, and no signing key is fetched.
//!
//! Exit codes: 0 when the check passes, 1 when the configuration or package
//! is refused, 2 for a usage error, and 3 when a file could not be read or
//! the report could not be written.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_messaging::config::{RuntimeConfig, RuntimeConfigError};
use serde_json::{json, Value};

#[derive(Debug, Parser)]
#[command(
    name = "messagingctl",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Registry Messaging adopter and local operator tooling"
)]
struct Cli {
    /// Emit the selected command's report in this format.
    #[arg(long, value_enum, global = true, default_value_t)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check a runtime configuration and its package offline.
    Check(CheckArgs),
}

#[derive(Debug, Args)]
struct CheckArgs {
    /// Absolute path to the runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

const REFUSAL_EXIT: u8 = 1;
const USAGE_EXIT: u8 = 2;
const OPERATIONAL_FAILURE_EXIT: u8 = 3;

/// The clap command tree, for the generated CLI reference.
#[must_use]
pub fn command() -> clap::Command {
    Cli::command()
}

pub fn main_entry() -> ExitCode {
    main_entry_from(
        std::env::args_os(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}

fn main_entry_from<I, T>(
    args: I,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let machine_mode = args
        .windows(2)
        .any(|pair| pair[0] == OsStr::new("--format") && pair[1] == OsStr::new("json"))
        || args.iter().any(|arg| arg == OsStr::new("--format=json"));
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            return match write!(stdout, "{error}") {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::from(OPERATIONAL_FAILURE_EXIT),
            };
        }
        Err(error) => {
            let report = json!({
                "ok": false,
                "diagnostics": [{"code": "usage.invalid", "path": "/", "message": error.to_string()}]
            });
            let format = if machine_mode {
                OutputFormat::Json
            } else {
                OutputFormat::Human
            };
            return finish(&report, format, USAGE_EXIT, stdout, stderr);
        }
    };
    let (report, exit) = match cli.command {
        Command::Check(args) => check(&args.runtime_config),
    };
    finish(&report, cli.format, exit, stdout, stderr)
}

/// Load the configuration and package the way `messaging serve` does, and
/// report what the runtime would serve.
fn check(path: &std::path::Path) -> (Value, u8) {
    let loaded = RuntimeConfig::load(path).and_then(|config| {
        let profiles = config.load_package()?;
        Ok((config, profiles))
    });
    match loaded {
        Ok((config, profiles)) => {
            let profiles: Vec<Value> = profiles
                .iter()
                .map(|profile| json!({"id": profile.id, "role": profile.role}))
                .collect();
            (
                json!({
                    "ok": true,
                    "runtimeConfig": path,
                    "listener": config.listener.bind.to_string(),
                    "metricsListener": config.metrics_listener.as_ref().map(|metrics| metrics.bind.to_string()),
                    "accessProfiles": profiles,
                    "retention": config.retention,
                }),
                0,
            )
        }
        Err(error) => {
            let exit = match error {
                RuntimeConfigError::Read(_) | RuntimeConfigError::PackageRead(_) => {
                    OPERATIONAL_FAILURE_EXIT
                }
                _ => REFUSAL_EXIT,
            };
            (
                json!({
                    "ok": false,
                    "diagnostics": [{
                        "code": "config.refused",
                        "path": error.path(),
                        "message": error.to_string(),
                    }]
                }),
                exit,
            )
        }
    }
}

/// Write the report and return the exit code, or the operational failure
/// code when the report itself could not be written.
fn finish(
    report: &Value,
    format: OutputFormat,
    exit: u8,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    let written = match format {
        OutputFormat::Json => serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout)),
        OutputFormat::Human => render_human(report, stdout, stderr),
    };
    match written {
        Ok(()) => ExitCode::from(exit),
        Err(_) => {
            // The report could not be written; this line may not land either,
            // and the exit code carries the failure regardless.
            let _ = writeln!(stderr, "messagingctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn render_human(
    report: &Value,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> io::Result<()> {
    if report["ok"] == json!(true) {
        writeln!(
            stdout,
            "ok: {}",
            report["runtimeConfig"].as_str().unwrap_or("")
        )?;
        writeln!(
            stdout,
            "listener: {}",
            report["listener"].as_str().unwrap_or("")
        )?;
        match report["metricsListener"].as_str() {
            Some(bind) => writeln!(stdout, "metrics listener: {bind}")?,
            None => writeln!(stdout, "metrics listener: none")?,
        }
        for profile in report["accessProfiles"].as_array().into_iter().flatten() {
            writeln!(
                stdout,
                "access profile: {} ({})",
                profile["id"].as_str().unwrap_or(""),
                profile["role"].as_str().unwrap_or("")
            )?;
        }
        let retention = &report["retention"];
        writeln!(
            stdout,
            "retention: payload {} days, record {} days, submission receipt {} days",
            retention["payloadDays"], retention["recordDays"], retention["submissionReceiptDays"]
        )
    } else {
        for diagnostic in report["diagnostics"].as_array().into_iter().flatten() {
            writeln!(
                stderr,
                "messagingctl: {} ({})",
                diagnostic["message"].as_str().unwrap_or(""),
                diagnostic["path"].as_str().unwrap_or("/")
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const PACKAGE: &str = r"apiVersion: registry.registrystack.org/messaging-package/v1alpha1
kind: MessagingPackage
accessProfiles:
  - id: operations
    principalClaim: sub
    requiredScopes: [messaging:operate]
    requesterClients: [operations-console]
    role: operator
    requestsPerMinute: 60
    burst: 10
";

    fn runtime(root: &Path, extra: &str) -> String {
        format!(
            r"apiVersion: registry.registrystack.org/messaging-runtime/v1alpha1
kind: MessagingRuntimeConfig
package:
  root: {root}/package
listener:
  bind: 127.0.0.1:8107
  tlsTermination: development-loopback
metricsListener:
  bind: 127.0.0.1:9107
secretProviders:
  environment: {{}}
database:
  runtimeUrlRef: secret:env/MESSAGING_RUNTIME_URL
  migrationUrlRef: secret:env/MESSAGING_MIGRATION_URL
authentication:
  oidc:
    issuer: https://identity.example.test
    audience: urn:example:messaging
    allowedClients: [operations-console]
audit:
  path: {root}/audit/messaging.jsonl
  hashKeyRef: secret:env/MESSAGING_AUDIT_KEY
{extra}",
            root = root.display()
        )
    }

    fn project(extra: &str) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("package")).unwrap();
        std::fs::write(root.path().join("package/messaging.yaml"), PACKAGE).unwrap();
        let path = root.path().join("runtime.yaml");
        std::fs::write(&path, runtime(root.path(), extra)).unwrap();
        (root, path)
    }

    fn run(arguments: &[&OsStr]) -> (ExitCode, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut args = vec![OsStr::new("messagingctl")];
        args.extend_from_slice(arguments);
        let exit = main_entry_from(args, &mut stdout, &mut stderr);
        (
            exit,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    fn check_json(path: &Path) -> (ExitCode, Value) {
        let (exit, stdout, _) = run(&[
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("check"),
            OsStr::new("--runtime-config"),
            path.as_os_str(),
        ]);
        (exit, serde_json::from_str(&stdout).unwrap())
    }

    #[test]
    fn the_package_formats_are_the_ones_the_runtime_reads() {
        assert!(PACKAGE.contains(registry_messaging_core::MESSAGING_PACKAGE_API_VERSION));
        assert!(PACKAGE.contains(registry_messaging_core::MESSAGING_PACKAGE_KIND));
        let (root, _) = project("");
        let runtime = runtime(root.path(), "");
        assert!(runtime.contains(registry_messaging_core::MESSAGING_RUNTIME_API_VERSION));
        assert!(runtime.contains(registry_messaging_core::MESSAGING_RUNTIME_KIND));
    }

    #[test]
    fn a_valid_configuration_passes_and_reports_what_would_be_served() {
        let (_root, path) = project("");
        let (exit, report) = check_json(&path);
        assert_eq!(exit, ExitCode::SUCCESS, "{report}");
        assert_eq!(report["ok"], true);
        assert_eq!(report["metricsListener"], "127.0.0.1:9107");
        assert_eq!(report["accessProfiles"][0]["id"], "operations");
        assert_eq!(report["accessProfiles"][0]["role"], "operator");
        assert_eq!(report["retention"]["payloadDays"], 7);

        let (exit, stdout, stderr) = run(&[
            OsStr::new("check"),
            OsStr::new("--runtime-config"),
            path.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(
            stdout.contains("access profile: operations (operator)"),
            "{stdout}"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn an_unknown_key_is_refused_with_its_path() {
        let (_root, path) = project("surprise: true\n");
        let (exit, report) = check_json(&path);
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert_eq!(report["ok"], false);
        assert_eq!(report["diagnostics"][0]["code"], "config.refused");
        assert!(report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("surprise"));
    }

    #[test]
    fn an_environment_expression_in_a_secret_reference_is_refused() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("package")).unwrap();
        std::fs::write(root.path().join("package/messaging.yaml"), PACKAGE).unwrap();
        let document = runtime(root.path(), "").replace(
            "secret:env/MESSAGING_AUDIT_KEY",
            "secret:env/${AUDIT_KEY_NAME:-MESSAGING_AUDIT_KEY}",
        );
        let path = root.path().join("runtime.yaml");
        std::fs::write(&path, document).unwrap();
        let (exit, report) = check_json(&path);
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert_eq!(report["diagnostics"][0]["path"], "audit.hashKeyRef");
    }

    #[test]
    fn a_human_refusal_goes_to_standard_error() {
        let (_root, path) = project("retention:\n  payloadDays: 31\n");
        let (exit, stdout, stderr) = run(&[
            OsStr::new("check"),
            OsStr::new("--runtime-config"),
            path.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert!(stdout.is_empty());
        assert!(stderr.contains("retention is out of bounds"), "{stderr}");
    }

    #[test]
    fn a_missing_file_is_an_operational_failure() {
        let root = tempfile::tempdir().unwrap();
        let (exit, report) = check_json(&root.path().join("absent.yaml"));
        assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT));
        assert_eq!(report["ok"], false);
    }

    #[test]
    fn usage_errors_exit_two_and_answer_json_in_machine_mode() {
        let (exit, stdout, _) = run(&[
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("check"),
        ]);
        assert_eq!(exit, ExitCode::from(USAGE_EXIT));
        let report: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
        let (exit, _, stderr) = run(&[OsStr::new("send")]);
        assert_eq!(exit, ExitCode::from(USAGE_EXIT));
        assert!(!stderr.is_empty());
    }

    #[test]
    fn the_format_values_match_every_sibling_ctl() {
        for format in ["human", "json"] {
            assert!(Cli::try_parse_from([
                "messagingctl",
                "--format",
                format,
                "check",
                "--runtime-config",
                "/etc/messaging/runtime.yaml"
            ])
            .is_ok());
        }
        assert!(Cli::try_parse_from([
            "messagingctl",
            "--format",
            "yaml",
            "check",
            "--runtime-config",
            "/etc/messaging/runtime.yaml"
        ])
        .is_err());
    }
}
