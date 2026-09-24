// SPDX-License-Identifier: Apache-2.0

//! `messagingctl`, the Registry Messaging adopter and local operator
//! tooling.
//!
//! - `init` writes the starter package and runtime example.
//! - `check` loads a package, or a runtime configuration and the package it
//!   names, exactly as `messaging serve` would, offline: no secret is
//!   resolved, no database is reached, and no signing key is fetched. It
//!   reports the package digest and renders every template's sample.
//! - `preview` renders one template version with given data, offline, and
//!   in JSON prints the exact bytes the runtime's preview route answers.
//! - `apply` compares the package with the database's package ledger, and
//!   with `--apply` records it as the package the runtime serves after its
//!   next restart.
//!
//! Exit codes: 0 when the command succeeds, 1 when the configuration,
//! package, or preview is refused, 2 for a usage error, and 3 when a file,
//! secret, or database could not be reached or the report could not be
//! written.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_messaging::config::{RuntimeConfig, RuntimeConfigError};
use registry_messaging::http::preview_json;
use registry_messaging::package::{load_package, LoadedPackage};
use registry_messaging::runtime::{apply_package, PackageChange, RuntimeError};
use registry_messaging_core::{ContentRefusal, TemplatePreviewRequest};
use serde_json::{json, Value};

mod starter;

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
    /// Write the starter package and runtime example into a new directory.
    Init(InitArgs),
    /// Check a package, or a runtime configuration and its package, offline.
    Check(CheckArgs),
    /// Render one template version with the given data, offline.
    Preview(PreviewArgs),
    /// Compare the package with the package ledger, and record it with
    /// --apply.
    Apply(ApplyArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// The directory to create. It must not exist.
    #[arg(value_name = "DIRECTORY")]
    directory: PathBuf,
}

/// Where a command reads the package from: a package directory, or the
/// runtime configuration that names one and may pin its digest.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("source").required(true).multiple(false)))]
struct PackageSource {
    /// Absolute path to the runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE", group = "source")]
    runtime_config: Option<PathBuf>,
    /// The package directory holding messaging.yaml.
    #[arg(long, value_name = "DIRECTORY", group = "source")]
    package: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct CheckArgs {
    #[command(flatten)]
    source: PackageSource,
}

#[derive(Debug, Args)]
struct PreviewArgs {
    #[command(flatten)]
    source: PackageSource,
    /// The template id.
    #[arg(value_name = "TEMPLATE")]
    template: String,
    /// The template version.
    #[arg(value_name = "VERSION")]
    version: String,
    /// A locale the template version declares.
    #[arg(long, value_name = "LOCALE")]
    locale: String,
    /// A JSON file holding the template data.
    #[arg(long, value_name = "FILE")]
    data: PathBuf,
}

#[derive(Debug, Args)]
struct ApplyArgs {
    /// Absolute path to the runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
    /// Record the package in the ledger. Without it, only report the change.
    #[arg(long)]
    apply: bool,
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

/// The largest template data file `preview` reads.
const MAXIMUM_DATA_BYTES: u64 = 1024 * 1024;

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

/// One command's result: the report, its exit code, and how a person reads
/// it. `raw_json`, when set, is printed in JSON mode instead of the report.
struct Outcome {
    report: Value,
    exit: u8,
    view: View,
    raw_json: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
enum View {
    Init,
    Check,
    Preview,
    Apply,
}

impl Outcome {
    fn new(report: Value, view: View) -> Self {
        Self {
            report,
            exit: 0,
            view,
            raw_json: None,
        }
    }

    fn refused(exit: u8, code: &str, path: &str, message: String) -> Self {
        Self {
            report: json!({
                "ok": false,
                "diagnostics": [{"code": code, "path": path, "message": message}]
            }),
            exit,
            view: View::Check,
            raw_json: None,
        }
    }
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
            let outcome = Outcome {
                report,
                exit: USAGE_EXIT,
                view: View::Check,
                raw_json: None,
            };
            return finish(&outcome, format, stdout, stderr);
        }
    };
    let outcome = match cli.command {
        Command::Init(args) => init(&args.directory),
        Command::Check(args) => check(&args.source),
        Command::Preview(args) => preview(&args),
        Command::Apply(args) => apply(&args.runtime_config, args.apply),
    };
    finish(&outcome, cli.format, stdout, stderr)
}

fn init(directory: &Path) -> Outcome {
    match starter::write(directory) {
        Ok(created) => Outcome::new(
            json!({
                "ok": true,
                "directory": directory,
                "created": created,
                "next": [
                    "Run messagingctl check --package DIRECTORY.",
                    "Copy runtime.example.yaml to runtime.yaml, set its absolute paths and secret references, run messaging migrate, then messagingctl apply --apply, then messaging serve.",
                ],
            }),
            View::Init,
        ),
        Err(starter::InitError::Exists) => Outcome::refused(
            REFUSAL_EXIT,
            "init.exists",
            "/",
            "the directory already exists; init never overwrites".to_owned(),
        ),
        Err(starter::InitError::Io(error)) => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "init.write-failed",
            "/",
            format!("the starter could not be written: {error}"),
        ),
    }
}

/// Load the package as `messaging serve` does: from the runtime
/// configuration, which also verifies a pinned digest and the admitted
/// clients, or from a bare package directory.
fn load(source: &PackageSource) -> Result<(Option<RuntimeConfig>, LoadedPackage), Outcome> {
    match (&source.runtime_config, &source.package) {
        (Some(path), _) => {
            let loaded = RuntimeConfig::load(path).and_then(|config| {
                let package = config.load_package()?;
                Ok((config, package))
            });
            loaded
                .map(|(config, package)| (Some(config), package))
                .map_err(|error| config_refusal(&error))
        }
        (None, Some(root)) => load_package(root)
            .map(|package| (None, package))
            .map_err(|error| {
                let exit = if error.is_read_failure() {
                    OPERATIONAL_FAILURE_EXIT
                } else {
                    REFUSAL_EXIT
                };
                Outcome::refused(exit, "config.refused", error.path(), error.to_string())
            }),
        (None, None) => Err(Outcome::refused(
            USAGE_EXIT,
            "usage.invalid",
            "/",
            "name --runtime-config or --package".to_owned(),
        )),
    }
}

fn config_refusal(error: &RuntimeConfigError) -> Outcome {
    let exit = match error {
        RuntimeConfigError::Read(_) => OPERATIONAL_FAILURE_EXIT,
        RuntimeConfigError::Package(error) if error.is_read_failure() => OPERATIONAL_FAILURE_EXIT,
        _ => REFUSAL_EXIT,
    };
    Outcome::refused(exit, "config.refused", error.path(), error.to_string())
}

/// Report what the runtime would serve, rendering each template's sample
/// in every locale it declares.
fn check(source: &PackageSource) -> Outcome {
    let (config, loaded) = match load(source) {
        Ok(loaded) => loaded,
        Err(refused) => return refused,
    };
    let package = &loaded.package;
    let profiles: Vec<Value> = package
        .access_profiles()
        .iter()
        .map(|profile| json!({"id": profile.id, "role": profile.role}))
        .collect();
    let mut templates = Vec::new();
    for template in package.templates() {
        let mut samples = Vec::new();
        if let Some(sample) = template.sample() {
            for locale in template.locales() {
                // The package check rendered every sample in every locale, so
                // a sample that stopped rendering here is a defect to report,
                // never one to hide.
                let request = TemplatePreviewRequest {
                    locale: locale.to_owned(),
                    data: sample.clone(),
                };
                match package.preview(template.id(), template.version(), &request) {
                    Ok(preview) => samples.push(json!({"locale": locale, "sms": preview.sms})),
                    Err(refusal) => {
                        return preview_refusal(&refusal);
                    }
                }
            }
        }
        templates.push(json!({
            "id": template.id(),
            "version": template.version(),
            "channel": template.channel(),
            "locales": template.locales().collect::<Vec<_>>(),
            "samples": samples,
        }));
    }
    let mut report = json!({
        "ok": true,
        "packageDigest": package.digest(),
        "packageFiles": loaded.files.len(),
        "templates": templates,
        "accessProfiles": profiles,
    });
    if let Some(config) = config {
        report["runtimeConfig"] = json!(source.runtime_config);
        report["listener"] = json!(config.listener.bind.to_string());
        report["metricsListener"] = json!(config
            .metrics_listener
            .as_ref()
            .map(|metrics| metrics.bind.to_string()));
        report["retention"] = json!(config.retention);
    } else {
        report["package"] = json!(source.package);
    }
    Outcome::new(report, View::Check)
}

fn preview(args: &PreviewArgs) -> Outcome {
    let (_, loaded) = match load(&args.source) {
        Ok(loaded) => loaded,
        Err(refused) => return refused,
    };
    let data = match read_data(&args.data) {
        Ok(data) => data,
        Err(refused) => return refused,
    };
    let request = TemplatePreviewRequest {
        locale: args.locale.clone(),
        data,
    };
    let preview = match loaded
        .package
        .preview(&args.template, &args.version, &request)
    {
        Ok(preview) => preview,
        Err(refusal) => return preview_refusal(&refusal),
    };
    let mut bytes = match preview_json(&preview) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Outcome::refused(
                OPERATIONAL_FAILURE_EXIT,
                "output.failed",
                "/",
                format!("the preview could not be serialized: {error}"),
            )
        }
    };
    bytes.push(b'\n');
    let report = match serde_json::to_value(&preview) {
        Ok(report) => report,
        Err(error) => {
            return Outcome::refused(
                OPERATIONAL_FAILURE_EXIT,
                "output.failed",
                "/",
                format!("the preview could not be serialized: {error}"),
            )
        }
    };
    Outcome {
        report,
        exit: 0,
        view: View::Preview,
        raw_json: Some(bytes),
    }
}

fn read_data(path: &Path) -> Result<Value, Outcome> {
    let unreadable = |error: io::Error| {
        Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "data.unreadable",
            "--data",
            format!("the data file could not be read: {error}"),
        )
    };
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let mut bytes = Vec::new();
    file.take(MAXIMUM_DATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() as u64 > MAXIMUM_DATA_BYTES {
        return Err(Outcome::refused(
            REFUSAL_EXIT,
            "data.invalid",
            "--data",
            format!("the data file exceeds {MAXIMUM_DATA_BYTES} bytes"),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        Outcome::refused(
            REFUSAL_EXIT,
            "data.invalid",
            "--data",
            format!("the data file is not JSON: {error}"),
        )
    })
}

/// A refused render, named by its problem code. Data diagnostics carry the
/// pointer and keyword of each refused member, never a value.
fn preview_refusal(refusal: &ContentRefusal) -> Outcome {
    let mut outcome = Outcome::refused(
        REFUSAL_EXIT,
        refusal.problem().code(),
        "/",
        refusal.to_string(),
    );
    if let ContentRefusal::DataInvalid {
        diagnostics,
        truncated,
    } = refusal
    {
        outcome.report["diagnostics"][0]["data"] = json!(diagnostics);
        outcome.report["diagnostics"][0]["truncated"] = json!(truncated);
    }
    outcome
}

fn apply(path: &Path, record: bool) -> Outcome {
    let config = match RuntimeConfig::load(path) {
        Ok(config) => config,
        Err(error) => return config_refusal(&error),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return Outcome::refused(
                OPERATIONAL_FAILURE_EXIT,
                "runtime.unavailable",
                "/",
                format!("the async runtime could not start: {error}"),
            )
        }
    };
    match runtime.block_on(apply_package(&config, record)) {
        Ok(applied) => Outcome::new(
            json!({
                "ok": true,
                "runtimeConfig": path,
                "packageDigest": applied.package_digest,
                "activeDigest": applied.active_digest,
                "change": applied.change,
                "applied": applied.applied,
                "restartRequired": applied.applied,
            }),
            View::Apply,
        ),
        Err(RuntimeError::Config(error)) => config_refusal(&error),
        Err(error) => Outcome::refused(
            OPERATIONAL_FAILURE_EXIT,
            "database.unavailable",
            "database",
            error.to_string(),
        ),
    }
}

/// Write the report and return the exit code, or the operational failure
/// code when the report itself could not be written.
fn finish(
    outcome: &Outcome,
    format: OutputFormat,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    let written = match (format, &outcome.raw_json) {
        (OutputFormat::Json, Some(bytes)) => stdout.write_all(bytes),
        (OutputFormat::Json, None) => serde_json::to_writer_pretty(&mut *stdout, &outcome.report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout)),
        (OutputFormat::Human, _) => render_human(outcome, stdout, stderr),
    };
    match written {
        Ok(()) => ExitCode::from(outcome.exit),
        Err(_) => {
            // The report could not be written; this line may not land either,
            // and the exit code carries the failure regardless.
            let _ = writeln!(stderr, "messagingctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}

fn render_human(
    outcome: &Outcome,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> io::Result<()> {
    let report = &outcome.report;
    if report["ok"] == json!(false) {
        for diagnostic in report["diagnostics"].as_array().into_iter().flatten() {
            writeln!(
                stderr,
                "messagingctl: {} ({})",
                text(&diagnostic["message"]),
                diagnostic["path"].as_str().unwrap_or("/")
            )?;
            for data in diagnostic["data"].as_array().into_iter().flatten() {
                writeln!(
                    stderr,
                    "  data {}: {}",
                    if text(&data["pointer"]).is_empty() {
                        "/"
                    } else {
                        text(&data["pointer"])
                    },
                    text(&data["keyword"])
                )?;
            }
        }
        return Ok(());
    }
    match outcome.view {
        View::Init => render_init(report, stdout),
        View::Check => render_check(report, stdout),
        View::Preview => render_preview(report, stdout),
        View::Apply => render_apply(report, stdout),
    }
}

fn render_init(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    writeln!(stdout, "created: {}", text(&report["directory"]))?;
    for file in report["created"].as_array().into_iter().flatten() {
        writeln!(stdout, "  {}", text(file))?;
    }
    for next in report["next"].as_array().into_iter().flatten() {
        writeln!(stdout, "next: {}", text(next))?;
    }
    Ok(())
}

fn render_check(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    match report["runtimeConfig"].as_str() {
        Some(path) => writeln!(stdout, "ok: {path}")?,
        None => writeln!(stdout, "ok: {}", text(&report["package"]))?,
    }
    writeln!(stdout, "package digest: {}", text(&report["packageDigest"]))?;
    if report.get("listener").is_some() {
        writeln!(stdout, "listener: {}", text(&report["listener"]))?;
        match report["metricsListener"].as_str() {
            Some(bind) => writeln!(stdout, "metrics listener: {bind}")?,
            None => writeln!(stdout, "metrics listener: none")?,
        }
    }
    for template in report["templates"].as_array().into_iter().flatten() {
        writeln!(
            stdout,
            "template: {} {} ({})",
            text(&template["id"]),
            text(&template["version"]),
            text(&template["channel"])
        )?;
        for sample in template["samples"].as_array().into_iter().flatten() {
            let sms = &sample["sms"];
            if sms.is_object() {
                writeln!(
                    stdout,
                    "  sample {}: {} segment(s), {} {} units",
                    text(&sample["locale"]),
                    sms["segments"],
                    text(&sms["encoding"]),
                    sms["units"]
                )?;
            } else {
                writeln!(stdout, "  sample {}: renders", text(&sample["locale"]))?;
            }
        }
    }
    for profile in report["accessProfiles"].as_array().into_iter().flatten() {
        writeln!(
            stdout,
            "access profile: {} ({})",
            text(&profile["id"]),
            text(&profile["role"])
        )?;
    }
    if let Some(retention) = report.get("retention") {
        writeln!(
            stdout,
            "retention: payload {} days, record {} days, submission receipt {} days",
            retention["payloadDays"], retention["recordDays"], retention["submissionReceiptDays"]
        )?;
    }
    Ok(())
}

fn render_preview(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    writeln!(
        stdout,
        "template: {} {} ({}, {})",
        text(&report["template"]["id"]),
        text(&report["template"]["version"]),
        text(&report["channel"]),
        text(&report["locale"])
    )?;
    writeln!(stdout, "package digest: {}", text(&report["packageDigest"]))?;
    for part in ["subject", "text", "html"] {
        if let Some(rendered) = report["parts"][part].as_str() {
            writeln!(stdout, "--- {part}")?;
            writeln!(stdout, "{}", rendered.trim_end_matches('\n'))?;
        }
    }
    let sms = &report["sms"];
    if sms.is_object() {
        writeln!(
            stdout,
            "--- sms: {} segment(s), {} {} units",
            sms["segments"],
            text(&sms["encoding"]),
            sms["units"]
        )?;
    }
    Ok(())
}

fn render_apply(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    writeln!(stdout, "package digest: {}", text(&report["packageDigest"]))?;
    writeln!(
        stdout,
        "active digest: {}",
        report["activeDigest"].as_str().unwrap_or("none")
    )?;
    let change = if report["change"] == json!(PackageChange::None) {
        "none: the ledger already names this package active"
    } else if report["applied"] == json!(true) {
        "recorded: restart the runtime to serve this package"
    } else {
        "activate: run again with --apply to record this package"
    };
    writeln!(stdout, "change: {change}")
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

    fn starter(root: &Path) -> PathBuf {
        let directory = root.join("starter");
        let (exit, stdout, stderr) = run(&[OsStr::new("init"), directory.as_os_str()]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stderr}");
        assert!(stdout.contains("created:"), "{stdout}");
        directory
    }

    fn data_file(root: &Path, data: &Value) -> PathBuf {
        let path = root.join("data.json");
        std::fs::write(&path, serde_json::to_vec(data).unwrap()).unwrap();
        path
    }

    fn preview_args<'a>(
        package: &'a Path,
        template: &'a str,
        locale: &'a str,
        data: &'a Path,
    ) -> Vec<&'a OsStr> {
        vec![
            OsStr::new("preview"),
            OsStr::new("--package"),
            package.as_os_str(),
            OsStr::new(template),
            OsStr::new("1"),
            OsStr::new("--locale"),
            OsStr::new(locale),
            OsStr::new("--data"),
            data.as_os_str(),
        ]
    }

    fn json_run(arguments: &[&OsStr]) -> (ExitCode, Value) {
        let mut args = vec![OsStr::new("--format"), OsStr::new("json")];
        args.extend_from_slice(arguments);
        let (exit, stdout, _) = run(&args);
        (exit, serde_json::from_str(&stdout).unwrap())
    }

    #[test]
    fn init_writes_the_published_starter_byte_for_byte_and_never_overwrites() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let published =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/messaging/examples/starter");
        let mut expected = Vec::new();
        let mut pending = vec![published.clone()];
        while let Some(folder) = pending.pop() {
            for entry in std::fs::read_dir(folder).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    expected.push(
                        path.strip_prefix(&published)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
        }
        expected.sort();
        let mut embedded: Vec<String> = starter::FILES
            .iter()
            .map(|(path, _)| (*path).to_owned())
            .collect();
        embedded.sort();
        assert_eq!(embedded, expected);
        for (relative, _) in starter::FILES {
            assert_eq!(
                std::fs::read(directory.join(relative)).unwrap(),
                std::fs::read(published.join(relative)).unwrap(),
                "{relative}"
            );
        }

        let (exit, report) = json_run(&[OsStr::new("init"), directory.as_os_str()]);
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert_eq!(report["diagnostics"][0]["code"], "init.exists");
        let leftovers: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![OsString::from("starter")]);
    }

    #[test]
    fn check_reports_the_package_digest_templates_and_sample_segments() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let expected = load_package(&directory).unwrap();
        let (exit, report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--package"),
            directory.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{report}");
        assert_eq!(report["packageDigest"], expected.package.digest());
        assert_eq!(report["packageFiles"], expected.files.len());
        let templates = report["templates"].as_array().unwrap();
        assert_eq!(templates.len(), 2);
        assert_eq!(templates[0]["id"], "appointment-reminder");
        assert_eq!(templates[0]["locales"], json!(["en", "fr"]));
        assert_eq!(
            templates[0]["samples"][1],
            json!({"locale": "fr", "sms": null})
        );
        assert_eq!(templates[1]["channel"], "sms");
        assert_eq!(templates[1]["samples"][0]["sms"]["segments"], 1);
        assert_eq!(templates[1]["samples"][0]["sms"]["encoding"], "gsm7");
        assert!(report.get("listener").is_none());

        let (exit, stdout, _) = run(&[
            OsStr::new("check"),
            OsStr::new("--package"),
            directory.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(
            stdout.contains("template: appointment-reminder-sms 1 (sms)"),
            "{stdout}"
        );
        assert!(stdout.contains("sample en: 1 segment(s), gsm7"), "{stdout}");
    }

    #[test]
    fn check_takes_exactly_one_package_source() {
        let (exit, report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--package"),
            OsStr::new("/a"),
            OsStr::new("--runtime-config"),
            OsStr::new("/b"),
        ]);
        assert_eq!(exit, ExitCode::from(USAGE_EXIT));
        assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
    }

    #[test]
    fn a_refused_package_names_the_refused_file() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        std::fs::write(
            directory.join("templates/appointment-reminder/1/en/text.j2"),
            "{% if %}",
        )
        .unwrap();
        let (exit, report) = json_run(&[
            OsStr::new("check"),
            OsStr::new("--package"),
            directory.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert!(report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("does not parse"));
    }

    #[test]
    fn preview_json_is_the_exact_body_the_route_answers() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let data = json!({"name": "Ada <Lovelace>", "day": "2026-10-01", "office": "Central"});
        let path = data_file(root.path(), &data);
        let mut args = vec![OsStr::new("--format"), OsStr::new("json")];
        args.extend(preview_args(
            &directory,
            "appointment-reminder",
            "fr",
            &path,
        ));
        let (exit, stdout, stderr) = run(&args);
        assert_eq!(exit, ExitCode::SUCCESS, "{stderr}");
        let loaded = load_package(&directory).unwrap();
        let preview = loaded
            .package
            .preview(
                "appointment-reminder",
                "1",
                &TemplatePreviewRequest {
                    locale: "fr".to_owned(),
                    data,
                },
            )
            .unwrap();
        let mut expected = preview_json(&preview).unwrap();
        expected.push(b'\n');
        assert_eq!(stdout.as_bytes(), expected.as_slice());
        assert!(stdout.contains("Ada &lt;Lovelace&gt;"), "{stdout}");
    }

    #[test]
    fn preview_in_human_form_prints_each_part_and_the_segment_count() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let data = json!({"name": "Ada", "day": "2026-10-01", "office": "Central"});
        let path = data_file(root.path(), &data);
        let (exit, stdout, _) = run(&preview_args(
            &directory,
            "appointment-reminder-sms",
            "en",
            &path,
        ));
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(stdout.contains("--- text\n"), "{stdout}");
        assert!(stdout.contains("--- sms: 1 segment(s), gsm7"), "{stdout}");
        assert!(!stdout.contains("--- subject"), "{stdout}");
    }

    #[test]
    fn preview_refusals_name_their_problem_code_and_never_a_value() {
        let root = tempfile::tempdir().unwrap();
        let directory = starter(root.path());
        let valid = json!({"name": "Ada", "day": "2026-10-01", "office": "Central"});
        let cases = [
            (
                "appointment-reminder",
                "de",
                valid.clone(),
                "template.locale-unavailable",
            ),
            ("absent", "en", valid.clone(), "template.not-found"),
            (
                "appointment-reminder",
                "en",
                json!({"name": "secret-value-7", "day": 3}),
                "template.data-invalid",
            ),
        ];
        for (template, locale, data, code) in cases {
            let path = data_file(root.path(), &data);
            let mut args = vec![OsStr::new("--format"), OsStr::new("json")];
            args.extend(preview_args(&directory, template, locale, &path));
            let (exit, stdout, _) = run(&args);
            assert_eq!(exit, ExitCode::from(REFUSAL_EXIT), "{code}");
            let report: Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(report["diagnostics"][0]["code"], code);
            assert!(!stdout.contains("secret-value-7"), "{stdout}");
        }
        let path = data_file(root.path(), &json!({"name": "Ada", "day": 3}));
        let (exit, _, stderr) = run(&preview_args(
            &directory,
            "appointment-reminder",
            "en",
            &path,
        ));
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert!(stderr.contains("data /day"), "{stderr}");

        let path = root.path().join("broken.json");
        std::fs::write(&path, "{").unwrap();
        let mut args = vec![OsStr::new("--format"), OsStr::new("json")];
        args.extend(preview_args(
            &directory,
            "appointment-reminder",
            "en",
            &path,
        ));
        let (exit, stdout, _) = run(&args);
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert!(stdout.contains("data.invalid"), "{stdout}");
    }

    #[test]
    fn apply_refuses_before_any_database_when_the_package_is_refused() {
        let (root, path) = project("");
        let pinned = runtime(root.path(), "").replace(
            &format!("  root: {}/package\n", root.path().display()),
            &format!(
                "  root: {}/package\n  expectedDigest: sha256:{}\n",
                root.path().display(),
                "0".repeat(64)
            ),
        );
        std::fs::write(&path, pinned).unwrap();
        let (exit, report) = json_run(&[
            OsStr::new("apply"),
            OsStr::new("--runtime-config"),
            path.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::from(REFUSAL_EXIT));
        assert_eq!(report["diagnostics"][0]["path"], "package.expectedDigest");
    }

    #[test]
    fn apply_without_a_database_credential_is_an_operational_failure() {
        let (root, path) = project("");
        let document = runtime(root.path(), "").replace(
            "secret:env/MESSAGING_MIGRATION_URL",
            "secret:env/MESSAGINGCTL_TEST_UNSET_MIGRATION_URL",
        );
        std::fs::write(&path, document).unwrap();
        let (exit, report) = json_run(&[
            OsStr::new("apply"),
            OsStr::new("--runtime-config"),
            path.as_os_str(),
        ]);
        assert_eq!(exit, ExitCode::from(OPERATIONAL_FAILURE_EXIT), "{report}");
        assert_eq!(report["diagnostics"][0]["code"], "database.unavailable");
    }
}
