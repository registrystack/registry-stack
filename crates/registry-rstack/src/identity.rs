// SPDX-License-Identifier: Apache-2.0

//! `rstack identity`: hosted identity configuration derived from product
//! configuration, and the offline check of the files it reads.
//!
//! `generate thunderid` never reads another product's files. It runs each
//! selected product's public `generate identity-facts` command, writes the
//! facts to a private scratch directory, and hands them with the operator's
//! deployment file to `registry-thunderid-tooling`. No secret value is read,
//! passed in an argument, or printed.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::store::InvocationLease;
use registry_platform_config::{substituted_variable_names, DEFAULT_MAX_RUNTIME_CONFIG_BYTES};
use registry_thunderid_tooling::identity_check;
use registry_thunderid_tooling::identity_generate::{generate_to_directory, Summary};
use registry_thunderid_tooling::ToolingError;
use serde_json::{json, Value};

/// Environment the driven tools receive, with the variables a runtime
/// configuration substitutes (see [`forward_substituted`]). Everything else,
/// including any variable that holds a secret, stays with the launcher.
const FORWARDED_ENVIRONMENT: [&str; 8] = [
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "LD_LIBRARY_PATH",
];

/// The most driven-tool diagnostic text repeated in a refusal, in bytes.
const MAXIMUM_TOOL_DIAGNOSTIC_BYTES: usize = 4096;

const REPORT_API_VERSION: &str = "id.registrystack.org/formats/platform/identity-report/v1alpha1";
const REPORT_KIND: &str = "PlatformIdentityReport";

/// A refusal (exit 1) or an operational failure (exit 3).
pub(crate) enum Failure {
    Domain(String),
    Operational(String),
}

/// One product whose public CLI writes identity facts.
pub(crate) struct ProductSpec {
    /// The product component name.
    pub(crate) name: &'static str,
    /// The product's public command-line tool.
    pub(crate) binary: &'static str,
    /// The environment variable that selects the tool.
    pub(crate) variable: &'static str,
    /// The flag that carries the product's configuration file.
    config_flag: &'static str,
    /// Whether the command takes the project directory.
    takes_project: bool,
    /// Whether the command accepts `--production`.
    takes_production: bool,
    /// Whether the configuration file is a runtime configuration, which
    /// substitutes `${NAME}` expressions from the environment.
    substitutes_environment: bool,
}

/// The products that admit OIDC tokens, in the order their facts are merged.
pub(crate) const PRODUCTS: [ProductSpec; 4] = [
    ProductSpec {
        name: "breg",
        binary: "bregctl",
        variable: "RSTACK_BREGCTL_BIN",
        config_flag: "--runtime-config",
        takes_project: true,
        takes_production: true,
        substitutes_environment: true,
    },
    ProductSpec {
        name: "casework",
        binary: "caseworkctl",
        variable: "RSTACK_CASEWORKCTL_BIN",
        config_flag: "--runtime-config",
        takes_project: true,
        takes_production: false,
        substitutes_environment: true,
    },
    ProductSpec {
        name: "evidence",
        binary: "evidencectl",
        variable: "RSTACK_EVIDENCECTL_BIN",
        config_flag: "--target",
        takes_project: true,
        takes_production: false,
        substitutes_environment: false,
    },
    ProductSpec {
        name: "messaging",
        binary: "messagingctl",
        variable: "RSTACK_MESSAGINGCTL_BIN",
        config_flag: "--runtime-config",
        takes_project: false,
        takes_production: false,
        substitutes_environment: true,
    },
];

/// One product's inputs, as the operator stated them.
pub(crate) struct Input {
    pub(crate) product: &'static ProductSpec,
    pub(crate) project: Option<PathBuf>,
    pub(crate) config: PathBuf,
    pub(crate) production: bool,
}

pub(crate) struct GenerateOptions {
    pub(crate) deployment: PathBuf,
    pub(crate) output: PathBuf,
    pub(crate) inputs: Vec<Input>,
}

fn refused(error: ToolingError) -> Failure {
    match error {
        ToolingError::FileRefused { .. }
        | ToolingError::IdentityRefused { .. }
        | ToolingError::InvalidDescription { .. }
        | ToolingError::OutputExists => Failure::Domain(error.to_string()),
        other => Failure::Operational(other.to_string()),
    }
}

/// A driven tool and the release generation lease that keeps it installed.
/// The lease, when there is one, lives as long as this value.
pub(crate) struct DrivenTool {
    pub(crate) path: PathBuf,
    pub(crate) _lease: Option<InvocationLease>,
}

/// Run each selected product's facts command, then generate. `resolve`
/// names the tool of the selected release for a product; every lease it
/// returns is held until generation has finished.
pub(crate) fn generate_thunderid(
    options: &GenerateOptions,
    resolve: &dyn Fn(&ProductSpec) -> Result<DrivenTool, Failure>,
) -> Result<Summary, Failure> {
    if std::fs::symlink_metadata(&options.output).is_ok() {
        return Err(Failure::Domain(format!(
            "the output directory {} already exists; choose a new directory",
            options.output.display()
        )));
    }
    // Resolve and version-check every tool before any of them runs.
    let mut tools = Vec::new();
    for input in &options.inputs {
        let tool = resolve(input.product)?;
        check_version(input.product, &tool.path)?;
        tools.push(tool);
    }
    let scratch = tempfile::Builder::new()
        .prefix("rstack-identity-")
        .tempdir()
        .map_err(|error| {
            Failure::Operational(format!(
                "cannot create a private scratch directory: {error}"
            ))
        })?;
    let mut facts = Vec::new();
    for (input, tool) in options.inputs.iter().zip(&tools) {
        let file = scratch
            .path()
            .join(format!("{}-identity-facts.yaml", input.product.name));
        write_facts(input, &tool.path, &file)?;
        facts.push(file);
    }
    generate_to_directory(&options.deployment, &facts, &options.output).map_err(refused)
}

/// The driven tool must be the build this launcher published.
fn check_version(product: &ProductSpec, binary: &Path) -> Result<(), Failure> {
    let expected = format!(
        "{} {}",
        product.binary,
        registry_platform_buildinfo::DISPLAY_VERSION
    );
    let output = tool_command(binary)
        .arg("--version")
        .output()
        .map_err(|error| Failure::Operational(format!("cannot run {}: {error}", product.binary)))?;
    let reported = String::from_utf8_lossy(&output.stdout);
    let reported = reported.trim();
    if output.status.success() && reported == expected {
        return Ok(());
    }
    let found = if output.status.success() && !reported.is_empty() {
        format!("found {}", bounded(reported))
    } else {
        "could not read its version".to_owned()
    };
    Err(Failure::Domain(format!(
        "identity generation drives the public {} tool of this release and {found}; it requires {expected}. Set {} to that binary, or run rstack install {}",
        product.binary, product.variable, product.name
    )))
}

fn write_facts(input: &Input, binary: &Path, file: &Path) -> Result<(), Failure> {
    let config = absolute(&input.config)?;
    let mut command = tool_command(binary);
    if input.product.substitutes_environment {
        forward_substituted(&mut command, &config);
    }
    command.args(["generate", "identity-facts"]);
    if input.product.takes_project {
        if let Some(project) = &input.project {
            command.arg(absolute(project)?);
        }
    }
    command.arg(input.product.config_flag).arg(&config);
    command.arg("--output").arg(file);
    if input.product.takes_production && input.production {
        command.arg("--production");
    }
    let name = input.product.binary;
    let output = command
        .output()
        .map_err(|error| Failure::Operational(format!("cannot run {name}: {error}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = format!(
            "{name} generate identity-facts failed ({}):\n{}",
            output.status.code().map_or_else(
                || "terminated by a signal".to_owned(),
                |code| format!("exit {code}")
            ),
            bounded(stderr.trim())
        );
        return Err(if output.status.code() == Some(1) {
            Failure::Domain(message)
        } else {
            Failure::Operational(message)
        });
    }
    if !file.is_file() {
        return Err(Failure::Operational(format!(
            "{name} generate identity-facts reported success but wrote no facts"
        )));
    }
    Ok(())
}

/// An operator path made absolute against the launcher's working directory.
/// Driven tools may refuse a relative path, and an absolute path can never be
/// read as an option.
fn absolute(path: &Path) -> Result<PathBuf, Failure> {
    std::path::absolute(path).map_err(|error| {
        Failure::Operational(format!(
            "cannot resolve {} against the working directory: {error}",
            path.display()
        ))
    })
}

/// A tool command with the forwarded environment only and no input.
fn tool_command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    command.env_clear().stdin(Stdio::null());
    for name in FORWARDED_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

/// Forward the variables that the runtime configuration at `runtime` reads
/// through `${NAME}` expressions in the values the loader substitutes and the
/// launcher has set, so the tool reads the configuration as it would when run
/// directly. A variable the file reaches only through `secret:env/NAME` is not
/// named by an expression and stays with the launcher. A file that is a
/// symlink or not a regular file, or cannot be read whole as UTF-8 within the
/// runtime configuration limit, forwards nothing more: the tool reads the same
/// path and refuses it itself, so nothing is lost silently. The file is opened
/// without following links and without waiting (opening a FIFO would block),
/// and its type is checked on the open handle, so a path swapped after the
/// check cannot make this wait.
fn forward_substituted(command: &mut Command, runtime: &Path) {
    use rustix::fs::{Mode, OFlags};
    let Ok(fd) = rustix::fs::open(
        runtime,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) else {
        return;
    };
    let file = File::from(fd);
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return;
    }
    let mut bytes = Vec::new();
    if file
        .take(DEFAULT_MAX_RUNTIME_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > DEFAULT_MAX_RUNTIME_CONFIG_BYTES
    {
        return;
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return;
    };
    for name in substituted_variable_names(text) {
        if let Some(value) = std::env::var_os(&name) {
            command.env(name, value);
        }
    }
}

fn bounded(text: &str) -> String {
    if text.len() <= MAXIMUM_TOOL_DIAGNOSTIC_BYTES {
        return text.to_owned();
    }
    let mut end = MAXIMUM_TOOL_DIAGNOSTIC_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

pub(crate) fn generate_report_human(summary: &Summary, output: &Path) -> String {
    let mut lines = vec![format!(
        "Wrote {} files to {}",
        summary.files.len(),
        output.display()
    )];
    lines.extend(summary.files.iter().map(|file| format!("  {file}")));
    lines.push(format!(
        "Resource servers: {}; machine clients: {}; browser apps: {}; users: {}",
        summary.resource_servers, summary.machine_clients, summary.browser_apps, summary.users
    ));
    lines.push(format!(
        "Environment variables to provide to ThunderID: {} (listed in identity-receipt.json)",
        summary.required_environment.len()
    ));
    lines.join("\n")
}

/// A JSON object whose members keep the order given: a machine-readable
/// operator report opens with `ok`, `command`, `status`, `apiVersion` and
/// `kind`, in that order (CFG-DIAG-4).
fn ordered_object(members: Vec<(&str, Value)>) -> String {
    let members: Vec<String> = members
        .into_iter()
        .map(|(name, value)| format!("{}:{}", json!(name), value))
        .collect();
    format!("{{{}}}", members.join(","))
}

pub(crate) fn generate_report_json(summary: &Summary, output: &Path) -> String {
    ordered_object(vec![
        ("ok", json!(true)),
        ("command", json!("identity generate thunderid")),
        ("status", json!("complete")),
        ("apiVersion", json!(REPORT_API_VERSION)),
        ("kind", json!(REPORT_KIND)),
        (
            "version",
            json!(registry_platform_buildinfo::DISPLAY_VERSION),
        ),
        ("outputDirectory", json!(output.display().to_string())),
        ("files", json!(summary.files)),
        ("resourceServers", json!(summary.resource_servers)),
        ("machineClients", json!(summary.machine_clients)),
        ("browserApps", json!(summary.browser_apps)),
        ("users", json!(summary.users)),
        (
            "requiredEnvironmentCount",
            json!(summary.required_environment.len()),
        ),
        ("diagnostics", json!([])),
    ])
}

/// The text to print and the exit code of one check.
pub(crate) struct CheckOutcome {
    pub(crate) text: String,
    pub(crate) code: i32,
}

/// Check a facts document or deployment file offline (CFG-CHECK-1, CFG-DIAG-4).
pub(crate) fn check(
    file: &Path,
    facts: &[PathBuf],
    deny_warnings: bool,
    json: bool,
) -> CheckOutcome {
    let checked = identity_check::check_file(file, facts);
    let report = &checked.report;
    let code = if checked.unreadable {
        3
    } else if report.has_errors() || (deny_warnings && report.warning_count() > 0) {
        1
    } else {
        0
    };
    let text = if json {
        let status = match code {
            0 => "complete",
            1 => "domain-refusal",
            _ => "operational-failure",
        };
        ordered_object(vec![
            ("ok", json!(code == 0)),
            ("command", json!("identity check")),
            ("status", json!(status)),
            ("apiVersion", json!(REPORT_API_VERSION)),
            ("kind", json!(REPORT_KIND)),
            (
                "version",
                json!(registry_platform_buildinfo::DISPLAY_VERSION),
            ),
            ("file", json!(file.display().to_string())),
            ("errors", json!(report.error_count())),
            ("warnings", json!(report.warning_count())),
            ("diagnostics", report.to_json_value()),
        ])
    } else {
        report.render_human().trim_end().to_owned()
    };
    CheckOutcome { text, code }
}

#[cfg(test)]
mod exit_mapping_tests {
    use super::*;

    fn kind(failure: Failure) -> &'static str {
        match failure {
            Failure::Domain(_) => "domain",
            Failure::Operational(_) => "operational",
        }
    }

    #[test]
    fn input_caused_refusals_exit_as_domain_and_filesystem_failures_as_operational() {
        for (error, expected) in [
            (ToolingError::InvalidDescription { reason: "r" }, "domain"),
            // Most render failures are the generator's own: a serializer, an
            // embedded asset, or its post-render assertion.
            (ToolingError::InvalidRender { reason: "r" }, "operational"),
            (ToolingError::OutputExists, "domain"),
            (
                ToolingError::IdentityRefused {
                    code: "c",
                    message: "m",
                    location: "l".to_owned(),
                },
                "domain",
            ),
            // A create or permission failure never reads as the operator's
            // input, whatever its text says.
            (
                ToolingError::Filesystem {
                    reason: "the output directory already exists or could not be created",
                },
                "operational",
            ),
            (
                ToolingError::Filesystem {
                    reason: "an input file could not be read",
                },
                "operational",
            ),
        ] {
            let text = error.to_string();
            assert_eq!(kind(refused(error)), expected, "{text}");
        }
    }
}
