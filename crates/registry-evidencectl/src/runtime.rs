//! Runtime preflight adapter.
//!
//! The Evidence runtime owns startup validation. This command delegates the
//! same dependency check without binding the public listener or sending an
//! evidence-data request. Audit initialization may briefly create its
//! operational lock file, but it never appends an application audit event.

use std::{
    io::Write as _,
    path::PathBuf,
    process::{Command, ExitCode, ExitStatus, Stdio},
};

use anyhow::{bail, Context as _, Result};
use clap::{ArgGroup, Args};
use serde::Serialize;

use crate::{evidence_binary, OutputFormat};

const MAX_DIAGNOSTIC_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("selection").multiple(false).args(["runtime_config", "project"])))]
pub(crate) struct DoctorArgs {
    /// Absolute Evidence runtime configuration file to inspect.
    #[arg(long, value_name = "FILE")]
    runtime_config: Option<PathBuf>,
    /// Also prove that the audit destination resolves below this persistent root.
    #[arg(long, value_name = "ABSOLUTE_DIRECTORY", requires = "runtime_config")]
    require_audit_under: Option<PathBuf>,
    /// Path to the matching Evidence runtime binary.
    #[arg(long, hide = true, requires = "runtime_config")]
    evidence_bin: Option<PathBuf>,
    /// Evidence project directory; defaults to the current directory.
    ///
    /// Compatibility form for inspecting a deployment project that holds
    /// runtime.yaml beside bundle/. New dependency checks use --runtime-config.
    #[arg(long, conflicts_with = "runtime_config")]
    project: Option<PathBuf>,
    /// Compatibility Mint configuration for the former artifact inspection.
    #[arg(long, conflicts_with = "runtime_config")]
    mint_config: Option<PathBuf>,
    /// Compatibility spelling for JSON artifact-inspection output.
    #[arg(long, conflicts_with_all = ["runtime_config", "output_format"])]
    json: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DoctorReport<'a> {
    operation: &'static str,
    status: &'static str,
    runtime_config: &'a std::path::Path,
    proof_boundary: &'static str,
    diagnostics: Vec<Diagnostic>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Diagnostic {
    severity: &'static str,
    code: &'static str,
    artifact: String,
    path: &'static str,
    message: String,
    suggested_action: &'static str,
}

pub(crate) fn run(args: DoctorArgs, format: OutputFormat) -> Result<ExitCode> {
    if args.runtime_config.is_none() {
        let project = args.project.unwrap_or_else(|| PathBuf::from("."));
        return crate::doctor::run(crate::doctor::DoctorArgs {
            project,
            mint_config: args.mint_config,
            json: args.json || format == OutputFormat::Json,
        });
    }
    let runtime_config = args.runtime_config.expect("runtime selection was checked");
    if !runtime_config.is_absolute() {
        bail!("--runtime-config must be an absolute path");
    }
    if args
        .require_audit_under
        .as_ref()
        .is_some_and(|path| !path.is_absolute())
    {
        bail!("--require-audit-under must be an absolute path");
    }

    let evidence = evidence_binary::resolve_matching(args.evidence_bin.as_deref())?;
    let base = invoke_check(&evidence, &runtime_config, false, None)?;
    if !base.status.success() {
        return render_refusal(
            &runtime_config,
            format,
            "evidence.runtime.configuration-refused",
            "domain-refusal",
            &base.stderr,
            1,
        );
    }
    let dependency = invoke_check(
        &evidence,
        &runtime_config,
        true,
        args.require_audit_under.as_deref(),
    )?;

    if dependency.status.success() {
        let report = DoctorReport {
            operation: "doctor",
            status: "ready",
            runtime_config: &runtime_config,
            proof_boundary: "live startup dependency preflight; no public listener, evidence-data request, or application audit event was produced",
            diagnostics: Vec::new(),
        };
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string(&report)?),
            OutputFormat::Human => {
                print!("{}", String::from_utf8_lossy(&dependency.stdout));
                println!(
                    "Dependency preflight passed for {}",
                    runtime_config.display()
                );
                println!("Proof: startup dependencies were checked without opening the public listener, sending an evidence-data request, or appending an application audit event. Audit initialization may briefly hold its operational lock.");
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    render_refusal(
        &runtime_config,
        format,
        "evidence.runtime.dependencies-unavailable",
        "operational-failure",
        &dependency.stderr,
        3,
    )
}

struct CheckOutcome {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn invoke_check(
    evidence: &std::path::Path,
    runtime_config: &std::path::Path,
    dependencies: bool,
    audit_root: Option<&std::path::Path>,
) -> Result<CheckOutcome> {
    let mut stdout = tempfile::tempfile().context("creating private Evidence doctor output")?;
    let mut stderr =
        tempfile::tempfile().context("creating private Evidence doctor diagnostics")?;
    let mut command = Command::new(evidence);
    command
        .arg("--runtime")
        .arg(runtime_config)
        .arg("check")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?));
    if dependencies {
        command.arg("--require-runtime-dependencies");
    }
    if let Some(root) = audit_root {
        command.arg("--require-audit-under").arg(root);
    }
    let mut child = command.spawn().with_context(|| {
        format!(
            "starting Evidence dependency preflight at {}",
            evidence.display()
        )
    })?;
    let status = evidence_binary::wait_bounded(
        &mut child,
        "Evidence runtime dependency preflight",
        evidence_binary::DELEGATED_RUN_DEADLINE,
        &|| Ok(()),
        &|| {
            evidence_binary::capture_over_limit(&stdout, MAX_DIAGNOSTIC_BYTES)
                || evidence_binary::capture_over_limit(&stderr, MAX_DIAGNOSTIC_BYTES)
        },
    )?;
    let runtime_output = evidence_binary::drain_capture(
        &mut stdout,
        MAX_DIAGNOSTIC_BYTES,
        "Evidence runtime dependency preflight output",
    )?;
    let runtime_diagnostic = evidence_binary::drain_capture(
        &mut stderr,
        MAX_DIAGNOSTIC_BYTES,
        "Evidence runtime dependency preflight diagnostics",
    )?;

    Ok(CheckOutcome {
        status,
        stdout: runtime_output,
        stderr: runtime_diagnostic,
    })
}

fn render_refusal(
    runtime_config: &std::path::Path,
    format: OutputFormat,
    code: &'static str,
    status: &'static str,
    runtime_diagnostic: &[u8],
    exit: u8,
) -> Result<ExitCode> {
    let detail = String::from_utf8_lossy(runtime_diagnostic)
        .trim()
        .to_owned();
    let report = DoctorReport {
        operation: "doctor",
        status,
        runtime_config,
        proof_boundary: "live startup dependency preflight; no public listener, evidence-data request, or application audit event was produced",
        diagnostics: vec![Diagnostic {
            severity: "error",
            code,
            artifact: runtime_config.display().to_string(),
            path: "$",
            message: if detail.is_empty() { "Evidence runtime check failed without a diagnostic.".to_owned() } else { detail },
            suggested_action: "Read the value-free Evidence diagnostic, correct the selected runtime artifact or dependency, and rerun doctor.",
        }],
    };
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string(&report)?),
        OutputFormat::Human => {
            eprintln!(
                "Evidence runtime dependency preflight refused {}",
                runtime_config.display()
            );
            std::io::stderr().write_all(runtime_diagnostic)?;
            eprintln!(
                "Next: correct the selected runtime artifact or dependency and rerun doctor."
            );
        }
    }
    Ok(ExitCode::from(exit))
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::Write as _,
        os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    };

    use super::*;

    #[test]
    fn dependency_preflight_delegates_check_without_a_serve_or_evaluate_operation() {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        let runtime = root.path().join("runtime.yaml");
        fs::write(&runtime, "version: 1\n").expect("runtime");
        let arguments = root.path().join("arguments");
        let binary = root.path().join("evidence");
        let mut script = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&binary)
            .expect("stub");
        writeln!(
            script,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf 'passed\\n'",
            arguments.display()
        )
        .expect("script");
        drop(script);

        let outcome = invoke_check(&binary, &runtime, true, Some(root.path())).expect("preflight");
        assert!(outcome.status.success());
        let invoked = fs::read_to_string(arguments).expect("arguments");
        assert_eq!(
            invoked,
            format!(
                "--runtime\n{}\ncheck\n--require-runtime-dependencies\n--require-audit-under\n{}\n",
                runtime.display(),
                root.path().display()
            )
        );
        assert!(!invoked.contains("serve"));
        assert!(!invoked.contains("evaluate"));
        assert!(!root.path().join("audit.jsonl").exists());
    }
}
