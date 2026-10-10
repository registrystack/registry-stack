//! Runtime preflight adapter.
//!
//! The Evidence runtime owns startup validation. This command delegates the
//! same dependency check without binding the public listener or sending an
//! evidence-data request. Audit initialization may briefly create its
//! operational lock file, but it never appends an application audit event.
//! With `--without-audit-lock` it leaves that lock to the running instance
//! that holds it and proves the rest of the audit destination read-only.

use std::{
    io::Write as _,
    path::Path,
    path::PathBuf,
    process::{Command, ExitCode, ExitStatus, Stdio},
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use clap::{ArgGroup, Args};
use serde::Serialize;

use crate::{evidence_binary, OutputFormat};

const MAX_DIAGNOSTIC_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub(crate) struct DoctorOperationalDiagnostic {
    pub(crate) artifact: String,
}

impl std::fmt::Display for DoctorOperationalDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the delegated Evidence runtime check did not complete safely")
    }
}

impl std::error::Error for DoctorOperationalDiagnostic {}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("selection").multiple(false).args(["runtime_config", "project"])))]
pub(crate) struct DoctorArgs {
    /// Runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: Option<PathBuf>,
    /// Also prove that the audit destination resolves below this persistent root.
    #[arg(long, value_name = "ABSOLUTE_DIRECTORY", requires = "runtime_config")]
    require_audit_under: Option<PathBuf>,
    /// Prove the audit destination without taking its single-writer lock.
    ///
    /// For a candidate staged beside the running instance it will replace,
    /// which holds that lock. Modes, write access, and a complete final entry
    /// are still proved, and every other dependency is proved as without it.
    #[arg(long, requires = "runtime_config")]
    without_audit_lock: bool,
    /// Path to the matching Evidence runtime binary.
    #[arg(long, hide = true, requires = "runtime_config")]
    evidence_bin: Option<PathBuf>,
    /// Evidence project directory; defaults to the current directory.
    ///
    /// Compatibility form for inspecting a deployment project that holds
    /// runtime.yaml beside bundle/. New dependency checks use --runtime-config.
    #[arg(long, conflicts_with = "runtime_config")]
    project: Option<PathBuf>,
    /// Compatibility spelling for JSON artifact-inspection output.
    #[arg(long, conflicts_with_all = ["runtime_config", "output_format"])]
    json: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DoctorReport<'a> {
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

impl DoctorArgs {
    /// Whether the compatibility `--json` spelling was given.
    pub(crate) fn json(&self) -> bool {
        self.json
    }
}

pub(crate) fn run(args: DoctorArgs, format: OutputFormat) -> Result<ExitCode> {
    if args.runtime_config.is_none() {
        let project = args.project.unwrap_or_else(|| PathBuf::from("."));
        return crate::doctor::run(crate::doctor::DoctorArgs {
            project,
            json: args.json || format == OutputFormat::Json,
            command: "doctor",
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

    let evidence = evidence_binary::resolve_matching_within(
        args.evidence_bin.as_deref(),
        version_handshake_deadline(),
    )
    .map_err(|error| {
        if error.chain().any(|cause| {
            cause
                .downcast_ref::<evidence_binary::DelegatedRunBoundError>()
                .is_some()
        }) {
            operational_diagnostic(&runtime_config)
        } else {
            error
        }
    })?;
    let base = invoke_check(&evidence, &runtime_config, false, None, false)?;
    if !base.status.success() {
        // `evidence check` exits 3 when an input it depends on could not be
        // read, such as an unreadable runtime file or package.
        let dependency_failure =
            base.status.code() == Some(3) || runtime_diagnostic_is_dependency_failure(&base.stderr);
        return render_refusal(
            &runtime_config,
            format,
            if dependency_failure {
                "evidence.runtime.dependencies-unavailable"
            } else {
                "evidence.runtime.configuration-refused"
            },
            if dependency_failure {
                "operational-failure"
            } else {
                "domain-refusal"
            },
            &base.stderr,
            if dependency_failure { 3 } else { 1 },
        );
    }
    let dependency = invoke_check(
        &evidence,
        &runtime_config,
        true,
        args.require_audit_under.as_deref(),
        args.without_audit_lock,
    )?;

    if dependency.status.success() {
        let report = DoctorReport {
            runtime_config: &runtime_config,
            proof_boundary: proof_boundary(args.without_audit_lock),
            diagnostics: Vec::new(),
        };
        match format {
            OutputFormat::Json => crate::print_report(&crate::report::success(
                "doctor",
                "ready",
                serde_json::to_value(&report)?,
            )),
            OutputFormat::Human => {
                print!("{}", String::from_utf8_lossy(&dependency.stdout));
                println!(
                    "Dependency preflight passed for {}",
                    runtime_config.display()
                );
                println!("Proof: startup dependencies were checked without opening the public listener, sending an evidence-data request, or appending an application audit event. {}", if args.without_audit_lock {
                    "The audit writer lock was not taken, so a second writer is not detected. The audit destination's ownership, modes, write access, and complete final entry were checked."
                } else {
                    "Audit initialization may briefly hold its operational lock."
                });
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

const LOCKED_PROOF_BOUNDARY: &str = "live startup dependency preflight; no public listener, evidence-data request, or application audit event was produced";

const LOCK_FREE_PROOF_BOUNDARY: &str = "live startup dependency preflight without the audit writer lock; no public listener, evidence-data request, or application audit event was produced; the audit writer lock was not taken, so a second writer is not detected";

/// What a passing dependency preflight proved, for the report a consumer
/// reads. The lock-free form proves less, and says so.
fn proof_boundary(without_audit_lock: bool) -> &'static str {
    if without_audit_lock {
        LOCK_FREE_PROOF_BOUNDARY
    } else {
        LOCKED_PROOF_BOUNDARY
    }
}

const DEFAULT_ACTION: &str = "Read the value-free Evidence diagnostic, correct the selected runtime artifact or dependency, and rerun doctor.";

const HELD_LOCK_ACTION: &str = "Another Evidence instance holds this audit destination's writer lock. To check a candidate staged beside it, rerun doctor with --without-audit-lock; otherwise stop the other writer first.";

/// The next step for a refusal. A held writer lock is the one refusal a
/// candidate beside a running instance meets by design, so it names the
/// lock-free form; every other refusal is corrected where the diagnostic says.
fn suggested_action(runtime_diagnostic: &[u8]) -> &'static str {
    if String::from_utf8_lossy(runtime_diagnostic)
        .contains("another process holds the single-writer lock beside the audit file")
    {
        HELD_LOCK_ACTION
    } else {
        DEFAULT_ACTION
    }
}

fn runtime_diagnostic_is_dependency_failure(diagnostic: &[u8]) -> bool {
    let diagnostic = String::from_utf8_lossy(diagnostic);
    [
        "deployment input is unavailable",
        "bound extract is stale",
        "runtime secret initialization failed",
        "runtime audit initialization failed",
        "runtime signing initialization failed",
        "runtime source initialization failed",
        "runtime rate-limit initialization failed",
    ]
    .iter()
    .any(|message| diagnostic.contains(message))
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
    without_audit_lock: bool,
) -> Result<CheckOutcome> {
    let mut stdout = tempfile::tempfile().context("creating private Evidence doctor output")?;
    let mut stderr =
        tempfile::tempfile().context("creating private Evidence doctor diagnostics")?;
    let mut command = Command::new(evidence);
    command
        .arg("check")
        .arg("--runtime-config")
        .arg(runtime_config)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?));
    if dependencies {
        command.arg("--require-runtime-dependencies");
    }
    if let Some(root) = audit_root {
        command.arg("--require-audit-under").arg(root);
    }
    if without_audit_lock {
        command.arg("--without-audit-lock");
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
        delegated_run_deadline(),
        &|| Ok(()),
        &|| {
            evidence_binary::capture_over_limit(&stdout, MAX_DIAGNOSTIC_BYTES)
                || evidence_binary::capture_over_limit(&stderr, MAX_DIAGNOSTIC_BYTES)
        },
    )
    .map_err(|_| operational_diagnostic(runtime_config))?;
    let runtime_output = evidence_binary::drain_capture(
        &mut stdout,
        MAX_DIAGNOSTIC_BYTES,
        "Evidence runtime dependency preflight output",
    )
    .map_err(|_| operational_diagnostic(runtime_config))?;
    let runtime_diagnostic = evidence_binary::drain_capture(
        &mut stderr,
        MAX_DIAGNOSTIC_BYTES,
        "Evidence runtime dependency preflight diagnostics",
    )
    .map_err(|_| operational_diagnostic(runtime_config))?;

    Ok(CheckOutcome {
        status,
        stdout: runtime_output,
        stderr: runtime_diagnostic,
    })
}

fn operational_diagnostic(runtime_config: &Path) -> anyhow::Error {
    DoctorOperationalDiagnostic {
        artifact: runtime_config.display().to_string(),
    }
    .into()
}

fn delegated_run_deadline() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(milliseconds) = std::env::var_os("EVIDENCECTL_TEST_DOCTOR_DEADLINE_MS")
        .and_then(|value| value.to_str().and_then(|value| value.parse::<u64>().ok()))
    {
        return Duration::from_millis(milliseconds.max(1));
    }
    evidence_binary::DELEGATED_RUN_DEADLINE
}

fn version_handshake_deadline() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(milliseconds) = std::env::var_os("EVIDENCECTL_TEST_DOCTOR_VERSION_DEADLINE_MS")
        .and_then(|value| value.to_str().and_then(|value| value.parse::<u64>().ok()))
    {
        return Duration::from_millis(milliseconds.max(1));
    }
    evidence_binary::VERSION_HANDSHAKE_DEADLINE
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
        runtime_config,
        proof_boundary: LOCKED_PROOF_BOUNDARY,
        diagnostics: vec![Diagnostic {
            severity: "error",
            code,
            artifact: runtime_config.display().to_string(),
            path: "$",
            message: if detail.is_empty() {
                "Evidence runtime check failed without a diagnostic.".to_owned()
            } else {
                detail
            },
            suggested_action: suggested_action(runtime_diagnostic),
        }],
    };
    match format {
        OutputFormat::Json => crate::print_report(&crate::report::refused(
            "doctor",
            status,
            serde_json::to_value(&report)?,
        )),
        OutputFormat::Human => {
            eprintln!(
                "Evidence runtime dependency preflight refused {}",
                runtime_config.display()
            );
            std::io::stderr().write_all(runtime_diagnostic)?;
            if suggested_action(runtime_diagnostic) == HELD_LOCK_ACTION {
                eprintln!("Next: {HELD_LOCK_ACTION}");
            } else {
                eprintln!(
                    "Next: correct the selected runtime artifact or dependency and rerun doctor."
                );
            }
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

        let outcome =
            invoke_check(&binary, &runtime, true, Some(root.path()), false).expect("preflight");
        assert!(outcome.status.success());
        let invoked = fs::read_to_string(arguments).expect("arguments");
        assert_eq!(
            invoked,
            format!(
                "check\n--runtime-config\n{}\n--require-runtime-dependencies\n--require-audit-under\n{}\n",
                runtime.display(),
                root.path().display()
            )
        );
        assert!(!invoked.contains("serve"));
        assert!(!invoked.contains("evaluate"));
        assert!(!root.path().join("audit.jsonl").exists());

        let outcome = invoke_check(&binary, &runtime, true, None, true).expect("preflight");
        assert!(outcome.status.success());
        assert_eq!(
            fs::read_to_string(root.path().join("arguments")).expect("arguments"),
            format!(
                "check\n--runtime-config\n{}\n--require-runtime-dependencies\n--without-audit-lock\n",
                runtime.display()
            )
        );
    }

    /// An automated consumer reads `proofBoundary`, not the human lines, so
    /// the lock-free form must say there what it left unproved.
    #[test]
    fn the_lock_free_form_states_its_own_proof_boundary() {
        let locked = proof_boundary(false);
        let lock_free = proof_boundary(true);
        assert_ne!(locked, lock_free);
        assert!(!locked.contains("lock"));
        assert!(lock_free.contains("audit writer lock was not taken"));
        assert!(lock_free.contains("second writer is not detected"));
    }

    #[test]
    fn a_held_audit_lock_points_at_the_lock_free_form() {
        assert_eq!(
            suggested_action(
                b"evidence: runtime audit initialization failed: another process holds the \
                  single-writer lock beside the audit file; stop it before starting this one\n"
            ),
            HELD_LOCK_ACTION
        );
        assert_eq!(
            suggested_action(b"evidence: runtime secret initialization failed\n"),
            DEFAULT_ACTION
        );
    }

    #[test]
    fn missing_runtime_inputs_and_secrets_are_operational_failures() {
        for diagnostic in [
            "evidence: deployment input is unavailable\n",
            "evidence: runtime secret initialization failed\n",
            "evidence: runtime audit initialization failed: secret unavailable\n",
            "evidence: runtime signing initialization failed\n",
            "evidence: bound extract is stale for source registry\n",
        ] {
            assert!(runtime_diagnostic_is_dependency_failure(
                diagnostic.as_bytes()
            ));
        }
        assert!(!runtime_diagnostic_is_dependency_failure(
            b"evidence: deployment configuration is invalid\n"
        ));
    }
}
