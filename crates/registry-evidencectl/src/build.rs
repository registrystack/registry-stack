//! Compile an editable Evidence authoring project into one closed deployment
//! candidate. Secrets and target-host paths remain operator-owned.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    os::unix::fs::PermissionsExt as _,
    path::{Component, Path, PathBuf},
    process::{Command, ExitCode, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::{anyhow, bail, Context as _, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{authoring, evidence_binary, source_import::ProjectLock, OutputFormat};

const MAX_EVIDENCE_CAPTURE_BYTES: u64 = 1024 * 1024;
/// How much of a failed `evidence bundle-check` diagnostic is kept for the
/// build failure message: the two bounds are applied together, whichever is
/// hit first.
const MAX_DIAGNOSTIC_EXCERPT_LINES: usize = 40;
const MAX_DIAGNOSTIC_EXCERPT_BYTES: usize = 8 * 1024;
const SECRET_PREFIX: &str = "secret:file/";
/// What a delegated validation run is called in the diagnostics it produces.
const EVIDENCE_VALIDATION: &str = "Evidence deployment validation";

#[derive(Debug)]
pub struct BuildArgs {
    /// Evidence project directory.
    ///
    /// This command reads the EvidenceProject in evidence.yaml.
    pub project: PathBuf,

    /// Explicit EvidenceTarget file.
    pub target: PathBuf,

    /// New candidate directory to create. It must not already exist.
    pub output: PathBuf,

    /// Optional source or review revision recorded in `REVISION`.
    pub revision: Option<String>,
}

#[derive(Debug)]
pub(crate) struct TargetDocumentDiagnostic {
    pub(crate) code: &'static str,
    pub(crate) path: String,
    pub(crate) message: String,
}

impl std::fmt::Display for TargetDocumentDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TargetDocumentDiagnostic {}

pub(crate) fn run_package_with_format(args: BuildArgs, format: OutputFormat) -> Result<ExitCode> {
    let interruption = BuildInterruption::install()?;
    run_inner(args, &interruption, format)
}

fn run_inner(
    args: BuildArgs,
    interruption: &BuildInterruption,
    format: OutputFormat,
) -> Result<ExitCode> {
    interruption.check()?;
    let _project_lock = ProjectLock::acquire(&args.project)
        .with_context(|| format!("locking editable project {}", args.project.display()))?;
    let target = read_target_documents(&args.target)?;
    reject_existing_output(&args.output)?;
    let project = plain_directory(&args.project, "authoring project")?;
    let output_parent = plain_parent(&args.output)?;
    let candidate = output_parent.join(
        args.output
            .file_name()
            .ok_or_else(|| anyhow!("candidate output must name one new directory"))?,
    );
    if candidate.starts_with(&project) {
        bail!("candidate output must remain outside the editable project");
    }
    verify_stable_package_root(&target.runtime, &candidate)?;
    let evidence_bin = crate::evidence_binary::resolve_matching(None)?;

    interruption.check()?;
    let staging = tempfile::Builder::new()
        .prefix(".evidencectl-build-")
        .tempdir_in(&output_parent)
        .with_context(|| format!("staging the candidate in {}", output_parent.display()))?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))
        .context("setting private deployment candidate staging permissions")?;
    let result = prepare_candidate(
        &project,
        &target,
        staging.path(),
        &evidence_bin,
        interruption,
        args.revision.as_deref(),
    );
    let (package_digest, secret_references) = match result {
        Ok(result) => result,
        Err(error) => {
            close_candidate_staging(staging)?;
            return Err(error);
        }
    };
    if let Err(error) = interruption.check() {
        close_candidate_staging(staging)?;
        return Err(error);
    }
    publish(staging, &candidate)?;

    if format == OutputFormat::Json {
        crate::report::print(&crate::report::success(
            "package",
            "packaged",
            json!({
                "project": args.project,
                "target": args.target,
                "output": args.output,
                "package": args.output.join("bundle"),
                "runtime": args.output.join("runtime.yaml"),
                "authority": args.output.join("compiled-authority.yaml"),
                "packageDigest": package_digest,
                "revision": args.revision,
                "requiredSecrets": secret_references,
                "proofBoundary": "offline deployment candidate compilation and fixture validation"
            }),
        ))?;
        return Ok(ExitCode::SUCCESS);
    }
    println!("Package digest: {package_digest}");
    if let Some(revision) = &args.revision {
        println!("Revision: {revision}");
    }
    println!("Package: {}", args.output.join("bundle").display());
    println!("Runtime: {}", args.output.join("runtime.yaml").display());
    println!(
        "Authority: {}",
        args.output.join("compiled-authority.yaml").display()
    );
    for reference in secret_references {
        println!("Provision {SECRET_PREFIX}{reference}");
    }
    println!(
        "Target runtime paths and deployment secret material remain unverified until `evidencectl doctor --runtime-config {}`.",
        args.output.join("runtime.yaml").display(),
    );
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn validated_question_revisions(
    project: &Path,
    target: &Path,
) -> Result<BTreeMap<String, String>> {
    let evidence_bin = crate::evidence_binary::resolve_matching(None)?;
    let interruption = BuildInterruption::passive();
    let compiled = compile_target_fixture_project(project, target, &evidence_bin)?;
    let report = run_bundle_check_report(
        &evidence_bin,
        &compiled.bundle_path,
        &compiled.runtime_path,
        Some(&compiled.target_path),
        project,
        &compiled.fixture_paths,
        &interruption,
    )?;
    for fixture in &compiled.fixture_paths {
        run_bundle_fixture(
            &evidence_bin,
            &compiled.bundle_path,
            fixture,
            project,
            &interruption,
        )?;
    }
    Ok(report
        .requirements
        .into_iter()
        .map(|requirement| (requirement.id, requirement.configuration_revision))
        .collect())
}

pub(crate) struct TargetFixtureProject {
    pub(crate) bundle_path: PathBuf,
    pub(crate) runtime_path: PathBuf,
    pub(crate) target_path: PathBuf,
    pub(crate) fixture_paths: Vec<String>,
    staging: tempfile::TempDir,
}

impl Drop for TargetFixtureProject {
    fn drop(&mut self) {
        if let Err(error) = make_tree_removable(self.staging.path()) {
            eprintln!(
                "{}",
                authoring::cleanup_failure_line(self.staging.path(), &error)
            );
        }
    }
}

pub(crate) fn compile_target_fixture_project(
    project: &Path,
    target: &Path,
    evidence_bin: &Path,
) -> Result<TargetFixtureProject> {
    let target_path = crate::target::target_path(target);
    let target = read_target_documents(&target_path)?;
    let staging = tempfile::Builder::new()
        .prefix("evidencectl-target-fixtures-")
        .tempdir()
        .context("creating private target fixture compilation staging")?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))
        .context("sealing private target fixture compilation staging")?;
    let staging_path = fs::canonicalize(staging.path())
        .context("resolving private target fixture compilation staging")?;
    let compiled = compile_with_target(project, &target, &staging_path, evidence_bin, None)?;
    Ok(TargetFixtureProject {
        bundle_path: compiled.bundle_path,
        runtime_path: compiled.runtime_path,
        target_path,
        fixture_paths: compiled.fixture_paths,
        staging,
    })
}

pub(crate) fn local_dev_target_inputs(target: &Path) -> Result<(Value, Value)> {
    let path = if target.is_dir() {
        target.join("target.yaml")
    } else {
        target.to_path_buf()
    };
    let bytes = crate::authored::read_authored_file(&path, "local EvidenceTarget")?;
    let target =
        registry_evidence_authoring::target::read_target(&path.to_string_lossy(), &bytes)?.value;
    if target.assurance_profile.is_some_and(|profile| {
        profile != registry_evidence_authoring::target::TargetAssuranceProfile::Local
    }) {
        bail!("dev requires a local target");
    }
    let connections = target
        .connections
        .iter()
        .map(|(id, value)| Ok((id.to_string(), value.governed_value()?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut outbound_tls = target
        .outbound_tls
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or_else(|| json!({"systemRoots":true,"trustProfiles":{}}));
    rebase_outbound_tls(
        crate::normalized::target_directory(&path),
        &mut outbound_tls,
    )?;
    Ok((json!(connections), outbound_tls))
}

struct BuildInterruption {
    requested: Arc<AtomicBool>,
    registrations: Vec<signal_hook::SigId>,
}

impl BuildInterruption {
    fn install() -> Result<Self> {
        let mut guard = Self {
            requested: Arc::new(AtomicBool::new(false)),
            registrations: Vec::new(),
        };
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            let registration = signal_hook::flag::register(signal, Arc::clone(&guard.requested))
                .context("installing the deployment-build signal handler")?;
            guard.registrations.push(registration);
        }
        Ok(guard)
    }

    fn passive() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
            registrations: Vec::new(),
        }
    }

    fn check(&self) -> Result<()> {
        if self.requested.load(Ordering::Relaxed) {
            bail!("deployment build interrupted");
        }
        Ok(())
    }
}

/// A target's `runtime.yaml` as a JSON value, read through the shared YAML
/// subset. The runtime document's envelope and members are the runtime's to
/// check, by `evidencectl doctor --runtime-config` and the `evidence` binary.
pub(crate) fn runtime_value(
    bytes: &[u8],
) -> std::result::Result<Value, registry_platform_yaml::Report> {
    registry_platform_yaml::Reader::new("runtime.yaml")
        .scan(bytes)
        .map(crate::authored::node_value)
}

pub(crate) struct TargetDocuments {
    pub(crate) root: PathBuf,
    pub(crate) runtime: Vec<u8>,
    pub(crate) governed_bundle: Value,
    pub(crate) normalized_target: Option<registry_evidence_authoring::target::EvidenceTarget>,
    pub(crate) authority_path: PathBuf,
    pub(crate) authority: Vec<u8>,
    pub(crate) source_path: Option<PathBuf>,
    pub(crate) _stage: Option<tempfile::TempDir>,
}

pub(crate) fn read_target_documents(target: &Path) -> Result<TargetDocuments> {
    crate::normalized::read_target_documents(target)
}

pub(crate) struct TargetCompilation {
    pub(crate) bundle_path: PathBuf,
    pub(crate) runtime_path: PathBuf,
    pub(crate) fixture_paths: Vec<String>,
    pub(crate) bundle: Value,
}

pub(crate) fn compile_with_target(
    project: &Path,
    target: &TargetDocuments,
    staging_root: &Path,
    evidence_bin: &Path,
    revision: Option<&str>,
) -> Result<TargetCompilation> {
    // Every project read and copied asset comes from the same descriptor-captured
    // snapshot, even if an editor replaces the original path during delegation.
    let snapshot = crate::project_snapshot::capture_project(project)?;
    let authority = if let Some(target_model) = &target.normalized_target {
        let (project_model, _) = crate::normalized::read(snapshot.root())
            .map_err(|error| crate::authored::project_refusal(error, snapshot.root(), project))?;
        if target_model.project != project_model.id {
            return Err(TargetDocumentDiagnostic {
                code: "evidence.target.project",
                path: format!(
                    "{}:/project",
                    target
                        .source_path
                        .as_deref()
                        .unwrap_or_else(|| Path::new("target.yaml"))
                        .display()
                ),
                message: "the selected target must name this EvidenceProject".to_owned(),
            }
            .into());
        }
        Some(crate::normalized::compiled_authority(
            &project_model,
            target_model,
            &target.authority_path,
            &target.authority,
        )?)
    } else {
        None
    };
    let compiled = authoring::compile_target_project_with_revision(
        snapshot.root(),
        &target.root,
        staging_root,
        target.governed_bundle.clone(),
        evidence_bin,
        revision,
    )
    .map_err(|error| {
        if let (Some(source), Some(diagnostic)) = (
            &target.source_path,
            error.downcast_ref::<authoring::AuthoredDiagnostic>(),
        ) {
            if let Some(pointer) = diagnostic.path.strip_prefix("target.yaml:") {
                return authoring::AuthoredDiagnostic {
                    code: diagnostic.code.clone(),
                    path: format!("{}:{pointer}", source.display()),
                    message: diagnostic.message.clone(),
                }
                .into();
            }
        }
        crate::authored::project_refusal(error, snapshot.root(), project)
    })?;
    if let Some(authority) = authority {
        fs::write(
            staging_root.join("compiled-authority.yaml"),
            crate::authored::to_indented_yaml(&authority)?,
        )?;
    }
    let runtime_path = staging_root.join("runtime.yaml");
    fs::write(&runtime_path, &target.runtime)?;
    Ok(TargetCompilation {
        bundle_path: compiled.bundle_path,
        runtime_path,
        fixture_paths: compiled.fixture_paths,
        bundle: compiled.bundle,
    })
}

impl Drop for BuildInterruption {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

fn prepare_candidate(
    project: &Path,
    target: &TargetDocuments,
    staging_root: &Path,
    evidence_bin: &Path,
    interruption: &BuildInterruption,
    revision: Option<&str>,
) -> Result<(String, Vec<String>)> {
    let compiled = compile_with_target(project, target, staging_root, evidence_bin, revision)?;
    interruption.check()?;
    reject_review_markers(&compiled.bundle_path)?;
    reject_review_markers_in_bytes(&target.runtime, "runtime.yaml")?;
    let package_digest = run_bundle_check(
        evidence_bin,
        &compiled.bundle_path,
        &compiled.runtime_path,
        target.source_path.as_deref(),
        project,
        &compiled.fixture_paths,
        interruption,
    )?;
    for fixture in &compiled.fixture_paths {
        interruption.check()?;
        run_bundle_fixture(
            evidence_bin,
            &compiled.bundle_path,
            fixture,
            project,
            interruption,
        )?;
    }
    // Secret references are collected only after the delegated bundle check
    // passes, so a malformed reference in the runtime section is reported by
    // that check at its authored location first.
    let runtime = runtime_value(&target.runtime).map_err(anyhow::Error::new)?;
    let secret_references = secret_references(&json!([compiled.bundle, runtime]))?;
    Ok((package_digest, secret_references))
}

/// Refuse a package whose deployment runtime would load a package
/// left behind by a different `package` invocation. `package.root` is the
/// one path the running process trusts at startup, so a runtime path nested in
/// one generated output could never remain stable across installations. This
/// check only compares the value against the package this
/// invocation is producing; it leaves full runtime shape validation to
/// `evidencectl doctor --runtime-config` and the `evidence` binary itself, so
/// a runtime document that is otherwise malformed is still caught there
/// rather than reported twice.
fn verify_stable_package_root(runtime_bytes: &[u8], candidate: &Path) -> Result<()> {
    let Ok(document) = runtime_value(runtime_bytes) else {
        return Ok(());
    };
    let Some(package_root) = document.pointer("/package/root").and_then(Value::as_str) else {
        return Ok(());
    };
    if Path::new(package_root) != candidate && !Path::new(package_root).starts_with(candidate) {
        return Ok(());
    }
    Err(TargetDocumentDiagnostic {
        code: "evidence.package.root-unstable",
        path: "runtime.yaml:/package/root".to_owned(),
        message: "deployment runtime package.root is inside the output directory of this package run; set it to a stable installed package path outside that directory".to_owned(),
    }
    .into())
}

fn run_bundle_check(
    evidence_bin: &Path,
    bundle: &Path,
    runtime: &Path,
    target: Option<&Path>,
    project: &Path,
    fixtures: &[String],
    interruption: &BuildInterruption,
) -> Result<String> {
    Ok(run_bundle_check_report(
        evidence_bin,
        bundle,
        runtime,
        target,
        project,
        fixtures,
        interruption,
    )?
    .package_digest)
}

fn run_bundle_check_report(
    evidence_bin: &Path,
    bundle: &Path,
    runtime: &Path,
    target: Option<&Path>,
    project: &Path,
    fixtures: &[String],
    interruption: &BuildInterruption,
) -> Result<BundleCheckReport> {
    let mut command = Command::new(evidence_bin);
    command
        .arg("bundle-check")
        .arg("--bundle")
        .arg(bundle)
        .arg("--runtime-config")
        .arg(runtime)
        .arg("--json")
        .env_remove("REGISTRY_EVIDENCE_RUNTIME");
    if let Some(parent) = bundle.parent() {
        let authority = parent.join("compiled-authority.yaml");
        if authority.is_file() {
            command.arg("--authority-document").arg(authority);
        }
    }
    let output = run_evidence(command, interruption, true, true)?;
    if !output.status.success() {
        if let Some(report) = crate::authored::runtime_refusal(&output.stdout) {
            let report = crate::authored::runtime_target_refusal(report, runtime, target);
            return Err(
                crate::authored::runtime_bundle_refusal(report, bundle, project, fixtures).into(),
            );
        }
        return runtime_failure(
            "Evidence rejected the generated deployment bundle",
            &format!("evidencectl test {}", project.display()),
            bounded_diagnostic(&output.stderr).as_deref(),
        );
    }
    parse_bundle_check_report(&output.stdout)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BundleCheckReport {
    pub(crate) package_digest: String,
    pub(crate) requirements: Vec<BundleCheckRequirement>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BundleCheckRequirement {
    pub(crate) id: String,
    pub(crate) configuration_revision: String,
}

/// Ask the owning runtime to validate a generated governed bundle and the
/// static bindings in its generated runtime document.
///
/// This seam deliberately cannot execute fixtures, resolve secrets, load
/// activated authority, or inspect target-host dependencies. It is used by
/// the offline authoring check after the existing compiler has assembled an
/// unpublished candidate.
pub(crate) fn check_compiled_bundle(
    evidence_bin: &Path,
    bundle: &Path,
    runtime: &Path,
    target: Option<&Path>,
    project: &Path,
    fixtures: &[String],
) -> Result<BundleCheckReport> {
    run_bundle_check_report(
        evidence_bin,
        bundle,
        runtime,
        target,
        project,
        fixtures,
        &BuildInterruption::passive(),
    )
}

fn parse_bundle_check_report(stdout: &[u8]) -> Result<BundleCheckReport> {
    let report: BundleCheckReport = serde_json::from_slice(stdout)
        .context("Evidence check returned an invalid package digest report")?;
    validate_digest(&report.package_digest, "packageDigest")?;
    if report.requirements.is_empty() {
        bail!("Evidence check returned no requirement revisions");
    }
    let mut ids = BTreeSet::new();
    for requirement in &report.requirements {
        if requirement.id.is_empty() || requirement.id.len() > 512 {
            bail!("Evidence check returned an invalid requirement id");
        }
        if !ids.insert(requirement.id.clone()) {
            bail!("Evidence check returned duplicate requirement revisions");
        }
        validate_digest(
            &requirement.configuration_revision,
            "requirement configurationRevision",
        )?;
    }
    Ok(report)
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    if value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Ok(());
    }
    bail!("Evidence check returned an invalid {label}")
}

fn run_bundle_fixture(
    evidence_bin: &Path,
    bundle: &Path,
    fixture: &str,
    project: &Path,
    interruption: &BuildInterruption,
) -> Result<()> {
    let mut command = Command::new(evidence_bin);
    command
        .arg("bundle-evaluate")
        .arg("--bundle")
        .arg(bundle)
        .arg("--fixture")
        .arg(fixture)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME");
    if let Some(parent) = bundle.parent() {
        let authority = parent.join("compiled-authority.yaml");
        if authority.is_file() {
            command.arg("--authority-document").arg(authority);
        }
    }
    let output = run_evidence(command, interruption, false, false)?;
    if output.status.success() {
        return Ok(());
    }
    runtime_failure(
        "Evidence rejected a deployment fixture",
        &format!("evidencectl test {} --fixture {fixture}", project.display()),
        None,
    )
}

struct EvidenceOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_evidence(
    mut command: Command,
    interruption: &BuildInterruption,
    capture_stdout: bool,
    capture_stderr: bool,
) -> Result<EvidenceOutput> {
    interruption.check()?;
    let mut stdout = capture_stdout
        .then(tempfile::tempfile)
        .transpose()
        .context("creating a private Evidence standard-output capture")?;
    let mut stderr = capture_stderr
        .then(tempfile::tempfile)
        .transpose()
        .context("creating a private Evidence standard-error capture")?;
    command.stdin(Stdio::null());
    if let Some(file) = &stdout {
        command.stdout(Stdio::from(file.try_clone()?));
    } else {
        command.stdout(Stdio::null());
    }
    if let Some(file) = &stderr {
        command.stderr(Stdio::from(file.try_clone()?));
    } else {
        command.stderr(Stdio::null());
    }
    let mut child = command
        .spawn()
        .context("starting the Evidence deployment validation")?;
    let status = evidence_binary::wait_bounded(
        &mut child,
        EVIDENCE_VALIDATION,
        evidence_binary::DELEGATED_RUN_DEADLINE,
        &|| interruption.check(),
        &|| capture_over_limit(&stdout) || capture_over_limit(&stderr),
    )?;
    interruption.check()?;

    Ok(EvidenceOutput {
        status,
        stdout: drain_capture(&mut stdout)?,
        stderr: drain_capture(&mut stderr)?,
    })
}

fn capture_over_limit(file: &Option<File>) -> bool {
    file.as_ref()
        .is_some_and(|file| evidence_binary::capture_over_limit(file, MAX_EVIDENCE_CAPTURE_BYTES))
}

fn drain_capture(file: &mut Option<File>) -> Result<Vec<u8>> {
    match file.as_mut() {
        Some(file) => {
            evidence_binary::drain_capture(file, MAX_EVIDENCE_CAPTURE_BYTES, EVIDENCE_VALIDATION)
        }
        None => Ok(Vec::new()),
    }
}

/// Refuse the build with a fixed sentence, the command that shows the reader
/// what Evidence objected to, and, when the caller has one, a bounded excerpt
/// of what Evidence printed.
///
/// `evidence bundle-check` only loads and statically compiles the generated
/// bundle: it never resolves a secret, runs a source query, or reads a
/// subject selector, so its stderr is safe to fold into an unattended build's
/// own error text. `evidence bundle-evaluate` runs a fixture through the
/// compiled bundle, so its stderr is not relayed here; `evidencectl fixtures
/// run` compiles the project again and relays it for an operator who asks for
/// it at a terminal.
fn runtime_failure<T>(message: &str, diagnosis_command: &str, excerpt: Option<&str>) -> Result<T> {
    match excerpt {
        Some(excerpt) => bail!(
            "{message}. Run `{diagnosis_command}` to read the diagnosis Evidence prints.\n\nEvidence reported:\n{excerpt}"
        ),
        None => bail!("{message}. Run `{diagnosis_command}` to read the diagnosis Evidence prints."),
    }
}

/// Keep only the most recent lines of a captured diagnostic, bounded first to
/// `MAX_DIAGNOSTIC_EXCERPT_LINES` lines and then to
/// `MAX_DIAGNOSTIC_EXCERPT_BYTES` bytes, and say so when earlier content was
/// cut. Returns `None` for empty input, so a caller with nothing to show
/// omits the excerpt entirely.
fn bounded_diagnostic(raw: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let all_lines: Vec<&str> = text.lines().collect();
    let mut trimmed = all_lines.len() > MAX_DIAGNOSTIC_EXCERPT_LINES;
    let start = all_lines.len().saturating_sub(MAX_DIAGNOSTIC_EXCERPT_LINES);
    let mut excerpt = all_lines[start..].join("\n");
    if excerpt.len() > MAX_DIAGNOSTIC_EXCERPT_BYTES {
        trimmed = true;
        let cut = excerpt.len() - MAX_DIAGNOSTIC_EXCERPT_BYTES;
        let cut = (cut..=excerpt.len())
            .find(|&index| excerpt.is_char_boundary(index))
            .unwrap_or(excerpt.len());
        excerpt = excerpt[cut..].to_owned();
    }
    if trimmed {
        excerpt = format!(
            "(diagnostic trimmed to the last {MAX_DIAGNOSTIC_EXCERPT_LINES} lines / {MAX_DIAGNOSTIC_EXCERPT_BYTES} bytes)\n{excerpt}"
        );
    }
    Some(excerpt)
}

fn secret_references(value: &Value) -> Result<Vec<String>> {
    let mut references = BTreeSet::new();
    collect_secret_references(value, &mut references)?;
    Ok(references.into_iter().collect())
}

fn collect_secret_references(value: &Value, references: &mut BTreeSet<String>) -> Result<()> {
    match value {
        Value::String(value) => {
            if let Some(reference) = value.strip_prefix(SECRET_PREFIX) {
                if !valid_secret_name(reference) {
                    bail!("deployment logical file secret reference has invalid syntax");
                }
                references.insert(reference.to_owned());
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_secret_references(value, references)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_secret_references(value, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn valid_secret_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 128
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// Refuse a compiled bundle that still carries an authoring review marker,
/// naming the offending file and the marker rule it matched so the refusal
/// is actionable from `check` and `package` alike, instead of the generic
/// message each command's `safe_command` wrapper falls back to for an
/// unnamed cause.
pub(crate) fn reject_review_markers(bundle: &Path) -> Result<()> {
    for path in bundle_files(bundle)? {
        let bytes = fs::read(&path).context("reading one generated bundle artifact")?;
        let relative = path.strip_prefix(bundle).unwrap_or(&path);
        reject_review_markers_in_bytes(&bytes, &format!("bundle/{}", relative.display()))?;
    }
    Ok(())
}

fn reject_review_markers_in_bytes(bytes: &[u8], artifact_path: &str) -> Result<()> {
    let marker = ["TODO(evidencectl)", "review-required", "placeholder_fact"]
        .into_iter()
        .find(|marker| {
            bytes
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        });
    let Some(marker) = marker else {
        return Ok(());
    };
    Err(TargetDocumentDiagnostic {
        code: "evidence.package.review-marker",
        path: artifact_path.to_owned(),
        message: format!(
            "{artifact_path} still contains the unresolved authoring review marker {marker}"
        ),
    }
    .into())
}

fn bundle_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(&path).context("walking the generated bundle")? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                bail!("the generated bundle contains a symbolic link");
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                files.push(path);
            } else {
                bail!("the generated bundle contains an unsupported entry");
            }
        }
    }
    files.sort();
    Ok(files)
}

fn reject_existing_output(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("output already exists; evidencectl package never overwrites a candidate"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspecting the candidate output path"),
    }
}

pub(crate) fn rebase_outbound_tls(target_root: &Path, outbound_tls: &mut Value) -> Result<()> {
    let outbound_tls = outbound_tls
        .as_object_mut()
        .ok_or_else(|| anyhow!("deployment runtime outboundTls must be a mapping"))?;
    let trust_profiles = outbound_tls
        .get_mut("trustProfiles")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("deployment runtime outboundTls.trustProfiles must be a mapping"))?;
    for profile in trust_profiles.values_mut() {
        let profile = profile
            .as_object_mut()
            .ok_or_else(|| anyhow!("deployment runtime TLS trust profiles must be mappings"))?;
        let Some(file) = profile.get_mut("caBundleFile") else {
            continue;
        };
        let file_name = file
            .as_str()
            .ok_or_else(|| anyhow!("deployment runtime TLS caBundleFile must be a string"))?;
        *file = Value::String(rebase_target_file(
            target_root,
            file_name,
            "TLS CA bundle file",
        )?);
    }
    Ok(())
}

fn rebase_target_file(target_root: &Path, value: &str, description: &str) -> Result<String> {
    let path = Path::new(value);
    let resolved = if path.is_absolute() {
        plain_file_path(path, description)?
    } else {
        if path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!("{description} must be an absolute path or a plain target-relative file path");
        }
        plain_file_path(&target_root.join(path), description)?
    };
    let metadata =
        fs::symlink_metadata(&resolved).with_context(|| format!("inspecting {description}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("{description} must be a plain file");
    }
    Ok(resolved.display().to_string())
}

fn plain_file_path(path: &Path, description: &str) -> Result<PathBuf> {
    if !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        bail!("{description} must name one file");
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    validate_plain_components(parent, description, true)?;
    let parent = fs::canonicalize(parent).with_context(|| format!("resolving {description}"))?;
    Ok(parent.join(path.file_name().expect("checked file name")))
}
fn plain_parent(path: &Path) -> Result<PathBuf> {
    if !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        bail!("candidate output must name one new directory");
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    validate_plain_components(parent, "candidate parent", true)?;
    fs::canonicalize(parent).context("resolving the candidate parent")
}

fn plain_directory(path: &Path, description: &str) -> Result<PathBuf> {
    validate_plain_components(path, description, true)?;
    fs::canonicalize(path).with_context(|| format!("resolving {description} directory"))
}

fn validate_plain_components(
    path: &Path,
    description: &str,
    final_is_directory: bool,
) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let components = absolute.components().collect::<Vec<_>>();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(value) => current.push(value),
            Component::CurDir => continue,
            Component::ParentDir => {
                current.pop();
                continue;
            }
            Component::Prefix(_) => bail!("{description} must use a local filesystem path"),
        }
        let metadata =
            fs::symlink_metadata(&current).with_context(|| format!("inspecting {description}"))?;
        if metadata.file_type().is_symlink() {
            bail!("{description} must not traverse symbolic links");
        }
        let is_final = index + 1 == components.len();
        if (!is_final || final_is_directory) && !metadata.is_dir() {
            bail!("{description} must be an existing plain directory");
        }
    }
    Ok(())
}

pub(crate) fn make_tree_removable(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            bail!("private staging contains a symbolic link");
        }
        if metadata.is_dir() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            make_tree_removable(&path)?;
        } else if metadata.is_file() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        } else {
            bail!("private staging contains an unsupported entry");
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn close_candidate_staging(staging: tempfile::TempDir) -> Result<()> {
    make_tree_removable(staging.path())?;
    staging
        .close()
        .context("removing private deployment candidate staging")
}

fn publish(staging: tempfile::TempDir, output: &Path) -> Result<()> {
    // The candidate owns one immutable package and separate target handoff
    // documents. Moving their common private parent publishes all three at once.
    for file in ["runtime.yaml", "compiled-authority.yaml"] {
        if let Err(error) =
            fs::set_permissions(staging.path().join(file), fs::Permissions::from_mode(0o400))
        {
            close_candidate_staging(staging)?;
            return Err(error).context("sealing the candidate target handoff");
        }
    }
    let staged_root = staging.keep();
    if let Err(error) = rename_noreplace(&staged_root, output) {
        let _ = make_tree_removable(&staged_root);
        let _ = fs::remove_dir_all(&staged_root);
        return Err(error).context("publishing the deployment candidate without replacement");
    }
    if let Err(error) = fs::set_permissions(output, fs::Permissions::from_mode(0o500)) {
        let _ = make_tree_removable(output);
        let _ = fs::remove_dir_all(output);
        return Err(error).context("sealing the published candidate root");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn rename_noreplace(_source: &Path, _destination: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace candidate publication is unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn sibling_candidate_parent_is_allowed_after_each_component_is_checked() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::create_dir(root.join("project")).unwrap();
        let candidate = root.join("project/../candidate");
        assert_eq!(plain_parent(&candidate).unwrap(), root);
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.join("linked")).unwrap();
        assert!(plain_parent(&root.join("linked/../candidate")).is_err());
    }

    #[test]
    fn normalized_target_reader_rejects_runtime_owned_keys() {
        let text = include_str!("../../../products/evidence/examples/standalone/local-target.yaml");
        let report = registry_evidence_authoring::target::read_target(
            "target.yaml",
            format!("{text}\nrequirements: []\n").as_bytes(),
        )
        .unwrap_err();
        assert!(report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.path == "/requirements"
                && diagnostic.code == "config.unknown-key"));
    }

    #[test]
    fn normalized_target_reader_accepts_bom_and_refuses_oversized_documents() {
        let text = include_str!("../../../products/evidence/examples/standalone/local-target.yaml");
        registry_evidence_authoring::target::read_target(
            "target.yaml",
            format!("\u{feff}{text}").as_bytes(),
        )
        .unwrap();
        let oversized = format!(
            "{text}{}",
            "#".repeat(registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES + 64)
        );
        let report =
            registry_evidence_authoring::target::read_target("target.yaml", oversized.as_bytes())
                .unwrap_err();
        assert!(report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "yaml.too-large"));
    }

    #[test]
    fn target_relative_tls_ca_files_are_rebased_without_following_links() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::create_dir(root.join("trust")).unwrap();
        fs::write(root.join("trust/ca.pem"), "synthetic CA").unwrap();
        let mut tls =
            json!({"systemRoots":true,"trustProfiles":{"local":{"caBundleFile":"trust/ca.pem"}}});
        rebase_outbound_tls(&root, &mut tls).unwrap();
        assert_eq!(
            tls["trustProfiles"]["local"]["caBundleFile"],
            root.join("trust/ca.pem").to_str().unwrap()
        );
        symlink(root.join("trust/ca.pem"), root.join("linked.pem")).unwrap();
        let mut linked = json!({"trustProfiles":{"local":{"caBundleFile":"linked.pem"}}});
        assert!(rebase_outbound_tls(&root, &mut linked).is_err());
    }

    #[test]
    fn package_report_and_secret_reference_parsing_are_closed() {
        let report = parse_bundle_check_report(
            serde_json::json!({
                "packageDigest": format!("sha256:{}", "b".repeat(64)),
                "requirements": [
                    {"id": "registry-status", "configurationRevision": format!("sha256:{}", "c".repeat(64))}
                ]
            })
            .to_string()
            .as_bytes(),
        )
        .expect("bundle-check JSON report");
        assert_eq!(report.package_digest, format!("sha256:{}", "b".repeat(64)));
        assert_eq!(
            report.requirements[0].configuration_revision,
            format!("sha256:{}", "c".repeat(64))
        );
        assert!(parse_bundle_check_report(
            serde_json::json!({
                "packageDigest": format!("sha256:{}", "b".repeat(64)),
                "requirements": [
                    {"id": "registry-status", "configurationRevision": format!("sha256:{}", "C".repeat(64))}
                ]
            })
            .to_string()
            .as_bytes()
        )
        .is_err());
        assert!(parse_bundle_check_report(
            br#"{"packageDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","requirements":[{"id":"dup","configurationRevision":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},{"id":"dup","configurationRevision":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]}"#
        )
        .is_err());

        let names = secret_references(&json!({
            "z": "secret:file/source-token",
            "a": ["secret:file/audit-key", "secret:file/source-token"]
        }))
        .expect("references");
        assert_eq!(names, ["audit-key", "source-token"]);
        assert!(secret_references(&json!({"key": "secret:file/../escape"})).is_err());
        assert!(secret_references(&json!({"key": "secret:file/nested/escape"})).is_err());
    }

    #[test]
    fn target_and_candidate_paths_reject_ancestor_symlinks() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = fs::canonicalize(temporary.path()).expect("canonical tempdir");
        let actual = root.join("actual");
        fs::create_dir(&actual).expect("actual directory");
        let link = root.join("link");
        symlink(&actual, &link).expect("ancestor symlink");

        assert!(plain_directory(&link, "deployment target").is_err());
        assert!(plain_parent(&link.join("candidate")).is_err());
    }

    #[test]
    fn review_markers_are_named_by_rule_and_path_without_repeating_surrounding_content() {
        for marker in ["TODO(evidencectl)", "review-required", "placeholder_fact"] {
            let surrounded = format!("before {marker} after-authored-suffix");
            let error = reject_review_markers_in_bytes(
                surrounded.as_bytes(),
                "schemas/example.schema.yaml",
            )
            .expect_err("review marker rejected")
            .to_string();
            assert!(error.contains(marker), "{error}");
            assert!(error.contains("schemas/example.schema.yaml"), "{error}");
            assert!(!error.contains("before"), "{error}");
            assert!(!error.contains("after-authored-suffix"), "{error}");
        }
    }

    #[test]
    fn bounded_diagnostic_omits_empty_input() {
        assert!(bounded_diagnostic(b"").is_none());
        assert!(bounded_diagnostic(b"   \n  \n").is_none());
    }

    #[test]
    fn bounded_diagnostic_passes_short_input_through_unchanged() {
        let raw = b"first line\nsecond line\n";
        assert_eq!(
            bounded_diagnostic(raw).expect("diagnostic present"),
            "first line\nsecond line"
        );
    }

    #[test]
    fn bounded_diagnostic_keeps_only_the_most_recent_lines() {
        let last_line_number = MAX_DIAGNOSTIC_EXCERPT_LINES + 10;
        let raw = (1..=last_line_number)
            .map(|number| format!("line {number}"))
            .collect::<Vec<_>>()
            .join("\n");
        let excerpt = bounded_diagnostic(raw.as_bytes()).expect("diagnostic present");
        assert!(
            excerpt.starts_with("(diagnostic trimmed to the last"),
            "excerpt says it was trimmed: {excerpt}"
        );
        assert!(excerpt.contains(&format!("line {last_line_number}")));
        assert!(!excerpt.contains("line 1\n") && !excerpt.ends_with("line 1"));
        assert_eq!(
            excerpt.lines().skip(1).count(),
            MAX_DIAGNOSTIC_EXCERPT_LINES
        );
    }

    #[test]
    fn bounded_diagnostic_bounds_total_bytes_even_within_the_line_limit() {
        let raw = "a".repeat(MAX_DIAGNOSTIC_EXCERPT_BYTES * 2);
        let excerpt = bounded_diagnostic(raw.as_bytes()).expect("diagnostic present");
        assert!(
            excerpt.starts_with("(diagnostic trimmed to the last"),
            "excerpt says it was trimmed: {excerpt}"
        );
        let kept = excerpt
            .rsplit('\n')
            .next()
            .expect("content survives the trim note");
        assert!(kept.len() <= MAX_DIAGNOSTIC_EXCERPT_BYTES);
    }
    #[test]
    fn candidate_publication_keeps_target_handoff_outside_immutable_package() {
        let root = tempfile::tempdir().unwrap();
        let stage = tempfile::Builder::new()
            .prefix("candidate-")
            .tempdir_in(root.path())
            .unwrap();
        fs::create_dir(stage.path().join("bundle")).unwrap();
        fs::write(
            stage.path().join("bundle/evidence.yaml"),
            b"compiled package",
        )
        .unwrap();
        fs::write(stage.path().join("runtime.yaml"), b"operator runtime").unwrap();
        fs::write(
            stage.path().join("compiled-authority.yaml"),
            b"complete target authority",
        )
        .unwrap();
        let output = root.path().join("candidate");
        publish(stage, &output).unwrap();
        assert!(output.join("bundle/evidence.yaml").is_file());
        assert!(output.join("runtime.yaml").is_file());
        assert!(output.join("compiled-authority.yaml").is_file());
        assert!(!output.join("bundle/compiled-authority.yaml").exists());
        let other = tempfile::Builder::new()
            .prefix("candidate-")
            .tempdir_in(root.path())
            .unwrap();
        fs::create_dir(other.path().join("bundle")).unwrap();
        fs::write(other.path().join("runtime.yaml"), b"replacement").unwrap();
        fs::write(other.path().join("compiled-authority.yaml"), b"replacement").unwrap();
        assert!(publish(other, &output).is_err());
        assert!(fs::read(output.join("runtime.yaml")).unwrap() == b"operator runtime");
        make_tree_removable(&output).unwrap();
    }
}
