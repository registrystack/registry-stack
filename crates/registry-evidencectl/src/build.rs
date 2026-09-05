//! Compile an editable Evidence authoring project into one closed deployment
//! candidate. Secrets and target-host paths remain operator-owned.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read as _, Seek as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    process::{Command, ExitCode, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use anyhow::{anyhow, bail, Context as _, Result};
use clap::Args;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::authoring;

const MAX_TARGET_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_CAPTURE_BYTES: u64 = 1024 * 1024;
/// How much of a failed `evidence bundle-check` diagnostic is kept for the
/// build failure message: the two bounds are applied together, whichever is
/// hit first.
const MAX_DIAGNOSTIC_EXCERPT_LINES: usize = 40;
const MAX_DIAGNOSTIC_EXCERPT_BYTES: usize = 8 * 1024;
const SECRET_PREFIX: &str = "secret:file/";

#[derive(Debug, Args)]
pub struct BuildArgs {
    /// Evidence project directory; defaults to the current directory.
    ///
    /// This command needs an editable project: one holding questions/ and
    /// sources/ beside evidence-project.yaml.
    #[arg(long, default_value = ".")]
    pub project: PathBuf,

    /// Explicit deployment target containing governance.yaml and runtime.yaml.
    #[arg(long)]
    pub target: PathBuf,

    /// New candidate directory to create. It must not already exist.
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TargetGovernance {
    version: u32,
    assurance_profile: String,
    service: Value,
    issuer: Value,
    #[serde(default)]
    publication: Option<Value>,
    authentication: Value,
    audit: Value,
    subject_binding: Value,
    rate_limits: Value,
    signing: Value,
    #[serde(default)]
    response_formats: Option<Value>,
    authority_profiles: Value,
}

impl TargetGovernance {
    fn into_bundle(self) -> Result<Value> {
        if self.version != 1 {
            bail!("deployment governance version must be 1");
        }
        if !matches!(
            self.assurance_profile.as_str(),
            "production" | "evidence-grade"
        ) {
            bail!("deployment governance assuranceProfile must be production or evidence-grade");
        }
        if self
            .authority_profiles
            .as_object()
            .is_none_or(Map::is_empty)
        {
            bail!("deployment governance requires at least one authority profile");
        }
        let mut object = Map::from_iter([
            ("version".to_owned(), json!(self.version)),
            (
                "assuranceProfile".to_owned(),
                Value::String(self.assurance_profile),
            ),
            ("service".to_owned(), self.service),
            ("issuer".to_owned(), self.issuer),
            ("authentication".to_owned(), self.authentication),
            ("audit".to_owned(), self.audit),
            ("subjectBinding".to_owned(), self.subject_binding),
            ("rateLimits".to_owned(), self.rate_limits),
            ("signing".to_owned(), self.signing),
            ("authorityProfiles".to_owned(), self.authority_profiles),
        ]);
        if let Some(response_formats) = self.response_formats {
            object.insert("responseFormats".to_owned(), response_formats);
        }
        if let Some(publication) = self.publication {
            object.insert("publication".to_owned(), publication);
        }
        Ok(Value::Object(object))
    }
}

pub fn run(args: BuildArgs) -> Result<ExitCode> {
    let interruption = BuildInterruption::install()?;
    run_inner(args, &interruption)
}

fn run_inner(args: BuildArgs, interruption: &BuildInterruption) -> Result<ExitCode> {
    interruption.check()?;
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
    let target = plain_directory(&args.target, "deployment target")?;
    let governance_bytes = read_plain_file(
        &target.join("governance.yaml"),
        MAX_TARGET_BYTES,
        "deployment governance",
    )?;
    let target_runtime = read_plain_file(
        &target.join("runtime.yaml"),
        MAX_TARGET_BYTES,
        "deployment runtime",
    )?;
    let governance: TargetGovernance = serde_norway::from_slice(&governance_bytes)
        .context("deployment governance is not the closed Version 1 target shape")?;
    let governed_bundle = governance.into_bundle()?;
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
        &target_runtime,
        governed_bundle,
        &evidence_bin,
        interruption,
    );
    let (revision, secret_references) = match result {
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
    publish(staging, &args.output)?;

    println!("Bundle revision: {revision}");
    println!("Candidate: {}", args.output.display());
    for reference in secret_references {
        println!("Provision {SECRET_PREFIX}{reference}");
    }
    println!(
        "Target runtime paths and deployment secret material remain unverified until `evidencectl doctor --project {}` and the target-host Evidence check.",
        args.output.display()
    );
    Ok(ExitCode::SUCCESS)
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

    fn check(&self) -> Result<()> {
        if self.requested.load(Ordering::Relaxed) {
            bail!("deployment build interrupted");
        }
        Ok(())
    }
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
    deployment_target: &Path,
    staging_root: &Path,
    target_runtime: &[u8],
    governed_bundle: Value,
    evidence_bin: &Path,
    interruption: &BuildInterruption,
) -> Result<(String, Vec<String>)> {
    let compiled = authoring::compile_production_project(
        project,
        deployment_target,
        staging_root,
        governed_bundle,
        evidence_bin,
    )?;
    interruption.check()?;
    reject_review_markers(&compiled.bundle_path)?;
    reject_review_markers_in_bytes(target_runtime, "deployment runtime")?;
    let runtime_path = staging_root.join("runtime.yaml");
    write_new_file(&runtime_path, target_runtime, 0o600)?;
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o400))
        .context("sealing the copied deployment runtime")?;

    let secret_references = secret_references(&compiled.bundle)?;
    let revision = run_bundle_check(evidence_bin, &compiled.bundle_path, project, interruption)?;
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
    Ok((revision, secret_references))
}

fn run_bundle_check(
    evidence_bin: &Path,
    bundle: &Path,
    project: &Path,
    interruption: &BuildInterruption,
) -> Result<String> {
    let mut command = Command::new(evidence_bin);
    command
        .arg("bundle-check")
        .arg("--bundle")
        .arg(bundle)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME");
    let output = run_evidence(command, interruption, true, true)?;
    if !output.status.success() {
        return runtime_failure(
            "Evidence rejected the generated deployment bundle",
            &format!("evidencectl fixtures run --project {}", project.display()),
            bounded_diagnostic(&output.stderr).as_deref(),
        );
    }
    parse_bundle_revision(&String::from_utf8_lossy(&output.stdout))
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
    let output = run_evidence(command, interruption, false, false)?;
    if output.status.success() {
        return Ok(());
    }
    runtime_failure(
        "Evidence rejected a deployment fixture",
        &format!(
            "evidencectl fixtures run --project {} --fixture {fixture}",
            project.display()
        ),
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
    let status = loop {
        if interruption.check().is_err() {
            terminate_validation_child(&mut child);
            return Err(anyhow!("deployment build interrupted"));
        }
        if capture_over_limit(&stdout) || capture_over_limit(&stderr) {
            terminate_validation_child(&mut child);
            bail!("Evidence deployment validation output exceeded its byte limit");
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                terminate_validation_child(&mut child);
                return Err(error).context("waiting for Evidence deployment validation");
            }
        }
    };
    interruption.check()?;

    Ok(EvidenceOutput {
        status,
        stdout: drain_capture(&mut stdout)?,
        stderr: drain_capture(&mut stderr)?,
    })
}

fn capture_over_limit(file: &Option<File>) -> bool {
    file.as_ref().is_some_and(|file| {
        file.metadata()
            .is_ok_and(|metadata| metadata.len() > MAX_EVIDENCE_CAPTURE_BYTES)
    })
}

fn drain_capture(file: &mut Option<File>) -> Result<Vec<u8>> {
    let mut captured = Vec::new();
    if let Some(file) = file.as_mut() {
        file.rewind()?;
        file.take(MAX_EVIDENCE_CAPTURE_BYTES + 1)
            .read_to_end(&mut captured)?;
        if captured.len() as u64 > MAX_EVIDENCE_CAPTURE_BYTES {
            bail!("Evidence deployment validation output exceeded its byte limit");
        }
    }
    Ok(captured)
}

fn terminate_validation_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
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

fn parse_bundle_revision(stdout: &str) -> Result<String> {
    let revision = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Evidence bundle "))
        .and_then(|line| line.split_whitespace().next())
        .filter(|value| {
            value.len() == 71
                && value.starts_with("sha256:")
                && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .ok_or_else(|| anyhow!("Evidence check returned no bundle revision"))?;
    Ok(revision.to_owned())
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

fn reject_review_markers(bundle: &Path) -> Result<()> {
    for path in bundle_files(bundle)? {
        let bytes = fs::read(&path).context("reading one generated bundle artifact")?;
        reject_review_markers_in_bytes(&bytes, "deployment bundle")?;
    }
    Ok(())
}

fn reject_review_markers_in_bytes(bytes: &[u8], description: &str) -> Result<()> {
    if [
        b"TODO(evidencectl)".as_slice(),
        b"review-required",
        b"placeholder_fact",
    ]
    .iter()
    .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
    {
        bail!("the {description} contains an unresolved authoring review marker");
    }
    Ok(())
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
        Ok(_) => bail!("output already exists; evidencectl build never overwrites a candidate"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspecting the candidate output path"),
    }
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
            Component::ParentDir | Component::Prefix(_) => {
                bail!("{description} must not contain path traversal")
            }
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

fn read_plain_file(path: &Path, maximum: u64, description: &str) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags};
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("opening {description}"))?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum {
        bail!("{description} must be a bounded regular file");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("{description} exceeds its byte limit");
    }
    Ok(bytes)
}

fn write_new_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn make_tree_removable(root: &Path) -> Result<()> {
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
    let staged = staging.keep();
    if let Err(error) = rename_noreplace(&staged, output) {
        let _ = make_tree_removable(&staged);
        let _ = fs::remove_dir_all(&staged);
        return Err(error).context("publishing the deployment candidate without replacement");
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
    fn production_governance_is_closed_at_the_target_boundary() {
        let unknown = serde_norway::from_str::<TargetGovernance>(
            r#"version: 1
assuranceProfile: production
service: {}
issuer: {}
authentication: {}
audit: {}
subjectBinding: {}
rateLimits: {}
signing: {}
authorityProfiles: {}
requirements: []
"#,
        );
        assert!(unknown.is_err());
    }

    #[test]
    fn revision_and_secret_reference_parsing_are_closed() {
        let revision = format!(
            "Evidence bundle sha256:{} passed check (2 requirements)\n",
            "a".repeat(64)
        );
        assert_eq!(
            parse_bundle_revision(&revision).expect("revision"),
            format!("sha256:{}", "a".repeat(64))
        );
        assert!(parse_bundle_revision(
            "Evidence deployment sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        )
        .is_err());
        assert!(parse_bundle_revision("Evidence bundle sha256:not-a-digest\n").is_err());

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
    fn review_markers_are_rejected_without_repeating_authored_values() {
        for marker in ["TODO(evidencectl)", "review-required", "placeholder_fact"] {
            let error = reject_review_markers_in_bytes(marker.as_bytes(), "production runtime")
                .expect_err("review marker rejected")
                .to_string();
            assert!(!error.contains(marker));
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
}
