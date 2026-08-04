//! Deployment-project mode walk.
//!
//! Evidence and Mint refuse, at startup, any deployment artifact whose
//! permissions or ownership are wrong: a bundle they could write to, a secret
//! readable past its owner, an audit chain another user could edit. Each
//! refusal is correct and each names one artifact, so an operator who has just
//! run `chmod -R` over a project discovers them one restart at a time.
//!
//! This walks the whole project and reports every artifact that would be
//! refused, in one pass, without starting anything. It re-states the runtime's
//! rules rather than deciding anything of its own: it makes no Evidence
//! semantic decision, needs no `evidence` binary, and is advisory. What the
//! runtime accepts at startup remains the only authority.
//!
//! Two caveats belong to the operator rather than to the code. Ownership is
//! compared against the user running this check, which is not necessarily the
//! user the service runs as. And a project on a read-only mount satisfies the
//! immutability rule whatever its modes say, which this mirrors.

use std::{
    fs::{self, Metadata},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use serde::Serialize;
use serde_norway::Value as YamlValue;

/// How a bundle names a secret the file provider resolves.
const SECRET_REFERENCE_PREFIX: &str = "secret:file/";

/// An optional paired Mint configuration inside a deployment project.
const MINT_CONFIG_FILE: &str = "mint/mint.yaml";

/// The example caller's own signing key, which `mint token --key` reads under
/// the same owner-only rule as Mint's. Named rather than discovered: this is
/// the filename `evidencectl keygen signing` writes.
const CALLER_SIGNING_KEY: &str = "caller/signing-ed25519-private-jwk";

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Deployment project directory containing runtime.yaml and bundle/.
    #[arg(long)]
    pub project: PathBuf,

    /// Emit one machine-readable JSON report on standard output.
    #[arg(long)]
    pub json: bool,
}

/// One artifact this walk refuses, and why.
#[derive(Debug, Serialize)]
struct Finding {
    path: String,
    problem: String,
}

/// One group of artifacts governed by a single runtime rule.
#[derive(Debug, Serialize)]
struct Check {
    name: &'static str,
    passed: bool,
    inspected: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    checks: Vec<Check>,
    passed: bool,
    /// Artifacts this walk looked at, summed. A reader mistakes the check
    /// count for coverage otherwise: six checks say nothing about whether the
    /// bundle beneath them held four files or four hundred.
    inspected: usize,
}

pub fn run(args: DoctorArgs) -> Result<ExitCode> {
    let project = args.project.as_path();
    let runtime_path = project.join("runtime.yaml");
    if !runtime_path.is_file() {
        bail!(
            "runtime configuration not found at {} (expected a deployment project directory containing runtime.yaml)",
            runtime_path.display()
        );
    }
    let runtime = read_yaml(&runtime_path)?;
    let bundle_directory = resolve_bundle_directory(&runtime, &runtime_path, project)?;
    let bundle_config_path = bundle_directory.join("evidence.yaml");
    let bundle = read_yaml(&bundle_config_path)?;

    let mut checks = vec![
        check_runtime_file(project, &runtime_path),
        check_bundle(project, &bundle_directory),
    ];
    checks.extend(check_secrets(project, &runtime, &runtime_path, &bundle));
    checks.push(check_audit(project, &runtime, &runtime_path));
    checks.extend(check_mint(project)?);

    let passed = checks.iter().all(|check| check.passed);
    let inspected = checks.iter().map(|check| check.inspected).sum();
    let report = DoctorReport {
        checks,
        passed,
        inspected,
    };

    if args.json {
        print_diagnostics(&report, true);
        let encoded = serde_json::to_string(&report).context("failed to encode the JSON report")?;
        println!("{encoded}");
    } else {
        print_diagnostics(&report, false);
    }

    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// The runtime file itself: a deployment input the service refuses to start
/// from if it could write to it.
fn check_runtime_file(project: &Path, runtime_path: &Path) -> Check {
    let mut run = CheckRun::new("runtime file", project);
    let read_only_mount = mount_is_read_only(runtime_path);
    require_immutable(&mut run, runtime_path, read_only_mount);
    run.finish()
}

/// The bundle directory and everything beneath it, under the same rule.
fn check_bundle(project: &Path, bundle_directory: &Path) -> Check {
    let mut run = CheckRun::new("bundle", project);
    let read_only_mount = mount_is_read_only(bundle_directory);
    walk_immutable(&mut run, bundle_directory, read_only_mount);
    run.finish()
}

/// The secret root and every secret the bundle names.
///
/// The secrets are discovered from the bundle's own `secret:file/` references
/// rather than by listing the secret directory. The difference matters: the
/// public half of a signing key is written into that directory at mode 0644 by
/// design, and a directory walk would report a project the runtime accepts.
fn check_secrets(
    project: &Path,
    runtime: &YamlValue,
    runtime_path: &Path,
    bundle: &YamlValue,
) -> Vec<Check> {
    let references = secret_references(bundle);
    let root = runtime
        .get("secretProviders")
        .and_then(|providers| providers.get("file"))
        .and_then(|file| file.get("root"))
        .and_then(YamlValue::as_str);

    let Some(root) = root else {
        if references.is_empty() {
            return Vec::new();
        }
        let mut run = CheckRun::new("secrets", project);
        run.refuse(
            runtime_path,
            format!(
                "names no file secret provider, and the bundle references {} secret(s) through one",
                references.len()
            ),
        );
        return vec![run.finish()];
    };
    let root = resolve_against(runtime_path, project, Path::new(root));

    let mut root_run = CheckRun::new("secret root", project);
    if let Some(metadata) = root_run.stat(&root) {
        if metadata.file_type().is_symlink() {
            root_run.refuse(&root, "is a symbolic link; the runtime requires a directory reached without traversing one".to_owned());
        } else if !metadata.is_dir() {
            root_run.refuse(&root, "is not a directory".to_owned());
        } else if metadata.permissions().mode() & 0o077 != 0 {
            root_run.refuse(&root, group_or_other(&metadata, 0o700));
        }
    }

    let mut secret_run = CheckRun::new("secrets", project);
    for name in references {
        let path = root.join(&name);
        let Some(metadata) = secret_run.stat(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            secret_run.refuse(
                &path,
                "is not a regular file reached without traversing a symbolic link".to_owned(),
            );
            continue;
        }
        // Secrets are the one artifact the runtime pins to an exact mode
        // rather than to a bound, so report the exact mode back.
        let mode = metadata.permissions().mode() & 0o7777;
        if mode != 0o600 {
            secret_run.refuse(
                &path,
                format!("has mode {mode:04o}; the runtime requires exactly 0600 (chmod 600)"),
            );
        }
        require_sole_owner(&mut secret_run, &path, &metadata);
    }

    vec![root_run.finish(), secret_run.finish()]
}

/// The audit chain and its lock companion, when they exist. Absence is not a
/// finding: the service creates both on first write.
fn check_audit(project: &Path, runtime: &YamlValue, runtime_path: &Path) -> Check {
    let mut run = CheckRun::new("audit", project);
    let Some(path) = runtime
        .get("auditStorage")
        .and_then(|storage| storage.get("path"))
        .and_then(YamlValue::as_str)
    else {
        return run.finish();
    };
    let path = resolve_against(runtime_path, project, Path::new(path));
    let lock = lock_companion(&path);
    for candidate in [path, lock] {
        if !candidate.exists() {
            continue;
        }
        let Some(metadata) = run.stat(&candidate) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            run.refuse(&candidate, "is not a regular file".to_owned());
            continue;
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            run.refuse(&candidate, group_or_other(&metadata, 0o600));
        }
        require_sole_owner(&mut run, &candidate, &metadata);
    }
    run.finish()
}

/// Mint's signing key and the example caller's, when the project carries a
/// paired Mint configuration. Both are read under the same owner-only rule.
fn check_mint(project: &Path) -> Result<Vec<Check>> {
    let config_path = project.join(MINT_CONFIG_FILE);
    if !config_path.is_file() {
        return Ok(Vec::new());
    }
    let config = read_yaml(&config_path)?;

    let mut run = CheckRun::new("mint keys", project);
    if let Some(key) = config
        .get("signing")
        .and_then(|signing| signing.get("activeKeyFile"))
        .and_then(YamlValue::as_str)
    {
        let key = resolve_against(&config_path, project, Path::new(key));
        require_owner_only_file(&mut run, &key);
    }
    let caller_key = project.join(CALLER_SIGNING_KEY);
    if caller_key.exists() {
        require_owner_only_file(&mut run, &caller_key);
    }
    Ok(vec![run.finish()])
}

/// One check under construction: the artifacts it looked at, and the reasons it
/// refused any of them.
struct CheckRun<'a> {
    name: &'static str,
    project: &'a Path,
    inspected: usize,
    findings: Vec<Finding>,
}

impl<'a> CheckRun<'a> {
    fn new(name: &'static str, project: &'a Path) -> Self {
        Self {
            name,
            project,
            inspected: 0,
            findings: Vec::new(),
        }
    }

    /// Read one artifact's own metadata, counting it as inspected. Symbolic
    /// links are not followed: every rule here is about the named entry.
    fn stat(&mut self, path: &Path) -> Option<Metadata> {
        self.inspected += 1;
        match fs::symlink_metadata(path) {
            Ok(metadata) => Some(metadata),
            Err(error) => {
                self.refuse(path, format!("cannot be read: {error}"));
                None
            }
        }
    }

    fn refuse(&mut self, path: &Path, problem: String) {
        self.findings.push(Finding {
            path: self.display(path),
            problem,
        });
    }

    /// Project-relative where possible, so a report reads as a list of things
    /// to fix rather than a column of temporary directory prefixes.
    fn display(&self, path: &Path) -> String {
        path.strip_prefix(self.project)
            .unwrap_or(path)
            .display()
            .to_string()
    }

    fn finish(self) -> Check {
        Check {
            name: self.name,
            passed: self.findings.is_empty(),
            inspected: self.inspected,
            findings: self.findings,
        }
    }
}

/// No write bits for anyone: what the runtime requires of a deployment input.
fn require_immutable(run: &mut CheckRun, path: &Path, read_only_mount: bool) {
    let Some(metadata) = run.stat(path) else {
        return;
    };
    refuse_unless_immutable(run, path, &metadata, read_only_mount);
}

/// The same rule over a directory tree, entry by entry.
fn walk_immutable(run: &mut CheckRun, path: &Path, read_only_mount: bool) {
    let Some(metadata) = run.stat(path) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        run.refuse(
            path,
            "is a symbolic link; the runtime refuses one anywhere in a bundle".to_owned(),
        );
        return;
    }
    refuse_unless_immutable(run, path, &metadata, read_only_mount);
    if !metadata.is_dir() {
        return;
    }
    match fs::read_dir(path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => walk_immutable(run, &entry.path(), read_only_mount),
                    Err(error) => run.refuse(path, format!("cannot be listed: {error}")),
                }
            }
        }
        Err(error) => run.refuse(path, format!("cannot be listed: {error}")),
    }
}

fn refuse_unless_immutable(
    run: &mut CheckRun,
    path: &Path,
    metadata: &Metadata,
    read_only_mount: bool,
) {
    let mode = metadata.permissions().mode() & 0o7777;
    if !read_only_mount && mode & 0o222 != 0 {
        run.refuse(
            path,
            format!("has mode {mode:04o}; the runtime requires no write bits (chmod a-w)"),
        );
    }
}

/// A regular file no one but its owner can reach: what Mint requires of a
/// private key file.
fn require_owner_only_file(run: &mut CheckRun, path: &Path) {
    let Some(metadata) = run.stat(path) else {
        return;
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        run.refuse(
            path,
            "is not a regular file reached without traversing a symbolic link".to_owned(),
        );
        return;
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        run.refuse(path, group_or_other(&metadata, 0o600));
    }
    require_sole_owner(run, path, &metadata);
}

/// Owned by this user and reachable under one name only. A second hard link is
/// a second name for the same bytes, which survives a permission change on the
/// first.
fn require_sole_owner(run: &mut CheckRun, path: &Path, metadata: &Metadata) {
    let euid = rustix::process::geteuid().as_raw();
    if metadata.uid() != euid {
        run.refuse(
            path,
            format!(
                "is owned by uid {}, not by the user running this check (uid {euid}); the runtime requires the user it runs as",
                metadata.uid()
            ),
        );
    }
    if metadata.nlink() != 1 {
        run.refuse(
            path,
            format!(
                "has {} hard links; the runtime requires exactly one",
                metadata.nlink()
            ),
        );
    }
}

fn group_or_other(metadata: &Metadata, required: u32) -> String {
    let mode = metadata.permissions().mode() & 0o7777;
    format!(
        "has mode {mode:04o}; the runtime requires no group or other access (chmod {required:o})"
    )
}

/// The audit sink's lock companion, `<audit file>.lock`.
fn lock_companion(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

/// Whether the filesystem carrying `path` is mounted read-only, in which case
/// the runtime accepts write bits it would otherwise refuse. An unreadable
/// mount is treated as writable, which reports rather than hides.
fn mount_is_read_only(path: &Path) -> bool {
    rustix::fs::statvfs(path).is_ok_and(|status| {
        status
            .f_flag
            .contains(rustix::fs::StatVfsMountFlags::RDONLY)
    })
}

/// Resolve a configured path: absolute as written, relative against the
/// configuration file's own directory.
fn resolve_against(config_path: &Path, project: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_path.parent().unwrap_or(project).join(path)
    }
}

/// Resolve the bundle directory a project's `runtime.yaml` names, on the same
/// terms `evidencectl fixtures run` does.
fn resolve_bundle_directory(
    runtime: &YamlValue,
    runtime_path: &Path,
    project: &Path,
) -> Result<PathBuf> {
    match runtime.get("bundleDirectory") {
        Some(value) => {
            let value = value.as_str().ok_or_else(|| {
                anyhow!(
                    "bundleDirectory in {} is not a string",
                    runtime_path.display()
                )
            })?;
            Ok(resolve_against(runtime_path, project, Path::new(value)))
        }
        None => Ok(project.join("bundle")),
    }
}

/// Every `secret:file/<name>` a bundle names, wherever in the document it sits.
///
/// This is discovery, not validation: the reference is found by its own prefix
/// rather than by the field carrying it, so a secret a future field names is
/// checked without this walk learning that field. `evidence check` is left to
/// reject a bundle that is otherwise malformed.
fn secret_references(bundle: &YamlValue) -> Vec<String> {
    let mut names = Vec::new();
    collect_secret_references(bundle, &mut names);
    names
}

fn collect_secret_references(value: &YamlValue, names: &mut Vec<String>) {
    match value {
        YamlValue::String(text) => {
            if let Some(name) = text.strip_prefix(SECRET_REFERENCE_PREFIX) {
                let name = name.to_owned();
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        YamlValue::Sequence(items) => {
            for item in items {
                collect_secret_references(item, names);
            }
        }
        YamlValue::Mapping(entries) => {
            for (_, entry) in entries {
                collect_secret_references(entry, names);
            }
        }
        _ => {}
    }
}

fn read_yaml(path: &Path) -> Result<YamlValue> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_norway::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

/// Print one line per check, every finding beneath it, and a summary line.
///
/// In JSON mode this goes to stderr, keeping stdout reserved for the single
/// JSON document; in human mode it is the entire report and goes to stdout.
/// Findings are never elided: a walk that reports some of what is broken sends
/// an operator back for a second restart, which is what this exists to avoid.
fn print_diagnostics(report: &DoctorReport, to_stderr: bool) {
    let mut lines = Vec::new();
    for check in &report.checks {
        let status = if check.passed { "PASS" } else { "FAIL" };
        lines.push(format!(
            "{status}: {} ({} inspected)",
            check.name, check.inspected
        ));
        for finding in &check.findings {
            lines.push(format!("    {}: {}", finding.path, finding.problem));
        }
    }
    let passed = report.checks.iter().filter(|check| check.passed).count();
    let failed = report.checks.len() - passed;
    lines.push(format!(
        "{passed} passed, {failed} failed ({} artifacts inspected)",
        report.inspected
    ));

    for line in lines {
        if to_stderr {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
}
