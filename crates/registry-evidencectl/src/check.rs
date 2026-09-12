//! Offline inspection of editable Evidence projects and explicit targets.
//!
//! These commands are adapters around the owning authoring compiler and the
//! runtime's bundle-only validator. They never execute a fixture, resolve a
//! secret, inspect a target-host path, or contact a dependency.

use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read as _},
    os::unix::{
        ffi::{OsStrExt as _, OsStringExt as _},
        fs::{symlink, DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
};

use anyhow::{bail, Context as _, Result};
use jsonschema::{Draft, JSONSchema};
use registry_evidence_authoring::{parse_project_marker, PROJECT_MARKER_FILE};
use serde_json::{json, Value};

use crate::{authoring, build, evidence_binary};

const RUNTIME_SCHEMA: &str =
    include_str!("../../../products/evidence/contracts/runtime.schema.yaml");

#[derive(Debug)]
pub(crate) struct DeniedFindings(pub Vec<Value>);

impl std::fmt::Display for DeniedFindings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the Evidence authoring findings were denied")
    }
}

impl std::error::Error for DeniedFindings {}

/// Validate an editable project, optionally joined to one explicit target.
///
/// A project-only success proves authoring closure under the local compiler
/// profile. Only a supplied target can produce a deployment-closure claim.
pub(crate) fn check(
    project: &Path,
    target: Option<&Path>,
    production: bool,
    deny_findings: bool,
) -> Result<Value> {
    Ok(check_and_capture_target(project, target, production, deny_findings)?.report)
}

struct CheckOutcome {
    report: Value,
    project_snapshot: ProjectSnapshot,
    target_documents: Option<build::TargetDocuments>,
}

fn check_and_capture_target(
    project: &Path,
    target: Option<&Path>,
    production: bool,
    deny_findings: bool,
) -> Result<CheckOutcome> {
    if production && target.is_none() {
        return Err(DeniedFindings(vec![diagnostic(
            "error",
            "evidence.target.required",
            "command_arguments",
            "--target",
            "--production requires an explicit Evidence deployment target",
            "Pass --target TARGET naming production or evidence-grade governance.",
        )])
        .into());
    }

    let project_snapshot = capture_project(project).map_err(|error| {
        if is_operational(&error) {
            error
        } else {
            unreadable_project(error, "check")
        }
    })?;
    let captured_project = project_snapshot.root();
    let mut findings = project_identity_findings(captured_project)?;
    let inventory = match inspect_project(captured_project) {
        Ok(inventory) => Some(inventory),
        Err(error) => {
            if is_operational(&error) {
                return Err(error);
            }
            let path = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<InspectionDiagnostic>())
                .map(|diagnostic| diagnostic.path.as_str())
                .unwrap_or(".");
            return Err(DeniedFindings(vec![diagnostic(
                "error",
                "evidence.authoring.unreadable",
                "authoring_project",
                path,
                "the authored project contains an unreadable or malformed artifact",
                "Correct the named project artifact, then run evidencectl check again.",
            )])
            .into());
        }
    };
    if inventory
        .as_ref()
        .is_some_and(|inventory| inventory.questions.is_empty())
    {
        findings.push(diagnostic(
            "finding",
            "evidence.question.missing",
            "authoring_project",
            "questions",
            "the project has no authored questions",
            "Add at least one questions/<id>.yaml document and its declared assets.",
        ));
    }
    if let Some(inventory) = inventory.as_ref() {
        match declared_asset_findings(captured_project, inventory) {
            Ok(asset_findings) => findings.extend(asset_findings),
            Err(error) if is_operational(&error) => return Err(error),
            Err(error) => return Err(compiler_refusal(error, "authoring_project")),
        }
        if !inventory.questions.is_empty() {
            if let Err(error) = authoring::validate_offline_local_access(captured_project) {
                return Err(classify_compiler_error(error, "authoring_project"));
            }
        } else if inventory.local_access["policies"]
            .as_array()
            .is_some_and(|policies| !policies.is_empty())
        {
            findings.push(diagnostic(
                "finding",
                "evidence.access.questions-missing",
                "local_access",
                "access/policies",
                "local access policies cannot be resolved until the project has questions",
                "Add the questions named by each local access policy.",
            ));
        }
    }

    let mut target_documents = None;
    let mut assurance_profile = None;
    let mut bundle_revision = None;
    if let Some(target) = target {
        match build::read_target_documents(target) {
            Ok(documents) => {
                assurance_profile = documents
                    .governed_bundle
                    .get("assuranceProfile")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if let Err(error) = validate_runtime_structure(&documents.runtime) {
                    return Err(DeniedFindings(vec![target_finding(target, error)]).into());
                }
                target_documents = Some(documents);
            }
            Err(error) => {
                if is_operational(&error) {
                    return Err(error);
                }
                return Err(DeniedFindings(vec![target_finding(target, error)]).into());
            }
        }
        if production && assurance_profile.as_deref() == Some("local") {
            findings.push(diagnostic(
                "error",
                "evidence.target.production-profile-required",
                "deployment_target",
                "governance.yaml:/assuranceProfile",
                "--production refuses a target whose assuranceProfile is local",
                "Select an explicit production or evidence-grade target; the command never upgrades a target profile.",
            ));
        }
    }
    if findings.is_empty() {
        let target_bound_sources = match authoring::target_bound_sources(captured_project) {
            Ok(sources) => sources,
            Err(error) => return Err(classify_compiler_error(error, "authoring_project")),
        };
        if target_documents.is_none() {
            findings.extend(target_bound_sources.into_iter().map(|source| {
                diagnostic(
                    "finding",
                    "evidence.target.source-connection-required",
                    "authored_source",
                    &format!("sources/{}.yaml:/connection", source.source_id),
                    "the source connection can be resolved only against an explicit deployment target",
                    "Pass --target TARGET naming governance that declares the source connection.",
                )
            }));
        }
        if findings.is_empty() {
            let checked = match target_documents.as_ref() {
                Some(documents) => check_with_target(captured_project, project, documents),
                None => check_project_only(captured_project, project),
            };
            match checked {
                Ok(checked) => {
                    bundle_revision = Some(checked.bundle_revision);
                }
                Err(error) => {
                    return Err(classify_compiler_error(
                        error,
                        if target.is_some() {
                            "deployment_target"
                        } else {
                            "authoring_project"
                        },
                    ));
                }
            }
        }
    }

    let complete = findings.is_empty();
    let report = json!({
        "ok": true,
        "command": "check",
        "project": project,
        "target": target,
        "status": if complete { "complete" } else { "incomplete" },
        "proof": if complete && target.is_some() { "deployment-closure" } else { "authoring" },
        "assuranceProfile": assurance_profile,
        "bundleRevision": bundle_revision,
        "fixtureProof": false,
        "findings": findings,
        "offline": true,
        "networkAccess": false,
        "fixtureExecution": false,
        "secretResolution": false,
        "targetHostPathChecks": false,
    });
    let findings = report["findings"].as_array().cloned().unwrap_or_default();
    if (production || deny_findings) && !findings.is_empty() {
        return Err(DeniedFindings(findings).into());
    }
    Ok(CheckOutcome {
        report,
        project_snapshot,
        target_documents,
    })
}

/// Explain authored inventory and, when supplied, target-owned governance.
pub(crate) fn explain(project: &Path, target: Option<&Path>) -> Result<Value> {
    let checked = check_and_capture_target(project, target, false, false)?;
    explain_captured(project, target, checked)
}

fn explain_captured(project: &Path, target: Option<&Path>, checked: CheckOutcome) -> Result<Value> {
    let validation = checked.report;
    let captured_project = checked.project_snapshot.root();
    let mut inventory = inspect_project(captured_project).map_err(|error| {
        if is_operational(&error) {
            error
        } else {
            let path = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<InspectionDiagnostic>())
                .map(|diagnostic| diagnostic.path.as_str())
                .unwrap_or(".");
            DeniedFindings(vec![diagnostic(
                "error",
                "evidence.authoring.unreadable",
                "authoring_project",
                path,
                "the authored project contains an unreadable or malformed artifact",
                "Correct the named project artifact, then run evidencectl explain again.",
            )])
            .into()
        }
    })?;
    let policies = if inventory.questions.is_empty() {
        if inventory.local_access["policies"]
            .as_array()
            .is_some_and(|policies| !policies.is_empty())
        {
            return Err(DeniedFindings(vec![diagnostic(
                "error",
                "evidence.access.questions-missing",
                "local_access",
                "access/policies",
                "local access policies cannot be resolved until the project has questions",
                "Add the questions named by each local access policy.",
            )])
            .into());
        }
        Vec::new()
    } else {
        authoring::validate_offline_local_access(captured_project)
            .map_err(|error| classify_compiler_error(error, "authoring_project"))?
    };
    inventory.local_access = json!({
        "mode": if policies.is_empty() { "implicit-local-caller" } else { "explicit-policies" },
        "policies": policies.iter().map(|policy| json!({
            "id": policy.id,
            "requesterTag": policy.requester_tag,
            "questions": policy.questions,
        })).collect::<Vec<_>>(),
        "clients": inventory.local_access["clients"],
    });
    let target_governance = checked
        .target_documents
        .as_ref()
        .map(|documents| explain_governance(&documents.governed_bundle));
    Ok(json!({
        "ok": true,
        "command": "explain",
        "project": project,
        "target": target,
        "status": validation["status"],
        "proof": validation["proof"],
        "bundleRevision": validation["bundleRevision"],
        "findings": validation["findings"],
        "questions": inventory.questions,
        "sources": inventory.sources,
        "selectors": inventory.selectors,
        "derivations": inventory.derivations,
        "localAccess": inventory.local_access,
        "targetGovernance": target_governance,
        "offline": true,
        "networkAccess": false,
        "secretResolution": false,
    }))
}

/// Render the semantic parts of check and explain reports for the CLI's human
/// output path. JSON rendering remains owned by the common CLI boundary.
pub(crate) fn render_human(report: &Value, out: &mut dyn io::Write) -> io::Result<()> {
    match report["command"].as_str() {
        Some("check") => {
            writeln!(
                out,
                "Evidence project check: {}",
                report["status"].as_str().unwrap_or("unknown")
            )?;
            writeln!(
                out,
                "Project: {}",
                report["project"].as_str().unwrap_or(".")
            )?;
            writeln!(
                out,
                "Proof: {}",
                report["proof"].as_str().unwrap_or("authoring")
            )?;
            if let Some(target) = report["target"].as_str() {
                writeln!(out, "Target: {target}")?;
            }
            if let Some(profile) = report["assuranceProfile"].as_str() {
                writeln!(out, "Assurance profile: {profile}")?;
            }
            render_findings(report, out)?;
        }
        Some("explain") => {
            writeln!(out, "Evidence project explanation")?;
            writeln!(
                out,
                "Project: {}",
                report["project"].as_str().unwrap_or(".")
            )?;
            writeln!(
                out,
                "Status: {}",
                report["status"].as_str().unwrap_or("unknown")
            )?;
            writeln!(
                out,
                "Proof: {}",
                report["proof"].as_str().unwrap_or("authoring")
            )?;
            render_findings(report, out)?;
            writeln!(out, "Questions:")?;
            for item in report["questions"].as_array().into_iter().flatten() {
                writeln!(out, "  {}", item["id"].as_str().unwrap_or("unknown"))?;
                write_optional(out, "source", &item["source"])?;
                write_list(out, "selectors", &item["selectors"])?;
                write_list(out, "selector profiles", &item["selectorProfiles"])?;
                write_optional(out, "derivation", &item["derivation"])?;
                write_list(out, "answers", &item["answers"])?;
                write_list(out, "response formats", &item["responseFormats"])?;
            }
            writeln!(out, "Sources:")?;
            for item in report["sources"].as_array().into_iter().flatten() {
                writeln!(out, "  {}", item["id"].as_str().unwrap_or("unknown"))?;
                write_optional(out, "transport", &item["transport"])?;
                write_optional(out, "posture", &item["posture"])?;
                write_optional(out, "connection", &item["connectionRef"])?;
                write_list(out, "references", &item["references"])?;
            }
            writeln!(out, "Selectors:")?;
            for item in report["selectors"].as_array().into_iter().flatten() {
                writeln!(out, "  {}", item["id"].as_str().unwrap_or("unknown"))?;
                write_list(out, "fields", &item["fields"])?;
            }
            writeln!(out, "Derivations:")?;
            for item in report["derivations"].as_array().into_iter().flatten() {
                writeln!(out, "  {}", item["id"].as_str().unwrap_or("unknown"))?;
                write_optional(out, "path", &item["path"])?;
            }
            writeln!(out, "Local access:")?;
            write_optional(out, "mode", &report["localAccess"]["mode"])?;
            for policy in report["localAccess"]["policies"]
                .as_array()
                .into_iter()
                .flatten()
            {
                writeln!(
                    out,
                    "  policy {}",
                    policy["id"].as_str().unwrap_or("unknown")
                )?;
                write_list(out, "questions", &policy["questions"])?;
            }
            for client in report["localAccess"]["clients"]
                .as_array()
                .into_iter()
                .flatten()
            {
                writeln!(
                    out,
                    "  client {}",
                    client["id"].as_str().unwrap_or("unknown")
                )?;
            }
            if let Some(governance) = report
                .get("targetGovernance")
                .filter(|value| !value.is_null())
            {
                writeln!(
                    out,
                    "Target assurance profile: {}",
                    governance["assuranceProfile"].as_str().unwrap_or("unknown")
                )?;
                write_optional(out, "service", &governance["serviceId"])?;
                write_optional(out, "issuer", &governance["issuer"])?;
                write_list(out, "authority profiles", &governance["authorityProfiles"])?;
                write_list(out, "source connections", &governance["sourceConnections"])?;
                write_list(out, "response formats", &governance["responseFormats"])?;
                write_optional(out, "active public key", &governance["activePublicKeyFile"])?;
            }
        }
        _ => writeln!(out, "Evidence command completed.")?,
    }
    Ok(())
}

fn render_findings(report: &Value, out: &mut dyn io::Write) -> io::Result<()> {
    for finding in report["findings"].as_array().into_iter().flatten() {
        writeln!(
            out,
            "{}[{}] {} {}: {}",
            finding["severity"].as_str().unwrap_or("finding"),
            finding["code"].as_str().unwrap_or("evidence.finding"),
            finding["artifact"].as_str().unwrap_or("authoring_project"),
            finding["path"].as_str().unwrap_or("."),
            finding["message"].as_str().unwrap_or("review required"),
        )?;
        if let Some(action) = finding["suggestedAction"].as_str() {
            writeln!(out, "  next: {action}")?;
        }
    }
    Ok(())
}

fn write_optional(out: &mut dyn io::Write, label: &str, value: &Value) -> io::Result<()> {
    if let Some(value) = value.as_str() {
        writeln!(out, "    {label}: {value}")?;
    }
    Ok(())
}

fn write_list(out: &mut dyn io::Write, label: &str, value: &Value) -> io::Result<()> {
    let values = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    writeln!(
        out,
        "    {label}: {}",
        if values.is_empty() {
            "none".to_owned()
        } else {
            values.join(", ")
        }
    )
}

struct CheckedBundle {
    bundle_revision: String,
}

fn check_project_only(project: &Path, display_project: &Path) -> Result<CheckedBundle> {
    let evidence_bin = evidence_binary::resolve_matching(None)?;
    let staging = tempfile::Builder::new()
        .prefix("evidencectl-check-")
        .tempdir()
        .context("creating private authoring-check staging")?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))
        .context("setting private authoring-check staging permissions")?;
    let compiled = authoring::compile_check_project(project, staging.path(), &evidence_bin)?;
    let report =
        build::check_compiled_bundle(&evidence_bin, &compiled.bundle_path, display_project)?;
    Ok(CheckedBundle {
        bundle_revision: report.bundle_revision,
    })
}

fn check_with_target(
    project: &Path,
    display_project: &Path,
    documents: &build::TargetDocuments,
) -> Result<CheckedBundle> {
    let evidence_bin = evidence_binary::resolve_matching(None)?;
    let staging = tempfile::Builder::new()
        .prefix("evidencectl-target-check-")
        .tempdir()
        .context("creating private target-check staging")?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))
        .context("setting private target-check staging permissions")?;
    let compiled = build::compile_with_target(project, documents, staging.path(), &evidence_bin)?;
    let report =
        build::check_compiled_bundle(&evidence_bin, &compiled.bundle_path, display_project)?;
    Ok(CheckedBundle {
        bundle_revision: report.bundle_revision,
    })
}

fn target_finding(target: &Path, error: anyhow::Error) -> Value {
    let runtime = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<RuntimeStructureDiagnostic>());
    let target_document = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<build::TargetDocumentDiagnostic>());
    let path = runtime
        .map(|diagnostic| diagnostic.path.clone())
        .or_else(|| target_document.map(|diagnostic| diagnostic.path.clone()))
        .unwrap_or_else(|| target.to_string_lossy().into_owned());
    let code = target_document
        .map(|diagnostic| diagnostic.code)
        .unwrap_or("evidence.target.incomplete");
    let message = runtime
        .map(|diagnostic| diagnostic.to_string())
        .or_else(|| target_document.map(|diagnostic| diagnostic.message.to_owned()))
        .unwrap_or_else(|| {
            "the deployment target does not match the closed offline validation contract".to_owned()
        });
    diagnostic(
        "error",
        code,
        "deployment_target",
        &path,
        message,
        "Correct the target governance, runtime structure, public keys, or source connections, then retry.",
    )
}

fn compiler_refusal(error: anyhow::Error, artifact: &str) -> anyhow::Error {
    let authored = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<authoring::AuthoredDiagnostic>());
    let path = authored
        .map(|diagnostic| diagnostic.path.clone())
        .unwrap_or_else(|| ".".to_owned());
    let code = authored
        .map(|diagnostic| diagnostic.code)
        .unwrap_or("evidence.offline-check.refused");
    let message = authored
        .map(|diagnostic| diagnostic.message.clone())
        .unwrap_or_else(|| "offline validation refused the authored configuration".to_owned());
    DeniedFindings(vec![diagnostic(
        "error",
        code,
        artifact,
        &path,
        message,
        "Correct the named authored or target field, then rerun evidencectl check.",
    )])
    .into()
}

fn classify_compiler_error(error: anyhow::Error, artifact: &str) -> anyhow::Error {
    if is_operational(&error) {
        error
    } else {
        compiler_refusal(error, artifact)
    }
}

fn is_operational(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<io::Error>().is_some())
}

fn validate_runtime_structure(bytes: &[u8]) -> Result<()> {
    let runtime: Value =
        serde_norway::from_slice(bytes).map_err(|_| RuntimeStructureDiagnostic {
            path: "runtime.yaml".to_owned(),
            rules: vec!["the document is not readable YAML or JSON".to_owned()],
        })?;
    let schema: Value = serde_norway::from_str(RUNTIME_SCHEMA)
        .context("the embedded Evidence runtime schema is invalid")?;
    let validator = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .map_err(|_| anyhow::anyhow!("the embedded Evidence runtime schema could not compile"))?;
    if let Err(errors) = validator.validate(&runtime) {
        let mut messages = errors
            .take(8)
            .map(|error| {
                format!(
                    "{} violates rule {}",
                    error.instance_path, error.schema_path
                )
            })
            .collect::<Vec<_>>();
        messages.sort();
        let path = messages
            .first()
            .and_then(|message| message.split_once(" violates rule ").map(|(path, _)| path))
            .unwrap_or(".");
        return Err(RuntimeStructureDiagnostic {
            path: format!("runtime.yaml:{path}"),
            rules: messages,
        }
        .into());
    }
    Ok(())
}

#[derive(Debug)]
struct RuntimeStructureDiagnostic {
    path: String,
    rules: Vec<String>,
}

impl std::fmt::Display for RuntimeStructureDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "deployment runtime does not satisfy Version 1: {}",
            self.rules.join("; ")
        )
    }
}

impl std::error::Error for RuntimeStructureDiagnostic {}

struct ProjectSnapshot {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    directories: Vec<PathBuf>,
}

impl ProjectSnapshot {
    fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for ProjectSnapshot {
    fn drop(&mut self) {
        for directory in &self.directories {
            let _ = fs::set_permissions(directory, fs::Permissions::from_mode(0o700));
        }
    }
}

fn capture_project(project: &Path) -> Result<ProjectSnapshot> {
    let metadata = fs::symlink_metadata(project)
        .with_context(|| format!("inspecting project root {}", project.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("project root must be a plain directory");
    }
    let temporary_root = std::env::temp_dir()
        .canonicalize()
        .context("resolving the private project snapshot parent")?;
    capture_project_in(project, &temporary_root)
}

fn capture_project_in(project: &Path, temporary_root: &Path) -> Result<ProjectSnapshot> {
    use rustix::fs::{Mode, OFlags};

    let project_descriptor = rustix::fs::open(
        project,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(io::Error::from)
    .context("opening the authoring project without following links")?;
    let temporary = tempfile::Builder::new()
        .prefix("evidencectl-project-snapshot-")
        .tempdir_in(temporary_root)
        .context("creating private project snapshot")?;
    let root = temporary.path().join("project");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .context("creating private project snapshot root")?;
    let mut directories = vec![root.clone()];

    for (relative, maximum) in [
        (PROJECT_MARKER_FILE, authoring::MAX_PROJECT_MARKER_BYTES),
        (authoring::OPENAPI_FILE, authoring::MAX_OPENAPI_BYTES),
    ] {
        capture_snapshot_entry_at(
            &project_descriptor,
            &root,
            OsStr::new(relative),
            Path::new(relative),
            maximum,
            &mut directories,
        )?;
    }
    for (relative, maximum) in [
        ("questions", authoring::MAX_QUESTION_BYTES),
        ("sources", authoring::MAX_SOURCE_ARTIFACT_BYTES),
        ("selectors", authoring::MAX_SOURCE_ARTIFACT_BYTES),
        ("derivations", authoring::MAX_DERIVATION_BYTES),
        ("schemas", authoring::MAX_SOURCE_ARTIFACT_BYTES),
        ("fixtures", authoring::MAX_SOURCE_ARTIFACT_BYTES),
        ("adapters", authoring::MAX_SOURCE_ARTIFACT_BYTES),
        ("queries", authoring::MAX_SOURCE_ARTIFACT_BYTES),
        ("codelists", authoring::MAX_SOURCE_ARTIFACT_BYTES),
    ] {
        capture_flat_directory_at(
            &project_descriptor,
            &root,
            OsStr::new(relative),
            Path::new(relative),
            maximum,
            &mut directories,
        )?;
    }
    capture_access(&project_descriptor, &root, &mut directories)?;

    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    let snapshot = ProjectSnapshot {
        _temporary: temporary,
        root,
        directories,
    };
    for directory in &snapshot.directories {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o500)).with_context(|| {
            format!("sealing project snapshot directory {}", directory.display())
        })?;
    }
    Ok(snapshot)
}

fn capture_access(
    project: &rustix::fd::OwnedFd,
    snapshot: &Path,
    directories: &mut Vec<PathBuf>,
) -> Result<()> {
    let relative = Path::new("access");
    let Some(access) = open_snapshot_directory(project, OsStr::new("access"), relative)? else {
        return Ok(());
    };
    let destination = snapshot.join(relative);
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    directories.push(destination);
    capture_flat_directory_at(
        &access,
        snapshot,
        OsStr::new("policies"),
        Path::new("access/policies"),
        authoring::MAX_ACCESS_POLICY_BYTES,
        directories,
    )?;
    capture_flat_directory_at(
        &access,
        snapshot,
        OsStr::new("clients"),
        Path::new("access/clients"),
        authoring::MAX_SOURCE_ARTIFACT_BYTES,
        directories,
    )
}

fn capture_flat_directory_at(
    parent: &rustix::fd::OwnedFd,
    snapshot: &Path,
    name: &OsStr,
    relative: &Path,
    maximum: u64,
    directories: &mut Vec<PathBuf>,
) -> Result<()> {
    let Some(directory) = open_snapshot_directory(parent, name, relative)? else {
        return Ok(());
    };
    let destination = snapshot.join(relative);
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    directories.push(destination);
    capture_directory_contents(&directory, snapshot, relative, maximum, directories)
}

fn capture_directory_contents(
    directory: &rustix::fd::OwnedFd,
    snapshot: &Path,
    relative: &Path,
    maximum: u64,
    directories: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut entries = rustix::fs::Dir::read_from(directory)
        .map_err(io::Error::from)?
        .map(|entry| {
            entry
                .map(|entry| OsString::from_vec(entry.file_name().to_bytes().to_vec()))
                .map_err(io::Error::from)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.retain(|name| name != "." && name != "..");
    entries.sort();
    for name in entries {
        let entry_relative = relative.join(&name);
        capture_snapshot_entry_at(
            directory,
            snapshot,
            &name,
            &entry_relative,
            maximum,
            directories,
        )?;
    }
    Ok(())
}

fn open_snapshot_directory(
    parent: &rustix::fd::OwnedFd,
    name: &OsStr,
    relative: &Path,
) -> Result<Option<rustix::fd::OwnedFd>> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    let metadata = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(io::Error::from(error)).context("inspecting project snapshot directory")
        }
    };
    if !FileType::from_raw_mode(metadata.st_mode).is_dir() {
        return Err(InspectionDiagnostic {
            path: relative.to_string_lossy().into_owned(),
        }
        .into());
    }

    match rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    ) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) => Err(snapshot_open_error(error, relative, "directory")),
    }
}

fn snapshot_open_error(
    error: rustix::io::Errno,
    relative: &Path,
    input_kind: &str,
) -> anyhow::Error {
    if snapshot_open_race(error) {
        InspectionDiagnostic {
            path: relative.to_string_lossy().into_owned(),
        }
        .into()
    } else {
        anyhow::Error::new(io::Error::from(error)).context(format!(
            "opening project snapshot {input_kind} {}",
            relative.display()
        ))
    }
}

fn snapshot_open_race(error: rustix::io::Errno) -> bool {
    matches!(
        error,
        rustix::io::Errno::NOENT | rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR
    )
}

fn capture_snapshot_entry_at(
    parent: &rustix::fd::OwnedFd,
    snapshot: &Path,
    name: &OsStr,
    relative: &Path,
    maximum: u64,
    directories: &mut Vec<PathBuf>,
) -> Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    let metadata = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => {
            return Err(io::Error::from(error)).context("inspecting project snapshot input")
        }
    };
    let destination = snapshot.join(relative);
    let file_type = FileType::from_raw_mode(metadata.st_mode);
    if file_type.is_symlink() {
        let target = rustix::fs::readlinkat(parent, name, Vec::new()).map_err(io::Error::from)?;
        symlink(OsStr::from_bytes(target.to_bytes()), &destination)?;
    } else if file_type.is_dir() {
        fs::DirBuilder::new().mode(0o700).create(&destination)?;
        directories.push(destination);
    } else if file_type.is_file() {
        let descriptor = match rustix::fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) => return Err(snapshot_open_error(error, relative, "input")),
        };
        let bytes = match read_bounded_descriptor(descriptor, maximum) {
            Ok(bytes) => bytes,
            Err(error) if is_operational(&error) => return Err(error),
            Err(_) => {
                return Err(InspectionDiagnostic {
                    path: relative.to_string_lossy().into_owned(),
                }
                .into())
            }
        };
        fs::write(&destination, bytes)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o400))?;
    } else {
        return Err(InspectionDiagnostic {
            path: relative.to_string_lossy().into_owned(),
        }
        .into());
    }
    Ok(())
}

fn project_identity_findings(project: &Path) -> Result<Vec<Value>> {
    let path = project.join(PROJECT_MARKER_FILE);
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(DeniedFindings(vec![diagnostic(
                "error",
                "evidence.project-marker.file-type",
                "authoring_project",
                PROJECT_MARKER_FILE,
                "the Evidence project marker must be a plain file",
                "Replace the marker with a plain Version 1 evidence-project.yaml file.",
            )])
            .into());
        }
    }
    match fs::read(&path) {
        Ok(bytes) => match parse_project_marker(&bytes) {
            Ok(_) => Ok(Vec::new()),
            Err(finding) => Err(DeniedFindings(vec![diagnostic(
                "error",
                finding.code,
                "authoring_project",
                &format!("{PROJECT_MARKER_FILE}:{}", finding.field),
                "the Evidence project marker does not match the closed Version 1 shape",
                "Correct the Evidence Version 1 project marker.",
            )])
            .into()),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(vec![diagnostic(
            "finding",
            "evidence.project-marker.missing",
            "authoring_project",
            PROJECT_MARKER_FILE,
            "the Evidence authoring project marker is missing",
            "Add the unchanged Version 1 evidence-project.yaml marker.",
        )]),
        Err(error) => Err(error).context("reading the Evidence authoring project marker"),
    }
}

struct ProjectInventory {
    questions: Vec<Value>,
    sources: Vec<Value>,
    selectors: Vec<Value>,
    derivations: Vec<Value>,
    local_access: Value,
}

#[derive(Debug)]
struct InspectionDiagnostic {
    path: String,
}

impl std::fmt::Display for InspectionDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} does not parse as an authored YAML document",
            self.path
        )
    }
}

impl std::error::Error for InspectionDiagnostic {}

fn unreadable_project(error: anyhow::Error, command: &str) -> anyhow::Error {
    let path = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<InspectionDiagnostic>())
        .map(|diagnostic| diagnostic.path.as_str())
        .unwrap_or(".");
    DeniedFindings(vec![diagnostic(
        "error",
        "evidence.authoring.unreadable",
        "authoring_project",
        path,
        "the authored project contains an unreadable or malformed artifact",
        &format!("Correct the named project artifact, then run evidencectl {command} again."),
    )])
    .into()
}

fn declared_asset_findings(project: &Path, inventory: &ProjectInventory) -> Result<Vec<Value>> {
    let source_ids = inventory
        .sources
        .iter()
        .filter_map(|source| source["id"].as_str())
        .collect::<BTreeSet<_>>();
    let selector_ids = inventory
        .selectors
        .iter()
        .filter_map(|selector| selector["id"].as_str())
        .collect::<BTreeSet<_>>();
    let derivation_ids = inventory
        .derivations
        .iter()
        .filter_map(|derivation| derivation["id"].as_str())
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();
    for path in regular_files(project, "sources", "yaml")? {
        let bytes = fs::read(&path)?;
        let source: Value = serde_norway::from_slice(&bytes)
            .with_context(|| format!("parsing {}", path.display()))?;
        let relative = path.strip_prefix(project).unwrap_or(&path).display();
        for pointer in [
            "/responseSchema",
            "/factSchema",
            "/extractScript",
            "/request/prepareScript",
            "/request/adapterParametersSchema",
            "/request/statement",
            "/batch/prepareScript",
            "/batch/extractScript",
            "/batch/responseSchema",
        ] {
            let Some(asset) = source.pointer(pointer).and_then(Value::as_str) else {
                continue;
            };
            if !authoring::valid_source_artifact_reference(asset) {
                return Err(authoring::AuthoredDiagnostic {
                    code: "source-artifact-reference",
                    path: format!("{relative}:{pointer}"),
                    message:
                        "source artifact references must stay in their project artifact directory"
                            .to_owned(),
                }
                .into());
            }
            let exists = plain_asset_exists(
                project,
                asset,
                "source-artifact-custody",
                &format!("{relative}:{pointer}"),
            )?;
            if !exists {
                findings.push(diagnostic(
                    "finding",
                    "evidence.source.asset-missing",
                    "authored_source",
                    &format!("{relative}:{pointer}"),
                    "the source names an artifact that is not present in this project",
                    "Add the declared project-relative source artifact or correct the reference.",
                ));
            }
        }
    }
    for path in regular_files(project, "questions", "yaml")? {
        let bytes = fs::read(&path)?;
        let question: Value = serde_norway::from_slice(&bytes)
            .with_context(|| format!("parsing {}", path.display()))?;
        let relative = path.strip_prefix(project).unwrap_or(&path).display();
        if question.get("governance").is_none() {
            findings.push(diagnostic(
                "finding",
                "evidence.question.governance-missing",
                "authored_question",
                &format!("{relative}:/governance"),
                "the question has no deployment governance",
                "Add stable requirement, evidence type, fixture, and disclosure-family governance.",
            ));
        }
        if let Some(source) = question.pointer("/source/ref").and_then(Value::as_str) {
            if !source_ids.contains(source) {
                findings.push(diagnostic(
                    "finding",
                    "evidence.question.source-missing",
                    "authored_question",
                    &format!("{relative}:/source/ref"),
                    "the question names a source that is not present in this project",
                    "Add the named sources/<id>.yaml artifact or correct the reference.",
                ));
            }
        }
        let subjects = question
            .get("subjects")
            .and_then(Value::as_array)
            .map(|values| values.iter().collect::<Vec<_>>())
            .or_else(|| question.get("subject").map(|subject| vec![subject]))
            .unwrap_or_default();
        for (index, subject) in subjects.into_iter().enumerate() {
            for selector in subject
                .get("profiles")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .chain(subject.get("profile").and_then(Value::as_str))
            {
                if !selector_ids.contains(selector) {
                    findings.push(diagnostic(
                        "finding",
                        "evidence.question.selector-missing",
                        "authored_question",
                        &format!("{relative}:/subjectProfiles/{index}"),
                        "the question names a selector profile that is not present in this project",
                        "Add the named selectors/<id>.yaml artifact or correct the reference.",
                    ));
                }
            }
        }
        if let Some(derivation) = question.get("derivation").and_then(Value::as_str) {
            if !authoring::valid_derivation_reference(derivation) {
                return Err(authoring::AuthoredDiagnostic {
                    code: "question-derivation-reference",
                    path: format!("{relative}:/derivation"),
                    message: "question derivation must stay in the project derivations directory"
                        .to_owned(),
                }
                .into());
            }
            let id = Path::new(derivation)
                .file_stem()
                .and_then(|value| value.to_str());
            let exists = plain_asset_exists(
                project,
                derivation,
                "question-derivation-custody",
                &format!("{relative}:/derivation"),
            )?;
            if !exists || id.is_none_or(|id| !derivation_ids.contains(id)) {
                findings.push(diagnostic(
                    "finding",
                    "evidence.question.derivation-missing",
                    "authored_question",
                    &format!("{relative}:/derivation"),
                    "the question's derivation artifact is missing",
                    "Add the named derivations/<id>.rhai artifact or correct the reference.",
                ));
            }
        }
        if let Some(fixture) = question
            .pointer("/governance/fixtures")
            .and_then(Value::as_str)
        {
            if !authoring::valid_fixture_reference(fixture) {
                return Err(authoring::AuthoredDiagnostic {
                    code: "question-fixture-reference",
                    path: format!("{relative}:/governance/fixtures"),
                    message: "question fixture must stay in the project fixtures directory"
                        .to_owned(),
                }
                .into());
            }
            let exists = plain_asset_exists(
                project,
                fixture,
                "question-fixture-custody",
                &format!("{relative}:/governance/fixtures"),
            )?;
            if !exists {
                findings.push(diagnostic(
                    "finding",
                    "evidence.question.fixture-missing",
                    "authored_question",
                    &format!("{relative}:/governance/fixtures"),
                    "the question's declared fixture artifact is missing",
                    "Add the named fixtures/<id>.yaml artifact or correct the reference.",
                ));
            }
        }
        for (index, answer) in question
            .get("answers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            if answer.get("id").is_none() {
                findings.push(diagnostic(
                    "finding",
                    "evidence.answer.stable-id-missing",
                    "authored_question",
                    &format!("{relative}:/answers/{index}/id"),
                    "the answer has no stable concept id",
                    "Add the stable concept identifier required for deployment authoring.",
                ));
            }
        }
    }
    Ok(findings)
}

fn plain_asset_exists(project: &Path, value: &str, code: &'static str, path: &str) -> Result<bool> {
    match authoring::plain_project_asset_exists(project, value) {
        Ok(exists) => Ok(exists),
        Err(error) if is_operational(&error) => Err(error),
        Err(_) => Err(authoring::AuthoredDiagnostic {
            code,
            path: path.to_owned(),
            message: "declared project artifacts must use plain in-project directories and files"
                .to_owned(),
        }
        .into()),
    }
}

fn inspect_project(project: &Path) -> Result<ProjectInventory> {
    let questions = yaml_inventory(project, "questions", |id, value| {
        let subjects = value
            .get("subjects")
            .and_then(Value::as_array)
            .map(|subjects| subjects.iter().collect::<Vec<_>>())
            .or_else(|| value.get("subject").map(|subject| vec![subject]))
            .unwrap_or_default();
        let selectors = subjects
            .iter()
            .filter_map(|subject| subject.get("selector").and_then(Value::as_str))
            .collect::<Vec<_>>();
        let selector_profiles = subjects
            .iter()
            .flat_map(|subject| {
                subject
                    .get("profiles")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .chain(subject.get("profile").and_then(Value::as_str))
            })
            .collect::<Vec<_>>();
        json!({
            "id": value.get("id").and_then(Value::as_str).unwrap_or(id),
            "source": value.pointer("/source/ref").and_then(Value::as_str),
            "selectors": selectors,
            "selectorProfiles": selector_profiles,
            "derivation": value.get("derivation").and_then(Value::as_str),
            "answers": value.get("answers").and_then(Value::as_array).map(|answers| answers.iter().filter_map(|answer| answer.get("concept").and_then(Value::as_str)).collect::<Vec<_>>()).unwrap_or_default(),
            "responseFormats": value.get("responseFormats").cloned().unwrap_or_else(|| json!(["signed-jws"])),
        })
    })?;
    let sources = yaml_inventory(project, "sources", |id, value| {
        let references = [
            "/connection",
            "/connectionRef",
            "/responseSchema",
            "/factSchema",
            "/extractScript",
            "/request/prepareScript",
            "/request/adapterParametersSchema",
            "/request/statement",
        ]
        .into_iter()
        .filter_map(|pointer| value.pointer(pointer).and_then(Value::as_str))
        .collect::<Vec<_>>();
        json!({
            "id": id,
            "transport": value.get("transport").and_then(Value::as_str),
            "connectionRef": value.get("connection").or_else(|| value.get("connectionRef")).and_then(Value::as_str),
            "posture": value.get("posture").and_then(Value::as_str),
            "references": references,
        })
    })?;
    let selectors = yaml_inventory(project, "selectors", |id, value| {
        let fields = value
            .get("fields")
            .and_then(Value::as_object)
            .map(|fields| fields.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        json!({"id": id, "fields": fields})
    })?;
    let derivations = file_inventory(project, "derivations", "rhai")?;
    let policies = yaml_inventory(
        project,
        "access/policies",
        |id, value| json!({"id": id, "questions": value.get("questions").cloned().unwrap_or_else(|| json!([]))}),
    )?;
    let clients = file_inventory(project, "access/clients", "yaml")?;
    Ok(ProjectInventory {
        questions,
        sources,
        selectors,
        derivations,
        local_access: json!({"policies": policies, "clients": clients}),
    })
}

fn yaml_inventory(
    project: &Path,
    directory: &str,
    describe: impl Fn(&str, &Value) -> Value,
) -> Result<Vec<Value>> {
    let mut entries = Vec::new();
    let maximum = match directory {
        "questions" => authoring::MAX_QUESTION_BYTES,
        "access/policies" => authoring::MAX_ACCESS_POLICY_BYTES,
        _ => authoring::MAX_SOURCE_ARTIFACT_BYTES,
    };
    for path in regular_files(project, directory, "yaml")? {
        let bytes = match read_bounded_plain_file(&path, maximum) {
            Ok(bytes) => bytes,
            Err(error) if is_operational(&error) => return Err(error),
            Err(_) => {
                return Err(InspectionDiagnostic {
                    path: path
                        .strip_prefix(project)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .into_owned(),
                }
                .into())
            }
        };
        let value: Value = serde_norway::from_slice(&bytes).map_err(|_| InspectionDiagnostic {
            path: path
                .strip_prefix(project)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned(),
        })?;
        let id = path
            .file_stem()
            .and_then(|name| name.to_str())
            .context("authored file name is not UTF-8")?;
        entries.push(describe(id, &value));
    }
    Ok(entries)
}

fn read_bounded_plain_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(io::Error::from)
    .with_context(|| format!("opening {}", path.display()))?;
    read_bounded_descriptor(descriptor, maximum)
}

fn read_bounded_descriptor(descriptor: rustix::fd::OwnedFd, maximum: u64) -> Result<Vec<u8>> {
    let mut file = File::from(descriptor);
    let metadata = file.metadata().context("inspecting authored input")?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum {
        bail!("authored input is not a bounded plain file");
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("reading authored input")?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        bail!("authored input exceeds its byte limit");
    }
    Ok(bytes)
}

fn file_inventory(project: &Path, directory: &str, extension: &str) -> Result<Vec<Value>> {
    regular_files(project, directory, extension)?
        .into_iter()
        .map(|path| {
            let id = path
                .file_stem()
                .and_then(|name| name.to_str())
                .context("authored file name is not UTF-8")?;
            Ok(json!({"id": id, "path": path.strip_prefix(project).unwrap_or(&path)}))
        })
        .collect()
}

fn regular_files(project: &Path, directory: &str, extension: &str) -> Result<Vec<PathBuf>> {
    let directory = project.join(directory);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", directory.display()))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("{} must be a plain directory", directory.display());
    }
    let mut paths = fs::read_dir(&directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?;
    paths.sort();
    for path in &paths {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || path.extension().and_then(|value| value.to_str()) != Some(extension)
        {
            return Err(InspectionDiagnostic {
                path: path
                    .strip_prefix(project)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .into_owned(),
            }
            .into());
        }
    }
    Ok(paths)
}

fn explain_governance(governance: &Value) -> Value {
    let names = |pointer: &str| {
        governance
            .pointer(pointer)
            .and_then(Value::as_object)
            .map(|values| values.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let formats = governance
        .get("responseFormats")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    json!({
        "assuranceProfile": governance.get("assuranceProfile"),
        "serviceId": governance.pointer("/publication/serviceId"),
        "issuer": governance.pointer("/issuer/id"),
        "authorityProfiles": names("/authorityProfiles"),
        "sourceConnections": names("/sourceConnections"),
        "responseFormats": formats,
        "activePublicKeyFile": governance.pointer("/signing/activePublicJwkFile"),
    })
}

fn diagnostic(
    severity: &str,
    code: &str,
    artifact: &str,
    path: &str,
    message: impl Into<String>,
    suggested_action: &str,
) -> Value {
    json!({
        "severity": severity,
        "code": code,
        "artifact": artifact,
        "path": path,
        "message": message.into(),
        "suggestedAction": suggested_action,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn temporary() -> tempfile::TempDir {
        let temporary_root = std::env::temp_dir().canonicalize().unwrap();
        tempfile::Builder::new()
            .prefix("evidencectl-check-test-")
            .tempdir_in(temporary_root)
            .unwrap()
    }

    fn put_marker(project: &Path) {
        fs::write(
            project.join(PROJECT_MARKER_FILE),
            registry_evidence_authoring::default_project_marker_document(),
        )
        .unwrap();
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &destination.join(entry.file_name()));
            } else {
                fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
            }
        }
    }

    fn rendered_denial(command: &str, project: &Path, findings: &[Value]) -> String {
        let report = json!({
            "command": command,
            "status": "refused",
            "proof": "none",
            "project": project,
            "findings": findings,
        });
        let mut output = Vec::new();
        render_human(&report, &mut output).unwrap();
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn incomplete_project_is_visible_without_a_deployment_claim() {
        let temporary = temporary();
        put_marker(temporary.path());
        fs::create_dir(temporary.path().join("questions")).unwrap();

        let report = check(temporary.path(), None, false, false).unwrap();

        assert_eq!(report["status"], "incomplete");
        assert_eq!(report["proof"], "authoring");
        assert_eq!(report["fixtureProof"], false);
        assert_eq!(report["findings"][0]["path"], "questions");
    }

    #[test]
    fn target_bound_source_is_valid_authoring_with_incomplete_target_closure() {
        let temporary = temporary();
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/sqlite-extract"),
            temporary.path(),
        );
        put_marker(temporary.path());
        fs::write(
            temporary.path().join("sources/record-status.yaml"),
            r#"transport: http-json
connection: records
posture: field-projected
request:
  method: GET
  pathTemplate: /records/{record_reference}
  pathBindings:
    record_reference: {from: selector, role: subject, profile: record-reference-v1, field: record_reference}
  fixedHeaders: [{name: Accept, value: application/json}]
  selectorInputs:
    - role: subject
      alternatives:
        - {profile: record-reference-v1, fields: [record_reference]}
  prepareScript: adapters/record-status-prepare.rhai
  adapterParameters: {}
  adapterParametersSchema: schemas/record-status-parameters.schema.yaml
  preparationLimits: {query: allowed, jsonBody: forbidden, maximumNormalizedBytes: 4096}
  projection: [/rows/*/qualifying_record_count]
  redirects: deny
  timeoutMilliseconds: 2000
  maximumResponseBytes: 8192
responseSchema: schemas/record-status-response.schema.yaml
extractScript: adapters/record-status-extract.rhai
factSchema: schemas/record-status-facts.schema.yaml
"#,
        )
        .unwrap();
        fs::write(
            temporary.path().join("adapters/record-status-prepare.rhai"),
            "fn prepare(selectors, context) { #{query: [], body: ()} }\n",
        )
        .unwrap();
        fs::write(
            temporary
                .path()
                .join("schemas/record-status-parameters.schema.yaml"),
            "type: object\nadditionalProperties: false\nrequired: []\nproperties: {}\n",
        )
        .unwrap();

        let report = check(temporary.path(), None, false, false)
            .expect("a valid authored connection reference is not refused");

        assert_eq!(report["status"], "incomplete");
        assert_eq!(report["proof"], "authoring");
        assert_eq!(report["bundleRevision"], Value::Null);
        assert_eq!(report["findings"].as_array().unwrap().len(), 1);
        assert_eq!(
            report["findings"][0]["code"],
            "evidence.target.source-connection-required"
        );
        assert_eq!(
            report["findings"][0]["path"],
            "sources/record-status.yaml:/connection"
        );
        assert!(!report["findings"][0]["message"]
            .as_str()
            .unwrap()
            .contains("records"));

        let denied = check(temporary.path(), None, false, true)
            .expect_err("--deny-findings refuses incomplete target closure");
        assert!(denied.downcast_ref::<DeniedFindings>().is_some());
    }

    #[test]
    fn malformed_question_is_a_domain_refusal_for_an_ordinary_check() {
        let temporary = temporary();
        put_marker(temporary.path());
        fs::create_dir(temporary.path().join("questions")).unwrap();
        fs::write(temporary.path().join("questions/broken.yaml"), "id: [\n").unwrap();

        let error = check(temporary.path(), None, false, false).unwrap_err();
        let denied = error.downcast_ref::<DeniedFindings>().unwrap();
        assert_eq!(denied.0[0]["severity"], "error");
        assert_eq!(denied.0[0]["code"], "evidence.authoring.unreadable");
        assert_eq!(denied.0[0]["path"], "questions/broken.yaml");
    }

    #[test]
    fn malformed_source_is_a_domain_refusal_for_an_ordinary_check() {
        let temporary = temporary();
        put_marker(temporary.path());
        fs::create_dir(temporary.path().join("questions")).unwrap();
        fs::create_dir(temporary.path().join("sources")).unwrap();
        fs::write(
            temporary.path().join("sources/broken.yaml"),
            "transport: [\n",
        )
        .unwrap();

        let error = check(temporary.path(), None, false, false).unwrap_err();
        let denied = error.downcast_ref::<DeniedFindings>().unwrap();
        assert_eq!(denied.0[0]["severity"], "error");
        assert_eq!(denied.0[0]["code"], "evidence.authoring.unreadable");
        assert_eq!(denied.0[0]["path"], "sources/broken.yaml");
    }

    #[test]
    fn oversized_authored_yaml_is_a_bounded_field_addressed_refusal() {
        for (relative, maximum) in [
            ("questions/oversized.yaml", authoring::MAX_QUESTION_BYTES),
            (
                "sources/oversized.yaml",
                authoring::MAX_SOURCE_ARTIFACT_BYTES,
            ),
            (
                "selectors/oversized.yaml",
                authoring::MAX_SOURCE_ARTIFACT_BYTES,
            ),
            (
                "access/policies/oversized.yaml",
                authoring::MAX_ACCESS_POLICY_BYTES,
            ),
        ] {
            let temporary = temporary();
            put_marker(temporary.path());
            let path = temporary.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(
                &path,
                vec![b'x'; usize::try_from(maximum).unwrap().saturating_add(1)],
            )
            .unwrap();

            let error = check(temporary.path(), None, false, false).unwrap_err();
            let denied = error.downcast_ref::<DeniedFindings>().unwrap();
            assert_eq!(denied.0[0]["code"], "evidence.authoring.unreadable");
            assert_eq!(denied.0[0]["path"], relative);
        }
    }

    #[test]
    fn project_snapshot_cleanup_removes_sealed_success_and_partial_refusal_trees() {
        let temporary = temporary();
        let project = temporary.path().join("project");
        fs::create_dir_all(project.join("questions")).unwrap();
        put_marker(&project);

        let snapshot = capture_project_in(&project, temporary.path()).unwrap();
        let snapshot_path = snapshot._temporary.path().to_path_buf();
        assert!(snapshot_path.exists());
        drop(snapshot);
        assert!(!snapshot_path.exists());

        fs::write(
            project.join("questions/oversized.yaml"),
            vec![
                b'x';
                usize::try_from(authoring::MAX_QUESTION_BYTES)
                    .unwrap()
                    .saturating_add(1)
            ],
        )
        .unwrap();
        assert!(capture_project_in(&project, temporary.path()).is_err());
        assert!(fs::read_dir(temporary.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("evidencectl-project-snapshot-")));
    }

    #[test]
    fn symlinked_access_parent_cannot_disclose_external_client_names() {
        const CANARY: &str = "EXTERNAL_CLIENT_NAME_CANARY";
        let temporary = temporary();
        let project = temporary.path().join("project");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(project.join("questions")).unwrap();
        fs::create_dir_all(outside.join("clients")).unwrap();
        put_marker(&project);
        fs::write(outside.join(format!("clients/{CANARY}.yaml")), CANARY).unwrap();
        symlink(&outside, project.join("access")).unwrap();

        let error = check(&project, None, false, false).unwrap_err();
        let denied = error.downcast_ref::<DeniedFindings>().unwrap();
        assert_eq!(denied.0[0]["path"], "access");
        assert!(!serde_json::to_string(&denied.0).unwrap().contains(CANARY));
    }

    #[test]
    fn snapshot_open_errors_preserve_custody_and_operational_classification() {
        for error in [
            rustix::io::Errno::NOENT,
            rustix::io::Errno::LOOP,
            rustix::io::Errno::NOTDIR,
        ] {
            let error = snapshot_open_error(error, Path::new("questions"), "directory");
            assert!(!is_operational(&error));
            assert!(error.downcast_ref::<InspectionDiagnostic>().is_some());
        }

        for error in [rustix::io::Errno::ACCESS, rustix::io::Errno::IO] {
            let error = snapshot_open_error(error, Path::new("questions"), "directory");
            assert!(is_operational(&error));
            assert!(error.downcast_ref::<InspectionDiagnostic>().is_none());
        }
    }

    #[test]
    fn opened_directory_snapshot_cannot_escape_after_path_replacement() {
        use rustix::fs::{Mode, OFlags};

        const CANARY: &str = "EXTERNAL_DIRECTORY_CANARY";
        let temporary = temporary();
        let project = temporary.path().join("project");
        let outside = temporary.path().join("outside");
        let snapshot = temporary.path().join("snapshot");
        fs::create_dir_all(project.join("questions")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::create_dir_all(snapshot.join("questions")).unwrap();
        fs::write(project.join("questions/captured.yaml"), "id: captured\n").unwrap();
        fs::write(outside.join(format!("{CANARY}.yaml")), CANARY).unwrap();
        let project_descriptor = rustix::fs::open(
            &project,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let questions = open_snapshot_directory(
            &project_descriptor,
            OsStr::new("questions"),
            Path::new("questions"),
        )
        .unwrap()
        .unwrap();
        fs::rename(
            project.join("questions"),
            project.join("captured-questions"),
        )
        .unwrap();
        symlink(&outside, project.join("questions")).unwrap();

        let mut directories = vec![snapshot.clone(), snapshot.join("questions")];
        capture_directory_contents(
            &questions,
            &snapshot,
            Path::new("questions"),
            authoring::MAX_QUESTION_BYTES,
            &mut directories,
        )
        .unwrap();

        assert!(snapshot.join("questions/captured.yaml").exists());
        assert!(!snapshot.join(format!("questions/{CANARY}.yaml")).exists());
    }

    #[test]
    fn typed_question_refusal_does_not_disclose_the_rejected_value() {
        const CANARY: &str = "QUESTION_SECRET_CANARY";
        let temporary = temporary();
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/sqlite-extract"),
            temporary.path(),
        );
        put_marker(temporary.path());
        let path = temporary.path().join("questions/record-status.yaml");
        let question = fs::read_to_string(&path).unwrap().replace(
            "purpose: record-status-check",
            &format!("purpose: [{CANARY}]"),
        );
        assert!(question.contains(CANARY));
        fs::write(&path, question).unwrap();

        for (command, error) in [
            (
                "check",
                check(temporary.path(), None, false, false).unwrap_err(),
            ),
            ("explain", explain(temporary.path(), None).unwrap_err()),
        ] {
            let denied = error.downcast_ref::<DeniedFindings>().unwrap();
            let json = serde_json::to_string(&denied.0).unwrap();
            let human = rendered_denial(command, temporary.path(), &denied.0);
            assert!(!json.contains(CANARY));
            assert!(!human.contains(CANARY));
            assert_eq!(denied.0[0]["code"], "question-parse");
            assert_eq!(denied.0[0]["path"], "questions/record-status.yaml:/purpose");
        }
    }

    #[test]
    fn typed_target_refusal_does_not_disclose_the_rejected_value() {
        const CANARY: &str = "TARGET_SECRET_CANARY";
        let temporary = temporary();
        let project = temporary.path().join("project");
        let target = temporary.path().join("target");
        fs::create_dir_all(project.join("questions")).unwrap();
        fs::create_dir(&target).unwrap();
        put_marker(&project);
        let governance = include_str!(
            "../../../products/evidence/reference/deployment-targets/environments/production/evidence/governance.yaml"
        )
        .replace(
            "assuranceProfile: evidence-grade",
            &format!("assuranceProfile: [{CANARY}]"),
        );
        assert!(governance.contains(CANARY));
        fs::write(target.join("governance.yaml"), governance).unwrap();
        fs::write(
            target.join("runtime.yaml"),
            include_str!(
                "../../../products/evidence/reference/deployment-targets/environments/production/evidence/runtime.yaml"
            ),
        )
        .unwrap();

        for (command, error) in [
            (
                "check",
                check(&project, Some(&target), false, false).unwrap_err(),
            ),
            ("explain", explain(&project, Some(&target)).unwrap_err()),
        ] {
            let denied = error.downcast_ref::<DeniedFindings>().unwrap();
            let json = serde_json::to_string(&denied.0).unwrap();
            let human = rendered_denial(command, &project, &denied.0);
            assert!(!json.contains(CANARY));
            assert!(!human.contains(CANARY));
            assert_eq!(denied.0[0]["code"], "evidence.target.governance-shape");
            assert_eq!(denied.0[0]["path"], "governance.yaml:/assuranceProfile");
        }
    }

    #[test]
    fn missing_declared_asset_is_a_finding_until_findings_are_denied() {
        let temporary = temporary();
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/sqlite-extract"),
            temporary.path(),
        );
        put_marker(temporary.path());
        fs::remove_file(temporary.path().join("derivations/record-status.rhai")).unwrap();
        fs::remove_file(temporary.path().join("fixtures/record-status.yaml")).unwrap();

        let report = check(temporary.path(), None, false, false).unwrap();
        assert_eq!(report["status"], "incomplete");
        assert!(report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["code"] == "evidence.question.derivation-missing"
                    && finding["path"] == "questions/record-status.yaml:/derivation"
            }));

        let error = check(temporary.path(), None, false, true).unwrap_err();
        assert!(error.downcast_ref::<DeniedFindings>().is_some());
    }

    #[test]
    fn missing_source_asset_is_an_incomplete_finding_before_compilation() {
        let temporary = temporary();
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/sqlite-extract"),
            temporary.path(),
        );
        put_marker(temporary.path());
        fs::remove_file(
            temporary
                .path()
                .join("schemas/record-status-response.schema.yaml"),
        )
        .unwrap();

        let report = check(temporary.path(), None, false, false).unwrap();
        assert_eq!(report["status"], "incomplete");
        assert!(report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["code"] == "evidence.source.asset-missing"
                    && finding["path"] == "sources/record-status.yaml:/responseSchema"
            }));

        let error = check(temporary.path(), None, false, true).unwrap_err();
        assert!(error.downcast_ref::<DeniedFindings>().is_some());
    }

    #[test]
    fn escaping_source_assets_are_refused_before_any_host_path_lookup() {
        for invalid in ["../outside.yaml", "/private/tmp/outside.yaml"] {
            let temporary = temporary();
            copy_tree(
                &Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/sqlite-extract"),
                temporary.path(),
            );
            put_marker(temporary.path());
            fs::remove_file(temporary.path().join("derivations/record-status.rhai")).unwrap();
            let source_path = temporary.path().join("sources/record-status.yaml");
            let mut source: Value =
                serde_norway::from_slice(&fs::read(&source_path).unwrap()).unwrap();
            source["responseSchema"] = json!(invalid);
            fs::write(&source_path, serde_norway::to_string(&source).unwrap()).unwrap();

            let error = check(temporary.path(), None, false, false).unwrap_err();
            let denied = error.downcast_ref::<DeniedFindings>().unwrap();
            assert_eq!(denied.0[0]["code"], "source-artifact-reference");
            assert_eq!(
                denied.0[0]["path"],
                "sources/record-status.yaml:/responseSchema"
            );
            assert!(!serde_json::to_string(&denied.0).unwrap().contains(invalid));
        }
    }

    #[test]
    fn symlinked_declared_assets_are_domain_refusals_even_with_other_gaps() {
        for (relative, code, path) in [
            (
                "schemas/record-status-response.schema.yaml",
                "source-artifact-custody",
                "sources/record-status.yaml:/responseSchema",
            ),
            (
                "derivations/record-status.rhai",
                "evidence.authoring.unreadable",
                "derivations/record-status.rhai",
            ),
            (
                "fixtures/record-status.yaml",
                "question-fixture-custody",
                "questions/record-status.yaml:/governance/fixtures",
            ),
        ] {
            let temporary = temporary();
            copy_tree(
                &Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/sqlite-extract"),
                temporary.path(),
            );
            put_marker(temporary.path());
            let outside = temporary.path().join("outside");
            fs::write(&outside, "outside").unwrap();
            let declared = temporary.path().join(relative);
            fs::remove_file(&declared).unwrap();
            symlink(&outside, &declared).unwrap();
            fs::remove_file(
                temporary
                    .path()
                    .join("schemas/record-status-facts.schema.yaml"),
            )
            .unwrap();

            let error = check(temporary.path(), None, false, false).unwrap_err();
            let denied = error.downcast_ref::<DeniedFindings>().unwrap();
            assert_eq!(denied.0[0]["code"], code);
            assert_eq!(denied.0[0]["path"], path);
        }
    }

    #[test]
    fn invalid_local_access_is_checked_without_reading_secrets() {
        let temporary = temporary();
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/sqlite-extract"),
            temporary.path(),
        );
        put_marker(temporary.path());
        fs::create_dir_all(temporary.path().join("access/policies")).unwrap();
        fs::write(
            temporary.path().join("access/policies/broken.yaml"),
            "version: 1\nid: broken\nquestions: [missing-question]\n",
        )
        .unwrap();

        let error = check(temporary.path(), None, false, false).unwrap_err();
        let denied = error.downcast_ref::<DeniedFindings>().unwrap();
        assert_eq!(
            denied.0[0]["path"],
            "access/policies/broken.yaml:/questions"
        );
        assert!(!temporary.path().join("secrets").exists());
    }

    #[test]
    fn production_requires_an_explicit_target() {
        let error = check(Path::new("project"), None, true, false).unwrap_err();
        let denied = error.downcast_ref::<DeniedFindings>().unwrap();
        assert_eq!(denied.0[0]["code"], "evidence.target.required");
    }

    #[test]
    fn production_refuses_a_local_target_without_upgrading_it() {
        let temporary = temporary();
        let project = temporary.path().join("project");
        let target = temporary.path().join("target");
        fs::create_dir_all(project.join("questions")).unwrap();
        fs::create_dir(&target).unwrap();
        put_marker(&project);
        let governance = include_str!(
            "../../../products/evidence/reference/deployment-targets/environments/production/evidence/governance.yaml"
        )
        .replace("assuranceProfile: evidence-grade", "assuranceProfile: local");
        fs::write(target.join("governance.yaml"), governance).unwrap();
        fs::write(
            target.join("runtime.yaml"),
            include_str!(
                "../../../products/evidence/reference/deployment-targets/environments/production/evidence/runtime.yaml"
            ),
        )
        .unwrap();

        let error = check(&project, Some(&target), true, false).unwrap_err();
        let denied = error.downcast_ref::<DeniedFindings>().unwrap();
        assert!(denied.0.iter().any(|finding| {
            finding["code"] == "evidence.target.production-profile-required"
                && finding["path"] == "governance.yaml:/assuranceProfile"
        }));
        let unchanged = fs::read_to_string(target.join("governance.yaml")).unwrap();
        assert!(unchanged.contains("assuranceProfile: local"));
    }

    #[test]
    fn target_report_and_explanation_share_the_captured_documents() {
        let temporary = temporary();
        let project = temporary.path().join("project");
        let target = temporary.path().join("target");
        fs::create_dir_all(project.join("questions")).unwrap();
        put_marker(&project);
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../products/evidence/reference/deployment-targets/environments/production/evidence",
            ),
            &target,
        );

        let checked = check_and_capture_target(&project, Some(&target), false, false).unwrap();
        let governance_path = target.join("governance.yaml");
        let replacement = fs::read_to_string(&governance_path).unwrap().replace(
            "assuranceProfile: evidence-grade",
            "assuranceProfile: local",
        );
        fs::write(&governance_path, replacement).unwrap();

        let captured = checked.target_documents.as_ref().unwrap();
        assert_eq!(checked.report["assuranceProfile"], "evidence-grade");
        assert_eq!(
            explain_governance(&captured.governed_bundle)["assuranceProfile"],
            "evidence-grade"
        );
        assert_eq!(
            build::read_target_documents(&target)
                .unwrap()
                .governed_bundle["assuranceProfile"],
            "local"
        );
    }

    #[test]
    fn explanation_reuses_the_captured_project_after_replacement() {
        let temporary = temporary();
        fs::create_dir(temporary.path().join("questions")).unwrap();
        put_marker(temporary.path());

        let checked = check_and_capture_target(temporary.path(), None, false, false).unwrap();
        fs::write(
            temporary.path().join("questions/replacement.yaml"),
            "id: replacement\n",
        )
        .unwrap();

        let report = explain_captured(temporary.path(), None, checked).unwrap();
        assert_eq!(report["status"], "incomplete");
        assert_eq!(report["questions"], json!([]));
        assert_eq!(
            inspect_project(temporary.path()).unwrap().questions.len(),
            1
        );
    }

    #[test]
    fn explain_inventory_never_infers_target_governance() {
        let temporary = temporary();
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/sqlite-extract"),
            temporary.path(),
        );
        put_marker(temporary.path());
        fs::remove_file(temporary.path().join("fixtures/record-status.yaml")).unwrap();

        let report = explain(temporary.path(), None).unwrap();

        assert!(report["targetGovernance"].is_null());
        assert_eq!(report["status"], "incomplete");
        assert_eq!(report["sources"][0]["id"], "record-status");
        assert_eq!(
            report["selectors"][0]["fields"],
            json!(["record_reference"])
        );
        assert_eq!(report["derivations"][0]["id"], "record-status");
        assert_eq!(report["localAccess"]["mode"], "implicit-local-caller");
    }

    #[test]
    fn question_inventory_reports_fields_and_profiles_for_both_subject_forms() {
        let temporary = temporary();
        fs::create_dir(temporary.path().join("questions")).unwrap();
        fs::write(
            temporary.path().join("questions/single.yaml"),
            "id: single\nsubject:\n  role: record\n  selector: record_reference\n  profile: record-reference-v1\n",
        )
        .unwrap();
        fs::write(
            temporary.path().join("questions/multiple.yaml"),
            "id: multiple\nsubjects:\n  - role: child\n    selector: child_reference\n    profile: child-reference-v1\n  - role: guardian\n    profiles: [guardian-reference-v1, guardian-composite-v1]\n",
        )
        .unwrap();

        let inventory = inspect_project(temporary.path()).unwrap();

        assert_eq!(inventory.questions[0]["id"], "multiple");
        assert_eq!(
            inventory.questions[0]["selectors"],
            json!(["child_reference"])
        );
        assert_eq!(
            inventory.questions[0]["selectorProfiles"],
            json!([
                "child-reference-v1",
                "guardian-reference-v1",
                "guardian-composite-v1"
            ])
        );
        assert_eq!(inventory.questions[1]["id"], "single");
        assert_eq!(
            inventory.questions[1]["selectors"],
            json!(["record_reference"])
        );
        assert_eq!(
            inventory.questions[1]["selectorProfiles"],
            json!(["record-reference-v1"])
        );
    }

    #[test]
    fn target_governance_reports_the_publication_service_identity() {
        let governance = json!({
            "assuranceProfile": "evidence-grade",
            "publication": {"serviceId": "urn:example:services:evidence"},
            "service": {"id": "urn:obsolete:path"},
        });

        let explanation = explain_governance(&governance);

        assert_eq!(explanation["serviceId"], "urn:example:services:evidence");
    }

    #[test]
    fn runtime_structure_accepts_target_host_paths_without_opening_them() {
        let runtime = include_bytes!(
            "../../../products/evidence/reference/deployment-targets/environments/production/evidence/runtime.yaml"
        );
        validate_runtime_structure(runtime).unwrap();
    }

    #[test]
    fn runtime_structure_refuses_unknown_fields() {
        let runtime = include_str!(
            "../../../products/evidence/reference/deployment-targets/environments/production/evidence/runtime.yaml"
        );
        let runtime = runtime.replace("version: 1", "version: 1\nunknown: true");
        let error = validate_runtime_structure(runtime.as_bytes()).unwrap_err();
        assert!(format!("{error:#}").contains("Version 1"));
    }

    #[test]
    fn diagnostics_keep_the_breg_field_set() {
        let value = diagnostic("finding", "code", "artifact", "path", "message", "action");
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            BTreeSet::from([
                "artifact".to_owned(),
                "code".to_owned(),
                "message".to_owned(),
                "path".to_owned(),
                "severity".to_owned(),
                "suggestedAction".to_owned(),
            ])
        );
    }
}
