//! Offline inspection of editable Evidence projects and explicit targets.
//!
//! These commands are adapters around the owning authoring compiler and the
//! runtime's bundle-only validator. They never execute a fixture, resolve a
//! secret, inspect a target-host path, or contact a dependency.
//!
//! Every problem they find is a diagnostic in the shared reader's one shape,
//! naming each file from the project and target paths as the command was
//! given them. An error refuses the command; a warning leaves the project
//! accepted but incomplete, unless `--deny-warnings` or `--production` makes
//! it refuse too.

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

use anyhow::{Context as _, Result};
use jsonschema::{Draft, JSONSchema};
use registry_evidence_authoring::{
    formats::{
        check_access_policy, check_question, decode_authored, scan_authored, ACCESS_CLIENT_KIND,
        ACCESS_POLICY_KIND, AUTHORING_PROJECT_KIND, MOCK_PLAN_KIND, QUESTION_KIND,
        TARGET_GOVERNANCE, TARGET_GOVERNANCE_KIND, TARGET_SETTINGS, TARGET_SETTINGS_KIND,
    },
    layout::{
        ACCESS_DIRECTORY, ACCESS_POLICIES_DIRECTORY, DERIVATIONS_DIRECTORY, FIXTURES_DIRECTORY,
        MAX_DERIVATION_BYTES, MAX_OPENAPI_BYTES, MAX_SOURCE_ARTIFACT_BYTES, OPENAPI_FILE,
        QUESTIONS_DIRECTORY, SCHEMAS_DIRECTORY, SELECTORS_DIRECTORY, SOURCES_DIRECTORY,
    },
    parse_project_marker, PROJECT_MARKER_FILE,
};
use registry_platform_yaml::{
    Diagnostic, Document, Node, NodeValue, Reader, Report, Severity, MAXIMUM_DOCUMENT_BYTES,
};
use serde_json::{json, Value};

use crate::{
    authored::{self, Gathered},
    authoring, build,
    evidence_binary::{self, EVIDENCE_RUNTIME_KIND},
    source_mock, target,
};

const RUNTIME_SCHEMA: &str =
    include_str!("../../../products/evidence/contracts/runtime.schema.yaml");

/// The project directory holding deployment targets and their settings.
const TARGETS_DIRECTORY: &str = "targets";
/// The project directory holding materialized source mock plans.
const MOCKS_DIRECTORY: &str = "mocks";

/// A check or explain that reached its verdict: the report it writes, and
/// the diagnostics that report carries, for the human renderer.
#[derive(Debug)]
pub(crate) struct Checked {
    pub(crate) report: Value,
    pub(crate) diagnostics: Report,
}

/// Validate an editable project, optionally joined to one explicit target.
///
/// A project-only success proves authoring closure under the local compiler
/// profile. Only a supplied target can produce a deployment-closure claim.
/// A refusal is the [`Report`] of every problem found.
pub(crate) fn check(
    project: &Path,
    target: Option<&Path>,
    production: bool,
    deny_warnings: bool,
) -> Result<Checked> {
    let outcome = check_and_capture_target(project, target, production, deny_warnings)?;
    Ok(Checked {
        report: outcome.report,
        diagnostics: outcome.diagnostics,
    })
}

struct CheckOutcome {
    report: Value,
    diagnostics: Report,
    project_snapshot: ProjectSnapshot,
    target_documents: Option<build::TargetDocuments>,
}

fn check_and_capture_target(
    project: &Path,
    target: Option<&Path>,
    production: bool,
    deny_warnings: bool,
) -> Result<CheckOutcome> {
    if production && target.is_none() {
        return Err(Report::new(vec![Diagnostic::error(
            "evidence.target.required",
            "",
            "--production requires an explicit Evidence deployment target",
            "Pass --target TARGET naming production or evidence-grade governance.",
        )])
        .into());
    }

    let project_snapshot =
        capture_project(project).map_err(|error| refusal(error, project, project))?;
    let captured_project = project_snapshot.root();
    let mut gathered = Gathered::default();
    read_project_marker(captured_project, &mut gathered)?;
    let inventory = inspect_project(captured_project, &mut gathered)?;
    let aside = inspect_project_files(captured_project, &mut gathered)?;
    let mut found = gathered.report();
    if found.has_errors() {
        found.extend(aside);
        found.set_files_checked(project_snapshot.files);
        return Err(in_project(found, captured_project, project).into());
    }
    if inventory.questions.is_empty() {
        found.push(authored::file_diagnostic(
            Severity::Warning,
            "evidence.question.missing",
            None,
            "questions",
            "",
            "the project has no authored questions",
            "Add at least one questions/<id>.yaml document and its declared assets.",
        ));
        if inventory.local_access["policies"]
            .as_array()
            .is_some_and(|policies| !policies.is_empty())
        {
            found.push(authored::file_diagnostic(
                Severity::Warning,
                "evidence.access.questions-missing",
                None,
                "access/policies",
                "",
                "local access policies cannot be resolved until the project has questions",
                "Add the questions named by each local access policy.",
            ));
        }
    } else {
        authoring::validate_offline_local_access(captured_project)
            .map_err(|error| refusal(error, captured_project, project))?;
    }
    found.extend(declared_asset_findings(captured_project, &inventory)?);
    let mut found = in_project(found, captured_project, project);
    if found.has_errors() {
        found.set_files_checked(project_snapshot.files);
        return Err(found.into());
    }

    let mut target_documents = None;
    let mut assurance_profile = None;
    let mut package_digest = None;
    if let Some(target) = target {
        let documents =
            build::read_target_documents(target).map_err(|error| target_refusal(error, target))?;
        assurance_profile = documents
            .governed_bundle
            .get("assuranceProfile")
            .and_then(Value::as_str)
            .map(str::to_owned);
        validate_runtime_structure("runtime.yaml", &documents.runtime)
            .map_err(|error| target_refusal(error, target))?;
        if production && assurance_profile.as_deref() == Some("local") {
            found.extend(in_target(
                Report::new(vec![authored::file_diagnostic(
                    Severity::Error,
                    "evidence.target.production-profile-required",
                    None,
                    "governance.yaml",
                    "/assuranceProfile",
                    "--production refuses a target whose assuranceProfile is local",
                    "Select an explicit production or evidence-grade target; the command never upgrades a target profile.",
                )]),
                target,
            ));
        }
        target_documents = Some(documents);
    }
    if found.is_empty() {
        let target_bound_sources = authoring::target_bound_sources(captured_project)
            .map_err(|error| refusal(error, captured_project, project))?;
        if target_documents.is_none() {
            let unresolved = Report::new(
                target_bound_sources
                    .into_iter()
                    .map(|source| {
                        authored::file_diagnostic(
                            Severity::Warning,
                            "evidence.target.source-connection-required",
                            None,
                            &format!("sources/{}.yaml", source.source_id),
                            "/connection",
                            "the source connection can be resolved only against an explicit deployment target",
                            "Pass --target TARGET naming governance that declares the source connection.",
                        )
                    })
                    .collect(),
            );
            found.extend(in_project(unresolved, captured_project, project));
        }
        if found.is_empty() {
            let checked = match target_documents.as_ref() {
                Some(documents) => check_with_target(captured_project, project, documents),
                None => check_project_only(captured_project, project),
            };
            let checked = checked
                .map_err(|error| compile_refusal(error, captured_project, project, target))?;
            package_digest = Some(checked.package_digest);
        }
    }

    found.extend(in_project(aside, captured_project, project));
    found.set_files_checked(project_snapshot.files + target.map_or(0, |_| TARGET_DOCUMENTS));
    if found.has_errors() || ((production || deny_warnings) && found.warning_count() > 0) {
        return Err(found.into());
    }
    let complete = found.is_empty();
    let report = crate::report::success(
        "check",
        if complete { "complete" } else { "incomplete" },
        json!({
            "project": project,
            "target": target,
            "proof": if complete && target.is_some() { "deployment-closure" } else { "authoring" },
            "assuranceProfile": assurance_profile,
            "packageDigest": package_digest,
            "fixtureProof": false,
            "diagnostics": found.to_json_value(),
            "offline": true,
            "networkAccess": false,
            "fixtureExecution": false,
            "secretResolution": false,
            "targetHostPathChecks": false,
        }),
    );
    Ok(CheckOutcome {
        report,
        diagnostics: found,
        project_snapshot,
        target_documents,
    })
}

/// The two target documents a check reads: governance and runtime.
const TARGET_DOCUMENTS: usize = 2;

/// Diagnostics about files inside the captured project, placed where each
/// member is written and named from the project path as given.
fn in_project(report: Report, captured: &Path, project: &Path) -> Report {
    authored::rebase(authored::place(report, captured), project)
}

/// The refusal a project read raised, as the report of every problem it
/// found, each file named from `project`. An operational failure is returned
/// unchanged.
fn refusal(error: anyhow::Error, captured: &Path, project: &Path) -> anyhow::Error {
    if let Some(inspection) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<InspectionDiagnostic>())
    {
        return Report::new(vec![inspection.diagnostic_in(project)]).into();
    }
    if is_operational(&error) {
        return error;
    }
    authored::project_refusal(error, captured, project)
}

/// The refusal the offline compiler or the runtime's bundle check raised.
/// A problem the compiler names in an authored or target file is reported
/// there; any other refusal names the project, with the next step.
fn compile_refusal(
    error: anyhow::Error,
    captured: &Path,
    project: &Path,
    target: Option<&Path>,
) -> anyhow::Error {
    if let Some(target) = target {
        if error.chain().any(|cause| {
            cause
                .downcast_ref::<build::TargetDocumentDiagnostic>()
                .is_some()
        }) {
            return target_refusal(error, target);
        }
    }
    if is_operational(&error)
        || authored::report_in(&error).is_some()
        || error.chain().any(|cause| {
            cause
                .downcast_ref::<authoring::AuthoredDiagnostic>()
                .is_some()
        })
    {
        return refusal(error, captured, project);
    }
    Report::new(vec![authored::file_diagnostic(
        Severity::Error,
        "evidence.offline-check.refused",
        None,
        &project.to_string_lossy(),
        "",
        "offline validation refused the authored configuration",
        "Run evidencectl test on the project for the runtime's own account, correct what it names, then rerun evidencectl check.",
    )])
    .into()
}

/// Diagnostics about a target's files, placed where each member is written
/// and named from the target path as given.
fn in_target(report: Report, target: &Path) -> Report {
    authored::rebase(authored::place(report, target), target)
}

/// The refusal reading or checking a target raised, as a report naming the
/// target's files from the target path as given. An operational failure is
/// returned unchanged.
fn target_refusal(error: anyhow::Error, target: &Path) -> anyhow::Error {
    const ACTION: &str =
        "Correct the target governance, runtime structure, public keys, or source connections, then retry.";
    let diagnostic = if let Some(report) = authored::report_in(&error) {
        return authored::rebase(report.clone(), target).into();
    } else if let Some(runtime) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<RuntimeStructureDiagnostic>())
    {
        authored::file_diagnostic(
            Severity::Error,
            "evidence.target.runtime-structure",
            None,
            "runtime.yaml",
            &runtime.pointer,
            &runtime.to_string(),
            ACTION,
        )
    } else if let Some(document) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<build::TargetDocumentDiagnostic>())
    {
        if document.code == "evidence.package.review-marker" {
            // The marker is in a file the compile generated, named by its
            // path inside the bundle; no target file holds it.
            return Report::new(vec![authored::file_diagnostic(
                Severity::Error,
                document.code,
                None,
                &document.path,
                "",
                &document.message,
                "Resolve the review marker in the authored file this bundle file is compiled from, then check the project again.",
            )])
            .into();
        }
        authored::located(
            Severity::Error,
            document.code,
            None,
            &document.path,
            &document.message,
            target_action(document.code),
        )
    } else if is_operational(&error) {
        return error;
    } else {
        authored::file_diagnostic(
            Severity::Error,
            "evidence.target.incomplete",
            None,
            "",
            "",
            "the deployment target does not match the closed offline validation contract",
            ACTION,
        )
    };
    in_target(Report::new(vec![diagnostic]), target).into()
}

/// The change that clears a refusal about a deployment target, by its code.
fn target_action(code: &str) -> &'static str {
    match code {
        "evidence.target.assurance-profile" => {
            "Set assuranceProfile in the target's governance.yaml to local, production, or evidence-grade."
        }
        "evidence.target.authority-profiles" => {
            "Declare at least one authority profile under authorityProfiles in the target's governance.yaml."
        }
        "evidence.package.production-profile-required" => {
            "Package against a target whose governance.yaml sets assuranceProfile to production or evidence-grade."
        }
        "evidence.package.root-unstable" => {
            "Set package.root in the target's runtime.yaml to a stable installed package path outside the package output directory."
        }
        _ => {
            "Correct the target governance, runtime structure, public keys, or source connections, then retry."
        }
    }
}

/// The report a refused check writes: the passing report's members, with
/// nothing claimed, and the diagnostics that refused it.
pub(crate) fn refused_check_report(
    project: &Path,
    target: Option<&Path>,
    diagnostics: &Report,
) -> Value {
    crate::report::refused(
        "check",
        "refused",
        json!({
            "project": project,
            "target": target,
            "proof": "none",
            "assuranceProfile": null,
            "packageDigest": null,
            "fixtureProof": false,
            "diagnostics": diagnostics.to_json_value(),
            "offline": true,
            "networkAccess": false,
            "fixtureExecution": false,
            "secretResolution": false,
            "targetHostPathChecks": false,
        }),
    )
}

/// The report a refused explain writes: the passing report's members, with
/// an empty inventory and the diagnostics that refused it.
pub(crate) fn refused_explain_report(
    project: &Path,
    target: Option<&Path>,
    diagnostics: &Report,
) -> Value {
    crate::report::refused(
        "explain",
        "refused",
        json!({
            "project": project,
            "target": target,
            "proof": "none",
            "packageDigest": null,
            "diagnostics": diagnostics.to_json_value(),
            "questions": [],
            "sources": [],
            "selectors": [],
            "derivations": [],
            "localAccess": null,
            "targetGovernance": null,
            "offline": true,
            "networkAccess": false,
            "secretResolution": false,
        }),
    )
}

/// Explain authored inventory and, when supplied, target-owned governance.
pub(crate) fn explain(project: &Path, target: Option<&Path>) -> Result<Checked> {
    let checked = check_and_capture_target(project, target, false, false)?;
    explain_captured(project, target, checked)
}

fn explain_captured(
    project: &Path,
    target: Option<&Path>,
    checked: CheckOutcome,
) -> Result<Checked> {
    let validation = checked.report;
    let captured_project = checked.project_snapshot.root();
    let mut gathered = Gathered::default();
    let mut inventory = inspect_project(captured_project, &mut gathered)?;
    gathered
        .checkpoint()
        .map_err(|error| refusal(error, captured_project, project))?;
    let policies = if inventory.questions.is_empty() {
        if inventory.local_access["policies"]
            .as_array()
            .is_some_and(|policies| !policies.is_empty())
        {
            return Err(Report::new(vec![authored::file_diagnostic(
                Severity::Error,
                "evidence.access.questions-missing",
                None,
                &project.join("access/policies").to_string_lossy(),
                "",
                "local access policies cannot be resolved until the project has questions",
                "Add the questions named by each local access policy.",
            )])
            .into());
        }
        Vec::new()
    } else {
        authoring::validate_offline_local_access(captured_project)
            .map_err(|error| refusal(error, captured_project, project))?
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
    let report = crate::report::success(
        "explain",
        validation["status"].as_str().unwrap_or("complete"),
        json!({
            "project": project,
            "target": target,
            "proof": validation["proof"],
            "packageDigest": validation["packageDigest"],
            "diagnostics": validation["diagnostics"],
            "questions": inventory.questions,
            "sources": inventory.sources,
            "selectors": inventory.selectors,
            "derivations": inventory.derivations,
            "localAccess": inventory.local_access,
            "targetGovernance": target_governance,
            "offline": true,
            "networkAccess": false,
            "secretResolution": false,
        }),
    );
    Ok(Checked {
        report,
        diagnostics: checked.diagnostics,
    })
}

/// Render a check or explain report for the CLI's human output path: what
/// the command concluded, then every diagnostic, position first, and the
/// summary line. JSON rendering remains owned by the common CLI boundary.
pub(crate) fn render_human(
    report: &Value,
    diagnostics: &Report,
    out: &mut dyn io::Write,
) -> io::Result<()> {
    let refused = report["status"].as_str() == Some("refused");
    match report["command"].as_str() {
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
            if !refused {
                render_inventory(report, out)?;
            }
        }
        _ => {
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
        }
    }
    write!(out, "{}", diagnostics.render_human())
}

fn render_inventory(report: &Value, out: &mut dyn io::Write) -> io::Result<()> {
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
    package_digest: String,
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
        package_digest: report.package_digest,
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
    let compiled =
        build::compile_with_target(project, documents, staging.path(), &evidence_bin, None)?;
    build::reject_review_markers(&compiled.bundle_path)?;
    let report =
        build::check_compiled_bundle(&evidence_bin, &compiled.bundle_path, display_project)?;
    Ok(CheckedBundle {
        package_digest: report.package_digest,
    })
}

fn is_operational(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<io::Error>().is_some())
}

/// Hold a target's runtime document to the published runtime contract. The
/// document is read through the shared YAML subset; its own reader decides
/// everything else about it when the runtime starts.
fn validate_runtime_structure(file: &str, bytes: &[u8]) -> Result<()> {
    let runtime = Reader::new(file)
        .scan(bytes)
        .map_err(anyhow::Error::from)?
        .map_or(Value::Null, |node| node.to_json_value());
    let schema = authored::embedded_document("Evidence runtime schema", RUNTIME_SCHEMA)?;
    let validator = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .map_err(|_| anyhow::anyhow!("the embedded Evidence runtime schema could not compile"))?;
    if let Err(errors) = validator.validate(&runtime) {
        let mut violations = errors
            .take(8)
            .map(|error| {
                (
                    error.instance_path.to_string(),
                    format!(
                        "{} violates rule {}",
                        error.instance_path, error.schema_path
                    ),
                )
            })
            .collect::<Vec<_>>();
        violations.sort();
        return Err(RuntimeStructureDiagnostic {
            pointer: violations
                .first()
                .map(|(pointer, _)| pointer.clone())
                .unwrap_or_default(),
            rules: violations.into_iter().map(|(_, rule)| rule).collect(),
        }
        .into());
    }
    Ok(())
}

#[derive(Debug)]
struct RuntimeStructureDiagnostic {
    pointer: String,
    rules: Vec<String>,
}

impl std::fmt::Display for RuntimeStructureDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "deployment runtime does not satisfy the published runtime contract: {}",
            self.rules.join("; ")
        )
    }
}

impl std::error::Error for RuntimeStructureDiagnostic {}

struct ProjectSnapshot {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    directories: Vec<PathBuf>,
    /// The plain files captured, each of which the check reads.
    files: usize,
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

/// How much of one captured file the snapshot keeps.
#[derive(Clone, Copy)]
enum Bound {
    /// A file the shared reader reads: kept up to one byte past the reader's
    /// document limit, so an oversized document is refused by the reader,
    /// with `yaml.too-large`, like every other configuration file.
    ForReader,
    /// Any other project file, refused above this many bytes.
    Refuse(u64),
}

/// The snapshot being captured: its root, every directory created under it,
/// and the number of plain files copied.
struct Capture {
    root: PathBuf,
    directories: Vec<PathBuf>,
    files: usize,
}

fn capture_project(project: &Path) -> Result<ProjectSnapshot> {
    let metadata = fs::symlink_metadata(project)
        .with_context(|| format!("inspecting project root {}", project.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(InspectionDiagnostic {
            path: String::new(),
            condition: Inspection::NotDirectory,
        }
        .into());
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
    let mut capture = Capture {
        directories: vec![root.clone()],
        root,
        files: 0,
    };

    for (relative, bound) in [
        (PROJECT_MARKER_FILE, Bound::ForReader),
        (OPENAPI_FILE, Bound::Refuse(MAX_OPENAPI_BYTES)),
    ] {
        capture_snapshot_entry_at(
            &project_descriptor,
            &mut capture,
            OsStr::new(relative),
            Path::new(relative),
            bound,
        )?;
    }
    for (relative, bound) in [
        (QUESTIONS_DIRECTORY, Bound::ForReader),
        (SOURCES_DIRECTORY, Bound::ForReader),
        (SELECTORS_DIRECTORY, Bound::ForReader),
        (DERIVATIONS_DIRECTORY, Bound::Refuse(MAX_DERIVATION_BYTES)),
        (SCHEMAS_DIRECTORY, Bound::Refuse(MAX_SOURCE_ARTIFACT_BYTES)),
        (FIXTURES_DIRECTORY, Bound::Refuse(MAX_SOURCE_ARTIFACT_BYTES)),
        ("adapters", Bound::Refuse(MAX_SOURCE_ARTIFACT_BYTES)),
        ("queries", Bound::Refuse(MAX_SOURCE_ARTIFACT_BYTES)),
        ("codelists", Bound::Refuse(MAX_SOURCE_ARTIFACT_BYTES)),
    ] {
        capture_flat_directory_at(
            &project_descriptor,
            &mut capture,
            OsStr::new(relative),
            Path::new(relative),
            bound,
        )?;
    }
    capture_access(&project_descriptor, &mut capture)?;
    for directory in [TARGETS_DIRECTORY, MOCKS_DIRECTORY] {
        capture_yaml_tree_at(
            &project_descriptor,
            &mut capture,
            OsStr::new(directory),
            Path::new(directory),
        )?;
    }
    capture_root_yaml(&project_descriptor, &mut capture)?;

    let Capture {
        root,
        mut directories,
        files,
    } = capture;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    let snapshot = ProjectSnapshot {
        _temporary: temporary,
        root,
        directories,
        files,
    };
    for directory in &snapshot.directories {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o500)).with_context(|| {
            format!("sealing project snapshot directory {}", directory.display())
        })?;
    }
    Ok(snapshot)
}

fn capture_access(project: &rustix::fd::OwnedFd, capture: &mut Capture) -> Result<()> {
    let relative = Path::new(ACCESS_DIRECTORY);
    let Some(access) = open_snapshot_directory(project, OsStr::new(ACCESS_DIRECTORY), relative)?
    else {
        return Ok(());
    };
    let destination = capture.root.join(relative);
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    capture.directories.push(destination);
    for name in [ACCESS_POLICIES_DIRECTORY, "clients"] {
        capture_flat_directory_at(
            &access,
            capture,
            OsStr::new(name),
            &relative.join(name),
            Bound::ForReader,
        )?;
    }
    Ok(())
}

fn capture_flat_directory_at(
    parent: &rustix::fd::OwnedFd,
    capture: &mut Capture,
    name: &OsStr,
    relative: &Path,
    bound: Bound,
) -> Result<()> {
    let Some(directory) = open_snapshot_directory(parent, name, relative)? else {
        return Ok(());
    };
    let destination = capture.root.join(relative);
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    capture.directories.push(destination);
    capture_directory_contents(&directory, capture, relative, bound)
}

fn capture_directory_contents(
    directory: &rustix::fd::OwnedFd,
    capture: &mut Capture,
    relative: &Path,
    bound: Bound,
) -> Result<()> {
    for name in directory_entries(directory)? {
        let entry_relative = relative.join(&name);
        capture_snapshot_entry_at(directory, capture, &name, &entry_relative, bound)?;
    }
    Ok(())
}

/// The names `directory` holds, sorted, without `.` and `..`.
fn directory_entries(directory: &rustix::fd::OwnedFd) -> Result<Vec<OsString>> {
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
    Ok(entries)
}

/// Whether a file name is a YAML file's, by its extension.
fn is_yaml_name(name: &OsStr) -> bool {
    matches!(
        Path::new(name).extension().and_then(OsStr::to_str),
        Some("yaml" | "yml")
    )
}

/// Capture the YAML files of `targets/` or `mocks/`, at any depth, with every
/// link there, so the check reads each YAML file by its envelope and refuses
/// each link. Other files, such as public keys and mock response bodies, are
/// read by the commands that use them and are not copied.
fn capture_yaml_tree_at(
    parent: &rustix::fd::OwnedFd,
    capture: &mut Capture,
    name: &OsStr,
    relative: &Path,
) -> Result<()> {
    use rustix::fs::{AtFlags, FileType};

    let Some(directory) = open_snapshot_directory(parent, name, relative)? else {
        return Ok(());
    };
    let destination = capture.root.join(relative);
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    capture.directories.push(destination);
    for entry in directory_entries(&directory)? {
        let entry_relative = relative.join(&entry);
        let metadata = match rustix::fs::statat(&directory, &entry, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => metadata,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => {
                return Err(io::Error::from(error)).context("inspecting project snapshot input")
            }
        };
        let file_type = FileType::from_raw_mode(metadata.st_mode);
        if file_type.is_dir() {
            capture_yaml_tree_at(&directory, capture, &entry, &entry_relative)?;
        } else if file_type.is_symlink() || is_yaml_name(&entry) {
            capture_snapshot_entry_at(
                &directory,
                capture,
                &entry,
                &entry_relative,
                Bound::ForReader,
            )?;
        }
    }
    Ok(())
}

/// Capture the YAML files at the project root other than the marker and the
/// OpenAPI description, so the check can identify each by its envelope.
fn capture_root_yaml(project: &rustix::fd::OwnedFd, capture: &mut Capture) -> Result<()> {
    use rustix::fs::{AtFlags, FileType};

    for entry in directory_entries(project)? {
        if entry == PROJECT_MARKER_FILE || entry == OPENAPI_FILE || !is_yaml_name(&entry) {
            continue;
        }
        let metadata = match rustix::fs::statat(project, &entry, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => metadata,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => {
                return Err(io::Error::from(error)).context("inspecting project snapshot input")
            }
        };
        if FileType::from_raw_mode(metadata.st_mode).is_dir() {
            continue;
        }
        capture_snapshot_entry_at(
            project,
            capture,
            &entry,
            Path::new(&entry),
            Bound::ForReader,
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
        return Err(InspectionDiagnostic::at(relative, Inspection::NotPlain).into());
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
        InspectionDiagnostic::at(relative, Inspection::Changed).into()
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
    capture: &mut Capture,
    name: &OsStr,
    relative: &Path,
    bound: Bound,
) -> Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    let metadata = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => {
            return Err(io::Error::from(error)).context("inspecting project snapshot input")
        }
    };
    let destination = capture.root.join(relative);
    let file_type = FileType::from_raw_mode(metadata.st_mode);
    if file_type.is_symlink() {
        let target = rustix::fs::readlinkat(parent, name, Vec::new()).map_err(io::Error::from)?;
        symlink(OsStr::from_bytes(target.to_bytes()), &destination)?;
    } else if file_type.is_dir() {
        fs::DirBuilder::new().mode(0o700).create(&destination)?;
        capture.directories.push(destination);
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
        let bytes = read_bounded_descriptor(descriptor, bound, relative)?;
        fs::write(&destination, bytes)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o400))?;
        capture.files += 1;
    } else {
        return Err(InspectionDiagnostic::at(relative, Inspection::NotPlain).into());
    }
    Ok(())
}

/// Read the project marker from the snapshot. A project without one is
/// accepted with a warning; a marker that is not the authoring project's
/// envelope is reported with every problem the reader found in it.
fn read_project_marker(project: &Path, gathered: &mut Gathered) -> Result<()> {
    let path = project.join(PROJECT_MARKER_FILE);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            gathered.push(authored::file_diagnostic(
                Severity::Warning,
                "evidence.project.marker-missing",
                None,
                PROJECT_MARKER_FILE,
                "",
                "the project has no evidence-project.yaml marker",
                "Add evidence-project.yaml with the apiVersion and kind lines evidencectl new writes.",
            ));
            return Ok(());
        }
        Err(error) => return Err(error).context("inspecting the Evidence project marker"),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            gathered.push(
                InspectionDiagnostic::at(Path::new(PROJECT_MARKER_FILE), Inspection::NotPlain)
                    .diagnostic(),
            );
            return Ok(());
        }
        Ok(_) => {}
    }
    let bytes = authored::read_authored_file(&path, "Evidence project marker")?;
    gathered.read_one();
    match parse_project_marker(PROJECT_MARKER_FILE, &bytes) {
        Ok(marker) => gathered.extend(marker.document.warnings()),
        Err(report) => gathered.extend(report),
    }
    Ok(())
}

struct ProjectInventory {
    questions: Vec<Value>,
    sources: Vec<Value>,
    selectors: Vec<Value>,
    derivations: Vec<Value>,
    local_access: Value,
    /// Each question read, by its file name inside the project.
    question_documents: Vec<(String, Value)>,
    /// Each source read, by its file name inside the project.
    source_documents: Vec<(String, Value)>,
}

/// A project entry the check refuses before reading it as an authored
/// document, named by its path inside the project.
#[derive(Debug)]
struct InspectionDiagnostic {
    path: String,
    condition: Inspection,
}

#[derive(Clone, Copy, Debug)]
enum Inspection {
    /// The project root is a link or not a directory.
    NotDirectory,
    /// An entry is a link, a hard-linked file, or a special file.
    NotPlain,
    /// A file is larger than its directory takes.
    TooLarge,
    /// A directory holds an entry its layout does not take.
    UnexpectedFile,
    /// An entry changed while the project was being captured.
    Changed,
}

impl InspectionDiagnostic {
    fn at(relative: &Path, condition: Inspection) -> Self {
        Self {
            path: relative.to_string_lossy().into_owned(),
            condition,
        }
    }

    fn parts(&self) -> (&'static str, &'static str, &'static str) {
        match self.condition {
            Inspection::NotDirectory => (
                "evidence.project.not-directory",
                "the project path is not a plain directory",
                "Pass the path of the project directory itself, not a link to it or a file.",
            ),
            Inspection::NotPlain => (
                "evidence.project.not-plain-file",
                "the project entry is a link, a hard-linked file, or a special file",
                "Replace the entry with a plain file or directory of its own inside the project.",
            ),
            Inspection::TooLarge => (
                "evidence.project.file-too-large",
                "the file is larger than its project directory takes",
                "Split or reduce the file; the authoring project reference lists each directory's limit.",
            ),
            Inspection::UnexpectedFile => (
                "evidence.project.unexpected-file",
                "the project directory holds an entry its layout does not take",
                "Remove the entry, or rename it with the extension its directory takes.",
            ),
            Inspection::Changed => (
                "evidence.project.changed",
                "the project entry changed while the project was being read",
                "Rerun the command once nothing else is writing to the project.",
            ),
        }
    }

    /// The diagnostic, naming the entry by its path inside the project.
    fn diagnostic(&self) -> Diagnostic {
        let (code, message, action) = self.parts();
        authored::file_diagnostic(Severity::Error, code, None, &self.path, "", message, action)
    }

    /// The diagnostic, naming the entry from the project path as given.
    fn diagnostic_in(&self, project: &Path) -> Diagnostic {
        let report = authored::rebase(Report::new(vec![self.diagnostic()]), project);
        report
            .into_diagnostics()
            .pop()
            .expect("one diagnostic was rebased")
    }
}

impl std::fmt::Display for InspectionDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.parts().1)
    }
}

impl std::error::Error for InspectionDiagnostic {}

/// Whether a declared project artifact is present, absent, or reached
/// through something other than plain in-project directories and files.
enum Asset {
    Present,
    Missing,
    OutOfCustody,
}

fn asset(project: &Path, value: &str) -> Result<Asset> {
    match authoring::plain_project_asset_exists(project, value) {
        Ok(true) => Ok(Asset::Present),
        Ok(false) => Ok(Asset::Missing),
        Err(error) if is_operational(&error) => Err(error),
        Err(_) => Ok(Asset::OutOfCustody),
    }
}

const CUSTODY_MESSAGE: &str =
    "declared project artifacts must use plain in-project directories and files";
const CUSTODY_ACTION: &str =
    "Replace the artifact, and every directory above it, with a plain file or directory inside the project.";

/// Every declared reference in the project's sources and questions that
/// names an artifact outside its directory, missing, or out of custody. A
/// missing artifact is a warning: the project is incomplete, not wrong.
fn declared_asset_findings(project: &Path, inventory: &ProjectInventory) -> Result<Report> {
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
    let mut report = Report::default();
    for (file, source) in &inventory.source_documents {
        let diagnostic = |severity, code: &str, pointer: &str, message: &str, action: &str| {
            authored::file_diagnostic(severity, code, None, file, pointer, message, action)
        };
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
            let Some(value) = source.pointer(pointer).and_then(Value::as_str) else {
                continue;
            };
            if !authoring::valid_source_artifact_reference(value) {
                report.push(diagnostic(
                    Severity::Error,
                    "evidence.source.artifact-reference",
                    pointer,
                    "source artifact references must stay in their project artifact directory",
                    "Name a file inside the project's schemas, adapters, queries, or codelists directory.",
                ));
                continue;
            }
            match asset(project, value)? {
                Asset::Present => {}
                Asset::Missing => report.push(diagnostic(
                    Severity::Warning,
                    "evidence.source.asset-missing",
                    pointer,
                    "the source names an artifact that is not present in this project",
                    "Add the declared project-relative source artifact or correct the reference.",
                )),
                Asset::OutOfCustody => report.push(diagnostic(
                    Severity::Error,
                    "evidence.source.artifact-custody",
                    pointer,
                    CUSTODY_MESSAGE,
                    CUSTODY_ACTION,
                )),
            }
        }
    }
    for (file, question) in &inventory.question_documents {
        let diagnostic = |severity, code: &str, pointer: &str, message: &str, action: &str| {
            authored::file_diagnostic(
                severity,
                code,
                Some(QUESTION_KIND),
                file,
                pointer,
                message,
                action,
            )
        };
        if question.get("governance").is_none() {
            report.push(diagnostic(
                Severity::Warning,
                "evidence.question.governance-missing",
                "/governance",
                "the question has no deployment governance",
                "Add stable requirement, evidence type, fixture, and disclosure-family governance.",
            ));
        }
        if let Some(source) = question.pointer("/source/ref").and_then(Value::as_str) {
            if !source_ids.contains(source) {
                report.push(diagnostic(
                    Severity::Warning,
                    "evidence.question.source-missing",
                    "/source/ref",
                    "the question names a source that is not present in this project",
                    "Add the named sources/<id>.yaml artifact or correct the reference.",
                ));
            }
        }
        for (pointer, selector) in selector_profile_references(question) {
            if !selector_ids.contains(selector) {
                report.push(diagnostic(
                    Severity::Warning,
                    "evidence.question.selector-missing",
                    &pointer,
                    "the question names a selector profile that is not present in this project",
                    "Add the named selectors/<id>.yaml artifact or correct the reference.",
                ));
            }
        }
        if let Some(derivation) = question.get("derivation").and_then(Value::as_str) {
            if !authoring::valid_derivation_reference(derivation) {
                report.push(diagnostic(
                    Severity::Error,
                    "evidence.question.derivation-reference",
                    "/derivation",
                    "question derivation must stay in the project derivations directory",
                    "Name a derivations/<id>.rhai file inside the project.",
                ));
            } else {
                let id = Path::new(derivation)
                    .file_stem()
                    .and_then(|value| value.to_str());
                match asset(project, derivation)? {
                    Asset::OutOfCustody => report.push(diagnostic(
                        Severity::Error,
                        "evidence.question.derivation-custody",
                        "/derivation",
                        CUSTODY_MESSAGE,
                        CUSTODY_ACTION,
                    )),
                    Asset::Present if id.is_some_and(|id| derivation_ids.contains(id)) => {}
                    Asset::Present | Asset::Missing => report.push(diagnostic(
                        Severity::Warning,
                        "evidence.question.derivation-missing",
                        "/derivation",
                        "the question's derivation artifact is missing",
                        "Add the named derivations/<id>.rhai artifact or correct the reference.",
                    )),
                }
            }
        }
        if let Some(fixture) = question
            .pointer("/governance/fixtures")
            .and_then(Value::as_str)
        {
            if !authoring::valid_fixture_reference(fixture) {
                report.push(diagnostic(
                    Severity::Error,
                    "evidence.question.fixture-reference",
                    "/governance/fixtures",
                    "question fixture must stay in the project fixtures directory",
                    "Name a fixtures/<id>.yaml file inside the project.",
                ));
            } else {
                match asset(project, fixture)? {
                    Asset::Present => {}
                    Asset::Missing => report.push(diagnostic(
                        Severity::Warning,
                        "evidence.question.fixture-missing",
                        "/governance/fixtures",
                        "the question's declared fixture artifact is missing",
                        "Add the named fixtures/<id>.yaml artifact or correct the reference.",
                    )),
                    Asset::OutOfCustody => report.push(diagnostic(
                        Severity::Error,
                        "evidence.question.fixture-custody",
                        "/governance/fixtures",
                        CUSTODY_MESSAGE,
                        CUSTODY_ACTION,
                    )),
                }
            }
        }
        for (index, answer) in question
            .get("answers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            if answer.get("uri").is_none() {
                report.push(diagnostic(
                    Severity::Warning,
                    "evidence.answer.stable-id-missing",
                    &format!("/answers/{index}/uri"),
                    "the answer has no stable concept uri",
                    "Add the stable concept `uri` required for deployment authoring.",
                ));
            }
        }
    }
    Ok(report)
}

/// The subjects a question declares: its `subjects` list, or its one
/// `subject`, each with the pointer it is written at.
fn question_subjects(question: &Value) -> Vec<(String, &Value)> {
    match question.get("subjects").and_then(Value::as_array) {
        Some(subjects) => subjects
            .iter()
            .enumerate()
            .map(|(index, subject)| (format!("/subjects/{index}"), subject))
            .collect(),
        None => question
            .get("subject")
            .map(|subject| vec![("/subject".to_owned(), subject)])
            .unwrap_or_default(),
    }
}

/// Every selector profile a question's subjects name, each with the pointer
/// it is written at.
fn selector_profile_references(question: &Value) -> Vec<(String, &str)> {
    let mut references = Vec::new();
    for (pointer, subject) in question_subjects(question) {
        for (index, profile) in subject
            .get("profiles")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            if let Some(profile) = profile.as_str() {
                references.push((format!("{pointer}/profiles/{index}"), profile));
            }
        }
        if let Some(profile) = subject.get("profile").and_then(Value::as_str) {
            references.push((format!("{pointer}/profile"), profile));
        }
    }
    references
}

/// Read every authored file in the project through the shared reader,
/// reporting each problem to `gathered` and describing each document read.
fn inspect_project(project: &Path, gathered: &mut Gathered) -> Result<ProjectInventory> {
    let question_documents =
        authored_documents(project, QUESTIONS_DIRECTORY, gathered, |file, bytes| {
            checked(check_question(file, bytes).map(|decoded| decoded.document))
        })?;
    let questions = question_documents
        .iter()
        .map(|(file, value)| describe_question(&file_id(file), value))
        .collect();
    let source_documents = authored_documents(project, SOURCES_DIRECTORY, gathered, scanned)?;
    let sources = source_documents
        .iter()
        .map(|(file, value)| describe_source(&file_id(file), value))
        .collect();
    let selectors = authored_documents(project, SELECTORS_DIRECTORY, gathered, scanned)?
        .iter()
        .map(|(file, value)| {
            let fields = value
                .get("fields")
                .and_then(Value::as_object)
                .map(|fields| fields.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            json!({"id": file_id(file), "fields": fields})
        })
        .collect();
    let derivations = regular_files(project, DERIVATIONS_DIRECTORY, "rhai", gathered)?
        .iter()
        .map(|file| json!({"id": file_id(file), "path": file}))
        .collect::<Vec<_>>();
    let policies_directory = format!("{ACCESS_DIRECTORY}/{ACCESS_POLICIES_DIRECTORY}");
    let policies = authored_documents(project, &policies_directory, gathered, |file, bytes| {
        checked(check_access_policy(file, bytes).map(|decoded| decoded.document))
    })?
    .iter()
    .map(|(file, value)| {
        json!({
            "id": file_id(file),
            "questions": value.get("questions").cloned().unwrap_or_else(|| json!([])),
        })
    })
    .collect::<Vec<_>>();
    let clients_directory = format!("{ACCESS_DIRECTORY}/clients");
    let clients = authored_documents(project, &clients_directory, gathered, |file, bytes| {
        checked(crate::access::check_client_document(file, bytes))
    })?
    .iter()
    .map(|(file, _)| json!({"id": file_id(file), "path": file}))
    .collect::<Vec<_>>();
    Ok(ProjectInventory {
        questions,
        sources,
        selectors,
        derivations,
        local_access: json!({"policies": policies, "clients": clients}),
        question_documents,
        source_documents,
    })
}

/// Read every YAML file under `targets/` and `mocks/`, and every YAML file
/// at the project root other than the marker and the OpenAPI description,
/// each identified by its envelope (CFG-CHECK-2). Problems are reported to
/// `gathered`, except that a root file holding no format the project reads
/// is returned as a warning, kept aside so it does not hold back the compile
/// the check runs once nothing else is found.
fn inspect_project_files(project: &Path, gathered: &mut Gathered) -> Result<Report> {
    for directory in [TARGETS_DIRECTORY, MOCKS_DIRECTORY] {
        for file in yaml_files_under(project, Path::new(directory), gathered)? {
            let bytes = authored::read_authored_file(&project.join(&file), "project file")?;
            gathered.read_one();
            gathered.extend(if directory == TARGETS_DIRECTORY {
                check_target_file(project, &file, &bytes)
            } else {
                check_mock_file(&file, &bytes)
            });
        }
    }
    let mut aside = Report::default();
    for file in root_yaml_files(project)? {
        let bytes = authored::read_authored_file(&project.join(&file), "project file")?;
        gathered.read_one();
        let scanned = Reader::new(&file).scan(&bytes);
        let root = scanned.as_ref().ok().and_then(Option::as_ref);
        if let Some((kind, action)) = root.and_then(kind_of).and_then(home_of) {
            gathered.push(misplaced(&file, kind, "at the project root", action));
        } else if root.and_then(|root| root.get("openapi")).is_none() {
            aside.push(unidentified(&file, Severity::Warning));
        }
    }
    Ok(aside)
}

/// The YAML files and links under `directory` of the captured project, by
/// their names inside the project, at any depth. A link is reported to
/// `gathered`; other files were never captured.
fn yaml_files_under(
    project: &Path,
    directory: &Path,
    gathered: &mut Gathered,
) -> Result<Vec<String>> {
    let path = project.join(directory);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("inspecting {}", path.display())),
    };
    if !metadata.is_dir() {
        gathered.push(InspectionDiagnostic::at(directory, Inspection::NotPlain).diagnostic());
        return Ok(Vec::new());
    }
    let mut names = fs::read_dir(&path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    names.sort();
    let mut files = Vec::new();
    for name in names {
        let relative = directory.join(&name);
        let metadata = fs::symlink_metadata(project.join(&relative))?;
        if metadata.is_dir() {
            files.extend(yaml_files_under(project, &relative, gathered)?);
        } else if metadata.file_type().is_symlink() || !metadata.is_file() {
            gathered.push(InspectionDiagnostic::at(&relative, Inspection::NotPlain).diagnostic());
        } else {
            files.push(relative.to_string_lossy().into_owned());
        }
    }
    Ok(files)
}

/// The YAML files captured at the project root, other than the marker and
/// the OpenAPI description, by name.
fn root_yaml_files(project: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(project)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == PROJECT_MARKER_FILE
            || name == OPENAPI_FILE
            || !is_yaml_name(&name)
            || entry.file_type()?.is_dir()
        {
            continue;
        }
        files.push(name.to_string_lossy().into_owned());
    }
    files.sort();
    Ok(files)
}

/// The `kind` a scanned document declares, when it declares one as text.
fn kind_of(root: &Node) -> Option<&str> {
    match &root.get("kind")?.value.value {
        NodeValue::String(text) => Some(text.text.as_str()),
        _ => None,
    }
}

/// An Evidence format by its kind, with the change that puts a file of it
/// where the project reads it.
fn home_of(kind: &str) -> Option<(&'static str, &'static str)> {
    [
        (
            AUTHORING_PROJECT_KIND,
            "Keep one evidence-project.yaml, at the project root, and remove this copy.",
        ),
        (
            QUESTION_KIND,
            "Move the file into questions/, named by the question id.",
        ),
        (
            ACCESS_POLICY_KIND,
            "Move the file into access/policies/, named by the policy id.",
        ),
        (ACCESS_CLIENT_KIND, "Move the file into access/clients/."),
        (
            TARGET_GOVERNANCE_KIND,
            "Move the file into a target directory under targets/, named governance.yaml.",
        ),
        (
            TARGET_SETTINGS_KIND,
            "Move the file into a target directory under targets/, named settings.yaml.",
        ),
        (
            EVIDENCE_RUNTIME_KIND,
            "Move the file into a target directory under targets/, named runtime.yaml.",
        ),
        (MOCK_PLAN_KIND, "Move the file into mocks/."),
    ]
    .into_iter()
    .find(|(known, _)| *known == kind)
}

/// A file holding an Evidence format somewhere the project does not read it.
fn misplaced(file: &str, kind: &str, place: &str, action: &str) -> Diagnostic {
    authored::file_diagnostic(
        Severity::Error,
        "evidence.project.misplaced-file",
        None,
        file,
        "/kind",
        &format!("an {kind} document does not belong {place}"),
        action,
    )
}

/// A YAML file in the project that declares no format the project reads.
fn unidentified(file: &str, severity: Severity) -> Diagnostic {
    authored::file_diagnostic(
        severity,
        "evidence.project.unidentified-file",
        None,
        file,
        "",
        "the file has no apiVersion and kind of a format the Evidence project reads",
        "Add the apiVersion and kind lines of the format the file holds, or move the file out of the project.",
    )
}

/// Check one YAML file under `targets/`: target settings, governance, or a
/// runtime document, by its kind, or by its name when it declares none.
fn check_target_file(project: &Path, file: &str, bytes: &[u8]) -> Report {
    let scanned = Reader::new(file).scan(bytes);
    let kind = scanned
        .as_ref()
        .ok()
        .and_then(Option::as_ref)
        .and_then(kind_of);
    let name = Path::new(file)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    match kind {
        Some(TARGET_SETTINGS_KIND) => return check_settings_file(project, file, bytes),
        Some(TARGET_GOVERNANCE_KIND) => return check_governance_file(file, bytes),
        Some(EVIDENCE_RUNTIME_KIND) => return check_runtime_file(file, bytes),
        _ => {}
    }
    if let Some((kind, action)) = kind.and_then(home_of) {
        return Report::new(vec![misplaced(file, kind, "under targets/", action)]);
    }
    match (name, scanned) {
        ("settings.yaml", _) => check_settings_file(project, file, bytes),
        ("governance.yaml", _) => check_governance_file(file, bytes),
        ("runtime.yaml", _) => check_runtime_file(file, bytes),
        (_, Err(report)) => report,
        (_, Ok(_)) => Report::new(vec![unidentified(file, Severity::Error)]),
    }
}

/// Check one YAML file under `mocks/` as a mock plan. Its references to the
/// OpenAPI description and response bodies are checked by
/// `evidencectl source mock check`.
fn check_mock_file(file: &str, bytes: &[u8]) -> Report {
    let kind = Reader::new(file)
        .scan(bytes)
        .ok()
        .flatten()
        .and_then(|root| kind_of(&root).and_then(home_of));
    match kind {
        Some((kind, action)) if kind != MOCK_PLAN_KIND => {
            Report::new(vec![misplaced(file, kind, "under mocks/", action)])
        }
        _ => source_mock::check_plan_document(file, bytes),
    }
}

/// Check target settings as `target new` reads them, each problem placed at
/// the member it names.
fn check_settings_file(project: &Path, file: &str, bytes: &[u8]) -> Report {
    const ACTION: &str = "Correct the named member of the target settings so it holds the closed deployment governance and runtime shapes, then check again.";
    let decoded = match decode_authored::<target::TargetSettings>(file, bytes, &TARGET_SETTINGS) {
        Ok(decoded) => decoded,
        Err(report) => return report,
    };
    let document = &decoded.document;
    let mut found = document.warnings();
    let local = decoded
        .value
        .governance
        .get("assuranceProfile")
        .and_then(Value::as_str)
        == Some("local");
    let mut refused = Vec::new();
    if let Err(report) = document.decode_at::<build::TargetGovernance>("/governance") {
        refused.extend(report.into_diagnostics());
    }
    if let Err(report) = document.decode_at::<target::TargetRuntime>("/runtime") {
        refused.extend(report.into_diagnostics());
    }
    // The decodes repeat the document's warnings, already reported above.
    // A local target's runtime may leave out the paths `target new --local`
    // fills; whether anything is still missing is judged once they are.
    refused.retain(|diagnostic| {
        diagnostic.severity == Severity::Error
            && !(local && diagnostic.code == "config.missing-key")
    });
    if !refused.is_empty() {
        found.extend(Report::new(refused));
        return found;
    }
    let Err(error) = target::validate_project_settings(
        project,
        &decoded.value.governance,
        &decoded.value.runtime,
    ) else {
        return found;
    };
    let diagnostic =
        if let Some(diagnostic) = governance_diagnostic(document, "/governance", &error) {
            diagnostic
        } else if let Some(settings) = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<target::SettingsDiagnostic>())
        {
            document.diagnostic_at_value(
                Severity::Error,
                "evidence.target-settings.invalid",
                &settings.pointer,
                &settings.message,
                ACTION,
            )
        } else {
            document.diagnostic_at_value(
            Severity::Error,
            "evidence.target-settings.invalid",
            "",
            "the target settings do not hold the closed deployment governance and runtime shapes",
            ACTION,
        )
        };
    found.push(diagnostic);
    found
}

/// Check target governance as `--target` reads it.
fn check_governance_file(file: &str, bytes: &[u8]) -> Report {
    let decoded = match decode_authored::<build::TargetGovernance>(file, bytes, &TARGET_GOVERNANCE)
    {
        Ok(decoded) => decoded,
        Err(report) => return report,
    };
    let mut found = decoded.document.warnings();
    let document = decoded.document;
    if let Err(error) = decoded.value.into_bundle() {
        found.push(
            governance_diagnostic(&document, "", &error).unwrap_or_else(|| {
                document.diagnostic_at_value(
                    Severity::Error,
                    "evidence.target.incomplete",
                    "",
                    "the deployment governance does not match the closed offline validation contract",
                    target_action(""),
                )
            }),
        );
    }
    found
}

/// The governance refusal in `error`, placed in `document` below `base`,
/// the pointer of the governance mapping.
fn governance_diagnostic(
    document: &Document,
    base: &str,
    error: &anyhow::Error,
) -> Option<Diagnostic> {
    let refused = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<build::TargetDocumentDiagnostic>())?;
    let pointer = refused
        .path
        .split_once(':')
        .map_or("", |(_, pointer)| pointer);
    Some(document.diagnostic_at_value(
        Severity::Error,
        refused.code,
        &format!("{base}{pointer}"),
        &refused.message,
        target_action(refused.code),
    ))
}

/// Check a deployment runtime document against the published runtime
/// contract, as `--target` does, without resolving any reference in it.
fn check_runtime_file(file: &str, bytes: &[u8]) -> Report {
    match validate_runtime_structure(file, bytes) {
        Ok(()) => Report::default(),
        Err(error) => {
            if let Some(report) = authored::report_in(&error) {
                return report.clone();
            }
            let pointer = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<RuntimeStructureDiagnostic>())
                .map_or_else(String::new, |runtime| runtime.pointer.clone());
            Report::new(vec![authored::file_diagnostic(
                Severity::Error,
                "evidence.target.runtime-structure",
                None,
                file,
                &pointer,
                &error.to_string(),
                target_action(""),
            )])
        }
    }
}

/// A read of one authored file: the document as a value and the warnings
/// the reader found in it, or every problem that refused it.
type Read = std::result::Result<(Value, Report), Report>;

/// A file read through the shared YAML subset alone, for a format whose
/// grammar the compiler holds.
fn scanned(file: &str, bytes: &[u8]) -> Read {
    scan_authored(file, bytes).map(|node| (authored::node_value(node), Report::default()))
}

/// A file checked as one enveloped authored format, every member decoded.
fn checked(read: std::result::Result<Document, Report>) -> Read {
    read.map(|document| (document.to_json_value(), document.warnings()))
}

fn describe_question(id: &str, value: &Value) -> Value {
    let subjects = question_subjects(value);
    let selectors = subjects
        .iter()
        .filter_map(|(_, subject)| subject.get("selector").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let selector_profiles = selector_profile_references(value)
        .into_iter()
        .map(|(_, profile)| profile)
        .collect::<Vec<_>>();
    json!({
        "id": value.get("id").and_then(Value::as_str).unwrap_or(id),
        "source": value.pointer("/source/ref").and_then(Value::as_str),
        "selectors": selectors,
        "selectorProfiles": selector_profiles,
        "derivation": value.get("derivation").and_then(Value::as_str),
        "answers": value
            .get("answers")
            .and_then(Value::as_array)
            .map(|answers| {
                answers
                    .iter()
                    .filter_map(|answer| answer.get("concept").and_then(Value::as_str))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        "responseFormats": value
            .get("responseFormats")
            .cloned()
            .unwrap_or_else(|| json!(["signed-jws"])),
    })
}

fn describe_source(id: &str, value: &Value) -> Value {
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
        "connectionRef": value
            .get("connection")
            .or_else(|| value.get("connectionRef"))
            .and_then(Value::as_str),
        "posture": value.get("posture").and_then(Value::as_str),
        "references": references,
    })
}

/// The id a file's name gives it: its name without the extension.
fn file_id(file: &str) -> String {
    Path::new(file)
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Every YAML file in `directory`, read through `read`. A file `read`
/// refuses is reported to `gathered` with every problem found in it, and the
/// rest are returned by their file names inside the project, their warnings
/// reported to `gathered` too.
fn authored_documents(
    project: &Path,
    directory: &str,
    gathered: &mut Gathered,
    read: impl Fn(&str, &[u8]) -> Read,
) -> Result<Vec<(String, Value)>> {
    let mut documents = Vec::new();
    for file in regular_files(project, directory, "yaml", gathered)? {
        let bytes = authored::read_authored_file(&project.join(&file), "authored file")?;
        gathered.read_one();
        match read(&file, &bytes) {
            Ok((value, warnings)) => {
                gathered.extend(warnings);
                documents.push((file, value));
            }
            Err(report) => gathered.extend(report),
        }
    }
    Ok(documents)
}

fn read_bounded_descriptor(
    descriptor: rustix::fd::OwnedFd,
    bound: Bound,
    relative: &Path,
) -> Result<Vec<u8>> {
    let mut file = File::from(descriptor);
    let metadata = file.metadata().context("inspecting authored input")?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(InspectionDiagnostic::at(relative, Inspection::NotPlain).into());
    }
    let limit = match bound {
        Bound::ForReader => u64::try_from(MAXIMUM_DOCUMENT_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
        Bound::Refuse(maximum) => {
            if metadata.len() > maximum {
                return Err(InspectionDiagnostic::at(relative, Inspection::TooLarge).into());
            }
            maximum.saturating_add(1)
        }
    };
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .context("reading authored input")?;
    if let Bound::Refuse(maximum) = bound {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
            return Err(InspectionDiagnostic::at(relative, Inspection::TooLarge).into());
        }
    }
    Ok(bytes)
}

/// The plain files with `extension` in a project directory, by their names
/// inside the project. Every other entry is reported to `gathered`.
fn regular_files(
    project: &Path,
    directory: &str,
    extension: &str,
    gathered: &mut Gathered,
) -> Result<Vec<String>> {
    let path = project.join(directory);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("inspecting {}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        gathered.push(
            InspectionDiagnostic::at(Path::new(directory), Inspection::NotPlain).diagnostic(),
        );
        return Ok(Vec::new());
    }
    let mut names = fs::read_dir(&path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    names.sort();
    let mut files = Vec::new();
    for name in names {
        let relative = Path::new(directory).join(&name);
        let metadata = fs::symlink_metadata(path.join(&name))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            gathered.push(InspectionDiagnostic::at(&relative, Inspection::NotPlain).diagnostic());
        } else if relative.extension().and_then(OsStr::to_str) != Some(extension) {
            gathered
                .push(InspectionDiagnostic::at(&relative, Inspection::UnexpectedFile).diagnostic());
        } else {
            files.push(relative.to_string_lossy().into_owned());
        }
    }
    Ok(files)
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

#[cfg(test)]
mod tests {
    use super::*;
    use registry_evidence_authoring::formats::{ACCESS_POLICY_API_VERSION, QUESTION_API_VERSION};
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

    fn sqlite_template(project: &Path) {
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/sqlite-extract"),
            project,
        );
    }

    /// A question document with its envelope, followed by `body`.
    fn question(body: &str) -> String {
        format!("apiVersion: {QUESTION_API_VERSION}\nkind: {QUESTION_KIND}\n{body}")
    }

    /// The diagnostics a refused check carries.
    fn refused(error: anyhow::Error) -> Report {
        authored::report_in(&error)
            .cloned()
            .unwrap_or_else(|| panic!("a refused check carries diagnostics: {error:#}"))
    }

    /// Each diagnostic's code, the file it names inside `base`, and its path.
    fn sites(report: &Report, base: &Path) -> Vec<(String, String, String)> {
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| {
                let file = diagnostic
                    .source
                    .as_ref()
                    .map(|source| {
                        let file = Path::new(&source.file);
                        file.strip_prefix(base)
                            .unwrap_or(file)
                            .to_string_lossy()
                            .into_owned()
                    })
                    .unwrap_or_default();
                (diagnostic.code.clone(), file, diagnostic.path.clone())
            })
            .collect()
    }

    fn reports(report: &Report, base: &Path, code: &str, file: &str, path: &str) -> bool {
        sites(report, base)
            .iter()
            .any(|site| site.0 == code && site.1 == file && site.2 == path)
    }

    /// `report` in both output forms, for a check that a value is never
    /// repeated.
    fn printed(report: &Report) -> String {
        format!("{}\n{}", report.to_json_value(), report.render_human())
    }

    #[test]
    fn the_template_marker_is_the_marker_new_writes() {
        assert_eq!(
            include_str!("../templates/sqlite-extract/evidence-project.yaml"),
            registry_evidence_authoring::default_project_marker_document()
        );
    }

    #[test]
    fn incomplete_project_is_visible_without_a_deployment_claim() {
        let temporary = temporary();
        put_marker(temporary.path());
        fs::create_dir(temporary.path().join("questions")).unwrap();

        let checked = check(temporary.path(), None, false, false).unwrap();

        assert_eq!(checked.report["status"], "incomplete");
        assert_eq!(checked.report["proof"], "authoring");
        assert_eq!(checked.report["fixtureProof"], false);
        assert_eq!(
            sites(&checked.diagnostics, temporary.path()),
            [(
                "evidence.question.missing".to_owned(),
                "questions".to_owned(),
                String::new()
            )]
        );
        assert_eq!(checked.report["diagnostics"][0]["severity"], "warning");
        assert_eq!(
            checked.report["diagnostics"][0]["code"],
            "evidence.question.missing"
        );
    }

    #[test]
    fn a_check_report_carries_the_shared_diagnostic_shape() {
        let temporary = temporary();
        put_marker(temporary.path());
        fs::create_dir(temporary.path().join("questions")).unwrap();

        let checked = check(temporary.path(), None, false, false).unwrap();

        assert!(checked.report.get("findings").is_none());
        let allowed = BTreeSet::from([
            "artifact",
            "code",
            "message",
            "path",
            "related",
            "severity",
            "source",
            "suggestedAction",
        ]);
        for diagnostic in checked.report["diagnostics"].as_array().unwrap() {
            for key in diagnostic.as_object().unwrap().keys() {
                assert!(allowed.contains(key.as_str()), "{key}");
            }
        }
        let human = checked.diagnostics.render_human();
        assert!(human.starts_with("warning[evidence.question.missing] "));
        assert!(
            human.ends_with("0 errors, 1 warning in 1 file\n"),
            "{human}"
        );
    }

    #[test]
    fn target_bound_source_is_valid_authoring_with_incomplete_target_closure() {
        let temporary = temporary();
        sqlite_template(temporary.path());
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

        let checked = check(temporary.path(), None, false, false)
            .expect("a valid authored connection reference is not refused");

        assert_eq!(checked.report["status"], "incomplete");
        assert_eq!(checked.report["proof"], "authoring");
        assert_eq!(checked.report["packageDigest"], Value::Null);
        assert_eq!(
            sites(&checked.diagnostics, temporary.path()),
            [(
                "evidence.target.source-connection-required".to_owned(),
                "sources/record-status.yaml".to_owned(),
                "/connection".to_owned()
            )]
        );
        assert!(!printed(&checked.diagnostics).contains("records"));

        let denied = refused(
            check(temporary.path(), None, false, true)
                .expect_err("--deny-warnings refuses incomplete target closure"),
        );
        assert_eq!(denied.error_count(), 0);
        assert_eq!(denied.warning_count(), 1);
    }

    #[test]
    fn a_retired_project_marker_is_refused_for_its_missing_envelope() {
        let temporary = temporary();
        fs::write(
            temporary.path().join(PROJECT_MARKER_FILE),
            "version: 1\nproject: evidence-authoring\n",
        )
        .unwrap();

        let report = refused(check(temporary.path(), None, false, false).unwrap_err());
        assert_eq!(
            sites(&report, temporary.path()),
            [
                (
                    "config.missing-envelope".to_owned(),
                    PROJECT_MARKER_FILE.to_owned(),
                    String::new()
                ),
                (
                    "config.removed-key".to_owned(),
                    PROJECT_MARKER_FILE.to_owned(),
                    "/version".to_owned()
                ),
                (
                    "config.removed-key".to_owned(),
                    PROJECT_MARKER_FILE.to_owned(),
                    "/project".to_owned()
                )
            ]
        );
    }

    #[test]
    fn a_marker_keeping_its_retired_keys_names_each_one() {
        let temporary = temporary();
        fs::write(
            temporary.path().join(PROJECT_MARKER_FILE),
            format!(
                "{}version: 1\nproject: evidence-authoring\n",
                registry_evidence_authoring::default_project_marker_document()
            ),
        )
        .unwrap();

        let report = refused(check(temporary.path(), None, false, false).unwrap_err());
        for path in ["/version", "/project"] {
            assert!(
                reports(
                    &report,
                    temporary.path(),
                    "config.removed-key",
                    PROJECT_MARKER_FILE,
                    path
                ),
                "{:?}",
                sites(&report, temporary.path())
            );
        }
    }

    #[test]
    fn an_unparseable_project_marker_is_refused_at_the_document() {
        let temporary = temporary();
        fs::write(
            temporary.path().join(PROJECT_MARKER_FILE),
            "- not a mapping\n",
        )
        .unwrap();

        let report = refused(check(temporary.path(), None, false, false).unwrap_err());
        let (code, file, path) = &sites(&report, temporary.path())[0];
        assert!(code.starts_with("config."), "{code}");
        assert_eq!(file, PROJECT_MARKER_FILE);
        assert_eq!(path, "");
    }

    #[test]
    fn malformed_question_is_a_domain_refusal_for_an_ordinary_check() {
        let temporary = temporary();
        put_marker(temporary.path());
        fs::create_dir(temporary.path().join("questions")).unwrap();
        fs::write(temporary.path().join("questions/broken.yaml"), "id: [\n").unwrap();

        let report = refused(check(temporary.path(), None, false, false).unwrap_err());
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.severity, Severity::Error);
        assert!(diagnostic.code.starts_with("yaml."), "{}", diagnostic.code);
        assert_eq!(
            sites(&report, temporary.path())[0].1,
            "questions/broken.yaml"
        );
        assert!(diagnostic.source.as_ref().unwrap().line.is_some());
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

        let report = refused(check(temporary.path(), None, false, false).unwrap_err());
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.severity, Severity::Error);
        assert!(diagnostic.code.starts_with("yaml."), "{}", diagnostic.code);
        assert_eq!(sites(&report, temporary.path())[0].1, "sources/broken.yaml");
    }

    #[test]
    fn every_problem_in_every_file_is_reported_in_one_run() {
        let temporary = temporary();
        put_marker(temporary.path());
        fs::create_dir(temporary.path().join("questions")).unwrap();
        fs::write(
            temporary.path().join("questions/first.yaml"),
            question("id: first\nfirstUnknown: 1\nsecondUnknown: 2\n"),
        )
        .unwrap();
        fs::write(temporary.path().join("questions/second.yaml"), "id: [\n").unwrap();

        let report = refused(check(temporary.path(), None, false, false).unwrap_err());
        for path in ["/firstUnknown", "/secondUnknown"] {
            assert!(
                reports(
                    &report,
                    temporary.path(),
                    "config.unknown-key",
                    "questions/first.yaml",
                    path
                ),
                "{:?}",
                sites(&report, temporary.path())
            );
        }
        assert!(sites(&report, temporary.path())
            .iter()
            .any(|site| site.1 == "questions/second.yaml"));
    }

    #[test]
    fn a_substitution_in_an_authored_file_is_refused_where_it_is_written() {
        let temporary = temporary();
        sqlite_template(temporary.path());
        let path = temporary.path().join("questions/record-status.yaml");
        let replaced = fs::read_to_string(&path).unwrap().replace(
            "purpose: record-status-check",
            "purpose: ${SUBSTITUTION_CANARY}",
        );
        fs::write(&path, replaced).unwrap();

        let report = refused(check(temporary.path(), None, false, false).unwrap_err());
        assert!(
            reports(
                &report,
                temporary.path(),
                "config.substitution-not-allowed",
                "questions/record-status.yaml",
                "/purpose"
            ),
            "{:?}",
            sites(&report, temporary.path())
        );
        assert!(!printed(&report).contains("SUBSTITUTION_CANARY"));
    }

    /// The template question padded with comment lines to exactly `size`
    /// bytes.
    fn padded_question(size: usize) -> Vec<u8> {
        let mut document = include_str!("../templates/sqlite-extract/questions/record-status.yaml")
            .as_bytes()
            .to_vec();
        let line = format!("# {}\n", "x".repeat(61));
        while document.len() + line.len() <= size {
            document.extend_from_slice(line.as_bytes());
        }
        let rest = size - document.len();
        if rest > 0 {
            document.push(b'#');
            document.extend(std::iter::repeat_n(b'x', rest - 1));
        }
        assert_eq!(document.len(), size);
        document
    }

    #[test]
    fn an_authored_file_at_the_reader_limit_is_read_and_one_byte_more_is_refused() {
        let temporary = temporary();
        sqlite_template(temporary.path());
        // Without its fixture the project stops at a warning, before the
        // compile that needs the runtime binary.
        fs::remove_file(temporary.path().join("fixtures/record-status.yaml")).unwrap();
        let path = temporary.path().join("questions/record-status.yaml");

        fs::write(&path, padded_question(MAXIMUM_DOCUMENT_BYTES)).unwrap();
        let checked = check(temporary.path(), None, false, false)
            .expect("a question of exactly the reader limit is read");
        assert!(!checked
            .diagnostics
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "yaml.too-large"));

        fs::write(&path, padded_question(MAXIMUM_DOCUMENT_BYTES + 1)).unwrap();
        let report = refused(check(temporary.path(), None, false, false).unwrap_err());
        assert_eq!(
            sites(&report, temporary.path()),
            [(
                "yaml.too-large".to_owned(),
                "questions/record-status.yaml".to_owned(),
                String::new()
            )]
        );
    }

    #[test]
    fn oversized_authored_yaml_is_refused_by_the_shared_reader() {
        for relative in [
            "questions/oversized.yaml",
            "sources/oversized.yaml",
            "selectors/oversized.yaml",
            "access/policies/oversized.yaml",
        ] {
            let temporary = temporary();
            put_marker(temporary.path());
            let path = temporary.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, vec![b'x'; MAXIMUM_DOCUMENT_BYTES + 1]).unwrap();

            let report = refused(check(temporary.path(), None, false, false).unwrap_err());
            assert!(
                reports(&report, temporary.path(), "yaml.too-large", relative, ""),
                "{:?}",
                sites(&report, temporary.path())
            );
        }
    }

    #[test]
    fn project_snapshot_cleanup_removes_sealed_success_and_partial_refusal_trees() {
        let temporary = temporary();
        let project = temporary.path().join("project");
        fs::create_dir_all(project.join("derivations")).unwrap();
        put_marker(&project);

        let snapshot = capture_project_in(&project, temporary.path()).unwrap();
        let snapshot_path = snapshot._temporary.path().to_path_buf();
        assert!(snapshot_path.exists());
        drop(snapshot);
        assert!(!snapshot_path.exists());

        fs::write(
            project.join("derivations/oversized.rhai"),
            vec![b'x'; usize::try_from(MAX_DERIVATION_BYTES).unwrap() + 1],
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

        let report = refused(check(&project, None, false, false).unwrap_err());
        assert_eq!(sites(&report, &project)[0].1, "access");
        assert!(!printed(&report).contains(CANARY));
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

        let mut capture = Capture {
            root: snapshot.clone(),
            directories: vec![snapshot.clone(), snapshot.join("questions")],
            files: 0,
        };
        capture_directory_contents(
            &questions,
            &mut capture,
            Path::new("questions"),
            Bound::ForReader,
        )
        .unwrap();

        assert!(snapshot.join("questions/captured.yaml").exists());
        assert!(!snapshot.join(format!("questions/{CANARY}.yaml")).exists());
        assert_eq!(capture.files, 1);
    }

    #[test]
    fn typed_question_refusal_does_not_disclose_the_rejected_value() {
        const CANARY: &str = "QUESTION_SECRET_CANARY";
        let temporary = temporary();
        sqlite_template(temporary.path());
        let path = temporary.path().join("questions/record-status.yaml");
        let question = fs::read_to_string(&path).unwrap().replace(
            "purpose: record-status-check",
            &format!("purpose: [{CANARY}]"),
        );
        assert!(question.contains(CANARY));
        fs::write(&path, question).unwrap();

        for error in [
            check(temporary.path(), None, false, false).map(|_| ()),
            explain(temporary.path(), None).map(|_| ()),
        ] {
            let report = refused(error.unwrap_err());
            assert!(!printed(&report).contains(CANARY));
            let (code, file, path) = &sites(&report, temporary.path())[0];
            assert!(code.starts_with("config."), "{code}");
            assert_eq!(file, "questions/record-status.yaml");
            assert_eq!(path, "/purpose");
        }
    }

    fn reference_target(target: &Path, governance: impl FnOnce(String) -> String) {
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../products/evidence/reference/deployment-targets/environments/production/evidence",
            ),
            target,
        );
        let path = target.join("governance.yaml");
        let replaced = governance(fs::read_to_string(&path).unwrap());
        fs::write(&path, replaced).unwrap();
    }

    #[test]
    fn typed_target_refusal_does_not_disclose_the_rejected_value() {
        const CANARY: &str = "TARGET_SECRET_CANARY";
        let temporary = temporary();
        let project = temporary.path().join("project");
        let target = temporary.path().join("target");
        fs::create_dir_all(project.join("questions")).unwrap();
        put_marker(&project);
        reference_target(&target, |governance| {
            let replaced = governance.replace(
                "assuranceProfile: evidence-grade",
                &format!("assuranceProfile: [{CANARY}]"),
            );
            assert!(replaced.contains(CANARY));
            replaced
        });

        for error in [
            check(&project, Some(&target), false, false).map(|_| ()),
            explain(&project, Some(&target)).map(|_| ()),
        ] {
            let report = refused(error.unwrap_err());
            assert!(!printed(&report).contains(CANARY));
            let (code, file, path) = &sites(&report, &target)[0];
            assert!(code.starts_with("config."), "{code}");
            assert_eq!(file, "governance.yaml");
            assert_eq!(path, "/assuranceProfile");
        }
    }

    /// A project with a marker, an empty questions directory, and `files`.
    fn project_with(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let temporary = temporary();
        put_marker(temporary.path());
        fs::create_dir(temporary.path().join("questions")).unwrap();
        for (file, bytes) in files {
            let path = temporary.path().join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        temporary
    }

    fn starter_settings() -> String {
        fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/breg/evidence/starter/targets/local/settings.yaml"),
        )
        .unwrap()
    }

    #[test]
    fn target_settings_in_the_project_are_read_by_their_envelope() {
        const SETTINGS: &str = "targets/local/settings.yaml";
        let clean = project_with(&[(SETTINGS, starter_settings().as_bytes())]);
        let checked = check(clean.path(), None, false, false).unwrap();
        assert_eq!(
            sites(&checked.diagnostics, clean.path()),
            [(
                "evidence.question.missing".to_owned(),
                "questions".to_owned(),
                String::new()
            )]
        );

        for (edit, code, path) in [
            (
                starter_settings() + "formatVersion: 1\n",
                "config.removed-key",
                "/formatVersion",
            ),
            (
                starter_settings().replace("assuranceProfile: local", "assuranceProfile: staging"),
                "evidence.target.assurance-profile",
                "/governance/assuranceProfile",
            ),
            (
                starter_settings().replace("kind: EvidenceRuntimeConfig", "kind: Elsewhere"),
                "evidence.target-settings.invalid",
                "/runtime/kind",
            ),
        ] {
            let project = project_with(&[(SETTINGS, edit.as_bytes())]);
            let report = refused(check(project.path(), None, false, false).unwrap_err());
            assert!(
                reports(&report, project.path(), code, SETTINGS, path),
                "{:?}",
                sites(&report, project.path())
            );
            let placed = report
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.code == code)
                .unwrap();
            assert!(placed.source.as_ref().unwrap().line.is_some());
        }
    }

    #[test]
    #[ignore = "run with EVIDENCE_BIN naming the evidence binary built from this commit"]
    fn the_reference_authoring_example_checks_with_no_diagnostic() {
        let example = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/reference/authoring-projects/example");
        let checked = check(&example, None, false, true).unwrap();
        assert!(
            checked.diagnostics.is_empty(),
            "{}",
            checked.diagnostics.render_human()
        );
    }

    #[test]
    fn a_local_settings_document_may_leave_out_the_paths_target_new_fills() {
        let settings = starter_settings()
            .replace("  package:\n    root: /absolute/path/to/package\n", "")
            .replace(
                "  audit:\n    path: /absolute/path/to/evidence/audit/evidence.jsonl\n",
                "",
            );
        assert!(!settings.contains("/absolute/path/to/package"));
        let project = project_with(&[("targets/local/settings.yaml", settings.as_bytes())]);
        let checked = check(project.path(), None, false, false).unwrap();
        assert_eq!(checked.diagnostics.error_count(), 0);
    }

    #[test]
    fn deployment_target_files_in_the_project_are_read_and_links_refused() {
        let temporary = project_with(&[]);
        let project = temporary.path();
        let mut bom = b"\xEF\xBB\xBF".to_vec();
        reference_target(&project.join("targets/production"), |governance| {
            bom.extend_from_slice(governance.as_bytes());
            governance
        });
        fs::write(project.join("targets/production/governance.yaml"), &bom).unwrap();
        fs::write(
            project.join("targets/production/public-keys/unread.jwk.json"),
            "not a key",
        )
        .unwrap();
        let checked = check(project, None, false, false).unwrap();
        assert_eq!(checked.diagnostics.error_count(), 0);

        symlink(
            project.join("targets/production/runtime.yaml"),
            project.join("targets/linked.yaml"),
        )
        .unwrap();
        let report = refused(check(project, None, false, false).unwrap_err());
        assert!(reports(
            &report,
            project,
            "evidence.project.not-plain-file",
            "targets/linked.yaml",
            ""
        ));
    }

    #[test]
    fn a_file_the_project_does_not_read_where_it_is_is_named() {
        let question = question("id: misplaced\n");
        let project = project_with(&[
            ("targets/local/question.yaml", question.as_bytes()),
            ("targets/local/notes.yml", b"note: kept by hand\n"),
            ("mocks/source.yaml", b"openapi: ../source.openapi.yaml\n"),
        ]);
        let report = refused(check(project.path(), None, false, false).unwrap_err());
        let sites = sites(&report, project.path());
        for (code, file, path) in [
            (
                "evidence.project.misplaced-file",
                "targets/local/question.yaml",
                "/kind",
            ),
            (
                "evidence.project.unidentified-file",
                "targets/local/notes.yml",
                "",
            ),
            ("config.missing-envelope", "mocks/source.yaml", ""),
        ] {
            assert!(
                sites
                    .iter()
                    .any(|site| site.0 == code && site.1 == file && site.2 == path),
                "{code} {file}: {sites:?}"
            );
        }
        let misplaced = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "evidence.project.misplaced-file")
            .unwrap();
        assert_eq!(misplaced.source.as_ref().unwrap().line, Some(2));
    }

    #[test]
    fn a_foreign_yaml_file_at_the_root_is_a_warning_and_the_check_goes_on() {
        let project = project_with(&[
            ("notes.yaml", b"owner: team\n"),
            (
                "openapi-copy.yaml",
                b"openapi: 3.1.0\ninfo: {title: t, version: '1'}\npaths: {}\n",
            ),
        ]);
        let checked = check(project.path(), None, false, false).unwrap();
        let sites = sites(&checked.diagnostics, project.path());
        assert!(sites.contains(&(
            "evidence.project.unidentified-file".to_owned(),
            "notes.yaml".to_owned(),
            String::new()
        )));
        assert!(!sites.iter().any(|site| site.1 == "openapi-copy.yaml"));
        assert_eq!(checked.diagnostics.error_count(), 0);
        assert!(check(project.path(), None, false, true).is_err());

        let marker = registry_evidence_authoring::default_project_marker_document();
        let copied = project_with(&[("evidence-project.yml", marker.as_bytes())]);
        let report = refused(check(copied.path(), None, false, false).unwrap_err());
        assert!(reports(
            &report,
            copied.path(),
            "evidence.project.misplaced-file",
            "evidence-project.yml",
            "/kind"
        ));
    }

    #[test]
    fn missing_declared_asset_is_a_warning_until_warnings_are_denied() {
        let temporary = temporary();
        sqlite_template(temporary.path());
        fs::remove_file(temporary.path().join("derivations/record-status.rhai")).unwrap();
        fs::remove_file(temporary.path().join("fixtures/record-status.yaml")).unwrap();

        let checked = check(temporary.path(), None, false, false).unwrap();
        assert_eq!(checked.report["status"], "incomplete");
        assert!(reports(
            &checked.diagnostics,
            temporary.path(),
            "evidence.question.derivation-missing",
            "questions/record-status.yaml",
            "/derivation"
        ));

        let report = refused(check(temporary.path(), None, false, true).unwrap_err());
        assert_eq!(report.error_count(), 0);
        assert!(report.warning_count() > 0);
    }

    #[test]
    fn missing_source_asset_is_an_incomplete_warning_before_compilation() {
        let temporary = temporary();
        sqlite_template(temporary.path());
        fs::remove_file(
            temporary
                .path()
                .join("schemas/record-status-response.schema.yaml"),
        )
        .unwrap();

        let checked = check(temporary.path(), None, false, false).unwrap();
        assert_eq!(checked.report["status"], "incomplete");
        assert!(reports(
            &checked.diagnostics,
            temporary.path(),
            "evidence.source.asset-missing",
            "sources/record-status.yaml",
            "/responseSchema"
        ));

        refused(check(temporary.path(), None, false, true).unwrap_err());
    }

    #[test]
    fn escaping_source_assets_are_refused_before_any_host_path_lookup() {
        for invalid in ["../outside.yaml", "/private/tmp/outside.yaml"] {
            let temporary = temporary();
            sqlite_template(temporary.path());
            fs::remove_file(temporary.path().join("derivations/record-status.rhai")).unwrap();
            let source_path = temporary.path().join("sources/record-status.yaml");
            let mut source: Value =
                serde_norway::from_slice(&fs::read(&source_path).unwrap()).unwrap();
            source["responseSchema"] = json!(invalid);
            fs::write(&source_path, serde_norway::to_string(&source).unwrap()).unwrap();

            let report = refused(check(temporary.path(), None, false, false).unwrap_err());
            assert_eq!(
                sites(&report, temporary.path())[0],
                (
                    "evidence.source.artifact-reference".to_owned(),
                    "sources/record-status.yaml".to_owned(),
                    "/responseSchema".to_owned()
                )
            );
            assert!(!printed(&report).contains(invalid));
        }
    }

    #[test]
    fn symlinked_declared_assets_are_domain_refusals_even_with_other_gaps() {
        for (relative, code, file, path) in [
            (
                "schemas/record-status-response.schema.yaml",
                "evidence.source.artifact-custody",
                "sources/record-status.yaml",
                "/responseSchema",
            ),
            (
                "derivations/record-status.rhai",
                "evidence.project.not-plain-file",
                "derivations/record-status.rhai",
                "",
            ),
            (
                "fixtures/record-status.yaml",
                "evidence.question.fixture-custody",
                "questions/record-status.yaml",
                "/governance/fixtures",
            ),
        ] {
            let temporary = temporary();
            sqlite_template(temporary.path());
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

            let report = refused(check(temporary.path(), None, false, false).unwrap_err());
            assert!(
                reports(&report, temporary.path(), code, file, path),
                "{:?}",
                sites(&report, temporary.path())
            );
        }
    }

    #[test]
    fn invalid_local_access_is_checked_without_reading_secrets() {
        let temporary = temporary();
        sqlite_template(temporary.path());
        fs::create_dir_all(temporary.path().join("access/policies")).unwrap();
        fs::write(
            temporary.path().join("access/policies/broken.yaml"),
            format!(
                "apiVersion: {ACCESS_POLICY_API_VERSION}\nkind: EvidenceAccessPolicy\nid: broken\nquestions: [missing-question]\n"
            ),
        )
        .unwrap();

        let report = refused(check(temporary.path(), None, false, false).unwrap_err());
        let (_, file, path) = &sites(&report, temporary.path())[0];
        assert_eq!(file, "access/policies/broken.yaml");
        assert!(path.starts_with("/questions"), "{path}");
        assert!(!temporary.path().join("secrets").exists());
    }

    #[test]
    fn production_requires_an_explicit_target() {
        let report = refused(check(Path::new("project"), None, true, false).unwrap_err());
        assert_eq!(report.diagnostics()[0].code, "evidence.target.required");
    }

    #[test]
    fn production_refuses_a_local_target_without_upgrading_it() {
        let temporary = temporary();
        let project = temporary.path().join("project");
        let target = temporary.path().join("target");
        fs::create_dir_all(project.join("questions")).unwrap();
        put_marker(&project);
        reference_target(&target, |governance| {
            governance.replace(
                "assuranceProfile: evidence-grade",
                "assuranceProfile: local",
            )
        });

        let report = refused(check(&project, Some(&target), true, false).unwrap_err());
        assert!(reports(
            &report,
            &target,
            "evidence.target.production-profile-required",
            "governance.yaml",
            "/assuranceProfile"
        ));
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
        reference_target(&target, |governance| governance);

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
            include_str!("../templates/sqlite-extract/questions/record-status.yaml")
                .replace("id: record-status", "id: replacement"),
        )
        .unwrap();

        let explained = explain_captured(temporary.path(), None, checked).unwrap();
        assert_eq!(explained.report["status"], "incomplete");
        assert_eq!(explained.report["questions"], json!([]));
        let mut gathered = Gathered::default();
        let inventory = inspect_project(temporary.path(), &mut gathered).unwrap();
        assert_eq!(inventory.questions.len(), 1);
        assert!(gathered.report().is_empty());
    }

    #[test]
    fn explain_inventory_never_infers_target_governance() {
        let temporary = temporary();
        sqlite_template(temporary.path());
        fs::remove_file(temporary.path().join("fixtures/record-status.yaml")).unwrap();

        let explained = explain(temporary.path(), None).unwrap();
        let report = &explained.report;

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
        let single = describe_question(
            "single",
            &json!({
                "id": "single",
                "subject": {
                    "role": "record",
                    "selector": "record_reference",
                    "profile": "record-reference-v1",
                },
            }),
        );
        let multiple = describe_question(
            "multiple",
            &json!({
                "id": "multiple",
                "subjects": [
                    {
                        "role": "child",
                        "selector": "child_reference",
                        "profile": "child-reference-v1",
                    },
                    {
                        "role": "guardian",
                        "profiles": ["guardian-reference-v1", "guardian-composite-v1"],
                    },
                ],
            }),
        );

        assert_eq!(multiple["id"], "multiple");
        assert_eq!(multiple["selectors"], json!(["child_reference"]));
        assert_eq!(
            multiple["selectorProfiles"],
            json!([
                "child-reference-v1",
                "guardian-reference-v1",
                "guardian-composite-v1"
            ])
        );
        assert_eq!(single["id"], "single");
        assert_eq!(single["selectors"], json!(["record_reference"]));
        assert_eq!(single["selectorProfiles"], json!(["record-reference-v1"]));
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
        validate_runtime_structure("runtime.yaml", runtime).unwrap();
    }

    #[test]
    fn runtime_structure_refuses_unknown_fields() {
        let runtime = include_str!(
            "../../../products/evidence/reference/deployment-targets/environments/production/evidence/runtime.yaml"
        );
        let runtime = runtime.replace(
            "kind: EvidenceRuntimeConfig\n",
            "kind: EvidenceRuntimeConfig\nunknown: true\n",
        );
        let error = validate_runtime_structure("runtime.yaml", runtime.as_bytes()).unwrap_err();
        assert!(format!("{error:#}").contains("published runtime contract"));
    }
}
