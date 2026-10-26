// SPDX-License-Identifier: Apache-2.0

//! `bregctl check`: the offline check of a project, of the runtime file that
//! binds it, or of a built package (CFG-CHECK-1). Every problem it finds is
//! one diagnostic of the shared shape (CFG-DIAG-1) in one report.
//!
//! The project's `registry.yaml` and every `modules/<id>/module.yaml` are
//! first read through the shared reader, and every reader diagnostic of every
//! file is reported together. The project is compiled only when every file
//! was read without error (CFG-DIAG-5). Compiler diagnostics address the
//! source by the compiler's own path, which this module places at the JSON
//! pointer, line, and column of the document it names.
//!
//! The project check then reads the tool files the project holds beside its
//! sources, `dev-clients.yaml` and every YAML file directly under `tests/`,
//! each as `bregctl check --file` checks it (CFG-CHECK-2).

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use registry_breg::contract::{read_module_yaml, read_project_yaml};
use registry_breg::package::PackageError;
use registry_breg::runtime_config::check_runtime_config;
use registry_breg::{CompiledRegistry, DiagnosticSeverity};
use registry_platform_yaml::{
    escape_pointer_segment, Diagnostic, Document, Node, NodeValue, Related, Report, Severity,
    Source, MAXIMUM_DOCUMENT_BYTES,
};
use serde::Serialize;
use serde_json::Value;

use super::{
    canonicalize_project_path, capture_resolved_project_source, compile_captured_registry,
    ensure_source_entry_identity, file_check, has_parent_component, inspect_package_integrity,
    path_diagnostic, read_module_directory_names, remap_derived_diagnostic_path, write_ctl_report,
    OutputFormat, ProfileArg, SafeDir, SafeEntry, SafePathError, DOMAIN_REFUSAL_EXIT,
    OPERATIONAL_FAILURE_EXIT,
};

/// The registered kind of `registry.yaml`, named as the `artifact` of a
/// diagnostic about the project as a whole.
const PROJECT_ARTIFACT: &str = registry_breg::contract::PROJECT_FORMAT.kind;
/// The registered kind of a module's `module.yaml`.
const MODULE_ARTIFACT: &str = registry_breg::contract::MODULE_FORMAT.kind;

const CORRECT_SOURCE: &str =
    "Correct the source at this path so it meets the rule the message states.";
const WRITE_REQUIRED_ROW_BOUNDARY: &str = "Write a rowBoundaries list on this permission with one entry for each boundary the entity's accessRequirements declare (field, claim, and operator); the unrestricted sentinel does not satisfy a requirement.";
const REVIEW_FINDING: &str =
    "Review the finding, and change the source if the behavior it describes is not intended.";
const RUN_SCHEMA_TEST: &str =
    "Run bregctl test against a disposable PostgreSQL database to verify the pattern.";
const LOCK_MODULES: &str =
    "Run bregctl project lock against this project, then review the module lock change it records.";
const ADD_READABLE_OR_REMOVE_PROCESSING: &str =
    "Add this field to readableFields, or remove it from filterableFields or sortableFields.";
const REVIEW_RELATED_DISCLOSURE: &str = "Remove fields that these readers should not see from this read path's readableFields, or remove the read path; use a direct permission on the related record type when its own row boundaries should apply.";
const FIND_PROJECT: &str = "Point bregctl check at a readable project directory that holds registry.yaml, or create one with bregctl init.";
const REBUILD_PACKAGE: &str = "Rebuild the package with bregctl package PROJECT --test-receipt RECEIPT --output BUILD; a package is checked as the build wrote it, unmodified.";
const REDUCE_MIGRATION_STATEMENTS: &str = "For an initial activation, reduce the generated schema or policy inventory below the supported package migration bound, for example by consolidating equivalent access profiles. A baseline-derived successor is checked against its actual migration when the package is prepared.";

/// What `bregctl check` was asked to check.
pub(super) struct Request<'a> {
    pub(super) project: Option<&'a Path>,
    pub(super) package: Option<&'a Path>,
    pub(super) production: bool,
    pub(super) deny_warnings: bool,
    pub(super) runtime_config: Option<&'a Path>,
    pub(super) environment: bool,
}

/// The report `bregctl check --format json` writes: the outcome, the
/// identities a successful check derives, and every diagnostic (CFG-DIAG-1).
/// `status` is `complete`, `domain-refusal` (exit 1), or `operational-failure`
/// (exit 3), the ctl report envelope's head after `ok` and `command`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckReport<'a> {
    ok: bool,
    command: &'static str,
    status: &'static str,
    profile: ProfileArg,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_revision: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_digest: Option<&'a str>,
    diagnostics: Vec<RankedDiagnostic<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RankedDiagnostic<'a> {
    #[serde(flatten)]
    diagnostic: &'a Diagnostic,
    #[serde(skip_serializing_if = "Option::is_none")]
    rank: Option<FindingRank>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum FindingRank {
    WidensAccess,
    Performance,
    Hygiene,
}

fn finding_rank(diagnostic: &Diagnostic) -> Option<FindingRank> {
    (diagnostic.severity == Severity::Warning).then(|| finding_rank_for_code(&diagnostic.code))
}

pub(super) fn ranked_diagnostics(diagnostics: &[Diagnostic]) -> Vec<RankedDiagnostic<'_>> {
    diagnostics
        .iter()
        .map(|diagnostic| RankedDiagnostic {
            diagnostic,
            rank: finding_rank(diagnostic),
        })
        .collect()
}

pub(super) fn finding_rank_for_code(code: &str) -> FindingRank {
    if matches!(
        code,
        "breg.access.consent-ungated-client"
            | "breg.access.profile-data-export"
            | "breg.access.profile-related-disclosure"
            | "breg.access.profile-revision-history"
            | "breg.access.profile-snapshot-history"
            | "breg.access.profile-subsumes-narrower"
            | "breg.access.profile-unrestricted-collection"
            | "breg.access.profile-unrestricted-rows"
            | "breg.access.profile-writable-row-boundary"
            | "breg.access.target-unrestricted-rows"
    ) {
        FindingRank::WidensAccess
    } else if code.starts_with("breg.record-type.list-unindexed-") {
        FindingRank::Performance
    } else {
        FindingRank::Hygiene
    }
}

/// What one run found, before it is written.
#[derive(Default)]
struct Outcome {
    report: Report,
    files: usize,
    /// Something the check depends on could not be read (exit 3).
    unavailable: bool,
    revision: Option<String>,
    package_digest: Option<String>,
}

pub(super) fn run(
    request: &Request<'_>,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let profile = if request.package.is_some() || request.production {
        ProfileArg::Production
    } else {
        ProfileArg::Authoring
    };
    let mut outcome = Outcome::default();
    let subject = match (request.project, request.package) {
        (Some(project), None) => {
            let compiled = check_project(project, profile, &mut outcome);
            if let Some(runtime) = request.runtime_config {
                check_runtime_file(
                    runtime,
                    request.environment,
                    compiled.as_ref(),
                    &mut outcome,
                );
                "project or its runtime configuration"
            } else {
                "project"
            }
        }
        (None, Some(package)) => {
            check_package(package, &mut outcome);
            "package"
        }
        _ => unreachable!("clap enforces exactly one of a project and a package"),
    };
    if outcome.files > 0 {
        outcome.report.set_files_checked(outcome.files);
    }
    if let Some(project) = request.project {
        registry_platform_config::apply_check_acceptances(project, &mut outcome.report);
        outcome.files = outcome.report.files_checked().unwrap_or(outcome.files);
    }
    let denied = request.deny_warnings && outcome.report.warning_count() > 0;
    let exit = if outcome.unavailable {
        OPERATIONAL_FAILURE_EXIT
    } else if outcome.report.has_errors() || denied {
        DOMAIN_REFUSAL_EXIT
    } else {
        0
    };
    let passed = exit == 0;
    let written = if format == OutputFormat::Json {
        let diagnostics = ranked_diagnostics(outcome.report.diagnostics());
        let report = CheckReport {
            ok: passed,
            command: "check",
            status: if passed {
                "complete"
            } else if outcome.unavailable {
                "operational-failure"
            } else {
                "domain-refusal"
            },
            profile,
            revision: outcome.revision.as_deref().filter(|_| passed),
            registry_revision: outcome.revision.as_deref().filter(|_| passed),
            package_digest: outcome.package_digest.as_deref().filter(|_| passed),
            diagnostics,
        };
        write_ctl_report(&mut *stdout, &report)
            .map_err(std::io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else if passed {
        let lead = match (&outcome.revision, &outcome.package_digest) {
            (Some(revision), Some(digest)) => {
                format!("Package verified; registry revision {revision}, package digest {digest}.")
            }
            (Some(revision), None) if profile == ProfileArg::Production => {
                format!("Production check passed; registry revision {revision}.")
            }
            (Some(revision), None) => {
                format!("Authoring check passed; registry revision {revision}.")
            }
            (None, _) => "Check passed.".to_owned(),
        };
        write!(stdout, "{lead}\n{}", outcome.report.render_human())
    } else {
        let lead = if outcome.unavailable {
            format!("bregctl check could not read the {subject}.")
        } else if outcome.report.has_errors() {
            format!("bregctl check refused the {subject}.")
        } else {
            format!("bregctl check refused the {subject}: --deny-warnings refuses a warning.")
        };
        write!(stderr, "{lead}\n{}", outcome.report.render_human())
    };
    if written.is_err() {
        let _ = writeln!(stderr, "bregctl: output could not be written");
        return ExitCode::from(OPERATIONAL_FAILURE_EXIT);
    }
    ExitCode::from(exit)
}

/// The project's documents, as the shared reader decoded them.
struct Documents {
    project: Document,
    /// Each module's directory name and its decoded `module.yaml`.
    modules: Vec<(String, Document)>,
}

impl Documents {
    /// Combine every compiler diagnostic with the retained warnings of the
    /// authored file that owns its primary source, then apply the shared
    /// per-file ordering and diagnostic budget once.
    fn extend_report(&self, outcome: &mut Outcome, diagnostics: Vec<Diagnostic>) {
        let mut project_diagnostics = Vec::new();
        let mut module_diagnostics = self.modules.iter().map(|_| Vec::new()).collect::<Vec<_>>();
        let mut other_diagnostics = Vec::new();
        for diagnostic in diagnostics {
            let owner = diagnostic.source.as_ref().and_then(|source| {
                if self.project.file() == source.file {
                    return Some(None);
                }
                self.modules
                    .iter()
                    .position(|(_, document)| document.file() == source.file)
                    .map(Some)
            });
            match owner {
                Some(Some(index)) => module_diagnostics[index].push(diagnostic),
                Some(None) => project_diagnostics.push(diagnostic),
                None => other_diagnostics.push(diagnostic),
            }
        }
        outcome
            .report
            .extend(self.project.report_with(project_diagnostics));
        for ((_, document), diagnostics) in self.modules.iter().zip(module_diagnostics) {
            outcome.report.extend(document.report_with(diagnostics));
        }
        outcome.report.extend(Report::new(other_diagnostics));
    }

    fn extend_warnings(&self, outcome: &mut Outcome) {
        self.extend_report(outcome, Vec::new());
    }
}

/// The authoring documents whose decoded trees produced one explanation.
///
/// `authoredPaths` records source presence only. A compiled member absent
/// from these paths is an engine default only when the explanation contract
/// documents that member's exact source pointer; compiled and derived members
/// do not acquire that meaning merely because they are absent here.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Authoring {
    documents: Vec<AuthoringDocument>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthoringDocument {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<String>,
    file: String,
    authored_paths: Vec<String>,
    bindings: Vec<AuthoringBinding>,
}

/// The exact source object that produced one identity-bearing object in the
/// model explanation. Both pointers use RFC 6901 against their respective
/// documents; no selector dialect is exposed.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthoringBinding {
    explanation_pointer: String,
    source_pointer: String,
}

impl Documents {
    fn authoring(&self) -> Authoring {
        let project = AuthoringDocument {
            kind: self.project.envelope().kind.clone(),
            module: None,
            file: "registry.yaml".to_owned(),
            authored_paths: authored_paths(self.project.root()),
            bindings: Vec::new(),
        };
        let modules = self.modules.iter().map(|(id, document)| AuthoringDocument {
            kind: document.envelope().kind.clone(),
            module: Some(id.clone()),
            file: format!("modules/{id}/module.yaml"),
            authored_paths: authored_paths(document.root()),
            bindings: Vec::new(),
        });
        Authoring {
            documents: std::iter::once(project).chain(modules).collect(),
        }
    }

    /// Bind identity-bearing model objects to the exact source objects that
    /// contributed them. A consumer may append a source-corresponding member
    /// name such as `/display` to both pointers and consult `authoredPaths`.
    /// The binding does not imply that every compiled child has a source peer.
    fn model_authoring(&self, compiled: &CompiledRegistry) -> Authoring {
        let model = registry_breg::artifacts::inspect_registry(compiled);
        let mut authoring = self.authoring();

        self.push_binding(
            &mut authoring,
            None,
            String::new(),
            &[Step::Member("project".to_owned())],
        );
        for (explanation_member, source_member) in [
            ("datasets", "datasets"),
            ("accessProfiles", "accessProfiles"),
            ("reviewAuthorities", "reviewAuthorities"),
            ("statisticalDatasets", "statisticalDatasets"),
        ] {
            for (index, item) in items(&model[explanation_member]).enumerate() {
                let id = item["id"]
                    .as_str()
                    .expect("compiled model identity is a string");
                self.push_binding(
                    &mut authoring,
                    None,
                    format!("/{explanation_member}/{index}"),
                    &id_item_steps(source_member, id),
                );
            }
        }

        for (record_index, item) in items(&model["recordTypes"]).enumerate() {
            let record_id = item["id"]
                .as_str()
                .expect("compiled Record type identity is a string");
            let record = compiled
                .entities()
                .get(record_id)
                .expect("explained Record type belongs to the compiled model");
            let record_module = record.source_module.as_deref();
            self.push_binding(
                &mut authoring,
                record_module,
                format!("/recordTypes/{record_index}"),
                &id_item_steps("recordTypes", record_id),
            );

            for (field_index, field) in items(&item["fields"]).enumerate() {
                let field_id = field["id"]
                    .as_str()
                    .expect("compiled field identity is a string");
                let (member_module, source_steps) =
                    if let Some(derivation_id) = field["derivation"].as_str() {
                        let module = record
                            .module_origins
                            .derived_relations
                            .get(derivation_id)
                            .map(String::as_str);
                        let mut steps = id_item_steps("derived", derivation_id);
                        steps.extend(id_item_steps("fields", field_id));
                        (module, steps)
                    } else {
                        let module = record
                            .module_origins
                            .fields
                            .get(field_id)
                            .map(String::as_str);
                        (module, id_item_steps("fields", field_id))
                    };
                self.push_record_member_binding(
                    &mut authoring,
                    member_module,
                    record_id,
                    format!("/recordTypes/{record_index}/fields/{field_index}"),
                    &source_steps,
                );
            }

            for hook_id in item["hooks"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(id, _)| id)
            {
                let module = record.module_origins.hooks.get(hook_id).map(String::as_str);
                self.push_record_member_binding(
                    &mut authoring,
                    module,
                    record_id,
                    format!(
                        "/recordTypes/{record_index}/hooks/{}",
                        escape_pointer_segment(hook_id)
                    ),
                    &id_item_steps("hooks", hook_id),
                );
            }
        }

        for (action_index, item) in items(&model["actions"]).enumerate() {
            let action_id = item["id"]
                .as_str()
                .expect("compiled Action identity is a string");
            let action = compiled
                .actions()
                .actions
                .iter()
                .find(|action| action.id == action_id)
                .expect("explained Action belongs to the compiled model");
            let module = action.source_module.as_deref();
            let action_steps = id_item_steps("actions", action_id);
            self.push_binding(
                &mut authoring,
                module,
                format!("/actions/{action_index}"),
                &action_steps,
            );
            for (input_index, input) in items(&item["inputs"]).enumerate() {
                let input_id = input["id"]
                    .as_str()
                    .expect("compiled Action input identity is a string");
                let mut source_steps = action_steps.clone();
                source_steps.extend(id_item_steps("inputs", input_id));
                self.push_binding(
                    &mut authoring,
                    module,
                    format!("/actions/{action_index}/inputs/{input_index}"),
                    &source_steps,
                );
            }
            for (hook_index, hook) in items(&item["execution"]["proposal"]["hooks"]).enumerate() {
                let hook_id = hook["id"]
                    .as_str()
                    .expect("compiled Proposal hook identity is a string");
                let mut source_steps = action_steps.clone();
                source_steps.extend([
                    Step::Member("execution".to_owned()),
                    Step::Member("proposal".to_owned()),
                ]);
                source_steps.extend(id_item_steps("hooks", hook_id));
                self.push_binding(
                    &mut authoring,
                    module,
                    format!("/actions/{action_index}/execution/proposal/hooks/{hook_index}"),
                    &source_steps,
                );
            }
        }
        authoring
    }

    fn push_binding(
        &self,
        authoring: &mut Authoring,
        module: Option<&str>,
        explanation_pointer: String,
        source_steps: &[Step],
    ) {
        let (document_index, document) = self.document_for_module(module);
        let resolved = resolve(document.root(), source_steps);
        assert!(
            resolved.complete,
            "compiled model object at {explanation_pointer} resolves to its exact source object"
        );
        authoring.documents[document_index]
            .bindings
            .push(AuthoringBinding {
                explanation_pointer,
                source_pointer: resolved.pointer,
            });
    }

    /// Resolve a Record member in its owning document. A module may both
    /// declare and extend the same Record type, so module identity alone does
    /// not distinguish the two source locations.
    fn push_record_member_binding(
        &self,
        authoring: &mut Authoring,
        module: Option<&str>,
        record_id: &str,
        explanation_pointer: String,
        member_steps: &[Step],
    ) {
        let (document_index, document) = self.document_for_module(module);
        let mut candidates = vec![id_item_steps("recordTypes", record_id)];
        let extension_items =
            document
                .root()
                .get("extendRecordTypes")
                .and_then(|entry| match &entry.value.value {
                    NodeValue::Sequence(items) => Some(items),
                    _ => None,
                });
        if let Some(items) = extension_items {
            for (index, item) in items.iter().enumerate() {
                if names(item, Some("recordType"), record_id) {
                    candidates.push(vec![
                        Step::Member("extendRecordTypes".to_owned()),
                        Step::Index(index),
                    ]);
                }
            }
        }
        let mut matches = candidates.into_iter().filter_map(|mut candidate| {
            candidate.extend_from_slice(member_steps);
            let resolved = resolve(document.root(), &candidate);
            resolved.complete.then_some(resolved)
        });
        let resolved = matches.next().unwrap_or_else(|| {
            panic!(
                "compiled model Record member at {explanation_pointer} resolves to its exact source object"
            )
        });
        assert!(
            matches.next().is_none(),
            "compiled model Record member at {explanation_pointer} has one exact source object"
        );
        authoring.documents[document_index]
            .bindings
            .push(AuthoringBinding {
                explanation_pointer,
                source_pointer: resolved.pointer,
            });
    }

    fn document_for_module(&self, module: Option<&str>) -> (usize, &Document) {
        match module {
            None => (0, &self.project),
            Some(module) => self
                .modules
                .iter()
                .enumerate()
                .find(|(_, (id, _))| id == module)
                .map(|(index, (_, document))| (index + 1, document))
                .expect("compiled module origin names a loaded document"),
        }
    }
}

fn items(value: &Value) -> impl Iterator<Item = &Value> {
    value.as_array().into_iter().flatten()
}

fn id_item_steps(collection: &str, id: &str) -> Vec<Step> {
    vec![
        Step::Member(collection.to_owned()),
        Step::Select {
            key: Some("id".to_owned()),
            value: id.to_owned(),
        },
    ]
}

/// Every node the author wrote, addressed by an exact RFC 6901 pointer in
/// source order. The empty pointer names the document root; list items are
/// present as well as their members, so an explicit empty collection remains
/// distinguishable from an omitted one.
fn authored_paths(root: &Node) -> Vec<String> {
    let mut paths = Vec::new();
    collect_authored_paths(root, String::new(), &mut paths);
    paths
}

fn collect_authored_paths(node: &Node, path: String, paths: &mut Vec<String>) {
    paths.push(path.clone());
    match &node.value {
        NodeValue::Mapping(entries) => {
            for entry in entries {
                let child = format!("{path}/{}", escape_pointer_segment(&entry.key));
                collect_authored_paths(&entry.value, child, paths);
            }
        }
        NodeValue::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_authored_paths(item, format!("{path}/{index}"), paths);
            }
        }
        _ => {}
    }
}

/// The compiled registry when the project compiled, so the runtime file can be
/// held to it.
fn check_project(
    project: &Path,
    profile: ProfileArg,
    outcome: &mut Outcome,
) -> Option<CompiledRegistry> {
    let selected_project = match canonicalize_project_path(project) {
        Ok(path) => path,
        Err(diagnostic) => {
            outcome.unavailable = diagnostic.code == "breg.source.project-invalid";
            outcome.report.push(file_diagnostic(
                &diagnostic.code,
                project,
                Some(PROJECT_ARTIFACT),
                &diagnostic.message,
                FIND_PROJECT,
            ));
            return None;
        }
    };
    let project = selected_project.as_path();
    let compiled = compile_project(project, profile, outcome);
    check_tool_files(project, compiled.as_ref(), outcome);
    compiled
}

/// The tool files a project holds beside its sources, each identified by its
/// envelope and checked as `bregctl check --file` checks it (CFG-CHECK-2):
/// `dev-clients.yaml`, and every `.yaml` and `.yml` file directly under
/// `tests/`. A file whose kind is no BReg tool file's is refused by the
/// reader, never skipped, and a directory under `tests/` is named as unread.
/// The journeys are held to `registry` when the project compiled.
fn check_tool_files(project: &Path, registry: Option<&CompiledRegistry>, outcome: &mut Outcome) {
    if project.as_os_str().is_empty()
        || has_parent_component(project)
        || SafeDir::resolve(project).is_err()
    {
        // The project directory was refused, and the report says why.
        return;
    }
    let mut files = Vec::new();
    let clients = project.join("dev-clients.yaml");
    if clients.symlink_metadata().is_ok() {
        files.push(clients);
    }
    let tests = project.join("tests");
    match SafeDir::resolve(&tests).map(|directory| directory.read_entries()) {
        Err(SafePathError::NotFound) => {}
        Ok(Ok(mut entries)) => {
            entries.sort_by(|left, right| left.name.cmp(&right.name));
            for entry in entries {
                let path = tests.join(&entry.name);
                if entry.is_dir {
                    let mut unread = file_diagnostic(
                        "breg.check.unread-directory",
                        &path,
                        None,
                        "bregctl check reads only the files directly under tests/, so nothing in this directory is read",
                        "Move the files this directory holds up into tests/, or move the directory out of tests/.",
                    );
                    unread.severity = Severity::Warning;
                    outcome.report.push(unread);
                } else if is_yaml(&path) {
                    files.push(path);
                }
            }
        }
        Ok(Err(_)) | Err(_) => outcome.report.push(file_diagnostic(
            "breg.check.directory-unreadable",
            &tests,
            None,
            "the tests directory could not be listed, so the files it holds were not checked: it must be a directory, and not a symbolic link",
            "Make tests a directory this user may read, or remove it.",
        )),
    }
    for file in files {
        outcome.files += 1;
        outcome
            .report
            .extend(file_check::check_project_file(&file, registry));
    }
}

fn is_yaml(file: &Path) -> bool {
    file.extension()
        .is_some_and(|extension| extension == "yaml" || extension == "yml")
}

/// Read and compile the project's sources.
fn compile_project(
    project: &Path,
    profile: ProfileArg,
    outcome: &mut Outcome,
) -> Option<CompiledRegistry> {
    compile_project_with_documents(project, profile, outcome).map(|(compiled, _)| compiled)
}

/// Compile the project and keep the exact decoded authoring documents used
/// to place diagnostics and describe source presence in inspection output.
fn compile_project_with_documents(
    project: &Path,
    profile: ProfileArg,
    outcome: &mut Outcome,
) -> Option<(CompiledRegistry, Documents)> {
    let source = match capture_resolved_project_source(project) {
        Ok(source) => source,
        Err(diagnostic) => {
            // The aggregate reader reports every positioned refusal when
            // capture stopped at the first invalid source. This fallback
            // never supplies provenance for a successfully compiled model.
            let documents = read_documents(project, outcome)?;
            let diagnostic = place(project, &documents, diagnostic, Severity::Error);
            documents.extend_report(outcome, vec![diagnostic]);
            return None;
        }
    };
    let documents = read_captured_documents(project, &source, outcome)?;
    let captured_planner_asset_missing = source
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.source.planner-asset-missing");
    let mut diagnostics = source
        .diagnostics
        .iter()
        .cloned()
        .map(|diagnostic| place(project, &documents, diagnostic, Severity::Error))
        .collect::<Vec<_>>();
    // A production check asserts the project is ready to package for
    // deployment, so it also reports the identity a deployable package must
    // not carry.
    if profile == ProfileArg::Production {
        for refusal in registry_breg::compiler::deployment_diagnostics(&source.project) {
            diagnostics.push(place(project, &documents, refusal, Severity::Error));
        }
    }
    match compile_captured_registry(&source, profile) {
        Ok(compiled) => {
            if profile == ProfileArg::Production {
                if let Some(diagnostic) =
                    migration_statement_capacity_diagnostic(compiled.ddl().statements.len())
                {
                    let severity = severity_of(diagnostic.severity);
                    diagnostics.push(place(project, &documents, diagnostic, severity));
                }
            }
            for finding in compiled
                .findings()
                .iter()
                .cloned()
                .chain(unverified_patterns(&compiled))
            {
                let severity = severity_of(finding.severity);
                diagnostics.push(place(project, &documents, finding, severity));
            }
            documents.extend_report(outcome, diagnostics);
            outcome.revision = Some(compiled.revision().to_owned());
            Some((compiled, documents))
        }
        Err(failure) => {
            for diagnostic in failure.diagnostics().iter().cloned() {
                if captured_planner_asset_missing
                    && matches!(
                        diagnostic.code.as_str(),
                        "breg.action.handler-source-missing"
                            | "breg.hook.handler-source-missing"
                            | "breg.proposal.hook-handler-source-missing"
                    )
                {
                    continue;
                }
                let diagnostic = remap_derived_diagnostic_path(diagnostic, &source);
                let severity = severity_of(diagnostic.severity);
                diagnostics.push(place(project, &documents, diagnostic, severity));
            }
            documents.extend_report(outcome, diagnostics);
            None
        }
    }
}

fn migration_statement_capacity_diagnostic(
    statement_count: usize,
) -> Option<registry_breg::Diagnostic> {
    (statement_count > registry_breg::package::MAX_MIGRATION_STATEMENTS).then(|| {
        registry_breg::Diagnostic {
            severity: DiagnosticSeverity::Finding,
            code: "breg.package.migration-statement-capacity".to_owned(),
            path: "project".to_owned(),
            message: format!(
                "The full compiled schema would require {statement_count} statements for an initial activation; a package migration supports at most {}. Baseline-derived successors are checked against their actual migration when the package is prepared.",
                registry_breg::package::MAX_MIGRATION_STATEMENTS
            ),
            related: Vec::new(),
        }
    })
}

/// Compile the same authoring source as `check`, retaining its positioned
/// diagnostics. Inspection does not validate unrelated dev clients or journeys.
pub(super) fn compile_for_inspection(
    project: &Path,
    profile: ProfileArg,
) -> Result<(CompiledRegistry, Vec<Diagnostic>, Authoring), super::Refusal> {
    let selected = canonicalize_project_path(project).map_err(|diagnostic| {
        super::source_failure(
            "explain",
            diagnostic,
            super::DiagnosticArtifact::RegistryProject,
            super::SuggestedAction::CorrectAuthoringSource,
        )
    })?;
    let mut outcome = Outcome::default();
    let compiled = compile_project_with_documents(&selected, profile, &mut outcome);
    registry_platform_config::apply_check_acceptances(&selected, &mut outcome.report);
    // A production compile can succeed while `check --production` still
    // refuses the project, as for a deployment identity a package must not
    // carry, so an error in the report refuses inspection too.
    match compiled {
        Some((compiled, documents)) if !outcome.report.has_errors() => {
            let authoring = documents.model_authoring(&compiled);
            Ok((compiled, outcome.report.into_diagnostics(), authoring))
        }
        _ => Err(super::Refusal::Document(super::DocumentRefusal {
            command: "explain",
            subject: "the project",
            report: outcome.report,
        })),
    }
}

/// Compiler findings from a command without source documents still use the
/// shared diagnostic contract. `compile_for_inspection` additionally places them.
pub(super) fn compiler_diagnostic(diagnostic: registry_breg::Diagnostic) -> Diagnostic {
    let severity = severity_of(diagnostic.severity);
    let mut result = Diagnostic::error(
        diagnostic.code.clone(),
        diagnostic.path,
        diagnostic.message,
        action_for(&diagnostic.code, severity),
    );
    result.severity = severity;
    result.artifact = Some(PROJECT_ARTIFACT.to_owned());
    result
}

/// A native pattern is checked offline for its structure and bounds only.
fn unverified_patterns(compiled: &CompiledRegistry) -> Vec<registry_breg::Diagnostic> {
    compiled
        .entities()
        .values()
        .flat_map(|entity| {
            entity.fields.values().filter_map(move |field| {
                field.pattern.as_ref().map(|_| registry_breg::Diagnostic {
                    severity: DiagnosticSeverity::Finding,
                    code: "breg.field.pattern-unverified-offline".to_owned(),
                    path: format!("recordTypes[{}].fields[{}].pattern", entity.id, field.id),
                    message: "Offline check validates pattern structure and bounds only. Run bregctl test against disposable PostgreSQL to verify native pattern syntax and storage behavior.".to_owned(),
                    related: Vec::new(),
                })
            })
        })
        .collect()
}

fn severity_of(severity: DiagnosticSeverity) -> Severity {
    match severity {
        DiagnosticSeverity::Error => Severity::Error,
        DiagnosticSeverity::Finding => Severity::Warning,
    }
}

/// Decode positions and source presence from the exact byte capture compiled
/// below. Reading the files again could mix an editor's later save with the
/// captured model and assign the wrong source object to a compiled member.
fn read_captured_documents(
    project: &Path,
    source: &super::CapturedProjectSource,
    outcome: &mut Outcome,
) -> Option<Documents> {
    outcome.files += 1;
    let project_document = match read_project_yaml(
        &project.join("registry.yaml").display().to_string(),
        &source.project_bytes,
    ) {
        Ok(decoded) => decoded.document,
        Err(report) => {
            outcome.report.extend(report);
            return None;
        }
    };
    let mut modules = Vec::with_capacity(source.modules.len());
    for module in &source.modules {
        outcome.files += 1;
        let file = project.join("modules").join(&module.id).join("module.yaml");
        match read_module_yaml(&file.display().to_string(), &module.bytes) {
            Ok(decoded) => modules.push((module.id.clone(), decoded.document)),
            Err(report) => {
                let documents = Documents {
                    project: project_document,
                    modules,
                };
                documents.extend_warnings(outcome);
                outcome.report.extend(report);
                return None;
            }
        }
    }
    Some(Documents {
        project: project_document,
        modules,
    })
}

/// Read `registry.yaml` and every authored `module.yaml` through the shared
/// reader, reporting every reader diagnostic of every file. `None` when any
/// file was refused or could not be read, so nothing is compiled.
fn read_documents(project: &Path, outcome: &mut Outcome) -> Option<Documents> {
    if project.as_os_str().is_empty() || has_parent_component(project) {
        outcome.report.push(file_diagnostic(
            "breg.source.project-path-unsafe",
            project,
            Some(PROJECT_ARTIFACT),
            "the project path must not contain parent-directory components",
            "Name the project directory by a path without `..` components.",
        ));
        return None;
    }
    match SafeDir::resolve(project) {
        Ok(_) => {}
        Err(error) => {
            let diagnostic = path_diagnostic(
                error,
                "breg.source.project-invalid",
                "project",
                "the project directory is not available",
                "the project directory must be a directory and must not be a symbolic link",
            );
            outcome.unavailable |=
                matches!(error, SafePathError::NotFound | SafePathError::Unavailable);
            outcome.report.push(file_diagnostic(
                &diagnostic.code,
                project,
                Some(PROJECT_ARTIFACT),
                &diagnostic.message,
                FIND_PROJECT,
            ));
            return None;
        }
    }

    let project_file = project.join("registry.yaml");
    let mut refused = false;
    let decoded_project = match read_file(
        &project_file,
        "registry.yaml",
        "breg.source.project-missing",
    ) {
        Ok(bytes) => {
            outcome.files += 1;
            decode(
                read_project_yaml(&project_file.display().to_string(), &bytes)
                    .map(|decoded| decoded.document),
                outcome,
            )
        }
        Err(problem) => {
            outcome.unavailable |= problem.unavailable;
            let action = if problem.unavailable {
                FIND_PROJECT
            } else {
                CORRECT_SOURCE
            };
            outcome.report.push(file_diagnostic(
                &problem.diagnostic.code,
                &project_file,
                Some(PROJECT_ARTIFACT),
                &problem.diagnostic.message,
                action,
            ));
            return None;
        }
    };
    refused |= decoded_project.is_none();

    let mut modules = Vec::new();
    match read_module_directory_names(project) {
        Ok(listed) => {
            for id in listed.names {
                let file = project.join("modules").join(&id).join("module.yaml");
                match read_file(
                    &file,
                    &format!("modules/{id}/module.yaml"),
                    "breg.source.module-missing",
                ) {
                    Ok(bytes) => {
                        outcome.files += 1;
                        match decode(
                            read_module_yaml(&file.display().to_string(), &bytes)
                                .map(|decoded| decoded.document),
                            outcome,
                        ) {
                            Some(document) => modules.push((id, document)),
                            None => refused = true,
                        }
                    }
                    Err(problem) => {
                        outcome.report.push(file_diagnostic(
                            &problem.diagnostic.code,
                            &file,
                            Some(MODULE_ARTIFACT),
                            &problem.diagnostic.message,
                            "Give the module directory a readable regular module.yaml, or remove the directory.",
                        ));
                        refused = true;
                    }
                }
            }
        }
        Err(diagnostic) => {
            outcome.report.push(file_diagnostic(
                &diagnostic.code,
                &project.join("modules"),
                None,
                &diagnostic.message,
                "Keep only module directories, each named by its module id, under modules.",
            ));
            refused = true;
        }
    }
    if refused {
        // Successful documents retain their warnings until every source has
        // been read. A later refusal still reports those warnings once, while
        // a complete read lets the caller combine them with the capture
        // diagnostic under each document's single budget.
        if let Some(document) = &decoded_project {
            outcome.report.extend(document.warnings());
        }
        for (_, document) in &modules {
            outcome.report.extend(document.warnings());
        }
        // A refused file always stops the check with an error, even if
        // the reader reported none for it.
        if !outcome.report.has_errors() {
            outcome.report.push(file_diagnostic(
                "breg.source.file-invalid",
                project,
                Some(PROJECT_ARTIFACT),
                "a project file was refused without a reported cause",
                CORRECT_SOURCE,
            ));
        }
        return None;
    }

    Some(Documents {
        project: decoded_project.expect("an accepted project document was decoded"),
        modules,
    })
}

/// Retain a decoded document with its warnings; report a refused one's diagnostics.
fn decode(read: Result<Document, Report>, outcome: &mut Outcome) -> Option<Document> {
    match read {
        Ok(document) => Some(document),
        Err(report) => {
            outcome.report.extend(report);
            None
        }
    }
}

/// A file that could not be read for the reader.
struct ReadProblem {
    diagnostic: registry_breg::Diagnostic,
    unavailable: bool,
}

/// Read up to one byte past the reader's size cap from a regular file that
/// is not a symbolic link, so the reader itself refuses an oversized file.
fn read_file(path: &Path, report_path: &str, missing_code: &str) -> Result<Vec<u8>, ReadProblem> {
    let refused = |code: &str, message: &str| ReadProblem {
        diagnostic: super::diagnostic(code, report_path, message),
        unavailable: false,
    };
    let unreadable = |code: &str| ReadProblem {
        diagnostic: super::diagnostic(
            code,
            report_path,
            "the required authoring source is not available",
        ),
        unavailable: true,
    };
    let entry = match SafeEntry::resolve(path) {
        Ok(entry) => entry,
        Err(error) => {
            let diagnostic = path_diagnostic(
                error,
                missing_code,
                report_path,
                "the required authoring source is not available",
                "authoring sources must be regular files and must not be symbolic links",
            );
            return Err(ReadProblem {
                diagnostic,
                unavailable: matches!(error, SafePathError::NotFound | SafePathError::Unavailable),
            });
        }
    };
    let stat = entry.stat().map_err(|_| unreadable(missing_code))?;
    if stat.is_symlink() || !stat.is_file() {
        return Err(refused(
            "breg.source.file-invalid",
            "authoring sources must be regular files and must not be symbolic links",
        ));
    }
    let file = entry
        .open_read()
        .map_err(|_| unreadable("breg.source.file-unreadable"))?;
    let opened = file
        .metadata()
        .map_err(|_| unreadable("breg.source.file-unreadable"))?;
    if !opened.is_file() {
        return Err(refused(
            "breg.source.file-invalid",
            "authoring sources must be regular files and must not be symbolic links",
        ));
    }
    ensure_source_entry_identity(stat, &opened, report_path).map_err(|diagnostic| ReadProblem {
        diagnostic,
        unavailable: false,
    })?;
    let mut bytes = Vec::new();
    file.take(MAXIMUM_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable("breg.source.file-unreadable"))?;
    Ok(bytes)
}

/// A diagnostic about a file or directory as a whole, with no position.
fn file_diagnostic(
    code: &str,
    file: &Path,
    artifact: Option<&str>,
    message: &str,
    action: &str,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(code, "", message, action);
    diagnostic.artifact = artifact.map(str::to_owned);
    diagnostic.source = Some(Source {
        file: file.display().to_string(),
        line: None,
        column: None,
    });
    diagnostic
}

fn check_runtime_file(
    path: &Path,
    environment: bool,
    registry: Option<&CompiledRegistry>,
    outcome: &mut Outcome,
) {
    let given = path.display().to_string();
    let Some(absolute) = absolute_lexical(path) else {
        outcome.unavailable = true;
        outcome.report.push(file_diagnostic(
            "platform.runtime-config.unavailable",
            path,
            None,
            "the runtime configuration file path cannot be resolved",
            "Name the runtime configuration file by a readable path.",
        ));
        return;
    };
    let absolute_text = absolute.display().to_string();
    let check = check_runtime_config(&absolute, environment, registry);
    outcome.files += 1;
    outcome.unavailable |= check.unavailable;
    for mut diagnostic in check.diagnostics {
        if let Some(source) = &mut diagnostic.source {
            if source.file == absolute_text {
                source.file.clone_from(&given);
            }
        }
        for related in &mut diagnostic.related {
            if related.file == absolute_text {
                related.file.clone_from(&given);
            }
        }
        outcome.report.push(diagnostic);
    }
}

/// The path made absolute against the working directory, with `.` and `..`
/// components removed lexically, as the runtime loader requires.
fn absolute_lexical(path: &Path) -> Option<PathBuf> {
    let absolute = std::path::absolute(path).ok()?;
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other),
        }
    }
    Some(normalized)
}

fn check_package(package: &Path, outcome: &mut Outcome) {
    match inspect_package_integrity(package) {
        Ok(inspected) => {
            outcome.revision = Some(inspected.registry().revision().to_owned());
            outcome.package_digest = Some(inspected.package_digest().to_owned());
        }
        Err(error) => {
            outcome.unavailable |= matches!(error, PackageError::Read);
            outcome.report.push(file_diagnostic(
                package_code(&error),
                package,
                None,
                &error.to_string(),
                package_action(&error),
            ));
        }
    }
}

/// The package refusal's code, one per class `bregctl` names a package
/// refusal by.
fn package_code(error: &PackageError) -> &'static str {
    match error {
        PackageError::UnsafePath => "breg.package.path-refused",
        PackageError::Permissions => "breg.package.permissions-refused",
        PackageError::Binding => "breg.package.binding-refused",
        PackageError::Envelope
        | PackageError::ExpectedDigestMismatch(_)
        | PackageError::Closure
        | PackageError::Integrity
        | PackageError::CanonicalJson
        | PackageError::Derivation
        | PackageError::MigrationPlan
        | PackageError::ReviewedMigration(_) => "breg.package.integrity-refused",
        PackageError::Bounds | PackageError::Read => "breg.package.refused",
        PackageError::DeploymentIdentity => "breg.package.deployment-identity-refused",
        PackageError::RetiredApiVersion => "config.retired-api-version",
    }
}

fn package_action(error: &PackageError) -> &'static str {
    match error {
        PackageError::UnsafePath => {
            "Point --package at the package directory itself, by a path without symbolic links."
        }
        PackageError::Permissions => {
            "Remove group and other write permission from the package directory and its files (chmod -R go-w), then check again."
        }
        PackageError::Read => {
            "Point --package at a readable package directory that bregctl package wrote."
        }
        PackageError::DeploymentIdentity => {
            "Replace canonicalBaseIri, rerun schema-test, and rebuild the deployment package."
        }
        PackageError::RetiredApiVersion => {
            "Rebuild the package with this bregctl: bregctl package PROJECT --test-receipt RECEIPT --output BUILD, then apply the rebuilt package to a new database: bregctl apply --initial --package BUILD."
        }
        _ => REBUILD_PACKAGE,
    }
}

// ---------------------------------------------------------------------------
// Placing a compiler diagnostic in the document it names

/// Place diagnostics from one captured source snapshot at their exact authored
/// files and values. The fallback keeps the compiler's logical path if a
/// future reader change makes the already accepted captured bytes undecodable.
pub(crate) fn place_captured_diagnostics(
    source: &super::CapturedProjectSource,
    diagnostics: Vec<registry_breg::Diagnostic>,
) -> Option<Vec<Diagnostic>> {
    let project_file = source.project_path.join("registry.yaml");
    let project = read_project_yaml(&project_file.display().to_string(), &source.project_bytes)
        .ok()
        .map(|decoded| decoded.document)?;
    let mut modules = Vec::with_capacity(source.modules.len());
    for module in &source.modules {
        let file = source
            .project_path
            .join("modules")
            .join(&module.id)
            .join("module.yaml");
        let document = read_module_yaml(&file.display().to_string(), &module.bytes)
            .ok()
            .map(|decoded| decoded.document)?;
        modules.push((module.id.clone(), document));
    }
    let documents = Documents { project, modules };
    Some(
        diagnostics
            .into_iter()
            .map(|diagnostic| {
                let severity = severity_of(diagnostic.severity);
                place(&source.project_path, &documents, diagnostic, severity)
            })
            .collect(),
    )
}

/// The compiler's diagnostic as a shared one, placed at the document, JSON
/// pointer, line, and column its path names.
fn place(
    project: &Path,
    documents: &Documents,
    diagnostic: registry_breg::Diagnostic,
    severity: Severity,
) -> Diagnostic {
    let related = diagnostic.related.clone();
    let diagnostic_severity = diagnostic.severity;
    let mut placed = place_primary(project, documents, diagnostic, severity);
    for relation in related {
        let related_diagnostic = registry_breg::Diagnostic {
            severity: diagnostic_severity,
            code: placed.code.clone(),
            path: relation.path,
            message: relation.message.clone(),
            related: Vec::new(),
        };
        let related_placed = place_primary(project, documents, related_diagnostic, severity);
        if let Some(source) = related_placed.source {
            placed.related.push(Related {
                file: source.file,
                line: source.line,
                column: source.column,
                path: related_placed.path,
                message: relation.message,
            });
        }
    }
    placed
}

fn place_primary(
    project: &Path,
    documents: &Documents,
    diagnostic: registry_breg::Diagnostic,
    severity: Severity,
) -> Diagnostic {
    let action = action_for(&diagnostic.code, severity);
    let path = diagnostic.path.as_str();
    let file_level = |file: PathBuf, artifact: Option<&str>| {
        let mut placed = file_diagnostic(
            &diagnostic.code,
            &file,
            artifact,
            &diagnostic.message,
            action,
        );
        placed.severity = severity;
        placed
    };
    match path {
        "project" => return file_level(project.to_path_buf(), Some(PROJECT_ARTIFACT)),
        "registry.yaml" => {
            return file_level(project.join("registry.yaml"), Some(PROJECT_ARTIFACT));
        }
        "modules" => return file_level(project.join("modules"), None),
        "arguments" => {
            let mut placed = Diagnostic::error(
                diagnostic.code.as_str(),
                "",
                diagnostic.message.as_str(),
                action,
            );
            placed.severity = severity;
            return placed;
        }
        _ => {}
    }
    if let Some((file, rest)) = path.split_once(':') {
        if let Some(id) = module_file_id(file) {
            if let Some((_, document)) = documents.modules.iter().find(|(name, _)| name == id) {
                let steps = parse_steps(rest);
                let found = resolve_module_path(document, &steps);
                return at_value(document, &diagnostic, severity, action, &found, rest);
            }
            return file_level(project.join(file), Some(MODULE_ARTIFACT));
        }
    }
    if let Some(relative) = path.strip_prefix("modules/") {
        let artifact = module_file_id(path).map(|_| MODULE_ARTIFACT);
        let _ = relative;
        return file_level(project.join(path), artifact);
    }
    if let Some(rest) = path.strip_prefix("project.") {
        let found = resolve(documents.project.root(), &parse_steps(rest));
        return at_value(
            &documents.project,
            &diagnostic,
            severity,
            action,
            &found,
            path,
        );
    }
    let steps = parse_steps(path);
    if matches!(steps.first(), Some(Step::Member(name)) if name == "modules") {
        if let Some((document, found)) = module_target(documents, &steps[1..]) {
            return at_value(document, &diagnostic, severity, action, &found, path);
        }
        let found = resolve(documents.project.root(), &steps[..1]);
        return at_value(
            &documents.project,
            &diagnostic,
            severity,
            action,
            &found,
            path,
        );
    }
    let mut best = (
        &documents.project,
        resolve(documents.project.root(), &steps),
    );
    for alternative in alternatives(&steps) {
        let found = resolve(documents.project.root(), &alternative);
        if found.better_than(&best.1) {
            best = (&documents.project, found);
        }
    }
    for (_, document) in &documents.modules {
        let found = resolve_module_path(document, &steps);
        if found.better_than(&best.1) {
            best = (document, found);
        }
    }
    at_value(best.0, &diagnostic, severity, action, &best.1, path)
}

/// The module id of `modules/<id>/module.yaml`.
fn module_file_id(file: &str) -> Option<&str> {
    let id = file
        .strip_prefix("modules/")?
        .strip_suffix("/module.yaml")?;
    (!id.is_empty() && !id.contains('/')).then_some(id)
}

/// The module document a `modules[...]` path names, and the place in it.
fn module_target<'d>(documents: &'d Documents, steps: &[Step]) -> Option<(&'d Document, Resolved)> {
    let (first, rest) = steps.split_first()?;
    let document = match first {
        Step::Select { value, .. } => documents
            .modules
            .iter()
            .find(|(id, _)| id == value)
            .map(|(_, document)| document)?,
        Step::Any if documents.modules.len() == 1 => &documents.modules[0].1,
        _ => return None,
    };
    Some((document, resolve_module_path(document, rest)))
}

fn resolve_module_path(document: &Document, steps: &[Step]) -> Resolved {
    let mut best = resolve(document.root(), steps);
    for alternative in record_extension_alternatives(document, steps) {
        let found = resolve(document.root(), &alternative);
        if found.better_than(&best) {
            best = found;
        }
    }
    best
}

/// Exact source spellings for a compiler path normalized under
/// `recordTypes` or explicitly naming `extendRecordTypes`. A module may declare
/// and extend the same Record type, and it may use more than one extension
/// block for that type, so every matching block is a candidate.
fn record_extension_alternatives(document: &Document, steps: &[Step]) -> Vec<Vec<Step>> {
    let [Step::Member(records), record, rest @ ..] = steps else {
        return Vec::new();
    };
    if records != "recordTypes" && records != "extendRecordTypes" {
        return Vec::new();
    }
    let Some(extensions) = document.root().get("extendRecordTypes") else {
        return Vec::new();
    };
    let NodeValue::Sequence(items) = &extensions.value.value else {
        return Vec::new();
    };
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| match record {
            Step::Select { value, .. } => names(item, Some("recordType"), value),
            Step::Any => true,
            Step::Index(_) | Step::Member(_) => false,
        })
        .map(|(index, _)| {
            let mut alternative = vec![
                Step::Member("extendRecordTypes".to_owned()),
                Step::Index(index),
            ];
            alternative.extend_from_slice(rest);
            alternative
        })
        .collect()
}

/// Other spellings of a path in the project document. The compiler names an
/// access profile's permission for an entity under the entity, and one for
/// an action under the action, while the project writes both under the
/// profile, each in the list for its kind.
fn alternatives(steps: &[Step]) -> Vec<Vec<Step>> {
    let under_profile = |group: &str, granted: &str, name: &str, profile: &str, rest: &[Step]| {
        let mut permission = vec![
            Step::Member("accessProfiles".to_owned()),
            Step::Select {
                key: Some("id".to_owned()),
                value: profile.to_owned(),
            },
            Step::Member("permissions".to_owned()),
            Step::Member(group.to_owned()),
            Step::Select {
                key: Some(granted.to_owned()),
                value: name.to_owned(),
            },
        ];
        permission.extend(rest.iter().cloned());
        vec![permission]
    };
    match steps {
        [Step::Member(entities), Step::Select { value: entity, .. }, Step::Member(profiles), Step::Select { value: profile, .. }, rest @ ..]
            if entities == "recordTypes" && profiles == "accessProfiles" =>
        {
            under_profile("records", "recordType", entity, profile, rest)
        }
        [Step::Member(actions), Step::Select { value: action, .. }, Step::Member(permissions), Step::Select {
            key,
            value: profile,
        }, rest @ ..]
            if actions == "actions"
                && permissions == "permissions"
                && key.as_deref() == Some("profile") =>
        {
            under_profile("actions", "action", action, profile, rest)
        }
        [Step::Member(actions), Step::Select { value: action, .. }, Step::Member(execution), Step::Member(proposal), Step::Member(permissions), Step::Select {
            key,
            value: profile,
        }, rest @ ..]
            if actions == "actions"
                && execution == "execution"
                && proposal == "proposal"
                && permissions == "permissions"
                && key.as_deref() == Some("profile") =>
        {
            under_profile("proposals", "action", action, profile, rest)
        }
        _ => Vec::new(),
    }
}

fn at_value(
    document: &Document,
    diagnostic: &registry_breg::Diagnostic,
    severity: Severity,
    action: &str,
    found: &Resolved,
    schematic: &str,
) -> Diagnostic {
    let message = if found.complete {
        diagnostic.message.clone()
    } else {
        format!("{} (in {})", diagnostic.message, without_values(schematic))
    };
    document.diagnostic_at_value(severity, &diagnostic.code, &found.pointer, &message, action)
}

/// The compiler path with the identifiers inside its brackets left out, so
/// the message repeats no value from the file.
fn without_values(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut depth = 0usize;
    for character in path.chars() {
        match character {
            '[' => {
                depth += 1;
                if depth == 1 {
                    out.push('[');
                }
            }
            ']' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    out.push(']');
                }
            }
            _ if depth > 0 => {}
            other => out.push(other),
        }
    }
    out
}

fn action_for(code: &str, severity: Severity) -> &'static str {
    match code {
        "breg.field.pattern-unverified-offline" => RUN_SCHEMA_TEST,
        "breg.package.migration-statement-capacity" => REDUCE_MIGRATION_STATEMENTS,
        "breg.module.lock-digest-missing"
        | "breg.module.lock-digest-required"
        | "breg.module.lock-digest-mismatch"
        | "breg.module.lock-version-mismatch"
        | "breg.module.lock-missing"
        | "breg.module.lock-stale"
        | "breg.module.lock-source-missing"
        | "breg.source.modules-unlocked" => LOCK_MODULES,
        "breg.access.requirements-row-boundary-missing" => WRITE_REQUIRED_ROW_BOUNDARY,
        "breg.access-profile.processing-wider-than-read"
        | "breg.access-profile.read-path-processing-wider-than-read" => {
            ADD_READABLE_OR_REMOVE_PROCESSING
        }
        "breg.access.profile-related-disclosure" => REVIEW_RELATED_DISCLOSURE,
        "breg.access.profile-higher-classification" => "Remove the field from readableFields, or confirm that the profile scopes and purposes admit only callers cleared for this classification.",
        "breg.access.profile-unrestricted-collection" | "breg.access.profile-unrestricted-rows" => "Add claim-bound or membership row boundaries, or restrict the profile scopes and purposes to callers authorized for registry-wide access.",
        "breg.access.profile-create-required-field-not-writable" => "Add the required field to writableFields, or remove create and import from this permission.",
        "breg.field.valid-time-start-required" => "Set required: true on the temporal start field, or remove its role and the temporal binding.",
        "breg.query.temporal-field-not-readable" => "Add the temporal boundary fields to this profile's readableFields if these callers may see them; otherwise remove list and snapshot from its operations.",
        "breg.record-type.api-name-invalid" => "Set apiName to a unique upper camel case name using only ASCII letters and digits.",
        "breg.record-type.stored-field-unfillable" => "Add the field to a grant's writableFields, a fixed Action set, a function plan write, or an import permission, or remove the field.",
        "breg.compile.later-checks-skipped" => "Correct the reported errors, then run bregctl check again to run the skipped checks.",
        "breg.action.handler-source-missing" | "breg.hook.handler-source-missing" | "breg.source.planner-asset-missing" => "Add the referenced Rhai source file at the authored project-relative path, then check again.",
        "breg.action.handler-parse" | "breg.hook.handler-parse" => "Correct the Rhai syntax at the reported line and column, then check again.",
        "breg.action.handler-entrypoint" | "breg.hook.handler-entrypoint" => "Define the required entrypoint in the referenced Rhai source, then check again.",
        "breg.manifest-projection.field-not-visible" => "Make the field readable under the projection's access profile, or remove it and any dependent identifier or vocabulary entry from manifestProjection.",
        "breg.manifest-projection.identifier-duplicate" => "Keep one identifier entry for this field and remove the duplicate entries.",
        "breg.manifest-projection.identifier-field-not-visible" => "Make the identifier field readable and representable under the selected access profile, or remove the identifier entry.",
        "breg.manifest-projection.identifier-kind-missing" => "Set a non-empty identifier kind, or remove the identifier entry.",
        "breg.manifest-projection.vocabulary-not-visible" => "Project a visible field that uses this vocabulary, or remove the vocabulary from manifestProjection.",
        _ if severity == Severity::Warning => REVIEW_FINDING,
        _ => CORRECT_SOURCE,
    }
}

/// One step of a compiler path such as
/// `recordTypes[id=person].fields[name].pattern`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    /// A mapping member.
    Member(String),
    /// `[]`: any item of a list.
    Any,
    /// `[3]`: the item at an index.
    Index(usize),
    /// `[id=person]` or `[person]`: the item that names `value`.
    Select { key: Option<String>, value: String },
}

fn parse_steps(path: &str) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut name = String::new();
    let mut chars = path.chars();
    while let Some(character) = chars.next() {
        match character {
            '.' => {
                if !name.is_empty() {
                    steps.push(Step::Member(std::mem::take(&mut name)));
                }
            }
            '[' => {
                if !name.is_empty() {
                    steps.push(Step::Member(std::mem::take(&mut name)));
                }
                let mut inside = String::new();
                let mut depth = 1usize;
                for inner in chars.by_ref() {
                    match inner {
                        '[' => depth += 1,
                        ']' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    inside.push(inner);
                }
                steps.push(bracket_step(&inside));
            }
            other => name.push(other),
        }
    }
    if !name.is_empty() {
        steps.push(Step::Member(name));
    }
    steps
}

fn bracket_step(inside: &str) -> Step {
    if inside.is_empty() {
        return Step::Any;
    }
    if let Ok(index) = inside.parse::<usize>() {
        return Step::Index(index);
    }
    match inside.split_once('=') {
        Some((key, value)) => Step::Select {
            key: Some(key.to_owned()),
            value: value.to_owned(),
        },
        None => Step::Select {
            key: None,
            value: inside.to_owned(),
        },
    }
}

/// How far a path resolved in one document.
struct Resolved {
    pointer: String,
    depth: usize,
    complete: bool,
}

impl Resolved {
    fn better_than(&self, other: &Resolved) -> bool {
        (self.complete, self.depth) > (other.complete, other.depth)
    }
}

/// Members that name a list item, in the order an unkeyed selector tries
/// them.
const NAMING_MEMBERS: [&str; 7] = [
    "id",
    "recordType",
    "field",
    "name",
    "effect",
    "profile",
    "path",
];

fn resolve(root: &Node, steps: &[Step]) -> Resolved {
    let mut node = root;
    let mut pointer = String::new();
    let mut depth = 0;
    for step in steps {
        let next = match (step, &node.value) {
            (Step::Member(name), NodeValue::Mapping(_)) => node
                .get(name)
                .map(|entry| (escape_pointer_segment(name), &entry.value)),
            (Step::Any, NodeValue::Sequence(items)) if items.len() == 1 => {
                Some(("0".to_owned(), &items[0]))
            }
            (Step::Index(index), NodeValue::Sequence(items)) => {
                items.get(*index).map(|item| (index.to_string(), item))
            }
            (Step::Select { key, value }, NodeValue::Sequence(items)) => items
                .iter()
                .position(|item| names(item, key.as_deref(), value))
                .map(|index| (index.to_string(), &items[index])),
            (Step::Select { value, .. }, NodeValue::Mapping(_)) => node
                .get(value)
                .map(|entry| (escape_pointer_segment(value), &entry.value)),
            _ => None,
        };
        let Some((segment, child)) = next else {
            break;
        };
        pointer.push('/');
        pointer.push_str(&segment);
        node = child;
        depth += 1;
    }
    Resolved {
        pointer,
        depth,
        complete: depth == steps.len(),
    }
}

/// Whether a list item is the one a selector names.
fn names(item: &Node, key: Option<&str>, value: &str) -> bool {
    let text = |node: &Node| matches!(&node.value, NodeValue::String(text) if text.text == value);
    match (&item.value, key) {
        (NodeValue::String(_), None | Some("value" | "field")) => text(item),
        (NodeValue::Mapping(_), Some(key)) => item.get(key).is_some_and(|entry| text(&entry.value)),
        (NodeValue::Mapping(_), None) => NAMING_MEMBERS
            .iter()
            .any(|member| item.get(member).is_some_and(|entry| text(&entry.value))),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporal_and_record_api_name_errors_identify_the_setting_to_change() {
        for (code, setting) in [
            ("breg.field.valid-time-start-required", "required: true"),
            ("breg.query.temporal-field-not-readable", "readableFields"),
            ("breg.record-type.api-name-invalid", "apiName"),
        ] {
            let action = action_for(code, Severity::Error);
            assert!(action.contains(setting), "{code}: {action}");
        }
    }

    #[test]
    fn production_capacity_diagnostic_names_actual_and_supported_statement_counts() {
        assert!(migration_statement_capacity_diagnostic(
            registry_breg::package::MAX_MIGRATION_STATEMENTS
        )
        .is_none());

        let actual = registry_breg::package::MAX_MIGRATION_STATEMENTS + 1;
        let diagnostic = migration_statement_capacity_diagnostic(actual)
            .expect("one statement beyond the supported initial bound is reported");
        assert_eq!(diagnostic.code, "breg.package.migration-statement-capacity");
        assert_eq!(diagnostic.severity, DiagnosticSeverity::Finding);
        assert!(diagnostic.message.contains(&actual.to_string()));
        assert!(diagnostic
            .message
            .contains(&registry_breg::package::MAX_MIGRATION_STATEMENTS.to_string()));
    }

    #[test]
    fn finding_ranks_separate_access_performance_and_hygiene() {
        let ranked = |code| {
            let diagnostic = Diagnostic::warning(code, "", "message", "action");
            serde_json::to_value(RankedDiagnostic {
                diagnostic: &diagnostic,
                rank: finding_rank(&diagnostic),
            })
            .unwrap()["rank"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert_eq!(
            ranked("breg.access.profile-unrestricted-collection"),
            "widens-access"
        );
        assert_eq!(
            ranked("breg.access.profile-subsumes-narrower"),
            "widens-access"
        );
        assert_eq!(
            ranked("breg.access.profile-revision-history"),
            "widens-access"
        );
        assert_eq!(
            ranked("breg.record-type.list-unindexed-filter"),
            "performance"
        );
        assert_eq!(
            ranked("breg.access.profile-higher-classification"),
            "hygiene"
        );
        assert_eq!(ranked("breg.access-profile.duplicate-label"), "hygiene");
    }

    fn document(text: &str) -> Document {
        read_project_yaml("registry.yaml", text.as_bytes())
            .expect("the test project reads")
            .document
    }

    fn module_document(text: &str) -> Document {
        read_module_yaml("module.yaml", text.as_bytes())
            .expect("the test module reads")
            .document
    }

    #[test]
    fn model_provenance_uses_captured_bytes_after_source_files_change() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/fixtures/generic-operator-workflows");
        let temporary = tempfile::tempdir().expect("temporary project");
        let project = temporary.path().canonicalize().expect("physical project");
        let module_file = "modules/record-notes/module.yaml";
        std::fs::create_dir_all(project.join("modules/record-notes")).unwrap();
        for relative in ["registry.yaml", module_file] {
            std::fs::copy(fixture.join(relative), project.join(relative)).unwrap();
        }
        let captured = capture_resolved_project_source(&project).expect("capture valid sources");

        let changed_project = String::from_utf8(captured.project_bytes.clone())
            .unwrap()
            .replacen(
                "  id: generic-registry\n",
                "  id: changed-registry\n  display: {label: Changed registry}\n",
                1,
            );
        let changed_module = String::from_utf8(captured.modules[0].bytes.clone())
            .unwrap()
            .replace("id: internal-note", "id: changed-note");
        std::fs::write(project.join("registry.yaml"), changed_project).unwrap();
        std::fs::write(project.join(module_file), changed_module).unwrap();

        let mut outcome = Outcome::default();
        let documents =
            read_captured_documents(&project, &captured, &mut outcome).expect("captured documents");
        let compiled = compile_captured_registry(&captured, ProfileArg::Authoring)
            .expect("captured sources compile");
        let authoring = serde_json::to_value(documents.model_authoring(&compiled)).unwrap();
        assert_eq!(outcome.files, 2);
        assert!(!outcome.report.has_errors());
        assert_eq!(compiled.registry_id(), "generic-registry");
        assert!(compiled.entities()["record"]
            .fields
            .contains_key("internal-note"));
        assert!(!compiled.entities()["record"]
            .fields
            .contains_key("changed-note"));
        assert!(!authoring["documents"][0]["authoredPaths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|pointer| pointer == "/project/display"));
        assert!(authoring["documents"][1]["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|binding| binding["sourcePointer"] == "/extendRecordTypes/0/fields/0"));
    }

    #[test]
    fn authoring_lists_exact_pointers_for_each_source_document() {
        let documents = Documents {
            project: document(
                "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject:\n  id: example\n  canonicalBaseIri: https://example.invalid\n  version: 0.1.0\n  defaultLanguage: en\naccessProfiles: []\n",
            ),
            modules: vec![(
                "base".to_owned(),
                module_document(
                    "apiVersion: id.registrystack.org/formats/breg/module/v1alpha1\nkind: BRegModule\nid: base\nversion: 0.1.0\n",
                ),
            )],
        };

        let authoring = serde_json::to_value(documents.authoring()).expect("authoring serializes");
        let source_documents = authoring["documents"]
            .as_array()
            .expect("documents is an array");
        assert_eq!(source_documents[0]["kind"], "BRegProject");
        assert_eq!(source_documents[0]["file"], "registry.yaml");
        assert!(source_documents[0].get("module").is_none());
        assert_eq!(
            source_documents[0]["authoredPaths"],
            serde_json::json!([
                "",
                "/apiVersion",
                "/kind",
                "/project",
                "/project/id",
                "/project/canonicalBaseIri",
                "/project/version",
                "/project/defaultLanguage",
                "/accessProfiles"
            ])
        );
        assert_eq!(source_documents[1]["kind"], "BRegModule");
        assert_eq!(source_documents[1]["module"], "base");
        assert_eq!(source_documents[1]["file"], "modules/base/module.yaml");
        assert_eq!(
            source_documents[1]["authoredPaths"],
            serde_json::json!(["", "/apiVersion", "/kind", "/id", "/version"])
        );
    }

    #[test]
    fn a_same_module_record_extension_resolves_to_the_extension_member() {
        let documents = Documents {
            project: document(
                "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject:\n  id: example\n  canonicalBaseIri: https://example.invalid\n  version: 0.1.0\n  defaultLanguage: en\n",
            ),
            modules: vec![(
                "combined".to_owned(),
                module_document(
                    "apiVersion: id.registrystack.org/formats/breg/module/v1alpha1\nkind: BRegModule\nid: combined\nversion: 0.1.0\nrecordTypes:\n  - id: record\n    route: records\n    mutationMode: mutable\n    fields:\n      - {id: base, type: string, maximumLength: 20, classification: internal}\nextendRecordTypes:\n  - recordType: record\n    fields:\n      - {id: extension, type: string, maximumLength: 20, classification: internal}\n",
                ),
            )],
        };
        let mut authoring = documents.authoring();

        documents.push_record_member_binding(
            &mut authoring,
            Some("combined"),
            "record",
            "/recordTypes/0/fields/1".to_owned(),
            &id_item_steps("fields", "extension"),
        );

        assert_eq!(authoring.documents[1].bindings.len(), 1);
        assert_eq!(
            authoring.documents[1].bindings[0].source_pointer,
            "/extendRecordTypes/0/fields/0"
        );
    }

    #[test]
    fn named_filter_and_sort_fields_resolve_to_distinct_scalar_elements() {
        let source = document(
            "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject:\n  id: test\n  version: 1.0.0\n  canonicalBaseIri: https://example.test\n  defaultLanguage: en\naccessProfiles:\n  - id: reader\n    principalClaim: principal\n    requiredScopes: unrestricted\n    permissions:\n      records:\n        - recordType: record\n          operations: [list]\n          rowBoundaries: unrestricted\n          filterableFields: [name, category]\n          sortableFields: [name, category]\n",
        );
        for member in ["filterableFields", "sortableFields"] {
            for (index, field) in ["name", "category"].iter().enumerate() {
                let path = format!(
                    "accessProfiles[id=reader].permissions.records[recordType=record].{member}[field={field}]"
                );
                let resolved = resolve(source.root(), &parse_steps(&path));
                assert!(resolved.complete, "{path}");
                assert_eq!(
                    resolved.pointer,
                    format!("/accessProfiles/0/permissions/records/0/{member}/{index}")
                );
            }
        }
    }

    #[test]
    fn a_missing_requirement_row_boundary_names_the_member_and_the_accepted_form() {
        let action = action_for(
            "breg.access.requirements-row-boundary-missing",
            Severity::Error,
        );
        assert_ne!(action, CORRECT_SOURCE);
        assert!(action.contains("rowBoundaries"), "{action}");
        assert!(action.contains("unrestricted"), "{action}");
    }

    #[test]
    fn a_compiler_path_resolves_to_the_pointer_of_the_value_it_names() {
        let project = document(
            "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject:\n  id: example\n  canonicalBaseIri: https://example.invalid\n  version: 0.1.0\n  defaultLanguage: en\nrecordTypes:\n  - id: first\n    route: firsts\n    mutationMode: mutable\n    fields:\n      - id: label\n        type: string\n        maximumLength: 20\n        required: true\n        classification: internal\n  - id: second\n    route: seconds\n    mutationMode: mutable\n    fields:\n      - id: code\n        type: string\n        maximumLength: 20\n        required: true\n        classification: internal\n",
        );
        let found = resolve(
            project.root(),
            &parse_steps("recordTypes[id=second].fields[code].type"),
        );
        assert_eq!(found.pointer, "/recordTypes/1/fields/0/type");
        assert!(found.complete);

        let partial = resolve(
            project.root(),
            &parse_steps("recordTypes[id=second].fields[absent].pattern"),
        );
        assert_eq!(partial.pointer, "/recordTypes/1/fields");
        assert!(!partial.complete);
    }

    #[test]
    fn a_selector_value_may_hold_a_dot() {
        assert_eq!(
            parse_steps("recordTypes[id=a].readPaths[path=address.city]"),
            vec![
                Step::Member("recordTypes".to_owned()),
                Step::Select {
                    key: Some("id".to_owned()),
                    value: "a".to_owned()
                },
                Step::Member("readPaths".to_owned()),
                Step::Select {
                    key: Some("path".to_owned()),
                    value: "address.city".to_owned()
                },
            ]
        );
        assert_eq!(
            without_values("recordTypes[id=a].readPaths[path=address.city]"),
            "recordTypes[].readPaths[]"
        );
    }

    #[test]
    fn an_entity_access_path_is_found_under_the_profile_that_grants_it() {
        let project = document(
            "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject:\n  id: example\n  canonicalBaseIri: https://example.invalid\n  version: 0.1.0\n  defaultLanguage: en\naccessProfiles:\n  - id: clerk\n    principalClaim: registry_principal\n    requiredScopes: unrestricted\n    permissions:\n      records:\n        - recordType: other\n          operations: [get]\n          rowBoundaries: unrestricted\n        - recordType: record\n          operations: [get]\n          rowBoundaries: unrestricted\n",
        );
        let steps = parse_steps("recordTypes[id=record].accessProfiles[id=clerk].operations");
        let found = alternatives(&steps)
            .iter()
            .map(|alternative| resolve(project.root(), alternative))
            .find(|found| found.complete)
            .expect("the profile's permission names the entity");
        assert_eq!(
            found.pointer,
            "/accessProfiles/0/permissions/records/1/operations"
        );
    }

    #[test]
    fn an_action_permission_path_is_found_under_the_profile_that_grants_it() {
        let project = document(
            "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject:\n  id: example\n  canonicalBaseIri: https://example.invalid\n  version: 0.1.0\n  defaultLanguage: en\naccessProfiles:\n  - id: reader\n    principalClaim: registry_principal\n    requiredScopes: unrestricted\n  - id: steward\n    principalClaim: registry_principal\n    requiredScopes: unrestricted\n    permissions:\n      records:\n        - recordType: record\n          operations: [get]\n          rowBoundaries: unrestricted\n      actions:\n        - action: import-record\n          operations: [invoke]\n          targets:\n            - {recordType: other, rowBoundaries: unrestricted}\n            - {recordType: record, rowBoundaries: unrestricted}\n",
        );
        let steps = parse_steps(
            "actions[id=import-record].permissions[profile=steward].targets[recordType=record].rowBoundaries",
        );
        let found = alternatives(&steps)
            .iter()
            .map(|alternative| resolve(project.root(), alternative))
            .find(|found| found.complete)
            .expect("the profile's permission names the action");
        assert_eq!(
            found.pointer,
            "/accessProfiles/1/permissions/actions/0/targets/1/rowBoundaries"
        );
    }

    #[test]
    fn a_proposal_permission_path_is_found_under_the_profile_that_grants_it() {
        let project = document(
            "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject:\n  id: example\n  canonicalBaseIri: https://example.invalid\n  version: 0.1.0\n  defaultLanguage: en\naccessProfiles:\n  - id: reader\n    principalClaim: registry_principal\n    requiredScopes: unrestricted\n  - id: steward\n    principalClaim: registry_principal\n    requiredScopes: unrestricted\n    permissions:\n      proposals:\n        - action: update-record\n          operations: [edit]\n          targets:\n            - {recordType: other, rowBoundaries: unrestricted}\n            - {recordType: record, rowBoundaries: unrestricted}\n",
        );
        let steps = parse_steps(
            "actions[id=update-record].execution.proposal.permissions[profile=steward].targets[recordType=record].rowBoundaries",
        );
        let found = alternatives(&steps)
            .iter()
            .map(|alternative| resolve(project.root(), alternative))
            .find(|found| found.complete)
            .expect("the profile's permission names the Proposal action");
        assert_eq!(
            found.pointer,
            "/accessProfiles/1/permissions/proposals/0/targets/1/rowBoundaries"
        );
    }
}
