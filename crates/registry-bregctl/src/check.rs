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
    escape_pointer_segment, Diagnostic, Document, Node, NodeValue, Report, Severity, Source,
    MAXIMUM_DOCUMENT_BYTES,
};
use serde::Serialize;

use super::{
    capture_project_source, compile_captured_project, ensure_source_entry_identity, file_check,
    has_parent_component, inspect_package_integrity, path_diagnostic, read_module_directory_names,
    write_ctl_report, OutputFormat, ProfileArg, SafeDir, SafeEntry, SafePathError,
    DOMAIN_REFUSAL_EXIT, OPERATIONAL_FAILURE_EXIT,
};

/// The registered kind of `registry.yaml`, named as the `artifact` of a
/// diagnostic about the project as a whole.
const PROJECT_ARTIFACT: &str = registry_breg::contract::PROJECT_FORMAT.kind;
/// The registered kind of a module's `module.yaml`.
const MODULE_ARTIFACT: &str = registry_breg::contract::MODULE_FORMAT.kind;

const CORRECT_SOURCE: &str =
    "Correct the source at this path so it meets the rule the message states.";
const WRITE_REQUIRED_ROW_BOUNDARY: &str =
    "Write a rowBoundaries list on this permission with one entry for each boundary the entity's accessRequirements declare (field, claim, and operator); the unrestricted sentinel does not satisfy a requirement.";
const REVIEW_FINDING: &str =
    "Review the finding, and change the source if the behavior it describes is not intended.";
const RUN_SCHEMA_TEST: &str =
    "Run bregctl test against a disposable PostgreSQL database to verify the pattern.";
const LOCK_MODULES: &str =
    "Run bregctl project lock against this project, then review the module lock change it records.";
const FIND_PROJECT: &str =
    "Point bregctl check at a readable project directory that holds registry.yaml, or create one with bregctl init.";
const REBUILD_PACKAGE: &str = "Rebuild the package with bregctl package PROJECT --test-receipt RECEIPT --output BUILD; a package is checked as the build wrote it, unmodified.";

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
    diagnostics: &'a [Diagnostic],
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
            diagnostics: outcome.report.diagnostics(),
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

/// The compiled registry when the project compiled, so the runtime file can be
/// held to it.
fn check_project(
    project: &Path,
    profile: ProfileArg,
    outcome: &mut Outcome,
) -> Option<CompiledRegistry> {
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
    let documents = read_documents(project, outcome)?;
    let source = match capture_project_source(project) {
        Ok(source) => source,
        Err(diagnostic) => {
            outcome
                .report
                .push(place(project, &documents, diagnostic, Severity::Error));
            return None;
        }
    };
    match compile_captured_project(&source, profile, "check") {
        Ok(compiled) => {
            for finding in compiled
                .findings()
                .iter()
                .cloned()
                .chain(unverified_patterns(&compiled))
            {
                let severity = severity_of(finding.severity);
                outcome
                    .report
                    .push(place(project, &documents, finding, severity));
            }
            outcome.revision = Some(compiled.revision().to_owned());
            Some(compiled)
        }
        Err(failure) => {
            for refusal in failure.diagnostics {
                let diagnostic = registry_breg::Diagnostic {
                    severity: refusal.severity,
                    code: refusal.code,
                    path: refusal.path,
                    message: refusal.message,
                };
                let severity = severity_of(diagnostic.severity);
                outcome
                    .report
                    .push(place(project, &documents, diagnostic, severity));
            }
            None
        }
    }
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
                    path: format!("entities[{}].fields[{}].pattern", entity.id, field.id),
                    message: "Offline check validates pattern structure and bounds only. Run bregctl test against disposable PostgreSQL to verify native pattern syntax and storage behavior.".to_owned(),
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
    match decoded_project {
        Some(document) if !refused => Some(Documents {
            project: document,
            modules,
        }),
        _ => {
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
            None
        }
    }
}

/// Keep a decoded document's warnings; report a refused one's diagnostics.
fn decode(read: Result<Document, Report>, outcome: &mut Outcome) -> Option<Document> {
    match read {
        Ok(document) => {
            outcome.report.extend(document.warnings());
            Some(document)
        }
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
        PackageError::RetiredApiVersion => "config.retired-api-version",
    }
}

fn package_action(error: &PackageError) -> &'static str {
    match error {
        PackageError::UnsafePath => "Point --package at the package directory itself, by a path without symbolic links.",
        PackageError::Permissions => "Remove group and other write permission from the package directory and its files (chmod -R go-w), then check again.",
        PackageError::Read => "Point --package at a readable package directory that bregctl package wrote.",
        PackageError::RetiredApiVersion => "Rebuild the package with this bregctl: bregctl package PROJECT --test-receipt RECEIPT --output BUILD, then apply the rebuilt package to a new database: bregctl apply --initial --package BUILD.",
        _ => REBUILD_PACKAGE,
    }
}

// ---------------------------------------------------------------------------
// Placing a compiler diagnostic in the document it names

/// The compiler's diagnostic as a shared one, placed at the document, JSON
/// pointer, line, and column its path names.
fn place(
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
            return file_level(project.join("registry.yaml"), Some(PROJECT_ARTIFACT))
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
                let found = resolve(document.root(), &steps);
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
        let found = resolve(document.root(), &steps);
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
    Some((document, resolve(document.root(), rest)))
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
            if entities == "entities" && profiles == "accessProfiles" =>
        {
            under_profile("entities", "entity", entity, profile, rest)
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
        "breg.module.lock-digest-missing"
        | "breg.module.lock-digest-required"
        | "breg.module.lock-digest-mismatch"
        | "breg.module.lock-version-mismatch"
        | "breg.module.lock-missing"
        | "breg.module.lock-stale"
        | "breg.module.lock-source-missing"
        | "breg.source.modules-unlocked" => LOCK_MODULES,
        "breg.access.requirements-row-boundary-missing" => WRITE_REQUIRED_ROW_BOUNDARY,
        _ if severity == Severity::Warning => REVIEW_FINDING,
        _ => CORRECT_SOURCE,
    }
}

/// One step of a compiler path such as
/// `entities[id=person].fields[name].pattern`.
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
const NAMING_MEMBERS: [&str; 7] = ["id", "entity", "field", "name", "effect", "profile", "path"];

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
        (NodeValue::String(_), None | Some("value")) => text(item),
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

    fn document(text: &str) -> Document {
        read_project_yaml("registry.yaml", text.as_bytes())
            .expect("the test project reads")
            .document
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
            "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject:\n  id: example\n  canonicalBaseIri: https://example.invalid\n  version: 0.1.0\n  defaultLanguage: en\nentities:\n  - id: first\n    route: firsts\n    mutationMode: mutable\n    fields:\n      - id: label\n        type: string\n        maximumLength: 20\n        required: true\n        classification: internal\n  - id: second\n    route: seconds\n    mutationMode: mutable\n    fields:\n      - id: code\n        type: string\n        maximumLength: 20\n        required: true\n        classification: internal\n",
        );
        let found = resolve(
            project.root(),
            &parse_steps("entities[id=second].fields[code].type"),
        );
        assert_eq!(found.pointer, "/entities/1/fields/0/type");
        assert!(found.complete);

        let partial = resolve(
            project.root(),
            &parse_steps("entities[id=second].fields[absent].pattern"),
        );
        assert_eq!(partial.pointer, "/entities/1/fields");
        assert!(!partial.complete);
    }

    #[test]
    fn a_selector_value_may_hold_a_dot() {
        assert_eq!(
            parse_steps("entities[id=a].readPaths[path=address.city]"),
            vec![
                Step::Member("entities".to_owned()),
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
            without_values("entities[id=a].readPaths[path=address.city]"),
            "entities[].readPaths[]"
        );
    }

    #[test]
    fn an_entity_access_path_is_found_under_the_profile_that_grants_it() {
        let project = document(
            "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject:\n  id: example\n  canonicalBaseIri: https://example.invalid\n  version: 0.1.0\n  defaultLanguage: en\naccessProfiles:\n  - id: clerk\n    principalClaim: registry_principal\n    requiredScopes: unrestricted\n    permissions:\n      entities:\n        - entity: other\n          operations: [get]\n          rowBoundaries: unrestricted\n        - entity: record\n          operations: [get]\n          rowBoundaries: unrestricted\n",
        );
        let steps = parse_steps("entities[id=record].accessProfiles[id=clerk].operations");
        let found = alternatives(&steps)
            .iter()
            .map(|alternative| resolve(project.root(), alternative))
            .find(|found| found.complete)
            .expect("the profile's permission names the entity");
        assert_eq!(
            found.pointer,
            "/accessProfiles/0/permissions/entities/1/operations"
        );
    }

    #[test]
    fn an_action_permission_path_is_found_under_the_profile_that_grants_it() {
        let project = document(
            "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject:\n  id: example\n  canonicalBaseIri: https://example.invalid\n  version: 0.1.0\n  defaultLanguage: en\naccessProfiles:\n  - id: reader\n    principalClaim: registry_principal\n    requiredScopes: unrestricted\n  - id: steward\n    principalClaim: registry_principal\n    requiredScopes: unrestricted\n    permissions:\n      entities:\n        - entity: record\n          operations: [get]\n          rowBoundaries: unrestricted\n      actions:\n        - action: import-record\n          operations: [invoke]\n          targets:\n            - {entity: other, rowBoundaries: unrestricted}\n            - {entity: record, rowBoundaries: unrestricted}\n",
        );
        let steps = parse_steps(
            "actions[id=import-record].permissions[profile=steward].targets[entity=record].rowBoundaries",
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
}
