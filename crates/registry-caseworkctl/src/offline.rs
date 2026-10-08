// SPDX-License-Identifier: Apache-2.0
//! The offline test files of a Casework project: fixtures under `fixtures/`,
//! simulations under `simulations/`, and the holiday sets simulations pin
//! under `simulations/holiday-sets/`. `check` reads every one (CFG-CHECK-2)
//! and resolves each reference and display against `casework.yaml`
//! (CFG-ID-4, CFG-VAL-9); `test` evaluates each against the project.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read as _};
use std::path::Path;

use anyhow::Result;
use registry_casework_core::{
    parse_elapsed_seconds, read_offline_file, CaseworkFixture, CaseworkHolidaySet, CaseworkProject,
    CaseworkSimulation, ClockPolicy, ConfigFinding, HolidaySetDocument, OfflineFile,
    OfflineFileKind, ReviewKindPolicy, ReviewValidationError, ReviewValidationReason,
    SubjectActivity, TargetExpectation, MAXIMUM_REVIEW_DISPLAY_BYTES, MAXIMUM_REVIEW_VALUE_DEPTH,
    NO_RULE,
};
use registry_platform_yaml::{
    escape_pointer_segment, Decoded, Diagnostic, Document, Related, Report, Severity, Source,
    MAXIMUM_DOCUMENT_BYTES,
};
use serde_json::Value;

use crate::display_schema::{json_types, render_types};

/// One offline file the project holds, read and checked on its own.
pub(crate) struct Located<T> {
    /// The path relative to the project directory, such as
    /// `fixtures/payment-review.yaml`.
    pub relative: String,
    pub decoded: Decoded<T>,
}

/// Every offline file a project holds that its own format accepts.
#[derive(Default)]
pub(crate) struct OfflineFiles {
    pub fixtures: Vec<Located<CaseworkFixture>>,
    pub simulations: Vec<Located<CaseworkSimulation>>,
    /// Holiday-set revisions by holiday-set id and revision, the pair the
    /// file name states.
    pub holiday_sets: BTreeMap<(String, u64), Located<CaseworkHolidaySet>>,
    /// The names of the files under `holiday-sets/` that were read and
    /// refused. A pin whose file is one of them is not reported missing:
    /// the file's own diagnostics say why it was not accepted.
    pub refused_holiday_files: BTreeSet<String>,
    /// How many files were read, accepted or not.
    pub files_read: usize,
}

impl OfflineFiles {
    /// The holiday-set revisions, as the runtime's holiday-set documents.
    pub fn holiday_documents(&self) -> BTreeMap<(String, u64), HolidaySetDocument> {
        self.holiday_sets
            .iter()
            .map(|(key, located)| (key.clone(), located.decoded.value.to_document()))
            .collect()
    }
}

const DIRECTORIES: [(&str, OfflineFileKind); 3] = [
    ("fixtures", OfflineFileKind::Fixture),
    ("simulations", OfflineFileKind::Simulation),
    ("simulations/holiday-sets", OfflineFileKind::HolidaySet),
];

/// The directory under `simulations/` that holds holiday sets.
const HOLIDAY_SETS: &str = "holiday-sets";

/// The most YAML files a project check reads from one offline directory.
pub(crate) const MAXIMUM_DIRECTORY_FILES: usize = 1024;

const FIXTURE_UNKNOWN: &str = "casework.fixture.unknown-reference";
const SIMULATION_UNKNOWN: &str = "casework.simulation.unknown-reference";
const FIXTURE_NOT_MET: &str = "casework.fixture.expectation-not-met";
const MISSING_HOLIDAY_SET: &str = "casework.simulation.missing-holiday-set";
const CLOCK_EXPECTATION: &str = "casework.simulation.clock-expectation";
const CLOCK_INPUT: &str = "casework.simulation.clock-input";

/// Read every `.yaml` and `.yml` file directly under `fixtures/`,
/// `simulations/`, and `simulations/holiday-sets/` (CFG-CHECK-2). A directory
/// that does not exist holds nothing; anything else the scan cannot read is
/// reported, never skipped silently.
pub(crate) fn scan(project: &Path) -> (OfflineFiles, Report) {
    let mut files = OfflineFiles::default();
    let mut report = Report::default();
    for (directory, kind) in DIRECTORIES {
        scan_directory(project, directory, kind, &mut files, &mut report);
    }
    report.set_files_checked(files.files_read);
    (files, report)
}

fn scan_directory(
    project: &Path,
    directory: &str,
    kind: OfflineFileKind,
    files: &mut OfflineFiles,
    report: &mut Report,
) {
    let path = project.join(directory);
    let shown = path.display().to_string();
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        // `simulations/` is not a directory, which its own scan reports.
        Err(error) if error.kind() == io::ErrorKind::NotADirectory => return,
        Err(_) => {
            report.push(unreadable(&shown));
            return;
        }
        Ok(metadata) if !metadata.file_type().is_dir() => {
            report.push(file_diagnostic(
                Severity::Error,
                "casework.project.not-a-directory",
                &shown,
                format!("{directory}/ is not a plain directory, so caseworkctl cannot read the files it should hold"),
                format!("Replace the link or file at {directory}/ with a directory holding the files."),
            ));
            return;
        }
        Ok(_) => {}
    }
    let mut entries =
        match fs::read_dir(&path).and_then(|entries| entries.collect::<io::Result<Vec<_>>>()) {
            Ok(entries) => entries,
            Err(_) => {
                report.push(unreadable(&shown));
                return;
            }
        };
    entries.sort_by_key(fs::DirEntry::file_name);
    let yaml_files = entries
        .iter()
        .filter(|entry| is_yaml(&entry.path()))
        .count();
    if yaml_files > MAXIMUM_DIRECTORY_FILES {
        report.push(file_diagnostic(
            Severity::Error,
            "casework.project.too-many-files",
            &shown,
            format!("{directory}/ holds more than the {MAXIMUM_DIRECTORY_FILES} YAML files caseworkctl reads from one directory, so none of them was read"),
            format!("Remove YAML files from {directory}/ until no more than {MAXIMUM_DIRECTORY_FILES} remain."),
        ));
        return;
    }
    for entry in entries {
        let entry_path = entry.path();
        let entry_shown = entry_path.display().to_string();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => {
                report.push(unreadable(&entry_shown));
                continue;
            }
        };
        let name = entry.file_name();
        if file_type.is_dir() {
            if kind == OfflineFileKind::Simulation && name == HOLIDAY_SETS {
                continue;
            }
            report.push(file_diagnostic(
                Severity::Warning,
                "casework.project.unread-directory",
                &entry_shown,
                format!("caseworkctl reads only the files directly under {directory}/, so nothing in this directory is read"),
                format!("Move the files this directory holds up into {directory}/, or move the directory out of {directory}/."),
            ));
            continue;
        }
        if !is_yaml(&entry_path) {
            continue;
        }
        if !file_type.is_file() {
            report.push(file_diagnostic(
                Severity::Error,
                "casework.project.not-a-regular-file",
                &entry_shown,
                "this path is not a regular file; caseworkctl reads offline files only as regular files",
                "Replace the link or special file with a regular file holding the document.",
            ));
            continue;
        }
        let bytes = match read_bounded(&entry_path) {
            Ok(bytes) => bytes,
            Err(_) => {
                report.push(unreadable(&entry_shown));
                continue;
            }
        };
        files.files_read += 1;
        let relative = format!("{directory}/{}", name.to_string_lossy());
        match read_offline_file(&entry_shown, &bytes, kind) {
            Ok(OfflineFile::Fixture(decoded)) => {
                report.extend(decoded.document.warnings());
                files.fixtures.push(Located {
                    relative,
                    decoded: *decoded,
                });
            }
            Ok(OfflineFile::Simulation(decoded)) => {
                report.extend(decoded.document.warnings());
                files.simulations.push(Located {
                    relative,
                    decoded: *decoded,
                });
            }
            Ok(OfflineFile::HolidaySet(decoded)) => {
                let name = name.to_string_lossy().into_owned();
                accept_holiday_set(
                    &name,
                    Located {
                        relative,
                        decoded: *decoded,
                    },
                    files,
                    report,
                );
            }
            Err(refused) => {
                if kind == OfflineFileKind::HolidaySet {
                    files
                        .refused_holiday_files
                        .insert(name.to_string_lossy().into_owned());
                }
                report.extend(refused);
            }
        }
    }
}

fn is_yaml(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension == "yaml" || extension == "yml")
}

/// Keep a holiday-set revision whose file name is
/// `<holidaySet>-<revision>.yaml`, the name a simulation finds it by; refuse
/// any other name, so one file holds each pinned revision.
fn accept_holiday_set(
    name: &str,
    located: Located<CaseworkHolidaySet>,
    files: &mut OfflineFiles,
    report: &mut Report,
) {
    let value = &located.decoded.value;
    let key = (value.holiday_set.to_string(), value.revision.get());
    report.extend(located.decoded.document.warnings());
    if name != format!("{}-{}.yaml", key.0, key.1) {
        report.push(located.decoded.document.diagnostic_at_value(
            Severity::Error,
            "casework.holiday-set.misnamed",
            "/holidaySet",
            "the file name does not state this holiday set and revision, and a simulation finds a revision by its file name",
            "Rename the file to <holidaySet>-<revision>.yaml, using this file's holidaySet and revision.",
        ));
        files.refused_holiday_files.insert(name.to_owned());
        return;
    }
    files.holiday_sets.insert(key, located);
}

/// Read the simulation at `file`, given on the command line, and the holiday
/// sets it pins from `holiday-sets/` beside it.
pub(crate) fn read_simulation_file(file: &Path) -> Result<OfflineFiles, Report> {
    let shown = file.display().to_string();
    let bytes = read_bounded(file).map_err(|_| Report::new(vec![unreadable(&shown)]))?;
    let decoded = CaseworkSimulation::read(&shown, &bytes)?;
    let mut files = OfflineFiles {
        files_read: 1,
        ..OfflineFiles::default()
    };
    let mut report = decoded.document.warnings();
    let directory = file.parent().unwrap_or(Path::new("")).join(HOLIDAY_SETS);
    for (holiday_set, revision) in &decoded.value.holiday_revisions {
        let name = format!("{holiday_set}-{}.yaml", revision.get());
        let path = directory.join(&name);
        let path_shown = path.display().to_string();
        match fs::symlink_metadata(&path) {
            // The resolution reports the missing revision at its pin.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Ok(metadata) if !metadata.file_type().is_file() => {
                report.push(file_diagnostic(
                    Severity::Error,
                    "casework.project.not-a-regular-file",
                    &path_shown,
                    "this path is not a regular file; caseworkctl reads offline files only as regular files",
                    "Replace the link or special file with a regular file holding the document.",
                ));
                continue;
            }
            _ => {}
        }
        let Ok(bytes) = read_bounded(&path) else {
            report.push(unreadable(&path_shown));
            continue;
        };
        files.files_read += 1;
        match read_offline_file(&path_shown, &bytes, OfflineFileKind::HolidaySet) {
            Ok(OfflineFile::HolidaySet(holidays)) => {
                let located = Located {
                    relative: format!("{HOLIDAY_SETS}/{name}"),
                    decoded: *holidays,
                };
                accept_holiday_set(&name, located, &mut files, &mut report);
            }
            Ok(_) => {}
            Err(refused) => report.extend(refused),
        }
    }
    files.simulations.push(Located {
        relative: shown,
        decoded,
    });
    report.set_files_checked(files.files_read);
    if report.has_errors() {
        Err(report)
    } else {
        Ok(files)
    }
}

/// The bytes of a file, read up to one byte past the shared reader's bound
/// so the reader refuses an oversized file itself.
pub(crate) fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAXIMUM_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The local development clients file a project may hold.
pub(crate) const DEV_CLIENTS: &str = "dev-clients.yaml";

/// Read the project's `dev-clients.yaml` when it holds one, and check it
/// against `casework.yaml` when that file was accepted (CFG-CHECK-2).
/// Returns how many files were read and every diagnostic found.
pub(crate) fn check_dev_clients(
    project: &Path,
    policy: Option<&CaseworkProject>,
) -> (usize, Report) {
    let path = project.join(DEV_CLIENTS);
    let shown = path.display().to_string();
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return (0, Report::default()),
        Ok(metadata) if !metadata.file_type().is_file() => {
            return (
                0,
                Report::new(vec![file_diagnostic(
                    Severity::Error,
                    "casework.project.not-a-regular-file",
                    &shown,
                    "this path is not a regular file; caseworkctl reads dev-clients.yaml only as a regular file",
                    "Replace the link or special file with a regular file holding the document.",
                )]),
            );
        }
        _ => {}
    }
    let Ok(bytes) = read_bounded(&path) else {
        return (0, Report::new(vec![unreadable(&shown)]));
    };
    let read = match policy {
        Some(policy) => crate::dev::config::read_against(&shown, &bytes, policy),
        None => crate::dev::config::read(&shown, &bytes),
    };
    match read {
        Ok(decoded) => (1, decoded.document.warnings()),
        Err(refused) => (1, refused),
    }
}

/// Where a project keeps the state of its local development session.
pub(crate) const DEV_STATE: &str = ".casework/dev/state.json";

/// Read the session state `caseworkctl dev` retains in the project when it
/// holds one, and check it (CFG-CHECK-1, CFG-CHECK-2). Returns how many files
/// were read and every diagnostic found.
pub(crate) fn check_dev_state(project: &Path) -> (usize, Report) {
    let path = project.join(DEV_STATE);
    let shown = path.display().to_string();
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return (0, Report::default()),
        Ok(metadata) if !metadata.file_type().is_file() => {
            return (
                0,
                Report::new(vec![file_diagnostic(
                    Severity::Error,
                    "casework.project.not-a-regular-file",
                    &shown,
                    "this path is not a regular file; caseworkctl reads the session state only as a regular file",
                    "Remove the link or special file, then start the session again with caseworkctl dev start.",
                )]),
            );
        }
        _ => {}
    }
    let Ok(bytes) = read_bounded(&path) else {
        return (0, Report::new(vec![unreadable(&shown)]));
    };
    (1, crate::dev::check_state(&shown, &bytes))
}

fn unreadable(file: &str) -> Diagnostic {
    file_diagnostic(
        Severity::Error,
        "casework.project.unreadable-file",
        file,
        "caseworkctl cannot read this path",
        "Make the path readable by the user running caseworkctl, or remove it.",
    )
}

fn file_diagnostic(
    severity: Severity,
    code: &str,
    file: &str,
    message: impl Into<String>,
    action: impl Into<String>,
) -> Diagnostic {
    let mut diagnostic = match severity {
        Severity::Error => Diagnostic::error(code, "", message, action),
        _ => Diagnostic::warning(code, "", message, action),
    };
    diagnostic.source = Some(Source {
        file: file.to_owned(),
        line: None,
        column: None,
    });
    diagnostic
}

/// A note about `pointer` in `casework.yaml`, placed where it is written,
/// or where its nearest written ancestor is.
pub(crate) fn project_related(
    project: &Decoded<CaseworkProject>,
    pointer: &str,
    message: &str,
) -> Related {
    let mut at = pointer;
    let start = loop {
        if let Some(span) = project.document.span_of(at) {
            break Some(span.start);
        }
        match at.rfind('/') {
            Some(index) => at = &at[..index],
            None => break None,
        }
    };
    Related {
        file: project.document.file().to_owned(),
        line: start.map(|position| position.line),
        column: start.map(|position| position.column),
        path: pointer.to_owned(),
        message: message.to_owned(),
    }
}

/// An error about `pointer` in `document`, placed at its nearest written
/// ancestor when the member is absent, with a note into `casework.yaml`.
fn absent_at(
    document: &Document,
    code: &'static str,
    pointer: &str,
    message: &str,
    action: &str,
    related: Related,
) -> Diagnostic {
    let mut diagnostic = ConfigFinding::new(code, pointer, message, action).to_diagnostic(document);
    diagnostic.related.push(related);
    diagnostic
}

/// An error at `pointer` in `document`, with a note into `casework.yaml`.
fn error_at(
    document: &Document,
    code: &str,
    pointer: &str,
    message: &str,
    action: &str,
    related: Related,
) -> Diagnostic {
    let mut diagnostic =
        document.diagnostic_at_value(Severity::Error, code, pointer, message, action);
    diagnostic.related.push(related);
    diagnostic
}

/// Resolve every reference the offline files make into `casework.yaml`
/// (CFG-ID-4), check each fixture display against its review kind's
/// `displaySchema` (CFG-VAL-9), and check that each simulation pins the
/// holiday sets and states the inputs its request's clock reads.
pub(crate) fn resolve(project: &Decoded<CaseworkProject>, files: &OfflineFiles) -> Report {
    let mut report = Report::default();
    for fixture in &files.fixtures {
        for diagnostic in resolve_fixture(project, &fixture.decoded) {
            report.push(diagnostic);
        }
    }
    for simulation in &files.simulations {
        for diagnostic in resolve_simulation(project, &simulation.decoded, files) {
            report.push(diagnostic);
        }
    }
    report
}

fn queue_diagnostic(
    project: &Decoded<CaseworkProject>,
    document: &Document,
    code: &str,
    queue: &str,
) -> Option<Diagnostic> {
    if project
        .value
        .queues
        .iter()
        .any(|declared| declared.id == queue)
    {
        return None;
    }
    Some(error_at(
        document,
        code,
        "/expect/queue",
        "the queue is not declared under queues in casework.yaml",
        "Name a queue declared under queues in casework.yaml.",
        project_related(project, "/queues", "the project declares its queues here"),
    ))
}

fn resolve_fixture(
    project: &Decoded<CaseworkProject>,
    fixture: &Decoded<CaseworkFixture>,
) -> Vec<Diagnostic> {
    let policy = &project.value;
    let document = &fixture.document;
    let value = &fixture.value;
    let mut found = Vec::new();
    found.extend(queue_diagnostic(
        project,
        document,
        FIXTURE_UNKNOWN,
        value.expect.queue.as_str(),
    ));
    if let Some(review) = &value.review {
        let Some(index) = policy
            .review_kinds
            .iter()
            .position(|kind| kind.id == review.kind.as_str())
        else {
            found.push(error_at(
                document,
                FIXTURE_UNKNOWN,
                "/review/kind",
                "the review kind is not declared under reviewKinds in casework.yaml",
                "Name a review kind declared under reviewKinds in casework.yaml.",
                project_related(
                    project,
                    "/reviewKinds",
                    "the project declares its review kinds here",
                ),
            ));
            return found;
        };
        let kind = &policy.review_kinds[index];
        for (position, outcome) in value
            .expect
            .outcomes
            .iter()
            .flat_map(|list| list.iter().enumerate())
        {
            if !kind
                .outcomes
                .iter()
                .any(|declared| declared.id == outcome.as_str())
            {
                found.push(error_at(
                    document,
                    FIXTURE_UNKNOWN,
                    &format!("/expect/outcomes/{position}"),
                    "the review kind declares no outcome with this id",
                    "Name an outcome the review kind declares under outcomes in casework.yaml, or remove it.",
                    project_related(
                        project,
                        &format!("/reviewKinds/{index}/outcomes"),
                        "the review kind declares its outcomes here",
                    ),
                ));
            }
        }
        if let Err(error) = kind.validate_display(&Value::Object(review.display.clone())) {
            found.push(display_diagnostic(project, index, kind, fixture, &error));
        }
    }
    if let Some(request) = &value.request {
        match policy
            .sources
            .iter()
            .position(|source| source.id == request.source.as_str())
        {
            None => found.push(error_at(
                document,
                FIXTURE_UNKNOWN,
                "/request/source",
                "the source is not declared under sources in casework.yaml",
                "Name a source declared under sources in casework.yaml.",
                project_related(project, "/sources", "the project declares its sources here"),
            )),
            Some(index) => {
                if !policy.sources[index]
                    .requests
                    .iter()
                    .any(|declared| declared.entity == request.entity.as_str())
                {
                    found.push(error_at(
                        document,
                        FIXTURE_UNKNOWN,
                        "/request/entity",
                        "the source declares no request for this entity in casework.yaml",
                        "Name an entity the source declares under requests in casework.yaml.",
                        project_related(
                            project,
                            &format!("/sources/{index}/requests"),
                            "the source declares its requests here",
                        ),
                    ));
                }
            }
        }
    }
    found
}

/// The refusal of a fixture display the review kind's `displaySchema` or
/// the display bounds refuse, placed at the refused value and naming the
/// type the schema declares for it, never the value (CFG-VAL-9, CFG-SEC-3).
fn display_diagnostic(
    project: &Decoded<CaseworkProject>,
    index: usize,
    kind: &ReviewKindPolicy,
    fixture: &Decoded<CaseworkFixture>,
    error: &ReviewValidationError,
) -> Diagnostic {
    let document = &fixture.document;
    match error.reason {
        ReviewValidationReason::MaximumBytesExceeded => {
            return document.diagnostic_at_value(
                Severity::Error,
                "casework.fixture.display-too-large",
                "/review/display",
                &format!("the display is larger than the {MAXIMUM_REVIEW_DISPLAY_BYTES} bytes of canonical JSON a review display holds"),
                "Shorten the display; keep long text in the source and show a reference to it.",
            );
        }
        ReviewValidationReason::MaximumDepthExceeded => {
            return document.diagnostic_at_value(
                Severity::Error,
                "casework.fixture.display-too-large",
                "/review/display",
                &format!("the display nests deeper than the {MAXIMUM_REVIEW_VALUE_DEPTH} levels a review display allows"),
                &format!("Flatten the display to at most {MAXIMUM_REVIEW_VALUE_DEPTH} levels."),
            );
        }
        _ => {}
    }
    let relative = error.path.strip_prefix("$.display").unwrap_or("");
    let schema_at = format!("/reviewKinds/{index}/displaySchema");
    let (declared, declared_at) = declared_schema(&kind.display_schema, relative, &schema_at);
    let display = &fixture.value.review.as_ref().map(|review| &review.display);
    let written = display.and_then(|display| {
        Value::Object(display.clone())
            .pointer(relative)
            .map(json_type)
    });
    let message = match (relative.is_empty(), declared.and_then(json_types), written) {
        (true, _, _) => {
            "this display does not satisfy the review kind's displaySchema".to_owned()
        }
        (false, Some(types), Some(written)) if !admits(&types, written) => format!(
            "the review kind's displaySchema declares this value as {}, and it is written as {written}",
            render_types(&types)
        ),
        (false, Some(types), _) => format!(
            "this value is outside what the review kind's displaySchema allows for a value declared as {}",
            render_types(&types)
        ),
        (false, None, _) => {
            "this value does not satisfy the review kind's displaySchema".to_owned()
        }
    };
    let action = if relative.is_empty() {
        format!("Write a display the displaySchema at {declared_at} in casework.yaml accepts: every required member, no member it does not declare, and each value as it declares.")
    } else {
        format!("Write a value the displaySchema accepts here; it is declared at {declared_at} in casework.yaml.")
    };
    error_at(
        document,
        "casework.fixture.display-mismatch",
        &format!("/review/display{relative}"),
        &message,
        &action,
        project_related(
            project,
            &declared_at,
            "the display schema declares the value here",
        ),
    )
}

/// The subschema `displaySchema` declares at `relative`, a JSON pointer into
/// the display, found through `properties` and `items`, with its pointer
/// into `casework.yaml`; `None` past the first step neither keyword states,
/// and the pointer then names the last schema found.
fn declared_schema<'a>(
    schema: &'a Value,
    relative: &str,
    base: &str,
) -> (Option<&'a Value>, String) {
    let mut current = schema;
    let mut at = base.to_owned();
    for token in relative.split('/').skip(1) {
        let name = token.replace("~1", "/").replace("~0", "~");
        if let Some(property) = current
            .get("properties")
            .and_then(|properties| properties.get(&name))
        {
            at = format!("{at}/properties/{token}");
            current = property;
        } else if token.parse::<usize>().is_ok()
            && current.get("items").is_some_and(Value::is_object)
        {
            at = format!("{at}/items");
            current = &current["items"];
        } else {
            return (None, at);
        }
    }
    (Some(current), at)
}

/// The JSON Schema type of a written value. A number with no fraction is an
/// integer, as JSON Schema counts it.
pub(crate) fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) => {
            if number.is_i64()
                || number.is_u64()
                || number.as_f64().is_some_and(|float| float.fract() == 0.0)
            {
                "integer"
            } else {
                "number"
            }
        }
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub(crate) fn admits(types: &BTreeSet<String>, written: &str) -> bool {
    types.contains(written) || (written == "integer" && types.contains("number"))
}

fn resolve_simulation(
    project: &Decoded<CaseworkProject>,
    simulation: &Decoded<CaseworkSimulation>,
    files: &OfflineFiles,
) -> Vec<Diagnostic> {
    let policy = &project.value;
    let document = &simulation.document;
    let value = &simulation.value;
    let mut found = Vec::new();
    found.extend(queue_diagnostic(
        project,
        document,
        SIMULATION_UNKNOWN,
        value.expect.queue.as_str(),
    ));
    for (holiday_set, revision) in &value.holiday_revisions {
        let pointer = format!(
            "/holidayRevisions/{}",
            escape_pointer_segment(holiday_set.as_str())
        );
        if !policy
            .calendars
            .iter()
            .any(|calendar| calendar.holiday_set == holiday_set.as_str())
        {
            let mut diagnostic = document.diagnostic_at_key(
                Severity::Error,
                SIMULATION_UNKNOWN,
                &pointer,
                "no calendar in casework.yaml names this holiday set",
                "Pin a holiday set a calendar names under calendars in casework.yaml, or remove the pin.",
            );
            diagnostic.related.push(project_related(
                project,
                "/calendars",
                "the project declares its calendars here",
            ));
            found.push(diagnostic);
        } else if !files
            .holiday_sets
            .contains_key(&(holiday_set.to_string(), revision.get()))
            && !files
                .refused_holiday_files
                .contains(&format!("{holiday_set}-{}.yaml", revision.get()))
        {
            found.push(document.diagnostic_at_value(
                Severity::Error,
                MISSING_HOLIDAY_SET,
                &pointer,
                "no file under holiday-sets/ beside this simulation holds this revision",
                "Write holiday-sets/<holidaySet>-<revision>.yaml beside this simulation for the pinned revision, or pin a revision one holds.",
            ));
        }
    }
    let Some(source_index) = policy
        .sources
        .iter()
        .position(|source| source.id == value.source.as_str())
    else {
        found.push(error_at(
            document,
            SIMULATION_UNKNOWN,
            "/source",
            "the source is not declared under sources in casework.yaml",
            "Name a source declared under sources in casework.yaml.",
            project_related(project, "/sources", "the project declares its sources here"),
        ));
        return found;
    };
    let source = &policy.sources[source_index];
    let Some(request_index) = source
        .requests
        .iter()
        .position(|request| request.entity == value.subject.entity.as_str())
    else {
        found.push(error_at(
            document,
            SIMULATION_UNKNOWN,
            "/subject/entity",
            "the source declares no request for this entity in casework.yaml",
            "Name an entity the source declares under requests in casework.yaml.",
            project_related(
                project,
                &format!("/sources/{source_index}/requests"),
                "the source declares its requests here",
            ),
        ));
        return found;
    };
    let request = &source.requests[request_index];
    let request_at = format!("/sources/{source_index}/requests/{request_index}");
    for field in value.subject.fields.keys() {
        if !request
            .projection
            .iter()
            .any(|projected| projected == field.as_str())
        {
            let mut diagnostic = document.diagnostic_at_key(
                Severity::Error,
                "casework.simulation.unprojected-field",
                &format!("/subject/fields/{}", escape_pointer_segment(field.as_str())),
                "the request's projection does not list this field, so routing never reads it",
                "Add the field to the request's projection in casework.yaml, or remove it here.",
            );
            diagnostic.related.push(project_related(
                project,
                &format!("{request_at}/projection"),
                "the request lists the fields routing reads here",
            ));
            found.push(diagnostic);
        }
    }
    if let Some(rule) = &value.expect.rule {
        if rule.as_str() != NO_RULE
            && !request
                .routing
                .iter()
                .any(|declared| declared.id == rule.as_str())
        {
            found.push(error_at(
                document,
                SIMULATION_UNKNOWN,
                "/expect/rule",
                "the request declares no routing rule with this id",
                "Name a rule under the request's routing in casework.yaml, or write rule: none when no rule matches.",
                project_related(project, &format!("{request_at}/routing"), "the request declares its routing rules here"),
            ));
        }
    }
    found.extend(resolve_clock(
        project,
        simulation,
        &request_at,
        request.clock.as_deref(),
    ));
    found
}

/// Check that a simulation expects only what its request's clock computes,
/// and states and pins every input that clock reads.
fn resolve_clock(
    project: &Decoded<CaseworkProject>,
    simulation: &Decoded<CaseworkSimulation>,
    request_at: &str,
    clock: Option<&str>,
) -> Vec<Diagnostic> {
    let policy = &project.value;
    let document = &simulation.document;
    let value = &simulation.value;
    let expect = &value.expect;
    let mut found = Vec::new();
    let clock_index = clock.and_then(|id| {
        policy
            .clocks
            .iter()
            .position(|declared| declared.id() == id)
    });
    let present = |member: &str| match member {
        "dueAt" => expect.due_at.is_some(),
        "dueState" => expect.due_state.is_some(),
        "eligibleReminders" => expect.eligible_reminders.is_some(),
        "eligibleSteps" => expect.eligible_steps.is_some(),
        _ => expect.remaining_milliseconds.is_some(),
    };
    let Some(clock_index) = clock_index else {
        for member in [
            "dueAt",
            "dueState",
            "eligibleReminders",
            "eligibleSteps",
            "remainingMilliseconds",
        ] {
            if present(member) {
                found.push(error_at(
                    document,
                    CLOCK_EXPECTATION,
                    &format!("/expect/{member}"),
                    "this expectation describes a clock, and the request declares none",
                    "Remove the member, or declare a clock on the request in casework.yaml.",
                    project_related(project, request_at, "the request is declared here"),
                ));
            }
        }
        return found;
    };
    let clock_at = format!("/clocks/{clock_index}");
    match &policy.clocks[clock_index] {
        ClockPolicy::Activity {
            calendar,
            reminders,
            steps,
            ..
        } => {
            if present("remainingMilliseconds") {
                found.push(error_at(
                    document,
                    CLOCK_EXPECTATION,
                    "/expect/remainingMilliseconds",
                    "remainingMilliseconds describes a subject clock, and the request's clock is an activity clock",
                    "Remove remainingMilliseconds; an activity clock is checked with dueAt, dueState, eligibleReminders, and eligibleSteps.",
                    project_related(project, &clock_at, "the request's clock is declared here"),
                ));
            }
            if value.subject.activity != SubjectActivity::Review {
                found.push(error_at(
                    document,
                    CLOCK_INPUT,
                    "/subject/activity",
                    "the request's activity clock starts when the record enters its review stage, so it runs only for activity: review",
                    "Write activity: review, or simulate a request whose clock fits this activity.",
                    project_related(project, &clock_at, "the request's clock is declared here"),
                ));
            }
            if value.subject.stage_entered_at.is_none() {
                found.push(absent_at(
                    document,
                    CLOCK_INPUT,
                    "/subject/stageEnteredAt",
                    "the request's activity clock starts at subject.stageEnteredAt, which is absent",
                    "Write subject.stageEnteredAt as an RFC 3339 timestamp with an offset.",
                    project_related(project, &clock_at, "the request's clock is declared here"),
                ));
            }
            if let Some(calendar_index) = policy
                .calendars
                .iter()
                .position(|declared| declared.id == *calendar)
            {
                let holiday_set = &policy.calendars[calendar_index].holiday_set;
                if !value
                    .holiday_revisions
                    .keys()
                    .any(|pinned| pinned.as_str() == holiday_set)
                {
                    found.push(absent_at(
                        document,
                        MISSING_HOLIDAY_SET,
                        "/holidayRevisions",
                        "the request's activity clock reads a calendar whose holiday set this simulation does not pin",
                        "Pin the calendar's holiday set under holidayRevisions with the revision to evaluate.",
                        project_related(
                            project,
                            &format!("/calendars/{calendar_index}/holidaySet"),
                            "the calendar names its holiday set here",
                        ),
                    ));
                }
            }

            for (member, declared, list, collection) in [
                (
                    "eligibleReminders",
                    reminders
                        .iter()
                        .map(|reminder| reminder.id.as_str())
                        .collect::<Vec<_>>(),
                    &expect.eligible_reminders,
                    "reminders",
                ),
                (
                    "eligibleSteps",
                    steps
                        .iter()
                        .map(|step| step.id.as_str())
                        .collect::<Vec<_>>(),
                    &expect.eligible_steps,
                    "steps",
                ),
            ] {
                for (position, id) in list.iter().flat_map(|list| list.iter().enumerate()) {
                    if !declared.contains(&id.as_str()) {
                        found.push(error_at(
                            document,
                            SIMULATION_UNKNOWN,
                            &format!("/expect/{member}/{position}"),
                            &format!("the request's clock declares no {} with this id", &collection[..collection.len() - 1]),
                            &format!("Name an id the clock declares under {collection} in casework.yaml, or remove it."),
                            project_related(project, &format!("{clock_at}/{collection}"), "the clock declares them here"),
                        ));
                    }
                }
            }
        }
        ClockPolicy::Subject { .. } => {
            for member in ["dueState", "eligibleReminders", "eligibleSteps"] {
                if present(member) {
                    found.push(error_at(
                        document,
                        CLOCK_EXPECTATION,
                        &format!("/expect/{member}"),
                        "this expectation describes an activity clock, and the request's clock is a subject clock",
                        "Remove the member; a subject clock is checked with dueAt and remainingMilliseconds.",
                        project_related(project, &clock_at, "the request's clock is declared here"),
                    ));
                }
            }
            if value.subject.review_timing.is_none() {
                found.push(absent_at(
                    document,
                    CLOCK_INPUT,
                    "/subject/reviewTiming",
                    "the request's subject clock reads subject.reviewTiming, which is absent",
                    "Write subject.reviewTiming with firstSubmittedAt and pausedMilliseconds.",
                    project_related(project, &clock_at, "the request's clock is declared here"),
                ));
            }
        }
    }
    found
}

/// The request a source description describes for `entity`, with its
/// pointer in the description.
pub(crate) fn described_request<'a>(
    description: &'a Value,
    entity: &str,
) -> Option<(String, &'a Value)> {
    match description.get("requests").and_then(Value::as_array) {
        Some(requests) => requests
            .iter()
            .enumerate()
            .find(|(_, described)| described["requestEntity"] == entity)
            .map(|(index, described)| (format!("/requests/{index}"), described)),
        None => Some(("/request".to_owned(), &description["request"]))
            .filter(|(_, described)| described["requestEntity"] == entity),
    }
}

/// Evaluate one fixture `resolve` accepted against the project. Each unmet
/// expectation is one error at the expectation, with a note at the
/// declaration it differs from.
pub(crate) fn evaluate_fixture(
    project_dir: &Path,
    project: &Decoded<CaseworkProject>,
    fixture: &Decoded<CaseworkFixture>,
) -> Result<Vec<Diagnostic>> {
    let policy = &project.value;
    let document = &fixture.document;
    let expect = &fixture.value.expect;
    let mut found = Vec::new();
    if let Some(review) = &fixture.value.review {
        let Some(index) = policy
            .review_kinds
            .iter()
            .position(|kind| kind.id == review.kind.as_str())
        else {
            return Ok(found);
        };
        let kind = &policy.review_kinds[index];
        if kind
            .stages
            .first()
            .is_some_and(|stage| stage.queue != expect.queue.as_str())
        {
            found.push(error_at(
                document,
                FIXTURE_NOT_MET,
                "/expect/queue",
                "the review kind's first stage uses another queue",
                "Write the queue the review kind's first stage names in casework.yaml.",
                project_related(
                    project,
                    &format!("/reviewKinds/{index}/stages/0/queue"),
                    "the first stage names its queue here",
                ),
            ));
        }
        if let Some(outcomes) = &expect.outcomes {
            let expected = outcomes
                .iter()
                .map(|outcome| outcome.as_str())
                .collect::<BTreeSet<_>>();
            let declared = kind
                .outcomes
                .iter()
                .map(|outcome| outcome.id.as_str())
                .collect::<BTreeSet<_>>();
            if expected != declared {
                found.push(error_at(
                    document,
                    FIXTURE_NOT_MET,
                    "/expect/outcomes",
                    "the review kind declares an outcome this list leaves out",
                    "List every outcome id the review kind declares in casework.yaml, or remove outcomes to leave them unchecked.",
                    project_related(project, &format!("/reviewKinds/{index}/outcomes"), "the review kind declares its outcomes here"),
                ));
            }
        }
    }
    if let Some(request) = &fixture.value.request {
        let Some(source_index) = policy
            .sources
            .iter()
            .position(|source| source.id == request.source.as_str())
        else {
            return Ok(found);
        };
        let source = &policy.sources[source_index];
        let Some(request_index) = source
            .requests
            .iter()
            .position(|declared| declared.entity == request.entity.as_str())
        else {
            return Ok(found);
        };
        let declared = &source.requests[request_index];
        let request_at = format!("/sources/{source_index}/requests/{request_index}");
        if declared.queue != expect.queue.as_str() {
            found.push(error_at(
                document,
                FIXTURE_NOT_MET,
                "/expect/queue",
                "the request uses another queue",
                "Write the queue the request names in casework.yaml.",
                project_related(
                    project,
                    &format!("{request_at}/queue"),
                    "the request names its queue here",
                ),
            ));
        }
        match (&expect.target, &declared.target) {
            (None, _) | (Some(TargetExpectation::Absent(_)), None) => {}
            (Some(TargetExpectation::Absent(_)), Some(_)) => found.push(error_at(
                document,
                FIXTURE_NOT_MET,
                "/expect/target",
                "the request declares an elapsed target",
                "Write the request's target as target: {elapsedMinutes: N}, or remove the target from the request in casework.yaml.",
                project_related(project, &format!("{request_at}/target"), "the request declares its target here"),
            )),
            (Some(TargetExpectation::Elapsed(_)), None) => found.push(error_at(
                document,
                FIXTURE_NOT_MET,
                "/expect/target",
                "the request declares no target",
                "Write target: none, or declare a target on the request in casework.yaml.",
                project_related(project, &request_at, "the request is declared here"),
            )),
            (Some(TargetExpectation::Elapsed(expected)), Some(target)) => {
                let seconds = i64::try_from(expected.elapsed_minutes.get())
                    .ok()
                    .and_then(|minutes| minutes.checked_mul(60));
                if parse_elapsed_seconds(&target.after.elapsed) != seconds {
                    found.push(error_at(
                        document,
                        FIXTURE_NOT_MET,
                        "/expect/target/elapsedMinutes",
                        "the request's target is another elapsed time",
                        "Write the request's target in minutes, from the elapsed time the request declares in casework.yaml.",
                        project_related(project, &format!("{request_at}/target/after/elapsed"), "the request declares its elapsed time here"),
                    ));
                }
            }
        }
        if let Some(mode) = expect.application_mode {
            if !project_dir.join(&source.description).is_file() {
                found.push(error_at(
                    document,
                    crate::project::MISSING_SOURCE_DESCRIPTION,
                    "/expect/applicationMode",
                    "the source description that states the application mode is not imported",
                    "Import the source description with caseworkctl source add, or remove applicationMode.",
                    project_related(project, &format!("/sources/{source_index}/description"), "the source names its description here"),
                ));
            } else {
                let description = crate::policy::load_source_description(project_dir, source)?;
                let described = described_request(&description, &declared.entity);
                let actual = described
                    .as_ref()
                    .and_then(|(_, described)| described["onApproved"]["mode"].as_str());
                if actual != Some(mode.as_str()) {
                    let mut diagnostic = document.diagnostic_at_value(
                        Severity::Error,
                        FIXTURE_NOT_MET,
                        "/expect/applicationMode",
                        "the source description states another application mode for this request",
                        "Write the mode the source description states at onApproved.mode for this request.",
                    );
                    diagnostic.related.push(Related {
                        file: project_dir.join(&source.description).display().to_string(),
                        line: None,
                        column: None,
                        path: described
                            .map_or_else(String::new, |(at, _)| format!("{at}/onApproved/mode")),
                        message: "the source description states the mode here".to_owned(),
                    });
                    found.push(diagnostic);
                }
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(report: &Report) -> Vec<(&str, Severity)> {
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.severity))
            .collect()
    }

    fn example_fixture() -> String {
        fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../products/casework/examples/payment-review/fixtures/payment-review.yaml",
            ),
        )
        .unwrap()
    }

    #[test]
    fn a_scan_reads_yml_files_and_ignores_files_that_are_not_yaml() {
        let root = crate::canonical_tempdir();
        let fixtures = root.path().join("fixtures");
        fs::create_dir(&fixtures).unwrap();
        fs::write(fixtures.join("payment-review.yml"), example_fixture()).unwrap();
        fs::write(fixtures.join("notes.txt"), "not a fixture").unwrap();

        let (files, report) = scan(root.path());

        assert!(codes(&report).is_empty(), "{report}");
        assert_eq!(files.files_read, 1);
        assert_eq!(files.fixtures.len(), 1);
        assert_eq!(files.fixtures[0].relative, "fixtures/payment-review.yml");
    }

    #[test]
    fn a_scan_reports_what_it_cannot_read_instead_of_skipping_it() {
        let root = crate::canonical_tempdir();
        let fixtures = root.path().join("fixtures");
        fs::create_dir_all(fixtures.join("nested")).unwrap();
        let elsewhere = root.path().join("elsewhere.yaml");
        fs::write(&elsewhere, example_fixture()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, fixtures.join("linked.yaml")).unwrap();
        fs::write(root.path().join("simulations"), "not a directory").unwrap();

        let (files, report) = scan(root.path());

        assert_eq!(files.files_read, 0);
        assert_eq!(
            codes(&report),
            [
                ("casework.project.not-a-regular-file", Severity::Error),
                ("casework.project.unread-directory", Severity::Warning),
                ("casework.project.not-a-directory", Severity::Error),
            ],
            "{report}"
        );
    }

    #[test]
    fn a_scan_refuses_a_directory_holding_more_yaml_files_than_it_reads() {
        let root = crate::canonical_tempdir();
        let fixtures = root.path().join("fixtures");
        fs::create_dir(&fixtures).unwrap();
        for index in 0..=MAXIMUM_DIRECTORY_FILES {
            fs::write(fixtures.join(format!("fixture-{index}.yaml")), "").unwrap();
        }

        let (files, report) = scan(root.path());

        assert_eq!(files.files_read, 0);
        assert_eq!(
            codes(&report),
            [("casework.project.too-many-files", Severity::Error)],
            "{report}"
        );
        let diagnostic = &report.diagnostics()[0];
        assert!(diagnostic.suggested_action.contains("1024"), "{report}");
    }

    /// Scan a copy of the multi-stage example, whose simulations pin
    /// `office-holidays` revision 7, with that revision's file replaced by
    /// `holidays`, and resolve it; the codes of both reports.
    fn check_pinned_holiday_set(holidays: &str) -> Vec<String> {
        let example = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/examples/multi-stage-routing-clocks");
        let root = crate::canonical_tempdir();
        let holiday_sets = root.path().join("simulations/holiday-sets");
        fs::create_dir_all(&holiday_sets).unwrap();
        for simulation in ["friday-review.yaml", "resubmitted-response.yaml"] {
            fs::copy(
                example.join("simulations").join(simulation),
                root.path().join("simulations").join(simulation),
            )
            .unwrap();
        }
        fs::write(holiday_sets.join("office-holidays-7.yaml"), holidays).unwrap();
        let project = CaseworkProject::read(
            "casework.yaml",
            &fs::read(example.join("casework.yaml")).unwrap(),
        )
        .unwrap();

        let (files, scanned) = scan(root.path());
        let resolved = resolve(&project, &files);

        scanned
            .diagnostics()
            .iter()
            .chain(resolved.diagnostics())
            .map(|diagnostic| diagnostic.code.clone())
            .collect()
    }

    #[test]
    fn a_pinned_holiday_set_file_the_reader_refuses_is_not_also_reported_missing() {
        let holidays = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../products/casework/examples/multi-stage-routing-clocks/simulations/holiday-sets/office-holidays-7.yaml",
        ))
        .unwrap();
        assert!(check_pinned_holiday_set(&holidays).is_empty());

        let refused = format!("{holidays}conformanceAlias: *conformance\n");
        assert_eq!(check_pinned_holiday_set(&refused), ["yaml.alias"]);

        let misnamed =
            holidays.replace("holidaySet: office-holidays", "holidaySet: other-holidays");
        assert_eq!(
            check_pinned_holiday_set(&misnamed),
            ["casework.holiday-set.misnamed"]
        );
    }

    #[test]
    fn a_pinned_holiday_set_with_no_file_is_reported_missing() {
        let root = crate::canonical_tempdir();
        let example = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/examples/multi-stage-routing-clocks");
        let simulations = root.path().join("simulations");
        fs::create_dir(&simulations).unwrap();
        fs::copy(
            example.join("simulations/friday-review.yaml"),
            simulations.join("friday-review.yaml"),
        )
        .unwrap();
        let project = CaseworkProject::read(
            "casework.yaml",
            &fs::read(example.join("casework.yaml")).unwrap(),
        )
        .unwrap();

        let (files, scanned) = scan(root.path());
        let resolved = resolve(&project, &files);

        assert!(codes(&scanned).is_empty(), "{scanned}");
        assert_eq!(
            codes(&resolved),
            [(MISSING_HOLIDAY_SET, Severity::Error)],
            "{resolved}"
        );
    }
}
