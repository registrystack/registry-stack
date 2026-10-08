//! `registry-render check`: the offline check of an authored bundle, a
//! deployment package, and a runtime file (CFG-CHECK-1). It reports every
//! finding at once in the shared diagnostic shape: the manifest and label
//! tables as the shared reader read them, label-script font coverage and
//! per-locale label key sets, every other YAML file of the bundle identified
//! by its envelope (CFG-CHECK-2), and the runtime file as `serve` reads it,
//! with no package, secret material, or listener.
//! The rendered file closure is governed where a render exists to capture
//! it: the golden suite pins each acceptance bundle's closure and proves
//! every file it reads is manifest-governed, and `compile --json` reports
//! `deps` for authors reviewing their own bundles.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use registry_platform_yaml::{Diagnostic, NodeValue, Reader, Report, Severity, Source};
use serde::Serialize;

use crate::bundle::{bundle_file_name, read_root_manifest, Bundle};
use crate::labels::{labels_path, read_labels, LABELS_KIND};
use crate::manifest::{error_at, read_manifest, MANIFEST_FILE, MANIFEST_KIND};
use crate::problem::{ProblemKind, RenderProblem};
use crate::runtime::RUNTIME_KIND;

/// The `apiVersion` of the report `check --format json` writes.
pub const CTL_REPORT_API_VERSION: &str = "id.registrystack.org/formats/render/ctl-report/v1alpha1";
/// The `kind` of the report `check --format json` writes.
pub const CTL_REPORT_KIND: &str = "RenderCtlReport";

/// Something was refused, or a warning was reported under `--deny-warnings`.
const DOMAIN_REFUSAL_EXIT: i32 = 1;
/// An input could not be read at all (CFG-DIAG-4).
const OPERATIONAL_FAILURE_EXIT: i32 = 3;

/// How `check` writes what it found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Diagnostics in the shared human shape (CFG-DIAG-2).
    #[default]
    Human,
    /// One report object on standard output (CFG-DIAG-1).
    Json,
}

/// What one `registry-render check` run reads and how it reports.
#[derive(Debug)]
pub struct CheckRequest<'a> {
    /// The authored bundle or package directory.
    pub bundle: Option<&'a Path>,
    /// The runtime file, as given on the command line.
    pub runtime: Option<&'a Path>,
    /// The directory the runtime file's audit file must resolve under.
    pub require_audit_under: Option<&'a Path>,
    /// Substitute `${NAME}` expressions in the runtime file from the process
    /// environment and check every value.
    pub environment: bool,
    pub format: OutputFormat,
    pub deny_warnings: bool,
}

/// What the bundle check found.
struct BundleCheck {
    diagnostics: Vec<Diagnostic>,
    files: usize,
    unavailable: bool,
    summary: Option<BundleSummary>,
}

/// The bundle a clean or warning-only check accepted, as the report states it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleSummary {
    bundle_version: u32,
    bundle_hash: String,
    fonts: usize,
    governed_files: usize,
    documents: Vec<DocumentSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DocumentSummary {
    id: String,
    version: u32,
    entry_file: String,
    labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pdf_standard: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditSummary {
    proven_under: String,
}

/// The report `check --format json` writes: the envelope members every ctl
/// report opens with, then the counts, what was accepted, and every
/// diagnostic.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CtlReport<'a> {
    ok: bool,
    command: &'static str,
    status: &'static str,
    api_version: &'static str,
    kind: &'static str,
    files_checked: usize,
    errors: usize,
    warnings: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<&'a BundleSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audit: Option<AuditSummary>,
    diagnostics: serde_json::Value,
}

/// Run `registry-render check` and report every finding (CFG-DIAG-4): exit 0
/// when nothing was refused, 1 when something was or a warning was reported
/// under `--deny-warnings`, and 3 when an input could not be read.
pub fn run(request: &CheckRequest<'_>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let mut diagnostics = Vec::new();
    let mut files = 0;
    let mut unavailable = false;
    let mut summary = None;
    let bundle_dir = match (request.bundle, request.runtime) {
        (Some(dir), _) => Some(dir),
        (None, None) => Some(Path::new(".")),
        (None, Some(_)) => None,
    };
    if let Some(dir) = bundle_dir {
        let checked = check_bundle(dir);
        diagnostics.extend(checked.diagnostics);
        files += checked.files;
        unavailable |= checked.unavailable;
        summary = checked.summary.map(|summary| (dir, summary));
    }
    let mut audit = None;
    if let Some(path) = request.runtime {
        let (checked, missing) =
            check_runtime_file(path, request.environment, request.require_audit_under);
        files += 1;
        unavailable |= missing;
        let proven = !missing
            && !checked
                .iter()
                .any(|diagnostic| diagnostic.severity == Severity::Error);
        if let (Some(root), true) = (request.require_audit_under, proven) {
            audit = Some(AuditSummary {
                proven_under: root.display().to_string(),
            });
        }
        diagnostics.extend(checked);
    }
    let mut report = Report::new(diagnostics);
    report.set_files_checked(files);
    let exit = if unavailable {
        OPERATIONAL_FAILURE_EXIT
    } else if report.has_errors() || (request.deny_warnings && report.warning_count() > 0) {
        DOMAIN_REFUSAL_EXIT
    } else {
        0
    };
    match request.format {
        OutputFormat::Json => {
            let document = CtlReport {
                ok: exit == 0,
                command: "check",
                status: match exit {
                    0 => "complete",
                    OPERATIONAL_FAILURE_EXIT => "operational-failure",
                    _ => "domain-refusal",
                },
                api_version: CTL_REPORT_API_VERSION,
                kind: CTL_REPORT_KIND,
                files_checked: files,
                errors: report.error_count(),
                warnings: report.warning_count(),
                bundle: summary.as_ref().map(|(_, summary)| summary),
                audit,
                diagnostics: report.to_json_value(),
            };
            let written = serde_json::to_writer_pretty(&mut *stdout, &document)
                .map_err(std::io::Error::other)
                .and_then(|()| writeln!(stdout));
            if written.is_err() {
                return OPERATIONAL_FAILURE_EXIT;
            }
        }
        OutputFormat::Human if exit == 0 => {
            let mut text = String::new();
            if let Some((dir, summary)) = &summary {
                text.push_str(&human_summary(dir, summary));
            }
            if let Some(audit) = &audit {
                text.push_str(&format!(
                    "audit file resolves under {}\n",
                    audit.proven_under
                ));
            }
            text.push_str(&report.render_human());
            if stdout.write_all(text.as_bytes()).is_err() {
                return OPERATIONAL_FAILURE_EXIT;
            }
        }
        OutputFormat::Human => {
            let sentence = if exit == OPERATIONAL_FAILURE_EXIT {
                "registry-render check could not read all of its input."
            } else {
                "registry-render check refused the input."
            };
            let _ = write!(stderr, "{sentence}\n{}", report.render_human());
        }
    }
    exit
}

/// One line per document, then one for the bundle.
fn human_summary(dir: &Path, summary: &BundleSummary) -> String {
    let mut text = String::new();
    for document in &summary.documents {
        text.push_str(&format!(
            "document {:<16} v{}  entry {}  labels [{}]  pdf {}\n",
            document.id,
            document.version,
            document.entry_file,
            document.labels.join(", "),
            document.pdf_standard.as_deref().unwrap_or("plain"),
        ));
    }
    text.push_str(&format!(
        "bundle {} v{} hash {} ({} fonts, {} documents, {} governed files)\n",
        dir.display(),
        summary.bundle_version,
        &summary.bundle_hash[..16.min(summary.bundle_hash.len())],
        summary.fonts,
        summary.documents.len(),
        summary.governed_files,
    ));
    text
}

/// Check the bundle or package directory `dir`: read it as `compile` and
/// `serve` do, then report its warnings, its label findings, and every YAML
/// file no document reads.
fn check_bundle(dir: &Path) -> BundleCheck {
    if let Some(diagnostic) = unreadable(dir) {
        return BundleCheck {
            diagnostics: vec![diagnostic],
            files: 0,
            unavailable: true,
            summary: None,
        };
    }
    let bundle = match Bundle::load_for_preview(dir) {
        Ok(bundle) => bundle,
        Err(problem) => {
            let linked = if problem.diagnostics.is_empty() {
                linked_members(dir)
            } else {
                Vec::new()
            };
            let diagnostics = if linked.is_empty() {
                load_refusal(dir, problem)
            } else {
                linked
            };
            let files = diagnostics
                .iter()
                .filter_map(|diagnostic| diagnostic.source.as_ref())
                .map(|source| source.file.as_str())
                .collect::<BTreeSet<_>>()
                .len();
            return BundleCheck {
                diagnostics,
                files,
                unavailable: false,
                summary: None,
            };
        }
    };
    let mut diagnostics = bundle.warnings.clone();
    diagnostics.extend(check_script_coverage(&bundle));
    diagnostics.extend(check_label_key_sets(&bundle));
    let (scanned, scanned_files) = scan_unread_yaml(dir, &bundle);
    diagnostics.extend(scanned);
    let schema_files = bundle
        .documents
        .values()
        .filter_map(|document| document.spec.schema.as_ref())
        .collect::<BTreeSet<_>>()
        .len();
    let summary = BundleSummary {
        bundle_version: bundle.manifest.bundle_version,
        bundle_hash: bundle.bundle_hash.clone(),
        fonts: bundle.fonts.len(),
        governed_files: bundle.package_inputs().len(),
        documents: bundle
            .documents
            .values()
            .map(|document| DocumentSummary {
                id: document.spec.id.clone(),
                version: document.spec.version,
                entry_file: document.spec.entry.display().to_string(),
                labels: document.spec.labels.clone(),
                pdf_standard: document.spec.pdf_standard.map(|s| s.to_string()),
            })
            .collect(),
    };
    BundleCheck {
        diagnostics,
        files: 1 + bundle.label_sources.len() + schema_files + scanned_files,
        unavailable: false,
        summary: Some(summary),
    }
}

/// The finding for a bundle directory, or its manifest, that cannot be read
/// at all.
fn unreadable(dir: &Path) -> Option<Diagnostic> {
    let (file, message, action) = if !fs::metadata(dir).is_ok_and(|meta| meta.is_dir()) {
        (
            dir.display().to_string(),
            "the bundle directory could not be read as a directory",
            "Check that the directory exists and that this user may read it, then run the check \
             again.",
        )
    } else if fs::File::open(dir.join(MANIFEST_FILE)).is_err() {
        (
            bundle_file_name(dir, MANIFEST_FILE),
            "the bundle has no manifest.yaml this user may read",
            "Name the directory that holds the bundle's manifest.yaml with --bundle, or check \
             that this user may read it.",
        )
    } else {
        return None;
    };
    let mut diagnostic = Diagnostic::error("render.bundle.unreadable", "", message, action);
    diagnostic.source = Some(Source {
        file,
        line: None,
        column: None,
    });
    Some(diagnostic)
}

/// The loader refuses a bundle that holds a link and names only the file
/// (CFG-VAL-8). When the link lies on a path the manifest names, the refusal
/// is placed at the member that names it instead, and comes before any
/// finding about the package as a whole. A manifest that cannot be read here
/// is left to the loader's own refusal.
fn linked_members(dir: &Path) -> Vec<Diagnostic> {
    let Ok(bytes) = read_root_manifest(dir) else {
        return Vec::new();
    };
    let Ok(read) = read_manifest(&bundle_file_name(dir, MANIFEST_FILE), &bytes) else {
        return Vec::new();
    };
    let mut diagnostics = Vec::new();
    for (index, spec) in read.manifest.documents.iter().enumerate() {
        let members = [
            ("entryFile", Some(&spec.entry)),
            ("schemaFile", spec.schema.as_ref()),
        ];
        for (member, path) in members {
            if path.is_some_and(|path| through_link(dir, path)) {
                diagnostics.push(error_at(
                    &read.document,
                    "render.bundle.refused-entry",
                    &format!("/documents/{index}/{member}"),
                    "the path leads through a link, and a bundle holds only regular files",
                    "Replace the link with the file it points to, inside the bundle.",
                ));
            }
        }
    }
    diagnostics
}

/// Whether any component of the bundle path `path` under `dir` is a link.
fn through_link(dir: &Path, path: &Path) -> bool {
    let mut current = dir.to_path_buf();
    path.components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .any(|component| {
            current.push(component);
            fs::symlink_metadata(&current).is_ok_and(|meta| meta.file_type().is_symlink())
        })
}

/// The diagnostics of a bundle the loader refused: the reader's own,
/// unchanged, or one diagnostic for a refusal that concerns the directory
/// rather than a position in a file.
fn load_refusal(dir: &Path, problem: RenderProblem) -> Vec<Diagnostic> {
    if !problem.diagnostics.is_empty() {
        return problem.diagnostics;
    }
    let (code, action) = match problem.kind {
        ProblemKind::BundleTampered | ProblemKind::BundleUnsealed | ProblemKind::RuntimeInvalid => (
            "render.bundle.package-mismatch",
            "Rebuild the package with registry-render package from its source bundle, and deploy \
             the whole directory.",
        ),
        ProblemKind::InvalidArgument => (
            "render.bundle.envelope-in-source",
            "Remove SHA256SUMS and REVISION from the source bundle; registry-render package \
             writes them into a new directory.",
        ),
        _ => (
            "render.bundle.refused-entry",
            "Replace each link with a regular file inside the bundle, and give every file a \
             UTF-8 name that no other file shares.",
        ),
    };
    let mut diagnostic = Diagnostic::error(code, "", problem.detail, action);
    diagnostic.source = Some(Source {
        file: dir.display().to_string(),
        line: None,
        column: None,
    });
    vec![diagnostic]
}

/// Identify every YAML file of the bundle that no document reads by its
/// envelope (CFG-CHECK-2): the root manifest and each declared locale's
/// label table were read when the bundle loaded. Returns the findings and
/// the number of files read.
fn scan_unread_yaml(dir: &Path, bundle: &Bundle) -> (Vec<Diagnostic>, usize) {
    let mut read = BTreeSet::from([MANIFEST_FILE.to_owned()]);
    read.extend(
        bundle
            .label_sources
            .keys()
            .map(|locale| labels_path(locale)),
    );
    let mut diagnostics = Vec::new();
    let mut files = 0;
    for (relative, bytes) in bundle.snapshot.iter() {
        let yaml = relative.ends_with(".yaml") || relative.ends_with(".yml");
        if !yaml || read.contains(relative) {
            continue;
        }
        files += 1;
        diagnostics.extend(identify(&bundle_file_name(dir, relative), bytes.as_slice()));
    }
    (diagnostics, files)
}

/// What a YAML file no document reads holds, by its envelope.
fn identify(file: &str, bytes: &[u8]) -> Vec<Diagnostic> {
    let unread = |message: &str| {
        let mut diagnostic = Diagnostic::warning(
            "render.bundle.unread-file",
            "",
            message,
            "Keep it if a template reads it as data; otherwise give a label table the \
             RenderLabels envelope at labels/<locale>.yaml, or remove the file.",
        );
        diagnostic.source = Some(Source {
            file: file.to_owned(),
            line: None,
            column: None,
        });
        vec![diagnostic]
    };
    let Ok(root) = Reader::new(file).scan(bytes) else {
        return unread(
            "the file is outside the YAML subset configuration files use, so the check cannot \
             identify it by its envelope; no Render runtime reads it as configuration",
        );
    };
    let text = |key: &str| {
        let entry = root.as_ref()?.get(key)?;
        match &entry.value.value {
            NodeValue::String(text) => Some((text.text.clone(), entry.value.span.start)),
            _ => None,
        }
    };
    let (Some((kind, at)), Some(_)) = (text("kind"), text("apiVersion")) else {
        return unread(
            "the file has no apiVersion and kind, so no Render runtime reads it as configuration",
        );
    };
    let at_kind = |severity: Severity, code: &str, message: &str, action: &str| {
        let mut diagnostic = Diagnostic::error(code, "/kind", message, action);
        diagnostic.severity = severity;
        diagnostic.source = Some(Source {
            file: file.to_owned(),
            line: Some(at.line),
            column: Some(at.column),
        });
        diagnostic
    };
    match kind.as_str() {
        LABELS_KIND => {
            let mut diagnostics = match read_labels(file, bytes) {
                Ok(read) => read.document.warnings().into_diagnostics(),
                Err(report) => report.into_diagnostics(),
            };
            let mut unused = at_kind(
                Severity::Warning,
                "render.bundle.unused-labels",
                "no document reads this label table; a document reads labels/<locale>.yaml for \
                 each locale it declares",
                "Move it to labels/<locale>.yaml and declare the locale on a document, or remove \
                 it.",
            );
            unused.artifact = Some(LABELS_KIND.to_owned());
            diagnostics.push(unused);
            diagnostics
        }
        RUNTIME_KIND => vec![at_kind(
            Severity::Error,
            "render.bundle.foreign-kind",
            "a runtime file does not belong in a bundle, which is packaged and deployed whole",
            "Move it out of the bundle and check it with --runtime-config.",
        )],
        MANIFEST_KIND => vec![at_kind(
            Severity::Error,
            "render.bundle.foreign-kind",
            "a bundle manifest belongs only at the root of its bundle",
            "Move the nested bundle out of this one; each bundle is its own directory.",
        )],
        _ => vec![at_kind(
            Severity::Error,
            "render.bundle.foreign-kind",
            "the file is of a kind a Render bundle does not hold",
            "Move the file out of the bundle.",
        )],
    }
}

/// The checks `registry-render package` applies to source before it writes
/// anything: the label findings, and every YAML file of a kind a bundle does
/// not hold.
pub fn check_package_source(bundle: &Bundle, dir: &Path) -> Result<(), RenderProblem> {
    let foreign = scan_unread_yaml(dir, bundle)
        .0
        .into_iter()
        .filter(|diagnostic| diagnostic.severity == Severity::Error)
        .collect::<Vec<_>>();
    match check_labels(bundle) {
        Err(mut problem) => {
            problem.diagnostics.extend(foreign);
            Err(problem)
        }
        Ok(()) if foreign.is_empty() => Ok(()),
        Ok(()) => Err(RenderProblem::new(
            ProblemKind::ManifestInvalid,
            format!(
                "the bundle {} holds files a package must not carry",
                dir.display()
            ),
        )
        .with_diagnostics(foreign)),
    }
}

/// Check the runtime file at `path` as given: the loader needs an absolute,
/// lexically normal path, and every diagnostic names the file as given.
/// Returns the findings and whether the file could not be read at all.
fn check_runtime_file(
    path: &Path,
    environment: bool,
    audit_root: Option<&Path>,
) -> (Vec<Diagnostic>, bool) {
    let given = path.display().to_string();
    let Some(absolute) = absolute_lexical(path) else {
        let mut diagnostic = Diagnostic::error(
            "render.check.runtime-unreadable",
            "",
            "the runtime file path could not be made absolute",
            "Name the runtime file by an absolute path, then run the check again.",
        );
        diagnostic.source = Some(Source {
            file: given,
            line: None,
            column: None,
        });
        return (vec![diagnostic], true);
    };
    let checked = crate::runtime::check_runtime(&absolute, environment, audit_root);
    let absolute = absolute.display().to_string();
    let diagnostics = checked
        .diagnostics
        .into_iter()
        .map(|mut diagnostic| {
            if let Some(source) = &mut diagnostic.source {
                if source.file == absolute {
                    source.file.clone_from(&given);
                }
            }
            for related in &mut diagnostic.related {
                if related.file == absolute {
                    related.file.clone_from(&given);
                }
            }
            diagnostic
        })
        .collect();
    (diagnostics, checked.unavailable)
}

/// `path` made absolute against the working directory, with `.` and `..`
/// resolved by name, as the runtime loader requires (CFG-ENV-5).
fn absolute_lexical(path: &Path) -> Option<PathBuf> {
    let absolute = std::path::absolute(path).ok()?;
    let mut normal = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    Some(normal)
}

/// Every label finding of the bundle at once (CFG-DIAG-5): the script
/// coverage of each label and the key set of each locale. A coverage
/// finding names the problem `font-invalid`; key sets alone name it
/// `labels-invalid`.
pub fn check_labels(bundle: &Bundle) -> Result<(), RenderProblem> {
    let coverage = check_script_coverage(bundle);
    let key_sets = check_label_key_sets(bundle);
    let kind = if !coverage.is_empty() {
        ProblemKind::FontInvalid
    } else if !key_sets.is_empty() {
        ProblemKind::LabelsInvalid
    } else {
        return Ok(());
    };
    let mut diagnostics = coverage;
    diagnostics.extend(key_sets);
    Err(
        RenderProblem::new(kind, "the bundle's label tables were refused")
            .with_diagnostics(diagnostics),
    )
}

/// Every character of every label value must be drawable by some bundle or
/// baseline font. This is the check-time half of the paper-safety rule: a
/// successful render that prints tofu is wrong on paper, so missing
/// coverage is a named problem here and glyph warnings fail `--strict` at
/// render time.
pub fn check_script_coverage(bundle: &Bundle) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for document in bundle.documents.values() {
        for (locale, table) in &document.labels {
            let Some(map) = table.as_object() else {
                continue;
            };
            for (key, value) in map {
                let Some(text) = value.as_str() else { continue };
                for ch in text.chars() {
                    if ch.is_ascii() || ch.is_whitespace() {
                        continue;
                    }
                    let covered = bundle.fonts.iter().any(|font| {
                        ttf_parser::Face::parse(font.data(), font.index())
                            .is_ok_and(|face| face.glyph_index(ch).is_some())
                    });
                    if !covered {
                        push_once(
                            &mut findings,
                            label_finding(
                                bundle,
                                locale,
                                "render.labels.uncovered-character",
                                &format!("/labels/{key}"),
                                &format!(
                                    "no bundle or baseline font draws the character U+{:04X} in this label",
                                    u32::from(ch)
                                ),
                                "Add a font that covers the label's script under fonts/, or change the label text.",
                                false,
                            ),
                        );
                        break;
                    }
                }
            }
        }
    }
    findings
}

/// Every locale of a document must define the same label key set: a key
/// missing from one locale fails only that locale's render, at template
/// runtime — the worst place to discover it. `check` (and serve startup)
/// name the divergence up front, so PAYLOAD.md's "a missing label key is a
/// `registry-render check` error, not a runtime surprise" holds.
pub fn check_label_key_sets(bundle: &Bundle) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for document in bundle.documents.values() {
        let mut reference: Option<(String, BTreeSet<String>)> = None;
        for (locale, table) in &document.labels {
            let keys: BTreeSet<String> = table
                .as_object()
                .map(|map| map.keys().cloned().collect())
                .unwrap_or_default();
            match &reference {
                None => reference = Some((locale.clone(), keys)),
                Some((reference_locale, reference_keys)) => {
                    for missing in reference_keys.difference(&keys) {
                        push_once(
                            &mut findings,
                            missing_key(bundle, locale, missing, reference_locale),
                        );
                    }
                    for undeclared in keys.difference(reference_keys) {
                        push_once(
                            &mut findings,
                            missing_key(bundle, reference_locale, undeclared, locale),
                        );
                    }
                }
            }
        }
    }
    findings
}

/// `locale`'s table lacks `key`, which `defined_in`'s table defines.
fn missing_key(bundle: &Bundle, locale: &str, key: &str, defined_in: &str) -> Diagnostic {
    label_finding(
        bundle,
        locale,
        "render.labels.missing-key",
        "/labels",
        &format!(
            "the table has no label {key}, which {} defines for the same document",
            labels_path(defined_in)
        ),
        &format!("Add {key} to this table, or remove it from every locale of the document."),
        true,
    )
}

/// An error in the label table of `locale`, at the member at `pointer`: its
/// key when `at_key`, otherwise its value.
fn label_finding(
    bundle: &Bundle,
    locale: &str,
    code: &str,
    pointer: &str,
    message: &str,
    action: &str,
    at_key: bool,
) -> Diagnostic {
    match bundle.label_sources.get(locale) {
        Some(document) if at_key => {
            document.diagnostic_at_key(Severity::Error, code, pointer, message, action)
        }
        Some(document) => {
            document.diagnostic_at_value(Severity::Error, code, pointer, message, action)
        }
        None => Diagnostic::error(code, pointer, message, action),
    }
}

/// Documents that share a locale share its table; report each finding once.
fn push_once(findings: &mut Vec<Diagnostic>, diagnostic: Diagnostic) {
    if !findings.contains(&diagnostic) {
        findings.push(diagnostic);
    }
}
