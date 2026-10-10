//! Reading authored files through the shared configuration reader, and
//! reporting what it and the authoring checks find in the one diagnostic
//! shape every checking command prints.
//!
//! The authoring commands read a project from its canonical root, so the
//! diagnostics they raise name each file by its path inside the project.
//! [`rebase`] joins those names to the project path as the command was given
//! it, which is the name an author recognizes.

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read as _,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context as _, Result};
use registry_evidence_authoring::{
    formats::{finding_action, finding_code},
    Finding,
};
use registry_platform_yaml::{
    Diagnostic, Node, Reader, Report, Severity, Source, MAXIMUM_DOCUMENT_BYTES,
};
use serde_json::Value;

/// Read one authored YAML file for the shared reader.
///
/// The file must be a plain file with one link. It is read up to one byte
/// past the reader's document limit, so an oversized document reaches the
/// reader and is refused there, with `yaml.too-large`, the way every other
/// configuration file is.
pub(crate) fn read_authored_file(path: &Path, description: &str) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("opening {description} {}", path.display()))?;
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {description} {}", path.display()))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        bail!("{description} {} is not a plain file", path.display());
    }
    let limit = u64::try_from(MAXIMUM_DOCUMENT_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {description} {}", path.display()))?;
    Ok(bytes)
}

/// A document this binary embeds, such as a published JSON Schema, as a JSON
/// value. It is read through the shared YAML subset without the authored
/// file rules: the document is reviewed with the binary, not written by an
/// author.
pub(crate) fn embedded_document(name: &str, text: &str) -> Result<Value> {
    Reader::new(name)
        .scan(text.as_bytes())
        .map_err(|report| anyhow::anyhow!("the embedded {name} is not readable YAML: {report}"))?
        .map(|node| node.to_json_value())
        .with_context(|| format!("the embedded {name} is empty"))
}

/// A whole file's root node as a JSON value, or `null` for an empty file.
pub(crate) fn node_value(node: Option<Node>) -> Value {
    node.map_or(Value::Null, |node| node.to_json_value())
}

/// A document the runtime owns, such as a runtime configuration or a sealed
/// bundle, read through the shared YAML subset for discovery alone: the same
/// size bound and refusals, and no envelope check, which the runtime makes
/// when it loads the document.
pub(crate) fn runtime_document(file: &str, bytes: &[u8]) -> std::result::Result<Value, Report> {
    Reader::new(file).scan(bytes).map(node_value)
}

/// Every finding of an authoring check over a file the shared reader does
/// not read, such as a derivation script, as an error naming that file.
pub(crate) fn file_findings_report(file: &str, area: &str, findings: Vec<Finding>) -> Report {
    let mut report = Report::new(
        findings
            .iter()
            .map(|finding| {
                let mut diagnostic = Diagnostic::error(
                    finding_code(area, finding.code),
                    finding.field.to_json_pointer(),
                    finding.message.clone(),
                    finding_action(finding.code),
                );
                diagnostic.source = Some(Source {
                    file: file.to_owned(),
                    line: None,
                    column: None,
                });
                diagnostic
            })
            .collect(),
    );
    report.set_files_checked(1);
    report
}

/// Every finding of an authoring check over a document the shared reader
/// scanned without an envelope, such as a reviewed JSON Schema, each placed
/// at the value it concerns or, when that value is absent, at the nearest
/// member that is written.
pub(crate) fn node_findings_report(
    file: &str,
    area: &str,
    root: &Node,
    findings: Vec<Finding>,
) -> Report {
    let mut report = Report::new(
        file_findings_report(file, area, findings)
            .into_diagnostics()
            .into_iter()
            .map(|diagnostic| placed(diagnostic, root))
            .collect(),
    );
    report.set_files_checked(1);
    report
}

/// The diagnostic with its line and column taken from the member its path
/// names: the value when it is written, and otherwise the key of the nearest
/// written member above it, where the missing member belongs.
fn placed(mut diagnostic: Diagnostic, root: &Node) -> Diagnostic {
    // The count of hidden problems concerns the whole file, not a member.
    if diagnostic.code == "config.too-many-problems" {
        return diagnostic;
    }
    let wanted = diagnostic.path.clone();
    let mut pointer = wanted.as_str();
    while root.pointer(pointer).is_none() && !pointer.is_empty() {
        pointer = pointer.rfind('/').map_or("", |slash| &pointer[..slash]);
    }
    let Some(node) = root.pointer(pointer) else {
        return diagnostic;
    };
    let entry = (pointer != wanted)
        .then(|| {
            let (parent, last) = pointer.rsplit_once('/')?;
            root.pointer(parent)?
                .get(&last.replace("~1", "/").replace("~0", "~"))
        })
        .flatten();
    let start = entry.map_or(node.span.start, |entry| entry.key_span.start);
    if let Some(source) = diagnostic.source.as_mut() {
        source.line = Some(start.line);
        source.column = Some(start.column);
    }
    diagnostic
}

/// The authored file at `file` inside `root`, scanned for positions only.
/// A file that cannot be read or scanned now yields no positions; the
/// diagnostics that name it are reported unplaced, as they were raised.
fn scanned(root: &Path, file: &str) -> Option<Node> {
    if !(file.ends_with(".yaml") || file.ends_with(".yml")) {
        return None;
    }
    let bytes = read_authored_file(&root.join(file), "authored file").ok()?;
    // Positions only: the reader without a substitution hook, so a runtime
    // document's references stay plain text and the file still scans.
    registry_platform_yaml::Reader::new(file)
        .scan(&bytes)
        .ok()
        .flatten()
}

/// The report with every unplaced diagnostic about a YAML file inside `root`
/// given the line and column of the member it names, read from that file.
/// The checks that raise such diagnostics read the project's documents as
/// values; this reads the file again only to say where the member is.
#[must_use]
pub(crate) fn place(report: Report, root: &Path) -> Report {
    let files_checked = report.files_checked();
    let mut nodes: BTreeMap<String, Option<Node>> = BTreeMap::new();
    let mut placed_report = Report::new(
        report
            .into_diagnostics()
            .into_iter()
            .map(|diagnostic| {
                let Some(file) = diagnostic
                    .source
                    .as_ref()
                    .filter(|source| source.line.is_none() && Path::new(&source.file).is_relative())
                    .map(|source| source.file.clone())
                else {
                    return diagnostic;
                };
                match nodes
                    .entry(file.clone())
                    .or_insert_with(|| scanned(root, &file))
                {
                    Some(node) => placed(diagnostic, node),
                    None => diagnostic,
                }
            })
            .collect(),
    );
    if let Some(files) = files_checked {
        placed_report.set_files_checked(files);
    }
    placed_report
}

/// One problem at `location`, written as `file:/pointer`, `file`, or a bare
/// JSON pointer, the form the compiler's own refusals name a member in.
pub(crate) fn located(
    severity: Severity,
    code: &str,
    artifact: Option<&str>,
    location: &str,
    message: &str,
    suggested_action: &str,
) -> Diagnostic {
    let (file, pointer) = match location.split_once(':') {
        Some((file, pointer)) if pointer.is_empty() || pointer.starts_with('/') => {
            (Some(file), pointer)
        }
        _ if location.is_empty() || location.starts_with('/') => (None, location),
        _ => (Some(location), ""),
    };
    match file {
        Some(file) => file_diagnostic(
            severity,
            code,
            artifact,
            file,
            pointer,
            message,
            suggested_action,
        ),
        None => {
            let mut diagnostic = Diagnostic::error(code, pointer, message, suggested_action);
            diagnostic.severity = severity;
            diagnostic.artifact = artifact.map(str::to_owned);
            diagnostic
        }
    }
}

/// The refusal an authoring read or compile raised, as a report whose files
/// are named from `project`, the project path as the command was given it:
/// the shared reader's own report, or a compiler refusal naming one member.
/// `root` is the directory the files were read from, which is where their
/// members are placed. Any other error is returned unchanged.
pub(crate) fn project_refusal(error: anyhow::Error, root: &Path, project: &Path) -> anyhow::Error {
    let report = if let Some(report) = report_in(&error) {
        report.clone()
    } else if let Some(refusal) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<crate::authoring::AuthoredDiagnostic>())
    {
        let mut report = Report::new(vec![compiler_diagnostic(refusal)]);
        report.set_files_checked(1);
        report
    } else {
        return error;
    };
    rebase(place(report, root), project).into()
}

/// A compiler refusal naming one authored member, in the one diagnostic
/// shape.
pub(crate) fn compiler_diagnostic(refusal: &crate::authoring::AuthoredDiagnostic) -> Diagnostic {
    located(
        Severity::Error,
        &refusal.code,
        None,
        &refusal.path,
        &refusal.message,
        compiler_action(&refusal.code),
    )
}

/// The change that clears a compiler refusal, by its code.
fn compiler_action(code: &str) -> &'static str {
    match code {
        "evidence.question.validity-exceeds-signing-maximum" => {
            "Lower the question's governance.validitySeconds to the deployment target's signing.maximumAssertionValiditySeconds or below, or raise that maximum in the target's governance.yaml."
        }
        "evidence.question.source-missing" => {
            "Add the named source under sources/, or name a source the project declares."
        }
        "evidence.question.selector-missing" => {
            "Add the named selector profile under selectors/, or name a selector profile the project declares."
        }
        "evidence.source.member-unknown" => {
            "Remove the member, which the closed Evidence source shape does not define."
        }
        "evidence.source.transport-missing" => {
            "Declare the source's transport: http-json or sqlite-extract."
        }
        "evidence.source.production-channel" => {
            "Give the production source an https baseUrl and an authentication kind other than none or review-required."
        }
        "evidence.source.production-transport" => {
            "Use a source transport with stated production conditions: http-json or sqlite-extract."
        }
        "evidence.bundle.shape" => {
            "Correct the named member so the compiled bundle satisfies the closed Evidence bundle shape the authoring reference describes."
        }
        "evidence.target.signing-key-missing" => {
            "Place the named public key file in the deployment target directory, or correct the file name in governance.yaml."
        }
        "evidence.target.publication-invalid" => {
            "Correct the publication member as the runtime's diagnosis describes, then check the project again."
        }
        other => finding_action(other.rsplit('.').next().unwrap_or_default()),
    }
}

/// Every problem found while reading a project's authored files, gathered so
/// that one run reports all of them, with the number of files read.
#[derive(Debug, Default)]
pub(crate) struct Gathered {
    report: Report,
    files: usize,
}

impl Gathered {
    /// Count one file read, whatever was found in it.
    pub(crate) fn read_one(&mut self) {
        self.files += 1;
    }

    pub(crate) fn extend(&mut self, report: Report) {
        self.report.extend(report);
    }

    pub(crate) fn push(&mut self, diagnostic: Diagnostic) {
        self.report.push(diagnostic);
    }

    pub(crate) fn has_errors(&self) -> bool {
        self.report.has_errors()
    }

    /// Stop with every problem gathered so far when any of them is an error.
    pub(crate) fn checkpoint(&self) -> Result<()> {
        if self.report.has_errors() {
            return Err(self.report().into());
        }
        Ok(())
    }

    /// The gathered problems, with the count of files read.
    pub(crate) fn report(&self) -> Report {
        let mut report = self.report.clone();
        report.set_files_checked(self.files);
        report
    }
}

/// One problem about a whole file, or a member of it the reader did not
/// place, named by its path inside the project.
pub(crate) fn file_diagnostic(
    severity: Severity,
    code: &str,
    artifact: Option<&str>,
    file: &str,
    pointer: &str,
    message: &str,
    suggested_action: &str,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(code, pointer, message, suggested_action);
    diagnostic.severity = severity;
    diagnostic.artifact = artifact.map(str::to_owned);
    diagnostic.source = Some(Source {
        file: file.to_owned(),
        line: None,
        column: None,
    });
    diagnostic
}

/// The report with every file name inside the project joined to `base`, the
/// project path as the command was given it. A name that is already
/// absolute is left as it is.
#[must_use]
pub(crate) fn rebase(report: Report, base: &Path) -> Report {
    let files_checked = report.files_checked();
    let mut rebased = Report::new(
        report
            .into_diagnostics()
            .into_iter()
            .map(|mut diagnostic| {
                if let Some(source) = diagnostic.source.as_mut() {
                    source.file = joined(base, &source.file);
                }
                for related in &mut diagnostic.related {
                    related.file = joined(base, &related.file);
                }
                diagnostic
            })
            .collect(),
    );
    if let Some(files) = files_checked {
        rebased.set_files_checked(files);
    }
    rebased
}

fn joined(base: &Path, file: &str) -> String {
    let path = Path::new(file);
    if file.is_empty() {
        return base.to_string_lossy().into_owned();
    }
    if path.is_absolute() {
        return file.to_owned();
    }
    let joined: PathBuf = base.join(path);
    joined.to_string_lossy().into_owned()
}

/// The shared reader's report carried by `error`, when it carries one.
pub(crate) fn report_in(error: &anyhow::Error) -> Option<&Report> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Report>())
}

/// Render a value as block YAML with every sequence indented beneath its key,
/// the form the convention's examples use. `serde_norway` writes a sequence
/// at its key's column, so each such block is shifted two columns right,
/// nested ones included.
pub(crate) fn to_indented_yaml<T: serde::Serialize>(value: &T) -> Result<String> {
    let compact = serde_norway::to_string(value).context("rendering YAML")?;
    let lines: Vec<&str> = compact.lines().collect();
    let column = |line: &str| line.len() - line.trim_start_matches(' ').len();
    let mut open: Vec<usize> = Vec::new();
    let mut rendered = String::with_capacity(compact.len() + compact.len() / 8);
    for (index, line) in lines.iter().enumerate() {
        if !line.trim().is_empty() {
            let at = column(line);
            let item = line.trim_start_matches(' ').starts_with("- ");
            while open
                .last()
                .is_some_and(|&key| at < key || (at == key && !item))
            {
                open.pop();
            }
            for _ in 0..open.len() * 2 {
                rendered.push(' ');
            }
            // The column the line's own key sits at: past any leading `- `.
            let mut rest = line.trim_start_matches(' ');
            let mut key = at;
            while let Some(after) = rest.strip_prefix("- ") {
                rest = after;
                key += 2;
            }
            if line.ends_with(':') {
                if let Some(next) = lines.get(index + 1) {
                    if column(next) == key && next.trim_start_matches(' ').starts_with("- ") {
                        open.push(key);
                    }
                }
            }
        }
        rendered.push_str(line);
        rendered.push('\n');
    }
    let reread = |text: &str| {
        registry_platform_yaml::Reader::new("rendered YAML")
            .scan(text.as_bytes())
            .map(|root| root.map(|node| node.to_json_value()))
    };
    if reread(&compact).ok() != reread(&rendered).ok() {
        bail!("indenting the rendered YAML changed its content");
    }
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
    use super::*;

    #[test]
    fn sequences_are_indented_beneath_their_keys_at_every_depth() {
        let value = serde_json::json!({
            "a": ["x", "y"],
            "b": [{"c": 1, "d": ["p", {"e": ["q"]}]}, {"c": 2}],
            "f": {"g": [[1, 2]], "h": "text"},
            "i": [],
        });
        let rendered = to_indented_yaml(&value).expect("render");
        assert_eq!(
            rendered,
            "a:\n  - x\n  - y\nb:\n  - c: 1\n    d:\n      - p\n      - e:\n          - q\n  - c: 2\nf:\n  g:\n    - - 1\n      - 2\n  h: text\ni: []\n"
        );
        let back: serde_json::Value = serde_norway::from_str(&rendered).expect("parse");
        assert_eq!(back, value);
    }

    #[test]
    fn a_file_inside_the_project_is_named_from_the_project_path_given() {
        let mut diagnostic = Diagnostic::error("evidence.question.x", "/id", "m", "a");
        diagnostic.source = Some(Source {
            file: "questions/a.yaml".to_owned(),
            line: Some(3),
            column: Some(5),
        });
        let rebased = rebase(Report::new(vec![diagnostic]), Path::new("./project"));
        let source = rebased.diagnostics()[0].source.as_ref().unwrap();
        assert_eq!(source.file, "./project/questions/a.yaml");
        assert_eq!((source.line, source.column), (Some(3), Some(5)));
    }

    #[test]
    fn the_count_of_hidden_problems_stays_at_the_file_rather_than_a_line() {
        let root = registry_platform_yaml::Reader::new("a.yaml")
            .scan(b"# comment\nkey: value\n")
            .expect("scans")
            .expect("a document");
        let mut diagnostic = Diagnostic::error("config.too-many-problems", "", "m", "a");
        diagnostic.source = Some(Source {
            file: "a.yaml".to_owned(),
            line: None,
            column: None,
        });
        let kept = placed(diagnostic, &root);
        let source = kept.source.as_ref().unwrap();
        assert_eq!((source.line, source.column), (None, None));
    }

    #[test]
    fn an_embedded_document_reads_as_json() {
        let value = embedded_document("schema", "type: object\nrequired: [id]\n").unwrap();
        assert_eq!(value["required"][0], "id");
    }
}
