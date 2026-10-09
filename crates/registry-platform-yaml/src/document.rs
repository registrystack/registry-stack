// SPDX-License-Identifier: Apache-2.0
//! Reading a file: bytes to a checked document tree, then to Rust types.
//!
//! A read goes through the same stages for every format:
//!
//! 1. the size cap and the UTF-8 check;
//! 2. the YAML subset, building the tree (every structural problem together);
//! 3. the envelope (`apiVersion` and `kind`);
//! 4. the format's removed keys (also reported beside a missing envelope
//!    when one format is expected, since such a file is usually an older
//!    layout whose removed header names the fix);
//! 5. decoding into the format's Rust type, recording every unknown key and
//!    stopping at the first other error.
//!
//! JSON is read the same way, as YAML 1.2 flow content.

use serde::de::DeserializeOwned;

use crate::de::{Ctx, NodeDe, Place};
use crate::diagnostic::{Diagnostic, Report, Severity};
use crate::envelope::{self, Envelope, Expect, RemovedKey};
use crate::messages::{self, Problem, Problems};
use crate::node::{escape_pointer_segment, unescape_segment, Node, NodeValue, Position, Span};
use crate::structure::{self, Built, ScalarHook};

/// The largest document the reader accepts, in bytes, before any other
/// check (CFG-YAML-6).
pub const MAXIMUM_DOCUMENT_BYTES: usize = 1024 * 1024;

/// The most diagnostics the reader reports for one file. Past it, the first
/// ones by position are kept and one `config.too-many-problems` diagnostic
/// counts the rest, so a damaged file cannot flood a terminal or a log.
pub const MAXIMUM_DIAGNOSTICS_PER_FILE: usize = 100;

const BYTE_ORDER_MARK: char = '\u{feff}';

/// Reads one file.
///
/// `file` is the name diagnostics carry in `source.file`, as the caller gave
/// it.
pub struct Reader<'h> {
    file: String,
    hook: Option<&'h mut dyn ScalarHook>,
}

impl Reader<'static> {
    pub fn new(file: impl Into<String>) -> Reader<'static> {
        Reader {
            file: file.into(),
            hook: None,
        }
    }
}

impl<'h> Reader<'h> {
    /// Inspect or replace scalars while the tree is built (substitution in
    /// operator files, or refusing it in authored ones).
    pub fn with_hook<'n>(self, hook: &'n mut dyn ScalarHook) -> Reader<'n> {
        Reader {
            file: self.file,
            hook: Some(hook),
        }
    }

    /// Read the YAML subset only, without an envelope: the tree, or every
    /// structural problem. `None` is an empty or comment-only stream.
    pub fn scan(self, bytes: &[u8]) -> Result<Option<Node>, Report> {
        let file = self.file;
        let mut built = tree(bytes, self.hook);
        let mut problems = built.problems;
        problems.append(&mut built.unrepresentable);
        if problems.is_empty() {
            return Ok(built.root);
        }
        Err(report(&file, None, problems, Vec::new()))
    }

    /// Read a document of one of the expected formats: the tree, its
    /// envelope, and no removed key. Unknown keys are found by
    /// [`Document::decode`].
    pub fn read(self, bytes: &[u8], expect: &Expect<'_>) -> Result<Document, Report> {
        let file = self.file.clone();
        let (document, removed, _) = self.read_stages(bytes, expect, false)?;
        if removed.is_empty() {
            return Ok(document);
        }
        let artifact = Some(document.envelope.kind.as_str());
        Err(report(&file, artifact, removed.into(), document.warnings))
    }

    /// Read a document and decode it into `T`. Every removed and unknown key
    /// is reported, with the first other decoding error.
    pub fn decode<T: DeserializeOwned>(
        self,
        bytes: &[u8],
        expect: &Expect<'_>,
    ) -> Result<Decoded<T>, Report> {
        let (document, removed, unrepresentable) = self.read_stages(bytes, expect, true)?;
        let value = document.decode_with::<T>("", removed, unrepresentable)?;
        Ok(Decoded { value, document })
    }

    /// The document, its removed keys, and, when `decoding`, the unquoted
    /// numbers the tree cannot represent, which decoding refuses in the
    /// words of the member that reads each. Otherwise they are refused here.
    fn read_stages(
        self,
        bytes: &[u8],
        expect: &Expect<'_>,
        decoding: bool,
    ) -> Result<(Document, Vec<Problem>, Problems), Report> {
        let file = self.file;
        let Built {
            root,
            mut problems,
            mut unrepresentable,
        } = tree(bytes, self.hook);
        if !decoding {
            problems.append(&mut unrepresentable);
        }
        if root.is_none() && !problems.is_empty() {
            // The read stopped before the tree was built (size, encoding,
            // or syntax): there is no envelope to check.
            problems.append(&mut unrepresentable);
            return Err(report(
                &file,
                expect.default_artifact(),
                problems,
                Vec::new(),
            ));
        }
        let outcome = envelope::check(root.as_ref(), expect, |pointer| {
            problems.reported_at(pointer) || unrepresentable.reported_at(pointer)
        });
        let artifact: Option<String> = outcome
            .matched
            .as_ref()
            .map(|(_, envelope)| envelope.kind.clone())
            .or_else(|| expect.default_artifact().map(str::to_owned));
        let warnings: Vec<Diagnostic> = outcome
            .warnings
            .into_iter()
            .map(|warning| warning.into_diagnostic(&file, artifact.as_deref()))
            .collect();
        // A file with no envelope is usually an older layout of the one
        // format expected, whose removed header key names the fix.
        let missing_envelope = outcome
            .problems
            .iter()
            .any(|problem| problem.code == "config.missing-envelope");
        // Structural and envelope problems are reported together.
        problems.extend(outcome.problems);
        if let ([only], true, Some(root)) = (expect.formats(), missing_envelope, root.as_ref()) {
            problems.extend(removed_keys(root, only.removed_keys));
        }
        let (Some(root), Some((index, envelope)), true) =
            (root, outcome.matched, problems.is_empty())
        else {
            problems.append(&mut unrepresentable);
            return Err(report(&file, artifact.as_deref(), problems, warnings));
        };
        let removed = removed_keys(&root, expect.formats()[index].removed_keys);
        Ok((
            Document {
                file,
                root,
                envelope,
                warnings,
            },
            removed,
            unrepresentable,
        ))
    }
}

/// Read a document of one of the expected formats. See [`Reader::read`].
pub fn read_document(
    file: impl Into<String>,
    bytes: &[u8],
    expect: &Expect<'_>,
) -> Result<Document, Report> {
    Reader::new(file).read(bytes, expect)
}

/// Read a document and decode it into `T`. See [`Reader::decode`].
pub fn decode_document<T: DeserializeOwned>(
    file: impl Into<String>,
    bytes: &[u8],
    expect: &Expect<'_>,
) -> Result<Decoded<T>, Report> {
    Reader::new(file).decode(bytes, expect)
}

/// A decoded value and the document it came from, for checks that report
/// their own diagnostics at a position.
#[derive(Debug)]
pub struct Decoded<T> {
    pub value: T,
    pub document: Document,
}

/// A document whose YAML, envelope, and keys passed the reader.
#[derive(Clone, Debug)]
pub struct Document {
    file: String,
    root: Node,
    envelope: Envelope,
    warnings: Vec<Diagnostic>,
}

impl Document {
    /// The file name, as given to the reader.
    pub fn file(&self) -> &str {
        &self.file
    }

    pub fn root(&self) -> &Node {
        &self.root
    }

    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// Warnings found while reading, such as a deprecated `apiVersion`.
    pub fn warnings(&self) -> Report {
        let mut report = Report::new(self.warnings.clone());
        report.set_files_checked(1);
        report
    }

    /// The document as JSON, mapping members in source order.
    pub fn to_json_value(&self) -> serde_json::Value {
        self.root.to_json_value()
    }

    /// Decode the whole document into `T`.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, Report> {
        self.decode_with("", Vec::new(), Problems::default())
    }

    /// Decode the node at an RFC 6901 pointer into `T`. Diagnostics carry
    /// the full path from the document root.
    pub fn decode_at<T: DeserializeOwned>(&self, pointer: &str) -> Result<T, Report> {
        if self.root.pointer(pointer).is_none() {
            let problem = Problem::error(
                "config.missing-key",
                pointer,
                None,
                messages::developer_misuse("the pointer names no node of this document"),
            );
            return Err(self.report(vec![problem].into()));
        }
        self.decode_with(pointer, Vec::new(), Problems::default())
    }

    fn decode_with<T: DeserializeOwned>(
        &self,
        pointer: &str,
        removed: Vec<Problem>,
        mut unrepresentable: Problems,
    ) -> Result<T, Report> {
        let (node, key_span) = self
            .root
            .pointer_entry(pointer)
            .expect("the caller checked the pointer");
        let member = pointer.rsplit('/').next().map(unescape_segment);
        let place = if pointer.is_empty() {
            Place::Root
        } else if key_span.is_some() {
            Place::Member
        } else {
            Place::Item
        };
        let ctx = Ctx::new(removed);
        let de = NodeDe::new(
            node,
            pointer.to_string(),
            key_span,
            member.as_deref().filter(|_| key_span.is_some()),
            place,
            &ctx,
        );
        let result = T::deserialize(de);
        if !unrepresentable.is_empty() {
            // An unrepresentable number fails the read as a structural
            // problem does, so it alone is reported: in the words of the
            // member that read it, or out of range where none did.
            drop(result);
            let claims = ctx.take_claims();
            for problem in unrepresentable.kept_mut() {
                if let Some(claim) = claims.iter().find(|claim| claim.pointer == problem.pointer) {
                    *problem = claim.clone();
                }
            }
            return Err(self.report(unrepresentable));
        }
        let mut problems = Vec::new();
        let value = match result {
            Ok(value) => Some(value),
            Err(error) => {
                problems.push(error.into_problem(node, pointer));
                None
            }
        };
        let mut found = ctx.into_problems();
        found.extend(problems);
        match value {
            Some(value) if found.is_empty() => Ok(value),
            _ => Err(self.report(found)),
        }
    }

    fn report(&self, problems: Problems) -> Report {
        report(
            &self.file,
            Some(self.envelope.kind.as_str()),
            problems,
            self.warnings.clone(),
        )
    }

    /// Where the node at `pointer` is written.
    pub fn span_of(&self, pointer: &str) -> Option<Span> {
        self.root.pointer(pointer).map(|node| node.span)
    }

    /// Where the key of the member at `pointer` is written; `None` for the
    /// root and for list items.
    pub fn key_span_of(&self, pointer: &str) -> Option<Span> {
        self.root.pointer_entry(pointer).and_then(|(_, key)| key)
    }

    /// A product diagnostic about the value at `pointer`, placed at its first
    /// character (CFG-DIAG-1). The message and action follow CFG-SEC-3: they
    /// never repeat a value.
    pub fn diagnostic_at_value(
        &self,
        severity: Severity,
        code: &str,
        pointer: &str,
        message: &str,
        suggested_action: &str,
    ) -> Diagnostic {
        let position = self.span_of(pointer).map(|span| span.start);
        self.diagnostic(severity, code, pointer, position, message, suggested_action)
    }

    /// A product diagnostic about the key of the member at `pointer`,
    /// placed at the key; at the value when the node has no key.
    pub fn diagnostic_at_key(
        &self,
        severity: Severity,
        code: &str,
        pointer: &str,
        message: &str,
        suggested_action: &str,
    ) -> Diagnostic {
        let position = self
            .key_span_of(pointer)
            .or_else(|| self.span_of(pointer))
            .map(|span| span.start);
        self.diagnostic(severity, code, pointer, position, message, suggested_action)
    }

    fn diagnostic(
        &self,
        severity: Severity,
        code: &str,
        pointer: &str,
        position: Option<Position>,
        message: &str,
        suggested_action: &str,
    ) -> Diagnostic {
        let mut problem = Problem::error(
            code,
            pointer,
            position,
            messages::Text {
                message: message.to_string(),
                action: suggested_action.to_string(),
            },
        );
        problem.severity = severity;
        problem.into_diagnostic(&self.file, Some(self.envelope.kind.as_str()))
    }
}

/// The size cap, the encoding, and the YAML subset.
fn tree(bytes: &[u8], hook: Option<&mut dyn ScalarHook>) -> Built {
    if bytes.len() > MAXIMUM_DOCUMENT_BYTES {
        let problem = Problem::error(
            "yaml.too-large",
            "",
            None,
            messages::too_large(MAXIMUM_DOCUMENT_BYTES),
        );
        return Built::refused(problem);
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            let valid = std::str::from_utf8(&bytes[..error.valid_up_to()])
                .expect("the prefix before the first invalid byte is UTF-8");
            let problem = Problem::error(
                "yaml.not-utf8",
                "",
                Some(position_after(valid)),
                messages::not_utf8(),
            );
            return Built::refused(problem);
        }
    };
    let text = text.strip_prefix(BYTE_ORDER_MARK).unwrap_or(text);
    structure::build(text, hook)
}

/// The position of the character after `text`, which may start with a
/// byte-order mark.
fn position_after(text: &str) -> Position {
    let text = text.strip_prefix(BYTE_ORDER_MARK).unwrap_or(text);
    let mut position = Position::START;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\n' => {
                position.line += 1;
                position.column = 1;
            }
            '\r' => {
                if chars.peek() != Some(&'\n') {
                    position.line += 1;
                    position.column = 1;
                }
            }
            _ => position.column += 1,
        }
    }
    position
}

fn report(
    file: &str,
    artifact: Option<&str>,
    problems: Problems,
    warnings: Vec<Diagnostic>,
) -> Report {
    let (kept, counted, counted_an_error) = problems.into_parts();
    let mut diagnostics: Vec<Diagnostic> = kept
        .into_iter()
        .map(|problem| problem.into_diagnostic(file, artifact))
        .collect();
    diagnostics.extend(warnings);
    let mut report = Report::new(diagnostics);
    report.sort_by_position();
    let hidden = report.split_off(MAXIMUM_DIAGNOSTICS_PER_FILE);
    if !hidden.is_empty() || counted > 0 {
        let mut problem = Problem::error(
            "config.too-many-problems",
            "",
            None,
            messages::too_many_problems(hidden.len() + counted),
        );
        if !counted_an_error
            && hidden
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Warning)
        {
            problem.severity = Severity::Warning;
        }
        report.push(problem.into_diagnostic(file, artifact));
    }
    report.set_files_checked(1);
    report
}

/// Every member the format removed (CFG-CHANGE-2), reported at its key.
fn removed_keys(root: &Node, removed: &[RemovedKey<'_>]) -> Vec<Problem> {
    let mut problems = Vec::new();
    for rule in removed {
        let Some(rest) = rule.pointer.strip_prefix('/') else {
            continue;
        };
        let segments: Vec<String> = rest.split('/').map(unescape_segment).collect();
        find_removed(root, &segments, String::new(), rule, &mut problems);
    }
    problems
}

fn find_removed(
    node: &Node,
    segments: &[String],
    path: String,
    rule: &RemovedKey<'_>,
    out: &mut Vec<Problem>,
) {
    let Some((segment, rest)) = segments.split_first() else {
        return;
    };
    let wildcard = segment == "*";
    match &node.value {
        NodeValue::Mapping(entries) => {
            for entry in entries {
                if !wildcard && entry.key != *segment {
                    continue;
                }
                let child = format!("{path}/{}", escape_pointer_segment(&entry.key));
                if rest.is_empty() {
                    out.push(Problem::error(
                        "config.removed-key",
                        child,
                        Some(entry.key_span.start),
                        messages::removed_key(&entry.key, rule.replacement),
                    ));
                } else {
                    find_removed(&entry.value, rest, child, rule, out);
                }
            }
        }
        NodeValue::Sequence(items) if !rest.is_empty() => {
            for (index, item) in items.iter().enumerate() {
                if wildcard || *segment == index.to_string() {
                    find_removed(item, rest, format!("{path}/{index}"), rule, out);
                }
            }
        }
        _ => {}
    }
}
