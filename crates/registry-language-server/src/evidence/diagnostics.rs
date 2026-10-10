// SPDX-License-Identifier: Apache-2.0
//! The authoring form's own checks, reported where the command line reports them.
//!
//! Nothing here decides whether a marker, question, or access policy is well formed.
//! `registry-evidence-authoring` holds those judgements and reads each document through the shared
//! Registry Stack reader, which places every diagnostic at a line and column. This module only
//! translates that position into the protocol's UTF-16 range. An editor that restated those rules,
//! or placed their findings by a walk of its own, would be a second implementation of the authoring
//! form, and the first day the two disagreed the author would believe the wrong one.

use std::path::Path;

use registry_evidence_authoring::{
    formats::{check_access_policy, check_question},
    model::{AccessPolicy, Question},
    parse_project_marker,
};
use registry_platform_yaml::{Decoded, Diagnostic, Report, Severity};
use tower_lsp_server::ls_types::{DiagnosticSeverity, Position, Range};

use crate::{
    refs::{bounded_message, IndexedDiagnostic, DOCUMENT_START},
    yaml::{ParsedDocument, SourceMap, YamlValue},
};

/// What one reading of a question document found.
///
/// `validated` is the question itself, and it is `Some` only when the reading found no error. That
/// is the condition `registry-evidencectl` compiles under: its compile step expects every inline
/// source to be validated already, so every cross-file check the compiler performs runs on a
/// question the form has already accepted. A caller that reads the two fields as the compiler does
/// says nothing about the operation, the selectors, or the facts of a question that is malformed,
/// which is where the author is already being told what to fix.
pub(crate) struct QuestionReading {
    pub(crate) diagnostics: Vec<IndexedDiagnostic>,
    pub(crate) validated: Option<Question>,
}

/// What one reading of an access policy found.
pub(crate) struct AccessPolicyReading {
    pub(crate) diagnostics: Vec<IndexedDiagnostic>,
    pub(crate) validated: Option<AccessPolicy>,
}

/// Read a present project marker before any dependent document is walked.
pub(crate) fn read_project_marker(
    path: &Path,
    source: &str,
    document: &ParsedDocument,
) -> Vec<IndexedDiagnostic> {
    let (diagnostics, _) = reading(
        path,
        source,
        document,
        parse_project_marker(&path.to_string_lossy(), source.as_bytes()),
    );
    diagnostics
}

/// Read one access policy with the same reader and intrinsic checks as the compiler.
pub(crate) fn read_access_policy(
    path: &Path,
    source: &str,
    document: &ParsedDocument,
) -> AccessPolicyReading {
    let (diagnostics, validated) = reading(
        path,
        source,
        document,
        check_access_policy(&path.to_string_lossy(), source.as_bytes()),
    );
    AccessPolicyReading {
        diagnostics,
        validated,
    }
}

/// Every way one question departs from the authoring form, at the place the command line reports
/// each departure, and the question itself when it departs from it nowhere.
pub(crate) fn read_question(
    path: &Path,
    source: &str,
    document: &ParsedDocument,
) -> QuestionReading {
    let (diagnostics, validated) = reading(
        path,
        source,
        document,
        check_question(&path.to_string_lossy(), source.as_bytes()),
    );
    QuestionReading {
        diagnostics,
        validated,
    }
}

/// The diagnostics one reading produced, and the value it decoded when it found no error. A
/// document the reader accepts may still carry warnings, and those are reported beside the value.
fn reading<T>(
    path: &Path,
    source: &str,
    document: &ParsedDocument,
    read: Result<Decoded<T>, Report>,
) -> (Vec<IndexedDiagnostic>, Option<T>) {
    match read {
        Ok(decoded) => (
            reader_diagnostics(
                path,
                source,
                document,
                decoded.document.warnings().diagnostics(),
            ),
            Some(decoded.value),
        ),
        Err(report) => (
            reader_diagnostics(path, source, document, report.diagnostics()),
            None,
        ),
    }
}

/// The shared reader's diagnostics as the editor shows them: the same code and the same sentence,
/// at the same line and column, counted in UTF-16 code units.
pub(crate) fn reader_diagnostics(
    path: &Path,
    source: &str,
    document: &ParsedDocument,
    diagnostics: &[Diagnostic],
) -> Vec<IndexedDiagnostic> {
    let source_map = SourceMap::new(source);
    diagnostics
        .iter()
        .map(|diagnostic| IndexedDiagnostic {
            path: path.to_path_buf(),
            range: reader_range(source, &source_map, document, diagnostic),
            severity: match diagnostic.severity {
                Severity::Error => DiagnosticSeverity::ERROR,
                Severity::Warning => DiagnosticSeverity::WARNING,
            },
            code: Some(diagnostic.code.clone()),
            // The sentence is the reader's or the authoring library's, so the editor and the
            // compiler say the same thing about the same document.
            message: bounded_message(&diagnostic.message),
        })
        .collect()
}

/// Where a reader diagnostic points, as a protocol range.
///
/// The reader counts a column in Unicode scalar values and does not count a leading byte-order
/// mark; the protocol counts UTF-16 code units of the text the editor holds. The range starts at
/// that place and, when a scalar the editor indexed starts there, ends where that scalar ends, so a
/// value is underlined whole. A diagnostic about the file as a whole is placed at its start.
fn reader_range(
    source: &str,
    source_map: &SourceMap<'_>,
    document: &ParsedDocument,
    diagnostic: &Diagnostic,
) -> Range {
    let Some((line, column)) = diagnostic
        .source
        .as_ref()
        .and_then(|place| Some((place.line?, place.column?)))
    else {
        return DOCUMENT_START;
    };
    let Some(byte) = byte_offset(source, line, column) else {
        return DOCUMENT_START;
    };
    let start = source_map.position(byte);
    let end = scalar_end_at(&document.value, start).unwrap_or(start);
    Range::new(start, end)
}

/// The byte offset of a 1-based line and a 1-based column counted in Unicode scalar values, with a
/// leading byte-order mark skipped the way the reader skips it.
fn byte_offset(source: &str, line: usize, column: usize) -> Option<usize> {
    let mut line_start = 0;
    for _ in 1..line {
        line_start += source.get(line_start..)?.find('\n')? + 1;
    }
    if line == 1 && source.starts_with('\u{feff}') {
        line_start = '\u{feff}'.len_utf8();
    }
    let text = source.get(line_start..)?;
    let within = text
        .char_indices()
        .nth(column.checked_sub(1)?)
        .map_or(text.len(), |(offset, _)| offset);
    Some(line_start + within)
}

/// The end of the key or scalar value the editor indexed at `start`. A quoted scalar's range starts
/// after its opening quote, one code unit past where the reader places it.
fn scalar_end_at(value: &YamlValue, start: Position) -> Option<Position> {
    let starts_here = |range: Range| {
        range.start == start
            || (range.start.line == start.line && range.start.character == start.character + 1)
    };
    match value {
        YamlValue::Scalar(scalar) => starts_here(scalar.range).then_some(scalar.range.end),
        YamlValue::Mapping(entries) => entries.iter().find_map(|entry| {
            if starts_here(entry.key.range) {
                Some(entry.key.range.end)
            } else {
                scalar_end_at(&entry.value, start)
            }
        }),
        YamlValue::Sequence(items) => items.iter().find_map(|item| scalar_end_at(item, start)),
        YamlValue::Other => None,
    }
}

#[cfg(test)]
mod tests {
    use registry_evidence_authoring::formats::check_question;

    use super::*;
    use crate::yaml::parse_yaml;

    const ENVELOPE: &str = "apiVersion: id.registrystack.org/formats/evidence/question/v1alpha1\n\
                            kind: EvidenceQuestion\n";

    const ACCEPTED: &str = "id: adult-status\n\
                            question: Is the person an adult?\n\
                            purpose: age-gating\n\
                            subject: {role: person, selector: person_id}\n\
                            source:\n  \
                            operation: readPerson\n  \
                            facts:\n    \
                            - {name: born, path: /date_of_birth, combine: exactly-one}\n\
                            answers:\n  \
                            - concept: is_adult\n    \
                            type: boolean\n\
                            derivation: derivations/adult-status.rhai\n\
                            disclosure: {allow: [is_adult]}\n";

    fn question(body: &str) -> String {
        format!("{ENVELOPE}{body}")
    }

    fn read(source: &str) -> QuestionReading {
        read_question(
            Path::new("/questions/adult-status.yaml"),
            source,
            &parse_yaml(source).unwrap(),
        )
    }

    /// The editor and the command line read the same document through the same reader, so they
    /// report the same code and sentence at the same line and column.
    #[test]
    fn a_question_the_reader_refuses_is_reported_where_the_command_line_reports_it() {
        let source =
            question(&ACCEPTED.replace("question: Is the person an adult?", "question: [1, 2]"));

        let reading = read(&source);

        let report = check_question("questions/adult-status.yaml", source.as_bytes())
            .expect_err("the command line refuses the question");
        let expected = report
            .diagnostics()
            .iter()
            .map(|diagnostic| {
                let place = diagnostic.source.as_ref().unwrap();
                (
                    Some(diagnostic.code.clone()),
                    diagnostic.message.clone(),
                    u32::try_from(place.line.unwrap() - 1).unwrap(),
                    u32::try_from(place.column.unwrap() - 1).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let reported = reading
            .diagnostics
            .iter()
            .map(|diagnostic| {
                (
                    diagnostic.code.clone(),
                    diagnostic.message.clone(),
                    diagnostic.range.start.line,
                    diagnostic.range.start.character,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(reported, expected);
        assert_eq!(reported[0].2, 3, "{reported:?}");
        assert!(
            reading.validated.is_none(),
            "a document that is not a question hands nothing on"
        );
    }

    /// The reader counts Unicode scalar values and the protocol counts UTF-16 code units, so a
    /// character outside the Basic Multilingual Plane earlier on the line moves the column by two.
    #[test]
    fn a_column_after_a_wide_character_is_counted_in_utf16_code_units() {
        let source = question(&ACCEPTED.replace(
            "subject: {role: person, selector: person_id}",
            "subject: {role: \u{1f600}, selektor: person_id}",
        ));

        let reading = read(&source);

        let unknown = reading
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code.as_deref() == Some("config.unknown-key"))
            .expect("the misspelled key is reported");
        // `subject: {role: ` is 16 code units, the emoji two more, and `, ` two more.
        assert_eq!(unknown.range.start, Position::new(5, 20));
        assert_eq!(
            unknown.range.end,
            Position::new(5, 28),
            "the key is underlined whole"
        );
    }

    /// A question the form accepts is handed on, and one it does not is not, so the checks that
    /// read it against the project's description run on exactly the questions the compiler would
    /// compile.
    #[test]
    fn only_a_question_the_form_accepts_is_handed_on() {
        let accepted = question(ACCEPTED);
        let refused = accepted.replace("operation: readPerson", "operation: ''");

        let reading = read(&accepted);
        assert!(reading.diagnostics.is_empty(), "{:?}", reading.diagnostics);
        assert!(reading.validated.is_some());

        let reading = read(&refused);
        assert_eq!(
            reading
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("evidence.question.operation-identifier")]
        );
        assert_eq!(reading.diagnostics[0].range.start, Position::new(7, 13));
        assert!(reading.validated.is_none());
    }

    /// An authored file is not expanded, and the editor says so where the command line does.
    #[test]
    fn an_environment_expression_is_refused_at_the_value_that_holds_it() {
        let source =
            question(&ACCEPTED.replace("operation: readPerson", "operation: ${OPERATION}"));

        let reading = read(&source);

        assert_eq!(
            reading
                .diagnostics
                .iter()
                .map(|diagnostic| (diagnostic.code.as_deref(), diagnostic.range.start))
                .collect::<Vec<_>>(),
            vec![(
                Some("config.substitution-not-allowed"),
                Position::new(7, 13)
            )]
        );
    }

    #[test]
    fn a_marker_without_its_envelope_is_reported_with_the_reader_s_codes() {
        let source = "version: 1\nproject: evidence-authoring\n";
        let diagnostics = read_project_marker(
            Path::new("/evidence-project.yaml"),
            source,
            &parse_yaml(source).unwrap(),
        );
        let codes = diagnostics
            .iter()
            .filter_map(|diagnostic| diagnostic.code.as_deref())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"config.missing-envelope"), "{codes:?}");
    }

    #[test]
    fn a_leading_byte_order_mark_is_skipped_the_way_the_reader_skips_it() {
        assert_eq!(byte_offset("\u{feff}id: x\n", 1, 5), Some(7));
        assert_eq!(byte_offset("id: x\nkind: y\n", 2, 7), Some(12));
        assert_eq!(byte_offset("id: x\n", 3, 1), None);
    }
}
