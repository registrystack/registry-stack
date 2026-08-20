// SPDX-License-Identifier: Apache-2.0
//! The authoring form's own checks, reported at the field each one names.
//!
//! Nothing here decides whether a marker, question, or access policy is well formed.
//! `registry-evidence-authoring` holds those judgements, and this module translates its
//! position-free [`Finding`](registry_evidence_authoring::finding::Finding) into a place in the
//! text. An editor that restated those rules would be a second implementation of the authoring
//! form, and the first day the two disagreed the author would believe the wrong one.

use std::path::Path;

use ls_types::{DiagnosticSeverity, Position, Range};
use registry_evidence_authoring::{
    finding::{FieldPath, FieldStep},
    model::{AccessPolicy, Question},
    parse_project_marker,
    validate::{validate_access_policy, validate_question},
};

use crate::{
    refs::{bounded_message, IndexedDiagnostic, DOCUMENT_START},
    yaml::{ParsedDocument, YamlPair, YamlValue},
};

/// What one reading of a question document found.
///
/// `validated` is the question itself, and it is `Some` only when `diagnostics` is empty. That is
/// the condition `registry-evidencectl` compiles under: `compile_question_plan`
/// (`crates/registry-evidencectl/src/authoring.rs:989`) writes
/// `.expect("inline source was validated")`, so every cross-file check the compiler performs runs on
/// a question the form has already accepted. A caller that reads the two fields as the compiler does
/// says nothing about the operation, the selectors, or the facts of a question that is malformed,
/// which is where the author is already being told what to fix.
pub struct QuestionReading {
    pub diagnostics: Vec<IndexedDiagnostic>,
    pub validated: Option<Question>,
}

/// What one reading of an access policy found.
pub struct AccessPolicyReading {
    pub diagnostics: Vec<IndexedDiagnostic>,
    pub validated: Option<AccessPolicy>,
}

/// Validate a present project marker before any dependent document is walked.
pub fn read_project_marker(
    path: &Path,
    source: &str,
    document: &ParsedDocument,
) -> Vec<IndexedDiagnostic> {
    parse_project_marker(source.as_bytes())
        .err()
        .map(|finding| finding_diagnostic(path, document, finding))
        .into_iter()
        .collect()
}

/// Read one access policy with the same closed model and intrinsic checks as the compiler.
pub fn read_access_policy(
    path: &Path,
    source: &str,
    document: &ParsedDocument,
) -> AccessPolicyReading {
    let policy = match serde_norway::from_str::<AccessPolicy>(source) {
        Ok(policy) => policy,
        Err(error) => {
            return AccessPolicyReading {
                diagnostics: vec![IndexedDiagnostic {
                    path: path.to_path_buf(),
                    range: deserializer_range(source, &error),
                    severity: DiagnosticSeverity::ERROR,
                    code: Some("evidence/access-policy-shape".to_owned()),
                    message: format!(
                        "This is not the shape of an access policy: {}",
                        bounded_message(&error.to_string())
                    ),
                }],
                validated: None,
            };
        }
    };
    let diagnostics = validate_access_policy(&policy)
        .into_iter()
        .map(|finding| finding_diagnostic(path, document, finding))
        .collect::<Vec<_>>();
    AccessPolicyReading {
        validated: diagnostics.is_empty().then_some(policy),
        diagnostics,
    }
}

/// Every way one question departs from the authoring form, at the field that holds each departure,
/// and the question itself when it departs from it nowhere.
///
/// A question the deserializer cannot read is reported once and not validated: the checks take a
/// `Question`, and a document that is not one has a single problem worth saying out loud.
pub fn read_question(path: &Path, source: &str, document: &ParsedDocument) -> QuestionReading {
    let question = match serde_norway::from_str::<Question>(source) {
        Ok(question) => question,
        Err(error) => {
            return QuestionReading {
                diagnostics: vec![IndexedDiagnostic {
                    path: path.to_path_buf(),
                    range: deserializer_range(source, &error),
                    severity: DiagnosticSeverity::ERROR,
                    code: Some("evidence/question-shape".to_owned()),
                    message: format!(
                        "This is not the shape of a question: {}",
                        bounded_message(&error.to_string())
                    ),
                }],
                validated: None,
            }
        }
    };

    let diagnostics = validate_question(&question)
        .into_iter()
        .map(|finding| finding_diagnostic(path, document, finding))
        .collect::<Vec<_>>();

    QuestionReading {
        validated: diagnostics.is_empty().then_some(question),
        diagnostics,
    }
}

fn finding_diagnostic(
    path: &Path,
    document: &ParsedDocument,
    finding: registry_evidence_authoring::Finding,
) -> IndexedDiagnostic {
    IndexedDiagnostic {
        path: path.to_path_buf(),
        range: range_at_field_path(document, &finding.field).unwrap_or(DOCUMENT_START),
        severity: DiagnosticSeverity::ERROR,
        code: Some(format!("evidence/{}", finding.code)),
        // The sentence is the authoring library's, so the editor and the compiler say the same
        // thing about the same document. Bound it because some findings quote authored names.
        message: bounded_message(&finding.message),
    }
}

/// Where in a document a field path points, as far as the document goes.
///
/// The walk stops at the first step the document does not have and answers with the deepest place
/// it did reach, because a check often names a field that is missing: "requires schema" points at a
/// `schema` that is not written yet, and the author needs to be shown the answer it belongs to
/// rather than the top of the file. `None` means the document holds nothing the walk could stop on,
/// and the caller reports against the document itself.
pub fn range_at_field_path(document: &ParsedDocument, field: &FieldPath) -> Option<Range> {
    let mut value = &document.value;
    let mut anchor = None;
    for step in field.steps() {
        let entry = match step {
            FieldStep::Key(name) => entry_at(value, name),
            FieldStep::MapKey(name) => entry_at(value, name.as_str()),
            FieldStep::Index(position) => {
                let Some(element) = value
                    .as_sequence()
                    .and_then(|elements| elements.get(*position))
                else {
                    break;
                };
                anchor = leading_range(element).or(anchor);
                value = element;
                continue;
            }
        };
        let Some(entry) = entry else {
            break;
        };
        anchor = Some(entry.key.range);
        value = &entry.value;
    }

    value.as_scalar().map(|scalar| scalar.range).or(anchor)
}

fn entry_at<'a>(value: &'a YamlValue, name: &str) -> Option<&'a YamlPair> {
    value
        .as_mapping()?
        .iter()
        .find(|entry| entry.key.value == name)
}

/// Where a value starts, for the values that begin with something the parser gave a position to.
/// A mapping is anchored at its first key, which is the first line an author sees of it; a sequence
/// and an unrecovered value have no position of their own.
fn leading_range(value: &YamlValue) -> Option<Range> {
    match value {
        YamlValue::Scalar(scalar) => Some(scalar.range),
        YamlValue::Mapping(entries) => entries.first().map(|entry| entry.key.range),
        YamlValue::Sequence(_) | YamlValue::Other => None,
    }
}

/// The line a deserializer stopped reading on, underlined whole.
///
/// The deserializer reports a line and a column, and only the line is used: its column counts what
/// libyaml counted, and the protocol wants UTF-16 code units into the line. Underlining the line the
/// author has to change is the honest part of that answer.
fn deserializer_range(source: &str, error: &serde_norway::Error) -> Range {
    let Some(line) = error
        .location()
        .and_then(|location| location.line().checked_sub(1))
        .and_then(|line| u32::try_from(line).ok())
    else {
        return DOCUMENT_START;
    };
    let width = source
        .lines()
        .nth(line as usize)
        .map_or(0, |text| text.encode_utf16().count());
    let Ok(width) = u32::try_from(width) else {
        return DOCUMENT_START;
    };
    Range::new(Position::new(line, 0), Position::new(line, width))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml::parse_yaml;

    const QUESTION: &str = "id: adult-status\n\
                            answers:\n  \
                            - concept: is_adult\n    \
                            type: boolean\n\
                            governance:\n  \
                            fixtures: fixtures/adult-status.yaml\n";

    fn position_at(document: &ParsedDocument, field: FieldPath) -> Option<(u32, u32)> {
        range_at_field_path(document, &field).map(|range| (range.start.line, range.start.character))
    }

    #[test]
    fn a_path_reaches_the_scalar_it_names() {
        let document = parse_yaml(QUESTION).unwrap();

        assert_eq!(
            position_at(&document, FieldPath::root().key("id")),
            Some((0, 4))
        );
        assert_eq!(
            position_at(
                &document,
                FieldPath::root().key("answers").index(0).key("concept")
            ),
            Some((2, 13))
        );
        assert_eq!(
            position_at(
                &document,
                FieldPath::root().key("governance").key("fixtures")
            ),
            Some((5, 12))
        );
    }

    #[test]
    fn a_path_through_a_mapping_key_the_author_chose_reaches_its_value() {
        let document = parse_yaml("projection:\n  /records: collect\n").unwrap();

        assert_eq!(
            position_at(
                &document,
                FieldPath::root().key("projection").map_key("/records")
            ),
            Some((1, 12))
        );
    }

    #[test]
    fn a_path_to_a_field_the_document_does_not_have_stops_at_the_deepest_field_it_does() {
        let document = parse_yaml(QUESTION).unwrap();

        // The check that asks for a schema names a field the author has not written, so the answer
        // it belongs to is the closest the document can get.
        assert_eq!(
            position_at(
                &document,
                FieldPath::root().key("answers").index(0).key("schema")
            ),
            Some((2, 4)),
        );
        // A sequence position that is not there stops at the sequence's own key.
        assert_eq!(
            position_at(&document, FieldPath::root().key("answers").index(7)),
            Some((1, 0)),
        );
    }

    #[test]
    fn a_path_into_a_document_that_holds_nothing_resolves_nowhere() {
        let document = parse_yaml("# a question the author has not started writing\n").unwrap();

        assert_eq!(position_at(&document, FieldPath::root().key("id")), None);
        assert_eq!(position_at(&document, FieldPath::root()), None);
    }

    /// A document that is one scalar holds no field to point at, so the walk stops on the text that
    /// is there. It is the deepest, and only, place the path reached.
    #[test]
    fn a_path_into_a_document_that_is_not_a_mapping_stops_on_what_is_written() {
        let document = parse_yaml("a scalar document\n").unwrap();

        assert_eq!(
            position_at(&document, FieldPath::root().key("id")),
            Some((0, 0))
        );
    }

    #[test]
    fn a_path_into_a_document_that_stops_parsing_reaches_what_parsed() {
        let document = parse_yaml("id: adult-status\npurpose: [unclosed\n").unwrap();
        assert!(
            document.syntax_error.is_some(),
            "the fixture must not parse cleanly"
        );

        assert_eq!(
            position_at(&document, FieldPath::root().key("id")),
            Some((0, 4))
        );
    }

    #[test]
    fn a_question_the_deserializer_cannot_read_is_reported_on_the_line_it_stopped_at() {
        let source = "id: adult-status\nquestion: [1, 2]\n";

        let reading = read_question(
            Path::new("/questions/adult-status.yaml"),
            source,
            &parse_yaml(source).unwrap(),
        );

        let diagnostics = reading.diagnostics;
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert_eq!(
            diagnostics[0].code.as_deref(),
            Some("evidence/question-shape")
        );
        assert_eq!(diagnostics[0].range.start.line, 1);
        assert!(
            diagnostics[0]
                .message
                .starts_with("This is not the shape of a question: "),
            "{}",
            diagnostics[0].message
        );
        assert!(
            reading.validated.is_none(),
            "a document that is not a question hands nothing on"
        );
    }

    /// The other half of the reading: a question the form accepts is handed on, and one it does not
    /// is not, so the checks that read it against the project's description run on exactly the
    /// questions the compiler would compile.
    #[test]
    fn only_a_question_the_form_accepts_is_handed_on() {
        let accepted = "id: adult-status\n\
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
        let refused = accepted.replace("operation: readPerson", "operation: ''");

        let path = Path::new("/questions/adult-status.yaml");
        let reading = read_question(path, accepted, &parse_yaml(accepted).unwrap());
        assert!(reading.diagnostics.is_empty(), "{:?}", reading.diagnostics);
        assert!(reading.validated.is_some());

        let reading = read_question(path, &refused, &parse_yaml(&refused).unwrap());
        assert_eq!(
            reading
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("evidence/operation-identifier")]
        );
        assert!(reading.validated.is_none());
    }
}
