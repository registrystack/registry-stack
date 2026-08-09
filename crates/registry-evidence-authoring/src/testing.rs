//! In-memory authoring project fixtures.
//!
//! A caller supplies every acceptance-case document itself; this module only
//! places each one at the mechanical path an authoring project holds it
//! under, plus the marker every scaffolded project now carries. Building a
//! fixture opens no file: the result is a list of paths and contents for the
//! caller to write.

use crate::{
    layout::{DERIVATIONS_DIRECTORY, FIXTURES_DIRECTORY, OPENAPI_FILE, QUESTIONS_DIRECTORY},
    marker::{default_project_marker_document, PROJECT_MARKER_FILE},
};

/// One file an authoring project fixture places inside a project root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectFile {
    pub path: String,
    pub contents: String,
}

/// A minimal project: an OpenAPI description, the marker, and one question
/// that answers a named operation directly, with no source, selector, or
/// schema file of its own. This is the shape a first authored project starts
/// from.
#[must_use]
pub fn compact_form_project(
    openapi_document: &str,
    question_id: &str,
    question_document: &str,
    derivation_document: &str,
) -> Vec<ProjectFile> {
    vec![
        ProjectFile {
            path: PROJECT_MARKER_FILE.to_owned(),
            contents: default_project_marker_document().to_owned(),
        },
        ProjectFile {
            path: OPENAPI_FILE.to_owned(),
            contents: openapi_document.to_owned(),
        },
        ProjectFile {
            path: format!("{QUESTIONS_DIRECTORY}/{question_id}.yaml"),
            contents: question_document.to_owned(),
        },
        ProjectFile {
            path: format!("{DERIVATIONS_DIRECTORY}/{question_id}.rhai"),
            contents: derivation_document.to_owned(),
        },
    ]
}

/// A project whose question reads a named source rather than an OpenAPI
/// operation directly: the OpenAPI description, the marker, one question and
/// its derivation, an optional fixture-run document, and the source's own
/// support files (a selector, adapters, and schemas), placed exactly where
/// the caller names them.
#[must_use]
pub fn referenced_form_project(
    openapi_document: &str,
    question_id: &str,
    question_document: &str,
    derivation_document: &str,
    fixture_document: Option<&str>,
    source_files: &[ProjectFile],
) -> Vec<ProjectFile> {
    let mut files = vec![
        ProjectFile {
            path: PROJECT_MARKER_FILE.to_owned(),
            contents: default_project_marker_document().to_owned(),
        },
        ProjectFile {
            path: OPENAPI_FILE.to_owned(),
            contents: openapi_document.to_owned(),
        },
        ProjectFile {
            path: format!("{QUESTIONS_DIRECTORY}/{question_id}.yaml"),
            contents: question_document.to_owned(),
        },
        ProjectFile {
            path: format!("{DERIVATIONS_DIRECTORY}/{question_id}.rhai"),
            contents: derivation_document.to_owned(),
        },
    ];
    if let Some(fixture_document) = fixture_document {
        files.push(ProjectFile {
            path: format!("{FIXTURES_DIRECTORY}/{question_id}.yaml"),
            contents: fixture_document.to_owned(),
        });
    }
    files.extend(source_files.iter().cloned());
    files
}

#[cfg(test)]
mod tests {
    use super::{compact_form_project, referenced_form_project, ProjectFile};

    #[test]
    fn a_compact_form_project_carries_the_marker_and_four_files() {
        let files = compact_form_project(
            "openapi-body",
            "sample-question",
            "question-body",
            "derivation-body",
        );
        assert_eq!(files.len(), 4);
        assert!(files.contains(&ProjectFile {
            path: "evidence-project.yaml".to_owned(),
            contents: "version: 1\nproject: evidence-authoring\n".to_owned(),
        }));
        assert!(files.contains(&ProjectFile {
            path: "source.openapi.yaml".to_owned(),
            contents: "openapi-body".to_owned(),
        }));
        assert!(files.contains(&ProjectFile {
            path: "questions/sample-question.yaml".to_owned(),
            contents: "question-body".to_owned(),
        }));
        assert!(files.contains(&ProjectFile {
            path: "derivations/sample-question.rhai".to_owned(),
            contents: "derivation-body".to_owned(),
        }));
    }

    #[test]
    fn a_referenced_form_project_places_the_fixture_and_every_source_file() {
        let source_files = [
            ProjectFile {
                path: "selectors/example.yaml".to_owned(),
                contents: "selector-body".to_owned(),
            },
            ProjectFile {
                path: "sources/example.yaml".to_owned(),
                contents: "source-body".to_owned(),
            },
        ];
        let files = referenced_form_project(
            "openapi-body",
            "sample-question",
            "question-body",
            "derivation-body",
            Some("fixture-body"),
            &source_files,
        );
        assert!(files.contains(&ProjectFile {
            path: "fixtures/sample-question.yaml".to_owned(),
            contents: "fixture-body".to_owned(),
        }));
        assert!(files.contains(&source_files[0]));
        assert!(files.contains(&source_files[1]));
    }

    #[test]
    fn a_referenced_form_project_without_a_fixture_document_omits_the_fixtures_file() {
        let files = referenced_form_project(
            "openapi-body",
            "sample-question",
            "question-body",
            "derivation-body",
            None,
            &[],
        );
        assert!(!files.iter().any(|file| file.path.starts_with("fixtures/")));
    }
}
