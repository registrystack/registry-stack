// SPDX-License-Identifier: Apache-2.0
//! Pure, deterministic Evidence authoring analysis shared by native and browser editors.
//!
//! The host supplies a bounded snapshot of relative UTF-8 document paths, the retained OpenAPI
//! description text, and existence-only paths for artifacts whose contents are not indexed. This
//! crate never discovers, opens, writes, or otherwise observes a host resource.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use ls_types::{DiagnosticSeverity, Position, Range};
use registry_evidence_authoring::layout::OPENAPI_FILE;
use serde::{Deserialize, Serialize};

pub mod evidence {
    pub mod diagnostics;
    pub mod index;
    pub mod layout;
    pub mod openapi;
}
pub mod refs;
pub mod yaml;

use refs::{IndexedDiagnostic, IndexedLocation, ProjectIndex};

pub const API_SCHEMA: &str = "registry.language.core/v1";
pub const API_VERSION: u32 = 1;
pub const MAX_DOCUMENTS: usize = 1024;
pub const MAX_PROJECT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PRESENT_ARTIFACTS: usize = 4096;
pub const MAX_RELATIONSHIPS: usize = 8192;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceProjectSnapshot {
    pub documents: Vec<SnapshotDocument>,
    pub openapi_document: Option<SnapshotDocument>,
    #[serde(default)]
    pub present_artifacts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotDocument {
    pub path: String,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub path: String,
    pub position: Position,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisRequest {
    pub schema: String,
    pub project: EvidenceProjectSnapshot,
    #[serde(default)]
    pub definition: Option<Query>,
    #[serde(default)]
    pub references: Option<Query>,
    #[serde(default)]
    pub completion: Option<Query>,
    #[serde(default)]
    pub hover: Option<Query>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub path: String,
    pub range: Range,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    pub path: String,
    pub range: Range,
    pub severity: String,
    pub code: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub container_name: Option<String>,
    pub path: String,
    pub range: Range,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Completion {
    pub label: String,
    pub new_text: String,
    pub filter_text: String,
    pub detail: String,
    pub range: Range,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hover {
    pub markdown: String,
    pub range: Range,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationshipTarget {
    pub kind: String,
    pub name: String,
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Relationship {
    pub source: Location,
    pub target: RelationshipTarget,
    pub definitions: Vec<Location>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisResult {
    pub schema: String,
    pub api_version: u32,
    pub diagnostics: Vec<Diagnostic>,
    pub symbols: Vec<Symbol>,
    pub relationships: Vec<Relationship>,
    pub definitions: Vec<Location>,
    pub references: Vec<Location>,
    pub completions: Vec<Completion>,
    pub hover: Option<Hover>,
    pub error: Option<ApiError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    InvalidPath,
    DuplicatePath,
    InputLimit,
    InvalidOpenApiPath,
}

/// Build the exact Evidence index from an in-memory snapshot.
pub fn index_snapshot(snapshot: EvidenceProjectSnapshot) -> Result<ProjectIndex, SnapshotError> {
    if snapshot.documents.len() > MAX_DOCUMENTS
        || snapshot.present_artifacts.len() > MAX_PRESENT_ARTIFACTS
    {
        return Err(SnapshotError::InputLimit);
    }

    let root = Path::new("");
    let mut documents = BTreeMap::new();
    let mut total = 0usize;
    for document in snapshot.documents {
        let path = checked_relative(&document.path)?;
        if evidence::layout::document_role(&path).is_none_or(|role| !role.is_indexed()) {
            return Err(SnapshotError::InvalidPath);
        }
        total = total
            .checked_add(document.text.len())
            .ok_or(SnapshotError::InputLimit)?;
        if total > MAX_PROJECT_BYTES {
            return Err(SnapshotError::InputLimit);
        }
        if documents.insert(path, document.text).is_some() {
            return Err(SnapshotError::DuplicatePath);
        }
    }

    let openapi_text = match snapshot.openapi_document {
        Some(document) if document.path == OPENAPI_FILE => Some(document.text),
        Some(_) => return Err(SnapshotError::InvalidOpenApiPath),
        None => None,
    };
    let mut present_artifacts = BTreeSet::new();
    for artifact in snapshot.present_artifacts {
        let path = checked_relative(&artifact)?;
        if !present_artifacts.insert(path) {
            return Err(SnapshotError::DuplicatePath);
        }
    }

    let mut parsed = BTreeMap::new();
    let mut diagnostics = Vec::new();
    for (path, source) in &documents {
        match yaml::parse_yaml(source) {
            Ok(document) => {
                parsed.insert(path.clone(), document);
            }
            Err(_) => diagnostics.push(refs::document_diagnostic(
                path,
                "Project document could not be parsed; the YAML parser is unavailable",
            )),
        }
    }
    let syntax_errors = parsed
        .iter()
        .filter_map(|(path, document)| document.syntax_error.map(|range| (path.clone(), range)))
        .collect();
    let dropped = BTreeSet::new();
    let walked = evidence::index::build_index(
        root,
        &documents,
        &parsed,
        &dropped,
        openapi_text
            .as_deref()
            .map(evidence::index::OpenApiInput::Text)
            .unwrap_or(evidence::index::OpenApiInput::Missing),
        &present_artifacts,
    );
    Ok(ProjectIndex::from_indexed(
        root,
        &documents,
        walked,
        diagnostics,
        syntax_errors,
        Some("evidence/syntax".to_owned()),
    ))
}

/// Analyse a supplied snapshot. Invalid requests return a versioned value instead of panicking.
pub fn analyze(request: AnalysisRequest) -> AnalysisResult {
    let mut result = AnalysisResult {
        schema: API_SCHEMA.to_owned(),
        api_version: API_VERSION,
        ..AnalysisResult::default()
    };
    if request.schema != API_SCHEMA {
        result.error = Some(ApiError {
            code: "unsupported-schema".to_owned(),
            message: format!("Expected {API_SCHEMA}"),
        });
        return result;
    }
    let index = match index_snapshot(request.project) {
        Ok(index) => index,
        Err(_) => {
            result.error = Some(ApiError {
                code: "invalid-snapshot".to_owned(),
                message: "The Evidence project snapshot is invalid or exceeds an analysis limit"
                    .to_owned(),
            });
            return result;
        }
    };
    result.diagnostics = index.diagnostics().iter().map(diagnostic_dto).collect();
    result.symbols = index
        .symbols()
        .iter()
        .filter(|symbol| matches!(symbol.kind, refs::SymbolKind::Evidence(_)))
        .map(|symbol| Symbol {
            name: symbol.name.clone(),
            kind: symbol.kind.label().to_owned(),
            container_name: symbol.container_name.clone(),
            path: relative_string(&symbol.location.path),
            range: symbol.location.range,
        })
        .collect();
    result.relationships = index
        .relationships(MAX_RELATIONSHIPS)
        .into_iter()
        .map(|relationship| Relationship {
            source: location_dto(&relationship.source),
            target: RelationshipTarget {
                kind: relationship.target_kind.label().to_owned(),
                name: relationship.target_name,
                scope: relationship.target_scope,
            },
            definitions: relationship.definitions.iter().map(location_dto).collect(),
        })
        .collect();
    if let Some(query) = request.definition.and_then(valid_query) {
        result.definitions = index
            .definitions_at(&query.0, query.1)
            .iter()
            .map(location_dto)
            .collect();
    }
    if let Some(query) = request.references.and_then(valid_query) {
        result.references = index
            .references_at(&query.0, query.1, true)
            .iter()
            .map(location_dto)
            .collect();
    }
    if let Some(query) = request.completion.and_then(valid_query) {
        result.completions = index
            .completions_at(&query.0, query.1)
            .into_iter()
            .map(|candidate| Completion {
                label: candidate.label,
                new_text: candidate.new_text,
                filter_text: candidate.filter_text,
                detail: candidate.detail,
                range: candidate.range,
            })
            .collect();
    }
    if let Some(query) = request.hover.and_then(valid_query) {
        result.hover = index.hover_at(&query.0, query.1).map(|hover| Hover {
            markdown: hover.markdown,
            range: hover.range,
        });
    }
    result
}

fn checked_relative(path: &str) -> Result<PathBuf, SnapshotError> {
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(SnapshotError::InvalidPath);
    }
    Ok(path.to_path_buf())
}

fn valid_query(query: Query) -> Option<(PathBuf, Position)> {
    checked_relative(&query.path)
        .ok()
        .map(|path| (path, query.position))
}

fn relative_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn location_dto(location: &IndexedLocation) -> Location {
    Location {
        path: relative_string(&location.path),
        range: location.range,
    }
}

fn diagnostic_dto(diagnostic: &IndexedDiagnostic) -> Diagnostic {
    Diagnostic {
        path: relative_string(&diagnostic.path),
        range: diagnostic.range,
        severity: match diagnostic.severity {
            DiagnosticSeverity::ERROR => "error",
            DiagnosticSeverity::WARNING => "warning",
            DiagnosticSeverity::INFORMATION => "information",
            DiagnosticSeverity::HINT => "hint",
            _ => "unknown",
        }
        .to_owned(),
        code: diagnostic.code.clone(),
        message: diagnostic.message.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_paths_are_relative_and_normal() {
        for path in ["", "/questions/a.yaml", "questions/../a.yaml", "./a.yaml"] {
            assert_eq!(checked_relative(path), Err(SnapshotError::InvalidPath));
        }
        assert_eq!(
            checked_relative("questions/a.yaml").unwrap(),
            Path::new("questions/a.yaml")
        );
    }

    #[test]
    fn exact_evidence_semantics_report_the_missing_openapi_prerequisite() {
        let result = analyze(AnalysisRequest {
            schema: API_SCHEMA.to_owned(),
            project: EvidenceProjectSnapshot {
                documents: vec![SnapshotDocument {
                    path: registry_evidence_authoring::marker::PROJECT_MARKER_FILE.to_owned(),
                    text: registry_evidence_authoring::marker::default_project_marker_document()
                        .to_owned(),
                }],
                ..EvidenceProjectSnapshot::default()
            },
            ..AnalysisRequest::default()
        });
        assert_eq!(
            result.diagnostics[0].code.as_deref(),
            Some("evidence/openapi-prerequisite")
        );
    }

    #[test]
    fn relationships_are_the_existing_reference_edges_with_existing_resolution() {
        let result = analyze(AnalysisRequest {
            schema: API_SCHEMA.to_owned(),
            project: EvidenceProjectSnapshot {
                documents: vec![
                    SnapshotDocument {
                        path: "selectors/person.yaml".to_owned(),
                        text: "id: person\nfields: {}\n".to_owned(),
                    },
                    SnapshotDocument {
                        path: "questions/check.yaml".to_owned(),
                        text: concat!(
                            "id: check\n",
                            "question: Is the record current?\n",
                            "purpose: test\n",
                            "subject: { role: subject, selector: id, profile: person }\n",
                            "source: { ref: people }\n",
                            "answers:\n",
                            "  - { concept: current, id: 'urn:concept:current', type: boolean }\n",
                            "derivation: derivations/check.rhai\n",
                            "disclosure: { allow: [current] }\n",
                            "governance:\n",
                            "  requirement: 'urn:requirement:check'\n",
                            "  kind: criterion\n",
                            "  referenceFrameworks: ['urn:framework:test']\n",
                            "  evidenceType: 'urn:evidence-type:check'\n",
                            "  validitySeconds: 60\n",
                            "  observationTimezone: Etc/UTC\n",
                            "  fixtures: fixtures/check.yaml\n",
                            "  disclosureFamilies: ['urn:family:check']\n",
                        )
                        .to_owned(),
                    },
                    SnapshotDocument {
                        path: "sources/people.yaml".to_owned(),
                        text: "transport: http-json\n".to_owned(),
                    },
                ],
                openapi_document: Some(SnapshotDocument {
                    path: OPENAPI_FILE.to_owned(),
                    text: "openapi: 3.1.0\ninfo: { title: source, version: '1' }\npaths: {}\n"
                        .to_owned(),
                }),
                present_artifacts: vec![
                    "derivations/check.rhai".to_owned(),
                    "fixtures/check.yaml".to_owned(),
                ],
            },
            ..AnalysisRequest::default()
        });
        assert!(result.relationships.iter().any(|edge| {
            edge.target.name == "person"
                && edge.target.kind == "selector profile"
                && edge
                    .definitions
                    .iter()
                    .any(|definition| definition.path == "selectors/person.yaml")
        }));
    }
}
