// SPDX-License-Identifier: Apache-2.0
//! Building an Evidence authoring project on disk and asking the index about it.
//!
//! Every test here works from real files under a temporary directory rather than from an in-memory
//! filesystem, because the loader's containment rules are filesystem rules: a mocked filesystem
//! would pass the tests and prove nothing about the symbolic link a project may actually hold.
//!
//! Positions come from cursor markers written into the fixture text. A marker is `<|name|>`, it is
//! removed before the file is written, and it records the position of the character that follows
//! it, so a test names the field it points at instead of counting columns.

// Each test binary compiles this module and uses part of it. The rest is used by a sibling binary,
// so it is unreachable here without being dead in the crate.
#![allow(dead_code)]

pub mod lsp;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use registry_evidence_authoring::testing::{referenced_form_project, ProjectFile};
use registry_language_server::ProjectIndex;
use tempfile::TempDir;
use tower_lsp_server::ls_types::Position;

/// An Evidence authoring project written to a temporary directory, and the positions its cursor
/// markers named.
pub struct EvidenceProject {
    _temp: TempDir,
    root: PathBuf,
    cursors: BTreeMap<String, BTreeMap<String, Position>>,
}

impl EvidenceProject {
    /// Writes every file, stripping and recording its cursor markers.
    pub fn new(files: &[ProjectFile]) -> Self {
        let temp = TempDir::new().expect("temporary project directory");
        let mut cursors = BTreeMap::new();
        for file in files {
            let (contents, marks) = strip_cursors(&file.contents);
            let path = temp.path().join(&file.path);
            fs::create_dir_all(path.parent().expect("project file has a parent"))
                .expect("project directory");
            fs::write(&path, contents).expect("project file");
            if !marks.is_empty() {
                cursors.insert(file.path.clone(), marks);
            }
        }
        let root = temp.path().canonicalize().expect("canonical project root");
        Self {
            _temp: temp,
            root,
            cursors,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The canonical path of one project file, as the index names it.
    pub fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// The position a named cursor marker pointed at.
    pub fn cursor(&self, relative: &str, name: &str) -> Position {
        *self
            .cursors
            .get(relative)
            .and_then(|marks| marks.get(name))
            .unwrap_or_else(|| panic!("{relative} carries a <|{name}|> cursor marker"))
    }

    pub fn index(&self) -> ProjectIndex {
        ProjectIndex::load_evidence(&self.root).expect("the project loads")
    }
}

/// The text without its cursor markers, and where each marker pointed.
fn strip_cursors(text: &str) -> (String, BTreeMap<String, Position>) {
    let mut stripped = String::with_capacity(text.len());
    let mut cursors = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let mut column = 0;
        let mut rest = line;
        while let Some(start) = rest.find("<|") {
            let (before, marker) = rest.split_at(start);
            stripped.push_str(before);
            column += before.encode_utf16().count();
            let marker = &marker["<|".len()..];
            let end = marker.find("|>").expect("a cursor marker closes with |>");
            let position = Position::new(number as u32, column as u32);
            assert!(
                cursors.insert(marker[..end].to_owned(), position).is_none(),
                "one document names each cursor marker once"
            );
            rest = &marker[end + "|>".len()..];
        }
        stripped.push_str(rest);
        stripped.push('\n');
    }
    (stripped, cursors)
}

/// One project file, for the fixtures below.
pub fn file(path: &str, contents: &str) -> ProjectFile {
    ProjectFile {
        path: path.to_owned(),
        contents: contents.to_owned(),
    }
}

/// The same file set with one path written differently, whether or not it was there before.
pub fn replacing(files: &[ProjectFile], path: &str, contents: &str) -> Vec<ProjectFile> {
    let mut files = files
        .iter()
        .filter(|candidate| candidate.path != path)
        .cloned()
        .collect::<Vec<_>>();
    files.push(file(path, contents));
    files
}

/// The same file set without one path.
pub fn without(files: &[ProjectFile], path: &str) -> Vec<ProjectFile> {
    files
        .iter()
        .filter(|candidate| candidate.path != path)
        .cloned()
        .collect()
}

/// The worked referenced-form project the edge tests start from: one question that reads a named
/// source, the source's own selector, adapters, and schemas, and one access policy that admits the
/// question. It is the shape `registry-evidencectl`'s own handoff fixture stages, so a document
/// the editor accepts here is a document that compiler has accepted.
pub fn adult_status_project() -> Vec<ProjectFile> {
    referenced_form_project(
        OPENAPI,
        "adult-status",
        QUESTION,
        DERIVATION,
        Some(FIXTURE),
        &[
            file("selectors/person-reference-v1.yaml", SELECTOR),
            file("sources/people.yaml", SOURCE),
            file("schemas/people-parameters.schema.yaml", SCHEMA),
            file("schemas/people-response.schema.yaml", SCHEMA),
            file("schemas/people-facts.schema.yaml", SCHEMA),
            file("adapters/people-prepare.rhai", ADAPTER),
            file("adapters/people-extract.rhai", ADAPTER),
            file("access/policies/adult-checks.yaml", ACCESS_POLICY),
        ],
    )
}

pub const QUESTION_PATH: &str = "questions/adult-status.yaml";
pub const SOURCE_PATH: &str = "sources/people.yaml";
pub const SELECTOR_PATH: &str = "selectors/person-reference-v1.yaml";
pub const FIXTURE_PATH: &str = "fixtures/adult-status.yaml";
pub const DERIVATION_PATH: &str = "derivations/adult-status.rhai";
pub const ACCESS_POLICY_PATH: &str = "access/policies/adult-checks.yaml";

pub const OPENAPI: &str =
    "openapi: 3.1.0\ninfo: {title: Example source, version: 1.0.0}\npaths: {}\n";

pub const QUESTION: &str = r#"id: <|id|>adult-status
question: Is the person at least 18 years old?
purpose: fixture-eligibility
subject:
  role: subject
  selector: person_id
  profile: <|subject-profile|>person-reference-v1
source:
  ref: <|source-ref|>people
answers:
  - concept: <|concept|>is_adult
    id: urn:example:concepts:is-adult
    type: boolean
derivation: <|derivation|>derivations/adult-status.rhai
disclosure:
  allow: [<|allow|>is_adult]
governance:
  requirement: urn:example:requirements:adult-status:v1
  kind: criterion
  referenceFrameworks: [urn:example:frameworks:adult-status:v1]
  evidenceType: urn:example:evidence-types:adult-status:v1
  validitySeconds: 86400
  observationTimezone: Etc/UTC
  fixtures: <|fixtures|>fixtures/adult-status.yaml
  disclosureFamilies: [urn:example:disclosure-families:adult-status]
"#;

pub const DERIVATION: &str = "fn answer(facts, selectors, context) {\n    #{is_adult: true}\n}\n";

pub const SOURCE: &str = r#"transport: http-json
baseUrl: https://source.invalid
posture: field-projected
authentication: {kind: static-bearer, tokenRef: 'secret:file/source-token'}
request:
  method: POST
  path: /v1/facts
  fixedHeaders: [{name: Accept, value: application/json}]
  selectorInputs:
    - role: subject
      alternatives:
        - profile: <|alternative-profile|>person-reference-v1
          fields: [person_id]
  prepareScript: adapters/people-prepare.rhai
  adapterParameters: {requestedFields: [date_of_birth], resultLimit: 2}
  adapterParametersSchema: <|parameters-schema|>schemas/people-parameters.schema.yaml
  preparationLimits: {query: forbidden, jsonBody: required, maximumJsonDepth: 8, maximumCollectionItems: 16, maximumStringBytes: 256, maximumNormalizedBytes: 4096}
  projection: [/total, /date_of_birth]
  redirects: deny
  timeoutMilliseconds: 3000
  maximumResponseBytes: 65536
  concurrencyLimit: 8
responseSchema: <|response-schema|>schemas/people-response.schema.yaml
extractScript: adapters/people-extract.rhai
factSchema: <|fact-schema|>schemas/people-facts.schema.yaml
"#;

pub const SELECTOR: &str = "maximumAggregateBytes: 200\nfields:\n  person_id: {type: string, minimumBytes: 1, maximumBytes: 200}\n";

pub const SCHEMA: &str = "type: object\nadditionalProperties: false\n";

pub const ADAPTER: &str = "fn prepare(selectors, context) {\n    #{query: [], body: #{}}\n}\n";

pub const FIXTURE: &str =
    "fixture: registry.evidence.acceptance.editor/v1\nsynthetic_only: true\ncases: []\n";

pub const ACCESS_POLICY: &str =
    "version: 1\nid: <|policy-id|>adult-checks\nquestions: [<|policy-question|>adult-status]\n";
