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

use registry_evidence_authoring::testing::{
    compact_form_project, referenced_form_project, ProjectFile,
};
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

/// The text a fixture writes to disk: its cursor markers removed and nothing else changed.
///
/// A test that hands a fixture to the authoring library rather than to the index needs the
/// document an author would have written, which is this and not the marked-up constant.
pub fn without_cursors(text: &str) -> String {
    strip_cursors(text).0
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
/// question.
///
/// Every test below leans on this project being one the compiler accepts, so the part of that
/// claim which can be executed here is executed:
/// `the_shared_fixture_questions_are_ones_the_authoring_form_accepts` hands [`QUESTION`] to the
/// same deserializer and the same checks `registry-evidencectl` reads a question with. The
/// remaining documents are paired by citation, because the rules that judge them are the
/// compiler's own and this crate must not depend on it.
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

/// The worked compact-form project the OpenAPI edges start from: one question that answers an
/// operation of the project's own description directly, with no source, selector, or schema file of
/// its own.
///
/// This is the other half of the authoring form. [`adult_status_project`] writes a question that
/// names a source document, so its description publishes nothing and the four edges that read one
/// have nothing to resolve against. Here the description publishes one operation, the question
/// selects a subject by its path parameter and projects one fact out of its response, and the
/// bound it declares names the collection that fact visits.
///
/// It is written down to a project `registry-evidencectl` really compiles, which is why the
/// description carries a loopback `servers` entry and closes its one selected string with a
/// `format`: without either, the build refuses the project for a reason none of these tests is
/// about, and every test asserting the editor is quiet over it would be asserting nothing.
pub fn operation_question_project() -> Vec<ProjectFile> {
    compact_form_project(
        OPERATION_OPENAPI,
        "adult-status",
        OPERATION_QUESTION,
        DERIVATION,
    )
}

pub const QUESTION_PATH: &str = "questions/adult-status.yaml";
pub const OPENAPI_PATH: &str = "source.openapi.yaml";
pub const SOURCE_PATH: &str = "sources/people.yaml";
pub const SELECTOR_PATH: &str = "selectors/person-reference-v1.yaml";
pub const FIXTURE_PATH: &str = "fixtures/adult-status.yaml";
pub const DERIVATION_PATH: &str = "derivations/adult-status.rhai";
pub const ACCESS_POLICY_PATH: &str = "access/policies/adult-checks.yaml";

pub const OPENAPI: &str =
    "openapi: 3.1.0\ninfo: {title: Example source, version: 1.0.0}\npaths: {}\n";

/// The description [`operation_question_project`] publishes one operation from, written down to the
/// keys `registry-evidencectl` allows a selected path item, operation, and path selector to carry.
pub const OPERATION_OPENAPI: &str = r#"openapi: 3.1.0
info: {title: Example source, version: 1.0.0}
servers: [{url: 'http://127.0.0.1:8000'}]
paths:
  /people/{person_id}:
    get:
      operationId: <|operation-id|>readPerson
      parameters:
        - name: person_id
          in: path
          required: true
          schema: {type: string}
      responses:
        '200':
          description: The records held for one person
          content:
            application/json:
              schema:
                type: object
                properties:
                  records:
                    type: array
                    items:
                      type: object
                      properties:
                        date_of_birth: {type: string, format: date}
"#;

/// The question [`operation_question_project`] holds: the same adult-status question written in the
/// compact form, so it names an operation instead of a source and projects its own facts.
pub const OPERATION_QUESTION: &str = r#"id: adult-status
question: Is the person at least 18 years old?
purpose: fixture-eligibility
subject:
  role: subject
  selector: <|selector|>person_id
source:
  operation: <|operation|>readPerson
  facts:
    - name: date_of_birth
      path: <|fact-path|>/records/*/date_of_birth
      combine: collect
  collectionBounds:
    <|collection-bound|>/records: 16
answers:
  - concept: <|concept|>is_adult
    id: urn:example:concepts:is-adult
    type: boolean
derivation: <|derivation|>derivations/adult-status.rhai
disclosure:
  allow: [<|allow|>is_adult]
"#;

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

/// The subject block [`QUESTION`] writes, so the rewrite below has something to replace.
const SINGULAR_SUBJECT: &str = concat!(
    "subject:\n",
    "  role: subject\n",
    "  selector: person_id\n",
    "  profile: <|subject-profile|>person-reference-v1\n",
);

/// The same subject declared in the plural form the authoring form also allows, with a second
/// subject beside it. Only the first is offered by a selector input of the source, so the second is
/// declared for the derivation, which is what the compiler asks of a subject the source does not
/// carry.
const PLURAL_SUBJECTS: &str = concat!(
    "subjects:\n",
    "  - role: subject\n",
    "    selector: person_id\n",
    "    profile: <|subject-profile|>person-reference-v1\n",
    "  - role: guardian\n",
    "    selector: person_id\n",
    "    profile: <|guardian-profile|>person-reference-v1\n",
    "    derivation: true\n",
);

/// The shared question with its subject written in the plural form.
pub fn question_with_plural_subjects() -> String {
    let written = QUESTION.replace(SINGULAR_SUBJECT, PLURAL_SUBJECTS);
    assert_ne!(
        written, QUESTION,
        "the shared question writes the singular subject block this rewrites"
    );
    written
}

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
  prepareScript: <|prepare-script|>adapters/people-prepare.rhai
  adapterParameters: {requestedFields: [date_of_birth], resultLimit: 2}
  adapterParametersSchema: <|parameters-schema|>schemas/people-parameters.schema.yaml
  preparationLimits: {query: forbidden, jsonBody: required, maximumJsonDepth: 8, maximumCollectionItems: 16, maximumStringBytes: 256, maximumNormalizedBytes: 4096}
  projection: [/total, /date_of_birth]
  redirects: deny
  timeoutMilliseconds: 3000
  maximumResponseBytes: 65536
  concurrencyLimit: 8
responseSchema: <|response-schema|>schemas/people-response.schema.yaml
extractScript: <|extract-script|>adapters/people-extract.rhai
factSchema: <|fact-schema|>schemas/people-facts.schema.yaml
"#;

pub const SELECTOR: &str = "maximumAggregateBytes: 200\nfields:\n  person_id: {type: string, minimumBytes: 1, maximumBytes: 200}\n";

pub const SCHEMA: &str = "type: object\nadditionalProperties: false\n";

/// The same schema in JSON. A source's own artifacts are copied into the bundle byte for byte
/// rather than parsed, so the compiler reads one wherever the source points and whatever it is
/// written in.
pub const SCHEMA_JSON: &str = "{\"type\": \"object\", \"additionalProperties\": false}\n";

pub const ADAPTER: &str = "fn prepare(selectors, context) {\n    #{query: [], body: #{}}\n}\n";

pub const FIXTURE: &str =
    "fixture: registry.evidence.acceptance.editor/v1\nsynthetic_only: true\ncases: []\n";

pub const ACCESS_POLICY: &str =
    "version: 1\nid: <|policy-id|>adult-checks\nquestions: [<|policy-question|>adult-status]\n";
