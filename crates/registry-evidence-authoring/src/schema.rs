//! A machine-readable description of the authoring form, for editors.
//!
//! An adopter writes YAML, and the editor they write it in already knows how to
//! offer key completion and shape checking from a JSON Schema. What it cannot
//! do is guess the form. This module derives that schema from the same Rust
//! types the checks in [`crate::validate`] read, so an editor's idea of the
//! form and adopter tooling's idea of the form come from one place and cannot
//! drift apart.
//!
//! Only a document with a Rust type behind it appears here. Sources, selectors,
//! derivations, schemas, fixtures, and sources are authored too, but this crate
//! holds no closed model of them yet, and a schema written by hand
//! for one of them would be the drift this module exists to prevent.
//!
//! What the derived schema describes is shape: which keys exist, which are
//! required, which values are one of a closed set. It does not describe
//! meaning, and it is not a second implementation of the checks. A document the
//! schema turns away is one the checks turn away too; a document it accepts may
//! still be wrong in ways only [`crate::validate`] can name, and an editor
//! should keep asking that question after the schema has stopped complaining.
//!
//! Rendering is canonical so the committed artifact reproduces byte for byte:
//! keys sort, indentation is `serde_json`'s pretty form, and every document
//! ends with exactly one newline. Writing the bytes stays with the caller, as
//! everywhere else in this crate.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::{marker::ProjectMarker, model::Question};

/// The JSON Schema dialect every generated document declares.
const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// The stable identifier space the generated documents live in.
///
/// The host is a reserved example domain on purpose: an identifier is how a
/// tool tells two schemas apart, not an address it should fetch.
const SCHEMA_ID_PREFIX: &str = "https://registrystack.example/schemas/evidence-authoring/";

/// The schema for one authored question, the documents under `questions/`.
pub const QUESTION_SCHEMA_FILE: &str = "question.schema.json";

/// The schema for the marker that anchors a project root.
pub const PROJECT_MARKER_SCHEMA_FILE: &str = "project-marker.schema.json";

/// Every generated schema, keyed by the filename it is committed under.
///
/// # Errors
///
/// Returns the `serde_json` error if a derived schema cannot be rendered, which
/// would mean `schemars` produced a value this crate cannot serialize.
pub fn documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let entries = [
        (
            QUESTION_SCHEMA_FILE,
            "Evidence authored question",
            "question.v1.json",
            serde_json::to_value(schemars::schema_for!(Question))?,
        ),
        (
            PROJECT_MARKER_SCHEMA_FILE,
            "Evidence authoring project marker",
            "project-marker.v1.json",
            serde_json::to_value(schemars::schema_for!(ProjectMarker))?,
        ),
    ];
    entries
        .into_iter()
        .map(|(file, title, identifier, derived)| {
            Ok((file, render(published(derived, title, identifier))?))
        })
        .collect()
}

/// Give one derived schema the dialect, identifier, and title a published
/// document carries.
///
/// `schemars` names a schema after its Rust type. That name is an
/// implementation detail of this crate, and an editor shows the title in a
/// tooltip, so the published documents carry the name an adopter would
/// recognize instead.
fn published(derived: Value, title: &str, identifier: &str) -> Value {
    let mut object = match derived {
        Value::Object(object) => object,
        other => {
            let mut object = Map::new();
            object.insert("$comment".to_owned(), other);
            object
        }
    };
    object.insert(
        "$schema".to_owned(),
        Value::String(SCHEMA_DIALECT.to_owned()),
    );
    object.insert(
        "$id".to_owned(),
        Value::String(format!("{SCHEMA_ID_PREFIX}{identifier}")),
    );
    object.insert("title".to_owned(), Value::String(title.to_owned()));
    Value::Object(object)
}

/// Render one schema the single way the committed artifact is written.
fn render(value: Value) -> Result<String, serde_json::Error> {
    let mut rendered = serde_json::to_string_pretty(&value)?;
    rendered.push('\n');
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::{documents, PROJECT_MARKER_SCHEMA_FILE, QUESTION_SCHEMA_FILE};

    #[test]
    fn both_documents_are_generated_under_their_committed_filenames() {
        let documents = documents().expect("the authoring schemas generate");
        assert!(documents.contains_key(QUESTION_SCHEMA_FILE));
        assert!(documents.contains_key(PROJECT_MARKER_SCHEMA_FILE));
        assert_eq!(documents.len(), 2);
    }

    #[test]
    fn a_derived_description_reaches_the_published_document() {
        let documents = documents().expect("the authoring schemas generate");
        assert!(
            documents[QUESTION_SCHEMA_FILE].contains("which governed concepts the answer carries"),
            "the model's own prose must reach the editor, or the schema explains nothing",
        );
    }
}
