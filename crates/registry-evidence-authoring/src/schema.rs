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
//! Every document states the envelope its format is read with: `apiVersion`
//! and `kind` as constants, both required, so an editor offers them first and
//! flags a file of another format before the reader does.
//!
//! Rendering is canonical so the committed artifact reproduces byte for byte:
//! keys sort, indentation is `serde_json`'s pretty form, and every document
//! ends with exactly one newline. Writing the bytes stays with the caller, as
//! everywhere else in this crate.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::{
    formats::{
        schema_id, AUTHORING_PROJECT_API_VERSION, AUTHORING_PROJECT_KIND, QUESTION_API_VERSION,
        QUESTION_KIND,
    },
    marker::ProjectMarker,
    model::Question,
};

/// The JSON Schema dialect every generated document declares.
const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

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
            "question",
            (QUESTION_API_VERSION, QUESTION_KIND),
            serde_json::to_value(schemars::schema_for!(Question))?,
        ),
        (
            PROJECT_MARKER_SCHEMA_FILE,
            "Evidence authoring project marker",
            "authoring-project",
            (AUTHORING_PROJECT_API_VERSION, AUTHORING_PROJECT_KIND),
            serde_json::to_value(schemars::schema_for!(ProjectMarker))?,
        ),
    ];
    entries
        .into_iter()
        .map(|(file, title, format, envelope, derived)| {
            let enveloped = with_envelope(derived, envelope);
            Ok((
                file,
                render(published(enveloped, title, &schema_id(format)))?,
            ))
        })
        .collect()
}

/// State the envelope a format is read with: `apiVersion` and `kind`, each a
/// required constant, ahead of the members the Rust type derives.
fn with_envelope(derived: Value, (api_version, kind): (&str, &str)) -> Value {
    let Value::Object(mut object) = derived else {
        return derived;
    };
    let mut properties = Map::new();
    for (name, expected) in [("apiVersion", api_version), ("kind", kind)] {
        let mut member = Map::new();
        member.insert("type".to_owned(), Value::String("string".to_owned()));
        member.insert("const".to_owned(), Value::String(expected.to_owned()));
        properties.insert(name.to_owned(), Value::Object(member));
    }
    if let Some(Value::Object(derived_properties)) = object.remove("properties") {
        properties.extend(derived_properties);
    }
    object.insert("properties".to_owned(), Value::Object(properties));
    let mut required = vec![
        Value::String("apiVersion".to_owned()),
        Value::String("kind".to_owned()),
    ];
    if let Some(Value::Array(derived_required)) = object.remove("required") {
        required.extend(derived_required);
    }
    object.insert("required".to_owned(), Value::Array(required));
    Value::Object(object)
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
    object.insert("$id".to_owned(), Value::String(identifier.to_owned()));
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
    fn every_document_states_its_envelope_and_published_identifier() {
        let documents = documents().expect("the authoring schemas generate");
        for (file, format, kind) in [
            (QUESTION_SCHEMA_FILE, "question", "EvidenceQuestion"),
            (
                PROJECT_MARKER_SCHEMA_FILE,
                "authoring-project",
                "EvidenceAuthoringProject",
            ),
        ] {
            let document: serde_json::Value =
                serde_json::from_str(&documents[file]).expect("the schema is JSON");
            assert_eq!(
                document["$id"],
                format!(
                    "https://id.registrystack.org/schemas/evidence/{format}/{format}.v1alpha1.schema.json"
                )
            );
            assert_eq!(document["properties"]["kind"]["const"], kind);
            assert_eq!(
                document["properties"]["apiVersion"]["const"],
                format!("id.registrystack.org/formats/evidence/{format}/v1alpha1")
            );
            assert_eq!(document["required"][0], "apiVersion");
            assert_eq!(document["required"][1], "kind");
        }
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
