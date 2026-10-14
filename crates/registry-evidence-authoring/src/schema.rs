//! A machine-readable description of the authoring form, for editors.
//!
//! An adopter writes YAML, and the editor they write it in already knows how to
//! offer key completion and shape checking from a JSON Schema. What it cannot
//! do is guess the form. This module derives that schema from the same Rust
//! types the checks in [`crate::validate`] read, so an editor's idea of the
//! form and adopter tooling's idea of the form come from one place and cannot
//! drift apart.
//!
//! The normalized project, target, and target authority are the three authored
//! documents this crate owns. Sources, selectors, functions, assertion
//! definitions, and outputs are members of that one project document rather
//! than parallel formats.
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

/// The JSON Schema dialect every generated document declares.
const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// The schema for the one normalized `evidence.yaml` project.
pub const PROJECT_SCHEMA_FILE: &str = "project.schema.json";
/// The schema for an environment's target bindings.
pub const TARGET_SCHEMA_FILE: &str = "target.schema.json";
/// The schema for the target's separately governed authority.
pub const TARGET_AUTHORITY_SCHEMA_FILE: &str = "target-authority.schema.json";

const TARGET_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/evidence/target/target.v1alpha1.schema.json";
const TARGET_AUTHORITY_SCHEMA_ID: &str = "https://id.registrystack.org/schemas/evidence/target-authority/target-authority.v1alpha1.schema.json";

/// Every generated schema, keyed by the filename it is committed under.
///
/// # Errors
///
/// Returns the `serde_json` error if a derived schema cannot be rendered, which
/// would mean `schemars` produced a value this crate cannot serialize.
pub fn documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let entries = [
        (
            PROJECT_SCHEMA_FILE,
            "Evidence project",
            crate::project::PROJECT_SCHEMA_ID,
            (
                crate::project::PROJECT_API_VERSION,
                crate::project::PROJECT_KIND,
            ),
            serde_json::to_value(schemars::schema_for!(crate::project::EvidenceProject))?,
        ),
        (
            TARGET_SCHEMA_FILE,
            "Evidence target",
            TARGET_SCHEMA_ID,
            (
                crate::target::TARGET_API_VERSION,
                crate::target::TARGET_KIND,
            ),
            serde_json::to_value(schemars::schema_for!(crate::target::EvidenceTarget))?,
        ),
        (
            TARGET_AUTHORITY_SCHEMA_FILE,
            "Evidence target authority",
            TARGET_AUTHORITY_SCHEMA_ID,
            (
                crate::target::AUTHORITY_API_VERSION,
                crate::target::AUTHORITY_KIND,
            ),
            serde_json::to_value(schemars::schema_for!(
                crate::target::EvidenceTargetAuthority
            ))?,
        ),
    ];
    entries
        .into_iter()
        .map(|(file, title, schema_id, envelope, derived)| {
            Ok((file, publish(derived, title, schema_id, envelope)?))
        })
        .collect()
}

/// Turn one derived schema into the document committed for its format: map
/// keys stated as identifiers, the envelope, then the dialect, `$id`, and
/// title, rendered the one canonical way. Tooling that owns a document type
/// of its own calls this so every committed schema is shaped alike.
///
/// # Errors
///
/// Returns the `serde_json` error if the schema cannot be rendered.
pub fn publish(
    derived: Value,
    title: &str,
    schema_id: &str,
    envelope: (&str, &str),
) -> Result<String, serde_json::Error> {
    let enveloped = with_envelope(type_map_keys(derived)?, envelope);
    render(published(enveloped, title, schema_id))
}

/// Schemars writes a map keyed by `LocalId` or `ExternalId` as
/// `patternProperties` under the identifier's pattern, which drops its other
/// bounds. State the key as the identifier itself (CFG-SCHEMA-4, CFG-ID-1):
/// `propertyNames` naming `$defs/LocalId` or `$defs/ExternalId`, and
/// `additionalProperties` carrying the value schema.
fn type_map_keys(mut derived: Value) -> Result<Value, serde_json::Error> {
    let identifiers = [
        (
            "LocalId",
            identifier_schema::<registry_platform_yaml::LocalId>()?,
        ),
        (
            "ExternalId",
            identifier_schema::<registry_platform_yaml::ExternalId>()?,
        ),
    ];
    for (name, identifier) in identifiers {
        let Some(pattern) = identifier.get("pattern").and_then(Value::as_str) else {
            continue;
        };
        let pattern = pattern.to_owned();
        if retype_maps(&mut derived, &pattern, name) {
            if let Some(root) = derived.as_object_mut() {
                let defs = root
                    .entry("$defs")
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Value::Object(defs) = defs {
                    defs.entry(name).or_insert(identifier);
                }
            }
        }
    }
    Ok(derived)
}

fn identifier_schema<T: schemars::JsonSchema>() -> Result<Value, serde_json::Error> {
    serde_json::to_value(T::json_schema(&mut schemars::SchemaGenerator::default()))
}

/// Rewrite every map keyed under `pattern`; true when one was rewritten.
fn retype_maps(schema: &mut Value, pattern: &str, name: &str) -> bool {
    let mut rewritten = false;
    match schema {
        Value::Object(object) => {
            let value = match object.get("patternProperties") {
                Some(Value::Object(patterns)) if patterns.len() == 1 => {
                    patterns.get(pattern).cloned()
                }
                _ => None,
            };
            if let Some(value) = value {
                object.remove("patternProperties");
                object.insert(
                    "propertyNames".to_owned(),
                    serde_json::json!({"$ref": format!("#/$defs/{name}")}),
                );
                object.insert("additionalProperties".to_owned(), value);
                rewritten = true;
            }
            for member in object.values_mut() {
                rewritten |= retype_maps(member, pattern, name);
            }
        }
        Value::Array(items) => {
            for item in items {
                rewritten |= retype_maps(item, pattern, name);
            }
        }
        _ => {}
    }
    rewritten
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
    use super::{
        documents, type_map_keys, PROJECT_SCHEMA_FILE, TARGET_AUTHORITY_SCHEMA_FILE,
        TARGET_SCHEMA_FILE,
    };

    #[test]
    fn normalized_documents_are_generated_under_their_committed_filenames() {
        let documents = documents().expect("the authoring schemas generate");
        assert_eq!(
            documents.keys().copied().collect::<Vec<_>>(),
            vec![
                PROJECT_SCHEMA_FILE,
                TARGET_AUTHORITY_SCHEMA_FILE,
                TARGET_SCHEMA_FILE,
            ]
        );
    }

    #[test]
    fn every_document_states_its_envelope_and_published_identifier() {
        let documents = documents().expect("the authoring schemas generate");
        for (file, format, kind, id) in [
            (
                PROJECT_SCHEMA_FILE,
                "project",
                "EvidenceProject",
                "https://id.registrystack.org/schemas/evidence/project/project.v1alpha1.schema.json",
            ),
            (
                TARGET_SCHEMA_FILE,
                "target",
                "EvidenceTarget",
                "https://id.registrystack.org/schemas/evidence/target/target.v1alpha1.schema.json",
            ),
            (
                TARGET_AUTHORITY_SCHEMA_FILE,
                "target-authority",
                "EvidenceTargetAuthority",
                "https://id.registrystack.org/schemas/evidence/target-authority/target-authority.v1alpha1.schema.json",
            ),
        ] {
            let document: serde_json::Value =
                serde_json::from_str(&documents[file]).expect("the schema is JSON");
            assert_eq!(document["$id"], id);
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
            documents[PROJECT_SCHEMA_FILE].contains("Optional presentation label"),
            "the model's own prose must reach the editor, or the schema explains nothing",
        );
    }

    #[test]
    fn a_map_key_definition_is_added_when_the_derived_schema_has_no_definitions() {
        let pattern = "^[^\\u0000-\\u001F\\u007F-\\u009F]+$";
        let derived = serde_json::json!({
            "type": "object",
            "properties": {
                "keys": {
                    "type": "object",
                    "patternProperties": {pattern: {"type": "string"}},
                },
            },
        });
        let typed = type_map_keys(derived).expect("the map keys are typed");
        assert_eq!(
            typed["properties"]["keys"]["propertyNames"]["$ref"],
            "#/$defs/ExternalId"
        );
        assert!(
            typed["$defs"]["ExternalId"].is_object(),
            "a reference to $defs/ExternalId must resolve inside the document"
        );
    }
}
