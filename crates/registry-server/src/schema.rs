// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schema for Registry Server authoring documents.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::contract::RegistryProject;

const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

pub const REGISTRY_PROJECT_SCHEMA_FILE: &str = "registry-project.schema.json";
pub const REGISTRY_PROJECT_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/registry-server/authoring/registry-project.v1alpha1.schema.json";

/// Every authoring schema under its committed artifact filename.
pub fn documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let entries = [(
        REGISTRY_PROJECT_SCHEMA_FILE,
        "Registry Server authored project",
        REGISTRY_PROJECT_SCHEMA_ID,
        serde_json::to_value(schemars::schema_for!(RegistryProject))?,
    )];
    entries
        .into_iter()
        .map(|(file, title, identifier, derived)| {
            Ok((file, render(published(derived, title, identifier))?))
        })
        .collect()
}

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

fn render(value: Value) -> Result<String, serde_json::Error> {
    let mut rendered = serde_json::to_string_pretty(&value)?;
    rendered.push('\n');
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use jsonschema::{Draft, JSONSchema};
    use serde_json::Value;

    use super::{documents, REGISTRY_PROJECT_SCHEMA_FILE, REGISTRY_PROJECT_SCHEMA_ID};

    const ACCEPTANCE_PROJECTS: &[&str] = &[
        "asset-site-placement",
        "business",
        "disability",
        "farmer",
        "publicschema-household",
    ];

    fn schema_document() -> String {
        documents()
            .expect("the Registry Server authoring schema generates")
            .remove(REGISTRY_PROJECT_SCHEMA_FILE)
            .expect("the RegistryProject schema is generated")
    }

    fn compile(document: &str) -> JSONSchema {
        let value: Value = serde_json::from_str(document).expect("a generated schema is JSON");
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&value)
            .expect("a generated schema compiles as 2020-12")
    }

    fn acceptance_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/registry-server/acceptance")
    }

    fn fixture(project: &str) -> Value {
        let path = acceptance_root().join(project).join("registry.yaml");
        serde_norway::from_str(&fs::read_to_string(path).expect("the fixture exists"))
            .expect("the fixture is well-formed YAML")
    }

    #[test]
    fn registry_project_schema_is_the_only_generated_authoring_document() {
        let documents = documents().expect("the Registry Server authoring schema generates");
        assert_eq!(
            documents.keys().copied().collect::<Vec<_>>(),
            vec![REGISTRY_PROJECT_SCHEMA_FILE],
        );
    }

    #[test]
    fn registry_project_schema_declares_the_published_dialect_identifier_and_title() {
        let document = schema_document();
        let value: Value = serde_json::from_str(&document).expect("the schema is JSON");
        assert_eq!(
            value.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema"),
        );
        assert_eq!(
            value.get("$id").and_then(Value::as_str),
            Some(REGISTRY_PROJECT_SCHEMA_ID),
        );
        assert_eq!(
            value.get("title").and_then(Value::as_str),
            Some("Registry Server authored project"),
        );
        assert_eq!(value.get("additionalProperties"), Some(&Value::Bool(false)));
    }

    #[test]
    fn registry_project_schema_reproduces_byte_for_byte() {
        assert_eq!(
            documents().expect("the Registry Server authoring schema generates"),
            documents().expect("the Registry Server authoring schema generates again"),
        );
    }

    #[test]
    fn registry_project_schema_is_pretty_json_with_one_trailing_newline() {
        let document = schema_document();
        assert!(document.ends_with('\n') && !document.ends_with("\n\n"));
        let value: Value = serde_json::from_str(&document).expect("the schema is JSON");
        let mut rendered =
            serde_json::to_string_pretty(&value).expect("a parsed schema renders again");
        rendered.push('\n');
        assert_eq!(document, rendered);
    }

    #[test]
    fn schema_accepts_the_current_registry_yaml_fixtures() {
        let document = schema_document();
        let schema = compile(&document);
        for project in ACCEPTANCE_PROJECTS {
            assert!(
                schema.is_valid(&fixture(project)),
                "{project}/registry.yaml"
            );
        }
    }

    #[test]
    fn schema_rejects_unknown_top_level_keys() {
        let document = schema_document();
        let schema = compile(&document);
        let mut instance = fixture("asset-site-placement");
        instance["unexpected"] = Value::Bool(true);

        assert!(!schema.is_valid(&instance));
    }

    #[test]
    fn schema_rejects_field_options_that_do_not_belong_to_the_field_type() {
        let document = schema_document();
        let schema = compile(&document);
        let mut instance = fixture("asset-site-placement");
        instance["entities"][0]["fields"][0]["precision"] = Value::from(2_u64);

        assert!(!schema.is_valid(&instance));
    }

    #[test]
    fn schema_rejects_missing_type_options_required_by_the_field_type() {
        let document = schema_document();
        let schema = compile(&document);
        let mut instance = fixture("asset-site-placement");
        instance["entities"][0]["fields"][0]
            .as_object_mut()
            .expect("the field is an object")
            .remove("maxLength");

        assert!(!schema.is_valid(&instance));
    }

    #[test]
    fn schema_rejects_unknown_field_kinds() {
        let document = schema_document();
        let schema = compile(&document);
        let mut instance = fixture("asset-site-placement");
        instance["entities"][0]["fields"][0]["type"] = Value::String("bytes".to_owned());

        assert!(!schema.is_valid(&instance));
    }

    #[test]
    fn schema_accepts_the_minimal_tagged_event_and_webhook_shape() {
        let schema = compile(&schema_document());
        let mut instance = fixture("asset-site-placement");
        instance["entities"][0]["events"] = serde_json::json!([{
            "id": "asset-created-v1",
            "trigger": "created",
            "projection": ["asset-code", "label"],
            "when": {
                "kind": "fields",
                "afterEquals": {"asset-class": "equipment"}
            },
            "webhook": {"destinationId": "asset-operations"}
        }]);

        assert!(schema.is_valid(&instance));
    }

    #[test]
    fn schema_rejects_per_event_delivery_policy() {
        let schema = compile(&schema_document());
        let mut instance = fixture("asset-site-placement");
        instance["entities"][0]["events"] = serde_json::json!([{
            "id": "asset-created-v1",
            "trigger": "created",
            "projection": ["asset-code"],
            "webhook": {
                "destinationId": "asset-operations",
                "authenticationProfile": "hmac_sha256_v1"
            }
        }]);

        assert!(!schema.is_valid(&instance));
    }

    #[test]
    fn committed_authoring_schema_matches_generated_bytes() {
        let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/registry-server/generated/authoring")
            .join(REGISTRY_PROJECT_SCHEMA_FILE);
        assert_eq!(
            fs::read_to_string(committed).expect("the committed schema exists"),
            schema_document(),
        );
    }
}
