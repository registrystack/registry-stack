// SPDX-License-Identifier: Apache-2.0

//! Generated JSON Schema for the Evidence code list format.
//!
//! The schema is derived from the reader types in [`crate::codelist`], never
//! written by hand. Regenerate the committed document with:
//!
//! ```bash
//! cargo run -p registry-evidence --features schema --example codelist-schema -- \
//!   --output products/evidence/generated/codelist
//! ```
//!
//! The derived schema states the rules `read_codelist` enforces beyond the
//! types: the envelope, and from 1 to 4096 items in each list or mapping.
//! That a mapping output appears in `allowedOutputs` is a cross-member rule
//! the reader alone checks.

use std::collections::BTreeMap;

use registry_platform_yaml::{ExternalId, LocalId};
use schemars::generate::SchemaSettings;
use serde_json::{json, Value};

use crate::codelist::{
    CodelistDocument, CODELIST_MAXIMUM_ITEMS, EVIDENCE_CODELIST_API_VERSION, EVIDENCE_CODELIST_KIND,
};
use crate::fixture::{EVIDENCE_FIXTURE_API_VERSION, EVIDENCE_FIXTURE_KIND, MAXIMUM_CASES};

/// The committed code list schema file name.
pub const CODELIST_SCHEMA_FILE: &str = "codelist.schema.json";

/// The code list schema `$id` (CFG-SCHEMA-3).
pub const CODELIST_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/evidence/codelist/codelist.v1alpha1.schema.json";

/// Every code list schema document, by file name.
pub fn codelist_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut generator = SchemaSettings::draft2020_12().into_generator();
    // A mapping key is a source code another system issues (CFG-ID-2), so the
    // schema names the shared definition beside the code spelling it reads.
    generator.subschema_for::<ExternalId>();
    let mut derived = serde_json::to_value(generator.into_root_schema_for::<CodelistDocument>())?;
    install_codelist_rules(&mut derived);
    let mut object = match derived {
        Value::Object(object) => object,
        _ => unreachable!("schemars derives a schema object for CodelistDocument"),
    };
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert(
        "$id".to_owned(),
        Value::String(CODELIST_SCHEMA_ID.to_owned()),
    );
    object.insert(
        "title".to_owned(),
        Value::String("Evidence code list".to_owned()),
    );
    let mut rendered = serde_json::to_string_pretty(&Value::Object(object))?;
    rendered.push('\n');
    Ok([(CODELIST_SCHEMA_FILE, rendered)].into())
}

/// The committed fixture schema file name.
pub const FIXTURE_SCHEMA_FILE: &str = "fixture.schema.json";

/// The fixture schema `$id` (CFG-SCHEMA-3).
pub const FIXTURE_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/evidence/fixture/fixture.v1alpha1.schema.json";

/// The fixture schema document, by file name.
///
/// `read_fixture` is untyped: it reads the envelope, `synthetic_only`, and the
/// case list, and hands every other member to the offline runner, which checks
/// the members of the replay mode it runs. The schema states what the reader
/// itself holds and leaves the runner's members open under a stated reason.
/// The schema requires `synthetic_only` but does not type it: the key is not
/// camelCase, so the schema cannot name it, and the reader alone refuses a
/// value other than `true`.
pub fn fixture_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let local_id = serde_json::to_value(<LocalId as schemars::JsonSchema>::json_schema(
        &mut SchemaSettings::draft2020_12().into_generator(),
    ))?;
    let runner = "the offline runner reads the members of the replay mode it runs and refuses what that mode does not know";
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": FIXTURE_SCHEMA_ID,
        "title": "Evidence fixture set",
        "type": "object",
        "required": ["apiVersion", "kind", "synthetic_only", "cases"],
        "properties": {
            "apiVersion": {"const": EVIDENCE_FIXTURE_API_VERSION},
            "kind": {"const": EVIDENCE_FIXTURE_KIND},
            "common": {
                "type": "object",
                "description": "What every case starts from.",
                "x-registry-passthrough": runner
            },
            "cases": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAXIMUM_CASES,
                "description": "The cases, which together cover every required category.",
                "items": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": {"$ref": "#/$defs/LocalId"},
                        "declaredUnresolved": {"const": true}
                    },
                    "additionalProperties": true,
                    "x-registry-passthrough": runner
                }
            }
        },
        "additionalProperties": true,
        "x-registry-passthrough": runner,
        "$defs": {"LocalId": local_id}
    });
    let mut rendered = serde_json::to_string_pretty(&schema)?;
    rendered.push('\n');
    Ok([(FIXTURE_SCHEMA_FILE, rendered)].into())
}

/// State the envelope and size rules `read_codelist` enforces, in each form.
fn install_codelist_rules(schema: &mut Value) {
    let maximum = CODELIST_MAXIMUM_ITEMS;
    // The envelope is stated once at the root, where a tool that reads only
    // the root finds it, and again in each form, which is closed.
    let root = schema
        .as_object_mut()
        .expect("the code list schema is an object");
    root.insert("type".to_owned(), json!("object"));
    root.insert(
        "properties".to_owned(),
        json!({
            "apiVersion": {"const": EVIDENCE_CODELIST_API_VERSION},
            "kind": {"const": EVIDENCE_CODELIST_KIND},
        }),
    );
    root.insert("required".to_owned(), json!(["apiVersion", "kind"]));
    root.insert("unevaluatedProperties".to_owned(), json!(false));
    let forms = schema["oneOf"]
        .as_array_mut()
        .expect("the code list schema declares its forms");
    for form in forms {
        let required = form["required"]
            .as_array_mut()
            .expect("each code list form requires its members");
        required.insert(0, json!("kind"));
        required.insert(0, json!("apiVersion"));
        let properties = form["properties"]
            .as_object_mut()
            .expect("each code list form has properties");
        properties.insert(
            "apiVersion".to_owned(),
            json!({"const": EVIDENCE_CODELIST_API_VERSION}),
        );
        properties.insert("kind".to_owned(), json!({"const": EVIDENCE_CODELIST_KIND}));
        for list in ["codes", "allowedOutputs"] {
            if let Some(member) = properties.get_mut(list).and_then(Value::as_object_mut) {
                member.insert("minItems".to_owned(), json!(1));
                member.insert("maxItems".to_owned(), json!(maximum));
            }
        }
        if let Some(entries) = properties.get_mut("entries").and_then(Value::as_object_mut) {
            entries.insert("minProperties".to_owned(), json!(1));
            entries.insert("maxProperties".to_owned(), json!(maximum));
            entries.insert(
                "propertyNames".to_owned(),
                json!({"allOf": [{"$ref": "#/$defs/ExternalId"}, {"$ref": "#/$defs/Code"}]}),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
    use super::*;

    fn schema() -> Value {
        serde_json::from_str(&codelist_documents().unwrap()[CODELIST_SCHEMA_FILE]).unwrap()
    }

    #[test]
    fn codelist_schema_is_deterministic_and_identified() {
        assert_eq!(codelist_documents().unwrap(), codelist_documents().unwrap());
        let document = schema();
        assert_eq!(document["$id"], CODELIST_SCHEMA_ID);
        assert_eq!(
            document["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            EVIDENCE_CODELIST_API_VERSION
        );
        assert_eq!(
            document["properties"]["kind"]["const"],
            EVIDENCE_CODELIST_KIND
        );
        assert_eq!(document["required"], json!(["apiVersion", "kind"]));
        assert_eq!(document["unevaluatedProperties"], false);
        for form in document["oneOf"].as_array().expect("two forms") {
            assert_eq!(form["additionalProperties"], false);
        }
    }

    #[test]
    fn the_schema_accepts_what_the_reader_accepts_and_refuses_what_it_refuses() {
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .should_validate_formats(true)
            .compile(&schema())
            .expect("the code list schema compiles");
        const E: &str = "apiVersion: id.registrystack.org/formats/evidence/codelist/v1alpha1\nkind: EvidenceCodelist\n";
        let prefix = "urn:example:codelist:";
        let boundary = format!("{prefix}{}", "é".repeat(512 - prefix.chars().count()));
        assert!(boundary.len() > 512, "the boundary exceeds 512 UTF-8 bytes");
        let identified =
            |scalar: &str| format!("{E}uri: {scalar}\nversion: '1'\ntype: code-list\ncodes: [A]\n");
        let cases: [(String, &str); 19] = [
            (identified(&boundary), "accepted"),
            (identified(&format!("{boundary}é")), "refused"),
            (identified("'urn:example:codelist:status '"), "refused"),
            (identified("' urn:example:codelist:status'"), "refused"),
            (identified("urn:example:codelist:sta tus"), "refused"),
            (identified("\"urn:example:codelist:sta\\ttus\""), "refused"),
            (identified("\"urn:example:codelist:status\\n\""), "refused"),
            (format!("{E}uri: urn:example:codelist:status\nversion: '1'\ntype: code-list\ncodes: [ACTIVE, SUSPENDED]\n"), "accepted"),
            (
                format!("{E}uri: urn:example:codelist:map\nversion: '2026-01'\ntype: mapping\nentries:\n  R-101: NORTH\nallowedOutputs: [NORTH]\n"),
                "accepted",
            ),
            ("uri: urn:example:codelist:status\nversion: '1'\ntype: code-list\ncodes: [A]\n".to_owned(), "refused"),
            (format!("{E}uri: urn:example:codelist:status\nversion: '1'\ncodes: [A]\n"), "refused"),
            (format!("{E}id: urn:example:codelist:status\nversion: '1'\ntype: code-list\ncodes: [A]\n"), "refused"),
            (format!("{E}uri: urn:example:codelist:status\nversion: '1'\ntype: code-list\n"), "refused"),
            (
                format!("{E}uri: urn:example:codelist:status\nversion: '1'\ntype: code-list\ncodes: [A]\nentries: {{B: C}}\nallowedOutputs: [C]\n"),
                "refused",
            ),
            (format!("{E}uri: urn:example:codelist:map\nversion: '1'\ntype: mapping\nentries: {{B: C}}\n"), "refused"),
            (format!("{E}uri: urn:example:codelist:map\nversion: '1'\ntype: mapping\nentries: {{B: C}}\nallowed_outputs: [C]\n"), "refused"),
            (
                format!("{E}uri: urn:example:codelist:map\nversion: '1'\ntype: mapping\nentries: {{'-B': C}}\nallowedOutputs: [C]\n"),
                "refused",
            ),
            (format!("{E}uri: urn:example:codelist:status\nversion: '1'\ntype: code-list\ncodes: [A, A]\n"), "refused"),
            (format!("{E}uri: urn:example:codelist:status\nversion: '1'\ntype: code-list\ncodes: [-A]\nsurprise: true\n"), "refused"),
        ];
        for (text, expected) in &cases {
            let (text, expected) = (text.as_str(), *expected);
            let reader = crate::codelist::read_codelist("codelists/case.yaml", text.as_bytes());
            let instance: Value =
                serde_json::to_value(serde_norway::from_str::<serde_norway::Value>(text).unwrap())
                    .unwrap();
            let schema_accepts = validator.is_valid(&instance);
            assert_eq!(reader.is_ok(), expected == "accepted", "reader: {text}");
            assert_eq!(schema_accepts, expected == "accepted", "schema: {text}");
        }
    }

    fn fixture_validator() -> jsonschema::JSONSchema {
        let document: Value =
            serde_json::from_str(&fixture_documents().unwrap()[FIXTURE_SCHEMA_FILE]).unwrap();
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&document)
            .expect("the fixture schema compiles")
    }

    #[test]
    fn the_fixture_schema_accepts_what_the_reader_accepts_and_refuses_what_it_refuses() {
        let validator = fixture_validator();
        let header = "apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1\nkind: EvidenceFixture\n";
        let complete: String = [
            "positive",
            "negative-false",
            "boundary-on",
            "missing-fact",
            "no-match",
            "ambiguous",
            "source-failure",
            "anti-reconstruction",
        ]
        .iter()
        .map(|id| format!("  - {{id: {id}}}\n"))
        .collect();
        let too_many: String = (0..257)
            .map(|n| format!("  - {{id: case-{n}}}\n"))
            .collect();
        let cases: Vec<(String, bool)> = vec![
            (format!("{header}synthetic_only: true\ncases:\n{complete}"), true),
            (format!("{header}synthetic_only: true\ncommon: {{observed_at: x}}\ncases:\n{complete}"), true),
            (format!("{header}cases:\n{complete}"), false),
            (format!("{header}synthetic_only: true\n"), false),
            (format!("{header}synthetic_only: true\ncases: []\n"), false),
            (format!("{header}synthetic_only: true\ncases:\n{too_many}"), false),
            (format!("{header}synthetic_only: true\ncases:\n  - {{id: Positive}}\n"), false),
            (format!("{header}synthetic_only: true\ncases:\n  - {{note: no id}}\n"), false),
            (
                format!("{header}synthetic_only: true\ncases:\n{complete}  - {{id: extra, declaredUnresolved: false}}\n"),
                false,
            ),
            (format!("synthetic_only: true\ncases:\n{complete}"), false),
        ];
        for (text, expected) in cases {
            let reader = crate::fixture::read_fixture("fixtures/case.yaml", text.as_bytes(), true);
            let instance: Value =
                serde_json::to_value(serde_norway::from_str::<serde_norway::Value>(&text).unwrap())
                    .unwrap();
            assert_eq!(reader.is_ok(), expected, "reader: {text}");
            assert_eq!(validator.is_valid(&instance), expected, "schema: {text}");
        }
    }

    #[test]
    fn committed_fixture_schema_matches_generated_bytes() {
        let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/generated/fixture")
            .join(FIXTURE_SCHEMA_FILE);
        assert_eq!(
            std::fs::read_to_string(committed).unwrap(),
            fixture_documents().unwrap()[FIXTURE_SCHEMA_FILE]
        );
    }

    #[test]
    fn committed_codelist_schema_matches_generated_bytes() {
        let generated = codelist_documents().unwrap();
        let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/generated/codelist")
            .join(CODELIST_SCHEMA_FILE);
        assert_eq!(
            std::fs::read_to_string(committed).unwrap(),
            generated[CODELIST_SCHEMA_FILE]
        );
    }
}
