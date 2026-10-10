// SPDX-License-Identifier: Apache-2.0
//! The schemas the shared types and the documented recipes emit, so a
//! format's schema states the same rules the reader enforces.

#![cfg(feature = "schema")]

use registry_platform_yaml::{
    shape_union, tagged_union, BoundedU32, BoundedU64, DataLiteral, Digest, ExternalId, LocalId,
    ProjectIdentity, UniqueIdList, UniqueList, Url,
};
use schemars::{schema_for, JsonSchema};
use serde::Deserialize;
use serde_json::{json, Value};

fn schema<T: JsonSchema>() -> Value {
    serde_json::to_value(schema_for!(T)).unwrap()
}

/// The schema of `name`, following a `$ref` into `$defs`.
fn property(schema: &Value, name: &str) -> Value {
    let property = &schema["properties"][name];
    match property["$ref"].as_str() {
        Some(reference) => {
            let definition = reference.trim_start_matches("#/$defs/");
            schema["$defs"][definition].clone()
        }
        None => property.clone(),
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
struct Limits {
    retention_days: BoundedU32<1, 36500>,
    maximum_request_bytes: BoundedU64<1, 1048576>,
    scopes: UniqueList<String>,
    steps: UniqueIdList<Step>,
    id: LocalId,
    issuer_id: ExternalId,
    digest: Digest,
    url: Url,
    value: DataLiteral,
}

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct Step {
    id: LocalId,
}

impl registry_platform_yaml::Identified for Step {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

#[test]
fn cfg_qty_4_bounded_integers_state_both_bounds() {
    let schema = schema::<Limits>();
    assert_eq!(
        property(&schema, "retentionDays"),
        json!({"type": "integer", "format": "uint32", "minimum": 1, "maximum": 36500})
    );
    assert_eq!(
        property(&schema, "maximumRequestBytes"),
        json!({"type": "integer", "format": "uint64", "minimum": 1, "maximum": 1048576})
    );
}

#[test]
fn cfg_id_6_a_set_declares_unique_items() {
    let schema = schema::<Limits>();
    assert_eq!(
        property(&schema, "scopes"),
        json!({"type": "array", "items": {"type": "string"}, "uniqueItems": true})
    );
    // Items with an `id` are unique by `id`, which a schema cannot state;
    // the reader enforces it.
    let steps = property(&schema, "steps");
    assert_eq!(steps["type"], "array");
    assert!(steps.get("uniqueItems").is_none());
}

#[test]
fn cfg_id_1_identifier_and_value_types_state_their_grammar() {
    let schema = schema::<Limits>();
    assert_eq!(
        property(&schema, "id")["pattern"],
        "^[a-z][a-z0-9_-]{0,63}$"
    );
    let issuer = property(&schema, "issuerId");
    assert_eq!(issuer["minLength"], 1);
    assert_eq!(issuer["maxLength"], 512);
    assert_eq!(
        property(&schema, "digest")["pattern"],
        "^sha256:[0-9a-f]{64}$"
    );
    let url = property(&schema, "url");
    assert_eq!(url["format"], "uri");
    assert_eq!(url["maxLength"], 2048);
    assert_eq!(
        property(&schema, "value")["type"],
        json!(["null", "boolean", "number", "string"])
    );
}

#[test]
fn cfg_val_7_the_url_pattern_and_the_reader_refuse_the_same_characters() {
    let schema = schema::<Limits>();
    let url = property(&schema, "url");
    let pattern = regex::Regex::new(url["pattern"].as_str().unwrap()).unwrap();
    // Every whitespace and control character is below U+10000; the three
    // above it stand for the rest.
    let characters = (char::MIN..='\u{FFFF}').chain(['\u{10000}', '\u{E0001}', char::MAX]);
    for character in characters {
        let code = u32::from(character);
        // After the authority the reader refuses a character only for being
        // whitespace or a control character, so the two agree on every one.
        let text = format!("https://a.example/x{character}y");
        assert_eq!(
            pattern.is_match(&text),
            Url::new(text.as_str()).is_ok(),
            "U+{code:04X} in the path"
        );
        if character.is_whitespace() || character.is_control() {
            for (place, text) in [
                ("before the scheme", format!("{character}https://a.example")),
                ("in the scheme", format!("ht{character}tps://a.example")),
                ("in the host", format!("https://a{character}.example")),
                ("in the query", format!("https://a.example?x={character}")),
                ("in the fragment", format!("https://a.example#x{character}")),
                ("at the end", format!("https://a.example{character}")),
            ] {
                assert!(!pattern.is_match(&text), "U+{code:04X} {place}");
                assert!(Url::new(text).is_err(), "U+{code:04X} {place}");
            }
        }
    }
}

#[test]
fn cfg_id_1_the_project_identity_is_closed() {
    let schema = schema::<ProjectIdentity>();
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], json!(["id", "version"]));
}

#[derive(Deserialize, JsonSchema)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
#[schemars(!remote, tag = "type")]
#[allow(dead_code)]
enum Source {
    Http { base_url: Url },
    None {},
}
tagged_union!(Source);

#[test]
fn cfg_schema_8_the_tagged_union_recipe_describes_the_tag() {
    let schema = schema::<Source>();
    let variants = schema["oneOf"].as_array().expect("one schema per variant");
    let tags: Vec<&Value> = variants
        .iter()
        .map(|variant| &variant["properties"]["type"])
        .collect();
    assert_eq!(
        tags,
        [
            &json!({"type": "string", "const": "http"}),
            &json!({"type": "string", "const": "none"}),
        ]
    );
    assert!(variants[0]["properties"].get("baseUrl").is_some());
    assert_eq!(variants[0]["required"], json!(["type", "baseUrl"]));
}

#[derive(Debug, JsonSchema)]
#[schemars(untagged)]
#[allow(dead_code)]
enum Scopes {
    One(String),
    Many(Vec<String>),
}
shape_union!(Scopes { scalar => One, list => Many });

#[test]
fn cfg_schema_8_the_shape_union_recipe_describes_each_shape() {
    let schema = schema::<Scopes>();
    assert_eq!(
        schema["anyOf"],
        json!([
            {"type": "string"},
            {"type": "array", "items": {"type": "string"}},
        ])
    );
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
struct Package {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/project"))]
    #[schemars(flatten)]
    project: ProjectIdentity,
    title: String,
}

#[test]
fn cfg_schema_8_the_shared_block_recipe_places_the_members_beside_the_host() {
    let schema = schema::<Package>();
    let properties: Vec<&String> = schema["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .collect();
    assert_eq!(properties, ["id", "title", "version"]);
    assert_eq!(schema["additionalProperties"], false);
    let mut required: Vec<&str> = schema["required"]
        .as_array()
        .expect("required")
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    required.sort_unstable();
    assert_eq!(required, ["id", "title", "version"]);
}
