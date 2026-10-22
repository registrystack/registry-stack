// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schema for the Casework project, `casework.yaml`, and for
//! the offline test files beside it: review fixtures and holiday sets.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::{
    CaseworkFixture, CaseworkHolidaySet, CaseworkProject, CASEWORK_API_VERSION,
    CASEWORK_FIXTURE_API_VERSION, CASEWORK_FIXTURE_KIND, CASEWORK_HOLIDAY_SET_API_VERSION,
    CASEWORK_HOLIDAY_SET_KIND, CASEWORK_KIND,
};

pub const PROJECT_SCHEMA_FILE: &str = "project.schema.json";
pub const PROJECT_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/project/project.v1alpha1.schema.json";
pub const FIXTURE_SCHEMA_FILE: &str = "fixture/fixture.schema.json";
pub const FIXTURE_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/fixture/fixture.v1alpha1.schema.json";
pub const HOLIDAY_SET_SCHEMA_FILE: &str = "holiday-set/holiday-set.schema.json";
pub const HOLIDAY_SET_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/holiday-set/holiday-set.v1alpha1.schema.json";

/// The committed schema documents, by file name.
pub fn project_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let rendered = render(
        schemars::schema_for!(CaseworkProject),
        CASEWORK_API_VERSION,
        CASEWORK_KIND,
        PROJECT_SCHEMA_ID,
        "Registry Casework project",
    )?;
    Ok([(PROJECT_SCHEMA_FILE, rendered)].into())
}

/// The committed schema documents of the offline test files, by path below
/// `products/casework/generated`.
pub fn offline_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    Ok([
        (
            FIXTURE_SCHEMA_FILE,
            render(
                schemars::schema_for!(CaseworkFixture),
                CASEWORK_FIXTURE_API_VERSION,
                CASEWORK_FIXTURE_KIND,
                FIXTURE_SCHEMA_ID,
                "Registry Casework synthetic review fixture",
            )?,
        ),
        (
            HOLIDAY_SET_SCHEMA_FILE,
            render(
                schemars::schema_for!(CaseworkHolidaySet),
                CASEWORK_HOLIDAY_SET_API_VERSION,
                CASEWORK_HOLIDAY_SET_KIND,
                HOLIDAY_SET_SCHEMA_ID,
                "Registry Casework holiday set",
            )?,
        ),
    ]
    .into())
}

/// One committed schema document: the derived schema with `null` refused,
/// each stated zero minimum kept, identifier-keyed maps typed, the envelope
/// pinned to `api_version` and `kind`, and the `$id` and title set.
pub fn render(
    schema: schemars::Schema,
    api_version: &str,
    kind: &str,
    id: &str,
    title: &str,
) -> Result<String, serde_json::Error> {
    let mut derived = serde_json::to_value(schema)?;
    refuse_null(&mut derived);
    state_zero_minimum(&mut derived);
    type_identifier_keyed_maps(&mut derived)?;
    set_const(&mut derived, "apiVersion", api_version);
    set_const(&mut derived, "kind", kind);
    let mut object = match derived {
        Value::Object(object) => object,
        _ => Map::new(),
    };
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert("$id".to_owned(), Value::String(id.to_owned()));
    object.insert("title".to_owned(), Value::String(title.to_owned()));
    let mut rendered = serde_json::to_string_pretty(&Value::Object(object))?;
    rendered.push('\n');
    Ok(rendered)
}

/// The reader refuses `null` in every member (CFG-EMPTY-1), so an optional
/// member is written by leaving it out: drop the `null` schemars adds to an
/// `Option` and the `default: null` it declares for one.
pub fn refuse_null(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            if object.get("default") == Some(&Value::Null) {
                object.remove("default");
            }
            if let Some(Value::Array(types)) = object.get_mut("type") {
                types.retain(|kind| kind != "null");
                if let [only] = types.as_slice() {
                    let only = only.clone();
                    object.insert("type".to_owned(), only);
                }
            }
            if let Some(Value::Array(branches)) = object.get_mut("anyOf") {
                branches.retain(|branch| branch.get("type") != Some(&Value::from("null")));
                if let [only] = branches.as_slice() {
                    let only = only.clone();
                    object.remove("anyOf");
                    if let Value::Object(only) = only {
                        object.extend(only);
                    }
                }
            }
            for member in object.values_mut() {
                refuse_null(member);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(refuse_null),
        _ => {}
    }
}

/// A bounded whole number whose least value is zero states `minimum: 0`
/// beside the unsigned `format` schemars adds, which reads as the format's
/// implicit bound rather than a stated one (CFG-QTY-4). Both bounds are
/// stated, so the format says nothing more and is dropped.
fn state_zero_minimum(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            let unsigned = object
                .get("format")
                .and_then(Value::as_str)
                .is_some_and(|format| format.starts_with("uint"));
            if unsigned
                && object.get("minimum") == Some(&Value::from(0))
                && object.contains_key("maximum")
            {
                object.remove("format");
            }
            object.values_mut().for_each(state_zero_minimum);
        }
        Value::Array(items) => items.iter_mut().for_each(state_zero_minimum),
        _ => {}
    }
}

/// Type every map keyed by a shared identifier type and add the identifier
/// definitions those maps then reference.
pub fn type_identifier_keyed_maps(schema: &mut Value) -> Result<(), serde_json::Error> {
    // A type used only as a map key is inlined as a pattern, so the
    // definitions come from the types rather than from `$defs`.
    let definitions = [
        ("LocalId", definition::<registry_platform_yaml::LocalId>()?),
        (
            "ExternalId",
            definition::<registry_platform_yaml::ExternalId>()?,
        ),
    ];
    let identifiers = definitions
        .iter()
        .filter_map(|(name, definition)| {
            let pattern = definition.get("pattern")?.as_str()?.to_owned();
            Some((pattern, *name))
        })
        .collect::<BTreeMap<_, _>>();
    type_map_keys(schema, &identifiers);
    for (name, definition) in definitions {
        let pointer = format!("#/$defs/{name}");
        if references(schema, &pointer) {
            if let Some(Value::Object(defs)) = schema.get_mut("$defs") {
                defs.entry(name).or_insert(definition);
            }
        }
    }
    Ok(())
}

/// Schemars writes a map keyed by an identifier type as `patternProperties`
/// under the identifier's pattern, which drops its other bounds. State the
/// key as the identifier itself (CFG-SCHEMA-4, CFG-ID-1):
/// `propertyNames: {$ref: #/$defs/<identifier>}` and
/// `additionalProperties: <value schema>`.
fn type_map_keys(schema: &mut Value, identifiers: &BTreeMap<String, &str>) {
    match schema {
        Value::Object(object) => {
            let keyed = match object.get("patternProperties") {
                Some(Value::Object(patterns)) if patterns.len() == 1 => {
                    patterns.iter().next().and_then(|(pattern, value)| {
                        identifiers.get(pattern).map(|name| (*name, value.clone()))
                    })
                }
                _ => None,
            };
            if let Some((name, value)) = keyed {
                object.remove("patternProperties");
                object.insert(
                    "propertyNames".to_owned(),
                    serde_json::json!({"$ref": format!("#/$defs/{name}")}),
                );
                object.insert("additionalProperties".to_owned(), value);
            }
            for member in object.values_mut() {
                type_map_keys(member, identifiers);
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| type_map_keys(item, identifiers)),
        _ => {}
    }
}

/// The definition of a shared type, as `$defs` holds it.
fn definition<T: schemars::JsonSchema>() -> Result<Value, serde_json::Error> {
    serde_json::to_value(T::json_schema(&mut schemars::SchemaGenerator::default()))
}

/// Whether any `$ref` in `schema` is `pointer`.
fn references(schema: &Value, pointer: &str) -> bool {
    match schema {
        Value::Object(object) => {
            object.get("$ref").and_then(Value::as_str) == Some(pointer)
                || object.values().any(|member| references(member, pointer))
        }
        Value::Array(items) => items.iter().any(|item| references(item, pointer)),
        _ => false,
    }
}

fn set_const(schema: &mut Value, property: &str, expected: &str) {
    if let Some(member) = schema
        .get_mut("properties")
        .and_then(|properties| properties.get_mut(property))
        .and_then(Value::as_object_mut)
    {
        member.insert("const".to_owned(), Value::String(expected.to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiled(document: &Value) -> jsonschema::JSONSchema {
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(document)
            .expect("the project schema compiles")
    }

    #[test]
    fn project_schema_publishes_only_canonical_review_model() {
        let documents = project_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[PROJECT_SCHEMA_FILE]).unwrap();
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            CASEWORK_API_VERSION
        );
        for property in [
            "reviewPolicies",
            "trustedProducers",
            "contextProviders",
            "teams",
        ] {
            assert!(document["properties"].get(property).is_some());
        }
        for removed in ["sources", "reviewKinds", "reviewProducers"] {
            assert!(document["properties"].get(removed).is_none());
        }
        assert!(!documents[PROJECT_SCHEMA_FILE].contains("itemKinds"));
    }

    #[test]
    fn provider_description_is_a_path_while_labels_are_display_text() {
        let documents = project_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[PROJECT_SCHEMA_FILE]).unwrap();
        let provider_description = &document["properties"]["contextProviders"]
            ["additionalProperties"]["properties"]["description"];
        assert_eq!(provider_description["type"], "string");
        assert!(provider_description.get("$ref").is_none());
        assert_eq!(
            document["properties"]["queues"]["additionalProperties"]["properties"]["label"]["$ref"],
            "#/$defs/DisplayText"
        );
    }

    #[test]
    fn project_schema_accepts_the_stage_clock_defaults_the_reader_accepts() {
        let documents = project_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[PROJECT_SCHEMA_FILE]).unwrap();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/examples/multi-stage-routing-clocks/casework.yaml");
        let authored = std::fs::read_to_string(&path).unwrap();
        let omitted = authored.replace(
            "    atRisk: {before: {workingDays: 1}}\n    reminders:\n      due-soon: {before: {workingDays: 1}}\n    steps:\n      - id: supervisor-at-deadline\n        because: The review deadline passed while the review remained active.\n        at: due\n        action: {reassign: {queue: overdue-review}}\n",
            "",
        );
        assert_ne!(omitted, authored);
        let decoded = crate::CaseworkProject::read(&path.display().to_string(), omitted.as_bytes())
            .expect("the project reader applies empty stage-clock defaults");
        assert!(compiled(&document).is_valid(&decoded.document.to_json_value()));
        let stage = &document["properties"]["clocks"]["additionalProperties"]["oneOf"][1];
        for optional in ["atRisk", "reminders", "steps"] {
            assert!(!stage["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|required| required == optional));
        }
    }

    #[test]
    fn project_schema_publishes_the_settling_negative_decision_default() {
        let documents = project_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[PROJECT_SCHEMA_FILE]).unwrap();
        let negative_decisions =
            &document["$defs"]["ReviewStagePolicy"]["properties"]["negativeDecisions"];
        assert_eq!(negative_decisions["default"], "settle");
        assert!(!document["$defs"]["ReviewStagePolicy"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|required| required == "negativeDecisions"));
    }

    #[test]
    fn context_contract_id_and_service_profile_keys_publish_the_reader_contract() {
        let documents = project_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[PROJECT_SCHEMA_FILE]).unwrap();
        let contract = &document["$defs"]["ReviewContextContract"]["properties"]["id"];
        assert_eq!(contract["$ref"], "#/$defs/ExternalId");
        assert_eq!(contract["maxLength"], 256);
        assert_eq!(contract["x-registry-maxBytes"], 256);
        assert_eq!(contract["pattern"], "\\S");
        assert!(contract["description"]
            .as_str()
            .unwrap()
            .contains("256 UTF-8 bytes"));

        let profiles = &document["properties"]["contextProviders"]["additionalProperties"]
            ["properties"]["serviceProfiles"];
        assert_eq!(profiles["propertyNames"]["$ref"], "#/$defs/LocalId");
        assert_eq!(profiles["additionalProperties"], false);
        assert_eq!(profiles["properties"].as_object().unwrap().len(), 4);

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/examples/canonical-review/casework.yaml");
        let authored = std::fs::read_to_string(&path).unwrap();
        let original_id =
            "urn:registry:breg:review-context:facility-registry:correct-address:facility-address-context";
        let unicode_boundary = authored.replace(original_id, &"é".repeat(128));
        let decoded =
            crate::CaseworkProject::read(&path.display().to_string(), unicode_boundary.as_bytes())
                .expect("the reader accepts an external id at exactly 256 UTF-8 bytes");
        assert!(compiled(&document).is_valid(&decoded.document.to_json_value()));

        let too_long = authored.replace(
            original_id,
            &"a".repeat(crate::MAXIMUM_CONTEXT_CONTRACT_ID_BYTES + 1),
        );
        assert_ne!(too_long, authored);
        let report = crate::CaseworkProject::read(&path.display().to_string(), too_long.as_bytes())
            .expect_err("the project reader enforces the context-contract id byte bound");
        assert!(report.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "casework.review-policy.context-contract"
                && diagnostic.path == "/reviewPolicies/facility-address-review/context/contract/id"
        }));

        let blank = authored.replace(original_id, "\"   \"");
        let report = crate::CaseworkProject::read(&path.display().to_string(), blank.as_bytes())
            .expect_err("the project reader rejects a blank context-contract id");
        assert!(report.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "casework.review-policy.context-contract"
                && diagnostic.path == "/reviewPolicies/facility-address-review/context/contract/id"
        }));

        let mut blank = decoded.document.to_json_value();
        blank["reviewPolicies"]["facility-address-review"]["context"]["contract"]["id"] =
            Value::from("   ");
        assert!(!compiled(&document).is_valid(&blank));

        let mut control = decoded.document.to_json_value();
        control["reviewPolicies"]["facility-address-review"]["context"]["contract"]["id"] =
            Value::from("external\u{1}id");
        assert!(!compiled(&document).is_valid(&control));
    }
}

#[cfg(test)]
mod policy_selection_tests {
    use crate::{ContentDigest, PolicySelection};
    use serde_json::json;

    #[test]
    fn policy_selection_schema_requires_the_complete_optional_pin() {
        let schema = serde_json::to_value(schemars::schema_for!(PolicySelection)).unwrap();
        let compiled = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        let digest = ContentDigest::for_bytes(b"policy");
        for value in [
            json!({"id":"review"}),
            json!({"id":"review", "version":"1", "digest":digest}),
        ] {
            assert!(compiled.is_valid(&value));
        }
        for value in [
            json!({"id":"review", "version":"1"}),
            json!({"id":"review", "digest":digest}),
            json!({"id":"review", "version":null}),
            json!({"id":"review", "version":"1", "digest":null}),
            json!({"id":"review", "other":true}),
        ] {
            assert!(!compiled.is_valid(&value), "invalid selector {value}");
        }
    }
}
