// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schema for the Casework runtime configuration.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::{RuntimeConfig, RUNTIME_CONFIG_API_VERSION, RUNTIME_CONFIG_KIND};

pub const RUNTIME_CONFIG_SCHEMA_FILE: &str = "runtime.schema.json";
pub const RUNTIME_CONFIG_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/runtime/runtime.v1alpha1.schema.json";

pub fn runtime_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut derived = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    set_const(&mut derived, "apiVersion", RUNTIME_CONFIG_API_VERSION);
    set_const(&mut derived, "kind", RUNTIME_CONFIG_KIND);
    install_runtime_constraints(&mut derived);
    let mut object = match derived {
        Value::Object(object) => object,
        _ => Map::new(),
    };
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert(
        "$id".to_owned(),
        Value::String(RUNTIME_CONFIG_SCHEMA_ID.to_owned()),
    );
    object.insert(
        "title".to_owned(),
        Value::String("Registry Casework runtime configuration".to_owned()),
    );
    let mut rendered = serde_json::to_string_pretty(&Value::Object(object))?;
    rendered.push('\n');
    Ok([(RUNTIME_CONFIG_SCHEMA_FILE, rendered)].into())
}

fn install_runtime_constraints(schema: &mut Value) {
    for (definition, property) in [
        ("RuntimePackageConfig", "root"),
        ("FileSecretProviderConfig", "root"),
        ("AuditConfig", "path"),
    ] {
        set_definition_property(
            schema,
            definition,
            property,
            "pattern",
            Value::String("^/".to_owned()),
        );
    }
    for (definition, property) in [
        ("DatabaseConfig", "runtimeUrlRef"),
        ("DatabaseConfig", "migrationUrlRef"),
        ("DatabaseConfig", "trustedRootCertificateRef"),
        ("AuditConfig", "hashKeyRef"),
        ("BregBinding", "clientIdRef"),
        ("BregBinding", "clientAssertionKeyRef"),
        ("BregBinding", "webhookSecretRef"),
        ("BregBinding", "trustedRootCertificatesRef"),
    ] {
        set_definition_property(
            schema,
            definition,
            property,
            "pattern",
            Value::String("^secret:(?:env|file)/".to_owned()),
        );
    }
    if let Some(providers) = schema
        .get_mut("$defs")
        .and_then(|definitions| definitions.get_mut("SecretProvidersConfig"))
        .and_then(Value::as_object_mut)
    {
        providers.insert(
            "anyOf".to_owned(),
            serde_json::json!([
                {"required": ["file"], "properties": {"file": {"$ref": "#/$defs/FileSecretProviderConfig"}}},
                {"required": ["environment"], "properties": {"environment": {"$ref": "#/$defs/EnvironmentSecretProviderConfig"}}}
            ]),
        );
    }
    if let Some(sources) = schema
        .get_mut("properties")
        .and_then(|properties| properties.get_mut("sources"))
        .and_then(Value::as_object_mut)
    {
        sources.insert(
            "propertyNames".to_owned(),
            serde_json::json!({"minLength": 1}),
        );
    }
}

fn set_definition_property(
    schema: &mut Value,
    definition: &str,
    property: &str,
    keyword: &str,
    value: Value,
) {
    if let Some(member) = schema
        .get_mut("$defs")
        .and_then(|definitions| definitions.get_mut(definition))
        .and_then(|definition| definition.get_mut("properties"))
        .and_then(|properties| properties.get_mut(property))
        .and_then(Value::as_object_mut)
    {
        member.insert(keyword.to_owned(), value);
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

    #[test]
    fn runtime_schema_is_deterministic_and_versioned() {
        let first = runtime_documents().unwrap();
        let second = runtime_documents().unwrap();
        assert_eq!(first, second);
        let document: Value = serde_json::from_str(&first[RUNTIME_CONFIG_SCHEMA_FILE]).unwrap();
        assert_eq!(document["$id"], RUNTIME_CONFIG_SCHEMA_ID);
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            RUNTIME_CONFIG_API_VERSION
        );
        assert_eq!(document["properties"]["kind"]["const"], RUNTIME_CONFIG_KIND);
        assert_eq!(
            document["$defs"]["RuntimePackageConfig"]["properties"]["root"]["pattern"],
            "^/"
        );
        assert_eq!(
            document["$defs"]["SecretProvidersConfig"]["anyOf"],
            serde_json::json!([
                {"required": ["file"], "properties": {"file": {"$ref": "#/$defs/FileSecretProviderConfig"}}},
                {"required": ["environment"], "properties": {"environment": {"$ref": "#/$defs/EnvironmentSecretProviderConfig"}}}
            ])
        );
    }

    #[test]
    fn committed_runtime_schema_matches_generated_bytes() {
        let generated = runtime_documents().unwrap();
        let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/generated/runtime")
            .join(RUNTIME_CONFIG_SCHEMA_FILE);
        assert_eq!(
            std::fs::read_to_string(committed).unwrap(),
            generated[RUNTIME_CONFIG_SCHEMA_FILE]
        );
    }
}
