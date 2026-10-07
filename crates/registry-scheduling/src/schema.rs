// SPDX-License-Identifier: Apache-2.0

//! Generated JSON Schema for the Scheduling runtime configuration.
//!
//! The schema is derived from the strict `RuntimeConfig` types, never written
//! by hand. Regenerate the committed document with:
//!
//! ```bash
//! cargo run -p registry-scheduling --features schema --example runtime-schema -- \
//!   --output products/scheduling/generated/runtime
//! ```
//!
//! The derived schema states the bounds `RuntimeConfig::check` enforces, so
//! a document an operator's editor accepts is one the runtime starts on
//! rather than one it refuses after the operator has already written it.

use std::collections::BTreeMap;

use serde_json::Value;

use registry_scheduling_core::{
    RUNTIME_SCHEMA_FILE, SCHEDULING_RUNTIME_API_VERSION, SCHEDULING_RUNTIME_KIND,
    SCHEDULING_RUNTIME_SCHEMA_ID,
};

use registry_platform_config::blocks::SECRET_PROVIDER_PATTERN;

use crate::config::RuntimeConfig;

pub fn runtime_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut derived = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    set_const(&mut derived, "apiVersion", SCHEDULING_RUNTIME_API_VERSION);
    set_const(&mut derived, "kind", SCHEDULING_RUNTIME_KIND);
    install_runtime_constraints(&mut derived);
    let mut object = match derived {
        Value::Object(object) => object,
        _ => unreachable!("schemars derives a schema object for RuntimeConfig"),
    };
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert(
        "$id".to_owned(),
        Value::String(SCHEDULING_RUNTIME_SCHEMA_ID.to_owned()),
    );
    object.insert(
        "title".to_owned(),
        Value::String("Registry Scheduling runtime configuration".to_owned()),
    );
    let mut rendered = serde_json::to_string_pretty(&Value::Object(object))?;
    rendered.push('\n');
    Ok([(RUNTIME_SCHEMA_FILE, rendered)].into())
}

/// State in the schema the bounds `RuntimeConfig::check` and
/// `validate_secret_references` enforce at load beyond the shared blocks,
/// which carry their own: the audit destination has the shape
/// `AuditConfig::destination` requires and its file is absolute with no `..`
/// segment, every Scheduling secret field is a secret reference, and a static
/// JWKS document names an enabled provider.
fn install_runtime_constraints(schema: &mut Value) {
    set_definition_property(
        schema,
        "AuditConfig",
        "path",
        "pattern",
        Value::String(registry_platform_audit::ABSOLUTE_AUDIT_PATH_PATTERN.to_owned()),
    );
    for (definition, property) in [
        ("ReminderDestinationConfig", "bearerTokenRef"),
        ("HookDestinationConfig", "hmacSha256KeyRef"),
    ] {
        set_definition_property(
            schema,
            definition,
            property,
            "pattern",
            Value::String(SECRET_PROVIDER_PATTERN.to_owned()),
        );
    }
    set_audit_destination_constraints(schema);
    if let Some(root) = schema.as_object_mut() {
        root.insert(
            "allOf".to_owned(),
            registry_platform_config::schema::jwks_document_provider_requirements(),
        );
    }
}

/// State the shape `AuditConfig::destination` requires: a `file`
/// destination, the default, names an absolute `path`, and `stdout` takes
/// none of the file-only settings. An explicit null reads as absent, as
/// serde reads it at load. The rotation and retention bounds are the
/// platform writer's.
fn set_audit_destination_constraints(schema: &mut Value) {
    set_definition_property(
        schema,
        "AuditConfig",
        "rotateBytes",
        "minimum",
        Value::from(registry_platform_audit::MIN_AUDIT_ROTATE_BYTES),
    );
    set_definition_property(
        schema,
        "AuditConfig",
        "rotateBytes",
        "maximum",
        Value::from(u32::MAX),
    );
    set_definition_property(
        schema,
        "AuditConfig",
        "retainDays",
        "minimum",
        Value::from(1),
    );
    set_definition_property(
        schema,
        "AuditConfig",
        "retainDays",
        "maximum",
        Value::from(registry_platform_audit::MAX_AUDIT_RETAIN_DAYS),
    );
    if let Some(audit) = schema
        .pointer_mut("/$defs/AuditConfig")
        .and_then(Value::as_object_mut)
    {
        audit.insert(
            "if".to_owned(),
            serde_json::json!({
                "required": ["destination"],
                "properties": {"destination": {"const": "stdout"}}
            }),
        );
        audit.insert(
            "then".to_owned(),
            serde_json::json!({
                "not": {"anyOf": [
                    {"required": ["path"], "properties": {"path": {"not": {"type": "null"}}}},
                    {"required": ["rotateBytes"], "properties": {"rotateBytes": {"not": {"type": "null"}}}},
                    {"required": ["retainDays"], "properties": {"retainDays": {"not": {"type": "null"}}}}
                ]}
            }),
        );
        audit.insert(
            "else".to_owned(),
            serde_json::json!({
                "required": ["path"],
                "properties": {"path": {"type": "string"}}
            }),
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
    use crate::config::{DestinationsConfig, RetentionConfig, MAX_HOOK_DESTINATIONS};

    #[test]
    fn runtime_schema_is_deterministic_and_versioned() {
        let first = runtime_documents().unwrap();
        let second = runtime_documents().unwrap();
        assert_eq!(first, second);
        let document: Value = serde_json::from_str(&first[RUNTIME_SCHEMA_FILE]).unwrap();
        assert_eq!(document["$id"], SCHEDULING_RUNTIME_SCHEMA_ID);
        assert_eq!(
            document["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(
            document["title"],
            "Registry Scheduling runtime configuration"
        );
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            SCHEDULING_RUNTIME_API_VERSION
        );
        assert_eq!(
            document["properties"]["kind"]["const"],
            SCHEDULING_RUNTIME_KIND
        );
    }

    #[test]
    fn the_schema_states_the_bounds_the_runtime_enforces() {
        let documents = runtime_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[RUNTIME_SCHEMA_FILE]).unwrap();
        for (definition, property) in [
            ("PackageConfig", "root"),
            ("FileSecretProviderConfig", "root"),
        ] {
            assert_eq!(
                document["$defs"][definition]["properties"][property]["pattern"], "^/",
                "{definition}.{property} must be absolute"
            );
        }
        assert_eq!(
            document["$defs"]["AuditConfig"]["properties"]["path"]["pattern"],
            registry_platform_audit::ABSOLUTE_AUDIT_PATH_PATTERN,
            "the audit path must be absolute with no `..` segment"
        );
        for property in [
            "runtimeUrlRef",
            "migrationUrlRef",
            "trustedRootCertificateRef",
        ] {
            assert_eq!(
                document["$defs"]["DatabaseConfig"]["properties"][property]["$ref"],
                "#/$defs/SecretReference",
                "DatabaseConfig.{property} must be a secret reference"
            );
        }
        for (definition, property) in [
            ("ReminderDestinationConfig", "bearerTokenRef"),
            ("HookDestinationConfig", "hmacSha256KeyRef"),
        ] {
            assert_eq!(
                document["$defs"][definition]["properties"][property]["pattern"],
                "^secret:(?:env|file)/",
                "{definition}.{property} must be a secret reference"
            );
        }
        assert_eq!(
            document["$defs"]["SecretProvidersConfig"]["anyOf"],
            serde_json::json!([
                {"required": ["file"], "properties": {"file": {"$ref": "#/$defs/FileSecretProviderConfig"}}},
                {"required": ["environment"], "properties": {"environment": {"$ref": "#/$defs/EnvironmentSecretProviderConfig"}}}
            ]),
            "at least one secret provider must be configured"
        );
        assert_eq!(
            document["$defs"]["JwksSource"]["oneOf"][2]["properties"]["documentRef"]["$ref"],
            "#/$defs/SecretReference"
        );
        // The shared blocks carry their own bounds into this schema.
        assert_eq!(
            document["$defs"]["AuditConfig"]["properties"]["hashKeyRef"]["$ref"],
            "#/$defs/SecretReference"
        );
        let assertion_issuers = &document["$defs"]["OidcConfig"]["properties"]["assertionIssuers"];
        assert_eq!(assertion_issuers["maxProperties"], 64);
        assert_eq!(assertion_issuers["propertyNames"]["maxLength"], 128);
        assert_eq!(assertion_issuers["additionalProperties"]["maxItems"], 16);
        assert_eq!(
            assertion_issuers["additionalProperties"]["items"]["maxLength"],
            512
        );
        assert_eq!(
            document["$defs"]["OidcConfig"]["properties"]["issuer"]["$ref"],
            "#/$defs/Url"
        );
        let audit = &document["$defs"]["AuditConfig"];
        assert_eq!(
            audit["properties"]["rotateBytes"]["minimum"],
            registry_platform_audit::MIN_AUDIT_ROTATE_BYTES
        );
        assert_eq!(
            audit["properties"]["retainDays"]["maximum"],
            registry_platform_audit::MAX_AUDIT_RETAIN_DAYS
        );
        assert_eq!(audit["if"]["properties"]["destination"]["const"], "stdout");
        assert_eq!(audit["else"]["required"], serde_json::json!(["path"]));
    }

    #[test]
    fn audit_schema_states_the_destination_rules_the_runtime_enforces() {
        let documents = runtime_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[RUNTIME_SCHEMA_FILE]).unwrap();
        let audit = serde_json::json!({
            "$defs": document["$defs"],
            "$ref": "#/$defs/AuditConfig"
        });
        let validator = jsonschema::JSONSchema::compile(&audit).unwrap();
        let key = "secret:env/AUDIT_HASH_KEY";
        for accepted in [
            serde_json::json!({"hashKeyRef": key, "path": "/var/lib/scheduling/audit.jsonl"}),
            serde_json::json!({"hashKeyRef": key, "destination": "file", "path": "/audit.jsonl",
                "rotateBytes": 1_048_576, "retainDays": 1}),
            serde_json::json!({"hashKeyRef": key, "destination": "stdout"}),
            // An explicit null reads as absent, as it does at load.
            serde_json::json!({"hashKeyRef": key, "destination": "stdout", "path": null}),
            serde_json::json!({"hashKeyRef": key, "destination": "stdout",
                "path": null, "rotateBytes": null, "retainDays": null}),
        ] {
            assert!(validator.is_valid(&accepted), "{accepted}");
        }
        for refused in [
            serde_json::json!({"hashKeyRef": key}),
            serde_json::json!({"hashKeyRef": key, "path": null}),
            serde_json::json!({"hashKeyRef": key, "path": "audit.jsonl"}),
            serde_json::json!({"hashKeyRef": key, "destination": "stdout", "path": "/audit.jsonl"}),
            serde_json::json!({"hashKeyRef": key, "destination": "stdout", "rotateBytes": 1_048_576}),
            serde_json::json!({"hashKeyRef": key, "destination": "stdout", "retainDays": 1}),
        ] {
            assert!(!validator.is_valid(&refused), "{refused}");
        }
    }

    #[test]
    fn the_schema_states_the_database_identity_grammar_the_runtime_enforces() {
        let documents = runtime_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[RUNTIME_SCHEMA_FILE]).unwrap();
        let validator =
            jsonschema::JSONSchema::compile(&document["properties"]["identity"]).unwrap();
        let with_id =
            |database_id: &str| validator.is_valid(&serde_json::json!({"databaseId": database_id}));
        for accepted in ["scheduling-production", "a", "two words", "caf\u{e9}"] {
            assert!(with_id(accepted), "{accepted:?} must be accepted");
        }
        for refused in [
            "",
            " ",
            " leading",
            "trailing ",
            "\u{a0}no-break",
            "ideographic\u{3000}",
            "line\u{2028}",
            "bell\u{7}inside",
            "next-line\u{85}inside",
            "tab\tinside",
        ] {
            assert!(!with_id(refused), "{refused:?} must be refused");
        }
    }

    /// Issue #1916: every retention period the schema accepts is one the
    /// runtime starts on, and every one it refuses is one the runtime refuses.
    #[test]
    fn the_schema_states_the_retention_bounds_the_runtime_enforces() {
        let documents = runtime_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[RUNTIME_SCHEMA_FILE]).unwrap();
        let retention = serde_json::json!({
            "$defs": document["$defs"],
            "$ref": "#/$defs/RetentionConfig"
        });
        let validator = jsonschema::JSONSchema::compile(&retention).unwrap();
        let periods = [0, 1, 7, 30, 31, 365, u16::MAX];
        for attempt_receipt_days in periods {
            for hook_payload_days in periods {
                let config = RetentionConfig {
                    attempt_receipt_days,
                    hook_payload_days,
                };
                let document = serde_json::json!({
                    "attemptReceiptDays": attempt_receipt_days,
                    "hookPayloadDays": hook_payload_days,
                });
                assert_eq!(
                    validator.is_valid(&document),
                    config.check().is_ok(),
                    "the schema and the runtime disagree on {document}"
                );
            }
        }
    }

    /// Issue #1928: every hook destination binding the schema accepts is one
    /// the runtime starts on, and every one it refuses is one the runtime
    /// refuses, at each bound's edge on both sides.
    #[test]
    fn the_schema_states_the_hook_destination_bounds_the_runtime_enforces() {
        let documents = runtime_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[RUNTIME_SCHEMA_FILE]).unwrap();
        let destinations = serde_json::json!({
            "$defs": document["$defs"],
            "$ref": "#/$defs/DestinationsConfig"
        });
        let validator = jsonschema::JSONSchema::compile(&destinations).unwrap();
        let binding = |timeout: u32, attempts: u8| {
            serde_json::json!({
                "url": "https://events.example.test/scheduling",
                "hmacSha256KeyRef": "secret:file/hook-key",
                "attemptTimeoutMilliseconds": timeout,
                "maximumAttempts": attempts
            })
        };
        let mut cases = Vec::new();
        for (timeout, accepted) in [
            (0, false),
            (99, false),
            (100, true),
            (5_000, true),
            (10_000, true),
            (10_001, false),
            (u32::MAX, false),
        ] {
            cases.push((
                serde_json::json!({"appointment-events": binding(timeout, 8)}),
                accepted,
            ));
        }
        for (attempts, accepted) in [
            (0, false),
            (1, true),
            (8, true),
            (20, true),
            (21, false),
            (u8::MAX, false),
        ] {
            cases.push((
                serde_json::json!({"appointment-events": binding(5_000, attempts)}),
                accepted,
            ));
        }
        for (id, accepted) in [
            ("a".to_owned(), true),
            ("appointment-events".to_owned(), true),
            ("events_2".to_owned(), true),
            ("a".repeat(64), true),
            ("a".repeat(65), false),
            (String::new(), false),
            ("Events".to_owned(), false),
            ("2events".to_owned(), false),
            ("-events".to_owned(), false),
            ("events.v1".to_owned(), false),
            ("events v1".to_owned(), false),
            ("\u{e9}v\u{e9}nements".to_owned(), false),
            ("events\n".to_owned(), false),
        ] {
            cases.push((serde_json::json!({id: binding(5_000, 8)}), accepted));
        }
        for (count, accepted) in [
            (0, true),
            (1, true),
            (MAX_HOOK_DESTINATIONS, true),
            (MAX_HOOK_DESTINATIONS + 1, false),
        ] {
            let hooks: serde_json::Map<String, Value> = (0..count)
                .map(|n| (format!("destination-{n}"), binding(5_000, 8)))
                .collect();
            cases.push((Value::Object(hooks), accepted));
        }
        for (hooks, accepted) in cases {
            let document = serde_json::json!({"hooks": hooks});
            let config: DestinationsConfig = serde_json::from_value(document.clone()).unwrap();
            assert_eq!(
                config.check().is_ok(),
                accepted,
                "the runtime decides {document} against its stated bounds"
            );
            assert_eq!(
                validator.is_valid(&document),
                accepted,
                "the schema and the runtime disagree on {document}"
            );
        }
    }

    #[test]
    fn committed_runtime_schema_matches_generated_bytes() {
        let generated = runtime_documents().unwrap();
        let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/scheduling/generated/runtime")
            .join(RUNTIME_SCHEMA_FILE);
        assert_eq!(
            std::fs::read_to_string(committed).unwrap(),
            generated[RUNTIME_SCHEMA_FILE]
        );
    }
}
