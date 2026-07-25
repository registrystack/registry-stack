// SPDX-License-Identifier: Apache-2.0
//! Reproducible Draft 2020-12 schema for the complete Notary runtime config.

#![allow(
    dead_code,
    reason = "schema adapter types are compile-time descriptions and are never constructed"
)]

use std::borrow::Cow;

use registry_platform_authcommon::CredentialFingerprintProvider;
use schemars::{generate::SchemaSettings, json_schema, JsonSchema, Schema, SchemaGenerator};
use serde_json::{json, Value};

use super::{SigningKeyProviderConfig, SigningKeyStatus, StandaloneRegistryNotaryConfig};

/// Stable identifier for the product-owned Notary runtime configuration schema.
pub const CONFIG_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/registry-notary/registry-notary.config.schema.json";

/// Schema-only contract for values parsed by `humantime_serde`.
pub(crate) struct HumantimeDurationSchema;

impl JsonSchema for HumantimeDurationSchema {
    fn schema_name() -> Cow<'static, str> {
        "HumantimeDuration".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A humantime duration string. The runtime parser remains authoritative for its complete grammar.",
            "type": "string"
        })
    }
}

/// Schema-only contract for YAML socket addresses parsed by `SocketAddr`.
pub(crate) struct SocketAddrSchema;

impl JsonSchema for SocketAddrSchema {
    fn schema_name() -> Cow<'static, str> {
        "SocketAddr".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A Rust SocketAddr string. The runtime parser remains authoritative for address and port validity.",
            "type": "string"
        })
    }
}

/// Schema-only contract for `IpNet` CIDR values.
pub(crate) struct IpNetSchema;

impl JsonSchema for IpNetSchema {
    fn schema_name() -> Cow<'static, str> {
        "IpNet".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "An IP network CIDR string. The runtime parser remains authoritative for address and prefix validity.",
            "type": "string"
        })
    }
}

pub(crate) struct CredentialFingerprintSchema;

impl JsonSchema for CredentialFingerprintSchema {
    fn schema_name() -> Cow<'static, str> {
        "CredentialFingerprintRef".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        // `CredentialFingerprintRef` has a custom deserializer. It accepts
        // either provider together with zero, one, or both optional references;
        // doctor/runtime validation decides whether the selected provider has a
        // usable, non-ambiguous reference. Keep that division of responsibility
        // instead of making the schema stricter than deserialization.
        json_schema!({
            "type": "object",
            "additionalProperties": false,
            "required": ["provider"],
            "properties": {
                "provider": string_enum(CredentialFingerprintProvider::ALL.iter().map(|provider| provider.as_str())),
                "name": { "type": ["string", "null"] },
                "path": { "type": ["string", "null"] }
            }
        })
    }
}

pub(crate) struct SigningKeyProviderSchema;

impl JsonSchema for SigningKeyProviderSchema {
    fn schema_name() -> Cow<'static, str> {
        "SigningKeyProviderSchema".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        string_enum(
            SigningKeyProviderConfig::ALL
                .iter()
                .map(|provider| provider.as_str()),
        )
    }
}

pub(crate) struct SigningKeyStatusSchema;

impl JsonSchema for SigningKeyStatusSchema {
    fn schema_name() -> Cow<'static, str> {
        "SigningKeyStatusSchema".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        string_enum(SigningKeyStatus::ALL.iter().map(|status| status.as_str()))
    }
}

fn string_enum(labels: impl Iterator<Item = &'static str>) -> Schema {
    json!({
        "type": "string",
        "enum": labels.collect::<Vec<_>>()
    })
    .try_into()
    .expect("a JSON object is always a valid JSON Schema")
}

/// Schema-only representation of the string-only consultation-input deserializer.
pub(crate) struct RelayConsultationInputSchema;

impl JsonSchema for RelayConsultationInputSchema {
    fn schema_name() -> Cow<'static, str> {
        "RelayConsultationInput".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A supported consultation input path. The runtime parser remains authoritative for exact stable-name bounds.",
            "type": "string",
            "minLength": 1
        })
    }
}

/// Generate the deserialization contract for [`StandaloneRegistryNotaryConfig`].
#[must_use]
pub fn document() -> Value {
    let schema = SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<StandaloneRegistryNotaryConfig>();
    let mut value = serde_json::to_value(schema).expect("JSON Schema serializes to JSON");
    let root = value.as_object_mut().expect("root schema is an object");
    root.insert(
        "$id".to_string(),
        Value::String(CONFIG_SCHEMA_ID.to_string()),
    );
    root.insert(
        "title".to_string(),
        Value::String("Registry Notary config".to_string()),
    );
    value
}

/// Serialize the generated schema deterministically with exactly one trailing LF.
#[must_use]
pub fn document_json() -> String {
    let mut output = serde_json::to_string_pretty(&document()).expect("JSON Schema serializes");
    output.push('\n');
    output
}
