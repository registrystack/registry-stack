// SPDX-License-Identifier: Apache-2.0
//! Reproducible Draft 2020-12 schema for the complete Relay runtime config.

#![allow(
    dead_code,
    reason = "schema adapter types are compile-time descriptions and are never constructed"
)]

use std::borrow::Cow;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::time::Duration;

use schemars::{generate::SchemaSettings, json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use super::Config;

/// Stable identifier for the product-owned Relay runtime configuration schema.
pub const CONFIG_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/registry-relay/registry-relay.config.schema.json";

/// Schema-only deployment-waiver reference contract shared with posture.
pub(crate) struct DeploymentWaiverReferenceSchema;

impl JsonSchema for DeploymentWaiverReferenceSchema {
    fn schema_name() -> Cow<'static, str> {
        "DeploymentWaiverReference".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        registry_platform_ops::deployment_waiver_reference_schema_fragment()
            .try_into()
            .expect("the shared waiver-reference fragment is a valid JSON Schema")
    }
}

/// Schema-only structural deployment-waiver summary contract shared with posture.
pub(crate) struct DeploymentWaiverSummarySchema;

impl JsonSchema for DeploymentWaiverSummarySchema {
    fn schema_name() -> Cow<'static, str> {
        "DeploymentWaiverSummary".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        registry_platform_ops::deployment_waiver_summary_schema_fragment()
            .try_into()
            .expect("the shared waiver-summary fragment is a valid JSON Schema")
    }
}

const IPV4_SOCKET_PATTERN: &str = concat!(
    "^(?:",
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.",
    "){3}",
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]):",
    r"(?:0|[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
);
const IPV6_SOCKET_PATTERN: &str = concat!(
    r"^\[(?:",
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|",
    r"(?:[0-9A-Fa-f]{1,4}:){1,7}:|",
    r"(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|",
    r"(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|",
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|",
    r"(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|",
    r"(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|",
    r"[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})|",
    r":(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)",
    r")\]:",
    r"(?:0|[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
);

const DURATION_PATTERN: &str =
    r"^[0-9]{1,10}(?:ns|us|ms|s|m|h|d|w)(?: [0-9]{1,10}(?:ns|us|ms|s|m|h|d|w))*$";
const MAX_DURATION_TEXT_BYTES: usize = 255;

/// Schema-only string contract for YAML listener socket addresses.
pub(crate) struct SocketAddrSchema;

impl JsonSchema for SocketAddrSchema {
    fn schema_name() -> Cow<'static, str> {
        "SocketAddr".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Canonical dotted-decimal IPv4 or bracketed IPv6 plus a decimal port from 0 through 65535",
            "oneOf": [
                { "type": "string", "pattern": IPV4_SOCKET_PATTERN },
                { "type": "string", "pattern": IPV6_SOCKET_PATTERN }
            ]
        })
    }
}

/// Schema-only string contract for the stable Relay humantime subset.
pub(crate) struct HumantimeDurationSchema;

impl JsonSchema for HumantimeDurationSchema {
    fn schema_name() -> Cow<'static, str> {
        "HumantimeDuration".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "One or more non-negative integer duration components separated by one ASCII space; supported units are ns, us, ms, s, m, h, d, and w",
            "type": "string",
            "pattern": DURATION_PATTERN,
            "maxLength": MAX_DURATION_TEXT_BYTES
        })
    }
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeploymentProfileSchema {
    Local,
    HostedLab,
    Production,
    EvidenceGrade,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuditWritePolicySchema {
    AvailabilityFirst,
    FailClosed,
    FailClosedRouteFamilies,
}

#[derive(JsonSchema)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CredentialFingerprintSchema {
    Env {
        #[schemars(with = "RuntimeEnvironmentNameSchema")]
        name: RuntimeEnvironmentNameSchema,
    },
    File {
        path: PathBuf,
    },
}

#[derive(JsonSchema)]
#[serde(transparent)]
pub(crate) struct AuditPseudonymKeyIdSchema(
    #[schemars(pattern(r"^[a-z0-9][a-z0-9._-]{0,63}$"))] String,
);

#[derive(JsonSchema)]
#[serde(transparent)]
pub(crate) struct RuntimeEnvironmentNameSchema(#[schemars(pattern(r"^[^=\x00]+$"))] String);

#[derive(JsonSchema)]
#[serde(transparent)]
pub(crate) struct AuditHashSecretEnvironmentNameSchema(
    #[schemars(pattern(
        r"^[^=\x00]*[^=\x00\x09-\x0D\x20\x85\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000][^=\x00]*$"
    ))]
    String,
);

#[derive(JsonSchema)]
#[serde(transparent)]
pub(crate) struct PostgresEnvironmentNameSchema(
    #[schemars(pattern(r"^[A-Za-z_][A-Za-z0-9_]*$"))] String,
);

pub(super) fn deserialize_socket_addr<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    parse_socket_addr(&value).map_err(serde::de::Error::custom)
}

pub(super) fn deserialize_optional_socket_addr<'de, D>(
    deserializer: D,
) -> Result<Option<SocketAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|value| parse_socket_addr(&value))
        .transpose()
        .map_err(serde::de::Error::custom)
}

fn parse_socket_addr(value: &str) -> Result<SocketAddr, &'static str> {
    let parsed = value
        .parse::<SocketAddr>()
        .map_err(|_| "listener address must use portable socket syntax")?;
    let port = match parsed {
        SocketAddr::V4(address) => portable_ipv4_port(value, &address)?,
        SocketAddr::V6(address) => portable_ipv6_port(value, &address)?,
    };
    if port == parsed.port().to_string() {
        Ok(parsed)
    } else {
        Err("listener port must use canonical decimal syntax")
    }
}

fn portable_ipv4_port<'a>(value: &'a str, address: &SocketAddrV4) -> Result<&'a str, &'static str> {
    let (host, port) = value
        .split_once(':')
        .ok_or("IPv4 listener address must include a port")?;
    if host == address.ip().to_string() {
        Ok(port)
    } else {
        Err("IPv4 listener address must use canonical dotted-decimal syntax")
    }
}

fn portable_ipv6_port<'a>(
    value: &'a str,
    _address: &SocketAddrV6,
) -> Result<&'a str, &'static str> {
    let (host, port) = value
        .strip_prefix('[')
        .and_then(|value| value.split_once("]:"))
        .ok_or("IPv6 listener address must be bracketed and include a port")?;
    if !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b':')
    {
        Ok(port)
    } else {
        Err("IPv6 listener address must use hexadecimal address syntax without a zone id")
    }
}

pub(super) fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if !is_portable_duration(&value) {
        return Err(serde::de::Error::custom(
            "duration must use the portable Relay humantime syntax",
        ));
    }
    humantime_serde::re::humantime::parse_duration(&value).map_err(serde::de::Error::custom)
}

fn is_portable_duration(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DURATION_TEXT_BYTES
        && value.split(' ').all(|component| {
            let digit_count = component.bytes().take_while(u8::is_ascii_digit).count();
            (1..=10).contains(&digit_count)
                && matches!(
                    &component[digit_count..],
                    "ns" | "us" | "ms" | "s" | "m" | "h" | "d" | "w"
                )
        })
}

fn add_integer_bounds(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(add_integer_bounds),
        Value::Object(object) => {
            add_integer_bounds_to_object(object);
            object.values_mut().for_each(add_integer_bounds);
        }
        _ => {}
    }
}

fn add_integer_bounds_to_object(object: &mut Map<String, Value>) {
    if !has_integer_type(object.get("type")) {
        return;
    }
    let Some(format) = object.get("format").and_then(Value::as_str) else {
        return;
    };
    let Some((minimum, maximum)) = integer_bounds(format) else {
        return;
    };
    object.entry("minimum").or_insert(minimum);
    object.entry("maximum").or_insert(maximum);
}

fn has_integer_type(schema_type: Option<&Value>) -> bool {
    match schema_type {
        Some(Value::String(schema_type)) => schema_type == "integer",
        Some(Value::Array(schema_types)) => schema_types
            .iter()
            .any(|schema_type| schema_type.as_str() == Some("integer")),
        _ => false,
    }
}

fn integer_bounds(format: &str) -> Option<(Value, Value)> {
    let bounds = match format {
        "int8" => (i8::MIN.into(), i8::MAX.into()),
        "int16" => (i16::MIN.into(), i16::MAX.into()),
        "int32" => (i32::MIN.into(), i32::MAX.into()),
        "int64" => (i64::MIN.into(), i64::MAX.into()),
        "int" => ((isize::MIN as i64).into(), (isize::MAX as i64).into()),
        "uint8" => (0.into(), u8::MAX.into()),
        "uint16" => (0.into(), u16::MAX.into()),
        "uint32" => (0.into(), u32::MAX.into()),
        "uint64" => (0.into(), u64::MAX.into()),
        "uint" => (0.into(), (usize::MAX as u64).into()),
        _ => return None,
    };
    Some(bounds)
}

/// Generate the deserialization contract for [`Config`].
#[must_use]
pub fn document() -> Value {
    let schema = SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<Config>();
    let mut value = serde_json::to_value(schema).expect("JSON Schema serializes to JSON");
    let root = value.as_object_mut().expect("root schema is an object");
    root.insert(
        "$id".to_string(),
        Value::String(CONFIG_SCHEMA_ID.to_string()),
    );
    root.insert(
        "title".to_string(),
        Value::String("Registry Relay config".to_string()),
    );
    add_integer_bounds(&mut value);
    value
}

/// Serialize the generated schema deterministically with exactly one trailing LF.
#[must_use]
pub fn document_json() -> String {
    let mut output = serde_json::to_string_pretty(&document()).expect("JSON Schema serializes");
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use jsonschema::{Draft, JSONSchema};
    use schemars::schema_for;
    use serde_json::json;

    use super::*;

    #[derive(Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct NullableIntegerFixture {
        signed: Option<i64>,
        unsigned: Option<u32>,
    }

    #[test]
    fn integer_bound_postprocessor_handles_nullable_integer_type_arrays() {
        let mut schema =
            serde_json::to_value(schema_for!(NullableIntegerFixture)).expect("schema serializes");
        add_integer_bounds(&mut schema);

        assert_eq!(schema["properties"]["signed"]["minimum"], json!(i64::MIN));
        assert_eq!(schema["properties"]["signed"]["maximum"], json!(i64::MAX));
        assert_eq!(schema["properties"]["unsigned"]["minimum"], json!(0));
        assert_eq!(schema["properties"]["unsigned"]["maximum"], json!(u32::MAX));

        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .expect("nullable integer fixture schema compiles");
        for valid in [
            json!({"signed": i64::MIN, "unsigned": 0}),
            json!({"signed": i64::MAX, "unsigned": u32::MAX}),
            json!({"signed": null, "unsigned": null}),
        ] {
            assert!(compiled.is_valid(&valid));
            assert!(serde_json::from_value::<NullableIntegerFixture>(valid).is_ok());
        }
        for invalid in [
            json!({"signed": 9223372036854775808_u64, "unsigned": 0}),
            json!({"signed": 0, "unsigned": -1}),
            json!({"signed": 0, "unsigned": u64::from(u32::MAX) + 1}),
        ] {
            assert!(!compiled.is_valid(&invalid));
            assert!(serde_json::from_value::<NullableIntegerFixture>(invalid).is_err());
        }
    }
}
