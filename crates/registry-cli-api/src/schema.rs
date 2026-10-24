// SPDX-License-Identifier: Apache-2.0
//! Generated schemas for Registry Stack CLI saved connections and check output.

use serde_json::Value;

pub const CONNECTIONS_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/platform/cli-connections/cli-connections.v1alpha1.schema.json";
pub const CONNECTIONS_SCHEMA_FILE: &str = "connections.schema.json";
pub const CONNECTION_CHECK_REPORT_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/platform/cli-connection-check-report/cli-connection-check-report.v1alpha1.schema.json";
pub const CONNECTION_CHECK_REPORT_SCHEMA_FILE: &str = "connection-check-report.schema.json";

/// Render the strict saved-connections schema from its owning Rust types.
pub fn document() -> Result<String, serde_json::Error> {
    let mut settings = schemars::generate::SchemaSettings::draft2020_12();
    settings.contract = schemars::generate::Contract::Deserialize;
    let schema = settings
        .into_generator()
        .into_root_schema_for::<crate::connection::Store>();
    let mut value = serde_json::to_value(schema)?;
    value["$id"] = Value::String(CONNECTIONS_SCHEMA_ID.to_owned());
    value["title"] = Value::String("Registry Stack CLI saved connections".to_owned());
    value["properties"]["apiVersion"] = serde_json::json!({
        "const": "id.registrystack.org/formats/platform/cli-connections/v1alpha1"
    });
    value["properties"]["kind"] = serde_json::json!({"const": "PlatformCliConnections"});
    Ok(serde_json::to_string_pretty(&value)? + "\n")
}

/// Render the shared machine-readable `connection check` report schema.
pub fn connection_check_report_document() -> Result<String, serde_json::Error> {
    let mut settings = schemars::generate::SchemaSettings::draft2020_12();
    settings.contract = schemars::generate::Contract::Serialize;
    let schema = settings
        .into_generator()
        .into_root_schema_for::<crate::PlatformCliConnectionCheckReport>();
    let mut value = serde_json::to_value(schema)?;
    value["$id"] = Value::String(CONNECTION_CHECK_REPORT_SCHEMA_ID.to_owned());
    value["title"] = Value::String("Registry Stack CLI connection check report".to_owned());
    value["properties"]["apiVersion"] = serde_json::json!({
        "const": crate::CONNECTION_CHECK_REPORT_API_VERSION
    });
    value["properties"]["kind"] = serde_json::json!({
        "const": crate::CONNECTION_CHECK_REPORT_KIND
    });
    value["properties"]["command"] = serde_json::json!({"const": "connection check"});
    close_direct_output_structs(&mut value);
    state_native_integer_bounds(&mut value);
    Ok(serde_json::to_string_pretty(&value)? + "\n")
}

/// Close structs emitted directly by this crate and the shared diagnostic DTOs.
fn close_direct_output_structs(schema: &mut Value) {
    if let Some(Value::Object(definitions)) = schema.get_mut("$defs") {
        for definition in definitions.values_mut() {
            let Value::Object(object) = definition else {
                continue;
            };
            if object.get("type") == Some(&Value::String("object".to_owned()))
                && object.contains_key("properties")
                && !object.contains_key("additionalProperties")
                && !["allOf", "anyOf", "oneOf"]
                    .iter()
                    .any(|keyword| object.contains_key(*keyword))
                && !object.contains_key("x-registry-foreign")
                && !object.contains_key("x-registry-passthrough")
            {
                object.insert("additionalProperties".to_owned(), Value::Bool(false));
            }
        }
    }
}

/// State the native range of each integer representation the report can emit.
fn state_native_integer_bounds(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            if object.contains_key("x-registry-foreign")
                || object.contains_key("x-registry-passthrough")
            {
                return;
            }
            let bounds = object
                .get("format")
                .and_then(Value::as_str)
                .and_then(native_integer_bounds);
            if let Some((minimum, maximum)) = bounds {
                object.entry("minimum").or_insert(minimum);
                object.entry("maximum").or_insert(maximum);
            }
            object.values_mut().for_each(state_native_integer_bounds);
        }
        Value::Array(items) => items.iter_mut().for_each(state_native_integer_bounds),
        _ => {}
    }
}

fn native_integer_bounds(format: &str) -> Option<(Value, Value)> {
    let signed = |minimum: i64, maximum: i64| (Value::from(minimum), Value::from(maximum));
    let unsigned = |maximum: u64| (Value::from(0), Value::from(maximum));
    match format {
        "int8" => Some(signed(i64::from(i8::MIN), i64::from(i8::MAX))),
        "int16" => Some(signed(i64::from(i16::MIN), i64::from(i16::MAX))),
        "int32" => Some(signed(i64::from(i32::MIN), i64::from(i32::MAX))),
        "int64" => Some(signed(i64::MIN, i64::MAX)),
        "int" => Some(signed(isize::MIN as i64, isize::MAX as i64)),
        "uint8" => Some(unsigned(u64::from(u8::MAX))),
        "uint16" => Some(unsigned(u64::from(u16::MAX))),
        "uint32" => Some(unsigned(u64::from(u32::MAX))),
        "uint64" => Some(unsigned(u64::MAX)),
        "uint" => Some(unsigned(usize::MAX as u64)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn checked_in_schema_matches_the_owning_types() {
        assert_eq!(
            super::document().expect("connections schema renders"),
            include_str!("../schema/connections.schema.json"),
            "regenerate with: cargo run -p registry-cli-api --features schema --example connections-schema -- --output crates/registry-cli-api/schema/connections.schema.json"
        );
        assert_eq!(
            super::connection_check_report_document().expect("connection check report schema renders"),
            include_str!("../schema/connection-check-report.schema.json"),
            "regenerate with: cargo run -p registry-cli-api --features schema --example connections-schema -- --output crates/registry-cli-api/schema/connections.schema.json --report-output crates/registry-cli-api/schema/connection-check-report.schema.json"
        );
    }
}
