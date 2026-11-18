// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schemas for the development plan and scenario files the
//! runner reads.
//!
//! Each schema is derived from the types the plan reader decodes and
//! published with the header the reader checks before decoding them. The
//! committed copies under `products/platform/generated/dev` come from the
//! `dev-schema` example; `products/platform/scripts/check-dev-schemas.sh`
//! fails when they differ from what the reader types generate.

use std::collections::BTreeMap;

use registry_platform_yaml::{EnvelopeRule, FormatSpec, VersionStatus};
use serde_json::{json, Map, Value};

use crate::plan;

const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
const SCHEMA_ID_BASE: &str = "https://id.registrystack.org/schemas/";

/// One published development file schema.
struct DevFormat {
    /// The format's namespace and name in the format registry.
    namespace: &'static str,
    format: &'static str,
    title: &'static str,
    spec: FormatSpec<'static>,
    members: fn() -> schemars::Schema,
}

fn formats() -> [DevFormat; 2] {
    [
        DevFormat {
            namespace: "rstack",
            format: "dev",
            title: "Registry Stack development plan",
            spec: plan::FORMAT,
            members: plan::schema,
        },
        DevFormat {
            namespace: "rstack",
            format: "scenarios",
            title: "Registry Stack authored development scenarios",
            spec: plan::SCENARIOS_FORMAT,
            members: plan::scenarios_schema,
        },
    ]
}

/// Every development file schema under its committed file name,
/// `<format>.<version>.schema.json`.
pub fn documents() -> Result<BTreeMap<String, String>, serde_json::Error> {
    formats()
        .into_iter()
        .map(|format| {
            let api_version = current_api_version(&format.spec);
            let version = api_version.rsplit('/').next().unwrap_or(api_version);
            let file = format!("{}.{version}.schema.json", format.format);
            let identifier = format!(
                "{SCHEMA_ID_BASE}{}/{}/{file}",
                format.namespace, format.format
            );
            let mut derived = serde_json::to_value((format.members)())?;
            refuse_null(&mut derived);
            let published = published(
                with_header(derived, api_version, format.spec.kind),
                format.title,
                &identifier,
            );
            let mut rendered = serde_json::to_string_pretty(&published)?;
            rendered.push('\n');
            Ok((file, rendered))
        })
        .collect()
}

fn current_api_version(spec: &FormatSpec<'static>) -> &'static str {
    match spec.envelope {
        EnvelopeRule::ApiVersionKind { api_versions, .. } => api_versions
            .iter()
            .find(|version| version.status == VersionStatus::Current)
            .map(|version| version.name)
            .expect("a published development format names its current apiVersion"),
        EnvelopeRule::Exempt { .. } => {
            unreachable!("a published development format carries the apiVersion and kind header")
        }
    }
}

/// The reader checks `apiVersion` and `kind` and removes them before it
/// decodes the members, so the derived schema lacks them; the published one
/// requires both, each with the one value this release reads.
fn with_header(mut derived: Value, api_version: &str, kind: &str) -> Value {
    let Value::Object(object) = &mut derived else {
        unreachable!("a reader type derives an object schema")
    };
    let properties = object
        .entry("properties")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(properties) = properties {
        properties.insert(
            "apiVersion".to_owned(),
            json!({
                "description": "The format and version this file is written in.",
                "type": "string",
                "const": api_version,
            }),
        );
        properties.insert(
            "kind".to_owned(),
            json!({
                "description": "The kind of document this file is.",
                "type": "string",
                "const": kind,
            }),
        );
    }
    let mut required = vec![Value::from("apiVersion"), Value::from("kind")];
    if let Some(Value::Array(members)) = object.remove("required") {
        required.extend(members);
    }
    object.insert("required".to_owned(), Value::Array(required));
    derived
}

fn published(derived: Value, title: &str, identifier: &str) -> Value {
    let Value::Object(mut object) = derived else {
        unreachable!("a reader type derives an object schema")
    };
    object.insert(
        "$schema".to_owned(),
        Value::String(SCHEMA_DIALECT.to_owned()),
    );
    object.insert("$id".to_owned(), Value::String(identifier.to_owned()));
    object.insert("title".to_owned(), Value::String(title.to_owned()));
    Value::Object(object)
}

/// The reader refuses `null` in every member (CFG-EMPTY-1), so an optional
/// member is written by leaving it out. This drops the `null` schemars adds
/// to an `Option` and the `default: null` it declares for one. Instance
/// values under `default`, `const`, `enum`, and `examples` are left as
/// written.
fn refuse_null(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            if object.get("default") == Some(&Value::Null) {
                object.remove("default");
            }
            if let Some(Value::Array(kinds)) = object.get_mut("type") {
                kinds.retain(|kind| kind != "null");
                if let [only] = kinds.as_slice() {
                    let only = only.clone();
                    object.insert("type".to_owned(), only);
                }
            }
            for keyword in ["anyOf", "oneOf"] {
                let Some(Value::Array(branches)) = object.get_mut(keyword) else {
                    continue;
                };
                branches.retain(|branch| branch.get("type") != Some(&Value::from("null")));
                if let [Value::Object(only)] = branches.as_slice() {
                    let only = only.clone();
                    object.remove(keyword);
                    object.extend(only);
                }
            }
            for (key, member) in object.iter_mut() {
                if matches!(key.as_str(), "default" | "const" | "enum" | "examples") {
                    continue;
                }
                refuse_null(member);
            }
        }
        Value::Array(items) => {
            for item in items {
                refuse_null(item);
            }
        }
        _ => {}
    }
}
