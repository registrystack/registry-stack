// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schema for the local development clients file a Casework
//! project holds, `dev-clients.yaml`.

use serde_json::Value;
use std::collections::BTreeMap;

use crate::dev::config::{Clients, DEV_CLIENTS_API_VERSION, DEV_CLIENTS_KIND};

pub const DEV_CLIENTS_SCHEMA_FILE: &str = "dev-clients/dev-clients.schema.json";
pub const DEV_CLIENTS_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/dev-clients/dev-clients.v1alpha1.schema.json";

/// The committed schema documents, by path below
/// `products/casework/generated`.
pub fn documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    Ok([(
        DEV_CLIENTS_SCHEMA_FILE,
        registry_casework_core::schema::render(
            schemars::schema_for!(Clients),
            DEV_CLIENTS_API_VERSION,
            DEV_CLIENTS_KIND,
            DEV_CLIENTS_SCHEMA_ID,
            "Registry Casework development clients",
        )?,
    )]
    .into())
}

/// The one command-tagged report schema derives from the owning output DTOs.
pub fn report_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut settings = schemars::generate::SchemaSettings::draft2020_12();
    settings.contract = schemars::generate::Contract::Serialize;
    let schema = settings
        .into_generator()
        .into_root_schema_for::<crate::report::CliReport>();
    let mut value = serde_json::to_value(schema)?;
    value["$id"] = Value::String(
        "https://id.registrystack.org/schemas/casework/report/report.v1alpha2.schema.json".into(),
    );
    value["title"] = Value::String("Casework command report".into());
    value["properties"] = serde_json::json!({"apiVersion":{"const":crate::report::REPORT_API_VERSION},"kind":{"const":crate::report::REPORT_KIND}});
    value["required"] = serde_json::json!([
        "ok",
        "command",
        "status",
        "apiVersion",
        "kind",
        "version",
        "diagnostics"
    ]);
    value["allOf"] = serde_json::json!([{"oneOf":[
        {"properties":{"ok":{"const":true},"status":{"const":"complete"}}},
        {"properties":{"ok":{"const":false},"status":{"enum":["domain-refusal","usage-error","operational-failure"]},"diagnostics":{"minItems":1}}}
    ]}]);
    value["unevaluatedProperties"] = Value::Bool(false);
    require_success_payloads(&mut value);
    registry_casework_core::schema::type_identifier_keyed_maps(&mut value)?;
    type_casework_activation_digests(&mut value)?;
    close_direct_output_structs(&mut value);
    state_native_integer_bounds(&mut value);

    Ok([(
        "report.schema.json",
        serde_json::to_string_pretty(&value)? + "\n",
    )]
    .into())
}

/// Schemars correctly flattens each optional command payload, but its members
/// must remain optional so the same command variant can describe a failure.
/// Require the payload's non-optional members only for successful reports.
fn require_success_payloads(schema: &mut Value) {
    let variants = schema["oneOf"]
        .as_array_mut()
        .expect("the report schema is a command union");
    for variant in variants {
        let command = variant["properties"]["command"]["const"]
            .as_str()
            .expect("a report variant has one command");
        let payload = crate::report::payload_members(command)
            .unwrap_or_else(|| panic!("{command} has no payload schema"));
        let mut payload_or_success = vec![serde_json::json!({
            "properties":{"ok":{"const":true}},"required":["ok"]
        })];
        payload_or_success.extend(
            payload
                .present
                .iter()
                .map(|member| serde_json::json!({"required":[member]})),
        );
        let mut constraints = vec![serde_json::json!({
            "if":{"anyOf":payload_or_success},
            "then":{"required":payload.required}
        })];
        if let Some(status) = match command {
            "usage" => Some("usage-error"),
            "internal" => Some("operational-failure"),
            _ => None,
        } {
            constraints.push(serde_json::json!({
                "properties":{"ok":{"const":false},"status":{"const":status}},
                "required":["ok","status"]
            }));
        }
        variant["allOf"] = Value::Array(constraints);
    }
}

/// Casework's activation ledger constrains both digest columns to canonical
/// `sha256:` values. The shared activation DTO remains deliberately generic,
/// so state the stronger Casework output guarantee only at this boundary.
fn type_casework_activation_digests(schema: &mut Value) -> Result<(), serde_json::Error> {
    let digest = "#/$defs/Digest";
    let properties = schema["$defs"]["Activation"]["properties"]
        .as_object_mut()
        .expect("the shared Activation schema has object properties");
    assert!(properties.contains_key("packageDigest"));
    assert!(properties.contains_key("predecessorPackageDigest"));
    properties.insert("packageDigest".into(), serde_json::json!({"$ref": digest}));
    properties.insert(
        "predecessorPackageDigest".into(),
        serde_json::json!({"anyOf":[{"$ref":digest},{"type":"null"}]}),
    );
    let definition = serde_json::to_value(
        <registry_platform_yaml::Digest as schemars::JsonSchema>::json_schema(
            &mut schemars::SchemaGenerator::default(),
        ),
    )?;
    schema["$defs"]
        .as_object_mut()
        .expect("the report schema has definitions")
        .entry("Digest")
        .or_insert(definition);
    Ok(())
}

/// Close only direct serialized struct definitions. Foreign, passthrough,
/// composed, and map schemas keep their owning shape.
fn close_direct_output_structs(schema: &mut Value) {
    if let Some(Value::Object(definitions)) = schema.get_mut("$defs") {
        for definition in definitions.values_mut() {
            let Value::Object(object) = definition else {
                continue;
            };
            if object.get("type") == Some(&Value::String("object".into()))
                && object.contains_key("properties")
                && !object.contains_key("additionalProperties")
                && !["allOf", "anyOf", "oneOf"]
                    .iter()
                    .any(|keyword| object.contains_key(*keyword))
                && !object.contains_key("x-registry-foreign")
                && !object.contains_key("x-registry-passthrough")
            {
                object.insert("additionalProperties".into(), Value::Bool(false));
            }
        }
    }
}

/// State the exact range of each integer representation the Rust report
/// writer can emit. Existing product bounds stay in place when they are
/// narrower than the native representation.
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
    use super::*;
    use jsonschema::{Draft, JSONSchema};
    use serde_json::Value;

    fn schema() -> JSONSchema {
        let document: Value = serde_json::from_str(&documents().unwrap()[DEV_CLIENTS_SCHEMA_FILE])
            .expect("the dev-clients schema is JSON");
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&document)
            .expect("the dev-clients schema compiles as Draft 2020-12")
    }

    fn assert_native_integer_bounds(value: &Value, path: &str) {
        match value {
            Value::Object(object) => {
                if object.contains_key("x-registry-foreign")
                    || object.contains_key("x-registry-passthrough")
                {
                    return;
                }
                if object
                    .get("format")
                    .and_then(Value::as_str)
                    .and_then(native_integer_bounds)
                    .is_some()
                {
                    assert!(object.contains_key("minimum"), "missing minimum at {path}");
                    assert!(object.contains_key("maximum"), "missing maximum at {path}");
                }
                for (key, member) in object {
                    assert_native_integer_bounds(member, &format!("{path}/{key}"));
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    assert_native_integer_bounds(item, &format!("{path}/{index}"));
                }
            }
            _ => {}
        }
    }

    fn example() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/examples/standalone-decision/dev-clients.yaml");
        let bytes = std::fs::read(path).expect("read the example");
        crate::dev::config::read("dev-clients.yaml", &bytes)
            .expect("the example is accepted")
            .document
            .to_json_value()
    }

    #[test]
    fn the_maintained_example_and_templates_validate_against_the_schema() {
        let schema = schema();
        assert!(schema.is_valid(&example()));
        let document = crate::dev::config::read(
            "dev-clients.yaml",
            crate::project::STANDALONE_DEV_CLIENTS.as_bytes(),
        )
        .unwrap()
        .document
        .to_json_value();
        assert!(schema.is_valid(&document));
    }

    #[test]
    fn the_schema_refuses_what_the_reader_refuses() {
        let schema = schema();
        let valid = example();
        let mut unknown = valid.clone();
        unknown["client"] = Value::Array(Vec::new());
        assert!(!schema.is_valid(&unknown));
        let mut retired = valid.clone();
        retired["version"] = Value::from(1);
        assert!(!schema.is_valid(&retired));
        let mut null = valid.clone();
        null["directory"] = Value::Null;
        assert!(!schema.is_valid(&null));
        let mut port = valid.clone();
        port["integrations"] = serde_json::json!({
            "resource": "https://casework.example.test",
            "taskAuthority": {"issuer": "https://issuer.example.test", "jwksPort": 0, "statusClients": {}}
        });
        assert!(!schema.is_valid(&port));
        let mut kind = valid;
        kind["kind"] = Value::from("BregDevClients");
        assert!(!schema.is_valid(&kind));
    }

    #[test]
    fn the_schema_is_deterministic_and_versioned() {
        let first = documents().unwrap();
        assert_eq!(first, documents().unwrap());
        let document: Value = serde_json::from_str(&first[DEV_CLIENTS_SCHEMA_FILE]).unwrap();
        assert_eq!(document["$id"], DEV_CLIENTS_SCHEMA_ID);
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            DEV_CLIENTS_API_VERSION
        );
        assert_eq!(document["properties"]["kind"]["const"], DEV_CLIENTS_KIND);
    }

    #[test]
    fn committed_schema_matches_generated_bytes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/generated");
        for (file, generated) in documents().unwrap() {
            assert_eq!(
                std::fs::read_to_string(root.join(file)).unwrap_or_default(),
                generated,
                "products/casework/generated/{file} differs from its generator; run cargo run -p registry-caseworkctl --features schema --example dev-clients-schema -- --output products/casework/generated"
            );
        }
    }

    #[test]
    fn report_schema_matches_the_closed_serialized_contract() {
        let document: Value =
            serde_json::from_str(&report_documents().unwrap()["report.schema.json"]).unwrap();
        assert_eq!(document["unevaluatedProperties"], false);
        assert!(document["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .all(|variant| { variant["properties"].get("data").is_none() }));
        assert!(document["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|variant| { variant["properties"]["command"]["const"] == "internal" }));
        for (name, member) in [("RoutingCondition", "fields"), ("TaskTemplate", "subjects")] {
            assert_eq!(
                document["$defs"][name]["properties"][member]["propertyNames"]["$ref"],
                "#/$defs/ExternalId"
            );
        }
        for name in [
            "Activation",
            "ActivationEffects",
            "ActivationPlan",
            "ActivationRefusal",
            "ActivationStatus",
            "EnforcementLayer",
            "LifecycleDescription",
            "LifecycleState",
            "LifecycleTransition",
            "PinnedWorkEffect",
            "StrandedWork",
            "TaskTemplateEffect",
            "Diagnostic",
            "Related",
            "Source",
        ] {
            assert_eq!(
                document["$defs"][name]["additionalProperties"], false,
                "{name}"
            );
        }
        assert_eq!(
            document["$defs"]["ExplainPolicy"]["properties"]["displaySchema"]["x-registry-foreign"],
            "json-schema-2020-12"
        );
        assert_eq!(
            document["$defs"]["ExplainPolicy"]["properties"]["resultSchema"]["x-registry-foreign"],
            "json-schema-2020-12"
        );
        let activity = &document["$defs"]["ClockPolicy"]["oneOf"][1];
        assert_eq!(activity["additionalProperties"], false);
        assert!(activity["properties"]["atRisk"].get("default").is_none());
        assert_eq!(
            activity["properties"]["atRisk"]["$ref"],
            "#/$defs/WorkingDaysBefore"
        );
        assert!(activity["properties"]["atRisk"].get("anyOf").is_none());
        assert!(!activity["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member == "atRisk"));

        let definitions = &document["$defs"];
        let variant = |command: &str| {
            document["oneOf"]
                .as_array()
                .unwrap()
                .iter()
                .find(|variant| variant["properties"]["command"]["const"] == command)
                .unwrap_or_else(|| panic!("missing {command} report variant"))
        };
        assert_eq!(
            definitions["Activation"]["properties"]["applyOrder"]["minimum"],
            i64::MIN
        );
        assert_eq!(
            definitions["Activation"]["properties"]["applyOrder"]["maximum"],
            i64::MAX
        );
        assert_eq!(
            variant("dev-grant")["properties"]["grantExpiresAt"]["minimum"],
            0
        );
        assert_eq!(
            variant("dev-grant")["properties"]["grantExpiresAt"]["maximum"],
            u64::MAX
        );
        assert_eq!(
            variant("check")["properties"]["filesChecked"]["maximum"],
            usize::MAX as u64
        );
        assert_eq!(
            definitions["WorkingDays"]["properties"]["workingDays"]["maximum"],
            3650
        );
        assert_eq!(
            definitions["Activation"]["properties"]["packageDigest"]["$ref"],
            "#/$defs/Digest"
        );
        assert_eq!(
            definitions["Activation"]["properties"]["predecessorPackageDigest"],
            serde_json::json!({"anyOf":[{"$ref":"#/$defs/Digest"},{"type":"null"}]})
        );
        assert_eq!(definitions["Digest"]["pattern"], "^sha256:[0-9a-f]{64}$");
        assert_native_integer_bounds(&document, "");
    }

    #[test]
    fn actual_flat_success_and_failure_reports_validate() {
        let document: Value =
            serde_json::from_str(&report_documents().unwrap()["report.schema.json"]).unwrap();
        let validator = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&document)
            .expect("the report schema compiles as Draft 2020-12");

        let success = crate::report::CliReport::from_value(
            "dev",
            serde_json::json!({
                "ok": true,
                "status": "ready",
                "project": "review",
                "stateFile": "state.json",
                "operatorConfig": "operator.yaml",
                "caseworkUrl": "http://127.0.0.1:8092",
                "tokenEndpoint": "http://127.0.0.1:8093/oauth2/token",
                "issuer": "http://127.0.0.1:8093",
                "clientAssertionAudience": "http://127.0.0.1:8093",
                "resource": "urn:casework:dev:review",
                "audience": "urn:casework:dev:review",
                "journal": "casework.ndjson",
                "contextProviders": [],
                "clients": [],
                "directory": {"revision": 1, "teams": 1}
            }),
        )
        .unwrap();
        let success = serde_json::to_value(success).unwrap();
        assert!(success.get("data").is_none());
        if let Err(errors) = validator.validate(&success) {
            panic!(
                "flat dev success violates the report schema: {}",
                errors
                    .map(|error| format!("{error} at {}", error.instance_path))
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }

        let mut warning_success = success.clone();
        warning_success["diagnostics"] = serde_json::json!([{
            "severity":"warning",
            "code":"casework.project.example-warning",
            "path":"/reviewPolicies/decision",
            "message":"The example keeps an accepted warning.",
            "suggestedAction":"Review the accepted warning before deployment.",
            "source":{"file":"casework.yaml","line":1,"column":1}
        }]);
        if let Err(errors) = validator.validate(&warning_success) {
            panic!(
                "flat success with a warning violates the report schema: {}",
                errors
                    .map(|error| format!("{error} at {}", error.instance_path))
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }

        let mut incomplete_success = success;
        incomplete_success
            .as_object_mut()
            .unwrap()
            .remove("outcome");
        assert!(!validator.is_valid(&incomplete_success));

        let payload_failure = crate::report::CliReport::from_value(
            "provider-add",
            serde_json::json!({
                "ok": false,
                "outcome": "changes-needed",
                "project": "review",
                "actionId": "correct-address",
                "pattern": "single-reviewer-approval",
                "sourceNamespace": "facility-registry",
                "policyId": "correct-address-review",
                "authorityId": "correct-address-review-authority",
                "providerId": "correct-address-context",
                "contextFields": [],
                "changes": [],
                "deployment": [],
                "bypassPaths": [],
                "sourceWrites": false,
                "next": "Apply the intended BReg changes, then retry.",
                "diagnostics": [{
                    "severity":"error",
                    "code":"casework.provider-add.breg-changes-needed",
                    "path":"--breg-project",
                    "message":"The BReg Action needs authored changes.",
                    "suggestedAction":"Review the proposed changes, apply them, then retry."
                }]
            }),
        )
        .unwrap();
        let payload_failure = serde_json::to_value(payload_failure).unwrap();
        if let Err(errors) = validator.validate(&payload_failure) {
            panic!(
                "complete provider-add failure payload violates the report schema: {}",
                errors
                    .map(|error| format!("{error} at {}", error.instance_path))
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }

        let bare_provider_failure = crate::report::CliReport::failure(
            "provider-add",
            crate::report::ReportStatus::DomainRefusal,
            vec![registry_platform_yaml::Diagnostic::error(
                "casework.provider-add.invalid-breg-report",
                "--breg-project",
                "The BReg report was refused.",
                "Inspect the BReg project, then retry.",
            )],
        )
        .unwrap();
        let bare_provider_failure = serde_json::to_value(bare_provider_failure).unwrap();
        if let Err(errors) = validator.validate(&bare_provider_failure) {
            panic!(
                "bare provider-add failure violates the report schema: {}: {bare_provider_failure}",
                errors
                    .map(|error| format!("{error} at {}", error.instance_path))
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
        let mut partial_failure = bare_provider_failure;
        partial_failure["outcome"] = Value::String("changes-needed".into());
        assert!(validator.validate(&partial_failure).is_err());

        let failure = crate::report::CliReport::failure(
            "internal",
            crate::report::ReportStatus::OperationalFailure,
            vec![registry_platform_yaml::Diagnostic::error(
                "caseworkctl.internal-error",
                "",
                "The command stopped because of an internal error.",
                "Preserve the input and report the diagnostic code.",
            )],
        )
        .unwrap();
        let failure = serde_json::to_value(failure).unwrap();
        if let Err(errors) = validator.validate(&failure) {
            panic!(
                "internal failure violates the report schema: {}",
                errors
                    .map(|error| format!("{error} at {}", error.instance_path))
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }

        let mut impossible_internal_success = failure.clone();
        impossible_internal_success["ok"] = Value::Bool(true);
        impossible_internal_success["status"] = Value::String("complete".into());
        impossible_internal_success["diagnostics"] = serde_json::json!([]);
        assert!(!validator.is_valid(&impossible_internal_success));

        let mut empty_failure = failure;
        empty_failure["diagnostics"] = serde_json::json!([]);
        assert!(!validator.is_valid(&empty_failure));

        for (command, status) in [
            ("usage", "operational-failure"),
            ("internal", "domain-refusal"),
        ] {
            let impossible = crate::report::CliReport::failure(
                command,
                match status {
                    "domain-refusal" => crate::report::ReportStatus::DomainRefusal,
                    "operational-failure" => crate::report::ReportStatus::OperationalFailure,
                    _ => unreachable!(),
                },
                vec![registry_platform_yaml::Diagnostic::error(
                    "caseworkctl.synthetic-failure",
                    "",
                    "The synthetic report carries the wrong status.",
                    "Use the status assigned to this failure command.",
                )],
            )
            .unwrap();
            let impossible = serde_json::to_value(impossible).unwrap();
            assert!(
                validator.validate(&impossible).is_err(),
                "{command} accepted {status}"
            );
        }
    }
}
