// SPDX-License-Identifier: Apache-2.0
//! HTTP admissions reuse the wire schemas owned by Review and platform hooks.
use super::{problem_responses, ProblemCode as P};
use serde_json::{json, Map, Value};

pub(super) fn extend(paths: &mut Map<String, Value>, schemas: &mut Value) {
    for (name, schema) in crate::contracts::admission_schemas()
        .as_object()
        .expect("generated admission schemas")
    {
        let mut schema = schema.clone();
        embed_refs(&mut schema, name);
        schemas[name] = schema;
    }
    event_path(paths);
}

/// A schema's local definitions stay scoped to that owning schema after it is
/// embedded in OpenAPI, including repeated definition names from other DTOs.
fn embed_refs(value: &mut Value, name: &str) {
    match value {
        Value::Object(object) => {
            if let Some(Value::String(reference)) = object.get_mut("$ref") {
                if let Some(suffix) = reference.strip_prefix('#') {
                    *reference = format!("#/components/schemas/{name}{suffix}");
                }
            }
            object
                .values_mut()
                .for_each(|value| embed_refs(value, name));
        }
        Value::Array(values) => values.iter_mut().for_each(|value| embed_refs(value, name)),
        _ => {}
    }
}

pub(super) fn webhook_parameters() -> [Value; 3] {
    [
        json!({"name":"webhook-id","in":"header","required":true,"schema":{"type":"string","format":"uuid"}}),
        json!({"name":"webhook-timestamp","in":"header","required":true,"schema":{"type":"string","pattern":"^(0|[1-9][0-9]{0,19})$"}}),
        json!({"name":"webhook-signature","in":"header","required":true,"schema":{"type":"string","minLength":1}}),
    ]
}

pub(super) fn webhook_challenge() -> Value {
    json!({
        "description":"Authenticate the exact delivery with the configured Standard Webhooks key.",
        "schema":{"type":"string","const":super::WEBHOOK_CHALLENGE}
    })
}

fn event_path(paths: &mut Map<String, Value>) {
    let mut responses = problem_responses(&[
        P::EventDevelopmentPeer,
        P::EventInvalid,
        P::EventUnauthenticated,
        P::EventTooLarge,
        P::RequestInvalid,
        P::RequestBodyTooLarge,
        P::RequestMethodNotAllowed,
        P::AdmissionRecoveryOnly,
        P::AdmissionHeld,
        P::ExecutionHeld,
        P::DeploymentRefused,
        P::DeploymentActivationChanged,
        P::DefinitionRefused,
        P::BindingConflict,
        P::BindingLiveConflict,
        P::IdempotencyKeyReused,
        P::InputInvalid,
        P::AuditResponseUnavailable,
        P::ServiceUnavailable,
        P::RuntimeFailure,
    ]);
    responses["401"]["headers"]["WWW-Authenticate"] = webhook_challenge();
    responses.insert("204".into(), json!({
        "description":"Run admission is committed, or the exact event was already admitted. Empty Hook response proposes no source mutation.",
        "headers":{"X-Coordinator-Run-Id":{"schema":{"type":"string","format":"uuid"}}}
    }));
    let mut parameters = ["workflow", "trigger"].into_iter().map(|name| {
        json!({"name":name,"in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":64}})
    }).collect::<Vec<_>>();
    parameters.extend(webhook_parameters());
    paths.insert("/v1/events/{workflow}/{trigger}".into(), json!({"post":{
        "operationId":"admitEvent","summary":"Start a workflow from an authenticated product event",
        "description":"Accept at most 1048576 canonical JSON bytes in a HookEnvelope, then hold the admitted event to the 131072-byte structured value profile. Standard Webhooks signs the webhook ID, Unix timestamp and exact body using the key for the trigger in the URL. The signed timestamp must be within 300 seconds in either direction. The webhook ID must equal the envelope ID, and the envelope must match the configured producer URI and authored event type and data schema. The source URI, event ID and trigger bind admission across retries. Every downstream call uses its own product authorization.",
        "security":[{"eventSource":[]}],"parameters":parameters,
        "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/HookEnvelope"}}}},
        "responses":responses
    }}));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_wire_schema_accepts_the_canonical_owner_envelope_and_refuses_structural_drift() {
        use registry_platform_hooks::{EnvelopeLimits, HookEnvelope};
        let event: HookEnvelope = serde_json::from_value(json!({
            "id":"572bbca9-8e29-456c-8d97-973303538349",
            "type":"record.created",
            "source":"urn:example:registry",
            "time":"2026-10-14T12:00:00Z",
            "subject":{"recordReference":"records/example","recordRevision":1},
            "dataschema":"urn:example:record-event:v1",
            "data":{"active":true},
            "causation":{"root":"572bbca9-8e29-456c-8d97-973303538349","hop":0}
        }))
        .unwrap();
        let bytes = event
            .to_canonical_bytes(&EnvelopeLimits::default())
            .unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let validator = crate::definition::compile_schema(
            &crate::contracts::admission_schemas()["HookEnvelope"],
        )
        .unwrap();
        assert!(validator.is_valid(&value));
        let mut invalid = value.clone();
        invalid["subject"]["recordRevision"] = json!(0);
        assert!(!validator.is_valid(&invalid));
        invalid = value.clone();
        invalid["causation"]["parent"] = Value::Null;
        assert!(
            !validator.is_valid(&invalid),
            "canonical owner encoding never emits null parent"
        );
        invalid = value.clone();
        invalid["causation"]["hop"] = json!(9);
        assert!(!validator.is_valid(&invalid));
        invalid = value.clone();
        invalid.as_object_mut().unwrap().remove("data");
        assert!(!validator.is_valid(&invalid));
        invalid = value;
        invalid["attempt"] = json!(1);
        assert!(
            !validator.is_valid(&invalid),
            "delivery attributes belong to transport headers"
        );
    }

    #[test]
    fn every_embedded_wire_reference_resolves_without_redeclaring_its_fields() {
        fn check(document: &Value, value: &Value) {
            match value {
                Value::Object(object) => {
                    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                        if let Some(pointer) = reference.strip_prefix('#') {
                            assert!(
                                document.pointer(pointer).is_some(),
                                "unresolved {reference}"
                            );
                        }
                    }
                    object.values().for_each(|value| check(document, value));
                }
                Value::Array(values) => values.iter().for_each(|value| check(document, value)),
                _ => {}
            }
        }
        let document = super::super::openapi();
        check(&document, &document);
        for (name, schema) in crate::contracts::admission_schemas().as_object().unwrap() {
            let mut expected = schema.clone();
            embed_refs(&mut expected, name);
            assert_eq!(document["components"]["schemas"][name], expected);
        }
    }
}
