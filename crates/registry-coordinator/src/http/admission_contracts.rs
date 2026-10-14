// SPDX-License-Identifier: Apache-2.0
//! HTTP admissions reuse the wire schemas owned by Review and platform hooks.
use super::{problem_responses, ProblemCode as P, AUTHENTICATED_PROBLEMS, BODY_PROBLEMS};
use registry_review_protocol::REVIEW_PROFILE_HEADER;
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
    schemas["WorkflowContract"]["required"]
        .as_array_mut()
        .expect("workflow contract fields")
        .push(json!("reviewPolicy"));
    schemas["WorkflowContract"]["properties"]["reviewPolicy"] = json!({
        "description":"Exact Review policy binding when this workflow exposes the Review protocol; otherwise null.",
        "anyOf":[{"$ref":"#/components/schemas/PolicyBinding"},{"type":"null"}]
    });
    review_paths(paths);
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

fn response(schema: &str, description: &str) -> Value {
    json!({"description":description,"content":{"application/json":{
        "schema":{"$ref":format!("#/components/schemas/{schema}")}
    }}})
}

fn review_paths(paths: &mut Map<String, Value>) {
    let admission = [
        P::WorkflowNotServed,
        P::WorkflowRevisionMismatch,
        P::AdmissionRecoveryOnly,
        P::AdmissionHeld,
        P::ExecutionHeld,
        P::DeploymentRefused,
        P::DeploymentActivationChanged,
        P::DefinitionRefused,
        P::BindingConflict,
        P::BindingLiveConflict,
        P::IdempotencyKeyInvalid,
        P::IdempotencyKeyReused,
        P::InputInvalid,
    ];
    let operations = [
        (
            "/v1/review-requests",
            "post",
            "createReviewRequest",
            "Submit an exact Review request to a workflow",
            Some("ReviewCreateRequest"),
            "ReviewRequestAccepted",
            "201",
            admission.to_vec(),
        ),
        (
            "/v1/review-requests/{request}",
            "get",
            "reviewRequest",
            "Read the current state of an owned Review request",
            None,
            "ReviewRequestView",
            "200",
            vec![
                P::RequestInvalid,
                P::RunNotVisible,
                P::RunPayloadErased,
                P::ExecutionHeld,
            ],
        ),
        (
            "/v1/review-requests/{request}/result",
            "get",
            "reviewResult",
            "Read an immutable Review result within its availability window",
            None,
            "ReviewResult",
            "200",
            vec![P::RequestInvalid, P::RunNotVisible, P::ExecutionHeld],
        ),
        (
            "/v1/review-requests/{request}/cancel",
            "post",
            "cancelReviewRequest",
            "Cancel an owned Review request under its original deadline",
            Some("ReviewCancelRequest"),
            "ReviewCancelResponse",
            "200",
            vec![
                P::RequestInvalid,
                P::RunNotVisible,
                P::ExecutionHeld,
                P::IdempotencyKeyInvalid,
                P::IdempotencyKeyReused,
                P::ReviewResultExpired,
                P::InputInvalid,
            ],
        ),
        (
            "/v1/review-results",
            "get",
            "reviewResults",
            "Read a page of currently authorized Review results",
            None,
            "ReviewResultFeedPage",
            "200",
            vec![
                P::RequestInvalid,
                P::RequestLimitOutOfRange,
                P::ExecutionHeld,
            ],
        ),
    ];
    for (path, method, id, summary, request, reply, status, problems) in operations {
        let mut problems = [&AUTHENTICATED_PROBLEMS[..], &problems].concat();
        if request.is_some() {
            problems.extend(BODY_PROBLEMS);
        }
        let mut responses = problem_responses(&problems);
        responses.insert(status.into(), response(reply, "Authorized Review result"));
        if id == "reviewResult" {
            responses.insert("202".into(), json!({"description":"The Review result is pending; no body.","headers":{"Retry-After":{"schema":{"type":"integer","const":30}}}}));
            responses.insert(
                "404".into(),
                json!({"description":"No currently authorized request is visible; no body."}),
            );
            responses.insert("410".into(), json!({"description":"The original result window or pending policy deadline expired; no body."}));
        }
        let mut parameters = vec![
            json!({"name":REVIEW_PROFILE_HEADER,"in":"header","required":true,
            "description":"The Review producer profile registered for this authenticated client.",
            "schema":{"type":"string","minLength":1}}),
        ];
        if path.contains("{request}") {
            parameters.push(json!({"name":"request","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}));
        }
        if request.is_some() {
            parameters.push(json!({"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string","minLength":1,"maxLength":256}}));
        }
        if id == "reviewResults" {
            parameters.extend([
                json!({"name":"cursor","in":"query","description":"The previous page's nextCursor; current source authorization is checked again.","schema":{"type":"string","format":"uuid"}}),
                json!({"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":100,"default":20}}),
            ]);
        }
        let mut operation = json!({"operationId":id,"summary":summary,"security":[{"bearer":[]}],"parameters":parameters,"responses":responses});
        if let Some(request) = request {
            operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{request}")}}}});
        }
        paths.entry(path).or_insert_with(|| json!({}))[method] = operation;
    }
}

fn event_path(paths: &mut Map<String, Value>) {
    let mut responses = problem_responses(&[
        P::EventInvalid,
        P::EventUnauthenticated,
        P::EventSourceUnavailable,
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
    responses["401"]["headers"]["WWW-Authenticate"] = json!({
        "description":"Authenticate the exact canonical event and delivery attempt with the configured source key.",
        "schema":{"type":"string","const":"Registry-Signature version=\"v1\""}
    });
    responses.insert("204".into(), json!({
        "description":"Run admission is committed, or the exact event was already admitted. Empty Hook response proposes no source mutation.",
        "headers":{"X-Coordinator-Run-Id":{"schema":{"type":"string","format":"uuid"}}}
    }));
    let mut parameters = ["workflow", "trigger"].into_iter().map(|name| {
        json!({"name":name,"in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":64}})
    }).collect::<Vec<_>>();
    for (name, schema) in [
        ("ce-specversion", json!({"const":"1.0"})),
        ("ce-id", json!({"type":"string","format":"uuid"})),
        ("ce-source", json!({"type":"string","minLength":1})),
        ("ce-type", json!({"type":"string","minLength":1})),
        ("ce-time", json!({"type":"string","format":"date-time"})),
        ("ce-dataschema", json!({"type":"string","minLength":1})),
        (
            "X-Registry-Event-Generation",
            json!({"type":"string","pattern":"^[0-9]{1,10}$"}),
        ),
        (
            "X-Registry-Delivery-Attempt",
            json!({"type":"string","pattern":"^[0-9]{1,10}$"}),
        ),
        (
            "X-Registry-Delivery-Time",
            json!({"type":"string","format":"date-time"}),
        ),
        (
            "Idempotency-Key",
            json!({"type":"string","minLength":1,"maxLength":256}),
        ),
    ] {
        parameters.push(json!({"name":name,"in":"header","required":true,"schema":schema}));
    }
    paths.insert("/v1/events/{workflow}/{trigger}".into(), json!({"post":{
        "operationId":"admitEvent","summary":"Start a workflow from an authenticated product event",
        "description":"Accept at most 65536 canonical JSON bytes using the platform HookEnvelope and v1 delivery signature. Envelope headers must match the body and the authored source, event type and data schema. Delivery time must be within 30 seconds; an older event may be redelivered. The exact source, event identity and trigger bind admission across retries. Every downstream call uses its own product authorization.",
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
