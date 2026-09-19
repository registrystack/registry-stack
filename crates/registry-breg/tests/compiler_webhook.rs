// SPDX-License-Identifier: Apache-2.0

use registry_breg::compiler::{
    compile_project, module_digest, CompileProfile, REQUEST_LIFECYCLE_STATES,
    REQUEST_LIFECYCLE_TRANSITIONS,
};
use registry_breg::contract::{
    parse_module_json, parse_project_json, Classification, EventTrigger, ModuleLockSource,
    RegistryModule, RegistryProject, WebhookAuthenticationProfile, WebhookDeadLetterMode,
};
use registry_breg::diagnostics::CompileFailure;
use registry_breg::model::{CompiledWebhookDeliveryMode, CompiledWebhookRetryProfile};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde_json::{json, Value};

fn project_value() -> Value {
    json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {"id": "webhook-contract", "version": "1", "defaultLanguage": "en",
                     "canonicalBaseIri": "https://webhook-contract.example.test"},
        "entities": [{
            "id": "case",
            "primaryDataset": "test-dataset",
            "route": "cases",
            "mutationMode": "mutable",
            "tombstone": true,
            "classification": "internal",
            "fields": [
                {"id": "label", "type": "string", "maxLength": 64, "classification": "public"},
                {"id": "region", "type": "string", "maxLength": 32, "classification": "internal"},
                {"id": "secret", "type": "string", "maxLength": 64, "classification": "restricted"}
            ],
            "hooks": [{
                "phase": "after",
                "id": "case-created",
                "trigger": "created",
                "projection": ["label", "region"],
                "when": {
                    "kind": "fields",
                    "afterEquals": {"region": "north"}
                },
                "handler": {
                    "kind": "url",
                    "destinationId": "case-operations"
                }
            }, {
                "phase": "after",
                "id": "case-patched-outbox",
                "trigger": "patched",
                "projection": ["label"]
            }]
        }]
    })
}

fn parse_project(value: &Value) -> RegistryProject {
    parse_project_json(&serde_json::to_vec(value).expect("test project serializes"))
        .expect("test project parses")
}

fn compile(value: &Value) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    compile_project(&parse_project(value), &[], CompileProfile::Authoring)
}

fn assert_compile_code(value: &Value, code: &str) {
    let failure = compile(value).expect_err("invalid webhook contract is refused");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code),
        "missing diagnostic {code:?}: {:?}",
        failure.diagnostics()
    );
}

fn change_request_event_project() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1",
        "kind":"RegistryProject",
        "registry":{"id":"request-events","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://request-events.example.test"},
        "entities":[{
            "id":"asset-site",
            "primaryDataset":"test-dataset",
            "route":"asset-sites",
            "mutationMode":"create_only",
            "classification":"internal",
            "fields":[
                {"id":"name","type":"string","maxLength":80,"required":true,"classification":"internal"}
            ]
        },{
            "id":"asset-placement",
            "primaryDataset":"test-dataset",
            "route":"asset-placements",
            "mutationMode":"mutable",
            "classification":"internal",
            "changeControl":{"requiredFor":["patch"]},
            "fields":[
                {"id":"site","type":"reference","target":"asset-site","required":true,"classification":"internal"}
            ]
        },{
            "id":"placement-correction-request",
            "primaryDataset":"test-dataset",
            "route":"placement-correction-requests",
            "mutationMode":"mutable",
            "classification":"internal",
            "fields":[
                {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
                {"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
                {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"restricted"}
            ],
            "hooks":[{
                "phase": "after",
                "id":"request-lifecycle",
                "trigger":"request_lifecycle",
                "projection":["proposed-site","reason"],
                "handler":{"kind":"url","destinationId":"review-operations"}
            }],
            "changeRequest":{
                "effects":[{
                    "target":{"fromField":"placement"},
                    "operation":"patch",
                    "set":{"site":{"fromField":"proposed-site"}}
                }],
                "review":{"authority":"casework-main","policyId":"placement-correction"},
                "onApproved":{"mode":"manual"}
            }
        }],
        "accessProfiles":[{
            "id":"submitter",
            "default":true,
            "principalClaim":"registry_principal",
            "permissions":[{
                "entity":"placement-correction-request",
                "operations":["create","get","list","patch","submit_request","revise_request","cancel_request"],
                "readableFields":["placement","proposed-site","reason"],
                "writableFields":["placement","proposed-site","reason"],
              "rowBoundaries": []
            }]
        },{
            "id":"reviewer",
            "principalClaim":"registry_principal",
            "permissions":[{
                "entity":"placement-correction-request",
                "operations":["get","list"],
                "readableFields":["placement","proposed-site","reason"],
              "rowBoundaries": []
            }]
        },{
            "id":"applier",
            "principalClaim":"registry_principal",
            "permissions":[{
                "entity":"placement-correction-request",
                "operations":["get","list","apply_request"],
                "readableFields":["placement","proposed-site","reason"],
                "applyTargets":[{"entity":"asset-placement","rowBoundaries":[]}],
              "rowBoundaries": []
            }]
        }]
    })
}

fn webhook_mut(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    value["entities"][0]["hooks"][0]["handler"]
        .as_object_mut()
        .expect("webhook object")
}

#[test]
fn governed_webhook_compiles_to_deterministic_destination_neutral_inventory() {
    let source = project_value();
    let first = compile(&source).expect("governed webhook compiles");
    let second = compile(&source).expect("same governed webhook compiles twice");
    assert_eq!(first, second);

    let inventory = first.event_deliveries();
    assert_eq!(inventory.deliveries.len(), 1);
    let delivery = &inventory.deliveries[0];
    assert_eq!(delivery.id, "events.case.case-created.webhook");
    assert_eq!(delivery.entity_id, "case");
    assert_eq!(delivery.event_id, "case-created");
    assert_eq!(delivery.destination_id.as_deref(), Some("case-operations"));
    assert_eq!(delivery.projection_fields, ["label", "region"]);
    assert_eq!(delivery.classification_ceiling, Classification::Internal);
    assert!(delivery.when.is_some());
    assert!(delivery
        .data_schema
        .starts_with("urn:breg:event-schema:webhook-contract:case:case-created:sha256:"));
    assert!(delivery.data_schema_fingerprint.starts_with("sha256:"));
    assert_eq!(
        delivery.data_schema_artifact_path,
        "generated/event-schemas/case.case-created.schema.json"
    );
    assert_eq!(
        delivery.authentication_profile,
        WebhookAuthenticationProfile::HmacSha256V1
    );
    assert_eq!(
        delivery.delivery_mode,
        CompiledWebhookDeliveryMode::AfterCommit
    );
    assert_eq!(
        delivery.retry_profile,
        CompiledWebhookRetryProfile::RegistryV1
    );
    assert_eq!(delivery.attempt_timeout_ms, 5000);
    assert_eq!(delivery.initial_backoff_ms, 1000);
    assert_eq!(delivery.maximum_backoff_ms, 8000);
    assert_eq!(delivery.maximum_attempts, 5);
    assert_eq!(delivery.exponential_backoff_multiplier, 2);
    assert_eq!(delivery.retry_delays_ms, [1000, 2000, 4000, 8000]);
    // The data object's worst case plus the envelope wrapper this project's
    // identifiers produce: 2288 + 644.
    assert_eq!(delivery.maximum_payload_bytes, 2932);
    assert_eq!(delivery.dead_letter, WebhookDeadLetterMode::Required);
    assert!(delivery.operator_replay);

    let artifact = first
        .artifacts()
        .get("compiled/event-deliveries.json")
        .expect("delivery inventory is captured as a compiler artifact");
    let parsed = parse_json_strict(&artifact.bytes).expect("inventory is strict JSON");
    assert_eq!(
        canonicalize_json(&parsed).expect("inventory canonicalizes"),
        artifact.bytes
    );
    assert_eq!(
        parsed,
        serde_json::to_value(inventory).expect("inventory serializes")
    );
    let schema = first
        .artifacts()
        .get(&delivery.data_schema_artifact_path)
        .expect("event data schema is generated");
    assert_eq!(schema.sha256, delivery.data_schema_fingerprint);
    let schema_value = parse_json_strict(&schema.bytes).expect("event schema is strict JSON");
    assert_eq!(
        schema_value["properties"]["values"]["required"],
        json!(["label", "region"])
    );
    let text = String::from_utf8(artifact.bytes.clone()).expect("artifact is UTF-8");
    for forbidden in ["http://", "https://", "secret", "tls", "certificate"] {
        assert!(!text.to_ascii_lowercase().contains(forbidden));
    }

    let entity = &first.entities()["case"];
    assert!(entity.hooks["case-created"].handler.is_some());
    assert!(entity.hooks["case-patched-outbox"].handler.is_none());
}

#[test]
fn application_reason_webhooks_require_internal_delivery_unless_conditions_exclude_apply() {
    let mut source = change_request_event_project();
    let request = &mut source["entities"][2];
    request["classification"] = json!("public");
    request["fields"][2]["classification"] = json!("public");
    request["hooks"][0]["projection"] = json!(["reason"]);
    for (condition, expected) in [
        (None, Classification::Internal),
        (
            Some(json!({"kind":"request_lifecycle", "transitions":["cancel"]})),
            Classification::Public,
        ),
        (
            Some(json!({"kind":"request_lifecycle", "toStates":["cancelled"]})),
            Classification::Public,
        ),
        (
            Some(json!({"kind":"request_lifecycle", "transitions":["apply"]})),
            Classification::Internal,
        ),
        (
            Some(json!({"kind":"request_lifecycle", "toStates":["applied"]})),
            Classification::Internal,
        ),
        (
            Some(
                json!({"kind":"request_lifecycle", "transitions":["cancel"], "toStates":["applied"]}),
            ),
            Classification::Public,
        ),
        (
            Some(
                json!({"kind":"request_lifecycle", "transitions":["apply","cancel"], "toStates":["applied"]}),
            ),
            Classification::Internal,
        ),
    ] {
        if let Some(condition) = &condition {
            source["entities"][2]["hooks"][0]["when"] = condition.clone();
        } else {
            source["entities"][2]["hooks"][0]
                .as_object_mut()
                .unwrap()
                .remove("when");
        }
        let compiled = compile(&source).expect("public request event compiles");
        let delivery = compiled
            .event_deliveries()
            .deliveries
            .iter()
            .find(|delivery| delivery.event_id == "request-lifecycle")
            .expect("delivery");
        assert_eq!(delivery.classification_ceiling, expected, "{condition:?}");
    }
}

#[test]
fn request_lifecycle_webhook_uses_classified_request_projection() {
    let compiled =
        compile(&change_request_event_project()).expect("request lifecycle event compiles");
    let delivery = compiled
        .event_deliveries()
        .deliveries
        .iter()
        .find(|delivery| delivery.event_id == "request-lifecycle")
        .expect("request lifecycle webhook delivery is compiled");
    assert_eq!(
        delivery.id,
        "events.placement-correction-request.request-lifecycle.webhook"
    );
    assert_eq!(delivery.entity_id, "placement-correction-request");
    assert_eq!(delivery.trigger, EventTrigger::RequestLifecycle);
    assert_eq!(delivery.projection_fields, ["proposed-site", "reason"]);
    assert_eq!(delivery.classification_ceiling, Classification::Restricted);
    assert!(delivery.data_schema.starts_with(
        "urn:breg:event-schema:request-events:placement-correction-request:request-lifecycle:sha256:"
    ));

    let schema = compiled
        .artifacts()
        .get(&delivery.data_schema_artifact_path)
        .expect("lifecycle event schema is generated");
    let schema_value = parse_json_strict(&schema.bytes).expect("event schema is strict JSON");
    assert_eq!(
        schema_value["properties"]["trigger"],
        json!({"const":"request_lifecycle"})
    );
    assert_eq!(
        schema_value["required"],
        json!([
            "entity",
            "recordId",
            "revision",
            "trigger",
            "packageRevision",
            "request",
            "values"
        ])
    );
    assert_eq!(
        schema_value["properties"]["request"]["required"],
        json!([
            "proposalVersion",
            "workflowRevision",
            "transition",
            "fromState",
            "toState",
            "reasonPresent",
            "effectDigest",
            "deduplicationKey"
        ])
    );
}

fn lifecycle_request_schema(source: &Value) -> Value {
    let compiled = compile(source).expect("lifecycle project compiles");
    let delivery = compiled
        .event_deliveries()
        .deliveries
        .iter()
        .find(|delivery| delivery.event_id == "request-lifecycle")
        .unwrap();
    let schema = compiled
        .artifacts()
        .get(&delivery.data_schema_artifact_path)
        .unwrap();
    parse_json_strict(&schema.bytes).unwrap()["properties"]["request"].clone()
}

fn lifecycle_request(transition: &str, to_state: &str) -> Value {
    json!({
        "proposalVersion": 1, "workflowRevision": 3,
        "transition": transition, "fromState": "submitted", "toState": to_state,
        "effectDigest": null, "deduplicationKey": "captured-event",
        "reasonPresent": false
    })
}

#[test]
fn lifecycle_event_reason_schema_matches_application_presence_and_negative_transition_pairs() {
    let schema = lifecycle_request_schema(&change_request_event_project());
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    for (transition, state) in [("apply", "applied")] {
        let mut request = lifecycle_request(transition, state);
        assert!(validator.is_valid(&request));
        request["reason"] = json!("explanation");
        assert!(!validator.is_valid(&request));
        request["reasonPresent"] = json!(true);
        for reason in [
            json!(""),
            json!(" ขอรายละเอียดเพิ่มเติม 🙂 "),
            json!("🙂".repeat(4096)),
        ] {
            request["reason"] = reason;
            assert!(validator.is_valid(&request));
        }
        request.as_object_mut().unwrap().remove("reason");
        assert!(!validator.is_valid(&request));
        for reason in [
            Value::Null,
            json!(false),
            json!(1),
            json!([]),
            json!({}),
            json!("a\0b"),
            json!("🙂".repeat(4097)),
        ] {
            request["reason"] = reason;
            assert!(!validator.is_valid(&request));
        }
        request["reason"] = json!("valid text");
        request.as_object_mut().unwrap().remove("reasonPresent");
        assert!(!validator.is_valid(&request));
    }
    for (transition, state) in [
        ("submit", "submitted"),
        ("revise", "draft"),
        ("cancel", "cancelled"),
        ("apply", "cancelled"),
    ] {
        let mut request = lifecycle_request(transition, state);
        request["reasonPresent"] = json!(true);
        request["reason"] = json!("");
        assert!(!validator.is_valid(&request));
    }
    let mut ordinary = lifecycle_request("submit", "submitted");
    assert!(validator.is_valid(&ordinary));
    ordinary["transition"] = json!("unknown");
    assert!(!validator.is_valid(&ordinary));
    ordinary["transition"] = json!("submit");
    ordinary["toState"] = json!("unknown");
    assert!(!validator.is_valid(&ordinary));
}

#[test]
fn lifecycle_event_schema_preserves_authored_filter_intersection() {
    let mut source = change_request_event_project();
    for condition in [
        json!({"kind":"request_lifecycle", "transitions":["apply"]}),
        json!({"kind":"request_lifecycle", "toStates":["applied"]}),
        json!({"kind":"request_lifecycle", "transitions":["apply"], "toStates":["applied"]}),
    ] {
        source["entities"][2]["hooks"][0]["when"] = condition;
        let schema = lifecycle_request_schema(&source);
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        assert!(validator.is_valid(&lifecycle_request("apply", "applied")));
        for (transition, state) in [("cancel", "cancelled"), ("submit", "submitted")] {
            let mut request = lifecycle_request(transition, state);
            assert!(!validator.is_valid(&request));
            request["reasonPresent"] = json!(true);
            request["reason"] = json!("explanation");
            assert!(!validator.is_valid(&request));
        }
    }
    source["entities"][2]["hooks"][0]["when"] = json!({
        "kind":"request_lifecycle", "transitions":["apply"],
        "toStates":["applied"]
    });
    let schema = lifecycle_request_schema(&source);
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    for (transition, state) in [("apply", "applied")] {
        let mut request = lifecycle_request(transition, state);
        request["reasonPresent"] = json!(true);
        request["reason"] = json!("");
        assert!(validator.is_valid(&request));
    }
}

#[test]
fn lifecycle_events_are_request_only_and_use_closed_lifecycle_conditions() {
    let mut non_request = project_value();
    non_request["entities"][0]["hooks"][0]["trigger"] = json!("request_lifecycle");
    assert_compile_code(
        &non_request,
        "event.trigger.request_lifecycle_requires_change_request",
    );

    let mut field_condition = change_request_event_project();
    field_condition["entities"][2]["hooks"][0]["when"] =
        json!({"kind":"fields","afterEquals":{"reason":"notify"}});
    assert_compile_code(&field_condition, "event.when.trigger_incompatible");

    let mut lifecycle_condition = change_request_event_project();
    lifecycle_condition["entities"][2]["hooks"][0]["when"] = json!({
        "kind":"request_lifecycle",
        "transitions":["apply"],
        "toStates":["applied"]
    });
    compile(&lifecycle_condition).expect("closed lifecycle condition compiles");

    let mut bad_transition = lifecycle_condition.clone();
    bad_transition["entities"][2]["hooks"][0]["when"]["transitions"] = json!(["callback_granted"]);
    assert_compile_code(
        &bad_transition,
        "event.when.request_lifecycle_transition_unknown",
    );
}

#[test]
fn unknown_lifecycle_predicates_list_the_closed_sets_the_runtime_accepts() {
    assert_eq!(
        REQUEST_LIFECYCLE_TRANSITIONS,
        ["submit", "revise", "rebase", "cancel", "apply"]
    );
    assert_eq!(
        REQUEST_LIFECYCLE_STATES,
        ["draft", "submitted", "cancelled", "applied", "superseded"]
    );

    let mut lifecycle_condition = change_request_event_project();
    lifecycle_condition["entities"][2]["hooks"][0]["when"] = json!({
        "kind":"request_lifecycle",
        "transitions":["apply"],
        "toStates":["applied"]
    });

    let mut bad_transition = lifecycle_condition.clone();
    bad_transition["entities"][2]["hooks"][0]["when"]["transitions"] = json!(["callback_granted"]);
    let failure = compile(&bad_transition).expect_err("an unknown transition is refused");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|item| item.code == "event.when.request_lifecycle_transition_unknown")
        .expect("the unknown transition is reported");
    assert!(
        diagnostic.message.contains("`callback_granted`"),
        "{diagnostic:?}"
    );
    for transition in REQUEST_LIFECYCLE_TRANSITIONS {
        assert!(
            diagnostic.message.contains(transition),
            "{transition} is listed: {diagnostic:?}"
        );
    }

    let mut bad_state = lifecycle_condition;
    bad_state["entities"][2]["hooks"][0]["when"]["toStates"] = json!(["escalated"]);
    let failure = compile(&bad_state).expect_err("an unknown request state is refused");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|item| item.code == "event.when.request_lifecycle_state_unknown")
        .expect("the unknown request state is reported");
    assert!(diagnostic.message.contains("`escalated`"), "{diagnostic:?}");
    for state in REQUEST_LIFECYCLE_STATES {
        assert!(
            diagnostic.message.contains(state),
            "{state} is listed: {diagnostic:?}"
        );
    }
}

#[test]
fn destination_auth_delivery_and_deployed_members_are_closed_and_value_free() {
    for destination in ["", "HTTPS://deployed.example/hook", "Uppercase", "bad.dot"] {
        let mut source = project_value();
        webhook_mut(&mut source).insert("destinationId".to_owned(), json!(destination));
        let failure = compile(&source).expect_err("invalid logical destination is refused");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "event.webhook.destination.invalid"));
        if !destination.is_empty() {
            assert!(!serde_json::to_string(&failure)
                .expect("failure serializes")
                .contains(destination));
        }
    }

    for (member, canary) in [
        ("destinationUrl", "https://deployed.example/webhook-canary"),
        ("secret", "raw-webhook-secret-canary"),
        ("tlsCertificate", "raw-tls-certificate-canary"),
        ("classificationCeiling", "restricted"),
        ("authenticationProfile", "hmac_sha256_v1"),
    ] {
        let mut source = project_value();
        webhook_mut(&mut source).insert(member.to_owned(), json!(canary));
        let failure = parse_project_json(
            &serde_json::to_vec(&source).expect("forbidden deployed source serializes"),
        )
        .expect_err("deployed transport or secret authority is not governed");
        assert_eq!(failure.diagnostics()[0].code, "source.shape.invalid");
        let diagnostic = serde_json::to_string(&failure).expect("failure serializes");
        assert!(!diagnostic.contains(canary));
    }

    let mut source = project_value();
    webhook_mut(&mut source).insert("delivery".to_owned(), json!({"attemptTimeoutMs": 5000}));
    let failure = parse_project_json(&serde_json::to_vec(&source).expect("source serializes"))
        .expect_err("per-event delivery policy is not authored");
    assert_eq!(failure.diagnostics()[0].code, "source.shape.invalid");
}

#[test]
fn webhook_projection_is_closed_and_classification_is_derived() {
    let mut missing = project_value();
    missing["entities"][0]["hooks"][0]
        .as_object_mut()
        .expect("event object")
        .remove("projection");
    let failure = parse_project_json(&serde_json::to_vec(&missing).expect("source serializes"))
        .expect_err("a missing event projection is refused");
    assert_eq!(failure.diagnostics()[0].code, "source.shape.invalid");

    let mut empty = project_value();
    empty["entities"][0]["hooks"][0]["projection"] = json!([]);
    assert_compile_code(&empty, "event.projection.empty");

    let mut unknown = project_value();
    unknown["entities"][0]["hooks"][0]["projection"] = json!(["unknown-field"]);
    assert_compile_code(&unknown, "event.projection.field_unknown");

    let mut restricted = project_value();
    restricted["entities"][0]["hooks"][0]["projection"] = json!(["secret"]);
    restricted["entities"][0]["hooks"][0]
        .as_object_mut()
        .expect("event object")
        .remove("when");
    assert_eq!(
        compile(&restricted)
            .expect("classification follows the projection")
            .event_deliveries()
            .deliveries[0]
            .classification_ceiling,
        Classification::Restricted
    );

    let mut minimized = project_value();
    minimized["entities"][0]["classification"] = json!("restricted");
    minimized["entities"][0]["hooks"][0]["projection"] = json!(["label"]);
    minimized["entities"][0]["hooks"][0]
        .as_object_mut()
        .expect("event object")
        .remove("when");
    let minimized = compile(&minimized)
        .expect("a restricted entity may deliver only explicitly projected public fields");
    assert_eq!(
        minimized.event_deliveries().deliveries[0].projection_fields,
        ["label"]
    );
    assert_eq!(
        minimized.event_deliveries().deliveries[0].classification_ceiling,
        Classification::Public
    );

    let mut condition_observes_restricted = project_value();
    condition_observes_restricted["entities"][0]["hooks"][0]["projection"] = json!(["label"]);
    condition_observes_restricted["entities"][0]["hooks"][0]["when"] = json!({
        "kind": "fields",
        "afterEquals": {"secret": "eligible"}
    });
    assert_eq!(
        compile(&condition_observes_restricted)
            .expect("observable condition classification is compiled")
            .event_deliveries()
            .deliveries[0]
            .classification_ceiling,
        Classification::Restricted,
        "event occurrence must carry the classification of predicate inputs"
    );

    let mut oversized = project_value();
    oversized["entities"][0]["fields"][0]["maxLength"] = json!(300_000);
    assert_compile_code(&oversized, "event.webhook.projection_too_large");

    let mut exact_envelope_boundary = project_value();
    exact_envelope_boundary["entities"][0]["fields"][0] = json!({
        "id": "label",
        "type": "structured",
        "maxBytes": 1_046_234,
        "schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "additionalProperties": false
        },
        "required": true,
        "classification": "public"
    });
    exact_envelope_boundary["entities"][0]["hooks"][0]["projection"] = json!(["label"]);
    exact_envelope_boundary["entities"][0]["hooks"][0]
        .as_object_mut()
        .expect("event object")
        .remove("when");
    assert_eq!(
        compile(&exact_envelope_boundary)
            .expect("a full event body at the transport bound compiles")
            .event_deliveries()
            .deliveries[0]
            .maximum_payload_bytes,
        1_048_576
    );
    exact_envelope_boundary["entities"][0]["fields"][0]["maxBytes"] = json!(1_046_235);
    assert_compile_code(
        &exact_envelope_boundary,
        "event.webhook.projection_too_large",
    );

    let mut exact_transport_mismatch = project_value();
    exact_transport_mismatch["entities"][0]["fields"][0] = json!({
        "id": "label",
        "type": "structured",
        "maxBytes": 1_048_576,
        "schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "additionalProperties": false
        },
        "classification": "public"
    });
    assert_compile_code(
        &exact_transport_mismatch,
        "event.webhook.projection_too_large",
    );

    let mut decimal_quote_boundary = project_value();
    decimal_quote_boundary["entities"][0]["fields"] = json!([{
        "id": "label",
        "type": "structured",
        "maxBytes": 1_048_517,
        "schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "additionalProperties": false
        },
        "classification": "public"
    }, {
        "id": "amount",
        "type": "decimal",
        "precision": 38,
        "scale": 0,
        "classification": "public"
    }]);
    decimal_quote_boundary["entities"][0]["hooks"][0]["projection"] = json!(["amount", "label"]);
    assert_compile_code(
        &decimal_quote_boundary,
        "event.webhook.projection_too_large",
    );

    let mut all_fractional_decimal_boundary = project_value();
    all_fractional_decimal_boundary["entities"][0]["fields"] = json!([{
        "id": "a",
        "type": "structured",
        "maxBytes": 1_048_518,
        "schema": {"type": "string"},
        "required": true,
        "classification": "public"
    }, {
        "id": "amount",
        "type": "decimal",
        "precision": 38,
        "scale": 38,
        "required": true,
        "classification": "public"
    }]);
    all_fractional_decimal_boundary["entities"][0]["hooks"][0]["projection"] =
        json!(["a", "amount"]);
    assert_compile_code(
        &all_fractional_decimal_boundary,
        "event.webhook.projection_too_large",
    );

    let mut optional_null_boundary = project_value();
    optional_null_boundary["entities"][0]["fields"] = json!([{
        "id": "a",
        "type": "structured",
        "maxBytes": 1_048_564,
        "schema": {"type": "string"},
        "required": true,
        "classification": "public"
    }, {
        "id": "b",
        "type": "structured",
        "maxBytes": 1,
        "schema": {"type": "string"},
        "classification": "public"
    }]);
    optional_null_boundary["entities"][0]["hooks"][0]["projection"] = json!(["a", "b"]);
    assert_compile_code(
        &optional_null_boundary,
        "event.webhook.projection_too_large",
    );
}

#[test]
fn field_conditions_are_typed_nonempty_and_trigger_compatible() {
    let mut patched = project_value();
    patched["entities"][0]["hooks"][0]["trigger"] = json!("patched");
    patched["entities"][0]["hooks"][0]["when"] = json!({
        "kind": "fields",
        "changed": ["region"],
        "beforeEquals": {"region": null},
        "afterEquals": {"region": "north"}
    });
    compile(&patched).expect("patched events support all Version 1 field predicates");

    let mut empty = project_value();
    empty["entities"][0]["hooks"][0]["when"] = json!({"kind": "fields"});
    assert_compile_code(&empty, "event.when.empty");

    let mut incompatible_created = project_value();
    incompatible_created["entities"][0]["hooks"][0]["when"] = json!({
        "kind": "fields",
        "changed": ["region"]
    });
    assert_compile_code(&incompatible_created, "event.when.trigger_incompatible");

    let mut incompatible_tombstone = project_value();
    incompatible_tombstone["entities"][0]["hooks"][0]["trigger"] = json!("tombstoned");
    incompatible_tombstone["entities"][0]["hooks"][0]["when"] = json!({
        "kind": "fields",
        "afterEquals": {"region": "north"}
    });
    assert_compile_code(&incompatible_tombstone, "event.when.trigger_incompatible");

    for when in [
        json!({"kind": "fields", "changed": ["unknown"]}),
        json!({"kind": "fields", "beforeEquals": {"unknown": "value"}}),
        json!({"kind": "fields", "afterEquals": {"unknown": "value"}}),
    ] {
        let mut source = patched.clone();
        source["entities"][0]["hooks"][0]["when"] = when;
        assert_compile_code(&source, "event.when.field_unknown");
    }

    let mut wrong_type = patched;
    wrong_type["entities"][0]["hooks"][0]["when"] = json!({
        "kind": "fields",
        "afterEquals": {"region": 7}
    });
    assert_compile_code(&wrong_type, "event.when.value_invalid");

    let mut structured = project_value();
    structured["entities"][0]["hooks"][0]["when"] = json!({
        "kind": "fields",
        "afterEquals": {"region": {"unexpected": true}}
    });
    let failure = parse_project_json(
        &serde_json::to_vec(&structured).expect("structured predicate source serializes"),
    )
    .expect_err("comparison values are scalar or null");
    assert_eq!(failure.diagnostics()[0].code, "source.shape.invalid");
}

#[test]
fn additive_modules_add_nonconflicting_subscriptions_deterministically_and_refuse_conflicts() {
    let mut project_value = project_value();
    project_value["entities"][0]["hooks"] = json!([]);
    let mut project = parse_project(&project_value);
    let module_a = webhook_module("module-a", "created-a", "destination-a");
    let module_b = webhook_module("module-b", "created-b", "destination-b");
    project.modules = vec![module_lock(&module_a), module_lock(&module_b)];

    let first = compile_project(
        &project,
        &[module_a.clone(), module_b.clone()],
        CompileProfile::Authoring,
    )
    .expect("nonconflicting module subscriptions compile");
    let second = compile_project(
        &project,
        &[module_b.clone(), module_a.clone()],
        CompileProfile::Authoring,
    )
    .expect("module input order does not change compilation");
    assert_eq!(first, second);
    assert_eq!(
        first
            .event_deliveries()
            .deliveries
            .iter()
            .map(|delivery| delivery.id.as_str())
            .collect::<Vec<_>>(),
        [
            "events.case.created-a.webhook",
            "events.case.created-b.webhook"
        ]
    );

    let conflicting = webhook_module("module-b", "created-a", "destination-b");
    let mut conflicting_project = project;
    conflicting_project.modules = vec![module_lock(&module_a), module_lock(&conflicting)];
    let failure = compile_project(
        &conflicting_project,
        &[module_a, conflicting],
        CompileProfile::Authoring,
    )
    .expect_err("module subscriptions cannot replace an existing event id");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "extension.event.duplicate"));
}

#[test]
fn event_ids_are_unique_across_entities_for_unambiguous_external_types() {
    let mut source = project_value();
    source["entities"]
        .as_array_mut()
        .expect("entities array")
        .push(json!({
            "id": "appeal",
            "primaryDataset": "test-dataset",
            "route": "appeals",
            "mutationMode": "create_only",
            "fields": [
                {"id": "label", "type": "string", "maxLength": 64, "classification": "public"}
            ],
            "hooks": [{
                "phase": "after",
                "id": "case-created",
                "trigger": "created",
                "projection": ["label"],
                "handler": {"kind":"url","destinationId": "appeal-operations"}
            }]
        }));
    assert_compile_code(&source, "event.id.registry_duplicate");
}

#[test]
fn outbox_only_event_is_authoring_only_and_production_requires_delivery() {
    let mut source = project_value();
    source["entities"][0]["hooks"] = json!([{
        "phase": "after",
        "id": "case-created",
        "trigger": "created",
        "projection": ["label"]
    }]);
    let compiled = compile(&source).expect("outbox-only events remain valid");
    assert!(compiled.event_deliveries().deliveries.is_empty());
    let artifact = compiled
        .artifacts()
        .get("compiled/event-deliveries.json")
        .expect("empty delivery inventory remains explicit");
    assert_eq!(artifact.bytes, br#"{"deliveries":[]}"#);
    assert!(compiled.entities()["case"].hooks["case-created"]
        .handler
        .is_none());

    let failure = compile_project(&parse_project(&source), &[], CompileProfile::Production)
        .expect_err("production has no supported outbox-only consumer API");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "event.delivery.required"));
}

fn webhook_module(id: &str, event_id: &str, destination_id: &str) -> RegistryModule {
    parse_module_json(
        &serde_json::to_vec(&json!({
            "id": id,
            "version": "1",
            "extendEntities": [{
                "entity": "case",
                "hooks": [{
                    "phase": "after",
                    "id": event_id,
                    "trigger": "created",
                    "projection": ["label"],
                    "handler": {
                        "kind": "url",
                        "destinationId": destination_id
                    }
                }]
            }]
        }))
        .expect("module serializes"),
    )
    .expect("module parses")
}

fn module_lock(module: &RegistryModule) -> ModuleLockSource {
    ModuleLockSource {
        id: module.id.clone(),
        version: module.version.clone(),
        digest: Some(module_digest(module)),
    }
}

#[test]
fn non_apply_lifecycle_payload_bounds_exclude_impossible_application_text() {
    let mut source = change_request_event_project();
    let request = &mut source["entities"][2];
    request["hooks"][0]["projection"] = json!(["reason"]);
    request["fields"][2]["maxLength"] = json!(173_000);
    for condition in [
        json!({"kind":"request_lifecycle", "transitions":["cancel"]}),
        json!({"kind":"request_lifecycle", "toStates":["cancelled"]}),
    ] {
        source["entities"][2]["hooks"][0]["when"] = condition;
        let compiled = compile(&source).expect("non-apply payload fits the webhook limit");
        let delivery = compiled
            .event_deliveries()
            .deliveries
            .iter()
            .find(|delivery| delivery.event_id == "request-lifecycle")
            .unwrap();
        assert!(delivery.maximum_payload_bytes < 1_048_576);
    }
    source["entities"][2]["hooks"][0]["when"] =
        json!({"kind":"request_lifecycle", "transitions":["apply"]});
    assert_compile_code(&source, "event.webhook.projection_too_large");
}

/// The envelope wrapper one hook of `project_value` produces.
///
/// 584 bytes are fixed for every hook: the canonical object punctuation of the
/// eight envelope members, the `causation` object with a parent, a quoted
/// UUID `id`, the fixed parts of `dataschema` and `source` with their digests
/// and a 64 byte instance id, the `subject` object, and the quoted UTC
/// millisecond `time`. The rest scales with the identifiers this project
/// declares: the registry id appears in both `dataschema` and `source`, the
/// entity id once in `dataschema`, and the hook id in both `dataschema` and
/// `type`.
const ENVELOPE_WRAPPER_BYTES: u32 = 584
    + 2 * "webhook-contract".len() as u32
    + "case".len() as u32
    + 2 * "case-created".len() as u32;

/// The data object worst case that exactly fills the transport bound, so a
/// project sized to it proves what the payload bound is measured over.
const DATA_OBJECT_AT_THE_TRANSPORT_BOUND: u32 = 1_046_878;

fn structured_label(maximum_bytes: u32) -> Value {
    json!({
        "id": "label",
        "type": "structured",
        "maxBytes": maximum_bytes,
        "schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "additionalProperties": false
        },
        "required": true,
        "classification": "public"
    })
}

/// The compiled payload proof measures the canonical envelope the runtime
/// stores and delivers, not the `data` object it carries.
///
/// Before the envelope commits the two measured different documents, so a
/// project could compile and then have a capture refused inside the record
/// transaction that produced it.
#[test]
fn the_compiled_payload_proof_measures_envelope_bytes_not_data_bytes() {
    let mut data_object_at_the_bound = project_value();
    data_object_at_the_bound["entities"][0]["fields"][0] =
        structured_label(DATA_OBJECT_AT_THE_TRANSPORT_BOUND);
    data_object_at_the_bound["entities"][0]["hooks"][0]["projection"] = json!(["label"]);
    data_object_at_the_bound["entities"][0]["hooks"][0]
        .as_object_mut()
        .expect("event object")
        .remove("when");
    assert_compile_code(
        &data_object_at_the_bound,
        "event.webhook.projection_too_large",
    );

    let mut envelope_at_the_bound = data_object_at_the_bound.clone();
    envelope_at_the_bound["entities"][0]["fields"][0] =
        structured_label(DATA_OBJECT_AT_THE_TRANSPORT_BOUND - ENVELOPE_WRAPPER_BYTES);
    assert_eq!(
        compile(&envelope_at_the_bound)
            .expect("an envelope at the transport bound compiles")
            .event_deliveries()
            .deliveries[0]
            .maximum_payload_bytes,
        1_048_576
    );

    let mut envelope_one_byte_over = envelope_at_the_bound;
    envelope_one_byte_over["entities"][0]["fields"][0] =
        structured_label(DATA_OBJECT_AT_THE_TRANSPORT_BOUND - ENVELOPE_WRAPPER_BYTES + 1);
    assert_compile_code(
        &envelope_one_byte_over,
        "event.webhook.projection_too_large",
    );
}

/// The request lifecycle trigger carries its own larger data object and the
/// same envelope wrapper, so its proof grows by the wrapper too.
#[test]
fn the_request_lifecycle_payload_proof_carries_the_same_envelope_wrapper() {
    let source = change_request_event_project();
    let compiled = compile(&source).expect("the lifecycle acceptance project compiles");
    let delivery = compiled
        .event_deliveries()
        .deliveries
        .iter()
        .find(|delivery| delivery.event_id == "request-lifecycle")
        .expect("the lifecycle hook compiles a delivery");
    // The lifecycle data object worst case, plus the wrapper this project's
    // identifiers produce.
    const LIFECYCLE_DATA_OBJECT_BYTES: u32 = 33_205;
    const LIFECYCLE_WRAPPER_BYTES: u32 = 584
        + 2 * "request-events".len() as u32
        + "placement-correction-request".len() as u32
        + 2 * "request-lifecycle".len() as u32;
    assert_eq!(
        delivery.maximum_payload_bytes,
        LIFECYCLE_DATA_OBJECT_BYTES + LIFECYCLE_WRAPPER_BYTES
    );
}
