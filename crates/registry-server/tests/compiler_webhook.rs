// SPDX-License-Identifier: Apache-2.0

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_server::compiler::{compile_project, module_digest, CompileProfile};
use registry_server::contract::{
    parse_module_json, parse_project_json, Classification, EventTrigger, ModuleLockSource,
    RegistryModule, RegistryProject, WebhookAuthenticationProfile, WebhookDeadLetterMode,
};
use registry_server::diagnostics::CompileFailure;
use registry_server::model::{CompiledWebhookDeliveryMode, CompiledWebhookRetryProfile};
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
            "events": [{
                "id": "case-created",
                "trigger": "created",
                "projection": ["label", "region"],
                "when": {
                    "kind": "fields",
                    "afterEquals": {"region": "north"}
                },
                "webhook": {
                    "destinationId": "case-operations"
                }
            }, {
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

fn compile(value: &Value) -> Result<registry_server::CompiledRegistry, CompileFailure> {
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
            "events":[{
                "id":"request-lifecycle",
                "trigger":"request_lifecycle",
                "projection":["proposed-site","reason"],
                "webhook":{"destinationId":"review-operations"}
            }],
            "changeRequest":{
                "effects":[{
                    "target":{"fromField":"placement"},
                    "operation":"patch",
                    "set":{"site":{"fromField":"proposed-site"}}
                }],
                "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
            }
        }],
        "accessProfiles":[{
            "id":"submitter",
            "default":true,
            "principalClaim":"registry_principal",
            "grants":[{
                "entity":"placement-correction-request",
                "operations":["create","get","list","patch","submit_request","revise_request","cancel_request"],
                "readableFields":["placement","proposed-site","reason"],
                "writableFields":["placement","proposed-site","reason"]
            }]
        },{
            "id":"reviewer",
            "principalClaim":"registry_principal",
            "grants":[{
                "entity":"placement-correction-request",
                "operations":["get","list","approve_request","reject_request","request_revision"],
                "readableFields":["placement","proposed-site","reason"],
                "reviewStages":[{
                    "stage":"review",
                    "targets":[{"entity":"asset-placement","readableFields":["site"],"rowBoundaries":[]}]
                }]
            }]
        },{
            "id":"applier",
            "principalClaim":"registry_principal",
            "grants":[{
                "entity":"placement-correction-request",
                "operations":["get","list","apply_request"],
                "readableFields":["placement","proposed-site","reason"],
                "applyTargets":[{"entity":"asset-placement","rowBoundaries":[]}]
            }]
        }]
    })
}

fn webhook_mut(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    value["entities"][0]["events"][0]["webhook"]
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
    assert_eq!(delivery.destination_id, "case-operations");
    assert_eq!(delivery.projection_fields, ["label", "region"]);
    assert_eq!(delivery.classification_ceiling, Classification::Internal);
    assert!(delivery.when.is_some());
    assert!(delivery.data_schema.starts_with(
        "urn:registry-server:event-schema:webhook-contract:case:case-created:sha256:"
    ));
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
    assert_eq!(delivery.maximum_payload_bytes, 2288);
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
    assert!(entity.events["case-created"].webhook.is_some());
    assert!(entity.events["case-patched-outbox"].webhook.is_none());
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
        "urn:registry-server:event-schema:request-events:placement-correction-request:request-lifecycle:sha256:"
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
            "stage",
            "effectDigest",
            "deduplicationKey"
        ])
    );
}

#[test]
fn lifecycle_events_are_request_only_and_use_closed_lifecycle_conditions() {
    let mut non_request = project_value();
    non_request["entities"][0]["events"][0]["trigger"] = json!("request_lifecycle");
    assert_compile_code(
        &non_request,
        "event.trigger.request_lifecycle_requires_change_request",
    );

    let mut field_condition = change_request_event_project();
    field_condition["entities"][2]["events"][0]["when"] =
        json!({"kind":"fields","afterEquals":{"reason":"notify"}});
    assert_compile_code(&field_condition, "event.when.trigger_incompatible");

    let mut lifecycle_condition = change_request_event_project();
    lifecycle_condition["entities"][2]["events"][0]["when"] = json!({
        "kind":"request_lifecycle",
        "transitions":["approve"],
        "toStates":["approved"],
        "stages":["review"]
    });
    compile(&lifecycle_condition).expect("closed lifecycle condition compiles");

    let mut bad_transition = lifecycle_condition.clone();
    bad_transition["entities"][2]["events"][0]["when"]["transitions"] = json!(["callback_granted"]);
    assert_compile_code(
        &bad_transition,
        "event.when.request_lifecycle_transition_unknown",
    );
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
    missing["entities"][0]["events"][0]
        .as_object_mut()
        .expect("event object")
        .remove("projection");
    let failure = parse_project_json(&serde_json::to_vec(&missing).expect("source serializes"))
        .expect_err("a missing event projection is refused");
    assert_eq!(failure.diagnostics()[0].code, "source.shape.invalid");

    let mut empty = project_value();
    empty["entities"][0]["events"][0]["projection"] = json!([]);
    assert_compile_code(&empty, "event.projection.empty");

    let mut unknown = project_value();
    unknown["entities"][0]["events"][0]["projection"] = json!(["unknown-field"]);
    assert_compile_code(&unknown, "event.projection.field_unknown");

    let mut restricted = project_value();
    restricted["entities"][0]["events"][0]["projection"] = json!(["secret"]);
    restricted["entities"][0]["events"][0]
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
    minimized["entities"][0]["events"][0]["projection"] = json!(["label"]);
    minimized["entities"][0]["events"][0]
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
    condition_observes_restricted["entities"][0]["events"][0]["projection"] = json!(["label"]);
    condition_observes_restricted["entities"][0]["events"][0]["when"] = json!({
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
        "maxBytes": 1_046_878,
        "schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "additionalProperties": false
        },
        "required": true,
        "classification": "public"
    });
    exact_envelope_boundary["entities"][0]["events"][0]["projection"] = json!(["label"]);
    exact_envelope_boundary["entities"][0]["events"][0]
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
    exact_envelope_boundary["entities"][0]["fields"][0]["maxBytes"] = json!(1_046_879);
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
    decimal_quote_boundary["entities"][0]["events"][0]["projection"] = json!(["amount", "label"]);
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
    all_fractional_decimal_boundary["entities"][0]["events"][0]["projection"] =
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
    optional_null_boundary["entities"][0]["events"][0]["projection"] = json!(["a", "b"]);
    assert_compile_code(
        &optional_null_boundary,
        "event.webhook.projection_too_large",
    );
}

#[test]
fn field_conditions_are_typed_nonempty_and_trigger_compatible() {
    let mut patched = project_value();
    patched["entities"][0]["events"][0]["trigger"] = json!("patched");
    patched["entities"][0]["events"][0]["when"] = json!({
        "kind": "fields",
        "changed": ["region"],
        "beforeEquals": {"region": null},
        "afterEquals": {"region": "north"}
    });
    compile(&patched).expect("patched events support all Version 1 field predicates");

    let mut empty = project_value();
    empty["entities"][0]["events"][0]["when"] = json!({"kind": "fields"});
    assert_compile_code(&empty, "event.when.empty");

    let mut incompatible_created = project_value();
    incompatible_created["entities"][0]["events"][0]["when"] = json!({
        "kind": "fields",
        "changed": ["region"]
    });
    assert_compile_code(&incompatible_created, "event.when.trigger_incompatible");

    let mut incompatible_tombstone = project_value();
    incompatible_tombstone["entities"][0]["events"][0]["trigger"] = json!("tombstoned");
    incompatible_tombstone["entities"][0]["events"][0]["when"] = json!({
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
        source["entities"][0]["events"][0]["when"] = when;
        assert_compile_code(&source, "event.when.field_unknown");
    }

    let mut wrong_type = patched;
    wrong_type["entities"][0]["events"][0]["when"] = json!({
        "kind": "fields",
        "afterEquals": {"region": 7}
    });
    assert_compile_code(&wrong_type, "event.when.value_invalid");

    let mut structured = project_value();
    structured["entities"][0]["events"][0]["when"] = json!({
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
    project_value["entities"][0]["events"] = json!([]);
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
            "events": [{
                "id": "case-created",
                "trigger": "created",
                "projection": ["label"],
                "webhook": {"destinationId": "appeal-operations"}
            }]
        }));
    assert_compile_code(&source, "event.id.registry_duplicate");
}

#[test]
fn outbox_only_event_is_authoring_only_and_production_requires_delivery() {
    let mut source = project_value();
    source["entities"][0]["events"] = json!([{
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
    assert!(compiled.entities()["case"].events["case-created"]
        .webhook
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
                "events": [{
                    "id": event_id,
                    "trigger": "created",
                    "projection": ["label"],
                    "webhook": {
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
