// SPDX-License-Identifier: Apache-2.0

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_server::compiler::{compile_project, module_digest, CompileProfile};
use registry_server::contract::{
    parse_module_json, parse_project_json, ModuleLockSource, RegistryModule, RegistryProject,
    WebhookAuthenticationProfile, WebhookDeadLetterMode,
};
use registry_server::diagnostics::CompileFailure;
use registry_server::model::CompiledWebhookDeliveryMode;
use serde_json::{json, Value};

fn project_value() -> Value {
    json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {"id": "webhook-contract", "version": "1", "defaultLanguage": "en"},
        "entities": [{
            "id": "case",
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
                "webhook": {
                    "destinationId": "case-operations",
                    "classificationCeiling": "internal",
                    "authenticationProfile": "hmac_sha256_v1",
                    "delivery": {
                        "attemptTimeoutMs": 5000,
                        "initialBackoffMs": 250,
                        "maximumBackoffMs": 2000,
                        "maximumAttempts": 5,
                        "deadLetter": "required",
                        "operatorReplay": false
                    }
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

fn webhook_mut(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    value["entities"][0]["events"][0]["webhook"]
        .as_object_mut()
        .expect("webhook object")
}

fn delivery_mut(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    webhook_mut(value)["delivery"]
        .as_object_mut()
        .expect("delivery object")
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
    assert_eq!(
        delivery.authentication_profile,
        WebhookAuthenticationProfile::HmacSha256V1
    );
    assert_eq!(
        delivery.delivery_mode,
        CompiledWebhookDeliveryMode::AfterCommit
    );
    assert_eq!(delivery.exponential_backoff_multiplier, 2);
    assert_eq!(delivery.retry_delays_ms, [250, 500, 1000, 2000]);
    assert_eq!(delivery.maximum_payload_bytes, 600);
    assert_eq!(delivery.dead_letter, WebhookDeadLetterMode::Required);
    assert!(!delivery.operator_replay);

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
    let text = String::from_utf8(artifact.bytes.clone()).expect("artifact is UTF-8");
    for forbidden in ["http://", "https://", "secret", "tls", "certificate"] {
        assert!(!text.to_ascii_lowercase().contains(forbidden));
    }

    let entity = &first.entities()["case"];
    assert!(entity.events["case-created"].webhook.is_some());
    assert!(entity.events["case-patched-outbox"].webhook.is_none());
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

    for (path, value) in [
        ("authenticationProfile", "bearer_token"),
        ("delivery.mode", "before_commit"),
    ] {
        let mut source = project_value();
        if path == "authenticationProfile" {
            webhook_mut(&mut source).insert(path.to_owned(), json!(value));
        } else {
            delivery_mut(&mut source).insert("mode".to_owned(), json!(value));
        }
        let failure = parse_project_json(
            &serde_json::to_vec(&source).expect("unsupported profile source serializes"),
        )
        .expect_err("unsupported closed mode is refused during strict parse");
        assert_eq!(failure.diagnostics()[0].code, "source.shape.invalid");
        assert!(!serde_json::to_string(&failure)
            .expect("failure serializes")
            .contains(value));
    }

    for (member, canary) in [
        ("destinationUrl", "https://deployed.example/webhook-canary"),
        ("secret", "raw-webhook-secret-canary"),
        ("tlsCertificate", "raw-tls-certificate-canary"),
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
}

#[test]
fn webhook_projection_and_classification_ceiling_are_closed() {
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

    let mut projected_above_ceiling = project_value();
    projected_above_ceiling["entities"][0]["events"][0]["projection"] = json!(["secret"]);
    assert_compile_code(
        &projected_above_ceiling,
        "event.webhook.classification_ceiling.underdeclared",
    );

    let mut minimized = project_value();
    minimized["entities"][0]["classification"] = json!("restricted");
    minimized["entities"][0]["events"][0]["projection"] = json!(["label"]);
    minimized["entities"][0]["events"][0]["webhook"]["classificationCeiling"] = json!("public");
    let minimized = compile(&minimized)
        .expect("a restricted entity may deliver only explicitly projected public fields");
    assert_eq!(
        minimized.event_deliveries().deliveries[0].projection_fields,
        ["label"]
    );

    let mut oversized = project_value();
    oversized["entities"][0]["fields"][0]["maxLength"] = json!(300_000);
    assert_compile_code(&oversized, "event.webhook.projection_too_large");

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
fn webhook_timeout_backoff_attempt_and_dead_letter_bounds_are_closed() {
    for (member, value, code) in [
        ("attemptTimeoutMs", 0_u32, "event.webhook.timeout.invalid"),
        ("attemptTimeoutMs", 10_001, "event.webhook.timeout.invalid"),
        ("initialBackoffMs", 0, "event.webhook.backoff.invalid"),
        (
            "maximumBackoffMs",
            3_600_001,
            "event.webhook.backoff.invalid",
        ),
        ("maximumAttempts", 0, "event.webhook.attempts.invalid"),
        ("maximumAttempts", 21, "event.webhook.attempts.invalid"),
    ] {
        let mut source = project_value();
        delivery_mut(&mut source).insert(member.to_owned(), json!(value));
        assert_compile_code(&source, code);
    }

    let mut incoherent = project_value();
    delivery_mut(&mut incoherent).insert("initialBackoffMs".to_owned(), json!(2001));
    assert_compile_code(&incoherent, "event.webhook.backoff.invalid");

    let mut missing_dead_letter = project_value();
    delivery_mut(&mut missing_dead_letter).remove("deadLetter");
    assert_compile_code(&missing_dead_letter, "event.webhook.dead_letter.required");

    let mut missing_replay = project_value();
    delivery_mut(&mut missing_replay).remove("operatorReplay");
    let failure = parse_project_json(
        &serde_json::to_vec(&missing_replay).expect("missing replay source serializes"),
    )
    .expect_err("operator replay permission must be explicit");
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
fn outbox_only_event_compatibility_emits_an_empty_delivery_inventory() {
    let mut source = project_value();
    source["entities"][0]["events"][0]
        .as_object_mut()
        .expect("event object")
        .remove("webhook");
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
                        "destinationId": destination_id,
                        "classificationCeiling": "internal",
                        "authenticationProfile": "hmac_sha256_v1",
                        "delivery": {
                            "attemptTimeoutMs": 1000,
                            "initialBackoffMs": 100,
                            "maximumBackoffMs": 1000,
                            "maximumAttempts": 3,
                            "deadLetter": "required",
                            "operatorReplay": true
                        }
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
