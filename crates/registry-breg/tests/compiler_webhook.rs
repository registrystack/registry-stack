// SPDX-License-Identifier: Apache-2.0

use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{
    parse_module_json, parse_project_json, parse_project_yaml, Classification,
    HookAuthenticationProfile, HookDeadLetterMode, ModuleLockSource, RegistryModule,
    RegistryProject,
};
use registry_breg::diagnostics::CompileFailure;
use registry_breg::model::{CompiledHookDeliveryMode, CompiledHookRetryProfile};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde_json::{json, Value};

fn project_value() -> Value {
    json!({"datasets":[{"id": "test-dataset"}],
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {"id": "webhook-contract", "version": "1", "defaultLanguage": "en",
                     "canonicalBaseIri": "https://webhook-contract.example.test"},
        "recordTypes": [{
            "id": "case",
            "primaryDataset": "test-dataset",
            "route": "cases",
            "mutationMode": "mutable",
            "tombstone": true,
            "classification": "internal",
            "fields": [
                {"id": "label", "type": "string", "maximumLength": 64, "classification": "public"},
                {"id": "region", "type": "string", "maximumLength": 32, "classification": "internal"},
                {"id": "secret", "type": "string", "maximumLength": 64, "classification": "restricted"}
            ],
            "hooks": [{
                "phase": "after",
                "id": "case-created",
                "trigger": "created",
                "projection": ["label", "region"],
                "when": {
                    "type": "fields",
                    "afterEquals": {"region": "north"}
                },
                "handler": {
                    "type": "url",
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
    let failure = compile(value).expect_err("invalid hook contract is refused");
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
    value["recordTypes"][0]["hooks"][0]["handler"]
        .as_object_mut()
        .expect("hook object")
}

#[test]
fn governed_webhook_compiles_to_deterministic_destination_neutral_inventory() {
    let source = project_value();
    let first = compile(&source).expect("governed hook compiles");
    let second = compile(&source).expect("same governed hook compiles twice");
    assert_eq!(first, second);

    let inventory = first.event_deliveries();
    assert_eq!(inventory.deliveries.len(), 1);
    let delivery = &inventory.deliveries[0];
    assert_eq!(delivery.id, "events.case.case-created.webhook");
    assert!(
        matches!(&delivery.owner,registry_breg::model::CompiledEventOwner::RecordType {record_type,..} if record_type == "case")
    );
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
        HookAuthenticationProfile::HmacSha256V1
    );
    assert_eq!(
        delivery.delivery_mode,
        CompiledHookDeliveryMode::AfterCommit
    );
    assert_eq!(delivery.retry_profile, CompiledHookRetryProfile::RegistryV1);
    assert_eq!(delivery.attempt_timeout_ms, 5000);
    assert_eq!(delivery.initial_backoff_ms, 1000);
    assert_eq!(delivery.maximum_backoff_ms, 8000);
    assert_eq!(delivery.maximum_attempts, 5);
    assert_eq!(delivery.exponential_backoff_multiplier, 2);
    assert_eq!(delivery.retry_delays_ms, [1000, 2000, 4000, 8000]);
    // The data object's worst case plus the envelope wrapper this project's
    // identifiers produce: 2292 + 644. The recordType key adds four bytes to data.
    assert_eq!(delivery.maximum_payload_bytes, 2936);
    assert_eq!(delivery.dead_letter, HookDeadLetterMode::Required);
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
fn destination_auth_delivery_and_deployed_members_are_closed_and_value_free() {
    for destination in ["", "HTTPS://deployed.example/hook", "Uppercase", "bad.dot"] {
        let mut source = project_value();
        webhook_mut(&mut source).insert("destinationId".to_owned(), json!(destination));
        let failure = compile(&source).expect_err("invalid logical destination is refused");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "breg.event.hook-destination-invalid"));
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
        ("authenticationProfile", "hmac-sha256-v1"),
    ] {
        let mut source = project_value();
        webhook_mut(&mut source).insert(member.to_owned(), json!(canary));
        let failure = parse_project_json(
            &serde_json::to_vec(&source).expect("forbidden deployed source serializes"),
        )
        .expect_err("deployed transport or secret authority is not governed");
        assert_eq!(failure.diagnostics()[0].code, "config.unknown-key");
        let diagnostic = serde_json::to_string(&failure).expect("failure serializes");
        assert!(!diagnostic.contains(canary));
    }

    let mut source = project_value();
    webhook_mut(&mut source).insert("delivery".to_owned(), json!({"attemptTimeoutMs": 5000}));
    let failure = parse_project_json(&serde_json::to_vec(&source).expect("source serializes"))
        .expect_err("per-event delivery policy is not authored");
    assert_eq!(failure.diagnostics()[0].code, "config.unknown-key");
}

#[test]
fn webhook_projection_is_closed_and_classification_is_derived() {
    let mut missing = project_value();
    missing["recordTypes"][0]["hooks"][0]
        .as_object_mut()
        .expect("event object")
        .remove("projection");
    let failure = parse_project_json(&serde_json::to_vec(&missing).expect("source serializes"))
        .expect_err("a missing event projection is refused");
    assert_eq!(failure.diagnostics()[0].code, "config.missing-key");

    let mut empty = project_value();
    empty["recordTypes"][0]["hooks"][0]["projection"] = json!([]);
    assert_compile_code(&empty, "breg.event.projection-empty");

    let mut unknown = project_value();
    unknown["recordTypes"][0]["hooks"][0]["projection"] = json!(["unknown-field"]);
    assert_compile_code(&unknown, "breg.event.projection-field-unknown");

    let mut restricted = project_value();
    restricted["recordTypes"][0]["hooks"][0]["projection"] = json!(["secret"]);
    restricted["recordTypes"][0]["hooks"][0]
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
    minimized["recordTypes"][0]["classification"] = json!("restricted");
    minimized["recordTypes"][0]["hooks"][0]["projection"] = json!(["label"]);
    minimized["recordTypes"][0]["hooks"][0]
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
    condition_observes_restricted["recordTypes"][0]["hooks"][0]["projection"] = json!(["label"]);
    condition_observes_restricted["recordTypes"][0]["hooks"][0]["when"] = json!({
        "type": "fields",
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
    oversized["recordTypes"][0]["fields"][0]["maximumLength"] = json!(300_000);
    assert_compile_code(&oversized, "breg.event.hook-projection-too-large");

    let mut exact_envelope_boundary = project_value();
    exact_envelope_boundary["recordTypes"][0]["fields"][0] = json!({
        "id": "label",
        "type": "structured",
        "maximumBytes": 1_046_230,
        "schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "additionalProperties": false
        },
        "required": true,
        "classification": "public"
    });
    exact_envelope_boundary["recordTypes"][0]["hooks"][0]["projection"] = json!(["label"]);
    exact_envelope_boundary["recordTypes"][0]["hooks"][0]
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
    exact_envelope_boundary["recordTypes"][0]["fields"][0]["maximumBytes"] = json!(1_046_231);
    assert_compile_code(
        &exact_envelope_boundary,
        "breg.event.hook-projection-too-large",
    );

    let mut exact_transport_mismatch = project_value();
    exact_transport_mismatch["recordTypes"][0]["fields"][0] = json!({
        "id": "label",
        "type": "structured",
        "maximumBytes": 1_048_576,
        "schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "additionalProperties": false
        },
        "classification": "public"
    });
    assert_compile_code(
        &exact_transport_mismatch,
        "breg.event.hook-projection-too-large",
    );

    let mut decimal_quote_boundary = project_value();
    decimal_quote_boundary["recordTypes"][0]["fields"] = json!([{
        "id": "label",
        "type": "structured",
        "maximumBytes": 1_048_517,
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
    decimal_quote_boundary["recordTypes"][0]["hooks"][0]["projection"] = json!(["amount", "label"]);
    assert_compile_code(
        &decimal_quote_boundary,
        "breg.event.hook-projection-too-large",
    );

    let mut all_fractional_decimal_boundary = project_value();
    all_fractional_decimal_boundary["recordTypes"][0]["fields"] = json!([{
        "id": "a",
        "type": "structured",
        "maximumBytes": 1_048_518,
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
    all_fractional_decimal_boundary["recordTypes"][0]["hooks"][0]["projection"] =
        json!(["a", "amount"]);
    assert_compile_code(
        &all_fractional_decimal_boundary,
        "breg.event.hook-projection-too-large",
    );

    let mut optional_null_boundary = project_value();
    optional_null_boundary["recordTypes"][0]["fields"] = json!([{
        "id": "a",
        "type": "structured",
        "maximumBytes": 1_048_564,
        "schema": {"type": "string"},
        "required": true,
        "classification": "public"
    }, {
        "id": "b",
        "type": "structured",
        "maximumBytes": 1,
        "schema": {"type": "string"},
        "classification": "public"
    }]);
    optional_null_boundary["recordTypes"][0]["hooks"][0]["projection"] = json!(["a", "b"]);
    assert_compile_code(
        &optional_null_boundary,
        "breg.event.hook-projection-too-large",
    );
}

#[test]
fn field_conditions_are_typed_nonempty_and_trigger_compatible() {
    let mut patched = project_value();
    patched["recordTypes"][0]["hooks"][0]["trigger"] = json!("patched");
    patched["recordTypes"][0]["hooks"][0]["when"] = json!({
        "type": "fields",
        "changed": ["region"],
        "beforeIsNull": ["region"],
        "afterEquals": {"region": "north"}
    });
    compile(&patched).expect("patched events support all Version 1 field predicates");
    // An unset value is stated with `beforeIsNull` or `afterIsNull`; `null`
    // is never a comparison literal (CFG-EMPTY-1).
    assert_eq!(
        parse_project_yaml(&serde_json::to_vec(&patched).expect("test project serializes"))
            .expect("the reader accepts beforeIsNull"),
        parse_project(&patched)
    );
    for member in ["beforeEquals", "afterEquals"] {
        let mut null_literal = patched.clone();
        null_literal["recordTypes"][0]["hooks"][0]["when"] =
            json!({"type": "fields", member: {"region": null}});
        let refused = parse_project_yaml(
            &serde_json::to_vec(&null_literal).expect("test project serializes"),
        )
        .expect_err("a null comparison literal is refused");
        assert!(
            format!("{refused:?}").contains("config.null-value"),
            "{member}: {refused:?}"
        );
    }
    for (trigger, member) in [("created", "beforeIsNull"), ("tombstoned", "afterIsNull")] {
        let mut incompatible = project_value();
        incompatible["recordTypes"][0]["hooks"][0]["trigger"] = json!(trigger);
        incompatible["recordTypes"][0]["hooks"][0]["when"] =
            json!({"type": "fields", member: ["region"]});
        assert_compile_code(&incompatible, "breg.event.when-trigger-incompatible");
    }
    for member in ["beforeIsNull", "afterIsNull"] {
        let mut unknown = patched.clone();
        unknown["recordTypes"][0]["hooks"][0]["when"] =
            json!({"type": "fields", member: ["unknown"]});
        assert_compile_code(&unknown, "breg.event.when-field-unknown");
    }

    let mut empty = project_value();
    empty["recordTypes"][0]["hooks"][0]["when"] = json!({"type": "fields"});
    assert_compile_code(&empty, "breg.event.when-empty");

    let mut incompatible_created = project_value();
    incompatible_created["recordTypes"][0]["hooks"][0]["when"] = json!({
        "type": "fields",
        "changed": ["region"]
    });
    assert_compile_code(
        &incompatible_created,
        "breg.event.when-trigger-incompatible",
    );

    let mut incompatible_tombstone = project_value();
    incompatible_tombstone["recordTypes"][0]["hooks"][0]["trigger"] = json!("tombstoned");
    incompatible_tombstone["recordTypes"][0]["hooks"][0]["when"] = json!({
        "type": "fields",
        "afterEquals": {"region": "north"}
    });
    assert_compile_code(
        &incompatible_tombstone,
        "breg.event.when-trigger-incompatible",
    );

    for when in [
        json!({"type": "fields", "changed": ["unknown"]}),
        json!({"type": "fields", "beforeEquals": {"unknown": "value"}}),
        json!({"type": "fields", "afterEquals": {"unknown": "value"}}),
    ] {
        let mut source = patched.clone();
        source["recordTypes"][0]["hooks"][0]["when"] = when;
        assert_compile_code(&source, "breg.event.when-field-unknown");
    }

    let mut wrong_type = patched;
    wrong_type["recordTypes"][0]["hooks"][0]["when"] = json!({
        "type": "fields",
        "afterEquals": {"region": 7}
    });
    assert_compile_code(&wrong_type, "breg.event.when-value-invalid");

    let mut structured = project_value();
    structured["recordTypes"][0]["hooks"][0]["when"] = json!({
        "type": "fields",
        "afterEquals": {"region": {"unexpected": true}}
    });
    let failure = parse_project_json(
        &serde_json::to_vec(&structured).expect("structured predicate source serializes"),
    )
    .expect_err("comparison values are scalar or null");
    assert_eq!(failure.diagnostics()[0].code, "config.invalid-type");
    let failure = parse_project_yaml(
        &serde_json::to_vec(&structured).expect("structured predicate source serializes"),
    )
    .expect_err("the reader refuses a mapping as a comparison literal");
    assert_eq!(failure.diagnostics()[0].code, "config.invalid-type");
    assert_eq!(
        failure.diagnostics()[0].path,
        "project.recordTypes[0].hooks[0].when.afterEquals.region"
    );
}

#[test]
fn additive_modules_add_nonconflicting_subscriptions_deterministically_and_refuse_conflicts() {
    let mut project_value = project_value();
    project_value["recordTypes"][0]["hooks"] = json!([]);
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
        .any(|diagnostic| diagnostic.code == "breg.extension.event-duplicate"));
}

#[test]
fn event_ids_are_unique_across_entities_for_unambiguous_external_types() {
    let mut source = project_value();
    source["recordTypes"]
        .as_array_mut()
        .expect("entities array")
        .push(json!({
            "id": "appeal",
            "primaryDataset": "test-dataset",
            "route": "appeals",
            "mutationMode": "create-only",
            "fields": [
                {"id": "label", "type": "string", "maximumLength": 64, "classification": "public"}
            ],
            "hooks": [{
                "phase": "after",
                "id": "case-created",
                "trigger": "created",
                "projection": ["label"],
                "handler": {"type":"url","destinationId": "appeal-operations"}
            }]
        }));
    assert_compile_code(&source, "breg.event.id-registry-duplicate");
}

#[test]
fn outbox_only_event_is_authoring_only_and_production_requires_delivery() {
    let mut source = project_value();
    source["recordTypes"][0]["hooks"] = json!([{
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
        .any(|diagnostic| diagnostic.code == "breg.event.delivery-required"));
}

fn webhook_module(id: &str, event_id: &str, destination_id: &str) -> RegistryModule {
    parse_module_json(
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule",
            "id": id,
            "version": "1",
            "extendRecordTypes": [{
                "recordType": "case",
                "hooks": [{
                    "phase": "after",
                    "id": event_id,
                    "trigger": "created",
                    "projection": ["label"],
                    "handler": {
                        "type": "url",
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

const ENVELOPE_WRAPPER_BYTES: u32 = 584
    + 2 * "webhook-contract".len() as u32
    + "case".len() as u32
    + 2 * "case-created".len() as u32;
// The recordType key uses four more bytes than the former entity key.
const DATA_OBJECT_AT_THE_TRANSPORT_BOUND: u32 = 1_046_874;

fn structured_label(maximum_bytes: u32) -> Value {
    json!({
        "id": "label",
        "type": "structured",
        "maximumBytes": maximum_bytes,
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
    data_object_at_the_bound["recordTypes"][0]["fields"][0] =
        structured_label(DATA_OBJECT_AT_THE_TRANSPORT_BOUND);
    data_object_at_the_bound["recordTypes"][0]["hooks"][0]["projection"] = json!(["label"]);
    data_object_at_the_bound["recordTypes"][0]["hooks"][0]
        .as_object_mut()
        .expect("event object")
        .remove("when");
    assert_compile_code(
        &data_object_at_the_bound,
        "breg.event.hook-projection-too-large",
    );

    let mut envelope_at_the_bound = data_object_at_the_bound.clone();
    envelope_at_the_bound["recordTypes"][0]["fields"][0] =
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
    envelope_one_byte_over["recordTypes"][0]["fields"][0] =
        structured_label(DATA_OBJECT_AT_THE_TRANSPORT_BOUND - ENVELOPE_WRAPPER_BYTES + 1);
    assert_compile_code(
        &envelope_one_byte_over,
        "breg.event.hook-projection-too-large",
    );
}
