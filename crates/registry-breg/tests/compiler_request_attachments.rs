// SPDX-License-Identifier: Apache-2.0

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_project_json, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_SLOTS};
use registry_breg::diagnostics::CompileFailure;
use registry_breg::CompiledRegistry;
use serde_json::{json, Value};

fn source() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1",
        "kind":"RegistryProject",
        "registry":{"id":"attachment-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
        "entities":[{
            "id":"item","primaryDataset":"test-dataset","route":"items","mutationMode":"mutable",
            "changeControl":{"requiredFor":["patch"]},
            "fields":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}]
        },{
            "id":"request","primaryDataset":"test-dataset","route":"requests","mutationMode":"mutable",
            "fields":[
                {"id":"item","type":"reference","target":"item","required":true,"classification":"internal"},
                {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
            ],
            "attachments":[slot()],
            "changeRequest":{
                "effects":[{"id":"apply-label","target":{"fromField":"item"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
                "review":{"stages":[{"id":"review","approvals":1}]}
            }
        }],
        "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"principal","grants":[{
                "entity":"request",
                "operations":["get","list","create","patch","submit_request","approve_request","reject_request","request_revision","apply_request"],
                "readableFields":["item","label","supporting-file"],
                "writableFields":["item","label","supporting-file"],
                "reviewStages":[{"stage":"review","targets":[
                    {"entity":"item","readableFields":["label"],"rowBoundaries":[]},
                    {"entity":"request","readableFields":["supporting-file"],"rowBoundaries":[]}
                ]}],
                "applyTargets":[{"entity":"item","rowBoundaries":[]}],
                "rowBoundaries":[]
            }]
        }]
    })
}

fn slot() -> Value {
    json!({"id":"supporting-file","required":true,"maximumBytes":1024,"contentTypes":["application/pdf"],"classification":"restricted"})
}

fn compile(source: &Value) -> Result<CompiledRegistry, CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn assert_diagnostic(source: &Value, code: &str, path: &str) {
    let failure = compile(source).expect_err("invalid attachment contract is refused");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|d| d.code == code && d.path == path),
        "expected {code} at {path}: {failure:?}"
    );
}

#[test]
fn request_slots_keep_field_authority_without_creating_scalar_query_columns() {
    let compiled = compile(&source()).unwrap();
    let entity = &compiled.entities()["request"];
    let slot = &entity.attachments["supporting-file"];
    assert_eq!(slot.maximum_bytes, 1024);
    assert!(slot.required);
    assert!(!entity.fields.contains_key(&slot.id));
    assert!(!entity
        .stored_fields
        .iter()
        .any(|field| field.logical.id == slot.id));
    assert!(!entity.source_relation.stored_fields.contains(&slot.id));
    assert!(entity.access_profiles["operator"]
        .readable_fields
        .contains(&slot.id));
    assert!(entity.access_profiles["operator"]
        .writable_fields
        .contains(&slot.id));
    assert!(entity
        .change_request
        .as_ref()
        .unwrap()
        .review_grants
        .iter()
        .any(
            |grant| grant.target_entity_id == "request" && grant.readable_fields.contains(&slot.id)
        ));
    for query in &compiled.queries().operations {
        assert!(!query.projection_fields.contains(&slot.id));
        assert!(!query.processing_fields.contains(&slot.id));
    }
    let mut only_slot = source();
    only_slot["accessProfiles"][0]["grants"][0]["writableFields"] = json!(["supporting-file"]);
    compile(&only_slot).expect("slot-only writable projections are valid");
}

#[test]
fn every_slot_policy_member_changes_compiled_and_request_contract_identity() {
    let original = source();
    let baseline = compile(&original).unwrap();
    let fingerprint = &baseline.entities()["request"]
        .change_request
        .as_ref()
        .unwrap()
        .contract_fingerprint;
    for (field, value) in [
        ("required", json!(false)),
        ("maximumBytes", json!(2048)),
        ("contentTypes", json!(["image/png"])),
        ("classification", json!("internal")),
    ] {
        let mut candidate = original.clone();
        candidate["entities"][1]["attachments"][0][field] = value;
        let compiled = compile(&candidate).unwrap();
        assert_ne!(compiled.revision(), baseline.revision(), "{field}");
        assert_ne!(
            &compiled.entities()["request"]
                .change_request
                .as_ref()
                .unwrap()
                .contract_fingerprint,
            fingerprint,
            "{field}"
        );
    }
    let mut renamed = original.clone();
    renamed["entities"][1]["attachments"][0]["id"] = json!("replacement-file");
    renamed["accessProfiles"][0]["grants"][0]["readableFields"] =
        json!(["item", "label", "replacement-file"]);
    renamed["accessProfiles"][0]["grants"][0]["writableFields"] =
        json!(["item", "label", "replacement-file"]);
    renamed["accessProfiles"][0]["grants"][0]["reviewStages"][0]["targets"][1]["readableFields"] =
        json!(["replacement-file"]);
    let compiled = compile(&renamed).unwrap();
    assert_ne!(compiled.revision(), baseline.revision());
    assert_ne!(
        &compiled.entities()["request"]
            .change_request
            .as_ref()
            .unwrap()
            .contract_fingerprint,
        fingerprint
    );
}

#[test]
fn absence_omits_attachment_members_from_source_and_compiled_contracts() {
    let mut source = source();
    source["entities"][1]
        .as_object_mut()
        .unwrap()
        .remove("attachments");
    source["accessProfiles"][0]["grants"][0]["readableFields"] = json!(["item", "label"]);
    source["accessProfiles"][0]["grants"][0]["writableFields"] = json!(["item", "label"]);
    source["accessProfiles"][0]["grants"][0]["reviewStages"][0]["targets"]
        .as_array_mut()
        .unwrap()
        .pop();
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    assert!(serde_json::to_value(&project).unwrap()["entities"][1]
        .get("attachments")
        .is_none());
    let compiled = compile(&source).unwrap();
    assert!(serde_json::to_value(&compiled.entities()["request"])
        .unwrap()
        .get("attachments")
        .is_none());
    source["entities"][1]["attachments"] = json!([]);
    assert_eq!(compile(&source).unwrap().revision(), compiled.revision());
}

#[test]
fn attachment_declarations_enforce_request_scope_bounds_and_closed_shape() {
    let mut candidate = source();
    candidate["entities"][0]["attachments"] = json!([slot()]);
    assert_diagnostic(
        &candidate,
        "attachment.entity.not_request",
        "entities[id=item].attachments",
    );
    for maximum in [0, MAX_ATTACHMENT_BYTES + 1] {
        let mut candidate = source();
        candidate["entities"][1]["attachments"][0]["maximumBytes"] = json!(maximum);
        assert_diagnostic(
            &candidate,
            "attachment.maximum_bytes.bounds_invalid",
            "entities[id=request].attachments[0].maximumBytes",
        );
    }
    let mut candidate = source();
    candidate["entities"][1]["attachments"] = json!((0..=MAX_ATTACHMENT_SLOTS)
        .map(|i| {
            let mut slot = slot();
            slot["id"] = json!(format!("slot-{i}"));
            slot
        })
        .collect::<Vec<_>>());
    assert_diagnostic(
        &candidate,
        "attachment.slots.bounds_invalid",
        "entities[id=request].attachments",
    );
    for member in ["backend", "bucket", "url", "sha256"] {
        let mut candidate = source();
        candidate["entities"][1]["attachments"][0][member] = json!("unsupported");
        assert!(
            parse_project_json(&serde_json::to_vec(&candidate).unwrap()).is_err(),
            "{member}"
        );
    }
}

#[test]
fn attachment_ids_refuse_invalid_duplicate_and_field_collisions() {
    let mut candidate = source();
    candidate["entities"][1]["attachments"] = json!([slot(), slot()]);
    assert_diagnostic(
        &candidate,
        "attachment.id.duplicate",
        "entities[id=request].attachments[1].id",
    );
    for id in ["id", "revision", "item", "label"] {
        let mut candidate = source();
        candidate["entities"][1]["attachments"][0]["id"] = json!(id);
        assert_diagnostic(
            &candidate,
            "attachment.id.collision",
            "entities[id=request].attachments[0].id",
        );
    }
    let mut candidate = source();
    candidate["entities"][1]["fields"][1]["apiName"] = json!("support");
    candidate["entities"][1]["attachments"][0]["id"] = json!("support");
    assert_diagnostic(
        &candidate,
        "attachment.id.collision",
        "entities[id=request].attachments[0].id",
    );
    for id in ["../file", "", "File", "file/name"] {
        let mut candidate = source();
        candidate["entities"][1]["attachments"][0]["id"] = json!(id);
        assert_diagnostic(
            &candidate,
            "identifier.invalid",
            "entities[id=request].attachments[0].id",
        );
    }
}

#[test]
fn content_types_are_bounded_concrete_and_unique() {
    for types in [json!([]), json!(vec!["application/pdf"; 17])] {
        let mut candidate = source();
        candidate["entities"][1]["attachments"][0]["contentTypes"] = types;
        assert_diagnostic(
            &candidate,
            "attachment.content_types.bounds_invalid",
            "entities[id=request].attachments[0].contentTypes",
        );
    }
    for content_type in [
        "application/*",
        "*/*",
        "text/plain; charset=utf-8",
        "Application/pdf",
        "text",
        "/plain",
        "text/",
        "text/plain\r\nx-header:value",
        "text/plain/extra",
    ] {
        let mut candidate = source();
        candidate["entities"][1]["attachments"][0]["contentTypes"] = json!([content_type]);
        assert_diagnostic(
            &candidate,
            "attachment.content_type.invalid",
            "entities[id=request].attachments[0].contentTypes[0]",
        );
    }
    let mut candidate = source();
    candidate["entities"][1]["attachments"][0]["contentTypes"] =
        json!(["application/pdf", "application/pdf"]);
    assert_diagnostic(
        &candidate,
        "attachment.content_type.duplicate",
        "entities[id=request].attachments[0].contentTypes[1]",
    );
    candidate["entities"][1]["attachments"][0]["contentTypes"] = json!([
        "application/pdf",
        "application/vnd.example.document+json",
        "image/png",
        "video/3gpp"
    ]);
    compile(&candidate).unwrap();
}

#[test]
fn attachments_cannot_be_anonymous_or_scalar_query_inputs() {
    for member in ["filterableFields", "sortableFields"] {
        let mut candidate = source();
        candidate["accessProfiles"][0]["grants"][0][member] = json!(["supporting-file"]);
        assert_diagnostic(
            &candidate,
            "attachment.access.processing_unsupported",
            &format!(
                "entities[id=request].accessProfiles[id=operator].{member}[value=supporting-file]"
            ),
        );
    }
    let mut candidate = source();
    candidate["accessProfiles"][0]["grants"][0]["rowBoundaries"] =
        json!([{"field":"supporting-file", "claim":"owner", "operator":"equals"}]);
    assert_diagnostic(
        &candidate,
        "attachment.access.processing_unsupported",
        "entities[id=request].accessProfiles[id=operator].rowBoundaries[0].field",
    );
    let mut candidate = source();
    candidate["accessProfiles"][0]["anonymous"] = json!(true);
    assert_diagnostic(
        &candidate,
        "attachment.access.authentication_required",
        "entities[id=request].accessProfiles[id=operator].readableFields[value=supporting-file]",
    );
}

#[test]
fn attachment_slots_are_not_scalar_effect_inputs() {
    let mut candidate = source();
    candidate["entities"][1]["changeRequest"]["effects"][0]["set"]["label"]["fromField"] =
        json!("supporting-file");
    assert_diagnostic(
        &candidate,
        "change_request.effect.value_field_unknown",
        "entities[id=request].changeRequest.effects[id=apply-label].set[field=label]",
    );
}

#[test]
fn generated_attachment_contract_exposes_binary_routes_and_read_only_metadata() {
    let compiled = compile(&source()).unwrap();
    let schema: Value = serde_json::from_slice(
        &compiled
            .artifacts()
            .get("generated/schemas/request.schema.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert_eq!(schema["properties"]["supporting-file"]["readOnly"], true);
    assert_eq!(
        schema["properties"]["supporting-file"]["x-registry-fieldKind"],
        "attachment"
    );
    assert_eq!(
        schema["properties"]["supporting-file"]["x-registry-attachment"]["classification"],
        "restricted"
    );
    assert!(
        !schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("supporting-file")),
        "required slots apply to submission, allowing incomplete drafts"
    );
    let openapi: Value = serde_json::from_slice(
        &compiled
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert!(
        openapi["components"]["schemas"]["request-create-input"]["properties"]
            .get("supporting-file")
            .is_none()
    );
    assert_eq!(
        openapi["paths"]["/v1/records/requests"]["get"]["x-registry-queryProfiles"]["operator"]
            ["selectableProperties"],
        json!(["item", "label", "supporting-file"])
    );
    assert_eq!(
        openapi["components"]["schemas"]["request"]["properties"]["supporting-file"]
            ["x-registry-attachment"]["classification"],
        "restricted"
    );
    let path = &openapi["paths"]["/v1/records/requests/{record_id}/attachments/supporting-file"];
    for method in ["get", "patch", "delete"] {
        let operation = &path[method];
        assert!(operation.is_object(), "{method}");
        assert_eq!(operation["security"], json!([{"bearerAuth":[]}]));
        assert_eq!(operation["x-registry-attachmentSlot"], "supporting-file");
        if method == "get" {
            assert!(operation["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .any(|parameter| parameter["name"] == "proposalVersion"
                    && parameter["required"] == true));
        } else {
            for header in ["If-Match", "Idempotency-Key"] {
                assert!(operation["parameters"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|parameter| parameter["name"] == header && parameter["required"] == true));
            }
        }
    }
    assert_eq!(
        path["patch"]["requestBody"]["content"]["application/pdf"]["schema"]["format"],
        "binary"
    );
    assert!(path["delete"].get("requestBody").is_none());
}
