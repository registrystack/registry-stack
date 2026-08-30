// SPDX-License-Identifier: Apache-2.0

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::data::{
    DataError, DataExportCheckpoint, DataExportPlan, DataImportCheckpoint, DataImportOperation,
    DataImportPlan,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ENTITY: &str = "entity-canary-9f31";
const PROFILE: &str = "operator-canary";
const PACKAGE: &str = "package-revision-canary";
const SCHEMA: &str = "schema-fingerprint-canary";

fn compiled(allow_data_export: bool) -> registry_server::CompiledRegistry {
    let source = json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {"id": "data-contract", "version": "1", "defaultLanguage": "en"},
        "entities": [{
            "id": ENTITY,
            "route": "records",
            "mutationMode": "mutable",
            "batch": {"maximumItems": 2, "maximumBytes": 400},
            "fields": [
                {"id": "code", "type": "string", "minLength": 2, "maxLength": 16,
                 "required": true, "classification": "internal"},
                {"id": "count", "type": "int64", "classification": "internal"},
                {"id": "readonly", "type": "text", "maxLength": 32,
                 "classification": "internal"},
                {"id": "hidden", "type": "string", "maxLength": 16,
                 "classification": "restricted"}
            ]
        }],
        "accessProfiles": [{
            "id": PROFILE,
            "principalClaim": "principal",
            "grants": [{
                "entity": ENTITY,
                "operations": ["create", "patch", "batch", "list"],
                "readableFields": ["code", "count", "readonly"],
                "writableFields": ["code", "count"],
                "allowDataExport": allow_data_export
            }]
        }]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).unwrap()
}

fn compile_source(source: Value) -> Result<registry_server::CompiledRegistry, Vec<String>> {
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).map_err(|failure| {
        failure
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect()
    })
}

fn create_line(code: &str, count: i64) -> String {
    serde_json::to_string(&json!({
        "operation": "create",
        "data": {"code": code, "count": count}
    }))
    .unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn data_export_requires_explicit_nonanonymous_profile_permission() {
    let ordinary_list = compiled(false);
    assert_eq!(
        DataExportPlan::from_compiled(&ordinary_list, ENTITY, PROFILE, ["code"]),
        Err(DataError::InvalidBinding)
    );

    let base = |anonymous: bool, operations: Value, readable: Value| {
        json!({
            "apiVersion": "registry.registrystack.org/v1alpha1",
            "kind": "RegistryProject",
            "registry": {"id": "export-contract", "version": "1", "defaultLanguage": "en"},
            "entities": [{
                "id": ENTITY, "route": "records", "mutationMode": "create_only",
                "fields": [{"id": "code", "type": "string", "maxLength": 16,
                            "classification": "internal"}]
            }],
            "accessProfiles": [{
                "id": PROFILE, "anonymous": anonymous,
                "principalClaim": if anonymous { Value::Null } else { json!("principal") },
                "grants": [{
                    "entity": ENTITY,
                    "operations": operations, "readableFields": readable,
                    "allowDataExport": true
                }]
            }]
        })
    };
    for invalid in [
        base(true, json!(["list"]), json!(["code"])),
        base(false, json!(["get"]), json!(["code"])),
        base(false, json!(["list"]), json!([])),
    ] {
        let diagnostics = compile_source(invalid).expect_err("invalid export authority is refused");
        assert!(diagnostics
            .iter()
            .any(|code| code == "access_profile.data_export.invalid"));
    }

    let explicit = compiled(true);
    let plan =
        DataExportPlan::from_compiled(&explicit, ENTITY, PROFILE, ["readonly", "code"]).unwrap();
    assert_eq!(plan.requested_fields(), &["code", "readonly"]);
    assert_eq!(plan.entity_id(), ENTITY);
    assert_eq!(plan.profile_id(), PROFILE);

    let project_profile = json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {"id": "project-export", "version": "1", "defaultLanguage": "en"},
        "accessProfiles": [{
            "id": "project-exporter", "principalClaim": "principal",
            "grants": [{"entity": ENTITY, "operations": ["list"],
                        "readableFields": ["code"], "allowDataExport": true}]
        }],
        "entities": [{
            "id": ENTITY, "route": "records", "mutationMode": "create_only",
            "fields": [{"id": "code", "type": "string", "maxLength": 16,
                        "classification": "internal"}]
        }]
    });
    let project_compiled = compile_source(project_profile).unwrap();
    assert!(
        project_compiled.entities()[ENTITY].access_profiles["project-exporter"].allow_data_export
    );
}

#[test]
fn data_validate_and_chunk_plan_reuse_runtime_rules_and_compiled_batch_bounds() {
    let registry = compiled(true);
    let input = format!(
        "{}\n{}\n{}\n",
        create_line("AA", 1),
        create_line("BB", 2),
        create_line("CC", 3)
    );
    let plan = DataImportPlan::from_jsonl(
        &registry,
        ENTITY,
        DataImportOperation::Create,
        PROFILE,
        input.as_bytes(),
    )
    .unwrap();
    assert_eq!(plan.item_count(), 3);
    assert_eq!(plan.maximum_items(), 2);
    assert_eq!(plan.maximum_bytes(), 400);
    assert_eq!(plan.chunks().len(), 2);
    assert_eq!(plan.chunks()[0].item_range(), 0..2);
    assert_eq!(plan.chunks()[1].item_range(), 2..3);
    for chunk in plan.chunks() {
        assert!(chunk.canonical_body().len() <= plan.maximum_bytes() as usize);
        let body = parse_json_strict(chunk.canonical_body()).unwrap();
        assert!(body["items"].as_array().unwrap().len() <= plan.maximum_items() as usize);
    }

    let invalid_create = [
        json!({"operation":"create","data":{"count":1}}),
        json!({"operation":"create","data":{"code":"A","count":1}}),
        json!({"operation":"create","data":{"code":"AA","count":"1"}}),
        json!({"operation":"create","data":{"code":"AA","readonly":"no"}}),
        json!({"operation":"create","data":{"code":"AA","hidden":"no"}}),
        json!({"operation":"create","data":{"code":"AA","unknown":"no"}}),
    ];
    for item in invalid_create {
        let line = format!("{}\n", serde_json::to_string(&item).unwrap());
        assert_eq!(
            DataImportPlan::from_jsonl(
                &registry,
                ENTITY,
                DataImportOperation::Create,
                PROFILE,
                line.as_bytes(),
            ),
            Err(DataError::InvalidItem)
        );
    }

    let patch = |operation: Value| {
        format!(
            "{}\n",
            serde_json::to_string(&json!({
                "operation":"patch",
                "recordId":"018f06d6-0248-7c7f-8a7e-df9dfbd83d2c",
                "ifMatch":"\"rs-revision\"",
                "patch":[operation]
            }))
            .unwrap()
        )
    };
    for invalid in [
        json!({"op":"remove","path":"/data/code"}),
        json!({"op":"replace","path":"/data/readonly","value":"no"}),
        json!({"op":"replace","path":"/data/hidden","value":"no"}),
        json!({"op":"replace","path":"/data/unknown","value":"no"}),
        json!({"op":"replace","path":"/data/count","value":"one"}),
        json!({"op":"test","path":"/data/hidden","value":"no"}),
        json!({"op":"move","path":"/data/count"}),
    ] {
        assert_eq!(
            DataImportPlan::from_jsonl(
                &registry,
                ENTITY,
                DataImportOperation::Patch,
                PROFILE,
                patch(invalid).as_bytes(),
            ),
            Err(DataError::InvalidItem)
        );
    }

    let duplicate = br#"{"operation":"create","operation":"create","data":{"code":"AA"}}
"#;
    assert_eq!(
        DataImportPlan::from_jsonl(
            &registry,
            ENTITY,
            DataImportOperation::Create,
            PROFILE,
            duplicate,
        ),
        Err(DataError::InvalidItem)
    );
    let oversized = format!("{}\n", create_line(&"X".repeat(600), 1));
    assert_eq!(
        DataImportPlan::from_jsonl(
            &registry,
            ENTITY,
            DataImportOperation::Create,
            PROFILE,
            oversized.as_bytes(),
        ),
        Err(DataError::InvalidItem),
        "field bounds are checked before HTTP body bounds"
    );
    let oversized_valid_field_registry = {
        let source = json!({
            "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
            "registry":{"id":"oversize", "version":"1", "defaultLanguage":"en"},
            "entities":[{"id":ENTITY,"route":"records","mutationMode":"create_only",
                "batch":{"maximumItems":2,"maximumBytes":100},
                "fields":[{"id":"code","type":"text","maxLength":1000,"required":true,
                           "classification":"internal"}]}],
            "accessProfiles":[{"id":PROFILE,"principalClaim":"principal","grants":[{
                    "entity":ENTITY,
                    "operations":["create","batch"],"readableFields":["code"],
                    "writableFields":["code"]}]}]
        });
        compile_source(source).unwrap()
    };
    assert_eq!(
        DataImportPlan::from_jsonl(
            &oversized_valid_field_registry,
            ENTITY,
            DataImportOperation::Create,
            PROFILE,
            format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "operation":"create", "data":{"code":"X".repeat(200)}
                }))
                .unwrap()
            )
            .as_bytes(),
        ),
        Err(DataError::ItemTooLarge)
    );
}

#[test]
fn data_lifecycle_uses_exact_compiled_api_names() {
    let registry = compile_source(json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {"id": "data-logical-names", "version": "1", "defaultLanguage": "en"},
        "entities": [{
            "id": ENTITY,
            "route": "records",
            "mutationMode": "mutable",
            "batch": {"maximumItems": 2, "maximumBytes": 400},
            "fields": [{
                "id": "record-code",
                "apiName": "publicCode",
                "type": "string",
                "minLength": 2,
                "maxLength": 16,
                "required": true,
                "classification": "internal"
            }]
        }],
        "accessProfiles": [{
            "id": PROFILE,
            "principalClaim": "principal",
            "grants": [{
                "entity": ENTITY,
                "operations": ["create", "patch", "batch", "list"],
                "readableFields": ["record-code"],
                "writableFields": ["record-code"],
                "allowDataExport": true
            }]
        }]
    }))
    .unwrap();

    let create = b"{\"operation\":\"create\",\"data\":{\"publicCode\":\"AA\"}}\n";
    let create_plan = DataImportPlan::from_jsonl(
        &registry,
        ENTITY,
        DataImportOperation::Create,
        PROFILE,
        create,
    )
    .unwrap();
    let canonical = parse_json_strict(create_plan.chunks()[0].canonical_body()).unwrap();
    assert_eq!(canonical["items"][0]["data"]["publicCode"], "AA");
    assert!(canonical["items"][0]["data"].get("record-code").is_none());

    let internal_create = b"{\"operation\":\"create\",\"data\":{\"record-code\":\"AA\"}}\n";
    assert_eq!(
        DataImportPlan::from_jsonl(
            &registry,
            ENTITY,
            DataImportOperation::Create,
            PROFILE,
            internal_create,
        ),
        Err(DataError::InvalidItem)
    );

    let patch = b"{\"operation\":\"patch\",\"recordId\":\"018f06d6-0248-7c7f-8a7e-df9dfbd83d2c\",\"ifMatch\":\"\\\"rs-revision\\\"\",\"patch\":[{\"op\":\"replace\",\"path\":\"/data/publicCode\",\"value\":\"BB\"}]}\n";
    DataImportPlan::from_jsonl(
        &registry,
        ENTITY,
        DataImportOperation::Patch,
        PROFILE,
        patch,
    )
    .unwrap();

    let export = DataExportPlan::from_compiled(&registry, ENTITY, PROFILE, ["publicCode"])
        .expect("the exact compiled API name is exportable");
    assert_eq!(export.requested_fields(), &["publicCode"]);
    assert_eq!(
        DataExportPlan::from_compiled(&registry, ENTITY, PROFILE, ["record-code"]),
        Err(DataError::InvalidBinding)
    );
}

#[test]
fn data_import_checkpoint_and_idempotency_are_exact_and_value_free() {
    let registry = compiled(true);
    let input = format!(
        "{}\n{}\n{}\n",
        create_line("ROW-CANARY-A", 1),
        create_line("ROW-CANARY-B", 2),
        create_line("ROW-CANARY-C", 3)
    );
    let plan = DataImportPlan::from_jsonl(
        &registry,
        ENTITY,
        DataImportOperation::Create,
        PROFILE,
        input.as_bytes(),
    )
    .unwrap();
    let mut checkpoint = DataImportCheckpoint::start(&plan, PACKAGE, SCHEMA).unwrap();
    let import_id = checkpoint.import_id().to_owned();
    let key = checkpoint
        .idempotency_key(&plan, 0, PACKAGE, SCHEMA, &import_id)
        .unwrap();
    assert_eq!(
        key,
        checkpoint
            .idempotency_key(&plan, 0, PACKAGE, SCHEMA, &import_id)
            .unwrap()
    );
    assert_ne!(
        key,
        checkpoint
            .idempotency_key(&plan, 1, PACKAGE, SCHEMA, &import_id)
            .unwrap()
    );
    checkpoint
        .commit_chunk(&plan, PACKAGE, SCHEMA, 0, &import_id)
        .unwrap();
    assert_eq!(checkpoint.completed_chunk_count(), 1);
    assert_eq!(checkpoint.next_item_index(), 2);
    assert!(checkpoint.next_byte_offset() > 0);
    assert!(!checkpoint.is_complete());
    let canonical = checkpoint.canonical_json().unwrap();
    assert_eq!(canonical, checkpoint.canonical_json().unwrap());
    DataImportCheckpoint::from_json(&canonical, &plan, PACKAGE, SCHEMA, &import_id).unwrap();

    for field in [
        "packageRevision",
        "schemaFingerprint",
        "profileId",
        "inputDigest",
        "inputLength",
        "itemCount",
        "maximumItems",
        "maximumBytes",
        "nextItemIndex",
        "nextByteOffset",
        "committedPrefixDigest",
        "completedChunkCount",
        "importId",
    ] {
        let mut substituted = parse_json_strict(&canonical).unwrap();
        substituted[field] = if field == "importId" {
            json!("ce0a5a52-9ed4-4cc8-b71e-5311ed29709e")
        } else {
            match substituted[field] {
                Value::Number(_) => json!(999999),
                _ => json!("SUBSTITUTED-CANARY"),
            }
        };
        let bytes = canonicalize_json(&substituted).unwrap();
        let error = DataImportCheckpoint::from_json(&bytes, &plan, PACKAGE, SCHEMA, &import_id)
            .expect_err("every checkpoint binding is exact");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("SUBSTITUTED-CANARY"));
        assert!(!rendered.contains(PACKAGE));
        assert!(!rendered.contains(PROFILE));
    }
    let mut unknown = parse_json_strict(&canonical).unwrap();
    unknown["unknownCanary"] = json!(true);
    assert_eq!(
        DataImportCheckpoint::from_json(
            &canonicalize_json(&unknown).unwrap(),
            &plan,
            PACKAGE,
            SCHEMA,
            &import_id,
        ),
        Err(DataError::CheckpointMismatch)
    );
    let debug = format!("{plan:?} {checkpoint:?}");
    for canary in [
        "ROW-CANARY",
        ENTITY,
        PROFILE,
        PACKAGE,
        SCHEMA,
        &key,
        &import_id,
    ] {
        assert!(!debug.contains(canary), "Debug leaked canary {canary}");
    }
}

#[test]
fn data_export_checkpoint_refuses_package_profile_projection_or_prefix_substitution() {
    let registry = compiled(true);
    let plan =
        DataExportPlan::from_compiled(&registry, ENTITY, PROFILE, ["readonly", "code"]).unwrap();
    let (checkpoint, resume_state) = DataExportCheckpoint::start(&plan, PACKAGE, SCHEMA).unwrap();
    let first_prefix = b"{\"code\":\"OUTPUT-ROW-CANARY\"}\n";
    assert_eq!(checkpoint.output_length(), 0);
    assert_eq!(checkpoint.record_count(), 0);
    assert!(!checkpoint.is_complete());
    let canonical = checkpoint.canonical_json().unwrap();
    DataExportCheckpoint::from_json(&canonical, &plan, PACKAGE, SCHEMA, &[], &resume_state)
        .unwrap();

    assert_eq!(
        checkpoint.validate_resume(&plan, "other-package", SCHEMA, &[], &resume_state,),
        Err(DataError::CheckpointMismatch)
    );
    assert_eq!(
        checkpoint.validate_resume(
            &plan,
            PACKAGE,
            SCHEMA,
            b"{\"code\":\"SUBSTITUTED-PREFIX-CANARY\"}\n",
            &resume_state,
        ),
        Err(DataError::CheckpointMismatch)
    );
    for (field, replacement) in [
        ("profileId", json!("other-profile")),
        ("requestedFields", json!(["code"])),
        ("outputPrefixDigest", json!("substituted-prefix")),
        ("recordCount", json!(99)),
        (
            "nextCursor",
            json!("SYNTACTICALLY-VALID-CURSOR-SUBSTITUTION"),
        ),
        ("complete", json!(true)),
    ] {
        let mut substituted = parse_json_strict(&canonical).unwrap();
        substituted[field] = replacement;
        let bytes = canonicalize_json(&substituted).unwrap();
        let error =
            DataExportCheckpoint::from_json(&bytes, &plan, PACKAGE, SCHEMA, &[], &resume_state)
                .expect_err("export resume substitution is refused");
        let rendered = format!("{error:?} {error}");
        for canary in [
            PACKAGE,
            PROFILE,
            "OUTPUT-ROW-CANARY",
            "SYNTACTICALLY-VALID-CURSOR-SUBSTITUTION",
        ] {
            assert!(!rendered.contains(canary));
        }
    }

    let mut forged_terminal = parse_json_strict(&canonical).unwrap();
    forged_terminal["outputLength"] = json!(first_prefix.len());
    forged_terminal["outputPrefixDigest"] = json!(sha256_hex(first_prefix));
    forged_terminal["recordCount"] = json!(1);
    forged_terminal["completedPageCount"] = json!(1);
    forged_terminal["nextCursor"] = Value::Null;
    forged_terminal["complete"] = json!(true);
    assert_eq!(
        DataExportCheckpoint::from_json(
            &canonicalize_json(&forged_terminal).unwrap(),
            &plan,
            PACKAGE,
            SCHEMA,
            first_prefix,
            &resume_state,
        ),
        Err(DataError::CheckpointMismatch),
        "a caller cannot turn an initial or partial checkpoint into terminal authority"
    );
    let debug = format!("{plan:?} {checkpoint:?}");
    for canary in [ENTITY, PROFILE, PACKAGE, SCHEMA, "OUTPUT-ROW-CANARY"] {
        assert!(!debug.contains(canary), "Debug leaked canary {canary}");
    }
}
