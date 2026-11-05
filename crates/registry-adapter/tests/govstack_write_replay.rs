// SPDX-License-Identifier: Apache-2.0

//! Offline replay proof for the fixed GovStack Write target. Replay exercises
//! the real source-write controls and wire rendering, but deliberately claims
//! only simulated durability.

use std::path::{Path, PathBuf};

use registry_adapter::engine::load::read_artifact;
use registry_adapter::govstack::built_in_profile;
use registry_adapter::replay_serve::{run_with_project_directory, ReplayDurability, ReplayFacade};
use registry_adapter_core::{
    AdapterFixture, AdapterPack, AdapterProject, ErrorClass, ADAPTER_PACK_API_VERSION,
    ADAPTER_PACK_KIND, ADAPTER_PROJECT_API_VERSION, ADAPTER_PROJECT_KIND,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const COLLECTION_PATH: &str = "/govstack/registries/v1/collections/contacts/records";
const RECORD_ID: &str = "contact-42";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn authored_inputs() -> (PathBuf, AdapterProject, PathBuf, AdapterPack) {
    let root = repository();
    let project_directory = root.join("products/adapter/examples/breg-govstack");
    let pack_path = root.join("products/adapter/packs/breg-records/pack.yaml");
    let (project, _): (AdapterProject, _) = read_artifact(
        &project_directory.join("project.yaml"),
        ADAPTER_PROJECT_KIND,
        ADAPTER_PROJECT_API_VERSION,
    )
    .expect("the maintained GovStack Write project reads");
    let (pack, _): (AdapterPack, _) =
        read_artifact(&pack_path, ADAPTER_PACK_KIND, ADAPTER_PACK_API_VERSION)
            .expect("the maintained BReg pack reads");
    (project_directory, project, pack_path, pack)
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn framed_hash(domain: &[u8], members: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for member in std::iter::once(domain).chain(members.iter().copied()) {
        hash.update((member.len() as u64).to_be_bytes());
        hash.update(member);
    }
    hash.finalize().into()
}

fn source_key(method: &str, target: &str, caller_key: &str) -> String {
    let scope = hex(framed_hash(
        b"registry-adapter:govstack-source-key:v1",
        &[
            b"https://fixture-replay.invalid",
            b"synthetic-fixture-caller",
            b"fixture-replay-client",
            b"fixture-replay-v1",
            method.as_bytes(),
            target.as_bytes(),
            caller_key.as_bytes(),
        ],
    ));
    let mut framed = Vec::new();
    for member in [
        b"registry-adapter:source-write-key:v2".as_slice(),
        scope.as_bytes(),
        b"00000000000000000000000000000000".as_slice(),
    ] {
        framed.extend_from_slice(&(member.len() as u64).to_be_bytes());
        framed.extend_from_slice(member);
    }
    framed.extend_from_slice(&0_u32.to_be_bytes());
    hex(Sha256::digest(framed))
}

#[allow(clippy::too_many_arguments)]
fn fixture(
    id: &str,
    operation: &str,
    path: &str,
    caller_key: &str,
    request_headers: Value,
    request_body: Value,
    source_body: Value,
    source_status: u16,
) -> AdapterFixture {
    let mut source_response = json!({"status": source_status});
    if !source_body.is_null() {
        source_response["body"] = source_body;
    }
    serde_json::from_value(json!({
        "id": id,
        "pack": "breg-records",
        "upstreamVersion": "0.45",
        "provenance": {"type": "documented", "reference": "offline replay regression"},
        "intercepts": [{"type": "endpoint", "endpoint": "registry"}],
        "entries": [{
            "facadeRequest": {
                "operation": operation,
                "path": path,
                "headers": request_headers,
                "body": request_body
            },
            "upstream": [{
                "request": {
                    "endpoint": "registry",
                    "method": "POST",
                    "path": "/v1/records/contacts:batch",
                    "query": "accessProfile=directory-editor",
                    "headers": {
                        "idempotency-key": source_key(
                            if operation == "create" { "POST" } else { "PATCH" },
                            path,
                            caller_key
                        )
                    },
                    "body": if operation == "create" {
                        json!({"items": [{
                            "operation": "create",
                            "data": {
                                "name": "Ada Lovelace",
                                "email": "ada@example.test",
                                "jurisdiction": "zone-a"
                            }
                        }]})
                    } else {
                        json!({"items": [{
                            "operation": "patch",
                            "recordIdentifier": RECORD_ID,
                            "ifMatch": "\"breg-v1\"",
                            "patch": [{"op": "add", "path": "/data/note", "value": "Updated"}]
                        }]})
                    }
                },
                "response": source_response
            }],
            "expected": {"type": "response", "status": 200}
        }]
    }))
    .expect("the replay fixture parses")
}

async fn replay(fixture: &AdapterFixture) -> ReplayFacade {
    let (project_directory, project, pack_path, pack) = authored_inputs();
    run_with_project_directory(
        &project,
        &built_in_profile(&project),
        &pack,
        pack_path.parent().expect("the pack directory"),
        &project_directory,
        fixture,
        0,
    )
    .await
    .expect("the fixed Write fixture replays")
}

async fn created_validator() -> String {
    let key = r#""create-contact-1""#;
    let created = replay(&fixture(
        "govstack-write-create",
        "create",
        COLLECTION_PATH,
        key,
        json!({"idempotency-key": key}),
        json!({"data": {"name": "Ada Lovelace", "email": "ada@example.test"}}),
        json!({"results": [{
            "operation": "create",
            "recordIdentifier": RECORD_ID,
            "etag": "\"breg-v1\"",
            "domainData": {
                "name": "Ada Lovelace",
                "email": "ada@example.test",
                "jurisdiction": "zone-a"
            }
        }]}),
        200,
    ))
    .await;

    assert_eq!(
        created.status, 201,
        "problem class {:?}, code {:?}",
        created.problem_class, created.problem_code
    );
    assert_eq!(created.write_durability, ReplayDurability::Simulated);
    assert_eq!(created.headers["cache-control"], "no-store");
    assert_eq!(
        created.headers["location"],
        format!("{COLLECTION_PATH}/{RECORD_ID}")
    );
    let body = created.body.expect("Create returns its receipt");
    assert_eq!(body["collectionId"], "contacts");
    assert_eq!(body["recordId"], RECORD_ID);
    assert_eq!(body["etag"], created.headers["etag"]);
    assert!(created.headers["etag"].starts_with("\"w2."));
    created.headers["etag"].clone()
}

#[tokio::test]
async fn fixed_write_replay_renders_create_and_conditional_update_semantics() {
    let validator = created_validator().await;
    let path = format!("{COLLECTION_PATH}/{RECORD_ID}");
    let key = r#""update-contact-1""#;
    let updated = replay(&fixture(
        "govstack-write-update",
        "update",
        &path,
        key,
        json!({"idempotency-key": key, "if-match": validator.clone()}),
        json!({"data": {"note": "Updated"}}),
        json!({"results": [{
            "operation": "patch",
            "recordIdentifier": RECORD_ID,
            "etag": "\"breg-v2\"",
            "domainData": {
                "name": "Ada Lovelace",
                "email": "ada@example.test",
                "note": "Updated",
                "jurisdiction": "zone-a"
            }
        }]}),
        200,
    ))
    .await;

    assert_eq!(updated.status, 204);
    assert_eq!(updated.write_durability, ReplayDurability::Simulated);
    assert_eq!(updated.headers["cache-control"], "no-store");
    assert!(updated.headers["etag"].starts_with("\"w2."));
    assert_ne!(updated.headers["etag"], validator);
    assert!(!updated.headers.contains_key("location"));
    assert_eq!(updated.body, None);
}

#[tokio::test]
async fn fixed_conditional_write_replay_maps_native_412_to_precondition_failed() {
    let validator = created_validator().await;
    let path = format!("{COLLECTION_PATH}/{RECORD_ID}");
    let key = r#""stale-contact-1""#;
    let refused = replay(&fixture(
        "govstack-write-stale",
        "update",
        &path,
        key,
        json!({"idempotency-key": key, "if-match": validator}),
        json!({"data": {"note": "Updated"}}),
        Value::Null,
        412,
    ))
    .await;

    assert_eq!(refused.status, 412);
    assert_eq!(refused.write_durability, ReplayDurability::Simulated);
    assert_eq!(refused.problem_class, Some(ErrorClass::OutcomeConflict));
    assert_eq!(
        refused.problem_code.as_deref(),
        Some("https://govstack.global/problems/digital-registries/precondition-failed")
    );
    assert_eq!(refused.headers["cache-control"], "no-store");
    assert_eq!(refused.headers["content-type"], "application/problem+json");
    let body = refused.body.expect("412 returns a problem");
    assert_eq!(body["status"], 412);
    let trace = body["traceId"].as_str().expect("problem trace id");
    assert_eq!(trace.len(), 32);
    assert_ne!(trace, "00000000000000000000000000000000");
    assert!(trace
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
}

#[tokio::test]
async fn fixed_write_replay_normalizes_native_404_without_source_detail() {
    let validator = created_validator().await;
    let path = format!("{COLLECTION_PATH}/{RECORD_ID}");
    let key = r#""missing-contact-1""#;
    let refused = replay(&fixture(
        "govstack-write-missing",
        "update",
        &path,
        key,
        json!({"idempotency-key": key, "if-match": validator}),
        json!({"data": {"note": "Updated"}}),
        json!({"status": 404, "code": "resource.not_found"}),
        404,
    ))
    .await;

    assert_eq!(refused.status, 404);
    assert_eq!(refused.write_durability, ReplayDurability::Simulated);
    assert_eq!(refused.problem_class, Some(ErrorClass::OutcomeNotFound));
    assert_eq!(
        refused.problem_code.as_deref(),
        Some("https://govstack.global/problems/digital-registries/record-not-available")
    );
    assert_eq!(refused.headers["cache-control"], "no-store");
    let body = refused.body.expect("404 returns a problem");
    assert_eq!(body["status"], 404);
    assert_eq!(body["traceId"].as_str().map(str::len), Some(32));
    assert!(!body.to_string().contains("resource.not_found"));
}

#[tokio::test]
async fn fixed_write_replay_normalizes_native_422_as_invalid_content() {
    let key = r#""invalid-contact-1""#;
    let refused = replay(&fixture(
        "govstack-write-invalid-content",
        "create",
        COLLECTION_PATH,
        key,
        json!({"idempotency-key": key}),
        json!({"data": {"name": "Ada Lovelace", "email": "ada@example.test"}}),
        json!({"status": 422, "code": "action.refused"}),
        422,
    ))
    .await;

    assert_eq!(refused.status, 422);
    assert_eq!(refused.write_durability, ReplayDurability::Simulated);
    assert_eq!(
        refused.problem_class,
        Some(ErrorClass::OutcomeInvalidRequest)
    );
    assert_eq!(
        refused.problem_code.as_deref(),
        Some("https://govstack.global/problems/digital-registries/invalid-content")
    );
    let body = refused.body.expect("422 returns a problem");
    let errors = body["errors"].as_array().expect("validation errors");
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["pointer"], "/data");
    assert!(errors[0]["message"]
        .as_str()
        .is_some_and(|text| !text.is_empty()));
    assert!(!body.to_string().contains("action.refused"));
}

#[tokio::test]
async fn fixed_write_replay_maps_native_shape_rejection_to_bad_gateway() {
    let key = r#""rejected-contact-1""#;
    let refused = replay(&fixture(
        "govstack-write-rejected-shape",
        "create",
        COLLECTION_PATH,
        key,
        json!({"idempotency-key": key}),
        json!({"data": {"name": "Ada Lovelace", "email": "ada@example.test"}}),
        json!({
            "status": 400,
            "code": "request.invalid",
            "errors": [{"field": "items[0].data.sourceOnlyMember"}]
        }),
        400,
    ))
    .await;

    assert_eq!(refused.status, 502);
    assert_eq!(refused.write_durability, ReplayDurability::Simulated);
    assert_eq!(refused.problem_class, Some(ErrorClass::OutcomeRejected));
    assert_eq!(
        refused.problem_code.as_deref(),
        Some("https://govstack.global/problems/digital-registries/bad-gateway")
    );
    let body = refused.body.expect("502 returns a problem");
    assert_eq!(body["status"], 502);
    assert_eq!(body["traceId"].as_str().map(str::len), Some(32));
    assert!(!body.to_string().contains("sourceOnlyMember"));
}
