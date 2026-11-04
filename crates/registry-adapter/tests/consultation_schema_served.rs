// SPDX-License-Identifier: Apache-2.0

//! Real-router regression for schema-bound Consultation disclosure. Project
//! schemas may use JSON Schema composition that the generic facade's legacy
//! record validator does not implement; the checked project validator remains
//! the authority for transformed `domainData`.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{digest_of, fixture, Served};
use std::path::{Path, PathBuf};

fn project() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter/examples/dhis2-consultation")
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create the project copy");
    for entry in std::fs::read_dir(from).expect("read the project tree") {
        let entry = entry.expect("a project entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy a project file");
        }
    }
}

fn replace_pinned_artifact(directory: &Path, relative: &str, replacement: &[u8]) {
    let artifact = directory.join(relative);
    let old = std::fs::read(&artifact).expect("read the pinned artifact");
    let project_path = directory.join("project.yaml");
    let project = std::fs::read_to_string(&project_path).expect("read the project");
    let old_digest = digest_of(&old);
    assert!(project.contains(&old_digest), "the old digest is pinned");
    std::fs::write(&artifact, replacement).expect("write the test artifact");
    std::fs::write(
        &project_path,
        project.replace(&old_digest, &digest_of(replacement)),
    )
    .expect("repin the test artifact");
}

fn install_composed_public_schema(directory: &Path) {
    let schema = serde_json::to_vec_pretty(&json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://registry.example/schemas/person-public-composed/1/schema.json",
        "title": "Composed public person data",
        "type": "object",
        "properties": {
            "source": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "minLength": 1, "maxLength": 128},
                    "type": {"type": "string", "minLength": 1, "maxLength": 128}
                },
                "required": ["id", "type"],
                "additionalProperties": false
            },
            "registration": {
                "type": "object",
                "properties": {
                    "organisationUnit": {"type": "string", "minLength": 1, "maxLength": 128},
                    "createdAt": {"type": "string", "minLength": 1, "maxLength": 128},
                    "updatedAt": {"type": "string", "minLength": 1, "maxLength": 128}
                },
                "required": ["organisationUnit", "createdAt", "updatedAt"],
                "additionalProperties": false
            }
        },
        "anyOf": [
            {"required": ["source"]},
            {"required": ["registration"]}
        ],
        "additionalProperties": false
    }))
    .expect("serialize the schema");
    replace_pinned_artifact(directory, "schemas/person-public.schema.json", &schema);
}

fn source_entity() -> Value {
    fixture("get-found")["entries"][0]["upstream"][0]["response"]["body"].clone()
}

fn source_page() -> Value {
    fixture("search-page")["entries"][0]["upstream"][0]["response"]["body"].clone()
}

#[tokio::test]
async fn composed_project_schema_preserves_record_identity_for_every_read_capability() {
    let directory = tempfile::tempdir().expect("a scratch project");
    copy_tree(&project(), directory.path());
    install_composed_public_schema(directory.path());

    let entity = source_entity();
    let page = source_page();
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(200, &entity.to_string()),
        Response::json(200, &entity.to_string()),
        Response::json(200, &page.to_string()),
        Response::json(200, &page.to_string()),
    ]);
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.read");

    let (status, _, retrieve) =
        served.get("/v1/collections/people/records/EeBJ3Sn9uLg", Some(&token));
    assert_eq!(status, 200, "{retrieve}\n{}", served.stderr_text());
    assert_eq!(retrieve["recordId"], "EeBJ3Sn9uLg");

    let (status, _, lookup) = served.post(
        "/v1/collections/people/lookup",
        Some(&token),
        &json!({
            "selector": "by-record-id",
            "values": {"record-id": "EeBJ3Sn9uLg"}
        }),
    );
    assert_eq!(status, 200, "{lookup}\n{}", served.stderr_text());
    assert_eq!(lookup["recordId"], "EeBJ3Sn9uLg");

    let (status, _, list) = served.get("/v1/collections/people/records?pageSize=5", Some(&token));
    assert_eq!(status, 200, "{list}\n{}", served.stderr_text());
    assert_eq!(list["items"][0]["recordId"], "EeBJ3Sn9uLg");

    let (status, _, search) = served.post(
        "/v1/collections/people/search",
        Some(&token),
        &json!({
            "search": "by-org-unit",
            "criteria": {"org-unit": "slSrf7H9lMf"},
            "pageSize": 5
        }),
    );
    assert_eq!(status, 200, "{search}\n{}", served.stderr_text());
    assert_eq!(search["items"][0]["recordId"], "EeBJ3Sn9uLg");
    assert_eq!(upstream.request_count(), 4);
}

#[tokio::test]
async fn composed_project_schema_still_denies_invalid_projection_output() {
    let directory = tempfile::tempdir().expect("a scratch project");
    copy_tree(&project(), directory.path());
    install_composed_public_schema(directory.path());
    replace_pinned_artifact(
        directory.path(),
        "scripts/person-public.rhai",
        br#"fn project_person_public(source) {
    #{privateCanary: "PRIVATE-CANARY"}
}
"#,
    );

    let entity = source_entity();
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(200, &entity.to_string())]);
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.read");

    let (status, _, body) = served.get("/v1/collections/people/records/EeBJ3Sn9uLg", Some(&token));
    assert_eq!(status, 500, "{body}\n{}", served.stderr_text());
    assert!(!body.to_string().contains("PRIVATE-CANARY"));
    assert!(!served.journal_text().await.contains("PRIVATE-CANARY"));
    assert_eq!(upstream.request_count(), 1);
}
