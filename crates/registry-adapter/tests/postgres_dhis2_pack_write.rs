// SPDX-License-Identifier: Apache-2.0

//! Served-loopback proof for the maintained DHIS2 write route's pack-owned
//! summary decisions and update identity mapping. Needs
//! `ADAPTER_TEST_DATABASE_URL`; absence is a failure, never a skip.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use registry_adapter_core::{
    derive_operation_request_schema, AdapterProfile, AdapterProject, ADAPTER_PROFILE_API_VERSION,
    ADAPTER_PROFILE_KIND, ADAPTER_PROJECT_API_VERSION, ADAPTER_PROJECT_KIND,
};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::Served;

const PROFILE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROFILE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROFILE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};
const PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROJECT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROJECT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

fn record(id: &str) -> Value {
    json!({
        "data": {
            "recordIdentifier": id,
            "domainData": {
                "tracked_entity_type": "cQWYtUfH6Vx",
                "org_unit": "qfg4XUDJtgS",
                "created_at": "2026-03-01T12:00:00.000",
                "updated_at": "2026-03-02T12:00:00.000"
            }
        }
    })
}

fn maintained_request_schema(binding_id: &str) -> Value {
    let read = |path: &Path, format: &'static FormatSpec<'static>| {
        let bytes = std::fs::read(path).expect("read maintained artifact");
        Reader::new(path.display().to_string())
            .read(&bytes, &Expect::one(format))
            .expect("read maintained artifact through the shared reader")
    };
    let profile = read(&Served::example_profile(), &PROFILE_FORMAT)
        .decode::<AdapterProfile>()
        .expect("decode maintained profile");
    let project_path = Served::example_project().join("project.yaml");
    let project = read(&project_path, &PROJECT_FORMAT)
        .decode::<AdapterProject>()
        .expect("decode maintained project");
    let binding = project
        .bindings
        .get(binding_id)
        .expect("maintained binding");
    derive_operation_request_schema(&profile, &project, binding)
        .expect("derive maintained request schema")
}

fn assert_matches_maintained_request_schema(binding_id: &str, request: &Value) {
    let schema = maintained_request_schema(binding_id);
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("the maintained request schema compiles");
    assert!(
        validator.is_valid(request),
        "the served request matches its maintained authored schema"
    );
}

fn raw_write(
    served: &Served,
    token: &str,
    method: &str,
    path: &str,
    key: &str,
    body: &Value,
) -> (u16, Vec<u8>) {
    let body = body.to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", served.port)).expect("connect to facade");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set facade timeout");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nIdempotency-Key: {key}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("send write");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read facade reply");
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("facade reply has a header block");
    let head = std::str::from_utf8(&response[..head_end]).expect("facade headers are text");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .expect("facade status");
    (status, response[head_end + 4..].to_vec())
}

fn import_summary(
    status: &str,
    created: u64,
    updated: u64,
    ignored: u64,
    error_reports: Value,
) -> String {
    json!({
        "status": status,
        "validationReport": {
            "errorReports": error_reports,
            "warningReports": [{
                "message": "UPSTREAM-SENSITIVE-CANARY",
                "trackerType": "TRACKED_ENTITY-SENSITIVE-CANARY",
                "uid": "UID-SENSITIVE-CANARY"
            }]
        },
        "stats": {
            "created": created,
            "updated": updated,
            "deleted": 0,
            "ignored": ignored,
            "total": created + updated + ignored
        }
    })
    .to_string()
}

async fn journal_rows(served: &Served) -> String {
    let (client, connection) = tokio_postgres::connect(&served.database, tokio_postgres::NoTls)
        .await
        .expect("connect the served journal schema");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .query(
            "SELECT to_jsonb(e)::text FROM adapter_journal_events AS e ORDER BY event_id",
            &[],
        )
        .await
        .expect("read every journal column")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn a_synchronous_create_uses_the_supplied_uid_and_replays_without_a_second_send() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        200,
        &import_summary("OK", 0, 1, 0, json!([])),
    )]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.write");
    let request = record("wk4JlTuVO9o");
    assert_matches_maintained_request_schema("person-create", &request);

    let first = raw_write(
        &served,
        &token,
        "POST",
        "/v1/records/person",
        "create-person-pack-1",
        &request,
    );
    let replay = raw_write(
        &served,
        &token,
        "POST",
        "/v1/records/person",
        "create-person-pack-1",
        &request,
    );

    assert_eq!(first.0, 201, "{}", String::from_utf8_lossy(&first.1));
    assert_eq!(replay, first, "the terminal update replays exact bytes");
    let requests = upstream.requests();
    assert_eq!(requests.len(), 1, "a replay makes no second source effect");
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].target, "/api/tracker?async=false");
    let bundle: Value = serde_json::from_slice(&requests[0].body).expect("tracker bundle JSON");
    assert_eq!(bundle["trackedEntities"][0]["trackedEntity"], "wk4JlTuVO9o");
    assert_eq!(bundle["trackedEntities"][0]["attributes"], json!([]));
}

#[tokio::test]
async fn a_synchronous_update_uses_the_path_bound_uid_and_replays_without_a_second_send() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        200,
        &import_summary("OK", 0, 1, 0, json!([])),
    )]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.write");
    let request = record("wk4JlTuVO9o");
    assert_matches_maintained_request_schema("person-update", &request);
    let mut missing_identity = request.clone();
    missing_identity["data"]
        .as_object_mut()
        .expect("request data is an object")
        .remove("recordIdentifier");
    let schema = maintained_request_schema("person-update");
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("the maintained request schema compiles");
    assert!(
        !validator.is_valid(&missing_identity),
        "the authored identity member is required by the exported schema"
    );

    let first = raw_write(
        &served,
        &token,
        "PUT",
        "/v1/records/person/wk4JlTuVO9o",
        "update-person-pack-1",
        &request,
    );
    let replay = raw_write(
        &served,
        &token,
        "PUT",
        "/v1/records/person/wk4JlTuVO9o",
        "update-person-pack-1",
        &request,
    );
    let mismatch = raw_write(
        &served,
        &token,
        "PUT",
        "/v1/records/person/wk4JlTuVO9o",
        "update-person-pack-mismatch",
        &record("another-person"),
    );

    assert_eq!(first.0, 200, "{}", String::from_utf8_lossy(&first.1));
    assert_eq!(replay, first, "the terminal update replays exact bytes");
    assert_eq!(mismatch.0, 422, "{}", String::from_utf8_lossy(&mismatch.1));
    let requests = upstream.requests();
    assert_eq!(
        requests.len(),
        1,
        "replay and mismatch make no source effect"
    );
    let bundle: Value = serde_json::from_slice(&requests[0].body).expect("tracker bundle JSON");
    assert_eq!(bundle["trackedEntities"][0]["trackedEntity"], "wk4JlTuVO9o");
    assert_eq!(bundle["trackedEntities"][0]["attributes"], json!([]));
}

#[tokio::test]
async fn a_partial_summary_discloses_only_four_counts_and_replays_without_a_second_send() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        200,
        &import_summary("WARNING", 1, 2, 1, json!([])),
    )]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.write");
    let request = record("wk4JlTuVO9o");

    let first = raw_write(
        &served,
        &token,
        "POST",
        "/v1/records/person",
        "partial-person-1",
        &request,
    );
    let replay = raw_write(
        &served,
        &token,
        "POST",
        "/v1/records/person",
        "partial-person-1",
        &request,
    );
    let (status, body) = &first;
    let problem: Value = serde_json::from_slice(body).expect("facade problem JSON");
    assert_eq!(*status, 409, "{}", String::from_utf8_lossy(body));
    assert_eq!(
        problem,
        json!({
            "title": "the write was only partially accepted",
            "status": 409,
            "detail": "The source accepted only part of the write.",
            "code": "source.write-partial",
            "data": {
                "imported": 1,
                "updated": 2,
                "ignored": 1,
                "rejected": 0
            }
        })
    );
    assert_eq!(replay, first, "the terminal 409 replays exact bytes");
    assert_eq!(upstream.request_count(), 1, "replay makes no second send");

    let problem_text = String::from_utf8_lossy(body);
    let journal = journal_rows(&served).await;
    for marker in [
        "UPSTREAM-SENSITIVE-CANARY",
        "TRACKED_ENTITY-SENSITIVE-CANARY",
        "EVENT-SENSITIVE-CANARY",
        "UID-SENSITIVE-CANARY",
    ] {
        assert!(!problem_text.contains(marker), "problem leaked {marker}");
        assert!(!journal.contains(marker), "journal leaked {marker}");
    }
}

#[tokio::test]
async fn an_unfinished_summary_is_explicitly_refused_until_d16_is_implemented() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        200,
        &json!({
            "status": "PENDING",
            "message": "UPSTREAM-SENSITIVE-CANARY"
        })
        .to_string(),
    )]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.write");

    let (status, body) = raw_write(
        &served,
        &token,
        "POST",
        "/v1/records/person",
        "unfinished-person-1",
        &record("wk4JlTuVO9o"),
    );
    let problem: Value = serde_json::from_slice(&body).expect("facade problem JSON");
    assert_eq!(status, 422, "{}", String::from_utf8_lossy(&body));
    assert_eq!(problem["code"], "source.validation");
    assert!(!String::from_utf8_lossy(&body).contains("UPSTREAM-SENSITIVE-CANARY"));
    assert_eq!(upstream.request_count(), 1);
}
