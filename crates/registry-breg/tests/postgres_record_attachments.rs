// SPDX-License-Identifier: Apache-2.0
//! Record attachment slots: an immediate Action create writes one file with
//! its record, a granted profile reads it inside its row boundary, and
//! retention removes references before it removes bytes.
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine as _;
use registry_breg::api::{VerifiedClaimValue, VerifiedRequestClaims};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::history_erasure::{
    erase_record_history, HistoryErasureRequest, HistoryErasureTimeouts, RecordHistoryErasureTarget,
};
use registry_breg::mutation::{MutationError, MutationFaultPoint};
use registry_breg::postgres::RegistryLockKey;
use registry_breg_client::{BRegIdempotencyKey, BRegProposalState};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tower::util::ServiceExt as _;
use uuid::Uuid;

const EVIDENCE: &[u8] = b"synthetic-evidence";
const FILE_CANARY: &[u8] = b"record-file-canary";

fn claims(subject: &str, jurisdiction: &str, scope: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        subject,
        BTreeSet::from([scope.to_owned()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string(jurisdiction).unwrap(),
        )]),
        registry_platform_oidc::ActorKind::Human,
    )
    .unwrap()
}
fn clerk(jurisdiction: &str) -> VerifiedRequestClaims {
    claims("clerk", jurisdiction, "application:manage")
}
fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}
fn repr_digest(bytes: &[u8]) -> String {
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(bytes))
    )
}

fn jurisdiction_boundary() -> Value {
    json!([{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}])
}

fn record_source() -> Value {
    json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"record-attachment-test","version":"1","defaultLanguage":"en",
            "canonicalBaseIri":"https://record-attachment.example.test"},
        "datasets":{"directory":{}},
        "recordTypes":{
            "programme":{"primaryDataset":"directory","route":"programmes","mutationMode":"mutable",
                "fields":[{"id":"open","type":"boolean","required":true,"classification":"internal"},
                    {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"}]},
            "application":{"primaryDataset":"directory","route":"applications","mutationMode":"mutable",
                "fields":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                    {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                    {"id":"programme","type":"reference","target":"programme","required":true,"classification":"internal"}],
                "attachments":[{"id":"evidence","maximumBytes":64,"contentTypes":["text/plain","application/pdf"],
                    "classification":"restricted","writeOnce":true}],
                "hooks":[{"phase":"after","id":"application-created","trigger":"created","projection":["name"]}]}},
        "actions":{
            "register":{"execution":{"mode":"immediate"},
                "inputs":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                    {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                    {"id":"programme","type":"reference","target":"programme","required":true,"classification":"internal"}],
                "commitGuards":{"targets":[{"input":"programme","field":"open","equals":true}]},
                "plan":{"type":"fixed","effects":[{"id":"application","target":{"recordType":"application"},
                    "operation":"create","set":{"name":{"fromInput":"name"},"jurisdiction":{"fromInput":"jurisdiction"},
                        "programme":{"fromInput":"programme"}},
                    "attachments":{"evidence":{"fromAttachment":"evidence"}}}]}},
            "rename":{"execution":{"mode":"proposal","proposal":{"review":{"type":"none"},
                    "application":{"mode":"manual"},"retention":{"mode":"operator-erase"},
                    "attachments":[{"id":"support","required":false,"maximumBytes":4096,
                        "contentTypes":["text/plain"],"classification":"restricted"}]}},
                "inputs":[{"id":"target","type":"reference","target":"application","required":true,"classification":"internal"},
                    {"id":"value","type":"string","required":true,"maximumLength":64,"classification":"internal"}],
                "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
                "plan":{"type":"fixed","effects":[{"id":"name","target":{"fromInput":"target"},"operation":"patch",
                    "set":{"name":{"fromInput":"value"}}}]}}},
        "accessProfiles":{
            "clerk":{"default":true,"principalClaim":"sub","requiredScopes":["application:manage"],
                "requiredPurposes":["registry-administration"],"permissions":{
                    "records":[{"recordType":"application","operations":["get","list"],
                            "readableFields":["name","jurisdiction","programme"],"readableAttachments":["evidence"],
                            "rowBoundaries":jurisdiction_boundary()},
                        {"recordType":"programme","operations":["get","list"],"readableFields":["open","jurisdiction"],
                            "rowBoundaries":jurisdiction_boundary()}],
                    "actions":[{"action":"register","operations":["invoke"],"results":["application"],"targets":[
                            {"recordType":"programme","rowBoundaries":jurisdiction_boundary()},
                            {"recordType":"application","rowBoundaries":jurisdiction_boundary()}]},
                        {"action":"rename","operations":["start"],"targets":[
                            {"recordType":"application","rowBoundaries":jurisdiction_boundary()}]}],
                    "proposals":[{"action":"rename","operations":["get","list","edit","submit","apply"],
                        "ownership":"caller","readableAttachments":["support"],"writableAttachments":["support"],
                        "targets":[{"recordType":"application","rowBoundaries":jurisdiction_boundary()}]}]}},
            "auditor":{"principalClaim":"sub","requiredScopes":["application:audit"],
                "requiredPurposes":["registry-administration"],"permissions":{
                    "records":[{"recordType":"application","operations":["get"],"readableFields":["name"],
                        "readableAttachments":["evidence"],"rowBoundaries":"unrestricted"}]}},
            "viewer":{"principalClaim":"sub","requiredScopes":["application:view"],
                "requiredPurposes":["registry-administration"],"permissions":{
                    "records":[{"recordType":"application","operations":["get"],"readableFields":["name"],
                        "rowBoundaries":"unrestricted"}]}}}})
}

fn compile(source: Value) -> Result<registry_breg::CompiledRegistry, String> {
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap())
        .map_err(|error| format!("{error:?}"))?;
    compile_project(&project, &[], CompileProfile::Authoring).map_err(|error| format!("{error:?}"))
}
fn registry() -> registry_breg::CompiledRegistry {
    compile(record_source()).expect("record attachment fixture compiles")
}

struct Exchange {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}
impl Exchange {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_owned()
    }
}

async fn send(
    fixture: &client_http::ClientFixture,
    claims: VerifiedRequestClaims,
    mut request: Request<Body>,
) -> Exchange {
    request.extensions_mut().insert(claims);
    let response = registry_breg::api::router(fixture.service())
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    Exchange {
        status,
        headers,
        body,
    }
}

fn file(content_type: &str, bytes: &[u8]) -> Value {
    json!({"contentType":content_type,"sha256":sha256_hex(bytes),
        "content":base64::engine::general_purpose::STANDARD.encode(bytes)})
}

async fn invoke(
    fixture: &client_http::ClientFixture,
    claims: VerifiedRequestClaims,
    idempotency_key: &str,
    input: Value,
    attachments: Option<Value>,
) -> Exchange {
    let mut body = json!({"input":input});
    if let Some(attachments) = attachments {
        body["attachments"] = attachments;
    }
    send(
        fixture,
        claims,
        Request::builder()
            .method("POST")
            .uri("/v1/actions/register")
            .header("content-type", "application/json")
            .header("idempotency-key", idempotency_key)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap(),
    )
    .await
}

fn register_input(programme: Uuid) -> Value {
    json!({"name":"Synthetic applicant","jurisdiction":"zone-a","programme":programme.to_string()})
}

async fn register(
    fixture: &client_http::ClientFixture,
    programme: Uuid,
    idempotency_key: &str,
    bytes: &[u8],
) -> Uuid {
    let response = invoke(
        fixture,
        clerk("zone-a"),
        idempotency_key,
        register_input(programme),
        Some(json!({"evidence":file("text/plain", bytes)})),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let id = response.json()["results"]["application"]["recordId"]
        .as_str()
        .expect("the granted result names the created record")
        .to_owned();
    Uuid::parse_str(&id).unwrap()
}

async fn download(
    fixture: &client_http::ClientFixture,
    claims: VerifiedRequestClaims,
    record: &str,
    slot: &str,
    profile: Option<&str>,
) -> Exchange {
    let query = profile.map_or_else(String::new, |profile| format!("?accessProfile={profile}"));
    send(
        fixture,
        claims,
        Request::builder()
            .method("GET")
            .uri(format!(
                "/v1/records/applications/{record}/attachments/{slot}{query}"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn insert_programme(
    fixture: &client_http::ClientFixture,
    open: bool,
    jurisdiction: &str,
) -> Uuid {
    let programme = &fixture.registry.entities()["programme"];
    let id = Uuid::new_v4();
    fixture
        .database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.\"{}\" (record_id, record_revision, record_lifecycle,
                    active_package_revision, \"{}\", \"{}\") VALUES ($1, 1, 'active', $2, $3, $4)",
                programme.physical_table,
                programme.fields["open"].physical_name,
                programme.fields["jurisdiction"].physical_name
            ),
            &[&id, &fixture.identity.activation_id, &open, &jurisdiction],
        )
        .await
        .unwrap();
    id
}

struct Counts {
    applications: i64,
    references: i64,
    live_references: i64,
    blobs: i64,
    outbox: i64,
}

async fn counts(fixture: &client_http::ClientFixture) -> Counts {
    let application = &fixture.registry.entities()["application"];
    let row = fixture
        .database
        .admin
        .query_one(
            &format!(
                "SELECT (SELECT count(*) FROM registry_data.\"{}\"),
                    (SELECT count(*) FROM registry_internal.registry_record_attachments),
                    (SELECT count(*) FROM registry_internal.registry_record_attachments
                      WHERE erased_at IS NULL),
                    (SELECT count(*) FROM registry_internal.registry_attachment_blobs),
                    (SELECT count(*) FROM registry_internal.registry_outbox)",
                application.physical_table
            ),
            &[],
        )
        .await
        .unwrap();
    Counts {
        applications: row.get(0),
        references: row.get(1),
        live_references: row.get(2),
        blobs: row.get(3),
        outbox: row.get(4),
    }
}

async fn erase_history(fixture: &client_http::ClientFixture, record: Uuid) {
    let (mut migration, task) = fixture.database.connect_migration().await;
    erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &fixture.identity,
            migration_role: &fixture.database.migration_role,
            lock_key: RegistryLockKey::derive(fixture.registry.registry_id()).unwrap(),
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &fixture
                .database
                .audit(AuditProfile::production_from_secret_bytes(vec![0x71; 32].into()).unwrap()),
            operator_reference: "operator-reference",
            reason: "retention-request",
            target: RecordHistoryErasureTarget::new("application", record, 1),
        },
    )
    .await
    .expect("history erasure succeeds");
    drop(migration);
    task.abort();
}

fn assert_file(response: &Exchange, bytes: &[u8]) {
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, bytes);
    assert_eq!(response.headers["content-type"], "text/plain");
    assert_eq!(response.headers["repr-digest"], repr_digest(bytes).as_str());
    assert_eq!(response.headers["x-content-type-options"], "nosniff");
    assert_eq!(response.headers["cache-control"], "no-store");
    assert!(response.headers["content-disposition"]
        .to_str()
        .unwrap()
        .starts_with("attachment"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_and_file_commit_together_and_every_granted_profile_reads_the_same_bytes() {
    let fixture = client_http::ClientFixture::start(registry(), clerk("zone-a")).await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let before = counts(&fixture).await;
    let record = register(&fixture, programme, "register-first", FILE_CANARY).await;
    let after = counts(&fixture).await;
    assert_eq!(after.applications, before.applications + 1);
    assert_eq!(after.references, 1);
    assert_eq!(after.blobs, 1);
    let stored = fixture
        .database
        .admin
        .query_one(
            "SELECT reference.sha256, reference.content_type, reference.byte_size,
                    reference.attached_revision, blob.state
               FROM registry_internal.registry_record_attachments AS reference
               JOIN registry_internal.registry_attachment_blobs AS blob USING (sha256)
              WHERE reference.entity_id = 'application' AND reference.record_id = $1
                AND reference.slot_id = 'evidence'",
            &[&record],
        )
        .await
        .unwrap();
    assert_eq!(stored.get::<_, String>(0), sha256_hex(FILE_CANARY));
    assert_eq!(stored.get::<_, String>(1), "text/plain");
    assert_eq!(stored.get::<_, i64>(2), FILE_CANARY.len() as i64);
    assert_eq!(stored.get::<_, i64>(3), 1);
    assert_eq!(stored.get::<_, String>(4), "live");

    let replay = invoke(
        &fixture,
        clerk("zone-a"),
        "register-first",
        register_input(programme),
        Some(json!({"evidence":file("text/plain", FILE_CANARY)})),
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(
        replay.json()["results"]["application"]["recordId"],
        record.to_string()
    );
    assert_eq!(
        counts(&fixture).await.references,
        1,
        "a replay attaches nothing"
    );
    let reused = invoke(
        &fixture,
        clerk("zone-a"),
        "register-first",
        register_input(programme),
        Some(json!({"evidence":file("text/plain", b"other bytes")})),
    )
    .await;
    assert_eq!(
        reused.status,
        StatusCode::CONFLICT,
        "a different file is a different request"
    );

    for _ in 0..2 {
        assert_file(
            &download(
                &fixture,
                clerk("zone-a"),
                &record.to_string(),
                "evidence",
                None,
            )
            .await,
            FILE_CANARY,
        );
    }
    assert_file(
        &download(
            &fixture,
            claims("auditor", "zone-z", "application:audit"),
            &record.to_string(),
            "evidence",
            Some("auditor"),
        )
        .await,
        FILE_CANARY,
    );

    let downloaded = fixture
        .http
        .client
        .download_record_attachment("applications", &record.to_string(), "evidence", None)
        .await
        .unwrap()
        .value;
    assert_eq!(downloaded.as_bytes(), FILE_CANARY);
    assert_eq!(downloaded.media_type(), "text/plain");
    assert_eq!(
        downloaded.representation_digest().unwrap().as_str(),
        repr_digest(FILE_CANARY)
    );

    // Hooks project declared fields only. The outbox never carries the file.
    let payloads = fixture
        .database
        .admin
        .query(
            "SELECT payload::text FROM registry_internal.registry_outbox",
            &[],
        )
        .await
        .unwrap();
    assert!(!payloads.is_empty(), "the created hook wrote an event");
    let encoded = base64::engine::general_purpose::STANDARD.encode(FILE_CANARY);
    for row in payloads {
        let payload: Option<String> = row.get(0);
        let payload = payload.unwrap_or_default();
        assert!(!payload.contains("record-file-canary"));
        assert!(!payload.contains(&encoded));
        assert!(!payload.contains("evidence"));
    }

    // The service never releases stored bytes that no longer match the
    // digest recorded when the file was attached.
    let mut corrupt = FILE_CANARY.to_vec();
    corrupt[0] = b'X';
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs SET content = $1",
            &[&corrupt],
        )
        .await
        .unwrap();
    assert_eq!(
        download(
            &fixture,
            clerk("zone-a"),
            &record.to_string(),
            "evidence",
            None
        )
        .await
        .status,
        StatusCode::SERVICE_UNAVAILABLE,
        "stored bytes that no longer match their digest are never released"
    );
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profiles_without_the_grant_or_outside_the_row_boundary_cannot_read() {
    let fixture = client_http::ClientFixture::start(registry(), clerk("zone-a")).await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let record = register(&fixture, programme, "register-boundary", EVIDENCE).await;
    let record = record.to_string();
    let viewer = || claims("viewer", "zone-a", "application:view");
    let viewed = send(
        &fixture,
        viewer(),
        Request::builder()
            .uri(format!(
                "/v1/records/applications/{record}?accessProfile=viewer"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        viewed.status,
        StatusCode::OK,
        "the viewer may read the record"
    );
    assert!(!String::from_utf8_lossy(&viewed.body).contains("evidence"));
    let refusals = [
        download(&fixture, viewer(), &record, "evidence", Some("viewer")).await,
        download(&fixture, clerk("zone-b"), &record, "evidence", None).await,
        download(&fixture, clerk("zone-a"), &record, "missing", None).await,
        download(
            &fixture,
            clerk("zone-a"),
            &Uuid::new_v4().to_string(),
            "evidence",
            None,
        )
        .await,
        download(&fixture, clerk("zone-a"), "not-a-record", "evidence", None).await,
        download(
            &fixture,
            claims("viewer", "zone-a", "application:view"),
            &record,
            "evidence",
            Some("auditor"),
        )
        .await,
    ];
    for refusal in refusals {
        assert_eq!(refusal.status, StatusCode::NOT_FOUND);
        assert!(!refusal.body.windows(EVIDENCE.len()).any(|w| w == EVIDENCE));
        assert!(refusal.headers.get("repr-digest").is_none());
    }
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_waiting_for_or_refused_by_verification_is_concealed() {
    let fixture = client_http::ClientFixture::start(registry(), clerk("zone-a")).await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let record = register(&fixture, programme, "register-verified", EVIDENCE)
        .await
        .to_string();
    // Pin a verification policy over the stored file, as a binding that
    // turns verification on does. No verdict means the file is pending.
    let policy = format!("sha256:{}", "a".repeat(64));
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_storage_binding
                SET verification_policy = $1",
            &[&policy],
        )
        .await
        .unwrap();
    let concealed = |response: Exchange| {
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert!(!response.body.windows(EVIDENCE.len()).any(|w| w == EVIDENCE));
        assert!(response.headers.get("repr-digest").is_none());
    };
    concealed(download(&fixture, clerk("zone-a"), &record, "evidence", None).await);
    let verdict = |verdict: &'static str| {
        let admin = &fixture.database.admin;
        let policy = policy.clone();
        async move {
            admin
                .execute(
                    "INSERT INTO registry_internal.registry_attachment_verification
                       (sha256, policy_digest, content_type, verdict)
                     VALUES ($1, $2, 'text/plain', $3)
                     ON CONFLICT (sha256, policy_digest, content_type)
                     DO UPDATE SET verdict = EXCLUDED.verdict",
                    &[&sha256_hex(EVIDENCE), &policy, &verdict],
                )
                .await
                .unwrap();
        }
    };
    verdict("approved").await;
    assert_file(
        &download(&fixture, clerk("zone-a"), &record, "evidence", None).await,
        EVIDENCE,
    );
    verdict("rejected").await;
    concealed(download(&fixture, clerk("zone-a"), &record, "evidence", None).await);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_commit_leaves_neither_the_record_nor_the_file() {
    for fault in [
        MutationFaultPoint::BeforeTerminalAudit,
        MutationFaultPoint::BeforeIdempotency,
        MutationFaultPoint::BeforeCommit,
    ] {
        let fixture =
            client_http::ClientFixture::start_with_mutations(registry(), clerk("zone-a"), |m| {
                m.with_fault_for_test(fault)
            })
            .await;
        let programme = insert_programme(&fixture, true, "zone-a").await;
        let response = invoke(
            &fixture,
            clerk("zone-a"),
            "register-fault",
            register_input(programme),
            Some(json!({"evidence":file("text/plain", EVIDENCE)})),
        )
        .await;
        // The fault fired inside the write, not at request validation.
        assert_eq!(
            response.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{fault:?}: {}",
            String::from_utf8_lossy(&response.body)
        );
        let after = counts(&fixture).await;
        assert_eq!(after.applications, 0, "{fault:?}");
        assert_eq!(after.references, 0, "{fault:?}");
        assert_eq!(after.blobs, 0, "{fault:?}");
        assert_eq!(after.outbox, 0, "{fault:?}");
        fixture.finish().await;
    }
    // The same request without a fault commits the record, the file and the
    // outbox row together.
    let fixture = client_http::ClientFixture::start(registry(), clerk("zone-a")).await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    register(&fixture, programme, "register-fault", EVIDENCE).await;
    let after = counts(&fixture).await;
    assert_eq!(after.applications, 1);
    assert_eq!(after.references, 1);
    assert_eq!(after.blobs, 1);
    assert!(after.outbox > 0);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_refusal_leaves_no_record_and_no_file() {
    let fixture = client_http::ClientFixture::start(registry(), clerk("zone-a")).await;
    let open = insert_programme(&fixture, true, "zone-a").await;
    let closed = insert_programme(&fixture, false, "zone-a").await;
    let mut wrong_digest = file("text/plain", EVIDENCE);
    wrong_digest["sha256"] = json!(sha256_hex(b"different"));
    let mut empty = file("text/plain", b"");
    empty["sha256"] = json!(sha256_hex(b""));
    let cases = [
        (
            "content-type",
            open,
            Some(json!({"evidence":file("image/png", EVIDENCE)})),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "attachment.content-type",
        ),
        (
            "too-large",
            open,
            Some(json!({"evidence":file("text/plain", &[b'a'; 65])})),
            StatusCode::PAYLOAD_TOO_LARGE,
            "attachment.too-large",
        ),
        (
            "digest",
            open,
            Some(json!({"evidence":wrong_digest})),
            StatusCode::UNPROCESSABLE_ENTITY,
            "attachment.digest-mismatch",
        ),
        ("missing", open, None, StatusCode::BAD_REQUEST, ""),
        (
            "unknown",
            open,
            Some(
                json!({"evidence":file("text/plain", EVIDENCE),"other":file("text/plain", EVIDENCE)}),
            ),
            StatusCode::BAD_REQUEST,
            "",
        ),
        (
            "empty",
            open,
            Some(json!({"evidence":empty})),
            StatusCode::BAD_REQUEST,
            "",
        ),
        (
            "guard",
            closed,
            Some(json!({"evidence":file("text/plain", EVIDENCE)})),
            StatusCode::PRECONDITION_FAILED,
            "action.guard_failed",
        ),
    ];
    for (name, programme, attachments, status, code) in cases {
        let response = invoke(
            &fixture,
            clerk("zone-a"),
            &format!("refusal-{name}"),
            register_input(programme),
            attachments,
        )
        .await;
        assert_eq!(
            response.status,
            status,
            "{name}: {}",
            String::from_utf8_lossy(&response.body)
        );
        if !code.is_empty() {
            assert_eq!(response.code(), code, "{name}");
        }
        let after = counts(&fixture).await;
        assert_eq!(after.applications, 0, "{name}");
        assert_eq!(after.references, 0, "{name}");
        assert_eq!(after.blobs, 0, "{name}");
    }
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_once_slot_refuses_a_second_file_even_after_erasure() {
    let fixture = client_http::ClientFixture::start(registry(), clerk("zone-a")).await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let record = register(&fixture, programme, "register-once", EVIDENCE).await;
    // The storage layer is the only second writer part A has: a create
    // effect cannot reach an existing record. It runs as the table owner.
    let second = |bytes: &'static [u8]| {
        let database = &fixture.database;
        async move {
            let (mut migration, task) = database.connect_migration().await;
            let result = registry_breg::attachment_store::test_support::attach_record(
                &mut migration,
                "application",
                record,
                "evidence",
                "text/plain",
                bytes,
                2,
            )
            .await;
            drop(migration);
            task.abort();
            result
        }
    };
    assert!(matches!(
        second(b"replacement").await,
        Err(MutationError::AttachmentSlotWriteOnce)
    ));
    assert!(matches!(
        second(EVIDENCE).await,
        Err(MutationError::AttachmentSlotWriteOnce)
    ));
    erase_history(&fixture, record).await;
    assert!(matches!(
        second(b"replacement").await,
        Err(MutationError::AttachmentSlotWriteOnce)
    ));
    let after = counts(&fixture).await;
    assert_eq!(after.references, 1);
    assert_eq!(after.live_references, 0);
    assert_eq!(after.blobs, 0, "refused writes leave no bytes behind");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_erasure_removes_the_reference_then_the_bytes_nothing_else_refers_to() {
    let fixture = client_http::ClientFixture::start(registry(), clerk("zone-a")).await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let first = register(&fixture, programme, "register-shared-a", EVIDENCE).await;
    let second = register(&fixture, programme, "register-shared-b", EVIDENCE).await;
    let shared = counts(&fixture).await;
    assert_eq!(shared.references, 2);
    assert_eq!(shared.blobs, 1, "equal bytes are stored once");

    erase_history(&fixture, first).await;
    let after_first = counts(&fixture).await;
    assert_eq!(after_first.live_references, 1);
    assert_eq!(
        after_first.blobs, 1,
        "the other record still refers to the bytes"
    );
    assert_eq!(
        download(
            &fixture,
            clerk("zone-a"),
            &first.to_string(),
            "evidence",
            None
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert_file(
        &download(
            &fixture,
            clerk("zone-a"),
            &second.to_string(),
            "evidence",
            None,
        )
        .await,
        EVIDENCE,
    );
    let erased = fixture
        .database
        .admin
        .query_one(
            "SELECT erased_at IS NOT NULL, attached_by IS NULL, attached_at IS NULL
               FROM registry_internal.registry_record_attachments WHERE record_id = $1",
            &[&first],
        )
        .await
        .unwrap();
    assert!(erased.get::<_, bool>(0));
    assert!(erased.get::<_, bool>(1));
    assert!(erased.get::<_, bool>(2));

    erase_history(&fixture, second).await;
    let after_second = counts(&fixture).await;
    assert_eq!(after_second.live_references, 0);
    assert_eq!(after_second.blobs, 0, "unreferenced bytes are removed");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proposal_erasure_never_removes_bytes_a_record_refers_to() {
    let fixture = client_http::ClientFixture::start(registry(), clerk("zone-a")).await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let record = register(&fixture, programme, "register-proposal", EVIDENCE).await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let action = metadata.value.select_action("rename", "clerk").unwrap();
    let input = registry_breg_client::BRegActionInvocationRequest::new(
        &action,
        json!({"target":record.to_string(),"value":"Renamed"})
            .as_object()
            .unwrap()
            .clone(),
        None,
    )
    .unwrap();
    let draft = client
        .start_proposal(&action, &input, &key("rename-start"))
        .await
        .unwrap()
        .value;
    // The storage layer stores equal bytes once, so this Proposal reference
    // and the record reference share one blob row.
    let uploaded = client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            EVIDENCE,
            &key("rename-upload"),
        )
        .await
        .unwrap()
        .value;
    assert_eq!(counts(&fixture).await.blobs, 1);
    let submit = client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("rename-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let apply = client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":1,"effectDigest":submitted.effect_digest().unwrap(),
                "reason":"rename-reason"}),
            &key("rename-apply"),
        )
        .unwrap();
    let applied = client.execute_proposal(&apply).await.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    let (mut migration, task) = fixture.database.connect_migration().await;
    let erasure = registry_breg::proposal_retention::erase_proposal_detail(
        &mut migration,
        &fixture.registry,
        registry_breg::proposal_retention::ProposalDetailErasureScope {
            action_id: "rename",
            proposal_id: Uuid::parse_str(applied.id()).unwrap(),
            submission_version: 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(erasure.attachment_references, 1);
    drop(migration);
    task.abort();
    let state = fixture
        .database
        .admin
        .query_one(
            "SELECT state FROM registry_internal.registry_attachment_blobs WHERE sha256 = $1",
            &[&sha256_hex(EVIDENCE)],
        )
        .await
        .unwrap();
    assert_eq!(state.get::<_, String>(0), "live");
    assert_file(
        &download(
            &fixture,
            clerk("zone-a"),
            &record.to_string(),
            "evidence",
            None,
        )
        .await,
        EVIDENCE,
    );
    fixture.finish().await;
}

#[test]
fn declarations_grants_and_effects_are_validated() {
    let refused = |mutate: &dyn Fn(&mut Value), code: &str| {
        let mut source = record_source();
        mutate(&mut source);
        let error = compile(source).expect_err(code);
        assert!(error.contains(code), "{code}: {error}");
    };
    refused(
        &|source| {
            source["recordTypes"]["application"]["attachments"][0]
                .as_object_mut()
                .unwrap()
                .remove("writeOnce");
        },
        "writeOnce",
    );
    refused(
        &|source| {
            source["recordTypes"]["application"]["attachments"][0]["writeOnce"] = json!(false)
        },
        "breg.attachment.write-once-required",
    );
    refused(
        &|source| {
            source["accessProfiles"]["viewer"]["permissions"]["records"][0]
                ["readableAttachments"] = json!(["missing"]);
        },
        "breg.access-profile.attachment-grant-invalid",
    );
    refused(
        &|source| {
            let grant = &mut source["accessProfiles"]["clerk"]["permissions"]["records"][0];
            grant["operations"] = json!(["list"]);
        },
        "breg.access-profile.attachment-grant-invalid",
    );
    refused(
        &|source| {
            source["actions"]["register"]["plan"]["effects"][0]["attachments"] =
                json!({"missing":{"fromAttachment":"evidence"}});
        },
        "breg.action.attachment-invalid",
    );
    refused(
        &|source| {
            source["actions"]["register"]["plan"]["effects"][0]["attachments"] =
                json!({"evidence":{"fromAttachment":"name"}});
        },
        "breg.action.attachment-invalid",
    );
    refused(
        &|source| {
            source["actions"]["rename"]["plan"]["effects"][0]["attachments"] =
                json!({"evidence":{"fromAttachment":"evidence"}});
        },
        "breg.action.attachment-invalid",
    );
    refused(
        &|source| {
            source["actions"]["register"]["execution"] = json!({"mode":"proposal","proposal":{"review":{"type":"none"},
                    "application":{"mode":"manual"},"retention":{"mode":"operator-erase"}}});
            source["accessProfiles"]["clerk"]["permissions"]["actions"][0]["operations"] =
                json!(["start"]);
        },
        "breg.action.attachment-invalid",
    );
}

#[test]
fn generated_contracts_publish_the_slot_download_and_the_invoke_file_member() {
    let compiled = registry();
    let artifact = |path: &str| -> Value {
        serde_json::from_slice(&compiled.artifacts().get(path).expect(path).bytes).unwrap()
    };
    let openapi = artifact("generated/openapi.json");
    let download =
        &openapi["paths"]["/v1/records/applications/{record_id}/attachments/evidence"]["get"];
    assert_eq!(
        download["operationId"],
        "records.application.get.attachment.evidence"
    );
    assert_eq!(download["x-registry-attachmentSlot"], "evidence");
    // Only the profiles whose grant names the slot are listed.
    assert_eq!(
        download["x-registry-accessProfiles"],
        json!(["auditor", "clerk"])
    );
    let content = download["responses"]["200"]["content"].as_object().unwrap();
    assert_eq!(
        content.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from(["application/pdf".to_owned(), "text/plain".to_owned()])
    );
    assert_eq!(content["text/plain"]["schema"]["maxLength"], 64);
    assert!(download["responses"]["200"]["headers"]["Repr-Digest"].is_object());
    // A record type with no slot has no download path.
    assert!(openapi["paths"]
        .as_object()
        .unwrap()
        .keys()
        .all(
            |path| !path.starts_with("/v1/records/programmes/") || !path.contains("/attachments/")
        ));

    let invoke = artifact("generated/action-schemas/register.invoke.input.schema.json");
    assert!(invoke["required"]
        .as_array()
        .unwrap()
        .contains(&json!("attachments")));
    let files = &invoke["properties"]["attachments"];
    assert_eq!(files["required"], json!(["evidence"]));
    assert_eq!(files["additionalProperties"], json!(false));
    let evidence = &files["properties"]["evidence"];
    assert_eq!(
        evidence["required"],
        json!(["contentType", "sha256", "content"])
    );
    assert_eq!(
        evidence["properties"]["contentType"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["application/pdf".to_owned(), "text/plain".to_owned()])
    );
    assert_eq!(evidence["x-registry-attachmentSlot"], "evidence");
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&invoke)
        .unwrap();
    let programme = Uuid::nil();
    assert!(
        validator.is_valid(&json!({"input":register_input(programme),
        "attachments":{"evidence":file("text/plain", EVIDENCE)}}))
    );
    assert!(!validator.is_valid(&json!({"input":register_input(programme)})));
    assert!(
        !validator.is_valid(&json!({"input":register_input(programme),
        "attachments":{"evidence":file("image/png", EVIDENCE)}}))
    );
    // A Proposal-mode Action carries no record file member.
    let start = artifact("generated/action-schemas/rename.invoke.input.schema.json");
    assert!(start["properties"].get("attachments").is_none());
}
