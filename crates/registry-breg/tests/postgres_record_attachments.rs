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
use registry_breg::field_encryption_backfill::{
    erase_field_encryption_history, FieldEncryptionHistoryErasureRequest,
};
use registry_breg::history_erasure::{
    erase_record_history, HistoryErasureRequest, HistoryErasureTimeouts, RecordHistoryErasureTarget,
};
use registry_breg::mutation::{MutationError, MutationFaultPoint};
use registry_breg::postgres::RegistryLockKey;
use registry_breg_client::{
    BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey, BRegProposalState, BRegRecordFormat,
};
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
                    "set":{"name":{"fromInput":"value"}}}]}},
            // The built-in executor applies `enrol`, so its promotion runs on
            // the automatic path. `note` is a Proposal file nothing promotes.
            "enrol":{"execution":{"mode":"proposal","proposal":{"review":{"type":"none"},
                    "application":{"mode":"automatic","maximumAttempts":3},"retention":{"mode":"operator-erase"},
                    "attachments":[{"id":"document","required":false,"maximumBytes":64,
                            "contentTypes":["text/plain"],"classification":"restricted"},
                        {"id":"note","required":false,"maximumBytes":64,
                            "contentTypes":["text/plain"],"classification":"restricted"}]}},
                "inputs":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                    {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                    {"id":"programme","type":"reference","target":"programme","required":true,"classification":"internal"}],
                "plan":{"type":"fixed","effects":[{"id":"application","target":{"recordType":"application"},
                    "operation":"create","set":{"name":{"fromInput":"name"},"jurisdiction":{"fromInput":"jurisdiction"},
                        "programme":{"fromInput":"programme"}},
                    "attachments":{"evidence":{"fromAttachment":"document"}}}]}},
            // A caller applies `amend`. One file fills the slot of the record
            // it creates and the slot of the record it updates.
            "amend":{"execution":{"mode":"proposal","proposal":{"review":{"type":"none"},
                    "application":{"mode":"manual"},"retention":{"mode":"operator-erase"},
                    "attachments":[{"id":"document","required":true,"maximumBytes":64,
                        "contentTypes":["text/plain"],"classification":"restricted"}]}},
                "inputs":[{"id":"target","type":"reference","target":"application","required":true,"classification":"internal"},
                    {"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                    {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                    {"id":"programme","type":"reference","target":"programme","required":true,"classification":"internal"}],
                "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
                "plan":{"type":"fixed","effects":[
                    {"id":"copy","target":{"recordType":"application"},"operation":"create",
                        "set":{"name":{"fromInput":"name"},"jurisdiction":{"fromInput":"jurisdiction"},
                            "programme":{"fromInput":"programme"}},
                        "attachments":{"evidence":{"fromAttachment":"document"}}},
                    {"id":"original","target":{"fromInput":"target"},"operation":"patch",
                        "set":{"name":{"fromInput":"name"}},
                        "attachments":{"evidence":{"fromAttachment":"document"}}}]}}},
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
                            {"recordType":"application","rowBoundaries":jurisdiction_boundary()}]},
                        {"action":"enrol","operations":["start"],"targets":[
                            {"recordType":"programme","rowBoundaries":jurisdiction_boundary()},
                            {"recordType":"application","rowBoundaries":jurisdiction_boundary()}]},
                        {"action":"amend","operations":["start"],"targets":[
                            {"recordType":"programme","rowBoundaries":jurisdiction_boundary()},
                            {"recordType":"application","rowBoundaries":jurisdiction_boundary()}]}],
                    "proposals":[{"action":"rename","operations":["get","list","edit","submit","apply"],
                        "ownership":"caller","readableAttachments":["support"],"writableAttachments":["support"],
                        "targets":[{"recordType":"application","rowBoundaries":jurisdiction_boundary()}]},
                        {"action":"enrol","operations":["get","list","edit","submit"],
                            "ownership":"caller","readableAttachments":["document","note"],
                            "writableAttachments":["document","note"],"targets":[
                                {"recordType":"programme","rowBoundaries":jurisdiction_boundary()},
                                {"recordType":"application","rowBoundaries":jurisdiction_boundary()}]},
                        {"action":"amend","operations":["get","list","edit","submit","apply"],
                            "ownership":"caller","readableAttachments":["document"],
                            "writableAttachments":["document"],"targets":[
                                {"recordType":"programme","rowBoundaries":jurisdiction_boundary()},
                                {"recordType":"application","rowBoundaries":jurisdiction_boundary()}]}]}},
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
    erase_history_through(fixture, record, 1).await;
}

async fn erase_history_through(fixture: &client_http::ClientFixture, record: Uuid, revision: i64) {
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
            target: RecordHistoryErasureTarget::new("application", record, revision),
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

fn enrol_input(programme: Uuid, name: &str) -> Value {
    json!({"name":name,"jurisdiction":"zone-a","programme":programme.to_string()})
}

fn amend_input(target: Uuid, programme: Uuid, name: &str) -> Value {
    json!({"target":target.to_string(),"name":name,"jurisdiction":"zone-a",
        "programme":programme.to_string()})
}

/// Starts a Proposal of `action_id`, uploads each `(slot, bytes)` file as
/// text and submits it.
async fn submit_proposal(
    fixture: &client_http::ClientFixture,
    action_id: &str,
    input: Value,
    files: &[(&str, &[u8])],
    prefix: &str,
) -> registry_breg_client::BRegProposal {
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let action = metadata.value.select_action(action_id, "clerk").unwrap();
    let request = registry_breg_client::BRegActionInvocationRequest::new(
        &action,
        input.as_object().unwrap().clone(),
        None,
    )
    .unwrap();
    let mut proposal = client
        .start_proposal(&action, &request, &key(&format!("{prefix}-start")))
        .await
        .unwrap()
        .value;
    for (slot, bytes) in files {
        proposal = client
            .upload_proposal_attachment(
                &proposal,
                slot,
                "text/plain",
                bytes,
                &key(&format!("{prefix}-upload-{slot}")),
            )
            .await
            .unwrap()
            .value;
    }
    let submit = client
        .prepare_proposal(
            &proposal,
            "submit",
            json!({}),
            &key(&format!("{prefix}-submit")),
        )
        .unwrap();
    client.execute_proposal(&submit).await.unwrap().value
}

async fn apply_proposal(
    fixture: &client_http::ClientFixture,
    submitted: &registry_breg_client::BRegProposal,
    prefix: &str,
) -> Result<registry_breg_client::BRegProposal, registry_breg_client::BaseRegistryClientError> {
    let client = &fixture.http.client;
    let apply = client
        .prepare_proposal(
            submitted,
            "apply",
            json!({"submissionVersion":1,"effectDigest":submitted.effect_digest().unwrap(),
                "reason":"promotion-reason"}),
            &key(&format!("{prefix}-apply")),
        )
        .unwrap();
    client
        .execute_proposal(&apply)
        .await
        .map(|complete| complete.value)
}

/// Runs the built-in executor once and returns the job's state and last
/// error code.
async fn run_automatic(
    fixture: &client_http::ClientFixture,
    proposal: &registry_breg_client::BRegProposal,
) -> (String, Option<String>) {
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT state,last_error_code FROM registry_internal.registry_proposal_application_jobs
             WHERE proposal_id=$1",
            &[&Uuid::parse_str(proposal.id()).unwrap()],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

async fn revisions(fixture: &client_http::ClientFixture) -> i64 {
    fixture
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_revisions",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

/// Live record references as `(record, slot, sha256, attached revision)`.
async fn record_references(
    fixture: &client_http::ClientFixture,
) -> BTreeSet<(Uuid, String, String, i64)> {
    fixture
        .database
        .admin
        .query(
            "SELECT record_id,slot_id,sha256,attached_revision
               FROM registry_internal.registry_record_attachments WHERE erased_at IS NULL",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect()
}

async fn blob_hashes(fixture: &client_http::ClientFixture) -> BTreeSet<String> {
    fixture
        .database
        .admin
        .query(
            "SELECT sha256 FROM registry_internal.registry_attachment_blobs WHERE state='live'",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

async fn application_ids(fixture: &client_http::ClientFixture, name: &str) -> BTreeSet<Uuid> {
    let application = &fixture.registry.entities()["application"];
    fixture
        .database
        .admin
        .query(
            &format!(
                "SELECT record_id FROM registry_data.\"{}\" WHERE \"{}\"=$1",
                application.physical_table, application.fields["name"].physical_name
            ),
            &[&name],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

async fn erase_proposal(
    fixture: &client_http::ClientFixture,
    action_id: &str,
    proposal: &registry_breg_client::BRegProposal,
) -> u64 {
    let (mut migration, task) = fixture.database.connect_migration().await;
    let erasure = registry_breg::proposal_retention::erase_proposal_detail(
        &mut migration,
        &fixture.registry,
        registry_breg::proposal_retention::ProposalDetailErasureScope {
            action_id,
            proposal_id: Uuid::parse_str(proposal.id()).unwrap(),
            submission_version: 1,
        },
    )
    .await
    .unwrap();
    drop(migration);
    task.abort();
    erasure.attachment_references
}

/// The operation a record slot download audits and logs under.
const DOWNLOAD_OPERATION: &str = "records.application.get:attachment:evidence";

/// The phase, outcome and operation of each audit entry since `before`.
fn audited_since(
    fixture: &client_http::ClientFixture,
    before: usize,
) -> Vec<(String, String, String)> {
    fixture.audit_capture.entries()[before..]
        .iter()
        .map(|entry| {
            let field = |name: &str| {
                entry["record"][name]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned()
            };
            (field("phase"), field("outcome"), field("operationId"))
        })
        .collect()
}

fn audited(phase: &str, outcome: &str) -> (String, String, String) {
    (
        phase.to_owned(),
        outcome.to_owned(),
        DOWNLOAD_OPERATION.to_owned(),
    )
}

async fn access_log_operations(fixture: &client_http::ClientFixture, record: Uuid) -> Vec<String> {
    fixture
        .database
        .admin
        .query(
            "SELECT operation_id FROM registry_internal.registry_subject_access_log
              WHERE entity_id = 'application' AND record_id = $1 ORDER BY accessed_at, event_id",
            &[&record],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_action_with_attachments_can_check_its_target_before_invocation() {
    let mut source = record_source();
    source["actions"]["register"]["commitGuards"]["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({"input":"programme","revision":"unchanged"}));
    let fixture =
        client_http::ClientFixture::start(compile(source).unwrap(), clerk("zone-a")).await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let request = |path, body: Value| {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let availability = send(
        &fixture,
        clerk("zone-a"),
        request(
            "/v1/actions/register/availability",
            json!({"targetInput":"programme","input":{"programme":programme.to_string()}}),
        ),
    )
    .await;
    assert_eq!(
        availability.status,
        StatusCode::OK,
        "{}",
        availability.json()
    );
    assert_eq!(availability.json()["availability"]["available"], true);

    let conditions = send(
        &fixture,
        clerk("zone-a"),
        request(
            "/v1/actions/register/target-conditions",
            json!({"input":{"programme":programme.to_string()}}),
        ),
    )
    .await;
    assert_eq!(conditions.status, StatusCode::OK, "{}", conditions.json());
    assert!(conditions.json()["preconditions"]["programme"]["ifMatch"].is_string());
    assert_eq!(counts(&fixture).await.applications, 0);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_and_file_commit_together_and_every_granted_profile_reads_the_same_bytes() {
    // The subject access log is on, so every released file is logged.
    let mut source = record_source();
    source["recordTypes"]["application"]["accessLog"] = json!({"subjectField":"name"});
    let registry = compile(source).expect("record attachment fixture with an access log compiles");
    let fixture = client_http::ClientFixture::start(registry, clerk("zone-a")).await;
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

    // A download is audited as an attempt and a Returned terminal under the
    // slot's own operation, and the subject access log records it once.
    let audit_before = fixture.audit_capture.entries().len();
    let logged = access_log_operations(&fixture, record).await;
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
    assert_eq!(
        audited_since(&fixture, audit_before),
        [audited("attempt", ""), audited("terminal", "returned")]
    );
    assert_eq!(
        access_log_operations(&fixture, record).await,
        [logged.clone(), vec![DOWNLOAD_OPERATION.to_owned()]].concat()
    );
    // The concealed 404 of a record the caller cannot see is audited as a
    // Refused terminal and logs nothing.
    let audit_before = fixture.audit_capture.entries().len();
    let absent = Uuid::new_v4();
    assert_eq!(
        download(
            &fixture,
            clerk("zone-a"),
            &absent.to_string(),
            "evidence",
            None
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        audited_since(&fixture, audit_before),
        [audited("attempt", ""), audited("terminal", "refused")]
    );
    assert!(access_log_operations(&fixture, absent).await.is_empty());

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
    let audit_before = fixture.audit_capture.entries().len();
    let logged = access_log_operations(&fixture, record).await;
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
    // A store failure after the attempt still ends in a Refused terminal,
    // and a file that was not released is not logged.
    assert_eq!(
        audited_since(&fixture, audit_before),
        [audited("attempt", ""), audited("terminal", "refused")]
    );
    assert_eq!(access_log_operations(&fixture, record).await, logged);
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
async fn immediate_action_refuses_a_completed_rejected_verdict_and_keeps_approved_and_unseen_files()
{
    use registry_breg::attachment_verification::AttachmentVerification;
    use registry_platform_config::{AttachmentVerifierConfig, SecretProvider, SecretResolver};
    use registry_platform_objectstore::{HttpVerifierSettings, VerifierNamespace};

    const REJECTED: &[u8] = b"synthetic-rejected-file";
    const APPROVED: &[u8] = b"synthetic-approved-file";
    const UNSEEN: &[u8] = b"synthetic-unseen-file";
    let secrets = tempfile::tempdir().unwrap();
    let credential = secrets.path().join("verifier");
    std::fs::write(&credential, b"synthetic-verifier-token").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let resolver = SecretResolver::new([SecretProvider::File], secrets.path()).unwrap();
    let config: AttachmentVerifierConfig = serde_json::from_value(json!({
        "url":"http://127.0.0.1:1/verify", "policyId":"synthetic-policy",
        "authorizationRef":"secret:file/verifier", "attemptTimeoutMilliseconds":2000
    }))
    .unwrap();
    let verification = AttachmentVerification::Http(std::sync::Arc::new(
        HttpVerifierSettings::from_config(&config)
            .unwrap()
            .activate(
                VerifierNamespace {
                    binding_domain: "breg-attachment-verification-http-v1",
                    max_content_bytes: registry_breg::contract::MAX_ATTACHMENT_BYTES as u64,
                },
                &resolver,
            )
            .unwrap(),
    ));
    let policy = verification.binding_digest();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(),
        clerk("zone-a"),
        move |mutations| mutations.with_attachment_verification(verification),
    )
    .await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    fixture
        .database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_attachment_storage_binding
               (singleton, backend_id, verification_policy) VALUES (true, 'database', $1)",
            &[&policy],
        )
        .await
        .unwrap();
    // Synthetic stored files whose verification has already completed.
    for (bytes, verdict) in [(REJECTED, "rejected"), (APPROVED, "approved")] {
        let hash = sha256_hex(bytes);
        fixture
            .database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_attachment_blobs
               (sha256, byte_size, backend_id, content, state)
             VALUES ($1, $2, 'database', $3, 'live')",
                &[&hash, &(bytes.len() as i64), &bytes],
            )
            .await
            .unwrap();
        fixture
            .database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_attachment_verification
               (sha256, policy_digest, content_type, verdict) VALUES ($1, $2, 'text/plain', $3)",
                &[&hash, &policy, &verdict],
            )
            .await
            .unwrap();
    }
    let before = counts(&fixture).await;
    let refused = invoke(
        &fixture,
        clerk("zone-a"),
        "register-rejected",
        register_input(programme),
        Some(json!({"evidence":file("text/plain", REJECTED)})),
    )
    .await;
    let after = counts(&fixture).await;
    let observed = (
        refused.status,
        refused.code(),
        after.applications,
        after.references,
        after.live_references,
        after.blobs,
        after.outbox,
    );

    let approved = register(&fixture, programme, "register-approved", APPROVED).await;
    let unseen = register(&fixture, programme, "register-unseen", UNSEEN).await;
    assert_file(
        &download(
            &fixture,
            clerk("zone-a"),
            &approved.to_string(),
            "evidence",
            None,
        )
        .await,
        APPROVED,
    );
    assert_eq!(
        download(
            &fixture,
            clerk("zone-a"),
            &unseen.to_string(),
            "evidence",
            None
        )
        .await
        .status,
        StatusCode::NOT_FOUND,
        "an unseen file still commits and waits for verification"
    );
    let pending: String = fixture
        .database
        .admin
        .query_one(
            "SELECT verdict FROM registry_internal.registry_attachment_verification
         WHERE sha256=$1 AND policy_digest=$2 AND content_type='text/plain'",
            &[&sha256_hex(UNSEEN), &policy],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(pending, "pending");
    fixture.finish().await;
    assert_eq!(
        observed,
        (
            StatusCode::PRECONDITION_FAILED,
            "precondition.failed".to_owned(),
            before.applications,
            before.references,
            before.live_references,
            before.blobs,
            before.outbox
        )
    );
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
        // Far past the slot, the body itself outgrows what the Action reads.
        // It is the same refusal, not a malformed request.
        (
            "far-too-large",
            open,
            Some(json!({"evidence":file("text/plain", &vec![b'a'; 3 * 1024 * 1024])})),
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

/// The built-in executor applies `enrol`. Its create effect promotes the
/// `document` file by reference to the bytes the Proposal stored. Erasing
/// the Proposal keeps those bytes and removes the `note` file nothing
/// promoted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_applied_proposal_promotes_its_file_by_reference_and_erasure_keeps_it() {
    let fixture = client_http::ClientFixture::start(registry(), clerk("zone-a")).await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let submitted = submit_proposal(
        &fixture,
        "enrol",
        enrol_input(programme, "Enrolled applicant"),
        &[("document", EVIDENCE), ("note", FILE_CANARY)],
        "enrol-promote",
    )
    .await;
    let before = counts(&fixture).await;
    assert_eq!(before.blobs, 2);
    assert_eq!(before.references, 0);

    assert_eq!(
        run_automatic(&fixture, &submitted).await,
        ("applied".to_owned(), None)
    );
    let record = *application_ids(&fixture, "Enrolled applicant")
        .await
        .first()
        .expect("the applied Proposal created the record");
    let after = counts(&fixture).await;
    assert_eq!(after.applications, before.applications + 1);
    assert_eq!(after.blobs, before.blobs, "promotion copies no bytes");
    assert_eq!(
        record_references(&fixture).await,
        BTreeSet::from([(record, "evidence".to_owned(), sha256_hex(EVIDENCE), 1)])
    );
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

    assert_eq!(erase_proposal(&fixture, "enrol", &submitted).await, 2);
    assert_eq!(
        blob_hashes(&fixture).await,
        BTreeSet::from([sha256_hex(EVIDENCE)]),
        "the promoted bytes stay and the unpromoted bytes are gone"
    );
    assert_eq!(counts(&fixture).await.blobs, 1);
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

/// The record source with the clerk reading application history.
fn history_source() -> Value {
    let mut source = record_source();
    let application = &mut source["accessProfiles"]["clerk"]["permissions"]["records"][0];
    application["operations"] = json!(["get", "list", "revisions"]);
    application["revisionAccess"] = json!(true);
    source
}

async fn get_json(
    fixture: &client_http::ClientFixture,
    claims: VerifiedRequestClaims,
    uri: &str,
) -> (StatusCode, Value) {
    let response = send(
        fixture,
        claims,
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    (response.status, response.json())
}

/// The Proposal ids record history links, newest revision first.
async fn history_links(fixture: &client_http::ClientFixture, record: Uuid) -> Vec<Value> {
    let (status, history) = get_json(
        fixture,
        clerk("zone-a"),
        &format!("/v1/records/applications/{record}/revisions"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{history}");
    history["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["proposal"]["proposalId"].clone())
        .collect()
}

/// `enrol` creates a record and promotes its file at revision 1, and a
/// `rename` Proposal writes revision 2. History erasure through revision 1
/// erases the promoted file and the link to the Proposal that wrote that
/// revision. Each Proposal still reads, only `rename` names a revision, and
/// `enrol` keeps its own file until its detail is erased. After history
/// erasure through revision 2, a current read of `rename` names no revision,
/// while a retry of its apply returns the receipt as first issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn history_erasure_removes_a_promoted_file_and_the_link_to_the_erased_revision() {
    let fixture =
        client_http::ClientFixture::start(compile(history_source()).unwrap(), clerk("zone-a"))
            .await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let enrol = submit_proposal(
        &fixture,
        "enrol",
        enrol_input(programme, "Erased applicant"),
        &[("document", EVIDENCE)],
        "erase-enrol",
    )
    .await;
    assert_eq!(
        run_automatic(&fixture, &enrol).await,
        ("applied".to_owned(), None)
    );
    let record = *application_ids(&fixture, "Erased applicant")
        .await
        .first()
        .expect("the applied Proposal created the record");
    let rename = submit_proposal(
        &fixture,
        "rename",
        json!({"target":record.to_string(),"value":"Renamed applicant"}),
        &[],
        "erase-rename",
    )
    .await;
    let renamed = apply_proposal(&fixture, &rename, "erase-rename")
        .await
        .unwrap();
    assert_eq!(renamed.state(), BRegProposalState::Applied);
    assert_eq!(
        history_links(&fixture, record).await,
        vec![json!(rename.id()), json!(enrol.id())],
        "each Proposal-written revision links its Proposal before erasure"
    );

    erase_history(&fixture, record).await;

    assert!(
        record_references(&fixture).await.is_empty(),
        "the file promoted at revision 1 is erased with it"
    );
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
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        blob_hashes(&fixture).await,
        BTreeSet::from([sha256_hex(EVIDENCE)]),
        "the enrol Proposal still refers to the bytes"
    );
    assert_eq!(
        history_links(&fixture, record).await,
        vec![json!(rename.id())],
        "history keeps the surviving revision's link and names no erased revision"
    );
    let (status, erased) = get_json(
        &fixture,
        clerk("zone-a"),
        &format!("/v1/records/applications/{record}/revisions/1"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{erased}");
    let (status, enrolled) = get_json(
        &fixture,
        clerk("zone-a"),
        &format!("/v1/proposals/{}", enrol.id()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enrolled}");
    assert_eq!(enrolled["state"], "applied", "{enrolled}");
    assert_eq!(
        enrolled["application"]["resultLinks"],
        json!([]),
        "the Proposal names no erased revision"
    );
    let (status, current) = get_json(
        &fixture,
        clerk("zone-a"),
        &format!("/v1/proposals/{}", rename.id()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{current}");
    assert_eq!(
        current["application"]["resultLinks"],
        json!([{"recordType":"application","recordId":record.to_string(),"revision":2}]),
        "{current}"
    );
    let client = &fixture.http.client;
    let retained = client.read_proposal(&enrol).await.unwrap().value;
    assert_eq!(
        client
            .download_proposal_attachment(&retained, "document")
            .await
            .expect("the Proposal keeps its own file")
            .value
            .as_bytes(),
        EVIDENCE
    );

    assert_eq!(erase_proposal(&fixture, "enrol", &enrol).await, 1);
    // `retained` still carries the download link read before this erasure.
    let error = client
        .download_proposal_attachment(&retained, "document")
        .await
        .expect_err("erasing the Proposal's detail ends the file download");
    assert_eq!(error.status(), Some(404));
    assert!(
        blob_hashes(&fixture).await.is_empty(),
        "bytes no reference holds are removed"
    );
    let (status, enrolled) = get_json(
        &fixture,
        clerk("zone-a"),
        &format!("/v1/proposals/{}", enrol.id()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enrolled}");
    assert_eq!(enrolled["state"], "applied", "{enrolled}");

    erase_history_through(&fixture, record, 2).await;

    let (status, current) = get_json(
        &fixture,
        clerk("zone-a"),
        &format!("/v1/proposals/{}", rename.id()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{current}");
    assert_eq!(
        current["application"]["resultLinks"],
        json!([]),
        "{current}"
    );
    let replayed = apply_proposal(&fixture, &rename, "erase-rename")
        .await
        .expect("the same caller retries the apply with its key");
    assert_eq!(
        serde_json::to_value(replayed.application()).unwrap(),
        serde_json::to_value(renamed.application()).unwrap(),
        "the receipt answers as first issued"
    );
    fixture.finish().await;
}

async fn create_programme(fixture: &client_http::ClientFixture) -> Uuid {
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.programme.create", "clerk")
        .unwrap()
    else {
        panic!("records.programme.create is a create binding")
    };
    let Value::Object(data) = json!({"open":true,"jurisdiction":"zone-a"}) else {
        unreachable!("create payload is an object")
    };
    let created = client
        .create_record(
            &create,
            &BRegCreateRequest::new(data).unwrap(),
            &key("rebaseline-programme"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    created.value.data.record_identifier.parse().unwrap()
}

/// Records that `application.name` was flipped with `erase-and-rebaseline`
/// by a later activation, so the revisions written so far are the pre-flip
/// ones. It writes the two ledger rows the lifecycle reads and encrypts nothing.
async fn record_erase_and_rebaseline_flip(
    fixture: &client_http::ClientFixture,
    migration: &tokio_postgres::Client,
) {
    let boundary = Uuid::from_u128(0xF11F).to_string();
    migration
        .execute(
            "INSERT INTO registry_internal.registry_migrations
                 (activation_id, apply_order, package_digest, predecessor_package_digest,
                  registry_revision, plan_kind, migration_kind, statement_checksums,
                  artifact_paths, artifact_checksums, outcome, completed_at, applied_at,
                  role_mode, runtime_role)
             SELECT $1::text::uuid, apply_order + 1, $2, package_digest, registry_revision,
                    'successor', 'metadata-only', ARRAY[]::text[], ARRAY[]::text[],
                    ARRAY[]::text[], 'applied', transaction_timestamp(),
                    transaction_timestamp(), role_mode, runtime_role
               FROM registry_internal.registry_migrations
              WHERE activation_id::text = $3",
            &[
                &boundary,
                &format!("sha256:{}", sha256_hex(boundary.as_bytes())),
                &fixture.identity.activation_id,
            ],
        )
        .await
        .expect("the boundary activation inserts");
    migration
        .execute(
            "INSERT INTO registry_internal.registry_field_encryption_flips
                 (entity_id, field_id, boundary_package_revision, history_choice,
                  history_commit_position, sealed_row_count, sealed_journal_row_count,
                  accepted_plaintext_journal_row_count,
                  accepted_proposal_target_row_count,
                  accepted_proposal_submission_row_count,
                  accepted_idempotency_row_count, accepted_outbox_row_count)
             SELECT 'application', 'name', $1, 'erase-and-rebaseline', latest_position + 1,
                    0, 0, 0, 0, 0, 0, 0
               FROM registry_internal.registry_commit_head WHERE singleton",
            &[&boundary],
        )
        .await
        .expect("the flip inserts");
}

/// The `erase-and-rebaseline` lifecycle erases the pre-flip revision an
/// applied Proposal wrote and completes. That Proposal stays applied and names
/// no erased revision, and the record keeps its file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn erase_and_rebaseline_erases_a_revision_a_proposal_wrote() {
    // The rebaseline checks each live row against its journal, so the
    // programme is created through the API instead of by `insert_programme`.
    let mut source = history_source();
    let grant = &mut source["accessProfiles"]["clerk"]["permissions"]["records"][1];
    grant["operations"] = json!(["create", "get", "list"]);
    grant["writableFields"] = json!(["open", "jurisdiction"]);
    let fixture =
        client_http::ClientFixture::start(compile(source).unwrap(), clerk("zone-a")).await;
    let programme = create_programme(&fixture).await;
    let enrol = submit_proposal(
        &fixture,
        "enrol",
        enrol_input(programme, "Rebaselined applicant"),
        &[("document", EVIDENCE)],
        "rebaseline-enrol",
    )
    .await;
    assert_eq!(
        run_automatic(&fixture, &enrol).await,
        ("applied".to_owned(), None)
    );
    let record = *application_ids(&fixture, "Rebaselined applicant")
        .await
        .first()
        .expect("the applied Proposal created the record");

    let (mut migration, task) = fixture.database.connect_migration().await;
    record_erase_and_rebaseline_flip(&fixture, &migration).await;
    // The rebaseline keeps the live record's newest revision, so `rename`
    // writes one past the flip, as sealing the live values does.
    let rename = submit_proposal(
        &fixture,
        "rename",
        json!({"target":record.to_string(),"value":"Renamed applicant"}),
        &[],
        "rebaseline-rename",
    )
    .await;
    apply_proposal(&fixture, &rename, "rebaseline-rename")
        .await
        .unwrap();
    let outcome = erase_field_encryption_history(
        &mut migration,
        FieldEncryptionHistoryErasureRequest {
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
            registry: &fixture.registry,
        },
    )
    .await
    .expect("the lifecycle completes");
    drop(migration);
    task.abort();
    assert_eq!(outcome.erased_record_count, 1);
    assert_eq!(outcome.erased_revision_count, 1);

    assert_eq!(
        history_links(&fixture, record).await,
        vec![json!(rename.id())]
    );
    let (status, enrolled) = get_json(
        &fixture,
        clerk("zone-a"),
        &format!("/v1/proposals/{}", enrol.id()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enrolled}");
    assert_eq!(enrolled["state"], "applied", "{enrolled}");
    assert_eq!(
        enrolled["application"]["resultLinks"],
        json!([]),
        "{enrolled}"
    );
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

/// The record source with an `overseer` profile that reads an `enrol`
/// Proposal only when the record it created is inside its row boundary. The
/// programme the Proposal names is unrestricted, so only the created record
/// bounds the read.
fn overseer_source() -> Value {
    let mut source = record_source();
    source["accessProfiles"]["overseer"] = json!({"principalClaim":"sub",
        "requiredScopes":["application:oversee"],"requiredPurposes":["registry-administration"],
        "permissions":{"proposals":[{"action":"enrol","operations":["get"],"ownership":"caller",
            "targets":[{"recordType":"programme","rowBoundaries":"unrestricted"},
                {"recordType":"application","rowBoundaries":jurisdiction_boundary()}]}]}});
    source
}

/// An applied Proposal reads only for a caller whose row boundary holds each
/// record it wrote. Erasing the revision it wrote removes the link, not
/// that check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_applied_proposal_stays_bounded_by_a_record_whose_revision_was_erased() {
    let fixture =
        client_http::ClientFixture::start(compile(overseer_source()).unwrap(), clerk("zone-a"))
            .await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let enrol = submit_proposal(
        &fixture,
        "enrol",
        enrol_input(programme, "Bounded applicant"),
        &[("document", EVIDENCE)],
        "bounded-enrol",
    )
    .await;
    assert_eq!(
        run_automatic(&fixture, &enrol).await,
        ("applied".to_owned(), None)
    );
    let record = *application_ids(&fixture, "Bounded applicant")
        .await
        .first()
        .expect("the applied Proposal created the record");
    let path = format!("/v1/proposals/{}?accessProfile=overseer", enrol.id());
    let inside = || claims("clerk", "zone-a", "application:oversee");
    let outside = || claims("clerk", "zone-b", "application:oversee");
    let (status, read) = get_json(&fixture, inside(), &path).await;
    assert_eq!(status, StatusCode::OK, "{read}");
    let (status, refused) = get_json(&fixture, outside(), &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{refused}");

    erase_history(&fixture, record).await;

    let (status, read) = get_json(&fixture, inside(), &path).await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(read["application"]["resultLinks"], json!([]), "{read}");
    let (status, still_refused) = get_json(&fixture, outside(), &path).await;
    assert_eq!(
        (status, &still_refused["code"]),
        (StatusCode::NOT_FOUND, &refused["code"]),
        "{still_refused}"
    );
    fixture.finish().await;
}

/// An optional Proposal slot left empty leaves the record slot empty, and
/// the apply succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_optional_source_leaves_the_record_slot_empty() {
    let fixture = client_http::ClientFixture::start(registry(), clerk("zone-a")).await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let submitted = submit_proposal(
        &fixture,
        "enrol",
        enrol_input(programme, "Applicant without file"),
        &[],
        "enrol-empty",
    )
    .await;
    assert_eq!(
        run_automatic(&fixture, &submitted).await,
        ("applied".to_owned(), None)
    );
    let record = *application_ids(&fixture, "Applicant without file")
        .await
        .first()
        .expect("the applied Proposal created the record");
    assert!(record_references(&fixture).await.is_empty());
    assert_eq!(counts(&fixture).await.blobs, 0);
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
        StatusCode::NOT_FOUND
    );
    fixture.finish().await;
}

/// A caller applies `amend` over HTTP. Its create and patch effects both
/// reference the one stored copy of the Proposal file, and the patch fills
/// the empty slot at the record's new revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_and_patch_effects_reference_one_stored_copy() {
    let fixture = client_http::ClientFixture::start(registry(), clerk("zone-a")).await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let enrolled = submit_proposal(
        &fixture,
        "enrol",
        enrol_input(programme, "Applicant to amend"),
        &[],
        "amend-target",
    )
    .await;
    assert_eq!(
        run_automatic(&fixture, &enrolled).await,
        ("applied".to_owned(), None)
    );
    let target = *application_ids(&fixture, "Applicant to amend")
        .await
        .first()
        .unwrap();
    let submitted = submit_proposal(
        &fixture,
        "amend",
        amend_input(target, programme, "Amended applicant"),
        &[("document", EVIDENCE)],
        "amend-empty",
    )
    .await;
    let before = counts(&fixture).await;
    assert_eq!(before.blobs, 1);
    let applied = apply_proposal(&fixture, &submitted, "amend-empty")
        .await
        .expect("both empty slots take the file");
    assert_eq!(applied.state(), BRegProposalState::Applied);
    let after = counts(&fixture).await;
    assert_eq!(after.blobs, before.blobs, "promotion copies no bytes");
    let records = application_ids(&fixture, "Amended applicant").await;
    assert_eq!(records.len(), 2);
    let copy = *records.iter().find(|record| **record != target).unwrap();
    assert_eq!(
        record_references(&fixture).await,
        BTreeSet::from([
            (copy, "evidence".to_owned(), sha256_hex(EVIDENCE), 1),
            (target, "evidence".to_owned(), sha256_hex(EVIDENCE), 2),
        ])
    );
    for record in [copy, target] {
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
    }
    fixture.finish().await;
}

/// A second file for a filled write-once slot answers 409
/// `attachment.slot-write-once` over HTTP. The apply rolls back as a whole:
/// the record its create effect wrote, that record's reference and every
/// revision are gone, and the Proposal stays submitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn promotion_into_a_filled_slot_answers_409_and_rolls_back_the_whole_apply() {
    let fixture = client_http::ClientFixture::start(registry(), clerk("zone-a")).await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    let target = register(&fixture, programme, "register-filled", EVIDENCE).await;
    let submitted = submit_proposal(
        &fixture,
        "amend",
        amend_input(target, programme, "Refused amendment"),
        &[("document", FILE_CANARY)],
        "amend-filled",
    )
    .await;
    let before = counts(&fixture).await;
    let before_revisions = revisions(&fixture).await;
    let before_references = record_references(&fixture).await;

    let error = apply_proposal(&fixture, &submitted, "amend-filled")
        .await
        .expect_err("the filled slot refuses the second file");
    assert_eq!(error.status(), Some(409));
    assert_eq!(
        error.problem_code(),
        Some(registry_breg_client::BRegProblemCode::AttachmentSlotWriteOnce)
    );

    let after = counts(&fixture).await;
    assert_eq!(after.applications, before.applications);
    assert_eq!(after.references, before.references);
    assert_eq!(after.blobs, before.blobs);
    assert_eq!(after.outbox, before.outbox);
    assert_eq!(revisions(&fixture).await, before_revisions);
    assert_eq!(record_references(&fixture).await, before_references);
    assert!(application_ids(&fixture, "Refused amendment")
        .await
        .is_empty());
    assert_file(
        &download(
            &fixture,
            clerk("zone-a"),
            &target.to_string(),
            "evidence",
            None,
        )
        .await,
        EVIDENCE,
    );
    let current = fixture
        .http
        .client
        .read_proposal(&submitted)
        .await
        .unwrap()
        .value;
    assert_eq!(current.state(), BRegProposalState::Submitted);
    fixture.finish().await;
}

/// The fixture plus `pair`, a Proposal Action whose two create effects each
/// promote a different Proposal file, `left` from `first` and `right` from
/// `second`.
fn paired_promotion_source() -> Value {
    let mut source = record_source();
    let slot = |id: &str| {
        json!({"id":id,"required":true,"maximumBytes":64,"contentTypes":["text/plain"],
            "classification":"restricted"})
    };
    let create = |id: &str, from: &str| {
        json!({"id":id,"target":{"recordType":"application"},"operation":"create",
            "set":{"name":{"fromInput":"name"},"jurisdiction":{"fromInput":"jurisdiction"},
                "programme":{"fromInput":"programme"}},
            "attachments":{"evidence":{"fromAttachment":from}}})
    };
    source["actions"]["pair"] = json!({"execution":{"mode":"proposal","proposal":{
            "review":{"type":"none"},"application":{"mode":"manual"},
            "retention":{"mode":"operator-erase"},"attachments":[slot("first"), slot("second")]}},
        "inputs":source["actions"]["enrol"]["inputs"].clone(),
        "plan":{"type":"fixed","effects":[create("left", "first"), create("right", "second")]}});
    let targets = json!([
        {"recordType":"programme","rowBoundaries":jurisdiction_boundary()},
        {"recordType":"application","rowBoundaries":jurisdiction_boundary()}]);
    let clerk = &mut source["accessProfiles"]["clerk"]["permissions"];
    clerk["actions"]
        .as_array_mut()
        .unwrap()
        .push(json!({"action":"pair","operations":["start"],"targets":targets.clone()}));
    clerk["proposals"]
        .as_array_mut()
        .unwrap()
        .push(json!({"action":"pair",
        "operations":["get","list","edit","submit","apply"],"ownership":"caller",
        "readableAttachments":["first","second"],"writableAttachments":["first","second"],
        "targets":targets}));
    source
}

/// Calls a session advisory lock `function` on the key the content-hash lock
/// of `bytes` takes, and returns its answer.
async fn hash_lock(client: &tokio_postgres::Client, function: &str, bytes: &[u8]) -> bool {
    client
        .query_one(
            &format!("SELECT {function}(hashtextextended($1, 960))"),
            &[&sha256_hex(bytes)],
        )
        .await
        .unwrap()
        .get(0)
}

/// Promotions lock content hashes in hash order, as the immediate path does,
/// so two applies that share files cannot each hold the hash the other
/// waits for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn promotions_lock_content_hashes_in_hash_order() {
    let fixture = client_http::ClientFixture::start(
        compile(paired_promotion_source()).unwrap(),
        clerk("zone-a"),
    )
    .await;
    let programme = insert_programme(&fixture, true, "zone-a").await;
    // `left` runs first and promotes the higher hash, so effect order and
    // hash order disagree.
    let (high, low): (&[u8], &[u8]) = if sha256_hex(b"paired-one") > sha256_hex(b"paired-two") {
        (b"paired-one", b"paired-two")
    } else {
        (b"paired-two", b"paired-one")
    };
    let submitted = submit_proposal(
        &fixture,
        "pair",
        enrol_input(programme, "Paired"),
        &[("first", high), ("second", low)],
        "pair",
    )
    .await;
    // Another apply holds the lower hash.
    let (holder, holder_task) = fixture.database.connect_migration().await;
    assert!(hash_lock(&holder, "pg_try_advisory_lock", low).await);
    let probe = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: i64 = fixture
                    .database
                    .admin
                    .query_one(
                        "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted
                           AND database=(SELECT oid FROM pg_database WHERE datname=current_database())",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get(0);
                if waiting != 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the apply waits for the lower hash");
        // While it waits, the apply must not hold the higher hash.
        let (prober, prober_task) = fixture.database.connect_migration().await;
        let free = hash_lock(&prober, "pg_try_advisory_lock", high).await;
        if free {
            assert!(hash_lock(&prober, "pg_advisory_unlock", high).await);
        }
        drop(prober);
        prober_task.abort();
        assert!(hash_lock(&holder, "pg_advisory_unlock", low).await);
        free
    };
    let (applied, higher_free) = tokio::join!(apply_proposal(&fixture, &submitted, "pair"), probe);
    holder_task.abort();
    assert!(
        higher_free,
        "an apply waiting for the lower hash holds no higher hash"
    );
    applied.expect("the apply completes once the lower hash is free");
    assert_eq!(counts(&fixture).await.references, 2);
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
    // `rename` declares only the `support` Proposal slot, so there is no
    // `evidence` file to promote.
    refused(
        &|source| {
            source["actions"]["rename"]["plan"]["effects"][0]["attachments"] =
                json!({"evidence":{"fromAttachment":"evidence"}});
        },
        "breg.action.attachment-invalid",
    );
    // As a Proposal Action, `register` declares no Proposal slot, so its
    // effect names a file nothing can promote.
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

#[test]
fn the_invoke_operation_documents_every_file_refusal() {
    let compiled = registry();
    let openapi: Value = serde_json::from_slice(
        &compiled
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let examples = |path: &str, status: &str| -> BTreeSet<String> {
        openapi["paths"][path]["post"]["responses"][status]["content"]["application/problem+json"]
            ["examples"]
            .as_object()
            .map(|examples| examples.keys().cloned().collect())
            .unwrap_or_default()
    };
    for (status, code) in [
        ("413", "attachment.too-large"),
        ("415", "attachment.content-type"),
        ("422", "attachment.digest-mismatch"),
        ("409", "attachment.slot-write-once"),
    ] {
        assert!(
            examples("/v1/actions/register", status).contains(code),
            "{status} {code}"
        );
        // An Action that takes no request files answers none of them.
        assert!(
            !examples("/v1/actions/rename", status).contains(code),
            "{status} {code}"
        );
    }
    assert_eq!(
        openapi["paths"]["/v1/actions/register"]["post"]["responses"]["413"]["content"]
            ["application/problem+json"]["examples"]["attachment.too-large"]["value"]["title"],
        "Content Too Large"
    );
}
