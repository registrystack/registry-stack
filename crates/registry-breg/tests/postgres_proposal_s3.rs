// SPDX-License-Identifier: Apache-2.0
//! Configured S3 Proposal transport over synthetic loopback HTTP and real PostgreSQL.
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::{
    body::{Body, Bytes},
    extract::{OriginalUri, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use registry_breg::{
    api::{VerifiedClaimValue, VerifiedRequestClaims},
    attachment_storage::AttachmentStorage,
    compiler::{compile_project, CompileProfile},
    contract::parse_project_json,
    runtime_config::{parse_runtime_config, RUNTIME_CONFIG_API_VERSION, RUNTIME_CONFIG_KIND},
};
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegRecordFormat,
};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

fn claims(subject: &str, jurisdiction: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "sub",
        subject,
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string(jurisdiction).unwrap(),
        )]),
    )
    .unwrap()
}
fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}
fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}
fn registry_source(automatic: bool) -> Value {
    let source = json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"proposal-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://proposal.example.test"},
        "datasets":[{"id":"directory"}],
        "recordTypes":[{"id":"target","primaryDataset":"directory","route":"targets","mutationMode":"mutable",
            "mutationPolicy":{"patch":"proposal-required"},
            "fields":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"}]}],
        "actions":[{"id":"correct-name","execution":{"mode":"proposal","proposal":{
            "review":{"type":"none"},"application":if automatic{json!({"mode":"automatic","maximumAttempts":3})}else{json!({"mode":"manual"})},
            "retention":{"mode":"operator-erase"},"attachments":[{"id":"support","required":false,"maximumBytes":4096,
                "contentTypes":["text/plain"],"classification":"restricted"}]}},
            "inputs":[{"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
                {"id":"value","type":"string","required":true,"maximumLength":64,"classification":"internal"}],
            "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{"id":"name","target":{"fromInput":"target"},"operation":"patch","set":{"name":{"fromInput":"value"}}}]}}],
        "accessProfiles":[{"id":"clerk","default":true,"principalClaim":"sub","requiredScopes":["proposal:manage"],
            "requiredPurposes":["registry-administration"],"permissions":{
                "records":[{"recordType":"target","operations":["create","get","list"],"readableFields":["name","jurisdiction"],
                    "writableFields":["name","jurisdiction"],"rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}],
                "actions":[{"action":"correct-name","operations":["start"],"targets":[{"recordType":"target",
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}],
                "proposals":[{"action":"correct-name","operations":["get","list","edit","submit","revise","rebase","retry","cancel","apply"],
                    "ownership":"caller","readableAttachments":["support"],"writableAttachments":["support"],"targets":[{"recordType":"target",
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}]}}]});
    source
}
fn compile(source: Value) -> registry_breg::CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).expect("standalone Proposal compiles")
}
fn registry(automatic: bool) -> registry_breg::CompiledRegistry {
    compile(registry_source(automatic))
}

async fn start(
    fixture: &client_http::ClientFixture,
    value: &str,
    key_name: &str,
) -> registry_breg_client::BRegProposal {
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key(&format!("{key_name}-record")),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"target":record.value.data.record_identifier,"value":value})),
        None,
    )
    .unwrap();
    client
        .start_proposal(&action, &input, &key(key_name))
        .await
        .unwrap()
        .value
}

fn valid_runtime(secret_root: &Path, package_root: &Path) -> String {
    let audit_path = secret_root
        .with_file_name("audit")
        .join("audit.jsonl")
        .display()
        .to_string();
    format!(
        r#"
apiVersion: {api_version}
kind: {kind}
listener:
  bind: 127.0.0.1:8080
identity:
  environment: production
  instanceId: registry-primary
  databaseId: registry-db
  databaseInitializationEnvironment: production
secretProviders:
  environment: {{}}
  file:
    root: {secret_root}
database:
  runtimeUrlRef: secret:env/BREG_RUNTIME_CONFIG_DATABASE_URL
  migrationUrlRef: secret:env/BREG_RUNTIME_CONFIG_MIGRATION_DATABASE_URL
  pool:
    maximumConnections: 4
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: registry_migration
    runtime: registry_runtime
package:
  root: {package_root}
authentication:
  oidc:
    issuer: https://issuer.example
    audience: urn:breg:test
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-client]
    deniedKids: [denied-kid]
    maximumTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maximumDocumentBytes: 65536
      attemptTimeoutMilliseconds: 5000
      outageToleranceSeconds: 900
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:file/audit-key
  path: {audit_path}
cursor:
  secretRef: secret:file/cursor-key
  maximumAgeSeconds: 300
eventDestinations: {{}}
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
"#,
        api_version = RUNTIME_CONFIG_API_VERSION,
        kind = RUNTIME_CONFIG_KIND,
        secret_root = secret_root.display(),
        package_root = package_root.display(),
    )
}

#[derive(Default)]
struct Objects {
    bytes: tokio::sync::Mutex<BTreeMap<String, Vec<u8>>>,
    requests: AtomicUsize,
    puts: AtomicUsize,
    deletes: AtomicUsize,
    // 1 unavailable, 2 corrupt body, 3 short body, 4 interrupted upload.
    mode: AtomicUsize,
    // External verifier: approve, reject, or exceed its transport deadline.
    verifier_mode: AtomicUsize,
    verifier_bytes: tokio::sync::Mutex<Vec<Vec<u8>>>,
    verifier_content_types: tokio::sync::Mutex<Vec<String>>,
}
async fn object_request(
    State(state): State<Arc<Objects>>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if uri.path() == "/verify" {
        use sha2::{Digest, Sha256};
        assert_eq!(method, Method::POST);
        assert_eq!(headers["authorization"], "Bearer synthetic-verifier");
        let content_type = headers["content-type"].to_str().unwrap();
        assert!(["text/plain", "application/pdf"].contains(&content_type));
        state
            .verifier_content_types
            .lock()
            .await
            .push(content_type.to_owned());
        assert_eq!(
            headers["x-content-sha256"].to_str().unwrap(),
            hex::encode(Sha256::digest(&body))
        );
        state.verifier_bytes.lock().await.push(body.to_vec());
        let mode = state.verifier_mode.load(Ordering::SeqCst);
        if mode == 2 {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        return axum::Json(json!({"verdict": if mode == 1 {"rejected"} else {"approved"}}))
            .into_response();
    }
    state.requests.fetch_add(1, Ordering::SeqCst);
    let mode = state.mode.load(Ordering::SeqCst);
    if mode == 1 {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if uri.query().is_some() {
        return (
            StatusCode::OK,
            "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>",
        )
            .into_response();
    }
    let path = uri.path().to_owned();
    match method {
        Method::PUT => {
            state.puts.fetch_add(1, Ordering::SeqCst);
            state.bytes.lock().await.insert(path, body.to_vec());
            if mode == 4 {
                std::future::pending::<()>().await;
            }
            StatusCode::OK.into_response()
        }
        Method::DELETE => {
            state.deletes.fetch_add(1, Ordering::SeqCst);
            state.bytes.lock().await.remove(&path);
            StatusCode::NO_CONTENT.into_response()
        }
        Method::GET => match state.bytes.lock().await.get(&path).cloned() {
            None => StatusCode::NOT_FOUND.into_response(),
            Some(mut bytes) => {
                if mode == 2 && !bytes.is_empty() {
                    bytes[0] ^= 1;
                }
                if mode == 3 {
                    bytes.pop();
                }
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(bytes))
                    .unwrap()
            }
        },
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}
struct S3Fixture {
    state: Arc<Objects>,
    storage: AttachmentStorage,
    config: registry_breg::runtime_config::RuntimeConfig,
    _secrets: tempfile::TempDir,
    server: tokio::task::JoinHandle<()>,
}
impl S3Fixture {
    async fn new() -> Self {
        let state = Arc::new(Objects::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .fallback(object_request)
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let secrets = tempfile::Builder::new()
            .prefix("breg-synthetic-s3-")
            .tempdir()
            .unwrap();
        for (name, bytes) in [
            ("access", b"synthetic-access".as_slice()),
            ("key", b"synthetic-test-secret".as_slice()),
            ("verifier", b"synthetic-verifier".as_slice()),
        ] {
            let path = secrets.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let raw = format!(
            "{}\nattachmentStorage:\n  type: s3\n  endpoint: {endpoint}\n  bucket: synthetic-proposal\n  region: us-east-1\n  accessKeyIdRef: secret:file/access\n  secretAccessKeyRef: secret:file/key\n  attemptTimeoutMilliseconds: 2000\nattachmentVerification:\n  type: http\n  endpoint: {endpoint}/verify\n  policyId: synthetic-policy\n  authorizationRef: secret:file/verifier\n  attemptTimeoutMilliseconds: 100\n",
            valid_runtime(secrets.path(), secrets.path())
        );
        let config = parse_runtime_config(&raw).unwrap();
        let storage = config
            .activate_attachment_storage("proposal-test")
            .await
            .unwrap();
        Self {
            state,
            storage,
            config,
            _secrets: secrets,
            server,
        }
    }
}
impl Drop for S3Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
fn cleanup(
    fixture: &client_http::ClientFixture,
    storage: AttachmentStorage,
) -> registry_breg::proposal_retention::ProposalRetentionOperatorService {
    use registry_breg::postgres::{ExpectedManagedCatalog, RegistryLockKey};
    registry_breg::proposal_retention::ProposalRetentionOperatorService::new_for_test(
        (*fixture.registry).clone(),
        fixture.identity.clone(),
        ExpectedManagedCatalog::compiled(&fixture.registry),
        RegistryLockKey::derive(fixture.registry.registry_id()).unwrap(),
        fixture.database.migration_config.clone(),
        fixture.database.migration_role.clone(),
        fixture.database.runtime_role.clone(),
        fixture.database.activation_audit(),
    )
    .with_attachment_storage_for_test(storage)
}
async fn raw_upload(
    http: &client_http::ClientHttp,
    draft: &registry_breg_client::BRegProposal,
    slot: &str,
    key: &str,
) -> reqwest::Response {
    let value = serde_json::to_value(draft).unwrap();
    reqwest::Client::new()
        .patch(format!(
            "{}/v1/proposals/{}/attachments/{slot}?accessProfile=clerk",
            http.base_url,
            draft.id()
        ))
        .header(
            "if-match",
            value["attachments"]["support"]["links"]["upload"]["ifMatch"]
                .as_str()
                .unwrap(),
        )
        .header("idempotency-key", key)
        .header("content-type", "text/plain")
        .body("synthetic-refused")
        .send()
        .await
        .unwrap()
}
async fn raw_download(
    http: &client_http::ClientHttp,
    draft: &registry_breg_client::BRegProposal,
) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!(
            "{}/v1/proposals/{}/attachments/support?accessProfile=clerk&submissionVersion=1",
            http.base_url,
            draft.id()
        ))
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_put_get_remove_and_exact_replay_without_storage_requests() {
    let s3 = S3Fixture::new().await;
    let storage = s3.storage.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(false),
        claims("synthetic-author", "zone-a"),
        move |mutations| mutations.with_attachment_storage(storage),
    )
    .await;
    let draft = start(&fixture, "After", "s3-start").await;
    let client = &fixture.http.client;
    let first = client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"synthetic-support",
            &key("s3-upload"),
        )
        .await
        .unwrap()
        .value;
    assert_eq!(
        client
            .download_proposal_attachment(&first, "support")
            .await
            .unwrap()
            .value
            .as_bytes(),
        b"synthetic-support"
    );
    assert_eq!(s3.state.puts.load(Ordering::SeqCst), 1);
    let requests = s3.state.requests.load(Ordering::SeqCst);
    s3.state.mode.store(1, Ordering::SeqCst);
    let replay = client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"synthetic-support",
            &key("s3-upload"),
        )
        .await
        .unwrap()
        .value;
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&replay).unwrap()
    );
    assert_eq!(
        s3.state.requests.load(Ordering::SeqCst),
        requests,
        "exact receipt replay does not contact unavailable storage"
    );
    s3.state.mode.store(0, Ordering::SeqCst);
    let removed = client
        .delete_proposal_attachment(&first, "support", &key("s3-remove"))
        .await
        .unwrap()
        .value;
    assert!(removed.revision() > first.revision());
    assert_eq!(
        raw_download(&fixture.http, &first).await.status(),
        StatusCode::NOT_FOUND
    );
    let result = cleanup(&fixture, s3.storage.clone())
        .cleanup_attachments()
        .await
        .unwrap();
    assert_eq!(result.pending_external_deletions, 0);
    assert_eq!(result.external_deletion_tombstones, 1);
    assert_eq!(s3.state.deletes.load(Ordering::SeqCst), 1);
    assert!(s3.state.bytes.lock().await.is_empty());
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_integrity_binding_quarantine_and_authority_refusals_precede_transport() {
    let s3 = S3Fixture::new().await;
    let storage = s3.storage.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(false),
        claims("synthetic-author", "zone-a"),
        move |mutations| mutations.with_attachment_storage(storage),
    )
    .await;
    let draft = start(&fixture, "After", "s3-integrity-start").await;
    let uploaded = fixture
        .http
        .client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"synthetic-integrity",
            &key("s3-integrity-upload"),
        )
        .await
        .unwrap()
        .value;
    for mode in [2, 3] {
        s3.state.mode.store(mode, Ordering::SeqCst);
        assert!(
            fixture
                .http
                .client
                .download_proposal_attachment(&uploaded, "support")
                .await
                .is_err(),
            "wrong hash/size is refused"
        );
    }
    s3.state.mode.store(0, Ordering::SeqCst);
    let requests = s3.state.requests.load(Ordering::SeqCst);
    assert!(
        !raw_upload(&fixture.http, &draft, "support", "s3-stale-etag")
            .await
            .status()
            .is_success(),
        "stale ETag is refused before staging or transport"
    );
    assert!(
        !raw_upload(&fixture.http, &draft, "support", "s3-integrity-upload")
            .await
            .status()
            .is_success(),
        "a changed idempotent payload is refused before transport"
    );
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_state SET blocked_reason='package-changed'",
            &[],
        )
        .await
        .unwrap();
    assert!(
        !raw_upload(&fixture.http, &uploaded, "support", "s3-blocked-proposal")
            .await
            .status()
            .is_success(),
        "blocked Proposal is refused before staging or transport"
    );
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_state SET blocked_reason=NULL",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(s3.state.requests.load(Ordering::SeqCst), requests);
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs SET backend_id='different-backend'",
            &[],
        )
        .await
        .unwrap();
    assert!(fixture
        .http
        .client
        .download_proposal_attachment(&uploaded, "support")
        .await
        .is_err());
    assert_eq!(
        s3.state.requests.load(Ordering::SeqCst),
        requests,
        "backend refusal precedes GET"
    );
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs SET backend_id=$1",
            &[&s3.storage.binding_digest()],
        )
        .await
        .unwrap();
    assert_eq!(
        raw_upload(&fixture.http, &uploaded, "unknown-slot", "s3-denied-slot")
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let wrong_target = fixture
        .client_for(claims("synthetic-author", "zone-b"))
        .await;
    assert!(
        !raw_upload(&wrong_target, &uploaded, "support", "s3-denied-target")
            .await
            .status()
            .is_success()
    );
    assert_eq!(
        raw_download(&wrong_target, &uploaded).await.status(),
        StatusCode::NOT_FOUND
    );
    let other_owner = fixture
        .client_for(claims("synthetic-other-author", "zone-a"))
        .await;
    assert_eq!(
        raw_upload(&other_owner, &uploaded, "support", "s3-other-owner")
            .await
            .status(),
        StatusCode::NOT_FOUND,
        "another owner cannot discover attachment state on a permitted target"
    );
    assert_eq!(
        raw_download(&other_owner, &uploaded).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        s3.state.requests.load(Ordering::SeqCst),
        requests,
        "slot, owner, and current target refusals precede transport"
    );
    let verification = s3.config.activate_attachment_verification().unwrap();
    let policy = verification.binding_digest();
    fixture.database.admin.execute("UPDATE registry_internal.registry_attachment_storage_binding SET verification_policy=$1",&[&policy]).await.unwrap();
    fixture.database.admin.execute("INSERT INTO registry_internal.registry_attachment_verification (sha256,policy_digest,content_type) SELECT sha256,$1,'text/plain' FROM registry_internal.registry_attachment_blobs",&[&policy]).await.unwrap();
    let quarantined = fixture
        .client_with_mutations(
            claims("synthetic-author", "zone-a"),
            fixture
                .mutations
                .as_ref()
                .clone()
                .with_attachment_verification(verification),
        )
        .await;
    assert_eq!(
        raw_download(&quarantined, &uploaded).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        s3.state.requests.load(Ordering::SeqCst),
        requests,
        "pending verification precedes GET"
    );
    drop(quarantined);
    drop(other_owner);
    drop(wrong_target);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_document_binding_refusals_precede_s3_and_revise_never_follows_successor() {
    let s3 = S3Fixture::new().await;
    let verification = s3.config.activate_attachment_verification().unwrap();
    let configured_verification = verification.clone();
    let mut source = registry_source(false);
    source["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({"id":"review-document","fields":{
        "document":{"type":"document","slot":"support"},"changes":{"type":"changes","recordType":"target","fields":["name"]}}});
    let mut reviewer = source["accessProfiles"][0].clone();
    reviewer["id"] = json!("reviewer");
    reviewer.as_object_mut().unwrap().remove("default");
    reviewer["permissions"]
        .as_object_mut()
        .unwrap()
        .remove("actions");
    reviewer["permissions"]["records"][0]["operations"] = json!(["get"]);
    reviewer["permissions"]["records"][0]
        .as_object_mut()
        .unwrap()
        .remove("writableFields");
    reviewer["permissions"]["proposals"][0]["operations"] = json!(["get-review-context"]);
    reviewer["permissions"]["proposals"][0]["readableContextFields"] =
        json!(["document", "changes"]);
    reviewer["permissions"]["proposals"][0]
        .as_object_mut()
        .unwrap()
        .remove("readableAttachments");
    reviewer["permissions"]["proposals"][0]
        .as_object_mut()
        .unwrap()
        .remove("writableAttachments");
    source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(reviewer);
    let storage = s3.storage.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("synthetic-author", "zone-a"),
        move |service| {
            service
                .with_attachment_storage(storage)
                .with_attachment_verification(configured_verification)
        },
    )
    .await;
    let (audit, _) = registry_breg::audit::test_support::capturing(
        registry_platform_audit::AuditProfile::production_from_secret_bytes(vec![0x64; 32].into())
            .unwrap(),
    );
    let worker = registry_breg::attachment_verification_worker::AttachmentVerificationWorker::new(
        fixture.pool.clone(),
        fixture.identity.clone(),
        registry_breg::postgres::RegistryLockKey::derive(fixture.registry.registry_id()).unwrap(),
        Duration::from_secs(2),
        audit,
        s3.storage.clone(),
        verification.clone(),
    );
    let draft = start(&fixture, "Frozen", "review-s3-start").await;
    let client = &fixture.http.client;
    let uploaded = client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"frozen-review-bytes",
            &key("review-s3-upload"),
        )
        .await
        .unwrap()
        .value;
    assert!(worker.run_once().await.unwrap());
    let uploaded = client.read_proposal(&uploaded).await.unwrap().value;
    let prepared = client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("review-s3-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&prepared).await.unwrap().value;
    let requests = s3.state.requests.load(Ordering::SeqCst);
    let context_response = reqwest::Client::new()
        .get(format!(
            "{}/v1/proposals/{}/review-context?accessProfile=reviewer",
            fixture.http.base_url,
            submitted.id()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(context_response.status(), StatusCode::OK);
    let context: Value = context_response.json().await.unwrap();
    assert_eq!(
        s3.state.requests.load(Ordering::SeqCst),
        requests,
        "context metadata never fetches object bytes"
    );
    let path = format!(
        "{}&accessProfile=reviewer",
        context["context"]["fields"]["document"]["download"]["path"]
            .as_str()
            .unwrap()
    );
    let download =
        |base: &str, path: &str| reqwest::Client::new().get(format!("{base}{path}")).send();
    let response = download(&fixture.http.base_url, &path).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        b"frozen-review-bytes"
    );
    let requests = s3.state.requests.load(Ordering::SeqCst);
    for denied in [
        path.replace("submissionVersion=1", "submissionVersion=2"),
        path.replace("reviewContextField=document", "reviewContextField=changes"),
        path.replace("attachments/support", "attachments/hidden"),
        path.replace("accessProfile=reviewer", "accessProfile=clerk"),
        path.replace(
            context["effectDigest"]
                .as_str()
                .unwrap()
                .replace(':', "%3A")
                .as_str(),
            &format!("sha256%3A{}", "f".repeat(64)),
        ),
        path.replace(
            context["context"]["contract"]["schemaDigest"]
                .as_str()
                .unwrap()
                .replace(':', "%3A")
                .as_str(),
            &format!("sha256%3A{}", "e".repeat(64)),
        ),
    ] {
        assert_eq!(
            download(&fixture.http.base_url, &denied)
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND,
            "{denied}"
        );
    }
    let wrong_owner = fixture.client_for(claims("other-author", "zone-a")).await;
    let wrong_target = fixture
        .client_for(claims("synthetic-author", "zone-b"))
        .await;
    for http in [&wrong_owner, &wrong_target] {
        assert_eq!(
            download(&http.base_url, &path).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_attachments SET byte_size=byte_size+1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        download(&fixture.http.base_url, &path)
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
        "live metadata must equal frozen manifest"
    );
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_attachments SET byte_size=byte_size-1",
            &[],
        )
        .await
        .unwrap();
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs SET backend_id='different-backend'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        download(&fixture.http.base_url, &path)
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs SET backend_id=$1",
            &[&s3.storage.binding_digest()],
        )
        .await
        .unwrap();
    assert_eq!(
        s3.state.requests.load(Ordering::SeqCst),
        requests,
        "binding, field, owner and current disclosure refusals precede external reads"
    );
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_verification SET verdict='rejected'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        download(&fixture.http.base_url, &path)
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
        "current quarantine conceals saved document link"
    );
    assert_eq!(
        s3.state.requests.load(Ordering::SeqCst),
        requests,
        "quarantine admission precedes external read"
    );
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_verification SET verdict='approved'",
            &[],
        )
        .await
        .unwrap();
    for mode in [1, 2, 3] {
        s3.state.mode.store(mode, Ordering::SeqCst);
        assert_eq!(
            download(&fixture.http.base_url, &path)
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable or corrupt bytes never escape"
        );
    }
    s3.state.mode.store(0, Ordering::SeqCst);
    let revise = client
        .prepare_proposal(&submitted, "revise", json!({}), &key("review-s3-revise"))
        .unwrap();
    let revised = client.execute_proposal(&revise).await.unwrap().value;
    let successor = client
        .upload_proposal_attachment(
            &revised,
            "support",
            "text/plain",
            b"successor-review-bytes",
            &key("review-s3-successor-upload"),
        )
        .await
        .unwrap()
        .value;
    assert!(worker.run_once().await.unwrap());
    let successor = client.read_proposal(&successor).await.unwrap().value;
    let submit = client
        .prepare_proposal(
            &successor,
            "submit",
            json!({}),
            &key("review-s3-successor-submit"),
        )
        .unwrap();
    let successor = client.execute_proposal(&submit).await.unwrap().value;
    let requests = s3.state.requests.load(Ordering::SeqCst);
    assert_eq!(
        download(&fixture.http.base_url, &path)
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        s3.state.requests.load(Ordering::SeqCst),
        requests,
        "a stale link must never fetch successor bytes"
    );
    let current: Value = download(
        &fixture.http.base_url,
        &format!(
            "/v1/proposals/{}/review-context?accessProfile=reviewer",
            successor.id()
        ),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let current_path = format!(
        "{}&accessProfile=reviewer",
        current["context"]["fields"]["document"]["download"]["path"]
            .as_str()
            .unwrap()
    );
    let cancel = client
        .prepare_proposal(&successor, "cancel", json!({}), &key("review-s3-cancel"))
        .unwrap();
    client.execute_proposal(&cancel).await.unwrap();
    cleanup(&fixture, s3.storage.clone())
        .with_verification_policy_for_test(verification.binding_digest())
        .erase(
            registry_breg::proposal_retention::ProposalDetailErasureScope {
                action_id: "correct-name",
                proposal_id: uuid::Uuid::parse_str(successor.id()).unwrap(),
                submission_version: 2,
            },
        )
        .await
        .unwrap();
    let requests = s3.state.requests.load(Ordering::SeqCst);
    assert_eq!(
        download(&fixture.http.base_url, &current_path)
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
        "operator erasure conceals saved current document link"
    );
    assert_eq!(s3.state.requests.load(Ordering::SeqCst), requests);
    drop(wrong_owner);
    drop(wrong_target);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_s3_put_retains_durable_staging_for_operator_cleanup() {
    let s3 = S3Fixture::new().await;
    let storage = s3.storage.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(false),
        claims("synthetic-author", "zone-a"),
        move |mutations| mutations.with_attachment_storage(storage),
    )
    .await;
    let draft = start(&fixture, "After", "s3-interrupted-start").await;
    // Only the interrupted upload gets a short deadline; setup and the
    // post-cancellation read retain the ordinary service budget.
    let interrupted_upload = fixture
        .client_with_mutations(
            claims("synthetic-author", "zone-a"),
            (*fixture.mutations)
                .clone()
                .with_action_timeout_for_test(Duration::from_millis(300)),
        )
        .await;
    s3.state.mode.store(4, Ordering::SeqCst);
    assert!(!raw_upload(
        &interrupted_upload,
        &draft,
        "support",
        "s3-interrupted-upload"
    )
    .await
    .status()
    .is_success());
    assert_eq!(s3.state.puts.load(Ordering::SeqCst), 1);
    let row=fixture.database.admin.query_one("SELECT state,(SELECT count(*) FROM registry_internal.registry_proposal_attachments) FROM registry_internal.registry_attachment_blobs",&[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "staged");
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(
        fixture
            .http
            .client
            .read_proposal(&draft)
            .await
            .unwrap()
            .value
            .revision(),
        draft.revision(),
        "timed out effects do not commit"
    );
    s3.state.mode.store(0, Ordering::SeqCst);
    fixture.database.admin.execute("UPDATE registry_internal.registry_attachment_blobs SET created_at=clock_timestamp()-interval '11 minutes'",&[]).await.unwrap();
    let result = cleanup(&fixture, s3.storage.clone())
        .cleanup_attachments()
        .await
        .unwrap();
    assert_eq!(result.pending_external_deletions, 0);
    assert_eq!(result.external_deletion_tombstones, 1);
    assert_eq!(s3.state.deletes.load(Ordering::SeqCst), 1);
    assert!(s3.state.bytes.lock().await.is_empty());
    drop(interrupted_upload);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_verifier_worker_releases_only_exact_approved_bytes() {
    use registry_breg::attachment_verification_worker::AttachmentVerificationWorker;
    use registry_breg::postgres::RegistryLockKey;
    use registry_platform_audit::AuditProfile;
    let s3 = S3Fixture::new().await;
    let storage = s3.storage.clone();
    let verification = s3.config.activate_attachment_verification().unwrap();
    let configured_verification = verification.clone();
    let mut source = registry_source(false);
    source["actions"][0]["execution"]["proposal"]["attachments"][0]["contentTypes"] =
        json!(["text/plain", "application/pdf"]);
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("synthetic-author", "zone-a"),
        move |mutations| {
            mutations
                .with_attachment_storage(storage)
                .with_attachment_verification(configured_verification)
        },
    )
    .await;
    let (audit, capture) = registry_breg::audit::test_support::capturing(
        AuditProfile::production_from_secret_bytes(vec![0x63; 32].into()).unwrap(),
    );
    let worker = AttachmentVerificationWorker::new(
        fixture.pool.clone(),
        fixture.identity.clone(),
        RegistryLockKey::derive(fixture.registry.registry_id()).unwrap(),
        Duration::from_secs(2),
        audit,
        s3.storage.clone(),
        verification,
    );
    let draft = start(&fixture, "After", "verifier-start").await;
    let client = &fixture.http.client;
    let approved = client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"approved-exact-bytes",
            &key("verifier-upload"),
        )
        .await
        .unwrap()
        .value;
    assert!(client
        .download_proposal_attachment(&approved, "support")
        .await
        .is_err());
    assert_eq!(
        raw_download(&fixture.http, &approved).await.status(),
        StatusCode::NOT_FOUND
    );
    assert!(worker.run_once().await.unwrap());
    let approved = client.read_proposal(&approved).await.unwrap().value;
    assert_eq!(
        client
            .download_proposal_attachment(&approved, "support")
            .await
            .unwrap()
            .value
            .as_bytes(),
        b"approved-exact-bytes"
    );

    assert_eq!(
        fixture
            .database
            .admin
            .query_one(
                "SELECT verdict FROM registry_internal.registry_attachment_verification",
                &[]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "approved"
    );

    // A verdict binds media type as well as bytes and policy. Keep the first
    // reference live so its approved decision remains available for deduplication.
    let other = start(&fixture, "Other media", "verifier-media-start").await;
    let other = client
        .upload_proposal_attachment(
            &other,
            "support",
            "application/pdf",
            b"approved-exact-bytes",
            &key("verifier-media-upload"),
        )
        .await
        .unwrap()
        .value;
    let bindings = fixture.database.admin.query("SELECT content_type,verdict,sha256 FROM registry_internal.registry_attachment_verification ORDER BY content_type",&[]).await.unwrap();
    assert_eq!(bindings.len(), 2);
    assert_eq!(bindings[0].get::<_, String>(0), "application/pdf");
    assert_eq!(bindings[0].get::<_, String>(1), "pending");
    assert_eq!(bindings[1].get::<_, String>(1), "approved");
    assert_eq!(
        bindings[0].get::<_, String>(2),
        bindings[1].get::<_, String>(2)
    );
    let blobs: i64 = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_attachment_blobs",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        blobs, 1,
        "same hash shares blob identity, never a verdict for another media type"
    );
    assert_eq!(
        raw_download(&fixture.http, &other).await.status(),
        StatusCode::NOT_FOUND
    );
    s3.state.verifier_mode.store(1, Ordering::SeqCst);
    assert!(worker.run_once().await.unwrap());
    assert_eq!(
        raw_download(&fixture.http, &other).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client
            .download_proposal_attachment(&approved, "support")
            .await
            .unwrap()
            .value
            .as_bytes(),
        b"approved-exact-bytes"
    );
    let cancel = client
        .prepare_proposal(&other, "cancel", json!({}), &key("verifier-media-cancel"))
        .unwrap();
    let other = client.execute_proposal(&cancel).await.unwrap().value;
    cleanup(&fixture, s3.storage.clone())
        .with_verification_policy_for_test(
            s3.config
                .activate_attachment_verification()
                .unwrap()
                .binding_digest(),
        )
        .erase(
            registry_breg::proposal_retention::ProposalDetailErasureScope {
                action_id: "correct-name",
                proposal_id: uuid::Uuid::parse_str(other.id()).unwrap(),
                submission_version: 1,
            },
        )
        .await
        .unwrap();

    // The previous approval cannot release replacement bytes in the same slot.
    s3.state.verifier_mode.store(1, Ordering::SeqCst);
    let rejected = client
        .upload_proposal_attachment(
            &approved,
            "support",
            "text/plain",
            b"replacement-rejected",
            &key("verifier-replace"),
        )
        .await
        .unwrap()
        .value;
    assert!(client
        .download_proposal_attachment(&rejected, "support")
        .await
        .is_err());
    assert!(worker.run_once().await.unwrap());
    assert!(client
        .download_proposal_attachment(&rejected, "support")
        .await
        .is_err());

    assert_eq!(
        raw_download(&fixture.http, &rejected).await.status(),
        StatusCode::NOT_FOUND
    );

    assert_eq!(
        fixture
            .database
            .admin
            .query_one(
                "SELECT verdict FROM registry_internal.registry_attachment_verification",
                &[]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "rejected"
    );

    // An eventual approval received after the transport deadline is no verdict.
    s3.state.verifier_mode.store(2, Ordering::SeqCst);
    let pending = client
        .upload_proposal_attachment(
            &rejected,
            "support",
            "text/plain",
            b"replacement-timeout",
            &key("verifier-timeout"),
        )
        .await
        .unwrap()
        .value;
    assert!(worker.run_once().await.unwrap());
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(client
        .download_proposal_attachment(&pending, "support")
        .await
        .is_err());
    assert_eq!(
        raw_download(&fixture.http, &pending).await.status(),
        StatusCode::NOT_FOUND
    );
    let rows = fixture.database.admin.query(
        "SELECT verdict,attempts FROM registry_internal.registry_attachment_verification ORDER BY verdict", &[],
    ).await.unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)))
            .collect::<Vec<_>>(),
        vec![("pending".into(), 1)]
    );
    let requests = s3.state.verifier_bytes.lock().await;
    assert_eq!(
        *requests,
        vec![
            b"approved-exact-bytes".to_vec(),
            b"approved-exact-bytes".to_vec(),
            b"replacement-rejected".to_vec(),
            b"replacement-timeout".to_vec()
        ]
    );
    drop(requests);
    assert_eq!(
        *s3.state.verifier_content_types.lock().await,
        vec!["text/plain", "application/pdf", "text/plain", "text/plain"]
    );
    let audit = capture.entries();
    assert!(audit
        .iter()
        .any(|record| record.to_string().contains("approved")));
    assert!(audit
        .iter()
        .any(|record| record.to_string().contains("rejected")));
    assert!(audit
        .iter()
        .any(|record| record.to_string().contains("retry-pending")));
    fixture.finish().await;
}
