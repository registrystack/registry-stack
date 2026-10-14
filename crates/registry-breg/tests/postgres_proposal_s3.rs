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
        assert_eq!(headers["content-type"], "text/plain");
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
            .tempdir_in("/private/tmp")
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
    assert_eq!(
        s3.state.requests.load(Ordering::SeqCst),
        requests,
        "slot/current target refusal precedes transport"
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
        move |mutations| {
            mutations
                .with_attachment_storage(storage)
                .with_action_timeout_for_test(Duration::from_millis(300))
        },
    )
    .await;
    let draft = start(&fixture, "After", "s3-interrupted-start").await;
    s3.state.mode.store(4, Ordering::SeqCst);
    assert!(
        !raw_upload(&fixture.http, &draft, "support", "s3-interrupted-upload")
            .await
            .status()
            .is_success()
    );
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
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(false),
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
            b"replacement-rejected".to_vec(),
            b"replacement-timeout".to_vec()
        ]
    );
    drop(requests);
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
