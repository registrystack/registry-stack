// SPDX-License-Identifier: Apache-2.0
//! Native Proposal operator retention, shared blobs, and deletion tombstones.
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
    http::{Method, StatusCode},
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
}
async fn object_request(
    State(state): State<Arc<Objects>>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    body: Bytes,
) -> Response {
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
            "{}\nattachmentStorage:\n  type: s3\n  endpoint: {endpoint}\n  bucket: synthetic-proposal\n  region: us-east-1\n  accessKeyIdRef: secret:file/access\n  secretAccessKeyRef: secret:file/key\n  attemptTimeoutMilliseconds: 2000\nattachmentVerification:\n  type: http\n  endpoint: {endpoint}/verify\n  policyId: synthetic-policy\n  authorizationRef: secret:file/verifier\n",
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
async fn applied(
    fixture: &client_http::ClientFixture,
    suffix: &str,
) -> registry_breg_client::BRegProposal {
    let draft = start(fixture, "After", &format!("{suffix}-start")).await;
    let client = &fixture.http.client;
    let uploaded = client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"shared-synthetic-content",
            &key(&format!("{suffix}-upload")),
        )
        .await
        .unwrap()
        .value;
    let submit = client
        .prepare_proposal(
            &uploaded,
            "submit",
            json!({}),
            &key(&format!("{suffix}-submit")),
        )
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let apply = client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":1,"effectDigest":submitted.effect_digest().unwrap()}),
            &key(&format!("{suffix}-apply")),
        )
        .unwrap();
    client.execute_proposal(&apply).await.unwrap().value
}
fn scope(
    proposal: &registry_breg_client::BRegProposal,
) -> registry_breg::proposal_retention::ProposalDetailErasureScope<'static> {
    registry_breg::proposal_retention::ProposalDetailErasureScope {
        action_id: "correct-name",
        proposal_id: uuid::Uuid::parse_str(proposal.id()).unwrap(),
        submission_version: 1,
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_attachment_bytes_survive_until_the_last_native_proposal_erasure() {
    let fixture =
        client_http::ClientFixture::start(registry(false), claims("author", "zone-a")).await;
    let first = applied(&fixture, "first").await;
    let second = applied(&fixture, "second").await;
    let count = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_attachment_blobs",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(count.get::<_, i64>(0), 1, "same content shares one blob");
    let operator = cleanup(&fixture, AttachmentStorage::Database);
    assert_eq!(
        operator
            .erase(scope(&first))
            .await
            .unwrap()
            .erasure
            .attachment_references,
        1
    );
    assert!(fixture
        .http
        .client
        .download_proposal_attachment(&first, "support")
        .await
        .is_err());
    let erased = fixture
        .http
        .client
        .read_proposal(&first)
        .await
        .unwrap()
        .value;
    assert_eq!(
        erased.state(),
        registry_breg_client::BRegProposalState::Applied
    );
    assert!(erased.effect_digest().is_none());
    assert!(erased.application_status().is_none());
    assert!(
        erased.application().is_none(),
        "erased evidence cannot settle a frozen-submission observation"
    );
    assert_eq!(
        fixture
            .http
            .client
            .download_proposal_attachment(&second, "support")
            .await
            .unwrap()
            .value
            .as_bytes(),
        b"shared-synthetic-content"
    );
    assert_eq!(
        operator
            .erase(scope(&second))
            .await
            .unwrap()
            .erasure
            .attachment_references,
        1
    );
    let count = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_attachment_blobs",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(count.get::<_, i64>(0), 0);
    fixture.finish().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_proposal_erasure_refuses_a_failed_request_audit_without_changing_detail() {
    use registry_breg::postgres::{ExpectedManagedCatalog, RegistryLockKey};
    let fixture =
        client_http::ClientFixture::start(registry(false), claims("author", "zone-a")).await;
    let proposal = applied(&fixture, "audit").await;
    let profile =
        registry_platform_audit::AuditProfile::production_from_secret_bytes(vec![0x44; 32].into())
            .unwrap();
    let (audit, capture) = registry_breg::audit::test_support::capturing(profile);
    capture.fail_after(0);
    let operator =
        registry_breg::proposal_retention::ProposalRetentionOperatorService::new_for_test(
            (*fixture.registry).clone(),
            fixture.identity.clone(),
            ExpectedManagedCatalog::compiled(&fixture.registry),
            RegistryLockKey::derive(fixture.registry.registry_id()).unwrap(),
            fixture.database.migration_config.clone(),
            fixture.database.migration_role.clone(),
            fixture.database.runtime_role.clone(),
            audit,
        );
    assert!(matches!(
        operator.erase(scope(&proposal)).await,
        Err(registry_breg::proposal_retention::ProposalRetentionError::Unavailable)
    ));
    assert_eq!(
        fixture
            .http
            .client
            .download_proposal_attachment(&proposal, "support")
            .await
            .unwrap()
            .value
            .as_bytes(),
        b"shared-synthetic-content"
    );
    let row=fixture.database.admin.query_one("SELECT count(*)::bigint FROM registry_internal.registry_proposal_submissions WHERE snapshot IS NOT NULL",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert!(capture.entries().is_empty());
    fixture.finish().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_tombstones_survive_late_writes_failed_rechecks_and_backend_change() {
    let s3 = S3Fixture::new().await;
    let storage = s3.storage.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(false),
        claims("author", "zone-a"),
        move |mutations| mutations.with_attachment_storage(storage),
    )
    .await;
    let proposal = applied(&fixture, "tombstone").await;
    let object = s3
        .state
        .bytes
        .lock()
        .await
        .iter()
        .next()
        .map(|(path, bytes)| (path.clone(), bytes.clone()))
        .unwrap();
    let operator = cleanup(&fixture, s3.storage.clone());
    let erased = operator.erase(scope(&proposal)).await.unwrap();
    assert_eq!(erased.external_deletion_tombstones, 1);
    assert!(s3.state.bytes.lock().await.is_empty());
    s3.state
        .bytes
        .lock()
        .await
        .insert(object.0.clone(), object.1.clone());
    s3.state.mode.store(1, Ordering::SeqCst);
    assert_eq!(
        operator
            .cleanup_attachments()
            .await
            .unwrap()
            .pending_external_deletions,
        1
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT state FROM registry_internal.registry_attachment_blobs",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "delete_pending");
    assert!(cleanup(&fixture, AttachmentStorage::Database)
        .cleanup_attachments()
        .await
        .is_err());
    s3.state.mode.store(0, Ordering::SeqCst);
    let result = operator.cleanup_attachments().await.unwrap();
    assert_eq!(result.pending_external_deletions, 0);
    assert_eq!(result.external_deletion_tombstones, 1);
    assert!(s3.state.bytes.lock().await.is_empty());
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT state FROM registry_internal.registry_attachment_blobs",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "delete_confirmed");
    fixture.finish().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_operator_retry_preserves_the_exact_job_and_refuses_stale_or_exhausted_work() {
    use registry_breg::review_recovery::{ReviewRecoveryOperatorService, ReviewRecoveryScope};
    let fixture =
        client_http::ClientFixture::start(registry(true), claims("author", "zone-a")).await;
    let draft = start(&fixture, "Retry", "retry-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("retry-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let id = uuid::Uuid::parse_str(submitted.id()).unwrap();
    let operator = ReviewRecoveryOperatorService::over_retention_service_for_test(cleanup(
        &fixture,
        AttachmentStorage::Database,
    ));
    let original=fixture.database.admin.query_one("SELECT job_id,proposal_digest,system_grant_revision FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",&[&id]).await.unwrap();
    let job: uuid::Uuid = original.get(0);
    let digest: String = original.get(1);
    let grant: String = original.get(2);
    let scope = || ReviewRecoveryScope {
        action_id: "correct-name",
        proposal_id: id,
        submission_version: 1,
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs SET state='blocked',attempt_count=1,last_error_code='dependency-outage' WHERE proposal_id=$1",&[&id]).await.unwrap();
    for (state, attempts, code) in [
        ("applying", 1, "dependency-outage"),
        ("blocked", 3, "dependency-outage"),
        ("blocked", 1, "target-stale"),
    ] {
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs SET state=$2,attempt_count=$3,last_error_code=$4 WHERE proposal_id=$1",&[&id,&state,&attempts,&code]).await.unwrap();
        assert!(operator.retry_application(scope()).await.is_err());
        let row=fixture.database.admin.query_one("SELECT state,attempt_count,last_error_code FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",&[&id]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), state);
        assert_eq!(row.get::<_, i32>(1), attempts);
        assert_eq!(row.get::<_, String>(2), code);
    }
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs SET state='blocked',attempt_count=1,last_error_code='dependency-outage' WHERE proposal_id=$1",&[&id]).await.unwrap();
    let wrong = format!("sha256:{}", "f".repeat(64));
    for column in ["proposal_digest", "system_grant_revision"] {
        fixture.database.admin.execute(&format!("UPDATE registry_internal.registry_proposal_application_jobs SET {column}=$2 WHERE proposal_id=$1"),&[&id,&wrong]).await.unwrap();
        assert!(operator.retry_application(scope()).await.is_err());
        fixture.database.admin.execute(&format!("UPDATE registry_internal.registry_proposal_application_jobs SET {column}=$2 WHERE proposal_id=$1"),&[&id,&if column=="proposal_digest"{&digest}else{&grant}]).await.unwrap();
    }
    let recovery = operator.retry_application(scope()).await.unwrap();
    assert_eq!(recovery.state, "queued");
    let row=fixture.database.admin.query_one("SELECT job_id,proposal_digest,system_grant_revision,state,attempt_count FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",&[&id]).await.unwrap();
    assert_eq!(row.get::<_, uuid::Uuid>(0), job);
    assert_eq!(row.get::<_, String>(1), digest);
    assert_eq!(row.get::<_, String>(2), grant);
    assert_eq!(row.get::<_, String>(3), "queued");
    assert_eq!(row.get::<_, i32>(4), 1);
    fixture.finish().await;
}
