// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::field_encryption::{FieldEncryptionProvider, FieldEncryptionService};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use registry_platform_config::{SecretProvider, SecretReference, SecretResolver};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PRINCIPAL: &str = "receipt-principal-must-not-enter-run-rows";
const PACKAGE_ID: &str = "ingestion-registry";
const PACKAGE_REVISION: &str = "package-ingestion-1";

/// A stored receipt releases its batch answer only with every sealed member
/// opened: a successor package that renames an encrypted field's API name
/// leaves the stored envelope under the retired member name, and both the
/// replay and the receipt recovery must then refuse instead of serving it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_renamed_encrypted_field_fails_the_receipt_closed() {
    let harness =
        IngestionHarness::from_registry_with_encryption(encrypted_widget_registry()).await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let chunks = plan_chunks(&encrypted_items("encrypted-rename", 2), 2);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);
    assert_eq!(durable_widget_count(&harness).await, 2);

    // The successor package renames the encrypted field's API name, so the
    // stored envelope sits under a member name the active entity no longer
    // reads. Every release of the retained receipt must fail closed.
    let successor = harness
        .restart_with_registry(renamed_serial_api_registry())
        .await;

    let replay = successor
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replay.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !contains_envelope_marker(&body_bytes(replay).await),
        "the replayed receipt answer carries no sealed envelope"
    );

    let recovered = successor
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks/0/receipt"),
            &claims,
        )
        .await;
    assert_eq!(recovered.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !contains_envelope_marker(&body_bytes(recovered).await),
        "the recovered receipt answer carries no sealed envelope"
    );

    assert_receipt_stays_sealed(&harness, &run_id).await;
    assert_eq!(
        durable_widget_count(&harness).await,
        2,
        "the refused releases commit nothing"
    );
}

/// The same successor activation without the rename still opens the stored
/// members on both release edges, so the refusal above is the rename's doing
/// and not the activation's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_successor_without_the_rename_still_opens_the_stored_members() {
    let harness =
        IngestionHarness::from_registry_with_encryption(encrypted_widget_registry()).await;
    let claims = operator_claims(PRINCIPAL, "zone-a");
    let chunks = plan_chunks(&encrypted_items("encrypted-successor", 2), 2);
    let run_id = harness.create_run(&claims, &chunks).await;
    let committed = harness
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(committed.status(), StatusCode::OK);

    let successor = harness
        .restart_with_registry(encrypted_widget_registry())
        .await;

    let replay = successor
        .post_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks"),
            &claims,
            chunk_body(&chunks, 0),
        )
        .await;
    assert_eq!(replay.status(), StatusCode::OK);
    let raw = body_bytes(replay).await;
    assert!(
        !contains_envelope_marker(&raw),
        "the replayed receipt answer carries no sealed envelope"
    );
    let body: Value = serde_json::from_slice(&raw).expect("replay answer is JSON");
    assert_eq!(body["receipt"]["replayed"], true);
    assert_eq!(
        body["receipt"]["batch"]["results"][0]["data"]["serialNumber"],
        "SN-0000"
    );

    let recovered = successor
        .get_json(
            &format!("/v1/records/widgets/ingestion-runs/{run_id}/chunks/0/receipt"),
            &claims,
        )
        .await;
    assert_eq!(recovered.status(), StatusCode::OK);
    let raw = body_bytes(recovered).await;
    assert!(
        !contains_envelope_marker(&raw),
        "the recovered receipt answer carries no sealed envelope"
    );
    let body: Value = serde_json::from_slice(&raw).expect("recovery answer is JSON");
    assert_eq!(
        body["batch"]["results"][0]["data"]["serialNumber"],
        "SN-0000"
    );

    assert_receipt_stays_sealed(&harness, &run_id).await;
}

/// Items over the encrypted fixture, so the stored receipt carries one sealed
/// serial-number envelope per created record.
fn encrypted_items(label_prefix: &str, count: i64) -> Vec<Value> {
    (0..count)
        .map(|index| {
            json!({"operation":"create", "data": {
                "jurisdiction": "zone-a",
                "label": format!("{label_prefix}-{index}"),
                "quantity": index,
                "serialNumber": format!("SN-{index:04}")
            }})
        })
        .collect()
}

/// The sealed-envelope member tag an opened answer must never carry.
const ENVELOPE_MARKER: &[u8] = b"__bregEncryptedV1";

fn contains_envelope_marker(bytes: &[u8]) -> bool {
    bytes
        .windows(ENVELOPE_MARKER.len())
        .any(|window| window == ENVELOPE_MARKER)
}

/// Assert one stored chunk receipt keeps its serial-number member sealed: the
/// envelope marker is present and no plaintext serial survives at rest.
async fn assert_receipt_stays_sealed(harness: &IngestionHarness, run_id: &str) {
    let row = harness
        .database
        .admin
        .query_one(
            "SELECT position('__bregEncryptedV1' in convert_from(receipt, 'UTF8')) > 0,
                    position('SN-0000' in convert_from(receipt, 'UTF8')) = 0
               FROM registry_internal.registry_ingestion_run_chunks
              WHERE run_id = $1 AND chunk_index = 0 AND erased_at IS NULL",
            &[&Uuid::parse_str(run_id).expect("run id parses")],
        )
        .await
        .expect("the stored chunk receipt reads");
    assert!(
        row.get::<_, bool>(0),
        "the stored receipt keeps the sealed envelope"
    );
    assert!(
        row.get::<_, bool>(1),
        "the stored receipt carries no plaintext serial"
    );
}

fn write_secret(path: &std::path::Path, value: &[u8]) {
    std::fs::write(path, value).expect("test secret writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("test secret permissions set");
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in Sha256::digest(bytes) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn chunk_digest(items: &[Value]) -> String {
    let canonical = registry_platform_canonical_json::canonicalize_json(&json!({ "items": items }))
        .expect("canonical JSON derives");
    hex_digest(&canonical)
}

fn plan_chunks(items: &[Value], maximum_per_chunk: usize) -> ChunkPlan {
    assert!(!items.is_empty(), "a run announces at least one item");
    let mut bounds = Vec::new();
    let mut start = 0;
    while start < items.len() {
        let end = (start + maximum_per_chunk).min(items.len());
        bounds.push((start, end));
        start = end;
    }
    chunk_plan(items, &bounds)
}

/// One chunk plan over contiguous item bounds: each chunk binds its digest,
/// and the prefix digests run over the raw source input through the end of
/// each chunk.
fn chunk_plan(items: &[Value], bounds: &[(usize, usize)]) -> ChunkPlan {
    assert!(!items.is_empty(), "a run announces at least one item");
    assert!(!bounds.is_empty(), "a plan carries at least one chunk");
    let lines: Vec<Vec<u8>> = items
        .iter()
        .map(|item| {
            let mut line = registry_platform_canonical_json::canonicalize_json(item)
                .expect("canonical JSON derives");
            line.push(b'\n');
            line
        })
        .collect();
    let mut raw_input = Vec::new();
    for line in &lines {
        raw_input.extend_from_slice(line);
    }
    let mut starts = Vec::new();
    let mut ends = Vec::new();
    let mut digests = Vec::new();
    let mut prefix_digests = Vec::new();
    for &(start, end) in bounds {
        let chunk = &items[start..end];
        let mut raw_prefix = Vec::new();
        for line in &lines[..end] {
            raw_prefix.extend_from_slice(line);
        }
        starts.push(start);
        ends.push(end);
        digests.push(chunk_digest(chunk));
        prefix_digests.push(hex_digest(&raw_prefix));
    }
    ChunkPlan {
        items: items.to_vec(),
        starts,
        ends,
        digests,
        prefix_digests,
        input_digest: hex_digest(&raw_input),
        input_length: raw_input.len() as i64,
        item_count: items.len() as i64,
        chunk_count: bounds.len() as i64,
    }
}

struct ChunkPlan {
    items: Vec<Value>,
    starts: Vec<usize>,
    ends: Vec<usize>,
    digests: Vec<String>,
    prefix_digests: Vec<String>,
    input_digest: String,
    input_length: i64,
    item_count: i64,
    chunk_count: i64,
}

fn chunk_body(plan: &ChunkPlan, index: usize) -> Value {
    json!({
        "chunkIndex": index,
        "items": plan.items[plan.starts[index]..plan.ends[index]],
        "digest": plan.digests[index],
        "prefixDigest": plan.prefix_digests[index],
    })
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .expect("request");
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("response")
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("JSON response")
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body")
        .to_vec()
}

async fn durable_widget_count(harness: &IngestionHarness) -> i64 {
    let table = &harness.registry.entities()["widget"].physical_table;
    let row = harness
        .database
        .admin
        .query_one(
            &format!("SELECT count(*) FROM registry_data.\"{table}\""),
            &[],
        )
        .await
        .expect("widget rows are readable");
    row.get(0)
}

const FIXTURE_HEAD: &str = r#"{
  "apiVersion":"registry.registrystack.org/v1alpha1",
  "kind":"RegistryProject",
  "registry":{"id":"ingestion-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
  "entities":[{
    "id":"widget","primaryDataset":"test-dataset","route":"widgets","mutationMode":"mutable","classification":"public",
    "batch":{"maximumItems":3,"maximumBytes":8192},
    "constraints":[{"kind":"unique","fields":["label"]}],
    "fields":[
      {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
      {"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"},
      {"id":"quantity","type":"int64","required":true,"classification":"public"}
    ]
  }],"#;

const FIXTURE_TAIL: &str = r#"
  "accessProfiles":[{
    "id":"operator","default":true,"principalClaim":"registry_principal",
    "requiredPurposes":["case-management","case-review"],
    "permissions":[{
      "entity":"widget","operations":["create","get","patch","batch"],
      "readableFields":["jurisdiction","label","quantity"],
      "writableFields":["jurisdiction","label","quantity"],
      "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
    }]
  }]
}"#;

/// The shared ingestion fixture with one restricted, encrypted field added,
/// so chunk receipts hold sealed envelope members only key state can open.
fn encrypted_widget_fixture() -> String {
    format!("{FIXTURE_HEAD}{FIXTURE_TAIL}")
        .replacen(
            concat!(
                r#"      {"id":"quantity","type":"int64","required":true,"classification":"public"}"#,
                "\n",
            ),
            concat!(
                r#"      {"id":"quantity","type":"int64","required":true,"classification":"public"},"#,
                "\n",
                r#"      {"id":"serial-number","apiName":"serialNumber","type":"string","maxLength":64,"classification":"restricted","encrypted":true}"#,
                "\n",
            ),
            1,
        )
        .replace(
            r#""readableFields":["jurisdiction","label","quantity"]"#,
            r#""readableFields":["jurisdiction","label","quantity","serial-number"]"#,
        )
        .replace(
            r#""writableFields":["jurisdiction","label","quantity"]"#,
            r#""writableFields":["jurisdiction","label","quantity","serial-number"]"#,
        )
}

fn encrypted_widget_registry() -> Arc<registry_breg::CompiledRegistry> {
    let project = parse_project_json(encrypted_widget_fixture().as_bytes())
        .expect("the encrypted fixture parses");
    Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("the encrypted fixture compiles to trusted inventories"),
    )
}

/// The same encrypted fixture under a successor package that renamed the
/// encrypted field's API name: the member name a stored envelope sits under
/// retires while the field id, and with it the envelope's key binding, stay.
fn renamed_serial_api_registry() -> Arc<registry_breg::CompiledRegistry> {
    let fixture = encrypted_widget_fixture().replacen(
        r#""apiName":"serialNumber""#,
        r#""apiName":"serialCode""#,
        1,
    );
    let project = parse_project_json(fixture.as_bytes()).expect("the renamed fixture parses");
    Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("the renamed fixture compiles to trusted inventories"),
    )
}

struct IngestionHarness {
    database: TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit_profile: AuditProfile,
    field_encryption: Option<Arc<FieldEncryptionService>>,
    /// Held, never read: the activated service keeps its key in memory, and
    /// the secret file must outlive every restart that shares the service.
    #[allow(dead_code)]
    secrets_root: Option<tempfile::TempDir>,
    app: axum::Router,
}

impl IngestionHarness {
    /// The harness with local-file field-encryption key state activated, so
    /// chunks over the encrypted field seal at rest under the key this
    /// harness holds for every restart that keeps it.
    async fn from_registry_with_encryption(registry: Arc<registry_breg::CompiledRegistry>) -> Self {
        let secrets_root = tempfile::Builder::new()
            .prefix("breg-receipt-field-dek-")
            .tempdir_in(
                std::env::temp_dir()
                    .canonicalize()
                    .expect("temporary parent canonicalizes"),
            )
            .expect("field-encryption secret root creates");
        write_secret(
            &secrets_root.path().join("field-dek"),
            BASE64.encode([0x71_u8; 32]).as_bytes(),
        );
        let database = TestDatabase::create(8).await;
        let (migration, migration_task) = database.connect_migration().await;
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("migration installs the compiler-owned schema");
        let identity = initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: PACKAGE_ID,
                environment: "local",
                instance_id: "ingestion-instance",
                database_id: "ingestion-database",
                package_revision: PACKAGE_REVISION,
                package_sequence: 1,
            },
        )
        .await
        .expect("active package identity is initialized");
        let dek_ref = SecretReference::parse("secret:file/field-dek")
            .expect("local-file key reference parses");
        let secrets = SecretResolver::new([SecretProvider::File], secrets_root.path())
            .expect("local-file secret resolver builds");
        let field_encryption = Some(Arc::new(
            FieldEncryptionService::activate(
                &FieldEncryptionProvider::LocalFile { dek_ref },
                registry.registry_id(),
                PACKAGE_REVISION,
                &secrets,
                &migration,
            )
            .await
            .expect("field-encryption key state activates"),
        ));
        migration_task.abort();
        let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
        let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x7c; 32].into())
            .expect("test owns a keyed audit profile");
        let pool = database
            .runtime_config
            .build_pool()
            .expect("bounded runtime pool builds");
        let app = build_router(
            pool,
            registry.clone(),
            identity.clone(),
            lock_key,
            audit_profile.clone(),
            field_encryption.clone(),
        );
        Self {
            database,
            registry,
            identity,
            lock_key,
            audit_profile,
            field_encryption,
            secrets_root: Some(secrets_root),
            app,
        }
    }

    /// Rebuild the HTTP surface from a caller-chosen successor registry, as a
    /// restarted process under an activated successor package would.
    async fn restart_with_registry(
        &self,
        registry: Arc<registry_breg::CompiledRegistry>,
    ) -> Surface {
        let successor = registry_breg::postgres::ExpectedRegistryIdentity {
            package_revision: "package-ingestion-2".to_owned(),
            package_sequence: 2,
            ..self.identity.clone()
        };
        let changed = self
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_state
                    SET active_package_revision = $1, schema_fingerprint = $2,
                        package_sequence = $3
                  WHERE singleton",
                &[
                    &successor.package_revision,
                    &successor.schema_fingerprint,
                    &successor.package_sequence,
                ],
            )
            .await
            .expect("successor revision activates");
        assert_eq!(changed, 1);
        let pool = self
            .database
            .runtime_config
            .build_pool()
            .expect("bounded runtime pool builds");
        Surface {
            app: build_router(
                pool,
                registry,
                successor,
                self.lock_key,
                self.audit_profile.clone(),
                self.field_encryption.clone(),
            ),
        }
    }

    fn run_body(&self, operation: &str, plan: &ChunkPlan) -> Value {
        json!({
            "operation": operation,
            "profileId": "operator",
            "packageRevision": PACKAGE_REVISION,
            "schemaFingerprint": self.identity.schema_fingerprint,
            "inputDigest": plan.input_digest,
            "inputLength": plan.input_length,
            "itemCount": plan.item_count,
            "chunkCount": plan.chunk_count,
            "chunkAlgorithmVersion": "greedy-canonical-http-batch-v1",
        })
    }

    async fn post_json(
        &self,
        uri: &str,
        claims: &VerifiedRequestClaims,
        body: Value,
    ) -> axum::response::Response {
        send(
            &self.app,
            Method::POST,
            uri,
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&body).expect("request JSON"),
        )
        .await
    }

    async fn create_run(&self, claims: &VerifiedRequestClaims, plan: &ChunkPlan) -> String {
        let response = self
            .post_json(
                "/v1/records/widgets/ingestion-runs",
                claims,
                self.run_body("create", plan),
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        body_json(response).await["run"]["runId"]
            .as_str()
            .expect("run id")
            .to_owned()
    }
}

/// A restarted HTTP surface over the same database, so a test can drive the
/// run through a process boundary with the same request helpers.
struct Surface {
    app: axum::Router,
}

impl Surface {
    async fn post_json(
        &self,
        uri: &str,
        claims: &VerifiedRequestClaims,
        body: Value,
    ) -> axum::response::Response {
        send(
            &self.app,
            Method::POST,
            uri,
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&body).expect("request JSON"),
        )
        .await
    }

    async fn get_json(
        &self,
        uri: &str,
        claims: &VerifiedRequestClaims,
    ) -> axum::response::Response {
        send(
            &self.app,
            Method::GET,
            uri,
            Some(claims.clone()),
            &[],
            Vec::new(),
        )
        .await
    }
}

fn build_router(
    pool: registry_breg::postgres::RuntimePool,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
    field_encryption: Option<Arc<FieldEncryptionService>>,
) -> axum::Router {
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x53; 32]), Duration::from_secs(300))
            .expect("cursor key is valid"),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        profile.clone(),
        cursors.clone(),
    ));
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        profile,
    );
    let mutations = match field_encryption {
        Some(service) => mutations.with_field_encryption(service),
        None => mutations,
    };
    router(Arc::new(
        HttpService::new(
            registry,
            ReadRuntimeIdentity {
                package_revision: identity.package_revision,
                schema_fingerprint: identity.schema_fingerprint,
            },
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(Arc::new(mutations)),
    ))
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn operator_claims(principal: &str, jurisdiction: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::new(),
        Some("case-management".to_owned()),
        BTreeMap::from([(
            "jurisdiction".to_owned(),
            VerifiedClaimValue::direct_string(jurisdiction).expect("direct claim"),
        )]),
    )
    .expect("verified claims are bounded")
}
