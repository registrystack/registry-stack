// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use postgres_harness::TestDatabase;
use registry_platform_audit::AuditProfile;
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::event_destination::ActivatedEventDestinationRegistry;
use registry_server::model::CompiledEventDelivery;
use registry_server::mutation::{
    MutationBody, MutationCoordinator, MutationError, MutationFaultPoint, MutationPlan,
    MutationRequest,
};
use registry_server::postgres::{
    install_compiled_schema, managed_schema_fingerprint, ClaimContext, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, RegistryLockKey, RowBoundaryContext,
};
use registry_server::runtime_config::parse_runtime_config;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::Row;
use uuid::Uuid;

const PACKAGE_REVISION: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SCHEMA_FINGERPRINT: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DESTINATION_ID: &str = "case-operations";
const ORIGIN_CANARY: &str = "webhook-url-canary.example";
const PATH_CANARY: &str = "/webhook-path-canary";
const SECRET_REF_CANARY: &str = "webhook-key-ref-canary";
const SECRET_KEY_CANARY: &[u8] = b"webhook-key-material-canary-0123456789abcdef";
const RESTRICTED_CANARY: &str = "restricted-projection-canary";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_webhook_outbox_capture_is_atomic_package_bound_and_deterministically_identified(
) {
    let database = TestDatabase::create(10).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = compiled_registry();
    let compiled_delivery = compiled.event_deliveries().deliveries[0].clone();
    let mut mismatched_value =
        serde_json::to_value(&compiled).expect("compiled registry serializes");
    mismatched_value["eventDeliveryInventory"]["deliveries"][0]["projectionFields"] =
        json!(["label"]);
    let mismatched =
        serde_json::from_value(mismatched_value).expect("strict mismatch deserializes");
    assert_eq!(
        MutationPlan::from_compiled(&mismatched, "records.case.create").err(),
        Some(MutationError::InvalidRequest),
        "a source/inventory mismatch is refused before mutation I/O"
    );

    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs the compiled data and capture schemas");
    let expected_catalog = ExpectedManagedCatalog::compiled(&compiled);
    let authoring_search_path: String = migration
        .query_one("SELECT current_setting('search_path')", &[])
        .await
        .expect("authoring search path reads")
        .get(0);
    let authoring_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("authoring-path fingerprint computes");
    assert_eq!(
        migration
            .query_one("SELECT current_setting('search_path')", &[])
            .await
            .expect("authoring search path rereads")
            .get::<_, String>(0),
        authoring_search_path,
        "fingerprinting restores the caller search path"
    );
    migration
        .batch_execute("SET search_path TO pg_catalog, registry_internal, registry_data, pg_temp")
        .await
        .expect("apply-style search path installs");
    let apply_search_path: String = migration
        .query_one("SELECT current_setting('search_path')", &[])
        .await
        .expect("apply search path reads")
        .get(0);
    let apply_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("apply-path fingerprint computes");
    assert_eq!(authoring_fingerprint, apply_fingerprint);
    assert_eq!(
        migration
            .query_one("SELECT current_setting('search_path')", &[])
            .await
            .expect("apply search path rereads")
            .get::<_, String>(0),
        apply_search_path,
        "fingerprinting restores the pinned apply search path"
    );
    let identity = expected_identity();
    initialize_registry_state(&migration, &identity).await;
    migration_task.abort();

    let fixture = DestinationFixture::new();
    let destinations = Arc::new(fixture.activate(&compiled));
    let binding_digest = destinations
        .lookup(DESTINATION_ID)
        .expect("compiled logical destination is activated")
        .binding_digest()
        .to_owned();
    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x5a; 32].into())
        .expect("test owns a strongly keyed audit profile");
    let plan = MutationPlan::from_compiled(&compiled, "records.case.create")
        .expect("create plan retains the exact compiler delivery");
    let claims = mutation_claims(&compiled);
    let table = &compiled.entities()["case"].physical_table;
    let lock_key =
        RegistryLockKey::derive("webhook-outbox-registry").expect("test lock identity is bounded");

    let without_activation = MutationCoordinator::new(
        lock_key,
        Duration::from_secs(2),
        identity.clone(),
        audit_profile.clone(),
    );
    let before_missing = durable_counts(&database, table).await;
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    assert_eq!(
        without_activation
            .execute(
                &mut client,
                create_request(&plan, &claims, "missing-activation", "missing"),
            )
            .await,
        Err(MutationError::Unavailable)
    );
    assert_eq!(durable_counts(&database, table).await, before_missing);

    let coordinator = MutationCoordinator::new_with_event_destinations(
        lock_key,
        Duration::from_secs(2),
        identity.clone(),
        audit_profile.clone(),
        Some(Arc::clone(&destinations)),
    );
    database
        .admin
        .batch_execute(&format!(
            "REVOKE INSERT ON registry_internal.registry_webhook_deliveries FROM \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("administrator can inject a capture privilege failure");
    let before_revoke = durable_counts(&database, table).await;
    assert_eq!(
        coordinator
            .execute(
                &mut client,
                create_request(&plan, &claims, "revoked-delivery-insert", "revoked"),
            )
            .await,
        Err(MutationError::Unavailable)
    );
    assert_eq!(durable_counts(&database, table).await, before_revoke);
    database
        .admin
        .batch_execute(&format!(
            "GRANT INSERT ON registry_internal.registry_webhook_deliveries TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("administrator restores the capture-only grant");

    for (index, fault) in [
        MutationFaultPoint::BeforeTerminalAudit,
        MutationFaultPoint::BeforeIdempotency,
        MutationFaultPoint::BeforeCommit,
    ]
    .into_iter()
    .enumerate()
    {
        let faulted = MutationCoordinator::new_with_event_destinations(
            lock_key,
            Duration::from_secs(2),
            identity.clone(),
            audit_profile.clone(),
            Some(Arc::clone(&destinations)),
        );
        let before = durable_counts(&database, table).await;
        assert_eq!(
            faulted
                .execute_with_fault(
                    &mut client,
                    create_request(
                        &plan,
                        &claims,
                        &format!("terminal-fault-{index}"),
                        &format!("fault-{index}"),
                    ),
                    fault,
                )
                .await,
            Err(MutationError::Unavailable)
        );
        assert_eq!(durable_counts(&database, table).await, before);
    }

    let first = coordinator
        .execute(
            &mut client,
            create_request(&plan, &claims, "successful-create", "first"),
        )
        .await
        .expect("configured webhook capture commits with the record");
    assert!(!first.replayed());
    let first_response: Value = serde_json::from_slice(first.response().body())
        .expect("held create response is strict JSON");
    let raw_record_id = first_response["id"]
        .as_str()
        .expect("create response contains a record id");
    let first_capture = capture(&database, 0).await;
    assert_capture_matches(
        &first_capture,
        &compiled_delivery,
        &binding_digest,
        &identity,
    );
    assert!(first_capture.payload == expected_payload());
    assert!(first_capture.payload.len() <= compiled_delivery.maximum_payload_bytes as usize);
    assert_delivery_is_transport_and_value_free(&database, first_capture.event_id, raw_record_id)
        .await;
    assert_initial_delivery_state(&database, &first_capture).await;
    assert_capture_acl_is_insert_and_select_only(&database).await;

    let after_first = durable_counts(&database, table).await;
    let replay = coordinator
        .execute(
            &mut client,
            create_request(&plan, &claims, "successful-create", "first"),
        )
        .await
        .expect("exact replay returns the held result");
    assert!(replay.replayed());
    assert!(replay.response() == first.response());
    assert_eq!(durable_counts(&database, table).await, after_first);

    let mut replay_client_a = pool
        .get_for_test()
        .await
        .expect("first concurrent replay connection is available");
    let mut replay_client_b = pool
        .get_for_test()
        .await
        .expect("second concurrent replay connection is available");
    let (replay_a, replay_b) = tokio::join!(
        coordinator.execute(
            &mut replay_client_a,
            create_request(&plan, &claims, "successful-create", "first"),
        ),
        coordinator.execute(
            &mut replay_client_b,
            create_request(&plan, &claims, "successful-create", "first"),
        )
    );
    for replay in [replay_a, replay_b] {
        let replay = replay.expect("concurrent exact replay returns the held result");
        assert!(replay.replayed());
        assert!(replay.response() == first.response());
    }
    assert_eq!(durable_counts(&database, table).await, after_first);
    assert_eq!(capture(&database, 0).await.event_id, first_capture.event_id);

    let second = coordinator
        .execute(
            &mut client,
            create_request(&plan, &claims, "second-create", "second"),
        )
        .await
        .expect("a distinct mutation captures a distinct event");
    assert!(!second.replayed());
    let second_capture = capture(&database, 1).await;
    assert_ne!(second_capture.event_id, first_capture.event_id);
    assert_eq!(
        second_capture.compiled_delivery_id,
        first_capture.compiled_delivery_id
    );
    assert_eq!(durable_counts(&database, table).await.delivery, 2);

    drop(replay_client_a);
    drop(replay_client_b);
    drop(client);
    drop(pool);
    database.cleanup().await;
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"webhook-outbox-registry","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"case","route":"cases","mutationMode":"create_only","classification":"restricted",
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
              {"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"},
              {"id":"restricted_note","type":"string","maxLength":64,"required":true,"classification":"restricted"}
            ],
            "accessProfiles":[{
              "id":"operator","default":true,"principalClaim":"registry_principal",
              "requiredPurposes":["case-management"],
              "operations":["create","get","list"],
              "readableFields":["jurisdiction","label","restricted_note"],
              "writableFields":["jurisdiction","label","restricted_note"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }],
            "events":[{
              "id":"case-created","trigger":"created","projection":["label","restricted_note"],
              "webhook":{
                "destinationId":"case-operations",
                "classificationCeiling":"restricted",
                "authenticationProfile":"hmac_sha256_v1",
                "delivery":{
                  "attemptTimeoutMs":5000,
                  "initialBackoffMs":250,
                  "maximumBackoffMs":2000,
                  "maximumAttempts":5,
                  "deadLetter":"required",
                  "operatorReplay":true
                }
              }
            }]
          }]
        }"#,
    )
    .expect("webhook capture fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("webhook capture fixture compiles")
}

fn expected_identity() -> ExpectedRegistryIdentity {
    ExpectedRegistryIdentity {
        package_id: "webhook-outbox-registry".to_owned(),
        environment: "local".to_owned(),
        instance_id: "webhook-outbox-instance".to_owned(),
        database_id: "webhook-outbox-database".to_owned(),
        package_revision: PACKAGE_REVISION.to_owned(),
        schema_fingerprint: SCHEMA_FINGERPRINT.to_owned(),
        package_sequence: 1,
    }
}

async fn initialize_registry_state(
    migration: &tokio_postgres::Client,
    identity: &ExpectedRegistryIdentity,
) {
    let changed = migration
        .execute(
            "INSERT INTO registry_internal.registry_state
                 (singleton, package_id, environment, instance_id, database_id,
                  active_package_revision, schema_fingerprint, package_sequence,
                  maintenance_status)
             VALUES (true, $1, $2, $3, $4, $5, $6, $7, 'ready')",
            &[
                &identity.package_id,
                &identity.environment,
                &identity.instance_id,
                &identity.database_id,
                &identity.package_revision,
                &identity.schema_fingerprint,
                &identity.package_sequence,
            ],
        )
        .await
        .expect("migration initializes the exact active package binding");
    assert_eq!(changed, 1);
}

fn mutation_claims(registry: &registry_server::CompiledRegistry) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        "case",
        Some("operator-principal".to_owned()),
        "operator",
        Some("case-management".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("compiled authority context is valid")
}

fn create_request<'a>(
    plan: &'a MutationPlan,
    claims: &'a ClaimContext,
    idempotency_key: &'a str,
    label: &'a str,
) -> MutationRequest<'a> {
    MutationRequest {
        plan,
        idempotency_key,
        claims,
        record_id: None,
        expected_etag: None,
        body: MutationBody::Create(Map::from_iter([
            ("jurisdiction".to_owned(), json!("zone-a")),
            ("label".to_owned(), json!(label)),
            ("restricted_note".to_owned(), json!(RESTRICTED_CANARY)),
        ])),
        response_fields: BTreeSet::from([
            "jurisdiction".to_owned(),
            "label".to_owned(),
            "restricted_note".to_owned(),
        ]),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DurableCounts {
    current: i64,
    revisions: i64,
    outbox: i64,
    delivery: i64,
    delivery_state: i64,
    idempotency: i64,
}

async fn durable_counts(database: &TestDatabase, table: &str) -> DurableCounts {
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT (SELECT count(*) FROM registry_data.\"{table}\"),
                        (SELECT count(*) FROM registry_internal.registry_revisions),
                        (SELECT count(*) FROM registry_internal.registry_outbox),
                        (SELECT count(*) FROM registry_internal.registry_webhook_deliveries),
                        (SELECT count(*) FROM registry_internal.registry_webhook_delivery_state),
                        (SELECT count(*) FROM registry_internal.registry_idempotency)"
            ),
            &[],
        )
        .await
        .expect("administrator can inspect minimized durable mutation state");
    DurableCounts {
        current: row.get(0),
        revisions: row.get(1),
        outbox: row.get(2),
        delivery: row.get(3),
        delivery_state: row.get(4),
        idempotency: row.get(5),
    }
}

struct CapturedDelivery {
    event_id: Uuid,
    payload: Vec<u8>,
    compiled_delivery_id: String,
    logical_destination_id: String,
    destination_binding_digest: String,
    package_revision: String,
    schema_fingerprint: String,
    classification_ceiling: String,
    authentication_profile: String,
    delivery_mode: String,
    attempt_timeout_ms: i64,
    initial_backoff_ms: i64,
    maximum_backoff_ms: i64,
    exponential_backoff_multiplier: i16,
    maximum_attempts: i16,
    retry_delays_ms: Vec<i64>,
    maximum_payload_bytes: i64,
    payload_digest: Vec<u8>,
    deployed_attempt_timeout_ms: i64,
    deployed_maximum_attempts: i16,
    dead_letter: String,
    operator_replay: bool,
}

impl From<Row> for CapturedDelivery {
    fn from(row: Row) -> Self {
        Self {
            event_id: row.get(0),
            payload: row.get(1),
            compiled_delivery_id: row.get(2),
            logical_destination_id: row.get(3),
            destination_binding_digest: row.get(4),
            package_revision: row.get(5),
            schema_fingerprint: row.get(6),
            classification_ceiling: row.get(7),
            authentication_profile: row.get(8),
            delivery_mode: row.get(9),
            attempt_timeout_ms: row.get(10),
            initial_backoff_ms: row.get(11),
            maximum_backoff_ms: row.get(12),
            exponential_backoff_multiplier: row.get(13),
            maximum_attempts: row.get(14),
            retry_delays_ms: row.get(15),
            maximum_payload_bytes: row.get(16),
            payload_digest: row.get(17),
            deployed_attempt_timeout_ms: row.get(18),
            deployed_maximum_attempts: row.get(19),
            dead_letter: row.get(20),
            operator_replay: row.get(21),
        }
    }
}

async fn capture(database: &TestDatabase, offset: i64) -> CapturedDelivery {
    database
        .admin
        .query_one(
            "SELECT outbox.event_id, outbox.payload,
                    delivery.compiled_delivery_id, delivery.logical_destination_id,
                    delivery.destination_binding_digest, delivery.package_revision,
                    delivery.schema_fingerprint, delivery.classification_ceiling,
                    delivery.authentication_profile, delivery.delivery_mode,
                    delivery.attempt_timeout_ms, delivery.initial_backoff_ms,
                    delivery.maximum_backoff_ms, delivery.exponential_backoff_multiplier,
                    delivery.maximum_attempts, delivery.retry_delays_ms,
                    delivery.maximum_payload_bytes, delivery.payload_digest,
                    delivery.deployed_attempt_timeout_ms,
                    delivery.deployed_maximum_attempts, delivery.dead_letter,
                    delivery.operator_replay
             FROM registry_internal.registry_outbox AS outbox
             JOIN registry_internal.registry_webhook_deliveries AS delivery
               ON delivery.event_id = outbox.event_id
             ORDER BY outbox.outbox_id
             OFFSET $1 LIMIT 1",
            &[&offset],
        )
        .await
        .expect("one outbox event has exactly one package-bound delivery")
        .into()
}

fn assert_capture_matches(
    actual: &CapturedDelivery,
    compiled: &CompiledEventDelivery,
    binding_digest: &str,
    identity: &ExpectedRegistryIdentity,
) {
    assert_eq!(actual.compiled_delivery_id, compiled.id);
    assert_eq!(actual.logical_destination_id, compiled.destination_id);
    assert_eq!(actual.destination_binding_digest, binding_digest);
    assert_eq!(actual.package_revision, identity.package_revision);
    assert_eq!(actual.schema_fingerprint, identity.schema_fingerprint);
    assert_eq!(actual.classification_ceiling, "restricted");
    assert_eq!(actual.authentication_profile, "hmac_sha256_v1");
    assert_eq!(actual.delivery_mode, "after_commit");
    assert_eq!(
        actual.attempt_timeout_ms,
        i64::from(compiled.attempt_timeout_ms)
    );
    assert_eq!(
        actual.initial_backoff_ms,
        i64::from(compiled.initial_backoff_ms)
    );
    assert_eq!(
        actual.maximum_backoff_ms,
        i64::from(compiled.maximum_backoff_ms)
    );
    assert_eq!(
        actual.exponential_backoff_multiplier,
        i16::from(compiled.exponential_backoff_multiplier)
    );
    assert_eq!(
        actual.maximum_attempts,
        i16::from(compiled.maximum_attempts)
    );
    assert_eq!(
        actual.retry_delays_ms,
        compiled
            .retry_delays_ms
            .iter()
            .copied()
            .map(i64::from)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        actual.maximum_payload_bytes,
        i64::from(compiled.maximum_payload_bytes)
    );
    assert_eq!(
        actual.payload_digest,
        Sha256::digest(&actual.payload).to_vec()
    );
    assert_eq!(actual.deployed_attempt_timeout_ms, 4000);
    assert_eq!(actual.deployed_maximum_attempts, 4);
    assert_eq!(actual.dead_letter, "required");
    assert_eq!(actual.operator_replay, compiled.operator_replay);
}

fn expected_payload() -> Vec<u8> {
    format!(r#"{{"label":"first","restricted_note":"{RESTRICTED_CANARY}"}}"#).into_bytes()
}

async fn assert_delivery_is_transport_and_value_free(
    database: &TestDatabase,
    event_id: Uuid,
    raw_record_id: &str,
) {
    let row_text: String = database
        .admin
        .query_one(
            "SELECT row_to_json(delivery)::text
             FROM registry_internal.registry_webhook_deliveries AS delivery
             WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("administrator can inspect the immutable delivery metadata")
        .get(0);
    for forbidden in [
        RESTRICTED_CANARY,
        ORIGIN_CANARY,
        PATH_CANARY,
        SECRET_REF_CANARY,
        std::str::from_utf8(SECRET_KEY_CANARY).expect("test key canary is UTF-8"),
        raw_record_id,
    ] {
        assert!(!row_text.contains(forbidden));
    }
    let columns = database
        .admin
        .query(
            "SELECT column_name
             FROM information_schema.columns
             WHERE table_schema = 'registry_internal'
               AND table_name = 'registry_webhook_deliveries'
             ORDER BY ordinal_position",
            &[],
        )
        .await
        .expect("administrator can inspect the fixed delivery schema")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    assert_eq!(
        columns,
        [
            "event_id",
            "compiled_delivery_id",
            "logical_destination_id",
            "destination_binding_digest",
            "package_revision",
            "schema_fingerprint",
            "classification_ceiling",
            "authentication_profile",
            "delivery_mode",
            "attempt_timeout_ms",
            "initial_backoff_ms",
            "maximum_backoff_ms",
            "exponential_backoff_multiplier",
            "maximum_attempts",
            "retry_delays_ms",
            "maximum_payload_bytes",
            "payload_digest",
            "deployed_attempt_timeout_ms",
            "deployed_maximum_attempts",
            "dead_letter",
            "operator_replay",
            "created_at",
        ]
    );
}

async fn assert_capture_acl_is_insert_and_select_only(database: &TestDatabase) {
    let privileges = database
        .admin
        .query(
            "SELECT privilege_type
             FROM information_schema.role_table_grants
             WHERE table_schema = 'registry_internal'
               AND table_name = 'registry_webhook_deliveries'
               AND grantee = $1
             ORDER BY privilege_type",
            &[&database.runtime_role.as_str()],
        )
        .await
        .expect("administrator can inspect capture ACL")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    assert_eq!(privileges, ["INSERT", "SELECT"]);

    let state_privileges = database
        .admin
        .query(
            "SELECT privilege_type
             FROM information_schema.role_table_grants
             WHERE table_schema = 'registry_internal'
               AND table_name = 'registry_webhook_delivery_state'
               AND grantee = $1
             ORDER BY privilege_type",
            &[&database.runtime_role.as_str()],
        )
        .await
        .expect("administrator can inspect state ACL")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    assert_eq!(state_privileges, ["INSERT", "SELECT", "UPDATE"]);
}

async fn assert_initial_delivery_state(database: &TestDatabase, capture: &CapturedDelivery) {
    let row = database
        .admin
        .query_one(
            "SELECT generation, state, attempt,
                    next_attempt_at IS NOT NULL,
                    attempt_started_at IS NULL,
                    lease_expires_at IS NULL,
                    lease_token IS NULL,
                    delivered_at IS NULL,
                    dead_lettered_at IS NULL
             FROM registry_internal.registry_webhook_delivery_state
             WHERE event_id = $1 AND compiled_delivery_id = $2",
            &[&capture.event_id, &capture.compiled_delivery_id],
        )
        .await
        .expect("capture atomically seeds one exact pending delivery state");
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, String>(1), "pending");
    assert_eq!(row.get::<_, i16>(2), 0);
    for index in 3..9 {
        assert!(row.get::<_, bool>(index));
    }
}

struct DestinationFixture {
    root: PathBuf,
    secret_root: PathBuf,
    package_root: PathBuf,
    trust_anchor: PathBuf,
}

impl DestinationFixture {
    fn new() -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("temporary parent canonicalizes")
            .join(format!(
                "registry-server-webhook-outbox-{suffix}-{}",
                std::process::id()
            ));
        fs::create_dir(&root).expect("fixture root creates");
        let secret_root = root.join("secrets");
        let package_root = root.join("package");
        fs::create_dir(&secret_root).expect("secret root creates");
        fs::create_dir(&package_root).expect("package root creates");
        let trust_anchor = root.join("trust-anchor.json");
        fs::write(&trust_anchor, "{}").expect("trust anchor placeholder writes");
        let key_path = secret_root.join(SECRET_REF_CANARY);
        fs::write(&key_path, SECRET_KEY_CANARY).expect("destination key writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))
                .expect("destination key permissions set");
        }
        Self {
            root,
            secret_root,
            package_root,
            trust_anchor,
        }
    }

    fn activate(
        &self,
        compiled: &registry_server::CompiledRegistry,
    ) -> ActivatedEventDestinationRegistry {
        let raw = format!(
            r#"
listener:
  bind: 127.0.0.1:8080
  trustedProxy: direct
identity:
  environment: local
  instanceId: webhook-outbox-instance
  databaseId: webhook-outbox-database
  databaseInitializationEnvironment: local
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 4
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: registry_migration
    runtime: registry_runtime
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: source-revision-1
  activeRevision: {}
  activeSequence: 1
authentication:
  oidc:
    issuer: https://issuer.example
    audience: urn:registry-server:webhook-outbox
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-client]
    deniedKids: [denied-kid]
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 900
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
    rowBoundaryClaims:
      - {{name: jurisdiction, type: directString}}
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
eventDestinations:
  {DESTINATION_ID}:
    origin: https://{ORIGIN_CANARY}/
    path: {PATH_CANARY}
    networkProfile: productionHttps
    dnsFamily: dualStackStrict
    allowedPrivateCidrs: []
    hmacSha256KeyRef: secret:file/{SECRET_REF_CANARY}
    deliveryCeilings:
      attemptTimeoutMilliseconds: 4000
      maximumAttempts: 4
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
"#,
            self.secret_root.display(),
            self.package_root.display(),
            self.trust_anchor.display(),
            PACKAGE_REVISION,
        );
        parse_runtime_config(&raw)
            .expect("strict destination configuration parses")
            .activate_event_destinations(compiled)
            .expect("exact destination inventory activates")
    }
}

impl Drop for DestinationFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
