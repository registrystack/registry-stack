// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::migration::{
    apply_verified_package, ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest,
};
use registry_breg::package::{
    load_package, prepare_package, PackageBuildRequest, PackageLoadContext,
    PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile, VerifiedPackage,
};
use registry_breg::postgres::{
    initialize_registry_state_for_catalog_test, install_compiled_schema,
    managed_schema_fingerprint, verify_runtime_role, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, RegistryStateTestIdentity, RoleMode,
};
use registry_breg::startup::{
    check_with_connection_config_for_test, prepare_with_connection_and_key_source_for_test,
    prepare_with_connection_config_for_test, serve_until_shutdown, PreparedServer, StartupError,
};
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    fetch_discovery_with_policy, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig,
};
use registry_platform_testing::{
    fixtures as testing_fixtures, jwks_from_private_jwk, sign_ed25519_compact_jwt, MockIdp,
};
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::oneshot;
use tokio_postgres::GenericClient;
use tower::ServiceExt as _;

const INSTANCE: &str = "startup-instance";
const DATABASE: &str = "startup-database";
const SOURCE_REVISION: &str = "startup-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/breg-journeys/v1
journeys:
  - id: neutral-record-list
    steps:
      - id: list-neutral-records
        entity: neutral-record
        accessProfile: reader
        claims: {principal: package-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
// Each prepared server owns the process-global configured WASM runtime.
static WASM_RUNTIME_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runtime_startup_names_a_missing_authority_and_its_retained_submission_count() {
    let _runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;

    let fixture = StartupFixture::new();
    let provisional = PackageFixture::build(&fixture.root, fingerprint(1));
    let provisional_context = provisional.context();
    let verified_provisional = load_package(&provisional.root, &provisional_context)
        .expect("provisional package loads enough to install schema");
    install_compiled_schema(
        &migration,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("compiled schema installs");
    let expected_catalog = ExpectedManagedCatalog::compiled(verified_provisional.registry());
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("compiled schema fingerprints");
    drop(provisional);

    let package = PackageFixture::build(&fixture.root, schema_fingerprint);
    let context = package.context();
    let verified = load_package(&package.root, &context).expect("final package verifies");
    initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified.registry()),
        RegistryStateTestIdentity {
            package_id: &verified.manifest().package_id,
            database_id: DATABASE,
            label: verified.package_digest(),
        },
    )
    .await
    .expect("Registry state initializes");

    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";
             GRANT SELECT ON registry_internal.registry_request_state TO \"{}\";",
            database.runtime_role.as_str(),
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");
    for request_id in [uuid::Uuid::new_v4(), uuid::Uuid::new_v4()] {
        database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_request_state
                 (request_entity_id,request_id,owner_reference,state,proposal_version,
                  workflow_revision)
                 VALUES ('requests',$1,'owner-retained','submitted',1,1)",
                &[&request_id],
            )
            .await
            .expect("retained request state inserts");
        database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_request_proposals
                 (request_entity_id,request_id,proposal_version,request_record_revision,
                  contract_fingerprint,effect_digest,snapshot)
                 VALUES ('requests',$1,1,1,$2,$2,'{}'::jsonb)",
                &[&request_id, &format!("sha256:{}", "a".repeat(64))],
            )
            .await
            .expect("retained proposal inserts");
        database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_request_review_submissions
                 (request_entity_id,request_id,proposal_version,proposal_digest,job_id,authority,
                  producer_id,policy_id,idempotency_key,create_request,
                  expected_submission_digest,on_approved_mode,executor,state,accepted_binding)
                 VALUES ('requests',$1,1,$2,$3,'casework-retained','producer-retained',
                         'policy-retained',$4,'{}'::jsonb,$2,'manual',NULL,'accepted','{}'::jsonb)",
                &[
                    &request_id,
                    &format!("sha256:{}", "a".repeat(64)),
                    &uuid::Uuid::new_v4(),
                    &format!("submit-{request_id}"),
                ],
            )
            .await
            .expect("accepted review submission inserts");
    }
    drop(migration);
    migration_task.abort();

    let idp = MockIdp::start().await;
    let config_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    assert_eq!(
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .err(),
        Some(StartupError::ReviewAuthorityMissing {
            authority: "casework-retained".to_owned(),
            retained_submissions: 2,
        })
    );

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_refuses_an_instance_id_change_while_deliveries_are_pending() {
    let _runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;

    let fixture = StartupFixture::new();
    let provisional = PackageFixture::build(&fixture.root, fingerprint(1));
    let provisional_context = provisional.context();
    let verified_provisional = load_package(&provisional.root, &provisional_context)
        .expect("provisional package loads enough to install schema");
    install_compiled_schema(
        &migration,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("compiled schema installs");
    let expected_catalog = ExpectedManagedCatalog::compiled(verified_provisional.registry());
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("compiled schema fingerprints");
    drop(provisional);

    let package = PackageFixture::build(&fixture.root, schema_fingerprint);
    let context = package.context();
    let verified = load_package(&package.root, &context).expect("final package verifies");
    let package_id = verified.manifest().package_id.clone();
    initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified.registry()),
        RegistryStateTestIdentity {
            package_id: &package_id,
            database_id: DATABASE,
            label: verified.package_digest(),
        },
    )
    .await
    .expect("Registry state initializes");
    drop(migration);
    migration_task.abort();

    let previous_source =
        format!("urn:registrystack:registry:{package_id}:instance:previous-instance");
    let idp = MockIdp::start().await;
    let config_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );

    // Finished work captured under the previous instance never reaches the
    // worker again, so it does not hold the rename back.
    insert_captured_delivery(
        &database,
        &previous_source,
        CapturedDeliveryState::Delivered,
    )
    .await;
    insert_captured_delivery(
        &database,
        &previous_source,
        CapturedDeliveryState::DeadLettered,
    )
    .await;
    let prepared =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .expect("finished deliveries under another instance do not block startup");
    drop(prepared);

    insert_captured_delivery(&database, &previous_source, CapturedDeliveryState::Pending).await;
    assert_eq!(
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .err(),
        Some(StartupError::InstanceIdChangedWithPendingDeliveries {
            stored_source: previous_source.clone(),
            configured_instance_id: INSTANCE.to_owned(),
            pending_deliveries: 1,
        })
    );
    insert_captured_delivery(&database, &previous_source, CapturedDeliveryState::Leased).await;
    let refusal =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .err()
            .expect("a leased delivery under another instance refuses startup");
    assert_eq!(
        refusal,
        StartupError::InstanceIdChangedWithPendingDeliveries {
            stored_source: previous_source.clone(),
            configured_instance_id: INSTANCE.to_owned(),
            pending_deliveries: 2,
        }
    );
    let rendered = refusal.to_string();
    for detail in [
        previous_source.as_str(),
        INSTANCE,
        "identity.instanceId",
        "drain",
    ] {
        assert!(
            rendered.contains(detail),
            "refusal omits {detail}: {rendered}"
        );
    }

    // Restoring the previous instance id passes the source check; this
    // package activates no destination, so the retained binding check that
    // follows is what refuses the same pending work.
    let restored_path = fixture.root.join("runtime-restored-instance.yaml");
    fs::write(
        &restored_path,
        fs::read_to_string(&config_path)
            .expect("runtime config reads")
            .replace(
                &format!("instanceId: {INSTANCE}\n"),
                "instanceId: previous-instance\n",
            ),
    )
    .expect("restored runtime config writes");
    assert_eq!(
        prepare_with_connection_config_for_test(&restored_path, database.runtime_config.clone())
            .await
            .err(),
        Some(StartupError::RetainedWebhookBindings {
            retained_deliveries: 2
        })
    );

    database.cleanup().await;
}

#[derive(Clone, Copy)]
enum CapturedDeliveryState {
    Pending,
    Leased,
    Delivered,
    DeadLettered,
}

/// Write one captured webhook delivery whose stored envelope names `source`,
/// in the given state, as a previous deployment's capture would have left it.
async fn insert_captured_delivery(
    database: &TestDatabase,
    source: &str,
    state: CapturedDeliveryState,
) {
    let event_id = uuid::Uuid::new_v4();
    let compiled_delivery_id = "events.neutral-record.neutral-created-v1.webhook";
    let package_revision = "captured-package-revision";
    let schema_fingerprint = "captured-schema-fingerprint";
    let payload = serde_json::to_vec(&json!({
        "specversion": "1.0",
        "id": event_id.to_string(),
        "source": source,
        "type": "neutral-created-v1",
    }))
    .expect("captured envelope serializes");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_outbox
                 (event_id, event_type, trigger, entity_id, record_reference,
                  record_revision, package_revision, schema_fingerprint, payload,
                  payload_expires_at)
             VALUES ($1, 'neutral-created-v1', 'created', 'neutral-record',
                     'record-reference', 1, $2, $3, $4,
                     transaction_timestamp() + interval '7 days')",
            &[&event_id, &package_revision, &schema_fingerprint, &payload],
        )
        .await
        .expect("captured outbox row inserts");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_webhook_deliveries
                 (event_id, compiled_delivery_id, handler_kind, logical_destination_id,
                  destination_binding_digest, package_revision, schema_fingerprint,
                  data_schema, classification_ceiling, authentication_profile, delivery_mode,
                  attempt_timeout_ms, initial_backoff_ms, maximum_backoff_ms,
                  exponential_backoff_multiplier, maximum_attempts, retry_delays_ms,
                  maximum_payload_bytes, payload_digest, deployed_attempt_timeout_ms,
                  deployed_maximum_attempts, dead_letter, operator_replay)
             VALUES ($1, $2, 'url', 'neutral-events', $3, $4, $5,
                     'https://schemas.example/neutral-created-v1', 'internal',
                     'hmac_sha256_v1', 'after_commit', 5000, 1000, 8000, 2, 2, $6, 1024,
                     $7, 4000, 2, 'required', false)",
            &[
                &event_id,
                &compiled_delivery_id,
                &format!("sha256:{}", "b".repeat(64)),
                &package_revision,
                &schema_fingerprint,
                &vec![1_000_i64],
                &vec![0_u8; 32],
            ],
        )
        .await
        .expect("captured delivery inserts");
    let state_columns = match state {
        CapturedDeliveryState::Pending => {
            "'pending', 0, transaction_timestamp(), NULL, NULL, NULL, NULL, NULL"
        }
        CapturedDeliveryState::Leased => {
            "'leased', 1, NULL, transaction_timestamp(),
             transaction_timestamp() + interval '1 minute', gen_random_uuid(), NULL, NULL"
        }
        CapturedDeliveryState::Delivered => {
            "'delivered', 1, NULL, NULL, NULL, NULL, transaction_timestamp(), NULL"
        }
        CapturedDeliveryState::DeadLettered => {
            "'dead_lettered', 1, NULL, NULL, NULL, NULL, NULL, transaction_timestamp()"
        }
    };
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_internal.registry_webhook_delivery_state
                     (event_id, compiled_delivery_id, generation, state, attempt,
                      next_attempt_at, attempt_started_at, lease_expires_at, lease_token,
                      delivered_at, dead_lettered_at)
                 VALUES ($1, $2, 1, {state_columns})"
            ),
            &[&event_id, &compiled_delivery_id],
        )
        .await
        .expect("captured delivery state inserts");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runtime_startup_preserves_retained_attachment_and_tombstone_backend_binding() {
    let _runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    verify_runtime_role(&migration, &database.migration_role)
        .await
        .expect_err("migration connection is not accepted as runtime");

    let fixture = StartupFixture::new();
    let provisional = PackageFixture::build(&fixture.root, fingerprint(1));
    let provisional_context = provisional.context();
    let verified_provisional = load_package(&provisional.root, &provisional_context)
        .expect("provisional package loads enough to install schema");
    install_compiled_schema(
        &migration,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("compiled schema installs");
    let expected_catalog = ExpectedManagedCatalog::compiled(verified_provisional.registry());
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("compiled schema fingerprints");
    drop(provisional);

    let package = PackageFixture::build(&fixture.root, schema_fingerprint);
    let context = package.context();
    let verified = load_package(&package.root, &context).expect("final package verifies");
    initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified.registry()),
        RegistryStateTestIdentity {
            package_id: &verified.manifest().package_id,
            database_id: DATABASE,
            label: verified.package_digest(),
        },
    )
    .await
    .expect("Registry state initializes");

    let idp = MockIdp::start().await;
    let database_config = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    let empty =
        prepare_with_connection_config_for_test(&database_config, database.runtime_config.clone())
            .await
            .expect("default database startup succeeds with no attachment rows");
    assert_ready(&empty, StatusCode::OK).await;
    drop(empty);

    // The mocked control endpoint proves actual S3 configuration activation;
    // retained-binding verification and startup run against real PostgreSQL.
    // Full object interoperability is covered by the real S3 integration tests.
    let control = axum::Router::new().fallback(axum::routing::get(|| async {
        (StatusCode::OK, "<VersioningConfiguration/>")
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let control_task = tokio::spawn(async move {
        axum::serve(listener, control).await.unwrap();
    });
    for (name, value) in [
        ("attachment-access", "startup-fixture-access"),
        ("attachment-secret", "startup-fixture-secret"),
    ] {
        let path = fixture.secret_root.join(name);
        fs::write(&path, value).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let s3_config = fixture.root.join("runtime-attachment-s3.yaml");
    let base_config = fs::read_to_string(&database_config).unwrap();
    fs::write(&s3_config,format!("{base_config}\nattachmentStorage:\n  kind: s3\n  endpoint: {endpoint}\n  bucket: startup-attachments\n  region: us-east-1\n  accessKeyIdRef: secret:file/attachment-access\n  secretAccessKeyRef: secret:file/attachment-secret\n")).unwrap();
    let activated = registry_breg::runtime_config::load_runtime_config(&s3_config)
        .unwrap()
        .activate_attachment_storage(verified.registry().registry_id())
        .await
        .unwrap();
    let original_backend = activated.binding_digest();
    let hash = "b".repeat(64);
    let tx = migration.transaction().await.unwrap();
    registry_breg::attachment_store::test_support::stage(&tx, &hash, 3, &original_backend)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    for state in ["live", "delete_confirmed"] {
        migration
            .execute(
                "UPDATE registry_internal.registry_attachment_blobs
             SET state=$2,deletion_checked_at=CASE WHEN $2='delete_confirmed'
                 THEN transaction_timestamp() ELSE NULL END WHERE sha256=$1",
                &[&hash, &state],
            )
            .await
            .unwrap();
        assert_eq!(
            prepare_with_connection_config_for_test(
                &database_config,
                database.runtime_config.clone()
            )
            .await
            .err(),
            Some(StartupError::AttachmentStorage),
            "actual runtime startup refuses backend changes while {state} storage remains",
        );
        let restored =
            prepare_with_connection_config_for_test(&s3_config, database.runtime_config.clone())
                .await
                .expect("restoring the original operator binding admits runtime startup");
        assert_ready(&restored, StatusCode::OK).await;
        drop(restored);
    }
    let changed_verifier_config = fixture
        .root
        .join("runtime-attachment-changed-verifier.yaml");
    let original_s3 = fs::read_to_string(&s3_config).unwrap();
    fs::write(&changed_verifier_config,format!("{original_s3}\nattachmentVerification:\n  kind: http\n  endpoint: {endpoint}/verify\n  policyId: changed-verifier-policy\n  authorizationRef: secret:file/attachment-secret\n")).unwrap();
    assert_eq!(
        prepare_with_connection_config_for_test(
            &changed_verifier_config,
            database.runtime_config.clone()
        )
        .await
        .err(),
        Some(StartupError::AttachmentStorage),
        "actual startup also refuses verifier policy changes against the same backend pin"
    );
    // Isolate the permanent first-write pin from all blob rows. A backend
    // switch remains forbidden even when there is no content left to inspect.
    migration
        .execute(
            "DELETE FROM registry_internal.registry_attachment_blobs",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        prepare_with_connection_config_for_test(&database_config, database.runtime_config.clone())
            .await
            .err(),
        Some(StartupError::AttachmentStorage)
    );
    let pinned =
        prepare_with_connection_config_for_test(&s3_config, database.runtime_config.clone())
            .await
            .expect("original binding remains valid with only the permanent pin");
    drop(pinned);
    migration_task.abort();
    control_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_startup_refuses_local_file_field_encryption_custody() {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    let fixture = StartupFixture::new();
    let module_source = module_bytes_with_encrypted_field();
    let provisional = PackageFixture::build_version_with_module(
        &fixture.root,
        fingerprint(1),
        None,
        false,
        module_source.clone(),
    );
    let provisional_context = provisional.context();
    let verified_provisional = load_package(&provisional.root, &provisional_context)
        .expect("provisional encrypted package loads enough to install schema");
    install_compiled_schema(
        &migration,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("compiled encrypted schema installs");
    let expected_catalog = ExpectedManagedCatalog::compiled(verified_provisional.registry());
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("compiled encrypted schema fingerprints");
    drop(provisional);

    let package = PackageFixture::build_version_with_module(
        &fixture.root,
        schema_fingerprint,
        None,
        false,
        module_source,
    );
    let context = package.context();
    let verified = load_package(&package.root, &context).expect("final encrypted package verifies");
    initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified.registry()),
        RegistryStateTestIdentity {
            package_id: &verified.manifest().package_id,
            database_id: DATABASE,
            label: verified.package_digest(),
        },
    )
    .await
    .expect("Registry state initializes");

    let idp = MockIdp::start().await;
    let base = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    // The local data key exists and is readable, so the refusal below names
    // custody policy, not an unreadable secret.
    let dek = fixture.secret_root.join("field-dek");
    fs::write(
        &dek,
        format!(
            "{}\n",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0x42_u8; 32])
        ),
    )
    .expect("local data key writes");
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&dek, fs::Permissions::from_mode(0o600))
            .expect("local data key is owner-only");
    }
    let local_file_config = fixture
        .root
        .join("runtime-field-encryption-local-file.yaml");
    let raw = fs::read_to_string(&base).expect("base runtime config reads");
    fs::write(
        &local_file_config,
        format!("{raw}\nfieldEncryption:\n  provider:\n    kind: localFile\n    dekRef: secret:file/field-dek\n"),
    )
    .expect("local-file runtime config writes");
    assert_eq!(
        prepare_with_connection_config_for_test(
            &local_file_config,
            database.runtime_config.clone()
        )
        .await
        .err(),
        Some(StartupError::FieldEncryptionCustody),
        "a databaseInitializationEnvironment other than local refuses plaintext data-key files"
    );
    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_server_wires_services_and_static_jwks_readiness_tracks_database() {
    let _runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    verify_runtime_role(&migration, &database.migration_role)
        .await
        .expect_err("migration connection is not accepted as runtime");

    let fixture = StartupFixture::new();
    let provisional = PackageFixture::build(&fixture.root, fingerprint(1));
    let provisional_context = provisional.context();
    let verified_provisional = load_package(&provisional.root, &provisional_context)
        .expect("provisional package loads enough to install schema");
    install_compiled_schema(
        &migration,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("compiled schema installs");
    let expected_catalog = ExpectedManagedCatalog::compiled(verified_provisional.registry());
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("compiled schema fingerprints");
    drop(provisional);

    let package = PackageFixture::build(&fixture.root, schema_fingerprint);
    let context = package.context();
    let verified = load_package(&package.root, &context).expect("final package verifies");
    initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified.registry()),
        RegistryStateTestIdentity {
            package_id: &verified.manifest().package_id,
            database_id: DATABASE,
            label: verified.package_digest(),
        },
    )
    .await
    .expect("Registry state initializes");
    migration_task.abort();

    let idp = MockIdp::start().await;
    let config_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    let raw = fs::read_to_string(&config_path).expect("runtime config reads");
    fs::write(
        &config_path,
        format!("{raw}metricsListener:\n  bind: {}\n", reserve_address()),
    )
    .expect("metrics listener runtime config writes");
    let prepared =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .expect("prepared server verifies package, database, audit, and OIDC");
    assert_ready(&prepared, StatusCode::OK).await;
    assert_unknown_static_kid_refuses_value_free(&prepared).await;
    assert_metrics_publish_the_verified_package_and_every_queue(&prepared, &verified).await;

    let wrong_role_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.intruder_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    assert_eq!(
        prepare_with_connection_config_for_test(&wrong_role_path, database.runtime_config.clone())
            .await
            .err(),
        Some(StartupError::DatabaseUnready)
    );

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET active_package_digest = $1
             WHERE singleton",
            &[&"sha256:0000000000000000000000000000000000000000000000000000000000000000"],
        )
        .await
        .expect("test invalidates active package");
    assert_ready(&prepared, StatusCode::SERVICE_UNAVAILABLE).await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET active_package_digest = $1
             WHERE singleton",
            &[&verified.package_digest()],
        )
        .await
        .expect("test restores active package");
    assert_ready(&prepared, StatusCode::OK).await;
    let unopened_config_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    idp.stop().await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_ready(&prepared, StatusCode::OK).await;
    drop(prepared);
    assert_audit_destination_has_one_writer_and_checks_take_none(
        &database,
        &config_path,
        &unopened_config_path,
    )
    .await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_server_sessions_are_named_bounded_and_pg_stat_statements_stays_unavailable_until_preloaded(
) {
    let _runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let fixture = StartupFixture::new();
    let provisional = PackageFixture::build(&fixture.root, fingerprint(1));
    let provisional_context = provisional.context();
    let verified_provisional = load_package(&provisional.root, &provisional_context)
        .expect("provisional package loads enough to install schema");
    install_compiled_schema(
        &migration,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("compiled schema installs");
    let expected_catalog = ExpectedManagedCatalog::compiled(verified_provisional.registry());
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("compiled schema fingerprints");
    drop(provisional);
    let package = PackageFixture::build(&fixture.root, schema_fingerprint);
    let context = package.context();
    let verified = load_package(&package.root, &context).expect("final package verifies");
    initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified.registry()),
        RegistryStateTestIdentity {
            package_id: &verified.manifest().package_id,
            database_id: DATABASE,
            label: verified.package_digest(),
        },
    )
    .await
    .expect("Registry state initializes");
    migration_task.abort();
    let idp = MockIdp::start().await;
    let config_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );

    let prepared =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .expect("prepared server verifies package, database, audit, and OIDC");
    let pool = prepared
        .runtime_pool_for_test()
        .expect("the verified startup path exposes its runtime pool");
    let client = pool.get_for_test().await.expect("runtime session opens");
    let row = client
        .query_one(
            "SELECT current_setting('application_name'),
                    setting,
                    source,
                    current_setting('jit')
             FROM pg_catalog.pg_settings
             WHERE name = 'idle_in_transaction_session_timeout'",
            &[],
        )
        .await
        .expect("runtime session reads its own settings");
    assert_eq!(row.get::<_, String>(0), "breg");
    assert_eq!(row.get::<_, String>(1), "120000");
    assert_eq!(row.get::<_, String>(2), "client");
    assert_eq!(
        row.get::<_, String>(3),
        "off",
        "runtime sessions never JIT-compile a row-level-security plan"
    );
    drop(client);
    let codes = prepared
        .postgres_advisories()
        .iter()
        .map(|advisory| advisory.code())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"postgres.pg_stat_statements.unavailable"));
    let pg_stat_statements = prepared
        .postgres_advisories()
        .iter()
        .find(|advisory| advisory.code() == "postgres.pg_stat_statements.unavailable")
        .expect("pg_stat_statements is not installed yet");
    assert!(pg_stat_statements.message().contains("not installed"));
    let connections = prepared
        .postgres_advisories()
        .iter()
        .find(|advisory| advisory.code().starts_with("postgres.connections."))
        .expect("the connection numbers are always reported");
    assert_eq!(connections.observed()[0], ("poolMaxSize", 4));
    assert_eq!(connections.observed()[1].0, "maxConnections");
    assert!(connections.observed()[1].1 > 0);
    drop(prepared);

    // This test server never sets shared_preload_libraries, so creating the
    // extension alone must not silence the advisory: PostgreSQL 17 lets
    // CREATE EXTENSION succeed either way, but its view then refuses every
    // query until a restart actually preloads the module.
    database
        .admin
        .batch_execute("CREATE EXTENSION pg_stat_statements")
        .await
        .expect("the test database installs pg_stat_statements");
    let prepared =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .expect("catalog verification and startup accept pg_stat_statements without preload");
    assert_ready(&prepared, StatusCode::OK).await;
    let pg_stat_statements = prepared
        .postgres_advisories()
        .iter()
        .find(|advisory| advisory.code() == "postgres.pg_stat_statements.unavailable")
        .expect("pg_stat_statements is installed but this server never preloaded it");
    assert!(pg_stat_statements
        .message()
        .contains("shared_preload_libraries"));
    drop(prepared);

    // A configured pg_stat_statements.max without the preload is only a
    // placeholder: current_setting() returns it, but the module never ran.
    database
        .admin
        .batch_execute(&format!(
            "ALTER ROLE {} SET pg_stat_statements.max = '5000'",
            database.runtime_role.as_str()
        ))
        .await
        .expect("the test role carries a placeholder pg_stat_statements setting");
    let prepared =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .expect("startup accepts a placeholder pg_stat_statements setting");
    let pg_stat_statements = prepared
        .postgres_advisories()
        .iter()
        .find(|advisory| advisory.code() == "postgres.pg_stat_statements.unavailable")
        .expect("a placeholder setting does not mean the module is loaded");
    assert!(pg_stat_statements
        .message()
        .contains("shared_preload_libraries"));
    drop(prepared);
    idp.stop().await;
    database.cleanup().await;
}

/// A logical restore carries the original instance claim into a database with
/// another physical identity. The copy refuses to serve by name, and readiness
/// fails on a running server, until an operator adopts it.
#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restored_copy_refuses_to_serve_until_adopted() {
    restored_copy_journey(false).await;
}

/// A managed PostgreSQL service may withhold `pg_control_system()` from
/// ordinary roles. The claim then compares the database oid alone, so the
/// Registry still installs, serves, refuses a copy, and adopts one.
#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_database_that_withholds_its_system_identifier_still_serves_and_refuses_a_copy() {
    restored_copy_journey(true).await;
}

#[cfg(feature = "tooling")]
async fn restored_copy_journey(withhold_system_identifier: bool) {
    use registry_breg::instance_claim::InstanceClaimService;
    use registry_breg::postgres::RegistryLockKey;
    use registry_platform_audit::AuditProfile;

    const AUDIT_KEY: &str = "0123456789abcdef0123456789abcdef";
    let _runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
    let database = TestDatabase::create(4).await;
    if withhold_system_identifier {
        // The function catalog belongs to this disposable database, so the
        // revocation reaches no other database in the cluster.
        database
            .admin
            .batch_execute("REVOKE EXECUTE ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC")
            .await
            .expect("test withholds the system identifier");
        for role in [&database.migration_role, &database.runtime_role] {
            let readable: bool = database
                .admin
                .query_one(
                    "SELECT pg_catalog.has_function_privilege(
                         $1, 'pg_catalog.pg_control_system()', 'EXECUTE')",
                    &[&role.as_str()],
                )
                .await
                .expect("function privilege reads")
                .get(0);
            assert!(
                !readable,
                "the fixture roles cannot read the system identifier"
            );
        }
    }
    let (migration, migration_task) = database.connect_migration().await;
    let fixture = StartupFixture::new();
    let provisional = PackageFixture::build(&fixture.root, fingerprint(1));
    let provisional_context = provisional.context();
    let verified_provisional = load_package(&provisional.root, &provisional_context)
        .expect("provisional package loads enough to install schema");
    install_compiled_schema(
        &migration,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("compiled schema installs");
    let expected_catalog = ExpectedManagedCatalog::compiled(verified_provisional.registry());
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("compiled schema fingerprints");
    drop(provisional);

    let package = PackageFixture::build(&fixture.root, schema_fingerprint.clone());
    let context = package.context();
    let verified = load_package(&package.root, &context).expect("final package verifies");
    let manifest = verified.manifest();
    let initialized = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified.registry()),
        RegistryStateTestIdentity {
            package_id: &manifest.package_id,
            database_id: DATABASE,
            label: verified.package_digest(),
        },
    )
    .await
    .expect("Registry state initializes");
    migration_task.abort();

    let idp = MockIdp::start().await;
    let config_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some(AUDIT_KEY),
    );
    let prepared =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .expect("the database that recorded the claim serves");
    assert_ready(&prepared, StatusCode::OK).await;

    let claims = InstanceClaimService::new_for_test(
        initialized,
        ExpectedManagedCatalog::compiled(verified.registry()),
        RegistryLockKey::derive(&manifest.package_id).expect("lock key derives"),
        database.migration_config.clone(),
        database.runtime_config.clone(),
        database.migration_role.clone(),
        database.runtime_role.clone(),
        database.audit(
            AuditProfile::production_from_secret_bytes(AUDIT_KEY.as_bytes().to_vec().into())
                .expect("test audit profile is keyed"),
        ),
    );
    let original = claims.status().await.expect("the claim reads");
    assert!(
        original.matches,
        "the installing database holds its own claim"
    );
    assert_eq!(
        original.live.system_identifier.is_none(),
        withhold_system_identifier,
        "the status names a system identifier exactly when it is readable"
    );
    assert_eq!(
        original
            .claim
            .as_ref()
            .map(|claim| claim.identity.system_identifier.is_none()),
        Some(withhold_system_identifier),
        "the claim records a system identifier exactly when it was readable"
    );
    assert_eq!(original.claim.map(|claim| claim.epoch), Some(1));

    // A logical restore keeps every row, so the copy holds the claim the
    // original recorded while the database it lands in has another oid.
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
                SET database_oid = 1
              WHERE singleton",
            &[],
        )
        .await
        .expect("test simulates a restored copy");
    assert_ready(&prepared, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .err(),
        Some(StartupError::InstanceClaimMismatch),
        "a copy the claim does not name refuses to serve by name"
    );
    let copied = claims.status().await.expect("the operator reads the claim");
    assert!(!copied.matches);
    assert_eq!(copied.claim.map(|claim| claim.epoch), Some(1));

    let adoption = claims.adopt().await.expect("the operator adopts the copy");
    assert_eq!(adoption.previous.map(|claim| claim.epoch), Some(1));
    assert_eq!(adoption.current.epoch, 2);
    let adopted = claims.status().await.expect("the adopted claim reads");
    assert!(adopted.matches);
    assert_eq!(adopted.claim.map(|claim| claim.epoch), Some(2));
    assert_ready(&prepared, StatusCode::OK).await;
    // One runtime holds the script engine at a time, so the running server
    // stops before the adopted copy starts afresh.
    drop(prepared);
    prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
        .await
        .expect("the adopted copy serves");

    let adoptions: Vec<serde_json::Value> = database
        .audit_entries()
        .into_iter()
        .filter(|entry| {
            entry["schema"] == "breg-instance-claim-audit/v1" && entry["phase"] == "response"
        })
        .map(|entry| entry["record"].clone())
        .filter(|record| record["outcome"] == "committed")
        .collect();
    assert_eq!(adoptions.len(), 1, "one adoption leaves one audit record");
    assert_eq!(adoptions[0]["event"], "adopted");
    assert_eq!(adoptions[0]["previous"]["epoch"], 1);
    assert_eq!(adoptions[0]["previous"]["databaseOid"], 1);
    assert_eq!(adoptions[0]["current"]["epoch"], 2);
    if withhold_system_identifier {
        // A claim recorded without the system identifier still names the
        // database once the identifier becomes readable.
        database
            .admin
            .batch_execute("GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO PUBLIC")
            .await
            .expect("test restores the default function privilege");
        let readable = claims.status().await.expect("the claim reads");
        assert!(readable.live.system_identifier.is_some());
        assert!(
            readable.matches,
            "an unrecorded identifier compares the oid"
        );
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .expect("the claim without an identifier keeps serving");
    }
    idp.stop().await;
    database.cleanup().await;
}

/// `bregctl instance-claim` reads the package the runtime file pins, so a
/// package root swapped under an `expectedDigest` pin is refused by the pin,
/// by name, before any database is reached.
#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn instance_claim_refuses_a_package_root_its_expected_digest_does_not_pin() {
    use registry_breg::instance_claim::{InstanceClaimError, InstanceClaimService};

    let database = TestDatabase::create(2).await;
    let fixture = StartupFixture::new();
    let deployed = PackageFixture::build(&fixture.root, fingerprint(1));
    let pinned = PackageFixture::build(&fixture.root, fingerprint(2));
    let pinned_digest = load_package(&pinned.root, &pinned.context())
        .expect("pinned package verifies")
        .package_digest()
        .to_owned();
    let idp = MockIdp::start().await;
    let config_path = fixture.write_static_jwks_config(
        &deployed,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    let raw = fs::read_to_string(&config_path).expect("runtime config reads");
    let root_line = format!("  root: {}\n", deployed.root.display());
    assert!(
        raw.contains(&root_line),
        "the fixture names its package root"
    );
    fs::write(
        &config_path,
        raw.replace(
            &root_line,
            &format!("{root_line}  expectedDigest: {pinned_digest}\n"),
        ),
    )
    .expect("pinned runtime config writes");
    let before = managed_database_snapshot(&database.admin).await;

    let refusal = InstanceClaimService::from_runtime_config(&config_path)
        .await
        .err()
        .expect("a swapped package root is refused");

    let InstanceClaimError::PackageRefused(message) = refusal else {
        panic!("the pin refuses the package by name, not as an unavailable claim: {refusal:?}");
    };
    assert!(
        message.contains(&format!("package.expectedDigest is {pinned_digest}")),
        "{message}"
    );
    assert!(message.contains("deploy the pinned package or update package.expectedDigest"));
    assert_eq!(managed_database_snapshot(&database.admin).await, before);
    idp.stop().await;
    database.cleanup().await;
}

/// A database no package was ever applied to refuses to serve through the
/// real startup path, names the command that activates the first package,
/// binds no listener, and writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_refuses_an_unapplied_database_naming_the_initial_apply_and_writes_nothing() {
    let _runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
    let database = TestDatabase::create(2).await;
    let fixture = StartupFixture::new();
    let package = PackageFixture::build(&fixture.root, fingerprint(1));
    let idp = MockIdp::start().await;
    let config_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    let before = managed_database_snapshot(&database.admin).await;

    let refusal =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .err();

    assert_eq!(refusal, Some(StartupError::DatabaseUninitialized));
    assert!(StartupError::DatabaseUninitialized
        .to_string()
        .contains("run `bregctl apply --package DIR --initial`"));
    assert_eq!(
        managed_database_snapshot(&database.admin).await,
        before,
        "a refused startup writes nothing"
    );
    idp.stop().await;
    database.cleanup().await;
}

/// A database holding registry state this release does not recognise, here
/// the kernel state table a release before the activation ledger created,
/// refuses to serve through the real startup path with the generic refusal,
/// binds no listener, and writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_refuses_an_unrecognised_registry_state_and_writes_nothing() {
    let _runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    let fixture = StartupFixture::new();
    let package = PackageFixture::build(&fixture.root, fingerprint(1));
    let verified = load_package(&package.root, &package.context()).expect("package verifies");
    install_unrecognised_registry_state(
        &migration,
        &verified.manifest().package_id,
        verified.package_digest(),
    )
    .await;
    migration_task.abort();
    let idp = MockIdp::start().await;
    let config_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    let before = managed_database_snapshot(&database.admin).await;

    let refusal =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .err();

    assert_eq!(refusal, Some(StartupError::UnrecognizedDatabase));
    assert!(StartupError::UnrecognizedDatabase
        .to_string()
        .contains("upgrade the database one release at a time"));
    assert_eq!(
        managed_database_snapshot(&database.admin).await,
        before,
        "a refused startup writes nothing"
    );
    idp.stop().await;
    database.cleanup().await;
}

/// Threat: in split mode the runtime credential is the one an attacker who
/// compromises the serving process holds, and a runtime role that can write
/// the activation ledger or the registry state could rewrite what the
/// ledger says was activated. Enforcement: split startup refuses a runtime
/// role that owns a registry object, holds CREATE on a registry schema, or
/// serves a table carrying a trigger the migrations never created, and
/// refuses a runtime role missing the grants the active package gives it,
/// each naming the apply that names or reissues the fix. A one-role runtime
/// file refuses a database last activated for a separate runtime role. Every
/// refusal writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn split_startup_refuses_a_runtime_role_that_can_write_the_ledger_and_writes_nothing() {
    let _runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
    let database = TestDatabase::create(4).await;
    let fixture = StartupFixture::new();
    let (package, verified, mut active) =
        split_activated_startup_package(&database, &fixture).await;
    let idp = MockIdp::start().await;
    let config_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    let prepared =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .expect("the split activation serves");
    assert_eq!(prepared.role_mode(), RoleMode::Split);
    drop(prepared);

    let table: String = database
        .admin
        .query_one(
            "SELECT pg_catalog.format('%I.%I', schemaname, tablename)
               FROM pg_catalog.pg_tables
              WHERE schemaname = 'registry_data'
              ORDER BY tablename
              LIMIT 1",
            &[],
        )
        .await
        .expect("a model table exists")
        .get(0);
    let runtime = quote(database.runtime_role.as_str());
    let migration = quote(database.migration_role.as_str());
    for (grant, undo) in [
        (
            format!("ALTER TABLE {table} OWNER TO {runtime}"),
            format!("REASSIGN OWNED BY {runtime} TO {migration}"),
        ),
        (
            format!("GRANT CREATE ON SCHEMA registry_data TO {runtime}"),
            format!("REVOKE CREATE ON SCHEMA registry_data FROM {runtime}"),
        ),
        (
            format!(
                "CREATE FUNCTION public.startup_foreign_trigger() RETURNS trigger
                     LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
                 CREATE TRIGGER startup_foreign_trigger BEFORE INSERT ON {table}
                     FOR EACH ROW EXECUTE FUNCTION public.startup_foreign_trigger()"
            ),
            format!(
                "DROP TRIGGER startup_foreign_trigger ON {table};
                 DROP FUNCTION public.startup_foreign_trigger()"
            ),
        ),
    ] {
        database
            .admin
            .batch_execute(&grant)
            .await
            .expect("administrator grants the runtime role write authority");
        let before = managed_database_snapshot(&database.admin).await;
        let refusal =
            prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
                .await
                .err();
        assert_eq!(
            refusal,
            Some(StartupError::RuntimeWriteAuthority),
            "{grant}"
        );
        assert_eq!(
            managed_database_snapshot(&database.admin).await,
            before,
            "a refused startup writes nothing"
        );
        database
            .admin
            .batch_execute(&undo)
            .await
            .expect("administrator applies the named fix");
        // A reassignment carries the runtime role's own grants away with the
        // ownership, so startup then names the apply that reissues them.
        match prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
        {
            Ok(_) => {}
            Err(StartupError::RuntimeGrantsMissing) => {
                active = apply_startup_package_result(
                    &database,
                    &verified,
                    ApplyPrecondition::RoleChange { current: &active },
                )
                .await
                .expect("the apply reissues the runtime grants");
                prepare_with_connection_config_for_test(
                    &config_path,
                    database.runtime_config.clone(),
                )
                .await
                .expect("the reissued grants serve");
            }
            Err(other) => panic!("{grant}: {other:?}"),
        }
    }
    assert!(StartupError::RuntimeWriteAuthority
        .to_string()
        .contains("run `bregctl apply --package DIR`"));

    // A revoked runtime grant is pending work the apply reissues.
    database
        .admin
        .batch_execute(&format!("REVOKE SELECT ON {table} FROM {runtime}"))
        .await
        .expect("administrator revokes a runtime grant");
    let before = managed_database_snapshot(&database.admin).await;
    let refusal =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .err();
    assert_eq!(refusal, Some(StartupError::RuntimeGrantsMissing));
    assert!(StartupError::RuntimeGrantsMissing
        .to_string()
        .contains("run `bregctl apply --package DIR` to reissue them"));
    assert_eq!(managed_database_snapshot(&database.admin).await, before);
    active = apply_startup_package_result(
        &database,
        &verified,
        ApplyPrecondition::RoleChange { current: &active },
    )
    .await
    .expect("the apply reissues the revoked grant");
    prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
        .await
        .expect("the reissued grant serves");

    // A one-role runtime file over a database activated for a separate
    // runtime role is refused until the apply activates it for one role.
    let single_config_path = write_single_role_config(&fixture, &package, &database, &idp);
    let before = managed_database_snapshot(&database.admin).await;
    let refusal = prepare_with_connection_config_for_test(
        &single_config_path,
        database.migration_config.clone(),
    )
    .await
    .err();
    assert_eq!(refusal, Some(StartupError::RoleModeChanged));
    assert!(StartupError::RoleModeChanged
        .to_string()
        .contains("run `bregctl apply --package DIR`"));
    assert_eq!(managed_database_snapshot(&database.admin).await, before);
    let single = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        &verified,
        ActivationDeployment::new("production", INSTANCE, DATABASE),
        ApplyPrecondition::RoleChange { current: &active },
        ApplyRoles::new(&database.migration_role, &database.migration_role),
        ApplyTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
            .expect("test apply timeouts are bounded"),
        database.activation_audit(),
    ))
    .await
    .expect("the apply activates the package for one role");
    let prepared = prepare_with_connection_config_for_test(
        &single_config_path,
        database.migration_config.clone(),
    )
    .await
    .expect("one role serves its own activation");
    assert_eq!(prepared.role_mode(), RoleMode::Single);
    drop(prepared);

    // The separate runtime role holds no grant of a one-role activation, so a
    // split runtime file names the apply that issues them.
    let refusal =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .err();
    assert_eq!(refusal, Some(StartupError::RuntimeGrantsMissing));
    apply_startup_package_result(
        &database,
        &verified,
        ApplyPrecondition::RoleChange { current: &single },
    )
    .await
    .expect("the apply activates the package for the separate role");
    prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
        .await
        .expect("the separate role serves again");
    idp.stop().await;
    database.cleanup().await;
}

/// Activate the startup package in split mode against a fingerprint the
/// compiled schema rehearses.
async fn split_activated_startup_package(
    database: &TestDatabase,
    fixture: &StartupFixture,
) -> (PackageFixture, VerifiedPackage, ExpectedRegistryIdentity) {
    let (mut migration, migration_task) = database.connect_migration().await;
    let provisional = PackageFixture::build(&fixture.root, fingerprint(1));
    let verified_provisional = load_package(&provisional.root, &provisional.context())
        .expect("provisional package verifies");
    let transaction = migration
        .transaction()
        .await
        .expect("fingerprint transaction starts");
    install_compiled_schema(
        &transaction,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("split-role schema rehearses");
    let schema_fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified_provisional.registry()),
    )
    .await
    .expect("split-role fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("split-role rehearsal rolls back");
    migration_task.abort();
    drop(provisional);

    let package = PackageFixture::build(&fixture.root, schema_fingerprint);
    let verified = load_package(&package.root, &package.context()).expect("package verifies");
    let active =
        apply_startup_package(database, &verified, ApplyPrecondition::InitialActivation).await;
    (package, verified, active)
}

/// A runtime file that serves and migrates with the migration role.
fn write_single_role_config(
    fixture: &StartupFixture,
    package: &PackageFixture,
    database: &TestDatabase,
    idp: &MockIdp,
) -> PathBuf {
    let config_path = fixture.write_static_jwks_config(
        package,
        &database.migration_role,
        &database.migration_role,
        idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    let raw = fs::read_to_string(&config_path).expect("runtime config reads");
    fs::write(
        &config_path,
        raw.replace(
            "migrationUrlRef: secret:file/migration-database-url",
            "migrationUrlRef: secret:file/database-url",
        ),
    )
    .expect("single-role runtime config writes");
    config_path
}

/// Registry state this release does not recognise: the kernel state table as
/// a release before the activation ledger created it, with the singleton row it
/// recorded for one activation.
async fn install_unrecognised_registry_state(
    migration: &impl GenericClient,
    package_id: &str,
    package_digest: &str,
) {
    migration
        .batch_execute(
            "CREATE TABLE registry_internal.registry_state (
                 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
                 environment text NOT NULL,
                 package_id text NOT NULL,
                 instance_id text NOT NULL,
                 database_id text NOT NULL,
                 active_package_revision text NOT NULL,
                 schema_fingerprint text NOT NULL,
                 package_sequence bigint NOT NULL,
                 maintenance_status text NOT NULL,
                 maintenance_target_revision text,
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
             )",
        )
        .await
        .expect("pre-ledger state table installs");
    migration
        .execute(
            "INSERT INTO registry_internal.registry_state (
                 environment, package_id, instance_id, database_id,
                 active_package_revision, schema_fingerprint, package_sequence,
                 maintenance_status
             ) VALUES ('production', $1, $2, $3, $4, $5, 1, 'ready')",
            &[
                &package_id,
                &INSTANCE,
                &DATABASE,
                &package_digest,
                &fingerprint(1),
            ],
        )
        .await
        .expect("pre-ledger state row records");
}

/// Every relation in the managed schemas, and every registry state row, as
/// text an assertion compares before and after a refused command.
async fn managed_database_snapshot(admin: &impl GenericClient) -> Vec<String> {
    let mut snapshot: Vec<String> = admin
        .query(
            "SELECT n.nspname || '.' || c.relname || ':' || c.relkind::text
               FROM pg_catalog.pg_class c
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname LIKE 'registry\\_%'
              ORDER BY 1",
            &[],
        )
        .await
        .expect("managed relations read")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    let state_exists: bool = admin
        .query_one(
            "SELECT to_regclass('registry_internal.registry_state') IS NOT NULL",
            &[],
        )
        .await
        .expect("state table presence reads")
        .get(0);
    if state_exists {
        snapshot.extend(
            admin
                .query(
                    "SELECT row_to_json(state)::text FROM registry_internal.registry_state state",
                    &[],
                )
                .await
                .expect("state rows read")
                .into_iter()
                .map(|row| row.get::<_, String>(0)),
        );
    }
    snapshot
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_database_role_applies_the_initial_package_and_serves_reads() {
    let _runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let fixture = StartupFixture::new();

    // The package fingerprint is computed against a split-role rehearsal, so
    // the same package must activate whichever role mode the operator runs.
    let provisional = PackageFixture::build(&fixture.root, fingerprint(1));
    let verified_provisional = load_package(&provisional.root, &provisional.context())
        .expect("provisional package verifies");
    let transaction = migration
        .transaction()
        .await
        .expect("fingerprint transaction starts");
    install_compiled_schema(
        &transaction,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("split-role schema rehearses");
    let schema_fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified_provisional.registry()),
    )
    .await
    .expect("split-role fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("split-role rehearsal rolls back");
    migration_task.abort();
    drop(provisional);

    let package = PackageFixture::build(&fixture.root, schema_fingerprint);
    let verified = load_package(&package.root, &package.context()).expect("package verifies");
    apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        &verified,
        ActivationDeployment::new("production", INSTANCE, DATABASE),
        ApplyPrecondition::InitialActivation,
        ApplyRoles::new(&database.migration_role, &database.migration_role),
        ApplyTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
            .expect("test apply timeouts are bounded"),
        database.activation_audit(),
    ))
    .await
    .expect("one role applies the initial package");

    let idp = MockIdp::start().await;
    let config_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.migration_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    let raw = fs::read_to_string(&config_path).expect("runtime config reads");
    fs::write(
        &config_path,
        raw.replace(
            "migrationUrlRef: secret:file/migration-database-url",
            "migrationUrlRef: secret:file/database-url",
        ),
    )
    .expect("single-role runtime config writes");
    let prepared =
        prepare_with_connection_config_for_test(&config_path, database.migration_config.clone())
            .await
            .expect("one role serves the applied package");
    assert_ready(&prepared, StatusCode::OK).await;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock follows epoch")
        .as_secs();
    let token = sign_ed25519_compact_jwt(
        testing_fixtures::ED25519_PRIVATE_JWK,
        "JWT",
        "registry-platform-testing-ed25519-1",
        json!({
            "iss": idp.issuer(),
            "aud": "urn:breg:test",
            "registry_actor_kind": "service",
            "principal": "package-reader",
            "iat": now,
            "nbf": now,
            "exp": now + 120
        }),
    );
    let response = prepared
        .app()
        .oneshot(
            Request::builder()
                .uri("/v1/records/neutral-records?accessProfile=reader")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body reads");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    drop(prepared);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_old_server_drains_apply_and_exact_successor_restart_becomes_ready() {
    let _runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let fixture = StartupFixture::new();

    let provisional = PackageFixture::build(&fixture.root, fingerprint(1));
    let verified_provisional = load_package(&provisional.root, &provisional.context())
        .expect("provisional initial package verifies");
    let transaction = migration
        .transaction()
        .await
        .expect("initial fingerprint transaction starts");
    install_compiled_schema(
        &transaction,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("initial schema rehearses");
    let initial_fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified_provisional.registry()),
    )
    .await
    .expect("initial target fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("initial rehearsal rolls back");
    drop(provisional);

    let initial_package = PackageFixture::build(&fixture.root, initial_fingerprint);
    let verified_initial = load_package(&initial_package.root, &initial_package.context())
        .expect("final initial package verifies");
    let initial = apply_startup_package(
        &database,
        &verified_initial,
        ApplyPrecondition::InitialActivation,
    )
    .await;

    let provisional_successor =
        PackageFixture::build_successor(&fixture.root, fingerprint(2), &initial.package_digest);
    let verified_provisional_successor = load_package(
        &provisional_successor.root,
        &provisional_successor.context(),
    )
    .expect("provisional successor verifies");
    let transaction = migration
        .transaction()
        .await
        .expect("successor fingerprint transaction starts");
    for statement in &verified_provisional_successor
        .manifest()
        .migration_plan
        .statements
    {
        transaction
            .batch_execute(&statement.sql)
            .await
            .expect("successor statement rehearses");
    }
    let added_table =
        &verified_provisional_successor.registry().entities()["second-record"].physical_table;
    transaction
        .batch_execute(&format!(
            "REVOKE ALL ON TABLE registry_data.{} FROM PUBLIC, \"{}\";
             GRANT SELECT ON TABLE registry_data.{} TO \"{}\";",
            quote(added_table),
            database.runtime_role.as_str(),
            quote(added_table),
            database.runtime_role.as_str(),
        ))
        .await
        .expect("successor rehearsal installs the compiled runtime ACL");
    for view in &verified_provisional_successor.registry().ddl().views {
        let schema = quote(&view.schema);
        let name = quote(&view.name);
        transaction
            .batch_execute(&format!(
                "REVOKE ALL ON TABLE {schema}.{name} FROM PUBLIC, \"{}\";",
                database.runtime_role.as_str()
            ))
            .await
            .expect("successor rehearsal revokes compiled view privileges");
        if !view.runtime_privileges.is_empty() {
            let privileges = view
                .runtime_privileges
                .iter()
                .map(|privilege| privilege.as_sql())
                .collect::<Vec<_>>()
                .join(", ");
            transaction
                .batch_execute(&format!(
                    "GRANT {privileges} ON TABLE {schema}.{name} TO \"{}\";",
                    database.runtime_role.as_str()
                ))
                .await
                .expect("successor rehearsal grants compiled view privileges");
        }
    }
    let successor_fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified_provisional_successor.registry()),
    )
    .await
    .expect("successor target fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("successor rehearsal rolls back");
    drop(provisional_successor);

    let successor_package = PackageFixture::build_successor(
        &fixture.root,
        successor_fingerprint,
        &initial.package_digest,
    );
    let verified_successor = load_package(&successor_package.root, &successor_package.context())
        .expect("final successor verifies");
    migration_task.abort();

    let record_id = uuid::Uuid::from_u128(1);
    let old_entity = &verified_initial.registry().entities()["neutral-record"];
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.{} (record_id, active_package_revision, {})
                 VALUES ($1, $2, $3)",
                quote(&old_entity.physical_table),
                quote(&old_entity.fields["code"].physical_name),
            ),
            &[&record_id, &initial.activation_id, &"old-row"],
        )
        .await
        .expect("old package row seeds");

    let idp = MockIdp::start().await;
    let key_source = mock_idp_key_source(&idp).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock follows epoch")
        .as_secs();
    let token = idp.mint_token(json!({
        "aud": "urn:breg:test",
        "registry_actor_kind": "service",
        "principal": "recovery-operator",
        "iat": now,
        "nbf": now,
        "exp": now + 120
    }));
    let old_address = reserve_address();
    let old_config = fixture.write_config_at(
        &initial_package,
        &database.migration_role,
        &database.runtime_role,
        &idp.issuer(),
        Some("0123456789abcdef0123456789abcdef"),
        old_address,
    );
    let old_prepared = prepare_with_connection_and_key_source_for_test(
        &old_config,
        database.runtime_config.clone(),
        Arc::clone(&key_source),
    )
    .await
    .expect("old exact package prepares");
    let (old_shutdown, old_server) = spawn_live_server(old_prepared, old_address).await;

    let (mut record_blocker_connection, record_blocker_task) = database.connect_migration().await;
    let record_blocker = record_blocker_connection
        .transaction()
        .await
        .expect("record blocker transaction starts");
    record_blocker
        .batch_execute(&format!(
            "LOCK TABLE registry_data.{} IN ACCESS EXCLUSIVE MODE",
            quote(&old_entity.physical_table)
        ))
        .await
        .expect("record blocker owns the old data table");

    let (mut ddl_blocker_connection, ddl_blocker_task) = database.connect_migration().await;
    let ddl_blocker = ddl_blocker_connection
        .transaction()
        .await
        .expect("DDL blocker transaction starts");
    let create_table_sql = verified_successor
        .manifest()
        .migration_plan
        .statements
        .iter()
        .find(|statement| statement.sql.starts_with("CREATE TABLE "))
        .expect("successor has one table creation")
        .sql
        .clone();
    ddl_blocker
        .batch_execute(&create_table_sql)
        .await
        .expect("uncommitted successor table blocks exact apply DDL");

    let record_path = format!("/v1/records/neutral-records/{record_id}?accessProfile=reader");
    let in_flight_address = old_address;
    let in_flight_path = record_path.clone();
    let in_flight_token = token.clone();
    let mut in_flight = tokio::spawn(async move {
        http_get(in_flight_address, &in_flight_path, Some(&in_flight_token)).await
    });
    tokio::select! {
        result = &mut in_flight => {
            let response = result
                .expect("premature in-flight task joins")
                .expect("premature in-flight HTTP exchange completes");
            panic!(
                "old record request returned before reaching its deterministic table wait with status {}",
                response.status
            );
        }
        () = wait_for_role_relation_wait(&database.admin, database.runtime_role.as_str()) => {}
    }

    let active = {
        let apply = apply_startup_package_result(
            &database,
            &verified_successor,
            ApplyPrecondition::Successor { current: &initial },
        );
        tokio::pin!(apply);
        tokio::select! {
            result = &mut apply => panic!("apply passed the prior in-flight record operation: {result:?}"),
            () = wait_for_role_advisory_wait(&database.admin, database.migration_role.as_str()) => {}
        }
        record_blocker
            .rollback()
            .await
            .expect("operator releases the deterministic record blocker");
        record_blocker_task.abort();
        let drained = tokio::time::timeout(Duration::from_secs(2), in_flight)
            .await
            .expect("prior in-flight request drains within the bound")
            .expect("prior in-flight task joins")
            .expect("prior in-flight HTTP exchange completes");
        // Apply wins only after the record transaction releases its shared
        // lock, so the read completed under the package that was active for
        // its whole transaction. Its response entry is written to the audit
        // file without reopening the database, and the old-package bytes it
        // read are released: the read is ordered before the apply.
        assert_eq!(drained.status, 200);
        assert!(drained.body.contains("old-row"));
        assert!(!drained.body.contains("recovery-operator"));
        assert!(!drained.body.contains(&token));

        tokio::select! {
            result = &mut apply => panic!("apply escaped the deterministic successor DDL blocker: {result:?}"),
            () = wait_for_maintenance_without_sleep(&database.admin, "applying") => {}
        }
        let refused_during_apply = tokio::time::timeout(
            Duration::from_secs(2),
            http_get(old_address, &record_path, Some(&token)),
        )
        .await
        .expect("new record work fails within the configured lock bound")
        .expect("old server returns a value-free refusal");
        assert_eq!(refused_during_apply.status, 503);
        assert!(!refused_during_apply.body.contains("old-row"));
        assert!(!refused_during_apply.body.contains("recovery-operator"));
        assert!(!refused_during_apply.body.contains(&token));

        ddl_blocker
            .rollback()
            .await
            .expect("operator releases the deterministic successor DDL blocker");
        ddl_blocker_task.abort();
        apply
            .await
            .expect("exact successor applies after prior work drains")
    };
    assert_eq!(active.package_digest, verified_successor.package_digest());

    let old_ready = http_get(old_address, "/ready", None)
        .await
        .expect("old process readiness responds after activation");
    assert_eq!(old_ready.status, 503);

    let (mut post_activation_blocker, post_activation_blocker_task) =
        database.connect_migration().await;
    let post_activation_lock = post_activation_blocker
        .transaction()
        .await
        .expect("post-activation record blocker starts");
    post_activation_lock
        .batch_execute(&format!(
            "LOCK TABLE registry_data.{} IN ACCESS EXCLUSIVE MODE",
            quote(&old_entity.physical_table)
        ))
        .await
        .expect("old record table is unavailable to prove pre-I/O refusal");
    let old_refusal = tokio::time::timeout(
        Duration::from_millis(750),
        http_get(old_address, &record_path, Some(&token)),
    )
    .await
    .expect("old process refuses before attempting blocked record I/O")
    .expect("old process returns its refusal");
    assert_eq!(old_refusal.status, 503);
    assert!(!old_refusal.body.contains("old-row"));
    assert!(!old_refusal.body.contains("recovery-operator"));
    assert!(!old_refusal.body.contains(&token));
    post_activation_lock
        .rollback()
        .await
        .expect("post-activation record blocker rolls back");
    post_activation_blocker_task.abort();

    old_shutdown
        .send(())
        .expect("old process shutdown signal sends");
    old_server
        .await
        .expect("old server task joins")
        .expect("old server shuts down cleanly");

    let new_address = reserve_address();
    let new_config = fixture.write_config_at(
        &successor_package,
        &database.migration_role,
        &database.runtime_role,
        &idp.issuer(),
        Some("0123456789abcdef0123456789abcdef"),
        new_address,
    );
    let new_prepared = prepare_with_connection_and_key_source_for_test(
        &new_config,
        database.runtime_config.clone(),
        key_source,
    )
    .await
    .expect("restart accepts only the exact active successor package");
    let (new_shutdown, new_server) = spawn_live_server(new_prepared, new_address).await;
    assert_eq!(
        http_get(new_address, "/ready", None)
            .await
            .expect("new process readiness responds")
            .status,
        200
    );
    new_shutdown
        .send(())
        .expect("new process shutdown signal sends");
    new_server
        .await
        .expect("new server task joins")
        .expect("new server shuts down cleanly");

    idp.stop().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_and_oidc_failures_refuse_before_listener_bind() {
    let _runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    let fixture = StartupFixture::new();
    let provisional = PackageFixture::build(&fixture.root, fingerprint(1));
    let verified_provisional =
        load_package(&provisional.root, &provisional.context()).expect("provisional package loads");
    install_compiled_schema(
        &migration,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("compiled schema installs");
    let catalog = ExpectedManagedCatalog::compiled(verified_provisional.registry());
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &catalog)
            .await
            .expect("compiled schema fingerprints");
    drop(provisional);

    let package = PackageFixture::build(&fixture.root, schema_fingerprint);
    let verified = load_package(&package.root, &package.context()).expect("final package verifies");
    initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified.registry()),
        RegistryStateTestIdentity {
            package_id: &verified.manifest().package_id,
            database_id: DATABASE,
            label: verified.package_digest(),
        },
    )
    .await
    .expect("Registry state initializes");
    migration_task.abort();

    let missing_audit_path = fixture.write_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        "http://127.0.0.1:9",
        None,
    );
    assert_eq!(
        prepare_with_connection_config_for_test(
            &missing_audit_path,
            database.runtime_config.clone()
        )
        .await
        .err(),
        Some(StartupError::Audit)
    );

    let bad_oidc_path = fixture.write_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        "http://127.0.0.1:9",
        Some("0123456789abcdef0123456789abcdef"),
    );
    assert_eq!(
        prepare_with_connection_config_for_test(&bad_oidc_path, database.runtime_config.clone())
            .await
            .err(),
        Some(StartupError::Oidc)
    );
    database.cleanup().await;
}

async fn apply_startup_package(
    database: &TestDatabase,
    package: &VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
) -> ExpectedRegistryIdentity {
    apply_startup_package_result(database, package, precondition)
        .await
        .expect("verified package applies")
}

async fn apply_startup_package_result(
    database: &TestDatabase,
    package: &VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
) -> registry_breg::migration::Result<ExpectedRegistryIdentity> {
    apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        package,
        ActivationDeployment::new("production", INSTANCE, DATABASE),
        precondition,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
            .expect("test apply timeouts are bounded"),
        database.activation_audit(),
    ))
    .await
}

struct LiveHttpResponse {
    status: u16,
    body: String,
}

fn reserve_address() -> SocketAddr {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("loopback address reservation binds");
    listener
        .local_addr()
        .expect("loopback reservation address reads")
}

async fn spawn_live_server(
    prepared: PreparedServer,
    address: SocketAddr,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), StartupError>>,
) {
    assert_eq!(prepared.bind(), address);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut task = tokio::spawn(serve_until_shutdown(prepared, async move {
        let _ = shutdown_rx.await;
        Ok(())
    }));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                result = &mut task => {
                    panic!("live PreparedServer stopped before its health route was reachable: {result:?}")
                }
                connection = tokio::net::TcpStream::connect(address) => {
                    if connection.is_ok() {
                        return;
                    }
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("live PreparedServer accepts HTTP without timing sleeps");
    (shutdown_tx, task)
}

async fn http_get(
    address: SocketAddr,
    path: &str,
    token: Option<&str>,
) -> std::io::Result<LiveHttpResponse> {
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let authorization = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {address}\r\n{authorization}Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    loop {
        let read = stream.read_buf(&mut response).await?;
        if read == 0 || complete_http_response(&response) {
            break;
        }
    }
    let response = String::from_utf8(response)
        .map_err(|_| std::io::Error::other("HTTP response is not UTF-8"))?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("HTTP response is incomplete"))?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other("HTTP response status is invalid"))?;
    Ok(LiveHttpResponse {
        status,
        body: body.to_owned(),
    })
}

fn complete_http_response(response: &[u8]) -> bool {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    length.is_some_and(|length| response.len() >= header_end + 4 + length)
}

async fn wait_for_role_relation_wait(client: &impl GenericClient, role: &str) {
    wait_for_role_lock(client, role, "relation").await;
}

async fn wait_for_role_advisory_wait(client: &impl GenericClient, role: &str) {
    wait_for_role_lock(client, role, "advisory").await;
}

async fn wait_for_role_lock(client: &impl GenericClient, role: &str, lock_type: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let waiting: bool = client
                .query_one(
                    "SELECT EXISTS (
                         SELECT 1
                         FROM pg_locks AS lock
                         JOIN pg_stat_activity AS activity USING (pid)
                         WHERE activity.datname = current_database()
                           AND activity.usename = $1
                           AND lock.locktype = $2
                           AND NOT lock.granted
                     )",
                    &[&role, &lock_type],
                )
                .await
                .expect("administrator observes lock waits")
                .get(0);
            if waiting {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the expected database lock wait is reached without timing sleeps");
}

async fn wait_for_maintenance_without_sleep(client: &impl GenericClient, expected: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let status: String = client
                .query_one(
                    "SELECT maintenance_status
                     FROM registry_internal.registry_state
                     WHERE singleton",
                    &[],
                )
                .await
                .expect("maintenance state reads")
                .get(0);
            if status == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("maintenance reaches its durable state without timing sleeps");
}

/// The registry the verified startup path builds names the package it
/// verified, and the runtime role can read every queue the scrape samples.
async fn assert_metrics_publish_the_verified_package_and_every_queue(
    prepared: &PreparedServer,
    verified: &VerifiedPackage,
) {
    let response = prepared
        .metrics_app_for_test()
        .expect("the runtime file configures a metrics listener")
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("metrics router responds");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("metrics body reads");
    let body = String::from_utf8(body.to_vec()).expect("metrics body is UTF-8");
    let packages = body
        .lines()
        .filter(|line| line.starts_with("breg_active_package_info{"))
        .collect::<Vec<_>>();
    assert_eq!(
        packages,
        [format!(
            "breg_active_package_info{{package_digest=\"{}\"}} 1",
            verified.package_digest()
        )],
        "the scrape names the verified package once:\n{body}"
    );
    for queue in [
        "webhook_delivery",
        "review_submission",
        "review_application",
    ] {
        assert!(
            body.contains(&format!(
                "breg_queue_oldest_pending_age_seconds{{queue=\"{queue}\"}} 0\n"
            )),
            "the {queue} queue is sampled and empty:\n{body}"
        );
    }
}

async fn assert_ready(prepared: &PreparedServer, expected: StatusCode) {
    let response = prepared
        .app()
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), expected);
}

/// A serving process holds its audit file's single-writer lock, so a second
/// process configured with the same path refuses to start. The startup check
/// that doctor runs only checks the destination is writable: it succeeds
/// beside the lock holder and creates no audit file. The process WASM
/// executor admits one prepared server at a time, so a directly opened writer
/// stands in for the serving process here. The check also covers the
/// `bregctl` sibling destination operator commands append to, not only the
/// runtime's own destination: doctor's check treats it exactly as it treats
/// the runtime's own destination, accepting a torn final entry the writer can
/// move aside and refusing one whose side file already holds other bytes.
async fn assert_audit_destination_has_one_writer_and_checks_take_none(
    database: &TestDatabase,
    serving_config: &Path,
    unopened: &Path,
) {
    let serving_writer = registry_platform_audit::AuditWriter::open(
        registry_platform_audit::AuditDestination::from_settings(
            registry_platform_audit::AuditDestinationKind::File,
            Some(configured_audit_path(serving_config)),
            None,
            None,
        )
        .expect("the configured audit destination is valid"),
    )
    .await
    .expect("the serving writer takes the audit file lock");
    let refusal =
        prepare_with_connection_config_for_test(serving_config, database.runtime_config.clone())
            .await
            .err();
    assert!(
        matches!(&refusal, Some(StartupError::AuditDestination(reason)) if reason.contains("stop it")),
        "a second writer over the serving audit file refuses to start and says to stop the other one: {refusal:?}"
    );
    check_with_connection_config_for_test(serving_config, database.runtime_config.clone())
        .await
        .expect("the startup check runs beside the serving writer");
    drop(serving_writer);

    check_with_connection_config_for_test(unopened, database.runtime_config.clone())
        .await
        .expect("the startup check accepts a destination no writer has opened");
    let audit_path = configured_audit_path(unopened);
    assert!(
        !audit_path.exists() && !audit_path.parent().expect("audit directory").exists(),
        "the startup check creates neither the audit directory nor its file"
    );

    let registry_platform_audit::AuditDestination::File(companion) =
        registry_platform_audit::AuditDestination::from_settings(
            registry_platform_audit::AuditDestinationKind::File,
            Some(audit_path),
            None,
            None,
        )
        .expect("the configured audit destination is valid")
        .for_process(registry_breg::audit::COMPANION_PROCESS_ROLE)
        .expect("bregctl is a valid process role")
    else {
        panic!("expected a file destination");
    };
    let companion_path = companion.path().to_path_buf();
    let companion_directory = companion_path.parent().expect("audit directory");
    fs::create_dir_all(companion_directory).expect("companion audit directory is created");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(companion_directory, fs::Permissions::from_mode(0o700))
            .expect("companion audit directory mode is set");
        // The first entry must be in the writer's current envelope format, so
        // the only thing the check can find is the torn final entry.
        let complete_entry = "{\"eventId\":\"5b1b5b8e-6f2b-4c1a-9b7a-6b1b5b8e6f2b\",\"schema\":\"registry.test.audit/v1\",\"time\":\"2024-01-01T00:00:00Z\",\"correlation\":\"bregctl-companion\",\"phase\":\"request\",\"record\":{}}\n";
        fs::write(&companion_path, format!("{complete_entry}{{"))
            .expect("torn companion entry is written");
        fs::set_permissions(&companion_path, fs::Permissions::from_mode(0o600))
            .expect("companion audit file mode is set");
        // A torn final line is recoverable: the writer moves it to the
        // `.torn` side file when it opens, so the check accepts it and
        // changes nothing.
        check_with_connection_config_for_test(unopened, database.runtime_config.clone())
            .await
            .expect("the startup check accepts a recoverable torn companion entry");
        assert_eq!(
            fs::read_to_string(&companion_path).expect("companion audit file reads"),
            format!("{complete_entry}{{"),
            "the startup check leaves the torn companion entry in place"
        );
        let mut torn_line = companion_path.clone().into_os_string();
        torn_line.push(".torn");
        let torn_line = PathBuf::from(torn_line);
        assert!(
            !torn_line.exists(),
            "the startup check writes no torn-line side file"
        );
        // A side file that already holds other bytes is the only copy of an
        // earlier torn line, so recovery cannot proceed and the check refuses.
        fs::write(&torn_line, "earlier").expect("conflicting side file is written");
        fs::set_permissions(&torn_line, fs::Permissions::from_mode(0o600))
            .expect("side file mode is set");
        let refusal =
            check_with_connection_config_for_test(unopened, database.runtime_config.clone())
                .await
                .err();
        assert!(
            matches!(&refusal, Some(StartupError::AuditDestination(reason)) if reason.contains("archive the side file")),
            "a torn companion entry beside a conflicting side file refuses the startup check and names the recovery: {refusal:?}"
        );
        fs::remove_file(&torn_line).expect("side file cleanup");
        fs::write(&companion_path, complete_entry).expect("companion entry is completed");
        check_with_connection_config_for_test(unopened, database.runtime_config.clone())
            .await
            .expect("the startup check accepts a completed companion destination");
    }
    fs::remove_dir_all(companion_directory).expect("companion audit directory cleanup");
}

fn configured_audit_path(config_path: &Path) -> PathBuf {
    let config = fs::read_to_string(config_path).expect("runtime config reads");
    let mut lines = config.lines().skip_while(|line| *line != "audit:");
    lines
        .find_map(|line| line.strip_prefix("  path: "))
        .map(PathBuf::from)
        .expect("the runtime config names its audit path")
}

async fn assert_unknown_static_kid_refuses_value_free(prepared: &PreparedServer) {
    const UNKNOWN_KID_CANARY: &str = "unknown-static-kid-canary";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock follows epoch")
        .as_secs();
    let token = sign_ed25519_compact_jwt(
        testing_fixtures::ED25519_PRIVATE_JWK,
        "JWT",
        UNKNOWN_KID_CANARY,
        json!({
            "aud": "urn:breg:test",
            "principal": "package-reader",
            "iat": now,
            "nbf": now,
            "exp": now + 120
        }),
    );
    let response = prepared
        .app()
        .oneshot(
            Request::builder()
                .uri("/v1/records/neutral-records?accessProfile=reader")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let mut rendered = response
        .headers()
        .iter()
        .map(|(name, value)| format!("{}:{}\n", name, value.to_str().unwrap_or("<binary>")))
        .collect::<String>();
    rendered.push_str(
        std::str::from_utf8(
            &to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("response body reads"),
        )
        .expect("response body is UTF-8"),
    );
    assert!(!rendered.contains(UNKNOWN_KID_CANARY));
}

async fn mock_idp_key_source(idp: &MockIdp) -> Arc<JwksFetcher> {
    let discovery = fetch_discovery_with_policy(
        &OidcDiscoveryConfig {
            issuer: idp.issuer(),
            jwks_uri_override: None,
            discovery_timeout: Duration::from_secs(5),
            max_doc_bytes: 16 * 1024,
        },
        &FetchUrlPolicy::dev(),
    )
    .await
    .expect("MockIdp discovery fetch succeeds");
    Arc::new(JwksFetcher::new_with_fetch_url_policy(
        discovery.jwks_uri,
        JwksFetcherConfig {
            cache_ttl: Duration::from_secs(1),
            negative_cache_ttl: Duration::from_secs(1),
            refresh_cooldown: Duration::from_secs(1),
            max_doc_bytes: 16 * 1024,
            request_timeout: Duration::from_secs(5),
            outage_tolerance: Duration::ZERO,
        },
        FetchUrlPolicy::dev(),
    ))
}

struct StartupFixture {
    root: PathBuf,
    secret_root: PathBuf,
}

impl StartupFixture {
    fn new() -> Self {
        let parent = std::env::temp_dir()
            .canonicalize()
            .expect("temporary parent canonicalizes");
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock follows epoch")
            .as_nanos();
        let ordinal = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = parent.join(format!(
            "breg-postgres-startup-{}-{suffix}-{ordinal}",
            std::process::id(),
        ));
        fs::create_dir(&root).expect("fixture root creates");
        let secret_root = root.join("secrets");
        fs::create_dir(&secret_root).expect("secret root creates");
        Self { root, secret_root }
    }

    fn write_config(
        &self,
        package: &PackageFixture,
        migration_role: &registry_breg::postgres::SqlIdentifier,
        runtime_role: &registry_breg::postgres::SqlIdentifier,
        issuer: &str,
        audit_key: Option<&str>,
    ) -> PathBuf {
        self.write_config_at(
            package,
            migration_role,
            runtime_role,
            issuer,
            audit_key,
            "127.0.0.1:9".parse().expect("fixture listener parses"),
        )
    }

    fn write_static_jwks_config(
        &self,
        package: &PackageFixture,
        migration_role: &registry_breg::postgres::SqlIdentifier,
        runtime_role: &registry_breg::postgres::SqlIdentifier,
        idp: &MockIdp,
        audit_key: Option<&str>,
    ) -> PathBuf {
        let public_jwks = jwks_from_private_jwk(
            &PrivateJwk::parse(testing_fixtures::ED25519_PRIVATE_JWK).expect("test IdP key parses"),
        );
        let jwks_path = self.secret_root.join("oidc-jwks");
        fs::write(
            &jwks_path,
            serde_json::to_vec(&public_jwks).expect("static JWKS serializes"),
        )
        .expect("static JWKS writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&jwks_path, fs::Permissions::from_mode(0o600))
                .expect("static JWKS permissions set");
        }
        let path = self.write_config(
            package,
            migration_role,
            runtime_role,
            &idp.issuer(),
            audit_key,
        );
        let raw = fs::read_to_string(&path).expect("runtime config reads");
        fs::write(
            &path,
            raw.replace(
                "    jwksCache:\n",
                "    jwksSource:\n      kind: static\n      documentRef: secret:file/oidc-jwks\n    jwksCache:\n",
            ),
        )
        .expect("static JWKS runtime config writes");
        path
    }

    fn write_config_at(
        &self,
        package: &PackageFixture,
        migration_role: &registry_breg::postgres::SqlIdentifier,
        runtime_role: &registry_breg::postgres::SqlIdentifier,
        issuer: &str,
        audit_key: Option<&str>,
        listener: SocketAddr,
    ) -> PathBuf {
        let hash_key_ref = if let Some(audit_key) = audit_key {
            let audit_key_path = self.secret_root.join("audit-key");
            fs::write(&audit_key_path, audit_key).expect("audit key writes");
            let cursor_key_path = self.secret_root.join("cursor-key");
            fs::write(&cursor_key_path, [0x53_u8; 32]).expect("cursor key writes");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&audit_key_path, fs::Permissions::from_mode(0o600))
                    .expect("audit key permissions set");
                fs::set_permissions(&cursor_key_path, fs::Permissions::from_mode(0o600))
                    .expect("cursor key permissions set");
            }
            "secret:file/audit-key"
        } else {
            "secret:file/missing-audit-key"
        };
        let ordinal = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = self.root.join(format!("runtime-{ordinal}.yaml"));
        let audit_path = self
            .root
            .join(format!("audit-{ordinal}"))
            .join("audit.jsonl")
            .display()
            .to_string();
        fs::write(
            &path,
            format!(
                r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: {listener}
identity:
  environment: production
  instanceId: {INSTANCE}
  databaseId: {DATABASE}
  databaseInitializationEnvironment: production
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 1
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: {}
    runtime: {}
package:
  root: {}
authentication:
  oidc:
    issuer: {}
    audience: urn:breg:test
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 200
      outageToleranceSeconds: 0
  authorityClaims:
    principal: principal
audit:
  hashKeyRef: {hash_key_ref}
  path: {audit_path}
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
operationalTimeouts:
  httpRequestMilliseconds: 5000
  shutdownGraceMilliseconds: 1000
  recordLockMilliseconds: 1000
  migrationLockMilliseconds: 1000
  migrationStatementMilliseconds: 1000
"#,
                self.secret_root.display(),
                migration_role.as_str(),
                runtime_role.as_str(),
                package.root.display(),
                issuer
            ),
        )
        .expect("runtime config writes");
        fs::write(self.secret_root.join("database-url"), "unused")
            .expect("unused DB URL secret writes");
        path
    }
}

impl Drop for StartupFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct PackageFixture {
    root: PathBuf,
}

impl PackageFixture {
    fn build(parent: &Path, schema_fingerprint: String) -> Self {
        Self::build_version(parent, schema_fingerprint, None, false)
    }

    fn build_successor(parent: &Path, schema_fingerprint: String, prior_revision: &str) -> Self {
        Self::build_version(parent, schema_fingerprint, Some(prior_revision), true)
    }

    fn build_version(
        parent: &Path,
        schema_fingerprint: String,
        prior_revision: Option<&str>,
        successor: bool,
    ) -> Self {
        Self::build_version_with_module(
            parent,
            schema_fingerprint,
            prior_revision,
            successor,
            module_bytes(successor),
        )
    }

    fn build_version_with_module(
        parent: &Path,
        schema_fingerprint: String,
        prior_revision: Option<&str>,
        successor: bool,
        module_source: Vec<u8>,
    ) -> Self {
        let ordinal = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = parent.join(format!("package-{ordinal}"));
        let module = parse_module_yaml(&module_source).expect("fixture module parses");
        let project_source = project_bytes(&module_digest(&module));
        let migration_plan = if successor {
            let prior_module_bytes = module_bytes(false);
            let prior_module =
                parse_module_yaml(&prior_module_bytes).expect("prior fixture module parses");
            let prior_project_bytes = project_bytes(&module_digest(&prior_module));
            let prior_project =
                parse_project_yaml(&prior_project_bytes).expect("prior fixture project parses");
            let prior_registry =
                compile_project(&prior_project, &[prior_module], CompileProfile::Production)
                    .expect("prior fixture Registry compiles");
            PackageMigrationPlanInput::Successor {
                prior_registry: Box::new(prior_registry),
            }
        } else {
            PackageMigrationPlanInput::InitialCompiledDdl
        };
        let prepared = prepare_package(PackageBuildRequest {
            from_package_digest: prior_revision.map(str::to_owned),
            compiler_source_revision: SOURCE_REVISION.to_owned(),
            schema_fingerprint,
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: project_source,
            },
            modules: vec![PackageModuleSource {
                id: "core".to_owned(),
                path: "source/modules/core/module.yaml".to_owned(),
                bytes: module_source,
                assets: Vec::new(),
            }],
            fixture_journeys: PackageSourceFile {
                path: "tests/journeys.yaml".to_owned(),
                bytes: FIXTURE_JOURNEYS.to_vec(),
            },
            migration_plan,
        })
        .expect("fixture package prepares");
        prepared
            .publish_to_directory(&root)
            .expect("fixture package publishes");
        Self { root }
    }

    fn context(&self) -> PackageLoadContext<'static> {
        PackageLoadContext {
            database_initialization_environment: "production",
        }
    }
}

fn project_bytes(module_digest: &str) -> Vec<u8> {
    let project = format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    );
    parse_project_yaml(project.as_bytes()).expect("project fixture parses");
    project.into_bytes()
}

fn module_bytes(successor: bool) -> Vec<u8> {
    let second = if successor {
        r#",{"id":"second-record","primaryDataset":"neutral-registry","route":"second-records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get"],"readableFields":["code"], "rowBoundaries": []}]}"#
    } else {
        ""
    };
    format!(
        r#"{{"id":"core","version":"1","entities":[{{"id":"neutral-record","primaryDataset":"neutral-registry","route":"neutral-records","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":8,"classification":"internal"}}],"accessProfiles":[{{"rowBoundaries": [], "id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"]}}]}}{second}]}}"#
    )
    .into_bytes()
}

/// One module whose `holder` entity carries an encrypted restricted field, so
/// a production package built from it requires field-encryption key state.
fn module_bytes_with_encrypted_field() -> Vec<u8> {
    r#"{"id":"core","version":"1","entities":[{"id":"holder","primaryDataset":"neutral-registry","route":"holders","mutationMode":"mutable","fields":[{"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},{"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"},{"id":"secret","type":"string","maxLength":256,"required":true,"classification":"restricted","encrypted":true,"lookup":{"normalization":["trim","uppercase"],"unique":true}}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["jurisdiction","label","secret"],"rowBoundaries":[]}]}]}"#
        .to_owned()
        .into_bytes()
}

fn fingerprint(byte: u8) -> String {
    format!("sha256:{}", format!("{byte:02x}").repeat(32))
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
