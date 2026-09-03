// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling", unix))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use postgres_harness::TestDatabase;
use registry_platform_audit::{verify_chain, AuditEnvelope, AuditProfile};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_platform_testing::{fixtures as testing_fixtures, jwks_from_private_jwk, MockIdp};
use registry_server::compiler::{
    compile_project, compile_project_with_assets, module_digest, module_digest_with_assets,
    CompileProfile,
};
use registry_server::contract::{parse_module_yaml, parse_project_yaml, ModuleAssetSource};
use registry_server::fixtures::{
    execute_schema_test, validate_fixture_journeys, validate_schema_test_receipt_for_package,
    FixtureError, FixtureModuleSource, FixtureSourceFile, PostgresFixtureTestRunner,
    SchemaTestCredentialBinding, SchemaTestCredentialBindings, SchemaTestSources,
};
use registry_server::package::{
    load_package, prepare_package, PackageBuildRequest, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageModuleSource, PackageSignature, PackageSourceFile,
    PackageTrustAnchor, PreparedPackage, SignaturePolicy, TrustAnchorKey, VerifiedPackage,
    FIXTURE_JOURNEYS_PATH, TRUST_ANCHOR_API_VERSION,
};
use registry_server::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    managed_schema_fingerprint, provision_postgis_prerequisites, spatial_bbox_role,
    ExpectedManagedCatalog, RegistryStateTestIdentity,
};
use registry_server::runtime_config::load_runtime_config;
use registry_server::startup::{
    prepare_schema_test_database_with_connection_configs_for_test,
    prepare_with_connection_config_for_test, PreparedServer,
};
use serde::Serialize;
use serde_json::json;
use tempfile::TempDir;
use zeroize::Zeroizing;

const PROJECT_TEMPLATE: &[u8] = include_bytes!("fixtures/fixture-tooling/project.yaml");
const MODULE_SOURCE: &[u8] = include_bytes!("fixtures/fixture-tooling/module.yaml");
const JOURNEY_SOURCE: &[u8] = include_bytes!("fixtures/fixture-tooling/journeys.yaml");
const TERMINAL_FAILURE_SOURCE: &[u8] =
    include_bytes!("fixtures/fixture-tooling/terminal-failure.yaml");
const SPATIAL_PROJECT_SOURCE: &[u8] = include_bytes!(
    "../../../products/registry-server/acceptance/spatial-service-sites/registry.yaml"
);
const SPATIAL_MODULE_SOURCE: &[u8] = include_bytes!(
    "../../../products/registry-server/acceptance/spatial-service-sites/modules/spatial-service-sites-core/module.yaml"
);
const SPATIAL_MAP_LABELS_SQL: &[u8] = include_bytes!(
    "../../../products/registry-server/acceptance/spatial-service-sites/modules/spatial-service-sites-core/sql/map-labels.sql"
);
const SPATIAL_JOURNEY_SOURCE: &[u8] = include_bytes!(
    "../../../products/registry-server/acceptance/spatial-service-sites/tests/journeys.yaml"
);
const COMPILER_SOURCE_REVISION: &str = "fixture-project-source";
const DATABASE_ID: &str = "fixture-database";
const INSTANCE_ID: &str = "fixture-instance";
const AUDIENCE: &str = "urn:registry-server:fixture-journeys";
const QUICKSTART_COMPILER_SOURCE_REVISION: &str = "quickstart-source";
const QUICKSTART_DATABASE_ID: &str = "generic-registry-local-db";
const QUICKSTART_INSTANCE_ID: &str = "generic_registry_local";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_test_runs_strict_journeys_through_the_real_postgres_router() {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let (compiled, project_source) = compiled_fixture();
    let registry = Arc::new(compiled);
    let expected_catalog = ExpectedManagedCatalog::compiled(&registry);
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("administrator installs the compiler-owned schema");
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("closed managed schema fingerprint computes");
    let package = package_fixture(&project_source, &schema_fingerprint);
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: &package.package.manifest().package_id,
            environment: &package.package.manifest().environment,
            instance_id: &package.package.manifest().instance_id,
            database_id: &package.package.manifest().database_id,
            package_revision: &package.package.manifest().package_revision,
            package_sequence: 1,
        },
    )
    .await
    .expect("administrator activates the exact verified package identity");
    assert_eq!(identity.schema_fingerprint, schema_fingerprint);
    drop(migration);
    migration_task.abort();

    let idp = MockIdp::start().await;
    let config_path = package.write_runtime_config(&database, &idp);
    let prepared =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .expect("verified startup constructs the authenticated fixture runtime");
    let audit = AuditProfile::production_from_secret_bytes(vec![0x71; 32].into())
        .expect("test audit profile is keyed");

    let suite = validate_fixture_journeys(JOURNEY_SOURCE, &registry).expect("journeys preflight");
    let raw = PreparedServer::from_parts_for_test(
        "127.0.0.1:0".parse().expect("test address parses"),
        Router::new(),
        Duration::from_secs(1),
    );
    assert_eq!(
        prepare_runner(&package, &suite, &raw, successful_tokens(&idp))
            .await
            .err(),
        Some(FixtureError::ExecutionRefused),
        "a raw caller-selected Router cannot obtain fixture runtime provenance"
    );

    let runner = prepare_runner(&package, &suite, &prepared, successful_tokens(&idp))
        .await
        .expect("runner derives exact package and same-database facts");
    let completed = runner
        .run_all()
        .await
        .expect("every journey passes through the prepared HTTP router");
    let receipt = completed
        .build_receipt(&suite)
        .expect("complete real-router journey emits a bound receipt");
    let receipt_bytes = receipt.canonical_bytes().expect("receipt canonicalizes");
    completed
        .revalidate_receipt(&receipt_bytes, &suite)
        .expect("exact real execution facts revalidate the receipt");
    assert_eq!(receipt.successful_journey_ids(), ["widget-lifecycle"]);
    assert!(!format!("{receipt:?}").contains("zone-a"));

    let failure_suite = validate_fixture_journeys(TERMINAL_FAILURE_SOURCE, &registry)
        .expect("terminal-failure journey preflights");
    assert_eq!(
        prepare_runner(
            &package,
            &failure_suite,
            &prepared,
            vec![operator_token(&idp, true), operator_token(&idp, true)],
        )
        .await
        .err(),
        Some(FixtureError::CandidateBindingRefused),
        "a journey suite outside the signed package closure cannot execute"
    );

    assert_exact_durable_journey_outcomes(&database, &registry, &audit).await;
    drop(prepared);
    idp.stop().await;
    drop(package);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_schema_test_executor_uses_only_prepared_database_and_private_credentials() {
    let (compiled, project_source) = compiled_fixture();
    let schema_fingerprint = measure_compiled_schema_fingerprint(&compiled).await;
    let package = package_fixture(&project_source, &schema_fingerprint);
    let suite = validate_fixture_journeys(JOURNEY_SOURCE, &compiled).expect("journeys preflight");
    let failure_suite = validate_fixture_journeys(TERMINAL_FAILURE_SOURCE, &compiled)
        .expect("terminal failure journey preflights");
    let idp = MockIdp::start().await;

    let first = TestDatabase::create(8).await;
    let first_config_path = package.write_runtime_config(&first, &idp);
    let first_config =
        load_runtime_config(&first_config_path).expect("strict runtime config loads");
    let first_database = prepare_schema_test_database_with_connection_configs_for_test(
        &first_config,
        &package.prepared,
        &first.migration_config,
        &first.runtime_config,
    )
    .await
    .expect("clean pre-provisioned database prepares");
    let first_receipt = execute_schema_test(
        first_database,
        &first_config,
        &package.prepared,
        &suite,
        successful_credential_bindings(&suite, &idp),
    )
    .await
    .expect("production executor dispatches validated journeys");
    assert_eq!(first_receipt.successful_journey_ids(), ["widget-lifecycle"]);
    let first_bytes = first_receipt
        .canonical_bytes()
        .expect("receipt canonicalizes");
    let first_value: serde_json::Value =
        serde_json::from_slice(&first_bytes).expect("receipt JSON parses");
    validate_schema_test_receipt_for_package(&first_bytes, &package.prepared, &suite)
        .expect("real PostgreSQL receipt revalidates against the exact unsigned package");
    assert!(first_value.get("registryRevision").is_some());
    assert!(first_value.get("candidatePackageRevision").is_some());
    assert!(first_value.get("signingInputSha256").is_some());
    assert!(first_value.get("currentDatabase").is_none());
    assert!(first_value.get("executionBinding").is_none());

    let second = TestDatabase::create(8).await;
    let second_config_path = package.write_runtime_config(&second, &idp);
    let second_config =
        load_runtime_config(&second_config_path).expect("second strict runtime config loads");
    let second_database = prepare_schema_test_database_with_connection_configs_for_test(
        &second_config,
        &package.prepared,
        &second.migration_config,
        &second.runtime_config,
    )
    .await
    .expect("second physical database prepares");
    let second_receipt = execute_schema_test(
        second_database,
        &second_config,
        &package.prepared,
        &suite,
        successful_credential_bindings(&suite, &idp),
    )
    .await
    .expect("second production execution succeeds");
    assert_eq!(
        first_bytes,
        second_receipt
            .canonical_bytes()
            .expect("second receipt canonicalizes"),
        "receipt must not bind to physical database or role names"
    );

    let dirty = TestDatabase::create(8).await;
    dirty
        .admin
        .batch_execute("CREATE TABLE registry_data.existing_managed_object(id bigint)")
        .await
        .expect("administrator can create a dirty managed object");
    let dirty_config_path = package.write_runtime_config(&dirty, &idp);
    let dirty_config = load_runtime_config(&dirty_config_path).expect("dirty runtime config loads");
    assert!(
        prepare_schema_test_database_with_connection_configs_for_test(
            &dirty_config,
            &package.prepared,
            &dirty.migration_config,
            &dirty.runtime_config,
        )
        .await
        .is_err(),
        "candidate DDL must not run against a nonempty managed database"
    );

    let wrong_role = TestDatabase::create(8).await;
    let wrong_role_config_path = package.write_runtime_config(&wrong_role, &idp);
    let wrong_role_config =
        load_runtime_config(&wrong_role_config_path).expect("wrong-role runtime config loads");
    assert!(
        prepare_schema_test_database_with_connection_configs_for_test(
            &wrong_role_config,
            &package.prepared,
            &wrong_role.runtime_config,
            &wrong_role.runtime_config,
        )
        .await
        .is_err(),
        "runtime role cannot stand in for the migration role"
    );

    let claim_mismatch = TestDatabase::create(8).await;
    let claim_mismatch_config_path = package.write_runtime_config(&claim_mismatch, &idp);
    let claim_mismatch_config = load_runtime_config(&claim_mismatch_config_path)
        .expect("claim-mismatch runtime config loads");
    let claim_mismatch_database = prepare_schema_test_database_with_connection_configs_for_test(
        &claim_mismatch_config,
        &package.prepared,
        &claim_mismatch.migration_config,
        &claim_mismatch.runtime_config,
    )
    .await
    .expect("claim-mismatch database prepares");
    assert_eq!(
        execute_schema_test(
            claim_mismatch_database,
            &claim_mismatch_config,
            &package.prepared,
            &suite,
            overprivileged_credential_bindings(&suite, &idp),
        )
        .await
        .unwrap_err(),
        FixtureError::StepFailed {
            journey_index: 0,
            step_index: 0,
            error: Box::new(FixtureError::AuthorityWideningRefused),
        }
    );

    let substituted = TestDatabase::create(8).await;
    let substituted_config_path = package.write_runtime_config(&substituted, &idp);
    let substituted_config =
        load_runtime_config(&substituted_config_path).expect("substituted runtime config loads");
    let substituted_database = prepare_schema_test_database_with_connection_configs_for_test(
        &substituted_config,
        &package.prepared,
        &substituted.migration_config,
        &substituted.runtime_config,
    )
    .await
    .expect("substitution database prepares");
    let other_package = package_fixture(&project_source, &schema_fingerprint);
    assert_eq!(
        execute_schema_test(
            substituted_database,
            &substituted_config,
            &other_package.prepared,
            &suite,
            successful_credential_bindings(&suite, &idp),
        )
        .await
        .unwrap_err(),
        FixtureError::CandidateBindingRefused
    );

    let terminal_package = package_fixture_with_journeys(
        &project_source,
        &schema_fingerprint,
        TERMINAL_FAILURE_SOURCE,
    );
    let terminal = TestDatabase::create(8).await;
    let terminal_config_path = terminal_package.write_runtime_config(&terminal, &idp);
    let terminal_config =
        load_runtime_config(&terminal_config_path).expect("terminal runtime config loads");
    let terminal_database = prepare_schema_test_database_with_connection_configs_for_test(
        &terminal_config,
        &terminal_package.prepared,
        &terminal.migration_config,
        &terminal.runtime_config,
    )
    .await
    .expect("terminal database prepares");
    assert_eq!(
        execute_schema_test(
            terminal_database,
            &terminal_config,
            &terminal_package.prepared,
            &failure_suite,
            terminal_failure_credential_bindings(&failure_suite, &idp),
        )
        .await
        .unwrap_err(),
        FixtureError::StepFailed {
            journey_index: 0,
            step_index: 1,
            error: Box::new(FixtureError::ResponseStatusMismatch {
                expected: 201,
                actual: 409,
            }),
        }
    );

    first.cleanup().await;
    second.cleanup().await;
    dirty.cleanup().await;
    wrong_role.cleanup().await;
    claim_mismatch.cleanup().await;
    substituted.cleanup().await;
    terminal.cleanup().await;
    idp.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_spatial_fixture_schema_test_runs_through_the_production_executor() {
    let (compiled, project_source) = compiled_spatial_fixture();
    let schema_fingerprint = measure_spatial_compiled_schema_fingerprint(&compiled).await;
    let package = spatial_package_fixture(&project_source, &schema_fingerprint);
    let suite =
        validate_fixture_journeys(SPATIAL_JOURNEY_SOURCE, &compiled).expect("journeys preflight");
    let idp = MockIdp::start().await;

    let database = TestDatabase::create(8).await;
    provision_postgis_prerequisites(
        &database.admin,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("administrator provisions spatial schema-test prerequisites");
    let config_path = package.write_spatial_runtime_config(&database, &idp);
    let config = load_runtime_config(&config_path).expect("spatial runtime config loads");
    let schema_test_database = prepare_schema_test_database_with_connection_configs_for_test(
        &config,
        &package.prepared,
        &database.migration_config,
        &database.runtime_config,
    )
    .await
    .expect("spatial schema-test database prepares");

    let receipt = execute_schema_test(
        schema_test_database,
        &config,
        &package.prepared,
        &suite,
        spatial_credential_bindings(&suite, &idp),
    )
    .await
    .expect("public spatial fixture schema-test succeeds");
    assert_eq!(
        receipt.successful_journey_ids(),
        ["service-site-source-profile-smoke"]
    );

    cleanup_spatial_prerequisites(&database).await;
    database.cleanup().await;
    idp.stop().await;
}

async fn prepare_runner(
    package: &PackageFixture,
    suite: &registry_server::fixtures::ValidatedFixtureJourneys,
    prepared: &PreparedServer,
    bearer_tokens: Vec<String>,
) -> Result<PostgresFixtureTestRunner, FixtureError> {
    let modules = [FixtureModuleSource {
        id: "fixture-core",
        path: "sources/modules/fixture-core.yaml",
        bytes: MODULE_SOURCE,
        assets: &[],
    }];
    PostgresFixtureTestRunner::prepare(
        &package.package,
        &SchemaTestSources {
            project: FixtureSourceFile {
                path: "sources/project.yaml",
                bytes: &package.project,
            },
            project_assets: &[],
            modules: &modules,
            migration_plan: FixtureSourceFile {
                path: "database/migration-plan.json",
                bytes: &package.migration_plan,
            },
        },
        suite,
        prepared,
        bearer_tokens,
    )
    .await
}

async fn assert_exact_durable_journey_outcomes(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    audit: &AuditProfile,
) {
    let table = &registry.physical_names().entities["widget"].table;
    let fields = &registry.physical_names().entities["widget"].fields;
    let quoted = |value: &str| format!("\"{}\"", value.replace('"', "\"\""));
    let rows = database
        .admin
        .query(
            &format!(
                "SELECT {label}, {note}, {quantity}, record_revision, record_lifecycle
                   FROM registry_data.{table}
                  ORDER BY {label}",
                label = quoted(&fields["label"]),
                note = quoted(&fields["note"]),
                quantity = quoted(&fields["quantity"]),
                table = quoted(table),
            ),
            &[],
        )
        .await
        .expect("administrator inspects exact current records");
    assert_eq!(rows.len(), 3);
    let current = rows
        .iter()
        .map(|row| {
            (
                row.get::<_, String>(0),
                row.get::<_, Option<String>>(1),
                row.get::<_, i64>(2),
                row.get::<_, i64>(3),
                row.get::<_, String>(4),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        current,
        vec![
            (
                "first".to_owned(),
                Some("revised".to_owned()),
                1,
                2,
                "active".to_owned()
            ),
            ("second".to_owned(), None, 2, 1, "active".to_owned()),
            ("third".to_owned(), None, 3, 1, "active".to_owned()),
        ]
    );

    let counts = database
        .admin
        .query_one(
            "SELECT
                 (SELECT count(*) FROM registry_internal.registry_revisions),
                 (SELECT count(*) FROM registry_internal.registry_revisions
                   WHERE mutation_kind = 'create'),
                 (SELECT count(*) FROM registry_internal.registry_revisions
                   WHERE mutation_kind = 'patch'),
                 (SELECT count(*) FROM registry_internal.registry_idempotency),
                 (SELECT count(*) FROM registry_internal.registry_idempotency
                   WHERE result_kind = 'record'),
                 (SELECT count(*) FROM registry_internal.registry_idempotency
                   WHERE result_kind = 'batch' AND result_count = 2),
                 (SELECT count(*) FROM registry_internal.registry_idempotency
                   WHERE response_status = 201),
                 (SELECT count(*) FROM registry_internal.registry_idempotency
                   WHERE response_status = 200),
                 (SELECT count(*) FROM registry_internal.registry_outbox),
                 (SELECT count(*) FROM registry_internal.registry_audit)",
            &[],
        )
        .await
        .expect("administrator inspects exact durable counts");
    assert_eq!(counts.get::<_, i64>(0), 4);
    assert_eq!(counts.get::<_, i64>(1), 3);
    assert_eq!(counts.get::<_, i64>(2), 1);
    assert_eq!(counts.get::<_, i64>(3), 3);
    assert_eq!(counts.get::<_, i64>(4), 2);
    assert_eq!(counts.get::<_, i64>(5), 1);
    assert_eq!(counts.get::<_, i64>(6), 1);
    assert_eq!(counts.get::<_, i64>(7), 2);
    assert_eq!(counts.get::<_, i64>(8), 0);
    assert_eq!(counts.get::<_, i64>(9), 11);

    let audit_rows = database
        .admin
        .query(
            "SELECT record_hash, envelope FROM registry_internal.registry_audit",
            &[],
        )
        .await
        .expect("administrator reads the closed audit chain");
    let mut by_previous = BTreeMap::<Option<[u8; 32]>, AuditEnvelope>::new();
    for row in audit_rows {
        let stored =
            <[u8; 32]>::try_from(row.get::<_, Vec<u8>>(0)).expect("stored audit hash is exact");
        let envelope: AuditEnvelope = serde_json::from_slice(&row.get::<_, Vec<u8>>(1))
            .expect("audit envelope is strict JSON");
        assert_eq!(stored, envelope.record_hash);
        assert!(by_previous.insert(envelope.prev_hash, envelope).is_none());
    }
    let mut ordered = Vec::new();
    let mut prior = None;
    while let Some(envelope) = by_previous.remove(&prior) {
        prior = Some(envelope.record_hash);
        ordered.push(envelope);
    }
    assert!(by_previous.is_empty());
    assert_eq!(ordered.len(), 11);
    verify_chain(&ordered, &audit.chain_hasher()).expect("keyed audit chain verifies exactly");
    let phases = ordered
        .iter()
        .fold(BTreeMap::<&str, usize>::new(), |mut counts, envelope| {
            let phase = envelope.record["phase"]
                .as_str()
                .expect("audit phase is closed");
            *counts.entry(phase).or_default() += 1;
            counts
        });
    assert_eq!(
        phases,
        BTreeMap::from([("attempt", 5), ("refusal", 1), ("terminal", 5)])
    );
    let audit_bytes = serde_json::to_vec(&ordered).expect("audit inspection serializes");
    let audit_text = String::from_utf8(audit_bytes).expect("audit inspection is UTF-8");
    for canary in ["fixture-operator", "zone-a", "terminal-first"] {
        assert!(!audit_text.contains(canary));
    }

    let head = database
        .admin
        .query_one(
            "SELECT last_hash FROM registry_internal.registry_audit_head WHERE singleton",
            &[],
        )
        .await
        .expect("audit head exists")
        .get::<_, Vec<u8>>(0);
    assert_eq!(head, ordered.last().unwrap().record_hash);
}

struct PackageFixture {
    _root: TempDir,
    directory: PathBuf,
    package_root: PathBuf,
    anchor: PathBuf,
    revision: String,
    prepared: PreparedPackage,
    package: VerifiedPackage,
    project: Vec<u8>,
    migration_plan: Vec<u8>,
}

fn package_fixture(project: &[u8], schema_fingerprint: &str) -> PackageFixture {
    package_fixture_with_journeys(project, schema_fingerprint, JOURNEY_SOURCE)
}

fn package_fixture_with_journeys(
    project: &[u8],
    schema_fingerprint: &str,
    journey_source: &[u8],
) -> PackageFixture {
    let signing =
        generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("package signing key generates");
    let key_id = signing.public().kid.expect("package signing key has an id");
    let prepared = prepare_package(PackageBuildRequest {
        environment: "production".to_owned(),
        instance_id: INSTANCE_ID.to_owned(),
        database_id: DATABASE_ID.to_owned(),
        sequence: 1,
        prior_revision: None,
        compiler_source_revision: COMPILER_SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 1,
            key_ids: vec![key_id.clone()],
        },
        project: PackageSourceFile {
            path: "sources/project.yaml".to_owned(),
            bytes: project.to_vec(),
        },
        modules: vec![PackageModuleSource {
            id: "fixture-core".to_owned(),
            path: "sources/modules/fixture-core.yaml".to_owned(),
            bytes: MODULE_SOURCE.to_vec(),
            assets: Vec::new(),
        }],
        fixture_journeys: PackageSourceFile {
            path: FIXTURE_JOURNEYS_PATH.to_owned(),
            bytes: journey_source.to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
    .expect("fixture package prepares");
    let migration_plan = prepared
        .file_bytes()
        .get("database/migration-plan.json")
        .expect("prepared package includes migration plan")
        .clone();
    let root = tempfile::tempdir().expect("temporary package root creates");
    let directory = root
        .path()
        .canonicalize()
        .expect("temporary package root canonicalizes");
    let package_root = directory.join("package");
    let revision = prepared.package_revision().to_owned();
    let signature =
        sign(prepared.canonical_signed_bytes(), &signing).expect("package canonical bytes sign");
    prepared
        .publish_to_directory(
            &package_root,
            vec![PackageSignature {
                key_id: key_id.clone(),
                signature_hex: hex(&signature),
            }],
        )
        .expect("Production package publishes");
    let anchor = directory.join("trust-anchor.json");
    write_json(
        &anchor,
        &PackageTrustAnchor {
            api_version: TRUST_ANCHOR_API_VERSION.to_owned(),
            environment: "production".to_owned(),
            instance_id: INSTANCE_ID.to_owned(),
            database_id: DATABASE_ID.to_owned(),
            threshold: 1,
            keys: vec![TrustAnchorKey {
                key_id,
                jwk: serde_json::to_value(signing.public()).expect("public JWK serializes"),
            }],
        },
    );
    let package = load_package(
        &package_root,
        &PackageLoadContext {
            environment: "production",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            database_initialization_environment: "production",
            compiler_source_revision: COMPILER_SOURCE_REVISION,
            trust_anchor: Some(&anchor),
            intent: PackageIntent::InitialActivation,
        },
    )
    .expect("package closure rederives into VerifiedPackage");
    PackageFixture {
        _root: root,
        directory,
        package_root,
        anchor,
        revision,
        prepared,
        package,
        project: project.to_vec(),
        migration_plan,
    }
}

fn spatial_package_fixture(project: &[u8], schema_fingerprint: &str) -> PackageFixture {
    let prepared = prepare_package(PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: QUICKSTART_INSTANCE_ID.to_owned(),
        database_id: QUICKSTART_DATABASE_ID.to_owned(),
        sequence: 1,
        prior_revision: None,
        compiler_source_revision: QUICKSTART_COMPILER_SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
        project: PackageSourceFile {
            path: "sources/project.yaml".to_owned(),
            bytes: project.to_vec(),
        },
        modules: vec![PackageModuleSource {
            id: "spatial-service-sites-core".to_owned(),
            path: "sources/modules/spatial-service-sites-core/module.yaml".to_owned(),
            bytes: SPATIAL_MODULE_SOURCE.to_vec(),
            assets: vec![PackageSourceFile {
                path: "sql/map-labels.sql".to_owned(),
                bytes: SPATIAL_MAP_LABELS_SQL.to_vec(),
            }],
        }],
        fixture_journeys: PackageSourceFile {
            path: FIXTURE_JOURNEYS_PATH.to_owned(),
            bytes: SPATIAL_JOURNEY_SOURCE.to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
    .expect("spatial package prepares");
    let migration_plan = prepared
        .file_bytes()
        .get("database/migration-plan.json")
        .expect("prepared package includes migration plan")
        .clone();
    let root = tempfile::tempdir().expect("temporary package root creates");
    let directory = root
        .path()
        .canonicalize()
        .expect("temporary package root canonicalizes");
    let package_root = directory.join("package");
    let revision = prepared.package_revision().to_owned();
    prepared
        .publish_to_directory(&package_root, Vec::new())
        .expect("local spatial package publishes");
    let anchor = directory.join("trust-anchor.json");
    let package = load_package(
        &package_root,
        &PackageLoadContext {
            environment: "local",
            instance_id: QUICKSTART_INSTANCE_ID,
            database_id: QUICKSTART_DATABASE_ID,
            database_initialization_environment: "local",
            compiler_source_revision: QUICKSTART_COMPILER_SOURCE_REVISION,
            trust_anchor: None,
            intent: PackageIntent::InitialActivation,
        },
    )
    .expect("spatial package closure rederives into VerifiedPackage");
    PackageFixture {
        _root: root,
        directory,
        package_root,
        anchor,
        revision,
        prepared,
        package,
        project: project.to_vec(),
        migration_plan,
    }
}

impl PackageFixture {
    fn write_runtime_config(&self, database: &TestDatabase, idp: &MockIdp) -> PathBuf {
        let secrets = self.directory.join("secrets");
        fs::create_dir_all(&secrets).expect("fixture secret root creates");
        write_private(&secrets.join("database-url"), b"unused-by-test-startup");
        write_private(&secrets.join("audit-key"), &[0x71; 32]);
        write_private(&secrets.join("cursor-key"), &[0x52; 32]);
        write_private(
            &secrets.join("oidc-jwks"),
            &serde_json::to_vec(&jwks_from_private_jwk(
                &PrivateJwk::parse(testing_fixtures::ED25519_PRIVATE_JWK)
                    .expect("test IdP key parses"),
            ))
            .expect("static JWKS serializes"),
        );
        let path = self.directory.join("runtime.yaml");
        fs::write(
            &path,
            format!(
                r#"apiVersion: registry.registrystack.org/server-runtime/v1alpha1
kind: RegistryServerRuntimeConfig
listener:
  bind: 127.0.0.1:9
identity:
  environment: production
  instanceId: {INSTANCE_ID}
  databaseId: {DATABASE_ID}
  databaseInitializationEnvironment: production
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 8
    waitTimeoutMilliseconds: 2000
    createTimeoutMilliseconds: 2000
    recycleTimeoutMilliseconds: 2000
  roles:
    migration: {}
    runtime: {}
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: {COMPILER_SOURCE_REVISION}
  activeRevision: {}
  activeSequence: 1
authentication:
  oidc:
    issuer: {}
    audience: {AUDIENCE}
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    maxTokenLifetimeSeconds: 3600
    leewayMilliseconds: 60000
    jwksSource:
      kind: static
      documentRef: secret:file/oidc-jwks
    jwksCache:
      cacheTtlSeconds: 60
      negativeCacheTtlSeconds: 1
      refreshCooldownSeconds: 1
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 0
  authorityClaims:
    principal: registry_principal
    purpose: purpose
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
operationalTimeouts:
  httpRequestMilliseconds: 5000
  shutdownGraceMilliseconds: 1000
  recordLockMilliseconds: 2000
  migrationLockMilliseconds: 2000
  migrationStatementMilliseconds: 5000
"#,
                secrets.display(),
                database.migration_role.as_str(),
                database.runtime_role.as_str(),
                self.package_root.display(),
                self.anchor.display(),
                self.revision,
                idp.issuer(),
            ),
        )
        .expect("strict fixture runtime configuration writes");
        set_private_permissions(&path);
        path
    }

    fn write_spatial_runtime_config(&self, database: &TestDatabase, idp: &MockIdp) -> PathBuf {
        let secrets = self.directory.join("secrets");
        fs::create_dir_all(&secrets).expect("fixture secret root creates");
        write_private(&secrets.join("database-url"), b"unused-by-test-startup");
        write_private(&secrets.join("audit-key"), &[0x71; 32]);
        write_private(&secrets.join("cursor-key"), &[0x52; 32]);
        write_private(
            &secrets.join("oidc-jwks"),
            &serde_json::to_vec(&jwks_from_private_jwk(
                &PrivateJwk::parse(testing_fixtures::ED25519_PRIVATE_JWK)
                    .expect("test IdP key parses"),
            ))
            .expect("static JWKS serializes"),
        );
        let path = self.directory.join("runtime-spatial.yaml");
        fs::write(
            &path,
            format!(
                r#"apiVersion: registry.registrystack.org/server-runtime/v1alpha1
kind: RegistryServerRuntimeConfig
listener:
  bind: 127.0.0.1:9
identity:
  environment: local
  instanceId: {QUICKSTART_INSTANCE_ID}
  databaseId: {QUICKSTART_DATABASE_ID}
  databaseInitializationEnvironment: local
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 8
    waitTimeoutMilliseconds: 2000
    createTimeoutMilliseconds: 2000
    recycleTimeoutMilliseconds: 2000
  roles:
    migration: {}
    runtime: {}
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: {QUICKSTART_COMPILER_SOURCE_REVISION}
  activeRevision: {}
  activeSequence: 1
authentication:
  oidc:
    issuer: {}
    audience: {AUDIENCE}
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    maxTokenLifetimeSeconds: 3600
    leewayMilliseconds: 60000
    jwksSource:
      kind: static
      documentRef: secret:file/oidc-jwks
    jwksCache:
      cacheTtlSeconds: 60
      negativeCacheTtlSeconds: 1
      refreshCooldownSeconds: 1
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 0
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
operationalTimeouts:
  httpRequestMilliseconds: 5000
  shutdownGraceMilliseconds: 1000
  recordLockMilliseconds: 2000
  migrationLockMilliseconds: 2000
  migrationStatementMilliseconds: 5000
"#,
                secrets.display(),
                database.migration_role.as_str(),
                database.runtime_role.as_str(),
                self.package_root.display(),
                self.anchor.display(),
                self.revision,
                idp.issuer(),
            ),
        )
        .expect("strict spatial fixture runtime configuration writes");
        set_private_permissions(&path);
        path
    }
}

fn successful_tokens(idp: &MockIdp) -> Vec<String> {
    let mut tokens = (0..5)
        .map(|_| operator_token(idp, true))
        .collect::<Vec<_>>();
    tokens.push(operator_token(idp, false));
    tokens
}

fn successful_credential_bindings(
    suite: &registry_server::fixtures::ValidatedFixtureJourneys,
    idp: &MockIdp,
) -> SchemaTestCredentialBindings {
    credential_bindings_for_tokens(
        suite,
        [
            (
                "widget-lifecycle",
                "create-widget",
                operator_token(idp, true),
            ),
            ("widget-lifecycle", "get-widget", operator_token(idp, true)),
            (
                "widget-lifecycle",
                "list-widgets",
                operator_token(idp, true),
            ),
            (
                "widget-lifecycle",
                "patch-widget",
                operator_token(idp, true),
            ),
            (
                "widget-lifecycle",
                "batch-create-widgets",
                operator_token(idp, true),
            ),
            (
                "widget-lifecycle",
                "concealed-without-purpose",
                operator_token(idp, false),
            ),
        ],
    )
}

fn spatial_credential_bindings(
    suite: &registry_server::fixtures::ValidatedFixtureJourneys,
    idp: &MockIdp,
) -> SchemaTestCredentialBindings {
    SchemaTestCredentialBindings::new(
        suite,
        vec![
            SchemaTestCredentialBinding::bearer(
                "service-site-source-profile-smoke",
                "create-central-service-site",
                Zeroizing::new(spatial_admin_token(idp)),
            ),
            SchemaTestCredentialBinding::bearer(
                "service-site-source-profile-smoke",
                "create-null-geometry-service-site",
                Zeroizing::new(spatial_admin_token(idp)),
            ),
            SchemaTestCredentialBinding::bearer(
                "service-site-source-profile-smoke",
                "create-edge-service-site",
                Zeroizing::new(spatial_admin_token(idp)),
            ),
            SchemaTestCredentialBinding::anonymous(
                "service-site-source-profile-smoke",
                "public-map-reader-lists-public-point-fields",
            ),
            SchemaTestCredentialBinding::anonymous(
                "service-site-source-profile-smoke",
                "public-map-reader-bbox-finds-central-site",
            ),
            SchemaTestCredentialBinding::anonymous(
                "service-site-source-profile-smoke",
                "directory-reader-lists-without-geometry",
            ),
            SchemaTestCredentialBinding::anonymous(
                "service-site-source-profile-smoke",
                "directory-reader-bbox-is-refused",
            ),
            SchemaTestCredentialBinding::bearer(
                "service-site-source-profile-smoke",
                "installation-client-sees-own-central-row",
                Zeroizing::new(spatial_map_token(idp)),
            ),
            SchemaTestCredentialBinding::bearer(
                "service-site-source-profile-smoke",
                "installation-client-cannot-see-other-installation-row",
                Zeroizing::new(spatial_map_token(idp)),
            ),
            SchemaTestCredentialBinding::bearer(
                "service-site-source-profile-smoke",
                "hidden-geometry-profile-gets-directory-fields",
                Zeroizing::new(spatial_directory_token(idp)),
            ),
            SchemaTestCredentialBinding::bearer(
                "service-site-source-profile-smoke",
                "get-only-profile-gets-site",
                Zeroizing::new(spatial_site_token(idp)),
            ),
            SchemaTestCredentialBinding::bearer(
                "service-site-source-profile-smoke",
                "admin-refuses-coordinate-outside-authored-bounds",
                Zeroizing::new(spatial_admin_token(idp)),
            ),
        ],
    )
    .expect("spatial credential bindings match validated journeys")
}

fn overprivileged_credential_bindings(
    suite: &registry_server::fixtures::ValidatedFixtureJourneys,
    idp: &MockIdp,
) -> SchemaTestCredentialBindings {
    let mut overprivileged = json!({
        "aud": AUDIENCE,
        "registry_principal": "fixture-operator",
        "jurisdiction": "zone-a",
        "purpose": "case-management",
        "scope": "registry-admin"
    });
    credential_bindings_for_tokens(
        suite,
        [
            (
                "widget-lifecycle",
                "create-widget",
                idp.mint_token(overprivileged.take()),
            ),
            ("widget-lifecycle", "get-widget", operator_token(idp, true)),
            (
                "widget-lifecycle",
                "list-widgets",
                operator_token(idp, true),
            ),
            (
                "widget-lifecycle",
                "patch-widget",
                operator_token(idp, true),
            ),
            (
                "widget-lifecycle",
                "batch-create-widgets",
                operator_token(idp, true),
            ),
            (
                "widget-lifecycle",
                "concealed-without-purpose",
                operator_token(idp, false),
            ),
        ],
    )
}

fn terminal_failure_credential_bindings(
    suite: &registry_server::fixtures::ValidatedFixtureJourneys,
    idp: &MockIdp,
) -> SchemaTestCredentialBindings {
    credential_bindings_for_tokens(
        suite,
        [
            (
                "terminal-failure",
                "create-terminal-record",
                operator_token(idp, true),
            ),
            (
                "terminal-failure",
                "duplicate-terminal-record",
                operator_token(idp, true),
            ),
        ],
    )
}

fn credential_bindings_for_tokens<const N: usize>(
    suite: &registry_server::fixtures::ValidatedFixtureJourneys,
    tokens: [(&'static str, &'static str, String); N],
) -> SchemaTestCredentialBindings {
    SchemaTestCredentialBindings::new(
        suite,
        tokens
            .into_iter()
            .map(|(journey, step, token)| {
                SchemaTestCredentialBinding::bearer(journey, step, Zeroizing::new(token))
            })
            .collect(),
    )
    .expect("credential bindings match validated journeys")
}

fn operator_token(idp: &MockIdp, purpose: bool) -> String {
    let mut claims = json!({
        "aud": AUDIENCE,
        "registry_principal": "fixture-operator",
        "jurisdiction": "zone-a",
    });
    if purpose {
        claims["purpose"] = json!("case-management");
    }
    idp.mint_token(claims)
}

fn spatial_admin_token(idp: &MockIdp) -> String {
    idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": "synthetic-service-site-admin",
        "registry_purpose": "service-site-administration",
        "scope": "service-sites:seed",
    }))
}

fn spatial_map_token(idp: &MockIdp) -> String {
    idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": "synthetic-qgis-installation",
        "registry_purpose": "service-site-map",
        "scope": "service-sites:map.read",
        "service_zones": "central",
    }))
}

fn spatial_directory_token(idp: &MockIdp) -> String {
    idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": "synthetic-directory-reader",
        "registry_purpose": "service-site-directory",
        "scope": "service-sites:directory.read",
    }))
}

fn spatial_site_token(idp: &MockIdp) -> String {
    idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": "synthetic-site-reader",
        "registry_purpose": "service-site-map",
        "scope": "service-sites:site.read",
    }))
}

async fn measure_compiled_schema_fingerprint(
    registry: &registry_server::CompiledRegistry,
) -> String {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    let expected_catalog = ExpectedManagedCatalog::compiled(registry);
    install_compiled_schema(&migration, registry, &database.runtime_role)
        .await
        .expect("administrator installs candidate schema for fingerprinting");
    let fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("candidate schema fingerprint computes");
    drop(migration);
    migration_task.abort();
    database.cleanup().await;
    fingerprint
}

async fn measure_spatial_compiled_schema_fingerprint(
    registry: &registry_server::CompiledRegistry,
) -> String {
    let database = TestDatabase::create(2).await;
    let bbox_role = provision_postgis_prerequisites(
        &database.admin,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("administrator provisions PostGIS prerequisites");
    let (migration, migration_task) = database.connect_migration().await;
    let expected_catalog = ExpectedManagedCatalog::compiled(registry);
    install_compiled_schema(&migration, registry, &database.runtime_role)
        .await
        .expect("administrator installs spatial candidate schema for fingerprinting");
    let fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("spatial candidate schema fingerprint computes");
    drop(migration);
    migration_task.abort();
    cleanup_bbox_role(&database, &bbox_role).await;
    database.cleanup().await;
    fingerprint
}

async fn cleanup_spatial_prerequisites(database: &TestDatabase) {
    let bbox_role = spatial_bbox_role(&database.runtime_role);
    cleanup_bbox_role(database, &bbox_role).await;
}

async fn cleanup_bbox_role(
    database: &TestDatabase,
    bbox_role: &registry_server::postgres::SqlIdentifier,
) {
    database
        .admin
        .batch_execute(&format!(
            "DROP OWNED BY {};
             REVOKE {} FROM {};
             DROP ROLE IF EXISTS {};",
            quote_identifier(bbox_role.as_str()),
            quote_identifier(bbox_role.as_str()),
            quote_identifier(database.migration_role.as_str()),
            quote_identifier(bbox_role.as_str()),
        ))
        .await
        .expect("spatial bbox role cleanup succeeds");
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn write_json(path: &Path, value: &impl Serialize) {
    let bytes = canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes");
    write_private(path, &bytes);
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("private fixture file writes");
    set_private_permissions(path);
}

fn set_private_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("private fixture permissions set");
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn compiled_fixture() -> (registry_server::CompiledRegistry, Vec<u8>) {
    let module = parse_module_yaml(MODULE_SOURCE).expect("module fixture parses");
    let project_source = String::from_utf8(PROJECT_TEMPLATE.to_vec())
        .expect("project fixture is UTF-8")
        .replace("MODULE_DIGEST", &module_digest(&module))
        .replace("environment: local", "environment: production")
        .into_bytes();
    let project = parse_project_yaml(&project_source).expect("project fixture parses");
    let registry = compile_project(&project, &[module], CompileProfile::Production)
        .expect("fixture project compiles in Production");
    (registry, project_source)
}

fn compiled_spatial_fixture() -> (registry_server::CompiledRegistry, Vec<u8>) {
    let module = parse_module_yaml(SPATIAL_MODULE_SOURCE).expect("spatial module fixture parses");
    let assets = vec![ModuleAssetSource {
        module: Some("spatial-service-sites-core".to_owned()),
        path: "sql/map-labels.sql".to_owned(),
        bytes: SPATIAL_MAP_LABELS_SQL.to_vec(),
    }];
    let project_source = String::from_utf8(SPATIAL_PROJECT_SOURCE.to_vec())
        .expect("spatial project fixture is UTF-8")
        .replace(
            "  environment: acceptance\n  instanceId: spatial-service-sites-acceptance\n  sequence: 1\n  sourceRevision: spatial-service-sites-acceptance-0.1.0\n",
            "  environment: local\n  instanceId: generic_registry_local\n  sequence: 1\n  sourceRevision: quickstart-source\n",
        )
        .replace(
            "    digest: \"sha256:f00b23dadbd5b3fe5bdd447f7b735381017c367bc177f43e5c429f85838e2725\"",
            &format!("    digest: \"{}\"", module_digest_with_assets(&module, &assets)),
        )
        .into_bytes();
    let project = parse_project_yaml(&project_source).expect("spatial project fixture parses");
    let registry =
        compile_project_with_assets(&project, &[module], &assets, CompileProfile::Production)
            .expect("spatial fixture project compiles in Production");
    (registry, project_source)
}
