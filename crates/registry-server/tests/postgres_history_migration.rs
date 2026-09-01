// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling", unix))]

#[allow(dead_code)]
#[path = "support/postgres_harness.rs"]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, Response, StatusCode};

use postgres_harness::TestDatabase;
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::canonicalize_json;
use registry_server::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedRequestClaims,
};
use registry_server::compiler::{compile_project, module_digest, CompileProfile};
use registry_server::contract::{parse_module_json, parse_project_yaml};
use registry_server::cursor::CursorCodec;
use registry_server::history_schema::HistorySchemaDescriptor;
use registry_server::migration::{
    apply_verified_package, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest, MigrationError,
};
use registry_server::migration_plan::{
    AffectedRowBounds, ArtifactDigestBinding, MigrationRehearsalReceipt, RehearsalFixture,
    RehearsalProofs, RehearsalRowAssertion, ReviewedChangeCover,
    ReviewedMigrationAssertionDescriptor, ReviewedMigrationDescriptor, ReviewedMigrationFile,
    ReviewedMigrationObject, ReviewedMigrationObjectKind, ReviewedMigrationRecovery,
    ReviewedMigrationSource, ReviewedMigrationStepDescriptor,
};
use registry_server::package::{
    compiled_registry_change_set, load_package, prepare_package, CompiledRegistryChangeClass,
    CompiledRegistryChangeCode, PackageBuildRequest, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile, SignaturePolicy,
    VerifiedPackage,
};
use registry_server::postgres::{
    initialize_registry_state_for_catalog_test, install_compiled_schema,
    managed_schema_fingerprint, ExpectedManagedCatalog, ExpectedRegistryIdentity,
    PostgresRecordMutationService, PostgresRecordReadService, PostgresRevisionReadService,
    RegistryLockKey, RegistryStateTestIdentity,
};
use registry_server::CompiledRegistry;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "history-migration-registry";
const INSTANCE_ID: &str = "history-migration-instance";
const DATABASE_ID: &str = "history-migration-database";
const SOURCE_REVISION: &str = "history-migration-source-revision";
const BASE_PACKAGE_REVISION: &str = "history-migration-base-1";
const RECORD_REFERENCE: &str =
    "hmac-sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ACTOR_REFERENCE: &str =
    "hmac-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REQUEST_REFERENCE: &str =
    "hmac-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const MIGRATION_SYSTEM_ORIGIN: &str = "registry-server-reviewed-migration-v1";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: asset-list
    steps:
      - id: list-assets
        entity: asset
        accessProfile: reader
        claims: {principal: package-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_update_establishes_existing_baseline_and_appends_migration_revision() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs required extension");
    let base = compile_registry(Variant::Base, 1);
    let current = install_old_active_database(
        &database,
        &base,
        &[SeedRow {
            id: Uuid::from_u128(1),
            code: "A1",
            status: "old",
        }],
    )
    .await;
    let candidate = compile_registry(Variant::StatusRestricted, 2);
    let package = reviewed_package(&current, &base, &candidate, 1);
    let descriptor =
        HistorySchemaDescriptor::from_compiled_registry(&base, &current.package_revision);

    let activated = apply_with_descriptor(&database, &package, &current, &descriptor)
        .await
        .expect("bounded reviewed update applies with predecessor history proof");

    let entity = &base.entities()["asset"];
    let table = quote(&entity.physical_table);
    let status = quote(&entity.fields["status"].physical_name);
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT record_revision, active_package_revision, {status}
                   FROM registry_data.{table}
                  WHERE record_id = $1"
            ),
            &[&Uuid::from_u128(1)],
        )
        .await
        .expect("administrator reads migrated live row");
    assert_eq!(row.get::<_, i64>(0), 2);
    assert_eq!(row.get::<_, String>(1), package.manifest().package_revision);
    assert_eq!(row.get::<_, String>(2), "new");

    let revision = database
        .admin
        .query_one(
            "SELECT record_revision, predecessor_revision, package_revision,
                    mutation_kind, principal_reference, request_reference, snapshot
               FROM registry_internal.registry_revisions
              WHERE entity_id = 'asset'
                AND record_id = $1
                AND record_revision = 2",
            &[&Uuid::from_u128(1)],
        )
        .await
        .expect("administrator reads internal migration revision");
    assert_eq!(revision.get::<_, i64>(0), 2);
    assert_eq!(revision.get::<_, Option<i64>>(1), Some(1));
    assert_eq!(
        revision.get::<_, String>(2),
        package.manifest().package_revision
    );
    assert_eq!(revision.get::<_, String>(3), "migration");
    assert_eq!(revision.get::<_, String>(4), MIGRATION_SYSTEM_ORIGIN);
    let migration_reference = revision.get::<_, String>(5);
    assert_eq!(
        migration_reference,
        "modules/core/migrations/status-classification/descriptor.json#backfill-status"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&revision.get::<_, Vec<u8>>(6))
            .expect("migration snapshot decodes"),
        json!({"code": "A1", "status": "new"})
    );

    let commits = database
        .admin
        .query(
            "SELECT c.commit_position, c.origin_kind, c.system_origin, c.migration_reference,
                    m.entity_id, m.record_id, m.record_revision
               FROM registry_internal.registry_revision_commits c
               LEFT JOIN registry_internal.registry_revision_commit_members m
                 ON m.commit_position = c.commit_position
              ORDER BY c.commit_position, m.member_index",
            &[],
        )
        .await
        .expect("administrator reads migration commits");
    assert_eq!(commits.len(), 2);
    assert_eq!(commits[0].get::<_, i64>(0), 0);
    assert_eq!(commits[0].get::<_, String>(1), "baseline");
    assert_eq!(commits[0].get::<_, String>(4), "asset");
    assert_eq!(commits[0].get::<_, i64>(6), 1);
    assert_eq!(commits[1].get::<_, i64>(0), 1);
    assert_eq!(commits[1].get::<_, String>(1), "migration");
    assert_eq!(commits[1].get::<_, String>(2), MIGRATION_SYSTEM_ORIGIN);
    assert_eq!(
        commits[1].get::<_, Option<String>>(3),
        Some(migration_reference)
    );
    assert_eq!(commits[1].get::<_, String>(4), "asset");
    assert_eq!(commits[1].get::<_, Uuid>(5), Uuid::from_u128(1));
    assert_eq!(commits[1].get::<_, i64>(6), 2);

    let app = mutation_revision_router(
        database
            .runtime_config
            .build_pool()
            .expect("runtime pool builds after reviewed migration"),
        Arc::new(candidate),
        activated,
    );
    let created = send(
        &app,
        Method::POST,
        "/v1/records/assets",
        Some(history_claims()),
        &[
            ("idempotency-key", "post-upgrade-create"),
            ("content-type", "application/json"),
        ],
        br#"{"data":{"code":"B1","status":"new"}}"#.to_vec(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = body_json(created).await;
    let created_id = created["data"]["recordIdentifier"]
        .as_str()
        .expect("create response id");
    let created_revision = send(
        &app,
        Method::GET,
        &format!("/v1/records/assets/{created_id}/revisions"),
        Some(history_claims()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(created_revision.status(), StatusCode::OK);
    let created_revision = body_json(created_revision).await;
    assert_eq!(created_revision["items"][0]["revisionIdentifier"], "1");
    assert_eq!(created_revision["items"][0]["mutationKind"], "create");
    assert_eq!(
        created_revision["items"][0]["domainData"],
        json!({"code": "B1"})
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn predecessor_baseline_mismatch_refuses_before_successor_update() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs required extension");
    let base = compile_registry(Variant::Base, 1);
    let current = install_old_active_database(
        &database,
        &base,
        &[SeedRow {
            id: Uuid::from_u128(1),
            code: "A1",
            status: "old",
        }],
    )
    .await;
    overwrite_live_status(&database, &base, Uuid::from_u128(1), "drift").await;
    let candidate = compile_registry(Variant::StatusRestricted, 2);
    let package = reviewed_package(&current, &base, &candidate, 1);
    let descriptor =
        HistorySchemaDescriptor::from_compiled_registry(&base, &current.package_revision);

    let refused = apply_with_descriptor(&database, &package, &current, &descriptor).await;
    assert_value_free(refused.err(), MigrationError::ApplyFailed);
    assert_live_status(&database, &base, Uuid::from_u128(1), "drift", 1).await;
    assert_no_history_head(&database).await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn predecessor_baseline_refuses_revisions_from_unretained_package_descriptor() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs required extension");
    let base = compile_registry(Variant::Base, 1);
    let current = install_old_active_database(
        &database,
        &base,
        &[SeedRow {
            id: Uuid::from_u128(1),
            code: "A1",
            status: "old",
        }],
    )
    .await;
    overwrite_revision_package(&database, Uuid::from_u128(1), "history-migration-base-0").await;
    let candidate = compile_registry(Variant::StatusRestricted, 2);
    let package = reviewed_package(&current, &base, &candidate, 1);
    let descriptor =
        HistorySchemaDescriptor::from_compiled_registry(&base, &current.package_revision);

    let refused = apply_with_descriptor(&database, &package, &current, &descriptor).await;
    assert_value_free(refused.err(), MigrationError::ApplyFailed);
    assert_live_status(&database, &base, Uuid::from_u128(1), "old", 1).await;
    assert_no_history_head(&database).await;
    assert_no_migration_revision(&database).await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_update_refuses_when_table_exceeds_declared_budget_before_data_changes() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs required extension");
    let base = compile_registry(Variant::Base, 1);
    let current = install_old_active_database(
        &database,
        &base,
        &[
            SeedRow {
                id: Uuid::from_u128(1),
                code: "A1",
                status: "old",
            },
            SeedRow {
                id: Uuid::from_u128(2),
                code: "A2",
                status: "old",
            },
        ],
    )
    .await;
    let candidate = compile_registry(Variant::StatusRestricted, 2);
    let package = reviewed_package(&current, &base, &candidate, 1);
    let descriptor =
        HistorySchemaDescriptor::from_compiled_registry(&base, &current.package_revision);

    let refused = apply_with_descriptor(&database, &package, &current, &descriptor).await;
    assert_value_free(refused.err(), MigrationError::ApplyFailed);
    assert_live_status(&database, &base, Uuid::from_u128(1), "old", 1).await;
    assert_live_status(&database, &base, Uuid::from_u128(2), "old", 1).await;
    assert_no_migration_revision(&database).await;
    database.cleanup().await;
}

#[derive(Clone, Copy)]
enum Variant {
    Base,
    StatusRestricted,
}

struct SeedRow<'a> {
    id: Uuid,
    code: &'a str,
    status: &'a str,
}

async fn install_old_active_database(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    rows: &[SeedRow<'_>],
) -> ExpectedRegistryIdentity {
    let fingerprint = initial_fingerprint(database, registry).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, registry, &database.runtime_role)
        .await
        .expect("old active database installs compiled schema");
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: BASE_PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("old active database records active package identity");
    assert_eq!(identity.schema_fingerprint, fingerprint);
    for row in rows {
        seed_live_row_and_revision(&database.admin, registry, row).await;
    }
    migration_task.abort();
    identity
}

async fn seed_live_row_and_revision(
    client: &tokio_postgres::Client,
    registry: &CompiledRegistry,
    row: &SeedRow<'_>,
) {
    let entity = &registry.entities()["asset"];
    let table = quote(&entity.physical_table);
    let code = quote(&entity.fields["code"].physical_name);
    let status = quote(&entity.fields["status"].physical_name);
    client
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                     (record_id, record_revision, record_lifecycle, active_package_revision,
                      {code}, {status})
                 VALUES ($1, 1, 'active', $2, $3, $4)"
            ),
            &[&row.id, &BASE_PACKAGE_REVISION, &row.code, &row.status],
        )
        .await
        .expect("fixture seeds live row");
    let snapshot = canonicalize_json(&json!({
        "code": row.code,
        "status": row.status,
    }))
    .expect("fixture snapshot canonicalizes");
    client
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision, operation_id,
                  mutation_kind, principal_reference, request_reference, snapshot)
             VALUES ('asset', $1, $2, 1, NULL, 'active', $3,
                     'records.asset.create', 'create', $4, $5, $6)",
            &[
                &row.id,
                &RECORD_REFERENCE,
                &BASE_PACKAGE_REVISION,
                &ACTOR_REFERENCE,
                &REQUEST_REFERENCE,
                &snapshot,
            ],
        )
        .await
        .expect("fixture seeds matching latest revision row");
}

fn reviewed_package(
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    max_rows: u64,
) -> VerifiedPackage {
    let source = reviewed_update_source(current, prior, candidate, max_rows);
    let package = prepare_package(build_request(
        2,
        Some(&current.package_revision),
        &current.schema_fingerprint,
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(prior.clone()),
            prior_schema_fingerprint: current.schema_fingerprint.clone(),
            migrations: vec![source],
        },
    ))
    .expect("reviewed package prepares");
    publish_and_load(
        package,
        PackageIntent::Activation {
            active_revision: &current.package_revision,
            active_sequence: u64::try_from(current.package_sequence)
                .expect("active sequence is positive"),
        },
    )
}

fn reviewed_update_source(
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    max_rows: u64,
) -> ReviewedMigrationSource {
    let change = compiled_registry_change_set(prior, candidate, &current.package_revision)
        .changes
        .into_iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldClassificationChanged)
        .expect("status classification change is reviewed");
    assert_eq!(
        change.class,
        CompiledRegistryChangeClass::AccessOrDisclosureChange
    );
    let entity = &candidate.entities()["asset"];
    let field = &entity.fields["status"];
    let base = "modules/core/migrations/status-classification";
    let step_path = format!("{base}/steps/backfill-status.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let object = ReviewedMigrationObject {
        schema: "registry_data".to_owned(),
        table: entity.physical_table.clone(),
        entity_id: "asset".to_owned(),
        kind: ReviewedMigrationObjectKind::Field,
        member_id: Some("status".to_owned()),
        physical_name: field.physical_name.clone(),
    };
    let descriptor = ReviewedMigrationDescriptor {
        id: "status-classification".to_owned(),
        change_class: CompiledRegistryChangeClass::AccessOrDisclosureChange,
        covers: vec![ReviewedChangeCover::from(&change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 50,
        statement_timeout_ms: 5_000,
        steps: vec![ReviewedMigrationStepDescriptor::TransactionalSql {
            id: "backfill-status".to_owned(),
            sql_path: step_path.clone(),
            objects: vec![object],
            affected_rows: Some(AffectedRowBounds {
                min: 1,
                max: max_rows,
            }),
        }],
        pre_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "pre".to_owned(),
            sql_path: pre_path.clone(),
        }],
        post_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "post".to_owned(),
            sql_path: post_path.clone(),
        }],
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    let sql = format!(
        "UPDATE registry_data.{} SET {} = 'new' WHERE {} = 'old'",
        entity.physical_table, field.physical_name, field.physical_name
    );
    reviewed_source(ReviewedSourceRequest {
        descriptor,
        current,
        final_fingerprint: &current.schema_fingerprint,
        steps: vec![(step_path, sql)],
        pre: (
            pre_path,
            format!(
                "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
                entity.physical_table
            ),
        ),
        post: (
            post_path,
            format!(
                "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
                entity.physical_table
            ),
        ),
        row_assertions: vec![RehearsalRowAssertion {
            step_id: "backfill-status".to_owned(),
            affected_rows: max_rows,
        }],
    })
}

struct ReviewedSourceRequest<'a> {
    descriptor: ReviewedMigrationDescriptor,
    current: &'a ExpectedRegistryIdentity,
    final_fingerprint: &'a str,
    steps: Vec<(String, String)>,
    pre: (String, String),
    post: (String, String),
    row_assertions: Vec<RehearsalRowAssertion>,
}

fn reviewed_source(request: ReviewedSourceRequest<'_>) -> ReviewedMigrationSource {
    let ReviewedSourceRequest {
        descriptor,
        current,
        final_fingerprint,
        steps,
        pre,
        post,
        row_assertions,
    } = request;
    let descriptor_path = format!("modules/core/migrations/{}/descriptor.json", descriptor.id);
    let descriptor_bytes = canonical(&descriptor);
    let fixture_path = format!(
        "modules/core/migrations/{}/fixtures/representative.jsonl",
        descriptor.id
    );
    let fixture_bytes = b"{\"fixture\":\"representative\"}\n".to_vec();
    let receipt = MigrationRehearsalReceipt {
        prior_revision: current.package_revision.clone(),
        prior_schema_fingerprint: current.schema_fingerprint.clone(),
        plan_sha256: digest(&descriptor_bytes),
        sql_sha256: steps
            .iter()
            .map(|(path, sql)| ArtifactDigestBinding {
                path: path.clone(),
                sha256: digest(sql.as_bytes()),
            })
            .collect(),
        assertion_sha256: vec![
            ArtifactDigestBinding {
                path: pre.0.clone(),
                sha256: digest(pre.1.as_bytes()),
            },
            ArtifactDigestBinding {
                path: post.0.clone(),
                sha256: digest(post.1.as_bytes()),
            },
        ],
        fixture_inventory: vec![RehearsalFixture {
            id: "representative".to_owned(),
            path: fixture_path.clone(),
            sha256: digest(&fixture_bytes),
            row_count: 1,
        }],
        postgres_major: 17,
        row_assertions,
        final_schema_fingerprint: final_fingerprint.to_owned(),
        proofs: RehearsalProofs {
            lock_timeout: true,
            chunk_resume: false,
            destructive_resume: false,
        },
    };
    let mut files = steps
        .into_iter()
        .map(|(path, sql)| ReviewedMigrationFile {
            path,
            bytes: sql.into_bytes(),
        })
        .collect::<Vec<_>>();
    files.extend([
        ReviewedMigrationFile {
            path: pre.0,
            bytes: pre.1.into_bytes(),
        },
        ReviewedMigrationFile {
            path: post.0,
            bytes: post.1.into_bytes(),
        },
        ReviewedMigrationFile {
            path: descriptor.rehearsal_receipt_path.clone(),
            bytes: canonical(&receipt),
        },
        ReviewedMigrationFile {
            path: fixture_path,
            bytes: fixture_bytes,
        },
    ]);
    files.sort_by(|left, right| left.path.cmp(&right.path));
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: descriptor_path,
            bytes: descriptor_bytes,
        },
        files,
    }
}

async fn apply_with_descriptor(
    database: &TestDatabase,
    package: &VerifiedPackage,
    current: &ExpectedRegistryIdentity,
    descriptor: &HistorySchemaDescriptor,
) -> registry_server::migration::Result<ExpectedRegistryIdentity> {
    apply_verified_package(
        request(database, package, ApplyPrecondition::Successor { current })
            .with_predecessor_history_descriptor(descriptor),
    )
    .await
}

fn request<'a>(
    database: &'a TestDatabase,
    package: &'a VerifiedPackage,
    precondition: ApplyPrecondition<'a>,
) -> ApplyVerifiedPackageRequest<'a> {
    ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        package,
        precondition,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
    )
}

async fn initial_fingerprint(database: &TestDatabase, registry: &CompiledRegistry) -> String {
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("initial fingerprint transaction starts");
    install_compiled_schema(&transaction, registry, &database.runtime_role)
        .await
        .expect("initial schema rehearses");
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
    )
    .await
    .expect("initial fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("initial rehearsal rolls back");
    task.abort();
    fingerprint
}

fn compile_registry(variant: Variant, sequence: u64) -> CompiledRegistry {
    let module_bytes = module_bytes(variant);
    let module = parse_module_json(&module_bytes).expect("test module parses");
    let project_bytes = project_bytes(sequence, &module_digest(&module));
    let project = parse_project_yaml(&project_bytes).expect("test project parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("test Registry compiles")
}

fn project_bytes(sequence: u64, digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"{PACKAGE_ID}","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://history-migration.example.test"}},"package":{{"environment":"local","instanceId":"{INSTANCE_ID}","sequence":{sequence},"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://history-migration.example.test","title":"History Migration Registry","publisher":{{"id":"history-migration-registry-authority","name":"History Migration Publisher"}}}},"publicService":{{"id":"history-migration-registry-service","title":"History Migration Registry"}},"datasets":[{{"id":"history-migration-registry","title":"History Migration Dataset","owner":"History Migration Publisher","status":"active"}}],"dataServices":[{{"id":"history-migration-registry-data-service","title":"History Migration Registry","endpointUrl":"https://history-migration.example.test","servesDatasets":["history-migration-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{digest}"}}]}}"#
    )
    .into_bytes()
}

fn module_bytes(variant: Variant) -> Vec<u8> {
    let status_classification = match variant {
        Variant::Base => "internal",
        Variant::StatusRestricted => "restricted",
    };
    format!(
        r#"{{"id":"core","version":"1","entities":[{{"id":"asset","primaryDataset":"history-migration-registry","route":"assets","mutationMode":"create_only","fields":[{{"id":"code","type":"string","required":true,"maxLength":8,"classification":"internal"}},{{"id":"status","type":"string","required":true,"maxLength":16,"classification":"{status_classification}"}}],"accessProfiles":[{{"id":"reader","principalClaim":"principal","operations":["create","get","list","revisions"],"revisionAccess":true,"readableFields":["code"],"writableFields":["code","status"]}}]}}]}}"#
    )
    .into_bytes()
}

fn build_request(
    sequence: u64,
    prior_revision: Option<&str>,
    schema_fingerprint: &str,
    migration_plan: PackageMigrationPlanInput,
) -> PackageBuildRequest {
    let module_bytes = module_bytes(if sequence == 1 {
        Variant::Base
    } else {
        Variant::StatusRestricted
    });
    let module = parse_module_json(&module_bytes).expect("package module parses");
    PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: INSTANCE_ID.to_owned(),
        database_id: DATABASE_ID.to_owned(),
        sequence,
        prior_revision: prior_revision.map(str::to_owned),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes(sequence, &module_digest(&module)),
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: module_bytes,
            assets: Vec::new(),
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan,
    }
}

fn publish_and_load(
    prepared: registry_server::package::PreparedPackage,
    intent: PackageIntent<'_>,
) -> VerifiedPackage {
    let root = tempfile::Builder::new()
        .prefix("registry-history-migration-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("package temporary directory creates");
    let package = root.path().join("package");
    prepared
        .publish_to_directory(&package, Vec::new())
        .expect("package publishes");
    load_package(
        &package,
        &PackageLoadContext {
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            database_initialization_environment: "local",
            compiler_source_revision: SOURCE_REVISION,
            trust_anchor: None,
            intent,
        },
    )
    .expect("published package loads with the requested lifecycle intent")
}

async fn overwrite_revision_package(
    database: &TestDatabase,
    record_id: Uuid,
    package_revision: &str,
) {
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_revisions
                SET package_revision = $1
              WHERE entity_id = 'asset'
                AND record_id = $2
                AND record_revision = 1",
            &[&package_revision, &record_id],
        )
        .await
        .expect("fixture points latest revision at an unavailable descriptor");
}

async fn overwrite_live_status(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    record_id: Uuid,
    value: &str,
) {
    let entity = &registry.entities()["asset"];
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET {} = $1 WHERE record_id = $2",
                quote(&entity.physical_table),
                quote(&entity.fields["status"].physical_name)
            ),
            &[&value, &record_id],
        )
        .await
        .expect("fixture mutates live row without updating journal");
}

async fn assert_live_status(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    record_id: Uuid,
    expected_status: &str,
    expected_revision: i64,
) {
    let entity = &registry.entities()["asset"];
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT record_revision, {}
                   FROM registry_data.{}
                  WHERE record_id = $1",
                quote(&entity.fields["status"].physical_name),
                quote(&entity.physical_table)
            ),
            &[&record_id],
        )
        .await
        .expect("administrator reads live row");
    assert_eq!(row.get::<_, i64>(0), expected_revision);
    assert_eq!(row.get::<_, String>(1), expected_status);
}

async fn assert_no_history_head(database: &TestDatabase) {
    let exists = database
        .admin
        .query_one(
            "SELECT EXISTS (
                 SELECT 1
                   FROM pg_catalog.pg_class c
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = 'registry_internal'
                    AND c.relname = 'registry_commit_head'
             )",
            &[],
        )
        .await
        .expect("administrator checks history head relation")
        .get::<_, bool>(0);
    if !exists {
        return;
    }
    let rows = database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_commit_head",
            &[],
        )
        .await
        .expect("administrator counts history head rows")
        .get::<_, i64>(0);
    assert_eq!(rows, 0);
}

fn mutation_revision_router(
    pool: registry_server::postgres::RuntimePool,
    registry: Arc<CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
) -> axum::Router {
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x4d; 32]), Duration::from_secs(300))
            .expect("test cursor key is valid"),
    );
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock identity is bounded");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x6d; 32].into())
        .expect("test audit profile is keyed");
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        Arc::clone(&registry),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit_profile.clone(),
        Arc::clone(&cursors),
    ));
    let mutations = Arc::new(PostgresRecordMutationService::new(
        pool.clone(),
        Arc::clone(&registry),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit_profile.clone(),
    ));
    let revisions = Arc::new(PostgresRevisionReadService::new(
        pool,
        Arc::clone(&registry),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit_profile,
    ));
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
        .with_postgres_mutations(mutations)
        .with_postgres_revisions(revisions),
    ))
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Response<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .expect("test request builds");
    for (name, value) in headers {
        request.headers_mut().append(
            axum::http::HeaderName::from_bytes(name.as_bytes()).expect("test header name"),
            axum::http::HeaderValue::from_str(value).expect("test header value"),
        );
    }
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns a response")
}

async fn body_json(response: Response<Body>) -> Value {
    serde_json::from_slice(&body_bytes(response).await).expect("response body is JSON")
}

async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body is bounded")
        .to_vec()
}

fn history_claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "principal",
        "package-reader",
        BTreeSet::new(),
        Some("case-review".to_owned()),
        BTreeMap::new(),
    )
    .expect("claims are verified")
}

async fn assert_no_migration_revision(database: &TestDatabase) {
    let rows = database
        .admin
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_revisions
              WHERE mutation_kind = 'migration'",
            &[],
        )
        .await
        .expect("administrator counts internal migration revisions")
        .get::<_, i64>(0);
    assert_eq!(rows, 0);
}

fn assert_value_free(actual: Option<MigrationError>, expected: MigrationError) {
    let actual = actual.expect("operation must fail");
    assert_eq!(actual, expected);
    let diagnostic = format!("{actual:?} {actual}");
    for canary in ["A1", "old", "drift", "registry_data"] {
        assert!(!diagnostic.contains(canary), "diagnostic leaked {canary}");
    }
}

fn canonical(value: &impl Serialize) -> Vec<u8> {
    canonicalize_json(&serde_json::to_value(value).expect("test value serializes"))
        .expect("test value canonicalizes")
}

fn digest(bytes: &[u8]) -> String {
    let mut result = String::from("sha256:");
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
