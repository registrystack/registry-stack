// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling", unix))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf, time::Duration};

use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::migration::{
    apply_verified_package, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest, DestructiveBackupEvidence, MigrationError,
};
use registry_breg::migration_plan::{
    ArtifactDigestBinding, ExternalBackupBinding, MigrationRehearsalReceipt, RehearsalFixture,
    RehearsalProofs, ReviewedChangeCover, ReviewedMigrationAssertionDescriptor,
    ReviewedMigrationDescriptor, ReviewedMigrationFile, ReviewedMigrationObject,
    ReviewedMigrationObjectKind, ReviewedMigrationRecovery, ReviewedMigrationSource,
    ReviewedMigrationStepDescriptor,
};
use registry_breg::package::{
    compiled_registry_change_set, load_package, prepare_package, CompiledRegistryChangeClass,
    CompiledRegistryChangeCode, PackageBuildRequest, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile, SignaturePolicy,
    VerifiedPackage,
};
use registry_breg::postgres::{
    begin_record_transaction, install_compiled_schema, managed_schema_fingerprint,
    provision_postgis_prerequisites, verify_catalog_identity_for_catalog, verify_postgis,
    ClaimContext, ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey, SqlIdentifier,
};
use registry_breg::startup::{prepare_startup, StartupError};
use registry_breg::CompiledRegistry;
use registry_platform_canonical_json::canonicalize_json;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio_postgres::GenericClient;
use uuid::Uuid;

const INSTANCE: &str = "spatial-migration-instance";
const DATABASE: &str = "spatial-migration-database";
const SOURCE_REVISION: &str = "spatial-migration-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/breg-journeys/v1
journeys:
  - id: site-list
    steps:
      - id: list-sites
        entity: site
        accessProfile: reader
        claims: {principal: package-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
const SITE_RECORD: &str = "00000000-0000-4000-8000-000000000101";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enabling_bbox_on_existing_point_registry_preserves_data_and_recovers_safely() {
    let database = TestDatabase::create(2).await;
    let base = compile_variant(Variant::NoBbox, 1);
    assert!(!base.ddl().requires_postgis);
    let base_fingerprint = initial_fingerprint(&database, &base).await;
    let spatial = compile_variant(Variant::WithBbox, 2);
    assert!(spatial.ddl().requires_postgis);
    let fingerprint_bbox_role = provision_postgis_prerequisites(
        &database.admin,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("administrator temporarily provisions PostGIS for target fingerprint");
    let spatial_fingerprint = initial_fingerprint(&database, &spatial).await;
    cleanup_postgis_prerequisites(&database, &fingerprint_bbox_role).await;

    let initial_package = publish_and_load(
        prepare_package(build_request(
            Variant::NoBbox,
            1,
            None,
            &base_fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ))
        .expect("initial non-GIS package prepares"),
        local_context(PackageIntent::InitialActivation),
    );
    let active = apply(
        &database,
        &initial_package.verified,
        ApplyPrecondition::InitialActivation,
    )
    .await
    .expect("initial non-GIS package activates");
    seed_existing_site_and_history(&database, &base, &active).await;
    let prior_rows = site_rows(&database, &base).await;
    let prior_history = revision_snapshots(&database).await;
    assert_eq!(prior_history.len(), 2);

    let spatial_source =
        metadata_only_source_between(&active, &base, &spatial, &spatial_fingerprint);
    let spatial_package = publish_and_load(
        prepare_package(build_request(
            Variant::WithBbox,
            2,
            Some(&active.package_revision),
            &spatial_fingerprint,
            PackageMigrationPlanInput::ReviewedSuccessor {
                prior_registry: Box::new(base.clone()),
                prior_schema_fingerprint: active.schema_fingerprint.clone(),
                migrations: vec![spatial_source],
            },
        ))
        .expect("reviewed bbox successor package prepares"),
        local_context(PackageIntent::Activation {
            active_revision: &active.package_revision,
            active_sequence: 1,
        }),
    );
    assert!(spatial_package
        .verified
        .manifest()
        .migration_plan
        .statements
        .iter()
        .any(|statement| statement
            .sql
            .contains("registry_spatial_ext.geometry(Point,4326)")));
    assert!(spatial_package
        .verified
        .manifest()
        .migration_plan
        .statements
        .iter()
        .any(|statement| statement.sql.contains("USING gist")));

    let missing_postgis = apply(
        &database,
        &spatial_package.verified,
        ApplyPrecondition::Successor { current: &active },
    )
    .await;
    assert_value_free(missing_postgis.err(), MigrationError::ApplyFailed);
    assert_ready_target(&database, &active).await;
    assert_eq!(site_rows(&database, &base).await, prior_rows);
    assert_eq!(revision_snapshots(&database).await, prior_history);

    let bbox_role = provision_postgis_prerequisites(
        &database.admin,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("administrator provisions PostGIS prerequisites");
    let spatial_active = apply(
        &database,
        &spatial_package.verified,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("bbox package applies after administrator-owned PostGIS is ready");
    assert_ready_target(&database, &spatial_active).await;
    assert_eq!(site_rows(&database, &spatial).await, prior_rows);
    assert_eq!(revision_snapshots(&database).await, prior_history);
    assert_spatial_projection_and_index(&database, &spatial).await;
    assert_spatial_candidate_view_owner(&database, &spatial, &bbox_role).await;
    assert_spatial_startup_accepts_exact_identity(&database, &spatial_package, &spatial_active)
        .await;
    assert_startup_refuses_bbox_bypassrls_drift(
        &database,
        &spatial_package,
        &spatial_active,
        &bbox_role,
    )
    .await;
    assert_startup_refuses_runtime_bbox_membership_drift(
        &database,
        &spatial_package,
        &spatial_active,
        &bbox_role,
    )
    .await;

    let removed = compile_variant(Variant::WithBboxLegacyRemoved, 3);
    let removed_fingerprint = destructive_target_fingerprint(&database, &spatial, &removed).await;
    let backup_bytes = synthetic_backup_sql(&spatial, &spatial_active, &database.runtime_role, 1);
    let backup_digest = digest(&backup_bytes);
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current time formats");
    let backup_binding = ExternalBackupBinding {
        database_id: DATABASE.to_owned(),
        prior_revision: spatial_active.package_revision.clone(),
        prior_schema_fingerprint: spatial_active.schema_fingerprint.clone(),
        sha256: backup_digest,
        byte_length: backup_bytes.len() as u64,
        created_at: now,
        max_age_seconds: 3_600,
    };
    let destructive_source = destructive_source_with_recovery_fault(
        &spatial_active,
        &spatial,
        &removed,
        &removed_fingerprint,
        backup_binding.clone(),
    );
    let destructive_package = publish_and_load(
        prepare_package(build_request(
            Variant::WithBboxLegacyRemoved,
            3,
            Some(&spatial_active.package_revision),
            &removed_fingerprint,
            PackageMigrationPlanInput::ReviewedSuccessor {
                prior_registry: Box::new(spatial.clone()),
                prior_schema_fingerprint: spatial_active.schema_fingerprint.clone(),
                migrations: vec![destructive_source],
            },
        ))
        .expect("reviewed destructive spatial successor prepares"),
        local_context(PackageIntent::Activation {
            active_revision: &spatial_active.package_revision,
            active_sequence: 2,
        }),
    );
    let backup_root = tempfile::Builder::new()
        .prefix("registry-spatial-migration-backup-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("backup temporary directory creates");
    let backup_path = backup_root.path().join("spatial-restore.backup");
    fs::write(&backup_path, &backup_bytes).expect("backup evidence writes");
    fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))
        .expect("backup evidence permissions close");
    let binding_path = destructive_package
        .verified
        .reviewed_migration_plan()
        .expect("destructive package carries a reviewed plan")
        .migrations()[0]
        .descriptor
        .backup_binding_path
        .as_deref()
        .expect("destructive backup binding path exists");
    let backup_evidence = [DestructiveBackupEvidence::new(binding_path, &backup_path)];
    let destructive_failure = apply_with_evidence(
        &database,
        &destructive_package.verified,
        &spatial_active,
        &backup_evidence,
    )
    .await;
    assert_value_free(destructive_failure.err(), MigrationError::ApplyFailed);
    assert_non_ready_target(
        &database,
        &spatial_active,
        &destructive_package.verified,
        "failed",
    )
    .await;
    assert_record_work_is_blocked(&database, &spatial, &spatial_active).await;
    assert_legacy_column_absent(&database, &spatial).await;

    restore_synthetic_backup(&database, &backup_binding, &backup_path).await;
    assert_eq!(site_rows(&database, &spatial).await, prior_rows);
    assert_eq!(revision_snapshots(&database).await, prior_history);

    let recovered = apply_with_evidence(
        &database,
        &destructive_package.verified,
        &spatial_active,
        &backup_evidence,
    )
    .await
    .expect("the exact failed target resumes after operator restore");
    assert_ready_target(&database, &recovered).await;
    assert_legacy_column_absent(&database, &spatial).await;
    assert_eq!(revision_snapshots(&database).await, prior_history);
    cleanup_bbox_role(&database, &bbox_role).await;
    database.cleanup().await;
}

#[derive(Clone, Copy)]
enum Variant {
    NoBbox,
    WithBbox,
    WithBboxLegacyRemoved,
}

struct PublishedPackage {
    _root: tempfile::TempDir,
    root: PathBuf,
    verified: VerifiedPackage,
}

fn publish_and_load(
    prepared: registry_breg::package::PreparedPackage,
    context: PackageLoadContext<'_>,
) -> PublishedPackage {
    let root = tempfile::Builder::new()
        .prefix("registry-spatial-migration-package-")
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
    let verified = load_package(&package, &context).expect("published package loads");
    PublishedPackage {
        _root: root,
        root: package,
        verified,
    }
}

fn compile_variant(variant: Variant, sequence: u64) -> CompiledRegistry {
    let module_bytes = module_bytes(variant);
    let module = parse_module_yaml(&module_bytes).expect("test module parses");
    let project_bytes = project_bytes(sequence, &module_digest(&module));
    let project = parse_project_yaml(&project_bytes).expect("test project parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("test Registry compiles")
}

fn project_bytes(sequence: u64, digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"spatial-migration-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://spatial-migration.example.test"}},"package":{{"environment":"local","instanceId":"{INSTANCE}","sequence":{sequence},"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://spatial-migration.example.test","title":"Spatial Migration Registry","publisher":{{"id":"spatial-migration-registry-authority","name":"Spatial Migration Publisher"}}}},"publicService":{{"id":"spatial-migration-registry-service","title":"Spatial Migration Registry"}},"datasets":[{{"id":"spatial-migration-registry","title":"Spatial Migration Dataset","owner":"Spatial Migration Publisher","status":"active"}}],"dataServices":[{{"id":"spatial-migration-registry-data-service","title":"Spatial Migration Registry","endpointUrl":"https://spatial-migration.example.test","servesDatasets":["spatial-migration-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{digest}"}}]}}"#
    )
    .into_bytes()
}

fn module_bytes(variant: Variant) -> Vec<u8> {
    let spatial_queries = if matches!(variant, Variant::WithBbox | Variant::WithBboxLegacyRemoved) {
        r#","spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":0.5,"maximumLatitudeSpanDegrees":0.25}}"#
    } else {
        ""
    };
    let legacy = if matches!(variant, Variant::WithBboxLegacyRemoved) {
        ""
    } else {
        r#",{"id":"legacy","type":"string","maxLength":16,"classification":"internal"}"#
    };
    format!(
        r#"{{"id":"core","version":"1","entities":[{{"id":"site","primaryDataset":"spatial-migration-registry","route":"sites","mutationMode":"mutable","classification":"internal","fields":[{{"id":"code","type":"string","maxLength":16,"required":true,"classification":"internal"}},{{"id":"location","type":"crs84-point","precision":6,"required":true,"classification":"internal"}}{legacy}],"geojson":{{"geometryField":"location"}},"accessProfiles":[{{"id":"reader","principalClaim":"principal","operations":["get","list","create","patch"],"readableFields":["code","location"],"writableFields":["code","location"]{spatial_queries}}}]}}]}}"#
    )
    .into_bytes()
}

fn build_request(
    variant: Variant,
    sequence: u64,
    prior_revision: Option<&str>,
    schema_fingerprint: &str,
    migration_plan: PackageMigrationPlanInput,
) -> PackageBuildRequest {
    let module_bytes = module_bytes(variant);
    let module = parse_module_yaml(&module_bytes).expect("package module parses");
    PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: INSTANCE.to_owned(),
        database_id: DATABASE.to_owned(),
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

fn local_context<'a>(intent: PackageIntent<'a>) -> PackageLoadContext<'a> {
    PackageLoadContext {
        environment: "local",
        instance_id: INSTANCE,
        database_id: DATABASE,
        database_initialization_environment: "local",
        compiler_source_revision: SOURCE_REVISION,
        trust_anchor: None,
        intent,
    }
}

async fn initial_fingerprint(database: &TestDatabase, registry: &CompiledRegistry) -> String {
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("fingerprint transaction starts");
    if let Err(error) =
        install_compiled_schema(&transaction, registry, &database.runtime_role).await
    {
        transaction
            .rollback()
            .await
            .expect("failed fingerprint rehearsal rolls back");
        task.abort();
        let statement_error = first_compiled_statement_error(database, registry).await;
        panic!(
            "schema rehearses for {} statements: {error:?}; first compiled statement error: {statement_error}",
            registry.ddl().statements.len(),
        );
    }
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
    )
    .await
    .expect("fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("fingerprint rehearsal rolls back");
    task.abort();
    fingerprint
}

async fn first_compiled_statement_error(
    database: &TestDatabase,
    registry: &CompiledRegistry,
) -> String {
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("diagnostic transaction starts");
    for statement in registry.ddl().statements.iter().filter(|statement| {
        statement.kind != registry_breg::generated_ddl::DdlStatementKind::Schema
    }) {
        if let Err(error) = transaction.batch_execute(&statement.sql).await {
            let rendered = format!("{} {:?}: {error:?}", statement.id, statement.kind);
            let _ = transaction.rollback().await;
            task.abort();
            return rendered;
        }
    }
    let _ = transaction.rollback().await;
    task.abort();
    "none; failure occurred before compiled DDL".to_owned()
}

fn metadata_only_source_between(
    current: &ExpectedRegistryIdentity,
    previous: &CompiledRegistry,
    candidate: &CompiledRegistry,
    final_fingerprint: &str,
) -> ReviewedMigrationSource {
    let change_set = compiled_registry_change_set(previous, candidate, &current.package_revision);
    let mut covers = change_set
        .changes
        .iter()
        .filter(|change| change.class != CompiledRegistryChangeClass::CompatibleAdditive)
        .map(ReviewedChangeCover::from)
        .collect::<Vec<_>>();
    covers.sort();
    assert!(covers.iter().all(|cover| {
        change_set
            .changes
            .iter()
            .find(|change| change.code == cover.code && change.target == cover.target)
            .is_some_and(|change| {
                change.class == CompiledRegistryChangeClass::AccessOrDisclosureChange
            })
    }));
    let base = "modules/core/migrations/metadata-only-spatial";
    let descriptor = ReviewedMigrationDescriptor {
        id: "metadata-only-spatial".to_owned(),
        change_class: CompiledRegistryChangeClass::AccessOrDisclosureChange,
        covers,
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 10_000,
        statement_timeout_ms: 60_000,
        steps: Vec::new(),
        pre_assertions: Vec::new(),
        post_assertions: Vec::new(),
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    let descriptor_bytes = canonical(&descriptor);
    let receipt = MigrationRehearsalReceipt {
        prior_revision: current.package_revision.clone(),
        prior_schema_fingerprint: current.schema_fingerprint.clone(),
        plan_sha256: digest(&descriptor_bytes),
        sql_sha256: Vec::new(),
        assertion_sha256: Vec::new(),
        fixture_inventory: Vec::new(),
        postgres_major: 17,
        row_assertions: Vec::new(),
        final_schema_fingerprint: final_fingerprint.to_owned(),
        proofs: RehearsalProofs {
            lock_timeout: true,
            chunk_resume: false,
            destructive_resume: false,
        },
    };
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: format!("{base}/descriptor.json"),
            bytes: descriptor_bytes,
        },
        files: vec![ReviewedMigrationFile {
            path: descriptor.rehearsal_receipt_path,
            bytes: canonical(&receipt),
        }],
    }
}

fn destructive_source_with_recovery_fault(
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    final_fingerprint: &str,
    backup: ExternalBackupBinding,
) -> ReviewedMigrationSource {
    let change = compiled_registry_change_set(prior, candidate, &current.package_revision)
        .changes
        .into_iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldRemoved)
        .expect("legacy removal is classified");
    let entity = &prior.entities()["site"];
    let field = &entity.fields["legacy"];
    let base = "modules/core/migrations/remove-legacy-after-spatial";
    let step_path = format!("{base}/steps/drop-legacy.sql");
    let recovery_step_path = format!("{base}/steps/drop-legacy-after-restore.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let assertion = format!(
        "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
        entity.physical_table
    );
    let object = ReviewedMigrationObject {
        schema: "registry_data".to_owned(),
        table: entity.physical_table.clone(),
        entity_id: "site".to_owned(),
        kind: ReviewedMigrationObjectKind::Field,
        member_id: Some("legacy".to_owned()),
        physical_name: field.physical_name.clone(),
    };
    let descriptor = ReviewedMigrationDescriptor {
        id: "remove-legacy-after-spatial".to_owned(),
        change_class: CompiledRegistryChangeClass::DestructiveOrIrreversible,
        covers: vec![ReviewedChangeCover::from(&change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 50,
        statement_timeout_ms: 5_000,
        steps: vec![
            ReviewedMigrationStepDescriptor::TransactionalSql {
                id: "drop-legacy".to_owned(),
                sql_path: step_path.clone(),
                objects: vec![object.clone()],
                affected_rows: None,
            },
            ReviewedMigrationStepDescriptor::TransactionalSql {
                id: "drop-legacy-after-restore".to_owned(),
                sql_path: recovery_step_path.clone(),
                objects: vec![object],
                affected_rows: None,
            },
        ],
        pre_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "pre".to_owned(),
            sql_path: pre_path.clone(),
        }],
        post_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "post".to_owned(),
            sql_path: post_path.clone(),
        }],
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: Some(format!("{base}/backup.json")),
    };
    let drop_sql = format!(
        "ALTER TABLE registry_data.{} DROP COLUMN {}",
        entity.physical_table, field.physical_name
    );
    reviewed_source(ReviewedSourceRequest {
        descriptor,
        current,
        final_fingerprint,
        steps: vec![
            (step_path, drop_sql.clone()),
            (recovery_step_path, drop_sql),
        ],
        pre: (pre_path, assertion.clone()),
        post: (post_path, assertion),
        backup: Some(backup),
    })
}

struct ReviewedSourceRequest<'a> {
    descriptor: ReviewedMigrationDescriptor,
    current: &'a ExpectedRegistryIdentity,
    final_fingerprint: &'a str,
    steps: Vec<(String, String)>,
    pre: (String, String),
    post: (String, String),
    backup: Option<ExternalBackupBinding>,
}

fn reviewed_source(request: ReviewedSourceRequest<'_>) -> ReviewedMigrationSource {
    let ReviewedSourceRequest {
        descriptor,
        current,
        final_fingerprint,
        steps,
        pre,
        post,
        backup,
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
        row_assertions: Vec::new(),
        final_schema_fingerprint: final_fingerprint.to_owned(),
        proofs: RehearsalProofs {
            lock_timeout: true,
            chunk_resume: false,
            destructive_resume: backup.is_some(),
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
    if let (Some(path), Some(binding)) = (&descriptor.backup_binding_path, backup) {
        files.push(ReviewedMigrationFile {
            path: path.clone(),
            bytes: canonical(&binding),
        });
    }
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

async fn seed_existing_site_and_history(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    active: &ExpectedRegistryIdentity,
) {
    let entity = &registry.entities()["site"];
    let table = quote(&entity.physical_table);
    let code = quote(&entity.fields["code"].physical_name);
    let location = quote(&entity.fields["location"].physical_name);
    let legacy = quote(&entity.fields["legacy"].physical_name);
    let first_snapshot = canonical(&json!({
        "code": "SITE-001",
        "legacy": "legacy-1",
        "location": {"type": "Point", "coordinates": [100.5, 13.75]}
    }));
    let second_snapshot = canonical(&json!({
        "code": "SITE-001",
        "legacy": "legacy-1",
        "location": {"type": "Point", "coordinates": [100.55, 13.76]}
    }));
    let current_location: Value = json!({"type": "Point", "coordinates": [100.55, 13.76]});
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                     (record_id, record_revision, record_lifecycle, active_package_revision,
                      {code}, {location}, {legacy})
                 VALUES ($1::text::uuid, 2, 'active', $2, $3, $4::jsonb, $5)"
            ),
            &[
                &SITE_RECORD,
                &active.package_revision,
                &"SITE-001",
                &current_location,
                &"legacy-1",
            ],
        )
        .await
        .expect("administrator seeds the existing current Point record");
    for (revision, predecessor, mutation, snapshot) in [
        (1_i64, None, "create", first_snapshot),
        (2_i64, Some(1_i64), "patch", second_snapshot),
    ] {
        database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_revisions
                     (entity_id, record_id, record_reference, record_revision,
                      predecessor_revision, record_lifecycle, package_revision, operation_id,
                      mutation_kind, principal_reference, request_reference, snapshot)
                 VALUES ('site', $1::text::uuid, 'site:SITE-001', $2, $3, 'active',
                         $4, $5, $6, 'principal:test', 'request:test', $7)",
                &[
                    &SITE_RECORD,
                    &revision,
                    &predecessor,
                    &active.package_revision,
                    &format!("records.site.{mutation}"),
                    &mutation,
                    &snapshot,
                ],
            )
            .await
            .expect("administrator seeds prior revision history");
    }
}

async fn site_rows(
    database: &TestDatabase,
    registry: &CompiledRegistry,
) -> Vec<(String, i64, Value)> {
    let entity = &registry.entities()["site"];
    let rows = database
        .admin
        .query(
            &format!(
                "SELECT record_id::text, record_revision, {}
                 FROM registry_data.{}
                 ORDER BY record_id",
                quote(&entity.fields["location"].physical_name),
                quote(&entity.physical_table)
            ),
            &[],
        )
        .await
        .expect("site rows read");
    rows.into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect()
}

async fn revision_snapshots(database: &TestDatabase) -> Vec<(i64, Option<i64>, Vec<u8>)> {
    database
        .admin
        .query(
            "SELECT record_revision, predecessor_revision, snapshot
             FROM registry_internal.registry_revisions
             WHERE entity_id = 'site'
             ORDER BY record_revision",
            &[],
        )
        .await
        .expect("revision snapshots read")
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect()
}

async fn assert_spatial_projection_and_index(database: &TestDatabase, registry: &CompiledRegistry) {
    let entity = &registry.entities()["site"];
    let table = &entity.physical_table;
    let geometry_column: String = database
        .admin
        .query_one(
            "SELECT column_name
             FROM information_schema.columns
             WHERE table_schema = 'registry_data'
               AND table_name = $1
               AND udt_schema = 'registry_spatial_ext'
               AND udt_name = 'geometry'",
            &[table],
        )
        .await
        .expect("generated geometry column is catalogued")
        .get(0);
    let matches_point: bool = database
        .admin
        .query_one(
            &format!(
                "SELECT registry_spatial_ext.ST_Intersects(
                            {},
                            registry_spatial_ext.ST_SetSRID(
                                registry_spatial_ext.ST_MakePoint(100.55, 13.76),
                                4326
                            )
                        )
                   FROM registry_data.{}
                  WHERE record_id = $1::text::uuid",
                quote(&geometry_column),
                quote(table)
            ),
            &[&SITE_RECORD],
        )
        .await
        .expect("generated projection is readable by administrator")
        .get(0);
    assert!(
        matches_point,
        "generated geometry stores longitude as X and latitude as Y"
    );
    let index_count: i64 = database
        .admin
        .query_one(
            "SELECT count(*)
             FROM pg_catalog.pg_indexes
             WHERE schemaname = 'registry_data'
               AND tablename = $1
               AND indexdef LIKE '%USING gist%'
               AND indexdef LIKE $2",
            &[table, &format!("%{}%", geometry_column)],
        )
        .await
        .expect("spatial index inventory reads")
        .get(0);
    assert_eq!(index_count, 1);
}

async fn assert_spatial_candidate_view_owner(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    bbox_role: &SqlIdentifier,
) {
    let view = registry
        .ddl()
        .views
        .iter()
        .find(|view| view.id == "entity.site.spatial-candidates")
        .expect("compiled spatial registry has a candidate-ID view");
    let qualified_view = format!("{}.{}", quote(&view.schema), quote(&view.name));
    let row = database
        .admin
        .query_one(
            "SELECT owner.rolname,
                    pg_catalog.has_table_privilege($1, $2, 'SELECT'),
                    pg_catalog.pg_has_role($1, $3, 'MEMBER')
               FROM pg_catalog.pg_class c
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
               JOIN pg_catalog.pg_roles owner ON owner.oid = c.relowner
              WHERE n.nspname = $4
                AND c.relname = $5",
            &[
                &database.runtime_role.as_str(),
                &qualified_view,
                &bbox_role.as_str(),
                &view.schema,
                &view.name,
            ],
        )
        .await
        .expect("candidate-ID view ownership reads");
    assert_eq!(row.get::<_, String>(0), bbox_role.as_str());
    assert!(row.get::<_, bool>(1));
    assert!(!row.get::<_, bool>(2));
}

async fn assert_spatial_startup_accepts_exact_identity(
    database: &TestDatabase,
    package: &PublishedPackage,
    active: &ExpectedRegistryIdentity,
) {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool.get_for_test().await.expect("runtime connects");
    let startup = prepare_startup(
        &package.root,
        &local_context(PackageIntent::Startup {
            active_revision: &active.package_revision,
            active_sequence: 2,
        }),
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    if let Err(error) = startup {
        let diagnostic = startup_diagnostic(database, package, active).await;
        panic!(
            "startup accepts the exact spatial package and database identity: {error:?}; {diagnostic}"
        );
    }
}

async fn startup_diagnostic(
    database: &TestDatabase,
    package: &PublishedPackage,
    active: &ExpectedRegistryIdentity,
) -> String {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("diagnostic runtime pool builds");
    let mut runtime = pool
        .get_for_test()
        .await
        .expect("diagnostic runtime connects");
    let transaction = runtime
        .transaction()
        .await
        .expect("diagnostic transaction starts");
    let role_ok = transaction
        .query_one(
            "SELECT current_user = $1,
                    rolsuper,
                    rolbypassrls,
                    rolcreatedb,
                    rolcreaterole,
                    current_user = $2,
                    pg_has_role(current_user, $2, 'MEMBER'),
                    has_database_privilege(current_user, current_database(), 'CREATE'),
                    has_schema_privilege(current_user, 'registry_internal', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_data', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_source', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_derived', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_context', 'CREATE'),
                    EXISTS (
                        SELECT 1
                        FROM pg_catalog.pg_class c
                        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname IN (
                            'registry_internal',
                            'registry_data',
                            'registry_source',
                            'registry_derived',
                            'registry_context'
                        )
                          AND c.relowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
                    )
             FROM pg_catalog.pg_roles
             WHERE rolname = current_user",
            &[
                &database.runtime_role.as_str(),
                &database.migration_role.as_str(),
            ],
        )
        .await
        .map(|row| {
            let current_is_runtime = row.get::<_, bool>(0);
            let forbidden_runtime_bits = (1..=4).any(|index| row.get::<_, bool>(index));
            let current_is_migration = row.get::<_, bool>(5);
            let member_of_migration = row.get::<_, bool>(6);
            let create_or_owner = (7..=13).any(|index| row.get::<_, bool>(index));
            current_is_runtime && !forbidden_runtime_bits && !current_is_migration && !member_of_migration && !create_or_owner
        })
        .unwrap_or(false);
    let postgis = verify_postgis(
        &*transaction,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    let postgis_ok = postgis.is_ok();
    let postgis_error = postgis
        .err()
        .map(|error| format!("{error:?}"))
        .unwrap_or_else(|| "none".to_owned());
    let maintenance = transaction
        .query_opt(
            "SELECT maintenance_status
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await
        .ok()
        .flatten()
        .map(|row| row.get::<_, String>(0))
        .unwrap_or_else(|| "<unreadable>".to_owned());
    let catalog_ok = verify_catalog_identity_for_catalog(
        &*transaction,
        active,
        &ExpectedManagedCatalog::compiled(package.verified.registry()),
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .is_ok();
    let _ = transaction.rollback().await;
    let postgis_steps = runtime_postgis_steps(database).await;
    format!(
        "startup diagnostic role_ok={role_ok} postgis_ok={postgis_ok} postgis_error={postgis_error} maintenance={maintenance} catalog_ok={catalog_ok} postgis_steps={postgis_steps}"
    )
}

async fn runtime_postgis_steps(database: &TestDatabase) -> String {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("postgis diagnostic runtime pool builds");
    let client = pool
        .get_for_test()
        .await
        .expect("postgis diagnostic runtime connects");
    let version = client
        .query_one("SELECT current_setting('server_version_num')", &[])
        .await
        .map(|_| "ok".to_owned())
        .unwrap_or_else(|error| format!("err:{error:?}"));
    let bbox_role = registry_breg::postgres::spatial_bbox_role(&database.runtime_role);
    let membership = client
        .query_opt(
            "SELECT bbox.rolcanlogin,
                    bbox.rolsuper,
                    bbox.rolbypassrls,
                    bbox.rolcreatedb,
                    bbox.rolcreaterole,
                    pg_catalog.pg_has_role($1, bbox.oid, 'MEMBER'),
                    m.inherit_option,
                    m.set_option,
                    m.admin_option,
                    pg_catalog.pg_has_role($2, bbox.oid, 'MEMBER'),
                    pg_catalog.pg_has_role(bbox.oid, runtime.oid, 'MEMBER')
               FROM pg_catalog.pg_roles migration
               JOIN pg_catalog.pg_roles runtime ON runtime.rolname = $2
               JOIN pg_catalog.pg_roles bbox ON bbox.rolname = $3
               JOIN pg_catalog.pg_auth_members m
                 ON m.member = migration.oid AND m.roleid = bbox.oid
              WHERE migration.rolname = $1",
            &[
                &database.migration_role.as_str(),
                &database.runtime_role.as_str(),
                &bbox_role.as_str(),
            ],
        )
        .await
        .map(|row| {
            row.map(|row| {
                let forbidden = (0..=4).any(|index| row.get::<_, bool>(index));
                let valid = row.get::<_, bool>(5)
                    && !row.get::<_, bool>(6)
                    && row.get::<_, bool>(7)
                    && !row.get::<_, bool>(8)
                    && !row.get::<_, bool>(9)
                    && !row.get::<_, bool>(10);
                format!("ok:present={} valid={}", true, !forbidden && valid)
            })
            .unwrap_or_else(|| "ok:present=false".to_owned())
        })
        .unwrap_or_else(|error| format!("err:{error:?}"));
    let extension = client
        .query_opt(
            "WITH postgis AS (
                 SELECT e.extversion, n.nspname, owner.rolname AS owner_name,
                        COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner)) AS acl
                   FROM pg_catalog.pg_extension e
                   JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
                   JOIN pg_catalog.pg_roles owner ON owner.oid = n.nspowner
                  WHERE e.extname = 'postgis'
             ), acl AS (
                 SELECT postgis.*, grant_acl.grantee, grant_acl.privilege_type
                   FROM postgis
                   CROSS JOIN LATERAL pg_catalog.aclexplode(postgis.acl) AS grant_acl
             )
             SELECT extversion,
                    nspname = 'registry_spatial_ext',
                    EXISTS (SELECT 1 FROM acl WHERE grantee = 0 AND privilege_type = 'CREATE'),
                    EXISTS (
                        SELECT 1 FROM acl
                         WHERE grantee = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1)
                           AND privilege_type = 'CREATE'
                    ),
                    EXISTS (
                        SELECT 1 FROM acl
                         WHERE grantee = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $2)
                           AND privilege_type = 'CREATE'
                    ),
                    pg_catalog.has_schema_privilege($3, nspname, 'CREATE'),
                    EXISTS (
                        SELECT 1 FROM acl
                         WHERE grantee = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $3)
                           AND privilege_type = 'USAGE'
                    ),
                    EXISTS (
                        SELECT 1 FROM acl
                         WHERE grantee = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1)
                           AND privilege_type = 'USAGE'
                    ),
                    owner_name = $1,
                    owner_name = $2,
                    owner_name = $3
               FROM postgis",
            &[
                &database.migration_role.as_str(),
                &database.runtime_role.as_str(),
                &bbox_role.as_str(),
            ],
        )
        .await
        .map(|row| {
            row.map(|row| {
                let supported_version = row
                    .get::<_, String>(0)
                    .split('.')
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(".");
                let valid = row.get::<_, bool>(1)
                    && !(2..=5).any(|index| row.get::<_, bool>(index))
                    && row.get::<_, bool>(6)
                    && row.get::<_, bool>(7)
                    && !(8..=10).any(|index| row.get::<_, bool>(index));
                format!("ok:present=true version={supported_version} valid={valid}")
            })
            .unwrap_or_else(|| "ok:present=false".to_owned())
        })
        .unwrap_or_else(|error| format!("err:{error:?}"));
    let symbols = client
        .query_one(
            "SELECT to_regtype('registry_spatial_ext.geometry') IS NOT NULL,
                    to_regprocedure('registry_spatial_ext.st_makepoint(double precision,double precision)') IS NOT NULL,
                    to_regprocedure('registry_spatial_ext.st_setsrid(registry_spatial_ext.geometry,integer)') IS NOT NULL,
                    to_regprocedure('registry_spatial_ext.st_makeline(registry_spatial_ext.geometry,registry_spatial_ext.geometry)') IS NOT NULL,
                    to_regprocedure('registry_spatial_ext.st_makeenvelope(double precision,double precision,double precision,double precision,integer)') IS NOT NULL,
                    to_regprocedure('registry_spatial_ext.st_intersects(registry_spatial_ext.geometry,registry_spatial_ext.geometry)') IS NOT NULL,
                    to_regoperator('registry_spatial_ext.&&(registry_spatial_ext.geometry,registry_spatial_ext.geometry)') IS NOT NULL",
            &[],
        )
        .await
        .map(|row| {
            let valid = (0..=6).all(|index| row.get::<_, bool>(index));
            format!("ok:valid={valid}")
        })
        .unwrap_or_else(|error| format!("err:{error:?}"));
    format!("version={version}; membership={membership}; extension={extension}; symbols={symbols}")
}

async fn assert_startup_refuses_bbox_bypassrls_drift(
    database: &TestDatabase,
    package: &PublishedPackage,
    active: &ExpectedRegistryIdentity,
    bbox_role: &SqlIdentifier,
) {
    database
        .admin
        .batch_execute(&format!(
            "ALTER ROLE {} BYPASSRLS",
            quote(bbox_role.as_str())
        ))
        .await
        .expect("test can seed bbox role drift");
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool.get_for_test().await.expect("runtime connects");
    let refused = prepare_startup(
        &package.root,
        &local_context(PackageIntent::Startup {
            active_revision: &active.package_revision,
            active_sequence: 2,
        }),
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    assert_eq!(refused.err(), Some(StartupError::DatabaseUnready));
    drop(runtime);

    database
        .admin
        .batch_execute(&format!(
            "ALTER ROLE {} NOBYPASSRLS",
            quote(bbox_role.as_str())
        ))
        .await
        .expect("test restores bbox role drift");
    assert_spatial_startup_accepts_exact_identity(database, package, active).await;
}

async fn assert_startup_refuses_runtime_bbox_membership_drift(
    database: &TestDatabase,
    package: &PublishedPackage,
    active: &ExpectedRegistryIdentity,
    bbox_role: &SqlIdentifier,
) {
    database
        .admin
        .batch_execute(&format!(
            "GRANT {} TO {} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE",
            quote(bbox_role.as_str()),
            quote(database.runtime_role.as_str())
        ))
        .await
        .expect("test can seed runtime bbox membership drift");
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool.get_for_test().await.expect("runtime connects");
    let refused = prepare_startup(
        &package.root,
        &local_context(PackageIntent::Startup {
            active_revision: &active.package_revision,
            active_sequence: 2,
        }),
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    assert_eq!(refused.err(), Some(StartupError::DatabaseUnready));
    drop(runtime);

    database
        .admin
        .batch_execute(&format!(
            "REVOKE {} FROM {}",
            quote(bbox_role.as_str()),
            quote(database.runtime_role.as_str())
        ))
        .await
        .expect("test restores runtime bbox membership drift");
    assert_spatial_startup_accepts_exact_identity(database, package, active).await;
}

async fn destructive_target_fingerprint(
    database: &TestDatabase,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
) -> String {
    let entity = &prior.entities()["site"];
    let table = quote(&entity.physical_table);
    let legacy = quote(&entity.fields["legacy"].physical_name);
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("destructive fingerprint transaction starts");
    drop_managed_views_for_fingerprint(&transaction).await;
    transaction
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{table} DROP COLUMN {legacy}"
        ))
        .await
        .expect("destructive target rehearses");
    create_candidate_views_for_fingerprint(&transaction, candidate, &database.runtime_role).await;
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(candidate),
    )
    .await
    .expect("destructive target fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("destructive fingerprint transaction rolls back");
    task.abort();
    fingerprint
}

async fn drop_managed_views_for_fingerprint(transaction: &impl GenericClient) {
    let rows = transaction
        .query(
            "SELECT schemaname, viewname
               FROM pg_catalog.pg_views
              WHERE schemaname IN ('registry_derived', 'registry_source')
                 OR (schemaname = 'registry_context' AND viewname LIKE 'breg_spcand\\_%' ESCAPE '\\')
              ORDER BY CASE schemaname
                           WHEN 'registry_context' THEN 0
                           WHEN 'registry_derived' THEN 1
                           ELSE 2
                       END,
                       viewname",
            &[],
        )
        .await
        .expect("fingerprint rehearsal inventories compiler-owned views");
    for row in rows {
        let schema: String = row.get(0);
        let view: String = row.get(1);
        transaction
            .batch_execute(&format!(
                "DROP VIEW {}.{} RESTRICT",
                quote(&schema),
                quote(&view)
            ))
            .await
            .expect("fingerprint rehearsal drops a compiler-owned read view");
    }
}

async fn create_candidate_views_for_fingerprint(
    transaction: &impl GenericClient,
    candidate: &CompiledRegistry,
    runtime_role: &SqlIdentifier,
) {
    for statement in
        candidate.ddl().statements.iter().filter(|statement| {
            statement.kind == registry_breg::generated_ddl::DdlStatementKind::View
        })
    {
        transaction
            .batch_execute(&statement.sql)
            .await
            .expect("fingerprint rehearsal creates a candidate read view");
        if statement
            .sql
            .starts_with("CREATE VIEW registry_context.\"breg_spcand_")
        {
            let bbox_role = registry_breg::postgres::spatial_bbox_role(runtime_role);
            let view_name = statement
                .sql
                .strip_prefix("CREATE VIEW registry_context.")
                .and_then(|rest| rest.split_whitespace().next())
                .expect("spatial candidate view DDL carries its view name");
            transaction
                .batch_execute(&format!(
                    "REVOKE ALL ON TABLE registry_context.{view_name} FROM PUBLIC, {};\n\
                     GRANT SELECT ON TABLE registry_context.{view_name} TO {};\n\
                     GRANT CREATE ON SCHEMA registry_context TO {};\n\
                     ALTER VIEW registry_context.{view_name} OWNER TO {};\n\
                     REVOKE CREATE ON SCHEMA registry_context FROM {};",
                    quote(runtime_role.as_str()),
                    quote(runtime_role.as_str()),
                    quote(bbox_role.as_str()),
                    quote(bbox_role.as_str()),
                    quote(bbox_role.as_str())
                ))
                .await
                .expect("fingerprint rehearsal transfers candidate view ownership");
        }
    }
    for view in &candidate.ddl().views {
        if view.schema == "registry_context" && view.name.starts_with("breg_spcand_") {
            continue;
        }
        let schema = quote(&view.schema);
        let name = quote(&view.name);
        transaction
            .batch_execute(&format!(
                "REVOKE ALL ON TABLE {schema}.{name} FROM PUBLIC, {};",
                quote(runtime_role.as_str())
            ))
            .await
            .expect("fingerprint rehearsal revokes candidate view privileges");
        if !view.runtime_privileges.is_empty() {
            let privileges = view
                .runtime_privileges
                .iter()
                .map(|privilege| privilege.as_sql())
                .collect::<Vec<_>>()
                .join(", ");
            transaction
                .batch_execute(&format!(
                    "GRANT {privileges} ON TABLE {schema}.{name} TO {};",
                    quote(runtime_role.as_str())
                ))
                .await
                .expect("fingerprint rehearsal grants candidate view privileges");
        }
    }
}

fn synthetic_backup_sql(
    registry: &CompiledRegistry,
    active: &ExpectedRegistryIdentity,
    runtime_role: &SqlIdentifier,
    count: u64,
) -> Vec<u8> {
    let entity = &registry.entities()["site"];
    let table = quote(&entity.physical_table);
    let code = quote(&entity.fields["code"].physical_name);
    let location = quote(&entity.fields["location"].physical_name);
    let legacy = quote(&entity.fields["legacy"].physical_name);
    let values = (0..count)
        .map(|index| {
            let record = if index == 0 {
                SITE_RECORD.to_owned()
            } else {
                Uuid::from_u128(index as u128 + 1).to_string()
            };
            format!(
                "('{}'::uuid, 2::bigint, 'active'::text, '{}', 'SITE-{index:03}'::varchar(16), '{{\"type\":\"Point\",\"coordinates\":[100.55,13.76]}}'::jsonb, 'legacy-1'::varchar(16))",
                record,
                active.package_revision.replace('\'', "''")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let create = registry
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.site.table")
        .expect("compiled table DDL exists");
    let site_views = registry
        .ddl()
        .views
        .iter()
        .filter(|view| view.id.starts_with("entity.site."))
        .filter(|view| {
            !(view.schema == "registry_context" && view.name.starts_with("breg_spcand_"))
        })
        .collect::<Vec<_>>();
    let mut sql = String::new();
    for schema in ["registry_derived", "registry_source"] {
        for view in site_views.iter().filter(|view| view.schema == schema) {
            sql.push_str(&format!(
                "DROP VIEW IF EXISTS {}.{} RESTRICT;\n",
                quote(&view.schema),
                quote(&view.name)
            ));
        }
    }
    sql.push_str(&format!(
        "DROP TABLE registry_data.{table};\n{};\n\
         INSERT INTO registry_data.{table}\n\
             (record_id, record_revision, record_lifecycle, active_package_revision, {code}, {location}, {legacy})\n\
         VALUES {values};\n",
        create.sql
    ));
    for statement in registry.ddl().statements.iter().filter(|statement| {
        statement.id.starts_with("entity.site.") && statement.id != "entity.site.table"
    }) {
        if statement
            .sql
            .starts_with("CREATE VIEW registry_context.\"breg_spcand_")
        {
            continue;
        }
        sql.push_str(&statement.sql);
        sql.push_str(";\n");
    }
    sql.push_str(&format!(
        "REVOKE ALL ON TABLE registry_data.{table} FROM PUBLIC, {};\n\
         GRANT SELECT, INSERT, UPDATE ON TABLE registry_data.{table} TO {};\n",
        quote(runtime_role.as_str()),
        quote(runtime_role.as_str())
    ));
    for view in site_views {
        let privileges = view
            .runtime_privileges
            .iter()
            .map(|privilege| privilege.as_sql())
            .collect::<Vec<_>>()
            .join(", ");
        sql.push_str(&format!(
            "REVOKE ALL ON TABLE {}.{} FROM PUBLIC, {};\n",
            quote(&view.schema),
            quote(&view.name),
            quote(runtime_role.as_str())
        ));
        if !privileges.is_empty() {
            sql.push_str(&format!(
                "GRANT {privileges} ON TABLE {}.{} TO {};\n",
                quote(&view.schema),
                quote(&view.name),
                quote(runtime_role.as_str())
            ));
        }
    }
    sql.into_bytes()
}

async fn restore_synthetic_backup(
    database: &TestDatabase,
    binding: &ExternalBackupBinding,
    backup_path: &std::path::Path,
) {
    let bytes = fs::read(backup_path).expect("operator reads retained backup artifact");
    assert_eq!(bytes.len() as u64, binding.byte_length);
    assert_eq!(digest(&bytes), binding.sha256);
    let sql = std::str::from_utf8(&bytes).expect("synthetic backup is UTF-8 SQL");
    let (migration, task) = database.connect_migration().await;
    migration
        .batch_execute(sql)
        .await
        .expect("operator executes the digest-verified restoration bytes");
    task.abort();
}

async fn apply(
    database: &TestDatabase,
    package: &VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
) -> registry_breg::migration::Result<ExpectedRegistryIdentity> {
    apply_verified_package(request(database, package, precondition)).await
}

async fn apply_with_evidence(
    database: &TestDatabase,
    package: &VerifiedPackage,
    current: &ExpectedRegistryIdentity,
    evidence: &[DestructiveBackupEvidence<'_>],
) -> registry_breg::migration::Result<ExpectedRegistryIdentity> {
    apply_verified_package(
        request(database, package, ApplyPrecondition::Successor { current })
            .with_destructive_backup_evidence(evidence),
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

async fn assert_record_work_is_blocked(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    active: &ExpectedRegistryIdentity,
) {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool.get_for_test().await.expect("runtime connects");
    let claims = ClaimContext::for_compiled(
        registry,
        "site",
        Some("spatial-migration-reader".to_owned()),
        "reader",
        None,
        Vec::new(),
    )
    .expect("claim context is compiler-bound");
    let lock_key = RegistryLockKey::derive(registry.registry_id()).expect("lock key is bounded");
    match begin_record_transaction(
        &mut runtime,
        lock_key,
        Duration::from_secs(1),
        active,
        &claims,
    )
    .await
    {
        Err(registry_breg::postgres::PostgresKernelError::RegistryUnavailable) => {}
        Err(error) => panic!("record transaction returned the wrong closed error: {error:?}"),
        Ok(transaction) => {
            transaction
                .rollback()
                .await
                .expect("unexpected transaction rolls back");
            panic!("record work entered while failed maintenance was unavailable");
        }
    };
}

async fn assert_non_ready_target(
    database: &TestDatabase,
    active: &ExpectedRegistryIdentity,
    target: &VerifiedPackage,
    expected_status: &str,
) {
    let row = database
        .admin
        .query_one(
            "SELECT active_package_revision, maintenance_status, maintenance_target_revision
             FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("maintenance state reads");
    assert_eq!(row.get::<_, String>(0), active.package_revision);
    assert_eq!(row.get::<_, String>(1), expected_status);
    assert_eq!(
        row.get::<_, Option<String>>(2).as_deref(),
        Some(target.manifest().package_revision.as_str())
    );
}

async fn assert_ready_target(database: &TestDatabase, expected: &ExpectedRegistryIdentity) {
    let row = database
        .admin
        .query_one(
            "SELECT active_package_revision, schema_fingerprint, package_sequence,
                    maintenance_status, maintenance_target_revision
             FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("ready state reads");
    assert_eq!(row.get::<_, String>(0), expected.package_revision);
    assert_eq!(row.get::<_, String>(1), expected.schema_fingerprint);
    assert_eq!(row.get::<_, i64>(2), expected.package_sequence);
    assert_eq!(row.get::<_, String>(3), "ready");
    assert_eq!(row.get::<_, Option<String>>(4), None);
}

async fn assert_legacy_column_absent(database: &TestDatabase, prior: &CompiledRegistry) {
    let entity = &prior.entities()["site"];
    let row = database
        .admin
        .query_one(
            "SELECT count(*)
             FROM information_schema.columns
             WHERE table_schema = 'registry_data'
               AND table_name = $1
               AND column_name = $2",
            &[
                &entity.physical_table,
                &entity.fields["legacy"].physical_name,
            ],
        )
        .await
        .expect("column absence reads");
    assert_eq!(row.get::<_, i64>(0), 0);
}

async fn cleanup_bbox_role(database: &TestDatabase, bbox_role: &SqlIdentifier) {
    database
        .admin
        .batch_execute(&format!(
            "DO $breg_spatial_cleanup$\n\
             DECLARE\n\
                 policy record;\n\
                 role_oid oid;\n\
             BEGIN\n\
                 SELECT oid INTO role_oid FROM pg_catalog.pg_roles WHERE rolname = '{}';\n\
                 IF role_oid IS NULL THEN\n\
                     RETURN;\n\
                 END IF;\n\
                 FOR policy IN\n\
                     SELECT n.nspname, c.relname, p.polname\n\
                     FROM pg_catalog.pg_policy p\n\
                     JOIN pg_catalog.pg_class c ON c.oid = p.polrelid\n\
                     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace\n\
                     WHERE role_oid = ANY(p.polroles)\n\
                 LOOP\n\
                     EXECUTE format(\n\
                         'DROP POLICY IF EXISTS %I ON %I.%I',\n\
                         policy.polname,\n\
                         policy.nspname,\n\
                         policy.relname\n\
                     );\n\
                 END LOOP;\n\
             END;\n\
             $breg_spatial_cleanup$;\n\
             DROP OWNED BY {};\n\
             REVOKE ALL ON SCHEMA registry_spatial_ext FROM {};\n\
             REVOKE {} FROM {};\n\
             REVOKE {} FROM {};\n\
             DROP ROLE IF EXISTS {};",
            bbox_role.as_str().replace('\'', "''"),
            quote(bbox_role.as_str()),
            quote(bbox_role.as_str()),
            quote(bbox_role.as_str()),
            quote(database.migration_role.as_str()),
            quote(bbox_role.as_str()),
            quote(database.runtime_role.as_str()),
            quote(bbox_role.as_str()),
        ))
        .await
        .expect("test cleanup removes temporary spatial bbox role");
}

async fn cleanup_postgis_prerequisites(database: &TestDatabase, bbox_role: &SqlIdentifier) {
    cleanup_bbox_role(database, bbox_role).await;
    database
        .admin
        .batch_execute(
            "DROP EXTENSION IF EXISTS postgis;\n\
             DROP SCHEMA IF EXISTS registry_spatial_ext;",
        )
        .await
        .expect("test cleanup removes temporary PostGIS objects");
}

fn assert_value_free(actual: Option<MigrationError>, expected: MigrationError) {
    let actual = actual.expect("operation must fail");
    assert_eq!(actual, expected);
    let diagnostic = format!("{actual:?} {actual}");
    for canary in ["SITE-001", "legacy-1", "spatial-restore", "registry_data"] {
        assert!(!diagnostic.contains(canary));
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
