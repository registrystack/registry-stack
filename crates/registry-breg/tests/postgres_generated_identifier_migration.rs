// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling", unix))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::time::Duration;

use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_json};
use registry_breg::migration::{
    apply_verified_package, ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest, MigrationError, ReviewedMigrationFaultPoint,
};
use registry_breg::migration_plan::{
    ArtifactDigestBinding, ChunkCursorProtocol, MigrationRehearsalReceipt, RehearsalFixture,
    RehearsalRowAssertion, ReviewedChangeCover, ReviewedMigrationAssertionDescriptor,
    ReviewedMigrationDescriptor, ReviewedMigrationFile, ReviewedMigrationObject,
    ReviewedMigrationObjectKind, ReviewedMigrationRecovery, ReviewedMigrationSource,
    ReviewedMigrationStepDescriptor,
};
use registry_breg::package::{
    compiled_registry_change_set, load_package, prepare_package, CompiledRegistryChangeCode,
    PackageBuildRequest, PackageLoadContext, PackageMigrationPlanInput, PackageModuleSource,
    PackageSourceFile, VerifiedPackage,
};
use registry_breg::postgres::{
    index_revisions_for_test, install_compiled_schema, managed_schema_fingerprint,
    ExpectedManagedCatalog, ExpectedRegistryIdentity,
};
use registry_breg::CompiledRegistry;
use registry_platform_canonical_json::canonicalize_json;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const ENVIRONMENT: &str = "local";
const INSTANCE: &str = "generated-identifier-migration-instance";
const DATABASE: &str = "generated-identifier-migration-database";
const SOURCE_REVISION: &str = "generated-identifier-migration-source";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reviewed_activation_preserves_and_reserves_an_empty_retained_identifier() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    let prior_source = source(false);
    let candidate_source = source(true);
    let prior = compile(&prior_source);
    let candidate = compile(&candidate_source);
    let prior_fingerprint = schema_fingerprint(&database, &prior).await;
    let candidate_fingerprint = schema_fingerprint(&database, &candidate).await;
    let initial = publish_and_load(
        prepare_package(build_request(
            prior_source,
            None,
            &prior_fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ))
        .expect("initial package prepares"),
    );
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("initial package activates");
    seed_retained_rows(&database, &prior, &active).await;

    let changes = compiled_registry_change_set(&prior, &candidate, &active.package_digest)
        .changes
        .into_iter()
        .filter(|change| {
            matches!(
                change.code,
                CompiledRegistryChangeCode::FieldRequirednessChanged
                    | CompiledRegistryChangeCode::FieldGenerationChanged
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        changes.len(),
        2,
        "generation makes the optional retained field required"
    );
    let successor = publish_and_load(
        prepare_package(build_request(
            candidate_source,
            Some(&active.package_digest),
            &candidate_fingerprint,
            PackageMigrationPlanInput::ReviewedSuccessor {
                prior_registry: Box::new(prior.clone()),
                prior_schema_fingerprint: active.schema_fingerprint.clone(),
                migrations: reviewed_migrations(
                    &active,
                    &candidate,
                    &candidate_fingerprint,
                    &changes,
                ),
            },
        ))
        .expect("reviewed successor package prepares"),
    );

    let interrupted = apply_verified_package(
        apply_request(
            &database,
            &successor,
            ApplyPrecondition::Successor { current: &active },
        )
        .with_fault_for_test(ReviewedMigrationFaultPoint::AfterCommittedChunk(1)),
    )
    .await;
    assert_eq!(interrupted, Err(MigrationError::ApplyFailed));
    assert_eq!(
        backfill_step(&database, &successor).await,
        ("applying".to_owned(), 1)
    );
    assert_eq!(
        retained_codes(&database, &candidate).await,
        vec![String::new(), "legacy-two".to_owned()],
        "the first backfill chunk is durable"
    );
    assert_eq!(reservation_count(&database).await, 0);
    assert!(
        !unique_constraint_exists(&database, &candidate).await,
        "reservation seeding and uniqueness stay behind the reviewed backfill"
    );
    let interrupted_activation = activation_for(&database, &successor).await;

    let activated = apply(
        &database,
        &successor,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("the exact reviewed successor resumes and activates");
    assert_eq!(activated.activation_id, interrupted_activation);
    assert_eq!(
        backfill_step(&database, &successor).await,
        ("completed".to_owned(), 2)
    );
    assert_eq!(
        retained_codes(&database, &candidate).await,
        vec![String::new(), "REG-000008".to_owned()]
    );
    assert_eq!(
        reserved_values(&database).await,
        vec![String::new(), "REG-000008".to_owned()]
    );
    assert_eq!(sequence_head(&database).await, "9");
    assert!(
        unique_constraint_exists(&database, &candidate).await,
        "the scoped unique constraint lands after retained values are reserved"
    );
    assert!(
        generated_identifier_is_not_null(&database, &candidate).await,
        "the upgraded column matches a freshly installed generated identifier"
    );

    database.cleanup().await;
}

struct Source {
    project: Vec<u8>,
    module: Vec<u8>,
}

fn source(generated: bool) -> Source {
    let mut identifier = json!({
        "id": "registration-code",
        "type": "string",
        "minimumLength": 0,
        "maximumLength": 24,
        "required": generated,
        "classification": "internal"
    });
    if generated {
        identifier["generate"] = json!({
            "type": "sequence",
            "prefix": "REG-",
            "minimumDigits": 6,
            "scope": ["jurisdiction"]
        });
    }
    let module = serde_json::to_vec(&json!({
        "apiVersion": "id.registrystack.org/formats/breg/module/v1alpha1",
        "kind": "BRegModule",
        "id": "core",
        "version": "1",
        "recordTypes": [{
            "id": "record",
            "primaryDataset": "records",
            "route": "records",
            "mutationMode": "mutable",
            "classification": "internal",
            "fields": [
                {
                    "id": "jurisdiction",
                    "type": "string",
                    "maximumLength": 16,
                    "required": true,
                    "classification": "internal"
                },
                identifier
            ],
            "accessProfiles": [{
                "id": "reader",
                "principalClaim": "registry_principal",
                "requiredScopes": "unrestricted",
                "operations": ["get", "list"],
                "readableFields": ["jurisdiction", "registration-code"],
                "rowBoundaries": "unrestricted"
            }]
        }]
    }))
    .expect("module serializes");
    let parsed_module = parse_module_yaml(&module).expect("module parses for its digest");
    let project = serde_json::to_vec(&json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {
            "id": "generated-identifier-migration",
            "version": "1",
            "defaultLanguage": "en",
            "canonicalBaseIri": "https://registry.example.test"
        },
        "package": {"sourceRevision": SOURCE_REVISION},
        "datasets": [{"id": "records"}],
        "manifestProjection": {
            "accessProfile": "reader",
            "classificationCeiling": "internal",
            "catalog": {
                "baseUrl": "https://registry.example.test",
                "title": "Generated Identifier Registry",
                "publisher": {"id": "registry-authority", "name": "Registry Authority"}
            },
            "publicService": {
                "id": "generated-identifier-service",
                "title": "Generated Identifier Registry"
            },
            "datasets": [{
                "id": "records",
                "title": "Records",
                "owner": "Registry Authority",
                "status": "active"
            }],
            "dataServices": [{
                "id": "generated-identifier-data-service",
                "title": "Generated Identifier Registry",
                "endpointUrl": "https://registry.example.test",
                "servesDatasets": ["records"]
            }]
        },
        "modules": [{
            "id": "core",
            "version": "1",
            "digest": module_digest(&parsed_module)
        }]
    }))
    .expect("project serializes");
    Source { project, module }
}

fn compile(source: &Source) -> CompiledRegistry {
    let project = parse_project_json(&source.project).expect("project parses");
    let module = parse_module_yaml(&source.module).expect("module parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("generated identifier migration fixture compiles")
}

fn reviewed_migrations(
    current: &ExpectedRegistryIdentity,
    candidate: &CompiledRegistry,
    final_fingerprint: &str,
    changes: &[registry_breg::package::CompiledRegistryChange],
) -> Vec<ReviewedMigrationSource> {
    let mut migrations = changes
        .iter()
        .map(|change| {
            let id = match change.code {
                CompiledRegistryChangeCode::FieldGenerationChanged => "generate-registration-code",
                CompiledRegistryChangeCode::FieldRequirednessChanged => "require-registration-code",
                _ => panic!("unexpected generated identifier migration change"),
            };
            reviewed_migration(current, candidate, final_fingerprint, change, id)
        })
        .collect::<Vec<_>>();
    migrations.sort_by(|left, right| left.descriptor.path.cmp(&right.descriptor.path));
    migrations
}

fn reviewed_migration(
    current: &ExpectedRegistryIdentity,
    candidate: &CompiledRegistry,
    final_fingerprint: &str,
    change: &registry_breg::package::CompiledRegistryChange,
    id: &str,
) -> ReviewedMigrationSource {
    let entity = &candidate.entities()["record"];
    let field = &entity.fields["registration-code"];
    let base = format!("modules/core/migrations/{id}");
    let step_id = format!("backfill-registration-code-{id}");
    let step_path = format!("{base}/steps/{step_id}.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let fixture_path = format!("{base}/fixtures/retained-records.jsonl");
    let step_sql = format!(
        "UPDATE registry_data.{} SET {} = CASE record_id \
         WHEN '{}'::pg_catalog.uuid THEN '' \
         WHEN '{}'::pg_catalog.uuid THEN 'REG-000008' ELSE {} END \
         WHERE record_id = ANY($1::pg_catalog.uuid[])",
        entity.physical_table,
        field.physical_name,
        Uuid::from_u128(1),
        Uuid::from_u128(2),
        field.physical_name,
    )
    .into_bytes();
    let pre_sql = format!(
        "SELECT pg_catalog.count(*) = 2 FROM registry_data.{}",
        entity.physical_table
    )
    .into_bytes();
    let post_sql = format!(
        "SELECT pg_catalog.count(*) = 2 AND pg_catalog.count(*) = \
         pg_catalog.count(*) FILTER (WHERE {} IS NOT NULL) \
         FROM registry_data.{}",
        field.physical_name, entity.physical_table
    )
    .into_bytes();
    let fixture = b"{\"jurisdiction\":\"north\",\"registrationCode\":\"\"}\n{\"jurisdiction\":\"north\",\"registrationCode\":\"REG-000008\"}\n".to_vec();
    let descriptor = ReviewedMigrationDescriptor {
        id: id.to_owned(),
        change_class: registry_breg::package::CompiledRegistryChangeClass::DataBackfillRequired,
        covers: vec![ReviewedChangeCover::from(change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        history: None,
        lock_timeout_ms: 1_000,
        statement_timeout_ms: 10_000,
        steps: vec![ReviewedMigrationStepDescriptor::ChunkedBackfill {
            id: step_id.clone(),
            entity_id: "record".to_owned(),
            sql_path: step_path.clone(),
            objects: vec![ReviewedMigrationObject {
                schema: "registry_data".to_owned(),
                table: entity.physical_table.clone(),
                entity_id: "record".to_owned(),
                kind: ReviewedMigrationObjectKind::Field,
                member_id: Some("registration-code".to_owned()),
                physical_name: field.physical_name.clone(),
            }],
            cursor: ChunkCursorProtocol::RecordIdUuidArray,
            chunk_size: 1,
            max_total_rows: 2,
            lock_timeout_ms: 1_000,
            statement_timeout_ms: 10_000,
            exact_affected_rows: true,
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
    let descriptor_bytes = canonical(&descriptor);
    let receipt = MigrationRehearsalReceipt {
        prior_package_digest: current.package_digest.clone(),
        prior_schema_fingerprint: current.schema_fingerprint.clone(),
        plan_sha256: digest(&descriptor_bytes),
        sql_sha256: vec![ArtifactDigestBinding {
            path: step_path.clone(),
            sha256: digest(&step_sql),
        }],
        assertion_sha256: vec![
            ArtifactDigestBinding {
                path: pre_path.clone(),
                sha256: digest(&pre_sql),
            },
            ArtifactDigestBinding {
                path: post_path.clone(),
                sha256: digest(&post_sql),
            },
        ],
        fixture_inventory: vec![RehearsalFixture {
            id: "retained-records".to_owned(),
            path: fixture_path.clone(),
            sha256: digest(&fixture),
            row_count: 2,
        }],
        postgres_major: 17,
        row_assertions: vec![RehearsalRowAssertion {
            step_id,
            affected_rows: 2,
        }],
        final_schema_fingerprint: final_fingerprint.to_owned(),
    };
    let mut files = vec![
        ReviewedMigrationFile {
            path: step_path,
            bytes: step_sql,
        },
        ReviewedMigrationFile {
            path: pre_path,
            bytes: pre_sql,
        },
        ReviewedMigrationFile {
            path: post_path,
            bytes: post_sql,
        },
        ReviewedMigrationFile {
            path: descriptor.rehearsal_receipt_path.clone(),
            bytes: canonical(&receipt),
        },
        ReviewedMigrationFile {
            path: fixture_path,
            bytes: fixture,
        },
    ];
    files.sort_by(|left, right| left.path.cmp(&right.path));
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: format!("{base}/descriptor.json"),
            bytes: descriptor_bytes,
        },
        files,
    }
}

fn build_request(
    source: Source,
    prior_revision: Option<&str>,
    schema_fingerprint: &str,
    migration_plan: PackageMigrationPlanInput,
) -> PackageBuildRequest {
    PackageBuildRequest {
        from_package_digest: prior_revision.map(str::to_owned),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        project: PackageSourceFile {
            path: "source/registry.json".to_owned(),
            bytes: source.project,
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.json".to_owned(),
            bytes: source.module,
            assets: Vec::new(),
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: list-records
    steps:
      - id: list-records
        recordType: record
        accessProfile: reader
        claims: {registry_principal: package-reader}
        request: {type: list}
        expect: {outcome: success, status: 200, count: 0}
"#
            .to_vec(),
        },
        migration_plan,
    }
}

fn publish_and_load(prepared: registry_breg::package::PreparedPackage) -> VerifiedPackage {
    let root = tempfile::Builder::new()
        .prefix("registry-generated-identifier-migration-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("package temporary directory creates");
    let package = root.path().join("package");
    prepared
        .publish_to_directory(&package)
        .expect("package publishes");
    load_package(
        &package,
        &PackageLoadContext {
            database_initialization_environment: "local",
        },
    )
    .expect("published package loads")
}

async fn schema_fingerprint(database: &TestDatabase, registry: &CompiledRegistry) -> String {
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("fingerprint transaction starts");
    install_compiled_schema(&transaction, registry, &database.runtime_role)
        .await
        .expect("compiled schema rehearses");
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
    )
    .await
    .expect("managed schema fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("fingerprint rehearsal rolls back");
    task.abort();
    fingerprint
}

async fn apply(
    database: &TestDatabase,
    package: &VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
) -> registry_breg::migration::Result<ExpectedRegistryIdentity> {
    apply_verified_package(apply_request(database, package, precondition)).await
}

fn apply_request<'a>(
    database: &'a TestDatabase,
    package: &'a VerifiedPackage,
    precondition: ApplyPrecondition<'a>,
) -> ApplyVerifiedPackageRequest<'a> {
    ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        package,
        ActivationDeployment::new(ENVIRONMENT, INSTANCE, DATABASE),
        precondition,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
        database.activation_audit(),
    )
}

async fn seed_retained_rows(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    active: &ExpectedRegistryIdentity,
) {
    let entity = &registry.entities()["record"];
    let table = quote(&entity.physical_table);
    let jurisdiction = quote(&entity.fields["jurisdiction"].physical_name);
    let code = quote(&entity.fields["registration-code"].physical_name);
    for (record_id, retained) in [(Uuid::from_u128(1), ""), (Uuid::from_u128(2), "legacy-two")] {
        database
            .admin
            .execute(
                &format!(
                    "INSERT INTO registry_data.{table}
                         (record_id, active_package_revision, {jurisdiction}, {code})
                     VALUES ($1, $2, 'north', $3)"
                ),
                &[&record_id, &active.activation_id, &retained],
            )
            .await
            .expect("retained row inserts");
    }

    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("retained revision transaction starts");
    for (record_id, retained) in [(Uuid::from_u128(1), ""), (Uuid::from_u128(2), "legacy-two")] {
        let snapshot = canonical(&json!({
            "jurisdiction": "north",
            "registration-code": retained,
        }));
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_revisions
                     (entity_id, record_id, record_reference, record_revision,
                      predecessor_revision, record_lifecycle, package_revision, operation_id,
                      mutation_kind, principal_reference, request_reference, snapshot)
                 VALUES ('record', $1, $2, 1, NULL, 'active', $3, 'seed-retained-record',
                         'create', 'actor:hash', 'request:hash', $4)",
                &[
                    &record_id,
                    &format!("record:{record_id}"),
                    &active.activation_id,
                    &snapshot,
                ],
            )
            .await
            .expect("retained revision inserts");
    }
    index_revisions_for_test(
        &transaction,
        &active.activation_id,
        &[
            ("record", Uuid::from_u128(1), 1),
            ("record", Uuid::from_u128(2), 1),
        ],
    )
    .await
    .expect("retained revisions join the current commit allocator");
    transaction
        .commit()
        .await
        .expect("retained revisions commit");
    task.abort();
}

async fn retained_codes(database: &TestDatabase, registry: &CompiledRegistry) -> Vec<String> {
    let entity = &registry.entities()["record"];
    database
        .admin
        .query(
            &format!(
                "SELECT {} FROM registry_data.{} ORDER BY record_id",
                quote(&entity.fields["registration-code"].physical_name),
                quote(&entity.physical_table),
            ),
            &[],
        )
        .await
        .expect("retained identifiers read")
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

async fn reservation_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT pg_catalog.count(*)
               FROM registry_internal.registry_generated_identifier_reservations
              WHERE entity_id = 'record' AND field_id = 'registration-code'",
            &[],
        )
        .await
        .expect("reservation count reads")
        .get(0)
}

async fn reserved_values(database: &TestDatabase) -> Vec<String> {
    database
        .admin
        .query(
            "SELECT generated_value
               FROM registry_internal.registry_generated_identifier_reservations
              WHERE entity_id = 'record'
                AND field_id = 'registration-code'
                AND scope_values = '[\"north\"]'::jsonb
              ORDER BY generated_value",
            &[],
        )
        .await
        .expect("retained reservations read")
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

async fn sequence_head(database: &TestDatabase) -> String {
    database
        .admin
        .query_one(
            "SELECT next_value::text
               FROM registry_internal.registry_generated_identifier_counters
              WHERE entity_id = 'record'
                AND field_id = 'registration-code'
                AND scope_values = '[\"north\"]'::jsonb",
            &[],
        )
        .await
        .expect("sequence head reads")
        .get(0)
}

async fn unique_constraint_exists(database: &TestDatabase, registry: &CompiledRegistry) -> bool {
    let entity = &registry.entities()["record"];
    let constraint =
        &registry.physical_names().entities["record"].constraints["generated:registration-code"];
    database
        .admin
        .query_one(
            "SELECT EXISTS (
                 SELECT 1
                   FROM pg_catalog.pg_constraint c
                   JOIN pg_catalog.pg_class t ON t.oid = c.conrelid
                   JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
                  WHERE n.nspname = 'registry_data'
                    AND t.relname = $1
                    AND c.conname = $2
                    AND c.contype = 'u'
             )",
            &[&entity.physical_table, constraint],
        )
        .await
        .expect("generated identifier constraint reads")
        .get(0)
}

async fn generated_identifier_is_not_null(
    database: &TestDatabase,
    registry: &CompiledRegistry,
) -> bool {
    let entity = &registry.entities()["record"];
    database
        .admin
        .query_one(
            "SELECT a.attnotnull
               FROM pg_catalog.pg_attribute a
               JOIN pg_catalog.pg_class t ON t.oid = a.attrelid
               JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
              WHERE n.nspname = 'registry_data'
                AND t.relname = $1
                AND a.attname = $2
                AND NOT a.attisdropped",
            &[
                &entity.physical_table,
                &entity.fields["registration-code"].physical_name,
            ],
        )
        .await
        .expect("generated identifier nullability reads")
        .get(0)
}

async fn backfill_step(database: &TestDatabase, package: &VerifiedPackage) -> (String, i64) {
    let row = database
        .admin
        .query_one(
            "SELECT outcome, affected_rows
               FROM registry_internal.registry_migration_steps
              WHERE activation_id = (
                        SELECT activation_id
                          FROM registry_internal.registry_migrations
                         WHERE package_digest = $1
                         ORDER BY apply_order DESC
                         LIMIT 1
                    )
                AND step_id = 'backfill-registration-code-generate-registration-code'",
            &[&package.package_digest()],
        )
        .await
        .expect("backfill checkpoint reads");
    (row.get(0), row.get(1))
}

async fn activation_for(database: &TestDatabase, package: &VerifiedPackage) -> String {
    database
        .admin
        .query_one(
            "SELECT activation_id::text
               FROM registry_internal.registry_migrations
              WHERE package_digest = $1
              ORDER BY apply_order DESC
              LIMIT 1",
            &[&package.package_digest()],
        )
        .await
        .expect("interrupted activation reads")
        .get(0)
}

fn canonical(value: &impl Serialize) -> Vec<u8> {
    canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes")
}

fn digest(bytes: &[u8]) -> String {
    let mut rendered = String::from("sha256:");
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        write!(&mut rendered, "{byte:02x}").expect("digest writes");
    }
    rendered
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
