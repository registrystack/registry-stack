// SPDX-License-Identifier: Apache-2.0

use super::*;
use registry_breg::contract::parse_project_json;
#[cfg(feature = "tooling")]
use registry_breg::migration_plan::{ArtifactDigestBinding, ReviewedMigrationAssertionDescriptor};
use registry_breg::package::MAX_MIGRATION_STATEMENTS;
use serde_json::{json, Value};

const OLD_MIGRATION_STATEMENT_LIMIT: usize = 1_024;

const PROPOSAL_OPERATIONS: &[&str] = &["get", "list", "edit", "submit", "cancel", "apply"];

fn reviewed_flow_project(profile_count: usize, proposal_operations: &[&str]) -> Value {
    let record_types = (0..3)
        .map(|ordinal| {
            json!({
                "id": format!("case-{ordinal}"),
                "primaryDataset": "cases",
                "route": format!("cases-{ordinal}"),
                "mutationMode": "mutable",
                "mutationPolicy": {"patch": "proposal-required"},
                "fields": [{
                    "id": "label", "type": "string", "required": true,
                    "maximumLength": 80, "classification": "internal"
                }]
            })
        })
        .collect::<Vec<_>>();
    let actions = (0..4)
        .map(|flow| {
            let inputs = (0..3)
                .flat_map(|target| {
                    [
                        json!({
                            "id": format!("case-{target}"),
                            "type": "reference", "target": format!("case-{target}"),
                            "required": true, "classification": "internal"
                        }),
                        json!({
                            "id": format!("case-{target}-label"),
                            "type": "string", "required": true,
                            "maximumLength": 80, "classification": "internal"
                        }),
                    ]
                })
                .collect::<Vec<_>>();
            let effects = (0..3)
                .map(|target| {
                    json!({
                        "id": format!("update-{target}"),
                        "target": {"fromInput": format!("case-{target}")},
                        "operation": "patch",
                        "set": {"label": {"fromInput": format!("case-{target}-label")}}
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "id": format!("review-flow-{flow}"),
                "execution": {"mode": "proposal", "proposal": {
                    "review": {"type": "none"},
                    "application": {"mode": "manual"},
                    "retention": {"mode": "retain"}
                }},
                "inputs": inputs,
                "plan": {"type": "fixed", "effects": effects}
            })
        })
        .collect::<Vec<_>>();
    let targets = (0..3)
        .map(|target| {
            json!({"recordType": format!("case-{target}"), "rowBoundaries": "unrestricted"})
        })
        .collect::<Vec<_>>();
    let readable_inputs = (0..3)
        .flat_map(|target| [format!("case-{target}"), format!("case-{target}-label")])
        .collect::<Vec<_>>();
    let access_profiles = (0..profile_count)
        .map(|profile| {
            let action_permissions = (0..4)
                .map(|flow| {
                    json!({
                        "action": format!("review-flow-{flow}"),
                        "operations": ["start"],
                        "targets": targets
                    })
                })
                .collect::<Vec<_>>();
            let proposal_permissions = if proposal_operations.is_empty() {
                Vec::new()
            } else {
                (0..4)
                    .map(|flow| {
                        json!({
                            "action": format!("review-flow-{flow}"),
                            "operations": proposal_operations,
                            "ownership": "caller",
                            "readableInputs": readable_inputs,
                            "targets": targets
                        })
                    })
                    .collect::<Vec<_>>()
            };
            let mut permissions = json!({
                "actions": action_permissions,
                "proposals": proposal_permissions
            });
            if profile == 0 {
                permissions["records"] = json!([{
                    "recordType": "case-0", "operations": ["get", "list"],
                    "readableFields": ["label"], "rowBoundaries": "unrestricted"
                }]);
            }
            json!({
                "id": format!("reviewer-{profile}"),
                "default": profile == 0,
                "principalClaim": "principal",
                "requiredScopes": [format!("review:{profile}")],
                "permissions": permissions
            })
        })
        .collect::<Vec<_>>();

    json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {
            "id": "review-capacity", "version": "1", "defaultLanguage": "en",
            "canonicalBaseIri": "https://review-capacity.example.test"
        },
        "package": {"sourceRevision": SOURCE_REVISION},
        "manifestProjection": {
            "accessProfile": "reviewer-0", "classificationCeiling": "internal",
            "catalog": {
                "baseUrl": "https://review-capacity.example.test",
                "title": "Review Capacity Registry",
                "publisher": {"id": "review-authority", "name": "Review Authority"}
            },
            "publicService": {"id": "review-service", "title": "Review Service"},
            "datasets": [{
                "id": "cases", "title": "Cases", "owner": "Review Authority", "status": "active"
            }],
            "dataServices": [{
                "id": "review-api", "title": "Review API",
                "endpointUrl": "https://review-capacity.example.test", "servesDatasets": ["cases"]
            }],
            "distributions": []
        },
        "datasets": [{"id": "cases"}],
        "recordTypes": record_types,
        "actions": actions,
        "accessProfiles": access_profiles
    })
}

fn capacity_request(
    project_bytes: Vec<u8>,
    schema_fingerprint: String,
    from_package_digest: Option<String>,
    migration_plan: PackageMigrationPlanInput,
) -> PackageBuildRequest {
    PackageBuildRequest {
        from_package_digest,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint,
        project: PackageSourceFile {
            path: "source/registry.json".to_owned(),
            bytes: project_bytes,
        },
        modules: Vec::new(),
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan,
    }
}

#[cfg(feature = "tooling")]
fn preassertion_review_source(
    changes: &[registry_breg::package::CompiledRegistryChange],
    prior_revision: &str,
    prior_schema_fingerprint: &str,
    final_schema_fingerprint: &str,
    physical_table: &str,
) -> ReviewedMigrationSource {
    let mut covers = changes
        .iter()
        .filter(|change| change.class != CompiledRegistryChangeClass::CompatibleAdditive)
        .map(ReviewedChangeCover::from)
        .collect::<Vec<_>>();
    covers.sort();
    assert!(!covers.is_empty());
    let base = "modules/core/migrations/capacity-access";
    let assertion_path = format!("{base}/assertions/pre.sql");
    let assertion_sql =
        format!("SELECT pg_catalog.count(*) >= 0 FROM registry_data.{physical_table}");
    let descriptor = ReviewedMigrationDescriptor {
        id: "capacity-access".to_owned(),
        change_class: CompiledRegistryChangeClass::AccessOrDisclosureChange,
        covers,
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        history: None,
        lock_timeout_ms: 100,
        statement_timeout_ms: 1_000,
        steps: Vec::new(),
        pre_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "pre".to_owned(),
            sql_path: assertion_path.clone(),
        }],
        post_assertions: Vec::new(),
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    let descriptor_bytes =
        canonicalize_json(&serde_json::to_value(&descriptor).expect("descriptor serializes"))
            .expect("descriptor canonicalizes");
    let receipt = MigrationRehearsalReceipt {
        prior_package_digest: prior_revision.to_owned(),
        prior_schema_fingerprint: prior_schema_fingerprint.to_owned(),
        plan_sha256: format!("sha256:{}", hex(&Sha256::digest(&descriptor_bytes))),
        sql_sha256: Vec::new(),
        assertion_sha256: vec![ArtifactDigestBinding {
            path: assertion_path.clone(),
            sha256: format!("sha256:{}", hex(&Sha256::digest(assertion_sql.as_bytes()))),
        }],
        fixture_inventory: Vec::new(),
        postgres_major: 17,
        row_assertions: Vec::new(),
        final_schema_fingerprint: final_schema_fingerprint.to_owned(),
    };
    let mut files = vec![
        ReviewedMigrationFile {
            path: assertion_path,
            bytes: assertion_sql.into_bytes(),
        },
        ReviewedMigrationFile {
            path: descriptor.rehearsal_receipt_path.clone(),
            bytes: canonicalize_json(&serde_json::to_value(receipt).expect("receipt serializes"))
                .expect("receipt canonicalizes"),
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

/// Puts back the 1,024-statement ledger constraint an earlier release
/// installed, and returns the schema fingerprint of the catalog that leaves.
async fn reinstall_legacy_statement_constraint(
    database: &TestDatabase,
    registry: &registry_breg::CompiledRegistry,
) -> String {
    database
        .admin
        .batch_execute(
            "ALTER TABLE registry_internal.registry_migrations
                 DROP CONSTRAINT registry_migrations_statement_checksums_bounded_v2;
             ALTER TABLE registry_internal.registry_migrations
                 ADD CONSTRAINT registry_migrations_checksums_nonempty
                 CHECK (
                     COALESCE(array_ndims(statement_checksums), 1) = 1
                     AND cardinality(statement_checksums) BETWEEN 0 AND 1024
                     AND array_position(statement_checksums, '') IS NULL
                     AND (
                         (migration_kind = 'metadata-only' AND cardinality(statement_checksums) = 0)
                         OR (migration_kind = 'reviewed' AND cardinality(statement_checksums) = 0)
                         OR (migration_kind IN ('compiled-additive', 'reviewed')
                             AND cardinality(statement_checksums) BETWEEN 1 AND 1024)
                     )
                 );",
        )
        .await
        .expect("fixture reinstalls the legacy statement constraint");
    let (migration, migration_task) = database.connect_migration().await;
    let legacy_fingerprint = managed_schema_fingerprint(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
    )
    .await
    .expect("the legacy ledger catalog fingerprints");
    drop(migration);
    migration_task.abort();
    legacy_fingerprint
}

/// The ledger statement constraints present: (v2, legacy).
async fn ledger_statement_constraints(database: &TestDatabase) -> (bool, bool) {
    let row = database
        .admin
        .query_one(
            "SELECT
                 EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                     WHERE conrelid = 'registry_internal.registry_migrations'::regclass
                       AND conname = 'registry_migrations_statement_checksums_bounded_v2'
                 ),
                 EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                     WHERE conrelid = 'registry_internal.registry_migrations'::regclass
                       AND conname = 'registry_migrations_checksums_nonempty'
                 )",
            &[],
        )
        .await
        .expect("ledger constraints are inspectable");
    (row.get(0), row.get(1))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reviewed_flow_package_beyond_the_old_statement_limit_prepares_and_activates() {
    let source = serde_json::to_vec(&reviewed_flow_project(4, PROPOSAL_OPERATIONS))
        .expect("fixture serializes");
    let project = parse_project_json(&source).expect("fixture project parses");
    let compiled = compile_project(&project, &[], CompileProfile::Production)
        .expect("reviewed-flow fixture compiles in production");
    let statement_count = compiled.ddl().statements.len();
    assert!(statement_count > OLD_MIGRATION_STATEMENT_LIMIT);
    assert!(statement_count <= MAX_MIGRATION_STATEMENTS);

    let database = TestDatabase::create(1).await;
    let schema_fingerprint = measure_fresh_compiled_schema(&database, &compiled).await;
    let prepared = prepare_package(capacity_request(
        source,
        schema_fingerprint,
        None,
        PackageMigrationPlanInput::InitialCompiledDdl,
    ))
    .expect("a reviewed-flow package beyond the old statement limit prepares");
    assert_eq!(
        prepared.manifest().migration_plan.statements.len(),
        statement_count
    );

    let root = TempRoot::create();
    prepared
        .publish_to_directory(root.path())
        .expect("capacity package publishes");
    let package = load_package(root.path(), &local_context()).expect("capacity package verifies");
    let active = apply_package(
        &database,
        &package,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(30),
        Duration::from_secs(60),
    )
    .await
    .expect("the full migration activates through the durable ledger");

    let recorded_statements: i32 = database
        .admin
        .query_one(
            "SELECT cardinality(statement_checksums) FROM registry_internal.registry_migrations WHERE activation_id = $1::text::uuid",
            &[&active.activation_id],
        )
        .await
        .expect("the activation has one durable ledger row")
        .get(0);
    assert_eq!(recorded_statements as usize, statement_count);
    database.cleanup().await;
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reviewed_successor_upgrades_the_legacy_ledger_and_applies_more_than_1024_statements() {
    let prior_source =
        serde_json::to_vec(&reviewed_flow_project(5, &[])).expect("prior fixture serializes");
    let candidate_source = serde_json::to_vec(&reviewed_flow_project(5, PROPOSAL_OPERATIONS))
        .expect("candidate fixture serializes");
    let prior_project = parse_project_json(&prior_source).expect("prior fixture parses");
    let candidate_project =
        parse_project_json(&candidate_source).expect("candidate fixture parses");
    let prior = compile_project(&prior_project, &[], CompileProfile::Production)
        .expect("prior fixture compiles");
    let candidate = compile_project(&candidate_project, &[], CompileProfile::Production)
        .expect("candidate fixture compiles");

    let database = TestDatabase::create(1).await;
    let prior_fingerprint = measure_fresh_compiled_schema(&database, &prior).await;
    let candidate_fingerprint = measure_fresh_compiled_schema(&database, &candidate).await;
    let prior_prepared = prepare_package(capacity_request(
        prior_source,
        prior_fingerprint,
        None,
        PackageMigrationPlanInput::InitialCompiledDdl,
    ))
    .expect("prior package prepares");
    let prior_root = TempRoot::create();
    prior_prepared
        .publish_to_directory(prior_root.path())
        .expect("prior package publishes");
    let prior_package =
        load_package(prior_root.path(), &local_context()).expect("prior package verifies");
    let mut current = apply_package(
        &database,
        &prior_package,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(30),
        Duration::from_secs(60),
    )
    .await
    .expect("prior package activates");

    let legacy_fingerprint = reinstall_legacy_statement_constraint(&database, &prior).await;
    assert_ne!(
        legacy_fingerprint, current.schema_fingerprint,
        "the constraint version belongs to the managed schema fingerprint"
    );
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET schema_fingerprint = $1
             WHERE singleton AND active_activation_id = $2::text::uuid",
            &[&legacy_fingerprint, &current.activation_id],
        )
        .await
        .expect("fixture records the historical active fingerprint");
    current.schema_fingerprint = legacy_fingerprint;

    let changes = compiled_registry_change_set(&prior, &candidate, &current.package_digest);
    let review = preassertion_review_source(
        &changes.changes,
        &current.package_digest,
        &current.schema_fingerprint,
        &candidate_fingerprint,
        &candidate.entities()["case-0"].physical_table,
    );
    let candidate_prepared = prepare_package(capacity_request(
        candidate_source,
        candidate_fingerprint,
        Some(current.package_digest.clone()),
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(prior),
            prior_schema_fingerprint: current.schema_fingerprint.clone(),
            migrations: vec![review],
        },
    ))
    .expect("reviewed successor beyond the legacy statement limit prepares");
    let statement_count = candidate_prepared
        .manifest()
        .migration_plan
        .statements
        .len();
    assert!(statement_count > OLD_MIGRATION_STATEMENT_LIMIT);
    assert!(statement_count <= MAX_MIGRATION_STATEMENTS);
    let ledger_statement_count = statement_count + 1;
    assert!(ledger_statement_count <= MAX_MIGRATION_STATEMENTS);
    let candidate_root = TempRoot::create();
    candidate_prepared
        .publish_to_directory(candidate_root.path())
        .expect("reviewed successor publishes");
    let candidate_package =
        load_package(candidate_root.path(), &local_context()).expect("reviewed successor verifies");
    for _ in 0..2 {
        plan_verified_package(ApplyVerifiedPackageRequest::plan(
            &database.migration_config,
            &candidate_package,
            ActivationDeployment::new("local", INSTANCE, DATABASE),
            ApplyPrecondition::Successor { current: &current },
            ApplyRoles::new(&database.migration_role, &database.runtime_role),
            ApplyTimeouts::new(Duration::from_secs(30), Duration::from_secs(60))
                .expect("capacity timeouts are bounded"),
        ))
        .await
        .expect("repeated rehearsal accepts the legacy constraint upgrade atomically");
    }
    let legacy_constraint_remains: bool = database
        .admin
        .query_one(
            "SELECT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_constraint
                 WHERE conrelid = 'registry_internal.registry_migrations'::regclass
                   AND conname = 'registry_migrations_checksums_nonempty'
             )",
            &[],
        )
        .await
        .expect("legacy constraint remains after rolled-back rehearsals")
        .get(0);
    assert!(legacy_constraint_remains);

    let table = &candidate.entities()["case-0"].physical_table;
    let (mut blocker_client, blocker_task) = database.connect_migration().await;
    let blocker = blocker_client
        .transaction()
        .await
        .expect("capacity blocker transaction starts");
    blocker
        .batch_execute(&format!(
            "LOCK TABLE registry_data.{table} IN ACCESS EXCLUSIVE MODE"
        ))
        .await
        .expect("capacity blocker holds the pre-assertion table");
    let refused = apply_package(
        &database,
        &candidate_package,
        ApplyPrecondition::Successor { current: &current },
        Duration::from_secs(30),
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(refused.err(), Some(MigrationError::ApplyFailed));
    blocker
        .rollback()
        .await
        .expect("capacity blocker rolls back");
    blocker_task.abort();
    let pinned = database
        .admin
        .query_one(
            "SELECT maintenance_status, maintenance_target_package_digest,
                    EXISTS (
                        SELECT 1 FROM pg_catalog.pg_constraint
                        WHERE conrelid = 'registry_internal.registry_migrations'::regclass
                          AND conname = 'registry_migrations_statement_checksums_bounded_v2'
                    ),
                    EXISTS (
                        SELECT 1 FROM pg_catalog.pg_constraint
                        WHERE conrelid = 'registry_internal.registry_migrations'::regclass
                          AND conname = 'registry_migrations_checksums_nonempty'
                    )
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await
        .expect("failed capacity activation remains inspectable");
    assert_eq!(pinned.get::<_, String>(0), "failed");
    assert_eq!(
        pinned.get::<_, Option<String>>(1).as_deref(),
        Some(candidate_package.package_digest())
    );
    assert!(pinned.get::<_, bool>(2));
    assert!(!pinned.get::<_, bool>(3));

    let active = apply_package(
        &database,
        &candidate_package,
        ApplyPrecondition::Successor { current: &current },
        Duration::from_secs(30),
        Duration::from_secs(60),
    )
    .await
    .expect("the exact target resumes after the transient pre-assertion lock clears");
    let ledger = database
        .admin
        .query_one(
            "SELECT cardinality(statement_checksums),
                    EXISTS (
                        SELECT 1 FROM pg_catalog.pg_constraint
                        WHERE conrelid = 'registry_internal.registry_migrations'::regclass
                          AND conname = 'registry_migrations_statement_checksums_bounded_v2'
                    ),
                    EXISTS (
                        SELECT 1 FROM pg_catalog.pg_constraint
                        WHERE conrelid = 'registry_internal.registry_migrations'::regclass
                          AND conname = 'registry_migrations_checksums_nonempty'
                    )
             FROM registry_internal.registry_migrations
             WHERE activation_id = $1::text::uuid",
            &[&active.activation_id],
        )
        .await
        .expect("successor ledger row and constraint are durable");
    let ledger = (
        ledger.get::<_, i32>(0),
        ledger.get::<_, bool>(1),
        ledger.get::<_, bool>(2),
    );
    assert_eq!(ledger, (ledger_statement_count as i32, true, false));
    database.cleanup().await;
}

/// A role change re-applies the active package and runs no DDL, so a registry
/// an earlier release activated keeps the ledger constraint the schema
/// fingerprint of that package covers. Only a successor widens the ledger.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn role_change_keeps_the_legacy_ledger_constraint_its_active_package_declares() {
    let source = serde_json::to_vec(&reviewed_flow_project(1, &[])).expect("fixture serializes");
    let project = parse_project_json(&source).expect("fixture project parses");
    let compiled = compile_project(&project, &[], CompileProfile::Production)
        .expect("fixture compiles in production");

    let database = TestDatabase::create(1).await;
    let fingerprint = measure_fresh_compiled_schema(&database, &compiled).await;
    let prepared = prepare_package(capacity_request(
        source.clone(),
        fingerprint,
        None,
        PackageMigrationPlanInput::InitialCompiledDdl,
    ))
    .expect("package prepares");
    let root = TempRoot::create();
    prepared
        .publish_to_directory(root.path())
        .expect("package publishes");
    let package = load_package(root.path(), &local_context()).expect("package verifies");
    let active = apply_package(
        &database,
        &package,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(30),
        Duration::from_secs(60),
    )
    .await
    .expect("package activates");

    // The registry as an earlier release left it: the legacy ledger
    // constraint, and an active package whose declared schema fingerprint
    // was measured with that constraint.
    let legacy_fingerprint = reinstall_legacy_statement_constraint(&database, &compiled).await;
    let legacy_prepared = prepare_package(capacity_request(
        source,
        legacy_fingerprint.clone(),
        None,
        PackageMigrationPlanInput::InitialCompiledDdl,
    ))
    .expect("the earlier release's package prepares");
    let legacy_root = TempRoot::create();
    legacy_prepared
        .publish_to_directory(legacy_root.path())
        .expect("the earlier release's package publishes");
    let legacy_package = load_package(legacy_root.path(), &local_context())
        .expect("the earlier release's package verifies");
    database
        .admin
        .batch_execute(&format!(
            "UPDATE registry_internal.registry_state
             SET active_package_digest = '{digest}', schema_fingerprint = '{legacy_fingerprint}'
             WHERE singleton AND active_activation_id = '{activation}'::uuid;
             UPDATE registry_internal.registry_migrations
             SET package_digest = '{digest}'
             WHERE activation_id = '{activation}'::uuid;",
            digest = legacy_package.package_digest(),
            activation = active.activation_id,
        ))
        .await
        .expect("fixture records the earlier release's active package");
    let current = ExpectedRegistryIdentity {
        package_digest: legacy_package.package_digest().to_owned(),
        schema_fingerprint: legacy_fingerprint.clone(),
        ..active
    };

    // The re-apply serves with the migration role alone, so it is a role
    // change rather than a re-apply that leaves nothing to activate.
    let reapplied = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        &legacy_package,
        ActivationDeployment::new("local", INSTANCE, DATABASE),
        ApplyPrecondition::RoleChange { current: &current },
        ApplyRoles::new(&database.migration_role, &database.migration_role),
        ApplyTimeouts::new(Duration::from_secs(30), Duration::from_secs(60))
            .expect("role change timeouts are bounded"),
        database.activation_audit(),
    ))
    .await
    .expect("the role change re-applies the package the earlier release activated");
    assert_eq!(reapplied.schema_fingerprint, legacy_fingerprint);
    assert_eq!(ledger_statement_constraints(&database).await, (false, true));
    database.cleanup().await;
}
