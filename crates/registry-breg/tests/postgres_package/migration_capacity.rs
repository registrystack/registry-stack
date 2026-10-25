// SPDX-License-Identifier: Apache-2.0

use super::*;
use registry_breg::contract::parse_project_json;
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
    let current = apply_package(
        &database,
        &prior_package,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(30),
        Duration::from_secs(60),
    )
    .await
    .expect("prior package activates");

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

    let changes = compiled_registry_change_set(&prior, &candidate, &current.package_digest);
    let review = metadata_only_review_source(
        &changes.changes,
        &current.package_digest,
        &current.schema_fingerprint,
        &candidate_fingerprint,
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

    let active = apply_package(
        &database,
        &candidate_package,
        ApplyPrecondition::Successor { current: &current },
        Duration::from_secs(30),
        Duration::from_secs(60),
    )
    .await
    .expect("reviewed successor widens the ledger and activates");
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
    assert_eq!(ledger, (statement_count as i32, true, false));
    database.cleanup().await;
}
