// SPDX-License-Identifier: Apache-2.0
//! Native successor activation for Proposal compatibility tests.
use super::client_http::ClientFixture;
use registry_breg::migration::{
    ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest, apply_verified_package,
};
use registry_breg::package::{
    PackageBuildRequest, PackageLoadContext, PackageMigrationPlanInput, PackageSourceFile,
    PreparedPackage, load_package, prepare_package,
};
use registry_breg::postgres::{
    ExpectedManagedCatalog, ExpectedRegistryIdentity, managed_schema_fingerprint,
    reconcile_compiled_runtime_acl_for_test,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;

fn canonical(value: &impl serde::Serialize) -> Vec<u8> {
    registry_platform_canonical_json::canonicalize_json(&serde_json::to_value(value).unwrap())
        .unwrap()
}
fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn prepare(
    prior: &registry_breg::CompiledRegistry,
    current: &ExpectedRegistryIdentity,
    source: &Value,
    fingerprint: &str,
) -> PreparedPackage {
    let mut source = source.clone();
    source["package"] = serde_json::json!({"sourceRevision":"0".repeat(40)});
    let source_bytes = serde_json::to_vec(&source).unwrap();
    let project = registry_breg::contract::parse_project_json(&source_bytes)
        .expect("successor source parses");
    let compiled = registry_breg::compiler::compile_project(
        &project,
        &[],
        registry_breg::compiler::CompileProfile::Production,
    )
    .expect("successor source satisfies production package requirements");
    let changes = registry_breg::package::compiled_registry_change_set(
        prior,
        &compiled,
        &current.package_digest,
    );
    let migration_plan = if changes.migration_plan.is_some() {
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(prior.clone()),
        }
    } else {
        use registry_breg::migration_plan::{
            MigrationRehearsalReceipt, ReviewedChangeCover, ReviewedMigrationDescriptor,
            ReviewedMigrationFile, ReviewedMigrationRecovery, ReviewedMigrationSource,
        };
        assert!(
            changes.changes.iter().all(|change| change.target.kind
                == registry_breg::package::CompiledRegistryChangeTargetKind::Action),
            "this native fixture reviews only Action metadata: {:?}",
            changes.changes
        );
        let base = "modules/core/migrations/action-contract";
        let descriptor = ReviewedMigrationDescriptor {
            id: "action-contract".into(),
            change_class:
                registry_breg::package::CompiledRegistryChangeClass::AccessOrDisclosureChange,
            covers: changes
                .changes
                .iter()
                .map(ReviewedChangeCover::from)
                .collect(),
            recovery: ReviewedMigrationRecovery::ExactTargetResume,
            lock_timeout_ms: 2000,
            statement_timeout_ms: 10000,
            steps: vec![],
            pre_assertions: vec![],
            post_assertions: vec![],
            rehearsal_receipt_path: format!("{base}/rehearsal.json"),
            backup_binding_path: None,
            history: None,
        };
        let bytes = canonical(&descriptor);
        let receipt = MigrationRehearsalReceipt {
            prior_package_digest: current.package_digest.clone(),
            prior_schema_fingerprint: current.schema_fingerprint.clone(),
            plan_sha256: digest(&bytes),
            sql_sha256: vec![],
            assertion_sha256: vec![],
            fixture_inventory: vec![],
            postgres_major: 17,
            row_assertions: vec![],
            final_schema_fingerprint: fingerprint.into(),
        };
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(prior.clone()),
            prior_schema_fingerprint: current.schema_fingerprint.clone(),
            migrations: vec![ReviewedMigrationSource {
                module_id: "core".into(),
                descriptor: ReviewedMigrationFile {
                    path: format!("{base}/descriptor.json"),
                    bytes,
                },
                files: vec![ReviewedMigrationFile {
                    path: descriptor.rehearsal_receipt_path,
                    bytes: canonical(&receipt),
                }],
            }],
        }
    };
    let journeys = serde_json::json!({"apiVersion":"id.registrystack.org/formats/breg/journeys/v1","kind":"BRegJourneys",
        "journeys":[{"id":"list-targets","steps":[{"id":"list","recordType":"target","accessProfile":"clerk",
            "claims":{"principal":"fixture","scopes":["proposal:manage"],"purpose":"registry-administration","directClaims":{"jurisdiction":"zone-a"}},
            "request":{"type":"list"},"expect":{"outcome":"success","status":200,"count":0}}]}]});
    prepare_package(PackageBuildRequest {
        from_package_digest: Some(current.package_digest.clone()),
        compiler_source_revision: "0".repeat(40),
        schema_fingerprint: fingerprint.into(),
        project: PackageSourceFile {
            path: "source/registry.yaml".into(),
            bytes: source_bytes,
        },
        modules: vec![],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".into(),
            bytes: serde_json::to_vec(&journeys).unwrap(),
        },
        migration_plan,
    })
    .expect("canonical successor package prepares")
}

pub async fn activate_successor(
    fixture: &ClientFixture,
    source: &Value,
) -> (registry_breg::CompiledRegistry, ExpectedRegistryIdentity) {
    let (package, active) =
        activate_with_compatibility(fixture, &fixture.registry, &fixture.identity, source, None)
            .await;
    (package.registry().clone(), active)
}

pub async fn activate_with_compatibility(
    fixture: &ClientFixture,
    prior: &registry_breg::CompiledRegistry,
    current: &ExpectedRegistryIdentity,
    source: &Value,
    authorities: Option<&registry_breg::review_store::ReviewAuthorityRegistry>,
) -> (
    registry_breg::package::VerifiedPackage,
    ExpectedRegistryIdentity,
) {
    let package = verified_successor(fixture, prior, current, source).await;
    let inventory = if let Some(authorities) = authorities {
        Some(
            registry_breg::proposal_retention::prepare_proposal_activation_compatibility(
                &fixture.pool,
                current,
                &package,
                authorities,
                Duration::from_secs(2),
            )
            .await
            .unwrap(),
        )
    } else {
        None
    };
    let request = ApplyVerifiedPackageRequest::new(
        &fixture.database.migration_config,
        &package,
        ActivationDeployment::new("local", "proposal-activation-test", &current.database_id),
        ApplyPrecondition::Successor { current },
        ApplyRoles::new(
            &fixture.database.migration_role,
            &fixture.database.runtime_role,
        ),
        ApplyTimeouts::new(Duration::from_secs(2), Duration::from_secs(10)).unwrap(),
        fixture.database.activation_audit(),
    );
    let request = if let Some(inventory) = &inventory {
        request.with_proposal_activation_compatibility(inventory)
    } else {
        request
    };
    let active = apply_verified_package(request)
        .await
        .expect("verified successor activates through the real ledger/catalog gate");
    (package, active)
}

/// Publish and rederive the genuine candidate without activating it.
pub async fn verified_successor(
    fixture: &ClientFixture,
    prior: &registry_breg::CompiledRegistry,
    current: &ExpectedRegistryIdentity,
    source: &Value,
) -> registry_breg::package::VerifiedPackage {
    // Rehearse only compiler-owned successor SQL in a transaction that rolls
    // back. The actual activation below uses a published, rederived package.
    let candidate = prepare(prior, current, source, &current.schema_fingerprint);
    let (mut migration, task) = fixture.database.connect_migration().await;
    let tx = migration.transaction().await.unwrap();
    for statement in &candidate.manifest().migration_plan.statements {
        tx.batch_execute(&statement.sql)
            .await
            .expect("compiler successor DDL rehearses");
    }
    reconcile_compiled_runtime_acl_for_test(
        &tx,
        candidate.registry(),
        &fixture.database.runtime_role,
    )
    .await
    .unwrap();
    let fingerprint = managed_schema_fingerprint(
        &tx,
        &fixture.database.runtime_role,
        &ExpectedManagedCatalog::compiled(candidate.registry()),
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    drop(migration);
    task.abort();
    let candidate = prepare(prior, current, source, &fingerprint);
    let directory = tempfile::Builder::new()
        .prefix("breg-proposal-activation-")
        .tempdir_in("/private/tmp")
        .unwrap();
    let path = directory.path().join("package");
    candidate.publish_to_directory(&path).unwrap();
    let package = load_package(
        &path,
        &PackageLoadContext {
            database_initialization_environment: "local",
        },
    )
    .unwrap();
    package
}
