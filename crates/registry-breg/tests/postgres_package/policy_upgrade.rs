// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Clone, Copy)]
enum ProfileSuccessor {
    Compiler,
    Reviewed,
    UnmanagedDrift,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_profile_removal_applies_and_matches_fresh_catalog() {
    assert_profile_successor(None, ProfileSuccessor::Compiler).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_profile_operation_narrowing_applies_and_matches_fresh_catalog() {
    assert_profile_successor(
        Some(json!({
            "id": "auditor", "principalClaim": "principal", "rowBoundaries": [],
            "operations": ["create"], "writableFields": ["code", "note"]
        })),
        ProfileSuccessor::Compiler,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_profile_create_revocation_applies_and_matches_fresh_catalog() {
    assert_profile_successor(
        Some(json!({
            "id": "auditor", "principalClaim": "principal", "rowBoundaries": [],
            "operations": ["get", "list"], "readableFields": ["code", "note"]
        })),
        ProfileSuccessor::Compiler,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_profile_field_narrowing_applies_and_matches_fresh_catalog() {
    assert_profile_successor(
        Some(json!({
            "id": "auditor", "principalClaim": "principal", "rowBoundaries": [],
            "operations": ["create", "get", "list"],
            "writableFields": ["code", "note"], "readableFields": ["code"]
        })),
        ProfileSuccessor::Reviewed,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_profile_cleanup_preserves_and_refuses_unmanaged_policy() {
    assert_profile_successor(None, ProfileSuccessor::UnmanagedDrift).await;
}

fn profile_module(auditor: Option<Value>) -> Vec<u8> {
    let mut module: Value = serde_json::from_slice(&module_bytes(PlanChoice::Schema)).unwrap();
    let entity = &mut module["entities"][0];
    entity["fields"].as_array_mut().unwrap().push(json!({
        "id": "note", "type": "string", "maxLength": 80, "classification": "internal"
    }));
    if let Some(auditor) = auditor {
        entity["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .push(auditor);
    }
    serde_json::to_vec(&module).unwrap()
}

fn compile_profile_module(bytes: &[u8], sequence: u64) -> registry_breg::model::CompiledRegistry {
    let module = parse_module_yaml(bytes).unwrap();
    compile_project(
        &parse_project_yaml(&project_bytes("local", sequence, &module_digest(&module))).unwrap(),
        &[module],
        CompileProfile::Production,
    )
    .unwrap()
}

async fn fresh_fingerprint(registry: &registry_breg::model::CompiledRegistry) -> String {
    let fresh = TestDatabase::create(1).await;
    let (migration, task) = fresh.connect_migration().await;
    install_compiled_schema(&migration, registry, &fresh.runtime_role)
        .await
        .unwrap();
    let fingerprint = managed_schema_fingerprint(
        &migration,
        &fresh.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
    )
    .await
    .unwrap();
    task.abort();
    fresh.cleanup().await;
    fingerprint
}

async fn assert_profile_successor(auditor: Option<Value>, kind: ProfileSuccessor) {
    let baseline_bytes = profile_module(Some(json!({
        "id": "auditor", "principalClaim": "principal", "rowBoundaries": [],
        "operations": ["create", "get", "list"],
        "writableFields": ["code", "note"], "readableFields": ["code", "note"]
    })));
    let baseline = compile_profile_module(&baseline_bytes, 1);
    let baseline_fingerprint = fresh_fingerprint(&baseline).await;
    let database = TestDatabase::create(1).await;
    let first = publish_temporal_policy_package(
        1,
        None,
        baseline_fingerprint,
        baseline_bytes,
        PackageMigrationPlanInput::InitialCompiledDdl,
    );
    let predecessor = load_package(
        first.path(),
        &local_context(PackageIntent::InitialActivation),
    )
    .unwrap();
    let active = apply_package(
        &database,
        &predecessor,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let candidate_bytes = profile_module(auditor);
    let candidate = compile_profile_module(&candidate_bytes, 2);
    let candidate_fingerprint = fresh_fingerprint(&candidate).await;
    let changes =
        compiled_registry_change_set(predecessor.registry(), &candidate, &active.package_revision);
    let plan = if matches!(kind, ProfileSuccessor::Reviewed) {
        // Readable-field narrowing changes the query contract and retains its
        // existing review requirement. Exercise that successor path as well.
        assert!(change_set_to_applicable_migration_plan(&changes).is_err());
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(predecessor.registry().clone()),
            prior_schema_fingerprint: active.schema_fingerprint.clone(),
            migrations: vec![metadata_only_review_source(
                &changes.changes,
                &active.package_revision,
                &active.schema_fingerprint,
                &candidate_fingerprint,
            )],
        }
    } else {
        change_set_to_applicable_migration_plan(&changes)
            .expect("ordinary profile removal or operation narrowing is compiler-applicable");
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(predecessor.registry().clone()),
        }
    };
    let next = publish_temporal_policy_package(
        2,
        Some(&active.package_revision),
        candidate_fingerprint.clone(),
        candidate_bytes,
        plan,
    );
    let successor = load_package(
        next.path(),
        &local_context(PackageIntent::Activation {
            active_revision: &active.package_revision,
            active_sequence: 1,
        }),
    )
    .unwrap();
    if matches!(kind, ProfileSuccessor::UnmanagedDrift) {
        let table = &predecessor.registry().entities()["neutral-record"].physical_table;
        database
            .admin
            .batch_execute(&format!(
                "CREATE POLICY registry_rls_unowned_policy ON registry_data.\"{table}\" USING (false)"
            ))
            .await
            .unwrap();
        let result = apply_package(
            &database,
            &successor,
            ApplyPrecondition::Successor { current: &active },
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await;
        assert!(
            result.is_err(),
            "the closed catalog must still reject an extra policy"
        );
        assert_eq!(database.admin.query_one(
            "SELECT count(*) FROM pg_catalog.pg_policies WHERE schemaname = 'registry_data' AND policyname = 'registry_rls_unowned_policy'", &[],
        ).await.unwrap().get::<_, i64>(0), 1, "cleanup must not sweep unmanaged policies");
        // Only the fixture administrator removes its deliberately injected
        // drift; retrying the exact target then exercises maintenance recovery.
        database
            .admin
            .batch_execute(&format!(
                "DROP POLICY registry_rls_unowned_policy ON registry_data.\"{table}\""
            ))
            .await
            .unwrap();
    }
    let upgraded = apply_package(
        &database,
        &successor,
        ApplyPrecondition::Successor { current: &active },
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .await
    .expect("profile successor applies without stranded maintenance");
    assert_eq!(upgraded.schema_fingerprint, candidate_fingerprint);
    assert_eq!(upgraded.package_sequence, 2);
    let (migration, task) = database.connect_migration().await;
    assert_eq!(
        managed_schema_fingerprint(
            &migration,
            &database.runtime_role,
            &ExpectedManagedCatalog::compiled(successor.registry()),
        )
        .await
        .unwrap(),
        candidate_fingerprint
    );
    let state = database.admin.query_one(
        "SELECT maintenance_status, active_package_revision FROM registry_internal.registry_state WHERE singleton", &[],
    ).await.unwrap();
    assert_eq!(state.get::<_, String>(0), "ready");
    assert_eq!(state.get::<_, String>(1), upgraded.package_revision);

    // Readiness is operational: the retained reader can enter a record
    // transaction under the new package, not merely observe a status string.
    let pool = database.runtime_config.build_pool().unwrap();
    let mut runtime = pool.get_for_test().await.unwrap();
    let claims = ClaimContext::for_compiled(
        successor.registry(),
        "neutral-record",
        Some("reader".to_owned()),
        "reader",
        None,
        Vec::new(),
    )
    .unwrap();
    let transaction = begin_record_transaction(
        &mut runtime,
        RegistryLockKey::derive(&successor.manifest().package_id).unwrap(),
        Duration::from_secs(5),
        &upgraded,
        &claims,
    )
    .await
    .expect("record work resumes after the successor activates");
    transaction.rollback().await.unwrap();
    drop(runtime);
    drop(pool);
    task.abort();
    database.cleanup().await;
}
