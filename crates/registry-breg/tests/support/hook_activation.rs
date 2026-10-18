// SPDX-License-Identifier: Apache-2.0

use super::*;
use registry_breg::migration::{
    apply_verified_package, plan_verified_package, ActivationDeployment, ApplyPrecondition,
    ApplyRoles, ApplyTimeouts, ApplyVerifiedPackageRequest,
};
use registry_breg::package::{
    load_package, prepare_package_with_project_assets, PackageBuildRequest, PackageLoadContext,
    PackageMigrationPlanInput, PackageSourceFile, VerifiedPackage,
};
use registry_breg::postgres::{managed_schema_fingerprint, ExpectedManagedCatalog};

fn project(local: bool) -> (Value, Vec<ModuleAssetSource>) {
    let handler = if local {
        PROPOSING_RHAI_HANDLER
    } else {
        r#"{"type":"url","destinationId":"case-operations"}"#
    };
    let mut project: Value = serde_json::from_str(&hook_project_json(
        &format!("[{}]", hook_json("case-created", true, handler)),
        "[]",
        r#""results":["followup"]"#,
        "",
    ))
    .unwrap();
    project["package"] = json!({"sourceRevision":"hook-activation-fixture"});
    let mut assets = vec![rhai_asset(
        "scripts/open-followup.rhai",
        ACTION_HANDLER_SCRIPT,
    )];
    if local {
        assets.push(rhai_asset("hooks/propose.rhai", PROPOSAL_HOOK_SCRIPT));
    }
    (project, assets)
}

async fn package(
    project: &Value,
    assets: &[ModuleAssetSource],
    prior: Option<(&CompiledRegistry, &str)>,
) -> VerifiedPackage {
    let bytes = serde_json::to_vec(project).unwrap();
    let compiled = compile_project_with_assets(
        &parse_project_json(&bytes).unwrap(),
        &[],
        assets,
        CompileProfile::Production,
    )
    .expect("activation fixture compiles for production");
    let database = TestDatabase::create(2).await;
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration.transaction().await.unwrap();
    install_compiled_schema(&transaction, &compiled, &database.runtime_role)
        .await
        .unwrap();
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&compiled),
    )
    .await
    .unwrap();
    transaction.rollback().await.unwrap();
    drop(migration);
    task.abort();
    database.cleanup().await;
    let prepared = prepare_package_with_project_assets(
        PackageBuildRequest {
            from_package_digest: prior.map(|(_, digest)| digest.to_owned()),
            compiler_source_revision: "hook-activation-fixture".to_owned(),
            schema_fingerprint: fingerprint,
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes,
            },
            modules: vec![],
            fixture_journeys: PackageSourceFile {
                path: "tests/journeys.yaml".to_owned(),
                bytes: br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: empty-cases
    steps:
      - id: list-cases
        recordType: case
        accessProfile: operator
        claims: {principal: operator-principal, purpose: case-management, jurisdiction: zone-a}
        request: {type: list}
        expect: {outcome: success, status: 200, count: 0}
"#
                .to_vec(),
            },
            migration_plan: prior.map_or(
                PackageMigrationPlanInput::InitialCompiledDdl,
                |(registry, _)| PackageMigrationPlanInput::Successor {
                    prior_registry: Box::new(registry.clone()),
                },
            ),
        },
        assets
            .iter()
            .map(|asset| PackageSourceFile {
                path: asset.path.clone(),
                bytes: asset.bytes.clone(),
            })
            .collect(),
    )
    .expect("activation package prepares");
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let path = root.path().join("package");
    prepared.publish_to_directory(&path).unwrap();
    load_package(
        &path,
        &PackageLoadContext {
            database_initialization_environment: "local",
        },
    )
    .unwrap()
}

fn request<'a>(
    database: &'a TestDatabase,
    package: &'a VerifiedPackage,
    precondition: ApplyPrecondition<'a>,
    plan: bool,
) -> ApplyVerifiedPackageRequest<'a> {
    let deployment =
        ActivationDeployment::new("local", "hook-proposal-instance", "hook-proposal-database");
    let roles = ApplyRoles::new(&database.migration_role, &database.runtime_role);
    let timeouts = ApplyTimeouts::new(Duration::from_secs(2), Duration::from_secs(5)).unwrap();
    if plan {
        ApplyVerifiedPackageRequest::plan(
            &database.migration_config,
            package,
            deployment,
            precondition,
            roles,
            timeouts,
        )
    } else {
        ApplyVerifiedPackageRequest::new(
            &database.migration_config,
            package,
            deployment,
            precondition,
            roles,
            timeouts,
            database.activation_audit(),
        )
    }
}

async fn activated_setup(
    package: &VerifiedPackage,
    receiver: &HttpsReceiver,
    local: bool,
) -> Setup {
    let database = TestDatabase::create(8).await;
    let identity = apply_verified_package(request(
        &database,
        package,
        ApplyPrecondition::InitialActivation,
        false,
    ))
    .await
    .expect("initial hook package activates");
    let compiled = package.registry().clone();
    let fixture = DestinationFixture::new(receiver);
    let destinations = Arc::new(if local {
        fixture.activate_without_destinations(&compiled)
    } else {
        fixture.activate(&compiled)
    });
    let pool = database.runtime_config.build_pool().unwrap();
    let audit =
        database.audit(AuditProfile::production_from_secret_bytes(vec![0x5a; 32].into()).unwrap());
    let lock_key = RegistryLockKey::derive("hook-proposal-registry").unwrap();
    let coordinator = MutationTransaction::new_with_event_destinations(
        lock_key,
        Duration::from_secs(2),
        identity.clone(),
        "hook-proposal-instance",
        audit.clone(),
        Some(destinations.clone()),
    );
    let service = WebhookDeliveryService::new(
        pool.clone(),
        destinations,
        Arc::new(HookHandlerRegistry::new(&compiled, &identity.activation_id)),
        Arc::new(compiled.clone()),
        identity.clone(),
        "hook-proposal-instance",
        lock_key,
        Duration::from_secs(2),
        audit,
    );
    Setup {
        database,
        compiled,
        pool,
        identity,
        coordinator,
        service,
        fixture,
    }
}

async fn successor(
    setup: &Setup,
    project: &mut Value,
    assets: &[ModuleAssetSource],
) -> VerifiedPackage {
    project["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"note","type":"string","maximumLength":64,"classification":"internal"
        }));
    package(
        project,
        assets,
        Some((&setup.compiled, &setup.identity.package_digest)),
    )
    .await
}

async fn assert_ready(setup: &Setup) {
    let row = setup.database.admin.query_one("SELECT active_package_digest, active_activation_id::text, maintenance_status, maintenance_target_package_digest FROM registry_internal.registry_state WHERE singleton", &[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), setup.identity.package_digest);
    assert_eq!(row.get::<_, String>(1), setup.identity.activation_id);
    assert_eq!(row.get::<_, String>(2), "ready");
    assert_eq!(row.get::<_, Option<String>>(3), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_local_hooks_refuse_plan_and_apply_before_maintenance() {
    let receiver = HttpsReceiver::start().await;
    let (mut project, assets) = project(true);
    let initial = package(&project, &assets, None).await;
    let setup = activated_setup(&initial, &receiver, true).await;
    let mut client = setup.pool.get_for_test().await.unwrap();
    let event = create_case(&setup, &mut client, "local-before-go-live").await;
    drop(client);
    let delivery_id = single_delivery(&event);
    let target = successor(&setup, &mut project, &assets).await;
    let inventory = setup
        .fixture
        .activate_without_destinations(target.registry())
        .compatibility_inventory();
    let before = setup.database.activation_audit_entries().len();
    let planned = plan_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            true,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .unwrap_err();
    assert_ready(&setup).await;
    assert_eq!(
        setup.database.activation_audit_entries().len(),
        before,
        "plan writes no audit"
    );
    let applied = apply_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            false,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .unwrap_err();
    assert_ready(&setup).await;
    assert_eq!(planned, applied, "plan and apply report the same refusal");
    let audit_outcome =
        setup.database.activation_audit_entries().last().unwrap()["record"]["outcome"].clone();
    assert!(
        format!("{planned:?}").contains("RetainedLocalHooks"),
        "named pre-maintenance refusal: {planned:?}; audit outcome: {audit_outcome}"
    );
    assert!(
        format!("{planned:?}").contains(delivery_id),
        "the refusal identifies the compiled delivery"
    );
    let entries = setup.database.activation_audit_entries();
    assert_eq!(entries.last().unwrap()["record"]["outcome"], "refused");
    let drained = setup
        .service
        .drain_local(10, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(drained.delivered, 1);
    assert_eq!(drained.remaining.retained_deliveries, 0);
    assert_eq!(drained.activation_id, setup.identity.activation_id);
    assert_eq!(record_count(&setup, "followup").await, 1);
    plan_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            true,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .unwrap();
    apply_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            false,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .unwrap();
    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn old_activation_hook_answer_is_terminal_and_names_both_activations() {
    let receiver = HttpsReceiver::start().await;
    let (mut project, assets) = project(false);
    let initial = package(&project, &assets, None).await;
    let setup = activated_setup(&initial, &receiver, false).await;
    let mut client = setup.pool.get_for_test().await.unwrap();
    let event = create_case(&setup, &mut client, "old-answer").await;
    drop(client);
    let delivery_id = single_delivery(&event);
    let target = successor(&setup, &mut project, &assets).await;
    let inventory = setup
        .fixture
        .activate(target.registry())
        .compatibility_inventory();
    plan_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            true,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .unwrap();
    let active = apply_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            false,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .unwrap();
    let active_id = active.activation_id.clone();
    let mut setup = setup;
    setup.compiled = target.registry().clone();
    let service = setup.service_for_identity(active);
    receiver
        .enqueue(ResponsePlan::Answer {
            body: HOOK_PROPOSAL_MESSAGE.to_vec(),
        })
        .await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::DeadLettered)
    );
    let row = delivery_row(&setup, event.event_id, delivery_id).await;
    assert_eq!(
        row.code.as_deref(),
        Some("hook.proposal.package_unavailable")
    );
    assert_eq!(record_count(&setup, "followup").await, 0);
    let summary = row.summary.unwrap();
    let listed = service.list(10).await.unwrap();
    let listed = listed
        .iter()
        .find(|row| row.event_id == event.event_id)
        .unwrap();
    assert!(!listed.replay_eligible);
    assert!(listed.discard_eligible);
    assert_eq!(
        listed.proposal_code.as_deref(),
        Some("hook.proposal.package_unavailable")
    );
    assert_eq!(listed.proposal_summary.as_deref(), Some(summary.as_str()));
    let replay = service.replay(event.event_id, delivery_id, 1).await;
    assert!(summary.contains(&setup.identity.activation_id) && summary.contains(&active_id) && replay == Err(WebhookDeliveryError::Unavailable), "old-activation refusal must name both activations and forbid replay; summary: {summary}; replay: {replay:?}");
    assert_eq!(service.discard(event.event_id, delivery_id, 1).await, Ok(2));
    drop(service);
    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_predecessor_answer_is_terminal_after_activation() {
    predecessor_answer_across_activation(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_predecessor_answer_recovers_committed_receipt_after_activation() {
    predecessor_answer_across_activation(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_predecessor_answer_keeps_unreadable_activation_uncertain() {
    predecessor_answer_across_activation(false, true).await;
}

async fn predecessor_answer_across_activation(committed: bool, unreadable_state: bool) {
    let receiver = HttpsReceiver::start().await;
    let (mut project, assets) = project(false);
    let initial = package(&project, &assets, None).await;
    let mut setup = activated_setup(&initial, &receiver, false).await;
    let mut client = setup.pool.get_for_test().await.unwrap();
    let event = create_case(&setup, &mut client, "in-flight-answer").await;
    drop(client);
    let delivery_id = single_delivery(&event);
    if committed {
        let payload = outbox_payload(&setup, &event).await;
        receiver
            .enqueue(ResponsePlan::Answer {
                body: HOOK_PROPOSAL_MESSAGE.to_vec(),
            })
            .await;
        assert_eq!(
            setup.service.deliver_once().await,
            Ok(WebhookWorkOutcome::Delivered)
        );
        assert_eq!(record_count(&setup, "followup").await, 1);
        rewind_to_crashed_lease(&setup, &event, delivery_id, &payload).await;
        assert_eq!(
            setup.service.deliver_once().await,
            Ok(WebhookWorkOutcome::Idle)
        );
        wait_until_delivery_is_due(&setup, &event, delivery_id).await;
    }
    // Exercise the final allowed attempt so a known late answer settles
    // with its specific result. The unreadable-state control stays uncertain;
    // this test does not exercise lease-expiry recovery.
    setup
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_delivery_state AS state
            SET attempt = delivery.deployed_maximum_attempts - 1
           FROM registry_internal.registry_webhook_deliveries AS delivery
          WHERE state.event_id = $1 AND state.compiled_delivery_id = $2
            AND delivery.event_id = state.event_id
            AND delivery.compiled_delivery_id = state.compiled_delivery_id
            AND state.state = 'pending'",
            &[&event.event_id, &delivery_id],
        )
        .await
        .unwrap();
    let target = successor(&setup, &mut project, &assets).await;
    let inventory = setup
        .fixture
        .activate(target.registry())
        .compatibility_inventory();
    plan_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            true,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .unwrap();
    let (request_seen_tx, request_seen_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    receiver
        .enqueue(ResponsePlan::GatedAnswer {
            body: HOOK_PROPOSAL_MESSAGE.to_vec(),
            request_seen: request_seen_tx,
            release: release_rx,
        })
        .await;
    let predecessor = setup.service.clone();
    let worker = tokio::spawn(async move { predecessor.deliver_once().await });
    tokio::time::timeout(Duration::from_secs(3), request_seen_rx)
        .await
        .expect("the predecessor sends before activation")
        .expect("the receiver holds the answer");
    let active = apply_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            false,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .expect("successor activates while the predecessor awaits its answer");
    let active_id = active.activation_id.clone();
    if unreadable_state {
        make_registry_state_unreadable(&setup).await;
    }
    release_tx.send(()).unwrap();
    let outcome = worker.await.unwrap();
    let row = delivery_row(&setup, event.event_id, delivery_id).await;
    assert_eq!(record_count(&setup, "case").await, 1);
    assert_eq!(record_count(&setup, "followup").await, i64::from(committed));
    if unreadable_state {
        assert_eq!(outcome, Err(WebhookDeliveryError::Unavailable));
        assert_eq!(row.state, "leased");
        assert_eq!(row.disposition, None);
        assert_eq!(row.code, None);
        setup.teardown().await;
        receiver.stop().await;
        return;
    }
    assert_eq!(
        outcome,
        Ok(if committed {
            WebhookWorkOutcome::Delivered
        } else {
            WebhookWorkOutcome::DeadLettered
        }),
        "the same predecessor worker must settle its late answer; state: {}; code: {:?}",
        row.state,
        row.code,
    );
    setup.compiled = target.registry().clone();
    let active_service = setup.service_for_identity(active);
    if committed {
        assert_eq!(row.state, "delivered");
        assert_eq!(row.disposition.as_deref(), Some("applied"));
        assert_eq!(row.resulting_revision, Some(1));
        assert_eq!(row.code, None);
    } else {
        assert_eq!(row.state, "dead-lettered");
        assert_eq!(
            row.code.as_deref(),
            Some("hook.proposal.package_unavailable")
        );
        let summary = row.summary.unwrap();
        assert!(summary.contains(&setup.identity.activation_id));
        assert!(summary.contains(&active_id));
        let listed = active_service.list(10).await.unwrap();
        let listed = listed
            .iter()
            .find(|row| row.event_id == event.event_id)
            .unwrap();
        assert!(!listed.replay_eligible);
        assert!(listed.discard_eligible);
        assert_eq!(
            active_service.replay(event.event_id, delivery_id, 1).await,
            Err(WebhookDeliveryError::Unavailable)
        );
    }
    assert_eq!(
        setup.service.deliver_once().await,
        Err(WebhookDeliveryError::Unavailable),
        "the predecessor cannot claim any further work after activation"
    );
    drop(active_service);
    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn classified_proposal_refusal_finishes_after_activation() {
    classified_proposal_across_activation(CompletionKind::Refused, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn classified_proposal_dead_letter_finishes_after_activation() {
    classified_proposal_across_activation(CompletionKind::DeadLettered, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn classified_proposal_application_finishes_after_activation_once() {
    classified_proposal_across_activation(CompletionKind::Applied, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn classified_proposal_completion_preserves_registry_and_lease_fences() {
    for fault in [
        CompletionFault::LeaseToken,
        CompletionFault::Generation,
        CompletionFault::Database,
        CompletionFault::Package,
        CompletionFault::Maintenance,
        CompletionFault::UnreadableState,
    ] {
        classified_proposal_across_activation(CompletionKind::Refused, Some(fault)).await;
    }
}

#[derive(Clone, Copy)]
enum CompletionKind {
    Applied,
    Refused,
    DeadLettered,
}

#[derive(Clone, Copy, Debug)]
enum CompletionFault {
    LeaseToken,
    Generation,
    Database,
    Package,
    Maintenance,
    UnreadableState,
}

async fn make_registry_state_unreadable(setup: &Setup) {
    setup
        .database
        .admin
        .batch_execute(&format!(
            "REVOKE SELECT ON registry_internal.registry_state FROM \"{}\"",
            setup.database.runtime_role.as_str(),
        ))
        .await
        .unwrap();
}

async fn classified_proposal_across_activation(
    kind: CompletionKind,
    fault: Option<CompletionFault>,
) {
    let receiver = HttpsReceiver::start().await;
    let (mut project, assets) = project(false);
    if matches!(kind, CompletionKind::DeadLettered) {
        assert!(project["recordTypes"][0]["hooks"][0]
            .as_object_mut()
            .unwrap()
            .remove("principal")
            .is_some());
    }
    let initial = package(&project, &assets, None).await;
    let mut setup = activated_setup(&initial, &receiver, false).await;
    let mut client = setup.pool.get_for_test().await.unwrap();
    let event = create_case(&setup, &mut client, "classified-before-activation").await;
    drop(client);
    let delivery_id = single_delivery(&event);
    let target = successor(&setup, &mut project, &assets).await;
    let inventory = setup
        .fixture
        .activate(target.registry())
        .compatibility_inventory();
    let (classified, resume) = setup.service.pause_proposal_completion_for_test().await;
    let body = if matches!(kind, CompletionKind::Refused) {
        HOOK_PROPOSAL_STR
            .replace("\"id\":\"followup\"", "\"id\":\"nonexistent-slot\"")
            .into_bytes()
    } else {
        HOOK_PROPOSAL_MESSAGE.to_vec()
    };
    receiver.enqueue(ResponsePlan::Answer { body }).await;
    let service = setup.service.clone();
    let worker = tokio::spawn(async move { service.deliver_once().await });
    tokio::time::timeout(Duration::from_secs(5), classified)
        .await
        .expect("classification completes before activation")
        .expect("the test barrier observes a settled proposal");
    let active = apply_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            false,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .expect("activation completes after classification has released its locks");
    assert_ne!(active.activation_id, setup.identity.activation_id);
    match fault {
        Some(CompletionFault::LeaseToken | CompletionFault::Generation) => {
            let assignment = if matches!(fault, Some(CompletionFault::LeaseToken)) {
                "lease_token = gen_random_uuid()"
            } else {
                "generation = generation + 1"
            };
            assert_eq!(setup.database.admin.execute(
                &format!("UPDATE registry_internal.registry_webhook_delivery_state
                    SET {assignment} WHERE event_id = $1 AND compiled_delivery_id = $2 AND state = 'leased'"),
                &[&event.event_id, &delivery_id],
            ).await.unwrap(), 1);
        }
        Some(CompletionFault::Database) => {
            setup
                .database
                .admin
                .batch_execute(
                    "UPDATE registry_internal.registry_state
                SET database_id = 'other-database-canary' WHERE singleton",
                )
                .await
                .unwrap();
        }
        Some(CompletionFault::Package) => {
            setup
                .database
                .admin
                .batch_execute(
                    "UPDATE registry_internal.registry_state
                SET package_id = 'other-package-canary' WHERE singleton",
                )
                .await
                .unwrap();
        }
        Some(CompletionFault::Maintenance) => {
            setup.database.admin.batch_execute("UPDATE registry_internal.registry_state
                SET maintenance_status = 'failed', maintenance_target_package_digest = active_package_digest
                WHERE singleton").await.unwrap();
        }
        Some(CompletionFault::UnreadableState) => make_registry_state_unreadable(&setup).await,
        None => {}
    }
    resume.send(()).unwrap();
    let result = worker.await.unwrap();
    let row = delivery_row(&setup, event.event_id, delivery_id).await;
    assert_eq!(record_count(&setup, "case").await, 1);
    assert_eq!(
        record_count(&setup, "followup").await,
        i64::from(matches!(kind, CompletionKind::Applied))
    );
    if let Some(fault) = fault {
        assert_eq!(result, Err(WebhookDeliveryError::Unavailable), "{fault:?}");
        assert_eq!(row.state, "leased", "{fault:?}");
        assert_eq!(row.disposition, None, "{fault:?}");
        assert_eq!(row.code, None, "{fault:?}");
    } else {
        let (expected_outcome, state, disposition, code) = match kind {
            CompletionKind::Applied => {
                (WebhookWorkOutcome::Delivered, "delivered", "applied", None)
            }
            CompletionKind::Refused => (
                WebhookWorkOutcome::Delivered,
                "delivered",
                "refused",
                Some("hook.proposal.outcome_refused"),
            ),
            CompletionKind::DeadLettered => (
                WebhookWorkOutcome::DeadLettered,
                "dead-lettered",
                "dead-lettered",
                Some("hook.proposal.no_principal"),
            ),
        };
        assert_eq!(
            result,
            Ok(expected_outcome),
            "the classified proposal must finish across activation; state: {}; code: {:?}",
            row.state,
            row.code
        );
        assert_eq!(row.state, state);
        assert_eq!(row.disposition.as_deref(), Some(disposition));
        assert_eq!(row.code.as_deref(), code);
        if matches!(kind, CompletionKind::Applied) {
            assert_eq!(row.resulting_revision, Some(1));
        }
        setup.compiled = target.registry().clone();
        let active_service = setup.service_for_identity(active);
        if matches!(kind, CompletionKind::DeadLettered) {
            let listed = active_service.list(10).await.unwrap();
            let listed = listed
                .iter()
                .find(|row| row.event_id == event.event_id)
                .unwrap();
            // This deployment-defect dead letter keeps its ordinary replay policy.
            assert!(listed.replay_eligible);
        } else {
            assert_eq!(
                active_service.replay(event.event_id, delivery_id, 1).await,
                Err(WebhookDeliveryError::Unavailable),
                "a delivered decision cannot be replayed"
            );
        }
    }
    assert_eq!(
        setup.service.deliver_once().await,
        Err(WebhookDeliveryError::Unavailable)
    );
    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_drain_limits_attempts_and_leaves_url_work_and_live_leases_untouched() {
    let receiver = HttpsReceiver::start().await;
    let (mut project, assets) = project(true);
    project["recordTypes"][0]["hooks"]
        .as_array_mut()
        .unwrap()
        .push(
            serde_json::from_str(&hook_json(
                "remote-created",
                true,
                r#"{"type":"url","destinationId":"case-operations"}"#,
            ))
            .unwrap(),
        );
    let initial = package(&project, &assets, None).await;
    let setup = activated_setup(&initial, &receiver, false).await;
    let mut client = setup.pool.get_for_test().await.unwrap();
    let first = create_case(&setup, &mut client, "drain-first").await;
    let second = create_case(&setup, &mut client, "drain-second").await;
    create_case(&setup, &mut client, "drain-leased").await;
    drop(client);
    let leased = setup.database.admin.query_one("SELECT delivery.event_id FROM registry_internal.registry_webhook_deliveries AS delivery
        JOIN registry_internal.registry_outbox AS outbox USING (event_id)
        WHERE delivery.handler_kind = 'rhai' ORDER BY outbox.outbox_id DESC LIMIT 1", &[]).await.unwrap().get::<_, Uuid>(0);
    let changed = setup.database.admin.execute("UPDATE registry_internal.registry_webhook_delivery_state AS state
        SET state = 'leased', attempt = 1, next_attempt_at = NULL,
            attempt_started_at = transaction_timestamp(), lease_expires_at = transaction_timestamp() + interval '60 seconds', lease_token = gen_random_uuid()
        FROM registry_internal.registry_webhook_deliveries AS delivery
        WHERE state.event_id = delivery.event_id AND state.compiled_delivery_id = delivery.compiled_delivery_id
          AND state.event_id = $1 AND delivery.handler_kind = 'rhai'", &[&leased]).await.unwrap();
    assert_eq!(changed, 1, "the newest local hook has a live lease");
    let report = setup
        .service
        .drain_local(1, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(report.completed_attempts, 1);
    assert_eq!(report.delivered, 1);
    assert_eq!(
        report.stop_reason,
        registry_breg::webhook::WebhookDrainStopReason::AttemptBudget
    );
    assert_eq!(report.remaining.retained_deliveries, 2);
    assert_eq!(record_count(&setup, "followup").await, 1);
    let report = setup
        .service
        .drain_local(10, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(report.delivered, 1);
    assert_eq!(
        report.stop_reason,
        registry_breg::webhook::WebhookDrainStopReason::Idle
    );
    assert_eq!(report.remaining.retained_deliveries, 1);
    let rows = setup.database.admin.query("SELECT state.state, state.attempt FROM registry_internal.registry_webhook_delivery_state AS state
        JOIN registry_internal.registry_webhook_deliveries AS delivery USING (event_id, compiled_delivery_id)
        WHERE delivery.handler_kind = 'url'", &[]).await.unwrap();
    assert_eq!(rows.len(), 3);
    for row in rows {
        assert_eq!(row.get::<_, String>(0), "pending");
        assert_eq!(row.get::<_, i16>(1), 0);
    }
    for event in [first, second] {
        let rows = setup.service.list(20).await.unwrap();
        assert!(rows.iter().any(|row| row.event_id == event.event_id
            && row.state == registry_breg::webhook::WebhookDeliveryStatusKind::Pending));
    }
    assert_ready(&setup).await;
    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failing_local_hooks_stay_retained_until_explicit_discard() {
    let receiver = HttpsReceiver::start().await;
    let (mut project, mut assets) = project(true);
    assets[1].bytes = br#"fn handle(ctx) { throw "canary failure"; }"#.to_vec();
    let initial = package(&project, &assets, None).await;
    let setup = activated_setup(&initial, &receiver, true).await;
    let mut client = setup.pool.get_for_test().await.unwrap();
    let event = create_case(&setup, &mut client, "failing-local").await;
    drop(client);
    let delivery_id = single_delivery(&event);
    for attempt in 1..=5 {
        setup.database.admin.execute("UPDATE registry_internal.registry_webhook_delivery_state SET next_attempt_at = transaction_timestamp() - interval '1 second' WHERE event_id = $1 AND state = 'pending'", &[&event.event_id]).await.unwrap();
        let report = setup
            .service
            .drain_local(1, Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(report.completed_attempts, 1);
        assert_eq!(report.remaining.retained_deliveries, 1);
        if attempt < 5 {
            assert_eq!(report.retry_scheduled, 1);
            setup
                .database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_webhook_delivery_state SET next_attempt_at = transaction_timestamp() + interval '1 hour' WHERE event_id = $1 AND state = 'pending'",
                    &[&event.event_id],
                )
                .await
                .unwrap();
            let idle = setup
                .service
                .drain_local(1, Duration::from_secs(10))
                .await
                .unwrap();
            assert_eq!(
                idle.completed_attempts, 0,
                "future retry is not made due by drain"
            );
        } else {
            assert_eq!(report.dead_lettered, 1);
        }
    }
    let row = delivery_row(&setup, event.event_id, delivery_id).await;
    assert_eq!(row.state, "dead-lettered");
    assert_eq!(row.attempt, 5);
    let idle = setup
        .service
        .drain_local(10, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(
        idle.completed_attempts, 0,
        "drain does not replay dead letters"
    );
    let target = successor(&setup, &mut project, &assets).await;
    let inventory = setup
        .fixture
        .activate_without_destinations(target.registry())
        .compatibility_inventory();
    let planned = plan_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            true,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .unwrap_err();
    let applied = apply_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            false,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .unwrap_err();
    assert_eq!(planned, applied);
    let registry_breg::migration::MigrationError::RetainedLocalHooks(retained) = applied else {
        panic!("named local refusal")
    };
    assert_eq!(retained.retained_deliveries, 1);
    assert_eq!(retained.compiled_delivery_ids, vec![delivery_id]);
    assert_ready(&setup).await;
    assert_eq!(
        setup.database.activation_audit_entries().last().unwrap()["record"]["outcome"],
        "refused"
    );
    assert!(
        setup.service.list(10).await.unwrap()[0].replay_eligible,
        "ordinary execution failure still permits explicit replay"
    );
    setup
        .service
        .discard(event.event_id, delivery_id, 1)
        .await
        .unwrap();
    apply_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            false,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .unwrap();
    assert_eq!(record_count(&setup, "followup").await, 0);
    setup.teardown().await;
    receiver.stop().await;
}

#[cfg(feature = "wasm")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_drain_executes_wasm_with_the_captured_active_authority() {
    registry_breg::wasm_runtime::install_default().unwrap();
    let receiver = HttpsReceiver::start().await;
    let (mut project, mut assets) = project(true);
    project["recordTypes"][0]["hooks"][0]["handler"] =
        json!({"type":"wasm", "module":"hooks/propose.wasm", "abi":"registry.hook-handler/v1"});
    assets[1] = ModuleAssetSource {
        module: None,
        path: "hooks/propose.wasm".to_owned(),
        bytes: outcome_guest(HOOK_PROPOSAL_STR),
    };
    let initial = package(&project, &assets, None).await;
    let setup = activated_setup(&initial, &receiver, true).await;
    let mut client = setup.pool.get_for_test().await.unwrap();
    create_case(&setup, &mut client, "wasm-drain").await;
    drop(client);
    let report = setup
        .service
        .drain_local(1, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(report.delivered, 1);
    assert_eq!(report.remaining.retained_deliveries, 0);
    assert_eq!(record_count(&setup, "followup").await, 1);
    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_drain_stops_at_the_time_budget_and_preserves_an_unfinished_lease() {
    let receiver = HttpsReceiver::start().await;
    let (project, assets) = project(true);
    let initial = package(&project, &assets, None).await;
    let setup = activated_setup(&initial, &receiver, true).await;
    let mut client = setup.pool.get_for_test().await.unwrap();
    let event = create_case(&setup, &mut client, "deadline-first").await;
    create_case(&setup, &mut client, "deadline-second").await;
    drop(client);
    let (mut blocker, task) = setup.database.connect_migration().await;
    let transaction = blocker.transaction().await.unwrap();
    let table = &setup.compiled.entities()["followup"].physical_table;
    transaction
        .batch_execute(&format!(
            "LOCK TABLE registry_data.{table} IN ACCESS EXCLUSIVE MODE"
        ))
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let report = setup
        .service
        .drain_local(100, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(
        report.stop_reason,
        registry_breg::webhook::WebhookDrainStopReason::TimeBudget
    );
    assert_eq!(report.completed_attempts, 0);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(report.remaining.retained_deliveries, 2);
    let row = delivery_row(&setup, event.event_id, single_delivery(&event)).await;
    assert_eq!(row.state, "leased");
    assert_eq!(row.attempt, 1);
    transaction.rollback().await.unwrap();
    drop(blocker);
    task.abort();
    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_local_hook_diagnostics_are_bounded_and_deduplicate_compiled_ids() {
    let receiver = HttpsReceiver::start().await;
    let (mut project, assets) = project(true);
    let initial = package(&project, &assets, None).await;
    let setup = activated_setup(&initial, &receiver, true).await;
    let mut client = setup.pool.get_for_test().await.unwrap();
    for index in 0..101 {
        create_case(&setup, &mut client, &format!("retained-{index}")).await;
    }
    drop(client);
    let target = successor(&setup, &mut project, &assets).await;
    let inventory = setup
        .fixture
        .activate_without_destinations(target.registry())
        .compatibility_inventory();
    let error = plan_verified_package(
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            true,
        )
        .with_event_destination_compatibility_inventory(&inventory),
    )
    .await
    .unwrap_err();
    let registry_breg::migration::MigrationError::RetainedLocalHooks(retained) = error else {
        panic!("named local refusal")
    };
    assert_eq!(retained.retained_deliveries, 100);
    assert!(retained.truncated);
    assert_eq!(retained.compiled_delivery_ids.len(), 1);
    assert_ready(&setup).await;
    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_hook_refusal_audit_failures_preserve_ready_state() {
    let receiver = HttpsReceiver::start().await;
    let (mut project, assets) = project(true);
    let initial = package(&project, &assets, None).await;
    let setup = activated_setup(&initial, &receiver, true).await;
    let mut client = setup.pool.get_for_test().await.unwrap();
    create_case(&setup, &mut client, "refusal-audit").await;
    drop(client);
    let target = successor(&setup, &mut project, &assets).await;
    let inventory = setup
        .fixture
        .activate_without_destinations(target.registry())
        .compatibility_inventory();
    let before = setup.database.activation_audit_entries().len();
    let apply = || {
        request(
            &setup.database,
            &target,
            ApplyPrecondition::Successor {
                current: &setup.identity,
            },
            false,
        )
        .with_event_destination_compatibility_inventory(&inventory)
    };

    setup.database.activation_audit_capture().fail_after(0);
    let refused = apply_verified_package(apply()).await.unwrap_err();
    assert_eq!(
        refused,
        registry_breg::migration::MigrationError::ActivationAuditUnavailable
    );
    assert_ready(&setup).await;
    assert_eq!(setup.database.activation_audit_entries().len(), before);

    setup.database.activation_audit_capture().restore();
    setup.database.activation_audit_capture().fail_after(1);
    let refused = apply_verified_package(apply()).await.unwrap_err();
    assert_ready(&setup).await;
    let entries = setup.database.activation_audit_entries();
    assert_eq!(entries.len(), before + 1, "only the request was accepted");
    let accepted = &entries[before];
    assert_eq!(
        accepted["schema"],
        registry_breg::migration::ACTIVATION_AUDIT_SCHEMA
    );
    assert_eq!(accepted["phase"], "request");
    assert_eq!(accepted["record"]["phase"], "attempt");
    assert_eq!(accepted["record"]["outcome"], "started");
    assert_eq!(
        accepted["record"]["priorActivationId"],
        setup.identity.activation_id
    );
    assert_eq!(accepted["record"]["packageDigest"], target.package_digest());
    assert_eq!(
        refused,
        registry_breg::migration::MigrationError::ActivationRefusalAuditIncomplete
    );
    setup.teardown().await;
    receiver.stop().await;
}
