use std::collections::BTreeMap;
use std::env;
use std::sync::Arc;

use registry_casework::{AttemptSettlementError, DatabaseConfig, PostgresStore, StoreError};
use registry_casework_core::{
    ActorContext, AttemptSettlement, AttemptSettlementOutcome, AttemptState,
    AttemptUncertainMarking, AuthoritativeObservation, BootstrapDirectoryRequest, CaseworkRole,
    HistoryKind, IssuerPrincipal, OccurrenceKind, OccurrenceState, OperationName,
    PreparedSourceAttempt, RecoveryEvidence, SourceBinding, SourceReceipt, SubjectRef,
    TransitionHint,
};
use registry_platform_config::{SecretProvider, SecretResolver};

fn actor(subject: &str, role: CaseworkRole, profile: &str) -> ActorContext {
    ActorContext {
        principal: IssuerPrincipal {
            issuer: "https://issuer.test".to_owned(),
            subject: subject.to_owned(),
        },
        profile_id: profile.to_owned(),
        role,
    }
}

fn binding_generation(revision: i64, version: &str, generation: &str) -> SourceBinding {
    SourceBinding {
        source_revision: revision.to_string(),
        version: version.to_owned(),
        integrity: Some(format!("digest-{version}")),
        generation: generation.to_owned(),
    }
}

fn observation(
    revision: i64,
    version: &str,
    kind: OccurrenceKind,
    state: OccurrenceState,
) -> AuthoritativeObservation {
    observation_generation(revision, version, kind, state, "binding-a")
}

fn observation_generation(
    revision: i64,
    version: &str,
    kind: OccurrenceKind,
    state: OccurrenceState,
    generation: &str,
) -> AuthoritativeObservation {
    observation_generation_with_etag(
        revision,
        version,
        kind,
        state,
        generation,
        &format!("\"representation-{revision}\""),
    )
}

fn observation_generation_with_etag(
    revision: i64,
    version: &str,
    kind: OccurrenceKind,
    state: OccurrenceState,
    generation: &str,
    representation_etag: &str,
) -> AuthoritativeObservation {
    let value = serde_json::json!({
        "subject": SubjectRef {
            source_id: "source-a".to_owned(),
            kind: "request-a".to_owned(),
            id: "subject-a".to_owned(),
        },
        "occurrenceKey": format!("{kind:?}:{version}:{generation}"),
        "orderedRevision": revision,
        "binding": binding_generation(revision, version, generation),
        "representationEtag": representation_etag,
        "occurrenceKind": kind,
        "stage": (kind == OccurrenceKind::Review).then(|| "review".to_owned()),
        "state": state,
        "remainingActions": [OperationName::parse("approve").expect("approve operation")],
    });
    serde_json::from_value(value).expect("strong representation ETag is an observation fact")
}

fn observation_with_representation_etag(
    revision: i64,
    version: &str,
    state: OccurrenceState,
    representation_etag: &str,
) -> AuthoritativeObservation {
    let mut value = serde_json::to_value(observation_generation(
        revision,
        version,
        OccurrenceKind::Review,
        state,
        "binding-a",
    ))
    .expect("serialize observation fixture");
    value["representationEtag"] = serde_json::Value::String(representation_etag.to_owned());
    serde_json::from_value(value).expect("strong representation ETag is an observation fact")
}

fn observation_for_subject(
    subject_id: &str,
    revision: i64,
    version: &str,
    state: OccurrenceState,
) -> AuthoritativeObservation {
    let mut observation = observation(revision, version, OccurrenceKind::Review, state);
    observation.subject.source_id = "source-cycle".to_owned();
    observation.subject.id = subject_id.to_owned();
    observation.binding.generation = "binding-cycle".to_owned();
    observation.occurrence_key = format!("Review:{version}:binding-cycle");
    observation
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transactional_checkpoint_invariants_hold_in_postgresql() {
    let _ = observation_with_representation_etag(1, "proposal-1", OccurrenceState::Open, "\"r1\"");
    let url = env::var("CASEWORK_TEST_DATABASE_URL")
        .expect("CASEWORK_TEST_DATABASE_URL is required for the real PostgreSQL test");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect dedicated test database");
    tokio::spawn(async move { connection.await.expect("test connection") });
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .await
        .expect("reset only the dedicated Casework test database");

    let secrets =
        SecretResolver::new([SecretProvider::Environment], "/private/tmp").expect("test resolver");
    let config = DatabaseConfig {
        runtime_url_ref: "secret:env/CASEWORK_TEST_DATABASE_URL".to_owned(),
        migration_url_ref: "secret:env/CASEWORK_TEST_DATABASE_URL".to_owned(),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let store = PostgresStore::connect_migration(&config, &secrets).expect("migration pool");
    store.migrate().await.expect("migrate");
    let runtime = PostgresStore::connect_runtime(&config, &secrets).expect("runtime pool");
    synchronization_claims_reserve_fresh_and_retry_capacity(&client, &runtime).await;
    item_identity_does_not_require_a_subject_ledger_parent(&client, &runtime).await;

    let admin = actor("admin", CaseworkRole::Administrator, "administrator");
    let officer_one = actor("officer-1", CaseworkRole::Staff, "staff");
    let officer_two = actor("officer-2", CaseworkRole::Staff, "staff");
    let supervisor = actor("supervisor", CaseworkRole::Supervisor, "supervisor");
    runtime
        .bootstrap_directory(
            &admin,
            0,
            &BootstrapDirectoryRequest {
                team_id: "team-a".to_owned(),
                staff: vec![officer_one.principal.clone(), officer_two.principal.clone()],
                supervisors: vec![supervisor.principal.clone()],
                queue_id: "default".to_owned(),
            },
            "bootstrap-a",
        )
        .await
        .expect("authorized bootstrap");

    let proposal_v1 = runtime
        .apply_observation(
            &observation_for_subject(
                "proposal-cycle-subject",
                1,
                "proposal-v1",
                OccurrenceState::Open,
            ),
            "default",
            Some(172_800),
        )
        .await
        .expect("proposal v1 observation")
        .expect("proposal v1 opens a review occurrence");
    runtime
        .apply_observation(
            &observation_for_subject(
                "proposal-cycle-subject",
                2,
                "proposal-v2",
                OccurrenceState::Superseded,
            ),
            "default",
            Some(172_800),
        )
        .await
        .expect("proposal v2 supersedes the prior occurrence");
    let superseded_subject = client
        .query_one(
            "SELECT active,sync_pending FROM casework_subjects WHERE source_id='source-cycle' AND subject_kind='request-a' AND subject_id='proposal-cycle-subject'",
            &[],
        )
        .await
        .expect("superseded subject reconciliation state");
    assert!(!superseded_subject.get::<_, bool>(0));
    assert!(!superseded_subject.get::<_, bool>(1));
    assert!(
        runtime
            .local_active_subjects("source-cycle", 10)
            .await
            .expect("scan active subjects after supersession")
            .is_empty(),
        "the next local reconciliation cycle must not re-enqueue a superseded subject"
    );
    let proposal_v2 = runtime
        .apply_observation(
            &observation_for_subject(
                "proposal-cycle-subject",
                3,
                "proposal-v2",
                OccurrenceState::Open,
            ),
            "default",
            Some(172_800),
        )
        .await
        .expect("resubmitted proposal v2 does not collide with historical v1")
        .expect("resubmitted proposal opens a review occurrence");
    assert_ne!(proposal_v2.item_id, proposal_v1.item_id);
    assert_eq!(proposal_v2.binding.version, "proposal-v2");
    assert_eq!(proposal_v2.state, OccurrenceState::Open);
    assert_eq!(proposal_v2.holder, None);
    let historical_v1 = runtime
        .item(proposal_v1.item_id)
        .await
        .expect("historical proposal v1 occurrence");
    assert_eq!(historical_v1.binding.version, "proposal-v1");
    assert_eq!(historical_v1.state, OccurrenceState::Superseded);

    let hint = TransitionHint {
        subject: observation(
            1,
            "proposal-1",
            OccurrenceKind::Review,
            OccurrenceState::Open,
        )
        .subject,
        deduplication_key: "event-1".to_owned(),
        ordered_revision: 1,
    };
    let (first, second) = tokio::join!(
        runtime.ingest_transition("binding-a", &hint),
        runtime.ingest_transition("binding-a", &hint)
    );
    assert_ne!(first.expect("first ingest"), second.expect("second ingest"));

    let item = runtime
        .apply_observation(
            &observation(
                1,
                "proposal-1",
                OccurrenceKind::Review,
                OccurrenceState::Open,
            ),
            "default",
            Some(172_800),
        )
        .await
        .expect("initial observation")
        .expect("item opened");
    assert!(item.passive_due_at.is_some());

    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let claim_one = {
        let runtime = runtime.clone();
        let actor = officer_one.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            runtime
                .claim(&actor, item.item_id, item.revision, "claim-one")
                .await
        })
    };
    let claim_two = {
        let runtime = runtime.clone();
        let actor = officer_two.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            runtime
                .claim(&actor, item.item_id, item.revision, "claim-two")
                .await
        })
    };
    barrier.wait().await;
    let result_one = claim_one.await.expect("first task");
    let result_two = claim_two.await.expect("second task");
    assert_eq!(
        usize::from(result_one.is_ok()) + usize::from(result_two.is_ok()),
        1
    );
    let (holder, claimed) = if let Ok(item) = result_one {
        (officer_one.clone(), item)
    } else {
        (officer_two.clone(), result_two.expect("other claim wins"))
    };
    assert_eq!(claimed.state, OccurrenceState::Claimed);
    assert_eq!(claimed.holder, Some(holder.principal.clone()));

    let refreshed = runtime
        .apply_observation(
            &observation(
                3,
                "proposal-1",
                OccurrenceKind::Review,
                OccurrenceState::Open,
            ),
            "default",
            Some(172_800),
        )
        .await
        .expect("newer observation")
        .expect("same item updated");
    assert_eq!(refreshed.holder, Some(holder.principal.clone()));
    assert_eq!(refreshed.state, OccurrenceState::Claimed);
    let higher_hint = TransitionHint {
        subject: refreshed.subject.clone(),
        deduplication_key: "event-higher-than-read".to_owned(),
        ordered_revision: 5,
    };
    assert!(runtime
        .ingest_transition("binding-a", &higher_hint)
        .await
        .expect("higher source watermark is retained"));
    let same_revision_changed_representation = observation_generation_with_etag(
        3,
        "proposal-1",
        OccurrenceKind::Review,
        OccurrenceState::Open,
        "binding-a",
        "\"representation-3-attachments-verified\"",
    );
    let refreshed_representation = runtime
        .apply_observation(
            &same_revision_changed_representation,
            "default",
            Some(172_800),
        )
        .await
        .expect("equal-revision observation")
        .expect("changed representation ETag refreshes the claimed occurrence");
    assert_eq!(refreshed_representation.item_id, refreshed.item_id);
    assert_eq!(refreshed_representation.holder, refreshed.holder);
    assert_eq!(refreshed_representation.state, OccurrenceState::Claimed);
    assert_eq!(
        refreshed_representation.first_observed_at,
        refreshed.first_observed_at
    );
    assert_eq!(
        refreshed_representation.passive_due_at,
        refreshed.passive_due_at
    );
    assert_eq!(refreshed_representation.revision, refreshed.revision + 1);
    let subject_sync = client
        .query_one(
            "SELECT wanted_revision,applied_revision,representation_etag,sync_pending FROM casework_subjects WHERE source_id='source-a' AND subject_kind='request-a' AND subject_id='subject-a'",
            &[],
        )
        .await
        .expect("subject synchronization state");
    assert_eq!(subject_sync.get::<_, i64>(0), 5);
    assert_eq!(subject_sync.get::<_, i64>(1), 3);
    assert_eq!(
        subject_sync.get::<_, Option<String>>(2).as_deref(),
        Some("\"representation-3-attachments-verified\"")
    );
    assert!(subject_sync.get::<_, bool>(3));
    assert!(runtime
        .apply_observation(
            &same_revision_changed_representation,
            "default",
            Some(172_800),
        )
        .await
        .expect("unchanged representation is accepted idempotently")
        .is_none());
    assert_eq!(
        runtime
            .item(refreshed.item_id)
            .await
            .expect("unchanged representation leaves item intact")
            .revision,
        refreshed_representation.revision
    );
    assert!(runtime
        .apply_observation(
            &observation(
                2,
                "proposal-1",
                OccurrenceKind::Review,
                OccurrenceState::Open
            ),
            "default",
            Some(172_800),
        )
        .await
        .expect("stale observation ignored")
        .is_none());
    let representation_after_stale = client
        .query_one(
            "SELECT representation_etag FROM casework_subjects WHERE source_id='source-a' AND subject_kind='request-a' AND subject_id='subject-a'",
            &[],
        )
        .await
        .expect("representation after stale observation");
    assert_eq!(
        representation_after_stale
            .get::<_, Option<String>>(0)
            .as_deref(),
        Some("\"representation-3-attachments-verified\"")
    );

    let draft = runtime
        .save_draft(
            &holder,
            refreshed_representation.item_id,
            refreshed_representation.revision,
            &refreshed_representation.binding,
            "Please correct the bounded field.",
            &["field-a".to_owned()],
            "draft-a",
        )
        .await
        .expect("draft saved");
    let replay = runtime
        .save_draft(
            &holder,
            refreshed_representation.item_id,
            refreshed_representation.revision,
            &refreshed_representation.binding,
            "Please correct the bounded field.",
            &["field-a".to_owned()],
            "draft-a",
        )
        .await
        .expect("lost draft response replays despite advanced item revision");
    assert_eq!(draft, replay);
    assert!(
        runtime
            .read_draft(&officer_one, item.item_id)
            .await
            .expect("private read")
            .is_some()
            == (holder.principal == officer_one.principal)
    );
    assert!(
        runtime
            .read_draft(&officer_two, item.item_id)
            .await
            .expect("private read")
            .is_some()
            == (holder.principal == officer_two.principal)
    );

    let current = runtime.item(item.item_id).await.expect("current item");
    let offered_binding_reference = current.binding_reference.clone();
    let prepared = PreparedSourceAttempt {
        source_binding: current.binding.clone(),
        recovery_evidence: RecoveryEvidence::new(b"inert recovery capsule".to_vec())
            .expect("bounded evidence"),
    };
    let (attempt, execution_token) = runtime
        .reserve_attempt_for_execution(
            &holder,
            current.item_id,
            current.revision,
            "reviewer",
            OperationName::parse("approve").expect("approve operation"),
            None,
            &[],
            "decision-a",
            "sha256:request-a",
            &prepared,
        )
        .await
        .expect("attempt reserved before egress");
    let fenced_representation = observation_generation_with_etag(
        3,
        "proposal-1",
        OccurrenceKind::Review,
        OccurrenceState::Open,
        "binding-a",
        "\"representation-3-after-attempt\"",
    );
    assert!(runtime
        .apply_observation(&fenced_representation, "default", Some(172_800))
        .await
        .expect("pending attempt fences representation refresh")
        .is_none());
    let fenced_subject = client
        .query_one(
            "SELECT representation_etag,sync_pending FROM casework_subjects WHERE source_id='source-a' AND subject_kind='request-a' AND subject_id='subject-a'",
            &[],
        )
        .await
        .expect("fenced synchronization state");
    assert_eq!(
        fenced_subject.get::<_, Option<String>>(0).as_deref(),
        Some("\"representation-3-attachments-verified\"")
    );
    assert!(fenced_subject.get::<_, bool>(1));
    assert!(matches!(
        runtime
            .release(
                &holder,
                current.item_id,
                attempt.item_revision,
                "release-blocked"
            )
            .await,
        Err(StoreError::AttemptPending)
    ));
    assert!(
        runtime
            .load_prepared_attempt(&officer_one, attempt.attempt_id)
            .await
            .is_ok()
            == (holder.principal == officer_one.principal)
    );
    assert!(
        runtime
            .load_prepared_attempt(&officer_two, attempt.attempt_id)
            .await
            .is_ok()
            == (holder.principal == officer_two.principal)
    );

    runtime
        .mark_attempt_uncertain(&holder, attempt.attempt_id, execution_token)
        .await
        .expect("uncertain remains durable");
    assert!(matches!(
        runtime
            .register_source_generation("source-a", "binding-b")
            .await,
        Err(StoreError::AttemptPending)
    ));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let recovery_token = runtime
        .acquire_recovery_execution(&holder, attempt.attempt_id)
        .await
        .expect("released uncertain attempt can acquire a recovery lease");
    assert!(matches!(
        runtime
            .mark_attempt_uncertain(&holder, attempt.attempt_id, execution_token)
            .await,
        Err(StoreError::AttemptPending)
    ));
    assert!(matches!(
        runtime
            .acquire_recovery_execution(&holder, attempt.attempt_id)
            .await,
        Err(StoreError::AttemptPending)
    ));
    runtime
        .mark_attempt_uncertain(&holder, attempt.attempt_id, recovery_token)
        .await
        .expect("current recovery lease can release itself");

    let receipt = SourceReceipt {
        source_revision: "4".to_owned(),
        resulting_state: "approved".to_owned(),
        binding: current.binding.clone(),
        actor_reference: None,
        metadata: BTreeMap::from([
            (
                "nativeReceipt".to_owned(),
                r#"{"action":"approve","requestId":"native-request-a"}"#.to_owned(),
            ),
            ("traceId".to_owned(), "source-trace-a".to_owned()),
        ]),
    };
    assert!(matches!(
        runtime
            .complete_attempt(&holder, attempt.attempt_id, execution_token, &receipt)
            .await,
        Err(StoreError::AttemptPending)
    ));
    runtime
        .complete_attempt(&holder, attempt.attempt_id, recovery_token, &receipt)
        .await
        .expect("authoritative receipt settles the old-generation attempt");
    runtime
        .register_source_generation("source-a", "binding-b")
        .await
        .expect("settled old generation can rebind");
    let rebound_subject = client
        .query_one(
            "SELECT binding_generation,applied_revision,representation_etag FROM casework_subjects WHERE source_id='source-a' AND subject_kind='request-a' AND subject_id='subject-a'",
            &[],
        )
        .await
        .expect("rebound subject state");
    assert_eq!(rebound_subject.get::<_, String>(0), "binding-b");
    assert_eq!(rebound_subject.get::<_, i64>(1), 0);
    assert_eq!(rebound_subject.get::<_, Option<String>>(2), None);

    let delayed_old_hint = TransitionHint {
        subject: hint.subject.clone(),
        deduplication_key: "delayed-binding-a".to_owned(),
        ordered_revision: 100,
    };
    runtime
        .ingest_transition("binding-a", &delayed_old_hint)
        .await
        .expect("old hint is durably deduplicated without crossing generations");
    let rebound = runtime
        .apply_observation(
            &observation_generation(
                1,
                "proposal-b",
                OccurrenceKind::Review,
                OccurrenceState::Open,
                "binding-b",
            ),
            "default",
            Some(172_800),
        )
        .await
        .expect("lower new-generation revision converges")
        .expect("new-generation item opens");
    assert_eq!(rebound.binding.generation, "binding-b");
    assert_ne!(rebound.binding_reference, offered_binding_reference);
    assert!(runtime
        .claim_sync_batch(10, 30)
        .await
        .expect("inspect post-rebind watermark")
        .is_empty());

    let by_key = runtime
        .terminal_attempt_by_key(&holder, current.item_id, "decision-a")
        .await
        .expect("terminal response-loss lookup by original key")
        .expect("terminal attempt exists");
    assert_eq!(by_key.1.attempt_id, attempt.attempt_id);
    let by_id = runtime
        .terminal_attempt_by_id(&holder, attempt.attempt_id)
        .await
        .expect("terminal lookup by attempt id")
        .expect("terminal attempt exists");
    assert_eq!(by_id.1.receipt, Some(receipt.clone()));

    let history = runtime
        .history(&holder, item.item_id, 100)
        .await
        .expect("history");
    assert!(history
        .iter()
        .any(|event| event.kind == registry_casework_core::HistoryKind::Claimed));
    assert!(history
        .iter()
        .any(|event| event.kind == registry_casework_core::HistoryKind::AttemptReserved));
    let reserved = history
        .iter()
        .find(|event| event.kind == registry_casework_core::HistoryKind::AttemptReserved)
        .expect("reserved history");
    let completed = history
        .iter()
        .find(|event| event.kind == registry_casework_core::HistoryKind::ActionCompleted)
        .expect("completed history");
    assert_eq!(
        reserved.detail["bindingReference"],
        offered_binding_reference
    );
    assert_eq!(reserved.detail["operation"], "approve");
    assert!(reserved.detail.get("reason").is_none());
    assert_eq!(
        completed.detail["bindingReference"],
        offered_binding_reference
    );
    assert_eq!(completed.detail["operation"], "approve");
    assert!(completed.detail.get("reason").is_none());
    assert_eq!(
        completed.detail["sourceReceipt"],
        serde_json::to_value(&receipt).expect("serialize receipt")
    );
    assert_eq!(
        runtime
            .events(None, 100)
            .await
            .expect("durable events")
            .into_iter()
            .filter(|event| event.item_id == item.item_id)
            .count(),
        history.len()
    );
}

async fn synchronization_claims_reserve_fresh_and_retry_capacity(
    client: &tokio_postgres::Client,
    store: &PostgresStore,
) {
    client
        .batch_execute(
            "INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending,sync_lease_until) SELECT 'fair-global','request',format('fresh-%s',lpad(value::text,3,'0')),'generation',1,0,true,true,NULL FROM generate_series(0,99) AS value; INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending,sync_lease_until) SELECT 'fair-global','request',format('retry-%s',lpad(value::text,3,'0')),'generation',1,0,true,true,now()-interval '2 hours'+value*interval '1 second' FROM generate_series(0,99) AS value; INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending,sync_lease_until) SELECT format('plan-%s',value%10),'request',format('fresh-%s',lpad(value::text,5,'0')),'generation',1,0,true,true,NULL FROM generate_series(0,9999) AS value; INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending,sync_lease_until) SELECT format('plan-%s',value%10),'request',format('retry-%s',lpad(value::text,5,'0')),'generation',1,0,true,true,now()-interval '2 hours'+value*interval '1 millisecond' FROM generate_series(0,9999) AS value; INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending,sync_lease_until) VALUES('fair-global','request','zz-live-lease','generation',1,0,true,true,now()+interval '1 hour'); ANALYZE casework_subjects",
        )
        .await
        .expect("seed balanced claim classes and realistic planner noise");

    assert_sync_claim_plan(
        client,
        "EXPLAIN SELECT source_id,subject_kind,subject_id FROM casework_subjects WHERE erased_at IS NULL AND sync_pending=true AND sync_lease_until<now() ORDER BY sync_lease_until,source_id,subject_kind,subject_id FOR UPDATE SKIP LOCKED LIMIT 100",
        &["casework_subjects_sync_claim_idx"],
    )
    .await;
    assert_sync_claim_plan(
        client,
        "EXPLAIN SELECT source_id,subject_kind,subject_id FROM casework_subjects WHERE erased_at IS NULL AND sync_pending=true AND sync_lease_until IS NULL ORDER BY source_id,subject_kind,subject_id FOR UPDATE SKIP LOCKED LIMIT 100",
        &[
            "casework_subjects_not_erased_sync_idx",
            "casework_subjects_sync_claim_idx",
        ],
    )
    .await;
    assert_sync_claim_plan(
        client,
        "EXPLAIN SELECT source_id,subject_kind,subject_id FROM casework_subjects WHERE source_id='plan-0' AND binding_generation='generation' AND erased_at IS NULL AND sync_pending=true AND sync_lease_until<now() ORDER BY sync_lease_until,subject_kind,subject_id FOR UPDATE SKIP LOCKED LIMIT 100",
        &["casework_subjects_source_sync_claim_idx"],
    )
    .await;
    assert_sync_claim_plan(
        client,
        "EXPLAIN SELECT source_id,subject_kind,subject_id FROM casework_subjects WHERE source_id='plan-0' AND binding_generation='generation' AND erased_at IS NULL AND sync_pending=true AND sync_lease_until IS NULL ORDER BY subject_kind,subject_id FOR UPDATE SKIP LOCKED LIMIT 100",
        &[
            "casework_subjects_not_erased_sync_idx",
            "casework_subjects_source_sync_claim_idx",
        ],
    )
    .await;
    client
        .execute(
            "DELETE FROM casework_subjects WHERE source_id LIKE 'plan-%'",
            &[],
        )
        .await
        .expect("remove planner backlog before fairness claims");

    let global = store
        .claim_sync_batch(100, 30)
        .await
        .expect("claim fair global synchronization batch");
    assert_eq!(global.len(), 100);
    assert_eq!(
        global
            .iter()
            .filter(|subject| subject.id.starts_with("fresh-"))
            .count(),
        50,
        "sustained retries must retain fresh global capacity"
    );
    assert_eq!(
        global
            .iter()
            .filter(|subject| subject.id.starts_with("retry-"))
            .count(),
        50,
        "sustained fresh arrivals must retain global retry capacity"
    );
    assert!(global.iter().any(|subject| subject.id == "retry-000"));
    assert!(!global.iter().any(|subject| subject.id == "zz-live-lease"));
    client
        .execute(
            "DELETE FROM casework_subjects WHERE source_id='fair-global'",
            &[],
        )
        .await
        .expect("remove global fairness fixture");

    client
        .batch_execute(
            "INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending,sync_lease_until) SELECT 'fair-source','request',format('fresh-%s',lpad(value::text,3,'0')),'generation',1,0,true,true,NULL FROM generate_series(0,99) AS value; INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending,sync_lease_until) SELECT 'fair-source','request',format('retry-%s',lpad(value::text,3,'0')),'generation',1,0,true,true,now()-interval '2 hours'+value*interval '1 second' FROM generate_series(0,99) AS value; INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending,sync_lease_until) VALUES('fair-source','request','zz-live-lease','generation',1,0,true,true,now()+interval '1 hour')",
        )
        .await
        .expect("seed isolated source claim classes");
    let source = store
        .claim_source_sync_batch("fair-source", "generation", 100, 30)
        .await
        .expect("claim fair source synchronization batch");
    assert_eq!(source.len(), 100);
    assert_eq!(
        source
            .iter()
            .filter(|subject| subject.id.starts_with("fresh-"))
            .count(),
        50,
        "sustained retries must retain fresh source capacity"
    );
    assert_eq!(
        source
            .iter()
            .filter(|subject| subject.id.starts_with("retry-"))
            .count(),
        50,
        "sustained fresh arrivals must retain source retry capacity"
    );
    assert!(source.iter().any(|subject| subject.id == "retry-000"));
    assert!(!source.iter().any(|subject| subject.id == "zz-live-lease"));
    client
        .batch_execute("DELETE FROM casework_subjects WHERE source_id='fair-source'; INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending,sync_lease_until) VALUES('small-global','request','fresh','generation',1,0,true,true,NULL),('small-global','request','retry','generation',1,0,true,true,now()-interval '1 hour'),('small-global','request','live','generation',1,0,true,true,now()+interval '1 hour')")
        .await
        .expect("replace large fixtures with small global batch");
    assert_eq!(
        store
            .claim_sync_batch(1, 30)
            .await
            .expect("claim one global retry")[0]
            .id,
        "retry"
    );
    assert_eq!(
        store
            .claim_sync_batch(1, 30)
            .await
            .expect("fill the next global batch from fresh work")[0]
            .id,
        "fresh"
    );
    assert!(store.claim_sync_batch(0, 30).await.unwrap().is_empty());
    assert!(matches!(
        store.claim_sync_batch(-1, 30).await,
        Err(StoreError::Invalid)
    ));
    client
        .batch_execute("DELETE FROM casework_subjects WHERE source_id='small-global'; INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending,sync_lease_until) SELECT 'sparse-source','request',format('retry-%s',value),'generation',1,0,true,true,now()-interval '1 hour' FROM generate_series(0,2) AS value")
        .await
        .expect("seed sparse source retry class");
    assert_eq!(
        store
            .claim_source_sync_batch("sparse-source", "generation", 5, 30)
            .await
            .expect("fill source batch from available retries")
            .len(),
        3
    );
    assert!(store
        .claim_source_sync_batch("sparse-source", "generation", 0, 30)
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        store
            .claim_source_sync_batch("sparse-source", "generation", -1, 30)
            .await,
        Err(StoreError::Invalid)
    ));
    client
        .execute(
            "DELETE FROM casework_subjects WHERE source_id='sparse-source'",
            &[],
        )
        .await
        .expect("remove sparse source fixture");
}

async fn assert_sync_claim_plan(
    client: &tokio_postgres::Client,
    query: &str,
    expected_indexes: &[&str],
) {
    let plan = client
        .query(query, &[])
        .await
        .expect("explain bounded sync claim stream")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        expected_indexes.iter().any(|index| plan.contains(index)),
        "expected one of {expected_indexes:?} in plan:\n{plan}"
    );
    assert!(
        !plan.contains("Sort"),
        "bounded sync claim stream must not sort the pending queue:\n{plan}"
    );
}

async fn item_identity_does_not_require_a_subject_ledger_parent(
    client: &tokio_postgres::Client,
    store: &PostgresStore,
) {
    let item_id = uuid::Uuid::new_v4();
    let binding = serde_json::to_value(binding_generation(1, "orphan-v1", "binding-a"))
        .expect("binding JSON");
    client.execute(
        "INSERT INTO casework_items(item_id,source_id,subject_kind,subject_id,occurrence_kind,occurrence_key,stage,binding,state,queue_id,revision,first_observed_at,updated_at) VALUES($1,'source-a','request-a','adapter-owned-subject','review','adapter-occurrence','review',$2,'open','default',1,now(),now())",
        &[&item_id, &binding],
    ).await.expect("adapter-owned item does not require a subject ledger row");
    let has_parent: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM casework_subjects WHERE source_id='source-a' AND subject_kind='request-a' AND subject_id='adapter-owned-subject')",
            &[],
        )
        .await
        .expect("read subject ledger")
        .get(0);
    assert!(!has_parent);
    let item = store.item(item_id).await.expect("read adapter-owned item");
    assert_eq!(item.subject.id, "adapter-owned-subject");
    assert_eq!(item.state, OccurrenceState::Open);
    client
        .execute("DELETE FROM casework_items WHERE item_id=$1", &[&item_id])
        .await
        .expect("delete isolated adapter-owned item fixture");
}

/// A schema of its own, so a focused test never races the checkpoint suite that
/// resets the public schema of the same database.
async fn isolated_schema(prefix: &str) -> (PostgresStore, tokio_postgres::Client, String) {
    let base = env::var("CASEWORK_TEST_DATABASE_URL")
        .expect("CASEWORK_TEST_DATABASE_URL is required for the real PostgreSQL test");
    let schema = format!("{prefix}_{}", uuid::Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let (admin, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect dedicated test database");
    tokio::spawn(async move { connection.await.expect("admin connection") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create isolated schema");
    let secret = format!("CASEWORK_SCHEMA_{}", uuid::Uuid::new_v4().simple()).to_ascii_uppercase();
    env::set_var(&secret, &scoped);
    let secrets =
        SecretResolver::new([SecretProvider::Environment], "/private/tmp").expect("test resolver");
    let config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret}"),
        migration_url_ref: format!("secret:env/{secret}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let store = PostgresStore::connect_migration(&config, &secrets).expect("migration pool");
    let (client, connection) = tokio_postgres::connect(&scoped, tokio_postgres::NoTls)
        .await
        .expect("connect isolated schema");
    tokio::spawn(async move { connection.await.expect("schema connection") });
    (store, client, schema)
}

async fn occurrence_index(client: &tokio_postgres::Client, schema: &str) -> (u32, bool) {
    let row = client
        .query_one(
            "SELECT c.oid,i.indisunique FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_index i ON i.indexrelid=c.oid WHERE n.nspname=$1 AND c.relname='casework_items_occurrence_idx'",
            &[&schema],
        )
        .await
        .expect("the occurrence identity index exists");
    (row.get(0), row.get(1))
}

async fn applied_versions(client: &tokio_postgres::Client) -> Vec<i64> {
    client
        .query(
            "SELECT version FROM casework_schema_migrations ORDER BY version",
            &[],
        )
        .await
        .expect("read the migration ledger")
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

#[tokio::test]
async fn repeated_migration_is_a_ledger_no_op_and_never_drops_the_occurrence_index() {
    let (store, client, schema) = isolated_schema("migrate").await;
    store.migrate().await.expect("first migration");
    let applied = applied_versions(&client).await;
    assert_eq!(applied, (1..=16).collect::<Vec<i64>>());
    let index = occurrence_index(&client, &schema).await;
    assert!(index.1, "the occurrence identity index is unique");

    store
        .migrate()
        .await
        .expect("a database already at the ledger head migrates cleanly");
    assert_eq!(applied_versions(&client).await, applied);
    assert_eq!(
        occurrence_index(&client, &schema).await,
        index,
        "the second migration leaves the occurrence identity index in place"
    );
}

async fn items_by_state(client: &tokio_postgres::Client) -> Vec<(String, String, uuid::Uuid)> {
    client
        .query(
            "SELECT occurrence_key,state,item_id FROM casework_items WHERE source_id='source-a' ORDER BY first_observed_at,item_id",
            &[],
        )
        .await
        .expect("read occurrence items")
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect()
}

/// Bind the subject to `generation` and observe it open there, the way a
/// restart onto a package or source binding and the next reconciliation do.
async fn observe_open_in_generation(store: &PostgresStore, generation: &str) -> uuid::Uuid {
    store
        .register_source_generation("source-a", generation)
        .await
        .expect("rebind the source generation");
    store
        .apply_observation(
            &observation_generation(
                1,
                "proposal-1",
                OccurrenceKind::Review,
                OccurrenceState::Open,
                generation,
            ),
            "default",
            None,
        )
        .await
        .expect("the observation in the returned-to generation applies")
        .expect("the observation opens an item")
        .item_id
}

#[tokio::test]
async fn returning_to_an_earlier_binding_generation_opens_a_fresh_occurrence() {
    let (store, client, _schema) = isolated_schema("generation_return").await;
    store.migrate().await.expect("migrate");

    let first_a = observe_open_in_generation(&store, "binding-a").await;
    let b = observe_open_in_generation(&store, "binding-b").await;
    let second_a = observe_open_in_generation(&store, "binding-a").await;

    assert_ne!(
        second_a, first_a,
        "a superseded occurrence stays terminal; the returned-to binding opens a fresh item"
    );
    let key_a = "Review:proposal-1:binding-a".to_owned();
    let key_b = "Review:proposal-1:binding-b".to_owned();
    assert_eq!(
        items_by_state(&client).await,
        [
            (key_a.clone(), "superseded".to_owned(), first_a),
            (key_b, "superseded".to_owned(), b),
            (key_a, "open".to_owned(), second_a),
        ]
    );
}

async fn item_reference_revision_and_history(
    client: &tokio_postgres::Client,
    item_id: uuid::Uuid,
) -> (Option<String>, i64, i64) {
    let row = client
        .query_one(
            "SELECT i.display_reference,i.revision,(SELECT count(*) FROM casework_history h WHERE h.item_id=i.item_id) FROM casework_items i WHERE i.item_id=$1",
            &[&item_id],
        )
        .await
        .expect("read the stored item");
    (row.get(0), row.get(1), row.get(2))
}

#[tokio::test]
async fn an_unchanged_source_revision_refreshes_the_stored_display_reference() {
    let (store, client, _schema) = isolated_schema("display_reference").await;
    store.migrate().await.expect("migrate");
    store
        .register_source_generation("source-a", "binding-a")
        .await
        .expect("bind the source generation");
    let mut observed = observation(
        1,
        "proposal-1",
        OccurrenceKind::Review,
        OccurrenceState::Open,
    );
    observed.display_reference = Some("REF-FIRST".to_owned());
    let item_id = store
        .apply_observation(&observed, "default", None)
        .await
        .expect("the first observation applies")
        .expect("the first observation opens an item")
        .item_id;
    let (reference, revision, history) =
        item_reference_revision_and_history(&client, item_id).await;
    assert_eq!(reference.as_deref(), Some("REF-FIRST"));

    // The same source revision and representation, read through a binding
    // whose displayReference now names another field.
    observed.display_reference = Some("REF-SECOND".to_owned());
    assert!(store
        .apply_observation(&observed, "default", None)
        .await
        .expect("the unchanged revision applies")
        .is_none());
    assert_eq!(
        item_reference_revision_and_history(&client, item_id).await,
        (Some("REF-SECOND".to_owned()), revision, history),
        "the stored reference follows the source while the item revision and history stay put"
    );

    observed.display_reference = None;
    store
        .apply_observation(&observed, "default", None)
        .await
        .expect("the unchanged revision without a reference applies");
    assert_eq!(
        item_reference_revision_and_history(&client, item_id).await,
        (None, revision, history),
        "a reference the source no longer discloses is not kept"
    );
    let applied: i64 = client
        .query_one(
            "SELECT applied_revision FROM casework_subjects WHERE source_id='source-a' AND subject_kind='request-a' AND subject_id='subject-a'",
            &[],
        )
        .await
        .expect("read the subject ledger")
        .get(0);
    assert_eq!(applied, 1);
}

#[tokio::test]
async fn a_database_failure_names_the_violated_constraint_without_row_data() {
    let (store, client, _schema) = isolated_schema("constraint_name").await;
    store.migrate().await.expect("migrate");
    let violation = client
        .execute(
            "INSERT INTO casework_schema_migrations(version,applied_at) VALUES(1,now())",
            &[],
        )
        .await
        .expect_err("a repeated ledger version is refused");
    assert!(violation
        .as_db_error()
        .and_then(|error| error.detail())
        .is_some_and(|detail| detail.contains("(version)=(1)")));

    assert_eq!(
        StoreError::Postgres(violation).to_string(),
        "the Casework database operation failed (constraint casework_schema_migrations_pkey)"
    );
}

#[tokio::test]
async fn migration_16_releases_superseded_identities_in_a_database_that_holds_them() {
    let (store, client, _schema) = isolated_schema("occurrence_identity_upgrade").await;
    store.migrate().await.expect("establish current schema");
    client
        .batch_execute(
            "DROP INDEX casework_items_occurrence_idx; \
             CREATE UNIQUE INDEX casework_items_occurrence_idx \
                 ON casework_items(source_id, subject_kind, subject_id, occurrence_key); \
             DELETE FROM casework_schema_migrations WHERE version=16;",
        )
        .await
        .expect("simulate the schema before migration 16");
    let first_a = observe_open_in_generation(&store, "binding-a").await;
    let b = observe_open_in_generation(&store, "binding-b").await;

    store
        .migrate()
        .await
        .expect("migration 16 applies over superseded rows");

    assert_eq!(
        applied_versions(&client).await,
        (1..=16).collect::<Vec<_>>()
    );
    let second_a = observe_open_in_generation(&store, "binding-a").await;
    let states: Vec<(uuid::Uuid, String)> = items_by_state(&client)
        .await
        .into_iter()
        .map(|(_, state, item_id)| (item_id, state))
        .collect();
    assert_eq!(
        states,
        [
            (first_a, "superseded".to_owned()),
            (b, "superseded".to_owned()),
            (second_a, "open".to_owned()),
        ]
    );
    let duplicate_active = client
        .execute(
            "INSERT INTO casework_items(item_id,source_id,subject_kind,subject_id,occurrence_kind,occurrence_key,stage,binding,state,queue_id,revision,first_observed_at,updated_at) SELECT $1,source_id,subject_kind,subject_id,occurrence_kind,occurrence_key,stage,binding,'open',queue_id,1,now(),now() FROM casework_items WHERE item_id=$2",
            &[&uuid::Uuid::new_v4(), &second_a],
        )
        .await
        .expect_err("a second live item for one occurrence identity is refused");
    assert_eq!(
        duplicate_active
            .as_db_error()
            .and_then(|error| error.constraint()),
        Some("casework_items_occurrence_idx")
    );
}

/// The schema Casework v0.32.0 migrated to: versions 1 through 14, the last
/// release whose ledger still held the hosted-item tables migration 15 drops.
const V0_32_MIGRATIONS: [&str; 14] = [
    include_str!("../migrations/0001_casework.sql"),
    include_str!("../migrations/0002_hosted_casework.sql"),
    include_str!("../migrations/0003_assignment.sql"),
    include_str!("../migrations/0004_clocks.sql"),
    include_str!("../migrations/0005_source_retention.sql"),
    include_str!("../migrations/0006_source_history.sql"),
    include_str!("../migrations/0007_directory_targets.sql"),
    include_str!("../migrations/0008_retention_and_inbox_indexes.sql"),
    include_str!("../migrations/0009_directory_display_names.sql"),
    include_str!("../migrations/0010_reference_lookup_and_sort.sql"),
    include_str!("../migrations/0011_source_reconciliation_progress.sql"),
    include_str!("../migrations/0012_absence_cursors.sql"),
    include_str!("../migrations/0013_sync_claim_indexes.sql"),
    include_str!("../migrations/0014_task_grants.sql"),
];

async fn establish_v0_32_schema(client: &tokio_postgres::Client) {
    client
        .batch_execute(
            "CREATE TABLE casework_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL)",
        )
        .await
        .expect("create the migration ledger");
    for (version, migration) in (1_i64..).zip(V0_32_MIGRATIONS) {
        client
            .batch_execute(migration)
            .await
            .unwrap_or_else(|error| panic!("apply migration {version}: {error}"));
        client
            .execute(
                "INSERT INTO casework_schema_migrations(version,applied_at) VALUES($1,now())",
                &[&version],
            )
            .await
            .unwrap_or_else(|error| panic!("record migration {version}: {error}"));
    }
}

async fn row_count(client: &tokio_postgres::Client, table: &str) -> i64 {
    client
        .query_one(&format!("SELECT count(*) FROM {table}"), &[])
        .await
        .unwrap_or_else(|error| panic!("count {table}: {error}"))
        .get(0)
}

#[tokio::test]
async fn migration_refuses_to_drop_retained_hosted_work_and_writes_nothing() {
    let (store, client, _schema) = isolated_schema("hosted_work_upgrade").await;
    establish_v0_32_schema(&client).await;
    // One claimed hosted item still in flight, and the accountability record
    // an earlier decision retains for a year.
    client
        .batch_execute(
            "INSERT INTO casework_hosted_items(item_id,kind_id,kind_version,kind_policy_digest,kind_policy,queue_id,state,holder_issuer,holder_subject,revision,created_at,updated_at) \
                 VALUES('00000000-0000-4000-8000-0000000000a1','payment-review','1','sha256:policy','{}','review','claimed','https://issuer.test','officer-one',2,now(),now()); \
             INSERT INTO casework_hosted_actor_references(actor_ref,issuer,subject) \
                 VALUES('actor-1','https://issuer.test','officer-one'); \
             INSERT INTO casework_hosted_accountability(event_id,item_id,actor_ref,actor_issuer,actor_subject,profile_id,queue_id,outcome,occurred_at,retained_until) \
                 VALUES('00000000-0000-4000-8000-0000000000b1','00000000-0000-4000-8000-0000000000a2','actor-1','https://issuer.test','officer-one','staff','review','approved',now(),now()+interval '365 days');",
        )
        .await
        .expect("seed hosted work the way v0.32.0 retained it");

    let refusal = store
        .migrate()
        .await
        .expect_err("migration must not drop retained hosted work");
    assert!(
        matches!(refusal, StoreError::HostedWorkWouldBeDropped { .. }),
        "{refusal:?}"
    );
    assert_eq!(
        refusal.to_string(),
        "the Casework database holds hosted work that schema migration 15 would drop: \
         casework_hosted_accountability (1 row), casework_hosted_items (1 row), \
         casework_hosted_actor_references (1 row); nothing was changed. This release does not \
         carry hosted work forward: keep this database with the release that wrote it until \
         the work it holds is exported, then migrate a fresh Casework database for this release"
    );
    assert_eq!(
        applied_versions(&client).await,
        (1..=14).collect::<Vec<_>>()
    );
    assert_eq!(row_count(&client, "casework_hosted_items").await, 1);
    assert_eq!(
        row_count(&client, "casework_hosted_accountability").await,
        1
    );
    assert_eq!(
        row_count(&client, "casework_hosted_actor_references").await,
        1
    );
    let review_tables: bool = client
        .query_one(
            "SELECT to_regclass('casework_review_requests') IS NULL",
            &[],
        )
        .await
        .expect("inspect the review schema")
        .get(0);
    assert!(review_tables, "migration 15 was not applied");
}

#[tokio::test]
async fn migration_replaces_empty_hosted_tables_through_the_ledger_head() {
    let (store, client, _schema) = isolated_schema("hosted_empty_upgrade").await;
    establish_v0_32_schema(&client).await;

    store
        .migrate()
        .await
        .expect("empty hosted tables hold nothing to drop");

    assert_eq!(
        applied_versions(&client).await,
        (1..=16).collect::<Vec<_>>()
    );
    let hosted_tables_remaining: bool = client
        .query_one(
            "SELECT to_regclass('casework_hosted_items') IS NOT NULL",
            &[],
        )
        .await
        .expect("inspect the hosted schema")
        .get(0);
    assert!(!hosted_tables_remaining);
    store.ready().await.expect("the migrated schema is current");
}

#[tokio::test]
async fn migration_13_adds_sync_claim_indexes_to_an_existing_schema() {
    let (store, client, _schema) = isolated_schema("sync_claim_indexes").await;
    store.migrate().await.expect("establish current schema");
    client
        .batch_execute(
            "DROP INDEX casework_subjects_sync_claim_idx; \
             DROP INDEX casework_subjects_source_sync_claim_idx; \
             DELETE FROM casework_schema_migrations WHERE version=13;",
        )
        .await
        .expect("simulate a schema missing migration 13 indexes");

    store.migrate().await.expect("apply sync claim indexes");

    assert_eq!(
        applied_versions(&client).await,
        (1..=16).collect::<Vec<_>>()
    );
    let indexes: Vec<String> = client
        .query(
            "SELECT indexrelid::regclass::text FROM pg_index WHERE indexrelid IN ('casework_subjects_sync_claim_idx'::regclass,'casework_subjects_source_sync_claim_idx'::regclass) ORDER BY indexrelid::regclass::text",
            &[],
        )
        .await
        .expect("read upgraded sync claim indexes")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        indexes,
        [
            "casework_subjects_source_sync_claim_idx",
            "casework_subjects_sync_claim_idx"
        ]
    );
}

#[tokio::test]
async fn readiness_accepts_the_current_migration_ledger() {
    let (store, _client, _schema) = isolated_schema("ready_current").await;
    store
        .migrate()
        .await
        .expect("migrate to the current schema");

    store
        .ready()
        .await
        .expect("the complete current migration ledger is ready");
}

#[tokio::test]
async fn readiness_rejects_an_unmigrated_schema() {
    let (store, _client, _schema) = isolated_schema("ready_unmigrated").await;

    assert!(
        matches!(store.ready().await, Err(StoreError::Postgres(_))),
        "a schema without the migration ledger must fail readiness"
    );
}

#[tokio::test]
async fn readiness_rejects_a_partial_schema_missing_review_tables() {
    let (store, client, _schema) = isolated_schema("ready_partial").await;
    store
        .migrate()
        .await
        .expect("migrate before simulating drift");
    client
        .batch_execute(
            "DROP TABLE casework_review_task_drafts; \
             DELETE FROM casework_schema_migrations WHERE version = 15;",
        )
        .await
        .expect("simulate a partial schema without the unified review migration");

    assert!(
        matches!(store.ready().await, Err(StoreError::Corrupt)),
        "a partial migration ledger must fail readiness"
    );
}

#[tokio::test]
async fn readiness_rejects_an_unsupported_migration_version() {
    let (store, client, _schema) = isolated_schema("ready_unsupported").await;
    store
        .migrate()
        .await
        .expect("migrate to the current schema");
    client
        .execute(
            "INSERT INTO casework_schema_migrations(version,applied_at) \
             SELECT max(version) + 1, now() FROM casework_schema_migrations",
            &[],
        )
        .await
        .expect("simulate a schema created by a newer runtime");

    let refusal = store
        .ready()
        .await
        .expect_err("a schema newer than this binary must fail readiness");
    assert!(
        matches!(
            refusal,
            StoreError::SchemaNewer {
                found: 17,
                supported: 16
            }
        ),
        "a newer schema is not reported as corrupt data: {refusal:?}"
    );
    assert_eq!(
        refusal.to_string(),
        "the Casework database schema version 17 is newer than this binary supports (16); run a casework release that supports it"
    );
}

#[tokio::test]
async fn migration_refuses_a_schema_newer_than_this_binary_and_writes_nothing() {
    let (store, client, _schema) = isolated_schema("migrate_newer").await;
    store
        .migrate()
        .await
        .expect("migrate to the current schema");
    client
        .execute(
            "INSERT INTO casework_schema_migrations(version,applied_at) VALUES(17,now())",
            &[],
        )
        .await
        .expect("simulate a schema created by a newer runtime");
    let before = applied_versions(&client).await;

    let refusal = store
        .migrate()
        .await
        .expect_err("an older binary must not report a newer schema as migrated");
    assert!(
        matches!(
            refusal,
            StoreError::SchemaNewer {
                found: 17,
                supported: 16
            }
        ),
        "{refusal:?}"
    );
    assert_eq!(applied_versions(&client).await, before);
}

#[tokio::test]
async fn directory_readiness_requires_service_for_every_expected_queue() {
    let (store, client, _schema) = isolated_schema("directory_ready").await;
    store.migrate().await.expect("migrate");
    let expected = vec!["default".to_owned(), "appeals".to_owned()];
    let admin = actor("admin", CaseworkRole::Administrator, "administrator");
    store
        .bootstrap_directory(
            &admin,
            0,
            &BootstrapDirectoryRequest {
                team_id: "team-a".to_owned(),
                staff: Vec::new(),
                supervisors: Vec::new(),
                queue_id: "default".to_owned(),
            },
            "bootstrap-directory-ready",
        )
        .await
        .expect("assign the first expected queue");

    assert!(
        !store
            .directory_ready(&expected)
            .await
            .expect("check partial directory readiness"),
        "one assigned queue must not make a multi-queue project ready"
    );

    client
        .batch_execute(
            "INSERT INTO casework_teams(team_id,revision) VALUES('team-b',2); \
             INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('appeals','team-b',2);",
        )
        .await
        .expect("assign the second expected queue");
    assert!(
        store
            .directory_ready(&expected)
            .await
            .expect("check complete directory readiness"),
        "every expected queue has a serving team"
    );
}

#[tokio::test]
async fn retrying_an_audit_publication_preserves_its_original_timestamp() {
    let (store, client, _schema) = isolated_schema("audit_publication_retry").await;
    store.migrate().await.expect("migrate");
    let event_id = uuid::Uuid::new_v4();
    client
        .execute(
            "INSERT INTO casework_audit_outbox(event_id,audit_record) VALUES($1,$2)",
            &[&event_id, &serde_json::json!({"event": "casework.test"})],
        )
        .await
        .expect("insert a pending audit record");

    store
        .mark_audit_published(event_id)
        .await
        .expect("mark the pending audit record as published");
    let published_at: chrono::DateTime<chrono::Utc> = client
        .query_one(
            "SELECT published_at FROM casework_audit_outbox WHERE event_id=$1",
            &[&event_id],
        )
        .await
        .expect("read the original publication timestamp")
        .get(0);

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    store
        .mark_audit_published(event_id)
        .await
        .expect("retry marking the audit record as published");
    let retried_at: chrono::DateTime<chrono::Utc> = client
        .query_one(
            "SELECT published_at FROM casework_audit_outbox WHERE event_id=$1",
            &[&event_id],
        )
        .await
        .expect("read the publication timestamp after the retry")
        .get(0);

    assert_eq!(retried_at, published_at);
}

#[tokio::test]
async fn a_resubmitted_proposal_supersedes_the_earlier_application_item() {
    let (store, client, _schema) = isolated_schema("casework_resubmission").await;
    store.migrate().await.expect("migrate");
    let admin = actor("admin", CaseworkRole::Administrator, "administrator");
    let holder = actor("officer-1", CaseworkRole::Staff, "staff");
    let supervisor = actor("supervisor", CaseworkRole::Supervisor, "supervisor");
    store
        .bootstrap_directory(
            &admin,
            0,
            &BootstrapDirectoryRequest {
                team_id: "team-a".to_owned(),
                staff: vec![holder.principal.clone()],
                supervisors: vec![supervisor.principal.clone()],
                queue_id: "default".to_owned(),
            },
            "bootstrap-resubmission",
        )
        .await
        .expect("authorized bootstrap");
    let first = store
        .apply_observation(
            &observation(
                1,
                "proposal-1",
                OccurrenceKind::Application,
                OccurrenceState::Open,
            ),
            "default",
            None,
        )
        .await
        .expect("first proposal observation")
        .expect("first proposal opens an application item");
    store
        .claim(
            &holder,
            first.item_id,
            first.revision,
            "claim-first-proposal",
        )
        .await
        .expect("holder claims the first proposal");

    let resubmitted = store
        .apply_observation(
            &observation(
                2,
                "proposal-2",
                OccurrenceKind::Application,
                OccurrenceState::WaitingApplication,
            ),
            "default",
            None,
        )
        .await
        .expect("resubmitted proposal observation")
        .expect("resubmitted proposal opens its own application item");
    assert_ne!(resubmitted.item_id, first.item_id);

    let earlier = store.item(first.item_id).await.expect("earlier item");
    assert_eq!(earlier.state, OccurrenceState::Superseded);
    assert_eq!(earlier.holder, None);
    assert_eq!(earlier.binding.version, "proposal-1");
    let active: i64 = client
        .query_one(
            "SELECT count(*) FROM casework_items WHERE source_id='source-a' AND subject_kind='request-a' AND subject_id='subject-a' AND state NOT IN ('completed','superseded','cancelled')",
            &[],
        )
        .await
        .expect("count active items")
        .get(0);
    assert_eq!(active, 1, "one proposal leaves one application item");
    let current = store.item(resubmitted.item_id).await.expect("current item");
    assert_eq!(current.state, OccurrenceState::WaitingApplication);
}

const SETTLEMENT_REASON: &str =
    "The source refused the saved evidence version; the registrar confirmed no change was made.";
const SETTLEMENT_DECIDED_BY: &str = "Registrar duty officer, ticket OPS-4411";
const MARKING_REASON: &str =
    "The officer who started the attempt has left; the source call outcome is unknown.";

/// One claimed item whose only attempt is left live by its executor, the way
/// a saved-evidence version the binary refuses leaves it.
struct SettlementFixture {
    store: PostgresStore,
    client: tokio_postgres::Client,
    holder: ActorContext,
    item_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
    execution_token: uuid::Uuid,
    binding_reference: String,
}

async fn settlement_fixture(prefix: &str, mark_uncertain: bool) -> SettlementFixture {
    let (store, client, _schema) = isolated_schema(prefix).await;
    store.migrate().await.expect("migrate");
    let admin = actor("admin", CaseworkRole::Administrator, "administrator");
    let holder = actor("officer-1", CaseworkRole::Staff, "staff");
    let supervisor = actor("supervisor", CaseworkRole::Supervisor, "supervisor");
    store
        .bootstrap_directory(
            &admin,
            0,
            &BootstrapDirectoryRequest {
                team_id: "team-a".to_owned(),
                staff: vec![holder.principal.clone()],
                supervisors: vec![supervisor.principal.clone()],
                queue_id: "default".to_owned(),
            },
            "bootstrap-settlement",
        )
        .await
        .expect("authorized bootstrap");
    let opened = observation(
        1,
        "proposal-1",
        OccurrenceKind::Review,
        OccurrenceState::Open,
    );
    store
        .ingest_transition(
            "binding-a",
            &TransitionHint {
                subject: opened.subject.clone(),
                deduplication_key: "settlement-event-1".to_owned(),
                ordered_revision: 1,
            },
        )
        .await
        .expect("source hint records the subject");
    let item = store
        .apply_observation(&opened, "default", Some(172_800))
        .await
        .expect("initial observation")
        .expect("item opened");
    let claimed = store
        .claim(&holder, item.item_id, item.revision, "claim-settlement")
        .await
        .expect("holder claims the item");
    let prepared = PreparedSourceAttempt {
        source_binding: claimed.binding.clone(),
        recovery_evidence: RecoveryEvidence::new(b"inert recovery capsule".to_vec())
            .expect("bounded evidence"),
    };
    let (attempt, execution_token) = store
        .reserve_attempt_for_execution(
            &holder,
            claimed.item_id,
            claimed.revision,
            "reviewer",
            OperationName::parse("approve").expect("approve operation"),
            None,
            &[],
            "decision-settlement",
            "sha256:request-settlement",
            &prepared,
        )
        .await
        .expect("attempt reserved before egress");
    if mark_uncertain {
        store
            .mark_attempt_uncertain(&holder, attempt.attempt_id, execution_token)
            .await
            .expect("the executor leaves the attempt uncertain");
    }
    SettlementFixture {
        store,
        client,
        holder,
        item_id: claimed.item_id,
        attempt_id: attempt.attempt_id,
        execution_token,
        binding_reference: claimed.binding_reference,
    }
}

impl SettlementFixture {
    fn settlement(&self, outcome: AttemptSettlementOutcome) -> AttemptSettlement {
        AttemptSettlement {
            attempt_id: self.attempt_id,
            outcome,
            reason: SETTLEMENT_REASON.to_owned(),
            decided_by: SETTLEMENT_DECIDED_BY.to_owned(),
        }
    }

    fn marking(&self) -> AttemptUncertainMarking {
        AttemptUncertainMarking {
            attempt_id: self.attempt_id,
            reason: MARKING_REASON.to_owned(),
            decided_by: SETTLEMENT_DECIDED_BY.to_owned(),
        }
    }

    /// The executor's lease has lapsed. Set on the database clock, the clock
    /// the settlement reads, so host and container clock skew cannot flake it.
    async fn lapse_execution_lease(&self) {
        self.client
            .execute(
                "UPDATE casework_attempts SET execution_lease_until=now()-interval '1 second' WHERE attempt_id=$1",
                &[&self.attempt_id],
            )
            .await
            .expect("lapse the execution lease");
    }

    /// Every row a settlement may write, so a refusal or a preview can be
    /// shown to have written nothing.
    async fn snapshot(&self) -> serde_json::Value {
        self.client
            .query_one(
                "SELECT jsonb_build_object('history',(SELECT count(*) FROM casework_history),'events',(SELECT count(*) FROM casework_events),'audit',(SELECT count(*) FROM casework_audit_outbox),'attempt',(SELECT to_jsonb(a) FROM casework_attempts a WHERE attempt_id=$1),'item',(SELECT to_jsonb(i) FROM casework_items i WHERE item_id=$2),'subject',(SELECT to_jsonb(s) FROM casework_subjects s WHERE source_id='source-a' AND subject_kind='request-a' AND subject_id='subject-a'))",
                &[&self.attempt_id, &self.item_id],
            )
            .await
            .expect("settlement snapshot")
            .get(0)
    }

    async fn attempt_row(&self) -> (String, Option<serde_json::Value>) {
        let row = self
            .client
            .query_one(
                "SELECT state,receipt FROM casework_attempts WHERE attempt_id=$1",
                &[&self.attempt_id],
            )
            .await
            .expect("attempt row");
        (row.get(0), row.get(1))
    }

    /// The single settlement event, checked against the exact recorded detail.
    async fn assert_settlement_recorded(&self, outcome: &str, item_revision: i64) {
        let history = self
            .store
            .history(&self.holder, self.item_id, 100)
            .await
            .expect("history");
        let settled: Vec<_> = history
            .iter()
            .filter(|event| event.kind == HistoryKind::AttemptSettled)
            .collect();
        assert_eq!(settled.len(), 1, "one settlement event");
        let settled = settled[0];
        assert_eq!(settled.actor, None, "an operator settlement has no actor");
        assert_eq!(settled.item_revision, item_revision);
        assert_eq!(
            settled.detail,
            serde_json::json!({
                "attemptId": self.attempt_id,
                "bindingReference": self.binding_reference,
                "operation": "approve",
                "outcome": outcome,
                "reason": SETTLEMENT_REASON,
                "decidedBy": SETTLEMENT_DECIDED_BY,
            })
        );
        let durable = self
            .client
            .query_one(
                "SELECT e.event_kind,e.detail,a.audit_record FROM casework_events e JOIN casework_audit_outbox a USING(event_id) WHERE e.event_id=$1",
                &[&settled.event_id],
            )
            .await
            .expect("the settlement is a durable event with an audit record");
        assert_eq!(durable.get::<_, String>(0), "attempt_settled");
        assert_eq!(durable.get::<_, serde_json::Value>(1), settled.detail);
        let audit: serde_json::Value = durable.get(2);
        assert_eq!(audit["event"], "casework.attempt_settled");
        assert_eq!(audit["itemRevision"], item_revision);
        assert!(audit["actor"].is_null());
    }
}

#[tokio::test]
async fn a_not_applied_settlement_refuses_the_attempt_and_returns_the_item_to_its_holder() {
    let fixture = settlement_fixture("settle_not_applied", true).await;
    let before = fixture
        .store
        .item(fixture.item_id)
        .await
        .expect("wedged item");
    assert_eq!(before.state, OccurrenceState::Synchronizing);

    let report = fixture
        .store
        .settle_attempt(&fixture.settlement(AttemptSettlementOutcome::NotApplied))
        .await
        .expect("an uncertain attempt with a lapsed lease settles");
    assert!(report.applied);
    assert_eq!(report.attempt_id, fixture.attempt_id);
    assert_eq!(report.item_id, fixture.item_id);
    assert_eq!(report.attempt_state, AttemptState::Refused);
    assert_eq!(report.item_state, OccurrenceState::Claimed);

    assert_eq!(fixture.attempt_row().await, ("refused".to_owned(), None));
    let after = fixture
        .store
        .item(fixture.item_id)
        .await
        .expect("settled item");
    assert_eq!(after.state, OccurrenceState::Claimed);
    assert_eq!(after.holder, Some(fixture.holder.principal.clone()));
    assert_eq!(after.revision, before.revision + 1);
    fixture
        .assert_settlement_recorded("not_applied", after.revision)
        .await;

    let prepared = PreparedSourceAttempt {
        source_binding: after.binding.clone(),
        recovery_evidence: RecoveryEvidence::new(b"inert recovery capsule".to_vec())
            .expect("bounded evidence"),
    };
    fixture
        .store
        .reserve_attempt_for_execution(
            &fixture.holder,
            after.item_id,
            after.revision,
            "reviewer",
            OperationName::parse("approve").expect("approve operation"),
            None,
            &[],
            "decision-after-settlement",
            "sha256:request-after-settlement",
            &prepared,
        )
        .await
        .expect("the settled item accepts the holder's next action");
}

#[tokio::test]
async fn an_applied_settlement_completes_the_attempt_without_a_receipt_and_awaits_the_source() {
    let fixture = settlement_fixture("settle_applied", true).await;
    let before = fixture
        .store
        .item(fixture.item_id)
        .await
        .expect("wedged item");

    let report = fixture
        .store
        .settle_attempt(&fixture.settlement(AttemptSettlementOutcome::Applied))
        .await
        .expect("an uncertain attempt with a lapsed lease settles");
    assert!(report.applied);
    assert_eq!(report.attempt_state, AttemptState::Completed);
    assert_eq!(report.item_state, OccurrenceState::Synchronizing);

    assert_eq!(fixture.attempt_row().await, ("completed".to_owned(), None));
    let after = fixture
        .store
        .item(fixture.item_id)
        .await
        .expect("settled item");
    assert_eq!(after.state, OccurrenceState::Synchronizing);
    assert_eq!(after.revision, before.revision + 1);
    let terminal = fixture
        .store
        .terminal_attempt_by_id(&fixture.holder, fixture.attempt_id)
        .await
        .expect("terminal lookup by attempt id")
        .expect("the settled attempt is terminal");
    assert_eq!(terminal.1.state, AttemptState::Completed);
    assert_eq!(terminal.1.receipt, None);
    let sync_pending: bool = fixture
        .client
        .query_one(
            "SELECT sync_pending FROM casework_subjects WHERE source_id='source-a' AND subject_kind='request-a' AND subject_id='subject-a'",
            &[],
        )
        .await
        .expect("subject synchronization state")
        .get(0);
    assert!(
        sync_pending,
        "the next source observation is requested to settle the item"
    );
    fixture
        .assert_settlement_recorded("applied", after.revision)
        .await;
}

#[tokio::test]
async fn a_live_execution_lease_refuses_settlement_and_writes_nothing() {
    let fixture = settlement_fixture("settle_live_lease", true).await;
    fixture
        .store
        .acquire_recovery_execution(&fixture.holder, fixture.attempt_id)
        .await
        .expect("a recovery executor holds a live lease");
    let before = fixture.snapshot().await;

    for outcome in [
        AttemptSettlementOutcome::Applied,
        AttemptSettlementOutcome::NotApplied,
    ] {
        assert!(matches!(
            fixture
                .store
                .preview_attempt_settlement(&fixture.settlement(outcome))
                .await,
            Err(AttemptSettlementError::LeaseLive)
        ));
        assert!(matches!(
            fixture
                .store
                .settle_attempt(&fixture.settlement(outcome))
                .await,
            Err(AttemptSettlementError::LeaseLive)
        ));
    }
    assert_eq!(fixture.snapshot().await, before);
}

#[tokio::test]
async fn only_an_uncertain_attempt_can_be_settled() {
    let pending = settlement_fixture("settle_pending", false).await;
    pending.lapse_execution_lease().await;
    let before = pending.snapshot().await;
    assert!(matches!(
        pending
            .store
            .settle_attempt(&pending.settlement(AttemptSettlementOutcome::NotApplied))
            .await,
        Err(AttemptSettlementError::NotUncertain("pending"))
    ));
    assert_eq!(pending.snapshot().await, before);

    let settled = settlement_fixture("settle_terminal", true).await;
    settled
        .store
        .settle_attempt(&settled.settlement(AttemptSettlementOutcome::Applied))
        .await
        .expect("first settlement");
    let before = settled.snapshot().await;
    for outcome in [
        AttemptSettlementOutcome::Applied,
        AttemptSettlementOutcome::NotApplied,
    ] {
        assert!(matches!(
            settled
                .store
                .preview_attempt_settlement(&settled.settlement(outcome))
                .await,
            Err(AttemptSettlementError::NotUncertain("completed"))
        ));
        assert!(matches!(
            settled
                .store
                .settle_attempt(&settled.settlement(outcome))
                .await,
            Err(AttemptSettlementError::NotUncertain("completed"))
        ));
    }
    assert_eq!(settled.snapshot().await, before);

    let unknown = AttemptSettlement {
        attempt_id: uuid::Uuid::new_v4(),
        ..settled.settlement(AttemptSettlementOutcome::NotApplied)
    };
    assert!(matches!(
        settled.store.settle_attempt(&unknown).await,
        Err(AttemptSettlementError::NotFound)
    ));
    assert!(matches!(
        settled.store.preview_attempt_settlement(&unknown).await,
        Err(AttemptSettlementError::NotFound)
    ));
}

#[tokio::test]
async fn a_settlement_preview_reports_the_outcome_and_writes_nothing() {
    let fixture = settlement_fixture("settle_preview", true).await;
    let before = fixture.snapshot().await;

    let not_applied = fixture
        .store
        .preview_attempt_settlement(&fixture.settlement(AttemptSettlementOutcome::NotApplied))
        .await
        .expect("preview of a not-applied settlement");
    assert!(!not_applied.applied);
    assert_eq!(not_applied.attempt_id, fixture.attempt_id);
    assert_eq!(not_applied.item_id, fixture.item_id);
    assert_eq!(not_applied.operation.as_str(), "approve");
    assert_eq!(not_applied.binding_reference, fixture.binding_reference);
    assert_eq!(not_applied.outcome, AttemptSettlementOutcome::NotApplied);
    assert_eq!(not_applied.reason, SETTLEMENT_REASON);
    assert_eq!(not_applied.decided_by, SETTLEMENT_DECIDED_BY);
    assert_eq!(not_applied.attempt_state, AttemptState::Refused);
    assert_eq!(not_applied.item_state, OccurrenceState::Claimed);

    let applied = fixture
        .store
        .preview_attempt_settlement(&fixture.settlement(AttemptSettlementOutcome::Applied))
        .await
        .expect("preview of an applied settlement");
    assert!(!applied.applied);
    assert_eq!(applied.attempt_state, AttemptState::Completed);
    assert_eq!(applied.item_state, OccurrenceState::Synchronizing);

    assert_eq!(fixture.snapshot().await, before);
}

#[tokio::test]
async fn a_settlement_needs_a_bounded_reason_and_decider() {
    let fixture = settlement_fixture("settle_bounds", true).await;
    let before = fixture.snapshot().await;
    let base = fixture.settlement(AttemptSettlementOutcome::NotApplied);
    for (settlement, field) in [
        (
            AttemptSettlement {
                reason: String::new(),
                ..base.clone()
            },
            "reason",
        ),
        (
            AttemptSettlement {
                reason: "   ".to_owned(),
                ..base.clone()
            },
            "reason",
        ),
        (
            AttemptSettlement {
                reason: "x".repeat(2_001),
                ..base.clone()
            },
            "reason",
        ),
        (
            AttemptSettlement {
                decided_by: String::new(),
                ..base.clone()
            },
            "decided-by",
        ),
        (
            AttemptSettlement {
                decided_by: "duty\nofficer".to_owned(),
                ..base.clone()
            },
            "decided-by",
        ),
        (
            AttemptSettlement {
                decided_by: "x".repeat(257),
                ..base.clone()
            },
            "decided-by",
        ),
    ] {
        for result in [
            fixture.store.preview_attempt_settlement(&settlement).await,
            fixture.store.settle_attempt(&settlement).await,
        ] {
            match result {
                Err(AttemptSettlementError::Invalid { field: refused, .. }) => {
                    assert_eq!(refused, field);
                }
                other => panic!("expected an invalid {field}, got {other:?}"),
            }
        }
    }
    let at_bound = AttemptSettlement {
        reason: "x".repeat(2_000),
        decided_by: "x".repeat(256),
        ..base
    };
    fixture
        .store
        .preview_attempt_settlement(&at_bound)
        .await
        .expect("values at the bound are accepted");
    assert_eq!(fixture.snapshot().await, before);
}

#[tokio::test]
async fn a_settlement_needs_the_item_to_await_the_source_outcome() {
    let fixture = settlement_fixture("settle_item_state", true).await;
    fixture.lapse_execution_lease().await;
    fixture
        .client
        .execute(
            "UPDATE casework_items SET state='superseded' WHERE item_id=$1",
            &[&fixture.item_id],
        )
        .await
        .expect("supersede the item");
    let before = fixture.snapshot().await;
    for outcome in [
        AttemptSettlementOutcome::Applied,
        AttemptSettlementOutcome::NotApplied,
    ] {
        assert!(matches!(
            fixture
                .store
                .preview_attempt_settlement(&fixture.settlement(outcome))
                .await,
            Err(AttemptSettlementError::ItemNotSynchronizing("superseded"))
        ));
        assert!(matches!(
            fixture
                .store
                .settle_attempt(&fixture.settlement(outcome))
                .await,
            Err(AttemptSettlementError::ItemNotSynchronizing("superseded"))
        ));
    }
    assert_eq!(fixture.snapshot().await, before);
}

#[tokio::test]
async fn an_operator_marks_an_expired_pending_attempt_uncertain_naming_both_parties() {
    let fixture = settlement_fixture("mark_uncertain", false).await;
    fixture.lapse_execution_lease().await;
    let before = fixture
        .store
        .item(fixture.item_id)
        .await
        .expect("wedged item");
    assert_eq!(before.state, OccurrenceState::Synchronizing);

    let report = fixture
        .store
        .mark_expired_attempt_uncertain(&fixture.marking())
        .await
        .expect("a pending attempt with a lapsed lease is marked uncertain");
    assert!(report.applied);
    assert_eq!(report.attempt_id, fixture.attempt_id);
    assert_eq!(report.item_id, fixture.item_id);
    assert_eq!(report.operation.as_str(), "approve");
    assert_eq!(report.binding_reference, fixture.binding_reference);
    assert_eq!(report.original_actor, fixture.holder.principal);
    assert_eq!(report.original_profile_id, "staff");
    assert_eq!(report.reason, MARKING_REASON);
    assert_eq!(report.decided_by, SETTLEMENT_DECIDED_BY);
    assert_eq!(report.attempt_state, AttemptState::Uncertain);
    assert_eq!(report.item_state, OccurrenceState::Synchronizing);

    assert_eq!(fixture.attempt_row().await, ("uncertain".to_owned(), None));
    let after = fixture
        .store
        .item(fixture.item_id)
        .await
        .expect("marked item");
    assert_eq!(after.state, OccurrenceState::Synchronizing);
    assert_eq!(after.revision, before.revision + 1);

    let history = fixture
        .store
        .history(&fixture.holder, fixture.item_id, 100)
        .await
        .expect("history");
    let marked: Vec<_> = history
        .iter()
        .filter(|event| event.kind == HistoryKind::AttemptUncertain)
        .collect();
    assert_eq!(marked.len(), 1, "one uncertainty event");
    let marked = marked[0];
    assert_eq!(marked.actor, None, "an operator decision has no actor");
    assert_eq!(marked.profile_id, "system:operator");
    assert_eq!(marked.item_revision, after.revision);
    assert_eq!(
        marked.detail,
        serde_json::json!({
            "attemptId": fixture.attempt_id,
            "bindingReference": fixture.binding_reference,
            "operation": "approve",
            "operatorReason": MARKING_REASON,
            "decidedBy": SETTLEMENT_DECIDED_BY,
            "originalActor": {
                "issuer": fixture.holder.principal.issuer,
                "subject": fixture.holder.principal.subject,
            },
            "originalProfileId": "staff",
        })
    );
    let durable = fixture
        .client
        .query_one(
            "SELECT e.event_kind,e.detail,a.audit_record FROM casework_events e JOIN casework_audit_outbox a USING(event_id) WHERE e.event_id=$1",
            &[&marked.event_id],
        )
        .await
        .expect("the decision is a durable event with an audit record");
    assert_eq!(durable.get::<_, String>(0), "attempt_uncertain");
    assert_eq!(durable.get::<_, serde_json::Value>(1), marked.detail);
    let audit: serde_json::Value = durable.get(2);
    assert_eq!(audit["event"], "casework.attempt_uncertain");
    assert_eq!(audit["itemRevision"], after.revision);
    assert_eq!(audit["profileId"], "system:operator");
    assert!(audit["actor"].is_null());

    // The executor that held the lapsed lease can no longer finish the attempt.
    let receipt = SourceReceipt {
        source_revision: "2".to_owned(),
        resulting_state: "approved".to_owned(),
        binding: after.binding.clone(),
        actor_reference: None,
        metadata: BTreeMap::new(),
    };
    assert!(matches!(
        fixture
            .store
            .complete_attempt(
                &fixture.holder,
                fixture.attempt_id,
                fixture.execution_token,
                &receipt
            )
            .await,
        Err(StoreError::AttemptPending)
    ));

    // The attempt is now one the operator can settle.
    fixture
        .store
        .settle_attempt(&fixture.settlement(AttemptSettlementOutcome::NotApplied))
        .await
        .expect("the uncertain attempt settles");
}

#[tokio::test]
async fn an_unexpired_lease_refuses_marking_uncertain_and_writes_nothing() {
    let fixture = settlement_fixture("mark_live_lease", false).await;
    let before = fixture.snapshot().await;
    assert!(matches!(
        fixture
            .store
            .preview_attempt_uncertain_marking(&fixture.marking())
            .await,
        Err(AttemptSettlementError::LeaseLive)
    ));
    assert!(matches!(
        fixture
            .store
            .mark_expired_attempt_uncertain(&fixture.marking())
            .await,
        Err(AttemptSettlementError::LeaseLive)
    ));
    assert_eq!(fixture.snapshot().await, before);
}

#[tokio::test]
async fn only_a_pending_attempt_can_be_marked_uncertain() {
    let uncertain = settlement_fixture("mark_uncertain_twice", true).await;
    let before = uncertain.snapshot().await;
    for result in [
        uncertain
            .store
            .preview_attempt_uncertain_marking(&uncertain.marking())
            .await,
        uncertain
            .store
            .mark_expired_attempt_uncertain(&uncertain.marking())
            .await,
    ] {
        assert!(matches!(
            result,
            Err(AttemptSettlementError::NotPending("uncertain"))
        ));
    }
    assert_eq!(uncertain.snapshot().await, before);

    uncertain
        .store
        .settle_attempt(&uncertain.settlement(AttemptSettlementOutcome::Applied))
        .await
        .expect("settlement");
    let before = uncertain.snapshot().await;
    assert!(matches!(
        uncertain
            .store
            .mark_expired_attempt_uncertain(&uncertain.marking())
            .await,
        Err(AttemptSettlementError::NotPending("completed"))
    ));
    assert_eq!(uncertain.snapshot().await, before);

    let unknown = AttemptUncertainMarking {
        attempt_id: uuid::Uuid::new_v4(),
        ..uncertain.marking()
    };
    assert!(matches!(
        uncertain
            .store
            .mark_expired_attempt_uncertain(&unknown)
            .await,
        Err(AttemptSettlementError::NotFound)
    ));
    assert!(matches!(
        uncertain
            .store
            .preview_attempt_uncertain_marking(&unknown)
            .await,
        Err(AttemptSettlementError::NotFound)
    ));
}

#[tokio::test]
async fn an_uncertainty_marking_preview_names_both_parties_and_writes_nothing() {
    let fixture = settlement_fixture("mark_preview", false).await;
    fixture.lapse_execution_lease().await;
    let before = fixture.snapshot().await;
    let preview = fixture
        .store
        .preview_attempt_uncertain_marking(&fixture.marking())
        .await
        .expect("preview");
    assert!(!preview.applied);
    assert_eq!(preview.original_actor, fixture.holder.principal);
    assert_eq!(preview.original_profile_id, "staff");
    assert_eq!(preview.decided_by, SETTLEMENT_DECIDED_BY);
    assert_eq!(preview.attempt_state, AttemptState::Uncertain);
    assert_eq!(preview.item_state, OccurrenceState::Synchronizing);
    assert_eq!(fixture.snapshot().await, before);
}

#[tokio::test]
async fn an_uncertainty_marking_needs_a_bounded_reason_and_decider() {
    let fixture = settlement_fixture("mark_bounds", false).await;
    fixture.lapse_execution_lease().await;
    let before = fixture.snapshot().await;
    let base = fixture.marking();
    for (marking, field) in [
        (
            AttemptUncertainMarking {
                reason: "   ".to_owned(),
                ..base.clone()
            },
            "reason",
        ),
        (
            AttemptUncertainMarking {
                reason: "x".repeat(2_001),
                ..base.clone()
            },
            "reason",
        ),
        (
            AttemptUncertainMarking {
                decided_by: "duty\nofficer".to_owned(),
                ..base.clone()
            },
            "decided-by",
        ),
        (
            AttemptUncertainMarking {
                decided_by: "x".repeat(257),
                ..base.clone()
            },
            "decided-by",
        ),
    ] {
        for result in [
            fixture
                .store
                .preview_attempt_uncertain_marking(&marking)
                .await,
            fixture.store.mark_expired_attempt_uncertain(&marking).await,
        ] {
            match result {
                Err(AttemptSettlementError::Invalid { field: refused, .. }) => {
                    assert_eq!(refused, field);
                }
                other => panic!("expected an invalid {field}, got {other:?}"),
            }
        }
    }
    assert_eq!(fixture.snapshot().await, before);
}

/// The HTTP recover route is the only non-operator path out of a pending
/// attempt, and it stays bound to the actor who started the attempt.
#[tokio::test]
async fn no_caller_but_the_original_actor_can_recover_an_expired_pending_attempt() {
    let fixture = settlement_fixture("mark_recovery_binding", false).await;
    fixture.lapse_execution_lease().await;
    let before = fixture.snapshot().await;
    for caller in [
        actor("supervisor", CaseworkRole::Supervisor, "supervisor"),
        actor("officer-2", CaseworkRole::Staff, "staff"),
        actor("admin", CaseworkRole::Administrator, "administrator"),
        actor("officer-1", CaseworkRole::Supervisor, "supervisor"),
    ] {
        assert!(matches!(
            fixture
                .store
                .acquire_recovery_execution(&caller, fixture.attempt_id)
                .await,
            Err(StoreError::AttemptPending)
        ));
    }
    assert_eq!(fixture.snapshot().await, before);
}
