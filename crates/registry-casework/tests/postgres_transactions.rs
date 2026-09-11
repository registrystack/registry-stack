use std::collections::BTreeMap;
use std::env;
use std::sync::Arc;

use registry_casework::{AttemptSettlementError, DatabaseConfig, PostgresStore, StoreError};
use registry_casework_core::{
    ActorContext, AttemptSettlement, AttemptSettlementOutcome, AttemptState,
    AuthoritativeObservation, BootstrapDirectoryRequest, CaseworkRole, HistoryKind,
    IssuerPrincipal, OccurrenceKind, OccurrenceState, OperationName, PreparedSourceAttempt,
    RecoveryEvidence, SourceBinding, SourceReceipt, SubjectRef, TransitionHint,
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
    assert_eq!(applied, (1..=11).collect::<Vec<i64>>());
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
async fn readiness_rejects_a_partial_schema_missing_hosted_tables() {
    let (store, client, _schema) = isolated_schema("ready_partial").await;
    store
        .migrate()
        .await
        .expect("migrate before simulating drift");
    client
        .batch_execute(
            "DROP TABLE casework_hosted_notes; \
             DELETE FROM casework_schema_migrations WHERE version = 2;",
        )
        .await
        .expect("simulate a partial schema without the hosted migration");

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

    assert!(
        matches!(store.ready().await, Err(StoreError::Corrupt)),
        "an unsupported migration version must fail readiness"
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

const SETTLEMENT_REASON: &str =
    "The source refused the saved evidence version; the registrar confirmed no change was made.";
const SETTLEMENT_DECIDED_BY: &str = "Registrar duty officer, ticket OPS-4411";

/// One claimed item whose only attempt is left live by its executor, the way
/// a saved-evidence version the binary refuses leaves it.
struct SettlementFixture {
    store: PostgresStore,
    client: tokio_postgres::Client,
    holder: ActorContext,
    item_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
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
