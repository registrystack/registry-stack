use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use registry_casework_core::{
    transition, ActorContext, AssignmentContext, AttemptState, AttemptStatus,
    AuthoritativeObservation, BootstrapDirectoryRequest, CaseworkRole, CorrectionRoutingCopy,
    Draft, DurableEvent, HistoryEntry, HistoryKind, InboxView, IssuerPrincipal, OccurrenceEvent,
    OccurrenceKind, OccurrenceState, OperationName, Page, PageStatus, PreparedSourceAttempt,
    SourceBinding, SourceReceipt, StaffingDiagnostic, SubjectRef, TeamRecord, TransitionHint,
    WorkItem, WorkItemRouting,
};
use registry_platform_config::SecretResolver;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_postgres::{Config as PgConfig, Row};
use uuid::Uuid;

use crate::DatabaseConfig;

const MIGRATION: &str = include_str!("../migrations/0001_casework.sql");
const HOSTED_MIGRATION: &str = include_str!("../migrations/0002_hosted_casework.sql");
const ASSIGNMENT_MIGRATION: &str = include_str!("../migrations/0003_assignment.sql");
const CLOCK_MIGRATION: &str = include_str!("../migrations/0004_clocks.sql");
const SOURCE_RETENTION_MIGRATION: &str = include_str!("../migrations/0005_source_retention.sql");
const SOURCE_HISTORY_MIGRATION: &str = include_str!("../migrations/0006_source_history.sql");

#[derive(Clone)]
pub struct PostgresStore {
    pool: Pool,
}

impl std::fmt::Debug for PostgresStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresStore")
            .finish_non_exhaustive()
    }
}

impl PostgresStore {
    pub fn connect_runtime(
        config: &DatabaseConfig,
        secrets: &SecretResolver,
    ) -> Result<Self, StoreError> {
        Self::connect_reference(config, secrets, &config.runtime_url_ref)
    }

    pub fn connect_migration(
        config: &DatabaseConfig,
        secrets: &SecretResolver,
    ) -> Result<Self, StoreError> {
        Self::connect_reference(config, secrets, &config.migration_url_ref)
    }

    fn connect_reference(
        config: &DatabaseConfig,
        secrets: &SecretResolver,
        reference: &str,
    ) -> Result<Self, StoreError> {
        let protected = secrets
            .resolve(reference)
            .map_err(|_| StoreError::Configuration)?;
        let url = std::str::from_utf8(protected.expose_secret())
            .map_err(|_| StoreError::Configuration)?;
        let mut postgres = PgConfig::from_str(url).map_err(|_| StoreError::Configuration)?;
        if postgres.get_user().is_none() || postgres.get_dbname().is_none() {
            return Err(StoreError::Configuration);
        }
        let manager_config = ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        };
        #[cfg(feature = "postgres-test")]
        let manager = if config.test_only_plaintext {
            postgres.ssl_mode(tokio_postgres::config::SslMode::Disable);
            Manager::from_config(postgres, tokio_postgres::NoTls, manager_config)
        } else {
            postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
            let connector = tls_connector(config, secrets)?;
            Manager::from_config(postgres, connector, manager_config)
        };
        #[cfg(not(feature = "postgres-test"))]
        let manager = {
            if config.test_only_plaintext {
                return Err(StoreError::Configuration);
            }
            postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
            let connector = tls_connector(config, secrets)?;
            Manager::from_config(postgres, connector, manager_config)
        };
        let pool = Pool::builder(manager)
            .max_size(32)
            .wait_timeout(Some(Duration::from_secs(5)))
            .create_timeout(Some(Duration::from_secs(5)))
            .recycle_timeout(Some(Duration::from_secs(5)))
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|_| StoreError::Configuration)?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        // The checkpoint schema predates a migration ledger. Apply its
        // idempotent migration once more, then establish the forward-only
        // ledger in the same transaction before adding hosted storage.
        let transaction = client.transaction().await?;
        transaction.batch_execute(MIGRATION).await?;
        transaction
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS casework_schema_migrations (\
                 version bigint PRIMARY KEY CHECK (version > 0),\
                 applied_at timestamptz NOT NULL);",
            )
            .await?;
        transaction
            .execute(
                "INSERT INTO casework_schema_migrations(version,applied_at) VALUES(1,now()) ON CONFLICT(version) DO NOTHING",
                &[],
            )
            .await?;
        transaction.commit().await?;

        let transaction = client.transaction().await?;
        let hosted_applied: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM casework_schema_migrations WHERE version=2)",
                &[],
            )
            .await?
            .get(0);
        if !hosted_applied {
            transaction.batch_execute(HOSTED_MIGRATION).await?;
            transaction
                .execute(
                    "INSERT INTO casework_schema_migrations(version,applied_at) VALUES(2,now())",
                    &[],
                )
                .await?;
        }
        transaction.commit().await?;

        let transaction = client.transaction().await?;
        let assignment_applied: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM casework_schema_migrations WHERE version=3)",
                &[],
            )
            .await?
            .get(0);
        if !assignment_applied {
            transaction.batch_execute(ASSIGNMENT_MIGRATION).await?;
            transaction
                .execute(
                    "INSERT INTO casework_schema_migrations(version,applied_at) VALUES(3,now())",
                    &[],
                )
                .await?;
        }
        transaction.commit().await?;

        let transaction = client.transaction().await?;
        let clocks_applied: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM casework_schema_migrations WHERE version=4)",
                &[],
            )
            .await?
            .get(0);
        if !clocks_applied {
            transaction.batch_execute(CLOCK_MIGRATION).await?;
            transaction
                .execute(
                    "INSERT INTO casework_schema_migrations(version,applied_at) VALUES(4,now())",
                    &[],
                )
                .await?;
        }
        transaction.commit().await?;

        let transaction = client.transaction().await?;
        let source_retention_applied: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM casework_schema_migrations WHERE version=5)",
                &[],
            )
            .await?
            .get(0);
        if !source_retention_applied {
            transaction
                .batch_execute(SOURCE_RETENTION_MIGRATION)
                .await?;
            transaction
                .execute(
                    "INSERT INTO casework_schema_migrations(version,applied_at) VALUES(5,now())",
                    &[],
                )
                .await?;
        }
        transaction.commit().await?;

        let transaction = client.transaction().await?;
        let source_history_applied: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM casework_schema_migrations WHERE version=6)",
                &[],
            )
            .await?
            .get(0);
        if !source_history_applied {
            transaction.batch_execute(SOURCE_HISTORY_MIGRATION).await?;
            transaction
                .execute(
                    "INSERT INTO casework_schema_migrations(version,applied_at) VALUES(6,now())",
                    &[],
                )
                .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn ready(&self) -> Result<(), StoreError> {
        self.client().await?.simple_query("SELECT 1").await?;
        Ok(())
    }

    pub async fn directory_ready(&self) -> Result<bool, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM casework_queue_service q JOIN casework_teams t ON t.team_id=q.team_id)",
                &[],
            )
            .await?
            .get(0))
    }

    pub(crate) async fn client(&self) -> Result<deadpool_postgres::Client, StoreError> {
        self.pool.get().await.map_err(|_| StoreError::Unavailable)
    }

    pub async fn bootstrap_directory(
        &self,
        actor: &ActorContext,
        expected_revision: i64,
        request: &BootstrapDirectoryRequest,
        idempotency_key: &str,
    ) -> Result<i64, StoreError> {
        if actor.role != CaseworkRole::Administrator {
            return Err(StoreError::Forbidden);
        }
        let request_hash = request_hash(request)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        if let Some(response) = idempotent_response(
            &transaction,
            actor,
            "directory.bootstrap",
            "directory",
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            return response
                .get("revision")
                .and_then(Value::as_i64)
                .ok_or(StoreError::Corrupt);
        }
        let actual: i64 = transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton = true FOR UPDATE",
                &[],
            )
            .await?
            .get(0);
        if actual != expected_revision {
            return Err(StoreError::Conflict);
        }
        let next = actual.checked_add(1).ok_or(StoreError::Corrupt)?;
        transaction
            .execute(
                "INSERT INTO casework_teams(team_id, revision) VALUES ($1,$2)",
                &[&request.team_id, &next],
            )
            .await
            .map_err(map_unique_conflict)?;
        for principal in &request.staff {
            insert_membership(&transaction, &request.team_id, principal, "staff").await?;
        }
        for principal in &request.supervisors {
            insert_membership(&transaction, &request.team_id, principal, "supervisor").await?;
        }
        transaction
            .execute(
                "INSERT INTO casework_queue_service(queue_id, team_id, revision) VALUES ($1,$2,$3)",
                &[&request.queue_id, &request.team_id, &next],
            )
            .await
            .map_err(map_unique_conflict)?;
        transaction
            .execute(
                "UPDATE casework_meta SET directory_revision=$1 WHERE singleton=true",
                &[&next],
            )
            .await?;
        let event_id = Uuid::new_v4();
        let now = Utc::now();
        let detail = json!({"teamId":request.team_id,"queueId":request.queue_id});
        transaction.execute(
            "INSERT INTO casework_directory_events(event_id,directory_revision,event_kind,occurred_at,actor_issuer,actor_subject,profile_id,detail) VALUES($1,$2,'directory_bootstrapped',$3,$4,$5,$6,$7)",
            &[&event_id,&next,&now,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&detail],
        ).await?;
        insert_audit_outbox(
            &transaction,
            event_id,
            json!({
                "event":"casework.directory_bootstrapped","directoryRevision":next,
                "actor":{"issuer":actor.principal.issuer,"subject":actor.principal.subject},
                "profileId":actor.profile_id,"teamId":request.team_id,"queueId":request.queue_id
            }),
        )
        .await?;
        let response = json!({"revision":next});
        insert_idempotency(
            &transaction,
            actor,
            "directory.bootstrap",
            "directory",
            idempotency_key,
            &request_hash,
            &response,
        )
        .await?;
        transaction.commit().await?;
        Ok(next)
    }

    pub async fn directory(
        &self,
        actor: &ActorContext,
    ) -> Result<(i64, Vec<TeamRecord>), StoreError> {
        if actor.role != CaseworkRole::Administrator {
            return Err(StoreError::Forbidden);
        }
        let client = self.client().await?;
        let revision: i64 = client
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true",
                &[],
            )
            .await?
            .get(0);
        let rows = client
            .query(
                "SELECT team_id, revision FROM casework_teams ORDER BY team_id",
                &[],
            )
            .await?;
        let mut teams = Vec::with_capacity(rows.len());
        for row in rows {
            let team_id: String = row.get(0);
            let members = membership_list(&client, &team_id, "staff").await?;
            let supervisors = membership_list(&client, &team_id, "supervisor").await?;
            let served_queues = client.query(
                "SELECT queue_id FROM casework_queue_service WHERE team_id=$1 ORDER BY queue_id", &[&team_id]
            ).await?.into_iter().map(|row| row.get(0)).collect();
            teams.push(TeamRecord {
                id: team_id,
                members,
                supervisors,
                served_queues,
                revision: row.get(1),
            });
        }
        Ok((revision, teams))
    }

    /// Deduplicate a verified transition and raise the wanted revision atomically.
    pub async fn ingest_transition(
        &self,
        generation: &str,
        hint: &TransitionHint,
    ) -> Result<bool, StoreError> {
        if hint.ordered_revision <= 0 {
            return Err(StoreError::Invalid);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let erased = transaction
            .query_opt(
                "SELECT erased_at FROM casework_subjects WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3 FOR UPDATE",
                &[&hint.subject.source_id, &hint.subject.kind, &hint.subject.id],
            )
            .await?
            .is_some_and(|row| row.get::<_, Option<DateTime<Utc>>>(0).is_some());
        if erased {
            transaction.commit().await?;
            return Ok(false);
        }
        let inserted = transaction.execute(
            "INSERT INTO casework_source_events(source_id,deduplication_key,subject_kind,subject_id,ordered_revision,received_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
            &[&hint.subject.source_id,&hint.deduplication_key,&hint.subject.kind,&hint.subject.id,&hint.ordered_revision,&Utc::now()]
        ).await? == 1;
        if inserted {
            transaction.execute(
                "INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending) VALUES($1,$2,$3,$4,$5,0,true,true) ON CONFLICT(source_id,subject_kind,subject_id) DO UPDATE SET wanted_revision=GREATEST(casework_subjects.wanted_revision,EXCLUDED.wanted_revision), sync_pending=true WHERE casework_subjects.binding_generation=EXCLUDED.binding_generation AND casework_subjects.erased_at IS NULL",
                &[&hint.subject.source_id,&hint.subject.kind,&hint.subject.id,&generation,&hint.ordered_revision]
            ).await?;
        }
        transaction.commit().await?;
        Ok(inserted)
    }

    pub async fn apply_observation(
        &self,
        observation: &AuthoritativeObservation,
        queue_id: &str,
        passive_target_seconds: Option<i64>,
    ) -> Result<Option<WorkItem>, StoreError> {
        self.apply_observation_with_context(
            observation,
            queue_id,
            passive_target_seconds,
            None,
            None,
        )
        .await
    }

    pub(crate) async fn apply_observation_with_context(
        &self,
        observation: &AuthoritativeObservation,
        queue_id: &str,
        passive_target_seconds: Option<i64>,
        routing: Option<&registry_casework_core::RoutingDecision>,
        clock: Option<&crate::ResolvedClockPolicy>,
    ) -> Result<Option<WorkItem>, StoreError> {
        self.apply_observation_with_policy_context(
            observation,
            queue_id,
            passive_target_seconds,
            routing,
            None,
            clock,
        )
        .await
    }

    pub(crate) async fn apply_observation_with_policy_context(
        &self,
        observation: &AuthoritativeObservation,
        queue_id: &str,
        passive_target_seconds: Option<i64>,
        routing: Option<&registry_casework_core::RoutingDecision>,
        routing_policy_digest: Option<&str>,
        clock: Option<&crate::ResolvedClockPolicy>,
    ) -> Result<Option<WorkItem>, StoreError> {
        if observation.ordered_revision <= 0
            || passive_target_seconds.is_some_and(|seconds| seconds <= 0)
            || observation.occurrence_key.is_empty()
            || observation.occurrence_key.len() > 512
            || observation.occurrence_key.chars().any(char::is_control)
        {
            return Err(StoreError::Invalid);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction.execute(
            "INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending) VALUES($1,$2,$3,$4,$5,0,true,true) ON CONFLICT(source_id,subject_kind,subject_id) DO NOTHING",
            &[&observation.subject.source_id,&observation.subject.kind,&observation.subject.id,&observation.binding.generation,&observation.ordered_revision]
        ).await?;
        let subject_row = transaction.query_opt(
            "SELECT binding_generation,wanted_revision,applied_revision,representation_etag,erased_at FROM casework_subjects WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3 FOR UPDATE",
            &[&observation.subject.source_id,&observation.subject.kind,&observation.subject.id]
        ).await?;
        let (generation, _wanted, applied, applied_representation_etag, erased): (
            String,
            i64,
            i64,
            Option<String>,
            bool,
        ) = if let Some(row) = subject_row {
            (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get::<_, Option<DateTime<Utc>>>(4).is_some(),
            )
        } else {
            return Err(StoreError::Corrupt);
        };
        if erased {
            transaction.commit().await?;
            return Ok(None);
        }
        if generation != observation.binding.generation {
            return Err(StoreError::StaleGeneration);
        }
        if observation.ordered_revision < applied {
            transaction.commit().await?;
            return Ok(None);
        }
        // A source observation must never advance the local reducer past an
        // execution whose outcome is still unknown. Leave the subject queued
        // so reconciliation retries after that exact attempt is recovered.
        let has_live_attempt: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM casework_attempts a JOIN casework_items i ON i.item_id=a.item_id WHERE i.source_id=$1 AND i.subject_kind=$2 AND i.subject_id=$3 AND a.state IN ('pending','uncertain'))",
                &[&observation.subject.source_id, &observation.subject.kind, &observation.subject.id],
            )
            .await?
            .get(0);
        if has_live_attempt {
            transaction.execute(
                "UPDATE casework_subjects SET sync_pending=true,sync_lease_until=NULL WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3",
                &[&observation.subject.source_id, &observation.subject.kind, &observation.subject.id],
            ).await?;
            transaction.commit().await?;
            return Ok(None);
        }
        if observation.ordered_revision == applied
            && applied_representation_etag.as_deref()
                == Some(observation.representation_etag.as_str())
        {
            crate::reconcile_clock_observation(&transaction, observation, clock, Utc::now())
                .await?;
            transaction.execute(
                "UPDATE casework_subjects SET sync_pending=(wanted_revision>$4),sync_lease_until=NULL WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3",
                &[&observation.subject.source_id,&observation.subject.kind,&observation.subject.id,&observation.ordered_revision]
            ).await?;
            transaction.commit().await?;
            return Ok(None);
        }

        let active_rows = transaction.query(
            "SELECT * FROM casework_items WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3 AND state NOT IN ('completed','superseded','cancelled') ORDER BY first_observed_at FOR UPDATE",
            &[&observation.subject.source_id,&observation.subject.kind,&observation.subject.id]
        ).await?;
        let now = Utc::now();
        let mut result = None;
        let terminal = matches!(
            observation.state,
            OccurrenceState::Completed | OccurrenceState::Cancelled
        );
        if terminal {
            for row in active_rows {
                let item = row_to_item(&row)?;
                let event = if observation.state == OccurrenceState::Cancelled {
                    OccurrenceEvent::Cancel
                } else {
                    OccurrenceEvent::Complete
                };
                result =
                    Some(update_observed_item(&transaction, &item, event, observation, now).await?);
            }
        } else {
            let matching = active_rows.iter().find_map(|row| {
                let item = row_to_item(row).ok()?;
                (item.occurrence_kind == observation.occurrence_kind
                    && row.get::<_, String>("occurrence_key") == observation.occurrence_key)
                    .then_some(item)
            });
            for row in &active_rows {
                let item = row_to_item(row)?;
                let is_match = matching
                    .as_ref()
                    .is_some_and(|current| current.item_id == item.item_id);
                if item.binding.generation != observation.binding.generation {
                    update_observed_item(
                        &transaction,
                        &item,
                        OccurrenceEvent::Supersede,
                        observation,
                        now,
                    )
                    .await?;
                } else if observation.occurrence_kind == OccurrenceKind::Application
                    && item.occurrence_kind == OccurrenceKind::Review
                {
                    update_observed_item(
                        &transaction,
                        &item,
                        OccurrenceEvent::Complete,
                        observation,
                        now,
                    )
                    .await?;
                } else if !is_match && item.occurrence_kind == OccurrenceKind::Review {
                    update_observed_item(
                        &transaction,
                        &item,
                        OccurrenceEvent::Supersede,
                        observation,
                        now,
                    )
                    .await?;
                }
            }
            if let Some(item) = matching {
                result = Some(
                    update_observed_item(
                        &transaction,
                        &item,
                        observation_event(observation.state)?,
                        observation,
                        now,
                    )
                    .await?,
                );
            } else if !matches!(
                observation.state,
                OccurrenceState::Synchronizing | OccurrenceState::Superseded
            ) {
                let item_id = Uuid::new_v4();
                let due = if observation.occurrence_kind == OccurrenceKind::Review {
                    passive_target_seconds.map(|seconds| now + TimeDelta::seconds(seconds))
                } else {
                    None
                };
                let binding = serde_json::to_value(&observation.binding)?;
                let binding_reference =
                    binding_reference(&observation.subject, &observation.binding)?;
                transaction.execute(
                    "INSERT INTO casework_items(item_id,source_id,subject_kind,subject_id,occurrence_kind,occurrence_key,stage,binding,state,queue_id,revision,first_observed_at,passive_due_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,$12,$11)",
                    &[&item_id,&observation.subject.source_id,&observation.subject.kind,&observation.subject.id,&occurrence_kind_name(observation.occurrence_kind),&observation.occurrence_key,&observation.stage,&binding,&state_name(observation.state),&queue_id,&now,&due]
                ).await?;
                let item = WorkItem {
                    item_id,
                    subject: observation.subject.clone(),
                    occurrence_kind: observation.occurrence_kind,
                    stage: observation.stage.clone(),
                    binding: observation.binding.clone(),
                    binding_reference,
                    state: observation.state,
                    queue_id: queue_id.to_owned(),
                    holder: None,
                    held_since: None,
                    assignment: None,
                    revision: 1,
                    first_observed_at: now,
                    passive_due_at: due,
                    updated_at: now,
                    hosted: None,
                    routing: None,
                    clock_occurrences: Vec::new(),
                    actions: Vec::new(),
                    routing_copy: None,
                    live_attempt: None,
                };
                if observation.occurrence_kind == OccurrenceKind::Review {
                    transaction.execute("INSERT INTO casework_correction_context(item_id,source_binding,reason,flagged_fields,created_at) SELECT $1,c.source_binding,c.reason,c.flagged_fields,c.created_at FROM casework_correction_context c JOIN casework_items prior ON prior.item_id=c.item_id WHERE prior.source_id=$2 AND prior.subject_kind=$3 AND prior.subject_id=$4 ORDER BY c.created_at DESC LIMIT 1 ON CONFLICT(item_id) DO NOTHING", &[&item_id,&observation.subject.source_id,&observation.subject.kind,&observation.subject.id]).await?;
                }
                let mut observed_detail = json!({
                    "sourceRevision": observation.ordered_revision,
                    "routingRule": routing.and_then(|decision| decision.rule_id.as_deref()),
                    "routingBecause": routing.and_then(|decision| decision.because.as_deref()),
                });
                if let Some(digest) = routing_policy_digest {
                    observed_detail["routingPolicyDigest"] = Value::String(digest.to_owned());
                }
                append_item_event(
                    &transaction,
                    &item,
                    HistoryKind::Observed,
                    None,
                    "system:reconciliation",
                    observed_detail,
                )
                .await?;
                result = Some(item);
            }
        }
        crate::reconcile_clock_observation(&transaction, observation, clock, now).await?;
        transaction.execute(
            "UPDATE casework_subjects SET applied_revision=$4,wanted_revision=GREATEST(wanted_revision,$4),sync_pending=(wanted_revision>$4),sync_lease_until=NULL,active=$5,representation_etag=$6 WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3",
            &[&observation.subject.source_id,&observation.subject.kind,&observation.subject.id,&observation.ordered_revision,&(!terminal),&observation.representation_etag]
        ).await?;
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn claim(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<WorkItem, StoreError> {
        self.change_holder(actor, item_id, expected_revision, idempotency_key, true)
            .await
    }

    pub async fn release(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<WorkItem, StoreError> {
        self.change_holder(actor, item_id, expected_revision, idempotency_key, false)
            .await
    }

    async fn change_holder(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        claim: bool,
    ) -> Result<WorkItem, StoreError> {
        let operation = if claim { "item.claim" } else { "item.release" };
        let resource = item_id.to_string();
        let request_hash = hash_bytes(format!("{item_id}:{expected_revision}:{claim}").as_bytes());
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT * FROM casework_items WHERE item_id=$1 FOR UPDATE",
                &[&item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let item = row_to_item(&row)?;
        let staff_authority = actor.role == CaseworkRole::Staff
            && is_staff_for_queue(&transaction, actor, &item.queue_id).await?;
        let supervisor_authority = !claim
            && actor.role == CaseworkRole::Supervisor
            && is_supervisor_for_queue(&transaction, actor, &item.queue_id).await?;
        if !staff_authority && (claim || !supervisor_authority) {
            return Err(StoreError::Forbidden);
        }
        if let Some(response) = idempotent_response(
            &transaction,
            actor,
            operation,
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            return serde_json::from_value(response).map_err(StoreError::Json);
        }
        if claim && item.holder.is_some() {
            return Err(StoreError::AlreadyClaimed);
        }
        if !claim
            && (item.holder.is_none()
                || (staff_authority && item.holder.as_ref() != Some(&actor.principal)))
        {
            return Err(StoreError::NotHolder);
        }
        if item.revision != expected_revision || !item.state.is_active() {
            return Err(StoreError::Conflict);
        }
        ensure_no_live_attempt(&transaction, item_id).await?;
        let holder_event = if claim {
            OccurrenceEvent::Claim
        } else {
            OccurrenceEvent::Release
        };
        let next_state = transition(item.state, holder_event).map_err(|_| StoreError::Conflict)?;
        let next_revision = item.revision.checked_add(1).ok_or(StoreError::Corrupt)?;
        let now = Utc::now();
        let holder = claim.then_some(&actor.principal);
        let previous_holder = item.holder.clone();
        transaction.execute(
            "UPDATE casework_items SET holder_issuer=$2,holder_subject=$3,state=$4,revision=$5,updated_at=$6,assignment_owner_issuer=$7,assignment_owner_subject=$8,assigned_by_issuer=NULL,assigned_by_subject=NULL,assignment_absence_ids='{}',staffing_diagnostic=NULL WHERE item_id=$1",
            &[&item_id,&holder.map(|p| &p.issuer),&holder.map(|p| &p.subject),&state_name(next_state),&next_revision,&now,&holder.map(|p| &p.issuer),&holder.map(|p| &p.subject)]
        ).await?;
        let mut updated = item;
        updated.holder = holder.cloned();
        updated.held_since = None;
        updated.assignment = holder.cloned().map(|owner| AssignmentContext {
            owner: Some(owner),
            assigned_by: None,
            absence_ids: Vec::new(),
            staffing_diagnostic: None,
        });
        updated.state = next_state;
        updated.revision = next_revision;
        updated.updated_at = now;
        let event_id = append_item_event(
            &transaction,
            &updated,
            if claim {
                HistoryKind::Claimed
            } else {
                HistoryKind::Released
            },
            Some(actor),
            &actor.profile_id,
            if claim {
                json!({})
            } else {
                json!({"previousHolder": previous_holder})
            },
        )
        .await?;
        if claim {
            updated.held_since = Some(
                transaction
                    .query_one(
                        "SELECT occurred_at FROM casework_history WHERE event_id=$1",
                        &[&event_id],
                    )
                    .await?
                    .get(0),
            );
        }
        let response = serde_json::to_value(&updated)?;
        insert_idempotency(
            &transaction,
            actor,
            operation,
            &resource,
            idempotency_key,
            &request_hash,
            &response,
        )
        .await?;
        transaction.commit().await?;
        Ok(updated)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn save_draft(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        binding: &SourceBinding,
        reason: &str,
        flagged_fields: &[String],
        idempotency_key: &str,
    ) -> Result<Draft, StoreError> {
        if reason.len() > 16_384 || flagged_fields.len() > 128 {
            return Err(StoreError::Invalid);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT * FROM casework_items WHERE item_id=$1 FOR UPDATE",
                &[&item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let mut item = row_to_item(&row)?;
        if item.holder.as_ref() != Some(&actor.principal) {
            return Err(StoreError::NotHolder);
        }
        if !is_staff_for_queue(&transaction, actor, &item.queue_id).await? {
            return Err(StoreError::Forbidden);
        }
        if &item.binding != binding {
            return Err(StoreError::Conflict);
        }
        let resource = item_id.to_string();
        let request_hash = hash_bytes(&serde_json::to_vec(&(
            expected_revision,
            binding,
            reason,
            flagged_fields,
        ))?);
        if let Some(response) = idempotent_response(
            &transaction,
            actor,
            "draft.save",
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            return serde_json::from_value(response).map_err(StoreError::Json);
        }
        if item.revision != expected_revision {
            return Err(StoreError::Conflict);
        }
        ensure_no_live_attempt(&transaction, item_id).await?;
        let existing=transaction.query_opt("SELECT revision FROM casework_drafts WHERE item_id=$1 AND author_issuer=$2 AND author_subject=$3 FOR UPDATE", &[&item_id,&actor.principal.issuer,&actor.principal.subject]).await?;
        let draft_revision = existing.map_or(1_i64, |row| row.get::<_, i64>(0) + 1);
        let next = item.revision + 1;
        let now = Utc::now();
        let binding_json = serde_json::to_value(binding)?;
        let fields_json = serde_json::to_value(flagged_fields)?;
        transaction.execute(
            "INSERT INTO casework_drafts(item_id,author_issuer,author_subject,binding,reason,flagged_fields,revision,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(item_id,author_issuer,author_subject) DO UPDATE SET binding=EXCLUDED.binding,reason=EXCLUDED.reason,flagged_fields=EXCLUDED.flagged_fields,revision=EXCLUDED.revision,updated_at=EXCLUDED.updated_at",
            &[&item_id,&actor.principal.issuer,&actor.principal.subject,&binding_json,&reason,&fields_json,&draft_revision,&now]
        ).await?;
        transaction
            .execute(
                "UPDATE casework_items SET revision=$2,updated_at=$3 WHERE item_id=$1",
                &[&item_id, &next, &now],
            )
            .await?;
        item.revision = next;
        item.updated_at = now;
        append_item_event(
            &transaction,
            &item,
            HistoryKind::DraftSaved,
            Some(actor),
            &actor.profile_id,
            json!({"draftRevision":draft_revision}),
        )
        .await?;
        let draft = Draft {
            item_id,
            author: actor.principal.clone(),
            binding: binding.clone(),
            reason: reason.to_owned(),
            flagged_fields: flagged_fields.to_vec(),
            revision: draft_revision,
            updated_at: now,
        };
        let response = serde_json::to_value(&draft)?;
        insert_idempotency(
            &transaction,
            actor,
            "draft.save",
            &resource,
            idempotency_key,
            &request_hash,
            &response,
        )
        .await?;
        transaction.commit().await?;
        Ok(draft)
    }

    pub async fn read_draft(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
    ) -> Result<Option<Draft>, StoreError> {
        let client = self.client().await?;
        let row=client.query_opt("SELECT binding,reason,flagged_fields,revision,updated_at FROM casework_drafts WHERE item_id=$1 AND author_issuer=$2 AND author_subject=$3", &[&item_id,&actor.principal.issuer,&actor.principal.subject]).await?;
        row.map(|row| {
            Ok(Draft {
                item_id,
                author: actor.principal.clone(),
                binding: serde_json::from_value(row.get(0))?,
                reason: row.get(1),
                flagged_fields: serde_json::from_value(row.get(2))?,
                revision: row.get(3),
                updated_at: row.get(4),
            })
        })
        .transpose()
    }

    pub async fn delete_draft(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<bool, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT * FROM casework_items WHERE item_id=$1 FOR UPDATE",
                &[&item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let mut item = row_to_item(&row)?;
        if item.holder.as_ref() != Some(&actor.principal) {
            return Err(StoreError::NotHolder);
        }
        if !is_staff_for_queue(&transaction, actor, &item.queue_id).await? {
            return Err(StoreError::Forbidden);
        }
        let resource = item_id.to_string();
        let request_hash =
            hash_bytes(format!("{item_id}:{expected_revision}:draft.delete").as_bytes());
        if idempotent_response(
            &transaction,
            actor,
            "draft.delete",
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        .is_some()
        {
            return Ok(true);
        }
        if item.revision != expected_revision {
            return Err(StoreError::Conflict);
        }
        ensure_no_live_attempt(&transaction, item_id).await?;
        let deleted=transaction.execute("DELETE FROM casework_drafts WHERE item_id=$1 AND author_issuer=$2 AND author_subject=$3", &[&item_id,&actor.principal.issuer,&actor.principal.subject]).await?==1;
        if !deleted {
            return Err(StoreError::NotFound);
        }
        item.revision += 1;
        item.updated_at = Utc::now();
        transaction
            .execute(
                "UPDATE casework_items SET revision=$2,updated_at=$3 WHERE item_id=$1",
                &[&item_id, &item.revision, &item.updated_at],
            )
            .await?;
        append_item_event(
            &transaction,
            &item,
            HistoryKind::DraftSaved,
            Some(actor),
            &actor.profile_id,
            json!({"deleted":true}),
        )
        .await?;
        insert_idempotency(
            &transaction,
            actor,
            "draft.delete",
            &resource,
            idempotency_key,
            &request_hash,
            &json!({"deleted":true}),
        )
        .await?;
        transaction.commit().await?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn reserve_attempt(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        source_profile_id: &str,
        operation: OperationName,
        reason: Option<&str>,
        flagged_fields: &[String],
        idempotency_key: &str,
        request_hash: &str,
        prepared: &PreparedSourceAttempt,
    ) -> Result<AttemptStatus, StoreError> {
        self.reserve_attempt_for_execution(
            actor,
            item_id,
            expected_revision,
            source_profile_id,
            operation,
            reason,
            flagged_fields,
            idempotency_key,
            request_hash,
            prepared,
        )
        .await
        .map(|(attempt, _)| attempt)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn reserve_attempt_for_execution(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        source_profile_id: &str,
        operation: OperationName,
        reason: Option<&str>,
        flagged_fields: &[String],
        idempotency_key: &str,
        request_hash: &str,
        prepared: &PreparedSourceAttempt,
    ) -> Result<(AttemptStatus, Uuid), StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT * FROM casework_items WHERE item_id=$1 FOR UPDATE",
                &[&item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let mut item = row_to_item(&row)?;
        if item.holder.as_ref() != Some(&actor.principal) {
            return Err(StoreError::NotHolder);
        }
        if !is_staff_for_queue(&transaction, actor, &item.queue_id).await? {
            return Err(StoreError::Forbidden);
        }
        if item.revision != expected_revision || item.binding != prepared.source_binding {
            return Err(StoreError::Conflict);
        }
        let reserved_state = transition(item.state, OccurrenceEvent::AttemptReserved)
            .map_err(|_| StoreError::Conflict)?;
        if let Some(existing) = transaction.query_opt(
            "SELECT attempt_id,state,item_revision,operation,created_at,receipt,actor_issuer,actor_subject,casework_profile_id,source_profile_id,displayed_binding,recovery_evidence FROM casework_attempts WHERE item_id=$1 AND idempotency_key=$2 FOR UPDATE",
            &[&item_id,&idempotency_key],
        ).await? {
            if existing.get::<_,String>(6)!=actor.principal.issuer
                || existing.get::<_,String>(7)!=actor.principal.subject
                || existing.get::<_,String>(8)!=actor.profile_id
                || existing.get::<_,String>(9)!=source_profile_id
                || existing.get::<_,Value>(10)!=serde_json::to_value(&prepared.source_binding)?
                || existing.get::<_,Vec<u8>>(11)!=prepared.recovery_evidence.as_bytes()
                || parse_operation(&existing.get::<_,String>(3))?!=operation
            { return Err(StoreError::IdempotencyConflict); }
            return Err(StoreError::AttemptPending);
        }
        ensure_no_live_attempt(&transaction, item_id).await?;
        let attempt_id = Uuid::new_v4();
        let execution_token = Uuid::new_v4();
        let now = Utc::now();
        let next = item.revision + 1;
        if flagged_fields.len() > 128
            || flagged_fields
                .iter()
                .any(|field| field.is_empty() || field.len() > 256)
        {
            return Err(StoreError::Invalid);
        }
        let binding = serde_json::to_value(&prepared.source_binding)?;
        let fields = serde_json::to_value(flagged_fields)?;
        transaction.execute(
            "INSERT INTO casework_attempts(attempt_id,item_id,actor_issuer,actor_subject,casework_profile_id,source_profile_id,item_revision,request_hash,operation,decision_reason,flagged_fields,idempotency_key,displayed_binding,recovery_evidence,state,execution_token,execution_lease_until,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'pending',$15,$16,$17,$17)",
            &[&attempt_id,&item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&source_profile_id,&expected_revision,&request_hash,&operation.as_str(),&reason,&fields,&idempotency_key,&binding,&prepared.recovery_evidence.as_bytes(),&execution_token,&(now+TimeDelta::seconds(330)),&now]
        ).await.map_err(map_unique_conflict)?;
        transaction
            .execute(
                "UPDATE casework_items SET revision=$2,state=$3,updated_at=$4 WHERE item_id=$1",
                &[&item_id, &next, &state_name(reserved_state), &now],
            )
            .await?;
        item.revision = next;
        item.state = reserved_state;
        item.updated_at = now;
        let mut history_detail = serde_json::Map::from_iter([
            ("attemptId".to_owned(), json!(attempt_id)),
            (
                "bindingReference".to_owned(),
                json!(binding_reference(&item.subject, &prepared.source_binding)?),
            ),
            ("operation".to_owned(), json!(operation.as_str())),
        ]);
        if let Some(reason) = reason {
            history_detail.insert("reason".to_owned(), json!(reason));
        }
        append_item_event(
            &transaction,
            &item,
            HistoryKind::AttemptReserved,
            Some(actor),
            &actor.profile_id,
            Value::Object(history_detail),
        )
        .await?;
        transaction.commit().await?;
        Ok((
            AttemptStatus {
                attempt_id,
                item_id,
                state: AttemptState::Pending,
                item_revision: next,
                operation,
                created_at: now,
                receipt: None,
            },
            execution_token,
        ))
    }

    pub async fn acquire_recovery_execution(
        &self,
        actor: &ActorContext,
        attempt_id: Uuid,
    ) -> Result<Uuid, StoreError> {
        let token = Uuid::new_v4();
        let client = self.client().await?;
        let row=client.query_opt("UPDATE casework_attempts SET execution_token=$2,execution_lease_until=now()+interval '330 seconds' WHERE attempt_id=$1 AND actor_issuer=$3 AND actor_subject=$4 AND casework_profile_id=$5 AND state IN ('pending','uncertain') AND execution_lease_until<=now() RETURNING execution_token", &[&attempt_id,&token,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id]).await?;
        row.map(|row| row.get(0)).ok_or(StoreError::AttemptPending)
    }

    pub async fn refuse_original_attempt(
        &self,
        actor: &ActorContext,
        attempt_id: Uuid,
        execution_token: Uuid,
    ) -> Result<AttemptStatus, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row=transaction.query_opt("SELECT attempt_id,item_id,actor_issuer,actor_subject,casework_profile_id,item_revision,operation,state,created_at,receipt,displayed_binding,decision_reason FROM casework_attempts WHERE attempt_id=$1 AND execution_token=$2 AND execution_lease_until>now() FOR UPDATE", &[&attempt_id,&execution_token]).await?.ok_or(StoreError::AttemptPending)?;
        if row.get::<_, String>(2) != actor.principal.issuer
            || row.get::<_, String>(3) != actor.principal.subject
            || row.get::<_, String>(4) != actor.profile_id
        {
            return Err(StoreError::Forbidden);
        }
        if !matches!(
            parse_attempt_state(&row.get::<_, String>(7))?,
            AttemptState::Pending | AttemptState::Uncertain
        ) {
            return Err(StoreError::AttemptPending);
        }
        let item_id: Uuid = row.get(1);
        let now = Utc::now();
        transaction
            .execute(
                "UPDATE casework_attempts SET state='refused',updated_at=$2 WHERE attempt_id=$1",
                &[&attempt_id, &now],
            )
            .await?;
        let item_row = transaction
            .query_one(
                "SELECT * FROM casework_items WHERE item_id=$1 FOR UPDATE",
                &[&item_id],
            )
            .await?;
        let mut item = row_to_item(&item_row)?;
        item.revision += 1;
        item.state = transition(item.state, OccurrenceEvent::AttemptRefused)
            .map_err(|_| StoreError::Corrupt)?;
        item.updated_at = now;
        transaction
            .execute(
                "UPDATE casework_items SET state=$2,revision=$3,updated_at=$4 WHERE item_id=$1",
                &[&item_id, &state_name(item.state), &item.revision, &now],
            )
            .await?;
        transaction
            .execute(
                "UPDATE casework_attempts SET item_revision=$2 WHERE attempt_id=$1",
                &[&attempt_id, &item.revision],
            )
            .await?;
        let mut history_detail = serde_json::Map::from_iter([
            ("attemptId".to_owned(), json!(attempt_id)),
            (
                "bindingReference".to_owned(),
                json!(binding_reference(
                    &item.subject,
                    &serde_json::from_value::<SourceBinding>(row.get(10))?,
                )?),
            ),
            ("definitivelyRefused".to_owned(), json!(true)),
            ("operation".to_owned(), json!(row.get::<_, String>(6))),
        ]);
        if let Some(reason) = row.get::<_, Option<String>>(11) {
            history_detail.insert("reason".to_owned(), json!(reason));
        }
        append_item_event(
            &transaction,
            &item,
            HistoryKind::AttemptUncertain,
            Some(actor),
            &actor.profile_id,
            Value::Object(history_detail),
        )
        .await?;
        transaction.commit().await?;
        Ok(AttemptStatus {
            attempt_id,
            item_id,
            state: AttemptState::Refused,
            item_revision: item.revision,
            operation: parse_operation(&row.get::<_, String>(6))?,
            created_at: row.get(8),
            receipt: None,
        })
    }

    /// Preserve an unresolved attempt for every recovery failure. Only a source
    /// receipt or a definitive result of the original execution can settle it.
    pub async fn mark_attempt_uncertain(
        &self,
        actor: &ActorContext,
        attempt_id: Uuid,
        execution_token: Uuid,
    ) -> Result<AttemptStatus, StoreError> {
        self.finish_attempt(
            actor,
            attempt_id,
            Some(execution_token),
            None,
            AttemptState::Uncertain,
        )
        .await
    }

    pub async fn complete_attempt(
        &self,
        actor: &ActorContext,
        attempt_id: Uuid,
        receipt: &SourceReceipt,
    ) -> Result<AttemptStatus, StoreError> {
        self.finish_attempt(
            actor,
            attempt_id,
            None,
            Some(receipt),
            AttemptState::Completed,
        )
        .await
    }

    async fn finish_attempt(
        &self,
        actor: &ActorContext,
        attempt_id: Uuid,
        execution_token: Option<Uuid>,
        receipt: Option<&SourceReceipt>,
        state: AttemptState,
    ) -> Result<AttemptStatus, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row=transaction.query_opt("SELECT attempt_id,item_id,actor_issuer,actor_subject,casework_profile_id,item_revision,operation,state,created_at,receipt,execution_token,decision_reason,flagged_fields,displayed_binding FROM casework_attempts WHERE attempt_id=$1 FOR UPDATE", &[&attempt_id]).await?.ok_or(StoreError::NotFound)?;
        let item_id: Uuid = row.get(1);
        if row.get::<_, String>(2) != actor.principal.issuer
            || row.get::<_, String>(3) != actor.principal.subject
            || row.get::<_, String>(4) != actor.profile_id
        {
            return Err(StoreError::Forbidden);
        }
        let old = parse_attempt_state(&row.get::<_, String>(7))?;
        if state != AttemptState::Completed && execution_token != Some(row.get::<_, Uuid>(10)) {
            return Err(StoreError::AttemptPending);
        }
        if old == AttemptState::Completed {
            return attempt_from_row(&row);
        }
        if old == AttemptState::Uncertain && state == AttemptState::Uncertain {
            transaction.execute("UPDATE casework_attempts SET execution_lease_until=now(),updated_at=now() WHERE attempt_id=$1", &[&attempt_id]).await?;
            let attempt = attempt_from_row(&row)?;
            transaction.commit().await?;
            return Ok(attempt);
        }
        if state == AttemptState::Completed && receipt.is_none() {
            return Err(StoreError::Invalid);
        }
        if let Some(receipt) = receipt {
            let revision = receipt
                .source_revision
                .parse::<i64>()
                .map_err(|_| StoreError::Invalid)?;
            if revision <= 0 || revision.to_string() != receipt.source_revision {
                return Err(StoreError::Invalid);
            }
        }
        let receipt_json = receipt.map(serde_json::to_value).transpose()?;
        let now = Utc::now();
        transaction.execute("UPDATE casework_attempts SET state=$2,receipt=$3,execution_lease_until=$4,updated_at=$4 WHERE attempt_id=$1", &[&attempt_id,&attempt_state_name(state),&receipt_json,&now]).await?;
        let item_row = transaction
            .query_one(
                "SELECT * FROM casework_items WHERE item_id=$1 FOR UPDATE",
                &[&item_id],
            )
            .await?;
        let mut item = row_to_item(&item_row)?;
        let next = item.revision + 1;
        let occurrence_event = match state {
            AttemptState::Completed => OccurrenceEvent::AttemptCompleted,
            AttemptState::Uncertain => OccurrenceEvent::AttemptUncertain,
            AttemptState::Pending | AttemptState::Refused => return Err(StoreError::Invalid),
        };
        item.state = transition(item.state, occurrence_event).map_err(|_| StoreError::Corrupt)?;
        transaction
            .execute(
                "UPDATE casework_items SET state=$2,revision=$3,updated_at=$4 WHERE item_id=$1",
                &[&item_id, &state_name(item.state), &next, &now],
            )
            .await?;
        item.revision = next;
        item.updated_at = now;
        transaction
            .execute(
                "UPDATE casework_attempts SET item_revision=$2 WHERE attempt_id=$1",
                &[&attempt_id, &next],
            )
            .await?;
        let history_kind = match state {
            AttemptState::Completed => HistoryKind::ActionCompleted,
            AttemptState::Pending | AttemptState::Uncertain | AttemptState::Refused => {
                HistoryKind::AttemptUncertain
            }
        };
        let displayed_binding: SourceBinding = serde_json::from_value(row.get(13))?;
        let binding_reference = binding_reference(&item.subject, &displayed_binding)?;
        let mut history_detail = serde_json::Map::from_iter([
            ("attemptId".to_owned(), json!(attempt_id)),
            ("bindingReference".to_owned(), json!(binding_reference)),
            ("operation".to_owned(), json!(row.get::<_, String>(6))),
        ]);
        if let Some(reason) = row.get::<_, Option<String>>(11) {
            history_detail.insert("reason".to_owned(), json!(reason));
        }
        if let Some(receipt) = receipt {
            history_detail.insert("sourceRevision".to_owned(), json!(receipt.source_revision));
            if state == AttemptState::Completed {
                history_detail.insert("sourceReceipt".to_owned(), json!(receipt_json));
            }
        }
        append_item_event(
            &transaction,
            &item,
            history_kind,
            Some(actor),
            &actor.profile_id,
            Value::Object(history_detail),
        )
        .await?;
        if state == AttemptState::Completed
            && parse_operation(&row.get::<_, String>(6))?.as_str() == "request_correction"
        {
            let reason: Option<String> = row.get(11);
            let reason = reason.ok_or(StoreError::Corrupt)?;
            transaction.execute("INSERT INTO casework_correction_context(item_id,source_binding,reason,flagged_fields,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(item_id) DO UPDATE SET source_binding=EXCLUDED.source_binding,reason=EXCLUDED.reason,flagged_fields=EXCLUDED.flagged_fields,created_at=EXCLUDED.created_at", &[&item_id,&row.get::<_,Value>(13),&reason,&row.get::<_,Value>(12),&now]).await?;
        }
        if let Some(receipt) = receipt {
            if let Ok(revision) = receipt.source_revision.parse::<i64>() {
                transaction.execute("UPDATE casework_subjects SET wanted_revision=GREATEST(wanted_revision,$4),sync_pending=true WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3", &[&item.subject.source_id,&item.subject.kind,&item.subject.id,&revision]).await?;
            }
        }
        transaction.commit().await?;
        Ok(AttemptStatus {
            attempt_id,
            item_id,
            state,
            item_revision: next,
            operation: parse_operation(&row.get::<_, String>(6))?,
            created_at: row.get(8),
            receipt: receipt.cloned(),
        })
    }

    /// Record that the caller opened the Casework task. This is a task-view
    /// accountability fact and deliberately does not change the item revision.
    pub async fn record_opened(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
    ) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT * FROM casework_items WHERE item_id=$1 FOR UPDATE",
                &[&item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let item = row_to_item(&row)?;
        if !is_staff_for_queue(&transaction, actor, &item.queue_id).await?
            && !is_supervisor_for_queue(&transaction, actor, &item.queue_id).await?
        {
            return Err(StoreError::NotFound);
        }
        append_item_event(
            &transaction,
            &item,
            HistoryKind::Opened,
            Some(actor),
            &actor.profile_id,
            json!({}),
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn correction_routing_copy(
        &self,
        item_id: Uuid,
    ) -> Result<Option<CorrectionRoutingCopy>, StoreError> {
        let client = self.client().await?;
        client.query_opt("SELECT source_binding,reason,flagged_fields FROM casework_correction_context WHERE item_id=$1", &[&item_id]).await?.map(|row|Ok(CorrectionRoutingCopy{source_binding:serde_json::from_value(row.get(0))?,reason:Some(row.get(1)),flagged_fields:serde_json::from_value(row.get(2))?})).transpose()
    }

    pub async fn load_prepared_attempt(
        &self,
        actor: &ActorContext,
        attempt_id: Uuid,
    ) -> Result<(String, String, PreparedSourceAttempt), StoreError> {
        let client = self.client().await?;
        let row=client.query_opt("SELECT source_profile_id,idempotency_key,displayed_binding,recovery_evidence,state,actor_issuer,actor_subject,casework_profile_id FROM casework_attempts WHERE attempt_id=$1", &[&attempt_id]).await?.ok_or(StoreError::NotFound)?;
        if row.get::<_, String>(5) != actor.principal.issuer
            || row.get::<_, String>(6) != actor.principal.subject
            || row.get::<_, String>(7) != actor.profile_id
        {
            return Err(StoreError::Forbidden);
        }
        let state = parse_attempt_state(&row.get::<_, String>(4))?;
        if !matches!(state, AttemptState::Pending | AttemptState::Uncertain) {
            return Err(StoreError::Conflict);
        }
        let evidence = registry_casework_core::RecoveryEvidence::new(row.get(3))
            .map_err(|_| StoreError::Corrupt)?;
        Ok((
            row.get(0),
            row.get(1),
            PreparedSourceAttempt {
                source_binding: serde_json::from_value(row.get(2))?,
                recovery_evidence: evidence,
            },
        ))
    }

    pub async fn load_prepared_attempt_by_key(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        idempotency_key: &str,
    ) -> Result<(Uuid, String, PreparedSourceAttempt), StoreError> {
        let client = self.client().await?;
        let row = client.query_opt(
            "SELECT attempt_id,source_profile_id,displayed_binding,recovery_evidence,state,actor_issuer,actor_subject,casework_profile_id FROM casework_attempts WHERE item_id=$1 AND idempotency_key=$2",
            &[&item_id,&idempotency_key],
        ).await?.ok_or(StoreError::NotFound)?;
        if row.get::<_, String>(5) != actor.principal.issuer
            || row.get::<_, String>(6) != actor.principal.subject
            || row.get::<_, String>(7) != actor.profile_id
        {
            return Err(StoreError::NotFound);
        }
        if !matches!(
            parse_attempt_state(&row.get::<_, String>(4))?,
            AttemptState::Pending | AttemptState::Uncertain
        ) {
            return Err(StoreError::Conflict);
        }
        Ok((
            row.get(0),
            row.get(1),
            PreparedSourceAttempt {
                source_binding: serde_json::from_value(row.get(2))?,
                recovery_evidence: registry_casework_core::RecoveryEvidence::new(row.get(3))
                    .map_err(|_| StoreError::Corrupt)?,
            },
        ))
    }

    pub async fn attempt_item_id(&self, attempt_id: Uuid) -> Result<Uuid, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query_opt(
                "SELECT item_id FROM casework_attempts WHERE attempt_id=$1",
                &[&attempt_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?
            .get(0))
    }

    /// Returns only an unresolved attempt owned by this exact actor, Casework
    /// profile, and source profile. Callers use this to preserve the original
    /// recovery handle when a second command races or uses a different key.
    pub async fn live_attempt_for_actor(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        source_profile_id: &str,
    ) -> Result<Option<Uuid>, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query_opt(
                "SELECT attempt_id FROM casework_attempts WHERE item_id=$1 AND actor_issuer=$2 AND actor_subject=$3 AND casework_profile_id=$4 AND source_profile_id=$5 AND state IN ('pending','uncertain') ORDER BY created_at DESC LIMIT 1",
                &[&item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&source_profile_id],
            )
            .await?
            .map(|row| row.get(0)))
    }

    /// Return a recovery handle only for the exact actor and selected profiles.
    pub async fn live_attempt_status_for_actor(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        source_profile_id: &str,
    ) -> Result<Option<AttemptStatus>, StoreError> {
        let client = self.client().await?;
        client.query_opt(
            "SELECT attempt_id,item_id,actor_issuer,actor_subject,casework_profile_id,item_revision,operation,state,created_at,receipt FROM casework_attempts WHERE item_id=$1 AND actor_issuer=$2 AND actor_subject=$3 AND casework_profile_id=$4 AND source_profile_id=$5 AND state IN ('pending','uncertain') ORDER BY created_at DESC LIMIT 1",
            &[&item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&source_profile_id],
        ).await?.as_ref().map(attempt_from_row).transpose()
    }

    pub async fn attempt_by_key(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        idempotency_key: &str,
        request_hash: &str,
    ) -> Result<Option<AttemptStatus>, StoreError> {
        let client = self.client().await?;
        let row = client.query_opt(
            "SELECT a.attempt_id,a.state,a.item_revision,a.operation,a.created_at,a.receipt,a.actor_issuer,a.actor_subject,a.casework_profile_id,a.request_hash,i.erased_at FROM casework_attempts a JOIN casework_items i ON i.item_id=a.item_id WHERE a.item_id=$1 AND a.idempotency_key=$2",
            &[&item_id,&idempotency_key],
        ).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        if row.get::<_, String>(6) != actor.principal.issuer
            || row.get::<_, String>(7) != actor.principal.subject
            || row.get::<_, String>(8) != actor.profile_id
            || row.get::<_, String>(9) != request_hash
        {
            return Err(StoreError::IdempotencyConflict);
        }
        if row.get::<_, Option<DateTime<Utc>>>(10).is_some() {
            return Err(StoreError::IdempotencyExpired);
        }
        Ok(Some(AttemptStatus {
            attempt_id: row.get(0),
            item_id,
            state: parse_attempt_state(&row.get::<_, String>(1))?,
            item_revision: row.get(2),
            operation: parse_operation(&row.get::<_, String>(3))?,
            created_at: row.get(4),
            receipt: row
                .get::<_, Option<Value>>(5)
                .map(serde_json::from_value)
                .transpose()?,
        }))
    }

    pub async fn terminal_attempt_by_key(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Option<(String, AttemptStatus)>, StoreError> {
        let client = self.client().await?;
        let row=client.query_opt("SELECT a.source_profile_id,a.attempt_id,a.state,a.item_revision,a.operation,a.created_at,a.receipt,a.actor_issuer,a.actor_subject,a.casework_profile_id,i.erased_at FROM casework_attempts a JOIN casework_items i ON i.item_id=a.item_id WHERE a.item_id=$1 AND a.idempotency_key=$2", &[&item_id,&idempotency_key]).await?;
        let Some(row) = row else { return Ok(None) };
        if row.get::<_, String>(7) != actor.principal.issuer
            || row.get::<_, String>(8) != actor.principal.subject
            || row.get::<_, String>(9) != actor.profile_id
        {
            return Err(StoreError::NotFound);
        }
        if row.get::<_, Option<DateTime<Utc>>>(10).is_some() {
            return Err(StoreError::IdempotencyExpired);
        }
        let state = parse_attempt_state(&row.get::<_, String>(2))?;
        if !matches!(state, AttemptState::Completed | AttemptState::Refused) {
            return Ok(None);
        }
        Ok(Some((
            row.get(0),
            AttemptStatus {
                attempt_id: row.get(1),
                item_id,
                state,
                item_revision: row.get(3),
                operation: parse_operation(&row.get::<_, String>(4))?,
                created_at: row.get(5),
                receipt: row
                    .get::<_, Option<Value>>(6)
                    .map(serde_json::from_value)
                    .transpose()?,
            },
        )))
    }

    pub async fn terminal_attempt_by_id(
        &self,
        actor: &ActorContext,
        attempt_id: Uuid,
    ) -> Result<Option<(String, AttemptStatus)>, StoreError> {
        let client = self.client().await?;
        let row=client.query_opt("SELECT a.source_profile_id,a.item_id,a.state,a.item_revision,a.operation,a.created_at,a.receipt,a.actor_issuer,a.actor_subject,a.casework_profile_id,i.erased_at FROM casework_attempts a JOIN casework_items i ON i.item_id=a.item_id WHERE a.attempt_id=$1", &[&attempt_id]).await?.ok_or(StoreError::NotFound)?;
        if row.get::<_, String>(7) != actor.principal.issuer
            || row.get::<_, String>(8) != actor.principal.subject
            || row.get::<_, String>(9) != actor.profile_id
        {
            return Err(StoreError::NotFound);
        }
        if row.get::<_, Option<DateTime<Utc>>>(10).is_some() {
            return Err(StoreError::IdempotencyExpired);
        }
        let state = parse_attempt_state(&row.get::<_, String>(2))?;
        if !matches!(state, AttemptState::Completed | AttemptState::Refused) {
            return Ok(None);
        }
        let item_id = row.get(1);
        Ok(Some((
            row.get(0),
            AttemptStatus {
                attempt_id,
                item_id,
                state,
                item_revision: row.get(3),
                operation: parse_operation(&row.get::<_, String>(4))?,
                created_at: row.get(5),
                receipt: row
                    .get::<_, Option<Value>>(6)
                    .map(serde_json::from_value)
                    .transpose()?,
            },
        )))
    }

    pub async fn resolve_cursor(
        &self,
        actor: &ActorContext,
        source_profile_id: &str,
        context: &str,
        cursor: Option<&str>,
    ) -> Result<Option<(Option<DateTime<Utc>>, Uuid)>, StoreError> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        let cursor_id = Uuid::parse_str(cursor).map_err(|_| StoreError::Invalid)?;
        let client = self.client().await?;
        let row=client.query_opt("SELECT last_passive_due_at,last_item_id FROM casework_cursors WHERE cursor_id=$1 AND issuer=$2 AND subject=$3 AND casework_profile_id=$4 AND source_profile_id=$5 AND context=$6 AND expires_at>now()", &[&cursor_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&source_profile_id,&context]).await?.ok_or(StoreError::Invalid)?;
        Ok(row
            .get::<_, Option<Uuid>>(1)
            .map(|item_id| (row.get(0), item_id)))
    }

    pub async fn issue_cursor(
        &self,
        actor: &ActorContext,
        source_profile_id: &str,
        context: &str,
        last: Option<(Option<DateTime<Utc>>, Uuid)>,
    ) -> Result<String, StoreError> {
        let cursor_id = Uuid::new_v4();
        let client = self.client().await?;
        let (last_due, last_id) = last.map_or((None, None), |(due, id)| (due, Some(id)));
        client.execute("INSERT INTO casework_cursors(cursor_id,issuer,subject,casework_profile_id,source_profile_id,context,last_passive_due_at,last_item_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '15 minutes')", &[&cursor_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&source_profile_id,&context,&last_due,&last_id]).await?;
        Ok(cursor_id.to_string())
    }

    pub async fn item(&self, item_id: Uuid) -> Result<WorkItem, StoreError> {
        let client = self.client().await?;
        let row = client
            .query_opt("SELECT * FROM casework_items WHERE item_id=$1", &[&item_id])
            .await?
            .ok_or(StoreError::NotFound)?;
        row_to_item(&row)
    }

    /// Check only for an erased, payload-free idempotency record. This never
    /// returns a saved success response and grants no authority for a new
    /// operation.
    pub(crate) async fn preflight_erased_item_idempotency(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        operation: &str,
        idempotency_key: &str,
        expected_hash: &str,
    ) -> Result<(), StoreError> {
        if idempotency_key.is_empty() || idempotency_key.len() > 256 {
            return Err(StoreError::Invalid);
        }
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT d.request_hash,d.response,i.queue_id,i.holder_issuer,i.holder_subject FROM casework_idempotency d JOIN casework_items i ON i.item_id=$1 AND i.erased_at IS NOT NULL WHERE d.issuer=$2 AND d.subject=$3 AND d.profile_id=$4 AND d.operation=$5 AND d.resource=$6 AND d.idempotency_key=$7",
                &[&item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&operation,&item_id.to_string(),&idempotency_key],
            )
            .await?;
        let Some(row) = row else {
            return Ok(());
        };
        let membership_kind = match (operation, actor.role) {
            ("item.claim" | "draft.save" | "draft.delete", CaseworkRole::Staff) => "staff",
            ("item.release", CaseworkRole::Staff) => "staff",
            ("item.release", CaseworkRole::Supervisor) => "supervisor",
            _ => return Ok(()),
        };
        let queue_id: String = row.get(2);
        let currently_serves: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=$1 AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind=$4)",
                &[&queue_id,&actor.principal.issuer,&actor.principal.subject,&membership_kind],
            )
            .await?
            .get(0);
        let holds_item = row.get::<_, Option<String>>(3).as_deref()
            == Some(actor.principal.issuer.as_str())
            && row.get::<_, Option<String>>(4).as_deref() == Some(actor.principal.subject.as_str());
        if !currently_serves || matches!(operation, "draft.save" | "draft.delete") && !holds_item {
            return Ok(());
        }
        if row.get::<_, String>(0) != expected_hash {
            return Err(StoreError::IdempotencyConflict);
        }
        if row.get::<_, Option<Value>>(1).is_none() {
            return Err(StoreError::IdempotencyExpired);
        }
        Ok(())
    }

    pub(crate) async fn preflight_erased_attempt(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        idempotency_key: &str,
        expected_hash: &str,
    ) -> Result<(), StoreError> {
        if idempotency_key.is_empty() || idempotency_key.len() > 256 {
            return Err(StoreError::Invalid);
        }
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT a.request_hash FROM casework_attempts a JOIN casework_items i ON i.item_id=a.item_id AND i.erased_at IS NOT NULL JOIN casework_queue_service q ON q.queue_id=i.queue_id JOIN casework_memberships m ON m.team_id=q.team_id AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind='staff' WHERE a.item_id=$1 AND a.idempotency_key=$4 AND a.actor_issuer=$2 AND a.actor_subject=$3 AND a.casework_profile_id=$5 AND i.holder_issuer=$2 AND i.holder_subject=$3",
                &[&item_id,&actor.principal.issuer,&actor.principal.subject,&idempotency_key,&actor.profile_id],
            )
            .await?;
        let Some(row) = row else {
            return Ok(());
        };
        if row.get::<_, String>(0) != expected_hash {
            return Err(StoreError::IdempotencyConflict);
        }
        Err(StoreError::IdempotencyExpired)
    }

    pub async fn can_view_item(
        &self,
        actor: &ActorContext,
        item: &WorkItem,
    ) -> Result<bool, StoreError> {
        let client = self.client().await?;
        Ok(
            is_staff_for_queue_client(&client, actor, &item.queue_id).await?
                || is_supervisor_for_queue_client(&client, actor, &item.queue_id).await?,
        )
    }

    pub async fn inbox_candidates(
        &self,
        actor: &ActorContext,
        limit: usize,
        after: Option<(Option<DateTime<Utc>>, Uuid)>,
        queue: Option<&str>,
    ) -> Result<Page<WorkItem>, StoreError> {
        self.inbox_candidates_for_view(actor, InboxView::MyTeams, limit, after, queue)
            .await
    }

    pub async fn inbox_candidates_for_view(
        &self,
        actor: &ActorContext,
        view: InboxView,
        limit: usize,
        after: Option<(Option<DateTime<Utc>>, Uuid)>,
        queue: Option<&str>,
    ) -> Result<Page<WorkItem>, StoreError> {
        let limit = i64::try_from(limit.min(100)).map_err(|_| StoreError::Invalid)?;
        let (after_due, after_id, has_after) =
            after.map_or((None, None, false), |(due, id)| (due, Some(id), true));
        let client = self.client().await?;
        let view = match view {
            InboxView::Mine => "mine",
            InboxView::MyTeams => "my_teams",
            InboxView::TeamHoldings => "team_holdings",
            InboxView::Overdue => "overdue",
            InboxView::CompletedByMe => "completed_by_me",
        };
        let rows=client.query(
            "SELECT i.* FROM casework_items i JOIN casework_queue_service q ON q.queue_id=i.queue_id JOIN casework_memberships m ON m.team_id=q.team_id AND m.issuer=$1 AND m.subject=$2 WHERE i.erased_at IS NULL AND m.membership_kind=$3 AND ($4::text IS NULL OR i.queue_id=$4) AND (($5='mine' AND i.state NOT IN ('completed','superseded','cancelled') AND i.holder_issuer=$1 AND i.holder_subject=$2) OR ($5='my_teams' AND i.state NOT IN ('completed','superseded','cancelled')) OR ($5='team_holdings' AND i.state NOT IN ('completed','superseded','cancelled') AND i.holder_issuer IS NOT NULL) OR ($5='overdue' AND i.state NOT IN ('completed','superseded','cancelled') AND i.passive_due_at<now()) OR ($5='completed_by_me' AND i.state='completed' AND EXISTS(SELECT 1 FROM casework_history h WHERE h.item_id=i.item_id AND h.kind='action_completed' AND h.actor_issuer=$1 AND h.actor_subject=$2))) AND (NOT $6 OR ($7::timestamptz IS NOT NULL AND (i.passive_due_at > $7 OR i.passive_due_at IS NULL OR (i.passive_due_at=$7 AND i.item_id>$8))) OR ($7::timestamptz IS NULL AND i.passive_due_at IS NULL AND i.item_id>$8)) ORDER BY i.passive_due_at NULLS LAST,i.item_id LIMIT $9",
            &[&actor.principal.issuer,&actor.principal.subject,&match actor.role { CaseworkRole::Staff=>"staff", CaseworkRole::Supervisor=>"supervisor", CaseworkRole::Administrator=>"administrator", CaseworkRole::Requester=>"requester" },&queue,&view,&has_after,&after_due,&after_id,&limit]
        ).await?;
        let items = rows
            .iter()
            .map(row_to_item)
            .collect::<Result<Vec<_>, _>>()?;
        let next =
            (items.len() == usize::try_from(limit).unwrap_or(100)).then(|| "more".to_owned());
        Ok(Page {
            items,
            next_cursor: next,
            status: PageStatus::Complete,
        })
    }

    pub async fn holdings(
        &self,
        actor: &ActorContext,
    ) -> Result<Vec<registry_casework_core::HoldingSummary>, StoreError> {
        if actor.role != CaseworkRole::Supervisor {
            return Err(StoreError::Forbidden);
        }
        let client = self.client().await?;
        let rows=client.query(
            "SELECT i.holder_issuer,i.holder_subject,i.queue_id,count(*)::bigint,count(*) FILTER(WHERE i.passive_due_at IS NOT NULL AND i.passive_due_at < now())::bigint FROM casework_items i JOIN casework_queue_service q ON q.queue_id=i.queue_id JOIN casework_memberships lead ON lead.team_id=q.team_id AND lead.issuer=$1 AND lead.subject=$2 AND lead.membership_kind='supervisor' WHERE i.erased_at IS NULL AND i.holder_issuer IS NOT NULL AND i.state NOT IN ('completed','superseded','cancelled') GROUP BY i.holder_issuer,i.holder_subject,i.queue_id ORDER BY i.queue_id,i.holder_issuer,i.holder_subject",
            &[&actor.principal.issuer,&actor.principal.subject]
        ).await?;
        rows.into_iter()
            .map(|row| {
                Ok(registry_casework_core::HoldingSummary {
                    principal: IssuerPrincipal {
                        issuer: row.get(0),
                        subject: row.get(1),
                    },
                    queue_id: row.get(2),
                    active_items: u32::try_from(row.get::<_, i64>(3))
                        .map_err(|_| StoreError::Corrupt)?,
                    overdue_items: u32::try_from(row.get::<_, i64>(4))
                        .map_err(|_| StoreError::Corrupt)?,
                })
            })
            .collect()
    }

    pub async fn history(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>, StoreError> {
        let client = self.client().await?;
        let item = self.item(item_id).await?;
        let visible = is_staff_for_queue_client(&client, actor, &item.queue_id).await?
            || is_supervisor_for_queue_client(&client, actor, &item.queue_id).await?;
        if !visible {
            return Err(StoreError::NotFound);
        }
        let limit = i64::try_from(limit.min(100)).map_err(|_| StoreError::Invalid)?;
        let rows=client.query("SELECT event_id,item_id,item_revision,kind,occurred_at,actor_issuer,actor_subject,profile_id,detail FROM casework_history WHERE item_id=$1 ORDER BY occurred_at,event_id LIMIT $2", &[&item_id,&limit]).await?;
        rows.into_iter().map(history_from_row).collect()
    }

    pub async fn work_item_routing(
        &self,
        item_id: Uuid,
    ) -> Result<Option<WorkItemRouting>, StoreError> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT h.detail->>'routingRule',h.detail->>'routingBecause',h.detail->>'routingPolicyDigest' FROM casework_history h JOIN casework_items i ON i.item_id=h.item_id AND i.erased_at IS NULL WHERE h.item_id=$1 AND h.kind='observed' AND h.detail->>'routingPolicyDigest' IS NOT NULL ORDER BY h.occurred_at,h.event_id LIMIT 1",
                &[&item_id],
            )
            .await?;
        Ok(row.map(|row| WorkItemRouting {
            rule_id: row.get(0),
            because: row.get(1),
            policy_digest: row.get(2),
        }))
    }

    pub(crate) async fn source_holder_timings(
        &self,
        item_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, i64, Option<DateTime<Utc>>)>, StoreError> {
        if item_ids.is_empty() {
            return Ok(Vec::new());
        }
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT i.item_id,i.revision,CASE WHEN i.holder_issuer IS NULL THEN NULL ELSE (SELECT h.occurred_at FROM casework_history h WHERE h.item_id=i.item_id AND h.kind IN ('claimed','assigned','delegated','caseload_moved') ORDER BY h.item_revision DESC,h.occurred_at DESC,h.event_id DESC LIMIT 1) END FROM casework_items i WHERE i.item_id=ANY($1) AND i.erased_at IS NULL",
                &[&item_ids],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get(0), row.get(1), row.get(2)))
            .collect())
    }

    pub async fn history_page(
        &self,
        actor: &ActorContext,
        source_profile_id: &str,
        item_id: Uuid,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Page<HistoryEntry>, StoreError> {
        let limit = limit.clamp(1, 100);
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction
            .query_opt(
                "SELECT item_id FROM casework_items WHERE item_id=$1 AND erased_at IS NULL FOR UPDATE",
                &[&item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let after = if let Some(cursor) = cursor {
            let cursor_id = Uuid::parse_str(cursor).map_err(|_| StoreError::CursorInvalid)?;
            let row = transaction
                .query_opt(
                    "SELECT issuer,subject,casework_profile_id,source_profile_id,item_id,last_occurred_at,last_event_id,expires_at FROM casework_history_cursors WHERE cursor_id=$1",
                    &[&cursor_id],
                )
                .await?
                .ok_or(StoreError::CursorInvalid)?;
            if row.get::<_, String>(0) != actor.principal.issuer
                || row.get::<_, String>(1) != actor.principal.subject
                || row.get::<_, String>(2) != actor.profile_id
                || row.get::<_, String>(3) != source_profile_id
                || row.get::<_, Uuid>(4) != item_id
            {
                return Err(StoreError::CursorInvalid);
            }
            if row.get::<_, DateTime<Utc>>(7) <= Utc::now() {
                return Err(StoreError::CursorExpired);
            }
            Some((row.get::<_, DateTime<Utc>>(5), row.get::<_, Uuid>(6)))
        } else {
            None
        };
        let membership_kind = match actor.role {
            CaseworkRole::Staff => "staff",
            CaseworkRole::Supervisor => "supervisor",
            CaseworkRole::Administrator | CaseworkRole::Requester => {
                return Err(StoreError::NotFound)
            }
        };
        let authorized: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM casework_items i JOIN casework_queue_service q ON q.queue_id=i.queue_id JOIN casework_memberships m ON m.team_id=q.team_id WHERE i.item_id=$1 AND i.erased_at IS NULL AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind=$4)",
                &[&item_id,&actor.principal.issuer,&actor.principal.subject,&membership_kind],
            )
            .await?
            .get(0);
        if !authorized {
            return Err(StoreError::NotFound);
        }
        let has_after = after.is_some();
        let (after_at, after_id) = after.unwrap_or((Utc::now(), Uuid::nil()));
        let query_limit = i64::try_from(limit + 1).map_err(|_| StoreError::Invalid)?;
        let rows = transaction
            .query(
                "SELECT h.event_id,h.item_id,h.item_revision,h.kind,h.occurred_at,h.actor_issuer,h.actor_subject,h.profile_id,h.detail FROM casework_history h JOIN casework_items i ON i.item_id=h.item_id AND i.erased_at IS NULL JOIN casework_queue_service q ON q.queue_id=i.queue_id JOIN casework_memberships m ON m.team_id=q.team_id AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind=$4 WHERE h.item_id=$1 AND (NOT $5 OR (h.occurred_at,h.event_id)>($6,$7)) ORDER BY h.occurred_at,h.event_id LIMIT $8",
                &[&item_id,&actor.principal.issuer,&actor.principal.subject,&membership_kind,&has_after,&after_at,&after_id,&query_limit],
            )
            .await?;
        let more = rows.len() > limit;
        let mut items = Vec::with_capacity(rows.len().min(limit));
        let mut last = None;
        for row in rows.into_iter().take(limit) {
            let history = history_from_row(row)?;
            last = Some((history.occurred_at, history.event_id));
            items.push(history);
        }
        let next_cursor = if more {
            let (last_occurred_at, last_event_id) = last.ok_or(StoreError::Corrupt)?;
            let cursor_id = Uuid::new_v4();
            transaction.execute(
                "INSERT INTO casework_history_cursors(cursor_id,issuer,subject,casework_profile_id,source_profile_id,item_id,last_occurred_at,last_event_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '15 minutes')",
                &[&cursor_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&source_profile_id,&item_id,&last_occurred_at,&last_event_id],
            ).await?;
            Some(cursor_id.to_string())
        } else {
            None
        };
        transaction.commit().await?;
        Ok(Page {
            items,
            next_cursor,
            status: PageStatus::Complete,
        })
    }

    pub async fn erase_expired_source_history_cursors(&self) -> Result<usize, StoreError> {
        let client = self.client().await?;
        let deleted = client
            .execute(
                "WITH due AS (SELECT cursor_id FROM casework_history_cursors WHERE expires_at<=now() ORDER BY expires_at,cursor_id LIMIT 100 FOR UPDATE SKIP LOCKED) DELETE FROM casework_history_cursors c USING due WHERE c.cursor_id=due.cursor_id",
                &[],
            )
            .await?;
        usize::try_from(deleted).map_err(|_| StoreError::Corrupt)
    }

    pub async fn claim_sync_batch(
        &self,
        limit: i64,
        lease_seconds: i64,
    ) -> Result<Vec<SubjectRef>, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let rows=transaction.query("SELECT source_id,subject_kind,subject_id FROM casework_subjects WHERE erased_at IS NULL AND sync_pending=true AND (sync_lease_until IS NULL OR sync_lease_until<now()) ORDER BY source_id,subject_kind,subject_id FOR UPDATE SKIP LOCKED LIMIT $1", &[&limit]).await?;
        let subjects: Vec<_> = rows
            .into_iter()
            .map(|row| SubjectRef {
                source_id: row.get(0),
                kind: row.get(1),
                id: row.get(2),
            })
            .collect();
        for subject in &subjects {
            transaction.execute("UPDATE casework_subjects SET sync_lease_until=now()+make_interval(secs=>$4::int) WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3", &[&subject.source_id,&subject.kind,&subject.id,&i32::try_from(lease_seconds).map_err(|_|StoreError::Invalid)?]).await?;
        }
        transaction.commit().await?;
        Ok(subjects)
    }

    pub async fn claim_source_sync_batch(
        &self,
        source_id: &str,
        generation: &str,
        limit: i64,
        lease_seconds: i64,
    ) -> Result<Vec<SubjectRef>, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let rows=transaction.query("SELECT source_id,subject_kind,subject_id FROM casework_subjects WHERE source_id=$1 AND binding_generation=$2 AND erased_at IS NULL AND sync_pending=true AND (sync_lease_until IS NULL OR sync_lease_until<now()) ORDER BY subject_kind,subject_id FOR UPDATE SKIP LOCKED LIMIT $3", &[&source_id,&generation,&limit]).await?;
        let subjects: Vec<_> = rows
            .into_iter()
            .map(|row| SubjectRef {
                source_id: row.get(0),
                kind: row.get(1),
                id: row.get(2),
            })
            .collect();
        let lease = i32::try_from(lease_seconds).map_err(|_| StoreError::Invalid)?;
        for subject in &subjects {
            transaction.execute("UPDATE casework_subjects SET sync_lease_until=now()+make_interval(secs=>$4::int) WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3", &[&subject.source_id,&subject.kind,&subject.id,&lease]).await?;
        }
        transaction.commit().await?;
        Ok(subjects)
    }

    pub async fn local_active_subjects(
        &self,
        source_id: &str,
        limit: i64,
    ) -> Result<Vec<SubjectRef>, StoreError> {
        let client = self.client().await?;
        let rows=client.query("SELECT source_id,subject_kind,subject_id FROM casework_subjects WHERE source_id=$1 AND active=true AND erased_at IS NULL ORDER BY subject_kind,subject_id LIMIT $2", &[&source_id,&limit]).await?;
        Ok(rows
            .into_iter()
            .map(|row| SubjectRef {
                source_id: row.get(0),
                kind: row.get(1),
                id: row.get(2),
            })
            .collect())
    }

    pub async fn enqueue_discovered(
        &self,
        generation: &str,
        subjects: &[SubjectRef],
    ) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        for subject in subjects {
            transaction.execute("INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,active,sync_pending) VALUES($1,$2,$3,$4,0,0,true,true) ON CONFLICT(source_id,subject_kind,subject_id) DO UPDATE SET sync_pending=true WHERE casework_subjects.binding_generation=EXCLUDED.binding_generation AND casework_subjects.erased_at IS NULL", &[&subject.source_id,&subject.kind,&subject.id,&generation]).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn register_source_generation(
        &self,
        source_id: &str,
        generation: &str,
    ) -> Result<(), StoreError> {
        if source_id.is_empty() || generation.is_empty() {
            return Err(StoreError::Invalid);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let live:bool=transaction.query_one("SELECT EXISTS(SELECT 1 FROM casework_attempts a JOIN casework_items i ON i.item_id=a.item_id JOIN casework_subjects s ON s.source_id=i.source_id AND s.subject_kind=i.subject_kind AND s.subject_id=i.subject_id WHERE s.source_id=$1 AND s.binding_generation<>$2 AND a.state IN ('pending','uncertain'))", &[&source_id,&generation]).await?.get(0);
        if live {
            return Err(StoreError::AttemptPending);
        }
        transaction.execute(
            "UPDATE casework_subjects SET binding_generation=$2,wanted_revision=0,applied_revision=0,representation_etag=NULL,sync_pending=true,sync_lease_until=NULL WHERE source_id=$1 AND binding_generation<>$2 AND erased_at IS NULL",
            &[&source_id,&generation],
        ).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn set_source_status(
        &self,
        source_id: &str,
        generation: &str,
        remote_complete: bool,
        unavailable: bool,
    ) -> Result<(), StoreError> {
        let client = self.client().await?;
        client.execute("INSERT INTO casework_source_status(source_id,binding_generation,remote_complete,unavailable,checked_at) VALUES($1,$2,$3,$4,now()) ON CONFLICT(source_id) DO UPDATE SET binding_generation=EXCLUDED.binding_generation,remote_complete=EXCLUDED.remote_complete,unavailable=EXCLUDED.unavailable,checked_at=EXCLUDED.checked_at", &[&source_id,&generation,&remote_complete,&unavailable]).await?;
        Ok(())
    }

    pub async fn source_status(
        &self,
        source_id: &str,
        generation: &str,
    ) -> Result<Option<(bool, bool)>, StoreError> {
        let client = self.client().await?;
        Ok(client.query_opt("SELECT remote_complete,unavailable FROM casework_source_status WHERE source_id=$1 AND binding_generation=$2 AND checked_at>now()-interval '2 minutes'", &[&source_id,&generation]).await?.map(|row|(row.get(0),row.get(1))))
    }

    pub async fn source_has_pending(
        &self,
        source_id: &str,
        generation: &str,
    ) -> Result<bool, StoreError> {
        let client = self.client().await?;
        Ok(client.query_one("SELECT EXISTS(SELECT 1 FROM casework_subjects WHERE source_id=$1 AND binding_generation=$2 AND erased_at IS NULL AND sync_pending=true)", &[&source_id,&generation]).await?.get(0))
    }

    pub async fn pending_audit(&self, limit: i64) -> Result<Vec<(Uuid, Value)>, StoreError> {
        let client = self.client().await?;
        Ok(client.query("SELECT event_id,audit_record FROM casework_audit_outbox WHERE published_at IS NULL ORDER BY event_id LIMIT $1", &[&limit]).await?.into_iter().map(|row|(row.get(0),row.get(1))).collect())
    }
    pub async fn mark_audit_published(&self, event_id: Uuid) -> Result<(), StoreError> {
        let client = self.client().await?;
        client
            .execute(
                "UPDATE casework_audit_outbox SET published_at=now() WHERE event_id=$1",
                &[&event_id],
            )
            .await?;
        Ok(())
    }

    pub async fn events(
        &self,
        after: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<DurableEvent>, StoreError> {
        let client = self.client().await?;
        let limit = i64::try_from(limit.min(1000)).map_err(|_| StoreError::Invalid)?;
        let rows = client.query(
            "SELECT e.event_id,e.item_id,e.item_revision,e.event_kind,e.occurred_at,e.actor_reference,e.detail FROM casework_events e JOIN casework_items i ON i.item_id=e.item_id AND i.erased_at IS NULL WHERE ($1::uuid IS NULL OR e.event_id>$1) ORDER BY e.event_id LIMIT $2",
            &[&after,&limit],
        ).await?;
        Ok(rows
            .into_iter()
            .map(|row| DurableEvent {
                event_id: row.get(0),
                item_id: row.get(1),
                item_revision: row.get(2),
                kind: row.get(3),
                occurred_at: row.get(4),
                actor_reference: row.get(5),
                detail: row.get(6),
            })
            .collect())
    }
}

fn tls_connector(
    config: &DatabaseConfig,
    secrets: &SecretResolver,
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, StoreError> {
    let provider = rustls::crypto::ring::default_provider();
    if provider.install_default().is_err()
        && rustls::crypto::CryptoProvider::get_default().is_none()
    {
        return Err(StoreError::Configuration);
    }
    if let Some(reference) = &config.trusted_root_certificate_ref {
        let certificate = secrets
            .resolve(reference)
            .map_err(|_| StoreError::Configuration)?;
        let mut roots = rustls::RootCertStore::empty();
        use rustls::pki_types::pem::PemObject as _;
        let mut count = 0usize;
        for certificate in
            rustls::pki_types::CertificateDer::pem_slice_iter(certificate.expose_secret())
        {
            roots
                .add(certificate.map_err(|_| StoreError::Configuration)?)
                .map_err(|_| StoreError::Configuration)?;
            count += 1;
        }
        if count == 0 {
            return Err(StoreError::Configuration);
        }
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(tokio_postgres_rustls::MakeRustlsConnect::new(client))
    } else {
        tokio_postgres_rustls::MakeRustlsConnect::with_native_certs()
            .map(|value| value.0)
            .map_err(|_| StoreError::Configuration)
    }
}

async fn insert_membership(
    transaction: &tokio_postgres::Transaction<'_>,
    team_id: &str,
    principal: &IssuerPrincipal,
    kind: &str,
) -> Result<(), StoreError> {
    transaction.execute("INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES($1,$2,$3,$4)",&[&team_id,&principal.issuer,&principal.subject,&kind]).await.map_err(map_unique_conflict)?;
    Ok(())
}
async fn membership_list(
    client: &deadpool_postgres::Client,
    team_id: &str,
    kind: &str,
) -> Result<Vec<IssuerPrincipal>, StoreError> {
    Ok(client.query("SELECT issuer,subject FROM casework_memberships WHERE team_id=$1 AND membership_kind=$2 ORDER BY issuer,subject", &[&team_id,&kind]).await?.into_iter().map(|row|IssuerPrincipal{issuer:row.get(0),subject:row.get(1)}).collect())
}

async fn is_staff_for_queue(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &ActorContext,
    queue: &str,
) -> Result<bool, StoreError> {
    if actor.role != CaseworkRole::Staff {
        return Ok(false);
    }
    authority(transaction, actor, queue, "staff").await
}
async fn is_supervisor_for_queue(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &ActorContext,
    queue: &str,
) -> Result<bool, StoreError> {
    if actor.role != CaseworkRole::Supervisor {
        return Ok(false);
    }
    authority(transaction, actor, queue, "supervisor").await
}
async fn authority(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &ActorContext,
    queue: &str,
    kind: &str,
) -> Result<bool, StoreError> {
    Ok(transaction.query_one("SELECT EXISTS(SELECT 1 FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=$1 AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind=$4)",&[&queue,&actor.principal.issuer,&actor.principal.subject,&kind]).await?.get(0))
}
async fn is_staff_for_queue_client(
    client: &deadpool_postgres::Client,
    actor: &ActorContext,
    queue: &str,
) -> Result<bool, StoreError> {
    if actor.role != CaseworkRole::Staff {
        return Ok(false);
    }
    Ok(client.query_one("SELECT EXISTS(SELECT 1 FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=$1 AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind='staff')", &[&queue,&actor.principal.issuer,&actor.principal.subject]).await?.get(0))
}
async fn is_supervisor_for_queue_client(
    client: &deadpool_postgres::Client,
    actor: &ActorContext,
    queue: &str,
) -> Result<bool, StoreError> {
    if actor.role != CaseworkRole::Supervisor {
        return Ok(false);
    }
    Ok(client.query_one("SELECT EXISTS(SELECT 1 FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=$1 AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind='supervisor')", &[&queue,&actor.principal.issuer,&actor.principal.subject]).await?.get(0))
}
async fn ensure_no_live_attempt(
    transaction: &tokio_postgres::Transaction<'_>,
    item_id: Uuid,
) -> Result<(), StoreError> {
    let exists:bool=transaction.query_one("SELECT EXISTS(SELECT 1 FROM casework_attempts WHERE item_id=$1 AND state IN ('pending','uncertain'))", &[&item_id]).await?.get(0);
    if exists {
        Err(StoreError::AttemptPending)
    } else {
        Ok(())
    }
}

async fn update_observed_item(
    transaction: &tokio_postgres::Transaction<'_>,
    item: &WorkItem,
    event: OccurrenceEvent,
    observation: &AuthoritativeObservation,
    now: DateTime<Utc>,
) -> Result<WorkItem, StoreError> {
    if transaction.query_one("SELECT EXISTS(SELECT 1 FROM casework_attempts WHERE item_id=$1 AND state IN ('pending','uncertain'))", &[&item.item_id]).await?.get::<_,bool>(0) { return Ok(item.clone()); }
    let state = transition(item.state, event).map_err(|_| StoreError::Corrupt)?;
    let holder = (state == OccurrenceState::Claimed)
        .then(|| item.holder.clone())
        .flatten();
    let next = item.revision + 1;
    let next_binding = if state == OccurrenceState::Superseded {
        &item.binding
    } else {
        &observation.binding
    };
    let binding = serde_json::to_value(next_binding)?;
    transaction.execute("UPDATE casework_items SET binding=$2,state=$3,holder_issuer=$4,holder_subject=$5,revision=$6,updated_at=$7 WHERE item_id=$1", &[&item.item_id,&binding,&state_name(state),&holder.as_ref().map(|p|&p.issuer),&holder.as_ref().map(|p|&p.subject),&next,&now]).await?;
    let mut updated = item.clone();
    updated.binding = next_binding.clone();
    updated.binding_reference = binding_reference(&updated.subject, &updated.binding)?;
    updated.state = state;
    updated.holder = holder;
    updated.revision = next;
    updated.updated_at = now;
    let kind = if state == OccurrenceState::Superseded {
        HistoryKind::Superseded
    } else if matches!(
        state,
        OccurrenceState::Completed | OccurrenceState::Cancelled
    ) {
        HistoryKind::Completed
    } else {
        HistoryKind::Observed
    };
    append_item_event(
        transaction,
        &updated,
        kind,
        None,
        "system:reconciliation",
        json!({"sourceRevision":observation.ordered_revision}),
    )
    .await?;
    Ok(updated)
}

fn observation_event(state: OccurrenceState) -> Result<OccurrenceEvent, StoreError> {
    match state {
        OccurrenceState::Open => Ok(OccurrenceEvent::ObserveOpen),
        OccurrenceState::WaitingApplicant => Ok(OccurrenceEvent::ObserveWaitingApplicant),
        OccurrenceState::WaitingApplication => Ok(OccurrenceEvent::ObserveWaitingApplication),
        OccurrenceState::Completed => Ok(OccurrenceEvent::Complete),
        OccurrenceState::Superseded => Ok(OccurrenceEvent::Supersede),
        OccurrenceState::Cancelled => Ok(OccurrenceEvent::Cancel),
        OccurrenceState::Claimed | OccurrenceState::Synchronizing => Err(StoreError::Invalid),
    }
}

pub(crate) async fn append_item_event(
    transaction: &tokio_postgres::Transaction<'_>,
    item: &WorkItem,
    kind: HistoryKind,
    actor: Option<&ActorContext>,
    profile_id: &str,
    detail: Value,
) -> Result<Uuid, StoreError> {
    let event_id = Uuid::new_v4();
    let now = Utc::now();
    let kind_name = history_kind_name(kind);
    let (issuer, subject) = actor
        .map(|a| (Some(&a.principal.issuer), Some(&a.principal.subject)))
        .unwrap_or((None, None));
    transaction.execute("INSERT INTO casework_history(event_id,item_id,item_revision,kind,occurred_at,actor_issuer,actor_subject,profile_id,detail) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", &[&event_id,&item.item_id,&item.revision,&kind_name,&now,&issuer,&subject,&profile_id,&detail]).await?;
    let actor_reference: Option<String> = None;
    transaction.execute("INSERT INTO casework_events(event_id,item_id,item_revision,event_kind,occurred_at,actor_reference,detail) VALUES($1,$2,$3,$4,$5,$6,$7)", &[&event_id,&item.item_id,&item.revision,&kind_name,&now,&actor_reference,&detail]).await?;
    insert_audit_outbox(transaction,event_id,json!({"event":format!("casework.{kind_name}"),"eventId":event_id,"itemId":item.item_id,"itemRevision":item.revision,"actor":actor.map(|a|json!({"issuer":a.principal.issuer,"subject":a.principal.subject})),"profileId":profile_id})).await?;
    Ok(event_id)
}
async fn insert_audit_outbox(
    transaction: &tokio_postgres::Transaction<'_>,
    event_id: Uuid,
    record: Value,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO casework_audit_outbox(event_id,audit_record) VALUES($1,$2)",
            &[&event_id, &record],
        )
        .await?;
    Ok(())
}

async fn idempotent_response(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
    hash: &str,
) -> Result<Option<Value>, StoreError> {
    if key.is_empty() || key.len() > 256 {
        return Err(StoreError::Invalid);
    }
    let row=transaction.query_opt("SELECT request_hash,response FROM casework_idempotency WHERE issuer=$1 AND subject=$2 AND profile_id=$3 AND operation=$4 AND resource=$5 AND idempotency_key=$6 FOR UPDATE", &[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&operation,&resource,&key]).await?;
    if let Some(row) = row {
        if row.get::<_, String>(0) != hash {
            return Err(StoreError::IdempotencyConflict);
        }
        return row
            .get::<_, Option<Value>>(1)
            .ok_or(StoreError::IdempotencyExpired)
            .map(Some);
    }
    Ok(None)
}
async fn insert_idempotency(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
    hash: &str,
    response: &Value,
) -> Result<(), StoreError> {
    transaction.execute("INSERT INTO casework_idempotency(issuer,subject,profile_id,operation,resource,idempotency_key,request_hash,response,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",&[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&operation,&resource,&key,&hash,&response,&Utc::now()]).await.map_err(map_unique_conflict)?;
    Ok(())
}
fn request_hash<T: serde::Serialize>(value: &T) -> Result<String, StoreError> {
    Ok(hash_bytes(&serde_json::to_vec(value)?))
}
fn binding_reference(
    subject: &SubjectRef,
    displayed_binding: &SourceBinding,
) -> Result<String, StoreError> {
    Ok(hash_bytes(&serde_json::to_vec(&(
        "registry-casework-binding-reference-v1",
        subject,
        displayed_binding,
    ))?))
}
fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

pub(crate) fn row_to_item(row: &Row) -> Result<WorkItem, StoreError> {
    if row.get::<_, Option<DateTime<Utc>>>("erased_at").is_some() {
        return Err(StoreError::NotFound);
    }
    let holder = match (
        row.get::<_, Option<String>>("holder_issuer"),
        row.get::<_, Option<String>>("holder_subject"),
    ) {
        (Some(issuer), Some(subject)) => Some(IssuerPrincipal { issuer, subject }),
        (None, None) => None,
        _ => return Err(StoreError::Corrupt),
    };
    let assignment = assignment_context(row)?;
    let subject = SubjectRef {
        source_id: row.get("source_id"),
        kind: row.get("subject_kind"),
        id: row.get("subject_id"),
    };
    let binding: SourceBinding = serde_json::from_value(row.get("binding"))?;
    Ok(WorkItem {
        item_id: row.get("item_id"),
        binding_reference: binding_reference(&subject, &binding)?,
        subject,
        occurrence_kind: parse_occurrence(&row.get::<_, String>("occurrence_kind"))?,
        stage: row.get("stage"),
        binding,
        state: parse_state(&row.get::<_, String>("state"))?,
        queue_id: row.get("queue_id"),
        holder,
        held_since: None,
        assignment,
        revision: row.get("revision"),
        first_observed_at: row.get("first_observed_at"),
        passive_due_at: row.get("passive_due_at"),
        updated_at: row.get("updated_at"),
        hosted: None,
        routing: None,
        clock_occurrences: Vec::new(),
        actions: Vec::new(),
        routing_copy: None,
        live_attempt: None,
    })
}

fn assignment_context(row: &Row) -> Result<Option<AssignmentContext>, StoreError> {
    let owner = match (
        row.get::<_, Option<String>>("assignment_owner_issuer"),
        row.get::<_, Option<String>>("assignment_owner_subject"),
    ) {
        (Some(issuer), Some(subject)) => Some(IssuerPrincipal { issuer, subject }),
        (None, None) => None,
        _ => return Err(StoreError::Corrupt),
    };
    let assigned_by = match (
        row.get::<_, Option<String>>("assigned_by_issuer"),
        row.get::<_, Option<String>>("assigned_by_subject"),
    ) {
        (Some(issuer), Some(subject)) => Some(IssuerPrincipal { issuer, subject }),
        (None, None) => None,
        _ => return Err(StoreError::Corrupt),
    };
    let absence_ids = row.get::<_, Vec<Uuid>>("assignment_absence_ids");
    let staffing_diagnostic = match row
        .get::<_, Option<String>>("staffing_diagnostic")
        .as_deref()
    {
        Some("no_cover_available") => Some(StaffingDiagnostic::NoCoverAvailable),
        None => None,
        Some(_) => return Err(StoreError::Corrupt),
    };
    if owner.is_none()
        && assigned_by.is_none()
        && absence_ids.is_empty()
        && staffing_diagnostic.is_none()
    {
        Ok(None)
    } else {
        Ok(Some(AssignmentContext {
            owner,
            assigned_by,
            absence_ids,
            staffing_diagnostic,
        }))
    }
}
fn history_from_row(row: Row) -> Result<HistoryEntry, StoreError> {
    let actor = match (
        row.get::<_, Option<String>>(5),
        row.get::<_, Option<String>>(6),
    ) {
        (Some(issuer), Some(subject)) => Some(IssuerPrincipal { issuer, subject }),
        (None, None) => None,
        _ => return Err(StoreError::Corrupt),
    };
    Ok(HistoryEntry {
        event_id: row.get(0),
        item_id: row.get(1),
        item_revision: row.get(2),
        kind: parse_history(&row.get::<_, String>(3))?,
        occurred_at: row.get(4),
        actor,
        profile_id: row.get(7),
        detail: row.get(8),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_reference_distinguishes_proposal_version_and_generation() {
        let subject = SubjectRef {
            source_id: "source-a".to_owned(),
            kind: "application".to_owned(),
            id: "subject-a".to_owned(),
        };
        let original = SourceBinding {
            source_revision: "1".to_owned(),
            version: "proposal-a".to_owned(),
            integrity: Some("sha256:proposal-a".to_owned()),
            generation: "generation-a".to_owned(),
        };
        let changed_proposal = SourceBinding {
            version: "proposal-b".to_owned(),
            integrity: Some("sha256:proposal-b".to_owned()),
            ..original.clone()
        };
        let changed_generation = SourceBinding {
            generation: "generation-b".to_owned(),
            ..original.clone()
        };

        let original_reference = binding_reference(&subject, &original).expect("reference");
        assert_ne!(
            original_reference,
            binding_reference(&subject, &changed_proposal).expect("changed proposal reference")
        );
        assert_ne!(
            original_reference,
            binding_reference(&subject, &changed_generation).expect("changed generation reference")
        );
    }
}
fn attempt_from_row(row: &Row) -> Result<AttemptStatus, StoreError> {
    Ok(AttemptStatus {
        attempt_id: row.get(0),
        item_id: row.get(1),
        state: parse_attempt_state(&row.get::<_, String>(7))?,
        item_revision: row.get(5),
        operation: parse_operation(&row.get::<_, String>(6))?,
        created_at: row.get(8),
        receipt: row
            .get::<_, Option<Value>>(9)
            .map(serde_json::from_value)
            .transpose()?,
    })
}

fn occurrence_kind_name(value: OccurrenceKind) -> &'static str {
    match value {
        OccurrenceKind::Review => "review",
        OccurrenceKind::Application => "application",
        OccurrenceKind::Hosted => "hosted",
    }
}
fn parse_occurrence(value: &str) -> Result<OccurrenceKind, StoreError> {
    match value {
        "review" => Ok(OccurrenceKind::Review),
        "application" => Ok(OccurrenceKind::Application),
        _ => Err(StoreError::Corrupt),
    }
}
fn state_name(value: OccurrenceState) -> &'static str {
    match value {
        OccurrenceState::Open => "open",
        OccurrenceState::Claimed => "claimed",
        OccurrenceState::WaitingApplicant => "waiting_applicant",
        OccurrenceState::WaitingApplication => "waiting_application",
        OccurrenceState::Synchronizing => "synchronizing",
        OccurrenceState::Completed => "completed",
        OccurrenceState::Superseded => "superseded",
        OccurrenceState::Cancelled => "cancelled",
    }
}
fn parse_state(value: &str) -> Result<OccurrenceState, StoreError> {
    match value {
        "open" => Ok(OccurrenceState::Open),
        "claimed" => Ok(OccurrenceState::Claimed),
        "waiting_applicant" => Ok(OccurrenceState::WaitingApplicant),
        "waiting_application" => Ok(OccurrenceState::WaitingApplication),
        "synchronizing" => Ok(OccurrenceState::Synchronizing),
        "completed" => Ok(OccurrenceState::Completed),
        "superseded" => Ok(OccurrenceState::Superseded),
        "cancelled" => Ok(OccurrenceState::Cancelled),
        _ => Err(StoreError::Corrupt),
    }
}
fn parse_operation(value: &str) -> Result<OperationName, StoreError> {
    OperationName::parse(value).map_err(|_| StoreError::Corrupt)
}
fn attempt_state_name(value: AttemptState) -> &'static str {
    match value {
        AttemptState::Pending => "pending",
        AttemptState::Uncertain => "uncertain",
        AttemptState::Completed => "completed",
        AttemptState::Refused => "refused",
    }
}
fn parse_attempt_state(value: &str) -> Result<AttemptState, StoreError> {
    match value {
        "pending" => Ok(AttemptState::Pending),
        "uncertain" => Ok(AttemptState::Uncertain),
        "completed" => Ok(AttemptState::Completed),
        "refused" => Ok(AttemptState::Refused),
        _ => Err(StoreError::Corrupt),
    }
}
fn history_kind_name(value: HistoryKind) -> &'static str {
    match value {
        HistoryKind::Observed => "observed",
        HistoryKind::Opened => "opened",
        HistoryKind::Claimed => "claimed",
        HistoryKind::Assigned => "assigned",
        HistoryKind::Delegated => "delegated",
        HistoryKind::CaseloadMoved => "caseload_moved",
        HistoryKind::Released => "released",
        HistoryKind::DraftSaved => "draft_saved",
        HistoryKind::AttemptReserved => "attempt_reserved",
        HistoryKind::AttemptUncertain => "attempt_uncertain",
        HistoryKind::ActionCompleted => "action_completed",
        HistoryKind::ClockReminder => "clock_reminder",
        HistoryKind::ClockStepApplied => "clock_step_applied",
        HistoryKind::ClockRecomputed => "clock_recomputed",
        HistoryKind::Superseded => "superseded",
        HistoryKind::Completed => "completed",
    }
}
fn parse_history(value: &str) -> Result<HistoryKind, StoreError> {
    match value {
        "observed" => Ok(HistoryKind::Observed),
        "opened" => Ok(HistoryKind::Opened),
        "claimed" => Ok(HistoryKind::Claimed),
        "assigned" => Ok(HistoryKind::Assigned),
        "delegated" => Ok(HistoryKind::Delegated),
        "caseload_moved" => Ok(HistoryKind::CaseloadMoved),
        "released" => Ok(HistoryKind::Released),
        "draft_saved" => Ok(HistoryKind::DraftSaved),
        "attempt_reserved" => Ok(HistoryKind::AttemptReserved),
        "attempt_uncertain" => Ok(HistoryKind::AttemptUncertain),
        "action_completed" => Ok(HistoryKind::ActionCompleted),
        "clock_reminder" => Ok(HistoryKind::ClockReminder),
        "clock_step_applied" => Ok(HistoryKind::ClockStepApplied),
        "clock_recomputed" => Ok(HistoryKind::ClockRecomputed),
        "superseded" => Ok(HistoryKind::Superseded),
        "completed" => Ok(HistoryKind::Completed),
        _ => Err(StoreError::Corrupt),
    }
}

fn map_unique_conflict(error: tokio_postgres::Error) -> StoreError {
    if error
        .as_db_error()
        .is_some_and(|e| e.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION)
    {
        StoreError::Conflict
    } else {
        StoreError::Postgres(error)
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("the Casework database configuration is invalid")]
    Configuration,
    #[error("the Casework database is unavailable")]
    Unavailable,
    #[error("the requested resource was not found")]
    NotFound,
    #[error("the caller is not authorized for this operation")]
    Forbidden,
    #[error("the expected revision is no longer current")]
    Conflict,
    #[error("the work item is already claimed")]
    AlreadyClaimed,
    #[error("the caller does not hold the work item")]
    NotHolder,
    #[error("the idempotency key was already used with different input")]
    IdempotencyConflict,
    #[error("the stored idempotent response has expired")]
    IdempotencyExpired,
    #[error(transparent)]
    Absence(#[from] registry_casework_core::AbsenceError),
    #[error("a source attempt is still pending recovery")]
    AttemptPending,
    #[error("the source binding generation is stale")]
    StaleGeneration,
    #[error("the request is invalid")]
    Invalid,
    #[error("the pagination cursor is invalid")]
    CursorInvalid,
    #[error("the pagination cursor has expired")]
    CursorExpired,
    #[error("stored Casework data is invalid")]
    Corrupt,
    #[error("the Casework database operation failed")]
    Postgres(#[from] tokio_postgres::Error),
    #[error("Casework serialization failed")]
    Json(#[from] serde_json::Error),
}
