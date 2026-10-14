//! Persisted task authority with immutable bounds and live eligibility checks.
use crate::{PostgresStore, StoreError};
use chrono::{DateTime, Utc};
use registry_casework_core::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(crate) struct StoredReviewTaskGrant {
    pub grant: ReviewTaskGrant,
    pub invalidated: bool,
}

fn membership_kind(role: CaseworkRole) -> Option<&'static str> {
    match role {
        CaseworkRole::Staff => Some("staff"),
        CaseworkRole::Supervisor => Some("supervisor"),
        CaseworkRole::Administrator | CaseworkRole::Requester => None,
    }
}

/// Activate the configured immutable template versions inside
/// `transaction`, under the same Directory lock used by approval and live
/// eligibility checks, and invalidate every live grant whose template is no
/// longer active. A configured version whose stored document differs, or one
/// larger than the template bound, is refused.
pub(crate) async fn activate_task_templates_in(
    transaction: &Transaction<'_>,
    audit: &mut crate::audit::AuditOperation,
    templates: &[TaskTemplate],
) -> Result<(), StoreError> {
    transaction
        .query_one(
            "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR UPDATE",
            &[],
        )
        .await?;
    for template in templates {
        let document = serde_json::to_value(template)?;
        if serde_json::to_vec(&document)?.len() > 65536 {
            return Err(StoreError::Configuration);
        }
        if let Some(row) = transaction.query_opt("SELECT document FROM casework_task_templates WHERE template_id=$1 AND template_version=$2", &[&template.id,&template.version]).await? {
            if template_behavior(row.get::<_,Value>(0)) != template_behavior(document.clone()) { return Err(StoreError::Configuration); }
            transaction.execute("UPDATE casework_task_templates SET document=$3 WHERE template_id=$1 AND template_version=$2",&[&template.id,&template.version,&document]).await?;
        } else {
            transaction.execute("INSERT INTO casework_task_templates(template_id,template_version,document) VALUES($1,$2,$3)", &[&template.id,&template.version,&document]).await?;
        }
    }
    transaction
        .execute(
            "UPDATE casework_task_templates SET active=false WHERE active",
            &[],
        )
        .await?;
    for template in templates {
        transaction.execute("UPDATE casework_task_templates SET active=true WHERE template_id=$1 AND template_version=$2", &[&template.id,&template.version]).await?;
    }
    let review_rows = transaction
        .query(
            "SELECT g.grant_id,g.record
             FROM casework_review_task_grants g
             WHERE g.invalidated_at IS NULL AND g.expires_at>now()
             ORDER BY g.task_id,g.grant_id
             FOR UPDATE OF g",
            &[],
        )
        .await?;
    for row in review_rows {
        let id = row.get("grant_id");
        let grant: ReviewTaskGrant = serde_json::from_value(row.get("record"))?;
        if templates.iter().any(|template| {
            template.id == grant.template.id
                && template.version == grant.template.version
                && template_digest(template).ok().as_ref() == Some(&grant.template_digest)
        }) {
            continue;
        }
        let first_invalidation = transaction
            .execute(
                "UPDATE casework_review_task_grants
                 SET invalidated_at=now(),invalidation_reason='template'
                 WHERE grant_id=$1 AND invalidated_at IS NULL",
                &[&id],
            )
            .await?
            == 1;
        if first_invalidation {
            review_grant_event(
                transaction,
                audit,
                &grant,
                id,
                "task-grant-invalidated",
                Some("template"),
                None,
            )
            .await?;
        }
    }
    Ok(())
}

impl PostgresStore {
    /// Activate the configured template versions in a transaction of their
    /// own. Package activation runs [`activate_task_templates_in`] inside its
    /// activation transaction instead.
    #[cfg(all(test, feature = "postgres-test"))]
    pub(crate) async fn activate_task_templates(
        &self,
        templates: &[TaskTemplate],
    ) -> Result<(), StoreError> {
        let mut audit = self.begin_background_audit().await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        activate_task_templates_in(&transaction, &mut audit, templates).await?;
        audit.commit(transaction).await?;
        Ok(())
    }

    /// The directory snapshot and grant invalidation are serialized with all
    /// directory mutations. Once invalidated, later re-eligibility cannot revive it.
    async fn review_task_grant_eligible(
        transaction: &Transaction<'_>,
        actor: &ActorContext,
        task_id: Uuid,
        template: &TaskTemplate,
        expected_revision: Option<i64>,
    ) -> Result<Option<(Uuid, i64, registry_casework_core::SubjectBinding, i64)>, StoreError> {
        let Some(kind) = membership_kind(actor.role) else {
            return Ok(None);
        };
        let row = transaction
            .query_opt(
                "SELECT t.request_id,t.revision,r.subject_source,r.subject_type,r.subject_id,
                        r.subject_version,r.subject_digest,t.assignment_generation,r.policy_snapshot
                 FROM casework_review_tasks t
                 JOIN casework_review_requests r ON r.request_id=t.request_id
                 JOIN casework_queue_service q ON q.queue_id=t.queue_id
                 JOIN casework_memberships m ON m.team_id=q.team_id
                 WHERE t.task_id=$1 AND t.state='claimed'
                   AND r.lifecycle='reviewing' AND t.stage_index=r.active_stage_index
                   AND t.holder_issuer=$2 AND t.holder_subject=$3
                   AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind=$4
                   AND m.team_id=ANY($5) AND $6=ANY($7)
                   AND ((r.policy_snapshot->'stages'->t.stage_index->'decidingProfiles') ? $6)
                   AND r.policy_id=ANY($8)
                   AND ($9::bigint IS NULL OR t.revision=$9)
                   AND r.subject_source=$10
                 FOR KEY SHARE OF t,r,q,m",
                &[
                    &task_id,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &kind,
                    &template.eligible_teams,
                    &actor.profile_id,
                    &template.eligible_profiles,
                    &template.review_policies,
                    &expected_revision,
                    &template.source,
                ],
            )
            .await?;
        let Some(row) = row else { return Ok(None) };
        let pinned: registry_casework_core::ReviewPolicyClosure =
            serde_json::from_value(row.get(8))?;
        pinned.verify().map_err(|_| StoreError::Corrupt)?;
        if !pinned
            .dependencies
            .task_templates
            .iter()
            .any(|candidate| template_digest(candidate).ok() == template_digest(template).ok())
        {
            return Ok(None);
        }
        Ok(Some((
            row.get(0),
            row.get(1),
            registry_casework_core::SubjectBinding {
                source: row.get(2),
                subject_type: row.get(3),
                id: row.get(4),
                version: row.get(5),
                digest: ContentDigest::parse(&row.get::<_, String>(6))
                    .map_err(|_| StoreError::Corrupt)?,
            },
            row.get(7),
        )))
    }

    pub(crate) async fn eligible_review_task_template(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        template: &TaskTemplate,
    ) -> Result<Option<(Uuid, i64, registry_casework_core::SubjectBinding, i64)>, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
                &[],
            )
            .await?;
        let eligible = if template_active(&transaction, template).await? {
            Self::review_task_grant_eligible(&transaction, actor, task_id, template, None).await?
        } else {
            None
        };
        transaction.commit().await?;
        Ok(eligible)
    }

    pub(crate) async fn approve_review_task_grant(
        &self,
        actor: &ActorContext,
        key: &str,
        grant: ReviewTaskGrant,
    ) -> Result<StoredReviewTaskGrant, StoreError> {
        if key.is_empty() || key.len() > 256 {
            return Err(StoreError::Invalid);
        }
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "task-grant-approved",
                Some(actor),
                &actor.profile_id,
                json!({"grantId": grant.id}),
            ))
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
                &[],
            )
            .await?;
        transaction
            .query_opt(
                "SELECT 1 FROM casework_review_tasks WHERE task_id=$1 FOR UPDATE",
                &[&grant.task_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        if !template_active(&transaction, &grant.template).await? {
            return Err(StoreError::Forbidden);
        }
        // The revision-agnostic eligibility call confirms the caller's current
        // authority without binding it to the retry's original revision.
        let Some((request_id, revision, subject, assignment_generation)) =
            Self::review_task_grant_eligible(
                &transaction,
                actor,
                grant.task_id,
                &grant.template,
                None,
            )
            .await?
        else {
            return Err(StoreError::Forbidden);
        };
        let mut request = json!({
            "reviewTaskId": grant.task_id,
            "reviewRequestId": grant.request_id,
            "taskRevision": grant.task_revision,
            "holder": grant.holder,
            "templateDigest": grant.template_digest,
            "subject": grant.subject,
            "subjects": grant.subjects,
            "sourceIssuer": grant.source_issuer,
        });
        if let Some(generation) = grant.assignment_generation {
            request["assignmentGeneration"] = json!(generation);
        }
        let hash = Sha256::digest(serde_json::to_vec(&request)?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        // A stored response is returned before the revision check so an
        // approval whose response was lost stays recoverable after an
        // intervening draft save advanced the task revision; the hash covers
        // every field the comparison below would check.
        if let Some(previous) = transaction
            .query_opt(
                "SELECT request_hash,record,invalidated_at IS NOT NULL
                 FROM casework_review_task_grants
                 WHERE task_id=$1 AND holder_issuer=$2 AND holder_subject=$3
                   AND approver_profile=$4 AND idempotency_key=$5",
                &[
                    &grant.task_id,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &actor.profile_id,
                    &key,
                ],
            )
            .await?
        {
            if previous.get::<_, String>(0) != hash {
                return Err(StoreError::IdempotencyConflict);
            }
            let stored = StoredReviewTaskGrant {
                grant: serde_json::from_value(previous.get(1))?,
                invalidated: previous.get(2),
            };
            audit.record_outcome(crate::audit::AuditOutcome::Replayed);
            audit.commit(transaction).await?;
            return Ok(stored);
        }
        if request_id != grant.request_id
            || revision != grant.task_revision
            || (!grant.template.authorization_mode.is_immediate()
                && grant.assignment_generation != Some(assignment_generation))
            || subject != grant.subject
            || grant.holder != actor.principal
            || template_digest(&grant.template)? != grant.template_digest
        {
            return Err(StoreError::Conflict);
        }
        let count: i64 = transaction
            .query_one(
                "SELECT count(*) FROM casework_review_task_grants WHERE task_id=$1",
                &[&grant.task_id],
            )
            .await?
            .get(0);
        if count >= 128 {
            return Err(StoreError::Invalid);
        }
        let approved = DateTime::from_timestamp(
            i64::try_from(grant.approved_at).map_err(|_| StoreError::Invalid)?,
            0,
        )
        .ok_or(StoreError::Invalid)?;
        let expires = DateTime::from_timestamp(
            i64::try_from(grant.expires_at).map_err(|_| StoreError::Invalid)?,
            0,
        )
        .ok_or(StoreError::Invalid)?;
        let record = serde_json::to_value(&grant)?;
        if serde_json::to_vec(&record)?.len() > 65_536 {
            return Err(StoreError::Invalid);
        }
        let role = membership_kind(actor.role).ok_or(StoreError::Forbidden)?;
        transaction
            .execute(
                "INSERT INTO casework_review_task_grants(
                    grant_id,task_id,request_id,task_revision,holder_issuer,holder_subject,
                    approver_profile,approver_role,idempotency_key,request_hash,record,
                    approved_at,expires_at)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
                &[
                    &grant.id,
                    &grant.task_id,
                    &grant.request_id,
                    &grant.task_revision,
                    &grant.holder.issuer,
                    &grant.holder.subject,
                    &grant.approver_profile,
                    &role,
                    &key,
                    &hash,
                    &record,
                    &approved,
                    &expires,
                ],
            )
            .await?;
        // The approval is audited like later revocations and invalidations,
        // bound to the approving actor.
        review_grant_event(
            &transaction,
            &mut audit,
            &grant,
            grant.id,
            "task-grant-approved",
            None,
            Some(actor),
        )
        .await?;
        audit.commit(transaction).await?;
        Ok(StoredReviewTaskGrant {
            grant,
            invalidated: false,
        })
    }

    pub(crate) async fn review_task_grant(
        &self,
        id: Uuid,
    ) -> Result<StoredReviewTaskGrant, StoreError> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT record,invalidated_at IS NOT NULL
                 FROM casework_review_task_grants WHERE grant_id=$1",
                &[&id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        Ok(StoredReviewTaskGrant {
            grant: serde_json::from_value(row.get(0))?,
            invalidated: row.get(1),
        })
    }

    pub(crate) async fn review_task_grants_for_task(
        &self,
        task_id: Uuid,
    ) -> Result<Vec<StoredReviewTaskGrant>, StoreError> {
        let client = self.client().await?;
        client
            .query(
                "SELECT record,invalidated_at IS NOT NULL
                 FROM casework_review_task_grants WHERE task_id=$1
                 ORDER BY approved_at,grant_id LIMIT 128",
                &[&task_id],
            )
            .await?
            .into_iter()
            .map(|row| {
                Ok(StoredReviewTaskGrant {
                    grant: serde_json::from_value(row.get(0))?,
                    invalidated: row.get(1),
                })
            })
            .collect()
    }

    pub(crate) async fn check_review_task_grant_eligibility(
        &self,
        grant: &ReviewTaskGrant,
        template: &TaskTemplate,
        configured_approver_role: Option<CaseworkRole>,
    ) -> Result<bool, StoreError> {
        let role = self
            .client()
            .await?
            .query_opt(
                "SELECT approver_role FROM casework_review_task_grants WHERE grant_id=$1",
                &[&grant.id],
            )
            .await?
            .ok_or(StoreError::NotFound)?
            .get::<_, String>(0);
        let role = match role.as_str() {
            "staff" => CaseworkRole::Staff,
            "supervisor" => CaseworkRole::Supervisor,
            _ => return Err(StoreError::Corrupt),
        };
        let actor = ActorContext {
            principal: grant.holder.clone(),
            profile_id: grant.approver_profile.clone(),
            role,
        };
        let mut audit = self.begin_background_audit().await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
                &[],
            )
            .await?;
        let eligible = Some(role) == configured_approver_role
            && template_active(&transaction, template).await?
            && Self::review_task_grant_eligible(
                &transaction,
                &actor,
                grant.task_id,
                template,
                if template.authorization_mode.is_immediate() {
                    Some(grant.task_revision)
                } else {
                    None
                },
            )
            .await?
            .is_some_and(|(_, _, subject, generation)| {
                subject == grant.subject
                    && (template.authorization_mode.is_immediate()
                        || grant.assignment_generation == Some(generation))
            })
            && template_digest(template)? == grant.template_digest;
        if !eligible {
            // The first eligibility invalidation is a loss of authority like
            // the template, source, and revocation paths, so it reaches the
            // same transactional history and audit events; a grant already
            // invalidated keeps its original reason.
            let first_invalidation = transaction
                .execute(
                    "UPDATE casework_review_task_grants
                     SET invalidated_at=now(),invalidation_reason='eligibility'
                     WHERE grant_id=$1 AND invalidated_at IS NULL",
                    &[&grant.id],
                )
                .await?
                == 1;
            if first_invalidation {
                review_grant_event(
                    &transaction,
                    &mut audit,
                    grant,
                    grant.id,
                    "task-grant-invalidated",
                    Some("eligibility"),
                    None,
                )
                .await?;
            }
        }
        let active = eligible
            && transaction
                .query_one(
                    "SELECT invalidated_at IS NULL AND expires_at>now()
                     FROM casework_review_task_grants WHERE grant_id=$1",
                    &[&grant.id],
                )
                .await?
                .get::<_, bool>(0);
        audit.commit(transaction).await?;
        Ok(active)
    }

    pub(crate) async fn invalidate_review_task_grant(
        &self,
        id: Uuid,
        reason: &str,
        actor: Option<&ActorContext>,
    ) -> Result<(), StoreError> {
        if !matches!(reason, "revoked" | "source" | "template") {
            return Err(StoreError::Invalid);
        }
        let mut audit = self
            .begin_audit_for(
                actor,
                if reason == "revoked" {
                    "task-grant-revoked"
                } else {
                    "task-grant-invalidated"
                },
                json!({"grantId": id}),
            )
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
                &[],
            )
            .await?;
        let row = transaction
            .query_opt(
                "SELECT record FROM casework_review_task_grants WHERE grant_id=$1 FOR UPDATE",
                &[&id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let grant: ReviewTaskGrant = serde_json::from_value(row.get(0))?;
        if let Some(actor) = actor {
            let Some(kind) = membership_kind(actor.role) else {
                return Err(StoreError::Forbidden);
            };
            if !template_active(&transaction, &grant.template).await?
                || !grant.template.eligible_profiles.contains(&actor.profile_id)
                || !transaction
                    .query_one(
                        "SELECT EXISTS(
                           SELECT 1 FROM casework_review_tasks t
                           JOIN casework_review_requests r ON r.request_id=t.request_id
                           JOIN casework_queue_service q ON q.queue_id=t.queue_id
                           JOIN casework_memberships m ON m.team_id=q.team_id
                           WHERE t.task_id=$1 AND t.request_id=$2
                             AND r.lifecycle='reviewing' AND t.stage_index=r.active_stage_index
                             AND m.issuer=$3 AND m.subject=$4 AND m.membership_kind=$5
                             AND m.team_id=ANY($6) AND $7=ANY($8)
                             AND ((r.policy_snapshot->'stages'->t.stage_index->'decidingProfiles') ? $7)
                             AND r.policy_id=ANY($9) AND r.subject_source=$10
                         )",
                        &[
                            &grant.task_id,
                            &grant.request_id,
                            &actor.principal.issuer,
                            &actor.principal.subject,
                            &kind,
                            &grant.template.eligible_teams,
                            &actor.profile_id,
                            &grant.template.eligible_profiles,
                            &grant.template.review_policies,
                            &grant.template.source,
                        ],
                    )
                    .await?
                    .get::<_, bool>(0)
            {
                return Err(StoreError::Forbidden);
            }
        }
        let first_invalidation = transaction
            .execute(
                "UPDATE casework_review_task_grants
                 SET invalidated_at=now(),
                     invalidation_reason=$2
                 WHERE grant_id=$1 AND invalidated_at IS NULL",
                &[&id, &reason],
            )
            .await?
            == 1;
        if first_invalidation {
            let kind = if reason == "revoked" {
                "task-grant-revoked"
            } else {
                "task-grant-invalidated"
            };
            review_grant_event(
                &transaction,
                &mut audit,
                &grant,
                id,
                kind,
                Some(reason),
                actor,
            )
            .await?;
        } else {
            // The grant was already invalidated, so no domain event is recorded.
            audit.record_outcome(crate::audit::AuditOutcome::Unchanged);
        }
        audit.commit(transaction).await?;
        Ok(())
    }
}

async fn review_grant_event(
    transaction: &Transaction<'_>,
    audit: &mut crate::audit::AuditOperation,
    grant: &ReviewTaskGrant,
    id: Uuid,
    kind: &str,
    reason: Option<&str>,
    actor: Option<&ActorContext>,
) -> Result<(), StoreError> {
    let event = Uuid::new_v4();
    let actor_ref = actor.map(|actor| crate::review::actor_reference(&actor.principal));
    let mut detail = json!({"grantId": id});
    if let Some(reason) = reason {
        detail["reason"] = json!(reason);
    }
    transaction
        .execute(
            "INSERT INTO casework_review_history(
                event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
             VALUES($1,$2,$3,$4,$5,$6,$7)",
            &[
                &event,
                &grant.request_id,
                &grant.task_id,
                &kind,
                &actor_ref,
                &detail,
                &Utc::now(),
            ],
        )
        .await?;
    let mut audit_record = json!({
        "event": format!("casework.{kind}"),
        "eventId": event,
        "reviewRequestId": grant.request_id,
        "reviewTaskId": grant.task_id,
        "grantId": id,
        "actor": actor.map(|actor| json!({
            "issuer": actor.principal.issuer,
            "subject": actor.principal.subject,
        })),
        "profileId": actor.map_or("system:task-grants", |actor| actor.profile_id.as_str()),
    });
    if let Some(reason) = reason {
        audit_record["reason"] = json!(reason);
    }
    audit.record(event, audit_record)
}

pub(crate) fn template_behavior(mut document: Value) -> Value {
    if let Some(fields) = document.as_object_mut() {
        fields.remove("label");
    }
    document
}
fn template_digest(template: &TaskTemplate) -> Result<ContentDigest, StoreError> {
    let bytes = registry_platform_canonical_json::canonicalize_json(&template_behavior(
        serde_json::to_value(template)?,
    ))
    .map_err(|_| StoreError::Invalid)?;
    Ok(ContentDigest::for_bytes(&bytes))
}

async fn template_active(
    transaction: &Transaction<'_>,
    template: &TaskTemplate,
) -> Result<bool, StoreError> {
    let document = serde_json::to_value(template)?;
    Ok(transaction.query_one("SELECT EXISTS(SELECT 1 FROM casework_task_templates WHERE active AND template_id=$1 AND template_version=$2 AND (document - 'label')=($3::jsonb - 'label'))", &[&template.id,&template.version,&document]).await?.get(0))
}

pub(crate) struct TaskAuthority {
    config: crate::TaskAuthorityConfig,
    key: registry_platform_crypto::PrivateJwk,
    identifiers: registry_platform_audit::AuditKeyHasher,
}
impl TaskAuthority {
    pub(crate) fn load(
        config: &crate::TaskAuthorityConfig,
        secrets: &registry_platform_config::SecretResolver,
        identifiers: registry_platform_audit::AuditKeyHasher,
    ) -> Result<Self, StoreError> {
        let secret = secrets
            .resolve(&config.signing_key_ref)
            .map_err(|_| StoreError::Configuration)?;
        let text =
            std::str::from_utf8(secret.expose_secret()).map_err(|_| StoreError::Configuration)?;
        let key = registry_platform_crypto::PrivateJwk::parse(text)
            .map_err(|_| StoreError::Configuration)?;
        if !matches!(key.alg.as_deref(), Some("ES256" | "RS256"))
            || key.kid.as_deref().is_none_or(str::is_empty)
        {
            return Err(StoreError::Configuration);
        }
        Ok(Self {
            config: config.clone(),
            key,
            identifiers,
        })
    }
    pub(crate) fn jwks(&self) -> Result<Value, StoreError> {
        Ok(json!({"keys":[self.key.public()]}))
    }
    fn approver_pseudonym(&self, approver: &IssuerPrincipal) -> Result<String, StoreError> {
        let approver =
            serde_json::to_string(&(approver.issuer.as_str(), approver.subject.as_str()))?;
        self.identifiers
            .audit_reference_hash("casework-principal-v1", "", &approver)
            .map_err(|_| StoreError::Invalid)
    }

    fn review_assertion(
        &self,
        grant: &ReviewTaskGrant,
        now: u64,
    ) -> Result<TaskAssertionResponse, StoreError> {
        self.assertion_for(
            grant.id,
            &grant.template,
            &grant.holder,
            &grant.subjects,
            grant.expires_at,
            now,
        )
    }
    fn assertion_for(
        &self,
        grant_id: Uuid,
        template: &TaskTemplate,
        approver_identity: &IssuerPrincipal,
        subjects: &std::collections::BTreeMap<String, Value>,
        grant_expires_at: u64,
        now: u64,
    ) -> Result<TaskAssertionResponse, StoreError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        if now >= grant_expires_at {
            return Err(StoreError::Forbidden);
        }
        // Evidence checks only the grant deadline and no grant status, so an
        // Evidence grant is never signed under the deferred window.
        if !template.authorization_mode.is_immediate()
            && matches!(
                template.bounds,
                registry_casework_core::TaskGrantBounds::Evidence { .. }
            )
        {
            return Err(StoreError::Forbidden);
        }
        let expires = grant_expires_at.min(
            now.checked_add(registry_casework_core::TASK_ASSERTION_LIFETIME_SECONDS)
                .ok_or(StoreError::Invalid)?,
        );
        let approver = self.approver_pseudonym(approver_identity)?;
        let mut payload = json!({"iss":self.config.issuer,"sub":template.agent.subject,"aud":self.config.exchange_audience,
            "iat":now,"nbf":now,"exp":expires,"jti":Uuid::new_v4(),"registry_actor_kind":"agent",
            "registry_grant_id":grant_id,
            "registry_grant_client":template.client,"registry_grant_resource":template.resource,
            "registry_purpose":template.purpose,"registry_grant_exp":grant_expires_at,
            "registry_grant_bounds":template.bounds,"registry_approver":approver,
            "scope":template.scopes.join(" "),"identity":subjects});
        if let Some(context) = &template.evidence_context {
            payload["evidence_tags"] = json!(context.requester_tags);
            payload["evidence_audience"] = json!(context.audience);
        }
        let header = json!({"alg":self.key.alg,"kid":self.key.kid,"typ":"JWT"});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?)
        );
        let signature = registry_platform_crypto::sign(input.as_bytes(), &self.key)
            .map_err(|_| StoreError::Unavailable)?;
        Ok(TaskAssertionResponse {
            assertion: format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)),
            expires_at: expires,
            grant_expires_at,
        })
    }
}

impl crate::CaseworkService {
    pub(crate) fn with_task_authority(mut self, authority: Option<TaskAuthority>) -> Self {
        self.task_authority = authority.map(std::sync::Arc::new);
        self
    }
    pub(crate) fn task_jwks(&self) -> Result<Value, crate::ServiceError> {
        self.task_authority
            .as_ref()
            .ok_or(crate::ServiceError::NotFound)?
            .jwks()
            .map_err(Into::into)
    }

    pub(crate) async fn preview_review_task_templates(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        source_profile: Option<&str>,
        token: &str,
    ) -> Result<TaskTemplatePreviews, crate::ServiceError> {
        let mut templates = Vec::new();
        let mut task_revision = None;
        if self.task_authority.is_none() {
            return Ok(TaskTemplatePreviews {
                task_revision: 0,
                templates,
            });
        }
        for template in self
            .project
            .task_templates
            .iter()
            .filter(|template| !template.review_policies.is_empty())
        {
            let Some((request_id, revision, subject, assignment_generation)) = self
                .store
                .eligible_review_task_template(actor, task_id, template)
                .await?
            else {
                continue;
            };
            let fields = template
                .subjects
                .values()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            self.preflight_review_grant_human(actor, task_id, source_profile, token)
                .await?;
            let values = self.review_grant_fields(task_id, revision, &fields).await?;
            let Ok(subjects) = template.disclosed_subjects(&values) else {
                continue;
            };
            let Some((
                current_request_id,
                current_revision,
                current_subject,
                current_assignment_generation,
            )) = self
                .store
                .eligible_review_task_template(actor, task_id, template)
                .await?
            else {
                continue;
            };
            if (
                current_request_id,
                current_revision,
                &current_subject,
                current_assignment_generation,
            ) != (request_id, revision, &subject, assignment_generation)
            {
                continue;
            }
            task_revision = Some(revision);
            templates.push(TaskTemplatePreview {
                id: template.id.clone(),
                version: template.version.clone(),
                label: template.label.clone(),
                agent: template.agent.clone(),
                client: template.client.clone(),
                resource: template.resource.clone(),
                scopes: template.scopes.clone(),
                purpose: template.purpose.clone(),
                bounds: template.bounds.clone(),
                evidence_context: template.evidence_context.clone(),
                subjects,
                authorization_mode: template.authorization_mode,
                lifetime_seconds: template.lifetime_seconds,
            });
        }
        Ok(TaskTemplatePreviews {
            task_revision: task_revision.unwrap_or(0),
            templates,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn approve_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        revision: i64,
        source_profile: Option<&str>,
        key: &str,
        token: &str,
        request: registry_casework_core::TaskApprovalRequest,
    ) -> Result<TaskGrantView, crate::ServiceError> {
        let authority = self
            .task_authority
            .as_ref()
            .ok_or(crate::ServiceError::Forbidden)?;
        let template = self
            .project
            .task_templates
            .iter()
            .find(|template| {
                !template.review_policies.is_empty()
                    && template.id == request.template_id
                    && template.version == request.template_version
            })
            .ok_or(crate::ServiceError::Forbidden)?;
        let Some((request_id, current_revision, subject, assignment_generation)) = self
            .store
            .eligible_review_task_template(actor, task_id, template)
            .await?
        else {
            return Err(crate::ServiceError::Forbidden);
        };
        if current_revision != revision {
            return Err(StoreError::Conflict.into());
        }
        self.preflight_review_grant_human(actor, task_id, source_profile, token)
            .await?;
        let fields = template
            .subjects
            .values()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let values = self.review_grant_fields(task_id, revision, &fields).await?;
        let subjects = template
            .disclosed_subjects(&values)
            .map_err(|_| crate::ServiceError::Forbidden)?;
        let now = now_seconds()?;
        let grant = ReviewTaskGrant {
            id: Uuid::new_v4(),
            task_id,
            request_id,
            task_revision: revision,
            assignment_generation: (!template.authorization_mode.is_immediate())
                .then_some(assignment_generation),
            holder: actor.principal.clone(),
            template: template.clone(),
            template_digest: template_digest(template)?,
            source_issuer: authority.config.issuer.clone(),
            approver_profile: actor.profile_id.clone(),
            subject,
            subjects,
            approved_at: now,
            expires_at: now
                .checked_add(template.lifetime_seconds)
                .ok_or(StoreError::Invalid)?,
        };
        let stored = self
            .store
            .approve_review_task_grant(actor, key, grant)
            .await?;
        Ok(review_grant_view(&stored))
    }

    pub(crate) async fn list_review_task_grants(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        source_profile: Option<&str>,
        token: &str,
    ) -> Result<TaskGrantList, crate::ServiceError> {
        let previews = self
            .preview_review_task_templates(actor, task_id, source_profile, token)
            .await?;
        if previews.task_revision == 0 {
            return Err(crate::ServiceError::NotFound);
        }
        let grants = self.store.review_task_grants_for_task(task_id).await?;
        let mut eligible = false;
        for template in self
            .project
            .task_templates
            .iter()
            .filter(|template| !template.review_policies.is_empty())
        {
            if self
                .store
                .eligible_review_task_template(actor, task_id, template)
                .await?
                .is_some_and(|(_, revision, _, _)| revision == previews.task_revision)
            {
                eligible = true;
                break;
            }
        }
        if !eligible {
            return Err(crate::ServiceError::NotFound);
        }
        Ok(TaskGrantList {
            grants: grants.iter().map(review_grant_view).collect(),
        })
    }

    pub(crate) async fn revoke_review_task_grant(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        id: Uuid,
    ) -> Result<TaskGrantRevocation, crate::ServiceError> {
        let stored = self.store.review_task_grant(id).await?;
        if stored.grant.task_id != task_id {
            return Err(crate::ServiceError::NotFound);
        }
        self.store
            .invalidate_review_task_grant(id, "revoked", Some(actor))
            .await?;
        Ok(TaskGrantRevocation {
            id,
            invalidated: true,
        })
    }

    async fn active_review_task(
        &self,
        id: Uuid,
    ) -> Result<StoredReviewTaskGrant, crate::ServiceError> {
        let stored = self.store.review_task_grant(id).await?;
        if stored.invalidated || now_seconds()? >= stored.grant.expires_at {
            return Err(crate::ServiceError::Forbidden);
        }
        let grant = &stored.grant;
        let Some(template) = self.project.task_templates.iter().find(|template| {
            template_digest(template).ok().as_ref() == Some(&grant.template_digest)
                && !template.review_policies.is_empty()
        }) else {
            self.store
                .invalidate_review_task_grant(id, "template", None)
                .await?;
            return Err(crate::ServiceError::Forbidden);
        };
        let configured_approver_role = self
            .project
            .access_profiles
            .iter()
            .find(|profile| profile.id == grant.approver_profile)
            .map(|profile| profile.role);
        if !self
            .store
            .check_review_task_grant_eligibility(grant, template, configured_approver_role)
            .await?
        {
            return Err(crate::ServiceError::Forbidden);
        }
        let fields = template
            .subjects
            .values()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let context = self
            .review_grant_fields(grant.task_id, grant.task_revision, &fields)
            .await;
        let valid = match context {
            Ok(values) => template
                .disclosed_subjects(&values)
                .is_ok_and(|subjects| subjects == grant.subjects),
            Err(crate::ServiceError::Context(ReviewContextError::Unavailable)) => {
                return Err(crate::ServiceError::Context(
                    ReviewContextError::Unavailable,
                ))
            }
            Err(
                error @ crate::ServiceError::Store(
                    StoreError::Unavailable
                    | StoreError::AuditUnavailable
                    | StoreError::Postgres(_),
                ),
            ) => return Err(error),
            Err(_) => false,
        };
        if !valid {
            self.store
                .invalidate_review_task_grant(id, "source", None)
                .await?;
            return Err(crate::ServiceError::Forbidden);
        }
        if !self
            .store
            .check_review_task_grant_eligibility(grant, template, configured_approver_role)
            .await?
            || now_seconds()? >= grant.expires_at
        {
            return Err(crate::ServiceError::Forbidden);
        }
        Ok(stored)
    }
    pub(crate) async fn task_assertion(
        &self,
        id: Uuid,
        client: &registry_platform_oidc::VerifiedToken,
    ) -> Result<TaskAssertionResponse, crate::ServiceError> {
        let authority = self
            .task_authority
            .as_ref()
            .ok_or(crate::ServiceError::Forbidden)?;
        let stored = self.store.review_task_grant(id).await?;
        require_grant_client(client, &stored.grant.template)?;
        let stored = self.active_review_task(id).await?;
        authority
            .review_assertion(&stored.grant, now_seconds()?)
            .map_err(Into::into)
    }

    pub(crate) async fn task_status(
        &self,
        id: Uuid,
        client: &registry_platform_oidc::VerifiedToken,
    ) -> Result<TaskGrantStatus, crate::ServiceError> {
        let authority = self
            .task_authority
            .as_ref()
            .ok_or(crate::ServiceError::Forbidden)?;
        let client = client
            .matched_client_id()
            .ok()
            .flatten()
            .ok_or(crate::ServiceError::Forbidden)?;
        let resource = authority
            .config
            .status_clients
            .get(client)
            .ok_or(crate::ServiceError::Forbidden)?;
        let stored = self.store.review_task_grant(id).await?;
        if stored.grant.template.resource != *resource {
            return Err(crate::ServiceError::NotFound);
        }
        match self.active_review_task(id).await {
            Ok(stored) => Ok(active_grant_status(
                stored.grant.id,
                stored.grant.source_issuer,
                stored.grant.template,
                stored.grant.subjects,
                stored.grant.expires_at,
            )),
            Err(crate::ServiceError::Forbidden) => Ok(inactive_grant_status()),
            Err(error) => Err(error),
        }
    }
}

fn require_grant_client(
    client: &registry_platform_oidc::VerifiedToken,
    template: &TaskTemplate,
) -> Result<(), crate::ServiceError> {
    if client.matched_client_id().ok().flatten() != Some(template.client.as_str())
        || client.claims.sub.as_deref() != Some(template.agent.subject.as_str())
        || client.claims.iss.as_deref() != Some(template.agent.issuer.as_str())
    {
        return Err(crate::ServiceError::NotFound);
    }
    Ok(())
}

fn active_grant_status(
    id: Uuid,
    source_issuer: String,
    template: TaskTemplate,
    subjects: std::collections::BTreeMap<String, Value>,
    expires_at: u64,
) -> TaskGrantStatus {
    TaskGrantStatus {
        active: true,
        grant: Some(TaskGrantStatusDetails {
            grant_id: id,
            source_issuer,
            principal: template.agent.subject,
            client: template.client,
            resource: template.resource,
            purpose: template.purpose,
            bounds: template.bounds,
            subjects,
            expires_at,
        }),
    }
}

fn inactive_grant_status() -> TaskGrantStatus {
    TaskGrantStatus {
        active: false,
        grant: None,
    }
}
fn now_seconds() -> Result<u64, StoreError> {
    u64::try_from(Utc::now().timestamp()).map_err(|_| StoreError::Invalid)
}

fn review_grant_view(stored: &StoredReviewTaskGrant) -> TaskGrantView {
    TaskGrantView {
        id: stored.grant.id,
        template_id: stored.grant.template.id.clone(),
        template_version: stored.grant.template.version.clone(),
        agent: stored.grant.template.agent.clone(),
        client: stored.grant.template.client.clone(),
        resource: stored.grant.template.resource.clone(),
        scopes: stored.grant.template.scopes.clone(),
        purpose: stored.grant.template.purpose.clone(),
        bounds: stored.grant.template.bounds.clone(),
        evidence_context: stored.grant.template.evidence_context.clone(),
        authorization_mode: stored.grant.template.authorization_mode,
        expires_at: stored.grant.expires_at,
        invalidated: stored.invalidated,
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    #[test]
    fn governed_scheduling_bounds_are_the_platform_verifiers_wire_contract() {
        let bounds: TaskGrantBounds = serde_json::from_value(json!({
            "type":"scheduling",
            "permissions":[{
                "service":"registry-update",
                "location":"bangkok-counter",
                "actions":["appointment.create"]
            }]
        }))
        .unwrap();
        bounds.check().unwrap();

        let claims: registry_platform_oidc::Claims = serde_json::from_value(json!({
            "sub":"agent",
            "exp":2000,
            "registry_grant_id":"00000000-0000-4000-8000-000000000001",
            "registry_grant_source_issuer":"https://casework.test",
            "registry_grant_client":"scheduling-agent",
            "registry_grant_resource":"urn:test:scheduling",
            "registry_grant_exp":1900,
            "registry_grant_bounds":serde_json::to_value(bounds).unwrap(),
            "registry_purpose":"schedule-registry-update",
            "registry_approver":"approver-reference"
        }))
        .unwrap();
        let grant = registry_platform_oidc::grant_claims(
            &claims,
            &registry_platform_oidc::ClaimNames::default(),
            1000,
        )
        .unwrap()
        .unwrap();
        let permissions = grant.bounds().scheduling_permissions().unwrap();
        assert_eq!(permissions[0].service(), "registry-update");
        assert_eq!(permissions[0].location(), "bangkok-counter");
        assert_eq!(permissions[0].actions(), ["appointment.create"]);
    }
}

#[cfg(all(test, feature = "postgres-test"))]
mod dev_session_logs;
#[cfg(all(test, feature = "postgres-test"))]
mod http_tests;
#[cfg(all(test, feature = "postgres-test"))]
mod local_session_tests;
#[cfg(all(test, feature = "postgres-test"))]
mod native_exchange_tests;
#[cfg(all(test, feature = "postgres-test"))]
mod native_resource;
#[cfg(all(test, feature = "postgres-test"))]
mod tests;

#[cfg(test)]
mod evidence_assertion_tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use std::collections::BTreeMap;
    fn authority() -> TaskAuthority {
        let mut key = registry_platform_crypto::generate_private_jwk(
            registry_platform_crypto::GeneratedKeyAlgorithm::Rs384,
        )
        .unwrap();
        key.alg = Some("RS256".into());
        key.kid = Some("task-authority-test".into());
        TaskAuthority {
            config: crate::TaskAuthorityConfig {
                issuer: "https://casework.test".into(),
                exchange_audience: "https://issuer.test".into(),
                signing_key_ref: "secret:unused".into(),
                status_clients: BTreeMap::new(),
            },
            key,
            identifiers: registry_platform_audit::AuditKeyHasher::unkeyed_dev_only(),
        }
    }
    fn template() -> TaskTemplate {
        serde_json::from_value(json!({"id":"evidence-check","version":"1","label":"Check evidence","eligibleTeams":["team"],"eligibleProfiles":["staff"],"source":"notices","reviewPolicies":["notice-review"],"agent":{"issuer":"https://issuer.test","subject":"agent"},"client":"evidence-agent","resource":"urn:test:evidence","scopes":["evidence:invoke"],"purpose":"notice-eligibility","bounds":{"type":"evidence","requirement":"urn:test:requirement:adult"},"evidenceContext":{"requesterTags":["agency"],"audience":"https://relying.test/procedure"},"subjects":{"given_name":"given-name"},"lifetimeSeconds":900})).unwrap()
    }
    #[test]
    fn task_assertion_refuses_a_deferred_evidence_grant() {
        let authority = authority();
        let mut template = template();
        let holder = IssuerPrincipal {
            issuer: "https://people.test".into(),
            subject: "holder-canary".into(),
        };
        let fields = BTreeMap::from([("given_name".into(), json!("Person"))]);
        assert!(authority
            .assertion_for(Uuid::new_v4(), &template, &holder, &fields, 1000, 200)
            .is_ok());
        template.authorization_mode = registry_casework_core::TaskAuthorizationMode::Deferred;
        assert!(matches!(
            authority.assertion_for(Uuid::new_v4(), &template, &holder, &fields, 1000, 200),
            Err(StoreError::Forbidden)
        ));
    }
    #[test]
    fn assertions_keep_credentials_short_and_approver_identity_pseudonymous() {
        let authority = authority();
        let holder = IssuerPrincipal {
            issuer: "https://people.test".into(),
            subject: "holder-canary".into(),
        };
        let fields = BTreeMap::from([("given_name".into(), json!("Person"))]);
        let response = authority
            .assertion_for(Uuid::new_v4(), &template(), &holder, &fields, 1000, 200)
            .unwrap();
        assert_eq!(response.expires_at, 260);
        assert_eq!(response.grant_expires_at, 1000);
        let payload: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(response.assertion.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(payload["evidence_tags"], json!(["agency"]));
        assert_eq!(
            payload["evidence_audience"],
            "https://relying.test/procedure"
        );
        assert!(!payload.to_string().contains("holder-canary"));
        assert!(!payload.to_string().contains("https://people.test"));
        assert!(payload.get("registry_grant_authority").is_none());
        assert!(matches!(
            authority.assertion_for(Uuid::new_v4(), &template(), &holder, &fields, 200, 200),
            Err(StoreError::Forbidden)
        ));
    }
}
