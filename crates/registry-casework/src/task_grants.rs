//! Persisted task authority with immutable bounds and live eligibility checks.
use crate::{PostgresStore, StoreError};
use chrono::{DateTime, Utc};
use registry_casework_core::{
    ActorContext, CaseworkRole, TaskAssertionResponse, TaskGrant, TaskGrantList,
    TaskGrantRevocation, TaskGrantStatus, TaskGrantStatusDetails, TaskGrantView,
    TaskProposalIdentity, TaskTemplate, TaskTemplatePreview, TaskTemplatePreviews, WorkItem,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(crate) struct StoredTaskGrant {
    pub grant: TaskGrant,
    pub invalidated: bool,
}

async fn eligible(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
    item: &WorkItem,
    template: &TaskTemplate,
) -> Result<bool, StoreError> {
    if !matches!(actor.role, CaseworkRole::Staff | CaseworkRole::Supervisor)
        || !template.eligible_profiles.contains(&actor.profile_id)
        || item.holder.as_ref() != Some(&actor.principal)
        || !template.item_states.contains(&item.state)
        || item.subject.source_id != template.source
        || !template.item_kinds.contains(&item.subject.kind)
    {
        return Ok(false);
    }
    let row = transaction.query_one(
        "SELECT EXISTS(SELECT 1 FROM casework_memberships m JOIN casework_queue_service q ON q.team_id=m.team_id WHERE m.issuer=$1 AND m.subject=$2 AND m.membership_kind IN ('staff','supervisor') AND m.team_id=ANY($3) AND q.queue_id=$4)",
        &[&actor.principal.issuer, &actor.principal.subject, &template.eligible_teams, &item.queue_id],
    ).await?;
    Ok(row.get(0))
}

impl PostgresStore {
    /// Activate the configured immutable template versions under the same
    /// Directory lock used by approval and live eligibility checks.
    pub(crate) async fn activate_task_templates(
        &self,
        templates: &[TaskTemplate],
    ) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
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
                if row.get::<_,Value>(0) != document { return Err(StoreError::Configuration); }
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
        let rows = transaction.query("SELECT i.*,g.grant_id FROM casework_task_grants g JOIN casework_items i ON i.item_id=g.item_id WHERE g.invalidated_at IS NULL AND g.expires_at>now() AND NOT EXISTS(SELECT 1 FROM casework_task_templates t WHERE t.active AND t.document=g.record->'template') ORDER BY i.item_id,g.grant_id FOR UPDATE OF i", &[]).await?;
        for row in rows {
            let item = crate::store::row_to_item(&row)?;
            invalidate(&transaction, &item, row.get("grant_id"), "template", None).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn eligible_task_template(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        template: &TaskTemplate,
    ) -> Result<bool, StoreError> {
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
                "SELECT * FROM casework_items WHERE item_id=$1 AND erased_at IS NULL FOR SHARE",
                &[&item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let item = crate::store::row_to_item(&row)?;
        let allowed = template_active(&transaction, template).await?
            && eligible(&transaction, actor, &item, template).await?;
        transaction.commit().await?;
        Ok(allowed)
    }

    pub(crate) async fn approve_task_grant(
        &self,
        actor: &ActorContext,
        expected_revision: i64,
        key: &str,
        grant: TaskGrant,
    ) -> Result<StoredTaskGrant, StoreError> {
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
                "SELECT * FROM casework_items WHERE item_id=$1 AND erased_at IS NULL FOR UPDATE",
                &[&grant.item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let item = crate::store::row_to_item(&row)?;
        if !template_active(&transaction, &grant.template).await?
            || !eligible(&transaction, actor, &item, &grant.template).await?
        {
            return Err(StoreError::Forbidden);
        }
        if TaskProposalIdentity::from(&item.binding) != grant.proposal {
            return Err(StoreError::Conflict);
        }
        let request = json!({"item":grant.item_id,"template":grant.template,"proposal":grant.proposal,"subjects":grant.subjects,"authority":grant.authority,"sourceIssuer":grant.source_issuer});
        let hash = Sha256::digest(serde_json::to_vec(&request)?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if let Some(previous) = transaction.query_opt("SELECT request_hash,record,invalidated_at IS NOT NULL FROM casework_task_grants WHERE item_id=$1 AND approver_issuer=$2 AND approver_subject=$3 AND approver_profile=$4 AND idempotency_key=$5", &[&item.item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&key]).await? {
            if previous.get::<_,String>(0) != hash { return Err(StoreError::IdempotencyConflict); }
            return Ok(StoredTaskGrant { grant: serde_json::from_value(previous.get(1))?, invalidated: previous.get(2) });
        }
        if item.revision != expected_revision {
            return Err(StoreError::Conflict);
        }
        let count: i64 = transaction
            .query_one(
                "SELECT count(*) FROM casework_task_grants WHERE item_id=$1",
                &[&item.item_id],
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
        if serde_json::to_vec(&record)?.len() > 65536 {
            return Err(StoreError::Invalid);
        }
        transaction.execute("INSERT INTO casework_task_grants(grant_id,item_id,approver_issuer,approver_subject,approver_profile,idempotency_key,request_hash,record,approved_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", &[&grant.id,&item.item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&key,&hash,&record,&approved,&expires]).await?;
        task_event(&transaction, &item, "task_approved", Some(actor), grant.id).await?;
        transaction.commit().await?;
        Ok(StoredTaskGrant {
            grant,
            invalidated: false,
        })
    }

    pub(crate) async fn task_grant(&self, id: Uuid) -> Result<StoredTaskGrant, StoreError> {
        let client = self.client().await?;
        let row = client.query_opt("SELECT g.record,g.invalidated_at IS NOT NULL FROM casework_task_grants g JOIN casework_items i ON i.item_id=g.item_id WHERE g.grant_id=$1 AND i.erased_at IS NULL", &[&id]).await?.ok_or(StoreError::NotFound)?;
        Ok(StoredTaskGrant {
            grant: serde_json::from_value(row.get(0))?,
            invalidated: row.get(1),
        })
    }

    pub(crate) async fn task_grants_for_item(
        &self,
        item: Uuid,
    ) -> Result<Vec<StoredTaskGrant>, StoreError> {
        let client = self.client().await?;
        client.query("SELECT g.record,g.invalidated_at IS NOT NULL FROM casework_task_grants g JOIN casework_items i ON i.item_id=g.item_id WHERE g.item_id=$1 AND i.erased_at IS NULL ORDER BY g.approved_at,g.grant_id LIMIT 128", &[&item]).await?.into_iter().map(|row| Ok(StoredTaskGrant { grant:serde_json::from_value(row.get(0))?, invalidated:row.get(1) })).collect()
    }

    /// The directory snapshot and grant invalidation are serialized with all
    /// directory mutations. Once invalidated, later re-eligibility cannot revive it.
    pub(crate) async fn check_task_eligibility(
        &self,
        grant: &TaskGrant,
        template: &TaskTemplate,
    ) -> Result<bool, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
                &[],
            )
            .await?;
        let Some(row) = transaction
            .query_opt(
                "SELECT * FROM casework_items WHERE item_id=$1 AND erased_at IS NULL FOR UPDATE",
                &[&grant.item_id],
            )
            .await?
        else {
            return Ok(false);
        };
        let item = crate::store::row_to_item(&row)?;
        let actor = ActorContext {
            principal: grant.approver.clone(),
            profile_id: grant.approver_profile.clone(),
            role: CaseworkRole::Staff,
        };
        let valid = template_active(&transaction, template).await?
            && eligible(&transaction, &actor, &item, template).await?
            && TaskProposalIdentity::from(&item.binding) == grant.proposal;
        if !valid {
            invalidate(&transaction, &item, grant.id, "eligibility", None).await?;
        }
        let row = transaction
            .query_opt(
                "SELECT invalidated_at IS NULL FROM casework_task_grants WHERE grant_id=$1",
                &[&grant.id],
            )
            .await?;
        let active = valid && row.is_some_and(|row| row.get::<_, bool>(0));
        transaction.commit().await?;
        Ok(active)
    }

    pub(crate) async fn invalidate_task_grant(
        &self,
        id: Uuid,
        reason: &'static str,
        actor: Option<&ActorContext>,
    ) -> Result<(), StoreError> {
        if !matches!(reason, "revoked" | "eligibility" | "template" | "source") {
            return Err(StoreError::Invalid);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
                &[],
            )
            .await?;
        let row=transaction.query_opt("SELECT i.* FROM casework_items i JOIN casework_task_grants g ON g.item_id=i.item_id WHERE g.grant_id=$1 AND i.erased_at IS NULL FOR UPDATE OF i", &[&id]).await?.ok_or(StoreError::NotFound)?;
        let item = crate::store::row_to_item(&row)?;
        if let Some(actor) = actor {
            let record: Value = transaction
                .query_one(
                    "SELECT record FROM casework_task_grants WHERE grant_id=$1",
                    &[&id],
                )
                .await?
                .get(0);
            let grant: TaskGrant = serde_json::from_value(record)?;
            if !eligible(&transaction, actor, &item, &grant.template).await? {
                return Err(StoreError::Forbidden);
            }
        }
        invalidate(&transaction, &item, id, reason, actor).await?;
        transaction.commit().await?;
        Ok(())
    }
}

async fn template_active(
    transaction: &Transaction<'_>,
    template: &TaskTemplate,
) -> Result<bool, StoreError> {
    let document = serde_json::to_value(template)?;
    Ok(transaction.query_one("SELECT EXISTS(SELECT 1 FROM casework_task_templates WHERE active AND template_id=$1 AND template_version=$2 AND document=$3)", &[&template.id,&template.version,&document]).await?.get(0))
}

async fn invalidate(
    transaction: &Transaction<'_>,
    item: &WorkItem,
    id: Uuid,
    reason: &str,
    actor: Option<&ActorContext>,
) -> Result<(), StoreError> {
    if transaction.execute("UPDATE casework_task_grants SET invalidated_at=now(),invalidation_reason=$2 WHERE grant_id=$1 AND invalidated_at IS NULL", &[&id,&reason]).await? == 1 {
        task_event(transaction,item,if reason=="revoked" {"task_revoked"} else {"task_invalidated"},actor,id).await?;
    }
    Ok(())
}
async fn task_event(
    transaction: &Transaction<'_>,
    item: &WorkItem,
    kind: &str,
    actor: Option<&ActorContext>,
    grant: Uuid,
) -> Result<(), StoreError> {
    let event = Uuid::new_v4();
    let now = Utc::now();
    let issuer = actor.map(|actor| &actor.principal.issuer);
    let subject = actor.map(|actor| &actor.principal.subject);
    let profile = actor.map_or("system:task-grants", |actor| actor.profile_id.as_str());
    let detail = json!({"grantId":grant});
    transaction.execute("INSERT INTO casework_history(event_id,item_id,item_revision,kind,occurred_at,actor_issuer,actor_subject,profile_id,detail) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", &[&event,&item.item_id,&item.revision,&kind,&now,&issuer,&subject,&profile,&detail]).await?;
    transaction.execute("INSERT INTO casework_audit_outbox(event_id,audit_record) VALUES($1,$2)", &[&event,&json!({"event":format!("casework.{kind}"),"eventId":event,"itemId":item.item_id,"actor":actor.map(|actor|json!({"issuer":actor.principal.issuer,"subject":actor.principal.subject})),"grantId":grant,"profileId":profile})]).await?;
    Ok(())
}

pub(crate) struct TaskAuthority {
    config: crate::TaskAuthorityConfig,
    key: registry_platform_crypto::PrivateJwk,
}
impl TaskAuthority {
    pub(crate) fn load(
        config: &crate::TaskAuthorityConfig,
        secrets: &registry_platform_config::SecretResolver,
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
        })
    }
    pub(crate) fn jwks(&self) -> Result<Value, StoreError> {
        Ok(json!({"keys":[self.key.public()]}))
    }
    fn assertion(&self, grant: &TaskGrant, now: u64) -> Result<TaskAssertionResponse, StoreError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        if now >= grant.expires_at {
            return Err(StoreError::Forbidden);
        }
        let expires = grant.expires_at.min(
            now.checked_add(registry_casework_core::TASK_ASSERTION_LIFETIME_SECONDS)
                .ok_or(StoreError::Invalid)?,
        );
        let payload = json!({"iss":self.config.issuer,"sub":grant.template.agent.subject,"aud":self.config.exchange_audience,
            "iat":now,"nbf":now,"exp":expires,"jti":Uuid::new_v4(),"registry_actor_kind":"agent",
            "registry_grant_id":grant.id,"registry_grant_authority":grant.authority,"registry_grant_source_issuer":grant.source_issuer,
            "registry_grant_client":grant.template.client,"registry_grant_resource":grant.template.resource,
            "registry_purpose":grant.template.purpose,"registry_grant_exp":grant.expires_at,
            "registry_grant_bounds":grant.template.bounds,"scope":grant.template.scopes.join(" "),"identity":grant.subjects});
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
            grant_expires_at: grant.expires_at,
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
    pub(crate) async fn preview_tasks(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        source_profile: &str,
        token: &str,
    ) -> Result<TaskTemplatePreviews, crate::ServiceError> {
        let (item, _) = self
            .caller_item(actor, item_id, source_profile, token)
            .await?;
        let mut templates = Vec::new();
        if self.task_authority.is_none() {
            return Ok(TaskTemplatePreviews {
                item_revision: item.revision,
                templates,
            });
        }
        for template in &self.project.task_templates {
            if !self
                .store
                .eligible_task_template(actor, item_id, template)
                .await?
            {
                continue;
            }
            let fields = template.subjects.values().cloned().collect::<Vec<_>>();
            let context = match self
                .adapter(&item.subject.source_id)?
                .read_task_context(
                    &item.subject,
                    &fields,
                    Some((
                        source_profile,
                        registry_casework_core::EphemeralCredential::new(token),
                    )),
                )
                .await
            {
                Ok(context) => context,
                Err(
                    registry_casework_core::SourceAdapterError::Denied
                    | registry_casework_core::SourceAdapterError::Concealed,
                ) => continue,
                Err(error) => return Err(error.into()),
            };
            if context.binding != item.binding {
                return Err(StoreError::Conflict.into());
            }
            let Ok(subjects) = template.disclosed_subjects(&context.values) else {
                continue;
            };
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
                subjects,
                lifetime_seconds: template.lifetime_seconds,
            });
        }
        Ok(TaskTemplatePreviews {
            item_revision: item.revision,
            templates,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn approve_task(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        revision: i64,
        source_profile: &str,
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
                template.id == request.template_id && template.version == request.template_version
            })
            .ok_or(crate::ServiceError::Forbidden)?;
        let (item, _) = self
            .caller_item(actor, item_id, source_profile, token)
            .await?;
        if item.revision != revision || item.holder.as_ref() != Some(&actor.principal) {
            return Err(crate::ServiceError::Forbidden);
        }
        if !self
            .store
            .eligible_task_template(actor, item_id, template)
            .await?
        {
            return Err(crate::ServiceError::Forbidden);
        }
        let fields = template.subjects.values().cloned().collect::<Vec<_>>();
        let context = self
            .adapter(&item.subject.source_id)?
            .read_task_context(
                &item.subject,
                &fields,
                Some((
                    source_profile,
                    registry_casework_core::EphemeralCredential::new(token),
                )),
            )
            .await?;
        if context.binding != item.binding {
            return Err(StoreError::Conflict.into());
        }
        let subjects = template
            .disclosed_subjects(&context.values)
            .map_err(|_| crate::ServiceError::Forbidden)?;
        let now = now_seconds()?;
        let grant = TaskGrant {
            id: Uuid::new_v4(),
            item_id,
            template: template.clone(),
            authority: authority.config.id.clone(),
            source_issuer: authority.config.issuer.clone(),
            approver: actor.principal.clone(),
            approver_profile: actor.profile_id.clone(),
            source_subject: item.subject.clone(),
            proposal: TaskProposalIdentity::from(&context.binding),
            subjects,
            approved_at: now,
            expires_at: now
                .checked_add(template.lifetime_seconds)
                .ok_or(StoreError::Invalid)?,
        };
        let stored = self
            .store
            .approve_task_grant(actor, revision, key, grant)
            .await?;
        Ok(grant_view(&stored))
    }
    pub(crate) async fn list_tasks(
        &self,
        actor: &ActorContext,
        item: Uuid,
        profile: &str,
        token: &str,
    ) -> Result<TaskGrantList, crate::ServiceError> {
        self.caller_item(actor, item, profile, token).await?;
        let grants = self.store.task_grants_for_item(item).await?;
        Ok(TaskGrantList {
            grants: grants.iter().map(grant_view).collect(),
        })
    }
    pub(crate) async fn revoke_task(
        &self,
        actor: &ActorContext,
        item: Uuid,
        id: Uuid,
        profile: &str,
        token: &str,
    ) -> Result<TaskGrantRevocation, crate::ServiceError> {
        self.caller_item(actor, item, profile, token).await?;
        let stored = self.store.task_grant(id).await?;
        if stored.grant.item_id != item {
            return Err(crate::ServiceError::NotFound);
        }
        self.store
            .invalidate_task_grant(id, "revoked", Some(actor))
            .await?;
        Ok(TaskGrantRevocation {
            id,
            invalidated: true,
        })
    }
    async fn active_task(&self, id: Uuid) -> Result<StoredTaskGrant, crate::ServiceError> {
        let stored = self.store.task_grant(id).await?;
        if stored.invalidated || now_seconds()? >= stored.grant.expires_at {
            return Err(crate::ServiceError::Forbidden);
        }
        let grant = &stored.grant;
        let Some(template) = self
            .project
            .task_templates
            .iter()
            .find(|template| **template == grant.template)
        else {
            self.store
                .invalidate_task_grant(id, "template", None)
                .await?;
            return Err(crate::ServiceError::Forbidden);
        };
        if !self.store.check_task_eligibility(grant, template).await? {
            return Err(crate::ServiceError::Forbidden);
        }
        let fields = template.subjects.values().cloned().collect::<Vec<_>>();
        let context = self
            .adapter(&grant.source_subject.source_id)?
            .read_task_context(&grant.source_subject, &fields, None)
            .await;
        let valid = match context {
            Ok(context) => {
                TaskProposalIdentity::from(&context.binding) == grant.proposal
                    && template
                        .disclosed_subjects(&context.values)
                        .is_ok_and(|subjects| subjects == grant.subjects)
            }
            Err(
                registry_casework_core::SourceAdapterError::Concealed
                | registry_casework_core::SourceAdapterError::Denied
                | registry_casework_core::SourceAdapterError::BindingMoved
                | registry_casework_core::SourceAdapterError::DefinitiveRefusal,
            ) => false,
            Err(error) => return Err(error.into()),
        };
        if !valid {
            self.store.invalidate_task_grant(id, "source", None).await?;
            return Err(crate::ServiceError::Forbidden);
        }
        // Recheck after source I/O so revocation during the read cannot release an assertion.
        if !self.store.check_task_eligibility(grant, template).await?
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
        let stored = self.store.task_grant(id).await?;
        if client.matched_client_id().ok().flatten() != Some(stored.grant.template.client.as_str())
            || client.claims.sub.as_deref() != Some(stored.grant.template.agent.subject.as_str())
            || client.claims.iss.as_deref() != Some(stored.grant.template.agent.issuer.as_str())
        {
            return Err(crate::ServiceError::NotFound);
        }
        let stored = self.active_task(id).await?;
        self.task_authority
            .as_ref()
            .ok_or(crate::ServiceError::Forbidden)?
            .assertion(&stored.grant, now_seconds()?)
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
        let stored = self.store.task_grant(id).await?;
        if stored.grant.template.resource != *resource {
            return Err(crate::ServiceError::NotFound);
        }
        match self.active_task(id).await {
            Ok(stored) => Ok(TaskGrantStatus {
                active: true,
                grant: Some(TaskGrantStatusDetails {
                    grant_id: stored.grant.id,
                    authority: stored.grant.authority,
                    source_issuer: stored.grant.source_issuer,
                    principal: stored.grant.template.agent.subject,
                    client: stored.grant.template.client,
                    resource: stored.grant.template.resource,
                    purpose: stored.grant.template.purpose,
                    bounds: stored.grant.template.bounds,
                    subjects: stored.grant.subjects,
                    expires_at: stored.grant.expires_at,
                }),
            }),
            Err(crate::ServiceError::Forbidden) => Ok(TaskGrantStatus {
                active: false,
                grant: None,
            }),
            Err(error) => Err(error),
        }
    }
}
fn now_seconds() -> Result<u64, StoreError> {
    u64::try_from(Utc::now().timestamp()).map_err(|_| StoreError::Invalid)
}
fn grant_view(stored: &StoredTaskGrant) -> TaskGrantView {
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
        expires_at: stored.grant.expires_at,
        invalidated: stored.invalidated,
    }
}

#[cfg(all(test, feature = "postgres-test"))]
mod tests;

#[cfg(all(test, feature = "postgres-test"))]
mod http_tests;

#[cfg(all(test, feature = "postgres-test"))]
mod native_exchange_tests;
