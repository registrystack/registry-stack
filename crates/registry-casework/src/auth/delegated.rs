use super::*;

use registry_casework_core::{DelegatedCredentialContext, IssuerPrincipal};
use registry_platform_oidc::{Audience, ASSERTION_ISSUER_CLAIM};

/// One verified delegated staff reader. Its human actor is deliberately
/// private to this module so no general Casework operation can accept it.
pub(crate) struct DelegatedStaffReader {
    actor: ActorContext,
    policy_id: String,
    gateway: IssuerPrincipal,
    client: String,
    credential_context: DelegatedCredentialContext,
}

impl std::fmt::Debug for DelegatedStaffReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedStaffReader")
            .field("policy_id", &self.policy_id)
            .field("profile_id", &self.actor.profile_id)
            .field("principal", &"<redacted>")
            .field("gateway", &"<redacted>")
            .field("client", &"<redacted>")
            .finish()
    }
}

impl DelegatedStaffReader {
    #[cfg(test)]
    pub(super) fn principal_for_test(&self) -> &IssuerPrincipal {
        &self.actor.principal
    }

    fn holds(&self, task: &registry_casework_core::ReviewTask) -> bool {
        matches!(
            &task.state,
            registry_casework_core::ReviewTaskState::Held { holder }
                if holder == &self.actor.principal
        )
    }
}

impl crate::CaseworkService {
    pub(crate) async fn delegated_review_tasks(
        &self,
        reader: &DelegatedStaffReader,
        source_profile: Option<&str>,
        token: &str,
        cursor: Option<uuid::Uuid>,
        limit: usize,
    ) -> Result<registry_casework_core::ReviewTaskPage, crate::ReviewRuntimeError> {
        let audit = self
            .store
            .begin_audit(crate::audit::delegated_read_request_record(
                "delegated-review-tasks-read",
                &reader.actor,
                &reader.gateway,
                &reader.client,
                &reader.policy_id,
                serde_json::json!({}),
            ))
            .await?;
        let outcome = self
            .review_staffing_tasks_with_delegation(
                &reader.actor,
                source_profile,
                token,
                registry_casework_core::ReviewStaffingQuery {
                    cursor,
                    limit: Some(limit),
                    ownership: Some(registry_casework_core::ReviewTaskOwnership::AssignedToMe),
                    sort: registry_casework_core::ReviewTaskSort::Due,
                    ..Default::default()
                },
                Some(&reader.credential_context),
            )
            .await;
        let outcome = match outcome {
            Ok(page) => {
                let mut current = Ok(());
                for task in &page.items {
                    let recheck = self
                        .store
                        .review_task_by_activity(&reader.actor, task.task_id, true, false)
                        .await
                        .map(|latest| reader.holds(&latest) && latest.revision == task.revision);
                    if let Err(error) = delegated_recheck(recheck) {
                        current = Err(error);
                        break;
                    }
                }
                current.map(|()| page)
            }
            Err(error) => Err(error),
        };
        let terminal = match &outcome {
            Ok(_) => crate::audit::AuditOutcome::Succeeded,
            Err(crate::ReviewRuntimeError::Forbidden | crate::ReviewRuntimeError::NotFound) => {
                crate::audit::AuditOutcome::Refused
            }
            Err(_) => crate::audit::AuditOutcome::Failed,
        };
        audit.conclude_without_change(terminal).await?;
        outcome
    }

    pub(crate) async fn delegated_review_task_context(
        &self,
        reader: &DelegatedStaffReader,
        source_profile: Option<&str>,
        token: &str,
        task_id: uuid::Uuid,
    ) -> Result<registry_casework_core::ReviewTaskContext, crate::ReviewRuntimeError> {
        let audit = self
            .store
            .begin_audit(crate::audit::delegated_read_request_record(
                "delegated-review-task-context-read",
                &reader.actor,
                &reader.gateway,
                &reader.client,
                &reader.policy_id,
                serde_json::json!({"reviewTaskId": task_id}),
            ))
            .await?;
        let initial = self
            .store
            .review_task_by_activity(&reader.actor, task_id, true, false)
            .await;
        let outcome = match initial {
            Ok(task) if reader.holds(&task) => {
                let revision = task.revision;
                match self
                    .review_task_context_with_delegation(
                        &reader.actor,
                        task_id,
                        source_profile,
                        token,
                        Some(&reader.credential_context),
                    )
                    .await
                {
                    Ok(context) => delegated_recheck(
                        self.store
                            .review_task_by_activity(&reader.actor, task_id, true, false)
                            .await
                            .map(|current| reader.holds(&current) && current.revision == revision),
                    )
                    .map(|()| context),
                    Err(error) => Err(error),
                }
            }
            Ok(_) => Err(crate::ReviewRuntimeError::NotFound),
            Err(error) => Err(error),
        };
        let terminal = match &outcome {
            Ok(_) => crate::audit::AuditOutcome::Succeeded,
            Err(crate::ReviewRuntimeError::Forbidden | crate::ReviewRuntimeError::NotFound) => {
                crate::audit::AuditOutcome::Refused
            }
            Err(_) => crate::audit::AuditOutcome::Failed,
        };
        audit.conclude_without_change(terminal).await?;
        outcome
    }
}

fn delegated_recheck(
    outcome: Result<bool, crate::ReviewRuntimeError>,
) -> Result<(), crate::ReviewRuntimeError> {
    match outcome {
        Ok(true) => Ok(()),
        Ok(false)
        | Err(
            crate::ReviewRuntimeError::Forbidden
            | crate::ReviewRuntimeError::NotFound
            | crate::ReviewRuntimeError::ResultExpired,
        ) => Err(crate::ReviewRuntimeError::NotFound),
        Err(error) => Err(error),
    }
}

impl CaseworkAuthenticator {
    pub(crate) async fn authenticate_staff_read(
        &self,
        token: &str,
        policy_id: &str,
        source_profile: Option<&str>,
    ) -> Result<DelegatedStaffReader, AuthenticationError> {
        validate_compact_access_token(token).map_err(|_| {
            self.record_header_refusal();
            AuthenticationError::Refused
        })?;
        let verified = self.verifier.verify(token).await.map_err(|error| {
            registry_platform_oidc::log_authentication_refusal!(
                self.verifier,
                error.authentication_stage(),
                "Casework delegated staff authentication refused"
            );
            AuthenticationError::Refused
        })?;
        let binding = self
            .delegated_staff_readers
            .get(policy_id)
            .ok_or(AuthenticationError::Profile)?;
        let profile = self
            .profiles
            .get(&binding.profile)
            .filter(|profile| profile.role == CaseworkRole::Staff)
            .ok_or(AuthenticationError::Profile)?;
        if source_profile.is_some_and(|source| {
            !binding
                .source_profiles
                .iter()
                .any(|allowed| allowed == source)
        }) {
            return Err(AuthenticationError::Profile);
        }
        if verified
            .matched_client_id()
            .map_err(|_| AuthenticationError::Refused)?
            != Some(binding.client.as_str())
            || verified
                .claims
                .extra
                .get(ASSERTION_ISSUER_CLAIM)
                .and_then(Value::as_str)
                != Some(binding.assertion_issuer.as_str())
            || verified
                .claims
                .extra
                .keys()
                .any(|key| key.starts_with("registry_grant_"))
        {
            return Err(AuthenticationError::Refused);
        }
        let audience = match verified.claims.aud.as_ref() {
            Some(Audience::One(audience)) if audience == &self.audience => audience.clone(),
            Some(Audience::Many(audiences))
                if audiences.len() == 1 && audiences[0] == self.audience =>
            {
                audiences[0].clone()
            }
            _ => return Err(AuthenticationError::Refused),
        };
        let issuer = verified
            .claims
            .iss
            .as_deref()
            .filter(|issuer| *issuer == binding.actor_issuer)
            .ok_or(AuthenticationError::Refused)?;
        let subject = verified
            .claims
            .sub
            .as_deref()
            .filter(|subject| !subject.is_empty())
            .ok_or(AuthenticationError::Claims)?;
        let expires_at = match (verified.claims.iat, verified.claims.exp) {
            (Some(issued_at), Some(expires_at))
                if issued_at >= 0
                    && expires_at > issued_at
                    && u64::try_from(expires_at - issued_at).is_ok_and(|lifetime| {
                        lifetime <= binding.maximum_token_lifetime_seconds
                    }) =>
            {
                expires_at
            }
            _ => return Err(AuthenticationError::Refused),
        };
        let act = strict_actor(
            verified.claims.extra.get("act"),
            &binding.actor_issuer,
            &binding.actor_subject,
        )?;
        let actual_scopes = verified.scopes.iter().cloned().collect::<BTreeSet<_>>();
        let mut expected_scopes = profile
            .required_scopes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        expected_scopes.insert(binding.required_scope.clone());
        if actual_scopes != expected_scopes || actual_scopes.len() != verified.scopes.len() {
            return Err(AuthenticationError::Profile);
        }
        if verified
            .claims
            .extra
            .get(&self.human_identity.claim)
            .and_then(Value::as_str)
            != Some(self.human_identity.value.as_str())
        {
            return Err(AuthenticationError::NotHuman);
        }
        let principal = if profile.principal_claim == "sub" {
            Some(subject)
        } else {
            verified
                .claims
                .extra
                .get(&profile.principal_claim)
                .and_then(Value::as_str)
        }
        .filter(|value| !value.is_empty())
        .ok_or(AuthenticationError::Claims)?;
        Ok(DelegatedStaffReader {
            actor: ActorContext {
                principal: IssuerPrincipal {
                    issuer: issuer.to_owned(),
                    subject: principal.to_owned(),
                },
                profile_id: profile.id.clone(),
                role: CaseworkRole::Staff,
            },
            policy_id: policy_id.to_owned(),
            gateway: IssuerPrincipal {
                issuer: act.0,
                subject: act.1,
            },
            client: binding.client.clone(),
            credential_context: DelegatedCredentialContext::verified(
                issuer.to_owned(),
                subject.to_owned(),
                audience,
                expires_at,
            ),
        })
    }
}

fn strict_actor(
    value: Option<&Value>,
    expected_issuer: &str,
    expected_subject: &str,
) -> Result<(String, String), AuthenticationError> {
    let object = value
        .and_then(Value::as_object)
        .filter(|object| object.len() == 2)
        .ok_or(AuthenticationError::Refused)?;
    let issuer = object
        .get("iss")
        .and_then(Value::as_str)
        .filter(|value| *value == expected_issuer)
        .ok_or(AuthenticationError::Refused)?;
    let subject = object
        .get("sub")
        .and_then(Value::as_str)
        .filter(|value| *value == expected_subject)
        .ok_or(AuthenticationError::Refused)?;
    Ok((issuer.to_owned(), subject.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::delegated_recheck;
    use crate::{ReviewRuntimeError, StoreError};

    #[test]
    fn delegated_recheck_conceals_authority_changes_but_preserves_store_failures() {
        assert!(matches!(
            delegated_recheck(Ok(false)),
            Err(ReviewRuntimeError::NotFound)
        ));
        assert!(matches!(
            delegated_recheck(Err(ReviewRuntimeError::Forbidden)),
            Err(ReviewRuntimeError::NotFound)
        ));
        assert!(matches!(
            delegated_recheck(Err(ReviewRuntimeError::ResultExpired)),
            Err(ReviewRuntimeError::NotFound)
        ));
        assert!(matches!(
            delegated_recheck(Err(ReviewRuntimeError::Store(StoreError::Unavailable))),
            Err(ReviewRuntimeError::Store(StoreError::Unavailable))
        ));
    }
}
