//! Activation preserves accepted policy closures and refuses orphaned open reviews.
use crate::{PostgresStore, StoreError};
use registry_casework_core::{
    CaseworkProject, ClockPolicy, ReviewContextPolicy, ReviewContextProvider, ReviewPolicyClosure,
};
use serde::Serialize;
use std::collections::BTreeSet;
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(extend("additionalProperties" = false)))]
#[serde(rename_all = "camelCase")]
pub struct StrandedWork {
    pub policy: String,
    pub version: String,
    pub reviews: u64,
    pub reason: String,
}
impl StrandedWork {
    pub fn describe(&self) -> String {
        format!(
            "{} open review(s) of policy {} version {}: {}",
            self.reviews, self.policy, self.version, self.reason
        )
    }
}
pub fn describe_stranded_work(items: &[StrandedWork]) -> String {
    items
        .iter()
        .map(StrandedWork::describe)
        .collect::<Vec<_>>()
        .join("; ")
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinnedWorkVerdict {
    Clear,
    Refused,
}
pub fn pinned_work_verdict(items: &[StrandedWork], _digest: &str) -> PinnedWorkVerdict {
    if items.is_empty() {
        PinnedWorkVerdict::Clear
    } else {
        PinnedWorkVerdict::Refused
    }
}
pub fn stranded_work_refusal(items: &[StrandedWork], _digest: &str) -> String {
    format!("the package would orphan pinned reviews: {}. Keep the prior package until these reviews finish, or cancel them through their bound producer before activation",describe_stranded_work(items))
}
#[derive(Clone, Debug)]
pub(crate) struct PinnedReviewGroup {
    pub policy: ReviewPolicyClosure,
    pub producer_id: String,
    pub source_namespace: String,
    pub active_stage_index: usize,
    pub reviews: u64,
}
#[derive(Default)]
pub(crate) struct PinnedWorkInventory {
    pub reviews: Vec<PinnedReviewGroup>,
}
pub async fn stranded_pinned_work(
    store: &PostgresStore,
    project: &CaseworkProject,
    providers: &[&dyn ReviewContextProvider],
) -> Result<Vec<StrandedWork>, StoreError> {
    let mut c = store.client().await?;
    let tx = c.transaction().await?;
    let i = crate::store::pinned_work_inventory_in(&tx).await?;
    Ok(compare_pinned_work(project, providers, &i))
}
pub(crate) fn compare_pinned_work(
    project: &CaseworkProject,
    providers: &[&dyn ReviewContextProvider],
    inventory: &PinnedWorkInventory,
) -> Vec<StrandedWork> {
    let queues: BTreeSet<_> = project.queues.iter().map(|q| q.id.as_str()).collect();
    let mut conflicts = Vec::new();
    for group in &inventory.reviews {
        let mut reasons = BTreeSet::new();
        if group.policy.verify().is_err() {
            reasons.insert("the retained policy closure cannot be verified".to_owned());
        }
        for stage in group.policy.stages.iter().skip(group.active_stage_index) {
            if !queues.contains(stage.queue.as_str()) {
                reasons.insert(format!("queue {} is removed", stage.queue));
            }
            for id in &stage.deciding_profiles {
                if !project
                    .access_profiles
                    .iter()
                    .any(|profile| profile.id == *id)
                {
                    reasons.insert("a required reviewer profile is removed".to_owned());
                } else if !profile_preserved(project, &group.policy, id) {
                    reasons.insert("a required reviewer profile authority changed".to_owned());
                }
            }
        }
        for rule in &group.policy.routing {
            if !queues.contains(rule.queue.as_str()) {
                reasons.insert(format!("routing queue {} is removed", rule.queue));
            }
        }
        for clock in &group.policy.dependencies.clocks {
            if let ClockPolicy::Stage { steps, .. } = clock {
                for step in steps {
                    if !queues.contains(step.action.reassign.queue.as_str()) {
                        reasons.insert(format!(
                            "clock reassignment queue {} is removed",
                            step.action.reassign.queue
                        ));
                    }
                }
            }
        }
        let pinned_producer = group
            .policy
            .dependencies
            .trusted_producers
            .iter()
            .find(|p| p.id == group.producer_id);
        match (
            project
                .trusted_producers
                .iter()
                .find(|p| p.id == group.producer_id),
            pinned_producer,
        ) {
            (Some(active), Some(pinned))
                if active.issuer == pinned.issuer
                    && active.subject == pinned.subject
                    && active.profile == pinned.profile
                    && profile_preserved(project, &group.policy, &pinned.profile)
                    && active.source_namespaces.contains(&group.source_namespace)
                    && active.review_policies.contains(&group.policy.identity.id) => {}
            _ => {
                reasons.insert(
                    "the bound producer can no longer recover or cancel this review".to_owned(),
                );
            }
        }
        if let ReviewContextPolicy::CurrentSource { provider, contract } = &group.policy.context {
            let retained = project
                .review_policies
                .iter()
                .any(|p| p.id == group.policy.identity.id && p.context == group.policy.context);
            let registered = providers.iter().find(|p| p.provider_id() == provider);
            if !retained || registered.is_none() {
                reasons.insert(
                    "the pinned context provider contract is removed or changed".to_owned(),
                );
            }
            // The context contract alone does not retain its deployment authority or
            // the read capabilities an accepted policy still needs. Additional
            // capabilities may serve new work; every pinned capability/profile stays.
            let dependency_preserved = group
                .policy
                .dependencies
                .context_provider
                .as_ref()
                .is_some_and(|pinned| {
                    project
                        .context_providers
                        .iter()
                        .find(|active| active.id == pinned.id)
                        .is_some_and(|active| {
                            active.source_namespace == pinned.source_namespace
                                && active.deployment_ref == pinned.deployment_ref
                                && pinned.capabilities.iter().all(|capability| {
                                    active.capabilities.contains(capability)
                                        && registered.is_some_and(|loaded| {
                                            loaded.capabilities().contains(capability)
                                        })
                                })
                                && pinned.service_profiles.iter().all(|(capability, profile)| {
                                    active.service_profiles.get(capability) == Some(profile)
                                })
                        })
                });
            if !dependency_preserved {
                reasons.insert(
                    "the pinned context provider dependency is removed or changed".to_owned(),
                );
            }
            if contract.id.is_empty() {
                reasons.insert("the pinned context contract is invalid".to_owned());
            }
        }
        for reason in reasons {
            conflicts.push(StrandedWork {
                policy: group.policy.identity.id.clone(),
                version: group.policy.identity.version.clone(),
                reviews: group.reviews,
                reason,
            });
        }
    }
    conflicts
}

fn profile_preserved(project: &CaseworkProject, policy: &ReviewPolicyClosure, id: &str) -> bool {
    match (
        project
            .access_profiles
            .iter()
            .find(|profile| profile.id == id),
        policy
            .dependencies
            .access_profiles
            .iter()
            .find(|profile| profile.id == id),
    ) {
        (Some(active), Some(pinned)) => {
            active.role == pinned.role
                && active.principal_claim == pinned.principal_claim
                && active.required_scopes.iter().collect::<BTreeSet<_>>()
                    == pinned.required_scopes.iter().collect::<BTreeSet<_>>()
        }
        _ => false,
    }
}
