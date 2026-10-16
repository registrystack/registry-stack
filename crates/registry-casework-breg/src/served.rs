// SPDX-License-Identifier: Apache-2.0
//! The review-context capabilities a BReg source serves, and the findings
//! for a project that needs one it does not.
use registry_casework_core::{
    CaseworkProject, ConfigFinding, ReviewContextCapability, ReviewContextPolicy,
    ReviewContextProviderPolicy,
};

/// Every capability a BReg context provider serves. Task-grant context and
/// routing context are not served yet.
pub const SERVED_CAPABILITIES: &[ReviewContextCapability] = &[
    ReviewContextCapability::HumanDisplay,
    ReviewContextCapability::ServiceStatus,
];

/// Where the BReg task-grant context work is tracked.
pub const TASK_GRANT_CONTEXT_ISSUE: &str =
    "https://github.com/registrystack/registry-stack/issues/2062";

fn name(capability: ReviewContextCapability) -> &'static str {
    match capability {
        ReviewContextCapability::HumanDisplay => "human-display",
        ReviewContextCapability::ServiceStatus => "service-status",
        ReviewContextCapability::TaskGrantContext => "task-grant-context",
        ReviewContextCapability::RoutingContext => "routing-context",
    }
}

fn pointer(collection: &str, id: &str, member: &str) -> String {
    format!(
        "/{collection}/{}/{member}",
        registry_platform_yaml::escape_pointer_segment(id)
    )
}

/// Findings for every place `project` needs a capability the BReg source
/// behind `provider` does not serve: a task template whose `subjects` need
/// task-grant context, a review policy whose routing needs routing context,
/// and a capability the provider declares. Empty when BReg serves them all.
#[must_use]
pub fn unserved_capabilities(
    project: &CaseworkProject,
    provider: &ReviewContextProviderPolicy,
) -> Vec<ConfigFinding> {
    let served = |capability: &ReviewContextCapability| SERVED_CAPABILITIES.contains(capability);
    let bound: Vec<_> = project
        .review_policies
        .iter()
        .filter(|policy| {
            matches!(&policy.context, ReviewContextPolicy::CurrentSource { provider: id, .. } if *id == provider.id)
        })
        .collect();
    let mut findings = Vec::new();
    for template in &project.task_templates {
        if template.subjects.is_empty()
            || !bound
                .iter()
                .any(|policy| template.review_policies.contains(&policy.id))
        {
            continue;
        }
        findings.push(ConfigFinding::new(
            "casework.task-template.unserved-capability",
            pointer("taskTemplates", &template.id, "subjects"),
            format!(
                "task template {} declares subjects, which need the task-grant-context \
                 capability, and BReg, the source behind context provider {}, does not serve \
                 task-grant context yet; see {TASK_GRANT_CONTEXT_ISSUE}",
                template.id, provider.id
            ),
            format!(
                "Remove `subjects` from task template {}, or bind the template to review \
                 policies whose source serves task-grant context.",
                template.id
            ),
        ));
    }
    for policy in &bound {
        if policy.routing_fields().is_empty() {
            continue;
        }
        findings.push(ConfigFinding::new(
            "casework.review-policy.unserved-capability",
            pointer("reviewPolicies", &policy.id, "routing"),
            format!(
                "review policy {} routes on source fields, which need the routing-context \
                 capability, and BReg, the source behind context provider {}, does not serve \
                 routing context",
                policy.id, provider.id
            ),
            format!(
                "Remove the routing rules that read source fields from review policy {}, or \
                 bind the policy to a source that serves routing context.",
                policy.id
            ),
        ));
    }
    let unserved: Vec<_> = provider
        .capabilities
        .iter()
        .filter(|capability| !served(capability))
        .map(|capability| name(*capability))
        .collect();
    if !unserved.is_empty() {
        findings.push(ConfigFinding::new(
            "casework.context-provider.unserved-capability",
            pointer("contextProviders", &provider.id, "capabilities"),
            format!(
                "context provider {} declares {}, which its BReg source does not serve; BReg \
                 serves human-display and service-status",
                provider.id,
                unserved.join(" and ")
            ),
            format!(
                "Remove {} from the capabilities and serviceProfiles of context provider {}.",
                unserved.join(" and "),
                provider.id
            ),
        ));
    }
    findings
}
