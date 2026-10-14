use crate::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewContextContract {
    pub id: String,
    pub revision: ContentDigest,
    pub schema_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    tag = "mode",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReviewContextPolicy {
    Submitted,
    CurrentSource {
        provider: String,
        contract: ReviewContextContract,
    },
}

// Serde ignores extra members on an internally tagged unit variant, even
// with deny_unknown_fields. Decode the submitted form as an empty struct so
// both variants enforce the same closed authoring contract. The public enum
// and its serialized form remain unchanged.
#[derive(Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ReviewContextPolicyWire {
    Submitted {},
    CurrentSource {
        provider: String,
        contract: ReviewContextContract,
    },
}
registry_platform_yaml::tagged_union!(ReviewContextPolicyWire, tag = "mode");

impl<'de> Deserialize<'de> for ReviewContextPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match <ReviewContextPolicyWire as Deserialize>::deserialize(deserializer)? {
            ReviewContextPolicyWire::Submitted {} => Ok(Self::Submitted),
            ReviewContextPolicyWire::CurrentSource { provider, contract } => {
                Ok(Self::CurrentSource { provider, contract })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewContextCapability {
    HumanDisplay,
    ServiceStatus,
    TaskGrantContext,
    RoutingContext,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewContextProviderPolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub capabilities: Vec<ReviewContextCapability>,
    pub source_namespace: String,
    pub deployment_ref: String,
    #[serde(default)]
    pub service_profiles: BTreeMap<ReviewContextCapability, String>,
}

/// Complete behavioral inputs retained beside an admitted request. Live Directory
/// membership and absence facts remain current authority, not policy inputs.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewPolicyDependencies {
    pub access_profiles: Vec<crate::AccessProfile>,
    pub queues: Vec<crate::QueuePolicy>,
    pub teams: Vec<crate::TeamPolicy>,
    pub clocks: Vec<crate::ClockPolicy>,
    pub calendars: Vec<crate::CalendarPolicy>,
    pub context_provider: Option<ReviewContextProviderPolicy>,
    pub task_templates: Vec<crate::TaskTemplate>,
    pub trusted_producers: Vec<crate::ReviewProducerPolicy>,
    pub inbox: crate::InboxPolicy,
}
