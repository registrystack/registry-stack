use std::fmt;

use serde::{Deserialize, Serialize};

/// A person is qualified by the issuer that authenticated the subject.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerPrincipal {
    pub issuer: String,
    pub subject: String,
}

/// A directory-scoped presentation of a person. The optional name belongs to
/// one team membership and never enters accountable actor identity.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryMember {
    pub issuer: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl From<IssuerPrincipal> for DirectoryMember {
    fn from(principal: IssuerPrincipal) -> Self {
        Self {
            issuer: principal.issuer,
            subject: principal.subject,
            display_name: None,
        }
    }
}

#[cfg(test)]
mod directory_member_tests {
    use super::*;

    #[test]
    fn display_names_remain_directory_scoped() {
        let member: DirectoryMember = serde_json::from_value(serde_json::json!({
            "issuer": "https://issuer.example",
            "subject": "officer-1",
            "displayName": "Officer One"
        }))
        .expect("directory member with display name");
        assert_eq!(member.display_name.as_deref(), Some("Officer One"));

        let unnamed: DirectoryMember = IssuerPrincipal {
            issuer: member.issuer.clone(),
            subject: member.subject.clone(),
        }
        .into();
        assert_eq!(
            serde_json::to_value(unnamed).expect("unnamed member"),
            serde_json::json!({
                "issuer": "https://issuer.example",
                "subject": "officer-1"
            })
        );
        assert!(
            serde_json::from_value::<IssuerPrincipal>(serde_json::json!({
                "issuer": "https://issuer.example",
                "subject": "officer-1",
                "displayName": "must not enter accountable identity"
            }))
            .is_err()
        );
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum CaseworkRole {
    Staff,
    Supervisor,
    Administrator,
    Requester,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActorContext {
    pub principal: IssuerPrincipal,
    pub profile_id: String,
    pub role: CaseworkRole,
}

/// A bearer credential may exist only for the duration of one request.
pub struct EphemeralCredential<'a>(&'a str);

impl<'a> EphemeralCredential<'a> {
    #[must_use]
    pub fn new(value: &'a str) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn expose(self) -> &'a str {
        self.0
    }
}

impl fmt::Debug for EphemeralCredential<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EphemeralCredential(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum StaffingDiagnostic {
    NoCoverAvailable,
    InsufficientDistinctApprovers,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum PageStatus {
    Complete,
    BudgetExhausted,
    SourceUnavailable,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Page<T> {
    pub items: Vec<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub status: PageStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HoldingSummary {
    pub principal: IssuerPrincipal,
    pub queue_id: String,
    pub active_items: u32,
    pub overdue_items: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueueRecord {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeamRecord {
    pub id: String,
    pub members: Vec<DirectoryMember>,
    pub supervisors: Vec<DirectoryMember>,
    pub served_queues: Vec<String>,
    pub revision: i64,
}
