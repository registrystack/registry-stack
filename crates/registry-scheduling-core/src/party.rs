// SPDX-License-Identifier: Apache-2.0
//! Source-neutral party facts retained with a Scheduling claim.

use crate::wire::ExternalReference;
use serde::{Deserialize, Serialize};

/// The most typed source references one booking may retain.
pub const MAXIMUM_PARTY_REFERENCES: usize = 16;

/// An explicit selector for a source-bound managing authority.
///
/// The selector carries no identity. Scheduling resolves the fixed signed
/// task-grant subject of the same name and verifies its current status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum ManagerSelection {
    SchedulingManager,
}

/// The declared party counts committed with a hold or appointment.
///
/// Recipients are the people the service is delivered to; attendees are
/// everyone expected to be present, recipients included. These values explain
/// a capacity decision. They are not an observation that attendance occurred,
/// and neither value is an inventory quantity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartyCounts {
    pub recipients: u32,
    pub attendees: u32,
}

impl PartyCounts {
    /// Whether the pair describes at least one person and attendees include
    /// every recipient.
    #[must_use]
    pub const fn is_coherent(self) -> bool {
        self.attendees > 0 && self.attendees >= self.recipients
    }
}

/// Whether an exact-time offering requires declared human party counts.
/// Arrival-window offerings always require them because recipient counts drive
/// their capacity units.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum PartyCountsRequirement {
    #[default]
    Required,
    Optional,
}

impl PartyCountsRequirement {
    #[must_use]
    pub const fn is_required(&self) -> bool {
        matches!(self, Self::Required)
    }
}

/// The source-owned meaning of an opaque party reference.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum PartyReferenceRole {
    Beneficiary,
    Organization,
}

/// A typed reference to a party record owned by another product.
///
/// Scheduling retains this value as booking data. It proves no relationship
/// and grants no read or mutation authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartyReference {
    pub role: PartyReferenceRole,
    pub reference: ExternalReference,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn party_counts_require_a_nonempty_coherent_headcount() {
        assert!(PartyCounts {
            recipients: 2,
            attendees: 3,
        }
        .is_coherent());
        assert!(PartyCounts {
            recipients: 0,
            attendees: 30,
        }
        .is_coherent());
        assert!(!PartyCounts {
            recipients: 2,
            attendees: 1,
        }
        .is_coherent());
        assert!(!PartyCounts {
            recipients: 0,
            attendees: 0,
        }
        .is_coherent());
    }

    #[test]
    fn party_count_policy_defaults_to_required() {
        assert_eq!(
            PartyCountsRequirement::default(),
            PartyCountsRequirement::Required
        );
        assert!(PartyCountsRequirement::Required.is_required());
        assert!(!PartyCountsRequirement::Optional.is_required());
    }

    #[test]
    fn manager_selection_names_only_the_fixed_signed_subject() {
        assert_eq!(
            serde_json::to_value(ManagerSelection::SchedulingManager).unwrap(),
            json!("schedulingManager")
        );
        assert!(serde_json::from_value::<ManagerSelection>(json!("arbitrary")).is_err());
    }

    #[test]
    fn party_references_are_typed_opaque_record_links() {
        let reference: PartyReference = serde_json::from_value(json!({
            "role": "organization",
            "reference": {
                "product": "source-product",
                "recordType": "requesting-organization",
                "identifier": "organization-17"
            }
        }))
        .expect("typed party reference");
        assert_eq!(reference.role, PartyReferenceRole::Organization);
        assert_eq!(
            serde_json::to_value(reference).expect("party reference JSON"),
            json!({
                "role": "organization",
                "reference": {
                    "product": "source-product",
                    "recordType": "requesting-organization",
                    "identifier": "organization-17"
                }
            })
        );
    }
}
