// SPDX-License-Identifier: Apache-2.0

//! The facade profile: the contract artifact a deployment serves
//! (`products/adapter/CONCEPT.md` sections 6 and 7).
//!
//! Nothing about any one target API is compiled in: a profile declares its
//! operation set by id, its request and response envelope templates over
//! the closed slot vocabulary, its pagination parameters, and its problem
//! codes and problem envelope. The engine owns the mechanism (filling
//! slots, encoding cursors, setting the status); the profile owns every
//! name and shape a caller sees.

use registry_platform_yaml::{BoundedU64, ExternalId, UniqueIdList};
use serde::{Deserialize, Serialize};

/// The closed envelope slot vocabulary the engine fills
/// (`products/adapter/CONCEPT.md` section 7). A slot outside this set is
/// refused by the authoring checks.
pub const ENVELOPE_SLOTS: &[&str] = &[
    "nextCursor",
    "problemCode",
    "problemDetail",
    "problemTitle",
    "record",
    "recordId",
    "recordType",
    "records",
    "requestId",
    "status",
];

/// The slot holding one validated route result.
pub const SLOT_RECORD: &str = "record";
/// The slot holding the validated result list.
pub const SLOT_RECORDS: &str = "records";
/// The problem envelope's code slot; a problem envelope without it is
/// refused.
pub const SLOT_PROBLEM_CODE: &str = "problemCode";

/// An envelope template: a JSON template whose string members carry
/// `{{slot}}` placeholders from the closed vocabulary
/// (`products/adapter/CONCEPT.md` section 7). The template is data; the
/// engine fills it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeTemplate(pub String);

impl EnvelopeTemplate {
    /// The template text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }

    /// Whether the template mentions a slot, in required (`{{slot}}`) or
    /// optional (`{{?slot}}`) form.
    #[must_use]
    pub fn mentions(&self, slot: &str) -> bool {
        crate::checks::placeholders(self.text())
            .into_iter()
            .any(|(name, _)| name == slot)
    }
}

/// One facade operation, declared by id
/// (`products/adapter/CONCEPT.md` sections 6 and 7). The id is a
/// profile-declared bounded string (CFG-ID-5), never an engine enum.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileOperation {
    /// The profile-declared operation id a binding names.
    pub id: ExternalId,
    /// The facade method.
    pub method: crate::model::HttpMethod,
    /// The facade path template, e.g. `/v2/cases/{type}`.
    pub path: String,
    /// Where a writable record sits in an incoming body. A write
    /// operation's request envelope must name the `record` slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_envelope: Option<EnvelopeTemplate>,
    /// The response envelope; must name its result slot.
    pub response_envelope: EnvelopeTemplate,
    /// The pagination parameters of a search operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pagination: Option<PaginationParameters>,
}

impl registry_platform_yaml::Identified for ProfileOperation {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// The pagination parameters of a search operation: the cursor and
/// page-size query parameter names and their bounds
/// (`products/adapter/CONCEPT.md` section 7). The engine owns encoding the
/// cursor; the profile owns the names.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaginationParameters {
    /// The cursor query parameter name.
    pub cursor_parameter: ExternalId,
    /// The page-size query parameter name.
    pub page_size_parameter: ExternalId,
    /// The smallest page size a caller may ask for.
    pub page_size_minimum: BoundedU64<1, 10_000>,
    /// The largest page size a caller may ask for.
    pub page_size_maximum: BoundedU64<1, 100_000>,
}

/// One parameterized part: a part of the profile a deployment declares at
/// bind time (`products/adapter/CONCEPT.md` sections 6 and 7).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParameterizedPart {
    /// The part name.
    pub name: ExternalId,
    /// What the part means, for review.
    pub description: String,
}

/// The facade profile artifact (`AdapterProfile`): the operation set, the
/// envelope templates, the pagination parameters, and the problem codes
/// and problem envelope.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterProfile {
    /// The profile identifier a project pins.
    pub id: ExternalId,
    /// The operations the profile serves.
    pub operations: UniqueIdList<ProfileOperation>,
    /// The facade problem codes, in the profile's own closed list. Route
    /// clause bodies must carry one of these codes
    /// (`products/adapter/CONCEPT.md` section 8.7).
    pub problem_codes: registry_platform_yaml::UniqueList<ExternalId>,
    /// The problem envelope template; must carry the `problemCode` slot.
    pub problem_envelope: EnvelopeTemplate,
    /// The parts of the profile a deployment declares at bind time.
    #[serde(default)]
    pub parameterized_parts: registry_platform_yaml::UniqueList<ParameterizedPart>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(id: &str, method: crate::model::HttpMethod) -> ProfileOperation {
        ProfileOperation {
            id: ExternalId::new(id).expect("id"),
            method,
            path: "/v2/cases/{type}".to_string(),
            request_envelope: None,
            response_envelope: EnvelopeTemplate(r#"{"cases": {{records}}}"#.to_string()),
            pagination: None,
        }
    }

    /// The profile artifact round-trips with profile-declared operation
    /// ids (`products/adapter/CONCEPT.md` section 7).
    #[test]
    fn profile_round_trips_with_declared_operation_ids() {
        let profile = AdapterProfile {
            id: ExternalId::new("case-api").expect("id"),
            operations: UniqueIdList::new(vec![
                operation("cases.find", crate::model::HttpMethod::Post),
                operation("cases.get", crate::model::HttpMethod::Get),
            ])
            .expect("unique"),
            problem_codes: registry_platform_yaml::UniqueList::new(vec![ExternalId::new(
                "cases.conflict",
            )
            .expect("code")])
            .expect("unique"),
            problem_envelope: EnvelopeTemplate(
                r#"{"code": "{{problemCode}}", "title": "{{problemTitle}}"}"#.to_string(),
            ),
            parameterized_parts: Default::default(),
        };
        let json = serde_json::to_string(&profile).expect("serialize");
        assert_eq!(
            serde_json::from_str::<AdapterProfile>(&json).ok(),
            Some(profile)
        );
    }

    /// Repeated operation ids are refused at the reader (CFG-ID-5).
    #[test]
    fn duplicate_operation_ids_are_refused() {
        assert!(
            UniqueIdList::new(vec![
                operation("cases.find", crate::model::HttpMethod::Post),
                operation("cases.find", crate::model::HttpMethod::Get),
            ])
            .is_err(),
            "duplicate operation id refused"
        );
    }

    /// The slot vocabulary is closed: the known slots resolve, and an
    /// unknown one does not. The refusal itself is an authoring check in
    /// `crate::checks`.
    #[test]
    fn slot_vocabulary_is_closed() {
        for slot in [
            "record",
            "records",
            "recordType",
            "recordId",
            "nextCursor",
            "requestId",
            "problemCode",
            "problemTitle",
            "problemDetail",
            "status",
        ] {
            assert!(
                ENVELOPE_SLOTS.contains(&slot),
                "{slot} must stay in the closed vocabulary"
            );
        }
        assert_eq!(ENVELOPE_SLOTS.len(), 10);
    }

    /// Envelope templates answer slot-mention queries in both placeholder
    /// forms (`{{name}}` and `{{?name}}`).
    #[test]
    fn envelope_templates_mention_slots() {
        let template = EnvelopeTemplate(
            r#"{"cursor": "{{?nextCursor}}", "record": {{record}}, "req": "{{requestId}}"}"#
                .to_string(),
        );
        assert!(template.mentions(SLOT_RECORD));
        assert!(template.mentions("nextCursor"));
        assert!(template.mentions("requestId"));
        assert!(!template.mentions(SLOT_RECORDS));
        assert!(!template.mentions("unknownSlot"));
    }

    /// Pagination parameters round-trip with their bounds.
    #[test]
    fn pagination_parameters_round_trip() {
        let pagination = PaginationParameters {
            cursor_parameter: ExternalId::new("cursor").expect("name"),
            page_size_parameter: ExternalId::new("limit").expect("name"),
            page_size_minimum: BoundedU64::<1, 10_000>::new(1).expect("min"),
            page_size_maximum: BoundedU64::<1, 100_000>::new(500).expect("max"),
        };
        let json = serde_json::to_string(&pagination).expect("serialize");
        assert!(json.contains("cursorParameter"));
        assert_eq!(
            serde_json::from_str::<PaginationParameters>(&json).ok(),
            Some(pagination)
        );
    }
}
