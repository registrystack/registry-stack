// SPDX-License-Identifier: Apache-2.0
//! Read-only, value-free change classification for operator tooling.

use serde::{Deserialize, Serialize};

use crate::model::CompiledRegistry;
use crate::package::{
    compiled_registry_change_set, CompiledRegistryChange, CompiledRegistryChangeClass,
    CompiledRegistryChangeCode,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffClassification {
    CompatibleAdditive,
    DataBackfillRequired,
    LockOrRewriteRisk,
    AccessChange,
    DisclosureWidening,
    DisclosureNarrowing,
    DestructiveOrIrreversible,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClassifiedRegistryChange {
    pub classification: DiffClassification,
    pub change: CompiledRegistryChange,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub access_details: Vec<AccessChangeDetail>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessChangeDetail {
    pub field: String,
    pub direction: AccessChangeDirection,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
    /// Why a guard asks for review, when the direction alone does not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessChangeDirection {
    Widening,
    Narrowing,
    ReviewRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRegistryDiff {
    pub baseline_package_revision: String,
    pub baseline_registry_revision: String,
    pub candidate_registry_revision: String,
    pub changes: Vec<ClassifiedRegistryChange>,
}

/// Compare the rederived package Registry with an authoring candidate.
///
/// The compiler-owned inventory remains authoritative. This layer only refines
/// classifications that can be proven from the two compiled models. It never
/// inspects source values, generated SQL, records, or a database.
pub fn classify_registry_diff(
    baseline: &CompiledRegistry,
    candidate: &CompiledRegistry,
    baseline_package_revision: &str,
) -> CompiledRegistryDiff {
    let change_set = compiled_registry_change_set(baseline, candidate, baseline_package_revision);
    let changes = change_set
        .changes
        .into_iter()
        .map(|change| ClassifiedRegistryChange {
            classification: classify_change(baseline, candidate, &change),
            access_details: access_change_details(baseline, candidate, &change),
            change,
        })
        .collect();
    CompiledRegistryDiff {
        baseline_package_revision: baseline_package_revision.to_owned(),
        baseline_registry_revision: baseline.revision().to_owned(),
        candidate_registry_revision: candidate.revision().to_owned(),
        changes,
    }
}

fn classify_change(
    baseline: &CompiledRegistry,
    candidate: &CompiledRegistry,
    change: &CompiledRegistryChange,
) -> DiffClassification {
    use CompiledRegistryChangeClass as BaseClass;
    use CompiledRegistryChangeCode as Code;

    match change.code {
        Code::ConstraintAdded | Code::IndexAdded => DiffClassification::LockOrRewriteRisk,
        Code::DerivedRelationChanged if change.class == BaseClass::CompatibleAdditive => {
            DiffClassification::CompatibleAdditive
        }
        Code::DerivedRelationAdded => DiffClassification::CompatibleAdditive,
        Code::DerivedRelationRemoved | Code::DerivedRelationChanged => {
            DiffClassification::DestructiveOrIrreversible
        }
        Code::EntityClassificationChanged | Code::FieldClassificationChanged => {
            classification_direction(baseline, candidate, change)
        }
        Code::AccessProfileChanged => access_profile_direction(baseline, candidate, change),
        Code::EntityRouteChanged
        | Code::EntityMutationModeChanged
        | Code::AccessProfileAdded
        | Code::AccessProfileRemoved
        | Code::EntityAccessRequirementsChanged
        | Code::ChangeRequestContractChanged
        | Code::RouteAdded
        | Code::RouteRemoved
        | Code::RouteChanged => DiffClassification::AccessChange,
        Code::QueryInventoryChanged => match change.class {
            BaseClass::AccessOrDisclosureChange => DiffClassification::AccessChange,
            _ => DiffClassification::Unsupported,
        },
        Code::EventAdded | Code::EventRemoved | Code::EventChanged => {
            DiffClassification::Unsupported
        }
        // Consent configuration and actions change who may read or write
        // without changing storage; their details carry the review reasons.
        Code::ConsentRecordChanged
        | Code::RecipientOrganizationAdded
        | Code::RecipientOrganizationRemoved
        | Code::RecipientOrganizationChanged
        | Code::RecipientGroupAdded
        | Code::RecipientGroupRemoved
        | Code::RecipientGroupChanged
        | Code::ActionAdded
        | Code::ActionRemoved
        | Code::ActionChanged => DiffClassification::AccessChange,
        _ => match change.class {
            BaseClass::CompatibleAdditive => DiffClassification::CompatibleAdditive,
            BaseClass::DataBackfillRequired => DiffClassification::DataBackfillRequired,
            BaseClass::DestructiveOrIrreversible => DiffClassification::DestructiveOrIrreversible,
            BaseClass::Unsupported => DiffClassification::Unsupported,
            // A new compiler change code must be reviewed here rather than
            // inheriting an access/disclosure guess.
            BaseClass::AccessOrDisclosureChange => DiffClassification::Unsupported,
        },
    }
}

/// The bound destination of a hook that delivers to one, for change summaries.
///
/// A hook with no handler, or one this engine does not deliver, summarizes as
/// null rather than inventing a destination the operator never declared.
fn hook_destination_id(hook: &crate::contract::HookSource) -> Option<&String> {
    match hook.handler.as_ref() {
        Some(crate::contract::HookHandlerSource::Url { destination_id }) => Some(destination_id),
        Some(_) | None => None,
    }
}

fn access_change_details(
    baseline: &CompiledRegistry,
    candidate: &CompiledRegistry,
    change: &CompiledRegistryChange,
) -> Vec<AccessChangeDetail> {
    use serde_json::{json, Value};
    use CompiledRegistryChangeCode as Code;
    match change.code {
        Code::RecipientOrganizationAdded
        | Code::RecipientOrganizationRemoved
        | Code::RecipientOrganizationChanged
        | Code::RecipientGroupAdded
        | Code::RecipientGroupRemoved
        | Code::RecipientGroupChanged => return recipient_details(baseline, candidate, change),
        Code::ActionAdded | Code::ActionChanged | Code::ActionVocabularyCodesAdded => {
            return action_details(baseline, candidate, change)
        }
        _ => {}
    }
    let Some(entity) = change.target.entity_id.as_deref() else {
        return vec![];
    };
    let before_entity = baseline.entities().get(entity);
    let after_entity = candidate.entities().get(entity);
    let member = change.target.member_id.as_deref().unwrap_or("");
    let serialize_profile = |entity: Option<&crate::model::CompiledEntity>| {
        entity
            .and_then(|e| e.access_profiles.get(member))
            .map(|p| json!(p))
            .unwrap_or(Value::Null)
    };
    let (before, after) = match change.code {
        Code::AccessProfileAdded | Code::AccessProfileRemoved | Code::AccessProfileChanged => (
            serialize_profile(before_entity),
            serialize_profile(after_entity),
        ),
        Code::EntityAccessRequirementsChanged => (
            json!(before_entity.and_then(|e| e.access_requirements.as_ref())),
            json!(after_entity.and_then(|e| e.access_requirements.as_ref())),
        ),
        Code::EventChanged => {
            let summarize = |entity: Option<&crate::model::CompiledEntity>| {
                entity.and_then(|e| e.hooks.get(member)).map(|e| json!({"projection": e.projection, "destinationId": hook_destination_id(e)})).unwrap_or(Value::Null)
            };
            (summarize(before_entity), summarize(after_entity))
        }
        Code::ConsentRecordChanged => {
            return consent_record_details(
                before_entity.and_then(|e| e.consent_record.as_ref()),
                after_entity.and_then(|e| e.consent_record.as_ref()),
            )
        }
        Code::FieldTypeChanged => {
            return consent_vocabulary_details(
                before_entity.and_then(|e| e.fields.get(member)),
                after_entity.and_then(|e| e.fields.get(member)),
            )
        }
        _ => return vec![],
    };
    if before.is_null() || after.is_null() {
        return vec![AccessChangeDetail {
            field: "profileOrRequirements".into(),
            direction: AccessChangeDirection::ReviewRequired,
            before,
            after,
            reason: None,
        }];
    }
    // A gated profile id is a consent scope: every subject consented to the
    // scope as it stood, so nothing may widen under the same id.
    let gated = change.code == Code::AccessProfileChanged
        && before_entity
            .and_then(|e| e.access_profiles.get(member))
            .is_some_and(|profile| !profile.require_consent.is_empty());
    object_details(&before, &after, |field, left, right| {
        let direction = access_direction(field, left, right);
        if !gated {
            (direction, None)
        } else if field == "requireConsent" && right.is_null() {
            (AccessChangeDirection::ReviewRequired, Some(UNGATED_SCOPE))
        } else if direction == AccessChangeDirection::Widening
            || (matches!(field, "lookups" | "readPaths") && adds_items(left, right))
        {
            (
                AccessChangeDirection::ReviewRequired,
                Some(GATED_SCOPE_WIDENED),
            )
        } else {
            (direction, None)
        }
    })
}

const GATED_SCOPE_WIDENED: &str = "this profile is a consent scope and subjects consented to the narrower scope; a new profile id is a new scope and asks again";
const UNGATED_SCOPE: &str = "removing requireConsent reads without the consent the scope was declared under; rename the profile and list the old id in retiredConsentScopes instead";
const CLIENT_ADDED: &str = "a new client extends every existing consent given to this organization, and to every group it belongs to, onto the new client";
const GROUP_MEMBERS_CHANGED: &str = "changing a group's members changes who holds every existing consent given to the group; prefer a new group id with a new notice clause";
const MAX_DURATION_RAISED: &str =
    "raising maxDuration makes existing gives last longer than the notice said";
const CODE_REMOVED: &str = "consent vocabulary codes are append-only; retire the code instead (an organization with no clients, or an id in retiredConsentScopes), since the migration also fails against existing rows that carry it";
const STEWARD_ISSUER: &str = "steward actions create consent without the subject's principal";
const ACTION_CODES_ADDED: &str = "the action accepts the added codes without review; check that each is one this action may write, such as a recipient or scope its notice names";

/// Whether `after` holds an item `before` lacks, reading an omitted list as empty.
fn adds_items(before: &serde_json::Value, after: &serde_json::Value) -> bool {
    let before = before.as_array().map(Vec::as_slice).unwrap_or_default();
    after
        .as_array()
        .is_some_and(|after| after.iter().any(|item| !before.contains(item)))
}

/// One detail per changed key of two serialized objects, each with its guard.
fn object_details(
    before: &serde_json::Value,
    after: &serde_json::Value,
    guard: impl Fn(
        &str,
        &serde_json::Value,
        &serde_json::Value,
    ) -> (AccessChangeDirection, Option<&'static str>),
) -> Vec<AccessChangeDetail> {
    let keys = before
        .as_object()
        .into_iter()
        .flat_map(|v| v.keys())
        .chain(after.as_object().into_iter().flat_map(|v| v.keys()))
        .collect::<std::collections::BTreeSet<_>>();
    keys.into_iter()
        .filter_map(|field| {
            let left = &before[field];
            let right = &after[field];
            if left == right {
                return None;
            }
            let (direction, reason) = guard(field, left, right);
            Some(AccessChangeDetail {
                field: field.clone(),
                direction,
                before: left.clone(),
                after: right.clone(),
                reason: reason.map(str::to_owned),
            })
        })
        .collect()
}

fn recipient_details(
    baseline: &CompiledRegistry,
    candidate: &CompiledRegistry,
    change: &CompiledRegistryChange,
) -> Vec<AccessChangeDetail> {
    use serde_json::{json, Value};
    use AccessChangeDirection::{Narrowing, ReviewRequired};
    use CompiledRegistryChangeCode as Code;
    let Some(id) = change.target.member_id.as_deref() else {
        return vec![];
    };
    let organization = |registry: &CompiledRegistry| {
        registry
            .recipients()
            .organizations
            .iter()
            .find(|organization| organization.id == id)
            .map(|organization| json!(organization))
            .unwrap_or(Value::Null)
    };
    let group = |registry: &CompiledRegistry| {
        registry
            .recipients()
            .groups
            .iter()
            .find(|group| group.id == id)
            .map(|group| json!(group))
            .unwrap_or(Value::Null)
    };
    let (field, before, after) = match change.code {
        Code::RecipientOrganizationAdded
        | Code::RecipientOrganizationRemoved
        | Code::RecipientOrganizationChanged => (
            "organization",
            organization(baseline),
            organization(candidate),
        ),
        _ => ("group", group(baseline), group(candidate)),
    };
    if before.is_null() || after.is_null() {
        // A new code has no consent yet; a removed one breaks every row that
        // carries it.
        return vec![AccessChangeDetail {
            field: field.into(),
            direction: ReviewRequired,
            reason: after.is_null().then(|| CODE_REMOVED.to_owned()),
            before,
            after,
        }];
    }
    object_details(&before, &after, |field, left, right| match field {
        "clients" if adds_items(left, right) => (ReviewRequired, Some(CLIENT_ADDED)),
        "clients" => (Narrowing, None),
        "members" => (ReviewRequired, Some(GROUP_MEMBERS_CHANGED)),
        _ => (ReviewRequired, None),
    })
}

fn consent_record_details(
    before: Option<&crate::model::CompiledConsentRecord>,
    after: Option<&crate::model::CompiledConsentRecord>,
) -> Vec<AccessChangeDetail> {
    use crate::consent::duration_seconds;
    use serde_json::json;
    use AccessChangeDirection::{Narrowing, ReviewRequired};
    let (Some(before), Some(after)) = (before, after) else {
        return vec![AccessChangeDetail {
            field: "consentRecord".into(),
            direction: ReviewRequired,
            before: json!(before),
            after: json!(after),
            reason: None,
        }];
    };
    let raised = duration_seconds(&after.max_duration) > duration_seconds(&before.max_duration);
    object_details(&json!(before), &json!(after), |field, _, _| match field {
        "maxDuration" if raised => (ReviewRequired, Some(MAX_DURATION_RAISED)),
        "maxDuration" => (Narrowing, None),
        _ => (ReviewRequired, None),
    })
}

/// A field bound to a consent vocabulary that lost a code.
fn consent_vocabulary_details(
    before: Option<&crate::model::CompiledField>,
    after: Option<&crate::model::CompiledField>,
) -> Vec<AccessChangeDetail> {
    use crate::contract::FieldTypeSource;
    let codes = |field: Option<&crate::model::CompiledField>| match field.map(|f| &f.field_type) {
        Some(FieldTypeSource::VocabularyCode { vocabulary, values })
            if crate::consent::is_reserved_vocabulary(vocabulary) =>
        {
            Some(values.clone())
        }
        _ => None,
    };
    let (Some(before), Some(after)) = (codes(before), codes(after)) else {
        return vec![];
    };
    if before.iter().all(|code| after.contains(code)) {
        return vec![];
    }
    vec![AccessChangeDetail {
        field: "values".into(),
        direction: AccessChangeDirection::ReviewRequired,
        before: serde_json::json!(before),
        after: serde_json::json!(after),
        reason: Some(CODE_REMOVED.to_owned()),
    }]
}

fn action_details(
    baseline: &CompiledRegistry,
    candidate: &CompiledRegistry,
    change: &CompiledRegistryChange,
) -> Vec<AccessChangeDetail> {
    use crate::contract::ConsentIssuerSource;
    use serde_json::{json, Map, Value};
    use CompiledRegistryChangeCode as Code;
    let Some(id) = change.target.member_id.as_deref() else {
        return vec![];
    };
    let action = |registry: &CompiledRegistry| {
        registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == id)
            .cloned()
    };
    let (before, Some(after)) = (action(baseline), action(candidate)) else {
        return vec![];
    };
    let mut details = Vec::new();
    let before_issuer = before.as_ref().and_then(|action| action.consent_issuer);
    if after.consent_issuer == Some(ConsentIssuerSource::Steward)
        && before_issuer != Some(ConsentIssuerSource::Steward)
    {
        details.push(AccessChangeDetail {
            field: "consentIssuer".into(),
            direction: AccessChangeDirection::ReviewRequired,
            before: json!(before_issuer),
            after: json!(after.consent_issuer),
            reason: Some(STEWARD_ISSUER.to_owned()),
        });
    }
    if change.code == Code::ActionVocabularyCodesAdded {
        let Some(before) = before else {
            return details;
        };
        let codes = |input: &crate::model::CompiledActionInput| match &input.field_type {
            crate::contract::FieldTypeSource::VocabularyCode { values, .. } => json!(values),
            _ => Value::Null,
        };
        let mut widened_before = Map::new();
        let mut widened_after = Map::new();
        for input in &after.inputs {
            let Some(previous) = before
                .inputs
                .iter()
                .find(|previous| previous.id == input.id)
            else {
                continue;
            };
            if previous.field_type != input.field_type {
                widened_before.insert(input.id.clone(), codes(previous));
                widened_after.insert(input.id.clone(), codes(input));
            }
        }
        details.push(AccessChangeDetail {
            field: "inputCodes".into(),
            direction: AccessChangeDirection::ReviewRequired,
            before: Value::Object(widened_before),
            after: Value::Object(widened_after),
            reason: Some(ACTION_CODES_ADDED.to_owned()),
        });
    }
    details
}

fn access_direction(
    field: &str,
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> AccessChangeDirection {
    use AccessChangeDirection::{Narrowing, ReviewRequired, Widening};
    // Empty membership requirements are omitted from the serialized profile.
    // Compare them as an empty conjunction when the first or last rule changes.
    let empty = serde_json::Value::Array(Vec::new());
    let before = if field == "membershipBoundaries" && before.is_null() {
        &empty
    } else {
        before
    };
    let after = if field == "membershipBoundaries" && after.is_null() {
        &empty
    } else {
        after
    };
    let reverse = matches!(
        field,
        "requiredScopes" | "rowBoundaries" | "membershipBoundaries"
    );
    if let (Some(before), Some(after)) = (before.as_array(), after.as_array()) {
        if matches!(field, "requiredPurposes" | "allowedPurposes") {
            if after.is_empty() {
                return Widening;
            }
            if before.is_empty() {
                return Narrowing;
            }
        }
        if matches!(field, "lookups" | "readPaths") {
            return ReviewRequired;
        }
        let added_only = before.iter().all(|item| after.contains(item));
        let removed_only = after.iter().all(|item| before.contains(item));
        if added_only && removed_only {
            return ReviewRequired;
        }
        if added_only {
            return if reverse { Narrowing } else { Widening };
        }
        if removed_only {
            return if reverse { Widening } else { Narrowing };
        }
    }
    if matches!(
        field,
        "anonymous" | "allowCount" | "revisionAccess" | "allowDataExport"
    ) {
        return if after == &serde_json::Value::Bool(true) {
            Widening
        } else {
            Narrowing
        };
    }
    ReviewRequired
}

fn access_profile_direction(
    baseline: &CompiledRegistry,
    candidate: &CompiledRegistry,
    change: &CompiledRegistryChange,
) -> DiffClassification {
    let (Some(entity_id), Some(profile_id)) = (
        change.target.entity_id.as_deref(),
        change.target.member_id.as_deref(),
    ) else {
        return DiffClassification::Unsupported;
    };
    let (Some(before), Some(after)) = (
        baseline
            .entities()
            .get(entity_id)
            .and_then(|entity| entity.access_profiles.get(profile_id)),
        candidate
            .entities()
            .get(entity_id)
            .and_then(|entity| entity.access_profiles.get(profile_id)),
    ) else {
        return DiffClassification::Unsupported;
    };
    if before.readable_fields == after.readable_fields {
        return DiffClassification::AccessChange;
    }
    let mut before_without_disclosure = before.clone();
    before_without_disclosure.readable_fields.clear();
    let mut after_without_disclosure = after.clone();
    after_without_disclosure.readable_fields.clear();
    if before_without_disclosure != after_without_disclosure {
        return DiffClassification::AccessChange;
    }
    if before.readable_fields.is_subset(&after.readable_fields) {
        DiffClassification::DisclosureWidening
    } else if after.readable_fields.is_subset(&before.readable_fields) {
        DiffClassification::DisclosureNarrowing
    } else {
        DiffClassification::AccessChange
    }
}

fn classification_direction(
    baseline: &CompiledRegistry,
    candidate: &CompiledRegistry,
    change: &CompiledRegistryChange,
) -> DiffClassification {
    let Some(entity_id) = change.change_target_entity_id() else {
        return DiffClassification::Unsupported;
    };
    let Some(before_entity) = baseline.entities().get(entity_id) else {
        return DiffClassification::Unsupported;
    };
    let Some(after_entity) = candidate.entities().get(entity_id) else {
        return DiffClassification::Unsupported;
    };
    let direction = match change.code {
        CompiledRegistryChangeCode::EntityClassificationChanged => before_entity
            .classification
            .cmp(&after_entity.classification),
        CompiledRegistryChangeCode::FieldClassificationChanged => {
            let Some(field_id) = change.change_target_member_id() else {
                return DiffClassification::Unsupported;
            };
            let Some(before) = before_entity.fields.get(field_id) else {
                return DiffClassification::Unsupported;
            };
            let Some(after) = after_entity.fields.get(field_id) else {
                return DiffClassification::Unsupported;
            };
            before.classification.cmp(&after.classification)
        }
        _ => return DiffClassification::Unsupported,
    };
    match direction {
        // A lower candidate classification expands where the field/entity can
        // be processed and disclosed.
        std::cmp::Ordering::Greater => DiffClassification::DisclosureWidening,
        std::cmp::Ordering::Less => DiffClassification::DisclosureNarrowing,
        std::cmp::Ordering::Equal => DiffClassification::Unsupported,
    }
}

trait ChangeTargetIds {
    fn change_target_entity_id(&self) -> Option<&str>;
    fn change_target_member_id(&self) -> Option<&str>;
}

impl ChangeTargetIds for CompiledRegistryChange {
    fn change_target_entity_id(&self) -> Option<&str> {
        self.target.entity_id.as_deref()
    }

    fn change_target_member_id(&self) -> Option<&str> {
        self.target.member_id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{compile_project, module_digest, CompileProfile};
    use crate::contract::{parse_module_json, parse_project_json};
    use crate::package::CompiledRegistryChangeCode;

    const PACKAGE_REVISION: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn disclosure_direction_threat_is_enforced_by_exact_classification_order_negative() {
        let internal = compiled("1", "internal", "", "", "principal");
        let public = compiled("1", "public", "", "", "principal");

        let widening = classify_registry_diff(&internal, &public, PACKAGE_REVISION);
        let widening_again = classify_registry_diff(&internal, &public, PACKAGE_REVISION);
        assert_eq!(widening, widening_again, "diff order and bytes are stable");
        assert!(widening.changes.iter().any(|change| {
            change.change.code == CompiledRegistryChangeCode::FieldClassificationChanged
                && change.classification == DiffClassification::DisclosureWidening
        }));

        let narrowing = classify_registry_diff(&public, &internal, PACKAGE_REVISION);
        assert!(narrowing.changes.iter().any(|change| {
            change.change.code == CompiledRegistryChangeCode::FieldClassificationChanged
                && change.classification == DiffClassification::DisclosureNarrowing
        }));
    }

    #[test]
    fn every_supported_diff_class_is_derived_from_an_exact_compiler_change() {
        let baseline = compiled("1", "internal", "", "", "principal");
        let optional = compiled(
            "1",
            "internal",
            r#",{"id":"optional","type":"string","maxLength":16,"classification":"internal"}"#,
            "",
            "principal",
        );
        assert_class(
            &baseline,
            &optional,
            CompiledRegistryChangeCode::FieldAddedOptional,
            DiffClassification::CompatibleAdditive,
        );

        let required = compiled(
            "1",
            "internal",
            r#",{"id":"required","type":"string","maxLength":16,"required":true,"classification":"internal"}"#,
            "",
            "principal",
        );
        assert_class(
            &baseline,
            &required,
            CompiledRegistryChangeCode::FieldAddedRequired,
            DiffClassification::DataBackfillRequired,
        );

        let constrained = compiled(
            "1",
            "internal",
            "",
            r#", "constraints":[{"kind":"unique","id":"code-unique","fields":["code"]}],"indexes":[{"id":"code-index","fields":["code"]}]"#,
            "principal",
        );
        assert_class(
            &baseline,
            &constrained,
            CompiledRegistryChangeCode::ConstraintAdded,
            DiffClassification::LockOrRewriteRisk,
        );
        assert_class(
            &baseline,
            &constrained,
            CompiledRegistryChangeCode::IndexAdded,
            DiffClassification::LockOrRewriteRisk,
        );

        let access = compiled("1", "internal", "", "", "subject");
        assert_class(
            &baseline,
            &access,
            CompiledRegistryChangeCode::AccessProfileChanged,
            DiffClassification::AccessChange,
        );

        assert_class(
            &optional,
            &baseline,
            CompiledRegistryChangeCode::FieldRemoved,
            DiffClassification::DestructiveOrIrreversible,
        );

        let identity_changed = compiled("2", "internal", "", "", "principal");
        assert_class(
            &baseline,
            &identity_changed,
            CompiledRegistryChangeCode::RegistryIdentityChanged,
            DiffClassification::Unsupported,
        );
    }

    #[test]
    fn query_removed_by_snapshot_profile_revocation_is_supported_access_change() {
        let baseline = compiled_temporal_with_profile(r#""list","snapshot""#, "");
        let candidate = compiled_temporal_with_profile(r#""list""#, "");

        let diff = classify_registry_diff(&baseline, &candidate, PACKAGE_REVISION);
        let query_changes = diff
            .changes
            .iter()
            .filter(|change| {
                change.change.code == CompiledRegistryChangeCode::QueryInventoryChanged
            })
            .collect::<Vec<_>>();

        assert!(
            !query_changes.is_empty(),
            "snapshot revocation removes query operations"
        );
        assert!(query_changes
            .iter()
            .all(|change| change.classification == DiffClassification::AccessChange));
        assert!(diff
            .changes
            .iter()
            .all(|change| change.classification != DiffClassification::Unsupported));
    }

    #[test]
    fn query_added_by_snapshot_profile_grant_is_supported_access_change() {
        let baseline = compiled_temporal_with_profile(r#""list""#, "");
        let candidate = compiled_temporal_with_profile(r#""list","snapshot""#, "");

        let diff = classify_registry_diff(&baseline, &candidate, PACKAGE_REVISION);
        let query_changes = diff
            .changes
            .iter()
            .filter(|change| {
                change.change.code == CompiledRegistryChangeCode::QueryInventoryChanged
            })
            .collect::<Vec<_>>();

        assert!(
            !query_changes.is_empty(),
            "snapshot adoption adds query operations"
        );
        assert!(query_changes
            .iter()
            .all(|change| change.classification == DiffClassification::AccessChange));
        assert!(diff
            .changes
            .iter()
            .all(|change| change.classification != DiffClassification::Unsupported));
    }

    #[test]
    fn query_rewrite_from_readable_filterable_delta_is_supported_access_change() {
        let baseline = compiled_temporal_with_profile(r#""list","snapshot""#, "");
        let candidate = compiled_temporal_with_profile_fields(
            r#""list","snapshot""#,
            r#",{"id":"label","type":"string","maxLength":32,"classification":"internal"}"#,
            r#""readableFields":["subject","valid-from","valid-to","label"],"filterableFields":["subject","valid-from","label"]"#,
            "",
        );

        let diff = classify_registry_diff(&baseline, &candidate, PACKAGE_REVISION);

        assert!(diff.changes.iter().any(|change| {
            change.change.code == CompiledRegistryChangeCode::QueryInventoryChanged
                && change.classification == DiffClassification::AccessChange
        }));
    }

    #[test]
    fn changed_query_shape_without_operation_removal_requires_reviewed_access_change() {
        let baseline = compiled_temporal_with_profile(r#""list","snapshot""#, "");
        let candidate =
            compiled_temporal_with_profile(r#""list","snapshot""#, r#", "allowCount": true"#);

        let diff = classify_registry_diff(&baseline, &candidate, PACKAGE_REVISION);

        assert!(diff.changes.iter().any(|change| {
            change.change.code == CompiledRegistryChangeCode::QueryInventoryChanged
                && change.classification == DiffClassification::AccessChange
        }));
    }

    fn assert_class(
        baseline: &CompiledRegistry,
        candidate: &CompiledRegistry,
        code: CompiledRegistryChangeCode,
        classification: DiffClassification,
    ) {
        let diff = classify_registry_diff(baseline, candidate, PACKAGE_REVISION);
        assert!(diff.changes.iter().any(|change| {
            change.change.code == code && change.classification == classification
        }));
    }

    fn compiled_temporal_with_profile(operations: &str, profile_extra: &str) -> CompiledRegistry {
        compiled_temporal_with_profile_fields(
            operations,
            "",
            r#""readableFields":["subject","valid-from","valid-to"],"filterableFields":["subject","valid-from"]"#,
            profile_extra,
        )
    }

    fn compiled_temporal_with_profile_fields(
        operations: &str,
        extra_fields: &str,
        access_fields: &str,
        profile_extra: &str,
    ) -> CompiledRegistry {
        let module_bytes = format!(
            r#"{{"id":"core","version":"1","entities":[{{"id":"membership","primaryDataset":"temporal-registry","route":"memberships","mutationMode":"mutable","fields":[{{"id":"subject","type":"string","maxLength":64,"required":true,"classification":"internal"}},{{"id":"valid-from","type":"date","required":true,"classification":"internal"}},{{"id":"valid-to","type":"date","classification":"internal"}}{extra_fields}],"temporal":{{"startField":"valid-from","endField":"valid-to"}},"constraints":[{{"id":"membership-window","kind":"temporal-non-overlap","scopeFields":["subject"],"startField":"valid-from","endField":"valid-to"}}],"accessProfiles":[{{"rowBoundaries": [], "id":"consumer","principalClaim":"principal","operations":[{operations}],{access_fields}{profile_extra}}}]}}]}}"#
        );
        let module = parse_module_json(module_bytes.as_bytes()).expect("module parses");
        let digest = module_digest(&module);
        let project_bytes = format!(
            r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"temporal-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"environment":"local","instanceId":"instance-under-test","sequence":1,"sourceRevision":"compiler-source-revision"}},"manifestProjection":{{"accessProfile":"consumer","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Temporal Registry Catalog","publisher":{{"id":"temporal-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"temporal-registry-service","title":"Temporal Registry Catalog"}},"datasets":[{{"id":"temporal-registry","title":"Temporal Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"temporal-registry-data-service","title":"Temporal Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["temporal-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{digest}"}}]}}"#
        );
        let project = parse_project_json(project_bytes.as_bytes()).expect("project parses");
        compile_project(&project, &[module], CompileProfile::Production).expect("fixture compiles")
    }

    fn compiled(
        version: &str,
        classification: &str,
        extra_fields: &str,
        entity_members: &str,
        principal_claim: &str,
    ) -> CompiledRegistry {
        let module_bytes = format!(
            r#"{{"id":"core","version":"1","entities":[{{"id":"record","primaryDataset":"neutral-registry","route":"records","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":16,"classification":"{classification}"}}{extra_fields}],"accessProfiles":[{{"rowBoundaries": [], "id":"reader","principalClaim":"{principal_claim}","operations":["get"],"readableFields":["code"]}}]{entity_members}}}]}}"#
        );
        let module = parse_module_json(module_bytes.as_bytes()).expect("module parses");
        let digest = module_digest(&module);
        let project_bytes = format!(
            r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"{version}","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"environment":"local","instanceId":"instance-under-test","sequence":1,"sourceRevision":"compiler-source-revision"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"restricted","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{digest}"}}]}}"#
        );
        let project = parse_project_json(project_bytes.as_bytes()).expect("project parses");
        compile_project(&project, &[module], CompileProfile::Production).expect("fixture compiles")
    }
}
