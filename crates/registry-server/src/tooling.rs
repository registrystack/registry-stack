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
        | Code::QueryInventoryChanged
        | Code::RouteAdded
        | Code::RouteRemoved
        | Code::RouteChanged => DiffClassification::AccessChange,
        Code::EventAdded | Code::EventRemoved | Code::EventChanged => {
            DiffClassification::Unsupported
        }
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

fn access_change_details(
    baseline: &CompiledRegistry,
    candidate: &CompiledRegistry,
    change: &CompiledRegistryChange,
) -> Vec<AccessChangeDetail> {
    use serde_json::{json, Value};
    use CompiledRegistryChangeCode as Code;
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
                entity.and_then(|e| e.events.get(member)).map(|e| json!({"projection": e.projection, "destinationId": e.webhook.as_ref().map(|w| &w.destination_id)})).unwrap_or(Value::Null)
            };
            (summarize(before_entity), summarize(after_entity))
        }
        _ => return vec![],
    };
    if before.is_null() || after.is_null() {
        return vec![AccessChangeDetail {
            field: "profileOrRequirements".into(),
            direction: AccessChangeDirection::ReviewRequired,
            before,
            after,
        }];
    }
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
            Some(AccessChangeDetail {
                field: field.clone(),
                direction: access_direction(field, left, right),
                before: left.clone(),
                after: right.clone(),
            })
        })
        .collect()
}

fn access_direction(
    field: &str,
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> AccessChangeDirection {
    use AccessChangeDirection::{Narrowing, ReviewRequired, Widening};
    let reverse = matches!(field, "requiredScopes" | "rowBoundaries");
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

    fn compiled(
        version: &str,
        classification: &str,
        extra_fields: &str,
        entity_members: &str,
        principal_claim: &str,
    ) -> CompiledRegistry {
        let module_bytes = format!(
            r#"{{"id":"core","version":"1","entities":[{{"id":"record","route":"records","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":16,"classification":"{classification}"}}{extra_fields}],"accessProfiles":[{{"id":"reader","principalClaim":"{principal_claim}","operations":["get"],"readableFields":["code"]}}]{entity_members}}}]}}"#
        );
        let module = parse_module_json(module_bytes.as_bytes()).expect("module parses");
        let digest = module_digest(&module);
        let project_bytes = format!(
            r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"{version}","defaultLanguage":"en"}},"package":{{"environment":"local","instanceId":"instance-under-test","sequence":1,"sourceRevision":"compiler-source-revision"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"restricted","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"name":"Package Test Publisher"}}}},"dataset":{{"title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}}},"modules":[{{"id":"core","version":"1","digest":"{digest}"}}]}}"#
        );
        let project = parse_project_json(project_bytes.as_bytes()).expect("project parses");
        compile_project(&project, &[module], CompileProfile::Production).expect("fixture compiles")
    }
}
