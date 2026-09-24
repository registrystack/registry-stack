// SPDX-License-Identifier: Apache-2.0

//! `bregctl diff` guards over consent configuration. None refuses: each one
//! asks for review and says why, because the runtime cannot see the earlier
//! configuration a consent was given under.

#[path = "support/consent_fixture.rs"]
mod consent_fixture;

use consent_fixture::{compile, self_issued_project, source, CONSENT_RECORD};
use registry_breg::package::CompiledRegistryChangeCode as Code;
use registry_breg::tooling::{
    classify_registry_diff, AccessChangeDetail, AccessChangeDirection, ClassifiedRegistryChange,
    CompiledRegistryDiff, DiffClassification,
};
use serde_json::{json, Value};

const PACKAGE_REVISION: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const FOOD_TARGETING: usize = 0;
const STEWARD: usize = 2;
const PERSON_PERMISSION: usize = 0;

fn classify(before: &Value, after: &Value) -> CompiledRegistryDiff {
    classify_registry_diff(
        &compile(before).unwrap(),
        &compile(after).unwrap(),
        PACKAGE_REVISION,
    )
}

fn change<'a>(
    diff: &'a CompiledRegistryDiff,
    code: Code,
    member: Option<&str>,
) -> &'a ClassifiedRegistryChange {
    diff.changes
        .iter()
        .find(|change| {
            change.change.code == code && change.change.target.member_id.as_deref() == member
        })
        .unwrap_or_else(|| panic!("{code:?} at {member:?} in {diff:#?}"))
}

/// The change to one entity's permission in a profile.
fn profile_change<'a>(
    diff: &'a CompiledRegistryDiff,
    entity: &str,
    profile: &str,
) -> &'a ClassifiedRegistryChange {
    diff.changes
        .iter()
        .find(|change| {
            change.change.code == Code::AccessProfileChanged
                && change.change.target.entity_id.as_deref() == Some(entity)
                && change.change.target.member_id.as_deref() == Some(profile)
        })
        .unwrap_or_else(|| panic!("{profile} over {entity} in {diff:#?}"))
}

fn detail<'a>(change: &'a ClassifiedRegistryChange, field: &str) -> &'a AccessChangeDetail {
    change
        .access_details
        .iter()
        .find(|detail| detail.field == field)
        .unwrap_or_else(|| panic!("{field} in {change:#?}"))
}

fn assert_guard(detail: &AccessChangeDetail, reason: &str) {
    assert_eq!(
        detail.direction,
        AccessChangeDirection::ReviewRequired,
        "{detail:?}"
    );
    let stated = detail.reason.as_deref().unwrap_or_default();
    assert!(stated.contains(reason), "{reason:?} in {detail:?}");
}

fn food_targeting_person(value: &mut Value) -> &mut Value {
    &mut value["accessProfiles"][FOOD_TARGETING]["permissions"][PERSON_PERMISSION]
}

#[test]
fn widening_a_gated_profile_asks_for_a_new_scope() {
    let mut widened = source();
    food_targeting_person(&mut widened)["filterableFields"] = json!(["district", "given-name"]);
    widened["accessProfiles"][FOOD_TARGETING]["requiredPurposes"] =
        json!(["food-assistance", "health-referral"]);
    let diff = classify(&source(), &widened);
    let person = profile_change(&diff, "person", "food-targeting");
    for field in ["filterableFields", "requiredPurposes"] {
        assert_guard(detail(person, field), "a new profile id is a new scope");
    }
}

#[test]
fn adding_a_lookup_to_a_gated_profile_asks_for_a_new_scope() {
    let mut narrowed = source();
    food_targeting_person(&mut narrowed)
        .as_object_mut()
        .unwrap()
        .remove("lookups");
    food_targeting_person(&mut narrowed)["operations"] =
        json!(["get", "list", "snapshot", "revisions"]);
    // Removing the lookup narrows the scope and states no consent reason.
    let removed = classify(&source(), &narrowed);
    let person = profile_change(&removed, "person", "food-targeting");
    assert!(
        person
            .access_details
            .iter()
            .all(|detail| detail.reason.is_none()),
        "{person:#?}"
    );
    assert_eq!(
        detail(person, "operations").direction,
        AccessChangeDirection::Narrowing
    );
    // Adding it back widens the scope.
    let added = classify(&narrowed, &source());
    let person = profile_change(&added, "person", "food-targeting");
    assert_guard(detail(person, "lookups"), "a new profile id is a new scope");
    assert_guard(
        detail(person, "operations"),
        "a new profile id is a new scope",
    );
}

#[test]
fn widening_an_ungated_profile_keeps_its_plain_direction() {
    let mut widened = source();
    widened["accessProfiles"][STEWARD]["permissions"][0]["filterableFields"] = json!(["district"]);
    let diff = classify(&source(), &widened);
    let steward = profile_change(&diff, "person", "steward");
    let filterable = detail(steward, "filterableFields");
    assert_eq!(filterable.direction, AccessChangeDirection::Widening);
    assert_eq!(filterable.reason, None);
}

#[test]
fn ungating_a_profile_asks_to_rename_it_and_retire_the_scope() {
    let mut ungated = source();
    food_targeting_person(&mut ungated)
        .as_object_mut()
        .unwrap()
        .remove("requireConsent");
    let diff = classify(&source(), &ungated);
    let person = profile_change(&diff, "person", "food-targeting");
    assert_guard(detail(person, "requireConsent"), "rename the profile");
    assert_guard(detail(person, "requireConsent"), "retiredConsentScopes");
}

#[test]
fn adding_a_client_to_an_organization_extends_its_consents() {
    let mut added = source();
    added["recipients"]["organizations"][0]["clients"] = json!(["wfp-scope", "wfp-field"]);
    let diff = classify(&source(), &added);
    let wfp = change(&diff, Code::RecipientOrganizationChanged, Some("wfp"));
    assert_eq!(wfp.classification, DiffClassification::AccessChange);
    assert_guard(detail(wfp, "clients"), "onto the new client");

    let removed = classify(&added, &source());
    let wfp = change(&removed, Code::RecipientOrganizationChanged, Some("wfp"));
    let clients = detail(wfp, "clients");
    assert_eq!(clients.direction, AccessChangeDirection::Narrowing);
    assert_eq!(clients.reason, None);
}

#[test]
fn changing_group_membership_changes_who_holds_its_consents() {
    for members in [json!(["wfp", "ngo-alpha", "ngo-beta"]), json!(["wfp"])] {
        let mut changed = source();
        changed["recipients"]["groups"][0]["members"] = members;
        let diff = classify(&source(), &changed);
        let group = change(&diff, Code::RecipientGroupChanged, Some("referral-network"));
        assert_eq!(group.classification, DiffClassification::AccessChange);
        assert_guard(detail(group, "members"), "prefer a new group id");
    }
}

#[test]
fn raising_max_duration_outlasts_the_notice() {
    let mut raised = source();
    raised["entities"][CONSENT_RECORD]["consentRecord"]["validity"]["maxDuration"] = json!("P2Y");
    let diff = classify(&source(), &raised);
    let record = change(&diff, Code::ConsentRecordChanged, None);
    assert_eq!(record.classification, DiffClassification::AccessChange);
    assert_guard(detail(record, "maxDuration"), "longer than the notice said");

    let lowered = classify(&raised, &source());
    let record = change(&lowered, Code::ConsentRecordChanged, None);
    let duration = detail(record, "maxDuration");
    assert_eq!(duration.direction, AccessChangeDirection::Narrowing);
    assert_eq!(duration.reason, None);
}

#[test]
fn removing_a_consent_vocabulary_code_asks_to_retire_it() {
    let mut removed = source();
    removed["recipients"]["organizations"]
        .as_array_mut()
        .unwrap()
        .remove(2);
    removed["recipients"]["groups"] = json!([]);
    removed
        .as_object_mut()
        .unwrap()
        .remove("retiredConsentScopes");
    let diff = classify(&source(), &removed);
    for (code, member) in [
        (Code::RecipientOrganizationRemoved, "ngo-beta"),
        (Code::RecipientGroupRemoved, "referral-network"),
    ] {
        let removal = change(&diff, code, Some(member));
        assert_eq!(removal.classification, DiffClassification::AccessChange);
        assert_eq!(removal.access_details.len(), 1, "{removal:#?}");
        assert_guard(&removal.access_details[0], "append-only");
    }
    for field in ["recipient", "scope"] {
        let column = change(&diff, Code::FieldTypeChanged, Some(field));
        assert_eq!(
            column.classification,
            DiffClassification::DestructiveOrIrreversible
        );
        assert_guard(detail(column, "values"), "append-only");
    }
}

#[test]
fn a_steward_issuer_creates_consent_without_the_subject() {
    let before = self_issued_project();
    let mut switched = before.clone();
    switched["actions"][1]["consentIssuer"] = json!("steward");
    let diff = classify(&before, &switched);
    let action = change(&diff, Code::ActionChanged, Some("withdraw-consent"));
    assert_eq!(action.classification, DiffClassification::AccessChange);
    assert_guard(
        detail(action, "consentIssuer"),
        "without the subject's principal",
    );

    // Switching back to the subject states no consent reason.
    let restored = classify(&switched, &before);
    let action = change(&restored, Code::ActionChanged, Some("withdraw-consent"));
    assert!(
        action
            .access_details
            .iter()
            .all(|detail| detail.reason.is_none()),
        "{action:#?}"
    );

    let mut added = source();
    let mut second = added["actions"][0].clone();
    second["id"] = json!("record-referral-consent");
    added["actions"].as_array_mut().unwrap().push(second);
    let mut permission = added["accessProfiles"][STEWARD]["permissions"][5].clone();
    assert_eq!(permission["action"], "record-consent");
    permission["action"] = json!("record-referral-consent");
    added["accessProfiles"][STEWARD]["permissions"]
        .as_array_mut()
        .unwrap()
        .push(permission);
    let diff = classify(&source(), &added);
    let action = change(&diff, Code::ActionAdded, Some("record-referral-consent"));
    assert_eq!(action.classification, DiffClassification::AccessChange);
    assert_guard(
        detail(action, "consentIssuer"),
        "without the subject's principal",
    );
}

#[test]
fn widened_action_codes_stay_additive_and_say_what_they_accept() {
    let mut added = source();
    added["recipients"]["organizations"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "ngo-gamma", "name": "NGO Gamma",
            "contact": "privacy@ngo-gamma.example.test", "clients": []
        }));
    let diff = classify(&source(), &added);
    let action = change(
        &diff,
        Code::ActionVocabularyCodesAdded,
        Some("record-consent"),
    );
    assert_eq!(
        action.classification,
        DiffClassification::CompatibleAdditive
    );
    let codes = detail(action, "inputCodes");
    assert_guard(codes, "without review");
    assert_eq!(
        codes.after["recipient"],
        json!([
            "ngo-alpha",
            "ngo-beta",
            "ngo-gamma",
            "referral-network",
            "wfp"
        ])
    );
    assert!(codes.before.get("purpose").is_none(), "{codes:?}");
    let organization = change(&diff, Code::RecipientOrganizationAdded, Some("ngo-gamma"));
    assert_eq!(
        organization.classification,
        DiffClassification::AccessChange
    );
    assert!(organization
        .access_details
        .iter()
        .all(|d| d.reason.is_none()));
}

#[test]
fn a_consent_change_never_classifies_as_unsupported() {
    let mut changed = source();
    changed["recipients"]["organizations"][2]["clients"] = json!(["ngo-beta-portal"]);
    changed["recipients"]["groups"][0]["members"] = json!(["wfp"]);
    changed["entities"][CONSENT_RECORD]["consentRecord"]["validity"]["maxDuration"] = json!("P30D");
    let diff = classify(&source(), &changed);
    assert!(
        diff.changes
            .iter()
            .all(|change| change.classification != DiffClassification::Unsupported),
        "{diff:#?}"
    );
}
