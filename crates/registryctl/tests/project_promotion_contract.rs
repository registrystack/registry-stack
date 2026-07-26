// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

#[path = "../src/project_authoring/promotion.rs"]
mod promotion;

use promotion::{
    build_project_promotion_report, ProjectPromotionBuildError, ProjectPromotionInput,
    ProjectPromotionReportV1, PromotionBlockingReason, PromotionChangeEffect, PromotionChangeInput,
    PromotionChangeKind, PromotionCompatibilityInput, PromotionCompatibilityState,
    PromotionDisposition, PromotionFieldClassification, PromotionFieldOwnership,
    PromotionProductAction, ReviewedCeilingInput, ReviewedRevisionComparison, TrustResolutionInput,
    MAX_PROMOTION_CHANGES,
};
use serde_json::{json, Value};

const SCHEMA: &str =
    include_str!("../schemas/project-reports/registry.project.promotion.v1.schema.json");
const FIXTURE: &str = include_str!("fixtures/project-reports/registry.project.promotion.v1.json");

fn parse(input: &str) -> Value {
    serde_json::from_str(input).expect("JSON parses")
}

fn validator() -> jsonschema::JSONSchema {
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&parse(SCHEMA))
        .expect("promotion schema compiles")
}

fn assert_schema_valid(document: &Value) {
    if let Err(errors) = validator().validate(document) {
        let details = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("document should validate: {details:?}");
    }
}

fn assert_schema_invalid(document: &Value) {
    assert!(
        validator().validate(document).is_err(),
        "document should not validate"
    );
}

fn compatible() -> PromotionCompatibilityInput {
    PromotionCompatibilityInput {
        product: PromotionCompatibilityState::Compatible,
        capability: PromotionCompatibilityState::Compatible,
        schema: PromotionCompatibilityState::Compatible,
        abi: PromotionCompatibilityState::Compatible,
    }
}

fn change(
    kind: PromotionChangeKind,
    classification: PromotionFieldClassification,
    ownership: PromotionFieldOwnership,
    effect: PromotionChangeEffect,
) -> PromotionChangeInput {
    PromotionChangeInput {
        kind,
        classification: Some(classification),
        ownership,
        effect,
    }
}

fn canonical_input() -> ProjectPromotionInput {
    ProjectPromotionInput {
        reviewed_revision: ReviewedRevisionComparison::DifferentReviewedSemanticRevision,
        changes: vec![
            change(
                PromotionChangeKind::CapabilityEnablement,
                PromotionFieldClassification::Structural,
                PromotionFieldOwnership::EnvironmentOwned,
                PromotionChangeEffect::ChangedWithinReviewedAuthority,
            ),
            change(
                PromotionChangeKind::Disclosure,
                PromotionFieldClassification::Internal,
                PromotionFieldOwnership::ReviewedProjectOwned,
                PromotionChangeEffect::Narrowed,
            ),
            change(
                PromotionChangeKind::Origin,
                PromotionFieldClassification::Sensitive,
                PromotionFieldOwnership::EnvironmentOwned,
                PromotionChangeEffect::ChangedWithinReviewedAuthority,
            ),
            change(
                PromotionChangeKind::Purpose,
                PromotionFieldClassification::Internal,
                PromotionFieldOwnership::ReviewedProjectOwned,
                PromotionChangeEffect::ChangedWithinReviewedAuthority,
            ),
            change(
                PromotionChangeKind::CredentialBinding,
                PromotionFieldClassification::SecretReference,
                PromotionFieldOwnership::EnvironmentOwned,
                PromotionChangeEffect::ChangedWithinReviewedAuthority,
            ),
            change(
                PromotionChangeKind::IntegrationCeiling,
                PromotionFieldClassification::Structural,
                PromotionFieldOwnership::ReviewedProjectOwned,
                PromotionChangeEffect::Narrowed,
            ),
            change(
                PromotionChangeKind::Trust,
                PromotionFieldClassification::Sensitive,
                PromotionFieldOwnership::EnvironmentOwned,
                PromotionChangeEffect::ChangedWithinReviewedAuthority,
            ),
            change(
                PromotionChangeKind::Operational,
                PromotionFieldClassification::Internal,
                PromotionFieldOwnership::EnvironmentOwned,
                PromotionChangeEffect::ChangedWithinReviewedAuthority,
            ),
            change(
                PromotionChangeKind::Claim,
                PromotionFieldClassification::Internal,
                PromotionFieldOwnership::ReviewedProjectOwned,
                PromotionChangeEffect::ChangedWithinReviewedAuthority,
            ),
            change(
                PromotionChangeKind::ProductEnablement,
                PromotionFieldClassification::Structural,
                PromotionFieldOwnership::EnvironmentOwned,
                PromotionChangeEffect::ChangedWithinReviewedAuthority,
            ),
            change(
                PromotionChangeKind::ServicePolicy,
                PromotionFieldClassification::Internal,
                PromotionFieldOwnership::ReviewedProjectOwned,
                PromotionChangeEffect::Narrowed,
            ),
            change(
                PromotionChangeKind::Caller,
                PromotionFieldClassification::Sensitive,
                PromotionFieldOwnership::EnvironmentOwned,
                PromotionChangeEffect::Narrowed,
            ),
        ],
        reviewed_ceiling: ReviewedCeilingInput::Narrowed,
        trust: TrustResolutionInput::Resolved,
        compatibility: compatible(),
    }
}

#[test]
fn canonical_fixture_validates_and_roundtrips_exactly() {
    let document = parse(FIXTURE);
    assert_schema_valid(&document);
    let decoded: ProjectPromotionReportV1 =
        serde_json::from_value(document.clone()).expect("canonical fixture decodes");
    assert_eq!(
        serde_json::to_value(decoded).expect("canonical fixture re-encodes"),
        document
    );
}

#[test]
fn pure_builder_is_deterministic_value_free_and_matches_fixture() {
    let first = build_project_promotion_report(canonical_input()).expect("report builds");
    let second = build_project_promotion_report(canonical_input()).expect("report rebuilds");
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_value(&first).expect("report serializes"),
        parse(FIXTURE)
    );
    assert_eq!(
        first.disposition,
        PromotionDisposition::ReadyAfterRequiredActions
    );
    assert_eq!(
        first.required_actions.re_sign,
        PromotionProductAction::RelayAndNotary
    );
    assert_eq!(
        first.required_actions.reactivate,
        PromotionProductAction::RelayAndNotary
    );
    assert_eq!(
        first.required_actions.restart,
        PromotionProductAction::RelayAndNotary
    );
    assert!(first.blocking_reasons.is_empty());
}

#[test]
fn policy_and_ceiling_widening_fail_closed() {
    let report = build_project_promotion_report(ProjectPromotionInput {
        reviewed_revision: ReviewedRevisionComparison::DifferentReviewedSemanticRevision,
        changes: vec![change(
            PromotionChangeKind::ServicePolicy,
            PromotionFieldClassification::Internal,
            PromotionFieldOwnership::ReviewedProjectOwned,
            PromotionChangeEffect::Widened,
        )],
        reviewed_ceiling: ReviewedCeilingInput::Widened,
        trust: TrustResolutionInput::Resolved,
        compatibility: compatible(),
    })
    .expect("blocked report builds");

    assert_eq!(report.disposition, PromotionDisposition::Blocked);
    assert!(report
        .blocking_reasons
        .contains(&PromotionBlockingReason::PolicyWidening));
    assert!(report
        .blocking_reasons
        .contains(&PromotionBlockingReason::ReviewedCeilingWidening));
}

#[test]
fn missing_incompatible_and_unresolved_compatibility_fail_closed() {
    let report = build_project_promotion_report(ProjectPromotionInput {
        reviewed_revision: ReviewedRevisionComparison::SameReviewedSemanticRevision,
        changes: Vec::new(),
        reviewed_ceiling: ReviewedCeilingInput::WithinReviewedCeiling,
        trust: TrustResolutionInput::Unresolved,
        compatibility: PromotionCompatibilityInput {
            product: PromotionCompatibilityState::Compatible,
            capability: PromotionCompatibilityState::Missing,
            schema: PromotionCompatibilityState::Incompatible,
            abi: PromotionCompatibilityState::Unresolved,
        },
    })
    .expect("blocked report builds");

    assert_eq!(report.disposition, PromotionDisposition::Blocked);
    for reason in [
        PromotionBlockingReason::TrustUnresolved,
        PromotionBlockingReason::MissingCapability,
        PromotionBlockingReason::IncompatibleSchema,
        PromotionBlockingReason::CompatibilityUnresolved,
    ] {
        assert!(report.blocking_reasons.contains(&reason));
    }
}

#[test]
fn ownership_and_classification_boundaries_fail_closed() {
    let report = build_project_promotion_report(ProjectPromotionInput {
        reviewed_revision: ReviewedRevisionComparison::SameReviewedSemanticRevision,
        changes: vec![
            change(
                PromotionChangeKind::Origin,
                PromotionFieldClassification::Sensitive,
                PromotionFieldOwnership::ReviewedProjectOwned,
                PromotionChangeEffect::ChangedWithinReviewedAuthority,
            ),
            PromotionChangeInput {
                kind: PromotionChangeKind::Operational,
                classification: None,
                ownership: PromotionFieldOwnership::Unclassified,
                effect: PromotionChangeEffect::Unresolved,
            },
            change(
                PromotionChangeKind::Claim,
                PromotionFieldClassification::Internal,
                PromotionFieldOwnership::ReviewedProjectOwned,
                PromotionChangeEffect::ChangedWithinReviewedAuthority,
            ),
        ],
        reviewed_ceiling: ReviewedCeilingInput::WithinReviewedCeiling,
        trust: TrustResolutionInput::Resolved,
        compatibility: compatible(),
    })
    .expect("blocked report builds");

    assert_eq!(report.disposition, PromotionDisposition::Blocked);
    for reason in [
        PromotionBlockingReason::EnvironmentOwnershipViolation,
        PromotionBlockingReason::UnclassifiedChange,
        PromotionBlockingReason::UnresolvedChange,
    ] {
        assert!(report.blocking_reasons.contains(&reason));
    }
}

#[test]
fn incomplete_revision_and_ceiling_evidence_fail_closed() {
    let report = build_project_promotion_report(ProjectPromotionInput {
        reviewed_revision: ReviewedRevisionComparison::DifferentReviewedSemanticRevision,
        changes: vec![change(
            PromotionChangeKind::Origin,
            PromotionFieldClassification::Sensitive,
            PromotionFieldOwnership::EnvironmentOwned,
            PromotionChangeEffect::ChangedWithinReviewedAuthority,
        )],
        reviewed_ceiling: ReviewedCeilingInput::Narrowed,
        trust: TrustResolutionInput::Resolved,
        compatibility: compatible(),
    })
    .expect("blocked report builds");
    assert_eq!(report.disposition, PromotionDisposition::Blocked);
    assert!(report
        .blocking_reasons
        .contains(&PromotionBlockingReason::ComparisonEvidenceIncomplete));
}

#[test]
fn schema_and_dto_reject_unknown_fields_and_value_sentinels() {
    for (pointer, field, sentinel) in [
        ("", "source_environment", "COUNTRY_ENVIRONMENT_SENTINEL"),
        (
            "/changes/0",
            "origin",
            "https://COUNTRY_ORIGIN_SENTINEL.invalid",
        ),
        ("/changes/1", "secret_name", "COUNTRY_SECRET_NAME_SENTINEL"),
        ("/changes/2", "client_id", "COUNTRY_CLIENT_ID_SENTINEL"),
        ("/changes/3", "value", "COUNTRY_VALUE_SENTINEL"),
        ("/changes/4", "digest", "COUNTRY_SENSITIVE_HASH_SENTINEL"),
    ] {
        let mut document = parse(FIXTURE);
        document
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .expect("test object exists")
            .insert(field.to_owned(), json!(sentinel));
        assert_schema_invalid(&document);
        assert!(serde_json::from_value::<ProjectPromotionReportV1>(document).is_err());
    }

    let mut path_sentinel = parse(FIXTURE);
    path_sentinel["changes"][0]["address"]["path"] = json!("/COUNTRY/PATH/SENTINEL");
    assert_schema_invalid(&path_sentinel);
    assert!(serde_json::from_value::<ProjectPromotionReportV1>(path_sentinel).is_err());

    let serialized = serde_json::to_string(
        &build_project_promotion_report(canonical_input()).expect("report builds"),
    )
    .expect("report serializes");
    for forbidden in [
        "COUNTRY_",
        "https://",
        "client_id",
        "secret_name",
        "source_environment",
        "target_environment",
    ] {
        assert!(!serialized.contains(forbidden));
    }
}

#[test]
fn report_cannot_claim_deployment_or_runtime_activation() {
    let mut document = parse(FIXTURE);
    document["deployment"] = json!("performed");
    assert_schema_invalid(&document);

    let mut document = parse(FIXTURE);
    document["runtime_activation"] = json!("active");
    assert_schema_invalid(&document);

    let mut document = parse(FIXTURE);
    document["evidence_limitations"][2] = json!("deployment_verified");
    assert_schema_invalid(&document);
}

#[test]
fn dto_rejects_decisions_that_do_not_match_the_classified_evidence() {
    let mut document = parse(FIXTURE);
    document["disposition"] = json!("ready");
    assert!(
        validator().validate(&document).is_ok(),
        "the structural schema deliberately leaves cross-field decisions to the DTO"
    );
    assert!(serde_json::from_value::<ProjectPromotionReportV1>(document).is_err());

    let mut document = parse(FIXTURE);
    document["changes"][0]["boundary"] = json!("allowed_environment_owned");
    assert!(serde_json::from_value::<ProjectPromotionReportV1>(document).is_err());

    let mut document = parse(FIXTURE);
    document["compatibility"]
        .as_array_mut()
        .expect("compatibility is an array")
        .swap(0, 1);
    assert_schema_invalid(&document);
    assert!(serde_json::from_value::<ProjectPromotionReportV1>(document).is_err());
}

#[test]
fn change_capacity_is_bounded_before_report_construction() {
    let repeated = change(
        PromotionChangeKind::Origin,
        PromotionFieldClassification::Sensitive,
        PromotionFieldOwnership::EnvironmentOwned,
        PromotionChangeEffect::ChangedWithinReviewedAuthority,
    );
    let error = build_project_promotion_report(ProjectPromotionInput {
        reviewed_revision: ReviewedRevisionComparison::SameReviewedSemanticRevision,
        changes: vec![repeated; MAX_PROMOTION_CHANGES + 1],
        reviewed_ceiling: ReviewedCeilingInput::WithinReviewedCeiling,
        trust: TrustResolutionInput::Resolved,
        compatibility: compatible(),
    });
    assert_eq!(error, Err(ProjectPromotionBuildError::TooManyChanges));
}
