// SPDX-License-Identifier: Apache-2.0

use registryctl::{
    build_project_migration_report, AuthoringVersionSet, MigrationAffectedCount,
    MigrationAffectedSurfaces, MigrationApplicationPolicy, MigrationArtifact,
    MigrationAuthoredFilePolicy, MigrationBlockingReason, MigrationCandidateArtifact,
    MigrationCandidateEligibility, MigrationCandidateEmission, MigrationChangeInput,
    MigrationCompatibility, MigrationDecisionKind, MigrationDecisionOwner, MigrationDecisionScope,
    MigrationDiagnostic, MigrationDiagnosticCode, MigrationDiagnosticPhase,
    MigrationDiagnosticRemediation, MigrationDisposition, MigrationExecution, MigrationField,
    MigrationGateResults, MigrationGateStatus, MigrationOperation, MigrationOutputMode,
    MigrationOutputRequest, MigrationReplacementDisposition, MigrationReplacementInput,
    MigrationReviewClass, MigrationSafety, MigrationSemanticEffect, MigrationVersionDirection,
    MigrationVersionSupport, MigrationVersionSupportAssessment, MigrationWriteAuthority,
    ProjectMigrationBuildError, ProjectMigrationInput, ProjectMigrationReportV1,
    UnresolvedMigrationDecision,
};
use serde_json::{json, Value};

const SCHEMA: &str =
    include_str!("../schemas/project-reports/registry.project.migration.v1.schema.json");
const FIXTURE: &str = include_str!("fixtures/project-reports/registry.project.migration.v1.json");

fn parse(input: &str) -> Value {
    serde_json::from_str(input).expect("JSON parses")
}

fn validator() -> jsonschema::JSONSchema {
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&parse(SCHEMA))
        .expect("migration schema compiles")
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

fn versions(version: u32) -> AuthoringVersionSet {
    AuthoringVersionSet {
        project: Some(version),
        integration: Some(version),
        entity: Some(version),
        fixture: Some(version),
        environment: Some(version),
    }
}

fn supported() -> MigrationVersionSupportAssessment {
    MigrationVersionSupportAssessment {
        source: MigrationVersionSupport::Supported,
        target: MigrationVersionSupport::Supported,
    }
}

fn all_passed() -> MigrationGateResults {
    MigrationGateResults {
        schema: MigrationGateStatus::Passed,
        fixture: MigrationGateStatus::Passed,
        check: MigrationGateStatus::Passed,
        build: MigrationGateStatus::Passed,
        generated_reference: MigrationGateStatus::Passed,
    }
}

fn all_not_applicable() -> MigrationGateResults {
    MigrationGateResults {
        schema: MigrationGateStatus::NotApplicable,
        fixture: MigrationGateStatus::NotApplicable,
        check: MigrationGateStatus::NotApplicable,
        build: MigrationGateStatus::NotApplicable,
        generated_reference: MigrationGateStatus::NotApplicable,
    }
}

fn absent_versions() -> AuthoringVersionSet {
    AuthoringVersionSet {
        project: None,
        integration: None,
        entity: None,
        fixture: None,
        environment: None,
    }
}

fn unaffected() -> MigrationAffectedSurfaces {
    MigrationAffectedSurfaces {
        fixtures: MigrationAffectedCount::known(0),
        services: MigrationAffectedCount::known(0),
        consultations: MigrationAffectedCount::known(0),
        claims: MigrationAffectedCount::known(0),
        environments: MigrationAffectedCount::known(0),
        generated_artifacts: Vec::new(),
    }
}

fn normalization(field: MigrationField) -> MigrationChangeInput {
    MigrationChangeInput {
        field,
        operation: MigrationOperation::NormalizeField,
        semantic_effect: MigrationSemanticEffect::Preserved,
        safety: MigrationSafety::Safe,
        replacement: MigrationReplacementInput::NotApplicable,
    }
}

fn canonical_input() -> ProjectMigrationInput {
    ProjectMigrationInput {
        source_versions: versions(1),
        target_versions: versions(1),
        version_support: supported(),
        changes: vec![
            normalization(MigrationField::EnvironmentDeployment),
            normalization(MigrationField::ProjectRegistry),
        ],
        affected: MigrationAffectedSurfaces {
            fixtures: MigrationAffectedCount::known(1),
            services: MigrationAffectedCount::known(1),
            consultations: MigrationAffectedCount::known(0),
            claims: MigrationAffectedCount::known(0),
            environments: MigrationAffectedCount::known(1),
            generated_artifacts: vec![
                MigrationArtifact::GeneratedConfigurationReference,
                MigrationArtifact::ProjectExplanation,
                MigrationArtifact::RelayConfig,
            ],
        },
        approved_reviews: vec![
            MigrationReviewClass::Authoring,
            MigrationReviewClass::Compatibility,
            MigrationReviewClass::Migration,
            MigrationReviewClass::Fixtures,
            MigrationReviewClass::Relay,
            MigrationReviewClass::Security,
            MigrationReviewClass::Operations,
            MigrationReviewClass::Documentation,
            MigrationReviewClass::Release,
        ],
        output: MigrationOutputRequest {
            mode: MigrationOutputMode::ReviewablePatch,
            write_authority: MigrationWriteAuthority::ExplicitCandidateWriteGranted,
            candidate_emission: MigrationCandidateEmission::NotEmitted,
        },
        rerun_gates: all_passed(),
        diagnostics: Vec::new(),
        unresolved_decisions: Vec::new(),
    }
}

fn unsupported_target_input(code: MigrationDiagnosticCode) -> ProjectMigrationInput {
    ProjectMigrationInput {
        source_versions: versions(1),
        target_versions: absent_versions(),
        version_support: MigrationVersionSupportAssessment {
            source: MigrationVersionSupport::Supported,
            target: MigrationVersionSupport::Unsupported,
        },
        changes: Vec::new(),
        affected: unaffected(),
        approved_reviews: Vec::new(),
        output: MigrationOutputRequest {
            mode: MigrationOutputMode::CheckOnly,
            write_authority: MigrationWriteAuthority::NotGranted,
            candidate_emission: MigrationCandidateEmission::NotEmitted,
        },
        rerun_gates: all_not_applicable(),
        diagnostics: vec![MigrationDiagnostic {
            code,
            phase: MigrationDiagnosticPhase::VersionInspection,
            contract: None,
            remediation: MigrationDiagnosticRemediation::SelectSupportedTargetVersion,
        }],
        unresolved_decisions: Vec::new(),
    }
}

#[test]
fn canonical_fixture_validates_and_roundtrips_exactly() {
    let document = parse(FIXTURE);
    assert_schema_valid(&document);
    let decoded: ProjectMigrationReportV1 =
        serde_json::from_value(document.clone()).expect("canonical fixture decodes");
    assert_eq!(
        serde_json::to_value(decoded).expect("canonical fixture re-encodes"),
        document
    );
}

#[test]
fn pure_builder_is_deterministic_value_free_and_matches_fixture() {
    let first = build_project_migration_report(canonical_input()).expect("report builds");
    let second = build_project_migration_report(canonical_input()).expect("report rebuilds");
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_value(&first).expect("report serializes"),
        parse(FIXTURE)
    );
    assert_eq!(
        first.disposition,
        MigrationDisposition::ReadyForExplicitWrite
    );
    assert_eq!(
        first.compatibility,
        MigrationCompatibility::CompatibleNormalizationOnly
    );
}

#[test]
fn compatible_normalization_is_separate_from_semantic_removal_and_rename() {
    let report = build_project_migration_report(ProjectMigrationInput {
        source_versions: versions(1),
        target_versions: versions(1),
        version_support: supported(),
        changes: vec![
            MigrationChangeInput {
                field: MigrationField::IntegrationInput,
                operation: MigrationOperation::RenameField,
                semantic_effect: MigrationSemanticEffect::Preserved,
                safety: MigrationSafety::Safe,
                replacement: MigrationReplacementInput::Field(
                    MigrationField::IntegrationCapability,
                ),
            },
            MigrationChangeInput {
                field: MigrationField::Claim,
                operation: MigrationOperation::RemoveField,
                semantic_effect: MigrationSemanticEffect::Changed,
                safety: MigrationSafety::Safe,
                replacement: MigrationReplacementInput::Field(MigrationField::ServicePolicy),
            },
        ],
        affected: MigrationAffectedSurfaces {
            fixtures: MigrationAffectedCount::known(1),
            services: MigrationAffectedCount::known(1),
            consultations: MigrationAffectedCount::known(0),
            claims: MigrationAffectedCount::known(1),
            environments: MigrationAffectedCount::known(0),
            generated_artifacts: vec![MigrationArtifact::NotaryConfig],
        },
        approved_reviews: Vec::new(),
        output: MigrationOutputRequest {
            mode: MigrationOutputMode::CheckOnly,
            write_authority: MigrationWriteAuthority::NotGranted,
            candidate_emission: MigrationCandidateEmission::NotEmitted,
        },
        rerun_gates: all_passed(),
        diagnostics: Vec::new(),
        unresolved_decisions: Vec::new(),
    })
    .expect("classified report builds");

    assert_eq!(report.compatible_normalizations.len(), 1);
    assert_eq!(
        report.compatible_normalizations[0].operation,
        MigrationOperation::RenameField
    );
    assert_eq!(
        report.compatible_normalizations[0].replacement.disposition,
        MigrationReplacementDisposition::Field
    );
    assert_eq!(report.semantic_changes.len(), 1);
    assert_eq!(
        report.semantic_changes[0].operation,
        MigrationOperation::RemoveField
    );
    assert_eq!(
        report.compatibility,
        MigrationCompatibility::SemanticReviewRequired
    );
    assert_eq!(report.disposition, MigrationDisposition::ReviewRequired);
}

#[test]
fn reviewed_same_v1_retirements_are_reviewable_without_claiming_semantic_equivalence() {
    let report = build_project_migration_report(ProjectMigrationInput {
        source_versions: versions(1),
        target_versions: versions(1),
        version_support: supported(),
        changes: vec![
            MigrationChangeInput {
                field: MigrationField::AttributeReleaseSubjectInput,
                operation: MigrationOperation::RemoveField,
                semantic_effect: MigrationSemanticEffect::Preserved,
                safety: MigrationSafety::Safe,
                replacement: MigrationReplacementInput::NoReplacement,
            },
            MigrationChangeInput {
                field: MigrationField::AttributeReleaseResponseMaxAge,
                operation: MigrationOperation::RemoveField,
                semantic_effect: MigrationSemanticEffect::Changed,
                safety: MigrationSafety::Safe,
                replacement: MigrationReplacementInput::NoReplacement,
            },
        ],
        affected: MigrationAffectedSurfaces {
            fixtures: MigrationAffectedCount::known(0),
            services: MigrationAffectedCount::known(1),
            consultations: MigrationAffectedCount::known(0),
            claims: MigrationAffectedCount::known(0),
            environments: MigrationAffectedCount::known(0),
            generated_artifacts: vec![MigrationArtifact::RelayConfig],
        },
        approved_reviews: Vec::new(),
        output: MigrationOutputRequest {
            mode: MigrationOutputMode::CheckOnly,
            write_authority: MigrationWriteAuthority::NotGranted,
            candidate_emission: MigrationCandidateEmission::NotEmitted,
        },
        rerun_gates: all_passed(),
        diagnostics: Vec::new(),
        unresolved_decisions: Vec::new(),
    })
    .expect("reviewed same-v1 report builds");

    assert_eq!(report.compatible_normalizations.len(), 1);
    assert_eq!(report.semantic_changes.len(), 1);
    assert_eq!(report.disposition, MigrationDisposition::ReviewRequired);
    assert!(!report
        .blocking_reasons
        .contains(&MigrationBlockingReason::RemovedFieldWithoutReplacement));
    assert!(report
        .reviews
        .iter()
        .any(|review| review.class == MigrationReviewClass::Privacy));
}

#[test]
fn unsafe_unresolved_or_incomplete_migration_fails_closed() {
    let mut source = versions(2);
    source.fixture = Some(1);
    let mut target = versions(1);
    target.fixture = None;
    let report = build_project_migration_report(ProjectMigrationInput {
        source_versions: source,
        target_versions: target,
        version_support: supported(),
        changes: vec![MigrationChangeInput {
            field: MigrationField::Claim,
            operation: MigrationOperation::RemoveField,
            semantic_effect: MigrationSemanticEffect::Changed,
            safety: MigrationSafety::Unsafe,
            replacement: MigrationReplacementInput::NoReplacement,
        }],
        affected: MigrationAffectedSurfaces {
            fixtures: MigrationAffectedCount::unresolved(),
            services: MigrationAffectedCount::known(1),
            consultations: MigrationAffectedCount::known(1),
            claims: MigrationAffectedCount::known(1),
            environments: MigrationAffectedCount::known(1),
            generated_artifacts: vec![MigrationArtifact::NotaryConfig],
        },
        approved_reviews: Vec::new(),
        output: MigrationOutputRequest {
            mode: MigrationOutputMode::ReviewablePatch,
            write_authority: MigrationWriteAuthority::NotGranted,
            candidate_emission: MigrationCandidateEmission::NotEmitted,
        },
        rerun_gates: MigrationGateResults {
            schema: MigrationGateStatus::Failed,
            fixture: MigrationGateStatus::NotRun,
            check: MigrationGateStatus::NotRun,
            build: MigrationGateStatus::NotRun,
            generated_reference: MigrationGateStatus::NotRun,
        },
        diagnostics: vec![registryctl::MigrationDiagnostic {
            code: registryctl::MigrationDiagnosticCode::RerunGateFailed,
            phase: registryctl::MigrationDiagnosticPhase::SchemaGate,
            contract: None,
            remediation: registryctl::MigrationDiagnosticRemediation::InspectCandidateSchema,
        }],
        unresolved_decisions: vec![
            UnresolvedMigrationDecision {
                owner: MigrationDecisionOwner::CountryAuthority,
                kind: MigrationDecisionKind::ClaimSemantics,
                scope: MigrationDecisionScope::Claim,
            },
            UnresolvedMigrationDecision {
                owner: MigrationDecisionOwner::ProjectOperator,
                kind: MigrationDecisionKind::OperatorTrust,
                scope: MigrationDecisionScope::Environment,
            },
        ],
    })
    .expect("blocked report builds");

    assert_schema_valid(&serde_json::to_value(&report).expect("blocked report serializes"));
    assert_eq!(report.disposition, MigrationDisposition::Blocked);
    assert_eq!(
        report.compatibility,
        MigrationCompatibility::UnsafeOrUnresolved
    );
    for reason in [
        MigrationBlockingReason::DowngradeOrContractRemoval,
        MigrationBlockingReason::UnsafeChange,
        MigrationBlockingReason::RemovedFieldWithoutReplacement,
        MigrationBlockingReason::AffectedSurfaceUnresolved,
        MigrationBlockingReason::UnresolvedCountryOrOperatorDecision,
        MigrationBlockingReason::RerunGateFailed,
        MigrationBlockingReason::RerunGateNotRun,
        MigrationBlockingReason::ExplicitWriteAuthorityMissing,
    ] {
        assert!(report.blocking_reasons.contains(&reason), "{reason:?}");
    }
    assert_eq!(report.unresolved_decisions.len(), 2);

    let supported_downgrade = build_project_migration_report(ProjectMigrationInput {
        source_versions: versions(2),
        target_versions: versions(1),
        version_support: supported(),
        changes: vec![normalization(MigrationField::ProjectRegistry)],
        affected: unaffected(),
        approved_reviews: Vec::new(),
        output: MigrationOutputRequest {
            mode: MigrationOutputMode::CheckOnly,
            write_authority: MigrationWriteAuthority::NotGranted,
            candidate_emission: MigrationCandidateEmission::NotEmitted,
        },
        rerun_gates: all_passed(),
        diagnostics: Vec::new(),
        unresolved_decisions: Vec::new(),
    })
    .expect("supported downgrade report builds");
    assert_eq!(
        supported_downgrade.compatibility,
        MigrationCompatibility::UnsafeOrUnresolved
    );
    assert!(supported_downgrade
        .blocking_reasons
        .contains(&MigrationBlockingReason::DowngradeOrContractRemoval));
}

#[test]
fn every_failed_gate_retains_one_closed_diagnostic_without_raw_error_text() {
    use registryctl::{
        MigrationDiagnostic, MigrationDiagnosticCode, MigrationDiagnosticPhase,
        MigrationDiagnosticRemediation,
    };

    let diagnostics = vec![
        MigrationDiagnostic {
            code: MigrationDiagnosticCode::RerunGateFailed,
            phase: MigrationDiagnosticPhase::SchemaGate,
            contract: None,
            remediation: MigrationDiagnosticRemediation::InspectCandidateSchema,
        },
        MigrationDiagnostic {
            code: MigrationDiagnosticCode::RerunGateFailed,
            phase: MigrationDiagnosticPhase::FixtureGate,
            contract: None,
            remediation: MigrationDiagnosticRemediation::RepairFixtures,
        },
        MigrationDiagnostic {
            code: MigrationDiagnosticCode::RerunGateFailed,
            phase: MigrationDiagnosticPhase::CheckGate,
            contract: None,
            remediation: MigrationDiagnosticRemediation::ResolveProjectCheck,
        },
        MigrationDiagnostic {
            code: MigrationDiagnosticCode::RerunGateFailed,
            phase: MigrationDiagnosticPhase::BuildGate,
            contract: None,
            remediation: MigrationDiagnosticRemediation::ResolveProjectBuild,
        },
        MigrationDiagnostic {
            code: MigrationDiagnosticCode::RerunGateFailed,
            phase: MigrationDiagnosticPhase::GeneratedReferenceGate,
            contract: None,
            remediation: MigrationDiagnosticRemediation::RegenerateConfigurationReference,
        },
    ];
    let report = build_project_migration_report(ProjectMigrationInput {
        source_versions: versions(1),
        target_versions: versions(1),
        version_support: supported(),
        changes: vec![normalization(MigrationField::ProjectRegistry)],
        affected: unaffected(),
        approved_reviews: Vec::new(),
        output: MigrationOutputRequest {
            mode: MigrationOutputMode::CheckOnly,
            write_authority: MigrationWriteAuthority::NotGranted,
            candidate_emission: MigrationCandidateEmission::NotEmitted,
        },
        rerun_gates: MigrationGateResults {
            schema: MigrationGateStatus::Failed,
            fixture: MigrationGateStatus::Failed,
            check: MigrationGateStatus::Failed,
            build: MigrationGateStatus::Failed,
            generated_reference: MigrationGateStatus::Failed,
        },
        diagnostics: diagnostics.clone(),
        unresolved_decisions: Vec::new(),
    })
    .expect("failed-gate report builds");

    assert_eq!(report.disposition, MigrationDisposition::Blocked);
    assert_eq!(report.diagnostics, diagnostics);
    let serialized = serde_json::to_string(&report).expect("report serializes");
    for forbidden in ["raw_error", "source_path", "COUNTRY_", "https://"] {
        assert!(!serialized.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn explicit_write_makes_a_candidate_eligible_without_applying_it() {
    let ready = build_project_migration_report(canonical_input()).expect("ready report builds");
    assert_eq!(ready.migration_execution, MigrationExecution::NotPerformed);
    assert_eq!(
        ready.output.candidate_eligibility,
        MigrationCandidateEligibility::EligibleToEmit
    );
    assert_eq!(
        ready.output.authored_file_policy,
        MigrationAuthoredFilePolicy::NeverOverwriteAuthoredFiles
    );
    assert_eq!(
        ready.output.application_policy,
        MigrationApplicationPolicy::ExplicitOperatorApplyRequired
    );
    assert_eq!(
        ready.output.candidate_emission,
        MigrationCandidateEmission::NotEmitted
    );

    let mut separate_output = canonical_input();
    separate_output.output.mode = MigrationOutputMode::SeparateOutputDirectory;
    let separate =
        build_project_migration_report(separate_output).expect("separate output report builds");
    assert_eq!(
        separate.output.candidate_artifact,
        MigrationCandidateArtifact::SeparateOutputDirectory
    );
    assert_eq!(
        separate.output.candidate_eligibility,
        MigrationCandidateEligibility::EligibleToEmit
    );

    let mut missing_authority = canonical_input();
    missing_authority.output.write_authority = MigrationWriteAuthority::NotGranted;
    let blocked = build_project_migration_report(missing_authority).expect("blocked report builds");
    assert_eq!(blocked.disposition, MigrationDisposition::Blocked);
    assert_eq!(
        blocked.output.candidate_eligibility,
        MigrationCandidateEligibility::Blocked
    );
    assert!(blocked
        .blocking_reasons
        .contains(&MigrationBlockingReason::ExplicitWriteAuthorityMissing));

    let mut mismatched_authority = canonical_input();
    mismatched_authority.output.mode = MigrationOutputMode::CheckOnly;
    let blocked =
        build_project_migration_report(mismatched_authority).expect("blocked report builds");
    assert!(blocked
        .blocking_reasons
        .contains(&MigrationBlockingReason::WriteAuthorityScopeMismatch));
}

#[test]
fn pending_reviews_allow_only_the_matching_review_candidate_emission() {
    let mut input = canonical_input();
    input.approved_reviews.clear();
    input.output.candidate_emission = MigrationCandidateEmission::ReviewablePatchCandidateEmitted;
    let report =
        build_project_migration_report(input).expect("reviewable pending candidate report builds");
    assert_eq!(report.disposition, MigrationDisposition::ReviewRequired);
    assert_eq!(
        report.output.candidate_eligibility,
        MigrationCandidateEligibility::EligibleToEmit
    );
    assert_eq!(
        report.output.candidate_emission,
        MigrationCandidateEmission::ReviewablePatchCandidateEmitted
    );
    assert!(report.blocking_reasons.is_empty());

    let mut invalid = canonical_input();
    invalid.output.candidate_emission = MigrationCandidateEmission::SeparateOutputCandidateEmitted;
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::InvalidCandidateEmission)
    );
}

#[test]
fn schema_and_dto_reject_unknown_fields_and_value_sentinels() {
    for (pointer, field, sentinel) in [
        ("", "country", "COUNTRY_IDENTIFIER_SENTINEL"),
        (
            "/compatible_normalizations/0",
            "value",
            "COUNTRY_VALUE_SENTINEL",
        ),
        (
            "/compatible_normalizations/1",
            "secret_name",
            "COUNTRY_SECRET_SENTINEL",
        ),
        ("/output", "output_path", "/COUNTRY/ABSOLUTE/PATH/SENTINEL"),
        (
            "/affected",
            "service_ids",
            "COUNTRY_SERVICE_IDENTIFIER_SENTINEL",
        ),
    ] {
        let mut document = parse(FIXTURE);
        document
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .expect("test object exists")
            .insert(field.to_owned(), json!(sentinel));
        assert_schema_invalid(&document);
        assert!(serde_json::from_value::<ProjectMigrationReportV1>(document).is_err());
    }

    let mut path_sentinel = parse(FIXTURE);
    path_sentinel["compatible_normalizations"][0]["address"]["path"] =
        json!("/COUNTRY/PATH/SENTINEL");
    assert_schema_invalid(&path_sentinel);
    assert!(serde_json::from_value::<ProjectMigrationReportV1>(path_sentinel).is_err());

    for (pointer, false_claim) in [
        ("/migration_execution", json!("performed")),
        (
            "/output/authored_file_policy",
            json!("overwrite_authored_files"),
        ),
        ("/output/candidate_emission", json!("candidate_emitted")),
        (
            "/evidence_limitations/3",
            json!("authored_files_overwritten"),
        ),
    ] {
        let mut document = parse(FIXTURE);
        *document.pointer_mut(pointer).expect("test field exists") = false_claim;
        assert_schema_invalid(&document);
        assert!(serde_json::from_value::<ProjectMigrationReportV1>(document).is_err());
    }

    let serialized = serde_json::to_string(
        &build_project_migration_report(canonical_input()).expect("report builds"),
    )
    .expect("report serializes");
    for forbidden in [
        "COUNTRY_",
        "https://",
        "secret_name",
        "secret_value",
        "source_path",
        "target_path",
        "registry_id",
        "service_id",
    ] {
        assert!(!serialized.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn dto_rejects_tampered_derived_decisions() {
    for mutation in [
        ("disposition", json!("checked_safe")),
        ("compatibility", json!("semantic_review_required")),
    ] {
        let mut document = parse(FIXTURE);
        document[mutation.0] = mutation.1;
        assert_schema_valid(&document);
        assert!(serde_json::from_value::<ProjectMigrationReportV1>(document).is_err());
    }

    let mut owner = parse(FIXTURE);
    owner["compatible_normalizations"][0]["owner"] = json!("country_author");
    assert_schema_valid(&owner);
    assert!(serde_json::from_value::<ProjectMigrationReportV1>(owner).is_err());

    let mut direction = parse(FIXTURE);
    direction["version_transitions"][0]["direction"] = json!("upgrade");
    assert_schema_valid(&direction);
    assert!(serde_json::from_value::<ProjectMigrationReportV1>(direction).is_err());

    let mut review = parse(FIXTURE);
    review["reviews"][0]["status"] = json!("required_pending");
    assert_schema_valid(&review);
    assert!(serde_json::from_value::<ProjectMigrationReportV1>(review).is_err());

    let mut gates = parse(FIXTURE);
    gates["rerun_gates"]
        .as_array_mut()
        .expect("gates are an array")
        .swap(0, 1);
    assert_schema_invalid(&gates);
    assert!(serde_json::from_value::<ProjectMigrationReportV1>(gates).is_err());

    let mut incoherent_diagnostic = parse(FIXTURE);
    incoherent_diagnostic["diagnostics"] = json!([{
        "code": "rerun_gate_failed",
        "phase": "schema_gate",
        "contract": null,
        "remediation": "inspect_candidate_schema"
    }]);
    assert_schema_valid(&incoherent_diagnostic);
    assert!(
        serde_json::from_value::<ProjectMigrationReportV1>(incoherent_diagnostic).is_err(),
        "the DTO enforces cross-array gate/diagnostic coherence"
    );
}

#[test]
fn unsupported_target_reports_have_no_fictional_target_or_migration_work() {
    for code in [
        MigrationDiagnosticCode::TargetVersionOutOfBounds,
        MigrationDiagnosticCode::TargetVersionUnsupported,
    ] {
        let report = build_project_migration_report(unsupported_target_input(code))
            .expect("unsupported target report builds");
        assert_eq!(report.disposition, MigrationDisposition::Blocked);
        assert_eq!(
            report.compatibility,
            MigrationCompatibility::UnsupportedTransition
        );
        assert_eq!(
            report.blocking_reasons,
            vec![MigrationBlockingReason::TargetVersionUnsupported]
        );
        assert!(report.compatible_normalizations.is_empty());
        assert!(report.semantic_changes.is_empty());
        assert!(report.reviews.is_empty());
        assert!(report.unresolved_decisions.is_empty());
        assert!(report.version_transitions.iter().all(|transition| {
            transition.target_version.is_none()
                && transition.direction == MigrationVersionDirection::UnsupportedTarget
        }));
        assert!(report
            .rerun_gates
            .iter()
            .all(|gate| gate.status == MigrationGateStatus::NotApplicable));

        let document = serde_json::to_value(&report).expect("report serializes");
        assert_schema_valid(&document);
        assert_eq!(
            serde_json::from_value::<ProjectMigrationReportV1>(document)
                .expect("schema-valid unsupported target report enters through the DTO"),
            report
        );
    }
}

#[test]
fn null_target_and_not_applicable_gates_are_rejected_outside_unsupported_targets() {
    for index in 0..5 {
        let mut supported_null = parse(FIXTURE);
        supported_null["version_transitions"][index]["target_version"] = Value::Null;
        assert_schema_invalid(&supported_null);
        assert!(
            serde_json::from_value::<ProjectMigrationReportV1>(supported_null).is_err(),
            "supported transition {index} cannot claim null target with a non-null direction"
        );

        let mut unsupported_direction = parse(FIXTURE);
        unsupported_direction["version_transitions"][index]["direction"] =
            json!("unsupported_target");
        assert_schema_invalid(&unsupported_direction);
        assert!(
            serde_json::from_value::<ProjectMigrationReportV1>(unsupported_direction).is_err(),
            "supported transition {index} cannot claim unsupported-target direction"
        );
    }

    let unsupported = build_project_migration_report(unsupported_target_input(
        MigrationDiagnosticCode::TargetVersionUnsupported,
    ))
    .expect("unsupported target report builds");

    let mut invented_target = serde_json::to_value(&unsupported).expect("report serializes");
    invented_target["version_transitions"][0]["target_version"] = json!(2);
    assert_schema_invalid(&invented_target);
    assert!(serde_json::from_value::<ProjectMigrationReportV1>(invented_target).is_err());

    let mut removed_contract = serde_json::to_value(&unsupported).expect("report serializes");
    removed_contract["version_transitions"][0]["direction"] = json!("removed_contract");
    assert_schema_invalid(&removed_contract);
    assert!(serde_json::from_value::<ProjectMigrationReportV1>(removed_contract).is_err());

    let mut misleading_gate = serde_json::to_value(&unsupported).expect("report serializes");
    misleading_gate["rerun_gates"][0]["status"] = json!("not_run");
    assert_schema_invalid(&misleading_gate);
    assert!(serde_json::from_value::<ProjectMigrationReportV1>(misleading_gate).is_err());

    let mut invalid = canonical_input();
    invalid.target_versions.project = None;
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::MissingProjectVersion)
    );

    let mut invalid = unsupported_target_input(MigrationDiagnosticCode::TargetVersionUnsupported);
    invalid.target_versions = versions(2);
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::InvalidVersionSupportEvidence)
    );

    let mut invalid = unsupported_target_input(MigrationDiagnosticCode::TargetVersionUnsupported);
    invalid.rerun_gates = all_passed();
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::InvalidGateStatus)
    );

    let mut invalid = canonical_input();
    invalid.rerun_gates = all_not_applicable();
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::InvalidGateStatus)
    );

    let mut invalid = unsupported_target_input(MigrationDiagnosticCode::TargetVersionUnsupported);
    invalid.changes = vec![normalization(MigrationField::ProjectRegistry)];
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::InvalidPreMigrationEvidence)
    );
}

#[test]
fn invalid_change_version_count_and_capacity_are_rejected() {
    let mut invalid = canonical_input();
    invalid.changes = vec![MigrationChangeInput {
        field: MigrationField::ProjectRegistry,
        operation: MigrationOperation::RenameField,
        semantic_effect: MigrationSemanticEffect::Preserved,
        safety: MigrationSafety::Safe,
        replacement: MigrationReplacementInput::Field(MigrationField::ProjectRegistry),
    }];
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::InvalidChange)
    );

    let mut invalid = canonical_input();
    invalid.source_versions.project = Some(0);
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::InvalidAuthoringVersion)
    );

    let mut invalid = canonical_input();
    invalid.target_versions.project = Some(65_536);
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::InvalidAuthoringVersion)
    );

    let mut invalid = canonical_input();
    invalid.affected.fixtures = MigrationAffectedCount {
        state: registryctl::MigrationAffectedState::Affected,
        count: Some(0),
    };
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::InvalidAffectedCount)
    );

    let mut invalid = canonical_input();
    invalid.affected.fixtures = MigrationAffectedCount::known(1_000_001);
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::TooManyAffectedItems)
    );

    let repeated = normalization(MigrationField::ProjectRegistry);
    let mut invalid = canonical_input();
    invalid.changes = vec![repeated; 257];
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::TooManyChanges)
    );

    let decision = UnresolvedMigrationDecision {
        owner: MigrationDecisionOwner::CountryAuthority,
        kind: MigrationDecisionKind::CountrySemanticIntent,
        scope: MigrationDecisionScope::Project,
    };
    let mut invalid = canonical_input();
    invalid.unresolved_decisions = vec![decision; 65];
    assert_eq!(
        build_project_migration_report(invalid),
        Err(ProjectMigrationBuildError::TooManyDecisions)
    );
}

#[test]
fn no_op_and_contract_coverage_remain_explicit() {
    let report = build_project_migration_report(ProjectMigrationInput {
        source_versions: versions(1),
        target_versions: versions(1),
        version_support: supported(),
        changes: Vec::new(),
        affected: unaffected(),
        approved_reviews: Vec::new(),
        output: MigrationOutputRequest {
            mode: MigrationOutputMode::CheckOnly,
            write_authority: MigrationWriteAuthority::NotGranted,
            candidate_emission: MigrationCandidateEmission::NotEmitted,
        },
        rerun_gates: MigrationGateResults {
            schema: MigrationGateStatus::NotRequired,
            fixture: MigrationGateStatus::NotRequired,
            check: MigrationGateStatus::NotRequired,
            build: MigrationGateStatus::NotRequired,
            generated_reference: MigrationGateStatus::NotRequired,
        },
        diagnostics: Vec::new(),
        unresolved_decisions: Vec::new(),
    })
    .expect("no-op report builds");
    assert_eq!(
        report.disposition,
        MigrationDisposition::NoMigrationRequired
    );
    assert_eq!(
        report.compatibility,
        MigrationCompatibility::NoMigrationRequired
    );
    assert_eq!(report.version_transitions.len(), 5);
    assert!(report
        .version_transitions
        .iter()
        .all(|transition| transition.direction == MigrationVersionDirection::Same));
    assert_eq!(report.rerun_gates.len(), 5);

    for field in MigrationField::ALL {
        assert_eq!(MigrationField::from_address(field.address()), Some(field));
    }
}

#[test]
fn every_affected_surface_artifact_and_review_class_is_covered() {
    let mut generated_artifacts = MigrationArtifact::ALL.to_vec();
    generated_artifacts.reverse();
    let report = build_project_migration_report(ProjectMigrationInput {
        source_versions: versions(1),
        target_versions: versions(1),
        version_support: supported(),
        changes: vec![
            normalization(MigrationField::ProjectRegistry),
            MigrationChangeInput {
                field: MigrationField::ServicePolicy,
                operation: MigrationOperation::ChangeSemantics,
                semantic_effect: MigrationSemanticEffect::Changed,
                safety: MigrationSafety::Safe,
                replacement: MigrationReplacementInput::NotApplicable,
            },
            MigrationChangeInput {
                field: MigrationField::Consultation,
                operation: MigrationOperation::ChangeSemantics,
                semantic_effect: MigrationSemanticEffect::Changed,
                safety: MigrationSafety::Safe,
                replacement: MigrationReplacementInput::NotApplicable,
            },
        ],
        affected: MigrationAffectedSurfaces {
            fixtures: MigrationAffectedCount::known(1),
            services: MigrationAffectedCount::known(1),
            consultations: MigrationAffectedCount::known(1),
            claims: MigrationAffectedCount::known(1),
            environments: MigrationAffectedCount::known(1),
            generated_artifacts,
        },
        approved_reviews: Vec::new(),
        output: MigrationOutputRequest {
            mode: MigrationOutputMode::CheckOnly,
            write_authority: MigrationWriteAuthority::NotGranted,
            candidate_emission: MigrationCandidateEmission::NotEmitted,
        },
        rerun_gates: all_passed(),
        diagnostics: Vec::new(),
        unresolved_decisions: Vec::new(),
    })
    .expect("coverage report builds");

    assert_eq!(
        report.affected.generated_artifacts,
        MigrationArtifact::ALL.to_vec()
    );
    assert_eq!(
        report
            .reviews
            .iter()
            .map(|review| review.class)
            .collect::<Vec<_>>(),
        MigrationReviewClass::ALL
    );
    assert!(report
        .reviews
        .iter()
        .all(|review| review.status == registryctl::MigrationReviewStatus::RequiredPending));
}
