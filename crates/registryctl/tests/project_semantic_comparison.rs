// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;
use std::process::Command;

use registryctl::{
    compare_registry_project_environments_semantically,
    compare_registry_project_to_embedded_starter_semantically,
    compare_registry_projects_semantically, init_registry_project, FieldSensitivity,
    ProjectEnvironmentSemanticComparisonOptions, ProjectInitOptions,
    ProjectSemanticComparisonOptions, ProjectStarter, ProjectStarterSemanticComparisonOptions,
    SemanticComparisonActivationRequirement, SemanticComparisonAssurance,
    SemanticComparisonChangeSource, SemanticComparisonConsumer, SemanticComparisonDimension,
    SemanticComparisonDirection, SemanticComparisonEquivalence,
    SemanticComparisonGeneratedArtifact, SemanticComparisonRequiredAction,
    SemanticComparisonRestartRequirement, SemanticComparisonReviewPlanState,
    SemanticComparisonSchemaFamily, SemanticComparisonSigningRequirement,
};
use serde_json::Value;

fn init_http_project(root: &Path) {
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: root.to_path_buf(),
    })
    .expect("HTTP project initializes");
}

fn rewrite_yaml(path: &Path, update: impl FnOnce(&mut Value)) {
    let bytes = fs::read(path).expect("YAML reads");
    let mut document: Value = serde_norway::from_slice(&bytes).expect("YAML parses");
    update(&mut document);
    fs::write(
        path,
        serde_norway::to_string(&document).expect("YAML serializes"),
    )
    .expect("YAML writes");
}

fn compare_projects(
    current: &Path,
    baseline: &Path,
) -> registryctl::ProjectSemanticComparisonReportV1 {
    compare_registry_projects_semantically(&ProjectSemanticComparisonOptions {
        current_project_directory: current.to_path_buf(),
        current_environment: "local".to_owned(),
        baseline_project_directory: baseline.to_path_buf(),
        baseline_environment: "local".to_owned(),
    })
    .expect("projects compare")
}

#[test]
fn local_project_comparison_is_semantic_and_deterministic() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let baseline = temporary.path().join("baseline");
    let current = temporary.path().join("current");
    init_http_project(&baseline);
    init_http_project(&current);

    rewrite_yaml(&current.join("registry-stack.yaml"), |document| {
        document["services"]["person-verification"]["purpose"] =
            Value::String("changed-purpose".to_owned());
    });
    let first = compare_projects(&current, &baseline);
    let second = compare_projects(&current, &baseline);
    assert_eq!(first.equivalence, SemanticComparisonEquivalence::Different);
    assert_eq!(
        first.review_plan.state,
        SemanticComparisonReviewPlanState::GeneratedPendingReview
    );
    assert!(first
        .changes
        .iter()
        .any(|change| change.dimension == SemanticComparisonDimension::ServicePolicy));
    assert!(first.changes.iter().any(|change| {
        change.address.schema_family == SemanticComparisonSchemaFamily::GeneratedApproval
    }));
    assert_eq!(
        first.canonical_json_bytes().expect("canonical report"),
        second.canonical_json_bytes().expect("canonical report")
    );
    assert!(first
        .changes
        .windows(2)
        .all(|pair| pair[0].address <= pair[1].address));
}

#[test]
fn formatting_and_explicit_equivalent_defaults_produce_zero_changes() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let baseline = temporary.path().join("baseline");
    let current = temporary.path().join("current");
    init_http_project(&baseline);
    init_http_project(&current);

    let project_path = current.join("registry-stack.yaml");
    let original = fs::read_to_string(&project_path).expect("project reads");
    fs::write(
        &project_path,
        format!("# formatting-only comment\n\n{original}\n"),
    )
    .expect("formatting changes");
    let formatting_only = compare_projects(&current, &baseline);
    assert_eq!(
        formatting_only.equivalence,
        SemanticComparisonEquivalence::Equivalent
    );
    assert!(formatting_only.changes.is_empty());

    rewrite_yaml(&current.join("environments/local.yaml"), |document| {
        document["issuance"]["algorithm"] = Value::String("EdDSA".to_owned());
    });
    let report = compare_projects(&current, &baseline);
    assert_eq!(
        report.equivalence,
        SemanticComparisonEquivalence::Equivalent
    );
    assert!(report.changes.is_empty());
    assert!(report.required_actions.is_empty());
}

#[test]
fn registry_id_change_requires_redeploying_both_products_without_reporting_values() {
    const BASELINE_ID: &str = "semantic-comparison-baseline";
    const CURRENT_ID: &str = "semantic-comparison-current";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let baseline = temporary.path().join("baseline");
    let current = temporary.path().join("current");
    init_http_project(&baseline);
    init_http_project(&current);
    rewrite_yaml(&baseline.join("registry-stack.yaml"), |document| {
        document["registry"]["id"] = Value::String(BASELINE_ID.to_owned());
    });
    rewrite_yaml(&current.join("registry-stack.yaml"), |document| {
        document["registry"]["id"] = Value::String(CURRENT_ID.to_owned());
    });

    let report = compare_projects(&current, &baseline);
    assert_eq!(report.equivalence, SemanticComparisonEquivalence::Different);
    let registry_id_change = report
        .changes
        .iter()
        .find(|change| {
            change.address.schema_family == SemanticComparisonSchemaFamily::Project
                && change.address.field.as_str() == "/properties/registry/properties/id"
        })
        .expect("registry.id change is classified");
    assert_eq!(
        registry_id_change.source,
        SemanticComparisonChangeSource::Authored
    );
    assert_eq!(
        registry_id_change.dimension,
        SemanticComparisonDimension::Project
    );
    assert_eq!(
        registry_id_change.direction,
        SemanticComparisonDirection::Changed
    );
    assert_eq!(registry_id_change.sensitivity, FieldSensitivity::Internal);
    assert_eq!(registry_id_change.occurrences, 1);
    assert_eq!(
        registry_id_change.consumers,
        vec![
            SemanticComparisonConsumer::RegistryctlAuthoring,
            SemanticComparisonConsumer::RegistryRelay,
            SemanticComparisonConsumer::RegistryNotary,
            SemanticComparisonConsumer::EditorTooling,
            SemanticComparisonConsumer::DocsGenerator,
            SemanticComparisonConsumer::BundleSigner,
            SemanticComparisonConsumer::DeploymentTooling,
            SemanticComparisonConsumer::Operator,
        ]
    );
    assert_eq!(
        registry_id_change.generated_artifacts,
        vec![
            SemanticComparisonGeneratedArtifact::EditorSchemas,
            SemanticComparisonGeneratedArtifact::ProjectBuild,
            SemanticComparisonGeneratedArtifact::RelayConfig,
            SemanticComparisonGeneratedArtifact::NotaryConfig,
            SemanticComparisonGeneratedArtifact::FieldReference,
        ]
    );
    assert_eq!(
        registry_id_change.requirements.signing,
        SemanticComparisonSigningRequirement::RelayAndNotaryBundles
    );
    assert_eq!(
        registry_id_change.requirements.activation,
        SemanticComparisonActivationRequirement::ApplyRelayAndNotaryConfig
    );
    assert_eq!(
        registry_id_change.requirements.restart,
        SemanticComparisonRestartRequirement::RegistryRelayAndNotary
    );
    assert_eq!(
        report.required_actions,
        vec![
            SemanticComparisonRequiredAction::ReviewSemanticChanges,
            SemanticComparisonRequiredAction::RunAffectedFixtures,
            SemanticComparisonRequiredAction::RegenerateGeneratedArtifacts,
            SemanticComparisonRequiredAction::ResignRelayBundle,
            SemanticComparisonRequiredAction::ResignNotaryBundle,
            SemanticComparisonRequiredAction::ReactivateRelayConfiguration,
            SemanticComparisonRequiredAction::ReactivateNotaryConfiguration,
            SemanticComparisonRequiredAction::RestartRegistryRelay,
            SemanticComparisonRequiredAction::RestartRegistryNotary,
        ]
    );

    let json = String::from_utf8(report.canonical_json_bytes().expect("report serializes"))
        .expect("JSON is UTF-8");
    for value in [BASELINE_ID, CURRENT_ID] {
        assert!(!json.contains(value));
        assert!(!report.human_safe_summary().contains(value));
        assert!(!format!("{report:?}").contains(value));
    }
}

#[test]
fn same_project_environment_comparison_detects_sensitive_changes_without_leaking_them() {
    const SENTINEL: &str = "SEMANTIC_COMPARISON_SECRET_SENTINEL";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    init_http_project(&project);
    let current_environment = project.join("environments/candidate.yaml");
    fs::copy(
        project.join("environments/local.yaml"),
        &current_environment,
    )
    .expect("environment copies");
    rewrite_yaml(&current_environment, |document| {
        document["integrations"]["person-record"]["source"]["credential"]["token"]["secret"] =
            Value::String(SENTINEL.to_owned());
    });

    let report = compare_registry_project_environments_semantically(
        &ProjectEnvironmentSemanticComparisonOptions {
            project_directory: project,
            current_environment: "candidate".to_owned(),
            baseline_environment: "local".to_owned(),
        },
    )
    .expect("environments compare");
    assert_eq!(report.equivalence, SemanticComparisonEquivalence::Different);
    assert!(report
        .changes
        .iter()
        .any(|change| change.dimension == SemanticComparisonDimension::OperatorSecurity));
    let json = String::from_utf8(report.canonical_json_bytes().expect("report serializes"))
        .expect("report is UTF-8");
    assert!(!json.contains(SENTINEL));
    assert!(!report.human_safe_summary().contains(SENTINEL));
    assert!(!format!("{report:?}").contains(SENTINEL));
}

#[test]
fn embedded_starter_comparison_distinguishes_unchanged_adapted_and_stale() {
    const STALE_SENTINEL: &str = "SEMANTIC_COMPARISON_STALE_SENTINEL";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    init_http_project(&project);
    let options = ProjectStarterSemanticComparisonOptions {
        project_directory: project.clone(),
        environment: "local".to_owned(),
        starter: None,
    };
    let unchanged = compare_registry_project_to_embedded_starter_semantically(&options)
        .expect("unchanged starter compares");
    assert_eq!(
        unchanged.assurance,
        SemanticComparisonAssurance::EmbeddedExactRelease
    );
    assert_eq!(
        unchanged.equivalence,
        SemanticComparisonEquivalence::Equivalent
    );

    rewrite_yaml(&project.join("registry-stack.yaml"), |document| {
        document["services"]["person-verification"]["purpose"] =
            Value::String("adapted-purpose".to_owned());
    });
    let adapted = compare_registry_project_to_embedded_starter_semantically(&options)
        .expect("adapted starter compares");
    assert_eq!(
        adapted.equivalence,
        SemanticComparisonEquivalence::Different
    );

    rewrite_yaml(&project.join("registry-stack.yaml"), |document| {
        document["starter"]["release"] = Value::String(STALE_SENTINEL.to_owned());
    });
    let error = compare_registry_project_to_embedded_starter_semantically(&options)
        .expect_err("stale provenance fails closed");
    let error = format!("{error:#}");
    assert!(!error.contains(STALE_SENTINEL));
    assert_eq!(
        error,
        "project starter provenance cannot be proved by this binary"
    );
}

#[test]
fn every_public_starter_compares_equivalent_to_its_exact_embedded_release() {
    for starter in [
        ProjectStarter::Http,
        ProjectStarter::Dhis2Tracker,
        ProjectStarter::OpencrvsDci,
        ProjectStarter::FhirR4,
        ProjectStarter::Snapshot,
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("project");
        init_registry_project(&ProjectInitOptions {
            starter,
            directory: project.clone(),
        })
        .unwrap_or_else(|error| panic!("{starter:?} starter initializes: {error:#}"));
        let report = compare_registry_project_to_embedded_starter_semantically(
            &ProjectStarterSemanticComparisonOptions {
                project_directory: project,
                environment: "local".to_owned(),
                starter: Some(starter),
            },
        )
        .unwrap_or_else(|error| panic!("{starter:?} starter compares: {error:#}"));
        assert_eq!(
            report.assurance,
            SemanticComparisonAssurance::EmbeddedExactRelease,
            "{starter:?}"
        );
        assert_eq!(
            report.equivalence,
            SemanticComparisonEquivalence::Equivalent,
            "{starter:?}"
        );
        assert!(report.changes.is_empty(), "{starter:?}");
        assert!(report.required_actions.is_empty(), "{starter:?}");
    }
}

#[test]
fn explicit_starter_kind_must_match_recorded_project_provenance() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    init_http_project(&project);

    let error = compare_registry_project_to_embedded_starter_semantically(
        &ProjectStarterSemanticComparisonOptions {
            project_directory: project,
            environment: "local".to_owned(),
            starter: Some(ProjectStarter::Snapshot),
        },
    )
    .expect_err("a mismatched explicit starter kind fails closed");
    assert_eq!(
        error.to_string(),
        "selected embedded starter does not match project starter provenance"
    );
}

#[test]
fn compare_cli_emits_value_free_human_and_strict_json_reports() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    init_http_project(&project);
    let project_argument = project.to_str().expect("temporary path is UTF-8");

    let json_output = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "compare",
            "--project-dir",
            project_argument,
            "--environment",
            "local",
            "--from-starter",
            "--format",
            "json",
        ])
        .output()
        .expect("registryctl compare runs");
    assert!(
        json_output.status.success(),
        "{}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let report: registryctl::ProjectSemanticComparisonReportV1 =
        serde_json::from_slice(&json_output.stdout).expect("JSON report is strict and typed");
    assert_eq!(
        report.equivalence,
        SemanticComparisonEquivalence::Equivalent
    );
    let serialized = String::from_utf8(json_output.stdout).expect("JSON output is UTF-8");
    assert!(!serialized.contains(project_argument));

    let explicit_output = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "compare",
            "--project-dir",
            project_argument,
            "--environment",
            "local",
            "--from-starter",
            "http",
            "--format",
            "json",
        ])
        .output()
        .expect("registryctl explicit starter comparison runs");
    assert!(
        explicit_output.status.success(),
        "{}",
        String::from_utf8_lossy(&explicit_output.stderr)
    );
    let explicit_report: registryctl::ProjectSemanticComparisonReportV1 =
        serde_json::from_slice(&explicit_output.stdout)
            .expect("explicit starter JSON report is strict and typed");
    assert_eq!(
        explicit_report.equivalence,
        SemanticComparisonEquivalence::Equivalent
    );

    let mismatch = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "compare",
            "--project-dir",
            project_argument,
            "--environment",
            "local",
            "--from-starter",
            "snapshot",
        ])
        .output()
        .expect("registryctl mismatched starter comparison runs");
    assert!(!mismatch.status.success());
    assert_eq!(
        String::from_utf8_lossy(&mismatch.stderr).trim(),
        "Error: selected embedded starter does not match project starter provenance"
    );
    assert!(!String::from_utf8_lossy(&mismatch.stderr).contains(project_argument));

    let human_output = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "compare",
            "--project-dir",
            project_argument,
            "--environment",
            "local",
            "--from-starter",
        ])
        .output()
        .expect("registryctl compare human output runs");
    assert!(human_output.status.success());
    let human = String::from_utf8(human_output.stdout).expect("human output is UTF-8");
    assert!(human.contains("semantic comparison: equivalent"));
    assert!(human.contains("External approval: not evaluated"));
    assert!(!human.contains(project_argument));
}

#[test]
fn fixture_change_is_included_in_the_generated_pending_review_plan() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let baseline = temporary.path().join("baseline");
    let current = temporary.path().join("current");
    init_http_project(&baseline);
    init_http_project(&current);
    rewrite_yaml(
        &current.join("integrations/person-record/fixtures/active.yaml"),
        |document| {
            document["interactions"][0]["respond"]["body"]["active"] = Value::Bool(false);
            document["expect"]["outputs"]["active"] = Value::Bool(false);
            document["expect"]["claims"]["person-active"] = Value::Bool(false);
        },
    );
    let report = compare_projects(&current, &baseline);
    assert_eq!(
        report.review_plan.state,
        SemanticComparisonReviewPlanState::GeneratedPendingReview
    );
    assert!(report
        .changes
        .iter()
        .any(|change| change.dimension == SemanticComparisonDimension::Fixture));
    assert!(report.changes.iter().any(|change| {
        change.address.schema_family == SemanticComparisonSchemaFamily::GeneratedApproval
    }));
}
