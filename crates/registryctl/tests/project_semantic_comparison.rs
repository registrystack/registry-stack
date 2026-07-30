// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

use registryctl::{
    compare_registry_project_environments_semantically,
    compare_registry_project_to_embedded_starter_semantically,
    compare_registry_projects_semantically, init_registry_project, FieldSensitivity,
    ProjectEnvironmentSemanticComparisonOptions, ProjectInitOptions,
    ProjectSemanticComparisonOptions, ProjectStarter, ProjectStarterSemanticComparisonOptions,
    RequiredProductAction, SemanticComparisonAffectedSubjectKind, SemanticComparisonAssurance,
    SemanticComparisonChangeSource, SemanticComparisonConsumer, SemanticComparisonDimension,
    SemanticComparisonDirection, SemanticComparisonEquivalence,
    SemanticComparisonGeneratedArtifact, SemanticComparisonRequiredAction,
    SemanticComparisonReviewClass, SemanticComparisonReviewPlanState,
    SemanticComparisonSchemaFamily,
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

fn fixture_project(name: &str) -> PathBuf {
    if name == "bounded-http-starter" {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/project-starters/bounded-http")
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/project-authoring")
            .join(name)
    }
}

fn copy_project_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("destination directory creates");
    for entry in fs::read_dir(source).expect("source project directory reads") {
        let entry = entry.expect("source project entry reads");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry
            .file_type()
            .expect("source project entry type reads")
            .is_dir()
        {
            copy_project_tree(&source_path, &destination_path);
        } else {
            fs::copy(&source_path, &destination_path).expect("project file copies");
        }
    }
}

fn copied_fixture_project(root: &Path, name: &str) -> PathBuf {
    let destination = root.join(name);
    copy_project_tree(&fixture_project(name), &destination);
    destination
}

fn registry_id_change(
    report: &registryctl::ProjectSemanticComparisonReportV1,
) -> &registryctl::ProjectSemanticComparisonChange {
    report
        .changes
        .iter()
        .find(|change| {
            change.address.schema_family == SemanticComparisonSchemaFamily::Project
                && change.address.field.as_str() == "/properties/registry/properties/id"
        })
        .expect("registry.id change is classified")
}

fn first_product_change(
    report: &registryctl::ProjectSemanticComparisonReportV1,
) -> &registryctl::ProjectSemanticComparisonChange {
    report
        .changes
        .iter()
        .find(|change| !change.requirements.signing.is_empty())
        .expect("product-impacting change is classified")
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
fn authored_integer_limit_changes_keep_their_security_direction() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let baseline = temporary.path().join("baseline");
    let current = temporary.path().join("current");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Snapshot,
        directory: baseline.clone(),
    })
    .expect("baseline Snapshot project initializes");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Snapshot,
        directory: current.clone(),
    })
    .expect("current Snapshot project initializes");

    const JSON_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
    let baseline_limit = JSON_SAFE_INTEGER;
    let current_limit = baseline_limit - 1;
    let configure_integer_output = |project: &Path, maximum: i64| {
        rewrite_yaml(&project.join("entities/people.yaml"), |document| {
            let status = document["schema"]["properties"]["registration_status"]
                .as_object_mut()
                .expect("registration_status is an object");
            status.insert(
                "type".to_owned(),
                Value::Array(vec![
                    Value::String("integer".to_owned()),
                    Value::String("null".to_owned()),
                ]),
            );
            status.remove("maxLength");
            status.insert("minimum".to_owned(), Value::from(-JSON_SAFE_INTEGER));
            status.insert("maximum".to_owned(), Value::from(maximum));
        });
        rewrite_yaml(
            &project.join("integrations/person-snapshot/fixtures/match.yaml"),
            |document| {
                document["interactions"][0]["respond"]["body"]["registration_status"] =
                    Value::from(1_i64);
                document["expect"]["outputs"]["registration_status"] = Value::from(1_i64);
                document["expect"]["claims"]["population-registration-status"] = Value::from(1_i64);
            },
        );
    };
    configure_integer_output(&baseline, baseline_limit);
    configure_integer_output(&current, current_limit);

    let limit_change = |report: registryctl::ProjectSemanticComparisonReportV1| {
        report
            .changes
            .into_iter()
            .find(|change| {
                change.address.schema_family == SemanticComparisonSchemaFamily::Entity
                    && change
                        .address
                        .field
                        .as_str()
                        .ends_with("/properties/maximum")
            })
            .expect("entity output maximum change is classified")
    };
    assert_eq!(
        limit_change(compare_projects(&current, &baseline)).direction,
        SemanticComparisonDirection::Narrowed
    );
    assert_eq!(
        limit_change(compare_projects(&baseline, &current)).direction,
        SemanticComparisonDirection::Widened
    );
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
        vec![
            RequiredProductAction::RelayPublic,
            RequiredProductAction::RelayConsultation,
            RequiredProductAction::Notary,
        ]
    );
    assert_eq!(
        registry_id_change.requirements.activation,
        vec![
            RequiredProductAction::RelayPublic,
            RequiredProductAction::RelayConsultation,
            RequiredProductAction::Notary,
        ]
    );
    assert_eq!(
        registry_id_change.requirements.restart,
        vec![
            RequiredProductAction::RelayPublic,
            RequiredProductAction::RelayConsultation,
            RequiredProductAction::Notary,
        ]
    );
    assert_eq!(
        registry_id_change
            .affected_subjects
            .iter()
            .find(|subject| subject.kind == SemanticComparisonAffectedSubjectKind::ProductInput)
            .expect("product input inventory is reported")
            .count,
        3
    );
    assert_eq!(
        report.required_actions,
        vec![
            SemanticComparisonRequiredAction::ReviewSemanticChanges,
            SemanticComparisonRequiredAction::RunAffectedFixtures,
            SemanticComparisonRequiredAction::RegenerateGeneratedArtifacts,
            SemanticComparisonRequiredAction::ResignRelayPublicBundle,
            SemanticComparisonRequiredAction::ResignRelayConsultationBundle,
            SemanticComparisonRequiredAction::ResignNotaryBundle,
            SemanticComparisonRequiredAction::ReactivateRelayPublicConfiguration,
            SemanticComparisonRequiredAction::ReactivateRelayConsultationConfiguration,
            SemanticComparisonRequiredAction::ReactivateNotaryConfiguration,
            SemanticComparisonRequiredAction::RestartRegistryRelayPublic,
            SemanticComparisonRequiredAction::RestartRegistryRelayConsultation,
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
fn relay_only_comparison_filters_actions_to_enabled_product_topology() {
    let temporary = tempfile::tempdir().expect("temporary directory");

    let relay_baseline = temporary.path().join("relay-baseline");
    copy_project_tree(
        &fixture_project("relay-only-materialization"),
        &relay_baseline,
    );
    let relay_current = temporary.path().join("relay-current");
    copy_project_tree(
        &fixture_project("relay-only-materialization"),
        &relay_current,
    );
    rewrite_yaml(&relay_current.join("entities/people.yaml"), |document| {
        document["schema"]["properties"]["status"]["maxLength"] = Value::from(31);
    });
    let relay_report = compare_projects(&relay_current, &relay_baseline);
    let relay_change = first_product_change(&relay_report);
    assert_eq!(
        relay_change.address.schema_family,
        SemanticComparisonSchemaFamily::Entity
    );
    assert!(relay_change
        .consumers
        .contains(&SemanticComparisonConsumer::RegistryRelay));
    assert!(!relay_change
        .consumers
        .contains(&SemanticComparisonConsumer::RegistryNotary));
    assert!(relay_change
        .generated_artifacts
        .contains(&SemanticComparisonGeneratedArtifact::RelayConfig));
    assert!(!relay_change
        .generated_artifacts
        .contains(&SemanticComparisonGeneratedArtifact::NotaryConfig));
    assert!(relay_change
        .review_classes
        .contains(&SemanticComparisonReviewClass::Relay));
    assert!(!relay_change
        .review_classes
        .contains(&SemanticComparisonReviewClass::Notary));
    assert_eq!(
        relay_change.requirements.signing,
        vec![RequiredProductAction::RelayPublic]
    );
    assert_eq!(
        relay_change.requirements.activation,
        vec![RequiredProductAction::RelayPublic]
    );
    assert_eq!(
        relay_change.requirements.restart,
        vec![RequiredProductAction::RelayPublic]
    );
    assert_eq!(
        relay_report.required_actions,
        vec![
            SemanticComparisonRequiredAction::ReviewSemanticChanges,
            SemanticComparisonRequiredAction::RunAffectedFixtures,
            SemanticComparisonRequiredAction::RegenerateGeneratedArtifacts,
            SemanticComparisonRequiredAction::ResignRelayPublicBundle,
            SemanticComparisonRequiredAction::ReactivateRelayPublicConfiguration,
            SemanticComparisonRequiredAction::RestartRegistryRelayPublic,
        ]
    );
}

#[test]
fn product_removal_comparison_keeps_removed_product_actions() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let baseline = copied_fixture_project(temporary.path(), "bounded-http-starter");
    let current = copied_fixture_project(temporary.path(), "relay-only-materialization");

    let report = compare_projects(&current, &baseline);
    let change = registry_id_change(&report);
    assert!(change
        .consumers
        .contains(&SemanticComparisonConsumer::RegistryRelay));
    assert!(change
        .consumers
        .contains(&SemanticComparisonConsumer::RegistryNotary));
    assert!(change
        .generated_artifacts
        .contains(&SemanticComparisonGeneratedArtifact::RelayConfig));
    assert!(change
        .generated_artifacts
        .contains(&SemanticComparisonGeneratedArtifact::NotaryConfig));
    assert_eq!(
        change.requirements.signing,
        vec![
            RequiredProductAction::RelayPublic,
            RequiredProductAction::RelayConsultation,
            RequiredProductAction::Notary,
        ]
    );
    assert_eq!(
        change.requirements.activation,
        vec![
            RequiredProductAction::RelayPublic,
            RequiredProductAction::RelayConsultation,
            RequiredProductAction::Notary,
        ]
    );
    assert_eq!(
        change.requirements.restart,
        vec![
            RequiredProductAction::RelayPublic,
            RequiredProductAction::RelayConsultation,
            RequiredProductAction::Notary,
        ]
    );
    assert!(report
        .required_actions
        .contains(&SemanticComparisonRequiredAction::ResignNotaryBundle));
    assert!(report
        .required_actions
        .contains(&SemanticComparisonRequiredAction::ReactivateNotaryConfiguration));
    assert!(report
        .required_actions
        .contains(&SemanticComparisonRequiredAction::RestartRegistryNotary));
    assert!(report
        .required_actions
        .contains(&SemanticComparisonRequiredAction::ResignRelayConsultationBundle));
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
    let generated_change = report
        .changes
        .iter()
        .find(|change| {
            change.address.schema_family == SemanticComparisonSchemaFamily::GeneratedApproval
                || change.address.schema_family == SemanticComparisonSchemaFamily::GeneratedReview
        })
        .expect("generated approval or review projection change is classified");
    assert!(generated_change
        .consumers
        .contains(&SemanticComparisonConsumer::BundleSigner));
    assert!(generated_change
        .consumers
        .contains(&SemanticComparisonConsumer::DeploymentTooling));
    assert!(generated_change
        .consumers
        .contains(&SemanticComparisonConsumer::Operator));
    assert!(!generated_change
        .consumers
        .contains(&SemanticComparisonConsumer::RegistryRelay));
    assert!(!generated_change
        .consumers
        .contains(&SemanticComparisonConsumer::RegistryNotary));
    assert_eq!(
        generated_change.requirements.signing,
        Vec::<RequiredProductAction>::new()
    );
    assert_eq!(
        generated_change.requirements.activation,
        Vec::<RequiredProductAction>::new()
    );
    assert_eq!(
        generated_change.requirements.restart,
        Vec::<RequiredProductAction>::new()
    );
}
