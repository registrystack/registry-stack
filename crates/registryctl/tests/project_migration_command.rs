// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use registryctl::{
    check_registry_project_with_context, init_registry_project,
    migrate_registry_project_with_context, AuthoringContract, MigrationBlockingReason,
    MigrationCandidateEmission, MigrationDiagnosticCode, MigrationDisposition, MigrationFieldPath,
    MigrationGateStatus, MigrationOperation, MigrationReviewStatus, MigrationVersionDirection,
    ProjectAuthoringDiagnostics, ProjectCheckOptions, ProjectExecutionContext, ProjectInitOptions,
    ProjectMigrationOptions, ProjectStarter,
};

const OLD_ATTRIBUTE_RELEASE: &str = "tests/fixtures/project-migration/old-40ec7a-attribute-release";
const MIGRATION_SCHEMA: &str =
    include_str!("../schemas/project-reports/registry.project.migration.v1.schema.json");

fn assert_schema_valid(document: &serde_json::Value) {
    let schema: serde_json::Value =
        serde_json::from_str(MIGRATION_SCHEMA).expect("migration schema parses");
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("migration schema compiles");
    if let Err(errors) = validator.validate(document) {
        let details = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("migration report should validate: {details:?}");
    };
}

fn worker() -> ProjectExecutionContext {
    ProjectExecutionContext::new(env!("CARGO_BIN_EXE_registryctl"))
        .expect("registryctl binary is a reviewed executable")
}

fn initialized_project(parent: &Path) -> PathBuf {
    let project = parent.join("source-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");
    project
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("fixture destination is created");
    for entry in fs::read_dir(source).expect("fixture directory reads") {
        let entry = entry.expect("fixture entry reads");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type().expect("fixture type reads").is_dir() {
            copy_tree(&source_path, &destination_path);
        } else {
            fs::copy(source_path, destination_path).expect("fixture file copies");
        }
    }
}

fn historical_attribute_release_project(parent: &Path) -> PathBuf {
    let project = parent.join("historical-project");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join(OLD_ATTRIBUTE_RELEASE),
        &project,
    );
    project
}

fn file_snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).expect("project directory reads") {
            let entry = entry.expect("project entry reads");
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).expect("project entry metadata reads");
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                visit(root, &path, files);
            } else if metadata.is_file() {
                files.insert(
                    path.strip_prefix(root)
                        .expect("entry remains in project")
                        .to_path_buf(),
                    fs::read(path).expect("project file reads"),
                );
            }
        }
    }

    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

#[test]
fn current_starter_is_no_change_and_does_not_emit_a_formatting_candidate() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = initialized_project(temporary.path());
    let before = file_snapshot(&project);
    let execution_context = worker();
    let candidate = temporary.path().join("unneeded-candidate");
    let report = migrate_registry_project_with_context(
        &ProjectMigrationOptions {
            project_directory: project.clone(),
            target_version: 1,
            output_directory: Some(candidate.clone()),
            write_candidate: true,
        },
        &execution_context,
    )
    .expect("current project migration check completes");
    assert_eq!(
        report.disposition,
        MigrationDisposition::NoMigrationRequired
    );
    assert_eq!(
        report.output.candidate_emission,
        MigrationCandidateEmission::NotEmitted
    );
    let fixture_transition = report
        .version_transitions
        .iter()
        .find(|transition| transition.contract == AuthoringContract::Fixture)
        .expect("fixture transition is present");
    assert_eq!(fixture_transition.source_version, Some(1));
    assert_eq!(fixture_transition.target_version, Some(1));
    assert!(!candidate.exists());
    assert_eq!(file_snapshot(&project), before);
}

#[test]
fn historical_attribute_release_emits_only_the_reviewable_catalog_transform() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = historical_attribute_release_project(temporary.path());
    let before = file_snapshot(&project);
    let execution_context = worker();
    let check_error = check_registry_project_with_context(
        &ProjectCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_owned(),
            explain: false,
            against: None,
            anchor: None,
        },
        &execution_context,
    )
    .expect_err("historical project requires a reviewed migration");
    let diagnostics = check_error
        .downcast::<ProjectAuthoringDiagnostics>()
        .expect("historical project returns typed authoring diagnostics");
    assert_eq!(diagnostics.diagnostics.len(), 1, "{diagnostics:#?}");
    let diagnostic = &diagnostics.diagnostics[0];
    assert_eq!(
        diagnostic.code, "registryctl.authoring.project.invalid",
        "{diagnostics:#?}"
    );
    assert_eq!(
        diagnostic.remediation,
        "Correct the project YAML using the project authoring schema. If this project passed with an earlier registryctl, run `registryctl migrate --project-dir <project-directory> --target-version 1` to check the reviewed compatibility catalog. It does not change or approve the source project; any candidate is separate and requires review."
    );
    let rendered = diagnostic.remediation;
    assert!(rendered.contains("<project-directory>"));
    assert!(!rendered.contains(project.to_string_lossy().as_ref()));
    assert!(!rendered.contains("solmara-nia-userinfo"));
    assert!(!rendered.contains("individual_id"));
    assert!(!rendered.contains("max_age_seconds"));

    let checked = migrate_registry_project_with_context(
        &ProjectMigrationOptions {
            project_directory: project.clone(),
            target_version: 1,
            output_directory: None,
            write_candidate: false,
        },
        &execution_context,
    )
    .expect("historical migration check completes");
    assert_eq!(checked.disposition, MigrationDisposition::ReviewRequired);
    assert!(checked
        .reviews
        .iter()
        .any(|review| review.status == MigrationReviewStatus::RequiredPending));
    assert_eq!(
        checked
            .version_transitions
            .iter()
            .find(|transition| transition.contract == AuthoringContract::Fixture)
            .expect("fixture transition is present")
            .source_version,
        None,
        "a project without fixture YAML has no fixture contract transition"
    );
    assert_eq!(file_snapshot(&project), before);
    let cli = migration_cli(&project, "1");
    assert_eq!(
        cli.status.code(),
        Some(0),
        "review_required is a successful check, not approval"
    );
    let cli_report: registryctl::ProjectMigrationReportV1 =
        serde_json::from_slice(&cli.stdout).expect("review report is JSON");
    assert_eq!(cli_report.disposition, MigrationDisposition::ReviewRequired);
    assert!(cli_report
        .reviews
        .iter()
        .any(|review| review.status == MigrationReviewStatus::RequiredPending));

    let candidate = temporary.path().join("reviewable-candidate");
    let emitted = migrate_registry_project_with_context(
        &ProjectMigrationOptions {
            project_directory: project.clone(),
            target_version: 1,
            output_directory: Some(candidate.clone()),
            write_candidate: true,
        },
        &execution_context,
    )
    .expect("migration candidate is emitted");
    assert_eq!(emitted.disposition, MigrationDisposition::ReviewRequired);
    assert_eq!(
        emitted.output.candidate_emission,
        MigrationCandidateEmission::SeparateOutputCandidateEmitted
    );
    assert!(emitted.blocking_reasons.is_empty());
    assert!(emitted.compatible_normalizations.iter().any(|change| {
        change.address.path == MigrationFieldPath::AttributeReleaseSubjectInput
            && change.operation == MigrationOperation::RemoveField
    }));
    assert!(emitted.semantic_changes.iter().any(|change| {
        change.address.path == MigrationFieldPath::AttributeReleaseResponseMaxAge
            && change.operation == MigrationOperation::RemoveField
    }));
    assert!(candidate.join("migration-report.json").is_file());
    assert_eq!(file_snapshot(&project), before);
    assert_eq!(
        fs::read(project.join("entities/population.yaml")).expect("source entity reads"),
        fs::read(candidate.join("entities/population.yaml")).expect("candidate entity reads")
    );
    assert_eq!(
        fs::read(project.join("environments/local.yaml")).expect("source environment reads"),
        fs::read(candidate.join("environments/local.yaml")).expect("candidate environment reads")
    );
    let migrated_project =
        fs::read_to_string(candidate.join("registry-stack.yaml")).expect("candidate project reads");
    assert!(!migrated_project.contains("input: individual_id"));
    assert!(!migrated_project.contains("max_age_seconds"));
    let migrated_value: serde_json::Value =
        serde_norway::from_str(&migrated_project).expect("candidate YAML parses");
    assert!(migrated_value
        .pointer("/services/nia-population-records/api/attribute_release_profiles/solmara-nia-userinfo/subject/input")
        .is_none());
    assert!(migrated_value
        .pointer("/services/nia-population-records/api/attribute_release_profiles/solmara-nia-userinfo/response")
        .is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&candidate)
                .expect("candidate metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(candidate.join("migration-report.json"))
                .expect("report metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    check_registry_project_with_context(
        &ProjectCheckOptions {
            project_directory: candidate,
            environment: "local".to_owned(),
            explain: false,
            against: None,
            anchor: None,
        },
        &execution_context,
    )
    .expect("separate candidate remains valid authoring input");

    let report = serde_json::to_string(&emitted).expect("report serializes");
    assert!(!report.contains(project.to_string_lossy().as_ref()));
    assert!(!report.contains(temporary.path().to_string_lossy().as_ref()));
}

#[test]
fn candidate_never_replaces_an_existing_destination() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = initialized_project(temporary.path());
    let candidate = temporary.path().join("existing-candidate");
    fs::create_dir(&candidate).expect("candidate directory");
    fs::write(candidate.join("sentinel"), b"keep-me").expect("sentinel writes");

    let error = migrate_registry_project_with_context(
        &ProjectMigrationOptions {
            project_directory: project,
            target_version: 1,
            output_directory: Some(candidate.clone()),
            write_candidate: true,
        },
        &worker(),
    )
    .expect_err("existing candidate blocks publication");
    assert!(error
        .to_string()
        .contains("candidate destination must not already exist"));
    assert_eq!(
        fs::read(candidate.join("sentinel")).expect("sentinel remains"),
        b"keep-me"
    );
}

#[test]
fn unsupported_target_fails_closed_in_the_cli_without_writing() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = initialized_project(temporary.path());
    let candidate = temporary.path().join("unsupported-candidate");
    for (target, expected_diagnostic) in [
        ("0", MigrationDiagnosticCode::TargetVersionOutOfBounds),
        ("2", MigrationDiagnosticCode::TargetVersionUnsupported),
        ("65536", MigrationDiagnosticCode::TargetVersionOutOfBounds),
    ] {
        let output = if target == "2" {
            Command::new(env!("CARGO_BIN_EXE_registryctl"))
                .args([
                    "migrate",
                    "--project-dir",
                    project.to_str().expect("project path is Unicode"),
                    "--target-version",
                    target,
                    "--output",
                    candidate.to_str().expect("candidate path is Unicode"),
                    "--write-candidate",
                    "--format",
                    "json",
                ])
                .output()
                .expect("migration CLI runs")
        } else {
            migration_cli(&project, target)
        };
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        let document: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("blocked report is JSON");
        assert_schema_valid(&document);
        let report: registryctl::ProjectMigrationReportV1 =
            serde_json::from_value(document).expect("blocked report enters through the DTO");
        assert_eq!(report.disposition, MigrationDisposition::Blocked);
        assert_eq!(
            report.blocking_reasons,
            vec![MigrationBlockingReason::TargetVersionUnsupported]
        );
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].code, expected_diagnostic);
        assert!(report.version_transitions.iter().all(|transition| {
            transition.target_version.is_none()
                && transition.direction == MigrationVersionDirection::UnsupportedTarget
        }));
        assert!(report
            .rerun_gates
            .iter()
            .all(|gate| gate.status == MigrationGateStatus::NotApplicable));
        assert!(report.compatible_normalizations.is_empty());
        assert!(report.semantic_changes.is_empty());
        assert!(report.reviews.is_empty());
    }
    assert!(!candidate.exists());

    let integration = project.join("integrations/person-record/integration.yaml");
    let source = fs::read_to_string(&integration).expect("integration reads");
    fs::write(&integration, source.replacen("version: 1", "version: 2", 1))
        .expect("unsupported integration version is authored");
    fs::create_dir_all(project.join("integrations/person-record/fixtures"))
        .expect("fixture directory is created");
    fs::write(
        project.join("integrations/person-record/fixtures/version-inheritance.yaml"),
        "name: version-inheritance\n",
    )
    .expect("fixture YAML is authored");
    let output = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "migrate",
            "--project-dir",
            project.to_str().expect("project path is Unicode"),
            "--target-version",
            "1",
            "--format",
            "json",
        ])
        .output()
        .expect("migration CLI runs");
    assert_eq!(output.status.code(), Some(1));
    let report: registryctl::ProjectMigrationReportV1 =
        serde_json::from_slice(&output.stdout).expect("unsupported source report is JSON");
    assert!(report
        .blocking_reasons
        .contains(&MigrationBlockingReason::SourceVersionUnsupported));
    let integration_version = report
        .version_transitions
        .iter()
        .find(|transition| transition.contract == AuthoringContract::Integration)
        .expect("integration transition is present")
        .source_version;
    let fixture_version = report
        .version_transitions
        .iter()
        .find(|transition| transition.contract == AuthoringContract::Fixture)
        .expect("fixture transition is present")
        .source_version;
    assert_eq!(
        fixture_version, integration_version,
        "fixture version follows the integration that owns real fixture YAML"
    );

    fs::write(&integration, source).expect("supported integration version is restored");
    let local_environment =
        fs::read_to_string(project.join("environments/local.yaml")).expect("environment reads");
    fs::write(
        project.join("environments/staging.yaml"),
        local_environment.replacen("version: 1", "version: 2", 1),
    )
    .expect("mixed environment version is authored");
    let output = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "migrate",
            "--project-dir",
            project.to_str().expect("project path is Unicode"),
            "--target-version",
            "1",
            "--format",
            "json",
        ])
        .output()
        .expect("migration CLI runs");
    assert_eq!(output.status.code(), Some(1));
    let report: registryctl::ProjectMigrationReportV1 =
        serde_json::from_slice(&output.stdout).expect("mixed-version source report is JSON");
    assert!(report
        .blocking_reasons
        .contains(&MigrationBlockingReason::SourceVersionUnsupported));
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == MigrationDiagnosticCode::SourceVersionsMixed));
}

#[cfg(unix)]
#[test]
fn catalog_staging_rejects_symlinks_without_publishing_or_changing_source() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = historical_attribute_release_project(temporary.path());
    let before = fs::read(project.join("registry-stack.yaml")).expect("source project reads");
    symlink("README.md", project.join("linked-note")).expect("test symlink is created");
    let candidate = temporary.path().join("candidate");
    let error = migrate_registry_project_with_context(
        &ProjectMigrationOptions {
            project_directory: project.clone(),
            target_version: 1,
            output_directory: Some(candidate.clone()),
            write_candidate: true,
        },
        &worker(),
    )
    .expect_err("a source symlink blocks catalog staging");
    assert!(error
        .to_string()
        .contains("symlinks are forbidden at the migration source boundary"));
    assert!(!candidate.exists());
    assert_eq!(
        fs::read(project.join("registry-stack.yaml")).expect("source project still reads"),
        before
    );
    assert!(fs::symlink_metadata(project.join("linked-note"))
        .expect("source symlink remains")
        .file_type()
        .is_symlink());
}

#[test]
fn invalid_source_versions_are_structured_value_free_json() {
    let cases = [
        (
            "missing",
            "version: 1\n",
            "",
            MigrationDiagnosticCode::SourceVersionMissing,
        ),
        (
            "malformed",
            "version: 1",
            "version: one",
            MigrationDiagnosticCode::SourceVersionMalformed,
        ),
        (
            "zero",
            "version: 1",
            "version: 0",
            MigrationDiagnosticCode::SourceVersionZero,
        ),
        (
            "out-of-bounds",
            "version: 1",
            "version: 65536",
            MigrationDiagnosticCode::SourceVersionOutOfBounds,
        ),
    ];
    for (name, from, to, expected) in cases {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = initialized_project(temporary.path());
        let path = project.join("registry-stack.yaml");
        let source = fs::read_to_string(&path).expect("project reads");
        fs::write(&path, source.replacen(from, to, 1)).expect("invalid version writes");
        let output = migration_cli(&project, "1");
        assert_eq!(output.status.code(), Some(1), "{name}");
        assert!(output.stderr.is_empty(), "{name}");
        let report: registryctl::ProjectMigrationReportV1 =
            serde_json::from_slice(&output.stdout).expect("blocked report is strict JSON");
        assert_eq!(report.disposition, MigrationDisposition::Blocked, "{name}");
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == expected),
            "{name}"
        );
        let serialized = String::from_utf8(output.stdout).expect("JSON is UTF-8");
        assert!(
            !serialized.contains(project.to_string_lossy().as_ref()),
            "{name}"
        );
    }
}

#[test]
fn malformed_source_yaml_is_a_structured_inspection_boundary() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = initialized_project(temporary.path());
    fs::write(project.join("registry-stack.yaml"), b"version: [\n")
        .expect("malformed project writes");
    let output = migration_cli(&project, "1");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report: registryctl::ProjectMigrationReportV1 =
        serde_json::from_slice(&output.stdout).expect("blocked report is strict JSON");
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == MigrationDiagnosticCode::SourceYamlMalformed));
}

#[test]
fn malformed_referenced_yaml_is_a_structured_inspection_boundary() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = initialized_project(temporary.path());
    fs::write(
        project.join("integrations/person-record/integration.yaml"),
        b"version: [\n",
    )
    .expect("malformed integration writes");
    let output = migration_cli(&project, "1");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report: registryctl::ProjectMigrationReportV1 =
        serde_json::from_slice(&output.stdout).expect("blocked report is strict JSON");
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == MigrationDiagnosticCode::SourceYamlMalformed
            && diagnostic.contract == Some(AuthoringContract::Integration)
    }));
}

fn migration_cli(project: &Path, target: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "migrate",
            "--project-dir",
            project.to_str().expect("project path is Unicode"),
            "--target-version",
            target,
            "--format",
            "json",
        ])
        .output()
        .expect("migration CLI runs")
}
