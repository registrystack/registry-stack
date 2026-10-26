// SPDX-License-Identifier: Apache-2.0

use registry_platform_config::apply_check_acceptances;
use registry_platform_yaml::{Diagnostic, Report, Source};

const ACCEPTANCES: &str = r#"apiVersion: id.registrystack.org/formats/platform/check-acceptances/v1alpha1
kind: PlatformCheckAcceptances
acceptances:
  - code: example.access.unrestricted
    scope:
      file: registry.yaml
      path: /accessProfiles/@id=registrar/rowBoundaries
    reason: National registrars intentionally work across every district.
"#;

fn warning(root: &std::path::Path) -> Diagnostic {
    let mut diagnostic = Diagnostic::warning(
        "example.access.unrestricted",
        "/accessProfiles/0/rowBoundaries",
        "This permission reaches every row.",
        "Review this permission.",
    );
    diagnostic.source = Some(Source {
        file: root.join("registry.yaml").display().to_string(),
        line: Some(3),
        column: Some(5),
    });
    diagnostic
}

fn project() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("registry.yaml"),
        "accessProfiles:\n  - id: registrar\n    rowBoundaries: unrestricted\n",
    )
    .unwrap();
    root
}

#[test]
fn an_unrelated_error_does_not_hide_an_accepted_warning() {
    let root = project();
    std::fs::write(root.path().join("check-acceptances.yaml"), ACCEPTANCES).unwrap();
    let mut report = Report::new(vec![
        warning(root.path()),
        Diagnostic::error(
            "example.project.invalid",
            "/project",
            "The project is invalid.",
            "Correct the project.",
        ),
    ]);

    apply_check_acceptances(root.path(), &mut report);

    assert_eq!(report.error_count(), 1);
    assert_eq!(report.warning_count(), 0);
    assert_eq!(report.accepted_warning_count(), 1);
    let warning = &report.diagnostics()[0];
    assert_eq!(
        warning.scope.as_ref().map(|scope| scope.file.as_str()),
        Some("registry.yaml")
    );
    assert_eq!(
        warning.accepted_reason.as_deref(),
        Some("National registrars intentionally work across every district.")
    );
}

#[cfg(unix)]
#[test]
fn an_acceptance_symlink_cannot_import_decisions_from_outside_the_project() {
    let root = project();
    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("check-acceptances.yaml");
    std::fs::write(&outside_file, ACCEPTANCES).unwrap();
    std::os::unix::fs::symlink(&outside_file, root.path().join("check-acceptances.yaml")).unwrap();
    let mut report = Report::new(vec![warning(root.path())]);

    apply_check_acceptances(root.path(), &mut report);

    assert_eq!(report.accepted_warning_count(), 0);
    assert_eq!(report.warning_count(), 1);
    assert!(report.has_errors());
    assert!(report
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "config.check-acceptances-unreadable"));
}

#[test]
fn a_bare_relative_source_ignores_a_process_file_outside_the_project() {
    assert!(
        std::path::Path::new("Cargo.toml").is_file(),
        "this regression requires Cargo's workspace working directory"
    );
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname = 'fixture'\n",
    )
    .unwrap();
    let mut diagnostic = Diagnostic::warning(
        "example.project.warning",
        "/package/name",
        "The package name needs review.",
        "Review the package name.",
    );
    diagnostic.source = Some(Source {
        file: "Cargo.toml".to_owned(),
        line: Some(2),
        column: Some(8),
    });
    let mut report = Report::new(vec![diagnostic]);

    apply_check_acceptances(root.path(), &mut report);

    let scope = report.diagnostics()[0]
        .scope
        .as_ref()
        .expect("the project-relative source has a scope");
    assert_eq!(scope.file, "Cargo.toml");
    assert_eq!(scope.path, "/package/name");
}

#[test]
fn a_project_root_warning_does_not_publish_an_empty_file_scope() {
    let root = tempfile::tempdir().unwrap();
    let canonical = root.path().canonicalize().unwrap();
    let mut diagnostic = Diagnostic::warning(
        "example.project.later-checks-skipped",
        "",
        "Later project checks did not run.",
        "Correct the errors and check again.",
    );
    diagnostic.source = Some(Source {
        file: canonical.display().to_string(),
        line: None,
        column: None,
    });
    let mut report = Report::new(vec![diagnostic]);

    apply_check_acceptances(&canonical, &mut report);

    assert!(report.diagnostics()[0].scope.is_none());
}
