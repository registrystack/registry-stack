// SPDX-License-Identifier: Apache-2.0

use registry_platform_config::apply_check_acceptances;
use registry_platform_yaml::{Diagnostic, Report, Source};

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

#[test]
fn project_file_is_optional_and_scopes_are_available_for_authoring_it() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("registry.yaml"),
        "accessProfiles:\n  - id: registrar\n    rowBoundaries: unrestricted\n",
    )
    .unwrap();
    let mut report = Report::new(vec![warning(root.path())]);
    apply_check_acceptances(root.path(), &mut report);
    assert_eq!(report.warning_count(), 1);
    let scope = report.diagnostics()[0].scope.as_ref().unwrap();
    assert_eq!(scope.file, "registry.yaml");
    assert_eq!(scope.path, "/accessProfiles/@id=registrar/rowBoundaries");
}

#[test]
fn project_acceptance_is_applied_and_a_missing_reason_is_an_error() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("registry.yaml"),
        "accessProfiles:\n  - id: registrar\n    rowBoundaries: unrestricted\n",
    )
    .unwrap();
    let input = "apiVersion: id.registrystack.org/formats/platform/check-acceptances/v1alpha1\nkind: PlatformCheckAcceptances\nacceptances:\n  - code: example.access.unrestricted\n    scope:\n      file: registry.yaml\n      path: /accessProfiles/@id=registrar/rowBoundaries\n    reason: National registrars work across all districts.\n";
    std::fs::write(root.path().join("check-acceptances.yaml"), input).unwrap();
    let mut report = Report::new(vec![warning(root.path())]);
    apply_check_acceptances(root.path(), &mut report);
    assert_eq!(report.warning_count(), 0);
    assert_eq!(report.accepted_warning_count(), 1);
    assert!(!report.has_errors());
    std::fs::write(
        root.path().join("check-acceptances.yaml"),
        input.replace(
            "    reason: National registrars work across all districts.\n",
            "",
        ),
    )
    .unwrap();
    let mut report = Report::new(vec![warning(root.path())]);
    apply_check_acceptances(root.path(), &mut report);
    assert!(report.has_errors());
    assert_eq!(report.warning_count(), 1);
}

#[test]
fn an_unreadable_acceptance_file_is_a_visible_failure() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("check-acceptances.yaml")).unwrap();
    let mut report = Report::default();
    apply_check_acceptances(root.path(), &mut report);
    assert!(report.has_errors());
    assert!(report
        .diagnostics()
        .iter()
        .any(|d| d.code == "config.check-acceptances-unreadable"));
}

#[test]
fn acceptance_reasons_follow_the_shared_authored_expression_policy() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("check-acceptances.yaml"),
        "apiVersion: id.registrystack.org/formats/platform/check-acceptances/v1alpha1\nkind: PlatformCheckAcceptances\nacceptances:\n  - code: example.access.unrestricted\n    scope: {file: registry.yaml, path: ''}\n    reason: '${CANARY_ACCEPTANCE_REASON}'\n").unwrap();
    let mut report = Report::default();
    apply_check_acceptances(root.path(), &mut report);
    assert!(report.has_errors());
    assert!(report
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "config.substitution-not-allowed"));
    assert!(!report.render_human().contains("CANARY_ACCEPTANCE_REASON"));
}
