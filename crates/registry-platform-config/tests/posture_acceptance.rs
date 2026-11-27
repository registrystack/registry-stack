// SPDX-License-Identifier: Apache-2.0
//! A posture diagnostic cannot be hidden by a project check acceptance.

use registry_platform_config::apply_check_acceptances;
use registry_platform_yaml::{Diagnostic, Report, Severity, Source};

const ACCEPTANCES: &str = "apiVersion: id.registrystack.org/formats/platform/check-acceptances/v1alpha1\nkind: PlatformCheckAcceptances\nacceptances:\n  - code: platform.posture.insecure-issuer-http\n    scope:\n      file: runtime.yaml\n      path: /issuer/allowInsecureHttp\n    reason: We need it on the laptop.\n";

fn posture_warning(root: &std::path::Path) -> Diagnostic {
    let mut diagnostic = Diagnostic::warning(
        "platform.posture.insecure-issuer-http",
        "/issuer/allowInsecureHttp",
        "The issuer is reached over plain HTTP; production refuses it",
        "Write allowInsecureHttp: false.",
    );
    diagnostic.source = Some(Source {
        file: root.join("runtime.yaml").display().to_string(),
        line: Some(4),
        column: Some(3),
    });
    diagnostic
}

#[test]
fn an_acceptance_naming_a_posture_code_is_refused_and_hides_nothing() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("runtime.yaml"),
        "issuer:\n  allowInsecureHttp: true\n",
    )
    .unwrap();
    std::fs::write(root.path().join("check-acceptances.yaml"), ACCEPTANCES).unwrap();
    let mut report = Report::new(vec![posture_warning(root.path())]);
    apply_check_acceptances(root.path(), &mut report);

    let posture = report
        .diagnostics()
        .iter()
        .find(|d| d.code == "platform.posture.insecure-issuer-http")
        .unwrap();
    assert_eq!(posture.accepted_reason, None);
    assert_eq!(report.accepted_warning_count(), 0);
    let refusal: Vec<_> = report
        .diagnostics()
        .iter()
        .filter(|d| d.code == "config.check-acceptance-not-acceptable")
        .collect();
    assert_eq!(refusal.len(), 1);
    assert_eq!(refusal[0].severity, Severity::Error);
    assert_eq!(refusal[0].path, "/acceptances/0/code");
}

#[test]
fn other_acceptances_in_the_same_file_still_apply() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("registry.yaml"), "a:\n  b: 1\n").unwrap();
    let input = ACCEPTANCES.to_owned()
        + "  - code: example.access.unrestricted\n    scope:\n      file: registry.yaml\n      path: /a/b\n    reason: Reviewed.\n";
    std::fs::write(root.path().join("check-acceptances.yaml"), input).unwrap();
    let mut other = Diagnostic::warning("example.access.unrestricted", "/a/b", "m", "a");
    other.source = Some(Source {
        file: root.path().join("registry.yaml").display().to_string(),
        line: Some(2),
        column: Some(3),
    });
    let mut report = Report::new(vec![posture_warning(root.path()), other]);
    apply_check_acceptances(root.path(), &mut report);
    assert_eq!(report.accepted_warning_count(), 1);
}
