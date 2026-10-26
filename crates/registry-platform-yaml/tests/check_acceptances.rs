// SPDX-License-Identifier: Apache-2.0

use registry_platform_yaml::{
    check_scope_path, read_check_acceptances, CheckScope, Diagnostic, Report, Severity,
};
use serde_json::json;

const ACCEPTANCES: &str = r#"apiVersion: id.registrystack.org/formats/platform/check-acceptances/v1alpha1
kind: PlatformCheckAcceptances
acceptances:
  - code: breg.access.target-unrestricted-rows
    scope:
      file: registry.yaml
      path: /accessProfiles/@id=registrar/rowBoundaries
    reason: Registrars intentionally work across all districts.
"#;

fn warning() -> Diagnostic {
    let mut diagnostic = Diagnostic::warning(
        "breg.access.target-unrestricted-rows",
        "/accessProfiles/0/rowBoundaries",
        "The permission reaches every row of its target type.",
        "Review this permission.",
    );
    diagnostic.scope = Some(CheckScope {
        file: "registry.yaml".into(),
        path: "/accessProfiles/@id=registrar/rowBoundaries".into(),
    });
    diagnostic
}

#[test]
fn acceptance_keeps_the_finding_and_reason_but_removes_it_from_the_warning_gate() {
    let accepted = read_check_acceptances("check-acceptances.yaml", ACCEPTANCES.as_bytes())
        .unwrap()
        .value;
    let mut report = Report::new(vec![warning()]);
    accepted.apply(&mut report);
    assert_eq!(report.warning_count(), 0);
    assert_eq!(report.accepted_warning_count(), 1);
    assert!(!report.has_errors());
    let diagnostics = report.to_json_value();
    assert_eq!(diagnostics[0]["severity"], "warning");
    assert_eq!(diagnostics[0]["path"], "/accessProfiles/0/rowBoundaries");
    assert_eq!(
        diagnostics[0]["acceptedReason"],
        "Registrars intentionally work across all districts."
    );
    assert!(report.render_human().contains("Accepted warnings:"));
    assert!(report.render_human().contains("Registrars intentionally"));
    assert!(report.summary().contains("1 accepted warning"));
}

#[test]
fn acceptance_matches_the_exact_code_file_and_scope_and_never_an_error() {
    let accepted = read_check_acceptances("check-acceptances.yaml", ACCEPTANCES.as_bytes())
        .unwrap()
        .value;
    let original = warning();
    let mut different_code = original.clone();
    different_code.code = "breg.access.profile-unrestricted-rows".into();
    let mut different_file = original.clone();
    different_file.scope.as_mut().unwrap().file = "modules/core/module.yaml".into();
    let mut different_subject = original.clone();
    different_subject.scope.as_mut().unwrap().path =
        "/accessProfiles/@id=clerk/rowBoundaries".into();
    let mut error = original.clone();
    error.severity = Severity::Error;
    let mut report = Report::new(vec![
        original,
        different_code,
        different_file,
        different_subject,
        error,
    ]);
    accepted.apply(&mut report);
    assert_eq!(report.accepted_warning_count(), 1);
    assert_eq!(report.warning_count(), 3);
    assert_eq!(report.error_count(), 1);
    assert!(report.diagnostics()[4].accepted_reason.is_none());
}

#[test]
fn invalid_acceptances_are_refused_without_repeating_their_values() {
    for (from, to) in [
        (
            "Registrars intentionally work across all districts.",
            "'   '",
        ),
        ("file: registry.yaml", "file: ../canary-private.yaml"),
        (
            "breg.access.target-unrestricted-rows",
            "canary-invalid-code",
        ),
        ("/@id=registrar/rowBoundaries", "/@id=registrar/~2bad"),
        ("reason:", "canaryUnknownMember:"),
    ] {
        let input = ACCEPTANCES.replace(from, to);
        let report =
            read_check_acceptances("check-acceptances.yaml", input.as_bytes()).unwrap_err();
        assert!(report.has_errors(), "{input}");
        assert!(!report.render_human().contains("canary-private"));
        assert!(!report.render_human().contains("canary-invalid-code"));
    }
}

#[test]
fn duplicate_acceptances_are_refused_and_unused_entries_are_harmless() {
    let input = format!(
        "{ACCEPTANCES}{}",
        ACCEPTANCES.split_once("acceptances:\n").unwrap().1
    );
    assert!(read_check_acceptances("check-acceptances.yaml", input.as_bytes()).is_err());
    let accepted = read_check_acceptances("check-acceptances.yaml", ACCEPTANCES.as_bytes())
        .unwrap()
        .value;
    let mut report = Report::default();
    accepted.apply(&mut report);
    assert!(report.is_empty());
}

#[test]
fn scope_uses_existing_resource_identifiers_and_survives_reordering() {
    let first = json!({"accessProfiles":[
        {"id":"registrar","permissions":{"actions":[{"action":"correct","targets":[{"recordType":"household","rowBoundaries":"unrestricted"}]}]}},
        {"id":"clerk","rowBoundaries":"unrestricted"}
    ]});
    let second = json!({"accessProfiles":[first["accessProfiles"][1].clone(), first["accessProfiles"][0].clone()]});
    let scope = "/accessProfiles/@id=registrar/permissions/actions/@action=correct/targets/@recordType=household/rowBoundaries";
    assert_eq!(
        check_scope_path(
            &first,
            "/accessProfiles/0/permissions/actions/0/targets/0/rowBoundaries"
        ),
        scope
    );
    assert_eq!(
        check_scope_path(
            &second,
            "/accessProfiles/1/permissions/actions/0/targets/0/rowBoundaries"
        ),
        scope
    );
}

#[test]
fn scope_does_not_merge_duplicate_ids_or_expose_arbitrary_values() {
    let duplicate = json!({"items":[{"id":"same"},{"id":"same"}]});
    assert_eq!(check_scope_path(&duplicate, "/items/1/id"), "/items/1/id");
    let arbitrary = json!({"items":[{"id":"CANARY SECRET / value"}]});
    assert_eq!(check_scope_path(&arbitrary, "/items/0/id"), "/items/0/id");
}

#[cfg(feature = "schema")]
#[test]
fn acceptance_schema_matches_its_generated_file_and_refuses_a_blank_reason() {
    let schema = registry_platform_yaml::check_acceptances_schema();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/platform/schemas/check-acceptances.schema.json");
    let committed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(schema, committed);
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let document = registry_platform_yaml::Reader::new("check-acceptances.yaml")
        .scan(ACCEPTANCES.as_bytes())
        .unwrap()
        .unwrap()
        .to_json_value();
    assert!(validator.is_valid(&document));
    let mut blank = document;
    blank["acceptances"][0]["reason"] = json!("   ");
    assert!(!validator.is_valid(&blank));
    for file in [
        "../outside.yaml",
        "/absolute.yaml",
        "dir/../outside.yaml",
        "dir\\outside.yaml",
        "",
    ] {
        let mut invalid = blank.clone();
        invalid["acceptances"][0]["reason"] = json!("An intentional warning.");
        invalid["acceptances"][0]["scope"]["file"] = json!(file);
        assert!(!validator.is_valid(&invalid), "{file}");
    }
}
