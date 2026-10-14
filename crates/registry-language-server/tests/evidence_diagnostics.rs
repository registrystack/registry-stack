// SPDX-License-Identifier: Apache-2.0
#[path = "support/normalized.rs"]
mod normalized;
use normalized::*;

#[test]
fn shared_parser_codes_messages_and_field_locations_match() {
    let source = SOURCE.replace("source: person}", "source: missing}");
    let p = Project::new(&source);
    let report =
        registry_evidence_authoring::project::read_project(PROJECT, source.as_bytes()).unwrap_err();
    let index = p.index();
    for finding in report.diagnostics() {
        let diagnostic = index
            .diagnostics()
            .iter()
            .find(|x| x.code.as_ref() == Some(&finding.code))
            .unwrap();
        assert_eq!(diagnostic.message, finding.message);
        let place = finding.source.as_ref().unwrap();
        assert_eq!(
            diagnostic.range.start.line,
            (place.line.unwrap() - 1) as u32
        );
    }
    assert_eq!(index.diagnostics().len(), report.diagnostics().len());
}
#[test]
fn unknown_keys_are_reported_at_the_key() {
    let source = SOURCE.replace("validitySeconds:", "validitySecondz:");
    let p = Project::new(&source);
    let index = p.index();
    let diagnostic = index
        .diagnostics()
        .iter()
        .find(|x| x.code.as_deref() == Some("config.unknown-key"))
        .unwrap();
    assert_eq!(diagnostic.range.start, at(&source, "validitySecondz"));
}
#[test]
fn environment_substitution_is_refused_without_expansion() {
    let p = Project::new(&SOURCE.replace("population", "${SOURCE_CONNECTION}"));
    assert!(p
        .index()
        .diagnostics()
        .iter()
        .any(|x| x.code.as_deref() == Some("config.substitution-not-allowed")));
}
#[test]
fn named_function_interface_fault_is_reported_without_executing_code() {
    let p = Project::new(SOURCE);
    p.write(DERIVE, "fn extract(response,selectors) {}\n");
    assert!(p
        .index()
        .diagnostics()
        .iter()
        .any(|x| x.path == p.path(DERIVE)
            && x.code.as_ref().unwrap().starts_with("evidence.function.")));
}
#[test]
fn authority_diagnostics_use_the_shared_grant_reader() {
    let p = Project::new(SOURCE);
    p.write(
        "targets/local/authority.yaml",
        &AUTHORITY.replace("definition: active-status", "definition: missing"),
    );
    assert!(p
        .index()
        .diagnostics()
        .iter()
        .any(|x| x.path == p.path("targets/local/authority.yaml")));
}
#[test]
fn old_question_inline_operation_and_disclosure_are_rejected() {
    for source in ["apiVersion: id.registrystack.org/formats/evidence/question/v1alpha1\nkind: EvidenceQuestion\nid: old\n".to_owned(),SOURCE.replace("    derive:","    disclosure: {allow: [active]}\n    derive:"),SOURCE.replace("    acquisition:","    source: {operation: readPerson}\n    acquisition:")] {
        let p=Project::new(&source);assert!(!p.index().diagnostics().is_empty());
    }
}
