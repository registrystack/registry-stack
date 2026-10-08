//! A derivation may read only the facts its question's source declares.
//!
//! The check is static: it reads the `answer` function's own index and
//! property reads on its first parameter, and names each literal key the
//! declared set does not hold. A key it cannot read statically, and a read
//! inside another function, are left to the fixtures.

use std::collections::BTreeSet;

use registry_evidence_authoring::{validate_answer_fact_reads, Finding};

fn declared(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn messages(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| format!("{}: {}", finding.code, finding.message))
        .collect()
}

#[test]
fn an_index_read_of_an_undeclared_fact_is_named() {
    let findings = validate_answer_fact_reads(
        "fn answer(facts, selectors, context) {\n\
             let status = required(facts[\"status\"], \"status_missing\");\n\
             #{ active: status == \"active\" }\n\
         }",
        &declared(&["code", "lifecycle_status"]),
    );
    assert_eq!(
        messages(&findings),
        [
            "derivation-fact-undeclared: authored derivation reads fact `status`, \
          which the question's source does not declare"
        ]
    );
}

#[test]
fn a_property_read_and_a_chained_read_are_named() {
    let findings = validate_answer_fact_reads(
        "fn answer(record, selectors, context) {\n\
             #{ a: record.status == \"active\", b: record[\"address\"].region, c: record?.missing }\n\
         }",
        &declared(&["status"]),
    );
    assert_eq!(
        messages(&findings),
        [
            "derivation-fact-undeclared: authored derivation reads fact `address`, \
             which the question's source does not declare",
            "derivation-fact-undeclared: authored derivation reads fact `missing`, \
             which the question's source does not declare",
        ]
    );
}

#[test]
fn declared_reads_and_reads_the_check_cannot_resolve_report_nothing() {
    let source = "fn helper(facts) { facts[\"elsewhere\"] }\n\
         fn answer(facts, selectors, context) {\n\
             let key = \"computed\";\n\
             let chosen = facts[key];\n\
             let marker = facts[\"marker\"];\n\
             let nested = facts.marker.inner;\n\
             let size = facts.len();\n\
             let other = selectors[\"not_a_fact\"];\n\
             #{ marked: marker == true }\n\
         }";
    assert_eq!(
        validate_answer_fact_reads(source, &declared(&["marker"])),
        Vec::new()
    );
}

#[test]
fn a_repeated_undeclared_read_is_named_once() {
    let findings = validate_answer_fact_reads(
        "fn answer(facts, selectors, context) { #{ a: facts.gone, b: facts[\"gone\"] } }",
        &declared(&[]),
    );
    assert_eq!(findings.len(), 1, "findings were: {findings:?}");
}

#[test]
fn a_shadowed_facts_parameter_is_not_read_as_the_source_facts() {
    let source = "fn answer(facts, selectors, context) {\n\
             let facts = #{ local: 1 };\n\
             #{ marked: facts.local == 1 }\n\
         }";
    assert_eq!(
        validate_answer_fact_reads(source, &declared(&[])),
        Vec::new()
    );
}

#[test]
fn an_answer_that_assigns_or_rebinds_its_first_parameter_reports_nothing() {
    for body in [
        "facts = #{ local: 1 };\n#{ marked: facts.local == 1 }",
        "facts.local = 1;\n#{ marked: facts.local == 1 }",
        "facts[\"local\"] += 1;\n#{ marked: facts.local == 2 }",
        "let total = 0;\nfor facts in [#{ local: 1 }] { total += facts.local; }\n#{ total: total }",
        "let total = 0;\nfor (row, facts) in [1] { total += row; }\n#{ total: total + facts.local }",
        "try { throw 1; } catch (facts) { return #{ caught: facts.local }; }\n#{}",
    ] {
        let source = format!("fn answer(facts, selectors, context) {{\n{body}\n}}");
        assert_eq!(
            validate_answer_fact_reads(&source, &declared(&[])),
            Vec::new(),
            "{source}"
        );
    }
}

#[test]
fn a_fallback_between_names_is_satisfied_by_any_declared_name() {
    let source = "fn answer(facts, selectors, context) {\n\
             #{ status: facts.status_code ?? facts[\"status\"] ?? \"unknown\" }\n\
         }";
    assert_eq!(
        validate_answer_fact_reads(source, &declared(&["status"])),
        Vec::new()
    );
    assert_eq!(
        validate_answer_fact_reads(source, &declared(&["status_code"])),
        Vec::new()
    );
}

#[test]
fn a_fallback_with_no_declared_name_names_each_of_them() {
    let findings = validate_answer_fact_reads(
        "fn answer(facts, selectors, context) { #{ s: facts.old ?? facts.older ?? \"none\" } }",
        &declared(&["status"]),
    );
    assert_eq!(
        messages(&findings),
        [
            "derivation-fact-undeclared: authored derivation reads fact `old`, \
             which the question's source does not declare",
            "derivation-fact-undeclared: authored derivation reads fact `older`, \
             which the question's source does not declare",
        ]
    );
}

#[test]
fn a_program_the_other_checks_refuse_reports_nothing_here() {
    for source in [
        "fn answer(facts, selectors, context) {",
        "fn helper() { 1 }",
    ] {
        assert_eq!(
            validate_answer_fact_reads(source, &declared(&[])),
            Vec::new()
        );
    }
}
