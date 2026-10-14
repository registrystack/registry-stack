//! Every sentence these checks produce, held to its exact text.
//!
//! The rules in this crate were adopter tooling's rules first: they lived
//! inside the local project compiler, reported through `anyhow`, and stopped at
//! the first departure they found. Moving them into a library was allowed to
//! change where they run and what a caller may do with the answer. It was not
//! allowed to change a single word an author reads, because those words are
//! quoted in tutorials, matched in tests, and pasted into issues.
//!
//! So this file is a corpus rather than a sample: one deliberately broken
//! document per rule, asserted byte for byte against the sentence that rule
//! produced before the move. A message that drifts fails here, loudly, with the
//! rule named.

#![allow(
    clippy::disallowed_macros,
    reason = "this test target embeds the public canonical fixture; the library performs no I/O"
)]

use registry_evidence_authoring::{project, validate_output_schema_document, Finding};
use serde_json::{json, Value};

const NORMALIZED_PROJECT: &str =
    include_str!("../../../products/evidence/examples/standalone/evidence.yaml");

fn normalized_project() -> project::EvidenceProject {
    project::read_project("evidence.yaml", NORMALIZED_PROJECT.as_bytes())
        .expect("the canonical project reads")
        .value
}

fn normalized_findings(mutate: impl FnOnce(&mut project::EvidenceProject)) -> Vec<Finding> {
    let mut project = normalized_project();
    mutate(&mut project);
    project::validate_project(&project)
}

fn assert_normalized_finding(findings: &[Finding], code: &str, path: &str, message: &str) {
    let matches = findings
        .iter()
        .filter(|finding| finding.code == code && finding.field.to_json_pointer() == path)
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "findings were: {findings:#?}");
    assert_eq!(matches[0].message, message);
}

// --- the corpus --------------------------------------------------------------

/// A question that passes every check, so that each case below differs from a
/// usable document in exactly one way.
fn base_question() -> Value {
    json!({
        "id": "record-check",
        "question": "Does the record carry the reviewed marker?",
        "purpose": "record-check",
        "subject": { "role": "holder", "selector": "record-key" },
        "source": {
            "operation": "getRecord",
            "facts": [{ "name": "marker", "path": "/marker", "combine": "exactly-one" }]
        },
        "answers": [{ "concept": "marked", "type": "boolean" }],
        "derivation": "derivations/record-check.rhai",
        "disclosure": { "allow": ["marked"] }
    })
}

// --- the assertions ----------------------------------------------------------

#[test]
fn normalized_question_rule_reports_its_exact_sentence() {
    let findings = normalized_findings(|project| {
        project
            .assertion_definitions
            .values_mut()
            .next()
            .unwrap()
            .question
            .clear();
    });
    assert_normalized_finding(
        &findings,
        "definition-question",
        "/assertionDefinitions/adult-status/question",
        "write one bounded human-readable question",
    );
}

#[test]
fn normalized_output_rule_reports_its_exact_sentence() {
    let findings = normalized_findings(|project| {
        project
            .assertion_definitions
            .values_mut()
            .next()
            .unwrap()
            .outputs
            .values_mut()
            .next()
            .unwrap()
            .values
            .push("unexpected".to_owned());
    });
    assert_normalized_finding(
        &findings,
        "output-bounds",
        "/assertionDefinitions/adult-status/outputs/adult",
        "declare exactly the finite bounds required by this Output type",
    );
}

#[test]
fn normalized_function_rule_reports_its_exact_sentence() {
    let findings = registry_evidence_authoring::derivation::validate_function(
        "fn derive(facts, selectors) { #{} }",
        project::FunctionInterface::AssertionDerive,
    );
    assert_case(
        "Function signature",
        "Function must expose exactly one entry point with its declared interface signature",
        &findings,
    );
    assert_eq!(first(&findings).code, "function-signature");
}

#[test]
fn a_usable_project_and_named_function_report_nothing() {
    assert_eq!(project::validate_project(&normalized_project()), Vec::new());
    assert_eq!(
        registry_evidence_authoring::derivation::validate_function(
            "fn derive(facts, selectors, context) { #{} }",
            project::FunctionInterface::AssertionDerive,
        ),
        Vec::new()
    );
}

#[test]
fn normalized_rule_codes_remain_machine_addressable() {
    let mut codes = Vec::new();
    codes.extend(normalized_findings(|project| {
        project.functions.push(project.functions[0].clone());
    }));
    codes.extend(normalized_findings(|project| {
        project.assertion_definitions.clear();
    }));
    codes.extend(normalized_findings(|project| {
        project.functions[0].source = "../bad.rhai".to_owned();
    }));
    codes.extend(normalized_findings(|project| {
        project
            .assertion_definitions
            .values_mut()
            .next()
            .unwrap()
            .question
            .clear();
    }));
    codes.extend(normalized_findings(|project| project.functions.clear()));
    codes.extend(normalized_findings(|project| {
        project.selector_profiles.clear()
    }));
    codes.extend(normalized_findings(|project| {
        project.sources.values_mut().next().unwrap().facts.clear();
    }));
    codes.extend(normalized_findings(|project| {
        let output = project
            .assertion_definitions
            .values_mut()
            .next()
            .unwrap()
            .outputs
            .values_mut()
            .next()
            .unwrap();
        output.concept = "relative".to_owned();
        output.value_type = "free-text".to_owned();
    }));
    let mut codes = codes
        .into_iter()
        .map(|finding| finding.code)
        .collect::<Vec<_>>();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(
        codes,
        [
            "definition-count",
            "definition-question",
            "function-interface",
            "function-source",
            "function-unique",
            "output-bounds",
            "output-concept",
            "output-type",
            "source-facts",
            "source-selector",
            "subject-selectors",
        ]
    );
}

fn assert_case(rule: &str, expected: &str, findings: &[Finding]) {
    let finding = first(findings);
    assert_eq!(
        finding.message, expected,
        "the `{rule}` rule changed the sentence it reports"
    );
    assert!(
        !finding.code.is_empty(),
        "the `{rule}` rule reports no code"
    );
}

fn first(findings: &[Finding]) -> &Finding {
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one finding, got: {findings:?}"
    );
    &findings[0]
}

#[test]
fn bounded_identifier_output_requires_exact_finite_constraints() {
    let mut project = normalized_project();
    let output = project
        .assertion_definitions
        .values_mut()
        .next()
        .unwrap()
        .outputs
        .values_mut()
        .next()
        .unwrap();
    output.value_type = "bounded-identifier".to_owned();
    output.prefix = Some("urn:example:report:".to_owned());
    output.minimum_bytes = Some(serde_json::from_value(json!(20)).unwrap());
    output.maximum_bytes = Some(serde_json::from_value(json!(64)).unwrap());
    assert!(project::validate_project(&project).is_empty());

    for mutate in [
        |output: &mut project::Output| output.values.push("A".to_owned()),
        |output: &mut project::Output| output.minimum_bytes = None,
        |output: &mut project::Output| output.maximum_bytes = None,
        |output: &mut project::Output| output.prefix = None,
    ] {
        let mut invalid = project.clone();
        mutate(
            invalid
                .assertion_definitions
                .values_mut()
                .next()
                .unwrap()
                .outputs
                .values_mut()
                .next()
                .unwrap(),
        );
        assert!(project::validate_project(&invalid)
            .iter()
            .any(|finding| finding.code == "output-bounds"));
    }
}

/// An object Output schema is the contract the output gate holds a derivation
/// to, so it may not permit properties it never declared. The findings name the
/// schema document's own fields, because the caller renders them beside
/// `schemas/<name>.yaml` rather than beside the question that referenced it.
#[test]
fn an_object_output_schema_must_close_the_properties_it_permits() {
    let closed = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"marker": {"type": "string"}}
    });
    assert_eq!(validate_output_schema_document(&closed), Vec::new());

    let open = json!({
        "type": "object",
        "properties": {"marker": {"type": "string"}}
    });
    let open_findings = validate_output_schema_document(&open);
    let finding = first(&open_findings);
    assert_eq!(finding.field.to_string(), ".additionalProperties");
    assert_eq!(finding.code, "evidence.output-schema.open-object");
    assert_eq!(
        finding.message,
        "an object Output schema must set additionalProperties: false"
    );

    // Only the boolean `false` closes the form; every other spelling, including
    // the schema dialect's own null, still permits an undeclared property.
    for additional in [
        json!(true),
        json!("false"),
        json!(null),
        json!({"not": "a boolean"}),
    ] {
        let document = json!({
            "type": "object",
            "additionalProperties": additional,
            "properties": {"marker": {"type": "string"}}
        });
        assert!(
            !validate_output_schema_document(&document).is_empty(),
            "{additional} closed an object Output schema"
        );
    }

    // A nullable object still answers with an object, so it closes the same way.
    let nullable = json!({
        "type": ["object", "null"],
        "properties": {"marker": {"type": "string"}}
    });
    assert!(
        !validate_output_schema_document(&nullable).is_empty(),
        "a nullable object Output schema escaped the closure rule"
    );

    let undeclared = json!({"type": "object", "additionalProperties": false});
    let undeclared_findings = validate_output_schema_document(&undeclared);
    let finding = first(&undeclared_findings);
    assert_eq!(finding.field.to_string(), ".properties");
    assert_eq!(finding.code, "evidence.output-schema.declared-properties");
    assert_eq!(
        finding.message,
        "an object Output schema must declare the properties it permits"
    );
    let non_object_properties = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": ["marker"]
    });
    assert!(
        !validate_output_schema_document(&non_object_properties).is_empty(),
        "a sequence of properties declared a property set"
    );
}

/// A schema that does not declare an object type permits no object property
/// set, so the closure rule has nothing to say about it.
#[test]
fn a_schema_that_declares_no_object_type_is_not_checked_for_closure() {
    for document in [
        json!({"type": "string"}),
        json!({"type": ["string", "null"]}),
        json!({"properties": {"marker": {"type": "string"}}}),
        json!({}),
    ] {
        assert_eq!(
            validate_output_schema_document(&document),
            Vec::new(),
            "a non-object schema was checked for object closure"
        );
    }
}

#[test]
fn normalized_subjects_are_closed_unique_and_reference_only() {
    let mut value = serde_json::to_value(normalized_project()).unwrap();
    value["assertionDefinitions"]["adult-status"]["subjects"][0]["selectors"] = json!([]);
    let empty: project::EvidenceProject = serde_json::from_value(value.clone()).unwrap();
    assert_normalized_finding(
        &project::validate_project(&empty),
        "subject-selectors",
        "/assertionDefinitions/adult-status/subjects/0",
        "declare distinct roles and existing selector profiles",
    );

    value["assertionDefinitions"]["adult-status"]["subjects"][0]["selectors"] =
        json!(["record-by-id", "record-by-id"]);
    assert!(serde_json::from_value::<project::EvidenceProject>(value.clone()).is_err());

    value["assertionDefinitions"]["adult-status"]["subjects"][0]["selectors"] =
        json!(["record-by-id"]);
    value["assertionDefinitions"]["adult-status"]["subjects"][0]["selector"] = json!("record-id");
    assert!(serde_json::from_value::<project::EvidenceProject>(value).is_err());
}

#[test]
fn the_normalized_reader_refuses_values_at_the_bounded_field() {
    project::read_project("evidence.yaml", NORMALIZED_PROJECT.as_bytes())
        .expect("the canonical project is accepted");
    for (from, to, code, path) in [
        (
            "id: standalone-evidence",
            "id: Standalone",
            "config.invalid-value",
            "/id",
        ),
        (
            "maximumAggregateBytes: 64",
            "maximumAggregateBytes: 0",
            "config.out-of-range",
            "/selectorProfiles/record-by-id/maximumAggregateBytes",
        ),
        (
            "validitySeconds: 300",
            "validitySeconds: 0",
            "config.out-of-range",
            "/assertionDefinitions/adult-status/validitySeconds",
        ),
    ] {
        let document = NORMALIZED_PROJECT.replacen(from, to, 1);
        let report = project::read_project("evidence.yaml", document.as_bytes())
            .expect_err("the reader refuses the value");
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(
            (diagnostic.code.as_str(), diagnostic.path.as_str()),
            (code, path)
        );
        assert!(diagnostic
            .source
            .as_ref()
            .is_some_and(|source| source.line.is_some()));
    }
}

#[test]
fn normalized_definition_diagnostics_keep_exact_messages_and_paths() {
    let findings = normalized_findings(|project| {
        project
            .assertion_definitions
            .values_mut()
            .next()
            .unwrap()
            .question
            .clear();
    });
    let finding = first(&findings);
    assert_eq!(finding.code, "definition-question");
    assert_eq!(finding.message, "write one bounded human-readable question");
    assert_eq!(
        finding.field.to_json_pointer(),
        "/assertionDefinitions/adult-status/question"
    );

    let findings = normalized_findings(|project| {
        project
            .assertion_definitions
            .values_mut()
            .next()
            .unwrap()
            .semantics
            .kind = "recommendation".to_owned();
    });
    let finding = first(&findings);
    assert_eq!(finding.code, "requirement-kind");
    assert_eq!(
        finding.message,
        "kind must be criterion, information-requirement or constraint"
    );
    assert_eq!(
        finding.field.to_json_pointer(),
        "/assertionDefinitions/adult-status/semantics/kind"
    );
}

#[test]
fn normalized_output_diagnostics_keep_type_and_constraint_sites_distinct() {
    let findings = normalized_findings(|project| {
        let output = project
            .assertion_definitions
            .values_mut()
            .next()
            .unwrap()
            .outputs
            .values_mut()
            .next()
            .unwrap();
        output.value_type = "free-text".to_owned();
    });
    assert!(findings.iter().any(|finding| {
        finding.code == "output-type"
            && finding.message == "declare a bounded Evidence output type"
            && finding.field.to_json_pointer()
                == "/assertionDefinitions/adult-status/outputs/adult/type"
    }));

    let findings = normalized_findings(|project| {
        project
            .assertion_definitions
            .values_mut()
            .next()
            .unwrap()
            .outputs
            .values_mut()
            .next()
            .unwrap()
            .concept = "not a URI".to_owned();
    });
    let finding = first(&findings);
    assert_eq!(finding.code, "output-concept");
    assert_eq!(finding.message, "an Output concept must be an absolute URI");
    assert_eq!(
        finding.field.to_json_pointer(),
        "/assertionDefinitions/adult-status/outputs/adult/concept"
    );
}

#[test]
fn normalized_references_distinguish_missing_assets_and_wrong_function_interfaces() {
    let findings = normalized_findings(|project| {
        project.functions.clear();
    });
    assert!(findings.iter().any(|finding| {
        finding.code == "function-interface"
            && finding.message == "extract must name a source-extract/v1 Function"
            && finding
                .field
                .to_json_pointer()
                .ends_with("/extract/function")
    }));
    assert!(findings.iter().any(|finding| {
        finding.code == "function-interface"
            && finding.message == "derive must name an assertion-derive/v1 Function"
            && finding
                .field
                .to_json_pointer()
                .ends_with("/derive/function")
    }));
}

#[test]
fn normalized_project_and_semantic_diagnostics_keep_exact_sites() {
    let findings = normalized_findings(|project| {
        project.functions.push(project.functions[0].clone());
    });
    assert_normalized_finding(
        &findings,
        "function-unique",
        "/functions",
        "function IDs must be unique",
    );

    let findings = normalized_findings(|project| project.assertion_definitions.clear());
    assert_normalized_finding(
        &findings,
        "definition-count",
        "/assertionDefinitions",
        "declare between one and 128 assertion definitions",
    );

    let findings = normalized_findings(|project| {
        project.functions[0].source = "../extract.rhai".to_owned();
    });
    assert_normalized_finding(
        &findings,
        "function-source",
        "/functions/0/source",
        "name one project-relative .rhai function asset without traversal",
    );

    let findings = normalized_findings(|project| {
        let requirement = project
            .assertion_definitions
            .values()
            .next()
            .unwrap()
            .semantics
            .requirement
            .clone();
        project
            .assertion_definitions
            .values_mut()
            .nth(1)
            .unwrap()
            .semantics
            .requirement = requirement;
    });
    assert!(findings.iter().any(|finding| {
        finding.code == "requirement-unique"
            && finding.message == "each definition must have a distinct Requirement URI"
            && finding
                .field
                .to_json_pointer()
                .ends_with("/semantics/requirement")
    }));

    let findings = normalized_findings(|project| {
        project
            .assertion_definitions
            .values_mut()
            .next()
            .unwrap()
            .semantics
            .evidence_type = "relative".to_owned();
    });
    assert_normalized_finding(
        &findings,
        "semantic-uri",
        "/assertionDefinitions/adult-status/semantics",
        "declare absolute Requirement, Evidence Type and reference-framework URIs",
    );

    let findings = normalized_findings(|project| {
        project
            .assertion_definitions
            .values_mut()
            .next()
            .unwrap()
            .grant_ceiling
            .authorities = Default::default();
    });
    assert_normalized_finding(
        &findings,
        "grant-ceiling-empty",
        "/assertionDefinitions/adult-status/grantCeiling",
        "declare complete, nonempty authority, actor, value-origin, audience and representation ceilings",
    );
}

#[test]
fn normalized_subject_and_acquisition_diagnostics_keep_exact_sites() {
    let findings = normalized_findings(|project| {
        project
            .assertion_definitions
            .values_mut()
            .next()
            .unwrap()
            .subjects
            .clear();
    });
    assert_normalized_finding(
        &findings,
        "subject-count",
        "/assertionDefinitions/adult-status/subjects",
        "declare between one and eight subject roles",
    );

    let findings = normalized_findings(|project| {
        let definition = project.assertion_definitions.values_mut().next().unwrap();
        definition.subjects.push(definition.subjects[0].clone());
    });
    assert_normalized_finding(
        &findings,
        "subject-selectors",
        "/assertionDefinitions/adult-status/subjects/1",
        "declare distinct roles and existing selector profiles",
    );

    let findings = normalized_findings(|project| {
        project.selector_profiles.clear();
    });
    assert!(findings.iter().any(|finding| {
        finding.code == "subject-selectors"
            && finding.message == "name an existing selector profile"
            && finding
                .field
                .to_json_pointer()
                .ends_with("/subjects/0/selectors/0")
    }));
    assert!(findings.iter().any(|finding| {
        finding.code == "source-selector"
            && finding.message == "name an existing selector profile"
            && finding
                .field
                .to_json_pointer()
                .ends_with("/selectors/0/profiles/0")
    }));

    let findings = normalized_findings(|project| {
        project.sources.clear();
    });
    assert!(findings.iter().any(|finding| {
        finding.code == "acquisition-source"
            && finding.message == "acquisition must name an existing Source"
            && finding
                .field
                .to_json_pointer()
                .ends_with("/acquisition/source")
    }));
}

#[test]
fn normalized_output_bounds_cover_each_retained_output_family() {
    for value_type in [
        "boolean",
        "controlled-category",
        "bounded-identifier",
        "bounded-integer",
        "reviewed-structured-value",
        "boolean-list",
    ] {
        let findings = normalized_findings(|project| {
            let output = project
                .assertion_definitions
                .values_mut()
                .next()
                .unwrap()
                .outputs
                .values_mut()
                .next()
                .unwrap();
            output.value_type = value_type.to_owned();
            match value_type {
                "boolean" => output.values.push("unexpected".to_owned()),
                "controlled-category" => output.values.clear(),
                "bounded-identifier" => output.prefix = Some("urn:example:".to_owned()),
                "bounded-integer" => output.minimum = Some(1),
                "reviewed-structured-value" => output.schema = Some("../shape.yaml".to_owned()),
                "boolean-list" => output.minimum_items = None,
                _ => unreachable!(),
            }
        });
        assert_normalized_finding(
            &findings,
            "output-bounds",
            "/assertionDefinitions/adult-status/outputs/adult",
            "declare exactly the finite bounds required by this Output type",
        );
    }
}

#[test]
fn normalized_source_diagnostics_keep_private_fact_and_interface_sites() {
    let findings = normalized_findings(|project| {
        project.sources.values_mut().next().unwrap().facts.clear();
    });
    assert_normalized_finding(
        &findings,
        "source-facts",
        "/sources/licence-record/facts",
        "declare the private fact schema",
    );

    let findings = normalized_findings(|project| {
        project.sources.values_mut().next().unwrap().connection = None;
    });
    assert_normalized_finding(
        &findings,
        "source-connection",
        "/sources/licence-record/connection",
        "an HTTP Source must name a target-bound connection",
    );

    let findings = normalized_findings(|project| {
        let source = project.sources.values_mut().next().unwrap();
        source.source_type = project::SourceType::SqliteExtract;
        source.extract_profile = None;
        source.maximum_extract_age_seconds = None;
    });
    assert_normalized_finding(
        &findings,
        "source-extract-binding",
        "/sources/licence-record",
        "a SQLite Source must name an extract profile and maximum age",
    );

    let findings = normalized_findings(|project| {
        project.sources.values_mut().next().unwrap().selectors[0].profiles = Default::default();
    });
    assert_normalized_finding(
        &findings,
        "source-selector",
        "/sources/licence-record/selectors/0/profiles",
        "Source selectors must name existing profiles",
    );
}

#[test]
fn named_function_abi_reports_compile_signature_and_interface_failures() {
    use registry_evidence_authoring::derivation::{validate_batch_function, validate_function};

    let compile = validate_function("fn derive(", project::FunctionInterface::AssertionDerive);
    assert_case(
        "Function compile",
        "Function does not compile as Rhai",
        &compile,
    );
    assert_eq!(first(&compile).code, "function-compile");

    let signature = validate_function(
        "fn derive(facts, selectors) { #{} }",
        project::FunctionInterface::AssertionDerive,
    );
    assert_case(
        "Function signature",
        "Function must expose exactly one entry point with its declared interface signature",
        &signature,
    );
    assert_eq!(first(&signature).code, "function-signature");

    let interface = validate_function(
        "fn derive(facts, selectors, context) { #{} } fn extract(response, context) { #{} }",
        project::FunctionInterface::AssertionDerive,
    );
    assert_case(
        "Function interface",
        "Function cannot expose another interface entry point",
        &interface,
    );
    assert_eq!(first(&interface).code, "function-interface");

    assert!(validate_function(
        "fn derive(facts, selectors, context) { #{} }",
        project::FunctionInterface::AssertionDerive,
    )
    .is_empty());
    assert!(validate_function(
        "fn extract(response, context) { #{} }",
        project::FunctionInterface::SourceExtract,
    )
    .is_empty());
    assert!(validate_function(
        "fn extract(response, selectors, context) { #{} }",
        project::FunctionInterface::SourceExtract,
    )
    .is_empty());

    let batch = validate_batch_function(
        "fn extract(response, selectors, context) { #{} }",
        project::FunctionInterface::SourceExtract,
    );
    assert_case(
        "batch Function signature",
        "source batch Functions must expose the two-argument source interface",
        &batch,
    );
    assert_eq!(first(&batch).code, "batch-function-signature");
}

#[test]
fn retired_question_answer_and_inline_operation_grammar_is_closed() {
    let retired = [
        serde_json::to_string(&base_question()).unwrap(),
        "apiVersion: id.registrystack.org/formats/evidence/question/v1alpha1\nkind: EvidenceQuestion\nid: old-question\nquestion: Old?\n".to_owned(),
        "apiVersion: id.registrystack.org/formats/evidence/project/v1alpha1\nkind: EvidenceProject\nid: old-project\nquestions: []\n".to_owned(),
        "apiVersion: id.registrystack.org/formats/evidence/project/v1alpha1\nkind: EvidenceProject\nid: old-project\naccessPolicies: []\n".to_owned(),
    ];
    for document in retired {
        assert!(
            project::read_project("evidence.yaml", document.as_bytes()).is_err(),
            "retired grammar was accepted: {document}"
        );
    }
}
