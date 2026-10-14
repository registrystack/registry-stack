#![allow(
    clippy::disallowed_macros,
    reason = "this test target embeds the public canonical fixtures; the library performs no I/O"
)]

use registry_evidence_authoring::{
    formats::{
        contains_environment_expression, envelope_lines, finding_code, read_authored,
        SUBSTITUTION_NOT_ALLOWED,
    },
    project::{self, PROJECT, PROJECT_API_VERSION, PROJECT_KIND},
    target::{
        AUTHORITY, AUTHORITY_API_VERSION, AUTHORITY_KIND, TARGET, TARGET_API_VERSION, TARGET_KIND,
    },
};
use registry_platform_yaml::Report;

const PROJECT_TEXT: &str =
    include_str!("../../../products/evidence/examples/standalone/evidence.yaml");
const TARGET_TEXT: &str =
    include_str!("../../../products/evidence/examples/standalone/local-target.yaml");
const AUTHORITY_TEXT: &str =
    include_str!("../../../products/evidence/examples/standalone/dev-authority.yaml");

fn codes(report: &Report) -> Vec<&str> {
    report
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
}

#[test]
fn the_normalized_project_reads_with_its_envelope() {
    let document = project::read_project("evidence.yaml", PROJECT_TEXT.as_bytes())
        .expect("the canonical project is valid");
    assert_eq!(document.document.envelope().kind, PROJECT_KIND);
    assert_eq!(
        document.document.envelope().api_version.as_deref(),
        Some(PROJECT_API_VERSION)
    );
}

#[test]
fn the_normalized_project_refuses_retired_parallel_members() {
    let report = project::read_project(
        "evidence.yaml",
        format!("{PROJECT_TEXT}questions: []\naccessPolicies: []\n").as_bytes(),
    )
    .expect_err("retired parallel documents are refused");
    assert_eq!(codes(&report), ["config.unknown-key", "config.unknown-key"]);
}

#[test]
fn a_retired_output_id_is_refused_at_the_normalized_output() {
    let text = PROJECT_TEXT.replacen(
        "        concept: urn:example:concept:adult-status:v1\n",
        "        concept: urn:example:concept:adult-status:v1\n        id: retired\n",
        1,
    );
    let report = project::read_project("evidence.yaml", text.as_bytes())
        .expect_err("the retired member is refused");
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.path.ends_with("/outputs/adult/id"))
        .expect("the retired member is addressed");
    assert_eq!(diagnostic.code, "config.unknown-key");
}

#[test]
fn normalized_documents_are_read_by_their_own_envelopes() {
    for (format, kind, api_version, text) in [
        (&PROJECT, PROJECT_KIND, PROJECT_API_VERSION, PROJECT_TEXT),
        (&TARGET, TARGET_KIND, TARGET_API_VERSION, TARGET_TEXT),
        (
            &AUTHORITY,
            AUTHORITY_KIND,
            AUTHORITY_API_VERSION,
            AUTHORITY_TEXT,
        ),
    ] {
        let decoded = read_authored("document.yaml", text.as_bytes(), format)
            .expect("a normalized file with its header is read");
        assert_eq!(decoded.envelope().kind, kind);
        assert_eq!(decoded.envelope().api_version.as_deref(), Some(api_version));

        let body = text.lines().skip(2).collect::<Vec<_>>().join("\n");
        let report = read_authored("document.yaml", body.as_bytes(), format)
            .expect_err("a file without its header is refused");
        assert_eq!(codes(&report), ["config.missing-envelope"]);
    }
}

#[test]
fn unknown_normalized_project_members_are_reported_at_their_keys() {
    let line = PROJECT_TEXT.lines().count();
    let text = format!("{PROJECT_TEXT}stray: \"MARKER\"\nx-note: \"MARKER\"\n");
    let report = project::read_project("evidence.yaml", text.as_bytes())
        .expect_err("members outside the closed shape are refused");
    let found: Vec<_> = report
        .diagnostics()
        .iter()
        .map(|diagnostic| {
            let source = diagnostic.source.as_ref().unwrap();
            (
                diagnostic.code.as_str(),
                diagnostic.path.as_str(),
                source.line,
                source.column,
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            ("config.unknown-key", "/stray", Some(line + 1), Some(1)),
            ("config.unknown-key", "/x-note", Some(line + 2), Some(1)),
        ]
    );
    assert!(!format!("{:?}", report.diagnostics()).contains("MARKER"));
}

#[test]
fn a_source_tagged_by_the_retired_transport_member_is_refused() {
    let text = PROJECT_TEXT.replacen("    type: http-json", "    transport: http-json", 1);
    let report = project::read_project("evidence.yaml", text.as_bytes())
        .expect_err("the retired source tag is refused");
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "config.unknown-key"
            && diagnostic.path == "/sources/person-record/transport"
    }));
}

#[test]
fn a_normalized_project_without_an_envelope_is_refused() {
    let body = PROJECT_TEXT.lines().skip(2).collect::<Vec<_>>().join("\n");
    let report = project::read_project("evidence.yaml", body.as_bytes())
        .expect_err("the envelope is required");
    assert!(codes(&report).contains(&"config.missing-envelope"));
}

#[test]
fn an_environment_expression_is_refused_in_an_authored_value_and_key() {
    let line = PROJECT_TEXT.lines().count() + 1;
    let text = format!("{PROJECT_TEXT}label: ${{HOME}}\n");
    let report = project::read_project("evidence.yaml", text.as_bytes())
        .expect_err("authored files are not expanded");
    let diagnostic = &report.diagnostics()[0];
    assert_eq!(diagnostic.code, SUBSTITUTION_NOT_ALLOWED);
    assert_eq!(diagnostic.path, "/label");
    assert!(!diagnostic.message.contains("HOME"));
    assert!(diagnostic.suggested_action.contains("not expanded"));
    let source = diagnostic.source.as_ref().expect("placed");
    assert_eq!((source.line, source.column), (Some(line), Some(8)));
}

#[test]
fn text_that_only_resembles_an_expression_is_left_alone() {
    assert!(!contains_environment_expression("costs ${ and more"));
    assert!(!contains_environment_expression("${1ABC}"));
    assert!(contains_environment_expression("prefix-${NAME:-fallback}"));
    assert!(contains_environment_expression("${_X}"));
}

#[test]
fn a_document_of_exactly_the_size_cap_is_read_and_one_byte_more_is_refused() {
    let cap = registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES;
    let mut text = envelope_lines(PROJECT_API_VERSION, PROJECT_KIND);
    while text.len() < cap {
        let room = cap - text.len();
        let line = if room > 81 { 80 } else { room - 1 };
        text.push('#');
        text.push_str(&" ".repeat(line.saturating_sub(1)));
        text.push('\n');
    }
    assert_eq!(text.len(), cap);
    read_authored("evidence.yaml", text.as_bytes(), &PROJECT)
        .expect("a file of exactly the cap is accepted");
    text.push('\n');
    let report = read_authored("evidence.yaml", text.as_bytes(), &PROJECT)
        .expect_err("one byte over the cap is refused");
    assert_eq!(codes(&report), ["yaml.too-large"]);
}

#[test]
fn finding_codes_name_their_area_once() {
    assert_eq!(
        finding_code("project", "project-question"),
        "evidence.project.question"
    );
    assert_eq!(
        finding_code("project", "output-concept"),
        "evidence.project.output-concept"
    );
    assert_eq!(
        finding_code("authority", "authority-definition"),
        "evidence.authority.definition"
    );
    assert_eq!(
        finding_code("function", "function-compile"),
        "evidence.function.compile"
    );
    assert_eq!(
        finding_code("schema", "evidence.output-schema.open-object"),
        "evidence.output-schema.open-object"
    );
}
