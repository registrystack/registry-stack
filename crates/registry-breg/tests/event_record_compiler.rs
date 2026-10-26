// SPDX-License-Identifier: Apache-2.0
//! Event record descriptors and display grouping compile onto the model
//! without touching any execution identity.

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_project_yaml, RegistryProject};
use registry_breg::diagnostics::DiagnosticSeverity;
use registry_breg::immediate_actions::migration_review_revision;
use registry_breg::CompiledRegistry;
use serde_json::{json, Value};

const SHAPES: &[u8] = include_bytes!("fixtures/event-record/shapes.yaml");

fn shapes_project() -> RegistryProject {
    parse_project_yaml(SHAPES).expect("the event record shapes fixture parses")
}

fn compile(project: &RegistryProject) -> CompiledRegistry {
    match compile_project(project, &[], CompileProfile::Authoring) {
        Ok(registry) => registry,
        Err(failure) => panic!("the project compiles: {:#?}", failure.diagnostics()),
    }
}

fn event_record_json(registry: &CompiledRegistry, record_type: &str) -> Value {
    serde_json::to_value(
        registry
            .entities()
            .get(record_type)
            .expect("the record type compiles")
            .event_record
            .as_ref(),
    )
    .expect("the descriptor serializes")
}

#[test]
fn three_event_record_shapes_and_an_ordinary_record_compile() {
    let registry = compile(&shapes_project());

    assert_eq!(
        event_record_json(&registry, "entry-registration"),
        json!({
            "descriptorVersion": 1,
            "label": "Entry registered",
            "subjects": [{"role": "entry", "label": "Entry", "kind": "native",
                "field": {"id": "entry", "apiName": "entry", "type": "reference", "target": "entry"}}],
            "summary": {"id": "summary", "apiName": "summary", "type": "text"},
            "occurredAt": {"type": "point",
                "at": {"id": "occurred-on", "apiName": "occurredOn", "type": "date"}},
            "effective": {"type": "point",
                "at": {"id": "effective-at", "apiName": "effectiveAt", "type": "timestamp"}},
            "sources": [{"role": "source", "label": "Source", "kind": "external",
                "namespace": "urn:example:synthetic:sources",
                "field": {"id": "source-reference", "apiName": "sourceReference", "type": "string"}}],
            "correction": {"relation": "corrects",
                "field": {"id": "corrects", "apiName": "corrects", "type": "reference",
                    "target": "entry-registration"}},
            "sourceEventId": {
                "field": {"id": "source-reference", "apiName": "sourceReference", "type": "string"},
                "namespace": "urn:example:synthetic:sources",
                "namespaceField": null,
                "duplicates": "reject",
                "constraint": "one-per-source"},
            "recordedTime": {"source": "creation-revision"}
        })
    );
    assert_eq!(
        event_record_json(&registry, "grant-pause-decision"),
        json!({
            "descriptorVersion": 1,
            "label": "Grant pause decided",
            "subjects": [{"role": "grant", "label": "Grant", "kind": "native",
                "field": {"id": "grant", "apiName": "grant", "type": "reference", "target": "grant"}}],
            "summary": {"id": "summary", "apiName": "summary", "type": "text"},
            "occurredAt": {"type": "point",
                "at": {"id": "decided-on", "apiName": "decidedOn", "type": "date"}},
            "effective": {"type": "interval", "meaning": "span",
                "start": {"id": "effective-from", "apiName": "effectiveFrom", "type": "date"},
                "end": {"id": "effective-until", "apiName": "effectiveUntil", "type": "date"}},
            "sources": [{"role": "basis", "label": "Basis", "kind": "external",
                "namespace": "urn:example:synthetic:notices",
                "field": {"id": "basis-reference", "apiName": "basisReference", "type": "string"}}],
            "correction": {"relation": "corrects",
                "field": {"id": "corrects", "apiName": "corrects", "type": "reference",
                    "target": "grant-pause-decision"}},
            "sourceEventId": null,
            "recordedTime": {"source": "creation-revision"}
        })
    );
    assert_eq!(
        event_record_json(&registry, "custody-handover"),
        json!({
            "descriptorVersion": 1,
            "label": "Custody handed over",
            "subjects": [
                {"role": "item", "label": "Item", "kind": "native",
                    "field": {"id": "item", "apiName": "item", "type": "reference", "target": "item"}},
                {"role": "previous-custody", "label": "Previous custody", "kind": "native",
                    "field": {"id": "previous-custody", "apiName": "previousCustody",
                        "type": "reference", "target": "custody-record"}},
                {"role": "new-custody", "label": "New custody", "kind": "native",
                    "field": {"id": "new-custody", "apiName": "newCustody",
                        "type": "reference", "target": "custody-record"}}
            ],
            "summary": null,
            "occurredAt": {"type": "interval", "meaning": "within",
                "start": {"id": "agreed-not-before", "apiName": "agreedNotBefore", "type": "date"},
                "end": {"id": "agreed-before", "apiName": "agreedBefore", "type": "date"}},
            "effective": {"type": "point",
                "at": {"id": "effective-at", "apiName": "effectiveAt", "type": "timestamp"}},
            "sources": [{"role": "deed", "label": "Deed", "kind": "external",
                "namespace": "urn:example:synthetic:deeds",
                "field": {"id": "deed-reference", "apiName": "deedReference", "type": "string"}}],
            "correction": null,
            "sourceEventId": {
                "field": {"id": "deed-reference", "apiName": "deedReference", "type": "string"},
                "namespace": "urn:example:synthetic:deeds",
                "namespaceField": null,
                "duplicates": "reject",
                "constraint": "one-per-deed"},
            "recordedTime": {"source": "creation-revision"}
        })
    );

    for ordinary in ["review-note", "entry", "grant", "item", "custody-record"] {
        assert!(
            registry.entities()[ordinary].event_record.is_none(),
            "{ordinary} declares no event record"
        );
    }
}

const CASES: &str = r#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project: {id: event-record-cases, version: "1", defaultLanguage: en, canonicalBaseIri: https://event-record-cases.example.test}
datasets: [{id: test-dataset}]
vocabularies:
  - {id: ns-vocab, values: [alpha, beta]}
recordTypes:
  - id: subject-record
    primaryDataset: test-dataset
    route: subject-records
    mutationMode: mutable
    classification: restricted
    fields:
      - {id: name, type: string, maximumLength: 40, classification: restricted}
  - id: plain
    primaryDataset: test-dataset
    route: plains
    mutationMode: mutable
    classification: restricted
    fields:
      - {id: name, type: string, maximumLength: 40, classification: restricted}
  - id: event
    primaryDataset: test-dataset
    route: events
    mutationMode: create-only
    classification: restricted
@@DISPLAY@@
    fields:
      - {id: ref-a, type: reference, target: subject-record, classification: restricted}
      - {id: ref-b, type: reference, target: subject-record, classification: restricted}
      - {id: to-plain, type: reference, target: plain, classification: restricted}
      - {id: to-self, type: reference, target: event, classification: restricted}
      - {id: ext-id, type: string, maximumLength: 80, classification: restricted}
      - {id: ext-uuid, type: uuid, classification: restricted}
      - {id: number, type: int64, classification: restricted}
      - {id: note, type: text, maximumLength: 200, classification: restricted}
      - {id: d1, type: date, classification: restricted}
      - {id: d2, type: date, classification: restricted}
      - {id: t1, type: timestamp, classification: restricted}
      - {id: t2, type: timestamp, classification: restricted}
      - {id: ns-code, type: vocabulary-code, vocabulary: ns-vocab, classification: restricted}
    constraints:
      - {id: u-ext, type: unique, fields: [ext-id]}
      - {id: u-ext-ns, type: unique, fields: [ext-id, ns-code]}
      - {id: u-ext-when, type: unique, fields: [ext-id], when: [{type: field-is-not-null, field: ext-id}]}
      - {id: u-uuid, type: unique, fields: [ext-uuid]}
      - {id: window, type: compare, left: d1, operator: less-than, right: d2}
@@EVENT_RECORD@@
"#;

/// An error diagnostic as (code, path, message).
type Diag = (String, String, String);

const SUBJECT: &str = "subjects: [{role: a, field: ref-a}]";

fn case_yaml(display: &str, event_record: &str) -> String {
    let display = if display.is_empty() {
        String::new()
    } else {
        format!("    display: {display}")
    };
    let event_record = if event_record.is_empty() {
        String::new()
    } else {
        format!("    eventRecord: {event_record}")
    };
    CASES
        .replace("@@DISPLAY@@", &display)
        .replace("@@EVENT_RECORD@@", &event_record)
}

/// The error diagnostics (code, path, message) of a case, from the parser or
/// the compiler, sorted for comparison.
fn case_errors(display: &str, event_record: &str) -> Vec<Diag> {
    let failure = match parse_project_yaml(case_yaml(display, event_record).as_bytes()) {
        Err(failure) => failure,
        Ok(project) => match compile_project(&project, &[], CompileProfile::Authoring) {
            Ok(_) => return Vec::new(),
            Err(failure) => failure,
        },
    };
    let mut errors = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .map(|diagnostic| {
            (
                diagnostic.code.clone(),
                diagnostic.path.clone(),
                diagnostic.message.clone(),
            )
        })
        .collect::<Vec<_>>();
    errors.sort();
    errors
}

fn error(code: &str, path: &str, message: &str) -> Diag {
    (
        code.to_owned(),
        format!("recordTypes[id=event].eventRecord{path}"),
        message.to_owned(),
    )
}

fn compiled_case(display: &str, event_record: &str) -> CompiledRegistry {
    let project = parse_project_yaml(case_yaml(display, event_record).as_bytes())
        .expect("the case project parses");
    compile(&project)
}

#[test]
fn invalid_mappings_fail_at_authored_paths() {
    let cases: Vec<(&str, String, Vec<Diag>)> = vec![
        (
            "subjects-empty",
            "{subjects: []}".to_owned(),
            vec![error(
                "breg.event-record.subjects-empty",
                ".subjects",
                "an event record declares at least one subject",
            )],
        ),
        (
            "role-invalid",
            "{subjects: [{role: Bad_Role, field: ref-a}]}".to_owned(),
            vec![error(
                "breg.event-record.role-invalid",
                ".subjects[0].role",
                "role \"Bad_Role\" must start with a lowercase letter and contain only lowercase letters, digits, hyphens and underscores, at most 64 characters",
            )],
        ),
        (
            "role-duplicate-across-subjects-and-sources",
            "{subjects: [{role: a, field: ref-a}], sources: [{role: a, field: ref-b}]}".to_owned(),
            vec![error(
                "breg.event-record.role-duplicate",
                ".sources[0].role",
                "role \"a\" is declared more than once in this event record",
            )],
        ),
        (
            "field-unknown",
            "{subjects: [{role: a, field: missing}]}".to_owned(),
            vec![error(
                "breg.event-record.field-unknown",
                ".subjects[role=a].field",
                "event record field \"missing\" names no stored field of record type \"event\"",
            )],
        ),
        (
            "field-unknown-in-time-bound",
            format!("{{{SUBJECT}, occurredAt: {{start: missing, end: d2, meaning: span}}}}"),
            vec![error(
                "breg.event-record.field-unknown",
                ".occurredAt.start",
                "event record field \"missing\" names no stored field of record type \"event\"",
            )],
        ),
        (
            "field-unknown-namespace-field",
            format!(
                "{{{SUBJECT}, sourceEventId: {{field: ext-id, namespaceField: missing, duplicates: allow}}}}"
            ),
            vec![error(
                "breg.event-record.field-unknown",
                ".sourceEventId.namespaceField",
                "event record field \"missing\" names no stored field of record type \"event\"",
            )],
        ),
        (
            "subject-field-type",
            "{subjects: [{role: a, field: ext-id}]}".to_owned(),
            vec![error(
                "breg.event-record.field-type",
                ".subjects[role=a].field",
                "subjects[role=a].field requires a reference field; field \"ext-id\" is string",
            )],
        ),
        (
            "external-source-field-type",
            format!("{{{SUBJECT}, sources: [{{role: s, field: ref-b, external: {{namespace: \"urn:example:ns\"}}}}]}}"),
            vec![error(
                "breg.event-record.field-type",
                ".sources[role=s].field",
                "sources[role=s].field requires a string or uuid field; field \"ref-b\" is reference",
            )],
        ),
        (
            "summary-field-type",
            format!("{{{SUBJECT}, summary: number}}"),
            vec![error(
                "breg.event-record.field-type",
                ".summary",
                "summary requires a string or text field; field \"number\" is int64",
            )],
        ),
        (
            "occurred-at-field-type",
            format!("{{{SUBJECT}, occurredAt: {{at: note}}}}"),
            vec![error(
                "breg.event-record.field-type",
                ".occurredAt.at",
                "occurredAt.at requires a date or timestamp field; field \"note\" is text",
            )],
        ),
        (
            "effective-end-field-type",
            format!("{{{SUBJECT}, effective: {{start: d1, end: number}}}}"),
            vec![error(
                "breg.event-record.field-type",
                ".effective.end",
                "effective.end requires a date or timestamp field; field \"number\" is int64",
            )],
        ),
        (
            "correction-field-type",
            format!("{{{SUBJECT}, correction: {{field: ext-id, relation: corrects}}}}"),
            vec![error(
                "breg.event-record.field-type",
                ".correction.field",
                "correction.field requires a reference field; field \"ext-id\" is string",
            )],
        ),
        (
            "source-event-field-type",
            format!(
                "{{{SUBJECT}, sourceEventId: {{field: number, namespace: \"urn:example:ns\", duplicates: allow}}}}"
            ),
            vec![error(
                "breg.event-record.field-type",
                ".sourceEventId.field",
                "sourceEventId.field requires a string or uuid field; field \"number\" is int64",
            )],
        ),
        (
            "source-event-namespace-field-type",
            format!(
                "{{{SUBJECT}, sourceEventId: {{field: ext-id, namespaceField: number, duplicates: allow}}}}"
            ),
            vec![error(
                "breg.event-record.field-type",
                ".sourceEventId.namespaceField",
                "sourceEventId.namespaceField requires a string or vocabulary-code field; field \"number\" is int64",
            )],
        ),
        (
            "field-reused-between-subjects",
            "{subjects: [{role: a, field: ref-a}, {role: b, field: ref-a}]}".to_owned(),
            vec![error(
                "breg.event-record.field-reused",
                ".subjects[role=b].field",
                "field \"ref-a\" is already mapped by subjects[role=a]",
            )],
        ),
        (
            "field-reused-by-summary",
            format!(
                "{{{SUBJECT}, sources: [{{role: s, field: ext-id, external: {{namespace: \"urn:example:ns\"}}}}], summary: ext-id}}"
            ),
            vec![error(
                "breg.event-record.field-reused",
                ".summary",
                "field \"ext-id\" is already mapped by sources[role=s]",
            )],
        ),
        (
            "field-reused-by-correction",
            "{subjects: [{role: a, field: to-self}], correction: {field: to-self, relation: corrects}}"
                .to_owned(),
            vec![error(
                "breg.event-record.field-reused",
                ".correction.field",
                "field \"to-self\" is already mapped by subjects[role=a]",
            )],
        ),
        (
            "reference-target",
            "{subjects: [{role: a, field: ref-a, target: plain}]}".to_owned(),
            vec![error(
                "breg.event-record.reference-target",
                ".subjects[role=a].target",
                "target \"plain\" does not match reference target \"subject-record\" of field \"ref-a\"",
            )],
        ),
        (
            "external-target",
            format!(
                "{{{SUBJECT}, sources: [{{role: s, field: ext-id, target: plain, external: {{namespace: \"urn:example:ns\"}}}}]}}"
            ),
            vec![error(
                "breg.event-record.external-target",
                ".sources[role=s].target",
                "an external reference has no native target",
            )],
        ),
        (
            "external-namespace-not-a-uri",
            format!(
                "{{{SUBJECT}, sources: [{{role: s, field: ext-id, external: {{namespace: \"not a uri\"}}}}]}}"
            ),
            vec![error(
                "breg.event-record.external-namespace",
                ".sources[role=s].external.namespace",
                "namespace must be an absolute URI of at most 512 bytes",
            )],
        ),
        (
            "external-namespace-too-long",
            format!(
                "{{{SUBJECT}, sources: [{{role: s, field: ext-id, external: {{namespace: \"urn:example:{}\"}}}}]}}",
                "a".repeat(600)
            ),
            vec![error(
                "breg.event-record.external-namespace",
                ".sources[role=s].external.namespace",
                "namespace must be an absolute URI of at most 512 bytes",
            )],
        ),
        (
            "source-event-namespace-not-a-uri",
            format!(
                "{{{SUBJECT}, sourceEventId: {{field: ext-id, namespace: \"not a uri\", duplicates: allow}}}}"
            ),
            vec![error(
                "breg.event-record.external-namespace",
                ".sourceEventId.namespace",
                "namespace must be an absolute URI of at most 512 bytes",
            )],
        ),
        (
            "occurred-at-both-at-and-start",
            format!("{{{SUBJECT}, occurredAt: {{at: d1, start: d2, meaning: span}}}}"),
            vec![error(
                "breg.event-record.time-shape",
                ".occurredAt",
                "declare either \"at\" or \"start\", not both",
            )],
        ),
        (
            "occurred-at-empty",
            format!("{{{SUBJECT}, occurredAt: {{}}}}"),
            vec![error(
                "breg.event-record.time-shape",
                ".occurredAt",
                "declare \"at\" or \"start\"",
            )],
        ),
        (
            "occurred-at-end-without-start",
            format!("{{{SUBJECT}, occurredAt: {{end: d2}}}}"),
            vec![error(
                "breg.event-record.time-shape",
                ".occurredAt",
                "\"end\" requires \"start\"",
            )],
        ),
        (
            "occurred-at-meaning-on-a-point",
            format!("{{{SUBJECT}, occurredAt: {{at: d1, meaning: span}}}}"),
            vec![error(
                "breg.event-record.time-shape",
                ".occurredAt",
                "\"meaning\" applies only to an interval",
            )],
        ),
        (
            "occurred-at-interval-without-meaning",
            format!("{{{SUBJECT}, occurredAt: {{start: d1, end: d2}}}}"),
            vec![error(
                "breg.event-record.time-shape",
                ".occurredAt",
                "an interval declares \"meaning\": span or within",
            )],
        ),
        (
            "occurred-at-within-without-end",
            format!("{{{SUBJECT}, occurredAt: {{start: d1, meaning: within}}}}"),
            vec![error(
                "breg.event-record.time-shape",
                ".occurredAt",
                "\"within\" requires \"end\"",
            )],
        ),
        (
            "effective-both-at-and-start",
            format!("{{{SUBJECT}, effective: {{at: d1, start: d2}}}}"),
            vec![error(
                "breg.event-record.time-shape",
                ".effective",
                "declare either \"at\" or \"start\", not both",
            )],
        ),
        (
            "effective-empty",
            format!("{{{SUBJECT}, effective: {{}}}}"),
            vec![error(
                "breg.event-record.time-shape",
                ".effective",
                "declare \"at\" or \"start\"",
            )],
        ),
        (
            "effective-end-without-start",
            format!("{{{SUBJECT}, effective: {{end: d2}}}}"),
            vec![error(
                "breg.event-record.time-shape",
                ".effective",
                "\"end\" requires \"start\"",
            )],
        ),
        (
            "occurred-at-interval-type-mismatch",
            format!("{{{SUBJECT}, occurredAt: {{start: d1, end: t1, meaning: span}}}}"),
            vec![error(
                "breg.event-record.interval-type-mismatch",
                ".occurredAt.end",
                "interval bounds must share one type; start is date, end is timestamp",
            )],
        ),
        (
            "effective-interval-type-mismatch",
            format!("{{{SUBJECT}, effective: {{start: t1, end: d1}}}}"),
            vec![error(
                "breg.event-record.interval-type-mismatch",
                ".effective.end",
                "interval bounds must share one type; start is timestamp, end is date",
            )],
        ),
        (
            "correction-target-declares-no-event-record",
            format!("{{{SUBJECT}, correction: {{field: to-plain, relation: corrects}}}}"),
            vec![error(
                "breg.event-record.correction-target",
                ".correction.field",
                "correction field \"to-plain\" targets record type \"plain\", which declares no event record",
            )],
        ),
        (
            "source-event-neither-namespace",
            format!("{{{SUBJECT}, sourceEventId: {{field: ext-id, duplicates: allow}}}}"),
            vec![error(
                "breg.event-record.source-event-namespace",
                ".sourceEventId",
                "declare exactly one of \"namespace\" or \"namespaceField\"",
            )],
        ),
        (
            "source-event-both-namespaces",
            format!(
                "{{{SUBJECT}, sourceEventId: {{field: ext-id, namespace: \"urn:example:ns\", namespaceField: ns-code, duplicates: allow}}}}"
            ),
            vec![error(
                "breg.event-record.source-event-namespace",
                ".sourceEventId",
                "declare exactly one of \"namespace\" or \"namespaceField\"",
            )],
        ),
        (
            "source-event-reject-without-constraint",
            format!(
                "{{{SUBJECT}, sourceEventId: {{field: ext-id, namespace: \"urn:example:ns\", duplicates: reject}}}}"
            ),
            vec![error(
                "breg.event-record.source-event-constraint",
                ".sourceEventId.constraint",
                "duplicates: reject requires \"constraint\"",
            )],
        ),
        (
            "source-event-allow-with-constraint",
            format!(
                "{{{SUBJECT}, sourceEventId: {{field: ext-id, namespace: \"urn:example:ns\", duplicates: allow, constraint: u-ext}}}}"
            ),
            vec![error(
                "breg.event-record.source-event-constraint",
                ".sourceEventId.constraint",
                "\"constraint\" applies only to duplicates: reject",
            )],
        ),
        (
            "source-event-constraint-is-not-unique",
            format!(
                "{{{SUBJECT}, sourceEventId: {{field: ext-id, namespace: \"urn:example:ns\", duplicates: reject, constraint: window}}}}"
            ),
            vec![error(
                "breg.event-record.source-event-constraint",
                ".sourceEventId.constraint",
                "constraint \"window\" is not a unique constraint of record type \"event\"",
            )],
        ),
        (
            "source-event-constraint-is-unknown",
            format!(
                "{{{SUBJECT}, sourceEventId: {{field: ext-id, namespace: \"urn:example:ns\", duplicates: reject, constraint: absent}}}}"
            ),
            vec![error(
                "breg.event-record.source-event-constraint",
                ".sourceEventId.constraint",
                "constraint \"absent\" is not a unique constraint of record type \"event\"",
            )],
        ),
        (
            "source-event-constraint-covers-another-field",
            format!(
                "{{{SUBJECT}, sourceEventId: {{field: ext-id, namespace: \"urn:example:ns\", duplicates: reject, constraint: u-uuid}}}}"
            ),
            vec![error(
                "breg.event-record.source-event-constraint",
                ".sourceEventId.constraint",
                "constraint \"u-uuid\" must cover exactly \"ext-id\" without \"when\"",
            )],
        ),
        (
            "source-event-constraint-has-when",
            format!(
                "{{{SUBJECT}, sourceEventId: {{field: ext-id, namespace: \"urn:example:ns\", duplicates: reject, constraint: u-ext-when}}}}"
            ),
            vec![error(
                "breg.event-record.source-event-constraint",
                ".sourceEventId.constraint",
                "constraint \"u-ext-when\" must cover exactly \"ext-id\" without \"when\"",
            )],
        ),
        (
            "source-event-constraint-omits-namespace-field",
            format!(
                "{{{SUBJECT}, sourceEventId: {{field: ext-id, namespaceField: ns-code, duplicates: reject, constraint: u-ext}}}}"
            ),
            vec![error(
                "breg.event-record.source-event-constraint",
                ".sourceEventId.constraint",
                "constraint \"u-ext\" must cover exactly \"ext-id\", \"ns-code\" without \"when\"",
            )],
        ),
    ];
    for (name, event_record, expected) in cases {
        let mut expected = expected;
        expected.sort();
        assert_eq!(case_errors("", &event_record), expected, "case {name}");
    }
}

#[test]
fn more_than_sixteen_subjects_are_refused_with_each_reuse_reported() {
    let subjects = (1..=17)
        .map(|n| format!("{{role: r{n}, field: ref-a}}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut expected = vec![error(
        "breg.event-record.roles-too-many",
        ".subjects",
        "an event record declares at most 16 subjects",
    )];
    expected.extend((2..=17).map(|n| {
        error(
            "breg.event-record.field-reused",
            &format!(".subjects[role=r{n}].field"),
            "field \"ref-a\" is already mapped by subjects[role=r1]",
        )
    }));
    expected.sort();
    assert_eq!(
        case_errors("", &format!("{{subjects: [{subjects}]}}")),
        expected
    );
}

#[test]
fn a_valid_event_record_with_every_member_family_compiles() {
    let registry = compiled_case(
        "",
        "{label: Event, subjects: [{role: a, field: ref-a, target: subject-record}, {role: b, field: ref-b}], \
         summary: note, occurredAt: {start: t1, end: t2, meaning: span}, effective: {start: d1}, \
         sources: [{role: s, field: ext-uuid, external: {namespace: \"urn:example:ns\"}}], \
         correction: {field: to-self, relation: supersedes}, \
         sourceEventId: {field: ext-id, namespaceField: ns-code, duplicates: reject, constraint: u-ext-ns}}",
    );
    let descriptor = event_record_json(&registry, "event");
    assert_eq!(descriptor["effective"]["type"], "interval");
    assert_eq!(descriptor["effective"]["end"], Value::Null);
    assert_eq!(descriptor["correction"]["relation"], "supersedes");
    assert_eq!(
        descriptor["sourceEventId"]["namespaceField"]["id"],
        "ns-code"
    );
    assert_eq!(descriptor["sourceEventId"]["namespace"], Value::Null);

    let allowing = compiled_case(
        "",
        &format!("{{{SUBJECT}, sourceEventId: {{field: ext-id, namespace: \"urn:example:ns\", duplicates: allow}}}}"),
    );
    let descriptor = event_record_json(&allowing, "event");
    assert_eq!(descriptor["sourceEventId"]["duplicates"], "allow");
    assert_eq!(descriptor["sourceEventId"]["constraint"], Value::Null);
}

fn display_error(code: &str, path: &str, message: &str) -> Diag {
    (code.to_owned(), path.to_owned(), message.to_owned())
}

#[test]
fn display_purpose_and_group_are_validated_on_records_and_actions_only() {
    // The shared parser reports unknown variants and members with its own codes.
    let errors = case_errors("{label: X, purpose: archival}", "");
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].0, "config.unknown-variant");
    assert_eq!(errors[0].1, "project.recordTypes[2].display.purpose");
    assert!(
        errors[0]
            .2
            .starts_with("expected one of `domain`, `processing`, `technical`, `synthetic-seed`"),
        "{errors:?}"
    );

    // A Record is never a synthetic seed.
    assert_eq!(
        case_errors("{label: X, purpose: synthetic-seed}", ""),
        vec![display_error(
            "breg.display.purpose-surface",
            "recordTypes[id=event].display.purpose",
            "purpose \"synthetic-seed\" applies only to Actions",
        )]
    );

    // Field displays keep the plain display shape.
    let yaml = String::from_utf8(SHAPES.to_vec()).unwrap().replace(
        "{id: entry-number, type: string, minimumLength: 1, maximumLength: 40, required: true, classification: restricted}",
        "{id: entry-number, type: string, minimumLength: 1, maximumLength: 40, required: true, classification: restricted, display: {label: Number, group: Register}}",
    );
    let failure = parse_project_yaml(yaml.as_bytes()).expect_err("a field display refuses group");
    let diagnostics = failure.diagnostics();
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(diagnostics[0].code, "config.unknown-key");
    assert_eq!(
        diagnostics[0].path,
        "project.recordTypes[0].fields[0].display.group"
    );

    // Absent members leave no grouping claim.
    let registry = compiled_case("{label: Event}", "");
    assert!(registry.entities()["event"].grouping.is_none());
    let registry = compiled_case("", "");
    assert!(registry.entities()["event"].grouping.is_none());
}

#[test]
fn grouping_compiles_onto_records_and_actions() {
    let registry = compile(&shapes_project());
    let grouping = |value: Option<&registry_breg::model::CompiledGrouping>| {
        serde_json::to_value(value).expect("grouping serializes")
    };
    assert_eq!(
        grouping(registry.entities()["entry"].grouping.as_ref()),
        json!({"purpose": "domain", "group": "Register"})
    );
    assert_eq!(
        grouping(registry.entities()["review-note"].grouping.as_ref()),
        json!({"purpose": "processing", "group": "Register"})
    );
    let actions = &registry.actions().actions;
    let action = |id: &str| {
        actions
            .iter()
            .find(|action| action.id == id)
            .unwrap_or_else(|| panic!("action {id} compiles"))
    };
    assert_eq!(
        grouping(action("seed-demonstration-entries").grouping.as_ref()),
        json!({"purpose": "synthetic-seed", "group": "Demonstration data"})
    );
    assert_eq!(
        grouping(action("record-grant-pause").grouping.as_ref()),
        json!({"purpose": "domain", "group": "Grants"})
    );
    // The compiled display keeps its own shape.
    let display = serde_json::to_value(&registry.entities()["entry"].display).unwrap();
    assert!(display.get("purpose").is_none() && display.get("group").is_none());
}

#[test]
fn directly_constructed_event_record_and_group_text_is_validated() {
    let unsafe_text = "reordered\u{202e}".to_owned();
    let mut project = shapes_project();
    let entry = project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "entry")
        .unwrap();
    entry.display.group = Some(unsafe_text.clone());
    let registration = project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "entry-registration")
        .unwrap();
    let event_record = registration.event_record.as_mut().unwrap();
    event_record.label = Some(unsafe_text.clone());
    event_record.subjects[0].label = Some(unsafe_text.clone());
    event_record.sources[0].label = Some(unsafe_text.clone());
    let action = project
        .actions
        .iter_mut()
        .find(|action| action.id == "record-grant-pause")
        .unwrap();
    action.display.group = Some(unsafe_text);

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("unsafe display text is refused");
    let mut paths = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.display-text.invalid")
        .map(|diagnostic| diagnostic.path.clone())
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            "actions[id=record-grant-pause].display.group",
            "recordTypes[id=entry-registration].eventRecord.label",
            "recordTypes[id=entry-registration].eventRecord.sources[role=source].label",
            "recordTypes[id=entry-registration].eventRecord.subjects[role=entry].label",
            "recordTypes[id=entry].display.group",
        ]
    );
}

#[test]
fn descriptor_and_grouping_leave_execution_identities_unchanged() {
    let declared = compile(&shapes_project());

    let mut stripped = shapes_project();
    for entity in &mut stripped.entities {
        entity.event_record = None;
        entity.display.purpose = None;
        entity.display.group = None;
    }
    for action in &mut stripped.actions {
        action.display.purpose = None;
        action.display.group = None;
    }
    let plain = compile(&stripped);

    assert!(plain
        .entities()
        .values()
        .all(|entity| entity.event_record.is_none()));
    assert!(plain
        .entities()
        .values()
        .all(|entity| entity.grouping.is_none()));
    assert!(plain
        .actions()
        .actions
        .iter()
        .all(|action| action.grouping.is_none()));

    for (id, entity) in declared.entities() {
        assert_eq!(
            entity.definition_revision,
            plain.entities()[id].definition_revision,
            "record type {id} definition revision"
        );
    }
    assert_eq!(
        declared.actions().actions.len(),
        plain.actions().actions.len()
    );
    let mut grants = 0;
    for (declared, plain) in declared
        .actions()
        .actions
        .iter()
        .zip(&plain.actions().actions)
    {
        assert_eq!(declared.id, plain.id);
        assert_eq!(
            declared.definition_revision, plain.definition_revision,
            "action {} definition revision",
            declared.id
        );
        assert_eq!(
            migration_review_revision(declared),
            migration_review_revision(plain),
            "action {} migration review revision",
            declared.id
        );
        if let registry_breg::model::CompiledActionExecution::Proposal { proposal } =
            &declared.execution
        {
            let registry_breg::model::CompiledActionExecution::Proposal { proposal: other } =
                &plain.execution
            else {
                panic!("execution mode is unchanged");
            };
            let grant = proposal
                .system_apply_grant
                .as_ref()
                .expect("automatic grant");
            let other_grant = other.system_apply_grant.as_ref().expect("automatic grant");
            assert_eq!(grant.revision, other_grant.revision, "grant revision");
            assert_eq!(grant.action_revision, other_grant.action_revision);
            grants += 1;
        }
    }
    assert_eq!(grants, 1, "the fixture covers one automatic Proposal grant");
    assert_eq!(
        serde_json::to_value(declared.ddl()).unwrap(),
        serde_json::to_value(plain.ddl()).unwrap(),
        "generated DDL"
    );
    assert_ne!(
        declared.revision(),
        plain.revision(),
        "the effective model carries the descriptor"
    );
}

#[test]
fn descriptor_does_not_change_temporal_roles() {
    let yaml = |event_record: &str| {
        format!(
            r#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project: {{id: event-record-temporal, version: "1", defaultLanguage: en, canonicalBaseIri: https://event-record-temporal.example.test}}
datasets: [{{id: test-dataset}}]
recordTypes:
  - id: subject-record
    primaryDataset: test-dataset
    route: subject-records
    mutationMode: mutable
    classification: restricted
    fields:
      - {{id: name, type: string, maximumLength: 40, classification: restricted}}
  - id: assignment
    primaryDataset: test-dataset
    route: assignments
    mutationMode: mutable
    classification: restricted
    temporal: {{startField: starts, endField: ends}}
    fields:
      - {{id: subject, type: reference, target: subject-record, classification: restricted}}
      - {{id: starts, type: date, required: true, classification: restricted}}
      - {{id: ends, type: date, classification: restricted}}
{event_record}
"#
        )
    };
    let mapped = compile(
        &parse_project_yaml(
            yaml("    eventRecord: {subjects: [{role: subject, field: subject}], effective: {start: starts, end: ends}}")
                .as_bytes(),
        )
        .unwrap(),
    );
    let unmapped = compile(&parse_project_yaml(yaml("").as_bytes()).unwrap());

    let mut mapped_entity = serde_json::to_value(&mapped.entities()["assignment"]).unwrap();
    assert!(mapped_entity["eventRecord"].is_object());
    mapped_entity.as_object_mut().unwrap().remove("eventRecord");
    assert_eq!(
        mapped_entity,
        serde_json::to_value(&unmapped.entities()["assignment"]).unwrap(),
        "the compiled record type differs only by its event record"
    );
    for (id, role) in [("starts", "valid-from"), ("ends", "valid-to")] {
        let field = mapped.entities()["assignment"]
            .stored_fields
            .iter()
            .find(|field| field.logical.id == id)
            .unwrap();
        assert_eq!(
            serde_json::to_value(field.valid_time_role).unwrap(),
            json!(role),
            "field {id}"
        );
    }
}

#[test]
fn unknown_event_record_members_and_variants_are_refused_by_the_parser() {
    let cases = [
        (
            "recordedAt is never authored",
            "{subjects: [{role: a, field: ref-a}], recordedAt: {at: d1}}",
            "config.unknown-key",
            "project.recordTypes[2].eventRecord.recordedAt",
        ),
        (
            "there is no event time member",
            "{subjects: [{role: a, field: ref-a}], event: {at: d1}}",
            "config.unknown-key",
            "project.recordTypes[2].eventRecord.event",
        ),
        (
            "effective has no meaning",
            "{subjects: [{role: a, field: ref-a}], effective: {at: d1, meaning: span}}",
            "config.unknown-key",
            "project.recordTypes[2].eventRecord.effective.meaning",
        ),
        (
            "unknown interval meaning",
            "{subjects: [{role: a, field: ref-a}], occurredAt: {start: d1, end: d2, meaning: around}}",
            "config.unknown-variant",
            "project.recordTypes[2].eventRecord.occurredAt.meaning",
        ),
        (
            "unknown correction relation",
            "{subjects: [{role: a, field: ref-a}], correction: {field: to-self, relation: replaces}}",
            "config.unknown-variant",
            "project.recordTypes[2].eventRecord.correction.relation",
        ),
        (
            "unknown duplicate policy",
            "{subjects: [{role: a, field: ref-a}], sourceEventId: {field: ext-id, namespace: \"urn:example:ns\", duplicates: maybe}}",
            "config.unknown-variant",
            "project.recordTypes[2].eventRecord.sourceEventId.duplicates",
        ),
        (
            "the duplicate policy is required",
            "{subjects: [{role: a, field: ref-a}], sourceEventId: {field: ext-id, namespace: \"urn:example:ns\"}}",
            "config.missing-key",
            "project.recordTypes[2].eventRecord.sourceEventId",
        ),
    ];
    for (name, event_record, code, path) in cases {
        let errors = case_errors("", event_record);
        assert_eq!(errors.len(), 1, "case {name}: {errors:?}");
        assert_eq!(
            (errors[0].0.as_str(), errors[0].1.as_str()),
            (code, path),
            "case {name}"
        );
    }
}
