// SPDX-License-Identifier: Apache-2.0
//! Product authoring references through the shared index and real LSP session.
mod support;

use registry_language_server::{ProductKind, ProjectIndex};
use serde_json::json;
use std::{fs, path::PathBuf};
use support::{
    file,
    lsp::{uri, LspSession},
    EvidenceProject as Project,
};

const BREG: &str = "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject: {id: <|project|>example}\nmodules: [{id: <|module-use|>core}]\naccessProfiles:\n  - id: reader\n    permissions:\n      records:\n        - recordType: <|use|>person\n          readableFields: [<|field-use|>name]\n";
const BREG_MODULE: &str = "apiVersion: id.registrystack.org/formats/breg/module/v1alpha1\nkind: BRegModule\nid: <|module|>core\nrecordTypes:\n  - id: <|definition|>person\n    fields: [{id: <|field|>name, type: string}]\n";
const CASEWORK: &str = "apiVersion: id.registrystack.org/formats/casework/project/v1alpha1\nkind: CaseworkProject\nproject: {id: <|project|>intake, version: '1'}\nqueues: [{id: <|definition|>triage, label: Triage}]\naccessProfiles: [{id: staff, principalClaim: sub, requiredScopes: [casework:staff], role: staff}]\nreviewPolicies:\n  - id: decision\n    version: '1'\n    purpose: answer\n    context: {mode: submitted}\n    stages: [{id: review, queue: <|use|>triage, decidingProfiles: [staff], requiredApprovals: 1}]\n    retention: {terminalDays: 30, accountabilityDays: 90}\n    displaySchema: {type: object}\n";
const SCHEDULING: &str = "apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1\nkind: SchedulingProject\nservices: [{id: <|definition|>visit}]\nofferings: [{id: consultation, service: <|use|>visit, location: <|location-use|>office, exactTime: {pool: <|pool-use|>stations}}]\n";
const RECORDS: &str = "locations: [{id: <|location|>office}]\npools: [{id: <|pool|>stations}]\n";
const MESSAGING: &str = "apiVersion: id.registrystack.org/formats/messaging/project/v1alpha1\nkind: MessagingProject\nproviders: [{id: <|definition|>smtp}]\nsenderProfiles: [{id: transactional, provider: <|use|>smtp}]\ntemplates: [{id: <|template|>notice, version: '1'}, {id: notice, version: '2'}]\naccessProfiles: [{id: staff, senderProfiles: [transactional], templates: [<|template-use|>notice]}]\n";

fn projects() -> Vec<(ProductKind, &'static str, Project, &'static str)> {
    vec![
        (
            ProductKind::Breg,
            "registry.yaml",
            Project::new(&[
                file("registry.yaml", BREG),
                file("modules/core/module.yaml", BREG_MODULE),
            ]),
            "person",
        ),
        (
            ProductKind::Casework,
            "casework.yaml",
            Project::new(&[file("casework.yaml", CASEWORK)]),
            "triage",
        ),
        (
            ProductKind::Scheduling,
            "scheduling.yaml",
            Project::new(&[
                file("scheduling.yaml", SCHEDULING),
                file("records.yaml", RECORDS),
            ]),
            "visit",
        ),
        (
            ProductKind::Messaging,
            "messaging.yaml",
            Project::new(&[
                file("messaging.yaml", MESSAGING),
                file("templates/notice/1/template.yaml", "channel: email\n"),
                file("templates/notice/2/template.yaml", "channel: email\n"),
            ]),
            "smtp",
        ),
    ]
}

#[test]
fn runtime_products_resolve_scoped_names_files_and_completion_candidates() {
    for (kind, document, project, name) in projects() {
        let index = ProjectIndex::load_product(project.root(), kind).unwrap();
        assert!(
            index.diagnostics().is_empty(),
            "{kind:?}: {:?}",
            index.diagnostics()
        );
        let path = project.path(document);
        let position = project.cursor(document, "use");
        let definitions = index.definitions_at(&path, position);
        assert_eq!(definitions.len(), 1, "{kind:?}");
        let target = if kind == ProductKind::Breg {
            "modules/core/module.yaml"
        } else {
            document
        };
        assert_eq!(definitions[0].path, project.path(target));
        assert_eq!(
            definitions[0].range.start,
            project.cursor(target, "definition")
        );
        assert!(index.hover_at(&path, position).is_some());
        assert!(index
            .completions_at(&path, position)
            .iter()
            .any(|candidate| candidate.label == name));
        assert!(index
            .references_at(
                &project.path(target),
                project.cursor(target, "definition"),
                false
            )
            .iter()
            .any(|reference| reference.path == path && reference.range.start == position));
        assert!(!index.document_symbols(&path).is_empty());
        if kind == ProductKind::Breg {
            let target = index.definitions_at(&path, project.cursor(document, "field-use"));
            assert_eq!(
                target[0].range.start,
                project.cursor("modules/core/module.yaml", "field")
            );
            let target = index.definitions_at(&path, project.cursor(document, "module-use"));
            assert!(target.iter().any(|location| location.range.start
                == project.cursor("modules/core/module.yaml", "module")));
            assert!(index
                .document_symbols(&path)
                .iter()
                .any(|symbol| symbol.name == "example"
                    && symbol.location.range.start == project.cursor(document, "project")));
        }
        if kind == ProductKind::Casework {
            assert!(index
                .document_symbols(&path)
                .iter()
                .any(|symbol| symbol.name == "intake"
                    && symbol.location.range.start == project.cursor(document, "project")));
        }
        if kind == ProductKind::Scheduling {
            for (reference, definition) in [("location-use", "location"), ("pool-use", "pool")] {
                assert_eq!(
                    index.definitions_at(&path, project.cursor(document, reference))[0]
                        .range
                        .start,
                    project.cursor("records.yaml", definition)
                );
            }
        }
        if kind == ProductKind::Messaging {
            assert!(!index
                .definitions_at(&path, project.cursor(document, "template-use"))
                .is_empty());
            assert_eq!(
                index.definitions_at(&path, project.cursor(document, "template"))[0].path,
                project.path("templates/notice/1/template.yaml")
            );
        }
    }
}

#[test]
fn review_context_navigation_resolves_current_and_frozen_fields_to_their_record_type() {
    let project = Project::new(&[file(
        "registry.yaml",
        r#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project: {id: directory}
recordTypes:
  - id: <|record-definition|>person
    fields: [{id: <|field-definition|>name, type: string}]
  - id: other
    fields: [{id: secret, type: string}]
actions:
  - id: rename
    inputs: [{id: <|input-definition|>person, type: reference, target: person}]
    execution:
      mode: proposal
      proposal:
        reviewContext:
          id: rename-context
          fields:
            subject: {type: input, input: <|input-use|>person}
            current: {type: record, input: <|record-input-use|>person, field: <|current-field-use|>name}
            changes: {type: changes, recordType: <|record-use|>person, fields: [<|frozen-field-use|>name]}
"#,
    )]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Breg).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    let path = project.path("registry.yaml");
    for (reference, definition) in [
        ("input-use", "input-definition"),
        ("record-input-use", "input-definition"),
        ("record-use", "record-definition"),
        ("current-field-use", "field-definition"),
        ("frozen-field-use", "field-definition"),
    ] {
        let position = project.cursor("registry.yaml", reference);
        let definitions = index.definitions_at(&path, position);
        assert_eq!(definitions.len(), 1, "{reference}");
        assert_eq!(
            definitions[0].range.start,
            project.cursor("registry.yaml", definition),
            "{reference}"
        );
    }
    let completions =
        index.completions_at(&path, project.cursor("registry.yaml", "frozen-field-use"));
    assert!(completions
        .iter()
        .any(|candidate| candidate.label == "name"));
    assert!(!completions
        .iter()
        .any(|candidate| candidate.label == "secret"));
}

#[tokio::test]
async fn every_runtime_product_reports_unsaved_refs_through_the_real_protocol() {
    for (kind, document, project, name) in projects() {
        let mut session = LspSession::start();
        session.initialize(project.root()).await;
        let path = project.path(document);
        let source = fs::read_to_string(&path).unwrap();
        session.open(&path, &source, 1).await;
        let position = project.cursor(document, "use");
        let params = json!({"textDocument":{"uri":uri(&path)},"position":position});
        let definitions = session
            .request("textDocument/definition", params.clone())
            .await;
        assert_eq!(definitions.as_array().unwrap().len(), 1, "{kind:?}");
        let hover = session.request("textDocument/hover", params.clone()).await;
        assert!(hover["contents"]["value"].as_str().unwrap().contains(name));
        let candidates = session.request("textDocument/completion", params).await;
        assert!(candidates["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate["label"] == name));
        let offset = source
            .split_inclusive('\n')
            .take(position.line as usize)
            .map(str::len)
            .sum::<usize>()
            + position.character as usize;
        let mut edited = source.clone();
        edited.replace_range(offset..offset + name.len(), "unknown-editor-reference");
        session.notify("textDocument/didChange",json!({"textDocument":{"uri":uri(&path),"version":2},"contentChanges":[{"text":edited}]})).await;
        assert!(
            session
                .published_diagnostics(&path)
                .unwrap()
                .iter()
                .any(|diagnostic| diagnostic["message"]
                    .as_str()
                    .unwrap()
                    .contains("unknown-editor-reference")),
            "{kind:?}"
        );
        session.notify("textDocument/didChange",json!({"textDocument":{"uri":uri(&path),"version":3},"contentChanges":[{"text":source}]})).await;
        assert!(
            session.published_diagnostics(&path).unwrap().is_empty(),
            "{kind:?}"
        );
    }
}

fn fixture(path: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path),
    )
    .unwrap()
}

#[test]
fn maintained_runtime_product_examples_have_no_invented_missing_references() {
    for (kind,document,relative,extras) in [
        (ProductKind::Breg,"registry.yaml","products/breg/examples/facility/registry.yaml",vec![("plans/correct-address.rhai","products/breg/examples/facility/plans/correct-address.rhai")]),
        (ProductKind::Casework,"casework.yaml","products/casework/examples/standalone-decision/casework.yaml",vec![]),
        (ProductKind::Scheduling,"scheduling.yaml","products/scheduling/examples/standalone-exact-time/scheduling.yaml",vec![("records.yaml","products/scheduling/examples/standalone-exact-time/records.yaml"),("fixtures/counter-stations.yaml","products/scheduling/examples/standalone-exact-time/fixtures/counter-stations.yaml")]),

    ] {
        let source=fixture(relative);
        let extra_sources=extras.iter().map(|(path,source)|(*path,fixture(source))).collect::<Vec<_>>();
        let mut files=vec![file(document,&source)];
        files.extend(extra_sources.iter().map(|(path,source)|file(path,source)));
        let project=Project::new(&files);
        let index=ProjectIndex::load_product(project.root(),kind).unwrap();
        assert!(index.diagnostics().is_empty(),"{relative}: {:?}",index.diagnostics());
        assert!(!index.symbols().is_empty());
    }
}

#[test]
fn all_maintained_authoring_examples_resolve_supported_edges() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut failures = Vec::new();
    let mut count = 0;
    for (kind, base, marker) in [
        (ProductKind::Breg, "products/breg/examples", "registry.yaml"),
        (
            ProductKind::Casework,
            "products/casework/examples",
            "casework.yaml",
        ),
        (
            ProductKind::Scheduling,
            "products/scheduling/examples",
            "scheduling.yaml",
        ),
        (
            ProductKind::Messaging,
            "products/messaging/examples",
            "messaging.yaml",
        ),
    ] {
        for entry in fs::read_dir(root.join(base)).unwrap() {
            let path = entry.unwrap().path();
            if !path.join(marker).is_file() {
                continue;
            }
            count += 1;
            let index = ProjectIndex::load_product(&path, kind).unwrap();
            if !index.diagnostics().is_empty() {
                failures.push(format!(
                    "{}: {}",
                    path.display(),
                    index
                        .diagnostics()
                        .iter()
                        .map(|diagnostic| diagnostic.message.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
        }
    }
    assert!(count >= 9, "native maintained corpus coverage: {count}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn disappearing_module_keeps_unsaved_buffer_until_file_returns() {
    let project = Project::new(&[
        file("registry.yaml", BREG),
        file("modules/core/module.yaml", BREG_MODULE),
    ]);
    let root = project.path("registry.yaml");
    let module = project.path("modules/core/module.yaml");
    let source = fs::read_to_string(&module).unwrap();
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    session
        .open(&module, &source.replace("person", "unsaved-person"), 1)
        .await;
    fs::remove_file(&module).unwrap();
    session
        .notify(
            "workspace/didChangeWatchedFiles",
            json!({"changes":[{"uri":uri(&module),"type":3}]}),
        )
        .await;
    fs::write(&module, &source).unwrap();
    session
        .notify(
            "workspace/didChangeWatchedFiles",
            json!({"changes":[{"uri":uri(&module),"type":1}]}),
        )
        .await;
    let symbols = session
        .request("workspace/symbol", json!({"query":"unsaved-person"}))
        .await;
    assert!(
        symbols
            .as_array()
            .unwrap()
            .iter()
            .any(|symbol| symbol["name"] == "unsaved-person"),
        "{symbols}"
    );
    session
        .notify(
            "textDocument/didClose",
            json!({"textDocument":{"uri":uri(&module)}}),
        )
        .await;
    let original=session.request("textDocument/definition",json!({"textDocument":{"uri":uri(&root)},"position":project.cursor("registry.yaml","use")})).await;
    assert_eq!(original.as_array().unwrap().len(), 1);
}

#[test]
fn module_assets_named_constraints_and_action_results_keep_their_own_scope() {
    let project=Project::new(&[
        file("registry.yaml","apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject: {id: example}\nmodules: [{id: core}, {id: extra}]\naccessProfiles: [{id: staff, permissions: {actions: [{action: register, results: [<|result|>created-record]}]}}]\n"),
        file("modules/core/module.yaml","apiVersion: id.registrystack.org/formats/breg/module/v1alpha1\nkind: BRegModule\nid: core\nrecordTypes:\n  - id: person\n    fields: [{id: <|field|>name, type: string}]\n    constraints: [{type: unique, id: named-rule, fields: [<|constraint|>name]}]\nactions:\n  - id: register\n    inputs: []\n    execution: {mode: immediate}\n    plan: {type: fixed, effects: [{id: <|effect|>created-record}]}\nfunctions: [{id: core-plan, source: <|script|>scripts/action.rhai}]\n"),
        file("modules/extra/module.yaml","apiVersion: id.registrystack.org/formats/breg/module/v1alpha1\nkind: BRegModule\nid: extra\nfunctions: [{id: extra-plan, source: scripts/action.rhai}]\n"),
        file("modules/core/scripts/action.rhai","// core\n"),
        file("modules/extra/scripts/action.rhai","// extra\n"),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Breg).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    let module = project.path("modules/core/module.yaml");
    assert_eq!(
        index.definitions_at(
            &module,
            project.cursor("modules/core/module.yaml", "constraint")
        )[0]
        .range
        .start,
        project.cursor("modules/core/module.yaml", "field")
    );
    assert_eq!(
        index.definitions_at(
            &module,
            project.cursor("modules/core/module.yaml", "script")
        )[0]
        .path,
        project.path("modules/core/scripts/action.rhai")
    );
    assert_eq!(
        index.definitions_at(
            &project.path("registry.yaml"),
            project.cursor("registry.yaml", "result")
        )[0]
        .range
        .start,
        project.cursor("modules/core/module.yaml", "effect")
    );
    let maintained =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/examples/minimal");
    assert!(ProjectIndex::load_product(&maintained, ProductKind::Breg)
        .unwrap()
        .diagnostics()
        .is_empty());
}

#[test]
fn casework_current_policy_directory_and_fixture_relationships_resolve() {
    let casework = fixture("products/casework/examples/standalone-decision/casework.yaml")
        .replacen("  - id: staff", "  - id: <|profile|>staff", 1)
        .replacen("  - id: decisions", "  - id: <|queue|>decisions", 1)
        .replacen("  - id: decision", "  - id: <|policy|>decision", 1)
        .replacen("      - id: answer", "      - id: <|stage|>answer", 1)
        .replacen(
            "  - id: requester",
            "  - id: <|requester-profile|>requester",
            1,
        )
        .replacen(
            "      - id: confirmed",
            "      - id: <|outcome|>confirmed",
            1,
        )
        .replacen(
            "    profile: requester",
            "    profile: <|producer-profile|>requester",
            1,
        )
        .replacen(
            "    reviewPolicies: [decision]",
            "    reviewPolicies: [<|producer-policy|>decision]",
            1,
        );
    let clients = fixture("products/casework/examples/standalone-decision/dev-clients.yaml")
        .replacen(
            "    accessProfile: staff",
            "    accessProfile: <|profile-use|>staff",
            1,
        )
        .replacen(
            "    queue: decisions",
            "    queue: <|queue-use|>decisions",
            1,
        )
        .replacen("    staff: [staff]", "    staff: [<|client-use|>staff]", 1)
        .replacen("  - id: staff", "  - id: <|client|>staff", 1);
    let fixture_source =
        fixture("products/casework/examples/standalone-decision/fixtures/standalone-decision.yaml")
            .replacen("  policy: decision", "  policy: <|policy-use|>decision", 1)
            .replacen(
                "  queue: decisions",
                "  queue: <|fixture-queue|>decisions",
                1,
            )
            .replacen(
                "  outcomes: [confirmed, rejected]",
                "  outcomes: [<|outcome-use|>confirmed, rejected]",
                1,
            );
    let project = Project::new(&[
        file("casework.yaml", &casework),
        file("dev-clients.yaml", &clients),
        file("fixtures/standalone-decision.yaml", &fixture_source),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Casework).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    for (document, reference, target, definition) in [
        (
            "casework.yaml",
            "producer-profile",
            "casework.yaml",
            "requester-profile",
        ),
        (
            "casework.yaml",
            "producer-policy",
            "casework.yaml",
            "policy",
        ),
        (
            "fixtures/standalone-decision.yaml",
            "policy-use",
            "casework.yaml",
            "policy",
        ),
        (
            "fixtures/standalone-decision.yaml",
            "fixture-queue",
            "casework.yaml",
            "queue",
        ),
        (
            "fixtures/standalone-decision.yaml",
            "outcome-use",
            "casework.yaml",
            "outcome",
        ),
        (
            "dev-clients.yaml",
            "profile-use",
            "casework.yaml",
            "profile",
        ),
        ("dev-clients.yaml", "queue-use", "casework.yaml", "queue"),
        (
            "dev-clients.yaml",
            "client-use",
            "dev-clients.yaml",
            "client",
        ),
    ] {
        let definitions =
            index.definitions_at(&project.path(document), project.cursor(document, reference));
        assert_eq!(definitions.len(), 1, "{document} {reference}");
        assert_eq!(definitions[0].path, project.path(target));
        assert_eq!(
            definitions[0].range.start,
            project.cursor(target, definition)
        );
    }
}

#[test]
fn casework_read_only_context_provider_and_schema_files_resolve() {
    let casework = fixture("products/casework/examples/canonical-review/casework.yaml")
        .replacen(
            "  - id: facility-proposal-context",
            "  - id: <|provider|>facility-proposal-context",
            1,
        )
        .replacen(
            "    deploymentRef: facility-registry",
            "    deploymentRef: <|deployment|>facility-registry",
            1,
        )
        .replacen(
            "      provider: facility-proposal-context",
            "      provider: <|provider-use|>facility-proposal-context",
            1,
        )
        .replacen(
            "      $ref: schemas/correct-address.schema.json",
            "      $ref: <|schema-use|>schemas/correct-address.schema.json",
            1,
        );
    let runtime = fixture("products/casework/examples/canonical-review/runtime.example.yaml")
        .replacen(
            "  facility-registry:",
            "  <|deployment-use|>facility-registry:",
            1,
        );
    let schema =
        fixture("products/casework/examples/canonical-review/schemas/correct-address.schema.json");
    let project = Project::new(&[
        file("casework.yaml", &casework),
        file("runtime.example.yaml", &runtime),
        file("schemas/correct-address.schema.json", &schema),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Casework).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    for (document, reference, target, definition) in [
        ("casework.yaml", "provider-use", "casework.yaml", "provider"),
        (
            "runtime.example.yaml",
            "deployment-use",
            "casework.yaml",
            "deployment",
        ),
    ] {
        let definitions =
            index.definitions_at(&project.path(document), project.cursor(document, reference));
        assert_eq!(definitions.len(), 1, "{document} {reference}");
        assert_eq!(definitions[0].path, project.path(target));
        assert_eq!(
            definitions[0].range.start,
            project.cursor(target, definition)
        );
    }
    assert_eq!(
        index.definitions_at(
            &project.path("casework.yaml"),
            project.cursor("casework.yaml", "schema-use"),
        )[0]
        .path,
        project.path("schemas/correct-address.schema.json")
    );

    let missing_schema_project = Project::new(&[
        file("casework.yaml", &casework),
        file("runtime.example.yaml", &runtime),
    ]);
    let missing_schema_index =
        ProjectIndex::load_product(missing_schema_project.root(), ProductKind::Casework).unwrap();
    assert!(missing_schema_index.diagnostics().iter().any(|diagnostic| {
        diagnostic.path == missing_schema_project.path("casework.yaml")
            && diagnostic.range.start
                == missing_schema_project.cursor("casework.yaml", "schema-use")
    }));
}

#[test]
fn casework_routing_teams_clocks_and_holiday_sets_resolve() {
    let casework = fixture("products/casework/examples/multi-stage-routing-clocks/casework.yaml")
        .replacen("{id: staff,", "{id: <|profile|>staff,", 1)
        .replacen("{id: triage,", "{id: <|triage|>triage,", 1)
        .replacen(
            "{id: northern-review,",
            "{id: <|northern|>northern-review,",
            1,
        )
        .replacen("{id: overdue-review,", "{id: <|overdue|>overdue-review,", 1)
        .replacen("  - id: regional-team", "  - id: <|team|>regional-team", 1)
        .replacen("    serves: [triage,", "    serves: [<|serves|>triage,", 1)
        .replacen(
            "    memberProfiles: [staff]",
            "    memberProfiles: [<|member-profile|>staff]",
            1,
        )
        .replacen(
            "  - id: regional-review",
            "  - id: <|policy|>regional-review",
            1,
        )
        .replacen(
            "          stage: technical",
            "          stage: <|stage-use|>technical",
            1,
        )
        .replacen(
            "          fields: {region:",
            "          fields: {<|field-use|>region:",
            1,
        )
        .replacen(
            "        queue: northern-review",
            "        queue: <|route-queue|>northern-review",
            1,
        )
        .replacen("      - id: technical", "      - id: <|stage|>technical", 1)
        .replacen(
            "        queue: triage",
            "        queue: <|stage-queue|>triage",
            1,
        )
        .replacen(
            "        decidingProfiles: [staff]",
            "        decidingProfiles: [<|deciding-profile|>staff]",
            1,
        )
        .replacen(
            "    clocks: [review-deadline, response-budget]",
            "    clocks: [<|clock-use|>review-deadline, response-budget]",
            1,
        )
        .replacen(
            "      - {id: approved,",
            "      - {id: <|outcome|>approved,",
            1,
        )
        .replacen(
            "        region: {type: string,",
            "        <|field|>region: {type: string,",
            1,
        )
        .replacen("  - id: office", "  - id: <|calendar|>office", 1)
        .replacen(
            "    holidaySet: office-holidays",
            "    holidaySet: <|holiday-use|>office-holidays",
            1,
        )
        .replacen(
            "  - id: review-deadline",
            "  - id: <|clock|>review-deadline",
            1,
        )
        .replacen(
            "    calendar: office",
            "    calendar: <|calendar-use|>office",
            1,
        )
        .replacen(
            "        action: {reassign: {queue: overdue-review}}",
            "        action: {reassign: {queue: <|step-queue|>overdue-review}}",
            1,
        )
        .replacen(
            "    reviewPolicies: [regional-review]",
            "    reviewPolicies: [<|producer-policy|>regional-review]",
            1,
        );
    let fixture_source = fixture(
        "products/casework/examples/multi-stage-routing-clocks/fixtures/multi-stage-policy.yaml",
    )
    .replacen(
        "  policy: regional-review",
        "  policy: <|fixture-policy|>regional-review",
        1,
    )
    .replacen("  queue: triage", "  queue: <|fixture-queue|>triage", 1)
    .replacen(
        "  outcomes: [approved, rejected]",
        "  outcomes: [<|fixture-outcome|>approved, rejected]",
        1,
    );
    let holiday = fixture(
        "products/casework/examples/multi-stage-routing-clocks/holiday-sets/office-holidays-7.yaml",
    )
    .replacen(
        "holidaySet: office-holidays",
        "holidaySet: <|holiday|>office-holidays",
        1,
    );
    let project = Project::new(&[
        file("casework.yaml", &casework),
        file("fixtures/multi-stage-policy.yaml", &fixture_source),
        file("holiday-sets/office-holidays-7.yaml", &holiday),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Casework).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    for (document, reference, target, definition) in [
        ("casework.yaml", "serves", "casework.yaml", "triage"),
        (
            "casework.yaml",
            "member-profile",
            "casework.yaml",
            "profile",
        ),
        ("casework.yaml", "stage-use", "casework.yaml", "stage"),
        ("casework.yaml", "field-use", "casework.yaml", "field"),
        ("casework.yaml", "route-queue", "casework.yaml", "northern"),
        ("casework.yaml", "stage-queue", "casework.yaml", "triage"),
        (
            "casework.yaml",
            "deciding-profile",
            "casework.yaml",
            "profile",
        ),
        ("casework.yaml", "clock-use", "casework.yaml", "clock"),
        ("casework.yaml", "calendar-use", "casework.yaml", "calendar"),
        (
            "casework.yaml",
            "holiday-use",
            "holiday-sets/office-holidays-7.yaml",
            "holiday",
        ),
        ("casework.yaml", "step-queue", "casework.yaml", "overdue"),
        (
            "casework.yaml",
            "producer-policy",
            "casework.yaml",
            "policy",
        ),
        (
            "fixtures/multi-stage-policy.yaml",
            "fixture-policy",
            "casework.yaml",
            "policy",
        ),
        (
            "fixtures/multi-stage-policy.yaml",
            "fixture-queue",
            "casework.yaml",
            "triage",
        ),
        (
            "fixtures/multi-stage-policy.yaml",
            "fixture-outcome",
            "casework.yaml",
            "outcome",
        ),
    ] {
        let definitions =
            index.definitions_at(&project.path(document), project.cursor(document, reference));
        assert_eq!(definitions.len(), 1, "{document} {reference}");
        assert_eq!(definitions[0].path, project.path(target));
        assert_eq!(
            definitions[0].range.start,
            project.cursor(target, definition)
        );
    }
}

#[test]
fn casework_policy_scopes_and_task_template_references_stay_local() {
    let project = Project::new(&[
        file(
            "casework.yaml",
            "kind: CaseworkProject\n\
             queues: [{id: queue}]\n\
             accessProfiles: [{id: <|profile|>staff}]\n\
             teams: [{id: <|team|>reviewers}]\n\
             contextProviders:\n  \
               - id: provider\n    \
                 sourceNamespace: <|provider-namespace|>opaque-source\n    \
                 deploymentRef: deployment\n\
             reviewPolicies:\n  \
               - id: alpha\n    \
                 context: {mode: submitted}\n    \
                 stages: [{id: <|alpha-stage|>review, queue: queue, decidingProfiles: [staff]}]\n    \
                 outcomes: [{id: <|alpha-outcome|>approved}]\n  \
               - id: <|beta-policy|>beta\n    \
                 context: {mode: submitted}\n    \
                 routing: [{id: route, when: {stage: <|stage-use|>review}, queue: queue}]\n    \
                 stages: [{id: <|beta-stage|>review, queue: queue, decidingProfiles: [staff]}]\n    \
                 outcomes: [{id: <|beta-outcome|>approved}]\n\
             trustedProducers:\n  \
               - id: producer\n    \
                 sourceNamespaces: [<|producer-namespace|>opaque-source]\n    \
                 reviewPolicies: [beta]\n\
             taskTemplates:\n  \
               - id: task\n    \
                 eligibleTeams: [<|team-use|>reviewers]\n    \
                 eligibleProfiles: [<|profile-use|>staff]\n    \
                 source: <|template-namespace|>opaque-source\n    \
                 reviewPolicies: [<|template-policy|>beta]\n",
        ),
        file(
            "fixtures/scoped.yml",
            "kind: CaseworkFixture\nid: scoped\nreview: {policy: <|fixture-policy|>beta, display: {}}\nexpect: {outcomes: [<|fixture-outcome|>approved]}\n",
        ),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Casework).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    for (document, reference, definition) in [
        ("casework.yaml", "stage-use", "beta-stage"),
        ("casework.yaml", "team-use", "team"),
        ("casework.yaml", "profile-use", "profile"),
        ("casework.yaml", "template-policy", "beta-policy"),
        ("fixtures/scoped.yml", "fixture-policy", "beta-policy"),
        ("fixtures/scoped.yml", "fixture-outcome", "beta-outcome"),
    ] {
        let definitions =
            index.definitions_at(&project.path(document), project.cursor(document, reference));
        assert_eq!(definitions.len(), 1, "{document} {reference}");
        assert_eq!(
            definitions[0].range.start,
            project.cursor("casework.yaml", definition)
        );
    }
    for marker in [
        "provider-namespace",
        "producer-namespace",
        "template-namespace",
    ] {
        assert!(
            index
                .definitions_at(
                    &project.path("casework.yaml"),
                    project.cursor("casework.yaml", marker)
                )
                .is_empty(),
            "{marker} is an opaque source namespace"
        );
    }
}

#[test]
fn casework_current_bad_references_are_reported_at_the_written_values() {
    let project = Project::new(&[
        file(
            "casework.yaml",
            "kind: CaseworkProject\n\
             queues: [{id: queue}]\n\
             accessProfiles: [{id: staff}]\n\
             teams:\n  \
               - id: team\n    \
                 serves: [<|team-queue|>missing-queue]\n    \
                 memberProfiles: [<|team-profile|>missing-profile]\n\
             contextProviders:\n  \
               - id: provider\n    \
                 sourceNamespace: <|opaque-provider|>remote-source\n    \
                 deploymentRef: deployment\n\
             reviewPolicies:\n  \
               - id: policy\n    \
                 context: {mode: current-source, provider: <|provider|>missing-provider}\n    \
                 routing: [{id: route, when: {stage: <|stage|>missing-stage}, queue: <|route-queue|>missing-queue}]\n    \
                 stages: [{id: review, queue: <|stage-queue|>missing-queue, decidingProfiles: [<|stage-profile|>missing-profile]}]\n    \
                 clocks: [<|policy-clock|>missing-clock]\n    \
                 outcomes: [{id: outcome}]\n\
             trustedProducers:\n  \
               - id: producer\n    \
                 profile: <|producer-profile|>missing-profile\n    \
                 sourceNamespaces: [<|opaque-producer|>remote-source]\n    \
                 reviewPolicies: [<|producer-policy|>missing-policy]\n\
             calendars: [{id: calendar, holidaySet: <|holiday|>missing-holiday}]\n\
             clocks:\n  \
               - id: clock\n    \
                 type: activity\n    \
                 calendar: <|calendar|>missing-calendar\n    \
                 steps: [{action: {reassign: {queue: <|clock-queue|>missing-queue}}}]\n\
             taskTemplates:\n  \
               - id: task\n    \
                 eligibleTeams: [<|template-team|>missing-team]\n    \
                 eligibleProfiles: [<|template-profile|>missing-profile]\n    \
                 source: <|opaque-template|>remote-source\n    \
                 reviewPolicies: [<|template-policy|>missing-policy]\n",
        ),
        file(
            "runtime.yaml",
            "kind: CaseworkRuntimeConfig\ncontextProviders: {<|runtime-provider|>missing-deployment: {}}\n",
        ),
        file(
            "fixtures/bad.yaml",
            "kind: CaseworkFixture\nid: bad\nreview: {policy: <|fixture-policy|>missing-policy, display: {}}\nexpect: {queue: <|fixture-queue|>missing-queue, outcomes: [<|fixture-outcome|>missing-outcome]}\n",
        ),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Casework).unwrap();
    for (document, marker) in [
        ("casework.yaml", "team-queue"),
        ("casework.yaml", "team-profile"),
        ("casework.yaml", "provider"),
        ("casework.yaml", "stage"),
        ("casework.yaml", "route-queue"),
        ("casework.yaml", "stage-queue"),
        ("casework.yaml", "stage-profile"),
        ("casework.yaml", "policy-clock"),
        ("casework.yaml", "producer-profile"),
        ("casework.yaml", "producer-policy"),
        ("casework.yaml", "holiday"),
        ("casework.yaml", "calendar"),
        ("casework.yaml", "clock-queue"),
        ("casework.yaml", "template-team"),
        ("casework.yaml", "template-profile"),
        ("casework.yaml", "template-policy"),
        ("runtime.yaml", "runtime-provider"),
        ("fixtures/bad.yaml", "fixture-policy"),
        ("fixtures/bad.yaml", "fixture-queue"),
        ("fixtures/bad.yaml", "fixture-outcome"),
    ] {
        assert!(
            index.diagnostics().iter().any(|diagnostic| {
                diagnostic.path == project.path(document)
                    && diagnostic.range.start == project.cursor(document, marker)
            }),
            "missing diagnostic at {document} <|{marker}|>: {:?}",
            index.diagnostics()
        );
    }
    for marker in ["opaque-provider", "opaque-producer", "opaque-template"] {
        assert!(
            index.diagnostics().iter().all(|diagnostic| {
                diagnostic.range.start != project.cursor("casework.yaml", marker)
            }),
            "{marker} is an opaque source namespace"
        );
    }
}

#[test]
fn scheduling_reopen_and_messaging_bodies_use_owned_document_contracts() {
    let project=Project::new(&[
        file("scheduling.yaml","kind: SchedulingProject\n"),
        file("records.yaml","locations: [{id: office}, {id: other}]\nexceptions: [{id: <|closure|>closure, location: office}, {id: closure, location: other}, {id: reopening, location: office, reopens: <|reopens|>closure}]\n"),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Scheduling).unwrap();
    let records = project.path("records.yaml");
    let target = index.definitions_at(&records, project.cursor("records.yaml", "reopens"));
    assert_eq!(target.len(), 1);
    assert_eq!(
        target[0].range.start,
        project.cursor("records.yaml", "closure")
    );
    let project=Project::new(&[
        file("messaging.yaml","kind: MessagingProject\nproviders: [{id: smtp}]\ntemplates: [{id: notice, version: '1'}]\n"),
        file("templates/notice/1/template.yaml","channel: email\nlocales: [<|locale|>en]\nparts: [subject, <|part|>text]\n"),
        file("templates/notice/1/en/subject.j2","Notification\n"),
        file("templates/notice/1/en/text.j2","{{ message }}\n"),
        file("templates/notice/1/schema.json","{}"),
        file("providers/smtp/provider.yaml","prepareScript: <|script|>prepare.rhai\n"),
        file("providers/smtp/prepare.rhai","// provider\n"),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Messaging).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    for cursor in ["locale", "part"] {
        assert!(index
            .definitions_at(
                &project.path("templates/notice/1/template.yaml"),
                project.cursor("templates/notice/1/template.yaml", cursor)
            )
            .iter()
            .any(|location| location.path == project.path("templates/notice/1/en/text.j2")));
    }
    assert_eq!(
        index.definitions_at(
            &project.path("providers/smtp/provider.yaml"),
            project.cursor("providers/smtp/provider.yaml", "script")
        )[0]
        .path,
        project.path("providers/smtp/prepare.rhai")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn unreadable_module_removes_stale_symbols_and_recovers_open_text() {
    use std::os::unix::fs::PermissionsExt;
    let project = Project::new(&[
        file("registry.yaml", BREG),
        file("modules/core/module.yaml", BREG_MODULE),
    ]);
    let module = project.path("modules/core/module.yaml");
    let source = fs::read_to_string(&module).unwrap();
    let original = fs::metadata(&module).unwrap().permissions();
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    session
        .open(&module, &source.replace("person", "unsaved-person"), 1)
        .await;
    fs::set_permissions(&module, fs::Permissions::from_mode(0o0)).unwrap();
    // Privileged execution cannot model this permissions boundary.
    if fs::read_to_string(&module).is_ok() {
        fs::set_permissions(&module, original).unwrap();
        return;
    }
    session
        .notify(
            "workspace/didChangeWatchedFiles",
            json!({"changes":[{"uri":uri(&module),"type":2}]}),
        )
        .await;
    let symbols = session
        .request("workspace/symbol", json!({"query":"unsaved-person"}))
        .await;
    fs::set_permissions(&module, original).unwrap();
    assert!(symbols.as_array().unwrap().is_empty(), "{symbols}");
    // The author is told why the read failed, not only that it did.
    let diagnostics = session
        .published_diagnostics(&project.path("registry.yaml"))
        .expect("the entry document carries the read failure");
    let read_failure = diagnostics
        .iter()
        .find(|diagnostic| diagnostic["code"] == "breg/document-read")
        .expect("a document-read diagnostic");
    assert!(
        read_failure["message"]
            .as_str()
            .unwrap()
            .contains("Permission denied"),
        "{read_failure}"
    );
    session
        .notify(
            "workspace/didChangeWatchedFiles",
            json!({"changes":[{"uri":uri(&module),"type":2}]}),
        )
        .await;
    let symbols = session
        .request("workspace/symbol", json!({"query":"unsaved-person"}))
        .await;
    assert!(symbols
        .as_array()
        .unwrap()
        .iter()
        .any(|symbol| symbol["name"] == "unsaved-person"));
}

#[test]
fn authored_unlocked_modules_still_supply_dependency_symbols() {
    let project = Project::new(&[
        file(
            "registry.yaml",
            "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject: {id: example}\nmodules: [{id: core}]\n",
        ),
        file(
            "modules/core/module.yaml",
            "apiVersion: id.registrystack.org/formats/breg/module/v1alpha1\nkind: BRegModule\nid: core\ndependencies: [<|dependency|>extra]\n",
        ),
        file(
            "modules/extra/module.yaml",
            "apiVersion: id.registrystack.org/formats/breg/module/v1alpha1\nkind: BRegModule\nid: <|definition|>extra\nrecordTypes: [{id: supplied}]\n",
        ),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Breg).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    let targets = index.definitions_at(
        &project.path("modules/core/module.yaml"),
        project.cursor("modules/core/module.yaml", "dependency"),
    );
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0].range.start,
        project.cursor("modules/extra/module.yaml", "definition")
    );
}
