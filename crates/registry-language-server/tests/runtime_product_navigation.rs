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

const BREG: &str = "apiVersion: registry.registrystack.org/v1alpha1\nkind: RegistryProject\nregistry: {id: example}\nmodules: [{id: <|module-use|>core}]\naccessProfiles:\n  - id: reader\n    permissions:\n      - entity: <|use|>person\n        readableFields: [<|field-use|>name]\n";
const BREG_MODULE: &str = "id: <|module|>core\nentities:\n  - id: <|definition|>person\n    fields: [{id: <|field|>name, type: string}]\n";
const CASEWORK: &str = "apiVersion: registry.registrystack.org/casework/v1alpha1\nkind: CaseworkProject\nqueues: [{id: <|definition|>triage}]\nsources:\n  - id: source\n    description: <|file-use|>sources/import.json\n    requests: [{queue: <|use|>triage}]\naccessProfiles: [{id: staff}]\nreviewKinds:\n  - id: decision\n    stages: [{id: review, queue: triage, decidingProfiles: [staff]}]\n";
const SCHEDULING: &str = "apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1\nkind: SchedulingProject\nservices: [{id: <|definition|>visit}]\nofferings: [{id: consultation, service: <|use|>visit, location: <|location-use|>office, exactTime: {pool: <|pool-use|>stations}}]\n";
const RECORDS: &str = "locations: [{id: <|location|>office}]\npools: [{id: <|pool|>stations}]\n";
const MESSAGING: &str = "apiVersion: registry.registrystack.org/messaging-package/v1alpha1\nkind: MessagingPackage\nproviders: [{id: <|definition|>smtp}]\nsenderProfiles: [{id: transactional, provider: <|use|>smtp}]\ntemplates: [{id: <|template|>notice, version: '1'}, {id: notice, version: '2'}]\naccessProfiles: [{id: staff, senderProfiles: [transactional], templates: [<|template-use|>notice]}]\n";

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
            Project::new(&[
                file("casework.yaml", CASEWORK),
                file("sources/import.json", "{\"fields\": []}"),
            ]),
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
        }
        if kind == ProductKind::Casework {
            assert_eq!(
                index.definitions_at(&path, project.cursor(document, "file-use"))[0].path,
                project.path("sources/import.json")
            );
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
        (ProductKind::Breg,"registry.yaml","products/breg/fixtures/asset-registration-actions/registry.yaml",vec![("modules/asset-registration-actions-core/module.yaml","products/breg/fixtures/asset-registration-actions/modules/asset-registration-actions-core/module.yaml")]),
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
        (
            ProductKind::Breg,
            "products/breg/acceptance",
            "registry.yaml",
        ),
        (ProductKind::Breg, "products/breg/examples", "registry.yaml"),
        (ProductKind::Breg, "products/breg/fixtures", "registry.yaml"),
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
    assert!(count >= 30, "maintained corpus coverage: {count}");
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
        file("registry.yaml","kind: RegistryProject\nmodules: [{id: core}, {id: extra}]\naccessProfiles: [{id: staff, permissions: [{action: register, results: [<|result|>created-record]}]}]\n"),
        file("modules/core/module.yaml","id: core\nentities:\n  - id: person\n    fields: [{id: <|field|>name, type: string}]\n    constraints: [{kind: unique, id: named-rule, fields: [<|constraint|>name]}]\nactions:\n  - id: register\n    effects: [{id: <|effect|>created-record}]\n    handler: {script: <|script|>scripts/action.rhai}\n"),
        file("modules/extra/module.yaml","id: extra\nactions: [{id: other, handler: {script: scripts/action.rhai}}]\n"),
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
    let maintained = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/access-review/task-profiles");
    assert!(ProjectIndex::load_product(&maintained, ProductKind::Breg)
        .unwrap()
        .diagnostics()
        .is_empty());
}

#[test]
fn casework_imported_fields_and_development_directory_resolve_locally() {
    let project=Project::new(&[
        file("casework.yaml","kind: CaseworkProject\nqueues: [{id: <|queue|>triage}]\naccessProfiles: [{id: <|profile|>staff}]\nreviewKinds: [{id: <|review|>decision}]\nsources:\n  - id: regional\n    description: imports/source-description.json\n    requests:\n      - entity: <|entity-use|>correction\n        queue: triage\n        projection: [<|field-use|>region]\n        routing: [{id: north, when: {fields: {<|routing|>region: {equals: north}}}, queue: triage}]\n"),
        file("imports/source-description.json","{\"sourceId\":\"regional\",\"request\":{\"requestEntity\":\"<|entity|>correction\",\"review\":{\"policyId\":\"<|review-use|>decision\"},\"fields\":[{\"field\":\"<|field|>region\"}]}}"),
        file("dev-clients.yaml","clients: [{id: <|client|>alice, accessProfile: <|profile-use|>staff}]\ndirectory: [{queue: <|queue-use|>triage, staff: [<|client-use|>alice], supervisors: [alice]}]\n"),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Casework).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    for (document, reference, target, definition) in [
        (
            "casework.yaml",
            "entity-use",
            "imports/source-description.json",
            "entity",
        ),
        (
            "casework.yaml",
            "field-use",
            "imports/source-description.json",
            "field",
        ),
        (
            "casework.yaml",
            "routing",
            "imports/source-description.json",
            "field",
        ),
        (
            "imports/source-description.json",
            "review-use",
            "casework.yaml",
            "review",
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
fn plural_casework_source_descriptions_resolve_each_owned_request() {
    let project=Project::new(&[
        file("casework.yaml","kind: CaseworkProject\nqueues: [{id: <|queue|>triage}]\naccessProfiles: [{id: <|profile|>staff}]\nreviewKinds: [{id: <|review|>decision}]\nsources:\n  - id: regional\n    description: imports/source-description.json\n    requests:\n      - entity: <|entity-use|>correction\n        queue: triage\n        projection: [<|field-use|>region]\n        routing: [{id: north, when: {fields: {<|routing|>region: {equals: north}}}, queue: triage}]\n"),
        file("imports/source-description.json","{\"sourceId\":\"regional\",\"requests\":[{\"requestEntity\":\"<|entity|>correction\",\"review\":{\"policyId\":\"<|review-use|>decision\"},\"fields\":[{\"field\":\"<|field|>region\"}]}]}"),
        file("dev-clients.yaml","clients: [{id: <|client|>alice, accessProfile: <|profile-use|>staff}]\ndirectory: [{queue: <|queue-use|>triage, staff: [<|client-use|>alice], supervisors: [alice]}]\n"),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Casework).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    for (document, reference, target, definition) in [
        (
            "casework.yaml",
            "entity-use",
            "imports/source-description.json",
            "entity",
        ),
        (
            "casework.yaml",
            "field-use",
            "imports/source-description.json",
            "field",
        ),
        (
            "casework.yaml",
            "routing",
            "imports/source-description.json",
            "field",
        ),
        (
            "imports/source-description.json",
            "review-use",
            "casework.yaml",
            "review",
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

// A source description is authored YAML or JSON. A description that names any other file, such
// as a signing key, must not make the server read it, even when its bytes parse as YAML.
#[test]
fn casework_source_descriptions_follow_only_authoring_documents() {
    const SOURCE: &str = "sourceId: regional\nrequest: {requestEntity: correction}\n";
    for (description, followed) in [
        ("keys/signing.key", false),
        ("keys/signing.pem", false),
        ("imports/source-description", false),
        ("imports/source-description.yaml", true),
        ("imports/source-description.yml", true),
        ("imports/source-description.json", true),
    ] {
        let project = Project::new(&[
            file(
                "casework.yaml",
                &format!(
                    "kind: CaseworkProject\n\
                     queues: [{{id: triage}}]\n\
                     sources:\n  \
                     - id: regional\n    \
                     description: {description}\n    \
                     requests: [{{entity: <|entity-use|>correction, queue: triage}}]\n"
                ),
            ),
            file(description, SOURCE),
        ]);
        let index = ProjectIndex::load_product(project.root(), ProductKind::Casework).unwrap();
        let definitions = index.definitions_at(
            &project.path("casework.yaml"),
            project.cursor("casework.yaml", "entity-use"),
        );
        assert_eq!(definitions.len(), usize::from(followed), "{description}");
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
        file("messaging.yaml","kind: MessagingPackage\nproviders: [{id: smtp}]\ntemplates: [{id: notice, version: '1'}]\n"),
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
            "kind: RegistryProject\nmodules: [{id: core}]\n",
        ),
        file(
            "modules/core/module.yaml",
            "id: core\ndependencies: [<|dependency|>extra]\n",
        ),
        file(
            "modules/extra/module.yaml",
            "id: <|definition|>extra\nentities: [{id: supplied}]\n",
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
