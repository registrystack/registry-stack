use super::resolution::{RESOLUTION_API_VERSION, RESOLUTION_KIND};
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt as _};

struct Fixture {
    root: tempfile::TempDir,
    project: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        put(
            &project,
            "evidence.yaml",
            r#"apiVersion: id.registrystack.org/formats/evidence/project/v1alpha1
kind: EvidenceProject
id: import-test
selectorProfiles:
  other-reference:
    maximumAggregateBytes: 64
    fields: {value: {type: string, minimumBytes: 1, maximumBytes: 64}}
functions:
- id: other-derive
  interface: assertion-derive/v1
  source: functions/other-derive.rhai
sources:
  other:
    pack: {id: other-pack, version: "1"}
    route: lookup
    connection: other
    acquisitionPosture: record-transformed
    inputs:
      value: {selector: {role: subject, profile: other-reference, field: value}}
# This authored boundary comment is outside the collections source import owns.
assertionDefinitions:
  other:
    question: Is the other synthetic record matched?
    semantics: {requirement: "urn:example:requirement:other", kind: criterion, evidenceType: "urn:example:evidence:other", referenceFrameworks: ["urn:example:framework:test"]}
    purpose: test
    grantCeiling: {authorities: [organizational], actorKinds: [service], valueOrigins: [request], audiences: ["urn:example:audience:test"]}
    subjects: [{role: subject, selectors: [other-reference]}]
    acquisition: {source: other}
    derive: {function: other-derive}
    outputs: {matched: {concept: "urn:example:concept:matched", type: boolean}}
    validitySeconds: 60
    subjectBinding: audience-scoped
    representations: [signed-jws]
"#,
        );
        put(
            &project,
            "functions/other-derive.rhai",
            "fn derive(facts, selectors, context) { [#{output: \"matched\", value: facts[\"matched\"]}] }\n",
        );
        let inputs = serde_json::to_string_pretty(&json!({
            "type":"object","additionalProperties":false,"required":["value"],
            "properties":{"value":{"type":"string","minLength":1,"maxLength":64}}
        }))
        .unwrap();
        let facts = serde_json::to_string_pretty(&json!({
            "type":"object","additionalProperties":false,"required":["matched"],
            "properties":{"matched":{"type":"boolean"}}
        }))
        .unwrap();
        put(
            &project,
            "adapter-packs/other-pack/schemas/inputs.json",
            &inputs,
        );
        put(
            &project,
            "adapter-packs/other-pack/schemas/facts.json",
            &facts,
        );
        put(
            &project,
            "adapter-packs/other-pack/pack.yaml",
            &serde_json::to_string_pretty(&json!({
                "apiVersion":"id.registrystack.org/formats/adapter/pack/v1alpha1",
                "kind":"AdapterPack","id":"other-pack","version":"1",
                "testedVersions":["test"],
                "sourceRoutes":[{"id":"lookup","evidence":{
                    "inputsSchema":{"path":"schemas/inputs.json","digest":format!("sha256:{}",digest(inputs.as_bytes()))},
                    "factsSchema":{"path":"schemas/facts.json","digest":format!("sha256:{}",digest(facts.as_bytes()))}
                },"steps":[{"setBody":{"constant":{"lookup":"matched","facts":{"matched":true}}}}]}],
                "capabilities":{"languages":["constant"],"eips":["setBody"]}
            }))
            .unwrap(),
        );
        Self { root, project }
    }

    fn export(
        &self,
        directory: &str,
        id: &str,
        revision: &str,
        artifacts: &[(&str, &str)],
    ) -> PathBuf {
        let root = self.root.path().join(directory);
        fs::create_dir_all(&root).unwrap();
        let source_path = format!("sources/{id}.yaml");
        let source_revision = artifacts
            .iter()
            .find_map(|(path, text)| (*path == source_path).then_some(*text))
            .unwrap_or("synthetic source");
        let extract = artifacts
            .iter()
            .find(|(path, _)| *path == format!("adapter-packs/{id}/scripts/lookup.rhai"))
            .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
            .unwrap_or_else(|| {
                (
                    format!("adapters/{id}.rhai"),
                    "fn lookup(exchange) { #{lookup: \"matched\", facts: #{matched: true}} }\n"
                        .to_owned(),
                )
            });
        let selector_id = artifacts
            .iter()
            .find_map(|(path, _)| {
                path.strip_prefix("selectors/")
                    .and_then(|name| name.strip_suffix(".yaml"))
            })
            .unwrap_or("imported-reference");
        let selector_path = format!("selectors/{selector_id}.yaml");
        let selector_revision = artifacts
            .iter()
            .find_map(|(path, text)| path.starts_with("selectors/").then_some(*text))
            .unwrap_or("synthetic selector");
        let version = format!("sha256:{}", digest(source_revision.as_bytes()));
        let input_name = "value";
        let source = format!(
            "apiVersion: id.registrystack.org/formats/evidence/source/v1alpha1\nkind: EvidenceSource\npack: {{id: {id}, version: {version:?}}}\nroute: lookup\nconnection: {id}\ninputs:\n  {input_name}: {{selector: {{role: subject, profile: {selector_id}, field: value}}}}\nacquisitionPosture: record-transformed\n"
        );
        let script_path = format!("adapter-packs/{id}/scripts/lookup.rhai");
        let script = extract.1;
        let inputs_path = format!("adapter-packs/{id}/schemas/inputs.json");
        let inputs = serde_json::to_string_pretty(&json!({
            "type":"object","additionalProperties":false,"required":[input_name],
            "properties":{input_name:{"type":"string","minLength":1,"maxLength":64}}
        }))
        .unwrap();
        let facts_path = format!("adapter-packs/{id}/schemas/facts.json");
        let facts = serde_json::to_string_pretty(&json!({
            "type":"object","additionalProperties":false,"required":["matched"],
            "properties":{"matched":{"type":"boolean"}}
        }))
        .unwrap();
        let pack_path = format!("adapter-packs/{id}/pack.yaml");
        let mut scripts = vec![json!({
            "path":"scripts/lookup.rhai",
            "digest":format!("sha256:{}",digest(script.as_bytes()))
        })];
        for (path, text) in artifacts.iter().filter(|(path, _)| {
            path.starts_with(&format!("adapter-packs/{id}/scripts/"))
                && *path != format!("adapter-packs/{id}/scripts/lookup.rhai")
        }) {
            scripts.push(json!({
                "path":path.strip_prefix(&format!("adapter-packs/{id}/")).unwrap(),
                "digest":format!("sha256:{}",digest(text.as_bytes()))
            }));
        }
        let pack = serde_json::to_string_pretty(&json!({
            "apiVersion":"id.registrystack.org/formats/adapter/pack/v1alpha1",
            "kind":"AdapterPack","id":id,"version":version,"testedVersions":["test"],
            "sourceRoutes":[{"id":"lookup","evidence":{
                "inputsSchema":{"path":"schemas/inputs.json","digest":format!("sha256:{}",digest(inputs.as_bytes()))},
                "factsSchema":{"path":"schemas/facts.json","digest":format!("sha256:{}",digest(facts.as_bytes()))}
            },"steps":[{"setBody":{"rhai":{"file":"scripts/lookup.rhai","entrypoint":"lookup"}}}]}],
            "scripts":scripts,
            "capabilities":{"languages":["rhai"],"eips":["setBody"]}
        }))
        .unwrap();
        let mut materialized = BTreeMap::from([
            (source_path, source),
            (script_path, script),
            (inputs_path, inputs),
            (facts_path, facts),
            (pack_path, pack),
            (
                selector_path,
                format!(
                    "apiVersion: id.registrystack.org/formats/evidence/selector/v1alpha1\nkind: EvidenceSelector\nmaximumAggregateBytes: 64\nfields: {{value: {{type: string, minimumBytes: 1, maximumBytes: 64, description: {}}}}}\n",
                    digest(selector_revision.as_bytes())
                ),
            ),
        ]);
        for (path, text) in artifacts {
            if path.starts_with("adapter-packs/") {
                materialized.insert((*path).to_owned(), (*text).to_owned());
            }
        }
        let mut entries = Vec::new();
        for (path, text) in materialized {
            put(&root, &path, &text);
            entries.push(ExportArtifact {
                path,
                sha256: digest(text.as_bytes()),
            });
        }
        let manifest = ExportManifest {
            source_id: id.to_owned(),
            provenance: BTreeMap::from([
                ("producer".to_owned(), "source-contract-test".to_owned()),
                ("revision".to_owned(), revision.to_owned()),
            ]),
            artifacts: entries,
        };
        fs::write(root.join(MANIFEST_FILE), export_document(&manifest)).unwrap();
        root
    }
}

/// `manifest` as an export writes it: the header, then a `digest` for each
/// artifact.
fn export_document(manifest: &ExportManifest) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "apiVersion": EXPORT_API_VERSION,
        "kind": EXPORT_KIND,
        "sourceId": manifest.source_id,
        "provenance": manifest.provenance,
        "artifacts": manifest
            .artifacts
            .iter()
            .map(|artifact| serde_json::json!({
                "path": artifact.path,
                "digest": format!("sha256:{}", artifact.sha256),
            }))
            .collect::<Vec<_>>(),
    }))
    .unwrap()
}

fn put(root: &Path, path: &str, text: &str) {
    fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
    fs::write(root.join(path), text).unwrap();
}

fn replace_export_artifact(root: &Path, path: &str, text: &str) {
    put(root, path, text);
    let manifest_path = root.join(MANIFEST_FILE);
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let artifact = manifest["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|artifact| artifact["path"] == path)
        .unwrap();
    artifact["digest"] = Value::String(format!("sha256:{}", digest(text.as_bytes())));
    fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
}

fn accepted(
    lock: &ProjectLock,
    exports: &[PathBuf],
    resolutions: BTreeMap<String, Resolution>,
) -> bool {
    let mut candidate = prepare(lock, exports, &resolutions).unwrap();
    // Unit tests exercise update mechanics. CLI integration supplies the real
    // authoring/compiler validation callback rather than this narrow fixture.
    candidate.validate(|_| Ok(())).unwrap();
    let no_op = candidate.report().no_op;
    candidate.apply(lock).unwrap();
    no_op
}

#[test]
fn canonical_block_project_imports_and_preserves_unowned_authored_text() {
    let fixture = Fixture::new();
    let before = fs::read_to_string(fixture.project.join("evidence.yaml")).unwrap();
    let unowned = before.split_once("assertionDefinitions:").unwrap().1;
    let export = fixture.export("export", "lookup", "v1", &[]);
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let mut candidate = prepare(&lock, &[export], &BTreeMap::new()).unwrap();
    let candidate_text = fs::read_to_string(candidate.project().join("evidence.yaml")).unwrap();
    assert_eq!(
        candidate_text
            .split_once("assertionDefinitions:")
            .unwrap()
            .1,
        unowned
    );
    assert!(candidate_text.contains(
        "# This authored boundary comment is outside the collections source import owns."
    ));
    let decoded = registry_evidence_authoring::project::read_project(
        "evidence.yaml",
        candidate_text.as_bytes(),
    )
    .unwrap();
    let imported = decoded
        .value
        .sources
        .iter()
        .find_map(|(id, source)| (id.as_str() == "lookup").then_some(source))
        .unwrap();
    assert_eq!(imported.pack.id.as_str(), "lookup");
    assert_eq!(imported.route.as_str(), "lookup");
    assert!(candidate
        .project()
        .join("adapter-packs/lookup/pack.yaml")
        .is_file());
    assert!(!decoded
        .value
        .functions
        .iter()
        .any(|function| function.id.as_str().starts_with("lookup-")));
    let (project, scripts) = crate::normalized::read(candidate.project()).unwrap();
    let pack_routes = crate::normalized::read_pack_routes(candidate.project(), &project).unwrap();
    registry_evidence_authoring::compile::compile_with_pack_routes(
        &project,
        &scripts,
        &pack_routes,
    )
    .expect("the imported current pack closure compiles without a legacy Function");
    candidate.validate(|_| Ok(())).unwrap();
    candidate.apply(&lock).unwrap();
    assert_eq!(
        fs::read_to_string(fixture.project.join("evidence.yaml")).unwrap(),
        candidate_text
    );
}

#[test]
fn current_fragment_headers_are_checked_then_removed_during_normalization() {
    let fixture = Fixture::new();
    let export = fixture.export("current-fragments", "lookup", "v1", &[]);
    let installed = load_export(&export).expect("current fragment headers are accepted");

    let source: Value = serde_json::from_str(&installed.upstream["source-fragments/lookup.json"])
        .expect("normalized source fragment is JSON");
    assert!(source["source"].get("apiVersion").is_none());
    assert!(source["source"].get("kind").is_none());

    let selector: Value =
        serde_json::from_str(&installed.upstream["selector-fragments/imported-reference.json"])
            .expect("normalized selector fragment is JSON");
    assert!(selector.get("apiVersion").is_none());
    assert!(selector.get("kind").is_none());
}

#[test]
fn import_refuses_invalid_source_and_selector_headers_without_leaking_values() {
    const PRIVATE_MARKER: &str = "private-fragment-marker-must-not-leak";
    const SOURCE_VERSION: &str = "id.registrystack.org/formats/evidence/source/v1alpha1";
    const SELECTOR_VERSION: &str = "id.registrystack.org/formats/evidence/selector/v1alpha1";

    for (fragment, field, replacement, expected_code, expected_path) in [
        (
            "source",
            "apiVersion",
            format!("apiVersion: {PRIVATE_MARKER}"),
            "config.unsupported-api-version",
            "/apiVersion",
        ),
        (
            "source",
            "apiVersion",
            String::new(),
            "config.missing-envelope",
            "",
        ),
        (
            "source",
            "apiVersion",
            format!("apiVersion: {{private: {PRIVATE_MARKER}}}"),
            "config.expected-string",
            "/apiVersion",
        ),
        (
            "source",
            "kind",
            format!("kind: {PRIVATE_MARKER}"),
            "config.wrong-kind",
            "/kind",
        ),
        (
            "source",
            "kind",
            String::new(),
            "config.missing-envelope",
            "",
        ),
        (
            "source",
            "kind",
            format!("kind: [{PRIVATE_MARKER}]"),
            "config.expected-string",
            "/kind",
        ),
        (
            "selector",
            "apiVersion",
            format!("apiVersion: {PRIVATE_MARKER}"),
            "config.unsupported-api-version",
            "/apiVersion",
        ),
        (
            "selector",
            "apiVersion",
            String::new(),
            "config.missing-envelope",
            "",
        ),
        (
            "selector",
            "apiVersion",
            format!("apiVersion: {{private: {PRIVATE_MARKER}}}"),
            "config.expected-string",
            "/apiVersion",
        ),
        (
            "selector",
            "kind",
            format!("kind: {PRIVATE_MARKER}"),
            "config.wrong-kind",
            "/kind",
        ),
        (
            "selector",
            "kind",
            String::new(),
            "config.missing-envelope",
            "",
        ),
        (
            "selector",
            "kind",
            format!("kind: [{PRIVATE_MARKER}]"),
            "config.expected-string",
            "/kind",
        ),
    ] {
        let fixture = Fixture::new();
        let export = fixture.export(
            &format!("invalid-{fragment}-{field}-{expected_code}"),
            "lookup",
            "v1",
            &[],
        );
        let path = match fragment {
            "source" => "sources/lookup.yaml",
            "selector" => "selectors/imported-reference.yaml",
            _ => unreachable!(),
        };
        let expected = match (fragment, field) {
            ("source", "apiVersion") => format!("apiVersion: {SOURCE_VERSION}"),
            ("source", "kind") => "kind: EvidenceSource".to_owned(),
            ("selector", "apiVersion") => format!("apiVersion: {SELECTOR_VERSION}"),
            ("selector", "kind") => "kind: EvidenceSelector".to_owned(),
            _ => unreachable!(),
        };
        let text = fs::read_to_string(export.join(path)).unwrap();
        let changed = text.replacen(&expected, &replacement, 1);
        assert_ne!(changed, text, "the test must replace the selected header");
        replace_export_artifact(&export, path, &changed);

        let error = load_export(&export).expect_err("an invalid fragment header is refused");
        let refused = error
            .downcast_ref::<DocumentRefused>()
            .expect("the shared reader's structured refusal is retained");
        assert_eq!(refused.report.diagnostics().len(), 1);
        let diagnostic = &refused.report.diagnostics()[0];
        assert_eq!(diagnostic.code, expected_code);
        assert_eq!(diagnostic.path, expected_path);
        assert_eq!(diagnostic.source.as_ref().unwrap().file, path);
        let rendered = refused.report.render_human();
        assert!(!rendered.contains(PRIVATE_MARKER), "{rendered}");
    }
}

#[test]
fn flow_and_empty_project_collections_import_without_partial_entries() {
    for functions in [
        "[{id: existing, interface: assertion-derive/v1, source: functions/existing.rhai}]",
        "\n  []",
    ] {
        let project = format!(
            "apiVersion: {}\nkind: {}\nfunctions: {functions}\n# Preserve this comment and the unowned member.\nuntouched: true\n",
            registry_evidence_authoring::project::PROJECT_API_VERSION,
            registry_evidence_authoring::project::PROJECT_KIND,
        );
        let document = registry_platform_yaml::Reader::new("evidence.yaml")
            .read(
                project.as_bytes(),
                &registry_platform_yaml::Expect::one(
                    &registry_evidence_authoring::project::PROJECT,
                ),
            )
            .unwrap();
        let replacement = json!([{
            "id": "imported-derive",
            "interface": "assertion-derive/v1",
            "source": "functions/imported-derive.rhai"
        }]);
        let replaced =
            replace_project_sections(&project, &document, [("/functions", &replacement)]).unwrap();
        registry_platform_yaml::Reader::new("evidence.yaml")
            .read(
                replaced.as_bytes(),
                &registry_platform_yaml::Expect::one(
                    &registry_evidence_authoring::project::PROJECT,
                ),
            )
            .unwrap();
        assert!(
            replaced.contains("# Preserve this comment and the unowned member.\nuntouched: true")
        );
        assert!(!replaced.contains("- ["));
    }
}

#[test]
fn json_project_import_remains_valid() {
    let fixture = Fixture::new();
    let project_path = fixture.project.join("evidence.yaml");
    let project = fs::read(&project_path).unwrap();
    let value = registry_platform_yaml::Reader::new("evidence.yaml")
        .scan(&project)
        .unwrap()
        .unwrap()
        .to_json_value();
    fs::write(&project_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let export = fixture.export("export", "lookup", "v1", &[]);
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let candidate = prepare(&lock, &[export], &BTreeMap::new()).unwrap();
    let candidate_text = fs::read_to_string(candidate.project().join("evidence.yaml")).unwrap();
    let decoded = registry_evidence_authoring::project::read_project(
        "evidence.yaml",
        candidate_text.as_bytes(),
    )
    .unwrap();
    assert!(decoded
        .value
        .sources
        .keys()
        .any(|id| id.as_str() == "lookup"));
}

#[test]
fn pinned_pack_artifact_tampering_is_refused_without_authored_changes() {
    let fixture = Fixture::new();
    let export = fixture.export("export", "lookup", "v1", &[]);
    let script = "adapter-packs/lookup/scripts/lookup.rhai";
    replace_export_artifact(
        &export,
        script,
        "fn lookup(exchange) { #{lookup: \"unresolved\"} }\n",
    );
    let before = snapshot(&fixture.project).unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let error = prepare(&lock, &[export], &BTreeMap::new())
        .err()
        .expect("a digest-pin mismatch is refused");
    assert!(error.to_string().contains("does not match its digest pin"));
    assert_eq!(snapshot(&fixture.project).unwrap(), before);
}

#[test]
fn retired_inline_source_contract_is_refused_without_a_converter() {
    let fixture = Fixture::new();
    let export = fixture.export("export", "lookup", "v1", &[]);
    let source_path = "sources/lookup.yaml";
    let mut source = fs::read_to_string(export.join(source_path)).unwrap();
    source.push_str("request: {method: GET, path: /lookup}\nextractScript: adapter-packs/lookup/scripts/lookup.rhai\n");
    replace_export_artifact(&export, source_path, &source);
    let before = snapshot(&fixture.project).unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let error = prepare(&lock, &[export], &BTreeMap::new())
        .err()
        .expect("retired request/extract members are refused");
    assert!(error.to_string().contains("current pack binding"));
    assert_eq!(snapshot(&fixture.project).unwrap(), before);
}

#[test]
fn moved_exports_and_reordered_inventory_are_true_no_ops() {
    let fixture = Fixture::new();
    let export = fixture.export(
        "first-location",
        "lookup",
        "v1",
        &[
            ("sources/lookup.yaml", "source revision one\n"),
            (
                "adapter-packs/lookup/scripts/lookup.rhai",
                "fn extract(response, context) { response }\n",
            ),
        ],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    assert!(!accepted(
        &lock,
        std::slice::from_ref(&export),
        BTreeMap::new()
    ));
    let state = fs::read(fixture.project.join(STATE_PATH)).unwrap();
    let moved = fixture.root.path().join("moved-export");
    fs::rename(export, &moved).unwrap();
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(moved.join(MANIFEST_FILE)).unwrap()).unwrap();
    manifest["artifacts"].as_array_mut().unwrap().reverse();
    fs::write(
        moved.join(MANIFEST_FILE),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    assert!(accepted(&lock, &[moved], BTreeMap::new()));
    assert_eq!(fs::read(fixture.project.join(STATE_PATH)).unwrap(), state);
}

#[test]
fn customization_conflicts_finish_with_keep_adopt_and_resolved_file() {
    for choice in ["keep", "adopt", "file"] {
        let fixture = Fixture::new();
        let original = fixture.export(
            "original",
            "lookup",
            "v1",
            &[
                ("sources/lookup.yaml", "source revision one\n"),
                ("adapter-packs/lookup/scripts/lookup.rhai", "upstream-one\n"),
            ],
        );
        let lock = ProjectLock::acquire(&fixture.project).unwrap();
        accepted(&lock, &[original], BTreeMap::new());
        put(
            &fixture.project,
            "adapter-packs/lookup/scripts/lookup.rhai",
            "authored-customization\n",
        );
        put(
            &fixture.project,
            "functions/unrelated.rhai",
            "independent-authoring\n",
        );
        let next = fixture.export(
            "next",
            "lookup",
            "v2",
            &[
                ("sources/lookup.yaml", "source revision two\n"),
                ("adapter-packs/lookup/scripts/lookup.rhai", "upstream-two\n"),
            ],
        );
        let mut conflict = prepare(&lock, std::slice::from_ref(&next), &BTreeMap::new()).unwrap();
        assert_eq!(
            conflict.report().conflicts,
            ["adapter-packs/lookup/scripts/lookup.rhai"]
        );
        assert!(conflict.validate(|_| Ok(())).is_err());
        let resolved = fixture.root.path().join("resolved.rhai");
        fs::write(&resolved, "reviewed-resolution\n").unwrap();
        let (resolution, expected) = match choice {
            "keep" => (Resolution::Keep {}, "authored-customization\n"),
            "adopt" => (Resolution::Adopt {}, "upstream-two\n"),
            _ => (Resolution::File { path: resolved }, "reviewed-resolution\n"),
        };
        accepted(
            &lock,
            std::slice::from_ref(&next),
            BTreeMap::from([(
                "adapter-packs/lookup/scripts/lookup.rhai".to_owned(),
                resolution,
            )]),
        );
        assert_eq!(
            fs::read_to_string(
                fixture
                    .project
                    .join("adapter-packs/lookup/scripts/lookup.rhai")
            )
            .unwrap(),
            expected
        );
        assert_eq!(
            fs::read_to_string(fixture.project.join("functions/unrelated.rhai")).unwrap(),
            "independent-authoring\n"
        );
        let state = parse_state(
            read(&fixture.project, STATE_PATH, MAX_STATE_BYTES)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        assert_eq!(
            state.imports["lookup"].upstream["adapter-packs/lookup/scripts/lookup.rhai"],
            "upstream-two\n"
        );
        assert_eq!(
            state.accepted["adapter-packs/lookup/scripts/lookup.rhai"].as_deref(),
            Some(expected)
        );
        assert!(accepted(&lock, &[next], BTreeMap::new()));
    }
}

#[test]
fn shared_changes_require_one_consistent_multi_export_candidate() {
    let fixture = Fixture::new();
    let first = fixture.export(
        "a-one",
        "first",
        "v1",
        &[
            ("sources/first.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 1\n"),
        ],
    );
    let second = fixture.export(
        "b-one",
        "second",
        "v1",
        &[
            ("sources/second.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 1\n"),
        ],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    accepted(&lock, &[first, second], BTreeMap::new());
    let first_next = fixture.export(
        "a-two",
        "first",
        "v2",
        &[
            ("sources/first.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 2\n"),
        ],
    );
    let second_next = fixture.export(
        "b-two",
        "second",
        "v2",
        &[
            ("sources/second.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 2\n"),
        ],
    );
    let conflict = prepare(&lock, std::slice::from_ref(&first_next), &BTreeMap::new()).unwrap();
    let shared = conflict
        .report()
        .changes
        .iter()
        .find(|change| change.path == "selector-fragments/shared.json")
        .unwrap();
    assert_eq!(shared.next_owners, ["first", "second"]);
    assert_eq!(
        conflict.report().conflicts,
        ["selector-fragments/shared.json"]
    );
    accepted(&lock, &[first_next, second_next], BTreeMap::new());
    let project = fs::read_to_string(fixture.project.join("evidence.yaml")).unwrap();
    assert!(project.contains(&digest(b"version: 2\n")));
}

#[test]
fn deleting_obsolete_pack_artifacts_preserves_explicit_customization() {
    let fixture = Fixture::new();
    let initial = fixture.export(
        "initial",
        "lookup",
        "v1",
        &[
            ("sources/lookup.yaml", "kind: initial\n"),
            (
                "adapter-packs/lookup/scripts/lookup.rhai",
                "fn extract(response, context) { response }\n",
            ),
            (
                "adapter-packs/lookup/scripts/unused.rhai",
                "fn unused(exchange) { exchange.body }\n",
            ),
            (
                "adapter-packs/lookup/scripts/custom.rhai",
                "fn custom(exchange) { exchange.body }\n",
            ),
        ],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    accepted(&lock, &[initial], BTreeMap::new());
    put(
        &fixture.project,
        "adapter-packs/lookup/scripts/custom.rhai",
        "fn custom(exchange) { #{customized: true} }\n",
    );
    let next = fixture.export(
        "next",
        "lookup",
        "v2",
        &[("sources/lookup.yaml", "kind: next\n")],
    );
    let mut candidate = prepare(
        &lock,
        &[next],
        &BTreeMap::from([(
            "adapter-packs/lookup/scripts/custom.rhai".to_owned(),
            Resolution::Keep {},
        )]),
    )
    .unwrap();
    assert_eq!(
        candidate
            .report()
            .changes
            .iter()
            .find(|change| change.path == "adapter-packs/lookup/scripts/unused.rhai")
            .unwrap()
            .action,
        "delete"
    );
    candidate.validate(|_| Ok(())).unwrap();
    candidate.apply(&lock).unwrap();
    assert!(!fixture
        .project
        .join("adapter-packs/lookup/scripts/unused.rhai")
        .exists());
    assert_eq!(
        fs::read_to_string(
            fixture
                .project
                .join("adapter-packs/lookup/scripts/custom.rhai")
        )
        .unwrap(),
        "fn custom(exchange) { #{customized: true} }\n"
    );
}

#[test]
fn stale_candidate_and_unvalidated_candidate_cannot_change_the_project() {
    let fixture = Fixture::new();
    let export = fixture.export(
        "export",
        "lookup",
        "v1",
        &[("sources/lookup.yaml", "version: 1\n")],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    assert!(
        prepare(&lock, std::slice::from_ref(&export), &BTreeMap::new())
            .unwrap()
            .apply(&lock)
            .is_err()
    );
    let mut candidate = prepare(&lock, &[export], &BTreeMap::new()).unwrap();
    candidate.validate(|_| Ok(())).unwrap();
    let mut independently_edited =
        fs::read_to_string(fixture.project.join("evidence.yaml")).unwrap();
    independently_edited.push_str("# independent authored edit\n");
    fs::write(fixture.project.join("evidence.yaml"), &independently_edited).unwrap();
    assert!(candidate.apply(&lock).is_err());
    assert!(!fixture.project.join(STATE_PATH).exists());
    assert_eq!(
        fs::read_to_string(fixture.project.join("evidence.yaml")).unwrap(),
        independently_edited
    );
}

#[test]
fn candidate_contains_no_secret_target_or_local_service_state() {
    let fixture = Fixture::new();
    put(
        &fixture.project,
        "secrets/credential",
        "sensitive-test-canary",
    );
    put(
        &fixture.project,
        ".evidence/dev/request.json",
        "private-request-canary",
    );
    put(
        &fixture.project,
        "targets/production/governance.yaml",
        "institution-target-canary",
    );
    put(
        &fixture.project,
        "access/clients/client.yaml",
        "caller-state-canary",
    );
    let export = fixture.export(
        "export",
        "lookup",
        "v1",
        &[("sources/lookup.yaml", "version: 1\n")],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let candidate = prepare(&lock, &[export], &BTreeMap::new()).unwrap();
    for path in ["secrets", ".evidence", "targets", "access"] {
        assert!(!candidate.project().join(path).exists());
    }
    let project = fs::read_to_string(candidate.project().join("evidence.yaml")).unwrap();
    assert!(project.contains("\"lookup\""));
    assert!(candidate
        .project()
        .join("adapter-packs/lookup/scripts/lookup.rhai")
        .exists());
}

#[test]
fn build_lock_serializes_updates_without_requiring_writable_project_state() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.project, fs::Permissions::from_mode(0o500)).unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    assert!(ProjectLock::acquire(&fixture.project).is_err());
    assert!(!fixture.project.join(".evidence").exists());
    drop(lock);
    assert!(ProjectLock::acquire(&fixture.project).is_ok());
    fs::set_permissions(&fixture.project, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn interrupted_replacement_and_baseline_advance_restore_the_complete_prior_state() {
    for applied_count in 0..=3 {
        let fixture = Fixture::new();
        let export = fixture.export(
            "initial",
            "lookup",
            "v1",
            &[
                ("sources/lookup.yaml", "version: 1\n"),
                ("adapter-packs/lookup/scripts/lookup.rhai", "original\n"),
            ],
        );
        let lock = ProjectLock::acquire(&fixture.project).unwrap();
        accepted(&lock, &[export], BTreeMap::new());
        let baseline = read(&fixture.project, STATE_PATH, MAX_STATE_BYTES).unwrap();
        let project_before = read(&fixture.project, "evidence.yaml", MAX_FILE_BYTES).unwrap();
        let operations = vec![
            Operation {
                path: "evidence.yaml".to_owned(),
                before: project_before.clone(),
                after: Some(Contents {
                    text: "candidate-project\n".to_owned(),
                    mode: 0o600,
                }),
            },
            Operation {
                path: "adapter-packs/lookup/scripts/lookup.rhai".to_owned(),
                before: read(
                    &fixture.project,
                    "adapter-packs/lookup/scripts/lookup.rhai",
                    MAX_FILE_BYTES,
                )
                .unwrap(),
                after: None,
            },
            Operation {
                path: STATE_PATH.to_owned(),
                before: baseline.clone(),
                after: Some(Contents {
                    text: "candidate-baseline\n".to_owned(),
                    mode: 0o600,
                }),
            },
        ];
        let journal = Journal {
            api_version: JOURNAL_API_VERSION.to_owned(),
            kind: JOURNAL_KIND.to_owned(),
            operations,
        };
        write(
            &fixture.project,
            JOURNAL_PATH,
            Some(&Contents {
                text: serde_json::to_string(&journal).unwrap(),
                mode: 0o600,
            }),
        )
        .unwrap();
        for operation in journal.operations.iter().take(applied_count) {
            write(&fixture.project, &operation.path, operation.after.as_ref()).unwrap();
        }
        drop(lock);
        // The same entry point used by builds recovers before granting a reader.
        let recovered = ProjectLock::acquire(&fixture.project).unwrap();
        assert_eq!(
            read(&fixture.project, "evidence.yaml", MAX_FILE_BYTES).unwrap(),
            project_before
        );
        assert_eq!(
            fs::read_to_string(
                fixture
                    .project
                    .join("adapter-packs/lookup/scripts/lookup.rhai")
            )
            .unwrap(),
            "original\n"
        );
        assert_eq!(
            read(&fixture.project, STATE_PATH, MAX_STATE_BYTES).unwrap(),
            baseline
        );
        assert!(!fixture.project.join(JOURNAL_PATH).exists());
        drop(recovered);
        ProjectLock::acquire(&fixture.project)
            .expect("acquiring the project lock after recovery must succeed");
    }
}

#[test]
fn recovery_checks_every_precondition_before_touching_independent_edits() {
    let fixture = Fixture::new();
    put(&fixture.project, "adapters/first.rhai", "after\n");
    put(
        &fixture.project,
        "adapters/second.rhai",
        "independent-edit\n",
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    files::ensure_state_directory(&fixture.project).unwrap();
    let operations = ["adapters/first.rhai", "adapters/second.rhai"]
        .into_iter()
        .map(|path| Operation {
            path: path.to_owned(),
            before: Some(Contents {
                text: "before\n".to_owned(),
                mode: 0o644,
            }),
            after: Some(Contents {
                text: "after\n".to_owned(),
                mode: 0o644,
            }),
        })
        .collect();
    write(
        &fixture.project,
        JOURNAL_PATH,
        Some(&Contents {
            text: serde_json::to_string(&Journal {
                api_version: JOURNAL_API_VERSION.to_owned(),
                kind: JOURNAL_KIND.to_owned(),
                operations,
            })
            .unwrap(),
            mode: 0o600,
        }),
    )
    .unwrap();
    drop(lock);
    assert!(ProjectLock::acquire(&fixture.project).is_err());
    assert_eq!(
        fs::read_to_string(fixture.project.join("adapters/first.rhai")).unwrap(),
        "after\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.project.join("adapters/second.rhai")).unwrap(),
        "independent-edit\n"
    );
    assert!(fixture.project.join(JOURNAL_PATH).exists());
}

#[test]
fn build_refuses_recovery_capability_planted_in_writable_shared_state() {
    for writable in [
        ".",
        ".evidence",
        ".evidence/source-imports",
        JOURNAL_PATH,
        STATE_PATH,
    ] {
        let fixture = Fixture::new();
        put(
            &fixture.project,
            "sources/protected.yaml",
            "reviewed: current\n",
        );
        let current = read(&fixture.project, "sources/protected.yaml", MAX_FILE_BYTES).unwrap();
        files::ensure_state_directory(&fixture.project).unwrap();
        let journal = Journal {
            api_version: JOURNAL_API_VERSION.to_owned(),
            kind: JOURNAL_KIND.to_owned(),
            operations: vec![Operation {
                path: "sources/protected.yaml".to_owned(),
                before: Some(Contents {
                    text: "unreviewed: replacement\n".to_owned(),
                    mode: 0o644,
                }),
                after: current,
            }],
        };
        write(
            &fixture.project,
            JOURNAL_PATH,
            Some(&Contents {
                text: serde_json::to_string(&journal).unwrap(),
                mode: 0o600,
            }),
        )
        .unwrap();
        write(
            &fixture.project,
            STATE_PATH,
            Some(&Contents {
                text: "{}\n".to_owned(),
                mode: 0o600,
            }),
        )
        .unwrap();
        let path = fixture.project.join(writable);
        let mode = if path.is_dir() { 0o777 } else { 0o666 };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();

        assert!(ProjectLock::acquire(&fixture.project).is_err());
        assert_eq!(
            fs::read_to_string(fixture.project.join("sources/protected.yaml")).unwrap(),
            "reviewed: current\n"
        );
        assert!(fixture.project.join(JOURNAL_PATH).exists());
    }
}

#[test]
fn detach_keeps_provenance_and_prevents_implicit_shared_artifact_changes() {
    let fixture = Fixture::new();
    let first = fixture.export(
        "a",
        "first",
        "v1",
        &[
            ("sources/first.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 1\n"),
        ],
    );
    let second = fixture.export(
        "b",
        "second",
        "v1",
        &[
            ("sources/second.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 1\n"),
        ],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    accepted(&lock, &[first.clone(), second], BTreeMap::new());
    let authored = snapshot(&fixture.project).unwrap();
    detach(&lock, "first").unwrap();
    detach(&lock, "first").unwrap();
    assert_eq!(snapshot(&fixture.project).unwrap(), authored);
    let state = parse_state(
        read(&fixture.project, STATE_PATH, MAX_STATE_BYTES)
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    assert!(state.imports["first"].detached);
    assert_eq!(state.imports["first"].manifest.provenance["revision"], "v1");
    assert!(prepare(&lock, &[first], &BTreeMap::new()).is_err());
    let next = fixture.export(
        "b-next",
        "second",
        "v2",
        &[
            ("sources/second.yaml", "profile: shared\n"),
            ("selectors/shared.yaml", "version: 2\n"),
        ],
    );
    let candidate = prepare(&lock, &[next], &BTreeMap::new()).unwrap();
    assert_eq!(
        candidate.report().conflicts,
        ["selector-fragments/shared.json"]
    );
}

#[test]
fn import_refuses_checksum_path_symlink_and_duplicate_identity_failures() {
    let fixture = Fixture::new();
    let export = fixture.export(
        "export",
        "lookup",
        "v1",
        &[("sources/lookup.yaml", "version: 1\n")],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    assert!(prepare(&lock, &[export.clone(), export.clone()], &BTreeMap::new()).is_err());
    let manifest_bytes = fs::read(export.join(MANIFEST_FILE)).unwrap();
    let mut duplicate: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let first = duplicate["artifacts"][0].clone();
    duplicate["artifacts"].as_array_mut().unwrap().push(first);
    fs::write(
        export.join(MANIFEST_FILE),
        serde_json::to_vec(&duplicate).unwrap(),
    )
    .unwrap();
    assert!(prepare(&lock, std::slice::from_ref(&export), &BTreeMap::new()).is_err());
    let mut hook: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    hook["install"] = Value::String("unexpected-hook".to_owned());
    fs::write(
        export.join(MANIFEST_FILE),
        serde_json::to_vec(&hook).unwrap(),
    )
    .unwrap();
    assert!(prepare(&lock, std::slice::from_ref(&export), &BTreeMap::new()).is_err());
    fs::write(export.join(MANIFEST_FILE), manifest_bytes).unwrap();
    put(&export, "sources/lookup.yaml", "version: 2\n");
    assert!(prepare(&lock, std::slice::from_ref(&export), &BTreeMap::new()).is_err());
    for path in [
        "../sources/lookup.yaml",
        "/sources/lookup.yaml",
        "sources/../lookup.yaml",
        "targets/authority.yaml",
        "adapters/nested/lookup.rhai",
        "sources\\lookup.yaml",
    ] {
        assert!(artifact_path(path).is_err());
    }
    fs::remove_file(export.join("sources/lookup.yaml")).unwrap();
    let outside = fixture.root.path().join("outside.yaml");
    fs::write(&outside, "version: 1\n").unwrap();
    symlink(&outside, export.join("sources/lookup.yaml")).unwrap();
    assert!(prepare(&lock, &[export], &BTreeMap::new()).is_err());
    assert!(!fixture.project.join(STATE_PATH).exists());
}

#[test]
fn exact_authored_destination_collision_requires_an_explicit_ownership_choice() {
    let fixture = Fixture::new();
    put(
        &fixture.project,
        "adapter-packs/lookup/scripts/lookup.rhai",
        "locally authored\n",
    );
    let export = fixture.export(
        "export",
        "lookup",
        "v1",
        &[("sources/lookup.yaml", "version: 1\n")],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let candidate = prepare(&lock, std::slice::from_ref(&export), &BTreeMap::new()).unwrap();
    assert_eq!(
        candidate.report().conflicts,
        ["adapter-packs/lookup/scripts/lookup.rhai"]
    );
    accepted(
        &lock,
        &[export],
        BTreeMap::from([(
            "adapter-packs/lookup/scripts/lookup.rhai".to_owned(),
            Resolution::Keep {},
        )]),
    );
    let next = fixture.export(
        "next",
        "lookup",
        "v2",
        &[
            ("sources/lookup.yaml", "version: 2\n"),
            (
                "adapter-packs/lookup/scripts/lookup.rhai",
                "upstream changed\n",
            ),
        ],
    );
    assert_eq!(
        prepare(&lock, &[next], &BTreeMap::new())
            .unwrap()
            .report()
            .conflicts,
        ["adapter-packs/lookup/scripts/lookup.rhai"]
    );
}

#[test]
fn structural_impact_follows_source_dependencies_without_inventing_revisions() {
    let fixture = Fixture::new();
    const SOURCE: &str = "source revision one\n";
    const EXTRACT_ONE: &str = "one\n";
    let first = fixture.export(
        "first",
        "lookup",
        "v1",
        &[
            ("sources/lookup.yaml", SOURCE),
            ("adapter-packs/lookup/scripts/lookup.rhai", EXTRACT_ONE),
        ],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    accepted(&lock, &[first], BTreeMap::new());
    let project_path = fixture.project.join("evidence.yaml");
    let decoded = registry_evidence_authoring::project::read_project(
        "evidence.yaml",
        &fs::read(&project_path).unwrap(),
    )
    .unwrap();
    let mut project = serde_json::to_value(decoded.value).unwrap();
    project["apiVersion"] = json!(registry_evidence_authoring::project::PROJECT_API_VERSION);
    project["kind"] = json!(registry_evidence_authoring::project::PROJECT_KIND);
    project["assertionDefinitions"]["other"]["subjects"][0]["selectors"] =
        json!(["imported-reference"]);
    project["assertionDefinitions"]["other"]["acquisition"] = json!({"source":"lookup"});
    fs::write(&project_path, serde_json::to_vec_pretty(&project).unwrap()).unwrap();
    let next = fixture.export(
        "next",
        "lookup",
        "v2",
        &[
            ("sources/lookup.yaml", SOURCE),
            ("adapter-packs/lookup/scripts/lookup.rhai", "two\n"),
        ],
    );
    let candidate = prepare(&lock, &[next], &BTreeMap::new()).unwrap();
    assert_eq!(candidate.report().affected_definitions, ["other"]);
    assert!(serde_json::to_value(candidate.report())
        .unwrap()
        .get("configurationRevision")
        .is_none());

    let selector_next = fixture.export(
        "selector-next",
        "lookup",
        "v2",
        &[
            ("sources/lookup.yaml", SOURCE),
            ("adapter-packs/lookup/scripts/lookup.rhai", EXTRACT_ONE),
        ],
    );
    replace_export_artifact(
        &selector_next,
        "selectors/imported-reference.yaml",
        "apiVersion: id.registrystack.org/formats/evidence/selector/v1alpha1\nkind: EvidenceSelector\nmaximumAggregateBytes: 65\nfields: {value: {type: string, minimumBytes: 1, maximumBytes: 64}}\n",
    );
    let candidate = prepare(&lock, &[selector_next], &BTreeMap::new()).unwrap();
    assert_eq!(candidate.report().affected_definitions, ["other"]);
}

#[test]
fn provenance_only_unconsumed_update_ignores_consumed_function_declaration_order() {
    let fixture = Fixture::new();
    let lookup = fixture.export("lookup", "lookup", "v1", &[]);
    let unrelated = fixture.export("unrelated", "unrelated", "v1", &[]);
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    accepted(&lock, &[lookup], BTreeMap::new());
    accepted(&lock, &[unrelated], BTreeMap::new());

    let project_path = fixture.project.join("evidence.yaml");
    let decoded = registry_evidence_authoring::project::read_project(
        "evidence.yaml",
        &fs::read(&project_path).unwrap(),
    )
    .unwrap();
    let mut project = serde_json::to_value(decoded.value).unwrap();
    project["apiVersion"] = json!(registry_evidence_authoring::project::PROJECT_API_VERSION);
    project["kind"] = json!(registry_evidence_authoring::project::PROJECT_KIND);
    project["assertionDefinitions"]["other"]["acquisition"] = json!({"source":"lookup"});
    project["assertionDefinitions"]["other"]["subjects"][0]["selectors"] =
        json!(["imported-reference"]);
    project["functions"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|function| {
            !function["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("lookup-"))
        });
    fs::write(&project_path, serde_json::to_vec_pretty(&project).unwrap()).unwrap();

    let provenance_only = fixture.export("unrelated-next", "unrelated", "v2", &[]);
    let candidate = prepare(&lock, &[provenance_only], &BTreeMap::new()).unwrap();
    assert_eq!(candidate.report().provenance_changed, ["unrelated"]);
    assert!(candidate.report().affected_definitions.is_empty());
}

#[test]
fn deleting_obsolete_artifact_with_a_local_edit_requires_an_explicit_resolution() {
    let fixture = Fixture::new();
    let initial = fixture.export(
        "initial",
        "lookup",
        "v1",
        &[
            ("sources/lookup.yaml", "kind: initial\n"),
            (
                "adapter-packs/lookup/scripts/lookup.rhai",
                "fn extract(response, context) { response }\n",
            ),
            (
                "adapter-packs/lookup/scripts/custom.rhai",
                "fn custom(exchange) { exchange.body }\n",
            ),
        ],
    );
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    accepted(&lock, &[initial], BTreeMap::new());
    let state_before = fs::read(fixture.project.join(STATE_PATH)).unwrap();
    put(
        &fixture.project,
        "adapter-packs/lookup/scripts/custom.rhai",
        "fn custom(exchange) { #{customized: true} }\n",
    );
    let next = fixture.export(
        "next",
        "lookup",
        "v2",
        &[("sources/lookup.yaml", "kind: next\n")],
    );
    // Unlike `deleting_obsolete_pack_artifacts_preserves_explicit_customization`,
    // no resolution is supplied for the edited, now-obsolete artifact, so the
    // conflict must reach `validate` unresolved instead of being silently
    // decided by an implicit keep or delete.
    let mut candidate = prepare(&lock, &[next], &BTreeMap::new()).unwrap();
    assert_eq!(
        candidate.report().conflicts,
        ["adapter-packs/lookup/scripts/custom.rhai"]
    );
    let error = candidate.validate(|_| Ok(())).unwrap_err();
    assert_eq!(
        error.to_string(),
        "source candidate has unresolved conflicts; choose keep, adopt, or an explicit resolved file"
    );
    assert_eq!(
        fs::read_to_string(
            fixture
                .project
                .join("adapter-packs/lookup/scripts/custom.rhai")
        )
        .unwrap(),
        "fn custom(exchange) { #{customized: true} }\n"
    );
    assert!(!fixture.project.join(JOURNAL_PATH).exists());
    assert_eq!(
        fs::read(fixture.project.join(STATE_PATH)).unwrap(),
        state_before
    );
}

#[test]
fn import_refuses_manifest_over_one_mebibyte() {
    let fixture = Fixture::new();
    let root = fixture.root.path().join("oversized-manifest");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join(MANIFEST_FILE),
        vec![b'a'; (MAX_FILE_BYTES + 1) as usize],
    )
    .unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let error = prepare(&lock, &[root], &BTreeMap::new())
        .err()
        .expect("bounded export is refused");
    assert_eq!(
        error.to_string(),
        "local artifact must be a bounded plain file"
    );
}

#[test]
fn import_refuses_more_than_256_artifacts() {
    let fixture = Fixture::new();
    let root = fixture.root.path().join("too-many-artifacts");
    fs::create_dir_all(&root).unwrap();
    let manifest = ExportManifest {
        source_id: "lookup".to_owned(),
        provenance: BTreeMap::from([("producer".to_owned(), "source-contract-test".to_owned())]),
        artifacts: (0..=MAX_ARTIFACTS)
            .map(|index| ExportArtifact {
                path: format!("adapters/pad-{index:03}.rhai"),
                sha256: "0".repeat(64),
            })
            .collect(),
    };
    fs::write(root.join(MANIFEST_FILE), export_document(&manifest)).unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let error = prepare(&lock, &[root], &BTreeMap::new())
        .err()
        .expect("bounded export is refused");
    assert_eq!(
        error.to_string(),
        "a source export must inventory between 1 and 256 artifacts"
    );
}

#[test]
fn import_refuses_artifact_over_one_mebibyte() {
    let fixture = Fixture::new();
    let root = fixture.root.path().join("oversized-artifact");
    fs::create_dir_all(&root).unwrap();
    put(
        &root,
        "sources/lookup.yaml",
        &"a".repeat((MAX_FILE_BYTES + 1) as usize),
    );
    let manifest = ExportManifest {
        source_id: "lookup".to_owned(),
        provenance: BTreeMap::from([("producer".to_owned(), "source-contract-test".to_owned())]),
        artifacts: vec![ExportArtifact {
            path: "sources/lookup.yaml".to_owned(),
            sha256: "0".repeat(64),
        }],
    };
    fs::write(root.join(MANIFEST_FILE), export_document(&manifest)).unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let error = prepare(&lock, &[root], &BTreeMap::new())
        .err()
        .expect("bounded export is refused");
    assert_eq!(
        error.to_string(),
        "local artifact must be a bounded plain file"
    );
}

#[test]
fn import_refuses_export_over_sixteen_mebibytes_aggregate() {
    let fixture = Fixture::new();
    let root = fixture.root.path().join("oversized-export");
    fs::create_dir_all(&root).unwrap();
    const PAD_ARTIFACTS: usize = 17;
    const PAD_BYTES: usize = 1_000_000;
    let padding = "x".repeat(PAD_BYTES);
    let mut artifacts = Vec::new();
    for index in 0..PAD_ARTIFACTS {
        let path = format!("adapters/pad-{index:02}.rhai");
        put(&root, &path, &padding);
        artifacts.push(ExportArtifact {
            path,
            sha256: digest(padding.as_bytes()),
        });
    }
    let sources = "kind: lookup\n";
    put(&root, "sources/lookup.yaml", sources);
    artifacts.push(ExportArtifact {
        path: "sources/lookup.yaml".to_owned(),
        sha256: digest(sources.as_bytes()),
    });
    let manifest = ExportManifest {
        source_id: "lookup".to_owned(),
        provenance: BTreeMap::from([("producer".to_owned(), "source-contract-test".to_owned())]),
        artifacts,
    };
    fs::write(root.join(MANIFEST_FILE), export_document(&manifest)).unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let error = prepare(&lock, &[root], &BTreeMap::new())
        .err()
        .expect("bounded export is refused");
    assert_eq!(
        error.to_string(),
        "source export exceeds its 16 MiB artifact bound"
    );
}

#[test]
fn import_refuses_provenance_outside_its_bounds() {
    let fixture = Fixture::new();
    let root = fixture.root.path().join("bad-provenance");
    fs::create_dir_all(&root).unwrap();
    let manifest = ExportManifest {
        source_id: "lookup".to_owned(),
        provenance: BTreeMap::new(),
        artifacts: Vec::new(),
    };
    fs::write(root.join(MANIFEST_FILE), export_document(&manifest)).unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let error = prepare(&lock, &[root], &BTreeMap::new())
        .err()
        .expect("bounded export is refused");
    assert_eq!(
        error.to_string(),
        "export provenance must be a bounded map of nonempty printable strings"
    );
}

#[test]
fn import_refuses_yaml_artifact_that_is_not_a_mapping() {
    let fixture = Fixture::new();
    let root = fixture.root.path().join("non-mapping-artifact");
    fs::create_dir_all(&root).unwrap();
    let content = "not-a-mapping\n";
    put(&root, "sources/lookup.yaml", content);
    let manifest = ExportManifest {
        source_id: "lookup".to_owned(),
        provenance: BTreeMap::from([("producer".to_owned(), "source-contract-test".to_owned())]),
        artifacts: vec![ExportArtifact {
            path: "sources/lookup.yaml".to_owned(),
            sha256: digest(content.as_bytes()),
        }],
    };
    fs::write(root.join(MANIFEST_FILE), export_document(&manifest)).unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let error = prepare(&lock, &[root], &BTreeMap::new())
        .err()
        .expect("bounded export is refused");
    assert_eq!(
        error.to_string(),
        "export source, selector, and schema artifacts must be objects"
    );
}

#[test]
fn import_refuses_export_without_exactly_one_sources_artifact() {
    let fixture = Fixture::new();
    let root = fixture.root.path().join("extra-sources-artifact");
    fs::create_dir_all(&root).unwrap();
    let lookup = "kind: lookup\n";
    let extra = "kind: extra\n";
    put(&root, "sources/lookup.yaml", lookup);
    put(&root, "sources/extra.yaml", extra);
    let manifest = ExportManifest {
        source_id: "lookup".to_owned(),
        provenance: BTreeMap::from([("producer".to_owned(), "source-contract-test".to_owned())]),
        artifacts: vec![
            ExportArtifact {
                path: "sources/lookup.yaml".to_owned(),
                sha256: digest(lookup.as_bytes()),
            },
            ExportArtifact {
                path: "sources/extra.yaml".to_owned(),
                sha256: digest(extra.as_bytes()),
            },
        ],
    };
    fs::write(root.join(MANIFEST_FILE), export_document(&manifest)).unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let error = prepare(&lock, &[root], &BTreeMap::new())
        .err()
        .expect("bounded export is refused");
    assert_eq!(
        error.to_string(),
        "one export must inventory exactly sources/<sourceId>.yaml and its auxiliary artifacts"
    );
}

#[test]
fn import_refuses_artifact_stem_outside_its_bounds() {
    let fixture = Fixture::new();
    let root = fixture.root.path().join("bad-stem-artifact");
    fs::create_dir_all(&root).unwrap();
    let manifest = ExportManifest {
        source_id: "lookup".to_owned(),
        provenance: BTreeMap::from([("producer".to_owned(), "source-contract-test".to_owned())]),
        artifacts: vec![ExportArtifact {
            path: "sources/Lookup.yaml".to_owned(),
            sha256: "0".repeat(64),
        }],
    };
    fs::write(root.join(MANIFEST_FILE), export_document(&manifest)).unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let error = prepare(&lock, &[root], &BTreeMap::new())
        .err()
        .expect("bounded export is refused");
    assert_eq!(
        error.to_string(),
        "export artifact names must be bounded lowercase authoring names"
    );
}

/// The codes and paths the shared reader reported for `manifest`.
fn export_refusal(fixture: &Fixture, directory: &str, manifest: &Value) -> Vec<(String, String)> {
    let root = fixture.root.path().join(directory);
    put(&root, "sources/lookup.yaml", "kind: lookup\n");
    fs::write(
        root.join(MANIFEST_FILE),
        serde_json::to_vec(manifest).unwrap(),
    )
    .unwrap();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    let error = prepare(&lock, &[root], &BTreeMap::new())
        .err()
        .expect("the manifest is refused");
    let refused = error
        .downcast_ref::<DocumentRefused>()
        .expect("the shared reader refused the manifest");
    refused
        .report
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
        .collect()
}

fn current_manifest() -> Value {
    serde_json::json!({
        "apiVersion": EXPORT_API_VERSION,
        "kind": EXPORT_KIND,
        "sourceId": "lookup",
        "provenance": {"producer": "source-contract-test"},
        "artifacts": [{
            "path": "sources/lookup.yaml",
            "digest": format!("sha256:{}", digest(b"kind: lookup\n")),
        }],
    })
}

#[test]
fn import_reads_the_current_export_manifest() {
    let fixture = Fixture::new();
    let root = fixture.root.path().join("current");
    put(&root, "sources/lookup.yaml", "kind: lookup\n");
    fs::write(
        root.join(MANIFEST_FILE),
        serde_json::to_vec(&current_manifest()).unwrap(),
    )
    .unwrap();
    let bytes = fs::read(root.join(MANIFEST_FILE)).unwrap();
    let document = export::read_export_manifest(MANIFEST_FILE, &bytes).unwrap();
    assert_eq!(document.source_id, "lookup");
    assert_eq!(document.artifacts.len(), 1);
}

#[test]
fn import_refuses_the_previous_export_manifest_at_each_key() {
    let fixture = Fixture::new();
    let mut headerless = current_manifest();
    let members = headerless.as_object_mut().unwrap();
    members.remove("apiVersion");
    members.remove("kind");
    members.insert("formatVersion".to_owned(), Value::from(1));
    assert_eq!(
        export_refusal(&fixture, "headerless", &headerless),
        [
            ("config.missing-envelope".to_owned(), String::new()),
            ("config.removed-key".to_owned(), "/formatVersion".to_owned())
        ]
    );

    let mut version = current_manifest();
    version["formatVersion"] = Value::from(1);
    assert_eq!(
        export_refusal(&fixture, "format-version", &version),
        [("config.removed-key".to_owned(), "/formatVersion".to_owned())]
    );

    let mut checksum = current_manifest();
    let artifact = checksum["artifacts"][0].as_object_mut().unwrap();
    let written = artifact.remove("digest").unwrap();
    artifact.insert(
        "sha256".to_owned(),
        Value::String(written.as_str().unwrap()["sha256:".len()..].to_owned()),
    );
    assert_eq!(
        export_refusal(&fixture, "sha256", &checksum),
        [
            ("config.missing-key".to_owned(), "/artifacts/0".to_owned()),
            (
                "config.removed-key".to_owned(),
                "/artifacts/0/sha256".to_owned()
            ),
        ]
    );
}

#[test]
fn import_refuses_a_bare_hex_digest_and_an_unknown_member() {
    let fixture = Fixture::new();
    let mut bare = current_manifest();
    bare["artifacts"][0]["digest"] = Value::String(digest(b"kind: lookup\n"));
    assert_eq!(
        export_refusal(&fixture, "bare-digest", &bare),
        [(
            "config.invalid-value".to_owned(),
            "/artifacts/0/digest".to_owned()
        )]
    );

    let mut hook = current_manifest();
    hook["install"] = Value::String("unexpected-hook".to_owned());
    assert_eq!(
        export_refusal(&fixture, "unknown-member", &hook),
        [("config.unknown-key".to_owned(), "/install".to_owned())]
    );

    // The manifest carries no dependency inventory, so one is refused too.
    let mut inventory = current_manifest();
    inventory["dependencies"] = json!({"fields": {}, "relatedEntities": {}});
    assert_eq!(
        export_refusal(&fixture, "dependency-inventory", &inventory),
        [("config.unknown-key".to_owned(), "/dependencies".to_owned())]
    );
}

/// The format's registered example, the manifest `bregctl generate
/// evidence-source` writes for the Evidence example registry, decodes through
/// the shared reader.
#[test]
fn import_reads_the_committed_example_manifest() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/formats/source-export.json");
    let bytes = fs::read(&path).expect("the example manifest reads");
    let document = export::read_export_manifest(MANIFEST_FILE, &bytes)
        .map_err(|refused| {
            refused
                .report
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.code.clone())
                .collect::<Vec<_>>()
        })
        .expect("the example manifest decodes");
    assert_eq!(document.source_id, "registry-status");
    assert_eq!(document.artifacts.len(), 8);
}

const EXAMPLES: &str =
    "../../products/evidence/examples/formats/source-imports/.evidence/source-imports";

fn example(name: &str) -> Contents {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(EXAMPLES)
        .join(name);
    Contents {
        text: fs::read_to_string(path).expect("the example reads"),
        mode: 0o600,
    }
}

#[test]
fn the_registered_state_example_is_a_readable_baseline() {
    let state = parse_state(Some(&example("state.json"))).expect("the example reads");
    assert_eq!(state.imports.len(), 1);
}

#[test]
fn the_registered_journal_example_is_a_readable_transaction() {
    let journal = example("transaction.json");
    require_envelope(
        &journal.text,
        JOURNAL_API_VERSION,
        JOURNAL_KIND,
        JOURNAL_EARLIER,
    )
    .expect("the envelope matches");
    let journal: Journal = serde_json::from_str(&journal.text).expect("the example decodes");
    assert_eq!(journal.operations.len(), 1);
}

#[test]
fn a_baseline_without_the_envelope_is_refused_with_its_fix() {
    let mut earlier: Value = serde_json::from_str(&example("state.json").text).unwrap();
    let members = earlier.as_object_mut().unwrap();
    members.remove("apiVersion");
    members.remove("kind");
    members.insert("formatVersion".to_owned(), Value::from(1));
    let text = serde_json::to_string(&earlier).unwrap();
    let error = parse_state(Some(&Contents { text, mode: 0o600 })).unwrap_err();
    assert_eq!(error.to_string(), STATE_EARLIER);
}

#[test]
fn a_journal_without_the_envelope_is_refused_with_its_fix_and_left_in_place() {
    let fixture = Fixture::new();
    let lock = ProjectLock::acquire(&fixture.project).unwrap();
    files::ensure_state_directory(&fixture.project).unwrap();
    let text = r#"{"formatVersion":1,"operations":[]}"#.to_owned();
    write(
        &fixture.project,
        JOURNAL_PATH,
        Some(&Contents {
            text: text.clone(),
            mode: 0o600,
        }),
    )
    .unwrap();
    let error = recover(&lock).unwrap_err();
    assert_eq!(error.to_string(), JOURNAL_EARLIER);
    assert_eq!(
        fs::read_to_string(fixture.project.join(JOURNAL_PATH)).unwrap(),
        text
    );
}

#[test]
fn a_written_baseline_carries_the_envelope() {
    let encoded = encode_state(&State::default()).unwrap();
    let written: Value = serde_json::from_str(&encoded.text).unwrap();
    assert_eq!(written["apiVersion"], STATE_API_VERSION);
    assert_eq!(written["kind"], STATE_KIND);
    assert!(written.get("formatVersion").is_none());
}

const RESOLUTION_EXAMPLE: &str = "../../products/evidence/examples/formats/source-resolutions.json";

fn resolution_refusal(text: &str) -> Vec<(String, String)> {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("resolutions.json");
    fs::write(&path, text).unwrap();
    let error = read_resolutions(Some(&path)).expect_err("the resolution file is refused");
    error
        .downcast_ref::<DocumentRefused>()
        .expect("the shared reader refused the resolution file")
        .report
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
        .collect()
}

fn resolution_text(keys: &[String]) -> String {
    let artifacts = keys
        .iter()
        .map(|key| format!("\"{key}\": {{\"type\": \"keep\"}}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"apiVersion\": \"{RESOLUTION_API_VERSION}\", \"kind\": \"{RESOLUTION_KIND}\", \"artifacts\": {{{artifacts}}}}}"
    )
}

#[test]
fn a_resolution_file_over_the_artifact_count_is_refused() {
    let keys = |count: usize| {
        (0..count)
            .map(|index| format!("sources/s{index}.yaml"))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        resolution_refusal(&resolution_text(&keys(257))),
        [(
            "evidence.source-resolution.too-many-artifacts".to_owned(),
            "/artifacts".to_owned()
        )]
    );
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("resolutions.json");
    fs::write(&path, resolution_text(&keys(256))).unwrap();
    assert_eq!(read_resolutions(Some(&path)).unwrap().len(), 256);
}

#[test]
fn a_resolution_file_keyed_by_an_unsafe_artifact_is_refused_by_the_check() {
    for key in ["../escape.yaml", "sources/Upper.yaml", "other/a.yaml"] {
        let text = resolution_text(&[key.to_owned()]);
        let refused = check_resolution_file("resolutions.json", text.as_bytes())
            .expect_err("the unsafe key is refused");
        let diagnostics = refused.report.diagnostics();
        assert_eq!(diagnostics.len(), 1, "{key}");
        assert_eq!(
            diagnostics[0].code, "evidence.source-resolution.invalid-artifact",
            "{key}"
        );
        assert!(diagnostics[0].path.starts_with("/artifacts/"), "{key}");
        assert!(
            diagnostics[0].source.as_ref().unwrap().line.is_some(),
            "{key}"
        );
        assert_eq!(resolution_refusal(&text).len(), 1, "{key}");
    }
}

#[test]
fn the_registered_resolution_example_is_readable() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(RESOLUTION_EXAMPLE);
    let resolutions = read_resolutions(Some(&path)).expect("the example reads");
    assert!(matches!(
        resolutions["adapters/lookup-extract.rhai"],
        Resolution::Keep {}
    ));
    assert!(matches!(
        resolutions["sources/lookup.yaml"],
        Resolution::Adopt {}
    ));
    let Resolution::File { path: resolved } = &resolutions["adapters/lookup-request.rhai"] else {
        panic!("the third artifact names a file");
    };
    assert!(resolved.is_absolute());
    assert!(resolved.ends_with("formats/reviewed/lookup-request.rhai"));
}

#[test]
fn a_resolution_file_in_the_previous_shape_is_refused() {
    assert_eq!(
        resolution_refusal(r#"{"formatVersion": 1, "artifacts": {}}"#),
        [
            ("config.missing-envelope".to_owned(), String::new()),
            ("config.removed-key".to_owned(), "/formatVersion".to_owned())
        ]
    );
}

#[test]
fn a_resolution_names_a_known_choice_and_no_other_member() {
    let envelope =
        format!(r#""apiVersion": "{RESOLUTION_API_VERSION}", "kind": "{RESOLUTION_KIND}""#);
    let unknown = resolution_refusal(&format!(
        r#"{{{envelope}, "artifacts": {{"a.yaml": {{"type": "merge"}}}}}}"#
    ));
    assert_eq!(unknown.len(), 1, "{unknown:?}");
    let stray = resolution_refusal(&format!(
        r#"{{{envelope}, "artifacts": {{"a.yaml": {{"type": "keep", "path": "b"}}}}}}"#
    ));
    assert_eq!(stray.len(), 1, "{stray:?}");
    let missing = resolution_refusal(&format!(
        r#"{{{envelope}, "artifacts": {{"a.yaml": {{"type": "file"}}}}}}"#
    ));
    assert_eq!(missing.len(), 1, "{missing:?}");
}
