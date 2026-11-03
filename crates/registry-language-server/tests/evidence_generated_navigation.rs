// SPDX-License-Identifier: Apache-2.0
#[path = "support/normalized.rs"]
mod normalized;
use normalized::*;

fn checked_route(
    project: &registry_evidence_authoring::project::EvidenceProject,
) -> registry_evidence_authoring::compile::CheckedPackRoute {
    // These exact bytes supply the checked pack contract for type projection.
    // Transport execution is outside this editor navigation test.
    const INPUTS: &[u8] = br#"{"type":"object","additionalProperties":false,"required":["personId"],"properties":{"personId":{"type":"string","minLength":1,"maxLength":64}}}"#;
    const FACTS: &[u8] = br#"{"type":"object","additionalProperties":false,"required":["active"],"properties":{"active":{"type":"boolean"}}}"#;
    const SCRIPT: &[u8] =
        br#"fn lookup(exchange) { #{lookup: "matched", facts: #{active: exchange.body.active}} }
"#;
    const PACK: &[u8] = br#"{"apiVersion":"id.registrystack.org/formats/adapter/pack/v1alpha1","kind":"AdapterPack","id":"population","version":"1","testedVersions":[],"endpoints":[{"id":"provider","component":"http","authentication":{"type":"none"},"attemptTimeoutMilliseconds":2000,"maximumResponseBytes":4096,"operations":[{"id":"read","safeUpstream":true}]}],"scripts":[{"path":"scripts/lookup.rhai","digest":"sha256:f0077ccb9d2e48ccfb6e54e82f7923bd841dda7855535cad257ce88c4087c5de"}],"sourceRoutes":[{"id":"person-lookup","evidence":{"inputsSchema":{"path":"schemas/inputs.json","digest":"sha256:7021e8f152203182bd8a618d6cfea4bf94ca1042d4bdbcc1d900ee486ac76ead"},"factsSchema":{"path":"schemas/facts.json","digest":"sha256:a8c6ce95c71da1d614aaf7a36d9092ed0d50c5cbc5281062ae1898ccd21b178c"},"acquisitionPosture":"record-transformed"},"steps":[{"setProperty":{"name":"person-id","value":{"jsonpath":"$.personId"}}},{"to":{"uri":"http:provider","parameters":{"httpMethod":"GET","operation":"read","path":"/people/{{person-id}}","pathParameters":{"person-id":{"exchangeProperty":"person-id"}}}}},{"setBody":{"rhai":{"file":"scripts/lookup.rhai","entrypoint":"lookup"}}}]}]}"#;
    let source = project
        .sources
        .values()
        .next()
        .expect("the fixture has one Source");
    registry_evidence_authoring::compile::CheckedPackRoute {
        pack: source.pack.clone(),
        route: source.route.clone(),
        digest: "sha256:2bc8cfe0ed1aa282714d06d8f7952e27137b40f393abccde0f07860afc64977a"
            .to_owned(),
        inputs_schema: serde_json::from_slice(INPUTS).unwrap(),
        facts_schema: serde_json::from_slice(FACTS).unwrap(),
        acquisition_posture: source.acquisition_posture,
        pack_bytes: PACK.to_vec(),
        artifacts: std::collections::BTreeMap::from([
            ("schemas/inputs.json".to_owned(), INPUTS.to_vec()),
            ("schemas/facts.json".to_owned(), FACTS.to_vec()),
            ("scripts/lookup.rhai".to_owned(), SCRIPT.to_vec()),
        ]),
    }
}
#[test]
fn typescript_and_python_outputs_navigate_to_the_same_normalized_model() {
    let p = Project::new(SOURCE);
    let project = registry_evidence_authoring::project::read_project(PROJECT, SOURCE.as_bytes())
        .unwrap()
        .value;
    let scripts = project
        .functions
        .iter()
        .map(|function| (function.source.clone(), p.read(&function.source)))
        .collect();
    let compiled = registry_evidence_authoring::compile::compile_with_pack_routes(
        &project,
        &scripts,
        &[checked_route(&project)],
    )
    .expect("the current compiler checks the pinned source contract before generating types");
    for (file, source) in [
        (
            "types/evidence.ts",
            registry_evidence_authoring::project::typescript(&project, &compiled),
        ),
        (
            "types/evidence.py",
            registry_evidence_authoring::project::python(&project, &compiled),
        ),
    ] {
        p.write(file, &source);
        let index = p.index();
        assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
        let output_offset = source.find("\"active\"").unwrap();
        let output = after(&source, &source[..output_offset + 1]);
        assert_eq!(
            index.definitions_at(&p.path(file), output)[0].range.start,
            at(SOURCE, "active: {concept:")
        );
        for (id, expected) in [
            ("person", "person:"),
            ("derive-status", "derive-status, interface:"),
        ] {
            let key = format!("\"{id}\":");
            let offset = if id == "person" {
                source.find(&key)
            } else {
                source.rfind(&key)
            }
            .unwrap();
            let position = after(&source, &source[..offset + 1]);
            assert_eq!(
                index
                    .definitions_at(&p.path(file), position)
                    .first()
                    .unwrap_or_else(|| panic!("missing generated {id} reference in {file}"))
                    .range
                    .start,
                at(SOURCE, expected)
            );
        }
        let definition = source.rfind("\"active-status\"").unwrap();
        let before = &source[..definition + 1];
        let position = tower_lsp_server::ls_types::Position::new(
            before.bytes().filter(|&b| b == b'\n').count() as u32,
            before.rsplit('\n').next().unwrap().encode_utf16().count() as u32,
        );
        assert_eq!(
            index.definitions_at(&p.path(file), position)[0].range.start,
            at(SOURCE, "active-status:")
        );
    }
}
#[test]
fn ordinary_code_files_are_not_indexed_as_generated_types() {
    let p = Project::new(SOURCE);
    p.write("ordinary.py", "active = 'private'\n");
    assert!(!p
        .index()
        .document_paths()
        .any(|x| x == p.path("ordinary.py")));
}
