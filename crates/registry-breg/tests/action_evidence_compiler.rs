// SPDX-License-Identifier: Apache-2.0
use registry_breg::{
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_json, ModuleAssetSource},
    model::CompiledRegistry,
};
use serde_json::{json, Value};
fn project() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"action-handler-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
        "entities":[{"id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable","fields":[
            {"id":"name","type":"string","maxLength":160,"required":true,"classification":"restricted"},
            {"id":"friend","type":"reference","target":"person","classification":"restricted"}
        ]}],
        "actions":[{"id":"register-person","inputs":[
            {"id":"given-name","apiName":"givenName","type":"string","maxLength":80,"required":true,"classification":"restricted"},
            {"id":"family-name","type":"string","maxLength":80,"classification":"restricted"},
            {"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"}
        ],"handler":{"kind":"rhai","script":"handlers/register.rhai","abi":"registry.action-handler/v1","refusals":[{"code":"blank-name","label":"A name is required."}],"writes":[
            {"id":"person","target":{"entity":"person"},"operation":"create","fields":["name","friend"]},
            {"id":"friend","target":{"entity":"person"},"operation":"create","fields":["name","friend"]},
            {"id":"existing","target":{"fromField":"person"},"operation":"patch","fields":["name","friend"]}
        ]}}],
        "accessProfiles":[{"id":"registrar","default":true,"principalClaim":"principal","grants":[{"action":"register-person","operations":["invoke"],"targets":[{"entity":"person","rowBoundaries":[]}],"results":["person","friend","existing"]}]}]
    })
}

fn contracts() -> Value {
    serde_json::from_str(r#"{"schema": "registry.evidence-client-contracts/v1", "assuranceProfile": "local", "audience": "urn:example:client:audience:relying-party", "issuedBy": "urn:example:client:issuer", "providedBy": "urn:example:client:provider", "definitions": [{"handle": "status-holds", "requirement": "urn:example:client:requirement:status:v1", "configurationRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000", "kind": "criterion", "evidenceType": "urn:example:client:evidence-type:status:v1", "purpose": "example-decision", "responseFormats": ["signed-jws", "sd-jwt-vc"], "referenceFrameworks": ["urn:example:client:framework:status:v1"], "subjects": [{"role": "subject", "cardinality": "one", "selector": {"profile": "record-lookup-v1", "valueOrigin": "request", "fields": [{"type": "string", "name": "record_reference", "minimumBytes": 1, "maximumBytes": 200}, {"type": "date", "name": "recorded_on"}, {"type": "integer", "name": "sequence", "minimum": 0, "maximum": 10}, {"type": "boolean", "name": "confirmed"}, {"type": "controlled-code", "name": "office", "scheme": "urn:example:client:scheme:office", "version": "1", "maximumBytes": 32}]}}], "concepts": [{"handle": "status-holds", "concept": "urn:example:client:concept:status-holds", "required": true, "form": "boolean"}]}]}"#).unwrap()
}
fn configured() -> Value {
    let mut source = project();
    source["evidenceProviders"] = json!([{"id":"provider","contracts":"evidence/contracts.json","subjectResolution":"trusted-provider-exact-selector"}]);
    source["actions"][0]["handler"]["abi"] = json!("registry.action-handler/v2");
    source["actions"][0]["evidence"] = json!([{"id":"status","provider":"provider","requirement":"urn:example:client:requirement:status:v1","subjects":{"subject":{"profile":"record-lookup-v1"}},"outputs":["status-holds"],"maximumObservationAgeSeconds":60}]);
    source
}
fn compile(
    source: Value,
    contract: Option<Value>,
) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    let source = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let mut assets = vec![ModuleAssetSource {
        module: None,
        path: "handlers/register.rhai".into(),
        bytes: b"fn handle(ctx) { #{effects: []} }".to_vec(),
    }];
    if let Some(contract) = contract {
        assets.push(ModuleAssetSource {
            module: None,
            path: "evidence/contracts.json".into(),
            bytes: serde_json::to_vec(&contract).unwrap(),
        });
    }
    compile_project_with_assets(&source, &[], &assets, CompileProfile::Authoring)
}
#[test]
fn offline_contract_is_exact_and_fingerprinted() {
    let compiled = compile(configured(), Some(contracts())).unwrap();
    let action = &compiled.actions().actions[0];
    assert_eq!(action.evidence.len(), 1);
    assert!(action.contract_fingerprint.starts_with("sha256:"));
    assert_eq!(action.contract_fingerprint.len(), 71);
    assert_eq!(
        action,
        &compile(configured(), Some(contracts()))
            .unwrap()
            .actions()
            .actions[0]
    );
    assert!(action.evidence[0]
        .contract_fingerprint
        .starts_with("sha256:"));
    assert_eq!(
        action.evidence[0].definition.subjects[0]
            .selector
            .fields
            .len(),
        5
    );
    let mut changed = contracts();
    changed["definitions"][0]["configurationRevision"] =
        json!(format!("sha256:{}", "1".repeat(64)));
    let other = compile(configured(), Some(changed)).unwrap();
    assert_ne!(
        action.contract_fingerprint,
        other.actions().actions[0].contract_fingerprint
    );
    assert!(compile(configured(), None).is_err());
}
#[test]
fn refuses_origin_profile_output_ambiguity_and_budget_widening() {
    for change in [
        "origin",
        "profile",
        "output",
        "ambiguous",
        "budget",
        "abi",
        "schema",
        "bounds",
    ] {
        let mut source = configured();
        let mut contract = contracts();
        match change {
            "origin" => {
                contract["definitions"][0]["subjects"][0]["selector"]["valueOrigin"] =
                    json!("authenticated-context")
            }
            "profile" => {
                source["actions"][0]["evidence"][0]["subjects"]["subject"]["profile"] =
                    json!("wrong")
            }
            "output" => source["actions"][0]["evidence"][0]["outputs"] = json!(["undeclared"]),
            "ambiguous" => {
                let mut duplicate = contract["definitions"][0].clone();
                duplicate["handle"] = json!("other");
                contract["definitions"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            "budget" => {
                let cap = source["actions"][0]["evidence"][0].clone();
                source["actions"][0]["evidence"] = json!([cap, cap, cap]);
            }
            "abi" => source["actions"][0]["handler"]["abi"] = json!("registry.action-handler/v1"),
            "schema" => contract["schema"] = json!("unknown"),
            "bounds" => {
                contract["definitions"][0]["subjects"][0]["selector"]["fields"][0]["minimumBytes"] =
                    json!(9999)
            }
            _ => unreachable!(),
        }
        assert!(compile(source, Some(contract)).is_err(), "{change}");
    }
}
#[test]
fn v2_allows_no_capability_and_contract_paths_are_confined() {
    let mut source = project();
    source["actions"][0]["handler"]["abi"] = json!("registry.action-handler/v2");
    assert!(compile(source, None).unwrap().actions().actions[0]
        .evidence
        .is_empty());
    for path in [
        "/contracts.json",
        "../contracts.json",
        "a//b.json",
        "a/./b.json",
        "a\\b.json",
        "https://example.test/contracts.json",
    ] {
        assert!(!registry_breg::action_evidence_contracts::valid_contract_path(path));
    }
}

#[cfg(all(feature = "tooling", feature = "runtime"))]
#[test]
fn imported_contract_is_sealed_and_rederived() {
    use registry_breg::package::{
        inspect_package_integrity, prepare_package_with_project_assets, PackageBuildRequest,
        PackageMigrationPlanInput, PackageSourceFile, SignaturePolicy,
    };
    let mut source = configured();
    source["package"] = json!({"environment":"local","instanceId":"instance-under-test","sequence":1,"sourceRevision":"compiler-source-revision"});
    let request = PackageBuildRequest {
        environment: "local".into(),
        instance_id: "instance-under-test".into(),
        database_id: "database-under-test".into(),
        sequence: 1,
        prior_revision: None,
        compiler_source_revision: "compiler-source-revision".into(),
        schema_fingerprint: format!("sha256:{}", "2".repeat(64)),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: vec![],
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".into(),
            bytes: serde_json::to_vec(&source).unwrap(),
        },
        modules: vec![],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".into(),
            bytes: b"apiVersion: registry.registrystack.org/breg-journeys/v1\njourneys: []\n"
                .to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    };
    let assets = vec![
        PackageSourceFile {
            path: "handlers/register.rhai".into(),
            bytes: b"fn handle(ctx) { #{effects: []} }".to_vec(),
        },
        PackageSourceFile {
            path: "evidence/contracts.json".into(),
            bytes: serde_json::to_vec(&contracts()).unwrap(),
        },
    ];
    let package = prepare_package_with_project_assets(request.clone(), assets.clone()).unwrap();
    assert!(prepare_package_with_project_assets(request, vec![assets[0].clone()]).is_err());
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let published = temp.path().join("package");
    package.publish_to_directory(&published, vec![]).unwrap();
    inspect_package_integrity(&published).unwrap();
    std::fs::write(
        published.join("source/project/evidence/contracts.json"),
        b"{}",
    )
    .unwrap();
    assert!(inspect_package_integrity(&published).is_err());
}

#[test]
fn invalid_evidence_helper_dispatch_is_refused_offline_even_inside_catch() {
    let source = parse_project_json(&serde_json::to_vec(&configured()).unwrap()).unwrap();
    for call in [
        "evidence::resolve()",
        "evidence::resolve(\"status\")",
        "evidence::resolve(\"status\", #{}, 1)",
        "evidence::other(\"status\", #{})",
        "evidence::nested::resolve(\"status\", #{})",
    ] {
        let script =
            format!("fn handle(ctx) {{ try {{ {call}; }} catch (error) {{ }} #{{effects: []}} }}");
        let assets = vec![
            ModuleAssetSource {
                module: None,
                path: "handlers/register.rhai".into(),
                bytes: script.into_bytes(),
            },
            ModuleAssetSource {
                module: None,
                path: "evidence/contracts.json".into(),
                bytes: serde_json::to_vec(&contracts()).unwrap(),
            },
        ];
        assert!(
            compile_project_with_assets(&source, &[], &assets, CompileProfile::Authoring).is_err(),
            "{call}"
        );
    }
}

#[test]
fn evidence_identifiers_use_the_governed_action_grammar() {
    for id in [
        "",
        "Upper",
        "status/selector",
        "status~selector",
        &"a".repeat(65),
    ] {
        let mut source = configured();
        source["actions"][0]["evidence"][0]["id"] = json!(id);
        assert!(compile(source, Some(contracts())).is_err(), "alias {id}");
        let mut source = configured();
        source["evidenceProviders"][0]["id"] = json!(id);
        source["actions"][0]["evidence"][0]["provider"] = json!(id);
        assert!(compile(source, Some(contracts())).is_err(), "provider {id}");
    }
}
