// SPDX-License-Identifier: Apache-2.0

use registry_breg::{compile_project, parse_project_json, CompileProfile};
use serde_json::{json, Value};

fn source() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"access-explanation","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://access.example.test"},
        "entities":[{"id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable","classification":"internal",
          "fields":[{"id":"district","type":"string","maxLength":32,"classification":"internal"}]}],
        "accessProfiles":[{"id":"clerk","principalClaim":"registry_principal","requiredScopes":["entry:edit"],
          "grants":[{"entity":"entry","operations":["get","patch"],"readableFields":["district"],"writableFields":["district"],
            "rowBoundaries":[{"field":"district","claim":"districts","operator":"in"}]}]}]
    })
}

fn compile(source: &Value) -> registry_breg::CompiledRegistry {
    compile_project(
        &parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap()
}

#[test]
fn access_explanation_connects_row_reach_to_typed_claim_requirements() {
    let registry = compile(&source());
    let explanation =
        serde_json::to_value(registry_breg::access::explain_access(&registry)).unwrap();
    assert_eq!(explanation["rowReach"][0]["rows"], "claim_bound");
    assert_eq!(explanation["rowReach"][0]["profile"], "clerk");
    assert_eq!(explanation["rowReach"][0]["ownerOnlyRequestReads"], false);
    assert_eq!(
        explanation["claimContract"]["directClaims"]["districts"]["multiValue"],
        true
    );
    assert_eq!(
        explanation["claimContract"]["directClaims"]["districts"]["fieldType"]["type"],
        "string"
    );
    assert_eq!(
        explanation["claimContract"]["directClaims"]["districts"]["uses"][0]["entityId"],
        "entry"
    );
    assert!(explanation["claimContractError"].is_null());
    assert!(explanation["evaluation"]
        .as_str()
        .unwrap()
        .contains("not evaluated"));

    let mut broad = source();
    broad["accessProfiles"][0]["grants"][0]["rowBoundaries"] = json!([]);
    let registry = compile(&broad);
    assert!(registry
        .findings()
        .iter()
        .any(|finding| finding.code == "access.profile.unrestricted_rows"));
    let explanation =
        serde_json::to_value(registry_breg::access::explain_access(&registry)).unwrap();
    assert_eq!(explanation["rowReach"][0]["rows"], "all");
    assert_eq!(
        explanation["entities"][0]["profiles"][0]["operations"],
        json!(["get", "patch"])
    );
}

#[test]
fn access_explanation_includes_nested_target_authority_and_owner_read_limits() {
    let project = registry_breg::contract::parse_project_yaml(include_bytes!(
        "../../../products/breg/acceptance/asset-site-placement-change-requests/registry.yaml"
    ))
    .unwrap();
    let registry = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let explanation = registry_breg::access::explain_access(&registry);
    for surface in ["review_target", "apply_target", "request_presence"] {
        let reach = explanation
            .row_reach
            .iter()
            .find(|reach| reach.surface == surface)
            .unwrap();
        assert_eq!(reach.rows, "all");
        assert!(registry
            .findings()
            .iter()
            .any(|finding| finding.code == "access.target.unrestricted_rows"
                && finding.path == reach.source_path));
    }
    let owner = explanation
        .row_reach
        .iter()
        .find(|reach| {
            reach.entity == "placement-correction-request"
                && reach.profile == "correction-submitter"
        })
        .unwrap();
    assert!(owner.owner_only_request_reads);
    assert_eq!(
        owner.rows, "all",
        "ownership applies to reads, not every granted operation"
    );
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
#[test]
fn synthetic_own_record_preview_reuses_principal_and_refuses_identity_override() {
    let mut source = source();
    source["accessProfiles"][0]["grants"][0]["rowBoundaries"] =
        json!([{"field":"district","claim":"registry_principal","operator":"equals"}]);
    let registry = compile(&source);
    let mut scenario = json!({
        "entity":"entry", "accessProfile":"clerk", "operation":"get",
        "claims":{"principalClaim":"registry_principal", "principal":"synthetic-clerk", "scopes":["entry:edit"]}
    });
    let preview = registry_breg::access_preview::preview_access(
        &registry,
        serde_json::from_value(scenario.clone()).unwrap(),
    )
    .unwrap();
    assert!(preview.admitted);
    assert_eq!(preview.record_access, "not_evaluated");
    scenario["claims"]["directClaims"] = json!({"registry_principal":"different-clerk"});
    assert!(registry_breg::access_preview::preview_access(
        &registry,
        serde_json::from_value(scenario).unwrap()
    )
    .is_err());
}
