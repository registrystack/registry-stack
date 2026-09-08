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

fn membership_source() -> Value {
    let mut source = source();
    source["entities"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"organization", "type":"reference", "target":"organization",
            "classification":"internal"
        }));
    source["entities"].as_array_mut().unwrap().extend([
        json!({"id":"organization", "primaryDataset":"test-dataset", "route":"organizations", "mutationMode":"mutable",
            "fields":[{"id":"label", "type":"string", "maxLength":32, "classification":"internal"}]}),
        json!({"id":"membership", "primaryDataset":"test-dataset", "route":"memberships", "mutationMode":"mutable",
            "fields":[
                {"id":"organization", "type":"reference", "target":"organization", "classification":"internal"},
                {"id":"principal", "type":"string", "maxLength":64, "classification":"internal"},
                {"id":"active", "type":"boolean", "classification":"internal"}
            ]}),
    ]);
    source["accessProfiles"][0]["principalClaim"] = json!("sub");
    let grant = &mut source["accessProfiles"][0]["grants"][0];
    grant["operations"] = json!(["get", "list"]);
    grant["writableFields"] = json!([]);
    grant["rowBoundaries"] = json!([]);
    grant["membershipBoundaries"] = json!([{
        "field":"organization", "membershipEntity":"membership",
        "membershipKeyField":"organization", "principalField":"principal", "activeField":"active"
    }]);
    source
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

#[test]
fn membership_row_reach_is_explicit_and_uses_the_selected_principal() {
    for (boundaries, rows, direct_claims) in [
        (json!([]), "membership_bound", 0),
        (
            json!([{"field":"district", "claim":"districts", "operator":"in"}]),
            "claim_and_membership_bound",
            1,
        ),
    ] {
        let mut source = membership_source();
        source["accessProfiles"][0]["grants"][0]["rowBoundaries"] = boundaries;
        let registry = compile(&source);
        let explanation = registry_breg::access::explain_access(&registry);
        let reach = explanation
            .row_reach
            .iter()
            .find(|reach| reach.entity == "entry" && reach.profile == "clerk")
            .unwrap();
        assert_eq!(reach.rows, rows);
        assert_eq!(reach.membership_boundaries.len(), 1);
        assert_eq!(reach.membership_boundaries[0].principal_field, "principal");
        assert!(!registry.findings().iter().any(|finding| matches!(
            finding.code.as_str(),
            "access.profile.unrestricted_rows" | "access.profile.unrestricted_collection"
        )));
        let claims = explanation.claim_contract.unwrap();
        assert_eq!(claims.principal_claims, ["sub".to_owned()].into());
        assert_eq!(claims.direct_claims.len(), direct_claims);
    }
}

#[test]
fn membership_only_profiles_require_authentication() {
    let mut source = membership_source();
    let profile = &mut source["accessProfiles"][0];
    profile.as_object_mut().unwrap().remove("principalClaim");
    profile["requiredScopes"] = json!([]);
    profile["anonymous"] = json!(true);
    let failure = compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .expect_err("stored membership never grants anonymous record access");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "access.membership.authentication"));
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
#[test]
fn membership_changes_report_authority_narrowing_and_widening() {
    use registry_breg::tooling::{classify_registry_diff, AccessChangeDirection};

    let mut source = membership_source();
    source["entities"][2]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"approved", "type":"boolean", "classification":"internal"}));
    let mut additional =
        source["accessProfiles"][0]["grants"][0]["membershipBoundaries"][0].clone();
    additional["activeField"] = json!("approved");
    let mut boundaries = source["accessProfiles"][0]["grants"][0]["membershipBoundaries"]
        .as_array()
        .unwrap()
        .clone();
    boundaries.push(additional);
    let registries = (0..=2)
        .map(|count| {
            source["accessProfiles"][0]["grants"][0]["membershipBoundaries"] =
                json!(&boundaries[..count]);
            compile(&source)
        })
        .collect::<Vec<_>>();
    for (before, after, expected) in [
        (0, 1, AccessChangeDirection::Narrowing),
        (1, 2, AccessChangeDirection::Narrowing),
        (2, 1, AccessChangeDirection::Widening),
        (1, 0, AccessChangeDirection::Widening),
    ] {
        let diff = classify_registry_diff(&registries[before], &registries[after], "baseline");
        let detail = diff
            .changes
            .iter()
            .flat_map(|change| &change.access_details)
            .find(|detail| detail.field == "membershipBoundaries")
            .expect("changed membership authority is reported");
        assert_eq!(detail.direction, expected, "{before} -> {after}");
    }
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
