// SPDX-License-Identifier: Apache-2.0
use registry_mcp::adapter::{contract_digest, AdapterContract};
use serde_json::{json, Value};

fn document() -> Value {
    let empty = json!({"type":"object","additionalProperties":false,"properties":{}});
    let contract = json!({
        "project":{"id":"fixture","version":"1"},"profileVersion":"1",
        "artifactDeploymentDigest":format!("sha256:{}", "a".repeat(64)),
        "authentication":{"scheme":"bearer","audience":"https://adapter.example.invalid/","clientAdmission":"allowlist"},
        "operations":[{"id":"records.list","version":"1","bindingId":"read","profileOperationId":"list","method":"GET","path":"/records","support":"served","effect":"read","input":{"path":empty.clone(),"query":empty.clone()},"output":empty.clone(),"access":{"anyOf":[{"allScopes":["read"]}]}}],
        "unserved":[],"problemSchema":empty
    });
    json!({"apiVersion":"id.registrystack.org/formats/adapter/effective-contract/v1alpha1","kind":"AdapterEffectiveContract","digest":contract_digest(&contract).unwrap(),"contract":contract})
}

#[test]
fn adapter_contract_is_pinned_and_only_effective_reads_can_be_bound() {
    let document = document();
    let bytes = serde_json::to_vec(&document).unwrap();
    let digest = document["digest"].as_str().unwrap();
    assert!(AdapterContract::parse(&bytes, digest).is_ok());
    let mut drifted = document.clone();
    drifted["contract"]["operations"][0]["path"] = json!("/another-route");
    assert!(AdapterContract::parse(&serde_json::to_vec(&drifted).unwrap(), digest).is_err());
    for (member, value) in [
        ("effect", json!("write")),
        ("support", json!("unserved")),
        ("method", json!("PUT")),
    ] {
        let mut changed = document.clone();
        changed["contract"]["operations"][0][member] = value;
        changed["digest"] = json!(contract_digest(&changed["contract"]).unwrap());
        assert!(AdapterContract::parse(
            &serde_json::to_vec(&changed).unwrap(),
            changed["digest"].as_str().unwrap()
        )
        .is_err());
    }
}

#[test]
fn adapter_schema_cannot_fetch_refs_or_accept_extra_arguments() {
    let mut document = document();
    document["contract"]["operations"][0]["input"]["query"] =
        json!({"$ref":"https://schemas.example.invalid/external"});
    document["digest"] = json!(contract_digest(&document["contract"]).unwrap());
    assert!(AdapterContract::parse(
        &serde_json::to_vec(&document).unwrap(),
        document["digest"].as_str().unwrap()
    )
    .is_err());
    let document = self::document();
    let parsed = AdapterContract::parse(
        &serde_json::to_vec(&document).unwrap(),
        document["digest"].as_str().unwrap(),
    )
    .unwrap();
    assert!(parsed
        .validate_arguments("records.list", &json!({"path":{},"query":{}}))
        .is_ok());
    assert!(parsed
        .validate_arguments(
            "records.list",
            &json!({"path":{},"query":{},"url":"https://elsewhere.invalid"})
        )
        .is_err());
}

#[test]
fn duplicate_json_members_are_refused() {
    let document = document();
    let bytes = serde_json::to_string(&document).unwrap().replacen(
        "\"kind\":",
        "\"kind\":\"ignored\",\"kind\":",
        1,
    );
    assert!(
        AdapterContract::parse(bytes.as_bytes(), document["digest"].as_str().unwrap()).is_err()
    );
}

#[test]
fn adapter_contract_rejects_missing_authentication_and_open_schema_branches() {
    let baseline = document();
    for schema in [
        json!({"type":["object","null"]}),
        json!({"anyOf":[{"type":"string"},{"type":"object"}]}),
        json!({"$dynamicRef":"https://elsewhere.invalid/schema"}),
    ] {
        let mut changed = baseline.clone();
        changed["contract"]["operations"][0]["input"]["query"] = schema;
        changed["digest"] = json!(contract_digest(&changed["contract"]).unwrap());
        assert!(AdapterContract::parse(
            &serde_json::to_vec(&changed).unwrap(),
            changed["digest"].as_str().unwrap()
        )
        .is_err());
    }
    let mut changed = baseline;
    changed["contract"]
        .as_object_mut()
        .unwrap()
        .remove("authentication");
    changed["digest"] = json!(contract_digest(&changed["contract"]).unwrap());
    assert!(AdapterContract::parse(
        &serde_json::to_vec(&changed).unwrap(),
        changed["digest"].as_str().unwrap()
    )
    .is_err());
}

#[test]
fn nested_reference_keywords_cannot_bypass_schema_review() {
    let mut changed = document();
    changed["contract"]["operations"][0]["input"]["query"] = json!({"type":"object","additionalProperties":false,"properties":{},"not":{"$ref":"#/$defs/x"},"$defs":{"x":{"type":"string"}}});
    changed["digest"] = json!(contract_digest(&changed["contract"]).unwrap());
    assert!(AdapterContract::parse(
        &serde_json::to_vec(&changed).unwrap(),
        changed["digest"].as_str().unwrap()
    )
    .is_err());
}
