// SPDX-License-Identifier: Apache-2.0

use registry_adapter_core::AdapterPack;
use registry_adapter_engine::{
    artifacts::PackArtifactBytes,
    evidence::{compile_evidence_pack, EvidenceCompileError, EvidenceLimits},
};
use registry_platform_config::sha256_uri;
use serde_json::json;

fn pack_with_steps(steps: serde_json::Value) -> (AdapterPack, PackArtifactBytes) {
    let inputs = serde_json::to_vec(&json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {}
    }))
    .expect("input schema");
    let facts = serde_json::to_vec(&json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"active": {"type": "boolean"}},
        "required": ["active"]
    }))
    .expect("facts schema");
    let mut pack = json!({
        "id": "static-budget",
        "version": "1",
        "testedVersions": [],
        "endpoints": [{
            "id": "register",
            "component": "http",
            "authentication": {"type": "none"},
            "attemptTimeoutMilliseconds": 1000,
            "maximumResponseBytes": 4096,
            "operations": []
        }],
        "sourceRoutes": [{
            "id": "lookup",
            "evidence": {
                "inputsSchema": {
                    "path": "schemas/inputs.json",
                    "digest": sha256_uri(&inputs)
                },
                "factsSchema": {
                    "path": "schemas/facts.json",
                    "digest": sha256_uri(&facts)
                }
            },
            "steps": []
        }]
    });
    pack["sourceRoutes"][0]["steps"] = steps;
    let pack = serde_json::from_value(pack).expect("pack");
    let artifacts = PackArtifactBytes::new([
        ("schemas/inputs.json".to_owned(), inputs),
        ("schemas/facts.json".to_owned(), facts),
    ]);
    (pack, artifacts)
}

fn three_operation_pack() -> (AdapterPack, PackArtifactBytes) {
    pack_with_steps(json!([
        {"to": {"uri": "http:register", "parameters": {
            "httpMethod": "GET", "path": "/first"
        }}},
        {"to": {"uri": "http:register", "parameters": {
            "httpMethod": "GET", "path": "/second"
        }}},
        {"to": {"uri": "http:register", "parameters": {
            "httpMethod": "GET", "path": "/third"
        }}},
        {"setBody": {"constant": {
            "lookup": "matched", "facts": {"active": true}
        }}}
    ]))
}

#[test]
fn compile_refuses_a_route_above_the_effective_operation_budget() {
    let (pack, artifacts) = three_operation_pack();
    let limits = EvidenceLimits::try_new(2, 30_000, 1024 * 1024).expect("limits");
    assert!(matches!(
        compile_evidence_pack(&pack, "lookup", &artifacts, limits),
        Err(EvidenceCompileError::StaticOperationBudgetExceeded {
            required: 3,
            maximum: 2,
        })
    ));
}

#[test]
fn compile_accepts_a_route_at_the_effective_operation_budget() {
    let (pack, artifacts) = three_operation_pack();
    let limits = EvidenceLimits::try_new(3, 30_000, 1024 * 1024).expect("limits");
    assert!(compile_evidence_pack(&pack, "lookup", &artifacts, limits).is_ok());
}

#[test]
fn compile_refuses_an_uncountable_route() {
    let mut steps = json!([{"to": {"uri": "http:register", "parameters": {
        "httpMethod": "GET", "path": "/record"
    }}}]);
    for _ in 0..=registry_platform_yaml::MAXIMUM_DEPTH {
        steps = json!([{"filter": {"constant": true, "steps": steps}}]);
    }
    let (pack, artifacts) = pack_with_steps(steps);
    assert!(matches!(
        compile_evidence_pack(&pack, "lookup", &artifacts, EvidenceLimits::default()),
        Err(EvidenceCompileError::StaticOperationBudgetUncountable)
    ));
}

#[test]
fn compile_refuses_an_arithmetic_overflow_even_with_the_largest_budget() {
    let mut steps = json!([{"to": {"uri": "http:register", "parameters": {
        "httpMethod": "GET", "path": "/record"
    }}}]);
    for _ in 0..4 {
        steps =
            json!([{"loop": {"constant": 100000, "maximumIterations": 100000, "steps": steps}}]);
    }
    let (pack, artifacts) = pack_with_steps(steps);
    let limits = EvidenceLimits::try_new(u64::MAX, 30_000, 1024 * 1024).expect("finite limits");
    assert!(matches!(
        compile_evidence_pack(&pack, "lookup", &artifacts, limits),
        Err(EvidenceCompileError::StaticOperationBudgetUncountable)
    ));
}
