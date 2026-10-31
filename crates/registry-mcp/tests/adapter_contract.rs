// SPDX-License-Identifier: Apache-2.0
use registry_mcp::adapter::{contract_digest, AdapterContract, InvalidAdapterContract};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};

const API_VERSION: &str = "id.registrystack.org/formats/adapter/effective-contract/v1alpha1";
const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

fn document() -> Value {
    let empty = json!({"type":"object","additionalProperties":false,"properties":{}});
    let problem = json!({
        "type":"object",
        "additionalProperties":false,
        "properties":{"code":{"type":"string"}},
        "required":["code"]
    });
    let protocol_problem = |code: &str, status: u16, title: &str| {
        json!({
            "type":"object",
            "properties":{
                "code":{"const":code},
                "status":{"const":status},
                "title":{"const":title},
                "requestId":{
                    "type":"string",
                    "minLength":32,
                    "maxLength":32,
                    "pattern":"^[0-9a-f]{32}$"
                }
            },
            "required":["code","status","title","requestId"],
            "additionalProperties":false
        })
    };
    let contract = json!({
        "schemaDialect":SCHEMA_DIALECT,
        "project":{"id":"fixture","version":"1"},
        "profileVersion":"1",
        "artifactDeploymentDigest":format!("sha256:{}", "a".repeat(64)),
        "authentication":{
            "scheme":"bearer",
            "audience":"https://adapter.example.invalid/",
            "clientAdmission":"allowlist"
        },
        "authority":{
            "callerMode":"trusted-machine",
            "representedSubject":"unsupported",
            "personalDelegation":"unsupported",
            "targetBinding":"unsupported",
            "rowDisclosureAuthority":"not-granted",
            "fieldDisclosureAuthority":"not-granted"
        },
        "operations":[{
            "id":"records.list",
            "version":"1",
            "bindingId":"read",
            "profileOperationId":"list",
            "method":"GET",
            "path":"/records",
            "support":"served",
            "effect":"read",
            "successStatus":200,
            "input":{"path":empty.clone(),"query":empty.clone()},
            "output":empty,
            "access":{"anyOf":[{"allScopes":["read"]}]}
        }],
        "unserved":[],
        "problemSchema":problem,
        "protocolProblems":{
            "schema":{
                "$schema":SCHEMA_DIALECT,
                "oneOf":[
                    protocol_problem(
                        "adapter.contract.precondition-failed",
                        412,
                        "Effective contract precondition failed"
                    ),
                    protocol_problem(
                        "adapter.contract.unavailable",
                        503,
                        "Effective contract unavailable"
                    )
                ]
            },
            "problems":[
                {
                    "code":"adapter.contract.precondition-failed",
                    "status":412,
                    "title":"Effective contract precondition failed"
                },
                {
                    "code":"adapter.contract.unavailable",
                    "status":503,
                    "title":"Effective contract unavailable"
                }
            ]
        }
    });
    json!({
        "apiVersion":API_VERSION,
        "kind":"AdapterEffectiveContract",
        "digest":contract_digest(&contract).unwrap(),
        "contract":contract
    })
}

fn rehash(document: &mut Value) {
    document["digest"] = json!(contract_digest(&document["contract"]).unwrap());
}

fn parse(document: &Value) -> Result<AdapterContract, InvalidAdapterContract> {
    AdapterContract::parse(
        &serde_json::to_vec(document).unwrap(),
        document["digest"].as_str().unwrap(),
    )
}

#[test]
fn adapter_contract_is_pinned_and_only_effective_reads_can_be_bound() {
    let document = document();
    assert!(parse(&document).is_ok());
    let digest = document["digest"].as_str().unwrap();
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
        rehash(&mut changed);
        assert!(parse(&changed).is_err());
    }
}

#[test]
fn digest_covers_the_domain_envelope_not_only_the_contract_body() {
    let document = document();
    let old_canonical = canonicalize_json(&document["contract"]).unwrap();
    let old_body_only_digest = registry_platform_config::sha256_uri(&old_canonical);
    assert_ne!(document["digest"], old_body_only_digest);

    let mut changed = document;
    changed["digest"] = json!(old_body_only_digest);
    assert!(AdapterContract::parse(
        &serde_json::to_vec(&changed).unwrap(),
        changed["digest"].as_str().unwrap()
    )
    .is_err());
}

#[test]
fn adapter_contract_requires_exact_machine_only_authority_metadata() {
    let baseline = document();
    for pointer in ["/contract/schemaDialect", "/contract/authority"] {
        let mut changed = baseline.clone();
        let (parent, member) = pointer.rsplit_once('/').unwrap();
        changed
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(member);
        rehash(&mut changed);
        assert!(
            parse(&changed).is_err(),
            "missing {pointer} must be refused"
        );
    }

    for (pointer, value) in [
        (
            "/contract/schemaDialect",
            json!("http://json-schema.org/draft-07/schema#"),
        ),
        (
            "/contract/authority/callerMode",
            json!("represented-person"),
        ),
        ("/contract/authority/representedSubject", json!("supported")),
        ("/contract/authority/personalDelegation", json!("supported")),
        (
            "/contract/authority/targetBinding",
            json!("caller-selected"),
        ),
        (
            "/contract/authority/rowDisclosureAuthority",
            json!("granted"),
        ),
        (
            "/contract/authority/fieldDisclosureAuthority",
            json!("granted"),
        ),
    ] {
        let mut changed = baseline.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        rehash(&mut changed);
        assert!(
            parse(&changed).is_err(),
            "non-machine authority at {pointer} must be refused"
        );
    }
}

#[test]
fn adapter_contract_rejects_unsupported_or_missing_success_status() {
    let baseline = document();
    for status in [0, 199, 300, 999] {
        let mut changed = baseline.clone();
        changed["contract"]["operations"][0]["successStatus"] = json!(status);
        rehash(&mut changed);
        assert!(parse(&changed).is_err(), "status {status} must be refused");
    }
    let mut changed = baseline;
    changed["contract"]["operations"][0]
        .as_object_mut()
        .unwrap()
        .remove("successStatus");
    rehash(&mut changed);
    assert!(parse(&changed).is_err());
}

#[test]
fn profile_and_protocol_problem_schemas_are_separate_and_exact() {
    let baseline = document();
    for pointer in ["/contract/problemSchema", "/contract/protocolProblems"] {
        let mut changed = baseline.clone();
        let (parent, member) = pointer.rsplit_once('/').unwrap();
        changed
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(member);
        rehash(&mut changed);
        assert!(
            parse(&changed).is_err(),
            "missing {pointer} must be refused"
        );
    }

    for (pointer, value) in [
        ("/contract/protocolProblems/problems/0/status", json!(503)),
        (
            "/contract/protocolProblems/problems/1/code",
            json!("adapter.contract.precondition-failed"),
        ),
        (
            "/contract/protocolProblems/schema/oneOf/0/properties/title/const",
            json!("Wrong title"),
        ),
        (
            "/contract/protocolProblems/schema/oneOf/1/properties/status/const",
            json!(412),
        ),
    ] {
        let mut changed = baseline.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        rehash(&mut changed);
        assert!(
            parse(&changed).is_err(),
            "protocol mismatch at {pointer} must be refused"
        );
    }
}

#[test]
fn adapter_schema_cannot_fetch_refs_or_accept_extra_arguments() {
    let mut document = document();
    document["contract"]["operations"][0]["input"]["query"] =
        json!({"$ref":"https://schemas.example.invalid/external"});
    rehash(&mut document);
    assert!(parse(&document).is_err());
    let document = self::document();
    let parsed = parse(&document).unwrap();
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
        rehash(&mut changed);
        assert!(parse(&changed).is_err());
    }
    let mut changed = baseline;
    changed["contract"]
        .as_object_mut()
        .unwrap()
        .remove("authentication");
    rehash(&mut changed);
    assert!(parse(&changed).is_err());
}

#[test]
fn nested_reference_keywords_cannot_bypass_schema_review() {
    let mut changed = document();
    changed["contract"]["operations"][0]["input"]["query"] = json!({"type":"object","additionalProperties":false,"properties":{},"not":{"$ref":"#/$defs/x"},"$defs":{"x":{"type":"string"}}});
    rehash(&mut changed);
    assert!(parse(&changed).is_err());
}

#[test]
fn current_paginated_export_constraints_narrow_a_closed_query_object() {
    let mut changed = document();
    changed["contract"]["operations"][0]["input"]["query"] = json!({
        "additionalProperties": false,
        "allOf": [{
            "anyOf": [
                {"required": ["cursor"]},
                {"required": ["limit"]}
            ]
        }],
        "properties": {
            "cursor": {
                "maxLength": 2796,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9_-]+$",
                "type": "string",
                "x-registry-runtime-validation": "The Adapter verifies authenticated cursor bytes and their caller, operation, deployment, filter, and expiry bindings."
            },
            "limit": {
                "maximum": 1000,
                "minimum": 1,
                "type": "integer"
            }
        },
        "required": [],
        "type": "object"
    });
    rehash(&mut changed);

    let parsed = parse(&changed).expect("the current Adapter pagination schema is executable");
    assert!(parsed
        .validate_arguments("records.list", &json!({"path":{},"query":{"limit":10}}))
        .is_ok());
    assert!(parsed
        .validate_arguments("records.list", &json!({"path":{},"query":{}}))
        .is_err());
}

#[test]
fn required_only_branches_need_an_existing_closed_object_shape() {
    let mut changed = document();
    changed["contract"]["operations"][0]["input"]["query"] = json!({
        "anyOf": [
            {"required": ["cursor"]},
            {"required": ["limit"]}
        ]
    });
    rehash(&mut changed);
    assert!(parse(&changed).is_err());

    let mut unknown = document();
    unknown["contract"]["operations"][0]["input"]["query"] = json!({
        "additionalProperties": false,
        "anyOf": [{"required": ["notDeclared"]}],
        "properties": {},
        "type": "object"
    });
    rehash(&mut unknown);
    assert!(parse(&unknown).is_err());
}

#[test]
fn protocol_metadata_uses_closed_semantics_not_literal_array_order() {
    let mut changed = document();
    changed["contract"]["protocolProblems"]["problems"]
        .as_array_mut()
        .unwrap()
        .reverse();
    changed["contract"]["protocolProblems"]["schema"]["oneOf"]
        .as_array_mut()
        .unwrap()
        .reverse();
    for branch in changed["contract"]["protocolProblems"]["schema"]["oneOf"]
        .as_array_mut()
        .unwrap()
    {
        branch["required"].as_array_mut().unwrap().reverse();
    }
    rehash(&mut changed);
    assert!(
        parse(&changed).is_ok(),
        "order-insensitive JSON Schema and tuple arrays preserve the same closed protocol"
    );
}
