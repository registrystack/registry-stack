// SPDX-License-Identifier: Apache-2.0
use registry_mcp::adapter::{
    contract_digest, AdapterContract, AdapterContractLoadError, AdapterToolBinding,
    InvalidAdapterContract,
};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};
use std::collections::BTreeSet;

const API_VERSION: &str = "id.registrystack.org/formats/adapter/effective-contract/v1alpha1";
const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
const PRODUCER_GOLDEN: &[u8] =
    include_bytes!("fixtures/adapter/govstack-facilities/effective-contract.json");
const PRODUCER_GOLDEN_DIGEST: &str =
    "sha256:837055a253b539255465834d1a030b80735360b8d61baf8ba698c5565760804c";
const PRODUCER_GOLDEN_BYTES_DIGEST: &str =
    "sha256:a46ac0a656ee599151c6557c0c233f5b9ecdec4dcfa50403d112153fca9d5a15";
const OPTIONAL_PAGINATION_GOLDEN: &[u8] =
    include_bytes!("fixtures/adapter/optional-pagination/effective-contract.json");
const OPTIONAL_PAGINATION_DIGEST: &str =
    "sha256:e3d9c7fe90cb10b1e6588051d429010ef656ffca96d65721e3c6aabfcc6da591";
const OPTIONAL_PAGINATION_BYTES_DIGEST: &str =
    "sha256:03c9c5f60f49f8d2929752ac5b072e537896148bd3a82000520b138ccaf1a7e8";

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
            "audience":"adapter-example",
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

fn binding(operation: &str, description: &str) -> AdapterToolBinding {
    AdapterToolBinding {
        operation: operation.to_owned(),
        description: description.to_owned(),
    }
}

fn selected(operations: &[&str]) -> BTreeSet<String> {
    operations
        .iter()
        .map(|operation| (*operation).to_owned())
        .collect()
}

#[test]
fn producer_generated_facility_contract_matches_fixed_bytes_and_parses() {
    assert_eq!(
        registry_platform_config::sha256_uri(PRODUCER_GOLDEN),
        PRODUCER_GOLDEN_BYTES_DIGEST
    );
    let selected = selected(&["records-get.facilities", "records-search.facilities"]);
    let contract = AdapterContract::parse_bound(PRODUCER_GOLDEN, PRODUCER_GOLDEN_DIGEST, &selected)
        .expect("the producer-generated Adapter facility export remains compatible");
    let bindings = [
        (
            "get_facility".to_owned(),
            binding("records-get.facilities", "Read one configured facility."),
        ),
        (
            "search_facilities".to_owned(),
            binding("records-search.facilities", "Search configured facilities."),
        ),
    ]
    .into_iter()
    .collect();
    contract
        .validate_binding(&bindings, "adapter-native-proof")
        .expect("the golden facility GET and read-only POST operations remain bindable");
}

#[test]
fn producer_optional_pagination_presence_schema_is_anchored_and_executable() {
    assert_eq!(
        registry_platform_config::sha256_uri(OPTIONAL_PAGINATION_GOLDEN),
        OPTIONAL_PAGINATION_BYTES_DIGEST
    );
    let contract = AdapterContract::parse_bound(
        OPTIONAL_PAGINATION_GOLDEN,
        OPTIONAL_PAGINATION_DIGEST,
        &selected(&["records-search.facilities"]),
    )
    .expect("the producer's optional-pagination read-only POST schema is compatible");
    let baseline = json!({
        "path":{},
        "query":{},
        "body":{
            "search":"byCriteria",
            "criteria":{"org_unit":"synthetic-service-area"}
        }
    });
    assert!(
        contract
            .validate_arguments("records-search.facilities", &baseline)
            .is_err(),
        "the producer requires cursor or pageSize when it has no default"
    );
    for member in [json!({"pageSize":5}), json!({"cursor":"synthetic_cursor"})] {
        let mut arguments = baseline.clone();
        arguments["body"]
            .as_object_mut()
            .unwrap()
            .extend(member.as_object().unwrap().clone());
        contract
            .validate_arguments("records-search.facilities", &arguments)
            .expect("either producer-declared pagination presence branch is valid");
    }
}

#[test]
fn bound_parser_ignores_unselected_future_schema_but_preserves_identity_checks() {
    let mut document: Value = serde_json::from_slice(PRODUCER_GOLDEN).unwrap();
    let operations = document["contract"]["operations"].as_array_mut().unwrap();
    let unselected = operations
        .iter_mut()
        .find(|operation| operation["id"] == "records-search.facilities")
        .unwrap();
    unselected["method"] = json!("PATCH");
    unselected["effect"] = json!("future-effect");
    unselected["output"] = json!({"$ref":"https://future.example.invalid/schema"});
    unselected["futureMetadata"] = json!({"shape":"unknown-to-this-consumer"});
    rehash(&mut document);
    let bytes = serde_json::to_vec(&document).unwrap();

    AdapterContract::parse_bound(
        &bytes,
        document["digest"].as_str().unwrap(),
        &selected(&["records-get.facilities"]),
    )
    .expect("unselected future operation metadata and schema are outside this binding");
    assert!(
        AdapterContract::parse(&bytes, document["digest"].as_str().unwrap()).is_err(),
        "the whole-contract compatibility wrapper still compiles every operation"
    );

    let operations = document["contract"]["operations"].as_array_mut().unwrap();
    let duplicate = operations[2]["id"].clone();
    operations[1]["id"] = duplicate;
    rehash(&mut document);
    assert!(
        AdapterContract::parse_bound(
            &serde_json::to_vec(&document).unwrap(),
            document["digest"].as_str().unwrap(),
            &selected(&["records-get.facilities"]),
        )
        .is_err(),
        "duplicate identities remain invalid even when both operations are unselected"
    );
}

#[test]
fn configured_operation_cap_does_not_cap_the_producer_catalog() {
    let mut document = document();
    let template = document["contract"]["operations"][0].clone();
    let operations = document["contract"]["operations"].as_array_mut().unwrap();
    for index in 1..129 {
        let mut operation = template.clone();
        operation["id"] = json!(format!("records.unselected.{index}"));
        operations.push(operation);
    }
    rehash(&mut document);
    let bytes = serde_json::to_vec(&document).unwrap();
    AdapterContract::parse_bound(
        &bytes,
        document["digest"].as_str().unwrap(),
        &selected(&["records.list"]),
    )
    .expect("one selected operation remains valid in a larger producer catalog");
    assert!(
        AdapterContract::parse(&bytes, document["digest"].as_str().unwrap()).is_err(),
        "the explicit whole-contract wrapper retains the configured 128-operation cap"
    );
}

#[test]
fn selected_operation_metadata_and_direct_descriptions_remain_closed() {
    let mut document = document();
    let digest = document["digest"].as_str().unwrap().to_owned();
    let selected_set = selected(&["records.list"]);
    let contract = AdapterContract::parse_bound(
        &serde_json::to_vec(&document).unwrap(),
        &digest,
        &selected_set,
    )
    .unwrap();
    let empty_description = [("read_records".to_owned(), binding("records.list", ""))]
        .into_iter()
        .collect();
    assert!(contract
        .validate_binding(&empty_description, "adapter-example")
        .is_err());
    for invalid in [
        binding("", "List configured records."),
        binding("records.list", "contains\ncontrol"),
        binding("records.list", &"a".repeat(4097)),
    ] {
        assert!(contract
            .validate_binding(
                &[('x'.to_string(), invalid)].into_iter().collect(),
                "adapter-example",
            )
            .is_err());
    }
    assert!(AdapterContract::parse_bound(
        &serde_json::to_vec(&document).unwrap(),
        &digest,
        &selected(&["records.missing"]),
    )
    .is_err());

    document["contract"]["operations"][0]["effect"] = json!("write");
    rehash(&mut document);
    assert!(
        AdapterContract::parse_bound(
            &serde_json::to_vec(&document).unwrap(),
            document["digest"].as_str().unwrap(),
            &selected_set,
        )
        .is_err(),
        "selected operation read metadata remains enforced"
    );
}

#[test]
fn empty_path_and_query_containers_are_optional_until_their_schema_requires_children() {
    let baseline = document();
    let contract = parse(&baseline).expect("baseline contract");
    contract
        .validate_arguments("records.list", &json!({}))
        .expect("empty path and query containers are optional");

    let mut required_path = baseline;
    required_path["contract"]["operations"][0]["path"] = json!("/records/{record_id}");
    required_path["contract"]["operations"][0]["input"]["path"] = json!({
        "type":"object",
        "additionalProperties":false,
        "properties":{"record_id":{"type":"string"}},
        "required":["record_id"]
    });
    rehash(&mut required_path);
    let contract = parse(&required_path).expect("required path contract");
    assert!(contract
        .validate_arguments("records.list", &json!({}))
        .is_err());
    contract
        .validate_arguments(
            "records.list",
            &json!({"path":{"record_id":"synthetic-record"}}),
        )
        .expect("query remains optional when only path has required children");
}

#[test]
fn checked_loader_distinguishes_unreadable_malformed_and_digest_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let selected_set = selected(&["records.list"]);
    let missing = directory.path().join("missing.json");
    assert_eq!(
        AdapterContract::load_bound_checked(&missing, "sha256:unused", &selected_set)
            .err()
            .expect("missing contract is refused"),
        AdapterContractLoadError::Unreadable
    );

    let malformed = directory.path().join("malformed.json");
    std::fs::write(
        &malformed,
        br#"{"apiVersion":"id.registrystack.org/formats/adapter/effective-contract/v1alpha1","apiVersion":"duplicate","kind":"AdapterEffectiveContract"}"#,
    )
    .unwrap();
    assert_eq!(
        AdapterContract::load_bound_checked(&malformed, "sha256:unused", &selected_set)
            .err()
            .expect("malformed contract is refused"),
        AdapterContractLoadError::Malformed
    );

    let document = document();
    let valid = directory.path().join("valid.json");
    std::fs::write(&valid, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    assert_eq!(
        AdapterContract::load_bound_checked(
            &valid,
            &format!("sha256:{}", "0".repeat(64)),
            &selected_set,
        )
        .err()
        .expect("reviewed digest mismatch is refused"),
        AdapterContractLoadError::DigestMismatch
    );
    assert_eq!(
        AdapterContract::load_bound_checked(
            &valid,
            document["digest"].as_str().unwrap(),
            &selected(&["records.missing"]),
        )
        .err()
        .expect("absent selected operation is refused"),
        AdapterContractLoadError::SelectionMismatch
    );

    let mut malformed_selection = document.clone();
    malformed_selection["contract"]["problemSchema"] =
        json!({"$ref":"https://invalid.example/schema"});
    rehash(&mut malformed_selection);
    let malformed_selection_path = directory.path().join("malformed-selection.json");
    std::fs::write(
        &malformed_selection_path,
        serde_json::to_vec_pretty(&malformed_selection).unwrap(),
    )
    .unwrap();
    assert_eq!(
        AdapterContract::load_bound_checked(
            &malformed_selection_path,
            malformed_selection["digest"].as_str().unwrap(),
            &selected(&["records.missing"]),
        )
        .err()
        .expect("malformed contract takes precedence over selection mismatch"),
        AdapterContractLoadError::Malformed
    );

    let mut unserved_write = document.clone();
    unserved_write["contract"]["unserved"] = json!([{
        "operationId":"records.create",
        "version":"1",
        "bindingId":"create",
        "profileOperationId":"create",
        "method":"POST",
        "support":"unserved",
        "effect":"write",
        "reasonCode":"adapter.operation.gateway-write-disabled",
        "reason":"the external gateway contract does not expose write operations"
    }]);
    rehash(&mut unserved_write);
    let unserved_write_path = directory.path().join("unserved-write.json");
    std::fs::write(
        &unserved_write_path,
        serde_json::to_vec_pretty(&unserved_write).unwrap(),
    )
    .unwrap();
    assert_eq!(
        AdapterContract::load_bound_checked(
            &unserved_write_path,
            unserved_write["digest"].as_str().unwrap(),
            &selected(&["records.create"]),
        )
        .err()
        .expect("selected producer-declared unserved write is refused precisely"),
        AdapterContractLoadError::UnsupportedSelection
    );

    let mut unsupported_selection = document.clone();
    unsupported_selection["contract"]["operations"][0]["effect"] = json!("write");
    unsupported_selection["contract"]["operations"][0]["method"] = json!("POST");
    unsupported_selection["contract"]["operations"][0]["successStatus"] = json!(201);
    unsupported_selection["contract"]["operations"][0]["input"]["body"] = json!({
        "type":"object",
        "additionalProperties":false,
        "properties":{}
    });
    rehash(&mut unsupported_selection);
    let unsupported_selection_path = directory.path().join("unsupported-selection.json");
    std::fs::write(
        &unsupported_selection_path,
        serde_json::to_vec_pretty(&unsupported_selection).unwrap(),
    )
    .unwrap();
    assert_eq!(
        AdapterContract::load_bound_checked(
            &unsupported_selection_path,
            unsupported_selection["digest"].as_str().unwrap(),
            &selected_set,
        )
        .err()
        .expect("selected write operation is refused"),
        AdapterContractLoadError::UnsupportedSelection
    );

    let mut malformed_write = unsupported_selection;
    malformed_write["contract"]["protocolProblems"] = json!({});
    rehash(&mut malformed_write);
    let malformed_write_path = directory.path().join("malformed-write.json");
    std::fs::write(
        &malformed_write_path,
        serde_json::to_vec_pretty(&malformed_write).unwrap(),
    )
    .unwrap();
    assert_eq!(
        AdapterContract::load_bound_checked(
            &malformed_write_path,
            malformed_write["digest"].as_str().unwrap(),
            &selected_set,
        )
        .err()
        .expect("malformed shared protocol takes precedence over unsupported selection"),
        AdapterContractLoadError::Malformed
    );

    let mut inconsistent = document;
    inconsistent["digest"] = json!(format!("sha256:{}", "1".repeat(64)));
    let inconsistent_path = directory.path().join("inconsistent.json");
    std::fs::write(
        &inconsistent_path,
        serde_json::to_vec_pretty(&inconsistent).unwrap(),
    )
    .unwrap();
    assert_eq!(
        AdapterContract::load_bound_checked(
            &inconsistent_path,
            inconsistent["digest"].as_str().unwrap(),
            &selected_set,
        )
        .err()
        .expect("internally inconsistent digest is refused"),
        AdapterContractLoadError::DigestMismatch
    );
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
fn adapter_contract_accepts_only_bounded_opaque_oidc_audiences() {
    let baseline = document();
    let parsed = parse(&baseline).expect("the producer's opaque OIDC audience is valid");
    let bindings = [(
        "Adapter.Record_Read".to_owned(),
        binding("records.list", "List configured records."),
    )]
    .into_iter()
    .collect();
    assert!(parsed
        .validate_binding(&bindings, "adapter-example")
        .is_ok());
    assert!(parsed
        .validate_binding(&bindings, "Adapter-example")
        .is_err());

    for audience in [
        String::new(),
        "contains\ncontrol".to_owned(),
        "a".repeat(513),
    ] {
        let mut changed = baseline.clone();
        changed["contract"]["authentication"]["audience"] = json!(audience);
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
