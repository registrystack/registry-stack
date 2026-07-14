use proptest::prelude::*;
use registry_platform_crypto::{canonicalize_json, parse_json_strict};
use registry_platform_httputil::destination::{
    DestinationAuthorizationValue, DestinationDnsFamily,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;
use crate::source_plan::artifact::{
    derive_consultation_policy, json_string_max_bytes, ResponseSchemaFieldDocument,
};

const PACK_DOMAIN: &[u8] = b"registry.relay.integration-pack.v1\0";
const POLICY_DOMAIN: &[u8] = b"registry.relay.consultation-policy.v1\0";
const CONTRACT_DOMAIN: &[u8] = b"registry.relay.consultation-contract.v1\0";
const BINDING_DOMAIN: &[u8] = b"registry.relay.consultation-binding.v1\0";
const SYNTHETIC_CONFORMANCE_EVIDENCE: &[u8] = b"synthetic registry conformance evidence v1\n";
const SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE: &[u8] =
    b"synthetic registry negative security evidence v1\n";
const SYNTHETIC_MINIMIZATION_EVIDENCE: &[u8] = b"synthetic registry minimization proof v1\n";

#[test]
fn fixed_source_purpose_requires_one_exact_profile_purpose() {
    assert!(exact_profile_bound_source_purpose(
        &["benefit-verification".to_owned()],
        "benefit-verification"
    ));
    assert!(!exact_profile_bound_source_purpose(
        &[
            "benefit-verification".to_owned(),
            "case-management".to_owned(),
        ],
        "benefit-verification"
    ));
    assert!(!exact_profile_bound_source_purpose(
        &["case-management".to_owned()],
        "benefit-verification"
    ));
}

// These exact portable inputs are also verified by `verify-vectors.mjs`.
// Changing one requires an artifact schema/version decision, not a snapshot refresh.
const VECTOR_MANIFEST: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/manifest.json");
const VECTOR_PACK: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/integration-pack.json");
const VECTOR_POLICY: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/consultation-policy.json");
const VECTOR_POLICY_UTF8_ORDERING: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/consultation-policy-utf8-ordering.json");
const VECTOR_CONTRACT: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/public-contract.json");
const VECTOR_CONTRACT_UTF8_ORDERING: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/public-contract-utf8-ordering.json");
const VECTOR_BINDING: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/private-binding.json");
const SNAPSHOT_EXACT_COMPILER_VECTORS: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/snapshot-exact-compiler-vectors.json");
const DHIS2_PACK: &[u8] =
    include_bytes!("../../../profiles/dhis2-2.41.9-enrollment-status/integration-pack.json");
const DHIS2_CONTRACT: &[u8] =
    include_bytes!("../../../profiles/dhis2-2.41.9-enrollment-status/public-contract.json");
const DHIS2_BINDING: &[u8] =
    include_bytes!("../../../profiles/dhis2-2.41.9-enrollment-status/private-binding.example.json");
const DHIS2_CONFORMANCE: &[u8] =
    include_bytes!("../../../profiles/dhis2-2.41.9-enrollment-status/evidence/conformance.json");
const DHIS2_NEGATIVE_SECURITY: &[u8] = include_bytes!(
    "../../../profiles/dhis2-2.41.9-enrollment-status/evidence/negative-security.json"
);
const DHIS2_MINIMIZATION: &[u8] =
    include_bytes!("../../../profiles/dhis2-2.41.9-enrollment-status/evidence/minimization.json");
const OPENCRVS_PACK: &[u8] = include_bytes!(
    "../../../profiles/opencrvs-1.9.0-rc.1-farajaland-birth-record-exists/integration-pack.json"
);
const OPENCRVS_CONTRACT: &[u8] = include_bytes!(
    "../../../profiles/opencrvs-1.9.0-rc.1-farajaland-birth-record-exists/public-contract.json"
);
const OPENCRVS_BINDING: &[u8] = include_bytes!(
    "../../../profiles/opencrvs-1.9.0-rc.1-farajaland-birth-record-exists/private-binding.example.json"
);
const OPENCRVS_CONFORMANCE: &[u8] = include_bytes!(
    "../../../profiles/opencrvs-1.9.0-rc.1-farajaland-birth-record-exists/evidence/conformance.json"
);
const OPENCRVS_NEGATIVE_SECURITY: &[u8] = include_bytes!(
    "../../../profiles/opencrvs-1.9.0-rc.1-farajaland-birth-record-exists/evidence/negative-security.json"
);
const OPENCRVS_MINIMIZATION: &[u8] = include_bytes!(
    "../../../profiles/opencrvs-1.9.0-rc.1-farajaland-birth-record-exists/evidence/minimization.json"
);
const DHIS2_PACK_HASH: &str =
    "sha256:3ebf1e17fba13e4071101a162ad53311e1a7404bea8e2624ec8621aa9d0ac997";
const DHIS2_POLICY_HASH: &str =
    "sha256:d9a93a8723464f8223db688ec7b9029a546b095687357344c5cc79cb9e8a1afe";
const DHIS2_CONTRACT_HASH: &str =
    "sha256:5204b26c004cdeb7530012ee00877e184854ed223cfdaa27fd82925117512a32";
const DHIS2_BINDING_HASH: &str =
    "sha256:2195fdb4b47ef523b3c23b45329d6cfaca9d32a2e6c5b2de6fbb520c5fbcb3ca";
const OPENCRVS_PACK_HASH: &str =
    "sha256:1756f16b1c496e11be1069831ea4f54d8953466ed62bb48efc9f0c7e7def8768";
const OPENCRVS_POLICY_HASH: &str =
    "sha256:d59063f01480bbe00781eacce6e2fea47e27319b8f254315ec796b4295a46507";
const OPENCRVS_CONTRACT_HASH: &str =
    "sha256:c86ebb8e721fe74a26b5c1726779e352ff120003c503b1a8e45740554218d583";
const OPENCRVS_BINDING_HASH: &str =
    "sha256:84d37eff9db4c95a1b35287087f7d40c9f7d017fd92262cfe8caee3c0bc087b1";

fn vector_manifest() -> &'static Value {
    static MANIFEST: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    MANIFEST.get_or_init(|| parse_json_strict(VECTOR_MANIFEST).expect("strict vector manifest"))
}

fn vector_entry(name: &str) -> &'static Value {
    vector_manifest()["vectors"]
        .as_array()
        .expect("vector manifest array")
        .iter()
        .find(|entry| entry["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("missing vector entry {name}"))
}

fn vector_expected_hash(name: &str) -> &'static str {
    vector_entry(name)["expected_hash"]
        .as_str()
        .expect("vector expected hash")
}

struct Fixture {
    contract_value: Value,
    pack_value: Value,
    binding_value: Value,
    contract: Vec<u8>,
    pack: Vec<u8>,
    binding: Vec<u8>,
    contract_hash: String,
    pack_hash: String,
}

impl Fixture {
    fn refresh_all(&mut self) {
        self.pack = serde_json::to_vec(&self.pack_value).expect("pack JSON");
        self.pack_hash = typed_hash(PACK_DOMAIN, &self.pack);
        self.contract_value["spec"]["integration_pack"]["hash"] =
            Value::String(self.pack_hash.clone());
        self.binding_value["integration_pack"]["hash"] = Value::String(self.pack_hash.clone());
        refresh_policy_hash(&mut self.contract_value);
        self.contract = serde_json::to_vec(&self.contract_value).expect("contract JSON");
        self.contract_hash = typed_hash(CONTRACT_DOMAIN, &self.contract);
        self.binding = serde_json::to_vec(&self.binding_value).expect("binding JSON");
    }

    fn refresh_binding(&mut self) {
        self.binding = serde_json::to_vec(&self.binding_value).expect("binding JSON");
    }
}

fn policy_preimage_value(contract: &Value) -> Value {
    let authorization = &contract["spec"]["authorization"];
    let policy = &authorization["policy"];
    json!({
        "schema": "registry.relay.consultation-policy.v1",
        "enforcement_profile": "registry.relay.consultation-pdp/v1",
        "rule_set": "registry.relay.consultation-policy-rules.v1",
        "id": policy["id"].clone(),
        "action": "consultation_execute",
        "target": {
            "profile": {
                "id": contract["id"].clone(),
                "version": contract["version"].clone()
            },
            "integration_pack": contract["spec"]["integration_pack"].clone()
        },
        "authorization": {
            "workload": authorization["workload"].clone(),
            "required_scope": authorization["required_scope"].clone(),
            "purposes": authorization["purposes"].clone(),
            "legal_basis": authorization["legal_basis"].clone(),
            "consent": authorization["consent"].clone(),
            "mandatory_obligations": authorization["mandatory_obligations"].clone()
        },
        "decision": {
            "permit": "unqualified",
            "decision_cache": policy["decision_cache"].clone(),
            "max_decision_age_ms": policy["max_decision_age_ms"].clone(),
            "unavailable": policy["unavailable"].clone()
        }
    })
}

fn refresh_policy_hash(contract: &mut Value) {
    let preimage = serde_json::to_vec(&policy_preimage_value(contract)).expect("policy preimage");
    contract["spec"]["authorization"]["policy"]["hash"] =
        Value::String(typed_hash(POLICY_DOMAIN, &preimage));
}

fn sync_complete_acquisition_from_responses(fixture: &mut Fixture) {
    let mut complete = serde_json::Map::new();
    for operation in fixture.pack_value["spec"]["plan"]["operations"]
        .as_array()
        .expect("operations")
    {
        let response = &operation["response"];
        let fields = match response["normalization"].as_str() {
            Some("json_object") => &response["schema"]["fields"],
            Some("json_array_probe_two") => &response["schema"]["items"]["fields"],
            Some("json_object_array_probe_two") => {
                let records_field = response["records_field"]
                    .as_str()
                    .expect("wrapper records field");
                &response["schema"]["fields"][records_field]["schema"]["items"]["fields"]
            }
            _ => panic!("known response normalization"),
        }
        .as_object()
        .expect("record fields");
        for (name, field) in fields {
            let schema = field["schema"].clone();
            if let Some(prior) = complete.insert(name.clone(), schema.clone()) {
                assert_eq!(prior, schema, "duplicate source field schema");
            }
        }
    }
    let complete = Value::Object(complete);
    fixture.pack_value["spec"]["acquisition"]["fields"] = complete.clone();
    fixture.contract_value["spec"]["acquisition"]["fields"] = complete;
}

fn fixture() -> Fixture {
    let pack = VECTOR_PACK.to_vec();
    let pack_value = parse_json_strict(&pack).expect("strict portable pack JSON");
    let pack_hash = typed_hash(PACK_DOMAIN, &pack);
    assert_eq!(pack_hash, vector_expected_hash("integration_pack"));

    let contract = VECTOR_CONTRACT.to_vec();
    let contract_value = parse_json_strict(&contract).expect("strict portable contract JSON");
    assert_eq!(
        contract_value["spec"]["authorization"]["policy"]["hash"].as_str(),
        Some(vector_expected_hash("consultation_policy"))
    );
    let contract_hash = typed_hash(CONTRACT_DOMAIN, &contract);
    assert_eq!(contract_hash, vector_expected_hash("public_contract"));

    let binding = VECTOR_BINDING.to_vec();
    let binding_value = parse_json_strict(&binding).expect("strict portable binding JSON");
    assert_eq!(
        typed_hash(BINDING_DOMAIN, &binding),
        vector_expected_hash("private_binding")
    );

    Fixture {
        contract_value,
        pack_value,
        binding_value,
        contract,
        pack,
        binding,
        contract_hash,
        pack_hash,
    }
}

fn open_crvs_fixture() -> Fixture {
    let mut fixture = fixture();
    let input = json!({
        "role": "selector",
        "type": "string",
        "maxLength": 32,
        "x-registry-max-bytes": 128,
        "pattern": "^[0-9]+$",
        "x-registry-canonicalization": "identity"
    });
    fixture.pack_value["spec"]["input_slots"] = json!({"uin": input.clone()});
    fixture.contract_value["spec"]["inputs"] = json!({"uin": input});

    let record_schema = json!({
        "type": "object",
        "nullable": false,
        "reject_unknown_fields": true,
        "fields": {
            "id": {
                "required": true,
                "schema": {"type": "string", "nullable": false, "max_bytes": 256}
            },
            "name": {
                "required": false,
                "schema": {
                    "type": "array",
                    "nullable": false,
                    "max_items": 8,
                    "items": {
                        "type": "object",
                        "nullable": false,
                        "reject_unknown_fields": true,
                        "fields": {
                            "use": {
                                "required": false,
                                "schema": {"type": "string", "nullable": false, "max_bytes": 64}
                            },
                            "text": {
                                "required": false,
                                "schema": {"type": "string", "nullable": false, "max_bytes": 512}
                            }
                        }
                    }
                }
            }
        }
    });
    let acquisition = json!({
        "class": "bounded_full_record",
        "fields": {"record": record_schema.clone()}
    });
    fixture.pack_value["spec"]["acquisition"] = acquisition.clone();
    fixture.contract_value["spec"]["acquisition"] = acquisition;
    fixture.pack_value["spec"]["reviewed_acquisition"] = json!({
        "class": "bounded_full_record",
        "fields": {"record": record_schema.clone()},
        "control_fields": {},
        "selector": {
            "type": "http_exact_and",
            "operation": "opencrvs-search",
            "components": {
                "uin": {"type": "codec", "role": "dci_exact_predicate"}
            }
        },
        "cardinality": "probe_two",
        "reject_unknown_fields": true
    });
    fixture.pack_value["spec"]["output"] = json!({});
    fixture.contract_value["spec"]["output"] = json!({});

    fixture.pack_value["spec"]["plan"]["operations"] = json!([{
        "id": "opencrvs-search",
        "method": "READ_ONLY_POST",
        "destination_slot": "registry-data",
        "path": "/registry/sync/search",
        "query": {},
        "headers": {},
        "body": null,
        "request_codec": "dci_exact_v1",
        "dci": {
            "protocol_version": "1.0.0",
            "sender_id": "registry-relay",
            "registry_type": "ns:org:RegistryType:Civil",
            "registry_event_type": "birth",
            "record_type": "spdci-extensions-dci:Person",
            "identifier_type": "UIN",
            "exact_and": {
                "uin": {"field": "UIN", "response_pointer": "/identifier/0/identifier_value"}
            },
            "locale": "eng",
            "page_number": 1,
            "jwks_operation": "fetch-signing-keys",
            "response_verifier": "dci_jws_v1"
        },
        "step_limits": {
            "max_request_bytes": 16384,
            "timeout_ms": 10000,
            "max_in_flight": 1
        },
        "auth": {"mode": "oauth_client_credentials"},
        "acquisition_fields": [],
        "control_fields": [],
        "projection": {"mechanism": "bounded_full_record"},
        "response": {
            "max_bytes": 65536,
            "max_records": 2,
            "normalization": "json_array_probe_two",
            "cardinality": {"mechanism": "dci_probe_two"},
            "schema": {
                "type": "array",
                "nullable": false,
                "max_items": 2,
                "items": {
                    "type": "object",
                    "nullable": false,
                    "reject_unknown_fields": true,
                    "fields": {
                        "record": {"required": true, "schema": record_schema}
                    }
                }
            },
            "accepted_statuses": [200],
            "output_mapping": {}
        }
    }]);
    fixture.pack_value["spec"]["plan"]["verification_destination_slot"] =
        json!("registry-verification");
    fixture.pack_value["spec"]["plan"]["verification_operations"] = json!([{
        "id": "fetch-signing-keys",
        "primitive": "jwks_v1",
        "destination_slot": "registry-verification",
        "method": "GET",
        "path": "/.well-known/jwks.json",
        "step_limits": {
            "max_request_bytes": 16384,
            "timeout_ms": 10000,
            "max_in_flight": 1
        },
        "max_response_bytes": 65536,
        "accepted_statuses": [200]
    }]);
    fixture.pack_value["spec"]["plan"]["steps"] = json!(["opencrvs-search"]);
    fixture.pack_value["spec"]["plan"]
        .as_object_mut()
        .expect("plan")
        .remove("step_conditions");
    let credential_request = fixture.pack_value["spec"]["plan"]["credential_operation"]["request"]
        .as_object_mut()
        .expect("credential request");
    credential_request.remove("audience");
    credential_request.remove("scopes");
    credential_request["timeout_ms"] = json!(10_000);
    fixture.pack_value["spec"]["plan"]["credential_operation"]["path"] =
        json!("/oauth2/client/token");
    fixture.pack_value["spec"]["plan"]["credential_operation"]["response"] = json!({
        "max_bytes": 16384,
        "accepted_statuses": [200],
        "schema": "strict_access_token_bearer_no_expiry",
        "access_token_max_bytes": 4089,
        "token_type": "Bearer",
        "cache_mode": "disabled"
    });
    fixture.pack_value["spec"]["bounds"]["max_data_exchanges"] = json!(2);
    fixture.pack_value["spec"]["bounds"]["max_source_bytes"] = json!(180_224);
    fixture.pack_value["spec"]["bounds"]["timeout_ms"] = json!(20_000);
    fixture.contract_value["spec"]["bounds"] = fixture.pack_value["spec"]["bounds"].clone();
    fixture.pack_value["spec"]["deployment_parameters"] = json!({});
    fixture.binding_value["deployment_parameters"] = json!({});
    fixture.binding_value["credential_destination"]["origin"] =
        fixture.binding_value["data_destination"]["origin"].clone();
    fixture.binding_value["verification_destination"] =
        fixture.binding_value["data_destination"].clone();
    fixture.binding_value["verification_destination"]["id"] =
        json!("registry-verification-private");
    fixture.binding_value["limits"]["max_source_bytes"] = json!(180_224);
    fixture.binding_value["limits"]["timeout_ms"] = json!(20_000);
    fixture.binding_value["limits"]
        .as_object_mut()
        .expect("binding limits")
        .remove("max_token_lifetime_ms");
    fixture.refresh_all();
    fixture
}

fn signed_dci_script_fixture() -> Fixture {
    let mut fixture = open_crvs_fixture();
    let outputs = json!({
        "found": {"type": "boolean", "nullable": false}
    });
    fixture.pack_value["spec"]["output"] = outputs.clone();
    fixture.contract_value["spec"]["output"] = outputs.clone();
    fixture.pack_value["spec"]["acquisition"]["fields"] = outputs.clone();
    fixture.contract_value["spec"]["acquisition"]["fields"] = outputs.clone();
    fixture.pack_value["spec"]["reviewed_acquisition"]["fields"] = outputs;
    let dci = fixture.pack_value["spec"]["plan"]["operations"][0]["dci"].clone();
    let plan = fixture.pack_value["spec"]["plan"]
        .as_object_mut()
        .expect("signed DCI Script plan");
    plan.remove("operations");
    plan.remove("steps");
    plan.remove("step_conditions");
    plan.insert("kind".to_owned(), json!("script"));
    plan.insert(
        "script_authority".to_owned(),
        json!({
            "allow": [{
                "method": "READ_ONLY_POST",
                "path": "/registry/sync/search",
                "semantics": "read_only",
            }],
            "request_headers": [],
            "response_headers": [],
            "response": { "format": "json", "max_bytes": 262_144 },
            "auth": { "mode": "oauth_client_credentials" },
            "request_max_bytes": 16_384,
            "signed_dci": dci,
        }),
    );
    let script = "fn consult(ctx) { result.no_match() }";
    plan.insert(
        "rhai".to_owned(),
        json!({
            "script": script,
            "script_hash": raw_hash(script.as_bytes()),
            "entrypoint": "consult",
            "abi": crate::rhai_worker::xw::XW_ABI_VERSION,
            "memory_bytes": 67_108_864,
            "cpu_ms": 500,
            "ipc_frame_bytes": 131_072,
            "instructions": 50_000,
            "call_depth": 8,
            "string_bytes": 32_768,
            "array_items": 256,
            "map_entries": 256,
            "output_bytes": 32_768,
            "concurrency": 1,
        }),
    );
    fixture.pack_value["spec"]["reviewed_acquisition"]["selector"] = Value::Null;
    fixture.pack_value["spec"]["plan"]["credential_operation"]["response"]["max_bytes"] =
        json!(8_192);
    fixture.pack_value["spec"]["bounds"]["max_source_bytes"] = json!(335_872);
    fixture.contract_value["spec"]["bounds"]["max_source_bytes"] = json!(335_872);
    fixture.binding_value["limits"]["max_source_bytes"] = json!(335_872);
    fixture.contract_value["spec"]["runtime"] = json!({
        "platform_profile": "registry-stack.consultation.v1",
        "source_capability": "script",
        "script_abi": crate::rhai_worker::xw::XW_ABI_VERSION,
    });
    fixture.binding_value["capabilities"]["allow_script"] = json!(true);
    fixture.binding_value["capabilities"]["script"] = json!({
        "max_calls": 1,
        "memory_bytes": 67_108_864,
        "cpu_ms": 500,
        "ipc_frame_bytes": 131_072,
        "instructions": 50_000,
        "call_depth": 8,
        "string_bytes": 32_768,
        "array_items": 256,
        "map_entries": 256,
        "output_bytes": 32_768,
        "concurrency": 1,
        "isolation": "one_shot_worker_v1",
    });
    fixture.refresh_all();
    fixture
}

fn dhis2_fixture() -> Fixture {
    let pack = DHIS2_PACK.to_vec();
    let pack_value = parse_json_strict(&pack).expect("strict DHIS2 pack JSON");
    let pack_hash = typed_hash(PACK_DOMAIN, &pack);
    let contract = DHIS2_CONTRACT.to_vec();
    let contract_value = parse_json_strict(&contract).expect("strict DHIS2 contract JSON");
    let contract_hash = typed_hash(CONTRACT_DOMAIN, &contract);
    let binding = DHIS2_BINDING.to_vec();
    let binding_value = parse_json_strict(&binding).expect("strict DHIS2 binding JSON");
    Fixture {
        contract_value,
        pack_value,
        binding_value,
        contract,
        pack,
        binding,
        contract_hash,
        pack_hash,
    }
}

fn maintained_opencrvs_fixture() -> Fixture {
    let pack = OPENCRVS_PACK.to_vec();
    let pack_value = parse_json_strict(&pack).expect("strict OpenCRVS pack JSON");
    let pack_hash = typed_hash(PACK_DOMAIN, &pack);
    let contract = OPENCRVS_CONTRACT.to_vec();
    let contract_value = parse_json_strict(&contract).expect("strict OpenCRVS contract JSON");
    let contract_hash = typed_hash(CONTRACT_DOMAIN, &contract);
    let binding = OPENCRVS_BINDING.to_vec();
    let binding_value = parse_json_strict(&binding).expect("strict OpenCRVS binding JSON");
    Fixture {
        contract_value,
        pack_value,
        binding_value,
        contract,
        pack,
        binding,
        contract_hash,
        pack_hash,
    }
}

fn compile(fixture: &Fixture) -> Result<CompiledSourcePlanRegistry, SourcePlanCompileError> {
    compile_with_rhai_workers(fixture, &[])
}

fn compile_with_rhai_workers(
    fixture: &Fixture,
    workers: &[RhaiWorkerCapability],
) -> Result<CompiledSourcePlanRegistry, SourcePlanCompileError> {
    let contracts = [PinnedSourcePlanArtifact::new(
        &fixture.contract,
        &fixture.contract_hash,
    )];
    let packs = [PinnedSourcePlanArtifact::new(
        &fixture.pack,
        &fixture.pack_hash,
    )];
    let bindings = [fixture.binding.as_slice()];
    let conformance_hash = raw_hash(SYNTHETIC_CONFORMANCE_EVIDENCE);
    let negative_security_hash = raw_hash(SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE);
    let minimization_hash = raw_hash(SYNTHETIC_MINIMIZATION_EVIDENCE);
    let evidence = [
        PinnedEvidenceArtifact::new(
            EvidenceClass::Conformance,
            SYNTHETIC_CONFORMANCE_EVIDENCE,
            &conformance_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::NegativeSecurity,
            SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE,
            &negative_security_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::Minimization,
            SYNTHETIC_MINIMIZATION_EVIDENCE,
            &minimization_hash,
        ),
    ];
    CompiledSourcePlanRegistry::compile(
        &SourcePlanArtifactBundle::new(&contracts, &packs, &bindings)
            .with_evidence(&evidence)
            .with_rhai_workers(workers),
    )
}

fn compile_with_evidence(
    fixture: &Fixture,
    evidence: &[PinnedEvidenceArtifact<'_>],
) -> Result<CompiledSourcePlanRegistry, SourcePlanCompileError> {
    let contracts = [PinnedSourcePlanArtifact::new(
        &fixture.contract,
        &fixture.contract_hash,
    )];
    let packs = [PinnedSourcePlanArtifact::new(
        &fixture.pack,
        &fixture.pack_hash,
    )];
    let bindings = [fixture.binding.as_slice()];
    CompiledSourcePlanRegistry::compile(
        &SourcePlanArtifactBundle::new(&contracts, &packs, &bindings).with_evidence(evidence),
    )
}

fn compile_dhis2(fixture: &Fixture) -> Result<CompiledSourcePlanRegistry, SourcePlanCompileError> {
    let evidence_hashes = [
        raw_hash(DHIS2_CONFORMANCE),
        raw_hash(DHIS2_NEGATIVE_SECURITY),
        raw_hash(DHIS2_MINIMIZATION),
    ];
    let evidence = [
        PinnedEvidenceArtifact::new(
            EvidenceClass::Conformance,
            DHIS2_CONFORMANCE,
            &evidence_hashes[0],
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::NegativeSecurity,
            DHIS2_NEGATIVE_SECURITY,
            &evidence_hashes[1],
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::Minimization,
            DHIS2_MINIMIZATION,
            &evidence_hashes[2],
        ),
    ];
    compile_with_evidence(fixture, &evidence)
}

fn compile_maintained_opencrvs(
    fixture: &Fixture,
) -> Result<CompiledSourcePlanRegistry, SourcePlanCompileError> {
    let evidence_hashes = [
        raw_hash(OPENCRVS_CONFORMANCE),
        raw_hash(OPENCRVS_NEGATIVE_SECURITY),
        raw_hash(OPENCRVS_MINIMIZATION),
    ];
    let evidence = [
        PinnedEvidenceArtifact::new(
            EvidenceClass::Conformance,
            OPENCRVS_CONFORMANCE,
            &evidence_hashes[0],
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::NegativeSecurity,
            OPENCRVS_NEGATIVE_SECURITY,
            &evidence_hashes[1],
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::Minimization,
            OPENCRVS_MINIMIZATION,
            &evidence_hashes[2],
        ),
    ];
    compile_with_evidence(fixture, &evidence)
}

fn completion_seed_value(fixture: &Fixture) -> Value {
    completion_seed_value_with_rhai_limits(fixture, None)
}

fn completion_seed_value_with_rhai_limits(
    fixture: &Fixture,
    rhai_limits: Option<RhaiWorkerLimits>,
) -> Value {
    let contract = parse_public_contract(&fixture.contract, &fixture.contract_hash)
        .expect("fixture contract parses");
    let pack =
        parse_integration_pack(&fixture.pack, &fixture.pack_hash).expect("fixture pack parses");
    let binding = parse_private_binding(&fixture.binding).expect("fixture binding parses");
    let binding_limits =
        validate_binding_narrowing(&contract, &pack, &binding).expect("fixture binding narrows");
    let limits = rhai_limits.map_or(binding_limits, |rhai_limits| {
        binding_limits
            .with_max_data_exchanges(rhai_limits.max_calls)
            .expect("Rhai call ceiling narrows public exchange ceiling")
    });
    let token_lifetime =
        effective_token_lifetime_ms(&pack, &binding).expect("fixture token lifetime validates");
    measure_completion_seed(
        &contract,
        &pack,
        &binding,
        binding.hash().as_str(),
        limits,
        token_lifetime,
        rhai_limits,
    )
    .expect("fixture completion seed sizes")
    .canonical_value_max
}

fn binding_as_strict_yaml(value: &Value) -> String {
    serde_saphyr::to_string(value).expect("binding YAML")
}

#[derive(Debug, PartialEq, Eq)]
struct OAuthCacheFingerprint {
    pack: String,
    binding: String,
    credential: String,
    generation: u64,
    destination: String,
    audience: Option<String>,
    scopes: Vec<String>,
    resource: Option<String>,
    max_token_lifetime_ms: u32,
    expiry_safety_skew_ms: u32,
}

fn oauth_cache_fingerprint(fixture: &Fixture) -> OAuthCacheFingerprint {
    let registry = compile(fixture).expect("OAuth fixture compiles");
    let cache = registry
        .iter()
        .next()
        .expect("plan")
        .oauth_cache_identity()
        .expect("OAuth cache identity");
    let parts = cache.cache_key_parts();
    OAuthCacheFingerprint {
        pack: parts.integration_pack_hash().to_owned(),
        binding: parts.binding_hash().to_owned(),
        credential: parts.credential_reference().to_owned(),
        generation: parts.credential_generation(),
        destination: parts.credential_destination_id().to_owned(),
        audience: parts.audience().map(str::to_owned),
        scopes: parts.scopes().map(str::to_owned).collect(),
        resource: parts.resource().map(str::to_owned),
        max_token_lifetime_ms: parts.max_token_lifetime_ms(),
        expiry_safety_skew_ms: parts.expiry_safety_skew_ms(),
    }
}

fn typed_hash(domain: &[u8], raw: &[u8]) -> String {
    let value = parse_json_strict(raw).expect("strict fixture JSON");
    let canonical = canonicalize_json(&value).expect("canonical fixture JSON");
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    let digest = hasher.finalize();
    let mut encoded = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String is infallible");
    }
    encoded
}

fn raw_hash(raw: &[u8]) -> String {
    let digest = Sha256::digest(raw);
    let mut encoded = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String is infallible");
    }
    encoded
}

fn response_field(schema: ResponseSchemaDocument) -> ResponseSchemaFieldDocument {
    ResponseSchemaFieldDocument {
        required: true,
        schema: Box::new(schema),
    }
}

fn parsed_string(value: &str) -> ParsedConsultationScalar {
    ParsedConsultationScalar::String(Zeroizing::new(value.to_owned()))
}

#[test]
fn typed_parameter_slots_accept_only_the_declared_scalar_or_explicit_null() {
    let contract_hash = ProfileContractHash::try_from(
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .expect("contract hash");
    let boolean = CompiledInputSlot {
        name: "include_history".into(),
        profile_contract_hash: contract_hash.clone(),
        slot_index: 1,
        max_bytes: 5,
        min_length: None,
        max_length: None,
        input_type: CompiledInputType::Boolean,
        role: CompiledInputRole::Parameter,
        nullable: true,
        canonicalization: CompiledInputCanonicalization::Identity,
        matcher: None,
        minimum: None,
        maximum: None,
        allowed_values: Box::new([]),
        constant: None,
    };
    let value = boolean
        .canonicalize_and_validate(&ParsedConsultationScalar::Boolean(true))
        .expect("Boolean parameter");
    assert_eq!(value.transient_json_value(), json!(true));
    let null = boolean
        .canonicalize_and_validate(&ParsedConsultationScalar::Null)
        .expect("explicit nullable parameter");
    assert_eq!(null.transient_json_value(), Value::Null);
    assert!(boolean
        .canonicalize_and_validate(&parsed_string("true"))
        .is_none());

    let selector = CompiledInputSlot {
        role: CompiledInputRole::Selector,
        ..boolean
    };
    assert!(selector
        .canonicalize_and_validate(&ParsedConsultationScalar::Null)
        .is_none());
}

#[test]
fn typed_input_slots_enforce_length_enum_and_const_without_debug_values() {
    let contract_hash = ProfileContractHash::try_from(
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .expect("contract hash");
    let slot = CompiledInputSlot {
        name: "programme".into(),
        profile_contract_hash: contract_hash,
        slot_index: 0,
        max_bytes: 64,
        min_length: Some(3),
        max_length: Some(16),
        input_type: CompiledInputType::String,
        role: CompiledInputRole::Parameter,
        nullable: false,
        canonicalization: CompiledInputCanonicalization::AsciiLowercase,
        matcher: None,
        minimum: None,
        maximum: None,
        allowed_values: Box::new([json!("child"), json!("maternal")]),
        constant: Some(json!("child")),
    };
    let accepted = slot
        .canonicalize_and_validate(&parsed_string("CHILD"))
        .expect("canonical enum and const value");
    assert_eq!(accepted.transient_json_value(), json!("child"));
    assert!(slot
        .canonicalize_and_validate(&parsed_string("tb"))
        .is_none());
    assert!(slot
        .canonicalize_and_validate(&parsed_string("maternal"))
        .is_none());
    assert!(!format!("{accepted:?}").contains("child"));
}

fn string_schema() -> ResponseSchemaDocument {
    ResponseSchemaDocument::String {
        nullable: false,
        max_bytes: 65_536,
    }
}

fn object_schema(fields: BTreeMap<String, ResponseSchemaFieldDocument>) -> ResponseSchemaDocument {
    ResponseSchemaDocument::Object {
        nullable: false,
        reject_unknown_fields: true,
        fields,
    }
}

fn maximum_recursive_response_schema_document() -> ResponseSchemaDocument {
    // Depth 8 chain with 15 non-array nodes under the 256-item array.
    let mut chain = string_schema();
    for depth in (4..=7).rev() {
        chain = object_schema(BTreeMap::from([(
            format!("depth_{depth}"),
            response_field(chain),
        )]));
    }
    let mut array_item_fields = BTreeMap::from([("chain".to_owned(), response_field(chain))]);
    for index in 0..9 {
        let name = if index == 0 {
            "n".repeat(128)
        } else {
            format!("sibling_{index:02}")
        };
        let schema = match index {
            1 => ResponseSchemaDocument::Boolean { nullable: true },
            2 => ResponseSchemaDocument::Integer {
                nullable: false,
                minimum: -9_007_199_254_740_991,
                maximum: 9_007_199_254_740_991,
            },
            3 => ResponseSchemaDocument::Number {
                nullable: true,
                minimum: -9_007_199_254_740_991,
                maximum: 9_007_199_254_740_991,
            },
            _ => string_schema(),
        };
        array_item_fields.insert(name, response_field(schema));
    }
    let maximal_array = ResponseSchemaDocument::Array {
        nullable: false,
        max_items: 256,
        items: Box::new(object_schema(array_item_fields)),
    };

    let mut root = BTreeMap::from([
        ("max_array".to_owned(), response_field(maximal_array)),
        (
            "adjustment_array".to_owned(),
            response_field(ResponseSchemaDocument::Array {
                nullable: true,
                max_items: 16,
                items: Box::new(string_schema()),
            }),
        ),
    ]);
    for branch in 0..6 {
        let fields = (0..32)
            .map(|index| (format!("field_{index:02}"), response_field(string_schema())))
            .collect();
        root.insert(
            format!("full_branch_{branch}"),
            response_field(object_schema(fields)),
        );
    }
    let partial = (0..15)
        .map(|index| (format!("field_{index:02}"), response_field(string_schema())))
        .collect();
    root.insert(
        "partial_branch".to_owned(),
        response_field(object_schema(partial)),
    );
    for index in 0..23 {
        root.insert(
            format!("root_scalar_{index:02}"),
            response_field(string_schema()),
        );
    }
    object_schema(root)
}

fn response_schema_chain(nodes: usize) -> ResponseSchemaDocument {
    let mut schema = string_schema();
    for index in 1..nodes {
        schema = object_schema(BTreeMap::from([(
            format!("level_{index}"),
            response_field(schema),
        )]));
    }
    schema
}

pub(crate) fn maximum_runtime_profile_fixture(
) -> super::super::runtime_profile::CompiledRuntimeProfile {
    let document = maximum_recursive_response_schema_document();
    let mut nodes = 0;
    let expanded = super::super::artifact::validate_response_schema(&document, 1, &mut nodes)
        .expect("maximum recursive schema is compiler-valid");
    assert_eq!((nodes, expanded), (256, 4_096));
    let schema = compile_runtime_response_schema(&document);
    let registry = compile(&fixture()).expect("portable source plan compiles");
    let plan = registry.plans.into_values().next().expect("one plan");
    let mut profile = plan.runtime_profile;
    profile
        .install_maximum_recursive_schema_fixture(schema)
        .expect("maximum runtime profile fixture remains typed");
    profile
}

pub(crate) fn bounded_runtime_vector_plan_fixture() -> CompiledSourcePlan {
    compile(&fixture())
        .expect("bounded vector plan compiles")
        .plans
        .into_values()
        .next()
        .expect("one bounded vector plan")
}

fn same_key_different_private_binding_plan_fixture() -> CompiledSourcePlan {
    let mut fixture = fixture();
    fixture.binding_value["registry_instance"] = json!("people-secondary");
    fixture.refresh_binding();
    compile(&fixture)
        .expect("same-key private-binding variant compiles")
        .plans
        .into_values()
        .next()
        .expect("one same-key private-binding variant")
}

#[test]
fn pre_authorization_rejects_same_key_with_a_different_private_binding() {
    use crate::consultation::{
        ConsultationValidationError, ParsedConsultationInputs, ParsedPurpose,
        PreAuthorizationConsultationCore, ResolvedConsultationProfile,
    };

    let baseline = bounded_runtime_vector_plan_fixture();
    let variant = same_key_different_private_binding_plan_fixture();
    assert_eq!(baseline.profile(), variant.profile());
    assert_eq!(baseline.integration_pack(), variant.integration_pack());
    assert_ne!(baseline.binding_hash(), variant.binding_hash());
    let resolved = ResolvedConsultationProfile::from_authenticated_registry_plan(&baseline);
    assert_eq!(
        PreAuthorizationConsultationCore::from_resolved_plan(
            resolved,
            &variant,
            ParsedPurpose::try_parse("benefit-verification").unwrap(),
            ParsedConsultationInputs::try_parse("subject_id", "12345").unwrap(),
        )
        .err(),
        Some(ConsultationValidationError::ResolvedProfileMismatch)
    );
}

#[test]
fn open_crvs_exact_presence_plan_compiles_embedded_jwks_and_fresh_oauth() {
    let fixture = open_crvs_fixture();
    let registry = compile(&fixture).expect("exact OpenCRVS plan compiles");
    let plan = registry.iter().next().expect("one plan");
    let operation = plan.operations().next().expect("one authored operation");
    assert!(operation.dci_exact().is_some());
    assert_eq!(operation.disclosed_fields().len(), 0);
    assert_eq!(operation.acquired_fields().collect::<Vec<_>>(), ["record"]);
    assert_eq!(operation.response().outputs().len(), 0);
    let template_debug = format!("{:?}", operation.transport_template());
    assert!(template_debug.contains("ReviewedReadOnlyPost"));
    assert!(template_debug.contains("header_count: 2"));
    assert!(template_debug.contains("Bearer"));
    assert!(template_debug.contains("Required"));
    let request = operation
        .transport_template()
        .render_zeroizing(
            &[],
            &[],
            Some(
                DestinationAuthorizationValue::bearer(b"production-token".to_vec())
                    .expect("Bearer authorization"),
            ),
            Some(Zeroizing::new(br#"{"header":{},"message":{}}"#.to_vec())),
        )
        .expect("production-shaped OpenCRVS request renders");
    let request_debug = format!("{request:?}");
    assert!(request_debug.contains("ReviewedReadOnlyPost"));
    assert!(request_debug.contains("[REDACTED]"));
    let jwks = operation
        .dci_exact()
        .map(|dci| dci.verification())
        .expect("embedded JWKS");
    assert_eq!(jwks.id().as_str(), "fetch-signing-keys");
    assert_eq!(jwks.fixed_path(), "/.well-known/jwks.json");
    assert_eq!(jwks.response_max_bytes(), 65_536);
    assert_eq!(
        plan.runtime_profile().permit_bindings().collect::<Vec<_>>(),
        [("credential", 0), ("verification", 0), ("data", 0)]
    );
    assert_eq!(plan.steps().count(), 1);
    assert_eq!(
        plan.runtime_profile()
            .dispatch()
            .bounded_http_operations()
            .expect("bounded dispatch")
            .iter()
            .map(OperationId::as_str)
            .collect::<Vec<_>>(),
        ["fetch-signing-keys", "opencrvs-search"]
    );
    assert_eq!(plan.runtime_profile().credential_token_lifetime_ms(), None);
    assert!(plan.oauth_cache_identity().is_none());
    let credential = plan.credential_operation().expect("credential operation");
    assert!(credential.parser().is_no_expiry());
    assert_eq!(credential.parser().max_response_bytes(), 16_384);
    assert_eq!(credential.parser().access_token_max_bytes(), 4_089);
    let token = credential
        .parser()
        .parse(200, br#"{"access_token":"fresh","token_type":"Bearer"}"#)
        .expect("strict two-member token response");
    assert_eq!(token.usable_lifetime_ms(), None);
    assert!(matches!(
        credential.parser().parse(
            200,
            br#"{"access_token":"fresh","token_type":"Bearer","expires_in":60}"#,
        ),
        Err(CredentialOperationFailure::MalformedResponse)
    ));
}

#[test]
fn open_crvs_exact_shape_rejects_optional_flexibility_and_unsafe_origin_changes() {
    type FixtureMutation = Box<dyn Fn(&mut Fixture)>;
    let cases: Vec<(&str, FixtureMutation)> = vec![
        (
            "operator query",
            Box::new(|fixture| {
                fixture.pack_value["spec"]["plan"]["operations"][0]["query"] =
                    json!({"optional": {"source": "literal", "value": "true"}});
            }),
        ),
        (
            "authored body",
            Box::new(|fixture| {
                fixture.pack_value["spec"]["plan"]["operations"][0]["body"] =
                    json!({"kind": "null"});
            }),
        ),
        (
            "missing verification operation",
            Box::new(|fixture| {
                fixture.pack_value["spec"]["plan"]["verification_operations"] = json!([]);
            }),
        ),
    ];
    for (label, mutation) in cases {
        let mut fixture = open_crvs_fixture();
        mutation(&mut fixture);
        fixture.refresh_all();
        assert!(compile(&fixture).is_err(), "accepted {label}");
    }
}

#[test]
fn dci_exact_rejects_malformed_reviewed_protocol_constants_before_activation() {
    for (field, invalid) in [
        ("protocol_version", "01.0.0"),
        ("sender_id", "contains a space"),
        ("identifier_type", ""),
        ("locale", "en\nUS"),
    ] {
        let mut fixture = open_crvs_fixture();
        fixture.pack_value["spec"]["plan"]["operations"][0]["dci"][field] = json!(invalid);
        fixture.refresh_all();
        assert!(
            matches!(
                compile(&fixture),
                Err(SourcePlanCompileError::Artifact(
                    SourcePlanArtifactError::InvalidPlan
                ))
            ),
            "accepted malformed DCI constant {field}"
        );
    }
}

#[test]
fn open_crvs_generated_body_and_embedded_jwks_are_charged_to_bounds() {
    let mut request_too_small = open_crvs_fixture();
    request_too_small.pack_value["spec"]["plan"]["operations"][0]["step_limits"]
        ["max_request_bytes"] = json!(8_192);
    request_too_small.refresh_all();
    assert!(matches!(
        compile(&request_too_small),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidLimits
        ))
    ));

    let mut source_too_small = open_crvs_fixture();
    source_too_small.pack_value["spec"]["bounds"]["max_source_bytes"] = json!(147_455);
    source_too_small.contract_value["spec"]["bounds"]["max_source_bytes"] = json!(147_455);
    source_too_small.binding_value["limits"]["max_source_bytes"] = json!(147_455);
    source_too_small.refresh_all();
    assert!(matches!(
        compile(&source_too_small),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidLimits
        )) | Err(SourcePlanCompileError::BindingWidening)
    ));
}

#[test]
fn source_plan_timeout_accepts_sixty_seconds_and_rejects_one_millisecond_more() {
    let mut fixture = fixture();
    for timeout_ms in [60_000, 60_001] {
        fixture.pack_value["spec"]["bounds"]["timeout_ms"] = json!(timeout_ms);
        fixture.contract_value["spec"]["bounds"]["timeout_ms"] = json!(timeout_ms);
        fixture.binding_value["limits"]["timeout_ms"] = json!(timeout_ms);
        fixture.refresh_all();
        if timeout_ms == 60_000 {
            compile(&fixture).expect("the maintained source timeout ceiling compiles");
        } else {
            assert!(matches!(
                compile(&fixture),
                Err(SourcePlanCompileError::Artifact(
                    SourcePlanArtifactError::InvalidLimits
                ))
            ));
        }
    }
}

pub(crate) fn dhis2_runtime_vector_plan_fixture() -> CompiledSourcePlan {
    compile_dhis2(&dhis2_fixture())
        .expect("maintained DHIS2 vector plan compiles")
        .plans
        .into_values()
        .next()
        .expect("one maintained DHIS2 vector plan")
}

pub(crate) fn open_crvs_completion_seed_fixture() -> Value {
    completion_seed_value(&open_crvs_fixture())
}

pub(crate) fn open_crvs_runtime_vector_plan_fixture() -> CompiledSourcePlan {
    compile(&open_crvs_fixture())
        .expect("exact OpenCRVS vector plan compiles")
        .plans
        .into_values()
        .next()
        .expect("one exact OpenCRVS vector plan")
}

pub(crate) fn signed_dci_script_runtime_plan_fixture() -> CompiledSourcePlan {
    let fixture = signed_dci_script_fixture();
    let worker = RhaiWorkerCapability::from_initialized_worker(
        &fixture.pack_hash,
        rhai_test_worker_limits(1),
    )
    .expect("signed DCI Script worker capability");
    compile_with_rhai_workers(&fixture, &[worker])
        .expect("signed DCI Script vector plan compiles")
        .plans
        .into_values()
        .next()
        .expect("one signed DCI Script vector plan")
}

pub(crate) fn signed_dci_expiring_oauth_runtime_plan_fixture() -> CompiledSourcePlan {
    let mut fixture = open_crvs_fixture();
    fixture.pack_value["spec"]["plan"]["credential_operation"]["response"] = json!({
        "max_bytes": 16384,
        "accepted_statuses": [200],
        "schema": "strict_access_token_bearer_expires_in",
        "access_token_max_bytes": 4089,
        "token_type": "Bearer",
        "expires_in_min_seconds": 60,
        "expires_in_max_seconds": 3600,
        "max_token_lifetime_ms": 3600000,
        "expiry_safety_skew_ms": 30000
    });
    fixture.refresh_all();
    compile(&fixture)
        .expect("signed DCI with expiring OAuth compiles")
        .plans
        .into_values()
        .next()
        .expect("one signed DCI plan")
}

pub(crate) fn maintained_open_crvs_runtime_plan_fixture() -> CompiledSourcePlan {
    compile_maintained_opencrvs(&maintained_opencrvs_fixture())
        .expect("maintained OpenCRVS profile compiles")
        .plans
        .into_values()
        .next()
        .expect("one maintained OpenCRVS plan")
}

pub(crate) fn open_crvs_runtime_vector_registry_fixture() -> CompiledSourcePlanRegistry {
    compile(&open_crvs_fixture()).expect("exact OpenCRVS vector registry compiles")
}

pub(crate) fn dhis2_duplicate_selector_runtime_vector_plan_fixture() -> CompiledSourcePlan {
    let mut fixture = dhis2_fixture();
    fixture.pack_value["spec"]["plan"]["operations"][0]["query"]["trackedEntityAlias"] =
        json!({"source": "consultation_input", "name": "tracked_entity"});
    fixture.refresh_all();
    compile_dhis2(&fixture)
        .expect("artifact-valid duplicate selector fixture compiles")
        .plans
        .into_values()
        .next()
        .expect("one duplicate selector vector plan")
}

pub(crate) fn rhai_runtime_vector_plan_fixture() -> CompiledSourcePlan {
    let fixture = rhai_five_operation_fixture();
    let worker = RhaiWorkerCapability::from_initialized_worker(
        &fixture.pack_hash,
        rhai_test_worker_limits(2),
    )
    .expect("Rhai vector worker capability");
    compile_with_rhai_workers(&fixture, &[worker])
        .expect("Rhai vector plan compiles")
        .plans
        .into_values()
        .next()
        .expect("one Rhai vector plan")
}

pub(crate) fn consent_runtime_vector_plan_fixture() -> CompiledSourcePlan {
    let mut fixture = fixture();
    fixture.contract_value["spec"]["authorization"]["consent"] = json!({
        "required": true,
        "verifier": {
            "id": "registry.consent.v1",
            "hash": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        },
        "max_age_ms": 60000,
        "revocation": "online_required",
        "unavailable": "deny"
    });
    fixture.refresh_all();
    compile(&fixture)
        .expect("consent vector plan compiles")
        .plans
        .into_values()
        .next()
        .expect("one consent vector plan")
}

#[test]
fn recursive_schema_accepts_every_exact_maximum_and_rejects_just_over() {
    let maximum = maximum_recursive_response_schema_document();
    let mut nodes = 0;
    let expanded = super::super::artifact::validate_response_schema(&maximum, 1, &mut nodes)
        .expect("exact recursive maxima are accepted");
    assert_eq!(nodes, 256);
    assert_eq!(expanded, 4_096);

    let mut nodes = 0;
    assert!(matches!(
        super::super::artifact::validate_response_schema(&response_schema_chain(9), 1, &mut nodes,),
        Err(SourcePlanArtifactError::InvalidLimits)
    ));

    let mut array_over = maximum.clone();
    if let ResponseSchemaDocument::Object { fields, .. } = &mut array_over {
        if let ResponseSchemaDocument::Array { max_items, .. } = fields
            .get_mut("max_array")
            .expect("max array")
            .schema
            .as_mut()
        {
            *max_items = 257;
        }
    }
    let mut nodes = 0;
    assert!(matches!(
        super::super::artifact::validate_response_schema(&array_over, 1, &mut nodes),
        Err(SourcePlanArtifactError::InvalidLimits)
    ));

    let profile = maximum_runtime_profile_fixture();
    assert_eq!(profile.acquisition().fields().len(), 64);
    assert_eq!(profile.output().len(), 64);
    assert_eq!(
        profile
            .acquisition()
            .field("recursive_max")
            .expect("recursive maximum field")
            .schema()
            .kind(),
        CompiledResponseSchemaKind::Object
    );
}

#[test]
fn completion_persistence_caps_accept_exact_maxima_and_reject_one_byte_over() {
    assert_eq!(
        validate_completion_sizing(
            super::super::runtime_profile::MAX_COMPLETION_SEED_CANONICAL_BYTES_V1,
            super::super::completion_seed::MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1,
        ),
        Ok(())
    );
    assert_eq!(
        validate_completion_sizing(
            super::super::runtime_profile::MAX_COMPLETION_SEED_CANONICAL_BYTES_V1 + 1,
            super::super::completion_seed::MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1,
        ),
        Err(SourcePlanCompileError::CompletionSeedTooLarge)
    );
    assert_eq!(
        validate_completion_sizing(
            super::super::runtime_profile::MAX_COMPLETION_SEED_CANONICAL_BYTES_V1,
            super::super::completion_seed::MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1 + 1,
        ),
        Err(SourcePlanCompileError::CompletionAuditTooLarge)
    );
}

fn semantic_alias_fixture() -> Fixture {
    let mut fixture = fixture();
    fixture.pack_value["spec"]["plan"]["operations"][0]["acquisition_fields"] =
        json!(["registration_status"]);
    fixture.pack_value["spec"]["plan"]["operations"][0]["response"]["output_mapping"] =
        json!({"status": "/registration_status"});
    fixture.pack_value["spec"]["output"] =
        json!({"status": {"type": "string", "nullable": false, "max_bytes": 64}});
    fixture.contract_value["spec"]["output"] =
        json!({"status": {"type": "string", "nullable": false, "max_bytes": 64}});
    fixture.refresh_all();
    fixture
}

fn rhai_five_operation_fixture() -> Fixture {
    let mut fixture = fixture();
    let public_fields = (0..5)
        .map(|index| {
            (
                format!("status_{index}"),
                json!({"type": "string", "nullable": false, "max_bytes": 64}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    fixture.pack_value["spec"]["output"] = Value::Object(public_fields.clone());
    fixture.contract_value["spec"]["output"] = Value::Object(public_fields.clone());

    let plan = fixture.pack_value["spec"]["plan"]
        .as_object_mut()
        .expect("Script plan");
    plan.remove("operations");
    plan.remove("steps");
    plan.remove("step_conditions");
    plan.insert("kind".to_owned(), json!("script"));
    plan.insert(
        "script_authority".to_owned(),
        json!({
            "allow": (0..5).map(|index| json!({
                "method": "GET",
                "path": format!("/api/person/status/{index}"),
            })).collect::<Vec<_>>(),
            "request_headers": [],
            "response_headers": [],
            "response": { "format": "json", "max_bytes": 16_000 },
            "auth": { "mode": "oauth_client_credentials" },
            "request_max_bytes": 65_536,
        }),
    );
    fixture.contract_value["spec"]["runtime"] = json!({
        "platform_profile": "registry-stack.consultation.v1",
        "source_capability": "script",
        "script_abi": crate::rhai_worker::xw::XW_ABI_VERSION
    });
    let script = "fn consult(ctx) { result.no_match() }";
    fixture.pack_value["spec"]["plan"]["rhai"] = json!({
        "script": script,
        "script_hash": raw_hash(script.as_bytes()),
        "entrypoint": "consult",
        "abi": crate::rhai_worker::xw::XW_ABI_VERSION,
        "memory_bytes": 67108864,
        "cpu_ms": 500,
        "ipc_frame_bytes": 131072,
        "instructions": 50000,
        "call_depth": 8,
        "string_bytes": 32768,
        "array_items": 256,
        "map_entries": 256,
        "output_bytes": 32768,
        "concurrency": 1
    });
    fixture.pack_value["spec"]["bounds"]["max_data_exchanges"] = json!(5);
    fixture.contract_value["spec"]["bounds"]["max_data_exchanges"] = json!(5);
    fixture.pack_value["spec"]["acquisition"]["class"] = json!("bounded_full_record");
    fixture.contract_value["spec"]["acquisition"]["class"] = json!("bounded_full_record");
    fixture.pack_value["spec"]["acquisition"]["fields"] = Value::Object(public_fields.clone());
    fixture.contract_value["spec"]["acquisition"]["fields"] = Value::Object(public_fields.clone());
    fixture.pack_value["spec"]["reviewed_acquisition"]["class"] = json!("bounded_full_record");
    fixture.pack_value["spec"]["reviewed_acquisition"]["fields"] = Value::Object(public_fields);
    fixture.pack_value["spec"]["reviewed_acquisition"]["control_fields"] = json!({});
    fixture.pack_value["spec"]["reviewed_acquisition"]["selector"] = Value::Null;
    fixture.pack_value["spec"]["reviewed_acquisition"]["cardinality"] = json!("probe_two");
    fixture.pack_value["spec"]["bounds"]["max_source_matches"] = json!(2);
    fixture.contract_value["spec"]["bounds"]["max_source_matches"] = json!(2);
    fixture.contract_value["spec"]["public_behavior"]["outcomes"] =
        json!(["match", "no_match", "ambiguous"]);
    fixture.binding_value["capabilities"]["allow_script"] = json!(true);
    fixture.binding_value["capabilities"]["script"] = json!({
        "max_calls": 2,
        "memory_bytes": 67108864,
        "cpu_ms": 500,
        "ipc_frame_bytes": 131072,
        "instructions": 50000,
        "call_depth": 8,
        "string_bytes": 32768,
        "array_items": 256,
        "map_entries": 256,
        "output_bytes": 32768,
        "concurrency": 1,
        "isolation": "one_shot_worker_v1"
    });
    fixture.refresh_all();
    fixture
}

fn rhai_test_worker_limits(max_calls: u8) -> RhaiWorkerLimits {
    RhaiWorkerLimits {
        max_calls,
        memory_bytes: 67_108_864,
        cpu_ms: 500,
        ipc_frame_bytes: 131_072,
        instructions: 50_000,
        call_depth: 8,
        string_bytes: 32_768,
        array_items: 256,
        map_entries: 256,
        output_bytes: 32_768,
        concurrency: 1,
    }
}

fn runtime_digests(fixture: &Fixture) -> (String, String) {
    let registry = compile(fixture).expect("bounded runtime profile compiles");
    let profile = registry.iter().next().expect("bounded runtime profile");
    (
        profile
            .runtime_profile()
            .predicate_plan_digest()
            .as_str()
            .to_owned(),
        profile
            .runtime_profile()
            .physical_projection_digest()
            .as_str()
            .to_owned(),
    )
}

fn rhai_runtime_digests(
    fixture: &Fixture,
    limits: RhaiWorkerLimits,
) -> Result<(String, String), SourcePlanCompileError> {
    let worker = RhaiWorkerCapability::from_initialized_worker(&fixture.pack_hash, limits)?;
    let registry = compile_with_rhai_workers(fixture, &[worker])?;
    let profile = registry
        .iter()
        .next()
        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
    Ok((
        profile
            .runtime_profile()
            .predicate_plan_digest()
            .as_str()
            .to_owned(),
        profile
            .runtime_profile()
            .physical_projection_digest()
            .as_str()
            .to_owned(),
    ))
}

pub(crate) fn normal_completion_seed_fixture() -> Value {
    completion_seed_value(&fixture())
}

pub(crate) fn dhis2_completion_seed_fixture() -> Value {
    completion_seed_value(&dhis2_fixture())
}

pub(crate) fn snapshot_completion_seed_fixture() -> Value {
    completion_seed_value(&snapshot_fixture())
}

pub(crate) fn shared_snapshot_registry_fixture() -> crate::source_plan::CompiledConsultationRegistry
{
    let first = snapshot_fixture();
    let mut second = snapshot_fixture();
    second.contract_value["id"] = json!("synthetic.person-status.snapshot-second");
    second.binding_value["profile"]["id"] = second.contract_value["id"].clone();
    second.refresh_all();

    let contracts = [
        PinnedSourcePlanArtifact::new(&first.contract, &first.contract_hash),
        PinnedSourcePlanArtifact::new(&second.contract, &second.contract_hash),
    ];
    let packs = [PinnedSourcePlanArtifact::new(&first.pack, &first.pack_hash)];
    let bindings = [first.binding.as_slice(), second.binding.as_slice()];
    let evidence_hashes = [
        raw_hash(SYNTHETIC_CONFORMANCE_EVIDENCE),
        raw_hash(SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE),
        raw_hash(SYNTHETIC_MINIMIZATION_EVIDENCE),
    ];
    let evidence = [
        PinnedEvidenceArtifact::new(
            EvidenceClass::Conformance,
            SYNTHETIC_CONFORMANCE_EVIDENCE,
            &evidence_hashes[0],
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::NegativeSecurity,
            SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE,
            &evidence_hashes[1],
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::Minimization,
            SYNTHETIC_MINIMIZATION_EVIDENCE,
            &evidence_hashes[2],
        ),
    ];
    let source_plans = CompiledSourcePlanRegistry::compile(
        &SourcePlanArtifactBundle::new(&contracts, &packs, &bindings).with_evidence(&evidence),
    )
    .expect("two profiles share one compatible snapshot materialization");
    crate::source_plan::CompiledConsultationRegistry::from_source_plans_for_test(source_plans)
}

pub(crate) fn semantic_alias_completion_seed_fixture() -> Value {
    completion_seed_value(&semantic_alias_fixture())
}

pub(crate) fn maximum_completion_seed_fixture() -> Value {
    let mut seed = normal_completion_seed_fixture();
    let mut fields = serde_json::Map::new();
    fields.insert(
        "recursive_max".to_owned(),
        serde_json::to_value(maximum_recursive_response_schema_document())
            .expect("maximum recursive schema serializes"),
    );
    for index in 0..63 {
        fields.insert(
            format!("scalar_{index:02}"),
            serde_json::to_value(string_schema()).expect("scalar schema serializes"),
        );
    }
    let mut disclosure_fields = fields.keys().cloned().collect::<Vec<_>>();
    disclosure_fields.sort_unstable();
    seed["acquisition"]["schema"]["fields"] = Value::Object(fields);
    seed["acquisition"]["disclosure_fields"] = json!(disclosure_fields);
    seed
}

pub(crate) fn rhai_five_operation_two_slot_completion_seed_fixture() -> Value {
    completion_seed_value_with_rhai_limits(
        &rhai_five_operation_fixture(),
        Some(RhaiWorkerLimits {
            max_calls: 2,
            memory_bytes: 67_108_864,
            cpu_ms: 500,
            ipc_frame_bytes: 131_072,
            instructions: 50_000,
            call_depth: 8,
            string_bytes: 32_768,
            array_items: 256,
            map_entries: 256,
            output_bytes: 32_768,
            concurrency: 1,
        }),
    )
}

fn snapshot_fixture() -> Fixture {
    let mut fixture = fixture();
    fixture.pack_value["spec"]["acquisition"]["class"] = json!("materialized_snapshot");
    fixture.pack_value["spec"]["reviewed_acquisition"]["class"] = json!("materialized_snapshot");
    fixture.pack_value["spec"]["reviewed_acquisition"]["selector"] = json!({
        "type": "snapshot_exact_and",
        "components": {"subject_id": "snapshot_key"}
    });
    fixture.pack_value["spec"]["plan"]["kind"] = json!("snapshot_exact");
    fixture.contract_value["spec"]["runtime"] = json!({
        "platform_profile": "registry-stack.consultation.v1",
        "source_capability": "snapshot",
        "script_abi": null
    });
    let plan = fixture.pack_value["spec"]["plan"]
        .as_object_mut()
        .expect("SnapshotExact plan");
    plan.insert("data_destination_slot".to_owned(), Value::Null);
    plan.insert("credential_destination_slot".to_owned(), Value::Null);
    plan.insert("credential_operation".to_owned(), Value::Null);
    plan.remove("operations");
    plan.remove("steps");
    fixture.binding_value["limits"]
        .as_object_mut()
        .expect("binding limits")
        .remove("max_token_lifetime_ms");
    fixture.pack_value["spec"]["plan"]["snapshot"] = json!({
        "max_snapshot_age_ms": 86_400_000,
        "unavailable": "unavailable",
        "immutable_generation": true
    });
    fixture.pack_value["spec"]["bounds"]["max_credential_exchanges"] = json!(0);
    fixture.pack_value["spec"]["bounds"]["max_data_exchanges"] = json!(0);
    fixture.pack_value["spec"]["bounds"]["max_data_destinations"] = json!(0);
    fixture.contract_value["spec"]["acquisition"]["class"] = json!("materialized_snapshot");
    fixture.contract_value["spec"]["bounds"]["max_credential_exchanges"] = json!(0);
    fixture.contract_value["spec"]["bounds"]["max_data_exchanges"] = json!(0);
    fixture.contract_value["spec"]["bounds"]["max_data_destinations"] = json!(0);
    fixture.contract_value["spec"]["materialization"] = json!({
        "max_snapshot_age_ms": 86_400_000,
        "stale_behavior": "unavailable",
        "footprint": {
            "fields": ["registration_status"],
            "max_source_records": 1000,
            "max_source_bytes": 1048576,
            "max_data_exchanges": 2,
            "max_credential_exchanges": 1,
            "max_data_destinations": 1
        },
        "refresh_class": "operator_triggered",
        "snapshot_retention_generations": 3,
        "immutable_generation": true,
        "digest_bound_active_pointer": true
    });
    fixture.binding_value["data_destination"] = Value::Null;
    fixture.binding_value["credential_destination"] = Value::Null;
    fixture.binding_value["credential"] = Value::Null;
    fixture.binding_value["materialization"] = json!({
        "table_provider": "people-snapshot",
        "mapping": {
            "key": {
                "input": "subject_id",
                "physical_field": "subject_key",
                "physical_type": "utf8",
                "comparison": "binary_equality"
            },
            "projection": {
                "registration_status": "registration_status_text"
            }
        },
        "max_snapshot_age_ms": 43_200_000,
        "max_source_records": 500,
        "max_source_bytes": 524_288,
        "max_data_exchanges": 1,
        "max_credential_exchanges": 0,
        "max_data_destinations": 1,
        "snapshot_retention_generations": 2
    });
    fixture.refresh_all();
    fixture
}

#[test]
fn compiles_closed_bundle_and_exposes_only_safe_metadata() {
    let fixture = fixture();
    let registry = compile(&fixture).expect("valid closed bundle");
    assert_eq!(registry.len(), 1);
    let plan = registry.iter().next().expect("compiled plan");
    assert_eq!(plan.kind(), SourcePlanKind::BoundedHttp);
    assert_eq!(plan.cardinality(), SourceCardinality::AmbiguityProbe);
    assert_eq!(plan.limits().operation().max_source_bytes, 81_920);
    assert_eq!(plan.operations().len(), 1);
    let operation = plan.operations().next().expect("operation");
    assert_eq!(operation.max_source_calls(), 1);
    assert_eq!(operation.max_source_records(), 2);
    assert_eq!(
        operation.acquisition_class(),
        AcquisitionClass::SourceProjectedExact
    );
    assert_eq!(operation.cardinality(), SourceCardinality::AmbiguityProbe);
    assert_eq!(operation.total_deadline_ms(), 4_000);
    assert_eq!(
        plan.steps().next().expect("step").id().as_str(),
        "lookup-status"
    );
    assert_eq!(plan.credential_reference(), Some(("people-api-reader", 7)));
    assert_eq!(plan.deployment_parameter_value(0), Some("benefits"));
    assert!(format!("{plan:?}").contains("operation_count"));
    assert!(!format!("{plan:?}").contains("registry.example.test"));
}

#[test]
fn maintained_dhis2_enrollment_status_pack_compiles_to_one_bounded_exchange() {
    let fixture = dhis2_fixture();
    assert_eq!(fixture.pack_hash, DHIS2_PACK_HASH);
    assert_eq!(fixture.contract_hash, DHIS2_CONTRACT_HASH);
    assert_eq!(
        fixture.contract_value["spec"]["authorization"]["policy"]["hash"].as_str(),
        Some(DHIS2_POLICY_HASH)
    );
    assert_eq!(
        typed_hash(BINDING_DOMAIN, &fixture.binding),
        DHIS2_BINDING_HASH
    );
    let registry = compile_dhis2(&fixture).expect("maintained DHIS2 profile compiles");
    let plan = registry.iter().next().expect("compiled DHIS2 plan");
    assert_eq!(plan.kind(), SourcePlanKind::BoundedHttp);
    assert_eq!(plan.cardinality(), SourceCardinality::AmbiguityProbe);
    assert!(matches!(
        plan.runtime_profile().subject().selector_provenance(),
        crate::consultation::SelectorProvenance::WorkloadSelected
    ));
    assert_eq!(plan.credential_reference(), Some(("dhis2-basic-reader", 1)));
    assert_eq!(plan.operations().len(), 1);

    let operation = plan.operations().next().expect("DHIS2 operation");
    assert_eq!(
        operation.fixed_path(),
        "/stable-2-41-9/api/tracker/enrollments"
    );
    assert_eq!(operation.auth(), CompiledSourceAuth::Basic);
    assert_eq!(operation.total_deadline_ms(), 10_000);
    assert_eq!(operation.max_source_records(), 2);
    assert_eq!(operation.acquired_fields().collect::<Vec<_>>(), ["status"]);
    assert_eq!(operation.disclosed_fields().collect::<Vec<_>>(), ["status"]);
    let decoder_debug = format!("{:?}", operation.response_decoder());
    assert!(decoder_debug.contains("projection_count: 1"));
    assert!(decoder_debug.contains("ObjectArrayProbeTwo"));
    assert!(!decoder_debug.contains("enrollments"));
    assert_eq!(
        operation
            .query()
            .map(CompiledNamedExpression::name)
            .collect::<Vec<_>>(),
        [
            "fields",
            "orgUnitMode",
            "pageSize",
            "program",
            "trackedEntity"
        ]
    );
    assert!(matches!(
        operation.response().normalization(),
        CompiledResponseNormalization::ObjectArrayProbeTwo {
            records_field_index: 0
        }
    ));
    assert_eq!(
        operation
            .response()
            .schema()
            .object_fields()
            .expect("strict wrapper object")[0]
            .name(),
        "enrollments"
    );
}

#[test]
fn maintained_opencrvs_birth_record_exists_pack_compiles_to_exact_closed_exchange() {
    let fixture = maintained_opencrvs_fixture();
    assert_eq!(fixture.pack_hash, OPENCRVS_PACK_HASH);
    assert_eq!(fixture.contract_hash, OPENCRVS_CONTRACT_HASH);
    assert_eq!(
        fixture.contract_value["spec"]["authorization"]["policy"]["hash"].as_str(),
        Some(OPENCRVS_POLICY_HASH)
    );
    parse_public_contract(&fixture.contract, OPENCRVS_CONTRACT_HASH)
        .expect("maintained OpenCRVS contract hash remains valid after normalization");
    parse_integration_pack(&fixture.pack, OPENCRVS_PACK_HASH)
        .expect("maintained OpenCRVS pack hash remains valid after normalization");

    let registry =
        compile_maintained_opencrvs(&fixture).expect("maintained OpenCRVS profile compiles");
    let plan = registry.iter().next().expect("compiled OpenCRVS plan");
    assert_eq!(plan.binding_hash(), OPENCRVS_BINDING_HASH);
    assert_eq!(plan.kind(), SourcePlanKind::BoundedHttp);
    assert_eq!(plan.cardinality(), SourceCardinality::AmbiguityProbe);
    assert_eq!(
        plan.credential_reference(),
        Some(("opencrvs-oauth-client", 1))
    );
    assert_eq!(plan.runtime_profile().credential_token_lifetime_ms(), None);
    assert!(plan.oauth_cache_identity().is_none());

    let operation = plan.operations().next().expect("OpenCRVS search operation");
    assert!(operation.dci_exact().is_some());
    assert_eq!(operation.total_deadline_ms(), 20_000);
    assert_eq!(operation.max_source_records(), 2);
    assert_eq!(operation.acquired_fields().collect::<Vec<_>>(), ["record"]);
    assert_eq!(operation.disclosed_fields().len(), 0);
    assert_eq!(
        plan.runtime_profile().permit_bindings().collect::<Vec<_>>(),
        [("credential", 0), ("verification", 0), ("data", 0)]
    );
}

#[test]
#[ignore = "review-only maintained profile hash printer"]
fn print_maintained_profile_hashes_for_review() {
    for (name, mut fixture) in [
        ("dhis2", dhis2_fixture()),
        ("opencrvs", maintained_opencrvs_fixture()),
    ] {
        fixture.refresh_all();
        println!(
            "{name}: pack={} policy={} contract={}",
            fixture.pack_hash,
            fixture.contract_value["spec"]["authorization"]["policy"]["hash"]
                .as_str()
                .expect("policy hash"),
            fixture.contract_hash,
        );
    }
}

#[test]
fn maintained_dhis2_seed_distinguishes_direct_basic_auth_from_credential_exchange() {
    let seed = dhis2_completion_seed_fixture();
    assert_eq!(
        seed["credential"],
        json!({"reference": "dhis2-basic-reader", "generation": 1})
    );
    assert_eq!(seed["bounds"]["credential_exchanges"], json!(0));
    assert_eq!(
        seed["destinations"]["credential_destination_id"],
        Value::Null
    );
    assert_eq!(seed["bounds"]["credential_token_lifetime_ms"], Value::Null);
}

#[test]
fn closed_decoder_compiles_every_reviewed_record_root() {
    let array = compile(&fixture()).expect("array-probe-two decoder compiles");
    let array_debug = format!(
        "{:?}",
        array
            .iter()
            .next()
            .expect("array plan")
            .operations()
            .next()
            .expect("array operation")
            .response_decoder()
    );
    assert!(array_debug.contains("ArrayProbeTwo"));

    let mut object = fixture();
    object.pack_value["spec"]["reviewed_acquisition"]["cardinality"] =
        json!("source_enforced_singleton");
    object.pack_value["spec"]["bounds"]["max_source_matches"] = json!(1);
    object.contract_value["spec"]["bounds"]["max_source_matches"] = json!(1);
    object.contract_value["spec"]["public_behavior"]["outcomes"] =
        json!(["match", "no_match", "ambiguous"]);
    let response = &mut object.pack_value["spec"]["plan"]["operations"][0]["response"];
    response["max_records"] = json!(1);
    response["normalization"] = json!("json_object");
    response["cardinality"] = json!({
        "mechanism": "source_enforced_singleton",
        "conformance_evidence": raw_hash(SYNTHETIC_CONFORMANCE_EVIDENCE)
    });
    response["schema"] = response["schema"]["items"].clone();
    object.refresh_all();
    let object = compile(&object).expect("object decoder compiles");
    let object_debug = format!(
        "{:?}",
        object
            .iter()
            .next()
            .expect("object plan")
            .operations()
            .next()
            .expect("object operation")
            .response_decoder()
    );
    assert!(object_debug.contains("root: Object"));

    let wrapper = compile_dhis2(&dhis2_fixture()).expect("object-wrapper decoder compiles");
    let wrapper_debug = format!(
        "{:?}",
        wrapper
            .iter()
            .next()
            .expect("wrapper plan")
            .operations()
            .next()
            .expect("wrapper operation")
            .response_decoder()
    );
    assert!(wrapper_debug.contains("ObjectArrayProbeTwo"));
}

#[test]
fn impossible_compiled_decoder_shapes_fail_closed_without_value_diagnostics() {
    let registry = compile(&fixture()).expect("valid decoder fixture compiles");
    let response = registry
        .iter()
        .next()
        .expect("plan")
        .operations()
        .next()
        .expect("operation")
        .response();

    let mut mismatched_root = response.clone();
    mismatched_root.normalization = CompiledResponseNormalization::Object;
    assert_eq!(
        compile_closed_json_decoder(&mismatched_root).unwrap_err(),
        SourcePlanCompileError::CompilerInvariant
    );

    let mut invalid_schema = response.clone();
    invalid_schema.schema = CompiledResponseSchema::Object {
        nullable: false,
        reject_unknown_fields: true,
        fields: Box::new([]),
    };
    invalid_schema.normalization = CompiledResponseNormalization::Object;
    assert_eq!(
        compile_closed_json_decoder(&invalid_schema).unwrap_err(),
        SourcePlanCompileError::CompilerInvariant
    );

    let mut invalid_projection = response.clone();
    invalid_projection.outputs[0].pointer = CompiledJsonPointer {
        tokens: Box::new([]),
    };
    assert_eq!(
        compile_closed_json_decoder(&invalid_projection).unwrap_err(),
        SourcePlanCompileError::CompilerInvariant
    );
}

#[test]
fn closed_json_decoder_matches_the_reviewed_response_byte_cap() {
    use registry_platform_httputil::destination::json::MAX_CLOSED_JSON_ENCODED_BODY_BYTES;

    assert_eq!(MAX_CLOSED_JSON_ENCODED_BODY_BYTES, 8 * 1_024 * 1_024);

    let mut at_cap = fixture();
    let credential_bytes = at_cap.pack_value["spec"]["plan"]["credential_operation"]["response"]
        ["max_bytes"]
        .as_u64()
        .expect("credential response bound");
    let platform_cap =
        u64::try_from(MAX_CLOSED_JSON_ENCODED_BODY_BYTES).expect("platform response cap fits u64");
    let source_bytes = platform_cap + credential_bytes;
    at_cap.pack_value["spec"]["plan"]["operations"][0]["response"]["max_bytes"] =
        json!(platform_cap);
    at_cap.pack_value["spec"]["bounds"]["max_source_bytes"] = json!(source_bytes);
    at_cap.contract_value["spec"]["bounds"]["max_source_bytes"] = json!(source_bytes);
    at_cap.binding_value["limits"]["max_source_bytes"] = json!(source_bytes);
    at_cap.refresh_all();
    compile(&at_cap).expect("artifact ceiling remains accepted by the platform decoder");

    let mut above_cap = at_cap;
    above_cap.pack_value["spec"]["plan"]["operations"][0]["response"]["max_bytes"] =
        json!(platform_cap + 1);
    above_cap.pack_value["spec"]["bounds"]["max_source_bytes"] = json!(source_bytes + 1);
    above_cap.contract_value["spec"]["bounds"]["max_source_bytes"] = json!(source_bytes + 1);
    above_cap.binding_value["limits"]["max_source_bytes"] = json!(source_bytes + 1);
    above_cap.refresh_all();
    assert_eq!(
        compile(&above_cap).unwrap_err(),
        SourcePlanCompileError::Artifact(SourcePlanArtifactError::InvalidLimits),
        "the artifact hard ceiling rejects a response above 8 MiB",
    );

    let registry = compile(&fixture()).expect("valid decoder fixture compiles");
    let mut impossible = registry
        .iter()
        .next()
        .expect("plan")
        .operations()
        .next()
        .expect("operation")
        .response()
        .clone();
    impossible.max_bytes =
        u32::try_from(MAX_CLOSED_JSON_ENCODED_BODY_BYTES + 1).expect("test cap fits u32");
    assert_eq!(
        compile_closed_json_decoder(&impossible).unwrap_err(),
        SourcePlanCompileError::CompilerInvariant
    );
}

#[test]
fn wrapper_records_field_index_resolves_non_first_compiled_schema_field() {
    let mut fixture = dhis2_fixture();
    fixture.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["fields"]
        ["aaa_metadata"] = json!({
        "required": true,
        "schema": {
            "type": "integer",
            "nullable": false,
            "minimum": 1,
            "maximum": 1
        }
    });
    fixture.refresh_all();

    let registry = compile_dhis2(&fixture).expect("non-first wrapper records field compiles");
    let operation = registry
        .iter()
        .next()
        .expect("plan")
        .operations()
        .next()
        .expect("operation");
    let records_field_index = match operation.response().normalization() {
        CompiledResponseNormalization::ObjectArrayProbeTwo {
            records_field_index,
        } => records_field_index,
        other => panic!("unexpected normalization: {other:?}"),
    };
    assert_eq!(records_field_index, 1);
    assert_eq!(
        operation
            .response()
            .schema()
            .object_fields()
            .expect("wrapper object")[records_field_index]
            .name(),
        "enrollments"
    );
}

#[test]
fn dhis2_wrapper_normalization_rejects_every_unbounded_or_unlinked_shape() {
    let reject = |mut fixture: Fixture| {
        fixture.refresh_all();
        assert!(matches!(
            compile_dhis2(&fixture),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::InvalidAcquisition
            ))
        ));
    };

    let mut missing = dhis2_fixture();
    missing.pack_value["spec"]["plan"]["operations"][0]["response"]
        .as_object_mut()
        .expect("response object")
        .remove("records_field");
    reject(missing);

    let mut unknown = dhis2_fixture();
    unknown.pack_value["spec"]["plan"]["operations"][0]["response"]["records_field"] =
        json!("unknown");
    reject(unknown);

    let mut optional = dhis2_fixture();
    optional.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["fields"]
        ["enrollments"]["required"] = json!(false);
    reject(optional);

    let mut second_array = dhis2_fixture();
    second_array.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["fields"]
        ["other"] = second_array.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]
        ["fields"]["enrollments"]
        .clone();
    reject(second_array);

    let mut wrong_bound = dhis2_fixture();
    wrong_bound.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["fields"]
        ["enrollments"]["schema"]["max_items"] = json!(1);
    reject(wrong_bound);

    let mut unlinked_probe = dhis2_fixture();
    unlinked_probe.pack_value["spec"]["plan"]["operations"][0]["query"]["pageSize"]["value"] =
        json!("1");
    reject(unlinked_probe);
}

#[test]
fn runtime_profile_is_typed_bounded_and_has_no_artifact_reparse_surface() {
    let fixture = fixture();
    let registry = compile(&fixture).expect("valid runtime profile");
    let plan = registry.iter().next().expect("plan");
    let profile = plan.runtime_profile();

    assert_eq!(profile.profile(), plan.profile());
    assert_eq!(profile.integration_pack(), plan.integration_pack());
    assert_eq!(profile.workload_id().as_str(), "registry-notary");
    assert_eq!(
        profile.required_scope().as_str(),
        "registry:consult:person-status"
    );
    assert_eq!(profile.tenant().as_str(), "synthetic-government");
    assert_eq!(profile.registry_instance().as_str(), "people-primary");
    assert_eq!(
        profile.purposes().collect::<Vec<_>>(),
        ["benefit-verification"]
    );
    assert_eq!(profile.legal_basis(), "public_task");
    assert!(profile.authorization().mandatory_obligations().is_empty());
    assert_eq!(
        profile.public_limits().operation().max_source_bytes,
        131_072
    );
    assert_eq!(
        profile.effective_limits().operation().max_source_bytes,
        81_920
    );
    assert_eq!(profile.acquisition().fields().len(), 1);
    assert_eq!(profile.output().len(), 1);
    assert_eq!(profile.operations().len(), 1);
    assert_eq!(
        profile
            .dispatch()
            .bounded_http_operations()
            .expect("bounded HTTP order")
            .iter()
            .map(OperationId::as_str)
            .collect::<Vec<_>>(),
        ["lookup-status"]
    );
    assert!(
        profile.completion_seed_canonical_bytes_max()
            <= super::super::runtime_profile::MAX_COMPLETION_SEED_CANONICAL_BYTES_V1
    );
    assert!(
        profile.completion_audit_canonical_bytes_max()
            <= super::super::completion_seed::MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1
    );
    assert_eq!(
        (
            profile.completion_seed_canonical_bytes_max(),
            profile.completion_audit_canonical_bytes_max(),
        ),
        (2_333, 7_890),
        "portable completion sizing is a reviewed golden",
    );

    let debug = format!("{profile:?}");
    for forbidden in [
        "synthetic-government",
        "people-primary",
        "people-api-reader",
        "registry-data-private",
        "https://registry.example.test",
    ] {
        assert!(
            !debug.contains(forbidden),
            "runtime Debug leaked {forbidden}"
        );
    }
    let source = include_str!("../runtime_profile.rs");
    for forbidden in [
        "serde_json::",
        "Serialize",
        "Deserialize",
        "canonical_public_contract",
        "canonical_json()",
    ] {
        assert!(
            !source.contains(forbidden),
            "runtime profile source unexpectedly contains {forbidden}"
        );
    }
}

#[test]
fn compiles_runtime_ready_request_response_and_input_capabilities() {
    let fixture = fixture();
    let registry = compile(&fixture).expect("compiled runtime descriptors");
    let plan = registry.iter().next().expect("plan");
    let input = plan.inputs().next().expect("input slot");
    assert_eq!(input.name(), "subject_id");
    let canonical = input
        .canonicalize_and_validate(&parsed_string("Person-42"))
        .expect("valid selector");
    assert!(canonical.binding_matches(
        plan.profile().contract_hash(),
        input.name(),
        0,
        input.input_type()
    ));
    let unrelated_contract = ProfileContractHash::try_from(
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    .unwrap();
    assert!(!canonical.binding_matches(&unrelated_contract, input.name(), 0, input.input_type()));
    assert_eq!(canonical.as_str(), "Person-42");
    assert!(!format!("{canonical:?}").contains("Person-42"));
    assert!(input
        .canonicalize_and_validate(&parsed_string("contains space"))
        .is_none());
    assert!(input
        .canonicalize_and_validate(&parsed_string(&"x".repeat(257)))
        .is_none());

    let operation = plan.operations().next().expect("operation");
    assert_eq!(operation.request_codec(), CompiledRequestCodec::None);
    assert_eq!(operation.request_signer(), None);
    assert_eq!(operation.request_max_bytes(), 8_192);
    assert_eq!(operation.request_timeout_ms(), 5_000);
    assert_eq!(operation.request_max_in_flight(), 1);
    assert_eq!(operation.auth(), CompiledSourceAuth::OAuthClientCredentials);
    assert_eq!(operation.query().len(), 4);
    assert_eq!(operation.headers().len(), 0);
    assert!(operation.body().is_none());
    assert!(matches!(
        operation.projection(),
        CompiledProjectionMechanism::QueryParameterExact { .. }
    ));
    assert_eq!(
        operation.response().accepted_statuses().collect::<Vec<_>>(),
        vec![200]
    );
    assert!(matches!(
        operation.response().schema(),
        CompiledResponseSchema::Array { max_items: 2, .. }
    ));
    assert!(matches!(
        operation.response().cardinality(),
        CompiledCardinalityMechanism::ProbeQueryParameter { .. }
    ));
    operation
        .transport_template()
        .render(
            &["registration_status", "2", "benefits", "Person-42"],
            &[],
            Some(DestinationAuthorizationValue::bearer(b"token".to_vec()).expect("typed bearer")),
            None,
        )
        .expect("compiled template renders exact values");
}

#[test]
fn resolved_core_is_consumed_only_by_its_exact_compiled_plan() {
    use crate::consultation::commitments::CanonicalConsultationInputs;
    use crate::consultation::{
        DeclaredOperationFootprint, ParsedConsultationInputs, ParsedPurpose,
        PreAuthorizationConsultationCore, ProfileIdentity, SelectorProvenance,
    };

    let fixture = fixture();
    let registry = compile(&fixture).expect("compiled runtime descriptors");
    let plan = registry.iter().next().expect("plan");
    let make_core = |profile: ProfileIdentity,
                     selector: SelectorProvenance,
                     purpose: &str,
                     input_name: &str,
                     input_value: &str,
                     footprint: DeclaredOperationFootprint| {
        PreAuthorizationConsultationCore::new_for_test(
            profile,
            selector,
            ParsedPurpose::try_parse(purpose).unwrap(),
            ParsedConsultationInputs::try_parse(input_name, input_value).unwrap(),
            footprint,
        )
    };

    let exact = make_core(
        plan.profile().clone(),
        plan.runtime_profile()
            .subject()
            .selector_provenance()
            .clone(),
        "benefit-verification",
        "subject_id",
        "Person-42",
        plan.footprint().clone(),
    );
    assert!(CanonicalConsultationInputs::try_from_resolved_core(plan, exact).is_ok());

    let wrong_profile = ProfileIdentity::new(
        plan.profile().id().clone(),
        plan.profile().version(),
        ProfileContractHash::try_from(
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .unwrap(),
    );
    let mut narrower_bounds = plan.footprint().bounds();
    narrower_bounds.timeout_ms -= 1;
    let wrong_footprint = DeclaredOperationFootprint::try_new(
        plan.footprint().operation().as_str(),
        plan.footprint().acquisition_class(),
        plan.footprint().acquired_fields(),
        narrower_bounds,
    )
    .unwrap();
    let mismatches = [
        make_core(
            wrong_profile,
            plan.runtime_profile()
                .subject()
                .selector_provenance()
                .clone(),
            "benefit-verification",
            "subject_id",
            "Person-42",
            plan.footprint().clone(),
        ),
        make_core(
            plan.profile().clone(),
            SelectorProvenance::WorkloadSelected,
            "benefit-verification",
            "subject_id",
            "Person-42",
            plan.footprint().clone(),
        ),
        make_core(
            plan.profile().clone(),
            plan.runtime_profile()
                .subject()
                .selector_provenance()
                .clone(),
            "unreviewed-purpose",
            "subject_id",
            "Person-42",
            plan.footprint().clone(),
        ),
        make_core(
            plan.profile().clone(),
            plan.runtime_profile()
                .subject()
                .selector_provenance()
                .clone(),
            "benefit-verification",
            "other_input",
            "Person-42",
            plan.footprint().clone(),
        ),
        make_core(
            plan.profile().clone(),
            plan.runtime_profile()
                .subject()
                .selector_provenance()
                .clone(),
            "benefit-verification",
            "subject_id",
            "contains space",
            plan.footprint().clone(),
        ),
        make_core(
            plan.profile().clone(),
            plan.runtime_profile()
                .subject()
                .selector_provenance()
                .clone(),
            "benefit-verification",
            "subject_id",
            "Person-42",
            wrong_footprint,
        ),
    ];
    for mismatch in mismatches {
        assert!(CanonicalConsultationInputs::try_from_resolved_core(plan, mismatch).is_err());
    }
}

#[test]
fn compiled_input_automaton_has_bounded_complexity_and_exact_semantics() {
    let mut matcher_fixture = fixture();
    for inputs in [
        &mut matcher_fixture.pack_value["spec"]["input_slots"],
        &mut matcher_fixture.contract_value["spec"]["inputs"],
    ] {
        inputs["subject_id"]["pattern"] = json!(r"^[A-Z]?\d+[._:-]$");
    }
    matcher_fixture.refresh_all();
    let registry = compile(&matcher_fixture).expect("bounded matcher grammar");
    let input = registry
        .iter()
        .next()
        .expect("plan")
        .inputs()
        .next()
        .expect("input");
    for matching in ["A12_", "12-", "Z0:"] {
        assert!(input
            .canonicalize_and_validate(&parsed_string(matching))
            .is_some());
    }
    for rejected in ["a12_", "A_", "12", "A12__"] {
        assert!(input
            .canonicalize_and_validate(&parsed_string(rejected))
            .is_none());
    }

    let mut lowercase = fixture();
    for inputs in [
        &mut lowercase.pack_value["spec"]["input_slots"],
        &mut lowercase.contract_value["spec"]["inputs"],
    ] {
        inputs["subject_id"]["pattern"] = json!("^[a-z]+$");
        inputs["subject_id"]["x-registry-canonicalization"] = json!("ascii_lowercase");
    }
    lowercase.refresh_all();
    let registry = compile(&lowercase).expect("lowercase matcher");
    let value = registry
        .iter()
        .next()
        .expect("plan")
        .inputs()
        .next()
        .expect("input")
        .canonicalize_and_validate(&parsed_string("SUBJECT"))
        .expect("canonical selector");
    assert_eq!(value.as_str(), "subject");

    for invalid in [
        format!("^{}$", "a".repeat(129)),
        "^(a+)+$".to_owned(),
        "^a*$".to_owned(),
    ] {
        let mut fixture = fixture();
        fixture.pack_value["spec"]["input_slots"]["subject_id"]["pattern"] = json!(invalid.clone());
        fixture.contract_value["spec"]["inputs"]["subject_id"]["pattern"] = json!(invalid);
        fixture.refresh_all();
        assert!(matches!(
            compile(&fixture),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::InvalidLimits | SourcePlanArtifactError::InvalidExpression
            ))
        ));
    }
}

#[test]
fn synthetic_hashes_are_stable_golden_vectors() {
    assert_eq!(
        vector_manifest()["schema"].as_str(),
        Some("registry.relay.source-plan-hash-vectors.v1")
    );
    assert_eq!(
        vector_manifest()["canonicalization"].as_str(),
        Some("RFC8785")
    );
    assert_eq!(
        vector_manifest()["numeric_domain"].as_str(),
        Some("finite-safe-integers-only")
    );
    assert_eq!(
        vector_manifest()["domain_separator"]["terminal_nul_bytes"].as_u64(),
        Some(1)
    );
    for (name, file, domain) in [
        ("integration_pack", "integration-pack.json", PACK_DOMAIN),
        (
            "consultation_policy",
            "consultation-policy.json",
            POLICY_DOMAIN,
        ),
        (
            "consultation_policy_utf8_ordering",
            "consultation-policy-utf8-ordering.json",
            POLICY_DOMAIN,
        ),
        ("public_contract", "public-contract.json", CONTRACT_DOMAIN),
        (
            "public_contract_utf8_ordering",
            "public-contract-utf8-ordering.json",
            CONTRACT_DOMAIN,
        ),
        ("private_binding", "private-binding.json", BINDING_DOMAIN),
    ] {
        let entry = vector_entry(name);
        assert_eq!(entry["file"].as_str(), Some(file));
        assert_eq!(
            entry["domain_label"].as_str().map(str::as_bytes),
            Some(domain.strip_suffix(&[0]).expect("one terminal NUL"))
        );
    }

    let fixture = fixture();
    assert_eq!(fixture.pack_hash, vector_expected_hash("integration_pack"));
    assert_eq!(
        typed_hash(POLICY_DOMAIN, VECTOR_POLICY),
        vector_expected_hash("consultation_policy")
    );
    assert_eq!(
        fixture.contract_hash,
        vector_expected_hash("public_contract")
    );
    assert_eq!(
        typed_hash(BINDING_DOMAIN, &fixture.binding),
        vector_expected_hash("private_binding")
    );
    let registry = compile(&fixture).expect("golden bundle compiles");
    assert_eq!(
        registry.iter().next().expect("golden plan").binding_hash(),
        vector_expected_hash("private_binding")
    );
    let contract = parse_public_contract(&fixture.contract, &fixture.contract_hash)
        .expect("golden contract parses");
    let derived_policy = derive_consultation_policy(&contract.document)
        .expect("normalized contract derives its policy");
    let vector_policy = parse_json_strict(VECTOR_POLICY).expect("strict portable policy JSON");
    assert_eq!(
        derived_policy.canonical_json,
        canonicalize_json(&vector_policy).expect("canonical policy vector")
    );
    assert_eq!(
        derived_policy.hash.as_str(),
        vector_expected_hash("consultation_policy")
    );

    assert_eq!(
        typed_hash(POLICY_DOMAIN, VECTOR_POLICY_UTF8_ORDERING),
        vector_expected_hash("consultation_policy_utf8_ordering")
    );
    assert_eq!(
        typed_hash(CONTRACT_DOMAIN, VECTOR_CONTRACT_UTF8_ORDERING),
        vector_expected_hash("public_contract_utf8_ordering")
    );
    let ordering_contract = parse_public_contract(
        VECTOR_CONTRACT_UTF8_ORDERING,
        vector_expected_hash("public_contract_utf8_ordering"),
    )
    .expect("UTF-8 ordering contract parses through production validation");
    let ordering_policy = derive_consultation_policy(&ordering_contract.document)
        .expect("UTF-8 ordering policy derives through production code");
    let ordering_vector = parse_json_strict(VECTOR_POLICY_UTF8_ORDERING)
        .expect("strict portable UTF-8 ordering policy JSON");
    assert_eq!(
        ordering_policy.canonical_json,
        canonicalize_json(&ordering_vector).expect("canonical UTF-8 ordering policy vector")
    );
    assert_eq!(
        ordering_policy.hash.as_str(),
        vector_expected_hash("consultation_policy_utf8_ordering")
    );
    let utf8_order = vec!["\u{e000}".to_owned(), "\u{10000}".to_owned()];
    assert_eq!(
        ordering_contract.document.spec.authorization.purposes,
        utf8_order
    );
    let mut utf16_order = utf8_order.clone();
    utf16_order.sort_by_key(|value| value.encode_utf16().collect::<Vec<_>>());
    assert_ne!(
        utf8_order, utf16_order,
        "vector must distinguish UTF-8 and UTF-16 order"
    );

    let mut changed_pack = fixture.pack_value.clone();
    changed_pack["spec"]["plan"]["operations"][0]["path"] = json!("/api/person/status-v2");
    assert_ne!(
        typed_hash(
            PACK_DOMAIN,
            &serde_json::to_vec(&changed_pack).expect("changed pack JSON")
        ),
        vector_expected_hash("integration_pack")
    );

    let mut changed_contract = fixture.contract_value.clone();
    changed_contract["spec"]["authorization"]["purposes"] =
        json!(["civil-registration-verification"]);
    assert_ne!(
        typed_hash(
            CONTRACT_DOMAIN,
            &serde_json::to_vec(&changed_contract).expect("changed contract JSON")
        ),
        vector_expected_hash("public_contract")
    );

    let mut changed_binding = fixture.binding_value.clone();
    changed_binding["credential"]["generation"] = json!(8);
    assert_ne!(
        typed_hash(
            BINDING_DOMAIN,
            &serde_json::to_vec(&changed_binding).expect("changed binding JSON")
        ),
        vector_expected_hash("private_binding")
    );

    let mut equivalent_origin = self::fixture();
    equivalent_origin.binding_value["data_destination"]["origin"] =
        json!("https://registry.example.test:443");
    equivalent_origin.binding_value["credential_destination"]["origin"] =
        json!("https://identity.example.test:443");
    equivalent_origin.refresh_binding();
    let registry = compile(&equivalent_origin).expect("equivalent canonical origins");
    assert_eq!(
        registry
            .iter()
            .next()
            .expect("equivalent-origin plan")
            .binding_hash(),
        vector_expected_hash("private_binding")
    );
}

#[test]
fn policy_preimage_has_the_closed_fixed_v1_decision_shape() {
    let policy = parse_json_strict(VECTOR_POLICY).expect("strict policy vector");
    assert_eq!(
        policy,
        json!({
            "schema": "registry.relay.consultation-policy.v1",
            "enforcement_profile": "registry.relay.consultation-pdp/v1",
            "rule_set": "registry.relay.consultation-policy-rules.v1",
            "id": "relay.synthetic.person-status.exact",
            "action": "consultation_execute",
            "target": {
                "profile": {
                    "id": "synthetic.person-status.exact",
                    "version": "1"
                },
                "integration_pack": {
                    "id": "synthetic.person-status",
                    "version": "1",
                    "hash": vector_expected_hash("integration_pack")
                }
            },
            "authorization": {
                "workload": "registry-notary",
                "required_scope": "registry:consult:person-status",
                "purposes": ["benefit-verification"],
                "legal_basis": "public_task",
                "consent": {"required": false},
                "mandatory_obligations": []
            },
            "decision": {
                "permit": "unqualified",
                "decision_cache": "disabled",
                "max_decision_age_ms": 1000,
                "unavailable": "deny"
            }
        })
    );
}

#[test]
fn every_authored_policy_semantic_changes_policy_and_contract_hashes() {
    let fixture = fixture();
    let base_policy_hash = fixture.contract_value["spec"]["authorization"]["policy"]["hash"]
        .as_str()
        .expect("base policy hash")
        .to_owned();
    let base_contract_hash = fixture.contract_hash;
    let changes = [
        ("/id", json!("synthetic.person-status.other")),
        ("/version", json!("2")),
        (
            "/spec/integration_pack/id",
            json!("synthetic.person-status.other"),
        ),
        ("/spec/integration_pack/version", json!("2")),
        (
            "/spec/integration_pack/hash",
            json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        ),
        ("/spec/authorization/workload", json!("registry-auditor")),
        (
            "/spec/authorization/required_scope",
            json!("registry:consult:other"),
        ),
        (
            "/spec/authorization/purposes",
            json!(["civil-registration-verification"]),
        ),
        ("/spec/authorization/legal_basis", json!("consent")),
        (
            "/spec/authorization/policy/id",
            json!("relay.synthetic.person-status.other"),
        ),
        (
            "/spec/authorization/consent",
            json!({
                "required": true,
                "verifier": {
                    "id": "registry.consent.v1",
                    "hash": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                },
                "max_age_ms": 60000,
                "revocation": "online_required",
                "unavailable": "deny"
            }),
        ),
        ("/spec/authorization/policy/max_decision_age_ms", json!(999)),
    ];

    for (pointer, replacement) in changes {
        let mut changed = fixture.contract_value.clone();
        *changed
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("known test pointer {pointer}")) = replacement;
        refresh_policy_hash(&mut changed);
        let changed_policy_hash = changed["spec"]["authorization"]["policy"]["hash"]
            .as_str()
            .expect("changed policy hash")
            .to_owned();
        assert_ne!(
            changed_policy_hash, base_policy_hash,
            "policy preimage omitted {pointer}"
        );
        let changed_contract = serde_json::to_vec(&changed).expect("changed contract");
        let changed_contract_hash = typed_hash(CONTRACT_DOMAIN, &changed_contract);
        let production_contract = parse_public_contract(&changed_contract, &changed_contract_hash)
            .unwrap_or_else(|error| {
                panic!("production parser rejected matching mutation {pointer}: {error}")
            });
        let production_policy = derive_consultation_policy(&production_contract.document)
            .unwrap_or_else(|error| {
                panic!("production derivation rejected matching mutation {pointer}: {error}")
            });
        assert_eq!(
            production_policy.hash.as_str(),
            changed_policy_hash,
            "production derivation disagrees with the independent oracle for {pointer}"
        );
        assert_ne!(
            changed_contract_hash, base_contract_hash,
            "contract hash did not bind policy change at {pointer}"
        );
    }
}

#[test]
fn stale_policy_digest_fails_before_a_matching_authored_contract_hash() {
    let mut fixture = fixture();
    fixture.contract_value["spec"]["authorization"]["policy"]["hash"] =
        json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    fixture.contract = serde_json::to_vec(&fixture.contract_value).expect("contract JSON");
    fixture.contract_hash = typed_hash(CONTRACT_DOMAIN, &fixture.contract);

    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::PolicyHashMismatch
        ))
    ));
}

#[test]
fn updated_policy_digest_requires_the_corresponding_contract_hash() {
    let mut fixture = fixture();
    let stale_contract_hash = fixture.contract_hash.clone();
    fixture.contract_value["spec"]["authorization"]["legal_basis"] = json!("consent");
    refresh_policy_hash(&mut fixture.contract_value);
    fixture.contract = serde_json::to_vec(&fixture.contract_value).expect("contract JSON");
    fixture.contract_hash = stale_contract_hash;

    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::HashMismatch
        ))
    ));

    fixture.contract_hash = typed_hash(CONTRACT_DOMAIN, &fixture.contract);
    compile(&fixture).expect("matching derived policy and contract hashes compile");
}

#[test]
fn external_policy_artifacts_and_overlays_are_not_part_of_v1() {
    let mut fixture = fixture();
    fixture.contract_value["spec"]["authorization"]["policy"]["artifact_uri"] =
        json!("https://policy.example.test/policy.json");
    fixture.contract = serde_json::to_vec(&fixture.contract_value).expect("contract JSON");
    fixture.contract_hash = typed_hash(CONTRACT_DOMAIN, &fixture.contract);

    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::ClosedSchema
        ))
    ));
}

#[test]
fn fixed_policy_controls_cannot_be_authored_or_widened() {
    for (field, value) in [
        ("permit", json!("qualified")),
        (
            "enforcement_profile",
            json!("operator-selected-enforcement"),
        ),
        ("rule_set", json!("operator-selected-rules")),
        ("action", json!("operator-selected-action")),
    ] {
        let mut fixture = fixture();
        fixture.contract_value["spec"]["authorization"]["policy"][field] = value;
        fixture.contract = serde_json::to_vec(&fixture.contract_value).expect("contract JSON");
        fixture.contract_hash = typed_hash(CONTRACT_DOMAIN, &fixture.contract);
        assert!(matches!(
            compile(&fixture),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::ClosedSchema
            ))
        ));
    }

    for (field, value) in [
        ("decision_cache", json!("enabled")),
        ("unavailable", json!("allow")),
    ] {
        let mut fixture = fixture();
        fixture.contract_value["spec"]["authorization"]["policy"][field] = value;
        fixture.contract = serde_json::to_vec(&fixture.contract_value).expect("contract JSON");
        fixture.contract_hash = typed_hash(CONTRACT_DOMAIN, &fixture.contract);
        assert!(matches!(
            compile(&fixture),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::ClosedSchema
            ))
        ));
    }

    let mut fixture = fixture();
    fixture.contract_value["spec"]["authorization"]["policy"]["max_decision_age_ms"] = json!(1001);
    fixture.contract = serde_json::to_vec(&fixture.contract_value).expect("contract JSON");
    fixture.contract_hash = typed_hash(CONTRACT_DOMAIN, &fixture.contract);
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidLimits
        ))
    ));
}

#[test]
fn required_consent_members_are_exactly_hash_covered() {
    let consent = json!({
        "required": true,
        "verifier": {
            "id": "registry.consent.v1",
            "hash": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        },
        "max_age_ms": 60000,
        "revocation": "online_required",
        "unavailable": "deny"
    });
    let mut required_fixture = fixture();
    required_fixture.contract_value["spec"]["authorization"]["consent"] = consent.clone();
    required_fixture.refresh_all();
    let base_policy_hash = required_fixture.contract_value["spec"]["authorization"]["policy"]
        ["hash"]
        .as_str()
        .expect("required-consent policy hash")
        .to_owned();

    let contract =
        parse_public_contract(&required_fixture.contract, &required_fixture.contract_hash)
            .expect("required-consent contract parses");
    let derived =
        derive_consultation_policy(&contract.document).expect("required-consent policy derives");
    let preimage = parse_json_strict(&derived.canonical_json).expect("strict derived policy");
    assert_eq!(preimage["authorization"]["consent"], consent);

    for (pointer, replacement) in [
        (
            "/spec/authorization/consent/verifier/id",
            json!("registry.consent.v2"),
        ),
        (
            "/spec/authorization/consent/verifier/hash",
            json!("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        ),
        ("/spec/authorization/consent/max_age_ms", json!(59999)),
    ] {
        let mut changed = required_fixture.contract_value.clone();
        *changed
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("known consent pointer {pointer}")) = replacement;
        refresh_policy_hash(&mut changed);
        let changed_policy_hash = changed["spec"]["authorization"]["policy"]["hash"]
            .as_str()
            .expect("changed consent policy hash")
            .to_owned();
        assert_ne!(
            changed_policy_hash, base_policy_hash,
            "policy preimage omitted {pointer}"
        );
        let changed_contract = serde_json::to_vec(&changed).expect("changed consent contract");
        let changed_contract_hash = typed_hash(CONTRACT_DOMAIN, &changed_contract);
        let production_contract = parse_public_contract(&changed_contract, &changed_contract_hash)
            .unwrap_or_else(|error| {
                panic!("production parser rejected matching consent mutation {pointer}: {error}")
            });
        let production_policy = derive_consultation_policy(&production_contract.document)
            .unwrap_or_else(|error| {
                panic!(
                    "production derivation rejected matching consent mutation {pointer}: {error}"
                )
            });
        assert_eq!(
            production_policy.hash.as_str(),
            changed_policy_hash,
            "production derivation disagrees with consent oracle for {pointer}"
        );
    }

    for member in ["verifier", "max_age_ms", "revocation", "unavailable"] {
        let mut incomplete = fixture();
        incomplete.contract_value["spec"]["authorization"]["consent"] = consent.clone();
        incomplete.contract_value["spec"]["authorization"]["consent"]
            .as_object_mut()
            .expect("consent object")
            .remove(member);
        incomplete.contract =
            serde_json::to_vec(&incomplete.contract_value).expect("incomplete contract JSON");
        incomplete.contract_hash = typed_hash(CONTRACT_DOMAIN, &incomplete.contract);
        assert!(matches!(
            compile(&incomplete),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::InvalidPlan
            ))
        ));
    }
}

#[test]
fn bundle_verification_checks_pack_then_policy_then_binding() {
    let mut fixture = fixture();
    fixture.pack_value["schema"] = json!("registry.relay.integration-pack.v2");
    fixture.pack = serde_json::to_vec(&fixture.pack_value).expect("pack JSON");
    fixture.contract_value["spec"]["authorization"]["policy"]["hash"] =
        json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    fixture.contract = serde_json::to_vec(&fixture.contract_value).expect("contract JSON");
    fixture.contract_hash = typed_hash(CONTRACT_DOMAIN, &fixture.contract);
    fixture.binding_value["unreviewed"] = json!(true);
    fixture.refresh_binding();

    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::UnsupportedSchema
        ))
    ));

    fixture.pack_value["schema"] = json!("registry.relay.integration-pack.v1");
    fixture.pack = serde_json::to_vec(&fixture.pack_value).expect("pack JSON");
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::PolicyHashMismatch
        ))
    ));
}

proptest! {
    #[test]
    fn policy_digest_is_invariant_to_raw_purpose_order(
        purposes in proptest::collection::btree_set("[a-z]{1,12}", 1..8)
    ) {
        let mut fixture = fixture();
        let sorted = purposes.into_iter().collect::<Vec<_>>();
        fixture.contract_value["spec"]["authorization"]["purposes"] = json!(sorted);
        fixture.refresh_all();
        let canonical_contract = canonicalize_json(&fixture.contract_value)
            .expect("canonical normalized contract");
        let canonical_hash = fixture.contract_hash.clone();
        let canonical_policy = fixture.contract_value["spec"]["authorization"]["policy"]["hash"]
            .clone();

        let mut reversed = fixture.contract_value["spec"]["authorization"]["purposes"]
            .as_array()
            .expect("purpose array")
            .clone();
        reversed.reverse();
        fixture.contract_value["spec"]["authorization"]["purposes"] = Value::Array(reversed);
        fixture.contract = serde_json::to_vec(&fixture.contract_value).expect("raw reordered contract");

        let registry = compile(&fixture)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let plan = registry.iter().next().expect("compiled plan");
        prop_assert_eq!(plan.canonical_public_contract(), canonical_contract.as_slice());
        prop_assert_eq!(
            plan.profile().contract_hash().as_str(),
            canonical_hash.as_str()
        );
        prop_assert_eq!(
            plan.runtime_profile().authorization().policy().hash().as_str(),
            canonical_policy.as_str().expect("policy hash")
        );
    }
}

#[test]
fn policy_purposes_normalize_in_utf8_byte_order() {
    let mut fixture = fixture();
    let expected = vec!["\u{e000}", "\u{10000}"];
    fixture.contract_value["spec"]["authorization"]["purposes"] = json!(expected);
    fixture.refresh_all();
    let expected_contract =
        canonicalize_json(&fixture.contract_value).expect("canonical normalized Unicode contract");

    fixture.contract_value["spec"]["authorization"]["purposes"] = json!(["\u{10000}", "\u{e000}"]);
    fixture.contract =
        serde_json::to_vec(&fixture.contract_value).expect("raw reordered Unicode contract");
    let registry = compile(&fixture).expect("raw purpose order is normalized");
    let plan = registry.iter().next().expect("compiled plan");

    assert_eq!(
        plan.runtime_profile().purposes().collect::<Vec<_>>(),
        expected
    );
    assert_eq!(plan.canonical_public_contract(), expected_contract);
}

#[test]
fn hashes_the_normalized_typed_object_not_raw_array_order() {
    let fixture = fixture();
    let mut contract = fixture.contract_value.clone();
    contract["spec"]["public_behavior"]["outcomes"] = json!(["ambiguous", "no_match", "match"]);
    let contract = serde_json::to_vec(&contract).expect("contract JSON");
    assert_ne!(
        typed_hash(CONTRACT_DOMAIN, &contract),
        fixture.contract_hash
    );

    let contracts = [PinnedSourcePlanArtifact::new(
        &contract,
        &fixture.contract_hash,
    )];
    let packs = [PinnedSourcePlanArtifact::new(
        &fixture.pack,
        &fixture.pack_hash,
    )];
    let bindings = [fixture.binding.as_slice()];
    let conformance_hash = raw_hash(SYNTHETIC_CONFORMANCE_EVIDENCE);
    let negative_security_hash = raw_hash(SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE);
    let minimization_hash = raw_hash(SYNTHETIC_MINIMIZATION_EVIDENCE);
    let evidence = [
        PinnedEvidenceArtifact::new(
            EvidenceClass::Conformance,
            SYNTHETIC_CONFORMANCE_EVIDENCE,
            &conformance_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::NegativeSecurity,
            SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE,
            &negative_security_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::Minimization,
            SYNTHETIC_MINIMIZATION_EVIDENCE,
            &minimization_hash,
        ),
    ];
    CompiledSourcePlanRegistry::compile(
        &SourcePlanArtifactBundle::new(&contracts, &packs, &bindings).with_evidence(&evidence),
    )
    .expect("set ordering normalizes before hashing");
}

#[test]
fn strict_yaml_and_json_bind_to_the_same_canonical_object() {
    let fixture = fixture();
    let json = parse_private_binding(&fixture.binding).expect("JSON binding");
    let yaml = binding_as_strict_yaml(&fixture.binding_value);
    let yaml = parse_private_binding(yaml.as_bytes()).expect("strict YAML binding");
    assert_eq!(json.hash().as_str(), yaml.hash().as_str());
    let quoted_key_yaml =
        binding_as_strict_yaml(&fixture.binding_value).replacen("tenant:", "\"tenant\":", 1);
    let quoted =
        parse_private_binding(quoted_key_yaml.as_bytes()).expect("quoted string mapping key");
    assert_eq!(json.hash().as_str(), quoted.hash().as_str());
}

#[test]
fn strict_yaml_rejects_ambiguous_features_in_every_scalar_context() {
    for invalid in [
        "value: &anchor safe\nother: *anchor\n",
        "base: &base {value: safe}\nmerged: {<<: *base}\n",
        "value: !custom safe\n",
        "--- {value: safe}\n",
        "value: safe\n...\n---\nvalue: other\n",
        "%YAML 1.2\nvalue: safe\n",
        "values:\n  - yes\n",
        "values: [on, 01, 0x10]\n",
        "value: 12:34:56\n",
        "value: 2026-07-11\n",
        "value: -0x10\n",
        "value: +01\n",
        "value: 1_000\n",
        "value: .5\n",
        "value: 9007199254740992\n",
        "value: -9007199254740992\n",
        "value: 9.007199254740992e15\n",
        "1: non-string-key\n",
        "true: non-string-key\n",
        "null: non-string-key\n",
        "[\"key\"]: non-string-key\n",
        "{\"key\": \"value\"}: non-string-key\n",
    ] {
        assert!(
            matches!(
                parse_private_binding(invalid.as_bytes()),
                Err(SourcePlanArtifactError::StrictJson)
            ),
            "accepted ambiguous YAML: {invalid:?}"
        );
    }

    let fixture = fixture();
    let yaml = binding_as_strict_yaml(&fixture.binding_value);
    let duplicate_plain = format!("tenant: duplicate-government\n{yaml}");
    assert!(matches!(
        parse_private_binding(duplicate_plain.as_bytes()),
        Err(SourcePlanArtifactError::StrictJson)
    ));
    let duplicate_escaped = format!("\"\\u0074enant\": \"duplicate-government\"\n{yaml}");
    assert!(matches!(
        parse_private_binding(duplicate_escaped.as_bytes()),
        Err(SourcePlanArtifactError::StrictJson)
    ));

    let mut maximum = fixture.binding_value.clone();
    maximum["credential"]["generation"] = json!(9_007_199_254_740_991_u64);
    let maximum = binding_as_strict_yaml(&maximum);
    parse_private_binding(maximum.as_bytes()).expect("maximum exact YAML integer");

    let integer_as_float = binding_as_strict_yaml(&fixture.binding_value).replacen(
        "generation: 7",
        "generation: 7.0",
        1,
    );
    assert!(parse_private_binding(integer_as_float.as_bytes()).is_err());
}

#[test]
fn rejects_duplicate_json_members_before_typed_parsing() {
    let fixture = fixture();
    let raw = String::from_utf8(fixture.contract.clone()).expect("UTF-8");
    let duplicate = raw.replacen(
        "\"schema\":",
        "\"schema\":\"registry.relay.consultation-contract.v1\",\"schema\":",
        1,
    );
    let contracts = [PinnedSourcePlanArtifact::new(
        duplicate.as_bytes(),
        &fixture.contract_hash,
    )];
    let packs = [PinnedSourcePlanArtifact::new(
        &fixture.pack,
        &fixture.pack_hash,
    )];
    let bindings = [fixture.binding.as_slice()];
    assert!(matches!(
        CompiledSourcePlanRegistry::compile(&SourcePlanArtifactBundle::new(
            &contracts, &packs, &bindings,
        )),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::StrictJson
        ))
    ));
}

#[test]
fn rejects_unknown_fields_at_every_closed_boundary() {
    let mut fixture = fixture();
    fixture.pack_value["spec"]["plan"]["operations"][0]["retry"] = json!(1);
    fixture.pack = serde_json::to_vec(&fixture.pack_value).expect("pack JSON");
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::ClosedSchema
        ))
    ));
}

#[test]
fn rejects_committed_hash_mismatch() {
    let fixture = fixture();
    let wrong_hash = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let contracts = [PinnedSourcePlanArtifact::new(&fixture.contract, wrong_hash)];
    let packs = [PinnedSourcePlanArtifact::new(
        &fixture.pack,
        &fixture.pack_hash,
    )];
    let bindings = [fixture.binding.as_slice()];
    assert!(matches!(
        CompiledSourcePlanRegistry::compile(&SourcePlanArtifactBundle::new(
            &contracts, &packs, &bindings,
        )),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::HashMismatch
        ))
    ));
}

#[test]
fn semantic_output_aliases_are_distinct_from_complete_raw_acquisition() {
    let fixture = semantic_alias_fixture();

    let registry = compile(&fixture).expect("semantic alias maps to a complete raw schema");
    let operation = registry
        .iter()
        .next()
        .expect("plan")
        .operations()
        .next()
        .expect("operation");
    assert_eq!(
        operation.acquired_fields().collect::<Vec<_>>(),
        ["registration_status"]
    );
    assert_eq!(operation.disclosed_fields().collect::<Vec<_>>(), ["status"]);

    let seed = completion_seed_value(&fixture);
    assert!(seed["acquisition"]["schema"]["fields"]
        .get("registration_status")
        .is_some());
    assert!(seed["acquisition"]["schema"]["fields"]
        .get("status")
        .is_none());
    assert_eq!(seed["acquisition"]["disclosure_fields"], json!(["status"]));
}

#[test]
fn full_date_fact_requires_an_exact_ten_byte_string_source() {
    let mut valid = semantic_alias_fixture();
    valid.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["items"]["fields"]
        ["registration_status"]["schema"]["max_bytes"] = json!(10);
    valid.pack_value["spec"]["reviewed_acquisition"]["fields"]["registration_status"]
        ["max_bytes"] = json!(10);
    valid.pack_value["spec"]["acquisition"]["fields"]["registration_status"]["max_bytes"] =
        json!(10);
    valid.contract_value["spec"]["acquisition"]["fields"]["registration_status"]["max_bytes"] =
        json!(10);
    valid.pack_value["spec"]["output"]["status"]["type"] = json!("date");
    valid.pack_value["spec"]["output"]["status"]["max_bytes"] = json!(10);
    valid.contract_value["spec"]["output"]["status"]["type"] = json!("date");
    valid.contract_value["spec"]["output"]["status"]["max_bytes"] = json!(10);
    valid.refresh_all();
    compile(&valid).expect("ten-byte string backs a full-date output");

    let mut invalid = valid;
    invalid.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["items"]["fields"]
        ["registration_status"]["schema"]["max_bytes"] = json!(11);
    invalid.pack_value["spec"]["reviewed_acquisition"]["fields"]["registration_status"]
        ["max_bytes"] = json!(11);
    invalid.pack_value["spec"]["acquisition"]["fields"]["registration_status"]["max_bytes"] =
        json!(11);
    invalid.contract_value["spec"]["acquisition"]["fields"]["registration_status"]["max_bytes"] =
        json!(11);
    invalid.refresh_all();
    assert!(matches!(
        compile(&invalid),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));
}

#[test]
fn reviewed_status_outcomes_bypass_record_decoding_and_are_disjoint() {
    let mut valid = fixture();
    valid.pack_value["spec"]["bounds"]["max_source_matches"] = json!(2);
    valid.contract_value["spec"]["bounds"]["max_source_matches"] = json!(2);
    valid.pack_value["spec"]["reviewed_acquisition"]["cardinality"] = json!("probe_two");
    valid.pack_value["spec"]["plan"]["operations"][0]["response"]["max_records"] = json!(1);
    valid.pack_value["spec"]["plan"]["operations"][0]["response"]["normalization"] =
        json!("json_object");
    let record =
        valid.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["items"].take();
    valid.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"] = record;
    valid.pack_value["spec"]["plan"]["operations"][0]["response"]["cardinality"] = json!({
        "mechanism": "source_enforced_singleton",
        "conformance_evidence": valid.pack_value["spec"]["evidence"]["conformance"][0].clone()
    });
    valid.pack_value["spec"]["plan"]["operations"][0]["response"]["accepted_statuses"] =
        json!([200, 404, 409]);
    valid.pack_value["spec"]["plan"]["operations"][0]["response"]["status_outcomes"] =
        json!({"no_match": [404], "ambiguous": [409]});
    valid.contract_value["spec"]["public_behavior"]["outcomes"] =
        json!(["match", "no_match", "ambiguous"]);
    valid.refresh_all();

    let registry = compile(&valid).expect("reviewed status outcomes");
    let response = registry
        .iter()
        .next()
        .expect("plan")
        .operations()
        .next()
        .expect("operation")
        .response();
    assert_eq!(
        response.status_outcome(404),
        Some(CompiledStatusOutcome::NoMatch)
    );
    assert_eq!(
        response.status_outcome(409),
        Some(CompiledStatusOutcome::Ambiguous)
    );
    assert_eq!(response.status_outcome(200), None);

    let mut overlap = valid;
    overlap.pack_value["spec"]["plan"]["operations"][0]["response"]["status_outcomes"]
        ["ambiguous"] = json!([404]);
    overlap.refresh_all();
    assert!(matches!(
        compile(&overlap),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));
}

#[test]
fn one_declared_input_path_segment_compiles_as_a_non_injectable_selector() {
    let mut fixture = fixture();
    let input = fixture.pack_value["spec"]["plan"]["operations"][0]["query"]["subject_id"].take();
    fixture.pack_value["spec"]["plan"]["operations"][0]["query"]
        .as_object_mut()
        .expect("query")
        .remove("subject_id");
    fixture.pack_value["spec"]["plan"]["operations"][0]["path"] =
        json!("/api/v2/spp/Individual/{individual_id}");
    fixture.pack_value["spec"]["plan"]["operations"][0]["path_parameters"] =
        json!({"individual_id": input});
    fixture.pack_value["spec"]["reviewed_acquisition"]["selector"]["components"]["subject_id"] =
        json!({"type": "path", "parameter": "individual_id"});
    fixture.refresh_all();

    let registry = compile(&fixture).expect("closed path selector");
    let operation = registry
        .iter()
        .next()
        .expect("plan")
        .operations()
        .next()
        .expect("operation");
    assert_eq!(operation.fixed_path(), "/api/v2/spp/Individual/");
    assert!(operation.path_segment().is_some());
    assert_eq!(
        operation.selector().location(),
        &CompiledSelectorLocation::PathSegment
    );

    let mut second = fixture;
    second.pack_value["spec"]["plan"]["operations"][0]["path_parameters"]["extra"] =
        json!({"source": "literal", "value": "fixed"});
    second.refresh_all();
    assert!(matches!(
        compile(&second),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidPlan
        ))
    ));
}

#[test]
fn completion_seed_static_shape_matches_the_frozen_sql_contract() {
    let seed = completion_seed_value(&fixture());
    assert_eq!(
        seed["acquisition"]["provenance_contract"],
        json!({
            "source_observed_at": null,
            "source_revision": null,
            "snapshot_generation": "absent",
            "snapshot_published_at": "absent"
        })
    );
    assert_eq!(
        seed["acquisition"]["public_outcomes"],
        json!(["match", "no_match", "ambiguous"])
    );
    assert_eq!(
        seed["acquisition"]["schema"]["type"],
        json!("acquisition_union")
    );
    assert!(seed.get("authorized_operation_union").is_none());
}

#[test]
fn completion_sizing_checks_every_purpose_when_exact_and_conservative_order_differ() {
    let mut fixture = fixture();
    let escaped_exact_winner = "\"".repeat(200);
    let longer_conservative_winner = "a".repeat(256);
    fixture.contract_value["spec"]["authorization"]["purposes"] =
        json!([escaped_exact_winner, longer_conservative_winner]);
    fixture.refresh_all();

    let seed = completion_seed_value(&fixture);
    assert_eq!(
        seed["purpose"],
        json!("\"".repeat(200)),
        "JSON escaping makes the shorter purpose the exact-canonical winner"
    );
    compile(&fixture).expect("every allowed purpose passes authoritative audit sizing");
}

#[test]
fn bounded_http_runtime_commitment_digests_are_stable() {
    let normal = runtime_digests(&fixture());
    assert_eq!(
        normal.0,
        "sha256:31f0fcbc0cba178ea211bdce5da7f27a5c643a02a25cfd74cff4f97d7e4097b6"
    );
    assert_eq!(
        normal.1,
        "sha256:550f3f915fc0396e5f1dc807ea8435d03db787d1d17f23fbef0eab0289bacb36"
    );
}

#[test]
fn rhai_runtime_commitment_digest_binds_safe_script_and_dispatch_outputs() {
    let limits = rhai_test_worker_limits(2);
    let base_fixture = rhai_five_operation_fixture();
    let base = rhai_runtime_digests(&base_fixture, limits).expect("base Rhai profile compiles");

    let mut changed_script = rhai_five_operation_fixture();
    let changed_script_source = "fn consult(ctx) { result.fail(failure.source_unavailable) }";
    changed_script.pack_value["spec"]["plan"]["rhai"]["script"] = json!(changed_script_source);
    changed_script.pack_value["spec"]["plan"]["rhai"]["script_hash"] =
        json!(raw_hash(changed_script_source.as_bytes()));
    changed_script.refresh_all();
    let changed_script_digest =
        rhai_runtime_digests(&changed_script, limits).expect("changed reviewed script compiles");
    assert_ne!(changed_script_digest.0, base.0);
    assert_ne!(
        changed_script.contract_hash, base_fixture.contract_hash,
        "a Script-only change must invalidate the pinned public contract"
    );

    let mut dual_entrypoint = rhai_five_operation_fixture();
    let dual_script =
        "fn consult(ctx) { result.no_match() } fn alternate(ctx) { result.no_match() }";
    dual_entrypoint.pack_value["spec"]["plan"]["rhai"]["script"] = json!(dual_script);
    dual_entrypoint.pack_value["spec"]["plan"]["rhai"]["script_hash"] =
        json!(raw_hash(dual_script.as_bytes()));
    dual_entrypoint.refresh_all();
    let primary_entrypoint =
        rhai_runtime_digests(&dual_entrypoint, limits).expect("dual-entrypoint script compiles");
    dual_entrypoint.pack_value["spec"]["plan"]["rhai"]["entrypoint"] = json!("alternate");
    dual_entrypoint.refresh_all();
    let alternate_entrypoint = rhai_runtime_digests(&dual_entrypoint, limits)
        .expect("alternate reviewed entrypoint compiles");
    assert_ne!(alternate_entrypoint.0, primary_entrypoint.0);

    let mut stale_script_hash = rhai_five_operation_fixture();
    stale_script_hash.pack_value["spec"]["plan"]["rhai"]["script_hash"] =
        json!("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    stale_script_hash.refresh_all();
    assert!(
        rhai_runtime_digests(&stale_script_hash, limits).is_err(),
        "a declared script hash that does not commit to the script must fail closed"
    );

    let mut one_call = rhai_five_operation_fixture();
    one_call.binding_value["capabilities"]["script"]["max_calls"] = json!(1);
    one_call.refresh_binding();
    let one_call_digest = rhai_runtime_digests(&one_call, rhai_test_worker_limits(1))
        .expect("one-call effective Rhai profile compiles");
    assert_ne!(one_call_digest.0, base.0);
    assert_eq!(
        one_call_digest.1, base.1,
        "effective call budget must not rewrite physical projection"
    );

    assert_eq!(
        base.0,
        "sha256:9cc086cf48221d1d5793b7dd9ec520d5cb16302de7a85140de2b22d271b46d7d"
    );
    assert_eq!(
        base.1,
        "sha256:fb6366892e6750e6efb9816f839b167af1aca64c10817d853745665291f1008d"
    );
    assert_eq!(
        changed_script_digest.0,
        "sha256:67e301a861318d8ae2cad483796af48bd7391fd74ff341c7bdb574d9cea0eba8"
    );
    assert_eq!(
        primary_entrypoint.0,
        "sha256:c63f22b783e038edca5ba725a6df02d64ab26a29e03f5f9608b10903f53483eb"
    );
    assert_eq!(
        alternate_entrypoint.0,
        "sha256:10a33a8873b9fe47a0d30cb84e224207185609025877b6f272e3dd684d26aeee"
    );
    assert_eq!(
        one_call_digest.0,
        "sha256:d8884109b57610c05c87b9581b51ab73ad994e04114a70ffe68c87dce9fc3468"
    );
}

#[test]
fn script_authority_uses_five_rules_but_two_effective_exchange_slots() {
    let fixture = rhai_five_operation_fixture();
    let worker_limits = RhaiWorkerLimits {
        max_calls: 2,
        memory_bytes: 67_108_864,
        cpu_ms: 500,
        ipc_frame_bytes: 131_072,
        instructions: 50_000,
        call_depth: 8,
        string_bytes: 32_768,
        array_items: 256,
        map_entries: 256,
        output_bytes: 32_768,
        concurrency: 1,
    };
    let worker = RhaiWorkerCapability::from_initialized_worker(&fixture.pack_hash, worker_limits)
        .expect("bounded Script worker capability");
    let registry = compile_with_rhai_workers(&fixture, &[worker]).expect("reviewed Rhai plan");
    let plan = registry.iter().next().expect("Rhai plan");
    let profile = plan.runtime_profile();
    assert_eq!(profile.public_limits().operation().max_data_exchanges, 5);
    assert_eq!(profile.effective_limits().operation().max_data_exchanges, 2);
    assert_eq!(plan.limits().operation().max_data_exchanges, 2);
    assert_eq!(plan.steps().len(), 0, "Rhai has no fixed runtime flow");
    assert_eq!(
        profile
            .dispatch()
            .script_limits()
            .expect("Rhai limits")
            .max_calls(),
        2
    );
    assert_eq!(plan.operations().len(), 0);

    let seed = rhai_five_operation_two_slot_completion_seed_fixture();
    assert_eq!(seed["bounds"]["data_exchanges"], json!(2));
    let permits = seed["dispatch"]["permit_bindings"]
        .as_array()
        .expect("permit bindings");
    assert_eq!(permits.len(), 3, "one credential plus two data slots");
    for permit in &permits[1..] {
        assert!(permit.get("allowed_operation_ids").is_none());
    }
}

#[test]
fn script_requires_one_consultation_wide_request_byte_budget() {
    let mut mismatch = rhai_five_operation_fixture();
    mismatch.pack_value["spec"]["plan"]["script_authority"]["request_max_bytes"] = json!(0);
    mismatch.refresh_all();
    assert!(matches!(
        compile(&mismatch),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidPlan
        ))
    ));
}

#[test]
fn script_post_authority_rejects_broad_duplicate_and_escaping_paths() {
    for path in [
        "/api/**",
        "/api/../private",
        "/api/%2Fprivate",
        "https://other.test/api",
    ] {
        let mut fixture = rhai_five_operation_fixture();
        fixture.pack_value["spec"]["plan"]["script_authority"]["allow"] = json!([{
            "method": "READ_ONLY_POST",
            "path": path,
            "semantics": "read_only"
        }]);
        fixture.refresh_all();
        assert!(matches!(
            compile(&fixture),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::InvalidPlan
            ))
        ));
    }

    let mut duplicate = rhai_five_operation_fixture();
    duplicate.pack_value["spec"]["plan"]["script_authority"]["allow"] = json!([
        {"method": "GET", "path": "/api/records/*"},
        {"method": "GET", "path": "/api/records/*"}
    ]);
    duplicate.refresh_all();
    assert!(matches!(
        compile(&duplicate),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidPlan
        ))
    ));
}

#[test]
fn script_post_authority_accepts_one_narrow_parameterized_path() {
    let mut fixture = rhai_five_operation_fixture();
    fixture.pack_value["spec"]["plan"]["script_authority"]["allow"] = json!([{
        "method": "READ_ONLY_POST",
        "path": "/api/records/*",
        "semantics": "read_only"
    }]);
    fixture.refresh_all();
    let worker = RhaiWorkerCapability::from_initialized_worker(
        &fixture.pack_hash,
        rhai_test_worker_limits(2),
    )
    .expect("Script worker capability");
    compile_with_rhai_workers(&fixture, &[worker]).expect("narrow POST authority compiles");
}

fn script_body_rhai_fixture() -> Fixture {
    rhai_five_operation_fixture()
}

#[test]
fn script_authority_accepts_bounded_bodies_without_synthesized_response_schemas() {
    let mut fixture = script_body_rhai_fixture();
    let normalized = super::super::artifact::author_integration_pack(&fixture.pack)
        .expect("script-body integration pack normalizes");
    fixture.pack_value = parse_json_strict(normalized.canonical_json()).expect("canonical pack");
    fixture.refresh_all();
    let worker = RhaiWorkerCapability::from_initialized_worker(
        &fixture.pack_hash,
        rhai_test_worker_limits(2),
    )
    .expect("script-body worker capability");
    let registry = compile_with_rhai_workers(&fixture, &[worker])
        .expect("product-neutral script-body operations compile");
    let plan = registry.iter().next().expect("script-body plan");
    assert_eq!(plan.operations().len(), 0);
    assert_eq!(
        plan.script_authority()
            .expect("Script authority")
            .response_max_bytes(),
        16_000
    );
}

#[test]
fn script_authority_rejects_an_unbounded_response_body() {
    let mut fixture = script_body_rhai_fixture();
    fixture.pack_value["spec"]["plan"]["script_authority"]["response"]["max_bytes"] = json!(0);
    fixture.refresh_all();
    assert!(matches!(
        super::super::artifact::author_integration_pack(&fixture.pack),
        Err(SourcePlanArtifactError::InvalidPlan)
    ));
}

#[test]
fn authoring_validation_initializes_reviewed_rhai_capabilities_without_bypassing_compilation() {
    let fixture = rhai_five_operation_fixture();
    let contracts = [PinnedSourcePlanArtifact::new(
        &fixture.contract,
        &fixture.contract_hash,
    )];
    let packs = [PinnedSourcePlanArtifact::new(
        &fixture.pack,
        &fixture.pack_hash,
    )];
    let bindings = [fixture.binding.as_slice()];
    let conformance_hash = raw_hash(SYNTHETIC_CONFORMANCE_EVIDENCE);
    let negative_security_hash = raw_hash(SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE);
    let minimization_hash = raw_hash(SYNTHETIC_MINIMIZATION_EVIDENCE);
    let evidence = [
        PinnedEvidenceArtifact::new(
            EvidenceClass::Conformance,
            SYNTHETIC_CONFORMANCE_EVIDENCE,
            &conformance_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::NegativeSecurity,
            SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE,
            &negative_security_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::Minimization,
            SYNTHETIC_MINIMIZATION_EVIDENCE,
            &minimization_hash,
        ),
    ];
    let registry = CompiledSourcePlanRegistry::compile_for_authoring_validation(
        &SourcePlanArtifactBundle::new(&contracts, &packs, &bindings).with_evidence(&evidence),
    )
    .expect("offline authoring validates the exact executable Rhai closure");
    assert_eq!(registry.len(), 1);
}

#[test]
fn script_terminal_output_contract_retains_each_scalar_bound() {
    let string_fixture = rhai_five_operation_fixture();
    let string_worker = RhaiWorkerCapability::from_initialized_worker(
        &string_fixture.pack_hash,
        rhai_test_worker_limits(2),
    )
    .expect("string-bound Rhai worker");
    let string_registry = compile_with_rhai_workers(&string_fixture, &[string_worker])
        .expect("string-bound Rhai plan");
    let string_bounds = string_registry
        .iter()
        .next()
        .expect("string plan")
        .rhai_outputs()
        .map(CompiledRhaiOutput::output_type)
        .collect::<Vec<_>>();
    assert_eq!(
        string_bounds,
        vec![CompiledRhaiOutputType::String { max_bytes: 64 }; 5]
    );

    let mut integer_fixture = rhai_five_operation_fixture();
    let integer = json!({
        "type": "integer",
        "nullable": false,
        "minimum": -2,
        "maximum": 2
    });
    for index in 0..5 {
        let name = format!("status_{index}");
        integer_fixture.pack_value["spec"]["reviewed_acquisition"]["fields"][&name] =
            integer.clone();
        integer_fixture.pack_value["spec"]["acquisition"]["fields"][&name] = integer.clone();
        integer_fixture.contract_value["spec"]["acquisition"]["fields"][&name] = integer.clone();
        integer_fixture.pack_value["spec"]["output"][&name] = integer.clone();
        integer_fixture.contract_value["spec"]["output"][&name] = integer.clone();
    }
    integer_fixture.refresh_all();
    let integer_worker = RhaiWorkerCapability::from_initialized_worker(
        &integer_fixture.pack_hash,
        rhai_test_worker_limits(2),
    )
    .expect("integer-bound Rhai worker");
    let integer_registry = compile_with_rhai_workers(&integer_fixture, &[integer_worker])
        .expect("integer-bound Rhai plan");
    assert!(integer_registry
        .iter()
        .next()
        .expect("integer plan")
        .rhai_outputs()
        .all(|output| matches!(
            output.output_type(),
            CompiledRhaiOutputType::Integer {
                minimum: -2,
                maximum: 2
            }
        )));
}

#[test]
fn rhai_rejects_authored_steps_and_conditions() {
    let mut sequenced = rhai_five_operation_fixture();
    sequenced.pack_value["spec"]["plan"]["steps"] = json!(["lookup-status-0"]);
    sequenced.refresh_all();
    let mut conditioned = rhai_five_operation_fixture();
    conditioned.pack_value["spec"]["plan"]["step_conditions"] = json!({
        "lookup-status-1": {
            "predicate": "string_equals",
            "step": "lookup-status-0",
            "output": "route",
            "value": "route-a"
        }
    });
    conditioned.refresh_all();

    for invalid in [&sequenced, &conditioned] {
        assert!(matches!(
            compile(invalid),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::InvalidPlan
            ))
        ));
    }
}

#[test]
fn response_byte_bounds_cover_one_http_request_and_repeated_largest_rhai_calls() {
    let mut bounded_exact = fixture();
    bounded_exact.pack_value["spec"]["bounds"]["max_source_bytes"] = json!(81_920);
    bounded_exact.contract_value["spec"]["bounds"]["max_source_bytes"] = json!(81_920);
    bounded_exact.refresh_all();
    compile(&bounded_exact).expect("fixed data plus credential response sum fits exactly");

    let mut bounded_private_short = fixture();
    bounded_private_short.binding_value["limits"]["max_source_bytes"] = json!(81_919);
    bounded_private_short.refresh_binding();
    assert!(matches!(
        compile(&bounded_private_short),
        Err(SourcePlanCompileError::BindingWidening)
    ));

    let mut bounded_short = bounded_exact;
    bounded_short.pack_value["spec"]["bounds"]["max_source_bytes"] = json!(81_919);
    bounded_short.contract_value["spec"]["bounds"]["max_source_bytes"] = json!(81_919);
    bounded_short.refresh_all();
    assert!(matches!(
        compile(&bounded_short),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidLimits
        ))
    ));

    let worker_limits = RhaiWorkerLimits {
        max_calls: 2,
        memory_bytes: 67_108_864,
        cpu_ms: 500,
        ipc_frame_bytes: 131_072,
        instructions: 50_000,
        call_depth: 8,
        string_bytes: 32_768,
        array_items: 256,
        map_entries: 256,
        output_bytes: 32_768,
        concurrency: 1,
    };
    let mut rhai_exact = rhai_five_operation_fixture();
    // The public bound covers five Script calls under the reviewed authority,
    // while the private binding narrows execution to two calls. Both include
    // the exact 16 KiB credential-response ceiling.
    rhai_exact.pack_value["spec"]["bounds"]["max_source_bytes"] = json!(96_384);
    rhai_exact.contract_value["spec"]["bounds"]["max_source_bytes"] = json!(96_384);
    rhai_exact.binding_value["limits"]["max_source_bytes"] = json!(48_384);
    rhai_exact.refresh_all();
    let worker =
        RhaiWorkerCapability::from_initialized_worker(&rhai_exact.pack_hash, worker_limits)
            .expect("exact-bound worker");
    compile_with_rhai_workers(&rhai_exact, &[worker])
        .expect("public and effective repeated-call byte bounds fit exactly");

    let mut public_short = rhai_exact;
    public_short.pack_value["spec"]["bounds"]["max_source_bytes"] = json!(96_383);
    public_short.contract_value["spec"]["bounds"]["max_source_bytes"] = json!(96_383);
    public_short.refresh_all();
    assert!(matches!(
        compile(&public_short),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidLimits
        ))
    ));

    let mut effective_short = rhai_five_operation_fixture();
    effective_short.binding_value["limits"]["max_source_bytes"] = json!(48_383);
    effective_short.refresh_all();
    let worker =
        RhaiWorkerCapability::from_initialized_worker(&effective_short.pack_hash, worker_limits)
            .expect("effective short-bound worker");
    assert!(matches!(
        compile_with_rhai_workers(&effective_short, &[worker]),
        Err(SourcePlanCompileError::BindingWidening)
    ));
}

#[test]
fn compiler_seed_values_use_the_exact_state_plane_identifier_grammars() {
    use super::super::identifiers::{
        CanonicalPurpose, CredentialReferenceId, LegalBasisId, SourceDestinationId,
    };

    let seed = normal_completion_seed_fixture();
    LegalBasisId::try_from(
        seed["policy"]["legal_basis_id"]
            .as_str()
            .expect("legal basis"),
    )
    .expect("SQL-compatible legal basis");
    CanonicalPurpose::try_from(seed["purpose"].as_str().expect("purpose"))
        .expect("SQL-compatible purpose");
    SourceDestinationId::try_from(
        seed["destinations"]["data_destination_id"]
            .as_str()
            .expect("data destination"),
    )
    .expect("SQL-compatible data destination");
    SourceDestinationId::try_from(
        seed["destinations"]["credential_destination_id"]
            .as_str()
            .expect("credential destination"),
    )
    .expect("SQL-compatible credential destination");
    CredentialReferenceId::try_from(
        seed["credential"]["reference"]
            .as_str()
            .expect("credential reference"),
    )
    .expect("SQL-compatible credential reference");

    let mut invalid_legal_basis = fixture();
    invalid_legal_basis.contract_value["spec"]["authorization"]["legal_basis"] =
        json!("public:task");
    invalid_legal_basis.refresh_all();
    assert!(matches!(
        compile(&invalid_legal_basis),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidIdentity
        ))
    ));

    let mut invalid_purpose = fixture();
    invalid_purpose.contract_value["spec"]["authorization"]["purposes"] =
        json!(["benefit,verification"]);
    invalid_purpose.refresh_all();
    assert!(matches!(
        compile(&invalid_purpose),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidText
        ))
    ));

    for (path, value) in [
        (("data_destination", "id"), "data:primary"),
        (("credential_destination", "id"), "credential:primary"),
        (("credential", "ref"), "reader:v1"),
    ] {
        let mut invalid_binding = fixture();
        invalid_binding.binding_value[path.0][path.1] = json!(value);
        invalid_binding.refresh_binding();
        assert!(matches!(
            compile(&invalid_binding),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::InvalidIdentity
            ))
        ));
    }
}

#[test]
fn rejects_pack_semantics_that_do_not_match_public_contract() {
    let mut fixture = fixture();
    fixture.pack_value["spec"]["input_slots"]["subject_id"]["pattern"] = json!("^[0-9]+$");
    fixture.refresh_all();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::ContractMismatch)
    ));
}

#[test]
fn rejects_private_limit_widening_but_accepts_resource_narrowing() {
    let mut fixture = fixture();
    fixture.binding_value["limits"]["timeout_ms"] = json!(5_001);
    fixture.refresh_binding();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::BindingWidening)
    ));

    fixture.binding_value["limits"]["timeout_ms"] = json!(1_000);
    fixture.refresh_binding();
    let registry = compile(&fixture).expect("downward refinement");
    assert_eq!(
        registry
            .iter()
            .next()
            .expect("plan")
            .limits()
            .operation()
            .timeout_ms,
        1_000
    );
}

#[test]
fn rejects_missing_credential_shape_and_overlapping_destinations() {
    let mut fixture = fixture();
    fixture.binding_value["credential"] = Value::Null;
    fixture.refresh_binding();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::InvalidCredentialBinding)
    ));

    let mut second = self::fixture();
    second.binding_value["credential_destination"]["origin"] =
        second.binding_value["data_destination"]["origin"].clone();
    second.refresh_binding();
    assert!(matches!(
        compile(&second),
        Err(SourcePlanCompileError::UnsafeDestination)
    ));
}

#[test]
fn rejects_credential_generation_outside_interoperable_json_range() {
    let mut fixture = fixture();
    fixture.binding_value["credential"]["generation"] = json!(9_007_199_254_740_992_u64);
    fixture.refresh_binding();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidLimits
        ))
    ));
}

#[test]
fn oauth_cache_identity_changes_for_every_security_relevant_input() {
    let baseline = oauth_cache_fingerprint(&fixture());

    let mut credential_generation = fixture();
    credential_generation.binding_value["credential"]["generation"] = json!(8);
    credential_generation.refresh_binding();
    assert_ne!(baseline, oauth_cache_fingerprint(&credential_generation));

    let mut credential_reference = fixture();
    credential_reference.binding_value["credential"]["ref"] = json!("other-reader");
    credential_reference.refresh_binding();
    assert_ne!(baseline, oauth_cache_fingerprint(&credential_reference));

    let mut destination = fixture();
    destination.binding_value["credential_destination"]["id"] = json!("registry-oauth-secondary");
    destination.refresh_binding();
    assert_ne!(baseline, oauth_cache_fingerprint(&destination));

    let mut tenant_binding = fixture();
    tenant_binding.binding_value["tenant"] = json!("other-government");
    tenant_binding.refresh_binding();
    assert_ne!(baseline, oauth_cache_fingerprint(&tenant_binding));

    let mut audience = fixture();
    audience.pack_value["spec"]["plan"]["credential_operation"]["request"]["audience"] =
        json!("other-audience");
    audience.refresh_all();
    assert_ne!(baseline, oauth_cache_fingerprint(&audience));

    let mut scopes = fixture();
    scopes.pack_value["spec"]["plan"]["credential_operation"]["request"]["scopes"] =
        json!(["registry.audit", "registry.read"]);
    scopes.refresh_all();
    assert_ne!(baseline, oauth_cache_fingerprint(&scopes));

    let mut resource = fixture();
    resource.pack_value["spec"]["plan"]["credential_operation"]["request"]["resource"] =
        json!("https://registry.example.test/");
    resource.refresh_all();
    assert_ne!(baseline, oauth_cache_fingerprint(&resource));

    let mut lifetime = fixture();
    lifetime.pack_value["spec"]["plan"]["credential_operation"]["response"]
        ["max_token_lifetime_ms"] = json!(1_800_000);
    lifetime.pack_value["spec"]["plan"]["credential_operation"]["response"]
        ["expires_in_max_seconds"] = json!(1_800);
    lifetime.binding_value["limits"]["max_token_lifetime_ms"] = json!(900_000);
    lifetime.refresh_all();
    assert_ne!(baseline, oauth_cache_fingerprint(&lifetime));

    let mut skew = fixture();
    skew.pack_value["spec"]["plan"]["credential_operation"]["response"]["expiry_safety_skew_ms"] =
        json!(45_000);
    skew.refresh_all();
    assert_ne!(baseline, oauth_cache_fingerprint(&skew));
}

#[test]
fn oauth_client_credentials_request_is_exact_bounded_and_redacted() {
    let registry = compile(&fixture()).expect("OAuth fixture compiles");
    let operation = registry
        .iter()
        .next()
        .expect("plan")
        .credential_operation()
        .expect("credential operation");
    let body = operation
        .encode_body(b"doctor-client", b"doctor-secret")
        .expect("bounded JSON OAuth body");
    assert_eq!(
            body.as_slice(),
            br#"{"grant_type":"client_credentials","client_id":"doctor-client","client_secret":"doctor-secret","audience":"registry-data","scope":"registry.read"}"#
        );
    assert_eq!(body.len(), body.capacity());

    let request = operation
        .render_request(
            Zeroizing::new(b"doctor-client".to_vec()),
            Zeroizing::new(b"doctor-secret".to_vec()),
        )
        .expect("rendered credential request");
    let debug = format!("{request:?} {operation:?}");
    assert!(!debug.contains("doctor-client"));
    assert!(!debug.contains("doctor-secret"));
    assert!(debug.contains("[REDACTED]"));

    for (client_id, client_secret) in [
        (Vec::new(), b"secret".to_vec()),
        (b"client".to_vec(), Vec::new()),
        (vec![b'x'; 257], b"secret".to_vec()),
        (b"client".to_vec(), vec![b'x'; 513]),
        (vec![0xff], b"secret".to_vec()),
    ] {
        assert!(matches!(
            operation.render_request(Zeroizing::new(client_id), Zeroizing::new(client_secret),),
            Err(CredentialOperationFailure::CredentialUnavailable)
        ));
    }
}

#[test]
fn oauth_request_encoders_cover_form_sorting_and_worst_case_json_escaping() {
    let mut form = fixture();
    form.pack_value["spec"]["plan"]["credential_operation"]["request"]["format"] =
        json!("form_client_secret_body");
    form.pack_value["spec"]["plan"]["credential_operation"]["request"]["scopes"] =
        json!(["registry.audit", "registry.read"]);
    form.refresh_all();
    let registry = compile(&form).expect("form OAuth fixture compiles");
    let operation = registry
        .iter()
        .next()
        .expect("plan")
        .credential_operation()
        .expect("credential operation");
    let body = operation
        .encode_body(b"client+id", b"secret/value")
        .expect("bounded form OAuth body");
    assert_eq!(
            body.as_slice(),
            b"grant_type=client_credentials&client_id=client%2Bid&client_secret=secret%2Fvalue&audience=registry-data&scope=registry.audit+registry.read"
        );
    assert_eq!(body.len(), body.capacity());

    let registry = compile(&fixture()).expect("JSON OAuth fixture compiles");
    let operation = registry
        .iter()
        .next()
        .expect("plan")
        .credential_operation()
        .expect("credential operation");
    let client_id = vec![0x01; 256];
    let client_secret = vec![0x1f; 512];
    let body = operation
        .encode_body(&client_id, &client_secret)
        .expect("worst-case control bytes remain in the reviewed bound");
    assert_eq!(body.len(), body.capacity());
    assert_eq!(
        body.len(),
        operation
            .encoded_body_len(&client_id, &client_secret)
            .expect("precomputed exact length")
    );
    assert!(body.windows(6).any(|window| window == br"\u0001"));
    assert!(body.windows(6).any(|window| window == br"\u001F"));
}

#[test]
fn oauth_token_parser_is_strict_bounded_and_fail_closed() {
    let registry = compile(&fixture()).expect("OAuth fixture compiles");
    let operation = registry
        .iter()
        .next()
        .expect("plan")
        .credential_operation()
        .expect("credential operation");
    let parser = operation.parser();
    let token = parser
        .parse(
            200,
            br#"{"access_token":"abc+/._~-==","token_type":"Bearer","expires_in":3600}"#,
        )
        .expect("strict token response");
    assert_eq!(token.usable_lifetime_ms(), Some(1_770_000));
    assert!(format!("{token:?}").contains("[REDACTED]"));
    assert!(!format!("{token:?}").contains("abc+"));
    assert!(token.bearer_authorization().is_ok());

    assert!(matches!(
        parser.parse(
            201,
            br#"{"access_token":"abc","token_type":"Bearer","expires_in":60}"#,
        ),
        Err(CredentialOperationFailure::Status)
    ));
    assert!(matches!(
        parser.parse(200, &vec![b' '; 16_385]),
        Err(CredentialOperationFailure::ResponseTooLarge)
    ));

    for malformed in [
        br#"{"access_token":"abc","token_type":"Bearer","expires_in":60,"extra":true}"#.as_slice(),
        br#"{"access_token":"abc","access_token":"def","token_type":"Bearer","expires_in":60}"#,
        br#"{"access_token":"abc","token_type":"Bearer"}"#,
        br#"{"access_token":"ab=cd","token_type":"Bearer","expires_in":60}"#,
        br#"{"access_token":"","token_type":"Bearer","expires_in":60}"#,
    ] {
        assert!(matches!(
            parser.parse(200, malformed),
            Err(CredentialOperationFailure::MalformedResponse)
        ));
    }
    assert!(matches!(
        parser.parse(
            200,
            br#"{"access_token":"abc","token_type":"bearer","expires_in":60}"#,
        ),
        Err(CredentialOperationFailure::InvalidTokenType)
    ));
    for invalid_expiry in [
        br#"{"access_token":"abc","token_type":"Bearer","expires_in":"60"}"#.as_slice(),
        br#"{"access_token":"abc","token_type":"Bearer","expires_in":60.5}"#,
        br#"{"access_token":"abc","token_type":"Bearer","expires_in":0}"#,
        br#"{"access_token":"abc","token_type":"Bearer","expires_in":3601}"#,
    ] {
        assert!(matches!(
            parser.parse(200, invalid_expiry),
            Err(CredentialOperationFailure::InvalidExpiresIn)
        ));
    }

    let expired = CompiledOAuth2TokenParser {
        max_response_bytes: 1_024,
        accepted_statuses: vec![200].into_boxed_slice(),
        access_token_max_bytes: 64,
        schema: CompiledOAuth2TokenSchema::StrictAccessTokenBearerExpiresIn,
        expires_in_min_seconds: Some(1),
        expires_in_max_seconds: Some(60),
        max_token_lifetime_ms: Some(30_000),
        expiry_safety_skew_ms: Some(30_000),
    };
    assert!(matches!(
        expired.parse(
            200,
            br#"{"access_token":"abc","token_type":"Bearer","expires_in":60}"#,
        ),
        Err(CredentialOperationFailure::ExpiredAfterSkew)
    ));

    let policy = operation.failure_policy();
    assert!(!policy.retry_allowed());
    assert!(!policy.stale_token_fallback_allowed());
    assert!(!policy.data_dispatch_allowed_after_failure());
}

#[test]
fn rejects_credential_id_collisions_and_token_lifetime_widening_or_misuse() {
    let mut collision = fixture();
    collision.pack_value["spec"]["plan"]["credential_operation"]["id"] = json!("lookup-status");
    collision.refresh_all();
    assert!(matches!(
        compile(&collision),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidPlan
        ))
    ));

    let mut widening = fixture();
    widening.binding_value["limits"]["max_token_lifetime_ms"] = json!(3_600_001);
    widening.refresh_binding();
    assert!(matches!(
        compile(&widening),
        Err(SourcePlanCompileError::BindingWidening)
    ));

    let mut unused = fixture();
    unused.pack_value["spec"]["plan"]["operations"][0]["auth"] = json!({
        "mode": "basic",
        "max_value_bytes": 256
    });
    unused.pack_value["spec"]["plan"]["credential_destination_slot"] = Value::Null;
    unused.pack_value["spec"]["plan"]["credential_operation"] = Value::Null;
    unused.pack_value["spec"]["bounds"]["max_credential_exchanges"] = json!(0);
    unused.contract_value["spec"]["bounds"]["max_credential_exchanges"] = json!(0);
    unused.binding_value["credential_destination"] = Value::Null;
    unused.refresh_all();
    assert!(matches!(
        compile(&unused),
        Err(SourcePlanCompileError::BindingWidening)
    ));
}

#[test]
fn rejects_missing_live_destination_and_unused_capability() {
    let mut fixture = fixture();
    fixture.binding_value["data_destination"] = Value::Null;
    fixture.refresh_binding();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::InvalidCredentialBinding)
    ));

    let mut second = self::fixture();
    second.binding_value["capabilities"]["allow_script"] = json!(true);
    second.refresh_binding();
    assert!(matches!(
        compile(&second),
        Err(SourcePlanCompileError::CapabilityMismatch)
    ));
}

#[test]
fn rejects_unreviewed_parameter_value_and_secret_shaped_field() {
    let mut fixture = fixture();
    fixture.binding_value["deployment_parameters"]["program"] = json!("unreviewed");
    fixture.refresh_binding();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::InvalidDeploymentParameter)
    ));

    let mut second = self::fixture();
    second.binding_value["secret"] = json!("must-not-be-accepted");
    second.refresh_binding();
    assert!(matches!(
        compile(&second),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::ClosedSchema
        ))
    ));
}

#[test]
fn consent_requires_closed_verifier_freshness_and_revocation_contract() {
    let mut fixture = fixture();
    fixture.contract_value["spec"]["authorization"]["consent"] = json!({"required": true});
    fixture.contract = serde_json::to_vec(&fixture.contract_value).expect("contract JSON");
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidPlan
        ))
    ));

    fixture.contract_value["spec"]["authorization"]["consent"] = json!({
        "required": true,
        "verifier": {
            "id": "registry.consent.v1",
            "hash":
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        },
        "max_age_ms": 60000,
        "revocation": "online_required",
        "unavailable": "deny"
    });
    fixture.refresh_all();
    compile(&fixture).expect("complete consent contract");
}

#[test]
fn mandatory_obligations_are_required_and_structurally_empty_in_v1() {
    let mut missing = fixture();
    missing.contract_value["spec"]["authorization"]
        .as_object_mut()
        .expect("authorization object")
        .remove("mandatory_obligations");
    missing.refresh_all();
    assert!(matches!(
        compile(&missing),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::ClosedSchema
        ))
    ));

    for value in [json!([{}]), json!(["unsupported"])] {
        let mut nonempty = fixture();
        nonempty.contract_value["spec"]["authorization"]["mandatory_obligations"] = value;
        nonempty.refresh_all();
        assert!(matches!(
            compile(&nonempty),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::ClosedSchema
            ))
        ));
    }
}

#[test]
fn source_provenance_is_hash_covered_and_frozen_absent_until_pointer_mapping_v2() {
    let mut missing_contract = fixture();
    missing_contract.contract_value["spec"]
        .as_object_mut()
        .expect("contract spec")
        .remove("source_provenance");
    missing_contract.refresh_all();
    assert!(matches!(
        compile(&missing_contract),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::ClosedSchema
        ))
    ));

    let mut acquired = fixture();
    let declaration = json!({
        "source_observed_at": {
            "type": "acquired_rfc3339",
            "field": "registration_status"
        },
        "source_revision": {"type": "absent"}
    });
    acquired.contract_value["spec"]["source_provenance"] = declaration.clone();
    acquired.pack_value["spec"]["source_provenance"] = declaration;
    acquired.refresh_all();
    assert!(matches!(
        compile(&acquired),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidPlan
        ))
    ));

    let profile = compile(&fixture())
        .expect("absent provenance contract")
        .plans
        .into_values()
        .next()
        .expect("plan")
        .runtime_profile;
    assert!(matches!(
        profile.acquisition_provenance().source_observed_at(),
        super::super::runtime_profile::CompiledSourceObservedAtContract::Absent
    ));
    assert!(matches!(
        profile.acquisition_provenance().source_revision(),
        super::super::runtime_profile::CompiledSourceRevisionContract::Absent
    ));
    assert!(!profile
        .acquisition_provenance()
        .snapshot_generation_required());
    assert!(!profile
        .acquisition_provenance()
        .snapshot_published_at_required());
}

#[test]
fn workload_and_deployment_boundaries_use_their_exact_newtype_grammars() {
    let mut workload = fixture();
    workload.contract_value["spec"]["authorization"]["workload"] = json!("registry:notary");
    workload.refresh_all();
    assert!(matches!(
        compile(&workload),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidIdentity
        ))
    ));

    for field in ["tenant", "registry_instance"] {
        let mut binding = fixture();
        binding.binding_value[field] = json!("government:primary");
        binding.refresh_binding();
        assert!(matches!(
            compile(&binding),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::InvalidIdentity
            ))
        ));
    }
}

#[test]
fn rejects_dynamic_or_unsupported_plan_shape() {
    let mut fixture = fixture();
    fixture.pack_value["spec"]["plan"]["operations"][0]["path"] = json!("/people/{subject_id}");
    fixture.pack = serde_json::to_vec(&fixture.pack_value).expect("pack JSON");
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidText
        ))
    ));

    let mut second = self::fixture();
    second.pack_value["spec"]["plan"]["kind"] = json!("arbitrary_http");
    second.pack = serde_json::to_vec(&second.pack_value).expect("pack JSON");
    assert!(matches!(
        compile(&second),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::ClosedSchema
        ))
    ));
}

#[test]
fn request_shape_matches_platform_canonicalization_and_all_budget_layers() {
    let mut colon_name = fixture();
    colon_name.pack_value["spec"]["plan"]["operations"][0]["query"]["selector:subject"] =
        json!({"source": "literal", "value": "x"});
    colon_name.refresh_all();
    compile(&colon_name).expect("colon query name uses shared conservative encoding bound");

    let mut noncanonical_path = fixture();
    noncanonical_path.pack_value["spec"]["plan"]["operations"][0]["path"] =
        json!("/api/%70erson/status");
    noncanonical_path.refresh_all();
    assert!(matches!(
        compile(&noncanonical_path),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidText
        ))
    ));

    for forbidden in [
        "accept-encoding",
        "authorization",
        "connection",
        "content-length",
        "cookie",
        "forwarded",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-forwarded-custom",
        "x-real-ip",
    ] {
        let mut fixture = fixture();
        fixture.pack_value["spec"]["plan"]["operations"][0]["headers"][forbidden] =
            json!({"source": "literal", "value": "smuggled"});
        fixture.refresh_all();
        assert!(
            matches!(
                compile(&fixture),
                Err(SourcePlanCompileError::Artifact(
                    SourcePlanArtifactError::InvalidExpression
                ))
            ),
            "accepted forbidden header {forbidden}"
        );
    }

    let mut aggregate = fixture();
    aggregate.pack_value["spec"]["plan"]["operations"][0]["step_limits"]["max_request_bytes"] =
        json!(4_096);
    aggregate.refresh_all();
    assert!(matches!(
        compile(&aggregate),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidLimits
        ))
    ));

    let mut codec = fixture();
    codec.pack_value["spec"]["plan"]["operations"][0]["request_codec"] = json!("json");
    codec.refresh_all();
    assert!(matches!(
        compile(&codec),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidPlan
        ))
    ));

    let mut duplicate_status = fixture();
    duplicate_status.pack_value["spec"]["plan"]["operations"][0]["response"]["accepted_statuses"] =
        json!([200, 200]);
    duplicate_status.refresh_all();
    assert!(matches!(
        compile(&duplicate_status),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidSet
        ))
    ));

    let mut unclassified_redirect = fixture();
    unclassified_redirect.pack_value["spec"]["plan"]["operations"][0]["response"]
        ["accepted_statuses"] = json!([200, 302]);
    unclassified_redirect.refresh_all();
    assert!(matches!(
        compile(&unclassified_redirect),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));

    let mut auth_bound = fixture();
    auth_bound.pack_value["spec"]["plan"]["credential_operation"]["response"]
        ["access_token_max_bytes"] = json!(8_186);
    auth_bound.refresh_all();
    assert!(matches!(
        compile(&auth_bound),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidLimits
        ))
    ));
}

#[test]
fn projection_and_cardinality_are_request_linked_not_boolean_assertions() {
    let mut projection = fixture();
    projection.pack_value["spec"]["plan"]["operations"][0]["query"]["fields"]["value"] =
        json!("extra_field,registration_status");
    projection.refresh_all();
    assert!(matches!(
        compile(&projection),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));

    let mut cardinality = fixture();
    cardinality.pack_value["spec"]["plan"]["operations"][0]["query"]["limit"]["value"] = json!("1");
    cardinality.refresh_all();
    assert!(matches!(
        compile(&cardinality),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));

    let mut boolean = fixture();
    boolean.pack_value["spec"]["plan"]["operations"][0]["response"]
        .as_object_mut()
        .expect("response object")
        .remove("cardinality");
    boolean.pack_value["spec"]["plan"]["operations"][0]["response"]["cardinality_enforced"] =
        json!(true);
    boolean.refresh_all();
    assert!(matches!(
        compile(&boolean),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::ClosedSchema
        ))
    ));
}

#[test]
fn basic_and_static_bearer_use_bound_credentials_without_oauth_destination() {
    for (mode, expected) in [
        ("basic", CompiledSourceAuth::Basic),
        ("static_bearer", CompiledSourceAuth::StaticBearer),
    ] {
        let mut fixture = fixture();
        fixture.pack_value["spec"]["plan"]["operations"][0]["auth"] = json!({
            "mode": mode,
            "max_value_bytes": 256
        });
        fixture.pack_value["spec"]["plan"]["credential_destination_slot"] = Value::Null;
        fixture.pack_value["spec"]["plan"]["credential_operation"] = Value::Null;
        fixture.pack_value["spec"]["bounds"]["max_credential_exchanges"] = json!(0);
        fixture.contract_value["spec"]["bounds"]["max_credential_exchanges"] = json!(0);
        fixture.binding_value["credential_destination"] = Value::Null;
        fixture.binding_value["limits"]
            .as_object_mut()
            .expect("binding limits")
            .remove("max_token_lifetime_ms");
        fixture.refresh_all();
        let registry = compile(&fixture).expect("direct bound credential mode");
        let plan = registry.iter().next().expect("plan");
        assert_eq!(
            plan.operations().next().expect("operation").auth(),
            expected
        );
        assert!(plan.credential_destination().is_none());

        fixture.binding_value["credential"] = Value::Null;
        fixture.refresh_binding();
        assert!(matches!(
            compile(&fixture),
            Err(SourcePlanCompileError::InvalidCredentialBinding)
        ));
    }
}

#[test]
fn api_keys_compile_only_into_fixed_noncolliding_credential_slots() {
    for (auth, expected) in [
        (
            json!({"mode":"api_key_header","name":"x-api-key","max_value_bytes":128}),
            CompiledSourceAuth::ApiKeyHeader,
        ),
        (
            json!({"mode":"api_key_query","name":"api_key","max_value_bytes":128}),
            CompiledSourceAuth::ApiKeyQuery,
        ),
    ] {
        let mut fixture = fixture();
        fixture.pack_value["spec"]["plan"]["operations"][0]["auth"] = auth;
        fixture.pack_value["spec"]["plan"]["credential_destination_slot"] = Value::Null;
        fixture.pack_value["spec"]["plan"]["credential_operation"] = Value::Null;
        fixture.pack_value["spec"]["bounds"]["max_credential_exchanges"] = json!(0);
        fixture.contract_value["spec"]["bounds"]["max_credential_exchanges"] = json!(0);
        fixture.binding_value["credential_destination"] = Value::Null;
        fixture.binding_value["limits"]
            .as_object_mut()
            .expect("binding limits")
            .remove("max_token_lifetime_ms");
        fixture.refresh_all();
        let registry = compile(&fixture).expect("fixed API-key provider");
        let operation = registry
            .iter()
            .next()
            .expect("plan")
            .operations()
            .next()
            .expect("operation");
        assert_eq!(operation.auth(), expected);
        assert_eq!(
            operation
                .api_key()
                .map(|placement| placement.max_value_bytes()),
            Some(128)
        );
        assert!(!format!("{operation:?}").contains("api_key"));
    }

    for auth in [
        json!({"mode":"api_key_header","name":"authorization","max_value_bytes":128}),
        json!({"mode":"api_key_query","name":"fields","max_value_bytes":128}),
    ] {
        let mut fixture = fixture();
        fixture.pack_value["spec"]["plan"]["operations"][0]["auth"] = auth;
        fixture.refresh_all();
        assert!(compile(&fixture).is_err());
    }
}

#[test]
fn bounded_http_rejects_more_than_one_request_and_auth_bypassing_headers() {
    let mut fixture = fixture();
    fixture.pack_value["spec"]["plan"]["steps"] = json!(["lookup-status", "lookup-status"]);
    fixture.pack_value["spec"]["bounds"]["max_data_exchanges"] = json!(2);
    fixture.pack = serde_json::to_vec(&fixture.pack_value).expect("pack JSON");
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidPlan
        ))
    ));

    let mut second = self::fixture();
    second.pack_value["spec"]["plan"]["operations"][0]["headers"] = json!({
        "authorization": {"source": "literal", "value": "embedded-credential"}
    });
    second.pack = serde_json::to_vec(&second.pack_value).expect("pack JSON");
    assert!(matches!(
        compile(&second),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidExpression
        ))
    ));
}

#[test]
fn bounded_http_selector_retains_its_exact_typed_source_and_request_location() {
    let registry = compile(&fixture()).expect("typed selector fixture");
    let operation = registry
        .iter()
        .next()
        .expect("plan")
        .operations()
        .next()
        .expect("bounded HTTP operation");
    assert_eq!(
        operation.selector().source(),
        CompiledSelectorSource::ConsultationInput { input_index: 0 }
    );
    let CompiledSelectorLocation::Query { component_index } = operation.selector().location()
    else {
        panic!("selector must be a query component");
    };
    assert_eq!(
        operation
            .query()
            .nth(*component_index)
            .expect("query")
            .name(),
        "subject_id"
    );
}

#[test]
fn decorative_selector_copies_cannot_satisfy_the_declared_location() {
    let mut fixture = fixture();
    fixture.pack_value["spec"]["plan"]["operations"][0]["query"]["subject_id"] = json!({
        "source": "literal",
        "value": "subject_id"
    });
    fixture.pack_value["spec"]["plan"]["operations"][0]["headers"]["x-subject-id"] =
        json!({"source": "consultation_input", "name": "subject_id"});
    fixture.refresh_all();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));
}

#[test]
fn compiles_bounded_nested_json_body_templates() {
    let mut fixture = fixture();
    fixture.pack_value["spec"]["plan"]["operations"][0]["method"] = json!("READ_ONLY_POST");
    fixture.pack_value["spec"]["plan"]["operations"][0]["request_codec"] = json!("json");
    fixture.pack_value["spec"]["plan"]["operations"][0]["body"] = json!({
        "kind": "object",
        "fields": {
            "query": {
                "kind": "string_literal",
                "value": "query Person($subjectId: ID!) { person(id: $subjectId) { status } }"
            },
            "variables": {
                "kind": "object",
                "fields": {
                    "subjectId": {
                        "kind": "expression",
                        "value": {
                            "source": "consultation_input",
                            "name": "subject_id"
                        }
                    }
                }
            }
        }
    });
    fixture.refresh_all();
    let registry = compile(&fixture).expect("bounded nested body");
    assert_eq!(
        registry
            .iter()
            .next()
            .expect("nested-body plan")
            .operations()
            .next()
            .expect("nested-body operation")
            .method(),
        ReadMethod::ReadOnlyPost
    );
}

#[test]
fn json_body_bounds_account_for_six_byte_control_character_escapes() {
    let body = BodyTemplateDocument::StringLiteral {
        value: "x".repeat(1_000),
    };
    assert_eq!(json_string_max_bytes(1_000), Ok(6_002));
    assert_eq!(
        body_template_max_bytes(&body, &BTreeMap::new(), &BTreeMap::new(), &BTreeMap::new(),),
        Ok(6_002)
    );
}

#[test]
fn compiles_closed_nested_response_schema_and_decoded_pointers() {
    let mut fixture = fixture();
    fixture.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["items"]["fields"] = json!({
        "person": {
            "required": true,
            "schema": {
                "type": "object",
                "nullable": false,
                "reject_unknown_fields": true,
                "fields": {
                    "registration/status": {
                        "required": true,
                        "schema": {
                            "type": "string",
                            "nullable": false,
                            "max_bytes": 64
                        }
                    },
                    "history": {
                        "required": false,
                        "schema": {
                            "type": "array",
                            "nullable": false,
                            "max_items": 4,
                            "items": {
                                "type": "object",
                                "nullable": false,
                                "reject_unknown_fields": true,
                                "fields": {
                                    "year": {
                                        "required": true,
                                        "schema": {
                                            "type": "integer",
                                            "nullable": false,
                                            "minimum": 1900,
                                            "maximum": 2200
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    fixture.pack_value["spec"]["plan"]["operations"][0]["response"]["output_mapping"]
        ["registration_status"] = json!("/person/registration~1status");
    fixture.pack_value["spec"]["plan"]["operations"][0]["query"]["fields"]["value"] =
        json!("person");
    sync_complete_acquisition_from_responses(&mut fixture);
    fixture.refresh_all();
    let registry = compile(&fixture).expect("closed nested response");
    let mapping = registry
        .iter()
        .next()
        .expect("plan")
        .operations()
        .next()
        .expect("operation")
        .response()
        .outputs()
        .next()
        .expect("mapping");
    assert_eq!(
        mapping.extraction_pointer().tokens().collect::<Vec<_>>(),
        vec!["person", "registration/status"]
    );
}

#[test]
fn complete_public_acquisition_cannot_omit_nested_source_fields() {
    let mut nested = fixture();
    nested.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["items"]["fields"]
        ["source_envelope"] = json!({
        "required": true,
        "schema": {
            "type": "object",
            "nullable": false,
            "reject_unknown_fields": true,
            "fields": {
                "routing": {
                    "required": true,
                    "schema": {
                        "type": "string",
                        "nullable": false,
                        "max_bytes": 32
                    }
                }
            }
        }
    });
    nested.pack_value["spec"]["plan"]["operations"][0]["query"]["fields"]["value"] =
        json!("registration_status,source_envelope");
    nested.refresh_all();
    assert!(matches!(
        compile(&nested),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));
}

#[test]
fn accepts_additive_raw_http_responses_but_rejects_unbounded_or_mismatched_shapes() {
    let mut open_nested = fixture();
    open_nested.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["items"]
        ["reject_unknown_fields"] = json!(false);
    open_nested.refresh_all();
    compile(&open_nested).expect("bounded HTTP may ignore unselected raw object members");

    let mut unbounded_array = fixture();
    unbounded_array.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]
        ["max_items"] = json!(257);
    unbounded_array.refresh_all();
    assert!(matches!(
        compile(&unbounded_array),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidLimits | SourcePlanArtifactError::InvalidAcquisition
        ))
    ));

    let mut missing_pointer = fixture();
    missing_pointer.pack_value["spec"]["plan"]["operations"][0]["response"]["output_mapping"]
        ["registration_status"] = json!("/missing");
    missing_pointer.refresh_all();
    assert!(matches!(
        compile(&missing_pointer),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));

    let mut wrong_scalar = fixture();
    wrong_scalar.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["items"]
        ["fields"]["registration_status"]["schema"] = json!({
        "type": "integer",
        "nullable": false,
        "minimum": 0,
        "maximum": 10
    });
    wrong_scalar.refresh_all();
    assert!(matches!(
        compile(&wrong_scalar),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));

    let mut invalid_escape = fixture();
    invalid_escape.pack_value["spec"]["plan"]["operations"][0]["response"]["output_mapping"]
        ["registration_status"] = json!("/bad~2pointer");
    invalid_escape.refresh_all();
    assert!(matches!(
        compile(&invalid_escape),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidText
        ))
    ));
}

#[test]
fn bounded_full_record_accepts_only_closed_bounded_nested_schema() {
    let mut fixture = fixture();
    fixture.pack_value["spec"]["acquisition"]["class"] = json!("bounded_full_record");
    fixture.pack_value["spec"]["reviewed_acquisition"]["class"] = json!("bounded_full_record");
    fixture.contract_value["spec"]["acquisition"]["class"] = json!("bounded_full_record");
    fixture.pack_value["spec"]["plan"]["operations"][0]["projection"] =
        json!({"mechanism": "bounded_full_record"});
    fixture.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["items"]["fields"]
        ["events"] = json!({
        "required": false,
        "schema": {
            "type": "array",
            "nullable": false,
            "max_items": 8,
            "items": {
                "type": "object",
                "nullable": false,
                "reject_unknown_fields": true,
                "fields": {
                    "code": {
                        "required": true,
                        "schema": {
                            "type": "string",
                            "nullable": false,
                            "max_bytes": 32
                        }
                    }
                }
            }
        }
    });
    sync_complete_acquisition_from_responses(&mut fixture);
    fixture.refresh_all();
    compile(&fixture).expect("bounded nested full record");
}

#[test]
fn rejects_script_without_explicit_deployment_opt_in() {
    let mut fixture = rhai_five_operation_fixture();
    let reviewed_capability = fixture.binding_value["capabilities"]["script"].clone();
    fixture.binding_value["capabilities"]["allow_script"] = json!(false);
    fixture.binding_value["capabilities"]["script"] = Value::Null;
    fixture.refresh_binding();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::RhaiNotEnabled)
    ));

    fixture.binding_value["capabilities"]["allow_script"] = json!(true);
    fixture.binding_value["capabilities"]["script"] = reviewed_capability;
    fixture.refresh_binding();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::RhaiWorkerUnavailable)
    ));
    let worker = RhaiWorkerCapability::from_initialized_worker(
        &fixture.pack_hash,
        rhai_test_worker_limits(2),
    )
    .expect("initialized worker capability");
    let registry = compile_with_rhai_workers(&fixture, &[worker])
        .expect("explicit binding plus initialized reviewed Rhai worker");
    let plan = registry.iter().next().expect("Rhai plan");
    assert_eq!(plan.steps().len(), 0, "Rhai has no fixed step sequence");
    let dispatch = plan.runtime_profile().dispatch();
    assert_eq!(plan.operations().len(), 0);
    assert_eq!(
        dispatch
            .script_limits()
            .expect("Rhai worker limits")
            .max_calls(),
        2
    );

    let mut wrong_worker_limits = rhai_test_worker_limits(2);
    wrong_worker_limits.memory_bytes -= 1;
    let wrong_limits =
        RhaiWorkerCapability::from_initialized_worker(&fixture.pack_hash, wrong_worker_limits)
            .expect("mismatched worker capability");
    assert!(matches!(
        compile_with_rhai_workers(&fixture, &[wrong_limits]),
        Err(SourcePlanCompileError::RhaiWorkerMismatch)
    ));

    let mut missing_detail = fixture.binding_value.clone();
    missing_detail["capabilities"]["script"] = Value::Null;
    fixture.binding_value = missing_detail;
    fixture.refresh_binding();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::RhaiNotEnabled)
    ));

    fixture.pack_value["spec"]["plan"]["rhai"]["script_hash"] =
        json!("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    fixture.pack = serde_json::to_vec(&fixture.pack_value).expect("pack JSON");
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::HashMismatch
        ))
    ));
}

#[test]
fn snapshot_plan_compiles_without_a_live_transport_capability() {
    let fixture = snapshot_fixture();

    let registry = compile(&fixture).expect("closed snapshot plan");
    let plan = registry.iter().next().expect("snapshot plan");
    assert_eq!(plan.kind(), SourcePlanKind::SnapshotExact);
    assert_eq!(plan.operations().len(), 0);
    assert_eq!(plan.steps().len(), 0);
    assert!(plan.data_destination().is_none());
    assert!(plan.credential_destination().is_none());
    assert_eq!(
        snapshot_completion_seed_fixture()["credential"],
        json!({"reference": null, "generation": null})
    );
    let snapshot = plan.snapshot_binding().expect("compiled snapshot binding");
    assert_eq!(snapshot.table_provider(), "people-snapshot");
    assert_eq!(snapshot.max_snapshot_age_ms(), 43_200_000);
    assert_eq!(snapshot.max_source_records(), 500);
    assert_eq!(snapshot.max_source_bytes(), 524_288);
    assert_eq!(snapshot.max_refresh_data_exchanges(), 1);
    assert_eq!(snapshot.max_refresh_credential_exchanges(), 0);
    assert_eq!(snapshot.max_refresh_data_destinations(), 1);
    assert_eq!(snapshot.snapshot_retention_generations(), 2);
    assert_eq!(snapshot.consultation_live_destinations(), 0);
    assert!(snapshot.immutable_generation());
    assert!(snapshot.digest_bound_active_pointer());
    assert_eq!(
        snapshot.keys().collect::<Vec<_>>(),
        vec![("subject_id", "subject_key")]
    );
    assert!(snapshot.keys_use_utf8_binary_equality());
    assert_eq!(
        snapshot.projection().collect::<Vec<_>>(),
        [("registration_status", "registration_status_text")]
    );
    assert_eq!(
        snapshot.physical_field_for("registration_status"),
        Some("registration_status_text")
    );
    assert_eq!(snapshot.physical_field_for("caller_selected"), None);
    assert_eq!(snapshot.source_observed_at_extraction(), None);
    assert_eq!(snapshot.source_revision_extraction(), None);
    assert!(plan
        .runtime_profile()
        .acquisition_provenance()
        .snapshot_generation_required());
    assert!(plan
        .runtime_profile()
        .acquisition_provenance()
        .snapshot_published_at_required());
    assert!(!format!("{snapshot:?}").contains("people-snapshot"));
    let vectors = parse_json_strict(SNAPSHOT_EXACT_COMPILER_VECTORS)
        .expect("strict portable SnapshotExact compiler vectors");
    assert_eq!(
        vectors["schema"],
        "registry.relay.snapshot-exact-compiler-vectors.v1"
    );
    for member in ["predicate_plan", "physical_projection"] {
        let domain = vectors[member]["domain"].as_str().expect("vector domain");
        let canonical =
            canonicalize_json(&vectors[member]["preimage"]).expect("canonical compiler preimage");
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update([0]);
        hasher.update(canonical);
        let digest = hasher.finalize();
        let digest = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            vectors[member]["digest"],
            format!("sha256:{digest}"),
            "portable {member} digest"
        );
    }
    assert_eq!(
        runtime_digests(&fixture),
        (
            vectors["predicate_plan"]["digest"]
                .as_str()
                .expect("predicate digest")
                .to_owned(),
            vectors["physical_projection"]["digest"]
                .as_str()
                .expect("projection digest")
                .to_owned(),
        )
    );
}

#[test]
fn snapshot_exact_mapping_is_closed_injective_and_hash_committed() {
    let baseline = snapshot_fixture();
    let baseline_digests = runtime_digests(&baseline);
    for (pointer, mutation) in [
        ("key_field", json!("another_subject_key")),
        ("projection", json!("another_status_text")),
    ] {
        let mut fixture = snapshot_fixture();
        match pointer {
            "key_field" => {
                fixture.binding_value["materialization"]["mapping"]["key"]["physical_field"] =
                    mutation;
            }
            "projection" => {
                fixture.binding_value["materialization"]["mapping"]["projection"]
                    ["registration_status"] = mutation;
            }
            _ => unreachable!("closed test mutation"),
        }
        fixture.refresh_all();
        assert_ne!(runtime_digests(&fixture), baseline_digests, "{pointer}");
    }

    for mutate in [
        |fixture: &mut Fixture| {
            fixture.binding_value["materialization"]["mapping"]["projection"]
                .as_object_mut()
                .expect("projection")
                .remove("registration_status");
        },
        |fixture: &mut Fixture| {
            fixture.binding_value["materialization"]["mapping"]["projection"]["unreviewed"] =
                json!("unreviewed_physical");
        },
        |fixture: &mut Fixture| {
            fixture.binding_value["materialization"]["mapping"]["projection"]
                ["registration_status"] = json!("subject_key");
        },
    ] {
        let mut fixture = snapshot_fixture();
        mutate(&mut fixture);
        fixture.refresh_all();
        assert!(matches!(
            compile(&fixture),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::InvalidAcquisition
            )) | Err(SourcePlanCompileError::ContractMismatch)
        ));
    }

    for (member, value, expected) in [
        (
            "input",
            json!("different_input"),
            Err(SourcePlanCompileError::ContractMismatch),
        ),
        (
            "physical_type",
            json!("unicode_casefold"),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::ClosedSchema,
            )),
        ),
        (
            "comparison",
            json!("text_equality"),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::ClosedSchema,
            )),
        ),
    ] {
        let mut fixture = snapshot_fixture();
        fixture.binding_value["materialization"]["mapping"]["key"][member] = value;
        fixture.refresh_all();
        assert_eq!(compile(&fixture).map(|_| ()), expected);
    }

    let mut unknown = snapshot_fixture();
    unknown.binding_value["materialization"]["mapping"]["key"]["collation"] = json!("binary");
    unknown.refresh_all();
    assert!(matches!(
        compile(&unknown),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::ClosedSchema
        ))
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn snapshot_exact_physical_mapping_mutations_change_both_runtime_digests(
        key_field in "[a-z][a-z0-9_]{0,20}",
        projected_field in "[a-z][a-z0-9_]{0,20}",
    ) {
        prop_assume!(key_field != projected_field);
        prop_assume!(key_field != "subject_key");
        prop_assume!(projected_field != "registration_status_text");
        let baseline = runtime_digests(&snapshot_fixture());
        let mut fixture = snapshot_fixture();
        fixture.binding_value["materialization"]["mapping"]["key"]["physical_field"] =
            json!(key_field);
        fixture.binding_value["materialization"]["mapping"]["projection"]
            ["registration_status"] = json!(projected_field);
        fixture.refresh_all();
        let mutated = runtime_digests(&fixture);
        prop_assert_ne!(mutated.0, baseline.0);
        prop_assert_ne!(mutated.1, baseline.1);
    }
}

#[test]
fn snapshot_exact_compiles_reviewed_provenance_extraction() {
    let mut fixture = snapshot_fixture();
    let observed_schema = json!({"type": "string", "nullable": false, "max_bytes": 64});
    let revision_schema = json!({"type": "string", "nullable": false, "max_bytes": 32});
    for (field, schema) in [
        ("source_observed_at", observed_schema),
        ("source_revision", revision_schema),
    ] {
        fixture.contract_value["spec"]["acquisition"]["fields"][field] = schema.clone();
        fixture.pack_value["spec"]["acquisition"]["fields"][field] = schema.clone();
        fixture.pack_value["spec"]["reviewed_acquisition"]["control_fields"][field] = schema;
    }
    let provenance = json!({
        "source_observed_at": {
            "type": "acquired_rfc3339",
            "field": "source_observed_at"
        },
        "source_revision": {
            "type": "acquired_string",
            "field": "source_revision",
            "max_bytes": 32
        }
    });
    fixture.contract_value["spec"]["source_provenance"] = provenance.clone();
    fixture.pack_value["spec"]["source_provenance"] = provenance;
    fixture.contract_value["spec"]["materialization"]["footprint"]["fields"] = json!([
        "registration_status",
        "source_observed_at",
        "source_revision"
    ]);
    fixture.binding_value["materialization"]["mapping"]["projection"]["source_observed_at"] =
        json!("observed_at_text");
    fixture.binding_value["materialization"]["mapping"]["projection"]["source_revision"] =
        json!("revision_text");
    fixture.refresh_all();

    let registry = compile(&fixture).expect("reviewed provenance mapping compiles");
    let plan = registry.iter().next().expect("snapshot plan");
    let snapshot = plan.snapshot_binding().expect("snapshot binding");
    assert_eq!(
        snapshot.source_observed_at_extraction(),
        Some(("source_observed_at", "observed_at_text"))
    );
    assert_eq!(
        snapshot.source_revision_extraction(),
        Some(("source_revision", "revision_text", 32))
    );
    let seed = completion_seed_value(&fixture);
    assert_eq!(
        seed["acquisition"]["provenance_contract"]["source_revision"]["max_bytes"],
        json!(32)
    );

    fixture.binding_value["materialization"]["mapping"]["projection"]["source_revision"] =
        json!("observed_at_text");
    fixture.refresh_all();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));
}

#[test]
fn snapshot_binding_rejects_missing_widened_or_live_destination_shapes() {
    let mut missing = snapshot_fixture();
    missing.binding_value["materialization"] = Value::Null;
    missing.refresh_binding();
    assert!(matches!(
        compile(&missing),
        Err(SourcePlanCompileError::MissingBinding)
    ));

    for (field, value) in [
        ("max_snapshot_age_ms", json!(86_400_001_u64)),
        ("max_source_records", json!(1_001_u64)),
        ("max_source_bytes", json!(1_048_577_u64)),
        ("max_data_exchanges", json!(3)),
        ("max_credential_exchanges", json!(2)),
        ("snapshot_retention_generations", json!(4)),
    ] {
        let mut fixture = snapshot_fixture();
        fixture.binding_value["materialization"][field] = value;
        fixture.refresh_binding();
        assert!(
            matches!(
                compile(&fixture),
                Err(SourcePlanCompileError::BindingWidening)
            ),
            "accepted widened snapshot field {field}"
        );
    }

    let mut zero_destination = snapshot_fixture();
    zero_destination.binding_value["materialization"]["max_data_destinations"] = json!(0);
    zero_destination.refresh_binding();
    assert!(matches!(
        compile(&zero_destination),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidLimits
        ))
    ));

    let mut live_destination = snapshot_fixture();
    live_destination.binding_value["data_destination"] =
        fixture().binding_value["data_destination"].clone();
    live_destination.refresh_binding();
    assert!(matches!(
        compile(&live_destination),
        Err(SourcePlanCompileError::InvalidCredentialBinding)
    ));

    for bound in [
        "max_data_exchanges",
        "max_credential_exchanges",
        "max_data_destinations",
    ] {
        let mut fixture = snapshot_fixture();
        fixture.pack_value["spec"]["bounds"][bound] = json!(1);
        fixture.contract_value["spec"]["bounds"][bound] = json!(1);
        fixture.refresh_all();
        assert!(
            matches!(
                compile(&fixture),
                Err(SourcePlanCompileError::Artifact(
                    SourcePlanArtifactError::InvalidPlan | SourcePlanArtifactError::InvalidLimits
                ))
            ),
            "accepted live Snapshot consultation bound {bound}"
        );
    }
}

#[test]
fn rejects_missing_extra_and_duplicate_artifacts() {
    let fixture = fixture();
    let contracts = [PinnedSourcePlanArtifact::new(
        &fixture.contract,
        &fixture.contract_hash,
    )];
    let packs = [PinnedSourcePlanArtifact::new(
        &fixture.pack,
        &fixture.pack_hash,
    )];
    assert!(matches!(
        CompiledSourcePlanRegistry::compile(&SourcePlanArtifactBundle::new(
            &contracts,
            &packs,
            &[],
        )),
        Err(SourcePlanCompileError::MissingBinding)
    ));

    let bindings = [fixture.binding.as_slice()];
    assert!(matches!(
        CompiledSourcePlanRegistry::compile(&SourcePlanArtifactBundle::new(
            &contracts,
            &[],
            &bindings,
        )),
        Err(SourcePlanCompileError::MissingPack)
    ));

    let duplicate_contracts = [
        PinnedSourcePlanArtifact::new(&fixture.contract, &fixture.contract_hash),
        PinnedSourcePlanArtifact::new(&fixture.contract, &fixture.contract_hash),
    ];
    assert!(matches!(
        CompiledSourcePlanRegistry::compile(&SourcePlanArtifactBundle::new(
            &duplicate_contracts,
            &packs,
            &bindings,
        )),
        Err(SourcePlanCompileError::DuplicateProfile)
    ));

    let duplicate_packs = [
        PinnedSourcePlanArtifact::new(&fixture.pack, &fixture.pack_hash),
        PinnedSourcePlanArtifact::new(&fixture.pack, &fixture.pack_hash),
    ];
    assert!(matches!(
        CompiledSourcePlanRegistry::compile(&SourcePlanArtifactBundle::new(
            &contracts,
            &duplicate_packs,
            &bindings,
        )),
        Err(SourcePlanCompileError::DuplicatePack)
    ));

    let duplicate_bindings = [fixture.binding.as_slice(), fixture.binding.as_slice()];
    assert!(matches!(
        CompiledSourcePlanRegistry::compile(&SourcePlanArtifactBundle::new(
            &contracts,
            &packs,
            &duplicate_bindings,
        )),
        Err(SourcePlanCompileError::DuplicateBinding)
    ));

    let mut extra_binding_value = fixture.binding_value.clone();
    extra_binding_value["profile"]["id"] = json!("synthetic.unreferenced");
    let extra_binding = serde_json::to_vec(&extra_binding_value).expect("extra binding JSON");
    let bindings_with_extra = [fixture.binding.as_slice(), extra_binding.as_slice()];
    assert!(matches!(
        CompiledSourcePlanRegistry::compile(&SourcePlanArtifactBundle::new(
            &contracts,
            &packs,
            &bindings_with_extra,
        )),
        Err(SourcePlanCompileError::ExtraBinding)
    ));

    let mut extra_pack_value = fixture.pack_value.clone();
    extra_pack_value["id"] = json!("synthetic.unused-pack");
    let extra_pack = serde_json::to_vec(&extra_pack_value).expect("extra pack JSON");
    let extra_pack_hash = typed_hash(PACK_DOMAIN, &extra_pack);
    let packs_with_extra = [
        PinnedSourcePlanArtifact::new(&fixture.pack, &fixture.pack_hash),
        PinnedSourcePlanArtifact::new(&extra_pack, &extra_pack_hash),
    ];
    assert!(matches!(
        CompiledSourcePlanRegistry::compile(&SourcePlanArtifactBundle::new(
            &contracts,
            &packs_with_extra,
            &bindings,
        )),
        Err(SourcePlanCompileError::ExtraPack)
    ));
}

#[test]
fn evidence_bundle_is_exact_typed_and_hash_verified() {
    let fixture = fixture();
    assert!(matches!(
        compile_with_evidence(&fixture, &[]),
        Err(SourcePlanCompileError::MissingEvidence)
    ));

    let conformance_hash = raw_hash(SYNTHETIC_CONFORMANCE_EVIDENCE);
    let negative_hash = raw_hash(SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE);
    let minimization_hash = raw_hash(SYNTHETIC_MINIMIZATION_EVIDENCE);
    let misclassified = [
        PinnedEvidenceArtifact::new(
            EvidenceClass::Minimization,
            SYNTHETIC_CONFORMANCE_EVIDENCE,
            &conformance_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::NegativeSecurity,
            SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE,
            &negative_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::Conformance,
            SYNTHETIC_MINIMIZATION_EVIDENCE,
            &minimization_hash,
        ),
    ];
    assert!(matches!(
        compile_with_evidence(&fixture, &misclassified),
        Err(SourcePlanCompileError::MisclassifiedEvidence)
    ));

    let duplicate = [
        PinnedEvidenceArtifact::new(
            EvidenceClass::Conformance,
            SYNTHETIC_CONFORMANCE_EVIDENCE,
            &conformance_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::Conformance,
            SYNTHETIC_CONFORMANCE_EVIDENCE,
            &conformance_hash,
        ),
    ];
    assert!(matches!(
        compile_with_evidence(&fixture, &duplicate),
        Err(SourcePlanCompileError::DuplicateEvidence)
    ));

    let extra_bytes = b"unreferenced evidence";
    let extra_hash = raw_hash(extra_bytes);
    let extra = [
        PinnedEvidenceArtifact::new(
            EvidenceClass::Conformance,
            SYNTHETIC_CONFORMANCE_EVIDENCE,
            &conformance_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::NegativeSecurity,
            SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE,
            &negative_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::Minimization,
            SYNTHETIC_MINIMIZATION_EVIDENCE,
            &minimization_hash,
        ),
        PinnedEvidenceArtifact::new(EvidenceClass::Conformance, extra_bytes, &extra_hash),
    ];
    assert!(matches!(
        compile_with_evidence(&fixture, &extra),
        Err(SourcePlanCompileError::ExtraEvidence)
    ));

    let mismatch = [PinnedEvidenceArtifact::new(
        EvidenceClass::Conformance,
        b"tampered evidence",
        &conformance_hash,
    )];
    assert!(matches!(
        compile_with_evidence(&fixture, &mismatch),
        Err(SourcePlanCompileError::EvidenceHashMismatch)
    ));
}

#[test]
fn evidence_manifest_requires_all_classes_and_enforces_count_and_bytes() {
    let mut missing_class = fixture();
    missing_class.pack_value["spec"]["evidence"]["minimization"] = json!([]);
    missing_class.refresh_all();
    assert!(matches!(
        compile(&missing_class),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidSet
        ))
    ));

    let mut cross_class_duplicate = fixture();
    cross_class_duplicate.pack_value["spec"]["evidence"]["minimization"] =
        cross_class_duplicate.pack_value["spec"]["evidence"]["conformance"].clone();
    cross_class_duplicate.refresh_all();
    assert!(matches!(
        compile(&cross_class_duplicate),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidSet
        ))
    ));

    let mut too_many = fixture();
    too_many.pack_value["spec"]["evidence"]["conformance"] = Value::Array(
        (1..=MAX_EVIDENCE_FILES_PER_CLASS + 1)
            .map(|index| Value::String(format!("sha256:{index:064x}")))
            .collect(),
    );
    too_many.refresh_all();
    assert!(matches!(
        compile(&too_many),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidSet
        ))
    ));

    let oversized_bytes = vec![b'x'; MAX_EVIDENCE_FILE_BYTES + 1];
    let oversized_hash = raw_hash(&oversized_bytes);
    let mut oversized = fixture();
    oversized.pack_value["spec"]["evidence"]["conformance"] = json!([oversized_hash.clone()]);
    oversized.refresh_all();
    let negative_hash = raw_hash(SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE);
    let minimization_hash = raw_hash(SYNTHETIC_MINIMIZATION_EVIDENCE);
    let supplied = [
        PinnedEvidenceArtifact::new(
            EvidenceClass::Conformance,
            &oversized_bytes,
            &oversized_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::NegativeSecurity,
            SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE,
            &negative_hash,
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::Minimization,
            SYNTHETIC_MINIMIZATION_EVIDENCE,
            &minimization_hash,
        ),
    ];
    assert!(matches!(
        compile_with_evidence(&oversized, &supplied),
        Err(SourcePlanCompileError::EvidenceBoundsExceeded)
    ));

    let class_files = (0..5)
        .map(|index| vec![u8::try_from(index).expect("small index"); 900_000])
        .collect::<Vec<_>>();
    let class_hashes = class_files
        .iter()
        .map(|bytes| raw_hash(bytes))
        .collect::<Vec<_>>();
    let mut manifest_hashes = class_hashes.clone();
    manifest_hashes.sort();
    let mut class_overflow = fixture();
    class_overflow.pack_value["spec"]["evidence"]["conformance"] =
        Value::Array(manifest_hashes.into_iter().map(Value::String).collect());
    class_overflow.refresh_all();
    let mut supplied = class_files
        .iter()
        .zip(&class_hashes)
        .map(|(bytes, hash)| PinnedEvidenceArtifact::new(EvidenceClass::Conformance, bytes, hash))
        .collect::<Vec<_>>();
    supplied.push(PinnedEvidenceArtifact::new(
        EvidenceClass::NegativeSecurity,
        SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE,
        &negative_hash,
    ));
    supplied.push(PinnedEvidenceArtifact::new(
        EvidenceClass::Minimization,
        SYNTHETIC_MINIMIZATION_EVIDENCE,
        &minimization_hash,
    ));
    assert!(matches!(
        compile_with_evidence(&class_overflow, &supplied),
        Err(SourcePlanCompileError::EvidenceBoundsExceeded)
    ));
}

#[test]
fn startup_bundle_has_a_global_artifact_count_ceiling() {
    let fixture = fixture();
    let contracts = vec![
        PinnedSourcePlanArtifact::new(&fixture.contract, &fixture.contract_hash);
        MAX_ARTIFACTS_PER_BUNDLE + 1
    ];
    assert!(matches!(
        CompiledSourcePlanRegistry::compile(&SourcePlanArtifactBundle::new(&contracts, &[], &[],)),
        Err(SourcePlanCompileError::TooManyArtifacts)
    ));
}

#[test]
fn destination_application_base_path_defaults_to_canonical_root() {
    let baseline = fixture();
    let baseline_binding =
        parse_private_binding(&baseline.binding).expect("default root binding parses");
    let registry = compile(&baseline).expect("default root binding compiles");
    assert_eq!(
        registry
            .iter()
            .next()
            .expect("plan")
            .operations()
            .next()
            .expect("operation")
            .fixed_path(),
        "/api/person/status"
    );

    let mut explicit_root = fixture();
    explicit_root.binding_value["data_destination"]["application_base_path"] = json!("/");
    explicit_root.binding_value["credential_destination"]["application_base_path"] = json!("/");
    explicit_root.refresh_binding();
    let explicit_binding =
        parse_private_binding(&explicit_root.binding).expect("explicit root binding parses");
    assert_eq!(baseline_binding.hash(), explicit_binding.hash());
    assert_eq!(
        compile(&explicit_root)
            .expect("explicit root binding compiles")
            .iter()
            .next()
            .expect("plan")
            .operations()
            .next()
            .expect("operation")
            .fixed_path(),
        "/api/person/status"
    );
}

#[test]
fn destination_dns_family_defaults_to_strict_dual_stack_without_changing_binding_identity() {
    let baseline = fixture();
    let baseline_binding =
        parse_private_binding(&baseline.binding).expect("default DNS-family binding parses");
    let baseline_registry = compile(&baseline).expect("default DNS-family binding compiles");
    let baseline_plan = baseline_registry.iter().next().expect("baseline plan");
    assert_eq!(
        baseline_plan
            .data_destination()
            .expect("data destination")
            .dns_family(),
        DestinationDnsFamily::DualStackStrict
    );
    assert_eq!(
        baseline_plan
            .credential_destination()
            .expect("credential destination")
            .dns_family(),
        DestinationDnsFamily::DualStackStrict
    );

    let mut explicit = fixture();
    explicit.binding_value["data_destination"]["dns_family"] = json!("dual_stack_strict");
    explicit.binding_value["credential_destination"]["dns_family"] = json!("dual_stack_strict");
    explicit.refresh_binding();
    let explicit_binding =
        parse_private_binding(&explicit.binding).expect("explicit strict DNS families parse");
    assert_eq!(baseline_binding.hash(), explicit_binding.hash());
    assert_eq!(
        explicit_binding.hash().as_str(),
        vector_expected_hash("private_binding")
    );
}

#[test]
fn ipv4_only_dns_family_is_hash_covered_and_compiled_for_each_destination_slot() {
    let baseline = fixture();
    let baseline_hash = parse_private_binding(&baseline.binding)
        .expect("baseline binding parses")
        .hash()
        .as_str()
        .to_owned();

    for destination in ["data_destination", "credential_destination"] {
        let mut ipv4_only = fixture();
        ipv4_only.binding_value[destination]["dns_family"] = json!("ipv4_only");
        ipv4_only.refresh_binding();
        let binding = parse_private_binding(&ipv4_only.binding).expect("IPv4-only binding parses");
        assert_ne!(binding.hash().as_str(), baseline_hash);

        let registry = compile(&ipv4_only).expect("IPv4-only destination binding compiles");
        let plan = registry.iter().next().expect("IPv4-only plan");
        let compiled = if destination == "data_destination" {
            plan.data_destination()
                .expect("compiled data destination")
                .dns_family()
        } else {
            plan.credential_destination()
                .expect("compiled credential destination")
                .dns_family()
        };
        assert_eq!(compiled, DestinationDnsFamily::Ipv4Only);
    }
}

#[test]
fn destination_dns_family_rejects_unknown_values_and_non_string_shapes() {
    for destination in ["data_destination", "credential_destination"] {
        for invalid in [
            json!("ipv6_only"),
            Value::Null,
            json!(true),
            json!(4),
            json!(["ipv4_only"]),
            json!({"mode": "ipv4_only"}),
        ] {
            let mut fixture = fixture();
            fixture.binding_value[destination]["dns_family"] = invalid;
            fixture.refresh_binding();
            assert!(matches!(
                compile(&fixture),
                Err(SourcePlanCompileError::Artifact(
                    SourcePlanArtifactError::ClosedSchema
                ))
            ));
        }
    }
}

#[test]
fn private_ca_and_mtls_references_are_hash_covered_and_leave_destinations_fail_closed() {
    let baseline = fixture();
    let baseline_hash = parse_private_binding(&baseline.binding)
        .expect("baseline binding")
        .hash()
        .as_str()
        .to_owned();

    for destination in ["data_destination", "credential_destination"] {
        let mut configured = fixture();
        configured.binding_value[destination]["ca"] = json!({
            "file": "/run/secrets/registry-ca.pem",
            "generation": 2,
        });
        configured.binding_value[destination]["mtls"] = json!({
            "certificate_file": "/run/secrets/relay-client.pem",
            "private_key": { "secret": "REGISTRY_RELAY_CLIENT_KEY" },
            "generation": 3,
        });
        configured.refresh_binding();
        let binding = parse_private_binding(&configured.binding).expect("private TLS binding");
        assert_ne!(binding.hash().as_str(), baseline_hash);

        let registry = compile(&configured).expect("private TLS references compile structurally");
        let plan = registry.iter().next().expect("compiled plan");
        let diagnostic = if destination == "data_destination" {
            format!("{:?}", plan.data_destination().expect("data destination"))
        } else {
            format!(
                "{:?}",
                plan.credential_destination()
                    .expect("credential destination")
            )
        };
        assert!(diagnostic.contains("tls: configured-required"));
        assert!(!diagnostic.contains("/run/secrets"));
        assert!(!diagnostic.contains("REGISTRY_RELAY_CLIENT_KEY"));
    }
}

#[test]
fn private_transport_references_reject_invalid_paths_generations_names_and_aliases() {
    for (field, value) in [
        ("ca", json!({"file": "relative.pem", "generation": 1})),
        (
            "ca",
            json!({"file": "/run/secrets/ca.pem", "generation": 0}),
        ),
        (
            "mtls",
            json!({
                "certificate_file": "/run/secrets/client.pem",
                "private_key": {"secret": "bad-name"},
                "generation": 1,
            }),
        ),
        (
            "mtls",
            json!({
                "certificate_file": "/run/secrets/client.pem",
                "private_key": {"secret": "REGISTRY_CLIENT_KEY"},
                "generation": 0,
            }),
        ),
    ] {
        let mut invalid = fixture();
        invalid.binding_value["data_destination"][field] = value;
        invalid.refresh_binding();
        assert!(matches!(
            parse_private_binding(&invalid.binding),
            Err(SourcePlanArtifactError::InvalidDestination)
        ));
    }

    let mut alias = fixture();
    alias.binding_value["data_destination"]["ca_file"] = json!("/run/secrets/registry-ca.pem");
    alias.refresh_binding();
    assert!(matches!(
        parse_private_binding(&alias.binding),
        Err(SourcePlanArtifactError::ClosedSchema)
    ));
}

#[test]
fn ipv4_only_dns_family_rejects_ipv6_private_cidrs_in_each_destination_slot() {
    for destination in ["data_destination", "credential_destination"] {
        for cidrs in [json!(["fd00::/64"]), json!(["10.0.0.0/8", "fd00::/64"])] {
            let mut fixture = fixture();
            fixture.binding_value[destination]["dns_family"] = json!("ipv4_only");
            fixture.binding_value[destination]["allowed_private_cidrs"] = cidrs;
            fixture.refresh_binding();
            assert!(matches!(
                compile(&fixture),
                Err(SourcePlanCompileError::UnsafeDestination)
            ));
        }
    }
}

#[test]
fn ipv4_only_dns_family_rejects_literal_origins_in_each_destination_slot() {
    for destination in ["data_destination", "credential_destination"] {
        for origin in ["https://192.0.2.1/", "https://[2001:db8::1]/"] {
            let mut fixture = fixture();
            fixture.binding_value[destination]["dns_family"] = json!("ipv4_only");
            fixture.binding_value[destination]["origin"] = json!(origin);
            fixture.refresh_binding();
            assert!(matches!(
                compile(&fixture),
                Err(SourcePlanCompileError::UnsafeDestination)
            ));
        }
    }
}

#[test]
fn exact_application_base_path_is_hash_covered_and_compiled_without_normalization() {
    let baseline = fixture();
    let baseline_hash = parse_private_binding(&baseline.binding)
        .expect("baseline binding parses")
        .hash()
        .as_str()
        .to_owned();

    let mut prefixed = fixture();
    prefixed.binding_value["data_destination"]["application_base_path"] =
        json!("/country-registry");
    prefixed.binding_value["credential_destination"]["application_base_path"] =
        json!("/.well-known/country-identity.json");
    prefixed.refresh_binding();
    let registry = compile(&prefixed).expect("canonical application base paths compile");
    let plan = registry.iter().next().expect("plan");
    assert_ne!(plan.binding_hash(), baseline_hash);
    assert_eq!(
        plan.operations().next().expect("operation").fixed_path(),
        "/country-registry/api/person/status"
    );
    plan.credential_operation()
        .expect("credential operation")
        .render_request(
            Zeroizing::new(b"client".to_vec()),
            Zeroizing::new(b"secret".to_vec()),
        )
        .expect("credential request with compiled base path renders");
}

#[test]
fn application_base_path_is_charged_to_each_reviewed_request_bound() {
    let mut data = fixture();
    // Exact root-path target, authorization, and query maximum for this fixture.
    data.pack_value["spec"]["plan"]["operations"][0]["step_limits"]["max_request_bytes"] =
        json!(5_101);
    data.refresh_all();
    compile(&data).expect("root data path fits the exact request bound");
    data.binding_value["data_destination"]["application_base_path"] = json!("/x");
    data.refresh_binding();
    assert!(matches!(
        compile(&data),
        Err(SourcePlanCompileError::BindingWidening)
    ));

    let mut credential = fixture();
    // Exact root path, fixed headers, and declared body maximum for this fixture.
    credential.pack_value["spec"]["plan"]["credential_operation"]["request"]["max_request_bytes"] =
        json!(8_254);
    credential.refresh_all();
    compile(&credential).expect("root credential path fits the exact request bound");
    credential.binding_value["credential_destination"]["application_base_path"] = json!("/x");
    credential.refresh_binding();
    assert!(matches!(
        compile(&credential),
        Err(SourcePlanCompileError::BindingWidening)
    ));
}

#[test]
fn application_base_path_rejects_aliases_delimiters_and_oversized_values() {
    for invalid in [
        "",
        "relative",
        "//authority",
        "/trailing/",
        "/two//segments",
        "/query?value",
        "/fragment#value",
        "/percent%2Fvalue",
        "/./current",
        "/../parent",
        "/back\\slash",
        "/control\nvalue",
        "/non-ascii-é",
    ] {
        let mut fixture = fixture();
        fixture.binding_value["data_destination"]["application_base_path"] = json!(invalid);
        fixture.refresh_binding();
        assert!(
            matches!(
                compile(&fixture),
                Err(SourcePlanCompileError::Artifact(
                    SourcePlanArtifactError::InvalidDestination
                ))
            ),
            "application base path alias must be rejected"
        );
    }

    let mut maximum = fixture();
    maximum.binding_value["data_destination"]["application_base_path"] = json!(format!(
        "/{}",
        "a".repeat(crate::source_plan::artifact::MAX_PATH_BYTES - 1)
    ));
    maximum.refresh_binding();
    parse_private_binding(&maximum.binding).expect("maximum application base path parses");

    let mut oversized = fixture();
    oversized.binding_value["data_destination"]["application_base_path"] = json!(format!(
        "/{}",
        "a".repeat(crate::source_plan::artifact::MAX_PATH_BYTES)
    ));
    oversized.refresh_binding();
    assert!(matches!(
        parse_private_binding(&oversized.binding),
        Err(SourcePlanArtifactError::InvalidDestination)
    ));
}

#[test]
fn rejects_non_https_production_destination() {
    let mut non_https = fixture();
    non_https.binding_value["data_destination"]["origin"] =
        json!("http://registry.example.test:80");
    non_https.refresh_binding();
    assert!(matches!(
        compile(&non_https),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidDestination
        ))
    ));

    let mut resource_origin = fixture();
    resource_origin.binding_value["data_destination"]["origin"] =
        json!("https://registry.example.test/application");
    resource_origin.refresh_binding();
    assert!(matches!(
        compile(&resource_origin),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidDestination
        ))
    ));
}

#[test]
fn canonicalizes_cidrs_before_binding_identity_and_rejects_aliases() {
    let mut expanded = fixture();
    expanded.binding_value["data_destination"]["allowed_private_cidrs"] =
        json!(["fd00:0:0:0:0:0:0:0/64"]);
    expanded.refresh_binding();
    let expanded_hash = compile(&expanded)
        .expect("expanded canonical network")
        .iter()
        .next()
        .expect("plan")
        .binding_hash()
        .to_owned();

    let mut canonical = fixture();
    canonical.binding_value["data_destination"]["allowed_private_cidrs"] = json!(["fd00::/64"]);
    canonical.refresh_binding();
    let canonical_hash = compile(&canonical)
        .expect("compressed canonical network")
        .iter()
        .next()
        .expect("plan")
        .binding_hash()
        .to_owned();
    assert_eq!(expanded_hash, canonical_hash);

    let mut duplicate = fixture();
    duplicate.binding_value["data_destination"]["allowed_private_cidrs"] =
        json!(["fd00::/64", "fd00:0:0:0:0:0:0:0/64"]);
    duplicate.refresh_binding();
    assert!(matches!(
        compile(&duplicate),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidSet
        ))
    ));

    let mut host_bits = fixture();
    host_bits.binding_value["data_destination"]["allowed_private_cidrs"] = json!(["10.0.0.1/24"]);
    host_bits.refresh_binding();
    assert!(matches!(
        compile(&host_bits),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidDestination
        ))
    ));
}
