use registry_platform_crypto::{canonicalize_json, parse_json_strict};
use registry_platform_httputil::destination::DestinationAuthorizationValue;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;
use crate::source_plan::artifact::{json_string_max_bytes, ResponseSchemaFieldDocument};

const PACK_DOMAIN: &[u8] = b"registry.relay.integration-pack.v1\0";
const CONTRACT_DOMAIN: &[u8] = b"registry.relay.consultation-contract.v1\0";
const BINDING_DOMAIN: &[u8] = b"registry.relay.consultation-binding.v1\0";
const SYNTHETIC_CONFORMANCE_EVIDENCE: &[u8] = b"synthetic registry conformance evidence v1\n";
const SYNTHETIC_NEGATIVE_SECURITY_EVIDENCE: &[u8] =
    b"synthetic registry negative security evidence v1\n";
const SYNTHETIC_MINIMIZATION_EVIDENCE: &[u8] = b"synthetic registry minimization proof v1\n";

// These exact portable inputs are also verified by `verify-vectors.mjs`.
// Changing one requires an artifact schema/version decision, not a snapshot refresh.
const VECTOR_MANIFEST: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/manifest.json");
const VECTOR_PACK: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/integration-pack.json");
const VECTOR_CONTRACT: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/public-contract.json");
const VECTOR_BINDING: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/private-binding.json");

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
        self.contract = serde_json::to_vec(&self.contract_value).expect("contract JSON");
        self.contract_hash = typed_hash(CONTRACT_DOMAIN, &self.contract);
        self.binding = serde_json::to_vec(&self.binding_value).expect("binding JSON");
    }

    fn refresh_binding(&mut self) {
        self.binding = serde_json::to_vec(&self.binding_value).expect("binding JSON");
    }
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

fn two_step_fixture() -> Fixture {
    let mut fixture = fixture();
    let complete_acquisition_fields = json!({
        "eligibility": {
            "type": "string",
            "nullable": false,
            "max_bytes": 32
        },
        "registration_status": {
            "type": "string",
            "nullable": false,
            "max_bytes": 64
        },
        "route": {
            "type": "string",
            "nullable": false,
            "max_bytes": 32
        }
    });
    fixture.pack_value["spec"]["acquisition"]["fields"] = complete_acquisition_fields.clone();
    fixture.contract_value["spec"]["acquisition"]["fields"] = complete_acquisition_fields;
    fixture.pack_value["spec"]["reviewed_acquisition"]["fields"]["eligibility"] = json!({
        "type": "string",
        "nullable": false,
        "max_bytes": 32
    });
    fixture.pack_value["spec"]["reviewed_acquisition"]["control_fields"]["route"] = json!({
        "type": "string",
        "nullable": false,
        "max_bytes": 32
    });
    fixture.pack_value["spec"]["output"]["eligibility"] =
        json!({"type": "string", "nullable": false});
    fixture.contract_value["spec"]["output"]["eligibility"] =
        json!({"type": "string", "nullable": false});

    let first = &mut fixture.pack_value["spec"]["plan"]["operations"][0];
    first["query"]["fields"]["value"] = json!("registration_status,route");
    first["control_fields"] = json!(["route"]);
    first["response"]["prior_outputs"] = json!({
        "route": {
            "pointer": "/route",
            "type": "string",
            "nullable": false,
            "max_bytes": 32
        }
    });
    first["response"]["schema"]["items"]["fields"]["route"] = json!({
        "required": true,
        "schema": {
            "type": "string",
            "nullable": false,
            "max_bytes": 32
        }
    });

    let mut second = first.clone();
    second["id"] = json!("lookup-eligibility");
    second["path"] = json!("/api/person/eligibility");
    second["query"]
        .as_object_mut()
        .expect("query object")
        .remove("subject_id");
    second["query"]["fields"]["value"] = json!("eligibility");
    second["query"]["route"] = json!({
        "source": "prior_step_output",
        "step": "lookup-status",
        "output": "route"
    });
    second["relation_selector"] = json!({
        "step": "lookup-status",
        "output": "route",
        "location": {
            "type": "query",
            "parameter": "route"
        }
    });
    second["acquisition_fields"] = json!(["eligibility"]);
    second["control_fields"] = json!([]);
    second["response"]["max_bytes"] = json!(32_768);
    second["response"]["output_mapping"] = json!({"eligibility": "/eligibility"});
    second["response"]
        .as_object_mut()
        .expect("response object")
        .remove("prior_outputs");
    second["response"]["schema"]["items"]["fields"] = json!({
        "eligibility": {
            "required": true,
            "schema": {
                "type": "string",
                "nullable": false,
                "max_bytes": 32
            }
        }
    });
    fixture.pack_value["spec"]["plan"]["operations"] = json!([first.clone(), second]);
    fixture.pack_value["spec"]["plan"]["steps"] = json!(["lookup-status", "lookup-eligibility"]);
    fixture.pack_value["spec"]["bounds"]["max_data_exchanges"] = json!(2);
    fixture.contract_value["spec"]["bounds"]["max_data_exchanges"] = json!(2);
    fixture.binding_value["limits"]["max_source_bytes"] = json!(114_688);
    fixture.refresh_all();
    fixture
}

fn semantic_alias_fixture() -> Fixture {
    let mut fixture = fixture();
    let disclosed_schema =
        fixture.pack_value["spec"]["reviewed_acquisition"]["fields"]["registration_status"].take();
    fixture.pack_value["spec"]["reviewed_acquisition"]["fields"] =
        json!({"status": disclosed_schema});
    fixture.pack_value["spec"]["plan"]["operations"][0]["acquisition_fields"] = json!(["status"]);
    fixture.pack_value["spec"]["plan"]["operations"][0]["response"]["output_mapping"] =
        json!({"status": "/registration_status"});
    fixture.pack_value["spec"]["output"] = json!({"status": {"type": "string", "nullable": false}});
    fixture.contract_value["spec"]["output"] =
        json!({"status": {"type": "string", "nullable": false}});
    fixture.refresh_all();
    fixture
}

fn rhai_five_operation_fixture() -> Fixture {
    let mut fixture = fixture();
    let scalar = json!({
        "type": "string",
        "nullable": false,
        "max_bytes": 64
    });
    let reviewed_fields = (0..5)
        .map(|index| (format!("status_{index}"), scalar.clone()))
        .collect::<serde_json::Map<_, _>>();
    fixture.pack_value["spec"]["reviewed_acquisition"]["fields"] = Value::Object(reviewed_fields);
    fixture.pack_value["spec"]["reviewed_acquisition"]["control_fields"] = json!({
        "route": {
            "type": "string",
            "nullable": false,
            "max_bytes": 32
        }
    });
    fixture.pack_value["spec"]["reviewed_acquisition"]["selector"]["operation"] =
        json!("lookup-status-0");
    let public_fields = (0..5)
        .map(|index| {
            (
                format!("status_{index}"),
                json!({"type": "string", "nullable": false}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    fixture.pack_value["spec"]["output"] = Value::Object(public_fields.clone());
    fixture.contract_value["spec"]["output"] = Value::Object(public_fields);

    let mut first = fixture.pack_value["spec"]["plan"]["operations"][0].clone();
    first["id"] = json!("lookup-status-0");
    first["path"] = json!("/api/person/status/0");
    first["query"]["fields"]["value"] = json!("route,status_0");
    first["acquisition_fields"] = json!(["status_0"]);
    first["control_fields"] = json!(["route"]);
    first["response"]["max_bytes"] = json!(20_000);
    first["response"]["schema"]["items"]["fields"] = json!({
        "route": {
            "required": true,
            "schema": {
                "type": "string",
                "nullable": false,
                "max_bytes": 32
            }
        },
        "status_0": {
            "required": true,
            "schema": scalar.clone()
        }
    });
    first["response"]["output_mapping"] = json!({"status_0": "/status_0"});
    first["response"]["prior_outputs"] = json!({
        "route": {
            "pointer": "/route",
            "type": "string",
            "nullable": false,
            "max_bytes": 32
        }
    });

    let mut operations = vec![first.clone()];
    for index in 1..5 {
        let mut operation = first.clone();
        operation["id"] = json!(format!("lookup-status-{index}"));
        operation["path"] = json!(format!("/api/person/status/{index}"));
        operation["query"]
            .as_object_mut()
            .expect("query object")
            .remove("subject_id");
        operation["query"]["fields"]["value"] = json!(format!("status_{index}"));
        operation["query"]["route"] = json!({
            "source": "prior_step_output",
            "step": "lookup-status-0",
            "output": "route"
        });
        operation["relation_selector"] = json!({
            "step": "lookup-status-0",
            "output": "route",
            "location": {
                "type": "query",
                "parameter": "route"
            }
        });
        operation["acquisition_fields"] = json!([format!("status_{index}")]);
        operation["control_fields"] = json!([]);
        operation["response"]["schema"]["items"]["fields"] = json!({
            format!("status_{index}"): {
                "required": true,
                "schema": scalar.clone()
            }
        });
        operation["response"]["output_mapping"] =
            json!({format!("status_{index}"): format!("/status_{index}")});
        operation["response"]
            .as_object_mut()
            .expect("response object")
            .remove("prior_outputs");
        operations.push(operation);
    }
    fixture.pack_value["spec"]["plan"]["operations"] = Value::Array(operations);
    fixture.pack_value["spec"]["plan"]["steps"] = json!([
        "lookup-status-0",
        "lookup-status-1",
        "lookup-status-2",
        "lookup-status-3",
        "lookup-status-4"
    ]);
    fixture.pack_value["spec"]["plan"]["kind"] = json!("sandboxed_rhai");
    let script = "fn consult() { () }";
    fixture.pack_value["spec"]["plan"]["rhai"] = json!({
        "script": script,
        "script_hash": raw_hash(script.as_bytes()),
        "entrypoint": "consult",
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
    sync_complete_acquisition_from_responses(&mut fixture);
    fixture.binding_value["capabilities"]["allow_sandboxed_rhai"] = json!(true);
    fixture.binding_value["capabilities"]["sandboxed_rhai"] = json!({
        "callable_operations": [
            "lookup-status-0",
            "lookup-status-1",
            "lookup-status-2",
            "lookup-status-3",
            "lookup-status-4"
        ],
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

pub(crate) fn normal_completion_seed_fixture() -> Value {
    completion_seed_value(&fixture())
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
        "type": "snapshot_key",
        "input": "subject_id"
    });
    fixture.pack_value["spec"]["plan"]["kind"] = json!("snapshot_exact");
    fixture.pack_value["spec"]["plan"]["data_destination_slot"] = Value::Null;
    fixture.pack_value["spec"]["plan"]["operations"] = json!([]);
    fixture.pack_value["spec"]["plan"]["steps"] = json!([]);
    fixture.pack_value["spec"]["plan"]["credential_destination_slot"] = Value::Null;
    fixture.pack_value["spec"]["plan"]["credential_operation"] = Value::Null;
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
        (2_513, 7_794),
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
        .canonicalize_and_validate("Person-42")
        .expect("valid selector");
    assert_eq!(canonical.as_str(), "Person-42");
    assert!(!format!("{canonical:?}").contains("Person-42"));
    assert!(input.canonicalize_and_validate("contains space").is_none());
    assert!(input.canonicalize_and_validate(&"x".repeat(257)).is_none());

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
        assert!(input.canonicalize_and_validate(matching).is_some());
    }
    for rejected in ["a12_", "A_", "12", "A12__"] {
        assert!(input.canonicalize_and_validate(rejected).is_none());
    }

    let mut lowercase = fixture();
    for inputs in [
        &mut lowercase.pack_value["spec"]["input_slots"],
        &mut lowercase.contract_value["spec"]["inputs"],
    ] {
        inputs["subject_id"]["pattern"] = json!("^[a-z]+$");
        inputs["subject_id"]["canonicalization"] = json!("ascii_lowercase");
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
        .canonicalize_and_validate("SUBJECT")
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
        ("public_contract", "public-contract.json", CONTRACT_DOMAIN),
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
    assert_eq!(
        seed["authorized_operation_union"],
        json!([
            {"kind": "credential", "operation_id": "acquire-token"},
            {"kind": "data", "operation_id": "lookup-status"}
        ])
    );
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
fn rhai_completion_seed_sorts_every_dynamic_callable_union() {
    let mut fixture = two_step_fixture();
    let script = "fn consult() { () }";
    fixture.pack_value["spec"]["plan"]["kind"] = json!("sandboxed_rhai");
    fixture.pack_value["spec"]["plan"]["rhai"] = json!({
        "script": script,
        "script_hash": raw_hash(script.as_bytes()),
        "entrypoint": "consult",
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
    fixture.pack_value["spec"]["bounds"]["max_source_bytes"] = json!(147_456);
    fixture.contract_value["spec"]["bounds"]["max_source_bytes"] = json!(147_456);
    fixture.refresh_all();
    let seed = completion_seed_value_with_rhai_limits(
        &fixture,
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
    );
    let bindings = seed["dispatch"]["permit_bindings"]
        .as_array()
        .expect("permit bindings");
    for binding in &bindings[1..] {
        assert_eq!(
            binding["allowed_operation_ids"],
            json!(["lookup-eligibility", "lookup-status"])
        );
    }
}

#[test]
fn rhai_uses_five_reviewed_callables_but_two_effective_exchange_slots() {
    let fixture = rhai_five_operation_fixture();
    let callable = [
        "lookup-status-0",
        "lookup-status-1",
        "lookup-status-2",
        "lookup-status-3",
        "lookup-status-4",
    ];
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
    let worker =
        RhaiWorkerCapability::from_initialized_worker(&fixture.pack_hash, &callable, worker_limits)
            .expect("five-operation worker capability");
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
            .sandboxed_rhai_limits()
            .expect("Rhai limits")
            .max_calls(),
        2
    );
    assert_eq!(
        profile
            .dispatch()
            .sandboxed_rhai_operations()
            .expect("reviewed callable union")
            .iter()
            .map(OperationId::as_str)
            .collect::<Vec<_>>(),
        callable
    );

    let seed = rhai_five_operation_two_slot_completion_seed_fixture();
    assert_eq!(seed["bounds"]["data_exchanges"], json!(2));
    let permits = seed["dispatch"]["permit_bindings"]
        .as_array()
        .expect("permit bindings");
    assert_eq!(permits.len(), 3, "one credential plus two data slots");
    for permit in &permits[1..] {
        assert_eq!(permit["allowed_operation_ids"], json!(callable));
    }
}

#[test]
fn rhai_reviewed_topology_rejects_duplicate_omitted_unknown_and_conditioned_operations() {
    let mut duplicate = rhai_five_operation_fixture();
    duplicate.pack_value["spec"]["plan"]["steps"] = json!([
        "lookup-status-0",
        "lookup-status-0",
        "lookup-status-2",
        "lookup-status-3",
        "lookup-status-4"
    ]);
    duplicate.refresh_all();

    let mut omitted = rhai_five_operation_fixture();
    omitted.pack_value["spec"]["plan"]["steps"]
        .as_array_mut()
        .expect("reviewed topology")
        .pop();
    omitted.refresh_all();

    let mut unknown = rhai_five_operation_fixture();
    unknown.pack_value["spec"]["plan"]["steps"][4] = json!("lookup-status-unknown");
    unknown.refresh_all();

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

    for invalid in [&duplicate, &omitted, &unknown, &conditioned] {
        assert!(matches!(
            compile(invalid),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::InvalidPlan
            ))
        ));
    }
}

#[test]
fn response_byte_bounds_cover_fixed_flow_and_repeated_largest_rhai_calls() {
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

    let callable = [
        "lookup-status-0",
        "lookup-status-1",
        "lookup-status-2",
        "lookup-status-3",
        "lookup-status-4",
    ];
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
    // Any slot may repeat the largest callable, so public sizing is
    // 5 * 20_000 data bytes + 16_384 credential bytes.
    rhai_exact.pack_value["spec"]["bounds"]["max_source_bytes"] = json!(116_384);
    rhai_exact.contract_value["spec"]["bounds"]["max_source_bytes"] = json!(116_384);
    rhai_exact.binding_value["limits"]["max_source_bytes"] = json!(56_384);
    rhai_exact.refresh_all();
    let worker = RhaiWorkerCapability::from_initialized_worker(
        &rhai_exact.pack_hash,
        &callable,
        worker_limits,
    )
    .expect("exact-bound worker");
    compile_with_rhai_workers(&rhai_exact, &[worker])
        .expect("public and effective repeated-call byte bounds fit exactly");

    let mut public_short = rhai_exact;
    public_short.pack_value["spec"]["bounds"]["max_source_bytes"] = json!(116_383);
    public_short.contract_value["spec"]["bounds"]["max_source_bytes"] = json!(116_383);
    public_short.refresh_all();
    assert!(matches!(
        compile(&public_short),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidLimits
        ))
    ));

    let mut effective_short = rhai_five_operation_fixture();
    effective_short.binding_value["limits"]["max_source_bytes"] = json!(56_383);
    effective_short.refresh_all();
    let worker = RhaiWorkerCapability::from_initialized_worker(
        &effective_short.pack_hash,
        &callable,
        worker_limits,
    )
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
    assert_eq!(token.usable_lifetime_ms(), 1_770_000);
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
        expires_in_min_seconds: 1,
        expires_in_max_seconds: 60,
        max_token_lifetime_ms: 30_000,
        expiry_safety_skew_ms: 30_000,
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
    second.binding_value["capabilities"]["allow_sandboxed_rhai"] = json!(true);
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
    fixture.contract = serde_json::to_vec(&fixture.contract_value).expect("contract JSON");
    fixture.contract_hash = typed_hash(CONTRACT_DOMAIN, &fixture.contract);
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

    for statuses in [json!([200, 200]), json!([302])] {
        let mut fixture = fixture();
        fixture.pack_value["spec"]["plan"]["operations"][0]["response"]["accepted_statuses"] =
            statuses;
        fixture.refresh_all();
        assert!(matches!(
            compile(&fixture),
            Err(SourcePlanCompileError::Artifact(
                SourcePlanArtifactError::InvalidSet
            ))
        ));
    }

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
fn rejects_ambiguous_steps_and_auth_bypassing_headers() {
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
fn compiles_named_prior_outputs_and_bounded_conditions_to_indexes() {
    let mut fixture = two_step_fixture();
    fixture.pack_value["spec"]["plan"]["step_conditions"] = json!({
        "lookup-eligibility": {
            "predicate": "string_equals",
            "step": "lookup-status",
            "output": "route",
            "value": "eligible-path"
        }
    });
    fixture.refresh_all();
    let registry = compile(&fixture).expect("typed prior output and condition");
    let plan = registry.iter().next().expect("plan");
    let operations = plan.operations().collect::<Vec<_>>();
    assert_eq!(operations[0].response().prior_outputs().len(), 1);
    assert_eq!(
        operations[0]
            .response()
            .prior_outputs()
            .next()
            .expect("route slot")
            .name(),
        "route"
    );
    assert!(matches!(
        operations[1]
            .query()
            .find(|component| component.name() == "route")
            .expect("compiled route query")
            .value(),
        CompiledValueExpression::PriorStepOutput {
            operation_index: 0,
            output_slot_index: 0
        }
    ));
    let second = plan.compiled_steps().nth(1).expect("conditional step");
    assert_eq!(second.condition_source_index(), Some(0));
    assert_eq!(second.condition_output_slot_index(), Some(0));
    assert!(matches!(
        second.condition(),
        Some(CompiledStepPredicate::StringEquals(value)) if value.as_ref() == "eligible-path"
    ));
}

#[test]
fn selector_bindings_retain_exact_typed_sources_and_request_locations() {
    let registry = compile(&two_step_fixture()).expect("typed selector fixture");
    let operations = registry
        .iter()
        .next()
        .expect("plan")
        .operations()
        .collect::<Vec<_>>();
    assert_eq!(
        operations[0].selector().source(),
        CompiledSelectorSource::ConsultationInput { input_index: 0 }
    );
    let CompiledSelectorLocation::Query { component_index } = operations[0].selector().location()
    else {
        panic!("root selector must be a query component");
    };
    assert_eq!(
        operations[0]
            .query()
            .nth(*component_index)
            .expect("query")
            .name(),
        "subject_id"
    );

    assert_eq!(
        operations[1].selector().source(),
        CompiledSelectorSource::PriorStepOutput {
            operation_index: 0,
            output_slot_index: 0,
        }
    );
    let CompiledSelectorLocation::Query { component_index } = operations[1].selector().location()
    else {
        panic!("relation selector must be a query component");
    };
    assert_eq!(
        operations[1]
            .query()
            .nth(*component_index)
            .expect("query")
            .name(),
        "route"
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
fn rejects_invalid_prior_output_and_condition_graphs() {
    let mut missing_slot = two_step_fixture();
    missing_slot.pack_value["spec"]["plan"]["operations"][1]["query"]["route"]["output"] =
        json!("missing");
    missing_slot.refresh_all();
    assert!(matches!(
        compile(&missing_slot),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidExpression
        ))
    ));

    let mut type_mismatch = two_step_fixture();
    type_mismatch.pack_value["spec"]["plan"]["operations"][0]["response"]["prior_outputs"]
        ["route"]["type"] = json!("boolean");
    type_mismatch.refresh_all();
    assert!(matches!(
        compile(&type_mismatch),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidLimits | SourcePlanArtifactError::InvalidAcquisition
        ))
    ));

    let mut duplicate_pointer = two_step_fixture();
    duplicate_pointer.pack_value["spec"]["plan"]["operations"][0]["response"]["output_mapping"]
        ["registration_status"] = json!("/route");
    duplicate_pointer.refresh_all();
    assert!(matches!(
        compile(&duplicate_pointer),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));

    let mut forward = two_step_fixture();
    forward.pack_value["spec"]["plan"]["step_conditions"] = json!({
        "lookup-status": {
            "predicate": "exists",
            "step": "lookup-eligibility",
            "output": "route"
        }
    });
    forward.refresh_all();
    assert!(matches!(
        compile(&forward),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidPlan
        ))
    ));

    let mut wrong_type = two_step_fixture();
    wrong_type.pack_value["spec"]["plan"]["step_conditions"] = json!({
        "lookup-eligibility": {
            "predicate": "boolean_equals",
            "step": "lookup-status",
            "output": "route",
            "value": true
        }
    });
    wrong_type.refresh_all();
    assert!(matches!(
        compile(&wrong_type),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidExpression
        ))
    ));

    let mut oversized = two_step_fixture();
    oversized.pack_value["spec"]["plan"]["step_conditions"] = json!({
        "lookup-eligibility": {
            "predicate": "string_equals",
            "step": "lookup-status",
            "output": "route",
            "value": "x".repeat(33)
        }
    });
    oversized.refresh_all();
    assert!(matches!(
        compile(&oversized),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidExpression
        ))
    ));

    let mut unknown_key = two_step_fixture();
    unknown_key.pack_value["spec"]["plan"]["step_conditions"] = json!({
        "not-a-step": {
            "predicate": "exists",
            "step": "lookup-status",
            "output": "route"
        }
    });
    unknown_key.refresh_all();
    assert!(matches!(
        compile(&unknown_key),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidPlan
        ))
    ));

    let mut self_reference = two_step_fixture();
    self_reference.pack_value["spec"]["plan"]["step_conditions"] = json!({
        "lookup-eligibility": {
            "predicate": "exists",
            "step": "lookup-eligibility",
            "output": "route"
        }
    });
    self_reference.refresh_all();
    assert!(matches!(
        compile(&self_reference),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidExpression
        ))
    ));
}

#[test]
fn rejects_unanchored_or_reordered_multi_step_acquisition() {
    let mut missing_anchor = two_step_fixture();
    missing_anchor.pack_value["spec"]["reviewed_acquisition"]["selector"]["operation"] =
        json!("missing-operation");
    missing_anchor.refresh_all();
    assert!(matches!(
        compile(&missing_anchor),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));

    let mut reordered = two_step_fixture();
    reordered.pack_value["spec"]["plan"]["steps"] = json!(["lookup-eligibility", "lookup-status"]);
    reordered.refresh_all();
    assert!(matches!(
        compile(&reordered),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidExpression
                | SourcePlanArtifactError::InvalidAcquisition
        ))
    ));

    let mut literal_only = two_step_fixture();
    literal_only.pack_value["spec"]["plan"]["operations"][1]["query"]
        .as_object_mut()
        .expect("query object")
        .remove("route");
    literal_only.refresh_all();
    assert!(matches!(
        compile(&literal_only),
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
        body_template_max_bytes(&body, &BTreeMap::new(), &BTreeMap::new()),
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
fn complete_public_acquisition_cannot_omit_nested_or_control_source_fields() {
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

    let mut control = two_step_fixture();
    control.pack_value["spec"]["acquisition"]["fields"]
        .as_object_mut()
        .expect("complete acquisition")
        .remove("route");
    control.contract_value["spec"]["acquisition"]["fields"]
        .as_object_mut()
        .expect("complete acquisition")
        .remove("route");
    control.refresh_all();
    assert!(matches!(
        compile(&control),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));
}

#[test]
fn rejects_open_unbounded_or_schema_mismatched_responses() {
    let mut open_nested = fixture();
    open_nested.pack_value["spec"]["plan"]["operations"][0]["response"]["schema"]["items"]
        ["reject_unknown_fields"] = json!(false);
    open_nested.refresh_all();
    assert!(matches!(
        compile(&open_nested),
        Err(SourcePlanCompileError::Artifact(
            SourcePlanArtifactError::InvalidAcquisition
        ))
    ));

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
fn rejects_sandboxed_rhai_without_explicit_deployment_opt_in() {
    let mut fixture = fixture();
    let script = "fn consult() { () }";
    fixture.pack_value["spec"]["plan"]["kind"] = json!("sandboxed_rhai");
    fixture.pack_value["spec"]["plan"]["rhai"] = json!({
        "script": script,
        "script_hash": raw_hash(script.as_bytes()),
        "entrypoint": "consult",
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
    fixture.refresh_all();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::RhaiNotEnabled)
    ));

    fixture.binding_value["capabilities"]["allow_sandboxed_rhai"] = json!(true);
    fixture.binding_value["capabilities"]["sandboxed_rhai"] = json!({
        "callable_operations": ["lookup-status"],
        "max_calls": 1,
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
    fixture.refresh_binding();
    assert!(matches!(
        compile(&fixture),
        Err(SourcePlanCompileError::RhaiWorkerUnavailable)
    ));
    let worker = RhaiWorkerCapability::from_initialized_worker(
        &fixture.pack_hash,
        &["lookup-status"],
        RhaiWorkerLimits {
            max_calls: 1,
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
        },
    )
    .expect("initialized worker capability");
    let registry = compile_with_rhai_workers(&fixture, &[worker])
        .expect("explicit binding plus initialized reviewed Rhai worker");
    let plan = registry.iter().next().expect("Rhai plan");
    assert_eq!(plan.steps().len(), 0, "Rhai has no fixed step sequence");
    let dispatch = plan.runtime_profile().dispatch();
    assert_eq!(
        dispatch
            .sandboxed_rhai_operations()
            .expect("Rhai callable union")
            .iter()
            .map(OperationId::as_str)
            .collect::<Vec<_>>(),
        ["lookup-status"]
    );
    assert_eq!(
        dispatch
            .sandboxed_rhai_limits()
            .expect("Rhai worker limits")
            .max_calls(),
        1
    );

    let wrong_limits = RhaiWorkerCapability::from_initialized_worker(
        &fixture.pack_hash,
        &["lookup-status"],
        RhaiWorkerLimits {
            max_calls: 1,
            memory_bytes: 67_108_863,
            cpu_ms: 500,
            ipc_frame_bytes: 131_072,
            instructions: 50_000,
            call_depth: 8,
            string_bytes: 32_768,
            array_items: 256,
            map_entries: 256,
            output_bytes: 32_768,
            concurrency: 1,
        },
    )
    .expect("mismatched worker capability");
    assert!(matches!(
        compile_with_rhai_workers(&fixture, &[wrong_limits]),
        Err(SourcePlanCompileError::RhaiWorkerMismatch)
    ));

    let wrong_allowlist = RhaiWorkerCapability::from_initialized_worker(
        &fixture.pack_hash,
        &["different-operation"],
        RhaiWorkerLimits {
            max_calls: 1,
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
        },
    )
    .expect("mismatched allowlist capability");
    assert!(matches!(
        compile_with_rhai_workers(&fixture, &[wrong_allowlist]),
        Err(SourcePlanCompileError::RhaiWorkerMismatch)
    ));

    let mut missing_detail = fixture.binding_value.clone();
    missing_detail["capabilities"]["sandboxed_rhai"] = Value::Null;
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
    assert!(plan
        .runtime_profile()
        .acquisition_provenance()
        .snapshot_generation_required());
    assert!(plan
        .runtime_profile()
        .acquisition_provenance()
        .snapshot_published_at_required());
    assert!(!format!("{snapshot:?}").contains("people-snapshot"));
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
fn rejects_non_https_production_destination() {
    let mut fixture = fixture();
    fixture.binding_value["data_destination"]["origin"] = json!("http://registry.example.test:80");
    fixture.refresh_binding();
    assert!(matches!(
        compile(&fixture),
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
