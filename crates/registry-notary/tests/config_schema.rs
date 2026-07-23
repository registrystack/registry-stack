// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use jsonschema::{Draft, JSONSchema};
use registry_notary_core::config::schema::{document, document_json, CONFIG_SCHEMA_ID};
use registry_notary_core::{
    ClaimEvidenceMode, SigningKeyProviderConfig, SigningKeyStatus, StandaloneRegistryNotaryConfig,
};
use registry_platform_authcommon::CredentialFingerprintProvider;
use registry_platform_ops::{
    deployment_waiver_reference_schema_fragment, deployment_waiver_summary_schema_fragment,
    validate_deployment_waiver_metadata, DeploymentWaiverMetadataError,
};
use serde_json::{json, Value};

const SCHEMA_ARTIFACT: &str = "schemas/registry-notary.config.schema.json";
const CONFIG_REFERENCE: &str = "products/notary/docs/operator-config-reference.md";
const KEY_PATHS_START: &str = "{/* registry-notary-config-key-paths:start */}";
const KEY_PATHS_END: &str = "{/* registry-notary-config-key-paths:end */}";

fn stack_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_yaml(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_norway::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {} as YAML: {error}", path.display()))
}

fn compile_schema(schema: &Value) -> JSONSchema {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .unwrap_or_else(|error| panic!("Notary schema must compile as Draft 2020-12: {error}"))
}

fn assert_valid(schema: &Value, instance: &Value, label: &str) {
    let compiled = compile_schema(schema);
    if let Err(errors) = compiled.validate(instance) {
        let details = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("{label} must validate against the Notary schema: {details:#?}");
    };
}

fn assert_invalid(schema: &Value, instance: &Value, label: &str) {
    assert!(
        !compile_schema(schema).is_valid(instance),
        "{label} must be rejected by the Notary schema"
    );
}

fn assert_runtime_deserializes(instance: &Value, label: &str) {
    let yaml = serde_norway::to_string(instance)
        .unwrap_or_else(|error| panic!("failed to serialize {label} as YAML: {error}"));
    serde_norway::from_str::<StandaloneRegistryNotaryConfig>(&yaml)
        .unwrap_or_else(|error| panic!("{label} must deserialize at runtime: {error}"));
}

fn assert_runtime_rejects(instance: &Value, label: &str) {
    let yaml = serde_norway::to_string(instance)
        .unwrap_or_else(|error| panic!("failed to serialize {label} as YAML: {error}"));
    assert!(
        serde_norway::from_str::<StandaloneRegistryNotaryConfig>(&yaml).is_err(),
        "{label} must be rejected during runtime deserialization"
    );
}

fn assert_runtime_load_rejects(instance: &Value, label: &str) {
    let yaml = serde_norway::to_string(instance)
        .unwrap_or_else(|error| panic!("failed to serialize {label} as YAML: {error}"));
    if let Ok(config) = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(&yaml) {
        assert!(
            config.validate().is_err(),
            "{label} must be rejected during runtime validation"
        );
    }
}

fn maintained_runtime_fixtures() -> Vec<PathBuf> {
    let profiles = stack_root().join("crates/registry-relay/profiles");
    let mut fixtures = fs::read_dir(profiles)
        .expect("profiles directory exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("notary-config.example.yaml"))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    fixtures.sort();
    fixtures
}

fn example_config() -> Value {
    parse_yaml(&stack_root().join(
        "crates/registry-relay/profiles/dhis2-2.41.9-enrollment-status/notary-config.example.yaml",
    ))
}

fn config_with_deployment_waiver(reference: &str, summary: Option<&str>) -> Value {
    let mut config = example_config();
    let mut waiver = json!({
        "finding": "notary.openapi.public",
        "reference": reference,
        "expires": "2999-01-01"
    });
    if let Some(summary) = summary {
        waiver["summary"] = json!(summary);
    }
    config["deployment"] = json!({
        "profile": "hosted_lab",
        "waivers": [waiver]
    });
    config
}

fn with_authorization_details(mut config: Value) -> Value {
    config["auth"]["api_keys"][0]["authorization_details"] = json!({
        "type": "registry_notary_authorization",
        "schema_version": "1",
        "subject": { "binding_claim": "sub", "id_type": "person_id" },
        "target": { "id_type": "person_id", "id": "target-123" },
        "relationship": { "relationship_type": "guardian", "proof_claim": "guardianship" },
        "assisted_access_context": { "channel": "service_desk" }
    });
    config
}

fn string_enum(schema: &Value, pointer: &str) -> BTreeSet<String> {
    schema
        .pointer(pointer)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing string enum at {pointer}"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("non-string enum value at {pointer}"))
                .to_string()
        })
        .collect()
}

fn collect_tag_constants(root: &Value, schema: &Value, values: &mut BTreeSet<String>) {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let target = root
            .pointer(reference.strip_prefix('#').expect("local schema reference"))
            .unwrap_or_else(|| panic!("unresolved schema reference {reference}"));
        collect_tag_constants(root, target, values);
    }
    for combinator in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = schema.get(combinator).and_then(Value::as_array) {
            for branch in branches {
                collect_tag_constants(root, branch, values);
            }
        }
    }
    if let Some(value) = schema
        .get("properties")
        .and_then(|properties| properties.get("type"))
        .and_then(|tag| tag.get("const"))
        .and_then(Value::as_str)
    {
        values.insert(value.to_string());
    }
}

fn collect_key_paths(
    root: &Value,
    schema: &Value,
    prefix: &str,
    paths: &mut BTreeSet<String>,
    visited_refs: &mut HashSet<String>,
) {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        if visited_refs.insert(reference.to_string()) {
            let target = root
                .pointer(reference.strip_prefix('#').expect("local schema reference"))
                .unwrap_or_else(|| panic!("unresolved schema reference {reference}"));
            collect_key_paths(root, target, prefix, paths, visited_refs);
            visited_refs.remove(reference);
        }
    }

    for combinator in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = schema.get(combinator).and_then(Value::as_array) {
            for branch in branches {
                collect_key_paths(root, branch, prefix, paths, visited_refs);
            }
        }
    }

    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            let property_path = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}.{name}")
            };
            paths.insert(property_path.clone());
            collect_key_paths(root, property, &property_path, paths, visited_refs);
        }
    }

    if let Some(items) = schema.get("items").filter(|value| value.is_object()) {
        let item_path = format!("{prefix}[]");
        paths.insert(item_path.clone());
        collect_key_paths(root, items, &item_path, paths, visited_refs);
    }

    if let Some(values) = schema
        .get("additionalProperties")
        .filter(|value| value.is_object())
    {
        let value_path = format!("{prefix}.*");
        paths.insert(value_path.clone());
        collect_key_paths(root, values, &value_path, paths, visited_refs);
    }
}

fn documented_key_paths(reference: &str) -> BTreeSet<String> {
    let Some((_, tail)) = reference.split_once(KEY_PATHS_START) else {
        return BTreeSet::new();
    };
    let (block, _) = tail
        .split_once(KEY_PATHS_END)
        .unwrap_or_else(|| panic!("missing {KEY_PATHS_END}"));
    block
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && *line != "```text" && *line != "```")
        .map(str::to_string)
        .collect()
}

#[test]
fn generated_schema_is_draft_2020_12_with_stable_id_and_no_byte_drift() {
    let generated = document();
    compile_schema(&generated);
    assert_eq!(
        generated["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(generated["$id"], CONFIG_SCHEMA_ID);

    let artifact = fs::read_to_string(stack_root().join(SCHEMA_ARTIFACT))
        .expect("committed Notary schema exists");
    assert_eq!(artifact, document_json());
    assert!(artifact.ends_with('\n'));
    assert!(!artifact.ends_with("\n\n"));
}

#[test]
fn schema_command_is_exactly_the_committed_artifact() {
    let output = Command::new(env!("CARGO_BIN_EXE_registry-notary"))
        .arg("schema")
        .output()
        .expect("schema command runs");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        fs::read(stack_root().join(SCHEMA_ARTIFACT)).expect("committed Notary schema exists")
    );
}

#[test]
fn maintained_runtime_config_fixtures_validate_and_deserialize() {
    let schema = document();
    let fixtures = maintained_runtime_fixtures();
    assert!(
        fixtures.len() >= 2,
        "fixture discovery unexpectedly narrowed"
    );
    for fixture in fixtures {
        let instance = parse_yaml(&fixture);
        assert_valid(&schema, &instance, &fixture.display().to_string());
        assert_runtime_deserializes(&instance, &fixture.display().to_string());
    }
}

#[test]
fn strict_nested_objects_and_tagged_variants_match_runtime_deserialization() {
    let schema = document();

    let mut unknown_nested = example_config();
    unknown_nested["evidence"]["claims"][0]["evidence_mode"]["unexpected"] = json!(true);
    assert_invalid(&schema, &unknown_nested, "unknown evidence-mode field");
    assert_runtime_rejects(&unknown_nested, "unknown evidence-mode field");

    let mut unknown_fingerprint = example_config();
    unknown_fingerprint["auth"]["api_keys"][0]["fingerprint"]["unexpected"] = json!(true);
    assert_invalid(&schema, &unknown_fingerprint, "unknown fingerprint field");
    assert_runtime_rejects(&unknown_fingerprint, "unknown fingerprint field");

    let mut unknown_signing_provider = example_config();
    unknown_signing_provider["evidence"]["signing_keys"] = json!({
        "issuer": {
            "provider": "not_a_provider",
            "alg": "EdDSA",
            "kid": "did:web:issuer.example#key",
            "status": "active"
        }
    });
    assert_invalid(
        &schema,
        &unknown_signing_provider,
        "unknown signing-key provider",
    );
    assert_runtime_rejects(&unknown_signing_provider, "unknown signing-key provider");

    let mut unknown_signing_status = example_config();
    unknown_signing_status["evidence"]["signing_keys"] = json!({
        "issuer": {
            "provider": "local_jwk_env",
            "alg": "EdDSA",
            "kid": "did:web:issuer.example#key",
            "status": "not_a_status"
        }
    });
    assert_invalid(
        &schema,
        &unknown_signing_status,
        "unknown signing-key status",
    );
    assert_runtime_rejects(&unknown_signing_status, "unknown signing-key status");
}

#[test]
fn deployment_waiver_schema_rejects_retired_and_noncanonical_metadata() {
    let schema = document();
    let mut config = example_config();
    config["deployment"] = json!({
        "profile": "hosted_lab",
        "waivers": [{
            "finding": "notary.openapi.public",
            "reference": "OPS..42",
            "expires": "2999-01-01"
        }]
    });
    assert_invalid(&schema, &config, "waiver reference containing '..'");

    config["deployment"]["waivers"][0]["reference"] = json!("OPS-42");
    config["deployment"]["waivers"][0]["summary"] = Value::Null;
    assert_invalid(&schema, &config, "null deployment waiver summary");
    assert_runtime_load_rejects(&config, "null deployment waiver summary");

    config["deployment"]["waivers"][0]
        .as_object_mut()
        .expect("waiver is an object")
        .remove("summary");
    config["deployment"]["waivers"][0]["reason"] = json!("retired waiver text");
    assert_invalid(&schema, &config, "retired deployment waiver reason");
    assert_runtime_load_rejects(&config, "retired deployment waiver reason");
}

#[test]
fn deployment_waiver_schema_matches_shared_portable_metadata_contract() {
    let schema = document();
    assert_eq!(
        schema.pointer("/$defs/DeploymentWaiverReference"),
        Some(&deployment_waiver_reference_schema_fragment())
    );
    assert_eq!(
        schema.pointer("/$defs/DeploymentWaiverSummary"),
        Some(&deployment_waiver_summary_schema_fragment())
    );

    for reference in ["OPS-42", "Bearer:", "Authorization:Basic:"] {
        validate_deployment_waiver_metadata(reference, None).unwrap_or_else(|error| {
            panic!("runtime rejected valid reference {reference:?}: {error}")
        });
        assert_valid(
            &schema,
            &config_with_deployment_waiver(reference, None),
            &format!("portable deployment waiver reference {reference:?}"),
        );
    }
    for reference in ["Bearer:abcdef", "authorization:bAsIc:abc123", "Bearer::"] {
        assert_eq!(
            validate_deployment_waiver_metadata(reference, None),
            Err(DeploymentWaiverMetadataError::ReferenceCredentialLiteral)
        );
        assert_invalid(
            &schema,
            &config_with_deployment_waiver(reference, None),
            &format!("credential-shaped deployment waiver reference {reference:?}"),
        );
    }

    for summary in [
        "Ordinary operator summary".to_string(),
        "\u{feff}summary\u{feff}".to_string(),
        "summary\u{2028}continued".to_string(),
        "é".repeat(256),
    ] {
        validate_deployment_waiver_metadata("OPS-42", Some(&summary))
            .unwrap_or_else(|error| panic!("runtime rejected valid summary {summary:?}: {error}"));
        assert_valid(
            &schema,
            &config_with_deployment_waiver("OPS-42", Some(&summary)),
            "structurally valid deployment waiver summary",
        );
    }
    for summary in [
        String::new(),
        " summary".to_string(),
        "summary\u{3000}".to_string(),
        "summary\u{001f}continued".to_string(),
        "é".repeat(257),
    ] {
        assert!(
            validate_deployment_waiver_metadata("OPS-42", Some(&summary)).is_err(),
            "runtime must reject structurally invalid summary {summary:?}"
        );
        assert_invalid(
            &schema,
            &config_with_deployment_waiver("OPS-42", Some(&summary)),
            "structurally invalid deployment waiver summary",
        );
    }

    for summary in [
        "Authorization: ＂Bearer abcdef＂",
        concat!("accidentally pasted -----BEGIN PRIVATE ", "KEY-----"),
    ] {
        assert_eq!(
            validate_deployment_waiver_metadata("OPS-42", Some(summary)),
            Err(DeploymentWaiverMetadataError::SummaryCredentialLiteral)
        );
        let config = config_with_deployment_waiver("OPS-42", Some(summary));
        assert_valid(
            &schema,
            &config,
            "contextual waiver summary left to semantic validation",
        );
        assert_runtime_load_rejects(
            &config,
            "contextual waiver summary rejected by semantic validation",
        );
    }
}

#[test]
fn authorization_details_preserve_extension_compatibility_at_every_policy_level() {
    let schema = document();
    let valid = with_authorization_details(example_config());
    assert_valid(&schema, &valid, "authorization-details config");
    assert_runtime_deserializes(&valid, "authorization-details config");

    let mut root_unknown = valid.clone();
    root_unknown["auth"]["api_keys"][0]["authorization_details"]["unexpected"] = json!(true);
    assert_valid(
        &schema,
        &root_unknown,
        "future authorization-details metadata",
    );
    assert_runtime_deserializes(&root_unknown, "future authorization-details metadata");

    let mut subject_unknown = valid.clone();
    subject_unknown["auth"]["api_keys"][0]["authorization_details"]["subject"]["unexpected"] =
        json!(true);
    assert_valid(
        &schema,
        &subject_unknown,
        "future authorization subject metadata",
    );
    assert_runtime_deserializes(&subject_unknown, "future authorization subject metadata");

    let mut target_unknown = valid.clone();
    target_unknown["auth"]["api_keys"][0]["authorization_details"]["target"]["unexpected"] =
        json!(true);
    assert_valid(
        &schema,
        &target_unknown,
        "future authorization target metadata",
    );
    assert_runtime_deserializes(&target_unknown, "future authorization target metadata");

    let mut relationship_unknown = valid.clone();
    relationship_unknown["auth"]["api_keys"][0]["authorization_details"]["relationship"]
        ["unexpected"] = json!(true);
    assert_valid(
        &schema,
        &relationship_unknown,
        "future authorization relationship metadata",
    );
    assert_runtime_deserializes(
        &relationship_unknown,
        "future authorization relationship metadata",
    );

    let mut context_unknown = valid;
    context_unknown["auth"]["api_keys"][0]["authorization_details"]["assisted_access_context"]
        ["unexpected"] = json!(true);
    assert_valid(
        &schema,
        &context_unknown,
        "future assisted-access context metadata",
    );
    assert_runtime_deserializes(&context_unknown, "future assisted-access context metadata");
}

#[test]
fn claim_ref_shorthand_and_object_forms_match_runtime_deserialization() {
    let schema = document();
    let mut valid = with_authorization_details(example_config());
    valid["auth"]["api_keys"][0]["authorization_details"]["claims"] =
        json!(["enrollment", { "id": "status", "version": "1" }]);
    assert_valid(
        &schema,
        &valid,
        "claim-reference shorthand and object forms",
    );
    assert_runtime_deserializes(&valid, "claim-reference shorthand and object forms");

    let mut missing_id = valid.clone();
    missing_id["auth"]["api_keys"][0]["authorization_details"]["claims"] =
        json!([{ "version": "1" }]);
    assert_invalid(&schema, &missing_id, "claim-reference object without id");
    assert_runtime_rejects(&missing_id, "claim-reference object without id");

    let mut unknown_field = valid;
    unknown_field["auth"]["api_keys"][0]["authorization_details"]["claims"] =
        json!([{ "id": "status", "unexpected": true }]);
    assert_invalid(
        &schema,
        &unknown_field,
        "claim-reference object with unknown field",
    );
    assert_runtime_rejects(&unknown_field, "claim-reference object with unknown field");
}

#[test]
fn adapter_rosters_are_generated_from_runtime_labels() {
    let schema = document();
    let runtime_fingerprint_providers = CredentialFingerprintProvider::ALL
        .iter()
        .map(|provider| provider.as_str().to_string())
        .collect();
    assert_eq!(
        string_enum(
            &schema,
            "/$defs/CredentialFingerprintRef/properties/provider/enum",
        ),
        runtime_fingerprint_providers,
        "credential fingerprint provider schema must consume the runtime roster"
    );
    for provider in CredentialFingerprintProvider::ALL {
        let label = serde_json::to_value(provider).expect("provider serializes");
        assert_eq!(label, json!(provider.as_str()));
        assert_eq!(
            serde_json::from_value::<CredentialFingerprintProvider>(label)
                .expect("provider label deserializes"),
            *provider
        );
    }

    let runtime_key_providers = SigningKeyProviderConfig::ALL
        .iter()
        .map(|provider| provider.as_str().to_string())
        .collect();
    assert_eq!(
        string_enum(&schema, "/$defs/SigningKeyProviderSchema/enum"),
        runtime_key_providers,
        "signing-key provider schema must consume the runtime roster"
    );
    for provider in SigningKeyProviderConfig::ALL {
        let label = serde_json::to_value(provider).expect("provider serializes");
        assert_eq!(label, json!(provider.as_str()));
        assert_eq!(
            serde_json::from_value::<SigningKeyProviderConfig>(label)
                .expect("provider label deserializes"),
            *provider
        );
    }

    let runtime_key_statuses = SigningKeyStatus::ALL
        .iter()
        .map(|status| status.as_str().to_string())
        .collect();
    assert_eq!(
        string_enum(&schema, "/$defs/SigningKeyStatusSchema/enum"),
        runtime_key_statuses,
        "signing-key status schema must consume the runtime roster"
    );
    for status in SigningKeyStatus::ALL {
        let label = serde_json::to_value(status).expect("status serializes");
        assert_eq!(label, json!(status.as_str()));
        assert_eq!(
            serde_json::from_value::<SigningKeyStatus>(label).expect("status label deserializes"),
            *status
        );
    }

    let runtime_evidence_modes = [
        serde_json::to_value(ClaimEvidenceMode::RegistryBacked {
            consultations: Default::default(),
        })
        .expect("registry-backed mode serializes"),
        serde_json::to_value(ClaimEvidenceMode::SelfAttested)
            .expect("self-attested mode serializes"),
    ]
    .into_iter()
    .map(|value| value["type"].as_str().expect("mode type label").to_string())
    .collect();
    let mut schema_evidence_modes = BTreeSet::new();
    collect_tag_constants(
        &schema,
        schema
            .pointer("/$defs/ClaimEvidenceMode")
            .expect("claim evidence-mode schema exists"),
        &mut schema_evidence_modes,
    );
    assert_eq!(
        schema_evidence_modes, runtime_evidence_modes,
        "claim evidence-mode schema must share the runtime tagged contract"
    );
}

#[test]
fn adapter_variant_rosters_and_scalar_shapes_match_runtime_deserialization() {
    let schema = document();

    let valid = example_config();
    assert_valid(&schema, &valid, "maintained registry-backed config");
    assert_runtime_deserializes(&valid, "maintained registry-backed config");

    let mut invalid_duration = example_config();
    invalid_duration["server"]["request_timeout"] = json!("not-a-duration");
    assert_valid(
        &schema,
        &invalid_duration,
        "duration shape delegated to the runtime parser",
    );
    assert_runtime_rejects(&invalid_duration, "invalid duration");

    let mut invalid_socket = example_config();
    invalid_socket["server"]["bind"] = json!("not-a-socket");
    assert_valid(
        &schema,
        &invalid_socket,
        "socket shape delegated to the runtime parser",
    );
    assert_runtime_rejects(&invalid_socket, "invalid socket address");

    let mut invalid_cidr = example_config();
    invalid_cidr["evidence"]["relay"]["allowed_private_cidrs"] = json!(["not-a-cidr"]);
    assert_valid(
        &schema,
        &invalid_cidr,
        "CIDR shape delegated to the runtime parser",
    );
    assert_runtime_rejects(&invalid_cidr, "invalid private CIDR");

    let mut deferred_fingerprint_shape = example_config();
    deferred_fingerprint_shape["auth"]["api_keys"][0]["fingerprint"] =
        json!({"provider": "env", "path": "/mounted/fingerprint"});
    assert_valid(
        &schema,
        &deferred_fingerprint_shape,
        "credential-fingerprint reference shape deferred to runtime validation",
    );
    assert_runtime_deserializes(
        &deferred_fingerprint_shape,
        "credential-fingerprint reference shape deferred to runtime validation",
    );

    let mut self_attested = example_config();
    self_attested["evidence"]["claims"][0]["evidence_mode"] = json!({"type": "self_attested"});
    self_attested["evidence"]
        .as_object_mut()
        .expect("evidence is an object")
        .remove("credential_profiles");
    self_attested
        .as_object_mut()
        .expect("config is an object")
        .remove("oid4vci");
    if let Some(subject_access) = self_attested
        .get_mut("subject_access")
        .and_then(Value::as_object_mut)
    {
        subject_access.remove("credential_profiles");
    }
    assert_valid(
        &schema,
        &self_attested,
        "evaluation-only self-attested claim",
    );
    assert_runtime_deserializes(&self_attested, "evaluation-only self-attested claim");
}

#[test]
fn schema_contains_no_concrete_secret_values() {
    let schema = document();
    let text = serde_json::to_string(&schema).expect("schema serializes");
    for secret in [
        "REGISTRY_NOTARY_DHIS2_API_KEY_HASH",
        "REGISTRY_NOTARY_AUDIT_HASH_SECRET",
        "/var/run/secrets/registry-notary/relay-access-token",
    ] {
        assert!(
            !text.contains(secret),
            "schema must not contain fixture secret material or paths: {secret}"
        );
    }
}

#[test]
fn schema_and_configuration_reference_have_exact_bidirectional_key_path_parity() {
    let schema = document();
    let mut schema_paths = BTreeSet::new();
    collect_key_paths(&schema, &schema, "", &mut schema_paths, &mut HashSet::new());
    let reference = fs::read_to_string(stack_root().join(CONFIG_REFERENCE))
        .expect("configuration reference exists");
    let documented_paths = documented_key_paths(&reference);
    assert_eq!(
        documented_paths,
        schema_paths,
        "configuration key paths differ; generated schema paths follow:\n{}",
        schema_paths.iter().cloned().collect::<Vec<_>>().join("\n")
    );
}
