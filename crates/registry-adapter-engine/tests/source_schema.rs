//! Provider envelopes use the same bounded, offline JSON Schema implementation.
use registry_adapter_core::ScriptReference;
use registry_adapter_engine::{artifacts::PackArtifactBytes, component::schema::ProviderSchema};
use serde_json::{json, Value};

fn compile(
    schema: Value,
) -> Result<ProviderSchema, registry_adapter_engine::component::schema::ProviderSchemaError> {
    let bytes = serde_json::to_vec(&schema).unwrap();
    let reference: ScriptReference = serde_json::from_value(json!({"path":"schemas/provider.json","digest":registry_platform_config::sha256_uri(&bytes)})).unwrap();
    ProviderSchema::compile(
        &reference,
        &PackArtifactBytes::new([("schemas/provider.json".to_owned(), bytes)]),
    )
}

#[test]
fn provider_arrays_validate_closed_nested_records_and_real_calendar_dates() {
    let checked = compile(json!({"type":"array","maxItems":2,"items":{
        "type":"object","additionalProperties":false,"required":["birthDate"],
        "properties":{"birthDate":{"type":"string","format":"date"}}
    }}))
    .unwrap();
    assert!(checked.validate(&json!([{"birthDate":"2000-02-29"}])));
    assert!(!checked.validate(&json!([{"birthDate":"2026-02-31"}])));
    assert!(!checked.validate(&json!([{"birthDate":"2000-02-29","private":"canary"}])));
}

#[test]
fn provider_schema_refuses_unpinned_bytes_external_refs_and_open_nested_objects() {
    assert!(compile(json!({"type":"array","items":{"type":"object"}})).is_err());
    assert!(compile(json!({"$ref":"file:///private-canary.json"})).is_err());
    let reference: ScriptReference = serde_json::from_value(json!({"path":"schemas/provider.json","digest":registry_platform_config::sha256_uri(b"reviewed")})).unwrap();
    assert!(ProviderSchema::compile(
        &reference,
        &PackArtifactBytes::new([("schemas/provider.json".to_owned(), b"{}".to_vec())])
    )
    .is_err());
    assert!(ProviderSchema::compile(&reference, &PackArtifactBytes::default()).is_err());
}
