use registry_language_core::{analyze, AnalysisRequest};
use registry_language_core_wasm::analyze_json;
use serde_json::Value;

const PROJECT: &str = include_str!("fixtures/evidence-project.json");

#[test]
fn native_and_wasm_json_boundaries_return_the_same_evidence_analysis() {
    let request: AnalysisRequest = serde_json::from_str(PROJECT).expect("fixture request is valid");
    let native = serde_json::to_value(analyze(request)).expect("native result is serializable");
    let wasm: Value = serde_json::from_str(&analyze_json(PROJECT)).expect("Wasm result is JSON");

    assert_eq!(wasm, native);
    assert_eq!(wasm["schema"], "registry.language.core/v1");
    assert!(wasm["error"].is_null());
    assert!(wasm["relationships"]
        .as_array()
        .is_some_and(|edges| !edges.is_empty()));
}
