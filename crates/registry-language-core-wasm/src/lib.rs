// SPDX-License-Identifier: Apache-2.0
//! Versioned JSON-only WebAssembly boundary for Evidence authoring analysis.

use registry_language_core::{
    analyze, AnalysisRequest, AnalysisResult, ApiError, API_SCHEMA, API_VERSION,
};
use wasm_bindgen::prelude::*;

/// Analyses a `registry.language.core/v1` JSON request and returns its JSON result.
/// The boundary deliberately accepts and returns strings so browser paths and positions never
/// inherit host filesystem types or Rust-only representation details.
#[wasm_bindgen]
pub fn analyze_json(request: &str) -> String {
    let result = match serde_json::from_str::<AnalysisRequest>(request) {
        Ok(request) => analyze(request),
        Err(_) => AnalysisResult {
            schema: API_SCHEMA.to_owned(),
            api_version: API_VERSION,
            error: Some(ApiError {
                code: "invalid-request".to_owned(),
                message: "Request is not valid registry.language.core/v1 JSON".to_owned(),
            }),
            ..AnalysisResult::default()
        },
    };
    serde_json::to_string(&result).expect("analysis result is serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundary_returns_versioned_error() {
        assert!(analyze_json("{}").contains("invalid-request"));
    }
}
