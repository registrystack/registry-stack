#![no_main]

//! The OpenAPI reading stage of the authoring form: parsing a description an
//! adopter supplies, resolving one operation's success response schema, and
//! flattening that schema into candidate leaves
//! (`registry-evidence-authoring`).

use libfuzzer_sys::fuzz_target;
use registry_evidence_authoring::openapi::{openapi::Spec, selectable_leaves};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let bounded: String = text.chars().take(16_384).collect();
    let Ok(spec) = Spec::parse(&bounded, "fuzz") else {
        return;
    };
    let _ = spec.openapi_version();
    let _ = spec.mock_hint();
    let _ = spec.servers();
    let Ok(operations) = spec.declared_operations() else {
        return;
    };
    for operation in operations.iter().take(3) {
        let _ = spec.operation(operation);
        let _ = spec.operation_parameters(operation);
        let _ = spec.page_size_maximums(operation);
        let _ = selectable_leaves(&spec, operation);
    }
});
