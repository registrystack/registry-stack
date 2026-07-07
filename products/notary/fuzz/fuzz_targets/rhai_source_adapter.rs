#![no_main]

use libfuzzer_sys::fuzz_target;
use registry_notary_source_adapter_rhai::convert::{dynamic_to_json, json_to_dynamic, ConvertCaps};
use registry_notary_source_adapter_rhai::{
    canonicalize_target_relative_path, validate_records, RhaiLimits, RhaiPolicy, ScriptEngine,
};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let bounded = take_chars(input, 8192);

    // The request-path security gate: a pure, synchronous traversal guard.
    let _ = canonicalize_target_relative_path(&bounded);

    // Untrusted Rhai script source handed to the sandboxed engine.
    let _ = ScriptEngine::compile(&bounded, "lookup", &RhaiPolicy::default());

    // Bounded JSON <-> Dynamic conversion (the depth/size-capped boundary that
    // guards against stack-overflow-via-recursion) and script-output shape
    // validation.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&bounded) {
        let caps = ConvertCaps::from_limits(&RhaiLimits::default());
        if let Ok(dynamic) = json_to_dynamic(&value, caps) {
            if let Ok(round_tripped) = dynamic_to_json(&dynamic, caps) {
                let _ = validate_records(round_tripped);
            }
        }
        let _ = validate_records(value);
    }
});

fn take_chars(input: &str, limit: usize) -> String {
    input.chars().take(limit).collect()
}
