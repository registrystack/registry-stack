#![no_main]

use libfuzzer_sys::fuzz_target;
use registry_notary_source_adapter_sidecar::render_governed_runtime_target_json;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let bounded = take_chars(input, 16384);

    // The real entry point for the sidecar's governed-config parse boundary:
    // YAML deserialization of the full `SidecarConfig` surface followed by
    // runtime-target validation.
    let _ = render_governed_runtime_target_json(&bounded);
});

fn take_chars(input: &str, limit: usize) -> String {
    input.chars().take(limit).collect()
}
