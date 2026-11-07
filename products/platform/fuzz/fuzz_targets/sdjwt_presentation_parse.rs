#![no_main]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use libfuzzer_sys::fuzz_target;
use registry_platform_sdjwt::{parse_presentation, resolve_disclosures, SdJwtLimits};
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let limits = SdJwtLimits::default();
    let Ok(parsed) = parse_presentation(input, &limits) else {
        return;
    };
    let _ = parsed.sd_hash();

    // The issuer signature is not checked here: resolution runs on whatever
    // payload the input carries, as it would after a verified signature.
    let Some(segment) = parsed.issuer_jwt.split('.').nth(1) else {
        return;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(segment) else {
        return;
    };
    let Ok(Value::Object(payload)) = serde_json::from_slice::<Value>(&bytes) else {
        return;
    };
    let _ = resolve_disclosures(&payload, &parsed.disclosures, &limits);
});
