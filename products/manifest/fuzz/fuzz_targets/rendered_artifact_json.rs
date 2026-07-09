#![no_main]

use libfuzzer_sys::fuzz_target;
use registry_manifest_core::{
    canonicalize_json, compile_manifest, compute_evidence_pack_policy_hash, compute_policy_hash,
    source_manifest_digest, validate_manifest, verify_evidence_pack_policy_hash,
    EvidencePackMetadata, MetadataManifest,
};

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let bounded = if data.len() > MAX_INPUT_BYTES {
        &data[..MAX_INPUT_BYTES]
    } else {
        data
    };

    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bounded) else {
        return;
    };

    let _ = canonicalize_json(&value);
    let _ = compute_policy_hash(&value);

    if let Ok(manifest) = serde_json::from_value::<MetadataManifest>(value.clone()) {
        let _ = source_manifest_digest(&manifest);
        if validate_manifest(&manifest).is_ok() {
            let _ = compile_manifest(&manifest);
        }
    }

    if let Ok(evidence_pack) = serde_json::from_value::<EvidencePackMetadata>(value) {
        let _ = compute_evidence_pack_policy_hash(&evidence_pack);
        let _ = verify_evidence_pack_policy_hash(&evidence_pack);
    }
});
