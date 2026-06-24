#![no_main]

use libfuzzer_sys::fuzz_target;
use registry_notary_core::{
    BatchEvaluateRequest, CredentialIssueRequest, EvaluateRequest, HolderRequest,
    RenderEvaluationRequest, RenderRequest,
};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<EvaluateRequest>(data);
    let _ = serde_json::from_slice::<BatchEvaluateRequest>(data);
    let _ = serde_json::from_slice::<RenderRequest>(data);
    let _ = serde_json::from_slice::<RenderEvaluationRequest>(data);
    let _ = serde_json::from_slice::<CredentialIssueRequest>(data);
    let _ = serde_json::from_slice::<HolderRequest>(data);
});
