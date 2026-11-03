//! Readiness keeps operator failure categories without reading source data.
use registry_adapter_core::EvidenceConnectionPolicy;
use registry_adapter_engine::evidence::{EvidenceLimits, EvidenceRuntimeBindings};
use registry_evidence::{
    bundle::{evidence_package_limits, Bundle},
    pack_source::{PackSourceError, PackSourceExecutor},
};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
use std::path::PathBuf;

#[tokio::test]
async fn missing_source_credential_retains_its_value_free_readiness_category() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/fixtures/acceptance/adult-status");
    let verified = registry_platform_config::verify_package(
        &root,
        &evidence_package_limits(),
        "evidencectl package",
    )
    .unwrap();
    let bundle = Bundle::load_as_found(&root, &verified).unwrap();
    let secret_root = tempfile::tempdir().unwrap();
    let runtime = EvidenceRuntimeBindings::new(
        serde_json::from_value(json!({
            "id":"readiness","endpoints":[{
                "endpoint":"provider","baseUrl":"http://127.0.0.1:9",
                "credential":{"type":"static-authorization","tokenRef":"secret:file/not-present"}
            }],"allowedPrivateCidrs":[]
        }))
        .unwrap(),
        SecretResolver::new([SecretProvider::File], secret_root.path()).unwrap(),
    );
    let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint":"provider","baseUrl":"http://127.0.0.1:9",
        "clientIdentity":"forbidden","authentication":{"type":"static-authorization"}
    }))
    .unwrap();
    let mut source = bundle.config.sources.get("source-a").unwrap().clone();
    source.connection = registry_platform_yaml::LocalId::new("readiness").unwrap();
    let executor = PackSourceExecutor::compile(
        &source,
        bundle.source_pack("source-a").unwrap(),
        &runtime,
        &[policy],
        EvidenceLimits::default(),
    )
    .unwrap();
    let error = executor.credentials_ready().await.unwrap_err();
    assert_eq!(error, PackSourceError::Credential);
    assert!(!error.to_string().contains("not-present"));
    assert!(!error.to_string().contains("127.0.0.1"));
}
