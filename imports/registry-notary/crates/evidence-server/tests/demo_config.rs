// SPDX-License-Identifier: Apache-2.0
//! Demo configuration loading for the split Evidence Server repository.

use evidence_core::StandaloneEvidenceServerConfig;
use evidence_server::standalone_router;

const DEMO_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

#[test]
fn split_demo_config_loads_validates_and_builds_router() {
    std::env::set_var("EVIDENCE_SERVER_API_KEY", "demo-evidence-api-key");
    std::env::set_var("EVIDENCE_SERVER_BEARER_TOKEN", "demo-evidence-bearer-token");
    std::env::set_var(
        "EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN",
        "demo-evidence-casework-system",
    );
    std::env::set_var("EVIDENCE_SERVER_ISSUER_JWK", DEMO_ISSUER_JWK);

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("demo/config/evidence-server.yaml");
    let raw = std::fs::read_to_string(config_path).expect("demo config is readable");
    let mut config: StandaloneEvidenceServerConfig =
        serde_yml::from_str(&raw).expect("demo config deserializes");
    let temp = tempfile::TempDir::new().expect("tempdir");
    config.audit.path = Some(
        temp.path()
            .join("evidence-server-audit.jsonl")
            .to_string_lossy()
            .into_owned(),
    );

    config.validate().expect("demo config validates");
    let _ = standalone_router(config).expect("demo config builds standalone router");
}
