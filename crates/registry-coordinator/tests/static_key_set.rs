// SPDX-License-Identifier: Apache-2.0
//! The static key set behind `deployment.authentication.jwksSource` loads
//! through the authenticator the server builds, and a refused set names the
//! key file's own problem at startup.
use registry_coordinator::access::{AccessConfig, Action, ClientPolicy};
use registry_platform_config::{
    FileSecretProviderConfig, JwksSource, OidcIssuerConfig, SecretProvidersConfig,
};
use registry_platform_testing::TokenSigner;
use registry_platform_yaml::Url;
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt};

const KEY_FILE: &str = "issuer-keys.json";

/// The corpus signer's public keys a static document may hold: RSA and EC
/// only, so its EdDSA key is left out.
fn public_keys() -> Value {
    let mut keys = TokenSigner::new().public_key_set();
    keys["keys"]
        .as_array_mut()
        .unwrap()
        .retain(|key| key["kty"] != "OKP");
    keys
}

async fn build(document: &Value) -> Result<(), registry_coordinator::CoordinatorError> {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let file = root_path.join(KEY_FILE);
    fs::write(&file, document.to_string()).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let secrets = SecretProvidersConfig {
        file: Some(FileSecretProviderConfig { root: root_path }),
        environment: None,
    };
    let access = AccessConfig {
        issuer: OidcIssuerConfig {
            issuer: Url::new("https://issuer.example.test".to_owned()).unwrap(),
            audience: "urn:coordinator:test".to_owned(),
            jwks_source: JwksSource::Static {
                document_ref: format!("secret:file/{KEY_FILE}"),
            },
            allow_insecure_http: false,
        },
        assertion_issuers: BTreeMap::new(),
        scope_claim: "scope".to_owned(),
        policies: BTreeMap::from([(
            "journey-app".to_owned(),
            ClientPolicy {
                subjects: vec!["subject".to_owned()],
                required_scopes: vec!["coordinator:start".to_owned()],
                workflows: vec!["follow-up".to_owned()],
                actions: vec![Action::Start],
                operator: false,
            },
        )]),
    };
    access.authenticator(&secrets).await.map(|_| ())
}

#[tokio::test]
async fn a_public_key_set_with_an_ext_member_loads() {
    let mut keys = public_keys();
    keys["keys"][0]["ext"] = json!(true);
    build(&keys).await.expect("a public key set with ext loads");
}

#[tokio::test]
async fn a_key_set_holding_a_private_member_is_refused_with_the_key_files_own_text() {
    let mut keys = public_keys();
    keys["keys"][0]["d"] = json!("AQAB");
    let error = match build(&keys).await {
        Ok(()) => panic!("a key set with a private member is refused"),
        Err(error) => error,
    };
    assert_eq!(error.code, "access.configuration");
    assert!(
        error.message.contains("static key set"),
        "the refusal names the key set, not the issuer or policies: {}",
        error.message
    );
    assert!(
        !error.message.contains("AQAB"),
        "the refusal carries no key material: {}",
        error.message
    );
}
