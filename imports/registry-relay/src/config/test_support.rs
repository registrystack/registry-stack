// SPDX-License-Identifier: Apache-2.0
//! Shared test fixtures for loading the governed example config.

use std::env;
use std::fs;
use std::path::Path;

use registry_platform_authcommon::{
    credential_fingerprint_commitment, CredentialCommitmentContext, CredentialProduct,
    CredentialType,
};

use super::{validate, Config};

fn test_fingerprint(index: usize) -> String {
    format!("sha256:{:064x}", index + 1)
}

/// Load the repository example config for tests.
///
/// The public example uses governed fingerprint commitments. Test fixtures do
/// not know the corresponding real secrets, so this helper assigns stable,
/// distinct fingerprints to the referenced env vars and recomputes the
/// in-memory commitments before running the normal validator.
#[must_use]
pub fn load_example_config_for_tests(audit_hash_secret: &str) -> Config {
    unsafe {
        env::set_var("REGISTRY_RELAY_AUDIT_HASH_SECRET", audit_hash_secret);
    }
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/example.yaml");
    let raw = fs::read_to_string(path).expect("example config reads");
    let mut config: Config = serde_saphyr::from_str(&raw).expect("example config parses");
    for (index, key) in config.auth.api_keys.iter_mut().enumerate() {
        let fingerprint = test_fingerprint(index);
        let env_name = key
            .fingerprint
            .name
            .as_deref()
            .expect("example API key fingerprint uses env provider");
        unsafe {
            env::set_var(env_name, &fingerprint);
        }
        key.fingerprint.commitment = credential_fingerprint_commitment(
            CredentialCommitmentContext {
                product: CredentialProduct::RegistryRelay,
                credential_type: CredentialType::ApiKey,
                credential_id: &key.id,
            },
            &fingerprint,
        );
    }
    validate::run(&config).expect("adjusted example config validates");
    config
}
