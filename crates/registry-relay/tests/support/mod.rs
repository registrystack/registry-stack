// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use registry_platform_authcommon::CredentialFingerprintProvider;
use registry_relay::config::{validate, Config};

static NEXT_CONFIG_ID: AtomicUsize = AtomicUsize::new(0);

fn test_env_namespace() -> String {
    let index = NEXT_CONFIG_ID.fetch_add(1, Ordering::Relaxed);
    format!(
        "REGISTRY_RELAY_EXAMPLE_CONFIG_TEST_{}_{}",
        std::process::id(),
        index
    )
}

fn test_fingerprint(index: usize) -> String {
    format!("sha256:{:064x}", index + 1)
}

pub fn load_example_config_for_tests(audit_hash_secret: &str) -> Config {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/example.yaml");
    let raw = fs::read_to_string(path).expect("example config reads");
    let mut config: Config = serde_saphyr::from_str(&raw).expect("example config parses");
    let namespace = test_env_namespace();
    let audit_hash_secret_env = format!("{namespace}_AUDIT_HASH_SECRET");
    std::env::set_var(&audit_hash_secret_env, audit_hash_secret);
    config.audit.hash_secret_env = Some(audit_hash_secret_env);

    for (index, key) in config.auth.api_keys.iter_mut().enumerate() {
        let fingerprint = test_fingerprint(index);
        let env_name = format!("{namespace}_API_KEY_FINGERPRINT_{index}");
        std::env::set_var(&env_name, &fingerprint);
        key.fingerprint.provider = CredentialFingerprintProvider::Env;
        key.fingerprint.name = Some(env_name);
        key.fingerprint.path = None;
    }

    validate::run(&config).expect("adjusted example config validates");
    config
}
