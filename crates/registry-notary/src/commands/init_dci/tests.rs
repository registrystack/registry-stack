// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::test_dci_options;

#[test]
fn generated_dci_config_uses_explicit_dci_and_generic_oauth() {
    let yaml = dci_config_yaml(&test_dci_options(true));
    assert!(!yaml.contains("preset:"));
    assert!(yaml.contains("type: oauth2_client_credentials"));
    assert!(yaml.contains("client_id_env: DCI_CLIENT_ID"));
    assert!(yaml.contains("field: 'SUBJECT_ID'"));
    let config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(&yaml).expect("generated config parses");
    config.validate().expect("generated config validates");
    let profile = config
        .evidence
        .credential_profiles
        .get("dci_record_sd_jwt")
        .expect("demo DCI credential profile exists");
    assert_eq!(profile.holder_binding.mode, "none");
    assert!(profile.holder_binding.proof_of_possession.is_none());
}
