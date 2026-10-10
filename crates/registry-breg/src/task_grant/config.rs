// SPDX-License-Identifier: Apache-2.0
//! BReg's product-specific policy around the shared exact-status transport.
use super::*;
use registry_platform_config::SecretResolver;
pub use registry_platform_oidc::task_grant::TaskGrantStatusConfig;

pub struct TaskGrantStatusRegistry(registry_platform_oidc::task_grant::TaskGrantStatusRegistry);
impl TaskGrantStatusRegistry {
    pub fn contains(&self, source_issuer: &str) -> bool {
        self.0.contains(source_issuer)
    }
    /// Check nonsecret client structure without resolving credential material.
    pub fn validate_configuration(
        configs: &[TaskGrantStatusConfig],
        resource: &str,
    ) -> Result<(), TaskGrantError> {
        registry_platform_oidc::task_grant::TaskGrantStatusRegistry::validate_configuration(
            configs, resource,
        )
    }
    pub fn activate(
        configs: &[TaskGrantStatusConfig],
        resource: &str,
        secrets: &SecretResolver,
    ) -> Result<Self, TaskGrantError> {
        registry_platform_oidc::task_grant::TaskGrantStatusRegistry::activate(
            configs, resource, secrets,
        )
        .map(Self)
    }
}
impl TaskGrantStatusChecker for TaskGrantStatusRegistry {
    fn check<'a>(
        &'a self,
        binding: &'a TaskGrantBinding,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskGrantError>> + Send + 'a>>
    {
        Box::pin(async move { self.0.check(&binding.status_binding()?).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_config::{SecretProvider, SecretReference};
    use registry_platform_yaml::{ExternalId, Url};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn configured_status_clients_pin_source_issuer_and_refuse_unsafe_or_duplicate_bindings() {
        let root = tempfile::tempdir().unwrap();
        let mut key = registry_platform_crypto::generate_private_jwk(
            registry_platform_crypto::GeneratedKeyAlgorithm::Rs384,
        )
        .unwrap();
        key.alg = Some("RS256".into());
        let path = root.path().join("status-key");
        let mut private = serde_json::to_value(&key).unwrap();
        for (name, value) in [
            ("d", &key.d),
            ("p", &key.p),
            ("q", &key.q),
            ("dp", &key.dp),
            ("dq", &key.dq),
            ("qi", &key.qi),
        ] {
            if let Some(value) = value {
                private[name] = Value::String(value.clone());
            }
        }
        std::fs::write(&path, serde_json::to_vec(&private).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let secrets = SecretResolver::new([SecretProvider::File], root.path()).unwrap();
        let config = TaskGrantStatusConfig {
            source_issuer: ExternalId::new("https://casework.test").unwrap(),
            base_url: Url::new("https://casework.test").unwrap(),
            token_endpoint: Url::new("https://identity.test/oauth2/token").unwrap(),
            client_assertion_audience: ExternalId::new("https://identity.test").unwrap(),
            client_id: ExternalId::new("breg-status").unwrap(),
            private_key_ref: SecretReference::parse("secret:file/status-key").unwrap(),
            casework_resource: ExternalId::new("urn:casework:test").unwrap(),
            ca_bundle_ref: None,
        };
        let status = TaskGrantStatusRegistry::activate(
            std::slice::from_ref(&config),
            "urn:breg:test",
            &secrets,
        )
        .unwrap();
        assert!(status.contains(&config.source_issuer));
        assert!(!status.contains("https://other.test"));
        let mut duplicate = config.clone();
        duplicate.base_url = Url::new("https://other-casework.test").unwrap();
        assert!(TaskGrantStatusRegistry::activate(
            &[config.clone(), duplicate],
            "urn:breg:test",
            &secrets
        )
        .is_err());
        assert!(Url::new("https://user@casework.test").is_err());
        for url in ["http://casework.test", "https://casework.test/#fragment"] {
            let mut invalid = config.clone();
            invalid.base_url = Url::new(url).unwrap();
            assert!(
                TaskGrantStatusRegistry::activate(&[invalid], "urn:breg:test", &secrets).is_err(),
                "{url}"
            );
        }
        let mut invalid = config.clone();
        invalid.casework_resource = ExternalId::new("not-an-absolute-resource").unwrap();
        assert!(TaskGrantStatusRegistry::activate(&[invalid], "urn:breg:test", &secrets).is_err());
        let mut retired = serde_json::to_value(config.clone()).unwrap();
        retired["authority"] = serde_json::json!("casework-v1");
        assert!(serde_json::from_value::<TaskGrantStatusConfig>(retired).is_err());
        let mut raw = serde_json::to_value(config).unwrap();
        raw["scopes"] = serde_json::json!(["admin"]);
        assert!(serde_json::from_value::<TaskGrantStatusConfig>(raw).is_err());
    }
}
