// SPDX-License-Identifier: Apache-2.0
//! Operator-pinned Casework endpoints and BREG's own status credentials,
//! checked by the shared exact-status transport.
use super::*;
use registry_platform_config::{SecretResolver, TaskGrantStatusConfig};
use registry_platform_oidc::task_grant::TaskGrantStatusEndpoint;

fn endpoints(configs: &[TaskGrantStatusConfig]) -> Vec<TaskGrantStatusEndpoint> {
    configs.iter().map(TaskGrantStatusEndpoint::from).collect()
}

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
            &endpoints(configs),
            resource,
        )
    }
    pub fn activate(
        configs: &[TaskGrantStatusConfig],
        resource: &str,
        secrets: &SecretResolver,
    ) -> Result<Self, TaskGrantError> {
        registry_platform_oidc::task_grant::TaskGrantStatusRegistry::activate(
            &endpoints(configs),
            resource,
            secrets,
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
    use registry_platform_config::SecretProvider;
    use registry_platform_yaml::{ExternalId, Url};
    use std::os::unix::fs::PermissionsExt;

    fn status_config(extra: serde_json::Value) -> TaskGrantStatusConfig {
        let mut raw = serde_json::json!({
            "sourceIssuer":"https://casework.test",
            "baseUrl":"https://casework.test",
            "tokenEndpoint":"https://identity.test/oauth2/token",
            "clientAssertionAudience":"https://identity.test",
            "clientId":"breg-status",
            "privateKeyRef":"secret:file/status-key",
            "caseworkResource":"urn:casework:test"
        });
        raw.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(raw).unwrap()
    }

    #[test]
    fn status_scope_and_path_default_to_casework_and_accept_operator_values() {
        let defaults = status_config(serde_json::json!({}));
        assert_eq!(defaults.status_scope.as_str(), "casework:grants:status");
        assert_eq!(defaults.status_path, "/v1/task-grants/{grantId}/status");
        let endpoint = TaskGrantStatusEndpoint::from(&defaults);
        assert_eq!(endpoint.status_resource.as_str(), "urn:casework:test");
        assert_eq!(endpoint.status_scope.as_str(), "casework:grants:status");
        assert_eq!(endpoint.status_path, "/v1/task-grants/{grantId}/status");

        let configured = status_config(serde_json::json!({
            "statusScope":"grants:status",
            "statusPath":"/api/grants/{grantId}"
        }));
        let endpoint = TaskGrantStatusEndpoint::from(&configured);
        assert_eq!(endpoint.status_scope.as_str(), "grants:status");
        assert_eq!(endpoint.status_path, "/api/grants/{grantId}");
        TaskGrantStatusRegistry::validate_configuration(&[configured], "urn:breg:test").unwrap();

        for extra in [
            serde_json::json!({"statusPath":"/api/grants"}),
            serde_json::json!({"statusScope":"grants:status other"}),
        ] {
            assert!(
                TaskGrantStatusRegistry::validate_configuration(
                    &[status_config(extra.clone())],
                    "urn:breg:test"
                )
                .is_err(),
                "{extra}"
            );
        }
    }

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
        let config = status_config(serde_json::json!({}));
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
