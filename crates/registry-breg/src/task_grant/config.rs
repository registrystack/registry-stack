// SPDX-License-Identifier: Apache-2.0
//! Operator-pinned Casework endpoints and BREG's own status credentials.
use super::*;
use registry_platform_config::SecretResolver;
use registry_platform_httputil::client::PrivateKeyJwtConfig;

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantStatusConfig {
    pub authority: String,
    pub source_issuer: String,
    pub base_url: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub private_key_ref: String,
    pub casework_resource: String,
    pub ca_bundle_ref: Option<String>,
}

pub struct TaskGrantStatusRegistry {
    clients: BTreeMap<(String, String), TaskGrantStatusClient>,
}

impl TaskGrantStatusRegistry {
    pub fn contains(&self, authority: &str, source_issuer: &str) -> bool {
        self.clients
            .contains_key(&(authority.to_owned(), source_issuer.to_owned()))
    }

    pub fn activate(
        configs: &[TaskGrantStatusConfig],
        resource: &str,
        secrets: &SecretResolver,
    ) -> Result<Self, TaskGrantError> {
        if configs.len() > 32 {
            return Err(TaskGrantError::Configuration);
        }
        let mut clients = BTreeMap::new();
        for config in configs {
            let secret = secrets
                .resolve(&config.private_key_ref)
                .map_err(|_| TaskGrantError::Configuration)?;
            let key = registry_platform_crypto::parse_json_strict(secret.expose_secret())
                .map_err(|_| TaskGrantError::Configuration)?;
            let key = serde_json::from_value(key).map_err(|_| TaskGrantError::Configuration)?;
            let ca = config
                .ca_bundle_ref
                .as_ref()
                .map(|reference| secrets.resolve(reference))
                .transpose()
                .map_err(|_| TaskGrantError::Configuration)?;
            let mut token = PrivateKeyJwtConfig::new(
                config
                    .token_endpoint
                    .parse()
                    .map_err(|_| TaskGrantError::Configuration)?,
                &config.client_id,
                key,
            )
            .with_resource(&config.casework_resource)
            .with_scopes(["casework:grants:status"]);
            if let Some(ca) = &ca {
                token = token.with_trusted_root_certificates(ca.expose_secret().to_vec());
            }
            let client = TaskGrantStatusClient::new(
                config.authority.clone(),
                config.source_issuer.clone(),
                resource.to_owned(),
                config
                    .base_url
                    .parse()
                    .map_err(|_| TaskGrantError::Configuration)?,
                Arc::new(PrivateKeyJwt::new(token).map_err(|_| TaskGrantError::Configuration)?),
                ca.as_ref().map(|value| value.expose_secret()),
            )?;
            if clients
                .insert(
                    (config.authority.clone(), config.source_issuer.clone()),
                    client,
                )
                .is_some()
            {
                return Err(TaskGrantError::Configuration);
            }
        }
        Ok(Self { clients })
    }
}

impl TaskGrantStatusChecker for TaskGrantStatusRegistry {
    fn check<'a>(
        &'a self,
        binding: &'a TaskGrantBinding,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskGrantError>> + Send + 'a>>
    {
        Box::pin(async move {
            let client = self
                .clients
                .get(&(binding.authority.clone(), binding.source_issuer.clone()))
                .ok_or(TaskGrantError::Refused)?;
            client.check(binding).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_config::SecretProvider;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn configured_status_clients_pin_authority_and_refuse_unsafe_or_duplicate_bindings() {
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
            authority: "https://casework.test/tasks".into(),
            source_issuer: "https://casework.test".into(),
            base_url: "https://casework.test".into(),
            token_endpoint: "https://identity.test/oauth2/token".into(),
            client_id: "breg-status".into(),
            private_key_ref: "secret:file/status-key".into(),
            casework_resource: "urn:casework:test".into(),
            ca_bundle_ref: None,
        };
        let status = TaskGrantStatusRegistry::activate(
            std::slice::from_ref(&config),
            "urn:breg:test",
            &secrets,
        )
        .unwrap();
        assert!(status.contains(&config.authority, &config.source_issuer));
        assert!(!status.contains(&config.authority, "https://other.test"));
        assert!(TaskGrantStatusRegistry::activate(
            &[config.clone(), config.clone()],
            "urn:breg:test",
            &secrets
        )
        .is_err());
        for url in [
            "http://casework.test",
            "https://user@casework.test",
            "https://casework.test/#fragment",
        ] {
            let mut invalid = config.clone();
            invalid.base_url = url.into();
            assert!(
                TaskGrantStatusRegistry::activate(&[invalid], "urn:breg:test", &secrets).is_err(),
                "{url}"
            );
        }
        let mut invalid = config.clone();
        invalid.casework_resource = "not-an-absolute-resource".into();
        assert!(TaskGrantStatusRegistry::activate(&[invalid], "urn:breg:test", &secrets).is_err());
        let mut raw = serde_json::to_value(config).unwrap();
        raw["scopes"] = serde_json::json!(["admin"]);
        assert!(serde_json::from_value::<TaskGrantStatusConfig>(raw).is_err());
    }
}
