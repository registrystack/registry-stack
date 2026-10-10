// SPDX-License-Identifier: Apache-2.0
//! Operator-pinned Casework endpoints and BREG's own status credentials.
use super::*;
use registry_platform_config::{SecretReference, SecretResolver};
use registry_platform_httputil::client::PrivateKeyJwtConfig;
use registry_platform_yaml::Url;

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantStatusConfig {
    /// The Casework task authority's issuer, exactly as Casework states it.
    /// `http` and `https` are both accepted, since the value is compared, not
    /// fetched.
    pub source_issuer: Url,
    /// The Casework base URL the status check calls. It is `https`; `http`
    /// is accepted only for a loopback host, for local development.
    pub base_url: Url,
    pub token_endpoint: String,
    pub client_assertion_audience: String,
    pub client_id: String,
    pub private_key_ref: SecretReference,
    pub casework_resource: String,
    /// PEM CA bundle for Casework and its token endpoint. Omitted, the
    /// platform's trusted roots verify them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle_ref: Option<SecretReference>,
}

pub struct TaskGrantStatusRegistry {
    clients: BTreeMap<String, TaskGrantStatusClient>,
}

impl TaskGrantStatusRegistry {
    pub fn contains(&self, source_issuer: &str) -> bool {
        self.clients.contains_key(source_issuer)
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
                .resolve_reference(&config.private_key_ref)
                .map_err(|_| TaskGrantError::Configuration)?;
            let key = registry_platform_crypto::parse_json_strict(secret.expose_secret())
                .map_err(|_| TaskGrantError::Configuration)?;
            let key = serde_json::from_value(key).map_err(|_| TaskGrantError::Configuration)?;
            let ca = config
                .ca_bundle_ref
                .as_ref()
                .map(|reference| secrets.resolve_reference(reference))
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
            .with_audience(&config.client_assertion_audience)
            .with_resource(&config.casework_resource)
            .with_scopes(["casework:grants:status"]);
            if let Some(ca) = &ca {
                token = token.with_trusted_root_certificates(ca.expose_secret().to_vec());
            }
            let client = TaskGrantStatusClient::new(
                config.source_issuer.as_str().to_owned(),
                resource.to_owned(),
                config
                    .base_url
                    .as_str()
                    .parse()
                    .map_err(|_| TaskGrantError::Configuration)?,
                Arc::new(PrivateKeyJwt::new(token).map_err(|_| TaskGrantError::Configuration)?),
                ca.as_ref().map(|value| value.expose_secret()),
            )?;
            if clients
                .insert(config.source_issuer.as_str().to_owned(), client)
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
                .get(&binding.source_issuer)
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
            source_issuer: Url::new("https://casework.test").unwrap(),
            base_url: Url::new("https://casework.test").unwrap(),
            token_endpoint: "https://identity.test/oauth2/token".into(),
            client_assertion_audience: "https://identity.test".into(),
            client_id: "breg-status".into(),
            private_key_ref: SecretReference::parse("secret:file/status-key").unwrap(),
            casework_resource: "urn:casework:test".into(),
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
        invalid.casework_resource = "not-an-absolute-resource".into();
        assert!(TaskGrantStatusRegistry::activate(&[invalid], "urn:breg:test", &secrets).is_err());
        let mut retired = serde_json::to_value(config.clone()).unwrap();
        retired["authority"] = serde_json::json!("casework-v1");
        assert!(serde_json::from_value::<TaskGrantStatusConfig>(retired).is_err());
        let mut raw = serde_json::to_value(config).unwrap();
        raw["scopes"] = serde_json::json!(["admin"]);
        assert!(serde_json::from_value::<TaskGrantStatusConfig>(raw).is_err());
    }
}
