// SPDX-License-Identifier: Apache-2.0
//! Operator-pinned authority endpoints and the resource server's status credential.
use super::*;
use registry_platform_config::{SecretReference, SecretResolver};
use registry_platform_httputil::client::PrivateKeyJwtConfig;
use registry_platform_yaml::{ExternalId, Url};

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantStatusConfig {
    /// The exact authority identifier, including an absolute URN issuer.
    /// It is compared rather than fetched and must be an absolute resource URI.
    pub source_issuer: ExternalId,
    /// HTTPS service base; plaintext HTTP is allowed only on loopback.
    pub base_url: Url,
    pub token_endpoint: Url,
    pub client_assertion_audience: ExternalId,
    pub client_id: ExternalId,
    pub private_key_ref: SecretReference,
    /// The status service audience, which must be an absolute resource URI.
    pub casework_resource: ExternalId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle_ref: Option<SecretReference>,
}
impl fmt::Debug for TaskGrantStatusConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskGrantStatusConfig(<configured>)")
    }
}

pub struct TaskGrantStatusRegistry {
    clients: BTreeMap<String, TaskGrantStatusClient>,
}

impl TaskGrantStatusRegistry {
    pub fn contains(&self, source_issuer: &str) -> bool {
        self.clients.contains_key(source_issuer)
    }

    /// Validate operator-pinned nonsecret structure without resolving keys or
    /// certificates, constructing HTTP clients, or contacting an endpoint.
    /// Activation repeats this check before its secret and provider readiness.
    ///
    /// # Errors
    /// Returns [`TaskGrantError::Configuration`] for duplicate source issuers,
    /// more than 32 entries, or a field the status/token clients would refuse.
    pub fn validate_configuration(
        configs: &[TaskGrantStatusConfig],
        resource: &str,
    ) -> Result<(), TaskGrantError> {
        if configs.len() > 32 {
            return Err(TaskGrantError::Configuration);
        }
        let mut issuers = std::collections::BTreeSet::new();
        for config in configs {
            if !registry_platform_httputil::valid_resource_uri(&config.source_issuer)
                || !registry_platform_httputil::valid_resource_uri(resource)
                || !registry_platform_httputil::valid_resource_uri(&config.casework_resource)
                || !issuers.insert(config.source_issuer.as_str())
            {
                return Err(TaskGrantError::Configuration);
            }
            ServiceBaseUrl::new(
                config
                    .base_url
                    .as_str()
                    .parse()
                    .map_err(|_| TaskGrantError::Configuration)?,
            )
            .map_err(|_| TaskGrantError::Configuration)?;
            PrivateKeyJwtConfig::check_identity(
                &config
                    .token_endpoint
                    .as_str()
                    .parse()
                    .map_err(|_| TaskGrantError::Configuration)?,
                config.client_id.as_str(),
                Some(&config.client_assertion_audience),
            )
            .map_err(|_| TaskGrantError::Configuration)?;
        }
        Ok(())
    }

    pub fn activate(
        configs: &[TaskGrantStatusConfig],
        resource: &str,
        secrets: &SecretResolver,
    ) -> Result<Self, TaskGrantError> {
        Self::validate_configuration(configs, resource)?;
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
                    .as_str()
                    .parse()
                    .map_err(|_| TaskGrantError::Configuration)?,
                config.client_id.as_str(),
                key,
            )
            .with_audience(config.client_assertion_audience.as_str())
            .with_resource(config.casework_resource.as_str())
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

impl TaskGrantStatusRegistry {
    pub async fn check(&self, binding: &TaskGrantStatusBinding) -> Result<(), TaskGrantError> {
        binding.validate()?;
        let client = self
            .clients
            .get(&binding.source_issuer)
            .ok_or(TaskGrantError::Refused)?;
        client.check(binding).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_config::SecretProvider;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn status_structure_is_checked_without_resolving_credential_material() {
        let config = TaskGrantStatusConfig {
            source_issuer: ExternalId::new("urn:casework:source").unwrap(),
            base_url: Url::new("https://unreachable.invalid/path").unwrap(),
            token_endpoint: Url::new("http://127.0.0.1:1/token").unwrap(),
            client_assertion_audience: ExternalId::new("urn:identity:test").unwrap(),
            client_id: ExternalId::new("status-client").unwrap(),
            private_key_ref: SecretReference::parse("secret:file/missing-key").unwrap(),
            casework_resource: ExternalId::new("urn:casework:test").unwrap(),
            ca_bundle_ref: Some(SecretReference::parse("secret:file/missing-ca").unwrap()),
        };
        TaskGrantStatusRegistry::validate_configuration(
            std::slice::from_ref(&config),
            "urn:scheduling:test",
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let secrets = SecretResolver::new([SecretProvider::File], root.path()).unwrap();
        assert!(
            TaskGrantStatusRegistry::activate(
                std::slice::from_ref(&config),
                "urn:scheduling:test",
                &secrets
            )
            .is_err(),
            "activation still requires real signer and CA readiness"
        );
        for resource in ["", "not-an-absolute-resource"] {
            TaskGrantStatusRegistry::validate_configuration(&[], resource).unwrap();
            TaskGrantStatusRegistry::activate(&[], resource, &secrets).unwrap();
            assert!(TaskGrantStatusRegistry::validate_configuration(
                std::slice::from_ref(&config),
                resource
            )
            .is_err());
        }
        let mut duplicate = config.clone();
        duplicate.base_url = Url::new("https://other.invalid").unwrap();
        assert!(TaskGrantStatusRegistry::validate_configuration(
            &[config.clone(), duplicate],
            "urn:scheduling:test"
        )
        .is_err());
        let entries: Vec<_> = (0..33)
            .map(|index| {
                let mut entry = config.clone();
                entry.source_issuer =
                    ExternalId::new(format!("urn:casework:source:{index}")).unwrap();
                entry
            })
            .collect();
        TaskGrantStatusRegistry::validate_configuration(&entries[..32], "urn:scheduling:test")
            .unwrap();
        assert!(
            TaskGrantStatusRegistry::validate_configuration(&entries, "urn:scheduling:test")
                .is_err()
        );
        assert!(!root.path().join("missing-key").exists());
        assert!(!root.path().join("missing-ca").exists());
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
        let mut urn_authority = config.clone();
        urn_authority.source_issuer = ExternalId::new("urn:casework:source").unwrap();
        let urn_status =
            TaskGrantStatusRegistry::activate(&[urn_authority], "urn:breg:test", &secrets).unwrap();
        assert!(urn_status.contains("urn:casework:source"));
        let mut duplicate = config.clone();
        duplicate.base_url = Url::new("https://other-casework.test").unwrap();
        assert!(TaskGrantStatusRegistry::activate(
            &[config.clone(), duplicate],
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
            let Ok(base_url) = Url::new(url) else {
                let mut invalid = serde_json::to_value(&config).unwrap();
                invalid["baseUrl"] = serde_json::json!(url);
                assert!(serde_json::from_value::<TaskGrantStatusConfig>(invalid).is_err());
                continue;
            };
            invalid.base_url = base_url;
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
