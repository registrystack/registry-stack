// SPDX-License-Identifier: Apache-2.0
//! Operator-pinned authority endpoints and the resource server's status credential.
use super::*;
use registry_platform_config::{SecretReference, SecretResolver, TaskGrantStatusConfig};
use registry_platform_httputil::client::{validate_requested_scopes, PrivateKeyJwtConfig};
use registry_platform_yaml::{ExternalId, Url};

/// One operator-pinned status authority, as a runtime's `taskGrantStatus`
/// entry states it. The shared [`TaskGrantStatusConfig`] block owns the
/// configuration grammar and its defaults and maps onto this type with
/// `From`; this type carries no protocol constant of its own.
#[derive(Clone)]
pub struct TaskGrantStatusEndpoint {
    /// The exact authority identifier, including an absolute URN issuer.
    /// It is compared rather than fetched and must be an absolute resource URI.
    pub source_issuer: ExternalId,
    /// HTTPS service base; plaintext HTTP is allowed only on loopback.
    pub base_url: Url,
    /// The status route appended to `base_url`'s path: it starts with `/` and
    /// has exactly one whole `{grantId}` segment, such as
    /// `/v1/task-grants/{grantId}/status`.
    pub status_path: String,
    pub token_endpoint: Url,
    pub client_assertion_audience: ExternalId,
    pub client_id: ExternalId,
    pub private_key_ref: SecretReference,
    /// The status service audience, which must be an absolute resource URI.
    pub status_resource: ExternalId,
    /// The one RFC 6749 scope token the status credential is requested with.
    pub status_scope: ExternalId,
    pub ca_bundle_ref: Option<SecretReference>,
}
impl fmt::Debug for TaskGrantStatusEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskGrantStatusEndpoint(<configured>)")
    }
}
impl From<&TaskGrantStatusConfig> for TaskGrantStatusEndpoint {
    fn from(config: &TaskGrantStatusConfig) -> Self {
        Self {
            source_issuer: config.source_issuer.clone(),
            base_url: config.base_url.clone(),
            status_path: config.status_path.clone(),
            token_endpoint: config.token_endpoint.clone(),
            client_assertion_audience: config.client_assertion_audience.clone(),
            client_id: config.client_id.clone(),
            private_key_ref: config.private_key_ref.clone(),
            status_resource: config.status_resource.clone(),
            status_scope: config.status_scope.clone(),
            ca_bundle_ref: config.ca_bundle_ref.clone(),
        }
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
    /// more than 32 entries, a status path or scope the client would not
    /// send, or a field the status/token clients would refuse.
    pub fn validate_configuration(
        configs: &[TaskGrantStatusEndpoint],
        resource: &str,
    ) -> Result<(), TaskGrantError> {
        if configs.len() > 32 {
            return Err(TaskGrantError::Configuration);
        }
        let mut issuers = std::collections::BTreeSet::new();
        for config in configs {
            if !registry_platform_httputil::valid_resource_uri(&config.source_issuer)
                || !registry_platform_httputil::valid_resource_uri(resource)
                || !registry_platform_httputil::valid_resource_uri(&config.status_resource)
                || validate_requested_scopes(&[config.status_scope.as_str().to_owned()]).is_err()
                || !issuers.insert(config.source_issuer.as_str())
            {
                return Err(TaskGrantError::Configuration);
            }
            StatusPath::parse(&config.status_path)?;
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
        configs: &[TaskGrantStatusEndpoint],
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
            .with_resource(config.status_resource.as_str())
            .with_scopes([config.status_scope.as_str()]);
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
                &config.status_path,
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

    fn endpoint() -> TaskGrantStatusEndpoint {
        TaskGrantStatusEndpoint {
            source_issuer: ExternalId::new("https://authority.test").unwrap(),
            base_url: Url::new("https://authority.test").unwrap(),
            status_path: "/v1/task-grants/{grantId}/status".into(),
            token_endpoint: Url::new("https://identity.test/oauth2/token").unwrap(),
            client_assertion_audience: ExternalId::new("https://identity.test").unwrap(),
            client_id: ExternalId::new("status-client").unwrap(),
            private_key_ref: SecretReference::parse("secret:file/status-key").unwrap(),
            status_resource: ExternalId::new("urn:authority:test").unwrap(),
            status_scope: ExternalId::new("grants:status").unwrap(),
            ca_bundle_ref: None,
        }
    }

    #[test]
    fn status_path_names_one_grant_segment_and_the_scope_is_one_token() {
        for path in [
            "/{grantId}",
            "/v1/task-grants/{grantId}/status",
            "/api/v2/grants/{grantId}",
            "/a.b_c~d-e/{grantId}",
        ] {
            let mut config = endpoint();
            config.status_path = path.into();
            TaskGrantStatusRegistry::validate_configuration(&[config], "urn:resource:test")
                .unwrap_or_else(|_| panic!("{path}"));
        }
        for path in [
            "",
            "/",
            "{grantId}",
            "v1/{grantId}",
            "/v1/status",
            "/{grantId}/{grantId}",
            "/v1//{grantId}",
            "/v1/{grantId}/",
            "/v1/../{grantId}",
            "/./{grantId}",
            "/v1/{grantId}?view=full",
            "/v1/{grantId}#status",
            "/v1/%2e%2e/{grantId}",
            "/v1/grant-{grantId}",
            "/v1/{grantid}",
            "/v1/{id}",
            "/v 1/{grantId}",
        ] {
            let mut config = endpoint();
            config.status_path = path.into();
            assert!(
                TaskGrantStatusRegistry::validate_configuration(&[config], "urn:resource:test")
                    .is_err(),
                "{path:?}"
            );
        }
        let mut long = endpoint();
        long.status_path = format!("/{}/{{grantId}}", "a".repeat(256));
        assert!(
            TaskGrantStatusRegistry::validate_configuration(&[long], "urn:resource:test").is_err()
        );
        for scope in ["grants:status other", "grants\\status", "grants\"status"] {
            let mut config = endpoint();
            config.status_scope = ExternalId::new(scope).unwrap();
            assert!(
                TaskGrantStatusRegistry::validate_configuration(&[config], "urn:resource:test")
                    .is_err(),
                "{scope}"
            );
        }
    }

    #[test]
    fn status_structure_is_checked_without_resolving_credential_material() {
        let mut config = endpoint();
        config.source_issuer = ExternalId::new("urn:authority:source").unwrap();
        config.base_url = Url::new("https://unreachable.invalid/path").unwrap();
        config.token_endpoint = Url::new("http://127.0.0.1:1/token").unwrap();
        config.client_assertion_audience = ExternalId::new("urn:identity:test").unwrap();
        config.private_key_ref = SecretReference::parse("secret:file/missing-key").unwrap();
        config.ca_bundle_ref = Some(SecretReference::parse("secret:file/missing-ca").unwrap());
        TaskGrantStatusRegistry::validate_configuration(
            std::slice::from_ref(&config),
            "urn:resource:test",
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let secrets = SecretResolver::new([SecretProvider::File], root.path()).unwrap();
        assert!(
            TaskGrantStatusRegistry::activate(
                std::slice::from_ref(&config),
                "urn:resource:test",
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
            "urn:resource:test"
        )
        .is_err());
        let entries: Vec<_> = (0..33)
            .map(|index| {
                let mut entry = config.clone();
                entry.source_issuer =
                    ExternalId::new(format!("urn:authority:source:{index}")).unwrap();
                entry
            })
            .collect();
        TaskGrantStatusRegistry::validate_configuration(&entries[..32], "urn:resource:test")
            .unwrap();
        assert!(
            TaskGrantStatusRegistry::validate_configuration(&entries, "urn:resource:test").is_err()
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
        let config = endpoint();
        let status = TaskGrantStatusRegistry::activate(
            std::slice::from_ref(&config),
            "urn:resource:test",
            &secrets,
        )
        .unwrap();
        assert!(status.contains(&config.source_issuer));
        assert!(!status.contains("https://other.test"));
        let mut urn_authority = config.clone();
        urn_authority.source_issuer = ExternalId::new("urn:authority:source").unwrap();
        let urn_status =
            TaskGrantStatusRegistry::activate(&[urn_authority], "urn:resource:test", &secrets)
                .unwrap();
        assert!(urn_status.contains("urn:authority:source"));
        let mut duplicate = config.clone();
        duplicate.base_url = Url::new("https://other-authority.test").unwrap();
        assert!(TaskGrantStatusRegistry::activate(
            &[config.clone(), duplicate],
            "urn:resource:test",
            &secrets
        )
        .is_err());
        assert!(Url::new("https://user@authority.test").is_err());
        for url in ["http://authority.test", "https://authority.test/#fragment"] {
            let mut invalid = config.clone();
            invalid.base_url = Url::new(url).unwrap();
            assert!(
                TaskGrantStatusRegistry::activate(&[invalid], "urn:resource:test", &secrets)
                    .is_err(),
                "{url}"
            );
        }
        let mut invalid = config;
        invalid.status_resource = ExternalId::new("not-an-absolute-resource").unwrap();
        assert!(
            TaskGrantStatusRegistry::activate(&[invalid], "urn:resource:test", &secrets).is_err()
        );
    }
}
