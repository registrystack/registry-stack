// SPDX-License-Identifier: Apache-2.0
//! Deployment-owned, explicitly pinned Evidence provider bindings.
use crate::{
    action_evidence::ActionEvidenceEvaluator,
    action_evidence_client::{EvidenceActionClient, EvidenceProviderBinding},
    model::CompiledRegistry,
};
use registry_platform_config::SecretResolver;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceProviderConfig {
    pub base_url: String,
    pub trust_binding_id: String,
    /// Compatibility path for a pre-issued token. Long-running providers
    /// should configure `privateKeyJwt` so expiry triggers a fresh exchange.
    pub token_ref: Option<String>,
    pub private_key_jwt: Option<EvidencePrivateKeyJwtConfig>,
    pub trusted_jwks_ref: String,
    #[serde(default)]
    pub revoked_key_ids: Vec<String>,
    pub ca_bundle_ref: Option<String>,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidencePrivateKeyJwtConfig {
    pub token_endpoint: String,
    pub client_id: String,
    pub private_key_ref: String,
    pub assertion_audience: Option<String>,
    pub resource: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for EvidencePrivateKeyJwtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EvidencePrivateKeyJwtConfig([protected])")
    }
}
impl std::fmt::Debug for EvidenceProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EvidenceProviderConfig([protected])")
    }
}

pub fn activate(
    registry: &CompiledRegistry,
    bindings: &BTreeMap<String, EvidenceProviderConfig>,
    secrets: &SecretResolver,
) -> Result<Option<Arc<ActionEvidenceEvaluator>>, crate::runtime_config::RuntimeConfigError> {
    use crate::runtime_config::RuntimeConfigError as Error;
    let required = required_provider_ids(registry);
    let has_required_evidence = !required.is_empty();
    if required != bindings.keys().cloned().collect() {
        return Err(Error::InvalidBinding);
    }
    let immediate_v2 = registry.actions().actions.iter().any(|action| {
        action
            .handler
            .as_ref()
            .is_some_and(|handler| handler.abi == "registry.action-handler/v2")
    });
    if !immediate_v2 && !has_required_evidence {
        return Ok(None);
    }
    let mut activated = BTreeMap::new();
    for (id, binding) in bindings {
        if binding.trust_binding_id.is_empty()
            || binding.trust_binding_id.len() > 128
            || binding.revoked_key_ids.len() > 128
        {
            return Err(Error::InvalidBinding);
        }
        let token_provider = token_provider(binding, secrets)?;
        let keys = secrets
            .resolve(&binding.trusted_jwks_ref)
            .map_err(|_| Error::Secret)?;
        let jwks = registry_platform_crypto::parse_json_strict(keys.expose_secret())
            .map_err(|_| Error::InvalidBinding)?;
        let jwks = serde_json::from_value(jwks).map_err(|_| Error::InvalidBinding)?;
        let mut config = registry_evidence_client::EvidenceClientConfig::new(
            binding
                .base_url
                .parse()
                .map_err(|_| Error::InvalidBinding)?,
            token_provider,
            jwks,
            binding.revoked_key_ids.clone(),
        );
        if let Some(reference) = &binding.ca_bundle_ref {
            let ca = secrets.resolve(reference).map_err(|_| Error::Secret)?;
            config = config.with_trusted_root_certificates(ca.expose_secret().to_vec());
        }
        let provider = EvidenceProviderBinding::new(binding.trust_binding_id.clone(), config)
            .map_err(|_| Error::InvalidBinding)?;
        activated.insert(id.clone(), provider);
    }
    Ok(Some(Arc::new(ActionEvidenceEvaluator::new(Arc::new(
        EvidenceActionClient::new(activated),
    )))))
}

fn required_provider_ids(registry: &CompiledRegistry) -> BTreeSet<String> {
    let immediate = registry.actions().actions.iter().flat_map(|action| {
        action
            .evidence
            .iter()
            .map(|capability| capability.provider.clone())
    });
    let reviewed_requests = registry
        .entities()
        .values()
        .filter_map(|entity| entity.change_request.as_ref())
        .flat_map(|request| request.application.preconditions.evidence.iter())
        .map(|evidence| evidence.capability.provider.clone());
    immediate.chain(reviewed_requests).collect()
}

fn token_provider(
    binding: &EvidenceProviderConfig,
    secrets: &SecretResolver,
) -> Result<
    Arc<dyn registry_evidence_client::TokenProvider>,
    crate::runtime_config::RuntimeConfigError,
> {
    use crate::runtime_config::RuntimeConfigError as Error;
    if binding.token_ref.is_some() == binding.private_key_jwt.is_some() {
        return Err(Error::InvalidBinding);
    }
    let provider: Arc<dyn registry_evidence_client::TokenProvider> = if let Some(reference) =
        &binding.token_ref
    {
        let token = secrets.resolve(reference).map_err(|_| Error::Secret)?;
        let token = std::str::from_utf8(token.expose_secret()).map_err(|_| Error::Secret)?;
        Arc::new(
            registry_evidence_client::StaticToken::new(token.to_owned())
                .map_err(|_| Error::InvalidBinding)?,
        )
    } else {
        let source = binding
            .private_key_jwt
            .as_ref()
            .ok_or(Error::InvalidBinding)?;
        let endpoint = source
            .token_endpoint
            .parse()
            .map_err(|_| Error::InvalidBinding)?;
        let key = secrets
            .resolve(&source.private_key_ref)
            .map_err(|_| Error::Secret)?;
        let key = std::str::from_utf8(key.expose_secret()).map_err(|_| Error::Secret)?;
        let key =
            registry_platform_crypto::PrivateJwk::parse(key).map_err(|_| Error::InvalidBinding)?;
        let mut token_config = registry_evidence_client::PrivateKeyJwtConfig::new(
            endpoint,
            source.client_id.clone(),
            key,
        );
        if let Some(audience) = &source.assertion_audience {
            token_config = token_config.with_audience(audience.clone());
        }
        if let Some(resource) = &source.resource {
            token_config = token_config.with_resource(resource.clone());
        }
        if !source.scopes.is_empty() {
            token_config = token_config.with_scopes(source.scopes.clone());
        }
        if let Some(reference) = &binding.ca_bundle_ref {
            let ca = secrets.resolve(reference).map_err(|_| Error::Secret)?;
            token_config = token_config.with_trusted_root_certificates(ca.expose_secret().to_vec());
        }
        Arc::new(
            registry_evidence_client::PrivateKeyJwt::new(token_config)
                .map_err(|_| Error::InvalidBinding)?,
        )
    };
    Ok(provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compiler::{compile_project_with_assets, CompileProfile},
        contract::{parse_project_yaml, ModuleAssetSource},
    };
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn zero_capability_v2_activates_without_secrets_and_extra_bindings_fail_closed() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance/farmer-landholding-evidence");
        let mut project =
            parse_project_yaml(&std::fs::read(root.join("registry.yaml")).unwrap()).unwrap();
        project
            .actions
            .retain(|action| action.id == "check-procedure");
        assert_eq!(project.actions.len(), 1);
        project.actions[0].evidence.clear();
        project.evidence_providers.clear();
        for profile in &mut project.access_profiles {
            profile.permissions.retain(|grant| {
                grant
                    .action
                    .as_ref()
                    .is_none_or(|id| project.actions.iter().any(|action| &action.id == id))
            });
        }
        let assets: Vec<_> = project
            .actions
            .iter()
            .filter_map(|action| action.handler.as_ref())
            .map(|handler| ModuleAssetSource {
                module: None,
                path: handler.script.clone(),
                bytes: std::fs::read(root.join(&handler.script)).unwrap(),
            })
            .collect();
        let compiled =
            compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring).unwrap();
        let secrets = SecretResolver::new(
            [registry_platform_config::SecretProvider::File],
            "/private/tmp",
        )
        .unwrap();
        assert!(activate(&compiled, &BTreeMap::new(), &secrets)
            .unwrap()
            .is_some());
        let binding = EvidenceProviderConfig {
            base_url: "https://invalid.example".into(),
            trust_binding_id: "unused".into(),
            token_ref: Some("secret:file/missing".into()),
            private_key_jwt: None,
            trusted_jwks_ref: "secret:file/missing".into(),
            revoked_key_ids: vec![],
            ca_bundle_ref: None,
        };
        assert!(matches!(
            activate(
                &compiled,
                &BTreeMap::from([("unused".into(), binding)]),
                &secrets
            ),
            Err(crate::runtime_config::RuntimeConfigError::InvalidBinding)
        ));
    }

    #[test]
    fn credential_binding_selects_exactly_one_provider_without_a_token_request() {
        let directory = tempfile::tempdir().unwrap();
        let write_secret = |name: &str, value: &str| {
            let path = directory.path().join(name);
            std::fs::write(&path, value).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        write_secret("token", "synthetic-token");
        // Published synthetic platform test key. No issuer or Evidence service
        // is running: constructing either provider must remain offline.
        let mut key = serde_json::json!({
            "kty":"EC", "crv":"P-256", "alg":"ES256",
            "d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4",
            "x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
            "y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"
        });
        let parsed = registry_platform_crypto::PrivateJwk::parse(&key.to_string()).unwrap();
        key["kid"] = serde_json::json!(parsed.public().jkt().unwrap());
        write_secret("key", &key.to_string());
        let secrets = SecretResolver::new(
            [registry_platform_config::SecretProvider::File],
            directory.path(),
        )
        .unwrap();
        let mut binding = EvidenceProviderConfig {
            base_url: "https://evidence.example.org".into(),
            trust_binding_id: "reviewed".into(),
            token_ref: Some("secret:file/token".into()),
            private_key_jwt: None,
            trusted_jwks_ref: "secret:file/unused".into(),
            revoked_key_ids: vec![],
            ca_bundle_ref: None,
        };
        assert!(token_provider(&binding, &secrets).is_ok());
        binding.private_key_jwt = Some(EvidencePrivateKeyJwtConfig {
            token_endpoint: "https://issuer.example.org/token".into(),
            client_id: "action-client".into(),
            private_key_ref: "secret:file/key".into(),
            assertion_audience: Some("https://issuer.example.org".into()),
            resource: Some("https://evidence.example.org".into()),
            scopes: vec!["evidence.read".into()],
        });
        assert!(matches!(
            token_provider(&binding, &secrets),
            Err(crate::runtime_config::RuntimeConfigError::InvalidBinding)
        ));
        binding.token_ref = None;
        assert!(token_provider(&binding, &secrets).is_ok());
        binding.private_key_jwt.as_mut().unwrap().resource = Some("not-an-uri".into());
        assert!(matches!(
            token_provider(&binding, &secrets),
            Err(crate::runtime_config::RuntimeConfigError::InvalidBinding)
        ));
        binding.private_key_jwt = None;
        assert!(matches!(
            token_provider(&binding, &secrets),
            Err(crate::runtime_config::RuntimeConfigError::InvalidBinding)
        ));
    }

    #[test]
    fn reviewed_request_guards_require_activation_even_without_an_immediate_action() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance/farmer-landholding-evidence");
        let project =
            parse_project_yaml(&std::fs::read(root.join("registry.yaml")).unwrap()).unwrap();
        let mut assets: Vec<_> = project
            .actions
            .iter()
            .filter_map(|action| action.handler.as_ref())
            .map(|handler| ModuleAssetSource {
                module: None,
                path: handler.script.clone(),
                bytes: std::fs::read(root.join(&handler.script)).unwrap(),
            })
            .collect();
        assets.push(ModuleAssetSource {
            module: None,
            path: "evidence/farmer-contracts.json".into(),
            bytes: std::fs::read(root.join("evidence/farmer-contracts.json")).unwrap(),
        });
        let compiled =
            compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring).unwrap();
        let capability = compiled
            .actions()
            .actions
            .iter()
            .flat_map(|action| action.evidence.iter())
            .next()
            .expect("the fixture has governed Evidence")
            .clone();
        let mut document = serde_json::to_value(compiled).unwrap();
        for action in document["actionInventory"]["actions"]
            .as_array_mut()
            .unwrap()
        {
            action["evidence"] = serde_json::json!([]);
            action.as_object_mut().unwrap().remove("handler");
        }
        let request = document["entities"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        request["changeRequest"] = serde_json::json!({
            "requestEntityId": "synthetic-request",
            "contractFingerprint": format!("sha256:{}", "0".repeat(64)),
            "retentionMode": "retain",
            "reviewMode": "stages",
            "application": {
                "mode": "manual", "allowedDispositions": [], "queueReasons": {},
                "preconditions": {"evidence": [{"capability": capability, "subjects": {}, "requires": []}]}
            },
            "effects": [], "stages": [], "actions": [], "reviewPermissions": [],
            "applyPermissions": [], "presencePermissions": [], "targetEntities": [],
            "maximumTargets": 1, "maximumFieldMutations": 1, "maximumSnapshotBytes": 1
        });
        let compiled: CompiledRegistry = serde_json::from_value(document).unwrap();
        assert!(compiled
            .actions()
            .actions
            .iter()
            .all(|action| action.handler.is_none()));
        assert_eq!(
            required_provider_ids(&compiled),
            BTreeSet::from(["farmer-registry".to_owned()])
        );
        let secrets = SecretResolver::new(
            [registry_platform_config::SecretProvider::File],
            "/private/tmp",
        )
        .unwrap();
        assert!(matches!(
            activate(&compiled, &BTreeMap::new(), &secrets),
            Err(crate::runtime_config::RuntimeConfigError::InvalidBinding)
        ));
        let binding = EvidenceProviderConfig {
            base_url: "https://evidence.example".into(),
            trust_binding_id: "reviewed".into(),
            token_ref: Some("secret:file/missing".into()),
            private_key_jwt: None,
            trusted_jwks_ref: "secret:file/missing".into(),
            revoked_key_ids: vec![],
            ca_bundle_ref: None,
        };
        assert!(matches!(
            activate(
                &compiled,
                &BTreeMap::from([("farmer-registry".into(), binding.clone())]),
                &secrets
            ),
            Err(crate::runtime_config::RuntimeConfigError::Secret)
        ));
        let directory = tempfile::tempdir().unwrap();
        for (name, contents) in [
            ("token", "synthetic-token".to_owned()),
            (
                "jwks",
                std::fs::read_to_string(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../registry-evidence-client-node/tests/fixtures/jwks.json"),
                )
                .unwrap(),
            ),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, contents).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let secrets = SecretResolver::new(
            [registry_platform_config::SecretProvider::File],
            directory.path(),
        )
        .unwrap();
        let binding = EvidenceProviderConfig {
            token_ref: Some("secret:file/token".into()),
            trusted_jwks_ref: "secret:file/jwks".into(),
            ..binding
        };
        assert!(activate(
            &compiled,
            &BTreeMap::from([("farmer-registry".into(), binding)]),
            &secrets
        )
        .unwrap()
        .is_some());
    }
}
