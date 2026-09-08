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
    pub token_ref: String,
    pub trusted_jwks_ref: String,
    #[serde(default)]
    pub revoked_key_ids: Vec<String>,
    pub ca_bundle_ref: Option<String>,
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
    let required: BTreeSet<_> = registry
        .actions()
        .actions
        .iter()
        .flat_map(|action| {
            action
                .evidence
                .iter()
                .map(|capability| capability.provider.clone())
        })
        .collect();
    if required != bindings.keys().cloned().collect() {
        return Err(Error::InvalidBinding);
    }
    if !registry.actions().actions.iter().any(|action| {
        action
            .handler
            .as_ref()
            .is_some_and(|handler| handler.abi == "registry.action-handler/v2")
    }) {
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
        let token = secrets
            .resolve(&binding.token_ref)
            .map_err(|_| Error::Secret)?;
        let token = std::str::from_utf8(token.expose_secret()).map_err(|_| Error::Secret)?;
        let token = registry_evidence_client::StaticToken::new(token.to_owned())
            .map_err(|_| Error::InvalidBinding)?;
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
            Arc::new(token),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compiler::{compile_project_with_assets, CompileProfile},
        contract::{parse_project_yaml, ModuleAssetSource},
    };

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
            profile.grants.retain(|grant| {
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
            token_ref: "secret:file/missing".into(),
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
}
