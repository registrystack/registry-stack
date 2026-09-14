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
            token_ref: "secret:file/missing".into(),
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
            token_ref: "secret:file/token".into(),
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
