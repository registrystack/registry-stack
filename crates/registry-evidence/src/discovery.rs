// SPDX-License-Identifier: Apache-2.0
//! Deterministic closed provider-publication projection for Evidence.

use std::collections::BTreeSet;

use registry_discovery_profile::{
    render_description, DiscoveryDescription, ProfileError, ServiceDescription, ServiceKind,
    ServiceRoles,
};

use crate::config::{EvidenceConfig, ResponseFormat, SubjectBindingMode};

/// Product-owned base identifier for the Evidence Version 1 service profile.
pub const EVIDENCE_PROFILE_ID: &str = "https://registrystack.org/evidence/profile/v1";

pub fn render(config: &EvidenceConfig) -> Result<Option<Vec<u8>>, ProfileError> {
    let Some(publication) = &config.publication else {
        return Ok(None);
    };
    let mut bindings = BTreeSet::new();
    for requirement in &config.requirements {
        for format in &config.response_formats {
            if let Some(capability) =
                capability_profile(requirement.subject_binding_mode(), *format)
            {
                bindings.insert((requirement.evidence_type.clone(), capability));
            }
        }
    }
    let roles = ServiceRoles {
        publisher_id: publication.publisher_id.clone(),
        operator_id: publication.operator_id.clone(),
        registry_authority_id: None,
        legal_issuer_id: Some(config.issuer.id.clone()),
        technical_provider_id: Some(config.service.provider_id.clone()),
    };
    let services = bindings
        .into_iter()
        .map(|(evidence_type, capability)| {
            ServiceDescription::new(
                publication.service_id.clone(),
                ServiceKind::Evidence,
                publication.title.clone(),
                publication.description.clone(),
                publication.endpoint_url.clone(),
                roles.clone(),
                publication.jurisdictions.clone(),
                vec![EVIDENCE_PROFILE_ID.to_owned(), capability],
                vec![evidence_type],
                Vec::new(),
                Vec::new(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    render_description(&DiscoveryDescription::new(services)?).map(Some)
}

fn capability_profile(binding: SubjectBindingMode, format: ResponseFormat) -> Option<String> {
    let tuple = match (binding, format) {
        (SubjectBindingMode::AudienceScoped, ResponseFormat::SignedJws) => {
            "audience-scoped/signed-jws"
        }
        (SubjectBindingMode::AudienceScoped, ResponseFormat::UnsignedJson) => {
            "audience-scoped/unsigned-json"
        }
        (SubjectBindingMode::AudienceScoped, ResponseFormat::SdJwtVc) => {
            "audience-scoped/sd-jwt-vc"
        }
        (SubjectBindingMode::HolderBound, ResponseFormat::SdJwtVc) => "holder-bound/sd-jwt-vc",
        (SubjectBindingMode::HolderBound, ResponseFormat::SdJwtVcBatch) => {
            "holder-bound/sd-jwt-vc-batch"
        }
        _ => return None,
    };
    Some(format!("{EVIDENCE_PROFILE_ID}/{tuple}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn config() -> EvidenceConfig {
        EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("acceptance bundle configuration parses")
    }

    #[test]
    fn provider_discovery_description_is_deterministic_and_profile_valid() {
        let config = config();
        let first = render(&config)
            .expect("description renders")
            .expect("publication is configured");
        let second = render(&config)
            .expect("description rerenders")
            .expect("publication is configured");
        assert_eq!(first, second);
        let parsed = registry_discovery_profile::parse_description(&first)
            .expect("description satisfies the shared profile");
        assert_eq!(
            parsed.services().len(),
            config.requirements.len() * config.response_formats.len()
        );
        let binding_ids = parsed
            .services()
            .iter()
            .map(ServiceDescription::binding_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(binding_ids.len(), parsed.services().len());
        for service in parsed.services() {
            assert_eq!(service.evidence_type_ids().len(), 1);
            assert_eq!(service.conforms_to().len(), 2);
            assert_eq!(service.conforms_to()[0], EVIDENCE_PROFILE_ID);
            assert!(service.conforms_to()[1].starts_with(&format!("{EVIDENCE_PROFILE_ID}/")));
        }
        let endpoint = Url::parse(parsed.services()[0].endpoint_url())
            .expect("the published endpoint is a client base URL");
        assert_eq!(
            endpoint.path(),
            "/",
            "publication must not include /v1/evidence"
        );
    }

    #[test]
    fn provider_discovery_description_never_advertises_impossible_capability_combinations() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/holder-bound/evidence.yaml"
        ))
        .expect("holder-bound acceptance configuration parses");
        let rendered = render(&config)
            .expect("description renders")
            .expect("publication is configured");
        let parsed = registry_discovery_profile::parse_description(&rendered)
            .expect("description satisfies the shared profile");
        let profiles = parsed
            .services()
            .iter()
            .flat_map(|service| service.conforms_to())
            .collect::<BTreeSet<_>>();
        assert!(profiles
            .iter()
            .any(|profile| profile.ends_with("/holder-bound/sd-jwt-vc")));
        assert!(profiles
            .iter()
            .any(|profile| profile.ends_with("/holder-bound/sd-jwt-vc-batch")));
        for impossible in [
            "/holder-bound/signed-jws",
            "/holder-bound/unsigned-json",
            "/audience-scoped/sd-jwt-vc-batch",
            "/holder-bound",
            "/signed-jws",
        ] {
            assert!(
                !profiles.iter().any(|profile| profile.ends_with(impossible)),
                "advertised impossible or independently combinable profile {impossible}"
            );
        }
        assert!(parsed.services().iter().all(|service| {
            service.evidence_type_ids().len() == 1 && service.conforms_to().len() == 2
        }));
    }

    #[test]
    fn provider_discovery_description_preserves_evidence_type_profile_correlation() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/holder-bound/evidence.yaml"
        ))
        .expect("holder-bound acceptance configuration parses");
        let audience_type = config.requirements[0].evidence_type.clone();
        config.requirements[0].subject_binding = None;
        let holder_type = config.requirements[1].evidence_type.clone();

        let rendered = render(&config)
            .expect("description renders")
            .expect("publication is configured");
        let parsed = registry_discovery_profile::parse_description(&rendered)
            .expect("description satisfies the shared profile");

        for service in parsed.services() {
            let evidence_type = &service.evidence_type_ids()[0];
            let capability_profile = &service.conforms_to()[1];
            if evidence_type == &audience_type {
                assert!(capability_profile.contains("/audience-scoped/"));
                assert!(!capability_profile.contains("/holder-bound/"));
            }
            if evidence_type == &holder_type {
                assert!(capability_profile.contains("/holder-bound/"));
                assert!(!capability_profile.contains("/audience-scoped/"));
            }
        }
        assert!(!parsed.services().iter().any(|service| {
            service.evidence_type_ids() == [audience_type.clone()]
                && service.conforms_to()[1].contains("/holder-bound/")
        }));
        assert!(!parsed.services().iter().any(|service| {
            service.evidence_type_ids() == [holder_type.clone()]
                && service.conforms_to()[1].contains("/audience-scoped/")
        }));
    }

    #[test]
    fn provider_discovery_description_excludes_private_configuration_fields() {
        let config = config();
        let rendered = render(&config)
            .expect("description renders")
            .expect("publication is configured");
        let rendered = std::str::from_utf8(&rendered).expect("description is UTF-8");
        for private in [
            "identity.invalid",
            "evidence_tags",
            "secret:file",
            "audit-hash-key",
            "source-a",
            "adapters/",
            "derivations/",
            "codelists/",
        ] {
            assert!(
                !rendered.contains(private),
                "provider-public projection leaked {private}"
            );
        }
    }

    #[test]
    fn every_maintained_acceptance_bundle_publishes_exact_valid_bytes() {
        for (config, packaged) in [
            (
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
                )
                .as_slice(),
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/adult-status/catalog.jsonld"
                )
                .as_slice(),
            ),
            (
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
                )
                .as_slice(),
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/all-definitions/catalog.jsonld"
                )
                .as_slice(),
            ),
            (
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/holder-bound/evidence.yaml"
                )
                .as_slice(),
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/holder-bound/catalog.jsonld"
                )
                .as_slice(),
            ),
            (
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/legal-parent-relationship/evidence.yaml"
                )
                .as_slice(),
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/legal-parent-relationship/catalog.jsonld"
                )
                .as_slice(),
            ),
            (
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/professional-licence/evidence.yaml"
                )
                .as_slice(),
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/professional-licence/catalog.jsonld"
                )
                .as_slice(),
            ),
            (
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/residence-region/evidence.yaml"
                )
                .as_slice(),
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/residence-region/catalog.jsonld"
                )
                .as_slice(),
            ),
            (
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/surviving-spouse-status/evidence.yaml"
                )
                .as_slice(),
                include_bytes!(
                    "../../../products/evidence/fixtures/acceptance/surviving-spouse-status/catalog.jsonld"
                )
                .as_slice(),
            ),
        ] {
            let config = EvidenceConfig::parse_yaml(config).expect("acceptance config parses");
            let rendered = render(&config)
                .expect("acceptance description renders")
                .expect("acceptance publication is configured");
            assert_eq!(rendered, packaged);
            registry_discovery_profile::parse_description(packaged)
                .expect("packaged acceptance description satisfies the shared profile");
        }
    }
}
