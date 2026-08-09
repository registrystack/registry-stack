//! The credential catalog, derived from what Evidence publishes.
//!
//! Every credential this service offers is one Evidence already agreed to issue
//! holder-bound. The catalog is built from the Evidence definitions document
//! and from nothing else: there is no configuration member to write an entry
//! into, and no member of this module accepts a hand-written one. A deployment
//! therefore cannot publish a credential description Evidence would refuse.
//!
//! Two rules narrow the document to what a wallet can actually be handed:
//!
//! - a definition whose subject bindings are audience-scoped is dropped. Such a
//!   credential names a relying party rather than a holder key, and offering it
//!   to a wallet would launder an audience-scoped assertion into one;
//! - a requirement carried by more than one definition is dropped, because the
//!   protocol identifies a credential by one identifier and this service will
//!   not choose between two shapes of it on a wallet's behalf.

use std::collections::BTreeMap;

use registry_evidence_client::{
    AssuranceProfile, DefinitionSubject, EvidenceDefinition, EvidenceDefinitionsDocument,
    ExpectedOutputDocument, SubjectBindingMode, MAXIMUM_EXPECTED_OUTPUTS, MAXIMUM_HOLDER_KEYS,
};
use serde_json::{json, Map, Value};

use crate::{config::DeliveryConfig, CREDENTIAL_FORMAT};

/// The proof signing algorithm a wallet must use, and the algorithm Evidence
/// signs a holder-bound credential with. Both are fixed by the frozen profile.
const ES256: &str = "ES256";

/// The two binding methods a holder may present. Both are self-contained in
/// the proof header; the `did:jwk` form is decoded locally and never resolved
/// over the network.
const JWK_BINDING: &str = "jwk";
const DID_JWK_BINDING: &str = "did:jwk";

/// The widest collection a requested concept may answer with.
///
/// A delivery front end holds no relying procedure, so it has no narrower
/// bound to state. The client refuses anything wider.
const MAXIMUM_LIST_ITEMS: usize = 64;

/// One credential this service can offer, as Evidence described it.
#[derive(Debug, Clone)]
pub struct CredentialConfiguration {
    /// The `credential_configuration_id` a wallet names, which is the Evidence
    /// requirement identifier and never a value of this service's own.
    pub id: String,
    /// The SD-JWT VC type, as Evidence publishes it.
    pub vct: String,
    pub purpose: String,
    pub configuration_revision: String,
    pub subjects: Vec<DefinitionSubject>,
    pub expected_outputs: Vec<ExpectedOutputDocument>,
}

/// Everything derived from one Evidence definitions document.
#[derive(Debug, Clone)]
pub struct CredentialCatalog {
    pub issued_by: String,
    pub provided_by: String,
    pub assurance_profile: AssuranceProfile,
    /// Effective holder-key ceiling reported by the backing Evidence
    /// deployment, bounded again by the requester's compile-time ceiling.
    maximum_holder_keys: usize,
    entries: BTreeMap<String, CredentialConfiguration>,
}

impl CredentialCatalog {
    /// Derive the catalog from what Evidence published.
    #[must_use]
    pub fn derive(document: &EvidenceDefinitionsDocument) -> Self {
        let mut entries: BTreeMap<String, CredentialConfiguration> = BTreeMap::new();
        let mut ambiguous: Vec<String> = Vec::new();
        for definition in &document.definitions {
            if definition.subject_binding_mode != Some(SubjectBindingMode::HolderBound) {
                continue;
            }
            let Some(configuration) = configuration_for(definition) else {
                continue;
            };
            if entries
                .insert(configuration.id.clone(), configuration)
                .is_some()
            {
                ambiguous.push(definition.requirement.clone());
            }
        }
        for requirement in ambiguous {
            entries.remove(&requirement);
        }
        let maximum_holder_keys =
            usize::from(document.holder_bound_batch_max_size).min(MAXIMUM_HOLDER_KEYS);
        // Zero is outside the definitions contract. Treat such a document as
        // incapable of serving holder-bound credentials instead of silently
        // widening it to one.
        if maximum_holder_keys == 0 {
            entries.clear();
        }
        Self {
            issued_by: document.issued_by.clone(),
            provided_by: document.provided_by.clone(),
            assurance_profile: document.assurance_profile,
            maximum_holder_keys,
            entries,
        }
    }

    /// The configuration a wallet named, when this service publishes one.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&CredentialConfiguration> {
        self.entries.get(id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Effective batch ceiling shared by metadata, offers, and credential
    /// validation. It is derived once from authenticated Evidence discovery.
    #[must_use]
    pub fn maximum_holder_keys(&self) -> usize {
        self.maximum_holder_keys
    }

    /// The published issuer metadata document.
    ///
    /// `credential_configurations_supported` is this catalog, rendered. Nothing
    /// else in the process can add an entry to it.
    #[must_use]
    pub fn issuer_metadata(&self, config: &DeliveryConfig) -> Value {
        // The configured identifier, verbatim. It is held in its published
        // spelling by the configuration that loaded it, so publishing anything
        // derived from it here would be a second opinion on one identifier.
        let issuer = &config.credential_issuer;
        let mut supported = Map::new();
        for (id, configuration) in &self.entries {
            supported.insert(
                id.clone(),
                json!({
                    "format": CREDENTIAL_FORMAT,
                    "vct": configuration.vct,
                    "cryptographic_binding_methods_supported": [JWK_BINDING, DID_JWK_BINDING],
                    "credential_signing_alg_values_supported": [ES256],
                    // An object keyed by proof type, not a list of type names.
                    "proof_types_supported": {
                        "jwt": {"proof_signing_alg_values_supported": [ES256]},
                    },
                }),
            );
        }
        let mut metadata = json!({
            "credential_issuer": issuer,
            "credential_endpoint": format!("{issuer}{}", crate::service::CREDENTIAL_PATH),
            "nonce_endpoint": format!("{issuer}{}", crate::service::NONCE_PATH),
            "authorization_servers": [issuer],
            "credential_configurations_supported": Value::Object(supported),
        });
        if self.maximum_holder_keys() > 0 {
            // The ceiling comes from authenticated Evidence discovery and is
            // pinned into each offer. It can never exceed either the backing
            // deployment's effective bundle limit or the client request limit.
            metadata["batch_credential_issuance"] =
                json!({"batch_size": self.maximum_holder_keys()});
        }
        metadata
    }
}

/// The authorization server metadata for this service's own token endpoint.
///
/// This service is the authorization server for the only grant it supports, so
/// a wallet that read the issuer metadata can find the token endpoint the same
/// way it would find any other: RFC 8414 discovery at the issuer origin.
#[must_use]
pub fn authorization_server_metadata(config: &DeliveryConfig) -> Value {
    let issuer = &config.credential_issuer;
    json!({
        "issuer": issuer,
        "token_endpoint": format!("{issuer}{}", crate::service::TOKEN_PATH),
        "grant_types_supported": [crate::PRE_AUTHORIZED_CODE_GRANT_TYPE],
        "response_types_supported": [],
        "token_endpoint_auth_methods_supported": ["none"],
        // A pre-authorized code is redeemed by whoever holds it, with no client
        // registration and no client authentication. Stating so is what tells a
        // wallet it may redeem one without an identity of its own, and it
        // matches the auth method published above.
        "pre-authorized_grant_anonymous_access_supported": true,
    })
}

/// Translate one holder-bound definition, or decline it.
///
/// A definition whose concepts the Evidence client would refuse to request is
/// declined rather than published: metadata describing a credential this
/// service could never ask for is metadata a wallet would be misled by.
fn configuration_for(definition: &EvidenceDefinition) -> Option<CredentialConfiguration> {
    let mut expected_outputs = Vec::with_capacity(definition.concepts.len());
    for concept in &definition.concepts {
        let expected = if concept.form.is_list() {
            concept.list_expected_output(1, MAXIMUM_LIST_ITEMS)
        } else {
            concept.scalar_expected_output()
        }?;
        expected_outputs.push(expected);
    }
    if expected_outputs.is_empty() || expected_outputs.len() > MAXIMUM_EXPECTED_OUTPUTS {
        return None;
    }
    if definition.subjects.is_empty() {
        return None;
    }
    Some(CredentialConfiguration {
        id: definition.requirement.clone(),
        vct: definition.evidence_type.clone(),
        purpose: definition.purpose.clone(),
        configuration_revision: definition.configuration_revision.clone(),
        subjects: definition.subjects.clone(),
        expected_outputs,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use crate::config::DeliveryConfig;

    pub(crate) const DEFINITIONS: &str = r#"{
      "schema": "registry.evidence-definitions/v1",
      "assuranceProfile": "local",
      "issuedBy": "https://registry.example.org",
      "providedBy": "https://provider.example.org",
      "holderBoundBatchMaxSize": 4,
      "definitions": [
        {
          "requirement": "urn:example:requirement:holder-bound",
          "configurationRevision": "rev-1",
          "kind": "criterion",
          "subjectBindingMode": "holder-bound",
          "evidenceType": "urn:example:evidence-type:holder-bound",
          "purpose": "urn:example:purpose:demonstration",
          "referenceFrameworks": [],
          "subjects": [
            {
              "role": "primary",
              "cardinality": "one",
              "selector": {
                "profile": "urn:example:selector:identifier",
                "valueOrigin": "request",
                "fields": [
                  {"type": "string", "name": "identifier", "minimumBytes": 1, "maximumBytes": 64}
                ]
              }
            }
          ],
          "concepts": [{"id": "urn:example:concept:outcome", "form": "boolean"}]
        },
        {
          "requirement": "urn:example:requirement:audience-scoped",
          "configurationRevision": "rev-1",
          "kind": "criterion",
          "evidenceType": "urn:example:evidence-type:audience-scoped",
          "purpose": "urn:example:purpose:demonstration",
          "referenceFrameworks": [],
          "subjects": [
            {
              "role": "primary",
              "cardinality": "one",
              "selector": {
                "profile": "urn:example:selector:identifier",
                "valueOrigin": "request",
                "fields": [
                  {"type": "string", "name": "identifier", "minimumBytes": 1, "maximumBytes": 64}
                ]
              }
            }
          ],
          "concepts": [{"id": "urn:example:concept:outcome", "form": "boolean"}]
        }
      ]
    }"#;

    pub(crate) fn document() -> EvidenceDefinitionsDocument {
        serde_json::from_str(DEFINITIONS).expect("the definitions document parses")
    }

    fn catalog() -> CredentialCatalog {
        CredentialCatalog::derive(&document())
    }

    #[test]
    fn every_published_configuration_is_derived_from_the_evidence_bundle() {
        let catalog = catalog();
        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog.maximum_holder_keys, 4);
        let entry = catalog
            .get("urn:example:requirement:holder-bound")
            .expect("the holder-bound requirement is published");
        assert_eq!(entry.vct, "urn:example:evidence-type:holder-bound");
        assert_eq!(entry.purpose, "urn:example:purpose:demonstration");
        assert_eq!(entry.configuration_revision, "rev-1");
        assert_eq!(entry.expected_outputs.len(), 1);
        assert_eq!(catalog.issued_by, "https://registry.example.org");
        assert_eq!(catalog.provided_by, "https://provider.example.org");
    }

    #[test]
    fn an_audience_scoped_requirement_is_never_published_to_a_wallet() {
        assert!(catalog()
            .get("urn:example:requirement:audience-scoped")
            .is_none());
    }

    #[test]
    fn a_requirement_carried_by_two_definitions_is_dropped_rather_than_chosen_between() {
        let mut document = document();
        let mut second = document.definitions[0].clone();
        second.purpose = "urn:example:purpose:other".to_owned();
        document.definitions.push(second);

        let catalog = CredentialCatalog::derive(&document);
        assert!(
            catalog.is_empty(),
            "an ambiguous requirement must be dropped"
        );
    }

    #[test]
    fn a_definition_with_no_concept_is_declined_rather_than_described() {
        let mut document = document();
        document.definitions[0].concepts.clear();
        assert!(CredentialCatalog::derive(&document).is_empty());
    }

    #[test]
    fn the_published_metadata_states_the_frozen_profile() {
        let config = crate::config::tests::valid_config();
        let metadata = catalog().issuer_metadata(&config);

        assert_eq!(
            metadata["credential_issuer"],
            json!("https://wallet.example.org")
        );
        assert_eq!(
            metadata["credential_endpoint"],
            json!("https://wallet.example.org/credential")
        );
        assert_eq!(
            metadata["nonce_endpoint"],
            json!("https://wallet.example.org/nonce")
        );
        let entry = &metadata["credential_configurations_supported"]
            ["urn:example:requirement:holder-bound"];
        assert_eq!(entry["format"], json!("dc+sd-jwt"));
        assert_eq!(
            entry["cryptographic_binding_methods_supported"],
            json!(["jwk", "did:jwk"])
        );
        assert_eq!(
            entry["credential_signing_alg_values_supported"],
            json!(["ES256"])
        );
        // An object keyed by proof type, never an array of type names.
        assert!(entry["proof_types_supported"].is_object());
        assert_eq!(
            entry["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"],
            json!(["ES256"])
        );
    }

    /// The published batch ceiling is the effective backing Evidence ceiling,
    /// bounded by the client ceiling the credential endpoint also enforces.
    ///
    #[test]
    fn the_published_batch_size_is_the_ceiling_the_service_enforces() {
        let config = crate::config::tests::valid_config();
        let metadata = catalog().issuer_metadata(&config);

        assert_eq!(
            metadata["batch_credential_issuance"]["batch_size"],
            json!(4)
        );

        let mut narrow = document();
        narrow.holder_bound_batch_max_size = 2;
        assert_eq!(
            CredentialCatalog::derive(&narrow).issuer_metadata(&config)
                ["batch_credential_issuance"]["batch_size"],
            json!(2)
        );

        let mut wider = document();
        wider.holder_bound_batch_max_size = u16::MAX;
        assert_eq!(
            CredentialCatalog::derive(&wider).issuer_metadata(&config)["batch_credential_issuance"]
                ["batch_size"],
            json!(MAXIMUM_HOLDER_KEYS)
        );
    }

    #[test]
    fn metadata_advertises_no_capability_outside_the_frozen_profile() {
        let config = crate::config::tests::valid_config();
        let issuer = catalog().issuer_metadata(&config);
        let authorization = authorization_server_metadata(&config);
        assert_eq!(
            issuer
                .as_object()
                .expect("issuer metadata")
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            [
                "authorization_servers",
                "batch_credential_issuance",
                "credential_configurations_supported",
                "credential_endpoint",
                "credential_issuer",
                "nonce_endpoint",
            ]
        );
        assert_eq!(
            authorization
                .as_object()
                .expect("authorization metadata")
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            [
                "grant_types_supported",
                "issuer",
                "pre-authorized_grant_anonymous_access_supported",
                "response_types_supported",
                "token_endpoint",
                "token_endpoint_auth_methods_supported",
            ]
        );
        let rendered = format!("{issuer}{authorization}");
        for unsupported in [
            "authorization_endpoint",
            "pushed_authorization_request_endpoint",
            "dpop_signing_alg_values_supported",
            "notification_endpoint",
            "deferred_credential_endpoint",
            "vc+sd-jwt",
        ] {
            assert!(!rendered.contains(unsupported), "advertised {unsupported}");
        }
    }

    #[test]
    fn the_authorization_server_metadata_states_only_the_pre_authorized_grant() {
        let config: DeliveryConfig = crate::config::tests::valid_config();
        let metadata = authorization_server_metadata(&config);
        assert_eq!(metadata["issuer"], json!("https://wallet.example.org"));
        assert_eq!(
            metadata["token_endpoint"],
            json!("https://wallet.example.org/token")
        );
        assert_eq!(
            metadata["grant_types_supported"],
            json!(["urn:ietf:params:oauth:grant-type:pre-authorized_code"])
        );
    }

    /// A wallet with no client registration must be told it may redeem a
    /// pre-authorized code anyway. The key is spelled the way OpenID4VCI spells
    /// it, with a hyphen inside `pre-authorized` and underscores elsewhere, so
    /// it is asserted verbatim rather than through a helper that could
    /// normalize it.
    #[test]
    fn the_authorization_server_metadata_states_anonymous_pre_authorized_access() {
        let config: DeliveryConfig = crate::config::tests::valid_config();
        let metadata = authorization_server_metadata(&config);

        assert_eq!(
            metadata["pre-authorized_grant_anonymous_access_supported"],
            json!(true)
        );
        assert_eq!(
            metadata["token_endpoint_auth_methods_supported"],
            json!(["none"])
        );
    }
}
