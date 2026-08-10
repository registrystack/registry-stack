//! The client half of the process: asking Evidence for credentials.
//!
//! This service signs nothing. It authenticates to Mint with its own private
//! key JWT, presents the resulting access token to Evidence, and hands back
//! whatever Evidence signed, unchanged. There is no credential signing key
//! here, no holder private key, and no place to put either: the only key this
//! module reads is the client assertion key, and the only thing it does with it
//! is authenticate.
//!
//! The credentials this service can offer are read from Evidence too, through
//! discovery, and derived into a [`CredentialCatalog`]. Nothing is written by
//! hand and nothing is inferred: a credential Evidence does not publish as
//! holder-bound cannot be offered.
//!
//! The resource-server half, which authorizes the adopter-facing offer
//! endpoint, is [`crate::authorizer`], and the two share no code path.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use registry_evidence_client::{
    EvidenceClientConfig, EvidenceClientError, HolderBoundRequestSpec, NonVerifyingEvidenceClient,
    PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider,
};
use registry_platform_crypto::PrivateJwk;
use tokio::sync::Mutex;
use url::Url;

use crate::{config::DeliveryConfig, metadata::CredentialCatalog};

/// How long a derived catalog is reused before discovery is read again.
///
/// This protects the authenticated discovery endpoint from public metadata and
/// offer load within one deployment generation. Evidence bundles are
/// startup-only, and discovery carries no generation identifier that could
/// safely invalidate this cache in place. A backing bundle change therefore
/// requires the coordinated process boundary documented for operators: stop
/// this adapter, restart Evidence, then start a fresh adapter whose cache is
/// necessarily empty.
const CATALOG_LIFETIME: Duration = Duration::from_secs(300);

/// Why a credential could not be obtained.
///
/// Coarse on purpose. Nothing a wallet or an adopter is told distinguishes
/// authentication from authorization at the Evidence boundary, and no variant
/// carries a selector value, a token, or a deployment message.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IssuanceError {
    #[error("the credential source cannot be reached")]
    Unavailable,
    #[error("the credential source refused the request")]
    Refused,
    #[error("the credential source has no evidence for this request")]
    NotAvailable,
    #[error("the credential source answered with something this service cannot use")]
    Malformed,
    #[error("the outbound credential client cannot be built: {0}")]
    Configuration(&'static str),
}

impl From<EvidenceClientError> for IssuanceError {
    fn from(error: EvidenceClientError) -> Self {
        match error {
            EvidenceClientError::Transport { .. } | EvidenceClientError::Token(_) => {
                Self::Unavailable
            }
            EvidenceClientError::Denied { .. } => Self::Refused,
            EvidenceClientError::NotAvailable { .. } => Self::NotAvailable,
            EvidenceClientError::Configuration { .. } | EvidenceClientError::Nonce(_) => {
                Self::Configuration("the prepared request was refused before it was sent")
            }
            EvidenceClientError::Protocol { .. } | EvidenceClientError::Verification(_) => {
                Self::Malformed
            }
            // The client's error type is non-exhaustive. A failure this mapping
            // has never seen is one it cannot describe, so it becomes the
            // category that commits to nothing about a subject and tells the
            // caller to try again later.
            _ => Self::Unavailable,
        }
    }
}

/// The seam the protocol endpoints obtain credentials through.
#[async_trait]
pub trait CredentialIssuer: Send + Sync {
    /// The credentials this deployment may offer, derived from Evidence.
    async fn catalog(&self) -> Result<Arc<CredentialCatalog>, IssuanceError>;

    /// Ask for one credential per holder key in the request, as one exchange.
    async fn issue(&self, spec: HolderBoundRequestSpec) -> Result<Vec<String>, IssuanceError>;
}

/// The Evidence-backed issuer.
#[derive(Debug)]
pub struct EvidenceIssuer {
    client: NonVerifyingEvidenceClient,
    catalog: Mutex<Option<(Arc<CredentialCatalog>, Instant)>>,
}

impl EvidenceIssuer {
    /// Build the outbound client from the deployment configuration and the
    /// client assertion key the service already holds.
    ///
    /// The key is used to build the token provider and is not retained here in
    /// any other form.
    pub fn new(config: &DeliveryConfig, client_key: &str) -> Result<Self, IssuanceError> {
        let token_endpoint = Url::parse(&config.mint.token_endpoint)
            .map_err(|_| IssuanceError::Configuration("the Mint token endpoint is not a URL"))?;
        let base_url = Url::parse(&config.evidence.base_url)
            .map_err(|_| IssuanceError::Configuration("the Evidence base URL is not a URL"))?;
        let key = PrivateJwk::parse(client_key).map_err(|_| {
            IssuanceError::Configuration("the Mint client key is not a private JWK")
        })?;
        let provider = PrivateKeyJwt::new(
            PrivateKeyJwtConfig::new(token_endpoint, config.mint.client_id.clone(), key)
                .with_audience(config.mint.client_assertion_audience().to_owned()),
        )
        .map_err(|_| IssuanceError::Configuration("the Mint client identity is unusable"))?;
        let provider: Arc<dyn TokenProvider> = Arc::new(provider);
        let client = NonVerifyingEvidenceClient::new(EvidenceClientConfig::without_verification(
            base_url, provider,
        ))
        .map_err(|_| IssuanceError::Configuration("the Evidence client is unusable"))?;
        Ok(Self {
            client,
            catalog: Mutex::new(None),
        })
    }
}

#[async_trait]
impl CredentialIssuer for EvidenceIssuer {
    async fn catalog(&self) -> Result<Arc<CredentialCatalog>, IssuanceError> {
        let mut cached = self.catalog.lock().await;
        if let Some((catalog, read_at)) = cached.as_ref() {
            if read_at.elapsed() < CATALOG_LIFETIME {
                return Ok(Arc::clone(catalog));
            }
        }
        let document = self.client.discover().await?;
        let catalog = Arc::new(CredentialCatalog::derive(&document));
        *cached = Some((Arc::clone(&catalog), Instant::now()));
        Ok(catalog)
    }

    async fn issue(&self, spec: HolderBoundRequestSpec) -> Result<Vec<String>, IssuanceError> {
        // One prepared request, one send. The batch response carries one
        // credential per holder key, in the order the keys were presented, and
        // this service reads none of them.
        let prepared = self.client.prepare_holder_bound(spec)?;
        let response = self.client.send_holder_bound_batch(&prepared).await?;
        Ok(response.into_credentials())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{config::tests::valid_config, testing::private_jwk};

    #[test]
    fn the_issuer_is_built_from_the_client_identity_and_nothing_from_the_offer_boundary() {
        let config = valid_config();
        EvidenceIssuer::new(&config, &private_jwk("delivery-client"))
            .expect("the outbound client is built");
    }

    #[test]
    fn a_client_key_that_is_not_a_private_jwk_is_a_configuration_fault() {
        let config = valid_config();
        assert!(matches!(
            EvidenceIssuer::new(&config, "{}"),
            Err(IssuanceError::Configuration(
                "the Mint client key is not a private JWK"
            ))
        ));
    }

    #[test]
    fn a_deployment_failure_is_never_reported_as_a_subject_statement() {
        // Every mapped failure is a coarse category. None of them can be read
        // as an answer about a subject, and none carries deployment text.
        assert_eq!(
            IssuanceError::from(EvidenceClientError::Denied {
                status: 403,
                code: "forbidden".to_owned(),
                operation: None,
                retry_after_seconds: None,
            }),
            IssuanceError::Refused
        );
        assert_eq!(
            IssuanceError::from(EvidenceClientError::NotAvailable { operation: None }),
            IssuanceError::NotAvailable
        );
        assert!(!IssuanceError::Refused.to_string().contains("forbidden"));
    }
}
