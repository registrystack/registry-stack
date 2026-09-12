//! The client half of the process: asking Evidence for credentials.
//!
//! This service signs nothing. It authenticates to its token issuer with its own private
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
        let token_endpoint = Url::parse(&config.token_client.token_endpoint)
            .map_err(|_| IssuanceError::Configuration("the token endpoint is not a URL"))?;
        let base_url = Url::parse(&config.evidence.base_url)
            .map_err(|_| IssuanceError::Configuration("the Evidence base URL is not a URL"))?;
        let key = PrivateJwk::parse(client_key).map_err(|_| {
            IssuanceError::Configuration("the token client key is not a private JWK")
        })?;
        let mut provider_config =
            PrivateKeyJwtConfig::new(token_endpoint, config.token_client.client_id.clone(), key)
                .with_audience(config.token_client.client_assertion_audience().to_owned());
        if let Some(resource) = config.token_client.resource.as_deref() {
            provider_config = provider_config.with_resource(resource.to_owned());
        }
        if let Some(scopes) = config.token_client.scopes.as_ref() {
            provider_config = provider_config.with_scopes(scopes.clone());
        }
        let provider = PrivateKeyJwt::new(provider_config)
            .map_err(|_| IssuanceError::Configuration("the token client identity is unusable"))?;
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

    use axum::{
        extract::{Form, State},
        routing::{get, post},
        Json, Router,
    };
    use serde_json::json;
    use std::collections::HashMap;

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
                "the token client key is not a private JWK"
            ))
        ));
    }

    #[tokio::test]
    async fn the_outbound_client_requests_its_configured_resource_and_scopes() {
        type Forms = Arc<Mutex<Vec<HashMap<String, String>>>>;

        async fn token(
            State(forms): State<Forms>,
            Form(form): Form<HashMap<String, String>>,
        ) -> Json<serde_json::Value> {
            forms.lock().await.push(form);
            Json(json!({
                "access_token": "synthetic-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
            }))
        }

        let forms: Forms = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/oauth2/token", post(token))
            .route(
                "/v1/evidence-definitions",
                get(|| async { axum::http::StatusCode::FORBIDDEN }),
            )
            .with_state(forms.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a local issuer can bind");
        let origin = format!("http://{}", listener.local_addr().expect("bound address"));
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("local issuer serves");
        });

        let mut config = valid_config();
        config.evidence.base_url = origin.clone();
        config.token_client.token_endpoint = format!("{origin}/oauth2/token");
        config.token_client.client_assertion_audience = Some(origin);
        config.token_client.resource = Some("urn:registry:evidence".to_owned());
        config.token_client.scopes = Some(vec!["evidence:invoke".to_owned()]);
        let issuer = EvidenceIssuer::new(&config, &private_jwk("delivery-client"))
            .expect("the outbound client is built");

        let _ = issuer.catalog().await;
        let recorded = forms.lock().await;
        assert_eq!(recorded.len(), 1, "one token request precedes discovery");
        let form = &recorded[0];
        assert_eq!(
            form.get("resource"),
            Some(&"urn:registry:evidence".to_owned())
        );
        assert_eq!(form.get("scope"), Some(&"evidence:invoke".to_owned()));
        assert_eq!(form.get("client_id"), Some(&"evidence-oid4vci".to_owned()));
        server.abort();
    }

    #[test]
    fn a_deployment_failure_is_never_reported_as_a_subject_statement() {
        // Every mapped failure is a coarse category. None of them can be read
        // as an answer about a subject, and none carries deployment text.
        assert_eq!(
            IssuanceError::from(EvidenceClientError::Denied {
                status: 403,
                code: "forbidden".to_owned(),
                trace_id: None,
                retry_after_seconds: None,
            }),
            IssuanceError::Refused
        );
        assert_eq!(
            IssuanceError::from(EvidenceClientError::NotAvailable { trace_id: None }),
            IssuanceError::NotAvailable
        );
        assert!(!IssuanceError::Refused.to_string().contains("forbidden"));
    }
}
