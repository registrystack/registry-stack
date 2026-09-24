// SPDX-License-Identifier: Apache-2.0

//! The outbound half of the gateway: one delegated registry client per call.
//!
//! The chat host's token is never sent to the registry. For each tool call the
//! gateway exchanges it (RFC 8693) at the issuer for a token bound to the
//! registry's audience and scopes, presenting its own client credential as the
//! actor, so the registry sees the citizen as subject and this gateway as the
//! agent acting for them. The exchanged token cannot outlive the citizen's
//! token, and it is used for that one call only. Nothing here reads the
//! inbound verifier or its configuration.

use std::{sync::Arc, time::Duration};

use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig};
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::client::{
    ExchangeAuthorization, ExchangeContext, PrivateKeyJwt, PrivateKeyJwtConfig, SubjectTokenType,
    TokenError, UpstreamSubjectToken,
};
use url::Url;

use crate::{
    config::{ExchangeConfig, RegistryConfig},
    inbound::VerifiedCaller,
};

/// The generation named in every exchange context. The gateway re-verifies
/// the inbound token on every request, so there is no longer-lived host fact
/// whose change a generation would have to track.
const EXCHANGE_GENERATION: &str = "breg-mcp-v1";

/// Why the outbound half could not be configured.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OutboundError {
    #[error("{0} is not a usable URL")]
    Url(&'static str),
    #[error("the gateway client credential could not be configured")]
    Credential(#[source] TokenError),
}

/// The configured outbound half.
pub(crate) struct Outbound {
    base_url: Url,
    audience: String,
    scopes: Vec<String>,
    token_endpoint: Url,
    client_id: String,
    key: PrivateJwk,
    assertion_audience: Option<String>,
    gateway_resource: String,
    timeout: Duration,
    /// The gateway's own client-credentials provider, shared so its cached
    /// credential serves every exchange. It carries no resource or scopes, so
    /// it is never itself a standing registry token.
    actor: Arc<PrivateKeyJwt>,
}

impl Outbound {
    pub(crate) fn new(
        registry: &RegistryConfig,
        exchange: &ExchangeConfig,
        gateway_resource: &str,
        key: PrivateJwk,
    ) -> Result<Self, OutboundError> {
        let base_url =
            Url::parse(&registry.base_url).map_err(|_| OutboundError::Url("registry.baseUrl"))?;
        let token_endpoint = Url::parse(&exchange.token_endpoint)
            .map_err(|_| OutboundError::Url("exchange.tokenEndpoint"))?;
        let timeout = Duration::from_millis(registry.request_timeout_milliseconds);
        let actor = PrivateKeyJwt::new(client_config(
            &token_endpoint,
            &exchange.client_id,
            exchange.assertion_audience.as_deref(),
            &key,
            timeout,
        ))
        .map_err(OutboundError::Credential)?;
        let outbound = Self {
            base_url,
            audience: registry.audience.clone(),
            scopes: registry.scopes.clone(),
            token_endpoint,
            client_id: exchange.client_id.clone(),
            key,
            assertion_audience: exchange.assertion_audience.clone(),
            gateway_resource: gateway_resource.to_owned(),
            timeout,
            actor: Arc::new(actor),
        };
        // Build one exchange provider now, so a key or binding the provider
        // refuses is a startup failure rather than one per call.
        outbound
            .exchange_provider()
            .map_err(OutboundError::Credential)?;
        Ok(outbound)
    }

    fn exchange_provider(&self) -> Result<PrivateKeyJwt, TokenError> {
        PrivateKeyJwt::new(
            client_config(
                &self.token_endpoint,
                &self.client_id,
                self.assertion_audience.as_deref(),
                &self.key,
                self.timeout,
            )
            .with_resource(self.audience.clone())
            .with_scopes(self.scopes.iter().cloned()),
        )
    }

    /// The single-use delegated credential for one call by `caller`.
    pub(crate) fn authorization(
        &self,
        caller: &VerifiedCaller,
    ) -> Result<ExchangeAuthorization, TokenError> {
        self.authorization_with_actor(caller, Arc::clone(&self.actor))
    }

    fn authorization_with_actor(
        &self,
        caller: &VerifiedCaller,
        actor: Arc<PrivateKeyJwt>,
    ) -> Result<ExchangeAuthorization, TokenError> {
        let context = ExchangeContext::first_party(
            caller.issuer(),
            caller.subject(),
            self.gateway_resource.clone(),
            EXCHANGE_GENERATION,
            caller.expires_at(),
        )?;
        let subject = UpstreamSubjectToken::new(
            caller.token(),
            SubjectTokenType::AccessToken,
            caller.expires_at(),
        )?;
        ExchangeAuthorization::upstream(self.exchange_provider()?, context, subject, Some(actor))
    }

    /// A registry client whose every request carries the delegated credential
    /// for `caller`. The exchange happens on the first request.
    pub(crate) fn client(&self, caller: &VerifiedCaller) -> Result<BaseRegistryClient, TokenError> {
        let authorization = self.authorization(caller)?;
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new(self.base_url.clone())
                .with_token_provider(Arc::new(authorization))
                .with_request_timeout(self.timeout),
        )
        .map_err(|_| TokenError::Configuration {
            reason: "the registry client could not be configured",
        })
    }
}

/// The gateway's own client identity at the token endpoint, with no resource
/// and no scopes.
fn client_config(
    token_endpoint: &Url,
    client_id: &str,
    assertion_audience: Option<&str>,
    key: &PrivateJwk,
    timeout: Duration,
) -> PrivateKeyJwtConfig {
    let config = PrivateKeyJwtConfig::new(token_endpoint.clone(), client_id, key.clone())
        .with_request_timeout(timeout);
    match assertion_audience {
        Some(audience) => config.with_audience(audience),
        None => config,
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
    use registry_platform_httputil::client::TokenProvider as _;
    use registry_platform_testing::{
        ExchangeProfile, TestActorKind, TestAuthorizationServer, TestClient,
    };
    use serde_json::Value;

    use super::*;

    const AUDIENCE: &str = "urn:breg:citizen-address-correction";
    const RESOURCE: &str = "https://gateway.example.test/mcp";
    const GATEWAY: &str = "citizen-gateway";
    const ACTOR: &str = "6f1c2d8e-3b4a-4e59-9c7d-2a8b5e0f1d34";
    const SCOPE: &str = "address-correction:self";

    struct Fixture {
        server: TestAuthorizationServer,
        outbound: Outbound,
        other_key: PrivateJwk,
    }

    async fn fixture() -> Fixture {
        let key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("key");
        let other_key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("key");
        let server = TestAuthorizationServer::builder()
            .client(
                TestClient::new(GATEWAY)
                    .with_public_jwk(key.public())
                    .with_resource(AUDIENCE)
                    .with_actor_kind(TestActorKind::Agent)
                    .with_service_subject(ACTOR),
            )
            .client(
                TestClient::new("another-service")
                    .with_public_jwk(other_key.public())
                    .with_resource(AUDIENCE),
            )
            .client(TestClient::new("chat-host").with_resource(RESOURCE))
            .exchange_profile(ExchangeProfile::Conformant)
            .start()
            .await;
        let outbound = Outbound::new(
            &RegistryConfig {
                base_url: "http://127.0.0.1:9/".to_owned(),
                access_profile: "citizen-agent".to_owned(),
                audience: AUDIENCE.to_owned(),
                scopes: vec![SCOPE.to_owned()],
                request_timeout_milliseconds: 5_000,
            },
            &ExchangeConfig {
                token_endpoint: server.token_endpoint(),
                client_id: GATEWAY.to_owned(),
                private_key_ref: "secret:file/unused".to_owned(),
                assertion_audience: None,
            },
            RESOURCE,
            key,
        )
        .expect("outbound configures");
        Fixture {
            server,
            outbound,
            other_key,
        }
    }

    fn now() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs(),
        )
        .expect("time fits")
    }

    fn caller(fixture: &Fixture, citizen: &str, expires_at: i64) -> VerifiedCaller {
        let token =
            fixture
                .server
                .issue_access_token("chat-host", citizen, RESOURCE, SCOPE, expires_at);
        VerifiedCaller::for_test(
            &fixture.server.issuer(),
            citizen,
            "chat-host",
            &token,
            expires_at,
        )
    }

    fn claims(header_value: &str) -> Value {
        let token = header_value.strip_prefix("Bearer ").expect("bearer");
        let payload = token.split('.').nth(1).expect("payload");
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .expect("base64"),
        )
        .expect("claims")
    }

    #[tokio::test]
    async fn the_exchanged_token_names_the_citizen_and_the_gateway_as_actor() {
        let fixture = fixture().await;
        let caller = caller(&fixture, "citizen-a", now() + 300);
        let authorization = fixture
            .outbound
            .authorization(&caller)
            .expect("authorization");
        let header = authorization
            .bearer_token()
            .await
            .expect("exchange succeeds")
            .authorization_header_value()
            .to_str()
            .expect("text")
            .to_owned();
        assert_ne!(header, format!("Bearer {}", caller.token()));
        let claims = claims(&header);
        assert_eq!(claims["sub"], "citizen-a");
        assert_eq!(claims["aud"], AUDIENCE);
        assert_eq!(claims["act"]["sub"], ACTOR);
        assert_eq!(claims["registry_actor_kind"], "agent");
    }

    #[tokio::test]
    async fn the_exchanged_token_never_outlives_the_citizens_token() {
        let fixture = fixture().await;
        let expires_at = now() + 30;
        let caller = caller(&fixture, "citizen-a", expires_at);
        let authorization = fixture
            .outbound
            .authorization(&caller)
            .expect("authorization");
        let token = authorization
            .bearer_token()
            .await
            .expect("exchange succeeds");
        let claims = claims(token.authorization_header_value().to_str().expect("text"));
        assert!(claims["exp"].as_i64().expect("exp") <= expires_at);
    }

    #[tokio::test]
    async fn an_expired_citizen_token_is_refused_before_any_exchange() {
        let fixture = fixture().await;
        let caller = caller(&fixture, "citizen-a", now() - 1);
        assert!(matches!(
            fixture.outbound.authorization(&caller),
            Err(TokenError::Invalid { .. } | TokenError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn an_actor_that_is_not_the_gateway_is_refused() {
        let fixture = fixture().await;
        let caller = caller(&fixture, "citizen-a", now() + 300);
        let foreign = PrivateKeyJwt::new(PrivateKeyJwtConfig::new(
            Url::parse(&fixture.server.token_endpoint()).expect("url"),
            "another-service",
            fixture.other_key.clone(),
        ))
        .expect("foreign provider");
        assert!(matches!(
            fixture
                .outbound
                .authorization_with_actor(&caller, Arc::new(foreign)),
            Err(TokenError::Configuration { .. })
        ));
    }
}
