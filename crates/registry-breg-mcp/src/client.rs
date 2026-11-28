// SPDX-License-Identifier: Apache-2.0

//! One maintained BReg client carrying the edge's opaque per-call authorization.

use std::{sync::Arc, time::Duration};

use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig};
use registry_mcp_edge::ProviderAuthorization;
use registry_platform_httputil::client::TokenError;
use registry_platform_httputil::PeerPolicy;
use url::Url;

#[derive(Clone)]
pub(crate) struct BRegClientFactory {
    base_url: Url,
    attempt_timeout: Duration,
    peer_policy: PeerPolicy,
}

impl BRegClientFactory {
    pub(crate) fn new(
        base_url: Url,
        attempt_timeout: Duration,
        peer_policy: PeerPolicy,
    ) -> Result<Self, ClientFactoryError> {
        if attempt_timeout.is_zero() {
            return Err(ClientFactoryError);
        }
        Ok(Self {
            base_url,
            attempt_timeout,
            peer_policy,
        })
    }

    pub(crate) fn client(
        &self,
        authorization: ProviderAuthorization,
    ) -> Result<BaseRegistryClient, TokenError> {
        BaseRegistryClient::new(
            authorized(
                BaseRegistryClientConfig::new(self.base_url.clone(), self.peer_policy),
                authorization,
            )
            .with_attempt_timeout(self.attempt_timeout)
            // The gateway owns same-key recovery. Client retries stacked under
            // a host retry would multiply an interactive turn and obscure an
            // uncertain mutation result.
            .with_maximum_mutation_retries(0),
        )
        .map_err(|_| TokenError::Configuration {
            reason: "the registry client could not be configured",
        })
    }
}

/// The only point where a credential reaches the maintained BReg client. The
/// value is constructed by the edge and exposes no bearer or text constructor.
#[allow(clippy::disallowed_methods)]
fn authorized(
    config: BaseRegistryClientConfig,
    authorization: ProviderAuthorization,
) -> BaseRegistryClientConfig {
    config.with_token_provider(Arc::new(authorization))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the BReg provider client configuration is invalid")]
pub(crate) struct ClientFactoryError;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_gateway_client_accepts_a_marked_registry_only_in_development() {
        use registry_mcp_edge::{
            AuthorizationFactory, Delegation, DelegationOptions, VerifiedCaller,
        };
        use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
        use registry_platform_testing::{
            ExchangeProfile, TestActorKind, TestAuthorizationServer, TestClient,
        };

        const RESOURCE: &str = "https://gateway.example.test/mcp";
        const AUDIENCE: &str = "urn:breg:citizen-address-correction";
        const SCOPE: &str = "address-correction:self";
        let key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).unwrap();
        let auth = TestAuthorizationServer::builder()
            .client(
                TestClient::new("gateway")
                    .with_public_jwk(key.public())
                    .with_resource(AUDIENCE)
                    .with_resource(RESOURCE)
                    .with_actor_kind(TestActorKind::Agent)
                    .with_service_subject("6f1c2d8e-3b4a-4e59-9c7d-2a8b5e0f1d34"),
            )
            .client(TestClient::new("chat-host").with_resource(RESOURCE))
            .exchange_profile(ExchangeProfile::Conformant)
            .start()
            .await;
        let tokens = Delegation::new(DelegationOptions {
            token_endpoint: Url::parse(&auth.token_endpoint()).unwrap(),
            client_id: "gateway".to_owned(),
            private_key: key,
            assertion_audience: auth.issuer(),
            gateway_resource: RESOURCE.to_owned(),
            downstream_resource: AUDIENCE.to_owned(),
            downstream_scopes: vec![SCOPE.to_owned()],
            attempt_timeout: Duration::from_secs(2),
            generation: "breg-mcp-v1".to_owned(),
        })
        .unwrap();
        let expires_at = chrono::Utc::now().timestamp() + 300;
        let token = auth.issue_access_token("chat-host", "citizen", RESOURCE, SCOPE, expires_at);
        let caller = VerifiedCaller::for_test(
            &auth.issuer(),
            "citizen",
            "chat-host",
            &token,
            expires_at,
            "principal",
            "client",
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let app = axum::Router::new().fallback(|| async {
            (
                [
                    ("Registry-Posture", "development"),
                    (
                        "traceparent",
                        "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                    ),
                    ("cache-control", "no-store"),
                ],
                axum::Json(serde_json::json!({})),
            )
        });
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        for (policy, accepted) in [
            (PeerPolicy::RefuseDevelopmentPeer, false),
            (PeerPolicy::AcceptDevelopmentPeer, true),
        ] {
            let client = BRegClientFactory::new(origin.clone(), Duration::from_secs(2), policy)
                .unwrap()
                .client(tokens.authorization(&caller).unwrap())
                .unwrap();
            let result = client.registry_metadata(None).await;
            if accepted {
                assert!(result.is_ok(), "{:?}", result.err());
            } else {
                assert!(
                    matches!(
                        result,
                        Err(registry_breg_client::BaseRegistryClientError::DevelopmentPeer)
                    ),
                    "{:?}",
                    result.err()
                );
            }
        }
        server.abort();
    }

    #[test]
    fn a_zero_attempt_timeout_is_refused() {
        assert!(BRegClientFactory::new(
            Url::parse("https://registry.example.test/").expect("URL"),
            Duration::ZERO,
            PeerPolicy::RefuseDevelopmentPeer,
        )
        .is_err());
    }
}
