//! Fresh Casework authority acquisition for a bounded agent task grant.

use async_trait::async_trait;
use registry_platform_httputil::{
    ExchangeAssertionSource, ExchangeContext, PrivateKeyJwt, SignedExchangeAssertion, TokenError,
    TokenProvider,
};
use uuid::Uuid;

use crate::CaseworkClient;

/// Uses the agent's narrow Casework bootstrap to obtain a new task assertion.
/// The source never accepts a human profile, an assertion body, or a replacement
/// grant ID. The exchange provider checks the signed claims against its own
/// immutable client, resource, scopes, and grant context before token I/O.
pub struct CaseworkTaskAssertionSource {
    casework: CaseworkClient,
    bootstrap: PrivateKeyJwt,
    grant_id: Uuid,
}

impl CaseworkTaskAssertionSource {
    pub fn new(
        casework: CaseworkClient,
        bootstrap: PrivateKeyJwt,
        grant_id: Uuid,
        casework_resource: &str,
    ) -> Result<Self, TokenError> {
        let (resource, scopes) = bootstrap.configured_resource_and_scopes();
        if !registry_platform_httputil::valid_resource_uri(casework_resource)
            || resource != Some(casework_resource)
            || scopes != ["casework:grants:assert"]
        {
            return Err(TokenError::Configuration {
                reason: "the agent bootstrap must address only the Casework assertion scope",
            });
        }
        Ok(Self {
            casework,
            bootstrap,
            grant_id,
        })
    }
}

#[async_trait]
impl ExchangeAssertionSource for CaseworkTaskAssertionSource {
    async fn assertion(
        &self,
        context: &ExchangeContext,
    ) -> Result<SignedExchangeAssertion, TokenError> {
        if context.grant_id() != Some(self.grant_id.to_string().as_str()) {
            return Err(TokenError::Invalid {
                reason: "the requested grant does not match the Casework source",
            });
        }
        let bootstrap = self.bootstrap.bearer_token().await?;
        let response = self
            .casework
            .task_assertion(&bootstrap, self.grant_id)
            .await
            .map_err(|_| TokenError::Unavailable)?;
        let value = response.value;
        if i64::try_from(value.grant_expires_at).ok() != Some(context.deadline()) {
            return Err(TokenError::Invalid {
                reason: "the Casework assertion changed the grant deadline",
            });
        }
        SignedExchangeAssertion::new(
            value.assertion,
            i64::try_from(value.expires_at).map_err(|_| TokenError::Invalid {
                reason: "the Casework assertion expiry is out of range",
            })?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::SigningKey;
    use registry_platform_crypto::PrivateJwk;
    use serde_json::json;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn key() -> PrivateJwk {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let signing = SigningKey::from_bytes(&seed);
        PrivateJwk::parse(
            &json!({
                "kty":"OKP", "crv":"Ed25519", "alg":"EdDSA", "kid":"test-key",
                "x":URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
                "d":URL_SAFE_NO_PAD.encode(signing.to_bytes()),
            })
            .to_string(),
        )
        .unwrap()
    }

    fn bootstrap(server: &MockServer, scopes: &[&str]) -> PrivateKeyJwt {
        PrivateKeyJwt::new(
            registry_platform_httputil::PrivateKeyJwtConfig::new(
                format!("{}/token", server.uri()).parse().unwrap(),
                "agent-client",
                key(),
            )
            .with_resource("urn:casework")
            .with_scopes(scopes.iter().copied()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn bootstrap_scope_and_grant_mismatch_refuse_before_http() {
        let server = MockServer::start().await;
        let client = CaseworkClient::new(crate::CaseworkClientConfig::new(
            server.uri().parse().unwrap(),
        ))
        .unwrap();
        let id = Uuid::new_v4();
        assert!(matches!(
            CaseworkTaskAssertionSource::new(
                client,
                bootstrap(&server, &["casework:grants:status"]),
                id,
                "urn:casework"
            ),
            Err(TokenError::Configuration { .. })
        ));
        let client = CaseworkClient::new(crate::CaseworkClientConfig::new(
            server.uri().parse().unwrap(),
        ))
        .unwrap();
        let source = CaseworkTaskAssertionSource::new(
            client,
            bootstrap(&server, &["casework:grants:assert"]),
            id,
            "urn:casework",
        )
        .unwrap();
        let context = ExchangeContext::grant(
            "https://casework.example",
            "agent",
            "https://issuer.example",
            "generation",
            2_000_000_000,
            Uuid::new_v4().to_string(),
        )
        .unwrap();
        assert!(matches!(
            source.assertion(&context).await,
            Err(TokenError::Invalid { .. })
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn fresh_assertion_uses_agent_bootstrap_and_empty_post() {
        let server = MockServer::start().await;
        let id = Uuid::new_v4();
        let deadline = 2_000_000_000i64;
        Mock::given(method("POST")).and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"bootstrap", "token_type":"Bearer", "expires_in":60, "scope":"casework:grants:assert"})))
            .mount(&server).await;
        Mock::given(method("POST")).and(path(format!("/v1/task-grants/{id}/assertion")))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                .set_body_json(json!({"assertion":"a.b.c","expiresAt":1_800_000_060u64,"grantExpiresAt":deadline})))
            .mount(&server).await;
        let client = CaseworkClient::new(crate::CaseworkClientConfig::new(
            server.uri().parse().unwrap(),
        ))
        .unwrap();
        let source = CaseworkTaskAssertionSource::new(
            client,
            bootstrap(&server, &["casework:grants:assert"]),
            id,
            "urn:casework",
        )
        .unwrap();
        let context = ExchangeContext::grant(
            "https://casework.example",
            "agent",
            "https://issuer.example",
            "generation",
            deadline,
            id.to_string(),
        )
        .unwrap();
        source.assertion(&context).await.unwrap();
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        let assertion = requests
            .iter()
            .find(|request| request.url.path().ends_with("/assertion"))
            .unwrap();
        assert_eq!(assertion.method.as_str(), "POST");
        assert!(assertion.body.is_empty());
        assert_eq!(
            assertion
                .headers
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer bootstrap"
        );
        assert!(assertion.headers.get("registry-casework-profile").is_none());
    }
}
