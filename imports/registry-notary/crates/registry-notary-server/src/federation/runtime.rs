// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::{env, sync::Arc, time::Duration};

use jsonwebtoken::Algorithm;
use registry_notary_core::{FederationConfig, FederationPeerConfig, FEDERATION_REQUEST_JWT_TYP};
use registry_platform_crypto::SigningProvider;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use registry_platform_replay::ReplayStore;

use super::signing::FederationResponseSigner;
use crate::metrics::AppMetrics;

#[derive(Clone)]
pub(crate) struct FederationRuntimeState {
    pub(super) response_signer: FederationResponseSigner,
    pub(super) pairwise_subject_hash_secret: Arc<Vec<u8>>,
    pub(super) peers_by_issuer: Arc<HashMap<String, FederationResolvedPeer>>,
    pub(super) replay: Arc<dyn ReplayStore>,
    pub(super) metrics: Arc<AppMetrics>,
    pub(super) audit: Option<crate::standalone::AuditPipeline>,
}

#[derive(Clone)]
pub(super) struct FederationResolvedPeer {
    pub(super) config: FederationPeerConfig,
    pub(super) verifier: Arc<TokenVerifier>,
}

impl FederationRuntimeState {
    pub(crate) fn from_config(
        config: &FederationConfig,
        signing_provider: Arc<dyn SigningProvider>,
        audit: Option<crate::standalone::AuditPipeline>,
        replay: Arc<dyn ReplayStore>,
        metrics: Arc<AppMetrics>,
    ) -> Result<Self, crate::standalone::StandaloneServerError> {
        let pairwise_subject_hash_secret = env::var(&config.pairwise_subject_hash.secret_env)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                crate::standalone::StandaloneServerError::MissingFederationSecretEnv(
                    config.pairwise_subject_hash.secret_env.clone(),
                )
            })?
            .into_bytes();
        let mut peers_by_issuer = HashMap::new();
        for peer in &config.peers {
            let fetch_url_policy = if peer.allow_insecure_private_network {
                FetchUrlPolicy {
                    allowed_schemes: vec!["http".to_string(), "https".to_string()],
                    allow_localhost: true,
                    allow_http_private_network: true,
                    deny_private_ranges: false,
                    deny_cloud_metadata: true,
                }
            } else if peer.allow_insecure_localhost {
                FetchUrlPolicy::dev()
            } else {
                FetchUrlPolicy::strict()
            };
            let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
                peer.jwks_uri.clone(),
                JwksFetcherConfig::defaults(),
                fetch_url_policy,
            ));
            let verifier = Arc::new(TokenVerifier::new(
                TokenVerifierConfig {
                    issuer: peer.issuer.clone(),
                    audiences: vec![config.node_id.clone()],
                    allowed_algorithms: vec![Algorithm::EdDSA],
                    allowed_typ: vec![FEDERATION_REQUEST_JWT_TYP.to_string()],
                    allowed_id_typ: vec!["JWT".to_string(), "id_token".to_string()],
                    allowed_userinfo_typ: vec!["JWT".to_string()],
                    userinfo_requires_exp: true,
                    scope_claim: "scope".to_string(),
                    scope_separator: ' ',
                    scope_map: None,
                    allowed_clients: Vec::new(),
                    leeway: Duration::from_secs(config.clock_leeway_seconds),
                },
                fetcher,
            ));
            peers_by_issuer.insert(
                peer.issuer.clone(),
                FederationResolvedPeer {
                    config: peer.clone(),
                    verifier,
                },
            );
        }
        Ok(Self {
            response_signer: FederationResponseSigner {
                provider: signing_provider,
            },
            pairwise_subject_hash_secret: Arc::new(pairwise_subject_hash_secret),
            peers_by_issuer: Arc::new(peers_by_issuer),
            replay,
            metrics,
            audit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_notary_core::{
        FederationEvaluationProfileConfig, FederationPairwiseSubjectHashConfig,
        FederationSigningConfig, FEDERATION_PROTOCOL_V0_1,
    };
    use registry_platform_replay::InMemoryReplayStore;
    use registry_platform_testing::{fixtures, sign_ed25519_compact_jwt, MockIdp};
    use serde_json::json;
    use time::OffsetDateTime;

    fn test_federation_config(peer_issuer: &str, peer_jwks_uri: &str) -> FederationConfig {
        FederationConfig {
            enabled: true,
            node_id: "did:web:agency-a.example.gov".to_string(),
            issuer: "https://agency-a.example.gov".to_string(),
            jwks_uri: "https://agency-a.example.gov/federation/jwks.json".to_string(),
            federation_api: "https://agency-a.example.gov/federation/v1".to_string(),
            supported_protocol_versions: vec![FEDERATION_PROTOCOL_V0_1.to_string()],
            signing: FederationSigningConfig {
                signing_key: "federation-key".to_string(),
            },
            pairwise_subject_hash: FederationPairwiseSubjectHashConfig {
                secret_env: "TEST_FEDERATION_RUNTIME_PAIRWISE_SECRET".to_string(),
            },
            peers: vec![FederationPeerConfig {
                node_id: "did:web:agency-b.example.gov".to_string(),
                issuer: peer_issuer.to_string(),
                jwks_uri: peer_jwks_uri.to_string(),
                allow_insecure_localhost: true,
                allowed_protocol_versions: vec![FEDERATION_PROTOCOL_V0_1.to_string()],
                allowed_purposes: vec!["https://purpose.example.test/eligibility".to_string()],
                allowed_profiles: vec!["farmer_under_4ha".to_string()],
                source_scopes: vec!["farmer_registry:evidence_verification".to_string()],
                ..FederationPeerConfig::default()
            }],
            evaluation_profiles: vec![FederationEvaluationProfileConfig {
                id: "farmer_under_4ha".to_string(),
                ruleset: "farmer-under-4ha-v1".to_string(),
                claim_id: "farmer-under-4ha".to_string(),
                subject_id_type: "national_id".to_string(),
                ..FederationEvaluationProfileConfig::default()
            }],
            ..FederationConfig::default()
        }
    }

    fn federation_token(issuer: &str, typ: &str) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        sign_ed25519_compact_jwt(
            fixtures::ED25519_PRIVATE_JWK,
            typ,
            "registry-platform-testing-ed25519-1",
            json!({
                "iss": issuer,
                "sub": "did:web:agency-b.example.gov",
                "aud": "did:web:agency-a.example.gov",
                "scope": "farmer_registry:evidence_verification",
                "iat": now,
                "nbf": now,
                "exp": now + 300,
                "jti": "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q999",
            }),
        )
    }

    #[tokio::test]
    async fn federation_runtime_verifier_accepts_only_federation_request_typ() {
        std::env::set_var(
            "TEST_FEDERATION_RUNTIME_PAIRWISE_SECRET",
            "federation-pairwise-secret",
        );
        let idp = MockIdp::start().await;
        let config = test_federation_config(&idp.issuer(), &idp.jwks_uri());
        let runtime = FederationRuntimeState::from_config(
            &config,
            Arc::new(fixtures::ed25519_signer()),
            None,
            Arc::new(InMemoryReplayStore::new()),
            Arc::new(AppMetrics::default()),
        )
        .expect("federation runtime builds");
        let peer = runtime
            .peers_by_issuer
            .get(&idp.issuer())
            .expect("peer verifier is registered");

        peer.verifier
            .verify(&federation_token(&idp.issuer(), FEDERATION_REQUEST_JWT_TYP))
            .await
            .expect("federation request typ is accepted");
        peer.verifier
            .verify(&federation_token(&idp.issuer(), "JWT"))
            .await
            .expect_err("plain JWT typ is rejected for federation");
        peer.verifier
            .verify(&federation_token(&idp.issuer(), "id_token"))
            .await
            .expect_err("ID token typ is rejected for federation");

        idp.stop().await;
    }
}
