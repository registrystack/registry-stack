// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::{env, sync::Arc, time::Duration};

use jsonwebtoken::Algorithm;
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use registry_witness_core::{
    FederationConfig, FederationPeerConfig, FEDERATION_REPLAY_IN_PROCESS_SINGLE_INSTANCE_ONLY,
    FEDERATION_REQUEST_JWT_TYP,
};
use zeroize::Zeroizing;

use super::replay::FederationReplayStore;
use super::signing::FederationResponseSigner;

#[derive(Clone)]
pub(crate) struct FederationRuntimeState {
    pub(super) response_signer: FederationResponseSigner,
    pub(super) pairwise_subject_hash_secret: Arc<Vec<u8>>,
    pub(super) peers_by_issuer: Arc<HashMap<String, FederationResolvedPeer>>,
    pub(super) replay: Arc<FederationReplayStore>,
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
        audit: Option<crate::standalone::AuditPipeline>,
    ) -> Result<Self, crate::standalone::StandaloneServerError> {
        let signing_key = Zeroizing::new(
            env::var(&config.signing.key_env)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    crate::standalone::StandaloneServerError::MissingFederationSecretEnv(
                        config.signing.key_env.clone(),
                    )
                })?,
        );
        let key = PrivateJwk::parse(signing_key.as_str()).map_err(|error| {
            crate::standalone::StandaloneServerError::InvalidFederationSigningKeyEnv(
                config.signing.key_env.clone(),
                error.to_string(),
            )
        })?;
        if config.replay.storage == FEDERATION_REPLAY_IN_PROCESS_SINGLE_INSTANCE_ONLY {
            tracing::warn!(
                target: "registry_witness::federation",
                "federation replay store is in-process single-instance only; do not deploy active-active"
            );
        }
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
                kid: config.signing.kid.clone(),
                key,
            },
            pairwise_subject_hash_secret: Arc::new(pairwise_subject_hash_secret),
            peers_by_issuer: Arc::new(peers_by_issuer),
            replay: Arc::new(FederationReplayStore::default()),
            audit,
        })
    }
}
