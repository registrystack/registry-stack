// SPDX-License-Identifier: Apache-2.0
//! Minimal process wrapper for the Registry Platform STS bridge.

use std::{env, error::Error, io, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

#[cfg(test)]
use std::path::Path;

use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use registry_platform_audit::{AuditProfile, ChainState, JsonlFileSink};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use registry_platform_sts::{
    sts_router, InMemoryRateLimitStore, OidcSubjectTokenVerifier, StsAuditError, StsAuditSink,
    StsHttpConfig, TokenExchangeConfig, TokenExchangeService, TokenMintAuditEvent,
};

const AUDIT_HASH_SECRET_ENV: &str = "REGISTRY_PLATFORM_STS_AUDIT_HASH_SECRET";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let bind: SocketAddr = env_or("REGISTRY_PLATFORM_STS_BIND", "127.0.0.1:9090").parse()?;
    let issuer = required_env("REGISTRY_PLATFORM_STS_ISSUER")?;
    let issuer = issuer.trim_end_matches('/').to_string();
    let notary_audience = required_env("REGISTRY_PLATFORM_STS_NOTARY_AUDIENCE")?;
    let signing_jwk = required_env("REGISTRY_PLATFORM_STS_SIGNING_JWK")?;
    let subject_issuer = required_env("REGISTRY_PLATFORM_STS_SUBJECT_ISSUER")?;
    let subject_audience = required_env("REGISTRY_PLATFORM_STS_SUBJECT_AUDIENCE")?;
    let subject_jwks_uri = required_env("REGISTRY_PLATFORM_STS_SUBJECT_JWKS_URI")?;
    let subject_claim = env_or("REGISTRY_PLATFORM_STS_SUBJECT_CLAIM", "sub");
    let session_binding_secret = required_env("REGISTRY_PLATFORM_STS_SESSION_BINDING_SECRET")?;
    let audit_hash_secret = required_env(AUDIT_HASH_SECRET_ENV)?;
    let audit_log_path = required_env("REGISTRY_PLATFORM_STS_AUDIT_LOG_PATH")?;
    let subject_allowed_typ = csv_env("REGISTRY_PLATFORM_STS_SUBJECT_ALLOWED_TYP", "at+jwt,JWT");
    let subject_allowed_algorithms =
        algorithms_env("REGISTRY_PLATFORM_STS_SUBJECT_ALLOWED_ALGS", "EdDSA,RS256")?;
    let audit_sink =
        Arc::new(JsonlStsAuditSink::production(audit_log_path, AUDIT_HASH_SECRET_ENV).await?);

    let signer = Arc::new(LocalJwkSigner::new(PrivateJwk::parse(&signing_jwk)?)?);
    let fetcher = Arc::new(JwksFetcher::new(
        subject_jwks_uri,
        JwksFetcherConfig::defaults(),
    ));
    let verifier = Arc::new(TokenVerifier::new(
        TokenVerifierConfig::access_token_profile(
            subject_issuer,
            vec![subject_audience],
            subject_allowed_algorithms,
            subject_allowed_typ,
        )
        .with_leeway(Duration::from_secs(60)),
        fetcher,
    ));
    let subject_verifier = Arc::new(OidcSubjectTokenVerifier::new(
        verifier,
        subject_claim.clone(),
    ));
    let service = Arc::new(
        TokenExchangeService::new(
            subject_verifier,
            signer,
            Arc::new(InMemoryRateLimitStore::default()),
            TokenExchangeConfig::notary_transaction_token(&issuer, notary_audience)
                .with_session_binding_secret(session_binding_secret)
                .with_subject_binding_claim(subject_claim)
                .with_audit_hash_secret(audit_hash_secret),
        )
        .with_audit_sink(audit_sink),
    );
    let app = sts_router(service, StsHttpConfig::local(&issuer));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

struct JsonlStsAuditSink {
    sink: JsonlFileSink,
    chain: ChainState,
}

impl JsonlStsAuditSink {
    async fn production(
        path: impl Into<PathBuf>,
        audit_hash_secret_env: &str,
    ) -> Result<Self, registry_platform_audit::AuditError> {
        let sink = JsonlFileSink::new(path);
        let profile = AuditProfile::production_from_env(audit_hash_secret_env)?;
        Self::from_profile(sink, &profile).await
    }

    async fn from_profile(
        sink: JsonlFileSink,
        profile: &AuditProfile,
    ) -> Result<Self, registry_platform_audit::AuditError> {
        let chain = profile.bootstrap_or_start_empty(&sink).await?;
        Ok(Self { sink, chain })
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        self.sink.path()
    }
}

#[async_trait]
impl StsAuditSink for JsonlStsAuditSink {
    async fn record_token_mint(&self, event: TokenMintAuditEvent) -> Result<(), StsAuditError> {
        self.chain
            .append(&self.sink, event)
            .await
            .map(|_| ())
            .map_err(|_| StsAuditError::Unavailable)
    }
}

fn required_env(name: &str) -> Result<String, io::Error> {
    env::var(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("required environment variable {name} is missing"),
        )
    })
}

fn env_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn csv_env(name: &str, default: &str) -> Vec<String> {
    env_or(name, default)
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn algorithms_env(name: &str, default: &str) -> Result<Vec<Algorithm>, io::Error> {
    csv_env(name, default)
        .into_iter()
        .map(|value| match value.as_str() {
            "EdDSA" => Ok(Algorithm::EdDSA),
            "RS256" => Ok(Algorithm::RS256),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported algorithm {value} in {name}"),
            )),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use time::OffsetDateTime;
    use ulid::Ulid;

    #[tokio::test]
    async fn jsonl_sts_audit_sink_persists_token_mint_events() {
        let dir = env::temp_dir().join(format!("registry-platform-sts-audit-{}", Ulid::new()));
        std::fs::create_dir_all(&dir).expect("temp audit dir");
        let path = dir.join("audit.jsonl");
        let profile = AuditProfile::unkeyed_dev_only();
        let sink = JsonlStsAuditSink::from_profile(JsonlFileSink::new(&path), &profile)
            .await
            .expect("audit sink");

        sink.record_token_mint(TokenMintAuditEvent {
            event_type: "registry-platform-sts.token_minted".to_string(),
            issuer: "https://sts.example".to_string(),
            audience: "registry-notary".to_string(),
            client_id: Some("client-1".to_string()),
            subject_hash: "subject-hash".to_string(),
            jti_hash: "jti-hash".to_string(),
            authorization_details_hash: "details-hash".to_string(),
            session_id: Some("session-1".to_string()),
            correlation_id: Some("corr-1".to_string()),
            actor_id_hash: None,
            issued_at: OffsetDateTime::now_utc().unix_timestamp(),
            expires_at: OffsetDateTime::now_utc().unix_timestamp() + 60,
        })
        .await
        .expect("audit write");

        let contents = std::fs::read_to_string(sink.path()).expect("audit contents");
        let envelope: Value = serde_json::from_str(contents.trim()).expect("audit json");
        assert_eq!(
            envelope["record"]["event_type"],
            "registry-platform-sts.token_minted"
        );

        std::fs::remove_dir_all(dir).expect("remove temp audit dir");
    }
}
