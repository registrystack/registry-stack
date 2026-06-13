// SPDX-License-Identifier: Apache-2.0
//! Minimal process wrapper for the Registry Platform STS bridge.

use std::{env, error::Error, io, net::SocketAddr, sync::Arc, time::Duration};

use jsonwebtoken::Algorithm;
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use registry_platform_sts::{
    sts_router, InMemoryRateLimitStore, OidcSubjectTokenVerifier, StsHttpConfig,
    TokenExchangeConfig, TokenExchangeService,
};

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
    let subject_allowed_typ = csv_env("REGISTRY_PLATFORM_STS_SUBJECT_ALLOWED_TYP", "at+jwt,JWT");
    let subject_allowed_algorithms =
        algorithms_env("REGISTRY_PLATFORM_STS_SUBJECT_ALLOWED_ALGS", "EdDSA,RS256")?;

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
    let service = Arc::new(TokenExchangeService::new(
        subject_verifier,
        signer,
        Arc::new(InMemoryRateLimitStore::default()),
        TokenExchangeConfig::notary_transaction_token(&issuer, notary_audience)
            .with_session_binding_secret(session_binding_secret)
            .with_subject_binding_claim(subject_claim),
    ));
    let app = sts_router(service, StsHttpConfig::local(&issuer));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
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
