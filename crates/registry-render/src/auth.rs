//! Bearer verification belongs only to the HTTP adapter.
use crate::problem::{ProblemKind, RenderProblem};
use crate::runtime::RenderRuntime;
use jsonwebtoken::Algorithm;
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery_for_issuer, IssuerNetworkPolicy, JwksFetcher,
    JwksFetcherConfig, OidcDiscoveryConfig, OidcError, TokenVerifier, TokenVerifierConfig,
};
use std::sync::Arc;
use std::time::Duration;

pub(crate) async fn verifier(
    runtime: &RenderRuntime,
) -> Result<Option<TokenVerifier>, RenderProblem> {
    let Some(oidc) = &runtime.auth.oidc else {
        return Ok(None);
    };
    let refuse = || {
        RenderProblem::new(ProblemKind::RuntimeInvalid, "auth.oidc signing keys could not be loaded; check the issuer and configured JWKS source")
    };
    let provider = &oidc.provider;
    let network = IssuerNetworkPolicy::new(provider.issuer.as_str(), provider.allow_insecure_http)
        .map_err(|_| refuse())?;
    let keys = match &provider.jwks_source {
        registry_platform_config::JwksSource::Discovery {} => {
            let (discovery, policy) = fetch_discovery_for_issuer(
                &OidcDiscoveryConfig {
                    issuer: provider.issuer.to_string(),
                    jwks_uri_override: None,
                    discovery_timeout: Duration::from_secs(5),
                    max_doc_bytes: 1024 * 1024,
                },
                provider.allow_insecure_http,
            )
            .await
            .map_err(|_| refuse())?;
            JwksFetcher::new_with_fetch_url_policy(
                discovery.jwks_uri,
                JwksFetcherConfig::defaults(),
                policy,
            )
        }
        registry_platform_config::JwksSource::Uri { uri } => {
            JwksFetcher::new_with_fetch_url_policy(
                uri.to_string(),
                JwksFetcherConfig::defaults(),
                network.declared_jwks_fetch_policy(),
            )
        }
        registry_platform_config::JwksSource::Static { document_ref } => {
            let bytes = crate::runtime::resolve_secret(runtime, document_ref)?;
            let keys = registry_platform_oidc::parse_static_jwks(&bytes).map_err(|_| refuse())?;
            JwksFetcher::new_static(keys, JwksFetcherConfig::defaults())
        }
    };
    let profile = TokenVerifierConfig::access_token_profile(
        provider.issuer.to_string(),
        vec![provider.audience.clone()],
        vec![Algorithm::RS256, Algorithm::ES256],
        access_token_typ_set("at+jwt"),
    )
    .with_allowed_clients(oidc.clients.allowed_clients.clone())
    .with_assertion_issuers(oidc.clients.assertion_issuers.clone());
    Ok(Some(TokenVerifier::new(profile, Arc::new(keys))))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AuthenticationError {
    Refused,
    Forbidden { caller_fingerprint: String },
    Unavailable,
}

fn verifier_failure(error: OidcError) -> AuthenticationError {
    match error {
        OidcError::Transport(_)
        | OidcError::BoundedRead(_)
        | OidcError::FetchUrl(_)
        | OidcError::HttpStatus(_)
        | OidcError::InvalidUrl
        | OidcError::Parse
        | OidcError::InvalidJwk
        | OidcError::EmptyKeySet
        | OidcError::MissingIssuer
        | OidcError::ConflictingEndpointConfiguration
        | OidcError::InsecureHttpRequiresOptIn
        | OidcError::EndpointRefused { .. } => AuthenticationError::Unavailable,
        _ => AuthenticationError::Refused,
    }
}

pub(crate) async fn authenticate(
    verifier: &TokenVerifier,
    token: &str,
) -> Result<String, AuthenticationError> {
    registry_platform_authcommon::validate_compact_access_token(token)
        .map_err(|_| AuthenticationError::Refused)?;
    let verified = verifier.verify(token).await.map_err(verifier_failure)?;
    // The verifier owns resource membership and the configured client binding.
    // Unrelated task-grant claims confer no Render authority.
    let caller_fingerprint = registry_platform_authcommon::fingerprint_api_key(token);
    if !verified.scopes.iter().any(|scope| scope == "render:render") {
        return Err(AuthenticationError::Forbidden { caller_fingerprint });
    }
    // Correlate the exact verified credential, as in legacy API-key mode.
    // Issuer, subject, and client claims are never written into the audit event.
    Ok(caller_fingerprint)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::Engine as _;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::{json, Value};
    const CANARY_KEY: &[u8] = b"canary-render-signing-key-01234567890123456789";
    pub(crate) fn test_jwks() -> Value {
        json!({"keys":[{"kty":"oct","kid":"canary","alg":"HS256","use":"sig","k":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(CANARY_KEY)}]})
    }
    pub(crate) fn test_verifier() -> TokenVerifier {
        test_verifier_over(Arc::new(JwksFetcher::new_static(
            serde_json::from_value(test_jwks()).unwrap(),
            JwksFetcherConfig::defaults(),
        )))
    }
    pub(crate) fn test_verifier_over(keys: Arc<JwksFetcher>) -> TokenVerifier {
        let profile = TokenVerifierConfig::access_token_profile(
            "https://issuer.example.test",
            vec!["urn:render:test".to_owned()],
            vec![Algorithm::HS256],
            access_token_typ_set("at+jwt"),
        )
        .with_allowed_clients(vec!["portal".to_owned()])
        .with_leeway(Duration::ZERO);
        TokenVerifier::new(profile, keys)
    }
    pub(crate) fn token(overrides: Value) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({"iss":"https://issuer.example.test","sub":"canary-principal","aud":"urn:render:test","iat":now,"exp":now+300,"client_id":"portal","scope":"render:render"});
        claims
            .as_object_mut()
            .unwrap()
            .extend(overrides.as_object().unwrap().clone());
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("canary".to_owned());
        header.typ = Some("at+jwt".to_owned());
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(CANARY_KEY)).unwrap()
    }
    #[tokio::test]
    async fn accepted_resource_membership_ignores_unrelated_grants() {
        let verifier = test_verifier();
        let credential = token(
            json!({"aud":["urn:other","urn:render:test"],"registry_grant_id":"canary-unrelated"}),
        );
        let caller = authenticate(&verifier, &credential)
            .await
            .expect("independently authorized Render token");
        assert_eq!(
            caller,
            registry_platform_authcommon::fingerprint_api_key(&credential)
        );
    }

    #[tokio::test]
    async fn caller_correlates_the_verified_credential_not_principal_claims() {
        let verifier = test_verifier();
        let first = token(json!({"jti":"canary-first"}));
        let second = token(json!({"jti":"canary-second"}));
        let caller = authenticate(&verifier, &first).await.unwrap();
        assert_eq!(
            caller,
            registry_platform_authcommon::fingerprint_api_key(&first)
        );
        assert_eq!(authenticate(&verifier, &first).await.unwrap(), caller);
        assert_ne!(authenticate(&verifier, &second).await.unwrap(), caller);
    }

    #[tokio::test]
    async fn resource_expiry_signature_scope_and_grant_boundaries() {
        let verifier = test_verifier();
        let caller = authenticate(&verifier, &token(json!({})))
            .await
            .expect("valid Render resource token");
        assert!(!caller.contains("canary-principal"));
        for overrides in [
            json!({"aud":"urn:other"}),
            json!({"exp":1}),
            json!({"scope":"other"}),
            json!({"client_id":"other"}),
        ] {
            assert!(authenticate(&verifier, &token(overrides)).await.is_err());
        }
        assert!(authenticate(&verifier, "canary-invalid-token")
            .await
            .is_err());
    }
}
