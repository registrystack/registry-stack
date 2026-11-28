//! Bearer verification belongs only to the HTTP adapter.
use crate::problem::{ProblemKind, RenderProblem};
use crate::runtime::RenderRuntime;
use registry_platform_authcommon::FailedCheck;
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery_for_issuer, AccessTokenAlgorithm, IssuerNetworkPolicy,
    JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig, OidcError, TokenVerifier,
    TokenVerifierConfig,
};
use std::sync::Arc;
use std::time::Duration;

/// The access-token signature algorithms the service accepts.
const ACCEPTED_ALGORITHMS: [AccessTokenAlgorithm; 2] =
    [AccessTokenAlgorithm::RS256, AccessTokenAlgorithm::ES256];

fn accepted_algorithms() -> Vec<jsonwebtoken::Algorithm> {
    ACCEPTED_ALGORITHMS
        .into_iter()
        .map(AccessTokenAlgorithm::to_jsonwebtoken)
        .collect()
}

pub(crate) async fn verifier(
    runtime: &RenderRuntime,
) -> Result<Option<TokenVerifier>, RenderProblem> {
    let Some(oidc) = &runtime.authentication.oidc else {
        return Ok(None);
    };
    let refuse = || {
        RenderProblem::new(ProblemKind::RuntimeInvalid, "authentication.oidc signing keys could not be loaded; check the issuer and configured JWKS source")
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
            let keys =
                registry_platform_oidc::parse_static_jwks(&bytes).map_err(|error| match error {
                    OidcError::StaticKeySet(refused) => RenderProblem::new(
                        ProblemKind::RuntimeInvalid,
                        format!(
                            "authentication.oidc.jwksSource.documentRef was refused: {refused}"
                        ),
                    ),
                    _ => refuse(),
                })?;
            JwksFetcher::new_static(keys, JwksFetcherConfig::defaults())
        }
    };
    let profile = TokenVerifierConfig::access_token_profile(
        provider.issuer.to_string(),
        vec![provider.audience.clone()],
        accepted_algorithms(),
        access_token_typ_set("at+jwt"),
    )
    .with_allowed_clients(oidc.clients.allowed_clients.clone())
    .with_assertion_issuers(oidc.clients.assertion_issuers.clone());
    Ok(Some(TokenVerifier::new(profile, Arc::new(keys))))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AuthenticationError {
    /// The credential was refused, by the check that refused it.
    Refused(FailedCheck),
    Forbidden {
        caller_fingerprint: String,
        check: FailedCheck,
    },
    Unavailable,
}

impl AuthenticationError {
    /// The check that refused the caller. A key source that cannot answer is
    /// the verifier's own outage.
    #[deny(clippy::wildcard_enum_match_arm)]
    pub(crate) fn failed_check(&self) -> FailedCheck {
        match self {
            Self::Refused(check) | Self::Forbidden { check, .. } => *check,
            Self::Unavailable => FailedCheck::KeySourceUnavailable,
        }
    }
}

fn verifier_failure(error: OidcError) -> AuthenticationError {
    if error.is_key_source_unavailable() {
        AuthenticationError::Unavailable
    } else {
        AuthenticationError::Refused(error.failed_check())
    }
}

/// The claim the verifier reads a token's scopes from.
pub(crate) const SCOPE_CLAIM: &str = "scope";

/// The scope the render and document routes require.
pub(crate) const RENDER_SCOPE: &str = "render:render";
/// The scope the seal route requires. Neither scope implies the other: a
/// sealing client is granted `render:seal` on its own, and a rendering
/// client's `render:render` never reaches a seal.
pub(crate) const SEAL_SCOPE: &str = "render:seal";

/// A verified Render resource credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Authenticated {
    /// The fingerprint of the exact credential, the only caller value the
    /// audit records.
    pub(crate) caller_fingerprint: String,
    /// The verified client, compared against a seal's `allowedClients` and
    /// never audited. `None` when the token names no client.
    pub(crate) client_id: Option<String>,
}

pub(crate) async fn authenticate(
    verifier: &TokenVerifier,
    token: &str,
    required_scope: &str,
) -> Result<Authenticated, AuthenticationError> {
    registry_platform_authcommon::validate_compact_access_token(token)
        .map_err(|_| AuthenticationError::Refused(FailedCheck::CredentialMalformed))?;
    let verified = verifier.verify(token).await.map_err(verifier_failure)?;
    // The verifier owns resource membership and the configured client binding.
    // Unrelated task-grant claims confer no Render authority.
    let caller_fingerprint = registry_platform_authcommon::fingerprint_api_key(token);
    if !verified.scopes.iter().any(|scope| scope == required_scope) {
        return Err(AuthenticationError::Forbidden {
            caller_fingerprint,
            check: FailedCheck::Scope,
        });
    }
    // With an allowlist the verifier has bound the client and records which
    // claim matched. Without one, the signed claims name it, in the same
    // order the verifier would read them: `azp`, then `client_id`.
    let client_id = match verified.matched_client_id() {
        Ok(Some(client)) => Some(client.to_owned()),
        Ok(None) => verified
            .claims
            .azp
            .clone()
            .or_else(|| verified.claims.client_id.clone())
            .filter(|client| !client.is_empty()),
        Err(_) => return Err(AuthenticationError::Refused(FailedCheck::TokenClient)),
    };
    // Correlate the exact verified credential, as in legacy API-key mode.
    // Issuer, subject, and client claims are never written into the audit event.
    Ok(Authenticated {
        caller_fingerprint,
        client_id,
    })
}

#[cfg(test)]
mod token_characterisation;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::Engine as _;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::{json, Value};
    const CANARY_KEY: &[u8] = b"canary-render-signing-key-01234567890123456789";
    #[test]
    fn the_service_accepts_exactly_rs256_and_es256_access_tokens() {
        assert_eq!(
            accepted_algorithms(),
            vec![Algorithm::RS256, Algorithm::ES256]
        );
    }
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
        let caller = authenticate(&verifier, &credential, RENDER_SCOPE)
            .await
            .expect("independently authorized Render token");
        assert_eq!(
            caller.caller_fingerprint,
            registry_platform_authcommon::fingerprint_api_key(&credential)
        );
    }

    #[tokio::test]
    async fn caller_correlates_the_verified_credential_not_principal_claims() {
        let verifier = test_verifier();
        let first = token(json!({"jti":"canary-first"}));
        let second = token(json!({"jti":"canary-second"}));
        let caller = authenticate(&verifier, &first, RENDER_SCOPE)
            .await
            .unwrap()
            .caller_fingerprint;
        assert_eq!(
            caller,
            registry_platform_authcommon::fingerprint_api_key(&first)
        );
        let again = authenticate(&verifier, &first, RENDER_SCOPE).await.unwrap();
        assert_eq!(again.caller_fingerprint, caller);
        let other = authenticate(&verifier, &second, RENDER_SCOPE)
            .await
            .unwrap();
        assert_ne!(other.caller_fingerprint, caller);
    }

    #[tokio::test]
    async fn resource_expiry_signature_scope_and_grant_boundaries() {
        let verifier = test_verifier();
        let caller = authenticate(&verifier, &token(json!({})), RENDER_SCOPE)
            .await
            .expect("valid Render resource token");
        assert!(!caller.caller_fingerprint.contains("canary-principal"));
        for overrides in [
            json!({"aud":"urn:other"}),
            json!({"exp":1}),
            json!({"scope":"other"}),
            json!({"client_id":"other"}),
        ] {
            assert!(authenticate(&verifier, &token(overrides), RENDER_SCOPE)
                .await
                .is_err());
        }
        assert!(
            authenticate(&verifier, "canary-invalid-token", RENDER_SCOPE)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn each_route_scope_authorizes_only_its_own_route() {
        let verifier = test_verifier();
        let render_only = token(json!({"scope":"render:render"}));
        let seal_only = token(json!({"scope":"render:seal"}));
        let both = token(json!({"scope":"render:render render:seal"}));
        assert!(matches!(
            authenticate(&verifier, &render_only, SEAL_SCOPE).await,
            Err(AuthenticationError::Forbidden { .. })
        ));
        assert!(matches!(
            authenticate(&verifier, &seal_only, RENDER_SCOPE).await,
            Err(AuthenticationError::Forbidden { .. })
        ));
        assert!(authenticate(&verifier, &seal_only, SEAL_SCOPE)
            .await
            .is_ok());
        assert!(authenticate(&verifier, &both, SEAL_SCOPE).await.is_ok());
        assert!(authenticate(&verifier, &both, RENDER_SCOPE).await.is_ok());
    }

    #[tokio::test]
    async fn the_verified_client_is_returned_for_the_seal_allowlist() {
        let bound = authenticate(&test_verifier(), &token(json!({})), RENDER_SCOPE)
            .await
            .unwrap();
        assert_eq!(bound.client_id.as_deref(), Some("portal"));
        let unrestricted = TokenVerifier::new(
            TokenVerifierConfig::access_token_profile(
                "https://issuer.example.test",
                vec!["urn:render:test".to_owned()],
                vec![Algorithm::HS256],
                access_token_typ_set("at+jwt"),
            )
            .with_leeway(Duration::ZERO),
            Arc::new(JwksFetcher::new_static(
                serde_json::from_value(test_jwks()).unwrap(),
                JwksFetcherConfig::defaults(),
            )),
        );
        for (claims, client) in [
            (json!({"client_id":"records"}), Some("records")),
            (
                json!({"client_id":"records","azp":"records"}),
                Some("records"),
            ),
            (json!({"client_id":null}), None),
        ] {
            let verified = authenticate(&unrestricted, &token(claims), RENDER_SCOPE)
                .await
                .unwrap();
            assert_eq!(verified.client_id.as_deref(), client);
        }
    }

    /// Builds the verifier from a runtime file whose static key set is `keys`.
    async fn verifier_over_static_keys(
        keys: &Value,
    ) -> Result<Option<TokenVerifier>, RenderProblem> {
        use std::os::unix::fs::PermissionsExt;
        let scratch = tempfile::tempdir().expect("home directory");
        let home = scratch
            .path()
            .canonicalize()
            .expect("physical home directory");
        std::fs::create_dir(home.join("bundle")).expect("package directory");
        std::fs::create_dir(home.join("audit")).expect("audit directory");
        let key_file = home.join("jwks.json");
        std::fs::write(&key_file, keys.to_string()).expect("write the key set");
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only key file");
        let runtime = format!(
            "apiVersion: {}\nkind: {}\nlistener:\n  bind: 127.0.0.1:18080\npackage:\n  root: {}\nsecretProviders:\n  file:\n    root: {}\nauthentication:\n  oidc:\n    issuer: https://issuer.example.test\n    audience: urn:render:test\n    allowedClients: [portal]\n    jwksSource:\n      type: static\n      documentRef: secret:file/jwks.json\naudit:\n  path: {}\n",
            crate::runtime::RUNTIME_API_VERSION,
            crate::runtime::RUNTIME_KIND,
            home.join("bundle").display(),
            home.display(),
            home.join("audit").join("render.jsonl").display(),
        );
        let path = home.join("runtime.yaml");
        std::fs::write(&path, runtime).expect("write the runtime file");
        let (runtime, _) = crate::runtime::load(&path).expect("the runtime file loads");
        verifier(&runtime).await
    }

    fn ec_public_key() -> Value {
        let set = registry_platform_testing::TokenSigner::new().public_key_set();
        set["keys"]
            .as_array()
            .expect("a key set lists keys")
            .iter()
            .find(|key| key["kty"] == "EC")
            .expect("the corpus holds an EC key")
            .clone()
    }

    #[tokio::test]
    async fn a_static_key_set_with_unknown_public_members_loads() {
        let mut key = ec_public_key();
        key["ext"] = json!(true);
        let verifier = verifier_over_static_keys(&json!({ "keys": [key] }))
            .await
            .expect("a public member the verifier does not read is ignored");
        assert!(verifier.is_some());
    }

    #[tokio::test]
    async fn a_static_key_set_with_a_private_member_is_refused_with_the_reason() {
        let mut key = ec_public_key();
        key["d"] = json!("private");
        let problem = match verifier_over_static_keys(&json!({ "keys": [key] })).await {
            Err(problem) => problem,
            Ok(_) => panic!("a key set holding a private member must be refused"),
        };
        assert_eq!(problem.kind, ProblemKind::RuntimeInvalid);
        assert!(
            problem.detail.contains("private-key member \"d\""),
            "the detail names the refused member: {}",
            problem.detail
        );
        assert!(
            problem.detail.contains("authentication.oidc.jwksSource"),
            "the detail names the setting: {}",
            problem.detail
        );
    }
}
