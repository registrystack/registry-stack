//! Strict OIDC access-token authentication and configured claim extraction.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::parse_json_strict;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig, VerifiedToken,
};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::config::{AccessTokenAlgorithm, AccessTokenType, AuthenticationConfig};

const MAX_TOKEN_BYTES: usize = 128 * 1024;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_CLAIMS_BYTES: usize = 64 * 1024;
const MAX_PRINCIPAL_BYTES: usize = 512;
const MAX_TAGS: usize = 32;

#[derive(Debug, Clone)]
pub struct AuthenticationClaimsConfig {
    pub principal_claim: String,
    pub requester_tags_claim: String,
    pub evidence_audience_claim: String,
    pub grant_id_claim: String,
    pub grant_authority_claim: String,
    pub actor_claim: Option<String>,
}

#[derive(Clone)]
pub struct Authenticator {
    verifier: Arc<TokenVerifier>,
    claims: AuthenticationClaimsConfig,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Authenticator")
            .field("claims", &self.claims)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct AuthenticatedContext {
    principal: String,
    actor: Option<String>,
    requester_tags: Vec<String>,
    evidence_audience: String,
    grant_id: Option<String>,
    grant_authority: Option<String>,
    verified_claims: Value,
}

impl AuthenticatedContext {
    pub fn principal(&self) -> &str {
        &self.principal
    }

    pub fn actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }

    pub fn requester_tags(&self) -> &[String] {
        &self.requester_tags
    }

    pub fn evidence_audience(&self) -> &str {
        &self.evidence_audience
    }

    pub fn grant_id(&self) -> Option<&str> {
        self.grant_id.as_deref()
    }

    pub fn grant_authority(&self) -> Option<&str> {
        self.grant_authority.as_deref()
    }

    pub fn claim_path(&self, path: &str) -> Option<&Value> {
        resolve_claim_path(&self.verified_claims, path)
    }

    /// Construct a context for the bundle-owned, offline fixture command.
    ///
    /// This is crate-private so no production caller can bypass token
    /// verification. The public fixture harness still runs the normal
    /// authorization and selector-resolution functions over this context.
    pub(crate) fn offline_fixture_context(
        requester_tags: Vec<String>,
        evidence_audience: &str,
        grant_id: Option<&str>,
        grant_authority: Option<&str>,
        verified_claims: Value,
    ) -> Self {
        Self {
            principal: "offline-fixture-principal".to_owned(),
            actor: None,
            requester_tags,
            evidence_audience: evidence_audience.to_owned(),
            grant_id: grant_id.map(ToOwned::to_owned),
            grant_authority: grant_authority.map(ToOwned::to_owned),
            verified_claims,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_context(
        principal: &str,
        requester_tags: Vec<String>,
        evidence_audience: &str,
        grant_id: Option<&str>,
        grant_authority: Option<&str>,
        verified_claims: Value,
    ) -> Self {
        let mut context = Self::offline_fixture_context(
            requester_tags,
            evidence_audience,
            grant_id,
            grant_authority,
            verified_claims,
        );
        context.principal = principal.to_owned();
        context
    }
}

impl std::fmt::Debug for AuthenticatedContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedContext")
            .field("principal", &"<redacted>")
            .field("actor", &self.actor.as_ref().map(|_| "<redacted>"))
            .field("requester_tags", &"<redacted>")
            .field("evidence_audience", &self.evidence_audience)
            .field("grant_id", &self.grant_id.as_ref().map(|_| "<redacted>"))
            .field(
                "grant_authority",
                &self.grant_authority.as_ref().map(|_| "<redacted>"),
            )
            .field("verified_claims", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("access token is malformed")]
    Malformed,
    #[error("access token verification failed")]
    Verification,
    #[error("required authenticated context is missing or invalid")]
    Context,
    #[error("access token is bound to a sender proof this profile cannot validate")]
    SenderConstrained,
}

/// RFC 7800 confirmation claim. Its presence means the authorization server
/// issued a token that is only valid when presented with a matching proof of
/// possession, such as DPoP or mutual TLS.
const CONFIRMATION_CLAIM: &str = "cnf";

impl Authenticator {
    /// Build the one strict resource-server profile from the loaded bundle.
    pub fn from_config(config: &AuthenticationConfig) -> Self {
        let algorithms = config
            .algorithms
            .iter()
            .map(|algorithm| match algorithm {
                AccessTokenAlgorithm::EdDSA => jsonwebtoken::Algorithm::EdDSA,
                AccessTokenAlgorithm::ES256 => jsonwebtoken::Algorithm::ES256,
                AccessTokenAlgorithm::RS256 => jsonwebtoken::Algorithm::RS256,
            })
            .collect();
        let token_types = config
            .token_types
            .iter()
            .map(|token_type| match token_type {
                AccessTokenType::AtJwt => "at+jwt".to_owned(),
                AccessTokenType::ApplicationAtJwt => "application/at+jwt".to_owned(),
            })
            .collect();
        let verifier_config = TokenVerifierConfig::access_token_profile(
            config.issuer.clone(),
            config.audiences.clone(),
            algorithms,
            token_types,
        );
        let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            config.jwks_uri.clone(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy {
                allowed_schemes: vec!["https".to_owned()],
                allow_localhost: true,
                allow_http_private_network: false,
                deny_private_ranges: false,
                deny_cloud_metadata: true,
            },
        ));
        let verifier = Arc::new(TokenVerifier::new(verifier_config, fetcher));
        let claims = AuthenticationClaimsConfig {
            principal_claim: config.principal_claim.clone(),
            requester_tags_claim: config.requester_tags_claim.clone(),
            evidence_audience_claim: config.evidence_audience_claim.clone(),
            grant_id_claim: config.grant_id_claim.clone(),
            grant_authority_claim: config.grant_authority_claim.clone(),
            actor_claim: config.actor_claim.clone(),
        };
        Self::new(verifier, claims)
    }

    pub fn new(verifier: Arc<TokenVerifier>, claims: AuthenticationClaimsConfig) -> Self {
        Self { verifier, claims }
    }

    pub async fn authenticate(
        &self,
        access_token: &str,
    ) -> Result<AuthenticatedContext, AuthenticationError> {
        strict_jwt_preflight(access_token)?;
        let verified = self
            .verifier
            .verify(access_token)
            .await
            .map_err(|_| AuthenticationError::Verification)?;
        self.extract_context(verified)
    }

    fn extract_context(
        &self,
        verified: VerifiedToken,
    ) -> Result<AuthenticatedContext, AuthenticationError> {
        let claims =
            serde_json::to_value(verified.claims).map_err(|_| AuthenticationError::Context)?;
        let claims_object = claims.as_object().ok_or(AuthenticationError::Context)?;

        // Version one validates no proof of possession. Treating a
        // sender-constrained token as an ordinary bearer would silently discard
        // the constraint the authorization server issued it under and make a
        // stolen token replayable for its whole lifetime, so the profile denies
        // rather than downgrades.
        if claims_object.contains_key(CONFIRMATION_CLAIM) {
            return Err(AuthenticationError::SenderConstrained);
        }

        let principal = required_direct_string(
            claims_object,
            &self.claims.principal_claim,
            MAX_PRINCIPAL_BYTES,
        )?;
        let evidence_audience = required_direct_string(
            claims_object,
            &self.claims.evidence_audience_claim,
            MAX_PRINCIPAL_BYTES,
        )?;
        url::Url::parse(&evidence_audience).map_err(|_| AuthenticationError::Context)?;
        let requester_tags =
            required_string_array(claims_object, &self.claims.requester_tags_claim, MAX_TAGS)?;
        let actor = self
            .claims
            .actor_claim
            .as_deref()
            .map(|claim| optional_direct_string(claims_object, claim, MAX_PRINCIPAL_BYTES))
            .transpose()?
            .flatten();
        let grant_id = optional_direct_string(
            claims_object,
            &self.claims.grant_id_claim,
            MAX_PRINCIPAL_BYTES,
        )?;
        let grant_authority = optional_direct_string(
            claims_object,
            &self.claims.grant_authority_claim,
            MAX_PRINCIPAL_BYTES,
        )?;
        if grant_id.is_some() != grant_authority.is_some() {
            return Err(AuthenticationError::Context);
        }

        Ok(AuthenticatedContext {
            principal,
            actor,
            requester_tags,
            evidence_audience,
            grant_id,
            grant_authority,
            verified_claims: claims,
        })
    }
}

pub fn strict_jwt_preflight(token: &str) -> Result<(), AuthenticationError> {
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(AuthenticationError::Malformed);
    }
    let mut segments = token.split('.');
    let header = segments.next().ok_or(AuthenticationError::Malformed)?;
    let claims = segments.next().ok_or(AuthenticationError::Malformed)?;
    let signature = segments.next().ok_or(AuthenticationError::Malformed)?;
    if segments.next().is_some() || header.is_empty() || claims.is_empty() || signature.is_empty() {
        return Err(AuthenticationError::Malformed);
    }
    decode_strict_object(header, MAX_HEADER_BYTES)?;
    decode_strict_object(claims, MAX_CLAIMS_BYTES)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| AuthenticationError::Malformed)?;
    if signature.is_empty() || signature.len() > MAX_HEADER_BYTES {
        return Err(AuthenticationError::Malformed);
    }
    Ok(())
}

fn decode_strict_object(segment: &str, maximum: usize) -> Result<(), AuthenticationError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| AuthenticationError::Malformed)?;
    if decoded.is_empty() || decoded.len() > maximum {
        return Err(AuthenticationError::Malformed);
    }
    let value = parse_json_strict(&decoded).map_err(|_| AuthenticationError::Malformed)?;
    if !value.is_object() {
        return Err(AuthenticationError::Malformed);
    }
    Ok(())
}

fn required_direct_string(
    claims: &Map<String, Value>,
    name: &str,
    maximum_bytes: usize,
) -> Result<String, AuthenticationError> {
    optional_direct_string(claims, name, maximum_bytes)?.ok_or(AuthenticationError::Context)
}

fn optional_direct_string(
    claims: &Map<String, Value>,
    name: &str,
    maximum_bytes: usize,
) -> Result<Option<String>, AuthenticationError> {
    let Some(value) = claims.get(name) else {
        return Ok(None);
    };
    let value = value.as_str().ok_or(AuthenticationError::Context)?;
    if value.is_empty() || value.len() > maximum_bytes {
        return Err(AuthenticationError::Context);
    }
    Ok(Some(value.to_owned()))
}

fn required_string_array(
    claims: &Map<String, Value>,
    name: &str,
    maximum_items: usize,
) -> Result<Vec<String>, AuthenticationError> {
    let values = claims
        .get(name)
        .and_then(Value::as_array)
        .ok_or(AuthenticationError::Context)?;
    if values.is_empty() || values.len() > maximum_items {
        return Err(AuthenticationError::Context);
    }
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let value = value.as_str().ok_or(AuthenticationError::Context)?;
        if value.is_empty() || value.len() > MAX_PRINCIPAL_BYTES {
            return Err(AuthenticationError::Context);
        }
        output.push(value.to_owned());
    }
    output.sort();
    output.dedup();
    Ok(output)
}

fn resolve_claim_path<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() || path.len() > 512 {
        return None;
    }
    let mut current = claims;
    for segment in path.split('.') {
        if !valid_claim_path_segment(segment) {
            return None;
        }
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

fn valid_claim_path_segment(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| {
            byte.is_ascii_uppercase()
                || byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(input: &str) -> String {
        URL_SAFE_NO_PAD.encode(input)
    }

    #[test]
    fn strict_preflight_accepts_three_strict_json_segments() {
        let token = format!(
            "{}.{}.{}",
            segment(r#"{"alg":"EdDSA","kid":"key","typ":"at+jwt"}"#),
            segment(r#"{"iss":"https://issuer.invalid","aud":"evidence","exp":2000000000}"#),
            URL_SAFE_NO_PAD.encode([1_u8; 64])
        );
        strict_jwt_preflight(&token).expect("token structure is valid");
    }

    #[test]
    fn strict_preflight_rejects_duplicate_members_and_bad_compact_shape() {
        let duplicate_header = format!(
            "{}.{}.{}",
            segment(r#"{"alg":"EdDSA","alg":"RS256"}"#),
            segment(r#"{"iss":"https://issuer.invalid"}"#),
            URL_SAFE_NO_PAD.encode([1_u8; 64])
        );
        assert!(strict_jwt_preflight(&duplicate_header).is_err());
        for token in ["", "a.b", "a.b.c.d", "a..c", " a.b.c"] {
            assert!(strict_jwt_preflight(token).is_err());
        }
    }

    #[test]
    fn claim_paths_are_exact_and_do_not_fallback() {
        let claims = serde_json::json!({"grant": {"subject-id": "value"}, "sub": "principal"});
        assert_eq!(
            resolve_claim_path(&claims, "grant.subject-id"),
            Some(&Value::String("value".to_string()))
        );
        assert!(resolve_claim_path(&claims, "grant.missing").is_none());
        assert!(resolve_claim_path(&claims, "grant..subject-id").is_none());
    }

    #[test]
    fn authenticated_context_debug_redacts_claim_material() {
        let mut context = AuthenticatedContext::test_context(
            "principal-canary",
            vec!["tag-canary".to_string()],
            "urn:example:audience",
            Some("grant-canary"),
            Some("authority-canary"),
            serde_json::json!({"protected": "claim-canary"}),
        );
        context.actor = Some("actor-canary".to_string());
        let debug = format!("{context:?}");
        for canary in [
            "principal-canary",
            "actor-canary",
            "tag-canary",
            "grant-canary",
            "authority-canary",
            "claim-canary",
        ] {
            assert!(!debug.contains(canary));
        }
    }
}
