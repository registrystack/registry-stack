// SPDX-License-Identifier: Apache-2.0
//! Relay V2 access-token authentication and compiled-operation authorization.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(test)]
use base64::Engine as _;
use http::header::AUTHORIZATION;
use http::HeaderMap;
use registry_platform_authcommon::{parse_bearer_token, validate_compact_access_token};
use registry_platform_oidc::{Audience, TokenVerifier, VerifiedToken};
use serde_json::{Map, Value};
use thiserror::Error;

#[cfg(feature = "tooling")]
use std::collections::BTreeMap;

use crate::model::{CompiledAccess, RowAuthoritySource};

const MAX_DIRECT_CLAIM_BYTES: usize = 512;

/// Verified caller context. Its `Debug` implementation deliberately redacts
/// authority-bearing values.
#[derive(Clone)]
pub struct Principal {
    identifier: String,
    scopes: BTreeSet<String>,
    claims: Value,
}

impl Principal {
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    fn required_direct_string(&self, name: &str) -> Result<&str, AuthenticationError> {
        direct_string(self.claims.as_object(), name).ok_or(AuthenticationError::Claims)
    }

    pub(crate) fn authorization_material(
        &self,
        access: &CompiledAccess,
        authorization: &Authorization,
    ) -> Vec<u8> {
        let mut material = Vec::new();
        material.extend_from_slice(b"registry-relay-v2-authorization-context-v1\0");
        material.extend_from_slice(self.identifier.as_bytes());
        if let CompiledAccess::Protected { scope, purpose, .. } = access {
            material.push(0);
            material.extend_from_slice(scope.as_bytes());
            if let Some(purpose) = purpose {
                material.push(0);
                if let Ok(value) = self.required_direct_string(&purpose.claim) {
                    material.extend_from_slice(value.as_bytes());
                }
            }
        }
        if let Some(row) = &authorization.row_authority {
            material.push(0);
            material.extend_from_slice(row.source_column.as_bytes());
            material.push(0);
            material.extend_from_slice(row.value.as_bytes());
        }
        material
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Principal")
            .field("identifier", &"<redacted>")
            .field("scopes", &self.scopes)
            .field("claims", &"<redacted>")
            .finish()
    }
}

/// A bound authority value injected by Relay into a reviewed SQL plan.
#[derive(Clone, PartialEq, Eq)]
pub struct RowAuthority {
    pub source_column: String,
    pub value: String,
}

impl fmt::Debug for RowAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RowAuthority")
            .field("source_column", &self.source_column)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub row_authority: Option<RowAuthority>,
    pub purpose: Option<String>,
}

#[derive(Clone)]
pub struct RelayAuthenticator {
    verifier: Option<Arc<TokenVerifier>>,
    expected_audience: Option<String>,
    clock_leeway: Duration,
    #[cfg(feature = "tooling")]
    fixtures: BTreeMap<String, Principal>,
}

impl RelayAuthenticator {
    #[must_use]
    pub fn new(
        verifier: Arc<TokenVerifier>,
        expected_audience: String,
        clock_leeway: Duration,
    ) -> Self {
        Self {
            verifier: Some(verifier),
            expected_audience: Some(expected_audience),
            clock_leeway,
            #[cfg(feature = "tooling")]
            fixtures: BTreeMap::new(),
        }
    }

    /// Authoring-tool-only real-router verifier seam. It supplies explicit
    /// synthetic fixture claims to the same principal resolution and
    /// authorization path. Runtime configuration cannot construct this mode.
    #[cfg(feature = "tooling")]
    #[must_use]
    pub(crate) fn for_offline_fixtures(tokens: BTreeMap<String, FixturePrincipal>) -> Self {
        let fixtures = tokens
            .into_iter()
            .map(|(token, item)| {
                (
                    token,
                    Principal {
                        identifier: item.identifier,
                        scopes: item.scopes,
                        claims: item.claims,
                    },
                )
            })
            .collect();
        Self {
            verifier: None,
            expected_audience: None,
            clock_leeway: Duration::ZERO,
            fixtures,
        }
    }

    /// Authenticate one already-extracted bearer token. The platform verifier
    /// enforces signature, issuer, audience, algorithm, key id, token type,
    /// expiration, not-before, and scopes. Relay adds bounded token shape,
    /// issued-at, token-id, and principal selection rules.
    pub async fn authenticate(&self, token: &str) -> Result<Principal, AuthenticationError> {
        strict_token_shape(token)?;
        #[cfg(feature = "tooling")]
        if let Some(principal) = self.fixtures.get(token) {
            return Ok(principal.clone());
        }
        let verified = self
            .verifier
            .as_ref()
            .ok_or(AuthenticationError::Verification)?
            .verify(token)
            .await
            .map_err(|_| AuthenticationError::Verification)?;
        Principal::from_verified(
            verified,
            self.expected_audience
                .as_deref()
                .ok_or(AuthenticationError::Verification)?,
            self.clock_leeway,
        )
    }

    /// Confirm the configured issuer key source can still verify tokens.
    /// Offline fixture authentication is already fully in memory and can only
    /// be constructed by crate-internal authoring tooling.
    pub async fn is_ready(&self) -> bool {
        match &self.verifier {
            Some(verifier) => verifier.key_source().ensure_key_set().await.is_ok(),
            None => true,
        }
    }

    /// Enforce the one compiled access rule. Caller query values and headers
    /// are deliberately absent from this function: only verified token claims
    /// can satisfy purpose and row-binding constraints.
    pub fn authorize(
        &self,
        access: &CompiledAccess,
        principal: Option<&Principal>,
    ) -> Result<Authorization, AuthorizationError> {
        match access {
            CompiledAccess::Public => Ok(Authorization {
                row_authority: None,
                purpose: None,
            }),
            CompiledAccess::Protected {
                scope,
                purpose,
                row_binding,
            } => {
                let principal = principal.ok_or(AuthorizationError::AuthenticationRequired)?;
                if !principal.has_scope(scope) {
                    return Err(AuthorizationError::ScopeDenied);
                }
                let authorized_purpose = if let Some(purpose) = purpose {
                    let value = principal
                        .required_direct_string(&purpose.claim)
                        .map_err(|_| AuthorizationError::PurposeDenied)?;
                    if !purpose.allowed.iter().any(|allowed| allowed == value) {
                        return Err(AuthorizationError::PurposeDenied);
                    }
                    Some(value.to_owned())
                } else {
                    None
                };
                let row_authority = row_binding
                    .as_ref()
                    .map(|binding| {
                        let value = match &binding.source {
                            RowAuthoritySource::Principal => principal.identifier().to_owned(),
                            RowAuthoritySource::Claim(claim) => principal
                                .required_direct_string(claim)
                                .map_err(|_| AuthorizationError::BindingDenied)?
                                .to_owned(),
                        };
                        Ok(RowAuthority {
                            source_column: binding.source_column.clone(),
                            value,
                        })
                    })
                    .transpose()?;
                Ok(Authorization {
                    row_authority,
                    purpose: authorized_purpose,
                })
            }
        }
    }
}

#[derive(Clone, Debug)]
#[cfg(feature = "tooling")]
pub(crate) struct FixturePrincipal {
    pub identifier: String,
    pub scopes: BTreeSet<String>,
    pub claims: Value,
}

impl Principal {
    fn from_verified(
        verified: VerifiedToken,
        expected_audience: &str,
        clock_leeway: Duration,
    ) -> Result<Self, AuthenticationError> {
        let VerifiedToken { claims, scopes, .. } = verified;
        if !matches!(
            claims.aud.as_ref(),
            Some(Audience::One(audience)) if audience == expected_audience
        ) {
            return Err(AuthenticationError::Claims);
        }
        let claims = serde_json::to_value(claims).map_err(|_| AuthenticationError::Claims)?;
        let object = claims.as_object().ok_or(AuthenticationError::Claims)?;
        let issued_at = object
            .get("iat")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .ok_or(AuthenticationError::Claims)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .ok_or(AuthenticationError::Claims)?;
        let leeway = i64::try_from(clock_leeway.as_secs()).unwrap_or(i64::MAX);
        if issued_at > now.saturating_add(leeway) {
            return Err(AuthenticationError::Claims);
        }
        let not_before = object
            .get("nbf")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .ok_or(AuthenticationError::Claims)?;
        let _ = not_before;
        let _jti = direct_string(Some(object), "jti").ok_or(AuthenticationError::Claims)?;
        let identifier = strict_principal_identifier(object)?;
        let scopes = scopes.into_iter().collect();
        Ok(Self {
            identifier,
            scopes,
            claims,
        })
    }
}

/// Resolve a principal without silently skipping a malformed higher-priority
/// identity claim. This prevents an issuer's `sub` from being bypassed by an
/// attacker-controlled fallback claim.
fn strict_principal_identifier(claims: &Map<String, Value>) -> Result<String, AuthenticationError> {
    for name in ["sub", "client_id", "azp"] {
        if let Some(value) = claims.get(name) {
            return direct_string_value(value)
                .map(str::to_owned)
                .ok_or(AuthenticationError::Claims);
        }
    }
    Err(AuthenticationError::Claims)
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AuthenticationError {
    #[error("access token is malformed")]
    Malformed,
    #[error("access token verification failed")]
    Verification,
    #[error("required access token claim is invalid")]
    Claims,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("authentication is required")]
    AuthenticationRequired,
    #[error("required scope is absent")]
    ScopeDenied,
    #[error("required purpose is absent")]
    PurposeDenied,
    #[error("authority binding is absent")]
    BindingDenied,
}

/// Stable refusal classes shared by data-plane adapters. Scope denial remains
/// concealed, while purpose and row-binding failures are explicit denials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationRefusalClass {
    MissingCredential,
    ConcealedScopeDenial,
    ExplicitDenial,
}

impl AuthorizationError {
    #[must_use]
    pub fn refusal_class(self) -> AuthorizationRefusalClass {
        match self {
            Self::AuthenticationRequired => AuthorizationRefusalClass::MissingCredential,
            Self::ScopeDenied => AuthorizationRefusalClass::ConcealedScopeDenial,
            Self::PurposeDenied | Self::BindingDenied => AuthorizationRefusalClass::ExplicitDenial,
        }
    }
}

/// Extract exactly one RFC 6750 Bearer credential. An invalid Authorization
/// header is never interpreted as anonymous access, including on public
/// operations and cacheable metadata routes.
pub fn bearer_token(headers: &HeaderMap) -> Result<Option<&str>, AuthenticationError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AuthenticationError::Malformed);
    }
    let value = first.to_str().map_err(|_| AuthenticationError::Malformed)?;
    let token = parse_bearer_token(value).map_err(|_| AuthenticationError::Malformed)?;
    Ok(Some(token))
}

fn strict_token_shape(token: &str) -> Result<(), AuthenticationError> {
    validate_compact_access_token(token).map_err(|_| AuthenticationError::Malformed)
}

fn direct_string<'a>(claims: Option<&'a Map<String, Value>>, name: &str) -> Option<&'a str> {
    direct_string_value(claims?.get(name)?)
}

fn direct_string_value(value: &Value) -> Option<&str> {
    let value = value.as_str()?;
    (!value.is_empty() && value.len() <= MAX_DIRECT_CLAIM_BYTES).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_oidc::Claims;

    #[test]
    fn malformed_jwt_shape_is_rejected_before_verification() {
        assert_eq!(strict_token_shape(""), Err(AuthenticationError::Malformed));
        assert_eq!(
            strict_token_shape("a.b"),
            Err(AuthenticationError::Malformed)
        );
        assert_eq!(
            strict_token_shape("a.b.c.d"),
            Err(AuthenticationError::Malformed)
        );
    }

    #[test]
    fn duplicate_json_members_are_rejected_recursively() {
        let encode = |value: &[u8]| URL_SAFE_NO_PAD.encode(value);
        let signature = encode(b"signature");
        for header in [
            br#"{"alg":"EdDSA","alg":"none","typ":"at+jwt","kid":"key"}"#.as_slice(),
            br#"{"alg":"EdDSA","typ":"at+jwt","kid":"one","kid":"two"}"#.as_slice(),
        ] {
            let token = format!(
                "{}.{}.{}",
                encode(header),
                encode(br#"{"iss":"issuer"}"#),
                signature
            );
            assert_eq!(
                strict_token_shape(&token),
                Err(AuthenticationError::Malformed)
            );
        }
        for claims in [
            br#"{"jti":"one","jti":"two"}"#.as_slice(),
            br#"{"iss":"one","iss":"two"}"#.as_slice(),
            br#"{"scope":"read","scope":"write"}"#.as_slice(),
            br#"{"authority":{"region":"one","region":"two"}}"#.as_slice(),
        ] {
            let token = format!(
                "{}.{}.{}",
                encode(br#"{"alg":"EdDSA","typ":"at+jwt","kid":"key"}"#),
                encode(claims),
                signature
            );
            assert_eq!(
                strict_token_shape(&token),
                Err(AuthenticationError::Malformed)
            );
        }
    }

    #[test]
    fn direct_string_rejects_empty_or_structured_claims() {
        let claims = serde_json::json!({"subject": "", "object": {"id": "x"}});
        let object = claims.as_object();
        assert!(direct_string(object, "subject").is_none());
        assert!(direct_string(object, "object").is_none());
    }

    #[test]
    fn malformed_subject_cannot_fall_back_to_client_identifier() {
        let claims = serde_json::json!({"sub": [], "client_id": "client-a"});
        assert_eq!(
            strict_principal_identifier(claims.as_object().expect("object")),
            Err(AuthenticationError::Claims)
        );
    }

    #[test]
    fn malformed_authorization_is_never_anonymous() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Basic abc".parse().expect("header"));
        assert_eq!(bearer_token(&headers), Err(AuthenticationError::Malformed));
    }

    #[test]
    fn bearer_scheme_is_ascii_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "bEaReR abc".parse().expect("header"));
        assert_eq!(bearer_token(&headers), Ok(Some("abc")));
    }

    #[test]
    fn verified_token_must_contain_not_before() {
        let claims: Claims = serde_json::from_value(serde_json::json!({
            "sub": "caller",
            "iat": 1,
            "jti": "token-1"
        }))
        .expect("claims parse");
        let verified = VerifiedToken {
            claims,
            matched_client: None,
            scopes: Vec::new(),
        };
        assert!(matches!(
            Principal::from_verified(verified, "relay", Duration::ZERO),
            Err(AuthenticationError::Claims)
        ));
    }
}
