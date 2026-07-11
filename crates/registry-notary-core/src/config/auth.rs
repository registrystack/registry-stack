// SPDX-License-Identifier: Apache-2.0
//! Caller authentication and token-signing configuration.

use super::*;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryNotaryCorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuthConfig {
    #[serde(default)]
    pub mode: EvidenceAuthMode,
    #[serde(default)]
    pub api_keys: Vec<EvidenceCredentialConfig>,
    #[serde(default)]
    pub bearer_tokens: Vec<EvidenceCredentialConfig>,
    #[serde(default)]
    pub oidc: Option<EvidenceOidcAuthConfig>,
    /// Trust anchor for Notary-minted access tokens (the pre-authorized-code
    /// flow's second verifier). Disabled by default so existing configs load
    /// unchanged.
    #[serde(default)]
    pub access_token_signing: AccessTokenSigningConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAuthMode {
    #[default]
    ApiKey,
    Oidc,
}

impl EvidenceAuthMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::Oidc => "oidc",
        }
    }
}

/// Self-issued access-token signing configuration.
///
/// When `enabled`, the Notary mints its own access tokens (for the
/// pre-authorized-code flow) signed with a dedicated `signing_keys` entry that
/// MUST be distinct from any credential-signing key. The minted token's
/// `iss`/`aud`/`typ`/alg pin the second verifier's trust anchor.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessTokenSigningConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Issuer (`iss`) the Notary stamps into its own access tokens.
    #[serde(default)]
    pub issuer: String,
    /// Audiences (`aud`) accepted for Notary-minted access tokens.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// Allowed signing algorithms. Only EdDSA is supported.
    #[serde(default = "default_access_token_signing_algorithms")]
    pub allowed_algorithms: Vec<String>,
    /// Header `typ` stamped into Notary access tokens, distinct from the
    /// credential `typ` so a token cannot be replayed as another class.
    #[serde(default = "default_access_token_typ")]
    pub token_typ: String,
    /// `evidence.signing_keys` entry used to sign access tokens. Must be a
    /// dedicated key, never a credential-signing key.
    #[serde(default)]
    pub signing_key_id: String,
    /// Additional publish-only `evidence.signing_keys` entries accepted for
    /// verifying previously minted Notary access tokens and pre-authorized
    /// codes during a governed key rotation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_key_ids: Vec<String>,
    /// Access-token lifetime in seconds.
    #[serde(default = "default_access_token_ttl_seconds")]
    pub access_token_ttl_seconds: u64,
}

impl Default for AccessTokenSigningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: String::new(),
            audiences: Vec::new(),
            allowed_algorithms: default_access_token_signing_algorithms(),
            token_typ: default_access_token_typ(),
            signing_key_id: String::new(),
            verification_key_ids: Vec::new(),
            access_token_ttl_seconds: default_access_token_ttl_seconds(),
        }
    }
}

pub(super) fn default_access_token_signing_algorithms() -> Vec<String> {
    vec![CREDENTIAL_SIGNING_ALG_EDDSA.to_string()]
}

pub(super) fn default_access_token_typ() -> String {
    "registry-notary-access+jwt".to_string()
}

pub(super) const fn default_access_token_ttl_seconds() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCredentialConfig {
    pub id: String,
    pub fingerprint: CredentialFingerprintRef,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<EvidenceAuthorizationDetails>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceOidcAuthConfig {
    pub issuer: String,
    pub jwks_url: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub userinfo_issuers: Vec<String>,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    #[serde(default = "default_oidc_allowed_algorithms")]
    pub allowed_algorithms: Vec<String>,
    #[serde(default = "default_oidc_allowed_token_types")]
    pub allowed_token_types: Vec<String>,
    #[serde(default = "default_oidc_scope_claim")]
    pub scope_claim: String,
    #[serde(default = "default_oidc_scope_separator")]
    pub scope_separator: String,
    #[serde(default)]
    pub scope_map: BTreeMap<String, Vec<String>>,
    #[serde(default = "default_oidc_principal_claim")]
    pub principal_claim: String,
    #[serde(default = "default_oidc_leeway", with = "humantime_serde")]
    pub leeway: Duration,
    #[serde(default)]
    pub allow_insecure_localhost: bool,
}

pub(super) fn default_oidc_allowed_algorithms() -> Vec<String> {
    vec![SD_JWT_VC_SIGNING_ALG.to_string()]
}

pub(super) fn default_oidc_allowed_token_types() -> Vec<String> {
    vec!["JWT".to_string()]
}

pub(super) fn default_oidc_scope_claim() -> String {
    "scope".to_string()
}

pub(super) fn default_oidc_scope_separator() -> String {
    " ".to_string()
}

pub(super) fn default_oidc_principal_claim() -> String {
    "sub".to_string()
}

pub(super) fn default_oidc_leeway() -> Duration {
    Duration::from_secs(60)
}

impl EvidenceOidcAuthConfig {
    pub(super) fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.issuer.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "issuer must not be empty".to_string(),
            });
        }
        if self.jwks_url.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "jwks_url must not be empty".to_string(),
            });
        }
        validate_jwks_url_transport(&self.jwks_url, self.allow_insecure_localhost)?;
        if let Some(userinfo_endpoint) = self.userinfo_endpoint.as_deref() {
            if userinfo_endpoint.trim().is_empty() {
                return Err(EvidenceConfigError::InvalidOidcConfig {
                    reason: "userinfo_endpoint must not be empty when configured".to_string(),
                });
            }
            validate_jwks_url_transport(userinfo_endpoint, self.allow_insecure_localhost)?;
        }
        validate_entries("auth.oidc.userinfo_issuers", &self.userinfo_issuers)?;
        if self.audiences.is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "audiences must list at least one accepted audience".to_string(),
            });
        }
        if self.scope_separator.chars().count() != 1 {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "scope_separator must be exactly one character".to_string(),
            });
        }
        if self.principal_claim.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "principal_claim must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

pub(super) fn validate_jwks_url_transport(
    jwks_url: &str,
    allow_insecure_localhost: bool,
) -> Result<(), EvidenceConfigError> {
    let jwks_url = jwks_url.trim();
    if jwks_url.starts_with("https://")
        || (allow_insecure_localhost && is_insecure_localhost_url(jwks_url))
    {
        return Ok(());
    }
    Err(EvidenceConfigError::InvalidOidcConfig {
        reason:
            "jwks_url must use https unless allow_insecure_localhost permits an http localhost URL"
                .to_string(),
    })
}

pub(super) fn is_insecure_localhost_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    let host = if let Some(after_bracket) = authority.strip_prefix('[') {
        after_bracket.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}
