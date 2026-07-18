// SPDX-License-Identifier: Apache-2.0
//! OpenID4VCI issuer configuration.

use super::*;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub credential_issuer: String,
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    #[serde(default)]
    pub accepted_token_audiences: Vec<String>,
    #[serde(default)]
    pub credential_endpoint: String,
    #[serde(default)]
    pub offer_endpoint: String,
    #[serde(default)]
    pub nonce_endpoint: Option<String>,
    #[serde(default)]
    pub nonce: Oid4vciNonceConfig,
    #[serde(default)]
    pub authorization: Oid4vciAuthorizationConfig,
    #[serde(default)]
    pub proof: Oid4vciProofConfig,
    /// Pre-authorized-code flow settings. Disabled by default; offers fall
    /// back to the `authorization_code` grant unless this is enabled.
    #[serde(default)]
    pub pre_authorized_code: Oid4vciPreAuthorizedCodeConfig,
    #[serde(default)]
    pub display: Vec<Oid4vciIssuerDisplayConfig>,
    #[serde(default)]
    pub credential_configurations: BTreeMap<String, Oid4vciCredentialConfigurationConfig>,
}

pub(super) fn oid4vci_config_is_default(config: &Oid4vciConfig) -> bool {
    config == &Oid4vciConfig::default()
}

impl Oid4vciConfig {
    pub(super) fn validate(
        &self,
        subject_access: &SubjectAccessConfig,
        evidence: &EvidenceConfig,
    ) -> Result<(), EvidenceConfigError> {
        // The pre-authorized-code block is validated regardless of the oid4vci
        // enable toggle so a partially-configured flow is rejected, but the
        // flow is an OID4VCI grant and so requires oid4vci itself enabled.
        if self.pre_authorized_code.enabled && !self.enabled {
            return invalid_oid4vci(
                "pre_authorized_code.enabled = true requires oid4vci.enabled = true",
            );
        }
        self.pre_authorized_code.validate()?;
        // The eSignet RP client assertion is signed with this key, so it must
        // resolve to an active signing key. Surface that at config time rather
        // than as a startup failure when the pre-auth flow is first built.
        if self.pre_authorized_code.enabled {
            let key_id = self
                .pre_authorized_code
                .esignet
                .client_signing_key_id
                .as_str();
            let key = evidence.signing_keys.get(key_id).ok_or_else(|| {
                EvidenceConfigError::InvalidOid4vciConfig {
                    reason: format!(
                        "pre_authorized_code.esignet.client_signing_key_id '{key_id}' must reference an evidence.signing_keys entry"
                    ),
                }
            })?;
            if !key.status.may_sign() {
                return invalid_oid4vci(format!(
                    "pre_authorized_code.esignet.client_signing_key_id '{key_id}' must reference an active signing key"
                ));
            }
        }
        // The pre-auth callback resolves the subject-binding claim from the
        // eSignet userinfo endpoint when the claim is userinfo-sourced, so the
        // endpoint must be configured for that path to work.
        if self.pre_authorized_code.enabled
            && subject_access.subject_binding.claim_source == SubjectAccessClaimSource::Userinfo
            && self
                .pre_authorized_code
                .esignet
                .userinfo_url
                .trim()
                .is_empty()
        {
            return invalid_oid4vci(
                "pre_authorized_code.esignet.userinfo_url must be set when subject_access.subject_binding.claim_source = userinfo",
            );
        }
        if self.pre_authorized_code.enabled
            && self.pre_authorized_code.tx_code.required
            && subject_access
                .rate_limits
                .tx_code_attempts_per_code_per_minute
                == 0
        {
            return invalid_oid4vci(
                "subject_access.rate_limits.tx_code_attempts_per_code_per_minute must be greater than zero when pre_authorized_code.enabled = true and tx_code.required = true",
            );
        }
        if !self.enabled {
            return Ok(());
        }
        if !subject_access.enabled {
            return invalid_oid4vci("enabled oid4vci requires subject_access.enabled = true");
        }
        validate_oid4vci_public_url("oid4vci.credential_issuer", &self.credential_issuer)?;
        validate_oid4vci_endpoint_url(
            "oid4vci.credential_endpoint",
            &self.credential_endpoint,
            &self.credential_issuer,
        )?;
        validate_oid4vci_endpoint_url(
            "oid4vci.offer_endpoint",
            &self.offer_endpoint,
            &self.credential_issuer,
        )?;
        validate_oid4vci_non_empty_entries(
            "oid4vci.authorization_servers",
            &self.authorization_servers,
        )?;
        for server in &self.authorization_servers {
            validate_oid4vci_public_url("oid4vci.authorization_servers", server)?;
        }
        validate_oid4vci_non_empty_entries(
            "oid4vci.accepted_token_audiences",
            &self.accepted_token_audiences,
        )?;
        if self.credential_configurations.is_empty() {
            return invalid_oid4vci("credential_configurations must not be empty");
        }
        if self.nonce.enabled {
            let nonce_endpoint = self.nonce_endpoint.as_deref().ok_or_else(|| {
                EvidenceConfigError::InvalidOid4vciConfig {
                    reason: "nonce_endpoint must be configured when nonce.enabled = true"
                        .to_string(),
                }
            })?;
            validate_oid4vci_endpoint_url(
                "oid4vci.nonce_endpoint",
                nonce_endpoint,
                &self.credential_issuer,
            )?;
        } else if let Some(nonce_endpoint) = self.nonce_endpoint.as_deref() {
            validate_oid4vci_endpoint_url(
                "oid4vci.nonce_endpoint",
                nonce_endpoint,
                &self.credential_issuer,
            )?;
        }
        self.nonce.validate()?;
        self.authorization.validate()?;
        self.proof.validate()?;
        for display in &self.display {
            display.validate("oid4vci.display")?;
        }

        let claim_ids: HashSet<&str> = evidence
            .claims
            .iter()
            .map(|claim| claim.id.as_str())
            .collect();
        let allowed_claim_ids: HashSet<&str> = subject_access
            .allowed_claims
            .iter()
            .map(String::as_str)
            .collect();
        let allowed_profiles: HashSet<&str> = subject_access
            .credential_profiles
            .iter()
            .map(String::as_str)
            .collect();

        let mut configured_vcts = HashSet::new();
        for (configuration_id, configuration) in &self.credential_configurations {
            configuration.validate(
                configuration_id,
                &self.credential_issuer,
                evidence,
                &claim_ids,
                &allowed_claim_ids,
                &allowed_profiles,
            )?;
            if !configured_vcts.insert(configuration.vct.as_str()) {
                return invalid_oid4vci(format!(
                    "credential configuration '{configuration_id}' vct must be unique"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciNonceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_oid4vci_nonce_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl Default for Oid4vciNonceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_seconds: default_oid4vci_nonce_ttl_seconds(),
        }
    }
}

impl Oid4vciNonceConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.ttl_seconds == 0 || self.ttl_seconds > 600 {
            return invalid_oid4vci("nonce.ttl_seconds must be between 1 and 600");
        }
        Ok(())
    }
}

pub(super) const fn default_oid4vci_nonce_ttl_seconds() -> u64 {
    300
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciAuthorizationConfig {
    #[serde(default = "default_oid4vci_pkce_method")]
    pub require_pkce_method: String,
}

impl Default for Oid4vciAuthorizationConfig {
    fn default() -> Self {
        Self {
            require_pkce_method: default_oid4vci_pkce_method(),
        }
    }
}

impl Oid4vciAuthorizationConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.require_pkce_method != PKCE_METHOD_S256 {
            return invalid_oid4vci("authorization.require_pkce_method must be S256");
        }
        Ok(())
    }
}

pub(super) fn default_oid4vci_pkce_method() -> String {
    PKCE_METHOD_S256.to_string()
}

/// Pre-authorized-code flow configuration.
///
/// All fields default so existing configs that omit this block load unchanged
/// with the flow disabled. When `enabled`, the eSignet RP login settings, the
/// callback redirect, and the TTLs become required (validated cross-block).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciPreAuthorizedCodeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub tx_code: Oid4vciTxCodeConfig,
    /// eSignet RP settings for the citizen login leg.
    #[serde(default)]
    pub esignet: Oid4vciEsignetRpConfig,
    /// Pre-authorized-code lifetime in seconds.
    #[serde(default = "default_pre_authorized_code_ttl_seconds")]
    pub pre_authorized_code_ttl_seconds: u64,
}

impl Default for Oid4vciPreAuthorizedCodeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tx_code: Oid4vciTxCodeConfig::default(),
            esignet: Oid4vciEsignetRpConfig::default(),
            pre_authorized_code_ttl_seconds: default_pre_authorized_code_ttl_seconds(),
        }
    }
}

impl Oid4vciPreAuthorizedCodeConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if !self.enabled {
            return Ok(());
        }
        self.tx_code.validate()?;
        self.esignet.validate()?;
        if self.pre_authorized_code_ttl_seconds == 0 || self.pre_authorized_code_ttl_seconds > 600 {
            return invalid_oid4vci(
                "pre_authorized_code.pre_authorized_code_ttl_seconds must be between 1 and 600",
            );
        }
        if !self.tx_code.required
            && self.pre_authorized_code_ttl_seconds > MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS
        {
            return invalid_oid4vci(
                "pre_authorized_code.pre_authorized_code_ttl_seconds must be between 1 and 300 when pre_authorized_code.tx_code.required = false",
            );
        }
        Ok(())
    }
}

pub const MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS: u64 = 300;

pub(super) const fn default_pre_authorized_code_ttl_seconds() -> u64 {
    300
}

/// `tx_code` (PIN) policy for the pre-authorized-code grant. A `tx_code` is
/// required by default because a code without a PIN is a bearer credential.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciTxCodeConfig {
    #[serde(default = "default_tx_code_required")]
    pub required: bool,
    #[serde(default = "default_tx_code_input_mode")]
    pub input_mode: String,
    #[serde(default = "default_tx_code_length")]
    pub length: u64,
}

impl Default for Oid4vciTxCodeConfig {
    fn default() -> Self {
        Self {
            required: default_tx_code_required(),
            input_mode: default_tx_code_input_mode(),
            length: default_tx_code_length(),
        }
    }
}

impl Oid4vciTxCodeConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if !self.required {
            return Ok(());
        }
        if self.input_mode != TX_CODE_INPUT_MODE_NUMERIC {
            return invalid_oid4vci("pre_authorized_code.tx_code.input_mode must be numeric");
        }
        if !(4..=12).contains(&self.length) {
            return invalid_oid4vci("pre_authorized_code.tx_code.length must be between 4 and 12");
        }
        Ok(())
    }
}

pub(super) const fn default_tx_code_required() -> bool {
    true
}

pub(super) fn default_tx_code_input_mode() -> String {
    TX_CODE_INPUT_MODE_NUMERIC.to_string()
}

pub(super) const fn default_tx_code_length() -> u64 {
    6
}

/// eSignet relying-party settings for the citizen login leg of the
/// pre-authorized-code flow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciEsignetRpConfig {
    /// Confidential client id the Notary presents to eSignet.
    #[serde(default)]
    pub client_id: String,
    /// `evidence.signing_keys` entry used to sign the eSignet
    /// `private_key_jwt` client assertion.
    #[serde(default)]
    pub client_signing_key_id: String,
    /// Notary callback the citizen browser is redirected back to.
    #[serde(default)]
    pub redirect_uri: String,
    /// eSignet authorize endpoint.
    #[serde(default)]
    pub authorize_url: String,
    /// eSignet token endpoint.
    #[serde(default)]
    pub token_url: String,
    /// eSignet OIDC issuer, pinned when validating the returned `id_token`.
    #[serde(default)]
    pub issuer: String,
    /// eSignet JWKS URI, used to resolve the `id_token` signing key by `kid`.
    #[serde(default)]
    pub jwks_uri: String,
    /// eSignet userinfo endpoint. Required when the subject-binding claim is
    /// sourced from userinfo rather than the `id_token`; the callback fetches
    /// the userinfo JWS with the eSignet access token and reads the binding
    /// claim from it.
    #[serde(default)]
    pub userinfo_url: String,
    /// OAuth scopes requested at eSignet.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Lifetime of the short-lived login state (PKCE verifier + nonce +
    /// selection) reserved between `offer/start` and `offer/callback`.
    #[serde(default = "default_login_state_ttl_seconds")]
    pub login_state_ttl_seconds: u64,
    /// Allow `http` loopback URLs for the eSignet endpoints and JWKS transport.
    /// For local development and tests only.
    #[serde(default)]
    pub allow_insecure_localhost: bool,
}

impl Oid4vciEsignetRpConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.client_id.trim().is_empty() {
            return invalid_oid4vci("pre_authorized_code.esignet.client_id must not be empty");
        }
        if self.client_signing_key_id.trim().is_empty() {
            return invalid_oid4vci(
                "pre_authorized_code.esignet.client_signing_key_id must not be empty",
            );
        }
        validate_oid4vci_public_url(
            "pre_authorized_code.esignet.redirect_uri",
            &self.redirect_uri,
        )?;
        validate_oid4vci_public_url(
            "pre_authorized_code.esignet.authorize_url",
            &self.authorize_url,
        )?;
        validate_oid4vci_public_url("pre_authorized_code.esignet.token_url", &self.token_url)?;
        validate_oid4vci_public_url("pre_authorized_code.esignet.issuer", &self.issuer)?;
        validate_oid4vci_public_url("pre_authorized_code.esignet.jwks_uri", &self.jwks_uri)?;
        if !self.userinfo_url.trim().is_empty() {
            validate_oid4vci_public_url(
                "pre_authorized_code.esignet.userinfo_url",
                &self.userinfo_url,
            )?;
        }
        validate_oid4vci_non_empty_entries("pre_authorized_code.esignet.scopes", &self.scopes)?;
        if self.login_state_ttl_seconds == 0 || self.login_state_ttl_seconds > 600 {
            return invalid_oid4vci(
                "pre_authorized_code.esignet.login_state_ttl_seconds must be between 1 and 600",
            );
        }
        Ok(())
    }
}

pub(super) const fn default_login_state_ttl_seconds() -> u64 {
    300
}

const TX_CODE_INPUT_MODE_NUMERIC: &str = "numeric";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciProofConfig {
    #[serde(default = "default_oid4vci_proof_max_age_seconds")]
    pub max_age_seconds: u64,
    #[serde(default = "default_oid4vci_proof_max_clock_skew_seconds")]
    pub max_clock_skew_seconds: u64,
}

impl Default for Oid4vciProofConfig {
    fn default() -> Self {
        Self {
            max_age_seconds: default_oid4vci_proof_max_age_seconds(),
            max_clock_skew_seconds: default_oid4vci_proof_max_clock_skew_seconds(),
        }
    }
}

impl Oid4vciProofConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.max_age_seconds == 0 || self.max_age_seconds > 600 {
            return invalid_oid4vci("proof.max_age_seconds must be between 1 and 600");
        }
        if self.max_clock_skew_seconds > 60 {
            return invalid_oid4vci("proof.max_clock_skew_seconds must be at most 60");
        }
        Ok(())
    }
}

pub(super) const fn default_oid4vci_proof_max_age_seconds() -> u64 {
    300
}

pub(super) const fn default_oid4vci_proof_max_clock_skew_seconds() -> u64 {
    60
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciCredentialConfigurationConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Oid4vciCredentialClaimConfig>,
    pub credential_profile: String,
    pub format: String,
    pub scope: String,
    pub vct: String,
    pub display_name: String,
    #[serde(default)]
    pub display: Oid4vciCredentialDisplayConfig,
    #[serde(default = "default_oid4vci_proof_signing_alg_values_supported")]
    pub proof_signing_alg_values_supported: Vec<String>,
    #[serde(default = "default_oid4vci_cryptographic_binding_methods_supported")]
    pub cryptographic_binding_methods_supported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciCredentialClaimConfig {
    pub id: String,
    pub output_path: Vec<String>,
    pub display_name: String,
    pub sd: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Oid4vciCredentialClaimMode<'a> {
    LegacyClaimWrapper {
        claim_id: &'a str,
    },
    FieldProjection {
        entries: &'a [Oid4vciCredentialClaimConfig],
    },
}

impl Oid4vciCredentialClaimMode<'_> {
    #[must_use]
    pub fn is_field_projection(&self) -> bool {
        matches!(self, Self::FieldProjection { .. })
    }
}

impl Oid4vciCredentialConfigurationConfig {
    #[must_use]
    pub fn credential_claim_mode(&self) -> Oid4vciCredentialClaimMode<'_> {
        if let Some(claim_id) = self.claim_id.as_deref() {
            Oid4vciCredentialClaimMode::LegacyClaimWrapper { claim_id }
        } else {
            Oid4vciCredentialClaimMode::FieldProjection {
                entries: &self.claims,
            }
        }
    }

    #[must_use]
    pub fn credential_claim_ids(&self) -> Vec<String> {
        match self.credential_claim_mode() {
            Oid4vciCredentialClaimMode::LegacyClaimWrapper { claim_id } => {
                vec![claim_id.to_string()]
            }
            Oid4vciCredentialClaimMode::FieldProjection { entries } => {
                entries.iter().map(|entry| entry.id.clone()).collect()
            }
        }
    }

    fn validate(
        &self,
        configuration_id: &str,
        credential_issuer: &str,
        evidence: &EvidenceConfig,
        claim_ids: &HashSet<&str>,
        allowed_claim_ids: &HashSet<&str>,
        allowed_profiles: &HashSet<&str>,
    ) -> Result<(), EvidenceConfigError> {
        if configuration_id.trim().is_empty() {
            return invalid_oid4vci("credential_configurations must not contain a blank id");
        }
        let claim_mode = self.validate_claim_mode(configuration_id)?;
        validate_oid4vci_non_empty_value(
            "credential_configurations.credential_profile",
            &self.credential_profile,
        )?;
        validate_oid4vci_non_empty_value("credential_configurations.scope", &self.scope)?;
        validate_oid4vci_non_empty_value(
            "credential_configurations.display_name",
            &self.display_name,
        )?;
        self.display.validate("credential_configurations.display")?;
        let profile = evidence
            .credential_profiles
            .get(&self.credential_profile)
            .ok_or_else(|| EvidenceConfigError::InvalidOid4vciConfig {
                reason: format!(
                    "credential configuration '{configuration_id}' references unknown credential profile '{}'",
                    self.credential_profile
                ),
            })?;
        if !allowed_profiles.contains(self.credential_profile.as_str()) {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' references credential profile '{}' outside subject_access.credential_profiles",
                self.credential_profile
            ));
        }
        if self.format != OID4VCI_SD_JWT_VC_FORMAT {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' format must be dc+sd-jwt"
            ));
        }
        if profile.format != FORMAT_SD_JWT_VC {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' references credential profile '{}' with unsupported format '{}'",
                self.credential_profile, profile.format
            ));
        }
        let mut projection_purpose = None;
        for claim_id in self.credential_claim_ids() {
            let claim = validate_oid4vci_credential_claim_reference(
                configuration_id,
                &claim_id,
                &self.credential_profile,
                evidence,
                profile,
                claim_ids,
                allowed_claim_ids,
            )?;
            if claim_mode.is_field_projection() {
                let purpose = claim.purpose.as_deref().ok_or_else(|| {
                    EvidenceConfigError::InvalidOid4vciConfig {
                        reason: format!(
                            "credential configuration '{configuration_id}' field projection claim '{claim_id}' must define purpose"
                        ),
                    }
                })?;
                if let Some(previous) = projection_purpose {
                    if previous != purpose {
                        return invalid_oid4vci(format!(
                            "credential configuration '{configuration_id}' field projection claims must share one purpose"
                        ));
                    }
                } else {
                    projection_purpose = Some(purpose);
                }
                if claim.disclosure.default != "value" {
                    return invalid_oid4vci(format!(
                        "credential configuration '{configuration_id}' field projection claim '{claim_id}' must use value as the default disclosure"
                    ));
                }
            }
        }
        if self.vct != profile.vct {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' vct must match credential profile '{}'",
                self.credential_profile
            ));
        }
        validate_oid4vci_public_url("credential_configurations.vct", &self.vct)?;
        validate_oid4vci_endpoint_url(
            "credential_configurations.vct",
            &self.vct,
            credential_issuer,
        )?;
        let Some((_, _, vct_path)) = split_absolute_url(&self.vct) else {
            return invalid_oid4vci("credential_configurations.vct must be an absolute URL");
        };
        let Some(expected_vct_prefix) = oid4vci_credentials_path_prefix(credential_issuer) else {
            return invalid_oid4vci("oid4vci.credential_issuer must be an absolute URL");
        };
        if !vct_path.starts_with(&expected_vct_prefix) {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' vct path must start with {expected_vct_prefix}"
            ));
        }
        validate_oid4vci_non_empty_entries(
            "credential_configurations.proof_signing_alg_values_supported",
            &self.proof_signing_alg_values_supported,
        )?;
        for alg in &self.proof_signing_alg_values_supported {
            if alg != CREDENTIAL_SIGNING_ALG_EDDSA {
                return invalid_oid4vci(format!(
                    "credential configuration '{configuration_id}' supports unsupported proof signing algorithm '{alg}'"
                ));
            }
        }
        validate_oid4vci_non_empty_entries(
            "credential_configurations.cryptographic_binding_methods_supported",
            &self.cryptographic_binding_methods_supported,
        )?;
        for method in &self.cryptographic_binding_methods_supported {
            if method != CRYPTOGRAPHIC_BINDING_METHOD_DID_JWK {
                return invalid_oid4vci(format!(
                    "credential configuration '{configuration_id}' supports unsupported binding method '{method}'"
                ));
            }
        }
        Ok(())
    }

    fn validate_claim_mode(
        &self,
        configuration_id: &str,
    ) -> Result<Oid4vciCredentialClaimMode<'_>, EvidenceConfigError> {
        match (self.claim_id.as_deref(), self.claims.is_empty()) {
            (Some(claim_id), true) => {
                validate_oid4vci_non_empty_value("credential_configurations.claim_id", claim_id)?;
                Ok(Oid4vciCredentialClaimMode::LegacyClaimWrapper { claim_id })
            }
            (None, false) => {
                validate_oid4vci_projection_claims(configuration_id, &self.claims)?;
                Ok(Oid4vciCredentialClaimMode::FieldProjection {
                    entries: &self.claims,
                })
            }
            (Some(_), false) => invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' must set exactly one of claim_id or claims"
            )),
            (None, true) => invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' must set exactly one of claim_id or claims"
            )),
        }
    }
}

pub(super) fn validate_oid4vci_projection_claims(
    configuration_id: &str,
    claims: &[Oid4vciCredentialClaimConfig],
) -> Result<(), EvidenceConfigError> {
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for claim in claims {
        validate_oid4vci_non_empty_value("credential_configurations.claims[].id", &claim.id)?;
        if !ids.insert(claim.id.as_str()) {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' contains duplicate claims[].id"
            ));
        }
        validate_oid4vci_non_empty_value(
            "credential_configurations.claims[].display_name",
            &claim.display_name,
        )?;
        validate_oid4vci_non_empty_value("credential_configurations.claims[].sd", &claim.sd)?;
        if claim.sd != "always" {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' claims[].sd must be always"
            ));
        }
        if claim.output_path.is_empty() {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' claims[].output_path must not be empty"
            ));
        }
        if claim.output_path.len() != 1 {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' claims[].output_path must be a single segment in V1"
            ));
        }
        let segment = &claim.output_path[0];
        validate_oid4vci_non_empty_value(
            "credential_configurations.claims[].output_path",
            segment,
        )?;
        if is_reserved_oid4vci_projection_output_name(segment) {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' claims[].output_path uses reserved claim name '{segment}'"
            ));
        }
        if !paths.insert(segment.as_str()) {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' contains duplicate claims[].output_path"
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_oid4vci_credential_claim_reference<'a>(
    configuration_id: &str,
    claim_id: &str,
    credential_profile_id: &str,
    evidence: &'a EvidenceConfig,
    profile: &CredentialProfileConfig,
    claim_ids: &HashSet<&str>,
    allowed_claim_ids: &HashSet<&str>,
) -> Result<&'a ClaimDefinition, EvidenceConfigError> {
    if !claim_ids.contains(claim_id) {
        return invalid_oid4vci(format!(
            "credential configuration '{configuration_id}' references unknown claim '{claim_id}'"
        ));
    }
    if !allowed_claim_ids.contains(claim_id) {
        return invalid_oid4vci(format!(
            "credential configuration '{configuration_id}' references claim '{claim_id}' outside subject_access.allowed_claims"
        ));
    }
    if !profile
        .allowed_claims
        .iter()
        .any(|allowed_claim_id| allowed_claim_id == claim_id)
    {
        return invalid_oid4vci(format!(
            "credential configuration '{configuration_id}' maps claim '{claim_id}' to credential profile '{credential_profile_id}' but the profile does not allow that claim"
        ));
    }
    let claim = evidence
        .claims
        .iter()
        .find(|claim| claim.id == claim_id)
        .ok_or_else(|| EvidenceConfigError::InvalidOid4vciConfig {
            reason: format!(
                "credential configuration '{configuration_id}' references unknown claim '{claim_id}'"
            ),
        })?;
    if !claim.evidence_mode.is_registry_backed() {
        return invalid_oid4vci(format!(
            "credential configuration '{configuration_id}' maps source-free claim '{claim_id}' to credential profile '{credential_profile_id}'; OID4VCI credential claims must be registry_backed"
        ));
    }
    if !claim
        .credential_profiles
        .iter()
        .any(|profile_id| profile_id == credential_profile_id)
    {
        return invalid_oid4vci(format!(
            "credential configuration '{configuration_id}' maps claim '{claim_id}' to credential profile '{credential_profile_id}' but the claim does not reference that profile"
        ));
    }
    Ok(claim)
}

pub(super) fn is_reserved_oid4vci_projection_output_name(value: &str) -> bool {
    const RESERVED: [&str; 17] = [
        "iss",
        "sub",
        "aud",
        "iat",
        "nbf",
        "exp",
        "vct",
        "vct#integrity",
        "id",
        "jti",
        "_sd",
        "_sd_alg",
        "cnf",
        "status",
        "issuanceDate",
        "expirationDate",
        "credential_configuration_id",
    ];
    RESERVED.contains(&value)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciIssuerDisplayConfig {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<Oid4vciDisplayImageConfig>,
}

impl Oid4vciIssuerDisplayConfig {
    fn validate(&self, name: &str) -> Result<(), EvidenceConfigError> {
        validate_oid4vci_non_empty_value(&format!("{name}.name"), &self.name)?;
        validate_optional_oid4vci_non_empty_value(
            &format!("{name}.locale"),
            self.locale.as_deref(),
        )?;
        validate_oid4vci_display_image(&format!("{name}.logo"), &self.logo)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciCredentialDisplayConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<Oid4vciDisplayImageConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_image: Option<Oid4vciDisplayImageConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_image: Option<Oid4vciDisplayImageConfig>,
}

impl Oid4vciCredentialDisplayConfig {
    fn validate(&self, name: &str) -> Result<(), EvidenceConfigError> {
        validate_optional_oid4vci_non_empty_value(
            &format!("{name}.locale"),
            self.locale.as_deref(),
        )?;
        validate_optional_oid4vci_non_empty_value(
            &format!("{name}.description"),
            self.description.as_deref(),
        )?;
        validate_optional_oid4vci_non_empty_value(
            &format!("{name}.background_color"),
            self.background_color.as_deref(),
        )?;
        validate_optional_oid4vci_non_empty_value(
            &format!("{name}.text_color"),
            self.text_color.as_deref(),
        )?;
        validate_oid4vci_display_image(&format!("{name}.logo"), &self.logo)?;
        validate_oid4vci_display_image(
            &format!("{name}.background_image"),
            &self.background_image,
        )?;
        validate_oid4vci_display_image(&format!("{name}.secondary_image"), &self.secondary_image)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciDisplayImageConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

pub(super) fn default_oid4vci_proof_signing_alg_values_supported() -> Vec<String> {
    vec![CREDENTIAL_SIGNING_ALG_EDDSA.to_string()]
}

pub(super) fn default_oid4vci_cryptographic_binding_methods_supported() -> Vec<String> {
    vec![CRYPTOGRAPHIC_BINDING_METHOD_DID_JWK.to_string()]
}

pub(super) fn validate_oid4vci_public_url(
    name: &str,
    url: &str,
) -> Result<(), EvidenceConfigError> {
    let url = url.trim();
    let (scheme, authority, _) =
        split_absolute_url(url).ok_or_else(|| EvidenceConfigError::InvalidOid4vciConfig {
            reason: format!("{name} must be an absolute URL"),
        })?;
    if scheme != "https" && !(scheme == "http" && is_insecure_localhost_url(url)) {
        return invalid_oid4vci(format!(
            "{name} must use https unless it is an http loopback URL"
        ));
    }
    if authority.is_empty() {
        return invalid_oid4vci(format!("{name} must include a host"));
    }
    if url.contains('#') {
        return invalid_oid4vci(format!("{name} must not include a fragment"));
    }
    Ok(())
}

pub(super) fn validate_oid4vci_endpoint_url(
    name: &str,
    url: &str,
    credential_issuer: &str,
) -> Result<(), EvidenceConfigError> {
    validate_oid4vci_public_url(name, url)?;
    let Some((_, _, path)) = split_absolute_url(url) else {
        return invalid_oid4vci(format!("{name} must be an absolute URL"));
    };
    if path.is_empty() || path == "/" {
        return invalid_oid4vci(format!("{name} must include an endpoint path"));
    }
    if url.contains('?') {
        return invalid_oid4vci(format!("{name} must not include a query string"));
    }
    let issuer_prefix = credential_issuer.trim().trim_end_matches('/');
    if !url.trim().starts_with(&format!("{issuer_prefix}/")) {
        return invalid_oid4vci(format!("{name} must be under oid4vci.credential_issuer"));
    }
    Ok(())
}

pub(super) fn oid4vci_credentials_path_prefix(credential_issuer: &str) -> Option<String> {
    let (_, _, issuer_path) = split_absolute_url(credential_issuer.trim())?;
    let issuer_path = issuer_path.trim_end_matches('/');
    if issuer_path.is_empty() {
        Some("/credentials/".to_string())
    } else {
        Some(format!("{issuer_path}/credentials/"))
    }
}

pub(super) fn split_absolute_url(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return None;
    }
    let path = if rest[authority_end..].starts_with('/') {
        rest[authority_end..]
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
    } else {
        ""
    };
    Some((scheme, authority, path))
}

pub(super) fn validate_oid4vci_non_empty_entries(
    name: &str,
    values: &[String],
) -> Result<(), EvidenceConfigError> {
    if values.is_empty() {
        return invalid_oid4vci(format!("{name} must not be empty"));
    }
    for value in values {
        validate_oid4vci_non_empty_value(name, value)?;
    }
    Ok(())
}

pub(super) fn validate_oid4vci_non_empty_value(
    name: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    if value.trim().is_empty() {
        return invalid_oid4vci(format!("{name} must not contain blank entries"));
    }
    Ok(())
}

pub(super) fn validate_optional_oid4vci_non_empty_value(
    name: &str,
    value: Option<&str>,
) -> Result<(), EvidenceConfigError> {
    if let Some(value) = value {
        validate_oid4vci_non_empty_value(name, value)?;
    }
    Ok(())
}

pub(super) fn validate_oid4vci_display_image(
    name: &str,
    image: &Option<Oid4vciDisplayImageConfig>,
) -> Result<(), EvidenceConfigError> {
    let Some(image) = image else {
        return Ok(());
    };
    validate_optional_oid4vci_non_empty_value(&format!("{name}.uri"), image.uri.as_deref())?;
    validate_optional_oid4vci_non_empty_value(&format!("{name}.url"), image.url.as_deref())?;
    validate_optional_oid4vci_non_empty_value(
        &format!("{name}.alt_text"),
        image.alt_text.as_deref(),
    )?;
    match (image.uri.as_deref(), image.url.as_deref()) {
        (None, None) => invalid_oid4vci(format!("{name} must include uri or url")),
        (uri, url) => {
            if let Some(uri) = uri {
                validate_oid4vci_public_url(&format!("{name}.uri"), uri)?;
            }
            if let Some(url) = url {
                validate_oid4vci_public_url(&format!("{name}.url"), url)?;
            }
            Ok(())
        }
    }
}

pub(super) fn invalid_oid4vci<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidOid4vciConfig {
        reason: reason.into(),
    })
}

pub(super) fn invalid_access_token_signing<T>(
    reason: impl Into<String>,
) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidAccessTokenSigningConfig {
        reason: reason.into(),
    })
}

pub(super) fn validate_access_token_signing_entries(
    field: &str,
    values: &[String],
) -> Result<(), EvidenceConfigError> {
    if values.is_empty() {
        return invalid_access_token_signing(format!("{field} must not be empty when enabled"));
    }
    if values.iter().any(|value| value.trim().is_empty()) {
        return invalid_access_token_signing(format!("{field} must not contain blank entries"));
    }
    Ok(())
}
