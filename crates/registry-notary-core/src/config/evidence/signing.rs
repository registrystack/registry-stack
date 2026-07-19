// SPDX-License-Identifier: Apache-2.0
//! Credential profile and signing-key configuration.

use super::*;

pub(in crate::config) fn validate_credential_profile_validity(
    profile_id: &str,
    profile: &CredentialProfileConfig,
    max_validity_seconds: u64,
) -> Result<(), EvidenceConfigError> {
    if profile.validity_seconds <= 0 {
        return Err(EvidenceConfigError::InvalidCredentialProfileValidity {
            profile: profile_id.to_string(),
            validity_seconds: profile.validity_seconds,
            max_validity_seconds,
        });
    }
    let validity_seconds = u64::try_from(profile.validity_seconds).map_err(|_| {
        EvidenceConfigError::InvalidCredentialProfileValidity {
            profile: profile_id.to_string(),
            validity_seconds: profile.validity_seconds,
            max_validity_seconds,
        }
    })?;
    if validity_seconds > max_validity_seconds {
        return Err(EvidenceConfigError::InvalidCredentialProfileValidity {
            profile: profile_id.to_string(),
            validity_seconds: profile.validity_seconds,
            max_validity_seconds,
        });
    }
    Ok(())
}

pub fn signing_provider_uses_local_software_custody(provider: SigningKeyProviderConfig) -> bool {
    matches!(
        provider,
        SigningKeyProviderConfig::LocalJwkEnv
            | SigningKeyProviderConfig::FileWatch
            | SigningKeyProviderConfig::LocalPkcs12File
    )
}

pub fn signing_key_uses_local_software_custody(key: &SigningKeyConfig) -> bool {
    key.status.may_sign() && signing_provider_uses_local_software_custody(key.provider)
}

pub(in crate::config) fn validate_signing_key_id(key_id: &str) -> Result<(), EvidenceConfigError> {
    if key_id.trim().is_empty() {
        return Err(EvidenceConfigError::InvalidSigningKeyConfig {
            key: key_id.to_string(),
            reason: "signing key id must not be empty".to_string(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialProfileConfig {
    pub format: String,
    pub issuer: String,
    pub signing_key: String,
    pub vct: String,
    #[serde(default = "default_credential_validity_seconds")]
    pub validity_seconds: i64,
    #[serde(default)]
    pub holder_binding: HolderBindingConfig,
    #[serde(default)]
    pub allowed_claims: Vec<String>,
    #[serde(default)]
    pub disclosure: CredentialDisclosureConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyConfig {
    #[schemars(with = "schema::SigningKeyProviderSchema")]
    pub provider: SigningKeyProviderConfig,
    pub alg: String,
    pub kid: String,
    #[schemars(with = "schema::SigningKeyStatusSchema")]
    pub status: SigningKeyStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_until_unix_seconds: Option<u64>,
    #[serde(default)]
    pub private_jwk_env: String,
    #[serde(default)]
    pub public_jwk_env: String,
    #[serde(default)]
    pub module_path: String,
    #[serde(default)]
    pub token_label: String,
    #[serde(default)]
    pub pin_env: String,
    #[serde(default)]
    pub key_label: String,
    #[serde(default)]
    pub key_id_hex: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub password_env: String,
}

impl SigningKeyConfig {
    pub(super) fn validate(&self, key_id: &str) -> Result<(), EvidenceConfigError> {
        validate_signing_key_non_empty(key_id, "alg", &self.alg)?;
        if self.alg != CREDENTIAL_SIGNING_ALG_EDDSA
            && self.alg != CREDENTIAL_SIGNING_ALG_ES256
            && self.alg != CLIENT_ASSERTION_SIGNING_ALG_RS256
        {
            return invalid_signing_key(
                key_id,
                format!(
                    "alg must be {CREDENTIAL_SIGNING_ALG_EDDSA}, {CREDENTIAL_SIGNING_ALG_ES256}, or {CLIENT_ASSERTION_SIGNING_ALG_RS256}"
                ),
            );
        }
        validate_signing_key_non_empty(key_id, "kid", &self.kid)?;
        if self.publish_until_unix_seconds.is_some()
            && !matches!(self.status, SigningKeyStatus::PublishOnly)
        {
            return invalid_signing_key(
                key_id,
                "publish_until_unix_seconds is valid only for publish_only signing keys",
            );
        }
        match self.provider {
            SigningKeyProviderConfig::LocalJwkEnv => {
                if self.status.may_sign() {
                    validate_signing_key_non_empty(
                        key_id,
                        "private_jwk_env",
                        &self.private_jwk_env,
                    )?;
                }
                if matches!(self.status, SigningKeyStatus::PublishOnly) {
                    validate_signing_key_non_empty(key_id, "public_jwk_env", &self.public_jwk_env)?;
                    validate_signing_key_absent(key_id, "private_jwk_env", &self.private_jwk_env)?;
                }
                validate_signing_key_absent(key_id, "module_path", &self.module_path)?;
                validate_signing_key_absent(key_id, "token_label", &self.token_label)?;
                validate_signing_key_absent(key_id, "pin_env", &self.pin_env)?;
                validate_signing_key_absent(key_id, "key_label", &self.key_label)?;
                validate_signing_key_absent(key_id, "key_id_hex", &self.key_id_hex)?;
                validate_signing_key_absent(key_id, "path", &self.path)?;
                validate_signing_key_absent(key_id, "password_env", &self.password_env)?;
            }
            SigningKeyProviderConfig::Pkcs11 => {
                if self.alg != CREDENTIAL_SIGNING_ALG_EDDSA {
                    return invalid_signing_key(key_id, "pkcs11 provider supports only EdDSA");
                }
                if self.status.may_publish() {
                    validate_signing_key_non_empty(key_id, "public_jwk_env", &self.public_jwk_env)?;
                }
                if self.status.may_sign() {
                    validate_signing_key_non_empty(key_id, "module_path", &self.module_path)?;
                    if !std::path::Path::new(&self.module_path).is_absolute() {
                        return invalid_signing_key(key_id, "module_path must be absolute");
                    }
                    validate_signing_key_non_empty(key_id, "token_label", &self.token_label)?;
                    validate_signing_key_non_empty(key_id, "pin_env", &self.pin_env)?;
                    validate_signing_key_non_empty(key_id, "key_label", &self.key_label)?;
                    validate_signing_key_non_empty(key_id, "key_id_hex", &self.key_id_hex)?;
                    if !self.key_id_hex.len().is_multiple_of(2)
                        || !self.key_id_hex.chars().all(|ch| ch.is_ascii_hexdigit())
                    {
                        return invalid_signing_key(key_id, "key_id_hex must be even-length hex");
                    }
                }
                if matches!(self.status, SigningKeyStatus::PublishOnly) {
                    validate_signing_key_absent(key_id, "module_path", &self.module_path)?;
                    validate_signing_key_absent(key_id, "token_label", &self.token_label)?;
                    validate_signing_key_absent(key_id, "pin_env", &self.pin_env)?;
                    validate_signing_key_absent(key_id, "key_label", &self.key_label)?;
                    validate_signing_key_absent(key_id, "key_id_hex", &self.key_id_hex)?;
                }
                validate_signing_key_absent(key_id, "private_jwk_env", &self.private_jwk_env)?;
                validate_signing_key_absent(key_id, "path", &self.path)?;
                validate_signing_key_absent(key_id, "password_env", &self.password_env)?;
            }
            SigningKeyProviderConfig::FileWatch => {
                if matches!(self.status, SigningKeyStatus::PublishOnly) {
                    return invalid_signing_key(
                        key_id,
                        "file_watch provider supports only active or disabled signing keys",
                    );
                }
                if self.status.may_sign() {
                    validate_signing_key_non_empty(key_id, "path", &self.path)?;
                }
                validate_signing_key_absent(key_id, "private_jwk_env", &self.private_jwk_env)?;
                validate_signing_key_absent(key_id, "public_jwk_env", &self.public_jwk_env)?;
                validate_signing_key_absent(key_id, "module_path", &self.module_path)?;
                validate_signing_key_absent(key_id, "token_label", &self.token_label)?;
                validate_signing_key_absent(key_id, "pin_env", &self.pin_env)?;
                validate_signing_key_absent(key_id, "key_label", &self.key_label)?;
                validate_signing_key_absent(key_id, "key_id_hex", &self.key_id_hex)?;
                validate_signing_key_absent(key_id, "password_env", &self.password_env)?;
            }
            SigningKeyProviderConfig::LocalPkcs12File => {
                invalid_signing_key(
                    key_id,
                    "local_pkcs12_file provider is intentionally not implemented yet",
                )?;
            }
            _ => {
                invalid_signing_key(key_id, "signing key provider is unsupported by this Notary")?;
            }
        }
        Ok(())
    }

    pub fn may_publish_at(&self, now_unix_seconds: u64) -> bool {
        if !self.status.may_publish() {
            return false;
        }
        self.publish_until_unix_seconds
            .is_none_or(|publish_until| now_unix_seconds <= publish_until)
    }
}

pub(in crate::config) fn validate_signing_key_non_empty(
    key_id: &str,
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    if value.trim().is_empty() {
        return invalid_signing_key(key_id, format!("{field} must not be empty"));
    }
    Ok(())
}

pub(in crate::config) fn validate_signing_key_absent(
    key_id: &str,
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    if !value.trim().is_empty() {
        return invalid_signing_key(
            key_id,
            format!("{field} is not valid for this signing key provider"),
        );
    }
    Ok(())
}

pub(in crate::config) fn invalid_signing_key<T>(
    key_id: &str,
    reason: impl Into<String>,
) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidSigningKeyConfig {
        key: key_id.to_string(),
        reason: reason.into(),
    })
}

pub(in crate::config) fn validate_profile_signing_key_issuer_binding(
    profile_id: &str,
    profile: &CredentialProfileConfig,
    key: &SigningKeyConfig,
) -> Result<(), EvidenceConfigError> {
    if let Some(kid_did) = key
        .kid
        .split('#')
        .next()
        .filter(|did| did.starts_with("did:web:"))
    {
        if profile.issuer.starts_with("did:web:") && profile.issuer != kid_did {
            return Err(
                EvidenceConfigError::CredentialProfileSigningKeyIssuerMismatch {
                    profile: profile_id.to_string(),
                    key: profile.signing_key.clone(),
                    reason: "did:web issuer must match signing key kid DID".to_string(),
                },
            );
        }
        if profile.issuer.starts_with("https://") {
            validate_did_web_https_issuer_binding(kid_did, &profile.issuer).map_err(|error| {
                EvidenceConfigError::CredentialProfileSigningKeyIssuerMismatch {
                    profile: profile_id.to_string(),
                    key: profile.signing_key.clone(),
                    reason: error.to_string(),
                }
            })?;
        }
    }
    Ok(())
}

pub(in crate::config) const fn default_credential_validity_seconds() -> i64 {
    600
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HolderBindingConfig {
    #[serde(default = "default_holder_binding_mode")]
    pub mode: String,
    #[serde(default)]
    pub proof_of_possession: Option<String>,
    #[serde(default = "default_holder_binding_allowed_did_methods")]
    pub allowed_did_methods: Vec<String>,
}

impl Default for HolderBindingConfig {
    fn default() -> Self {
        Self {
            mode: default_holder_binding_mode(),
            proof_of_possession: None,
            allowed_did_methods: default_holder_binding_allowed_did_methods(),
        }
    }
}

pub(in crate::config) fn default_holder_binding_mode() -> String {
    "did".to_string()
}

pub(in crate::config) fn default_holder_binding_allowed_did_methods() -> Vec<String> {
    vec![SD_JWT_VC_HOLDER_BINDING_METHOD.to_string()]
}
