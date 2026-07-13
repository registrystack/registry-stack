// SPDX-License-Identifier: Apache-2.0
//! Evidence, source, claim, disclosure, and signing configuration.

use super::*;

mod claims;
mod disclosure;
mod limits;
mod relay;
mod signing;

pub use claims::*;
pub use disclosure::*;
pub use limits::*;
pub use relay::*;
pub use signing::*;

/// Registry Notary configuration. Disabled by default so existing
/// Registry Relay deployments load unchanged.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_service_id")]
    pub service_id: String,
    #[serde(default = "default_api_version")]
    pub api_version: String,
    #[serde(default = "default_api_base_url")]
    pub api_base_url: String,
    #[serde(default = "default_claims_url")]
    pub claims_url: String,
    #[serde(default = "default_formats_url")]
    pub formats_url: String,
    #[serde(default = "default_inline_batch_limit")]
    pub inline_batch_limit: usize,
    #[serde(default = "default_max_credential_validity_seconds")]
    pub max_credential_validity_seconds: u64,
    #[serde(default)]
    pub allowed_purposes: Vec<String>,
    /// Closed union of request variables declared by authored services.
    #[serde(default)]
    pub variables: BTreeMap<String, RequestVariableConfig>,
    #[serde(default)]
    pub claims: Vec<ClaimDefinition>,
    #[serde(default)]
    pub signing_keys: BTreeMap<String, SigningKeyConfig>,
    #[serde(default)]
    pub credential_profiles: BTreeMap<String, CredentialProfileConfig>,
    /// The one Registry Relay connection available to registry-backed claims.
    /// Authentication remains a reloadable local file reference; core never
    /// loads the bearer token value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayConnectionConfig>,
    /// Per-request cap for concurrently evaluated subjects.
    #[serde(default)]
    pub concurrency: ConcurrencyConfig,
    /// Per-principal budget for machine `evaluate`/`batch_evaluate` traffic,
    /// counted in subjects (a single evaluate consumes 1; a batch consumes
    /// `items.len()`) over a fixed one-minute window. Disabled by default.
    #[serde(default)]
    pub machine_quota: MachineQuotaConfig,
}

pub(in crate::config) const fn default_max_credential_validity_seconds() -> u64 {
    600
}

impl EvidenceConfig {
    pub(in crate::config) fn validate_signing_keys(&self) -> Result<(), EvidenceConfigError> {
        let mut published_kids = HashSet::new();
        for (key_id, key) in &self.signing_keys {
            validate_signing_key_id(key_id)?;
            key.validate(key_id)?;
            if key.status.may_publish() && !published_kids.insert(key.kid.as_str()) {
                return Err(EvidenceConfigError::InvalidSigningKeyConfig {
                    key: key_id.clone(),
                    reason: format!("duplicate published kid '{}'", key.kid),
                });
            }
        }
        Ok(())
    }

    /// Validate resolved signing-capable key material after runtime providers
    /// have loaded their public JWKs. Static config can compare ids and kids,
    /// but only the resolved JWKs reveal whether different active entries reuse
    /// the same key material under different ids or kids.
    ///
    /// The reuse comparison is confined to the separated EdDSA signing roles
    /// issue #173 names: the access-token signing key and every credential
    /// profile signing key, plus the federation signing key (the documented
    /// separation boundary in `validate_signing_key_alg_usage` treats all three
    /// as distinct EdDSA roles). `reuse_scoped_key_ids` carries exactly those
    /// role keys. The eSignet pre-authorized-code RP client key is a separate,
    /// relaxed role that is deliberately allowed to share material with the
    /// credential issuer key, so callers must leave it out of
    /// `reuse_scoped_key_ids`; resolved JWKs for keys outside the set are not
    /// compared.
    pub fn validate_resolved_signing_key_material<'a, I>(
        &self,
        resolved_public_jwks: I,
        reuse_scoped_key_ids: &HashSet<&str>,
    ) -> Result<(), EvidenceConfigError>
    where
        I: IntoIterator<Item = (&'a str, &'a PublicJwk)>,
    {
        let mut thumbprints_by_key_id = BTreeMap::new();
        for (key_id, public_jwk) in resolved_public_jwks {
            let Some(key) = self.signing_keys.get(key_id) else {
                return invalid_signing_key(
                    key_id,
                    "resolved public JWK does not match a configured signing key",
                );
            };
            if !key.status.may_sign() {
                continue;
            }
            // Only the separated signing roles (#173) are compared against one
            // another; keys outside that set (notably the eSignet RP client
            // key) are allowed to reuse credential material by design.
            if !reuse_scoped_key_ids.contains(key_id) {
                continue;
            }
            let thumbprint =
                public_jwk
                    .jkt()
                    .map_err(|_| EvidenceConfigError::InvalidSigningKeyConfig {
                        key: key_id.to_string(),
                        reason: "resolved public JWK could not be thumbprinted".to_string(),
                    })?;
            if let Some(previous_key_id) =
                thumbprints_by_key_id.insert(thumbprint, key_id.to_string())
            {
                return invalid_signing_key(
                    key_id,
                    format!("reuses public key material with signing key '{previous_key_id}'"),
                );
            }
        }
        Ok(())
    }
}

pub(in crate::config) fn default_service_id() -> String {
    "registry-notary".to_string()
}

pub(in crate::config) fn default_api_version() -> String {
    "2026-05".to_string()
}

pub(in crate::config) fn default_api_base_url() -> String {
    "/".to_string()
}

pub(in crate::config) fn default_claims_url() -> String {
    "/v1/claims".to_string()
}

pub(in crate::config) fn default_formats_url() -> String {
    "/v1/formats".to_string()
}

pub(in crate::config) const fn default_inline_batch_limit() -> usize {
    100
}
