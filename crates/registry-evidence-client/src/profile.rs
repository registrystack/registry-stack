//! Strict, application-owned configuration for the progressive client.

use std::{
    env, fmt, fs,
    path::{Path, PathBuf},
};

use registry_platform_crypto::PrivateJwk;
use serde::{Deserialize, Serialize};

use crate::{error::EvidenceClientError, JwksDocument};

pub const EVIDENCE_CLIENT_PROFILE_SCHEMA_V1: &str = "registry.evidence-client-profile/v1";
pub const EVIDENCE_CLIENT_CONTRACTS_SCHEMA_V1: &str = "registry.evidence-client-contracts/v1";
pub const DEFAULT_METADATA_CACHE_SECONDS: u64 = 600;
pub const MAXIMUM_METADATA_CACHE_SECONDS: u64 = 600;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceClientProfile {
    pub schema: String,
    pub base_url: String,
    pub client_id: String,
    pub private_key: PrivateKeyReference,
    #[serde(default)]
    pub trust: TrustProfile,
    #[serde(default)]
    pub contracts: ContractsProfile,
    #[serde(default)]
    pub verification: VerificationProfile,
    #[serde(default)]
    pub expected: ExpectedServiceProfile,
    #[serde(default = "default_metadata_cache_seconds")]
    pub maximum_metadata_cache_seconds: u64,
    #[serde(skip)]
    origin_directory: Option<PathBuf>,
}

const fn default_metadata_cache_seconds() -> u64 {
    DEFAULT_METADATA_CACHE_SECONDS
}

impl EvidenceClientProfile {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, EvidenceClientError> {
        if bytes.len() > 256 * 1024 {
            return Err(profile_error());
        }
        let profile: Self = serde_json::from_slice(bytes).map_err(|_| profile_error())?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, EvidenceClientError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|_| profile_error())?;
        if bytes.len() > 256 * 1024 {
            return Err(profile_error());
        }
        let mut profile: Self = serde_json::from_slice(&bytes).map_err(|_| profile_error())?;
        profile.origin_directory = path.parent().map(Path::to_path_buf);
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), EvidenceClientError> {
        let base_url = url::Url::parse(&self.base_url).map_err(|_| profile_error())?;
        if self.schema != EVIDENCE_CLIENT_PROFILE_SCHEMA_V1
            || self.client_id.is_empty()
            || self.client_id.len() > 256
            || self.maximum_metadata_cache_seconds == 0
            || self.maximum_metadata_cache_seconds > MAXIMUM_METADATA_CACHE_SECONDS
            || self.verification.maximum_assertion_lifetime_seconds == 0
            || self.verification.maximum_assertion_lifetime_seconds > 31_536_000
            || self.verification.clock_skew_seconds > 300
        {
            return Err(profile_error());
        }
        let origin_only = base_url.path() == "/"
            && !self.base_url.ends_with('/')
            && base_url.query().is_none()
            && base_url.fragment().is_none()
            && base_url.username().is_empty()
            && base_url.password().is_none();
        let local_loopback = base_url.scheme() == "http"
            && base_url.host_str() == Some("127.0.0.1")
            && base_url.port().is_some_and(|port| port != 0);
        match self.trust {
            TrustProfile::HttpsDiscovery | TrustProfile::PinnedJwks { .. }
                if !origin_only || base_url.scheme() != "https" =>
            {
                return Err(profile_error())
            }
            TrustProfile::LocalLoopbackDiscovery if !origin_only || !local_loopback => {
                return Err(profile_error())
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.origin_directory
                .as_deref()
                .unwrap_or_else(|| Path::new("."))
                .join(path)
        }
    }

    pub(crate) fn load_private_key(&self) -> Result<PrivateJwk, EvidenceClientError> {
        let json = match &self.private_key {
            PrivateKeyReference::File { path } => {
                fs::read_to_string(self.resolve(path)).map_err(|_| profile_error())?
            }
            PrivateKeyReference::Environment { variable } => {
                env::var(variable).map_err(|_| profile_error())?
            }
        };
        PrivateJwk::parse(&json).map_err(|_| profile_error())
    }

    pub(crate) fn load_pinned_jwks(
        &self,
        file: &Path,
    ) -> Result<JwksDocument, EvidenceClientError> {
        let bytes = fs::read(self.resolve(file)).map_err(|_| profile_error())?;
        if bytes.len() > 1024 * 1024 {
            return Err(profile_error());
        }
        serde_json::from_slice(&bytes).map_err(|_| profile_error())
    }

    pub(crate) fn load_reviewed_contracts(
        &self,
        file: &Path,
    ) -> Result<crate::EvidenceDefinitionsDocument, EvidenceClientError> {
        let bytes = fs::read(self.resolve(file)).map_err(|_| profile_error())?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(profile_error());
        }
        let catalog: ReviewedContracts =
            serde_json::from_slice(&bytes).map_err(|_| profile_error())?;
        if catalog.schema != EVIDENCE_CLIENT_CONTRACTS_SCHEMA_V1 {
            return Err(profile_error());
        }
        Ok(catalog.into_definitions())
    }
}

impl fmt::Debug for EvidenceClientProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceClientProfile")
            .field("schema", &self.schema)
            .field("base_url", &self.base_url)
            .field("client_id", &self.client_id)
            .field("trust", &self.trust)
            .field("contracts", &self.contracts)
            .field("verification", &self.verification)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PrivateKeyReference {
    File { path: PathBuf },
    Environment { variable: String },
}

impl fmt::Debug for PrivateKeyReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKeyReference(<redacted>)")
    }
}

#[derive(Default, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TrustProfile {
    #[default]
    HttpsDiscovery,
    LocalLoopbackDiscovery,
    PinnedJwks {
        file: PathBuf,
    },
}

impl fmt::Debug for TrustProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpsDiscovery => formatter.write_str("HttpsDiscovery"),
            Self::LocalLoopbackDiscovery => formatter.write_str("LocalLoopbackDiscovery"),
            Self::PinnedJwks { .. } => formatter.write_str("PinnedJwks(<redacted>)"),
        }
    }
}

#[derive(Default, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ContractsProfile {
    #[default]
    Published,
    Reviewed {
        file: PathBuf,
    },
}

impl fmt::Debug for ContractsProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Published => formatter.write_str("Published"),
            Self::Reviewed { .. } => formatter.write_str("Reviewed(<redacted>)"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewedContracts {
    pub schema: String,
    pub assurance_profile: registry_evidence_verifier::AssuranceProfile,
    pub audience: String,
    pub issued_by: String,
    pub provided_by: String,
    pub definitions: Vec<crate::EvidenceDefinition>,
}

impl ReviewedContracts {
    fn into_definitions(self) -> crate::EvidenceDefinitionsDocument {
        crate::EvidenceDefinitionsDocument {
            schema: crate::EVIDENCE_DEFINITIONS_SCHEMA_V1.to_owned(),
            assurance_profile: self.assurance_profile,
            audience: self.audience,
            issued_by: self.issued_by,
            provided_by: self.provided_by,
            holder_bound_batch_max_size: 1,
            definitions: self.definitions,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationProfile {
    #[serde(default = "default_assertion_lifetime")]
    pub maximum_assertion_lifetime_seconds: u64,
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,
}

const fn default_assertion_lifetime() -> u64 {
    300
}
const fn default_clock_skew() -> u64 {
    30
}

impl Default for VerificationProfile {
    fn default() -> Self {
        Self {
            maximum_assertion_lifetime_seconds: default_assertion_lifetime(),
            clock_skew_seconds: default_clock_skew(),
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedServiceProfile {
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
}

pub(crate) fn profile_error() -> EvidenceClientError {
    EvidenceClientError::configuration("the client profile is invalid or unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_reference_debug_is_redacted() {
        let reference = PrivateKeyReference::File {
            path: PathBuf::from("/secret/canary.jwk"),
        };
        assert!(!format!("{reference:?}").contains("canary"));
        assert!(!format!(
            "{:?}",
            TrustProfile::PinnedJwks {
                file: PathBuf::from("/secret/canary.jwks")
            }
        )
        .contains("canary"));
        assert!(!format!(
            "{:?}",
            ContractsProfile::Reviewed {
                file: PathBuf::from("/secret/canary-contracts.json")
            }
        )
        .contains("canary"));
    }

    #[test]
    fn profile_is_closed_and_cache_is_bounded() {
        let json = r#"{"schema":"registry.evidence-client-profile/v1","baseUrl":"https://evidence.example.org","clientId":"client","privateKey":{"source":"environment","variable":"EVIDENCE_KEY"},"trust":{"type":"https-discovery"},"contracts":{"type":"published"},"verification":{}}"#;
        let profile: EvidenceClientProfile = serde_json::from_str(json).expect("profile parses");
        profile.validate().expect("profile validates");
        let widened = json.replace("\"clientId\"", "\"serverSecret\":true,\"clientId\"");
        assert!(serde_json::from_str::<EvidenceClientProfile>(&widened).is_err());

        let excessive_lifetime = json.replace(
            "\"verification\":{}",
            "\"verification\":{\"maximumAssertionLifetimeSeconds\":31536001}",
        );
        let profile: EvidenceClientProfile =
            serde_json::from_str(&excessive_lifetime).expect("profile parses");
        assert!(profile.validate().is_err());
    }
}
