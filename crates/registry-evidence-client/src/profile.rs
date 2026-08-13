//! Strict, application-owned configuration for the progressive client.

use std::{
    env, fmt,
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
};

use registry_platform_crypto::PrivateJwk;
use serde::{Deserialize, Serialize};

use crate::{error::EvidenceClientError, prepare::MAXIMUM_IDENTIFIER_BYTES, JwksDocument};

pub const EVIDENCE_CLIENT_PROFILE_SCHEMA_V1: &str = "registry.evidence-client-profile/v1";
pub const EVIDENCE_CLIENT_CONTRACTS_SCHEMA_V1: &str = "registry.evidence-client-contracts/v1";
pub const DEFAULT_METADATA_CACHE_SECONDS: u64 = 600;
pub const MAXIMUM_METADATA_CACHE_SECONDS: u64 = 600;
const MAXIMUM_PROFILE_BYTES: u64 = 256 * 1024;
const MAXIMUM_PRIVATE_KEY_BYTES: u64 = 64 * 1024;
const MAXIMUM_PINNED_JWKS_BYTES: u64 = 1024 * 1024;
const MAXIMUM_REVIEWED_CONTRACTS_BYTES: u64 = 4 * 1024 * 1024;
const MAXIMUM_PROFILE_REFERENCE_BYTES: usize = 4096;
const MAXIMUM_ENVIRONMENT_VARIABLE_BYTES: usize = 128;

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
        if bytes.len() as u64 > MAXIMUM_PROFILE_BYTES {
            return Err(profile_error());
        }
        let profile: Self = serde_json::from_slice(bytes).map_err(|_| profile_error())?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, EvidenceClientError> {
        let path = path.as_ref();
        let bytes = read_bounded_file(path, MAXIMUM_PROFILE_BYTES)?;
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
            || !valid_private_key_reference(&self.private_key)
            || !valid_trust_reference(&self.trust)
            || !valid_contracts_reference(&self.contracts)
            || [
                self.expected.audience.as_deref(),
                self.expected.issuer.as_deref(),
                self.expected.provider.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| !valid_expected_identity(value))
            || self.maximum_metadata_cache_seconds == 0
            || self.maximum_metadata_cache_seconds > MAXIMUM_METADATA_CACHE_SECONDS
            || self.verification.maximum_assertion_lifetime_seconds == 0
            || self.verification.maximum_assertion_lifetime_seconds > 31_536_000
            || self.verification.clock_skew_seconds > 300
        {
            return Err(profile_error());
        }
        let origin_only = self.base_url == base_url.origin().ascii_serialization();
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
                let bytes = read_bounded_file(&self.resolve(path), MAXIMUM_PRIVATE_KEY_BYTES)?;
                String::from_utf8(bytes).map_err(|_| profile_error())?
            }
            PrivateKeyReference::Environment { variable } => {
                let value = env::var(variable).map_err(|_| profile_error())?;
                if value.len() as u64 > MAXIMUM_PRIVATE_KEY_BYTES {
                    return Err(profile_error());
                }
                value
            }
        };
        PrivateJwk::parse(&json).map_err(|_| profile_error())
    }

    pub(crate) fn load_pinned_jwks(
        &self,
        file: &Path,
    ) -> Result<JwksDocument, EvidenceClientError> {
        let bytes = read_bounded_file(&self.resolve(file), MAXIMUM_PINNED_JWKS_BYTES)?;
        serde_json::from_slice(&bytes).map_err(|_| profile_error())
    }

    pub(crate) fn load_reviewed_contracts(
        &self,
        file: &Path,
    ) -> Result<crate::EvidenceDefinitionsDocument, EvidenceClientError> {
        let bytes = read_bounded_file(&self.resolve(file), MAXIMUM_REVIEWED_CONTRACTS_BYTES)?;
        let catalog: ReviewedContracts =
            serde_json::from_slice(&bytes).map_err(|_| profile_error())?;
        if catalog.schema != EVIDENCE_CLIENT_CONTRACTS_SCHEMA_V1 {
            return Err(profile_error());
        }
        Ok(catalog.into_definitions())
    }
}

fn valid_expected_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_IDENTIFIER_BYTES
        && url::Url::parse(value).is_ok_and(|url| !url.scheme().is_empty())
}

fn valid_private_key_reference(reference: &PrivateKeyReference) -> bool {
    match reference {
        PrivateKeyReference::File { path } => valid_profile_path(path),
        PrivateKeyReference::Environment { variable } => valid_environment_variable(variable),
    }
}

fn valid_trust_reference(trust: &TrustProfile) -> bool {
    match trust {
        TrustProfile::PinnedJwks { file } => valid_profile_path(file),
        TrustProfile::HttpsDiscovery | TrustProfile::LocalLoopbackDiscovery => true,
    }
}

fn valid_contracts_reference(contracts: &ContractsProfile) -> bool {
    match contracts {
        ContractsProfile::Reviewed { file } => valid_profile_path(file),
        ContractsProfile::Published => true,
    }
}

fn valid_profile_path(path: &Path) -> bool {
    path.to_str().is_some_and(|value| {
        !value.is_empty()
            && value.len() <= MAXIMUM_PROFILE_REFERENCE_BYTES
            && !value.chars().any(char::is_control)
    })
}

fn valid_environment_variable(variable: &str) -> bool {
    let mut bytes = variable.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && variable.len() <= MAXIMUM_ENVIRONMENT_VARIABLE_BYTES
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn read_bounded_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, EvidenceClientError> {
    let mut file = File::open(path).map_err(|_| profile_error())?;
    let initial = file.metadata().map_err(|_| profile_error())?;
    if !initial.is_file() || initial.len() > maximum_bytes {
        return Err(profile_error());
    }
    let mut bytes = Vec::with_capacity(initial.len() as usize);
    file.by_ref()
        .take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| profile_error())?;
    let final_length = file.metadata().map_err(|_| profile_error())?.len();
    if bytes.len() as u64 != initial.len()
        || bytes.len() as u64 > maximum_bytes
        || final_length != initial.len()
    {
        return Err(profile_error());
    }
    Ok(bytes)
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
    use std::fs;

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

    #[test]
    fn profile_origin_must_use_its_exact_canonical_serialization() {
        let profile = |base_url: &str| EvidenceClientProfile {
            schema: EVIDENCE_CLIENT_PROFILE_SCHEMA_V1.to_owned(),
            base_url: base_url.to_owned(),
            client_id: "client".to_owned(),
            private_key: PrivateKeyReference::Environment {
                variable: "EVIDENCE_KEY".to_owned(),
            },
            trust: TrustProfile::HttpsDiscovery,
            contracts: ContractsProfile::Published,
            verification: VerificationProfile::default(),
            maximum_metadata_cache_seconds: DEFAULT_METADATA_CACHE_SECONDS,
            expected: ExpectedServiceProfile::default(),
            origin_directory: None,
        };
        profile("https://evidence.example.org")
            .validate()
            .expect("canonical origin");
        for rejected in [
            "https://EVIDENCE.example.org",
            "https://evidence.example.org:443",
            "https://evidence.example.org/",
        ] {
            assert!(profile(rejected).validate().is_err(), "{rejected}");
        }
    }

    #[test]
    fn expected_service_identities_are_bounded_absolute_uris() {
        let profile = |expected: ExpectedServiceProfile| EvidenceClientProfile {
            schema: EVIDENCE_CLIENT_PROFILE_SCHEMA_V1.to_owned(),
            base_url: "https://evidence.example.org".to_owned(),
            client_id: "client".to_owned(),
            private_key: PrivateKeyReference::Environment {
                variable: "EVIDENCE_KEY".to_owned(),
            },
            trust: TrustProfile::HttpsDiscovery,
            contracts: ContractsProfile::Published,
            verification: VerificationProfile::default(),
            maximum_metadata_cache_seconds: DEFAULT_METADATA_CACHE_SECONDS,
            expected,
            origin_directory: None,
        };
        profile(ExpectedServiceProfile {
            audience: Some("urn:example:audience".to_owned()),
            issuer: Some("https://issuer.example.org".to_owned()),
            provider: Some("urn:example:provider".to_owned()),
        })
        .validate()
        .expect("bounded expected identities");

        for rejected in [
            ExpectedServiceProfile {
                audience: Some("not-a-uri".to_owned()),
                ..ExpectedServiceProfile::default()
            },
            ExpectedServiceProfile {
                issuer: Some(format!(
                    "urn:{}",
                    "a".repeat(MAXIMUM_IDENTIFIER_BYTES + 1 - "urn:".len())
                )),
                ..ExpectedServiceProfile::default()
            },
            ExpectedServiceProfile {
                provider: Some(String::new()),
                ..ExpectedServiceProfile::default()
            },
        ] {
            assert!(profile(rejected).validate().is_err());
        }
    }

    #[test]
    fn profile_artifact_references_are_bounded_and_closed_before_use() {
        let profile = |private_key, trust, contracts| EvidenceClientProfile {
            schema: EVIDENCE_CLIENT_PROFILE_SCHEMA_V1.to_owned(),
            base_url: "https://evidence.example.org".to_owned(),
            client_id: "client".to_owned(),
            private_key,
            trust,
            contracts,
            verification: VerificationProfile::default(),
            maximum_metadata_cache_seconds: DEFAULT_METADATA_CACHE_SECONDS,
            expected: ExpectedServiceProfile::default(),
            origin_directory: None,
        };
        profile(
            PrivateKeyReference::File {
                path: PathBuf::from("keys/client.jwk"),
            },
            TrustProfile::PinnedJwks {
                file: PathBuf::from("trust/evidence.jwks"),
            },
            ContractsProfile::Reviewed {
                file: PathBuf::from("contracts/evidence.json"),
            },
        )
        .validate()
        .expect("bounded artifact references");

        for rejected in [
            profile(
                PrivateKeyReference::File {
                    path: PathBuf::new(),
                },
                TrustProfile::HttpsDiscovery,
                ContractsProfile::Published,
            ),
            profile(
                PrivateKeyReference::File {
                    path: PathBuf::from("a".repeat(MAXIMUM_PROFILE_REFERENCE_BYTES + 1)),
                },
                TrustProfile::HttpsDiscovery,
                ContractsProfile::Published,
            ),
            profile(
                PrivateKeyReference::Environment {
                    variable: "1INVALID".to_owned(),
                },
                TrustProfile::HttpsDiscovery,
                ContractsProfile::Published,
            ),
            profile(
                PrivateKeyReference::Environment {
                    variable: "A".repeat(MAXIMUM_ENVIRONMENT_VARIABLE_BYTES + 1),
                },
                TrustProfile::HttpsDiscovery,
                ContractsProfile::Published,
            ),
            profile(
                PrivateKeyReference::Environment {
                    variable: "EVIDENCE_KEY".to_owned(),
                },
                TrustProfile::PinnedJwks {
                    file: PathBuf::new(),
                },
                ContractsProfile::Published,
            ),
            profile(
                PrivateKeyReference::Environment {
                    variable: "EVIDENCE_KEY".to_owned(),
                },
                TrustProfile::HttpsDiscovery,
                ContractsProfile::Reviewed {
                    file: PathBuf::from("a".repeat(MAXIMUM_PROFILE_REFERENCE_BYTES + 1)),
                },
            ),
        ] {
            assert!(rejected.validate().is_err());
        }
    }

    #[test]
    fn profile_linked_files_are_bounded_before_their_contents_are_read() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for (name, maximum) in [
            ("profile.json", MAXIMUM_PROFILE_BYTES),
            ("private.jwk", MAXIMUM_PRIVATE_KEY_BYTES),
            ("jwks.json", MAXIMUM_PINNED_JWKS_BYTES),
            ("contracts.json", MAXIMUM_REVIEWED_CONTRACTS_BYTES),
        ] {
            let path = directory.path().join(name);
            let file = File::create(&path).expect("bounded fixture");
            file.set_len(maximum + 1).expect("oversized sparse file");
            assert!(read_bounded_file(&path, maximum).is_err(), "{name}");
        }
    }

    #[test]
    fn bounded_file_reader_accepts_the_limit_and_refuses_directories() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("bounded.json");
        fs::write(&path, vec![b'a'; 32]).expect("bounded fixture");
        assert_eq!(
            read_bounded_file(&path, 32).expect("exact limit"),
            vec![b'a'; 32]
        );
        assert!(read_bounded_file(directory.path(), 32).is_err());
    }
}
