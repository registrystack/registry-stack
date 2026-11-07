// SPDX-License-Identifier: Apache-2.0
//! Configured issuer trust: which issuer may issue which credential types, and
//! where its signing key comes from.

use registry_platform_crypto::{PublicJwk, SigningAlgorithm};
use registry_platform_x509::{ChainPolicy, LeafKeyType, TrustAnchors};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use thiserror::Error;

/// Why an issuer trust configuration was refused. Entries are named by their
/// position in the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TrustConfigError {
    #[error("issuer trust lists no entries")]
    NoEntries,
    #[error("trust entry {entry} has an empty id or issuer")]
    EmptyIdentity { entry: usize },
    #[error("trust entry {entry} repeats an earlier id")]
    DuplicateId { entry: usize },
    #[error("trust entry {entry} repeats an earlier issuer")]
    DuplicateIssuer { entry: usize },
    #[error("trust entry {entry} lists no credential types, or an empty one")]
    EmptyVct { entry: usize },
    #[error("trust entry {entry} has no usable key source")]
    EmptyKeySource { entry: usize },
    #[error("trust entry {entry} has trust anchors that cannot be used")]
    InvalidAnchors { entry: usize },
    #[error("trust entry {entry} has a pinned key that is invalid or not Ed25519 or P-256")]
    InvalidKey { entry: usize },
    #[error("trust entry {entry} has a pinned key without a key identifier")]
    MissingKeyId { entry: usize },
    #[error("trust entry {entry} pins two keys with one key identifier")]
    DuplicateKeyId { entry: usize },
    #[error(
        "deny-list holds an empty issuer or a certificate fingerprint that is not 64 hex digits"
    )]
    InvalidDenyList,
}

/// Where an issuer's signature key comes from.
#[derive(Clone)]
pub enum KeySource {
    /// The `x5c` header chain, verified to these anchors. The anchor is never
    /// taken from the header.
    X5c {
        anchors: TrustAnchors,
        policy: ChainPolicy,
    },
    /// Keys pinned in configuration, selected by the header `kid`. Ed25519 and
    /// P-256 only.
    Jwks(Vec<PublicJwk>),
}

impl fmt::Debug for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X5c { anchors, .. } => f
                .debug_struct("X5c")
                .field("anchors", &anchors.digest())
                .finish_non_exhaustive(),
            Self::Jwks(keys) => f.debug_struct("Jwks").field("keys", &keys.len()).finish(),
        }
    }
}

/// One issuer the channel trusts.
#[derive(Debug, Clone)]
pub struct TrustEntry {
    /// Identifier reported with a verified credential.
    pub id: String,
    /// The exact `iss` value this entry vouches for.
    pub issuer: String,
    /// The `vct` values this issuer may issue.
    pub vct: Vec<String>,
    pub key_source: KeySource,
}

/// Issuers and certificates that are refused even when an allow-list entry
/// would otherwise accept them.
///
/// The list is checked before the allow-list lookup and before any signature
/// work. A certificate is denied by the SHA-256 fingerprint of its DER, whether
/// it is the leaf or an intermediate in the presented `x5c` chain.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct IssuerDenyList {
    issuers: HashSet<String>,
    certificates: HashSet<[u8; 32]>,
}

impl IssuerDenyList {
    /// Deny each of `issuers` (exact `iss` values) and each certificate whose
    /// DER hashes to one of `certificate_sha256`.
    #[must_use]
    pub fn new(issuers: Vec<String>, certificate_sha256: Vec<[u8; 32]>) -> Self {
        Self {
            issuers: issuers.into_iter().collect(),
            certificates: certificate_sha256.into_iter().collect(),
        }
    }

    pub(crate) fn denies_issuer(&self, issuer: &str) -> bool {
        self.issuers.contains(issuer)
    }

    pub(crate) fn denies_certificate(&self, der: &[u8]) -> bool {
        !self.certificates.is_empty() && {
            let fingerprint: [u8; 32] = Sha256::digest(der).into();
            self.certificates.contains(&fingerprint)
        }
    }
}

impl fmt::Debug for IssuerDenyList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuerDenyList")
            .field("issuers", &self.issuers.len())
            .field("certificates", &self.certificates.len())
            .finish()
    }
}

/// Configured deny-list. Both members are required, so an empty deny-list is an
/// explicit choice.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerDenyListConfig {
    pub issuers: Vec<String>,
    /// SHA-256 fingerprints of certificate DER, 64 hex digits each.
    pub certificate_sha256: Vec<String>,
}

impl TryFrom<IssuerDenyListConfig> for IssuerDenyList {
    type Error = TrustConfigError;

    fn try_from(config: IssuerDenyListConfig) -> Result<Self, Self::Error> {
        if config.issuers.iter().any(String::is_empty) {
            return Err(TrustConfigError::InvalidDenyList);
        }
        let certificates = config
            .certificate_sha256
            .iter()
            .map(|text| fingerprint_from_hex(text).ok_or(TrustConfigError::InvalidDenyList))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(config.issuers, certificates))
    }
}

fn fingerprint_from_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        *byte = u8::try_from(high * 16 + low).ok()?;
    }
    Some(out)
}

/// The validated list of trusted issuers, with the deny-list that overrides it.
#[derive(Clone)]
pub struct IssuerTrust {
    entries: Vec<TrustEntry>,
    deny: IssuerDenyList,
}

impl fmt::Debug for IssuerTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.entries.iter().map(|entry| &entry.id))
            .finish()
    }
}

impl IssuerTrust {
    /// Validate and keep `entries`.
    ///
    /// Refused: an empty list, an empty `id` or `issuer`, a repeated `id` or
    /// `issuer`, an empty `vct` list or value, and an empty or unusable key
    /// source (no anchors or leaf key types, no pinned keys, a pinned key that
    /// is not Ed25519 or P-256, has no `kid`, or repeats a `kid`).
    pub fn new(mut entries: Vec<TrustEntry>) -> Result<Self, TrustConfigError> {
        if entries.is_empty() {
            return Err(TrustConfigError::NoEntries);
        }
        for entry in &mut entries {
            if let KeySource::Jwks(keys) = &mut entry.key_source {
                keys.iter_mut().for_each(name_p256_algorithm);
            }
        }
        let mut ids = HashSet::new();
        let mut issuers = HashSet::new();
        for (entry, trust) in entries.iter().enumerate() {
            if trust.id.is_empty() || trust.issuer.is_empty() {
                return Err(TrustConfigError::EmptyIdentity { entry });
            }
            if !ids.insert(trust.id.as_str()) {
                return Err(TrustConfigError::DuplicateId { entry });
            }
            if !issuers.insert(trust.issuer.as_str()) {
                return Err(TrustConfigError::DuplicateIssuer { entry });
            }
            if trust.vct.is_empty() || trust.vct.iter().any(String::is_empty) {
                return Err(TrustConfigError::EmptyVct { entry });
            }
            validate_key_source(&trust.key_source, entry)?;
        }
        Ok(Self {
            entries,
            deny: IssuerDenyList::default(),
        })
    }

    /// Keep `deny` as the list checked before the allow-list.
    #[must_use]
    pub fn with_deny_list(mut self, deny: IssuerDenyList) -> Self {
        self.deny = deny;
        self
    }

    pub(crate) fn deny_list(&self) -> &IssuerDenyList {
        &self.deny
    }

    pub(crate) fn entry_for_issuer(&self, issuer: &str) -> Option<&TrustEntry> {
        self.entries.iter().find(|entry| entry.issuer == issuer)
    }
}

/// Issuer JWKS entries usually omit `alg`, which the platform requires for
/// every key type but Ed25519. A P-256 key can only be ES256, so name it.
fn name_p256_algorithm(key: &mut PublicJwk) {
    if key.alg.is_none() && key.kty == "EC" && key.crv.as_deref() == Some("P-256") {
        key.alg = Some("ES256".to_owned());
    }
}

fn validate_key_source(source: &KeySource, entry: usize) -> Result<(), TrustConfigError> {
    match source {
        KeySource::X5c { anchors, policy } => {
            if anchors.len() == 0 || policy.allowed_leaf_key_types.is_empty() {
                return Err(TrustConfigError::EmptyKeySource { entry });
            }
        }
        KeySource::Jwks(keys) => {
            if keys.is_empty() {
                return Err(TrustConfigError::EmptyKeySource { entry });
            }
            let mut kids = HashSet::new();
            for key in keys {
                // Re-parse so a key built by hand meets the same checks as one
                // read from configuration.
                let text = serde_json::to_string(key)
                    .map_err(|_| TrustConfigError::InvalidKey { entry })?;
                PublicJwk::parse(&text).map_err(|_| TrustConfigError::InvalidKey { entry })?;
                if !matches!(
                    key.algorithm(),
                    Ok(SigningAlgorithm::Es256 | SigningAlgorithm::EdDsa)
                ) {
                    return Err(TrustConfigError::InvalidKey { entry });
                }
                let kid = key
                    .kid
                    .as_deref()
                    .filter(|kid| !kid.is_empty())
                    .ok_or(TrustConfigError::MissingKeyId { entry })?;
                if !kids.insert(kid) {
                    return Err(TrustConfigError::DuplicateKeyId { entry });
                }
            }
        }
    }
    Ok(())
}

/// Leaf key types a configured chain policy allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LeafKeyTypeConfig {
    P256,
    Ed25519,
}

/// Configured `x5c` trust: anchors as PEM text the caller loaded, plus chain
/// policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct X5cConfig {
    /// PEM certificate bundles; every certificate in them is an anchor.
    pub anchors_pem: Vec<String>,
    /// Most intermediate CA certificates between leaf and anchor.
    #[serde(default = "default_max_path_length")]
    pub max_path_length: u8,
    /// Leaf key types accepted; both when omitted.
    #[serde(default)]
    pub leaf_key_types: Option<Vec<LeafKeyTypeConfig>>,
}

fn default_max_path_length() -> u8 {
    ChainPolicy::default().max_path_length
}

/// Configured key source of one entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeySourceConfig {
    #[serde(rename = "x5c")]
    X5c(X5cConfig),
    /// A pinned JWKS: public JWKs, each with a `kid`.
    Jwks(Vec<PublicJwk>),
}

/// One configured trust entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustEntryConfig {
    pub id: String,
    pub issuer: String,
    pub vct: Vec<String>,
    pub keys: KeySourceConfig,
}

impl TryFrom<Vec<TrustEntryConfig>> for IssuerTrust {
    type Error = TrustConfigError;

    fn try_from(entries: Vec<TrustEntryConfig>) -> Result<Self, Self::Error> {
        let entries = entries
            .into_iter()
            .enumerate()
            .map(|(entry, config)| {
                let key_source = match config.keys {
                    KeySourceConfig::Jwks(keys) => KeySource::Jwks(keys),
                    KeySourceConfig::X5c(x5c) => {
                        let pem = x5c.anchors_pem.join("\n");
                        let anchors = TrustAnchors::from_pem(pem.as_bytes())
                            .map_err(|_| TrustConfigError::InvalidAnchors { entry })?;
                        let defaults = ChainPolicy::default();
                        let allowed_leaf_key_types =
                            x5c.leaf_key_types
                                .map_or(defaults.allowed_leaf_key_types, |types| {
                                    types
                                        .into_iter()
                                        .map(|kind| match kind {
                                            LeafKeyTypeConfig::P256 => LeafKeyType::P256,
                                            LeafKeyTypeConfig::Ed25519 => LeafKeyType::Ed25519,
                                        })
                                        .collect()
                                });
                        KeySource::X5c {
                            anchors,
                            policy: ChainPolicy {
                                max_path_length: x5c.max_path_length,
                                allowed_leaf_key_types,
                            },
                        }
                    }
                };
                Ok(TrustEntry {
                    id: config.id,
                    issuer: config.issuer,
                    vct: config.vct,
                    key_source,
                })
            })
            .collect::<Result<Vec<_>, TrustConfigError>>()?;
        Self::new(entries)
    }
}

impl<'de> Deserialize<'de> for IssuerTrust {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = Vec::<TrustEntryConfig>::deserialize(deserializer)?;
        Self::try_from(entries).map_err(serde::de::Error::custom)
    }
}
