// SPDX-License-Identifier: Apache-2.0
//! Audit primitives shared by every Registry Stack product.
//!
//! - [`AuditWriter`] writes one JSON object per line to a durable, rotated
//!   file or to stdout: a `request` entry before protected I/O and a
//!   `response` entry with the outcome, sharing one correlation. It fails
//!   closed: an entry the destination does not accept is an error.
//!   [`AuditWriter::begin`] writes the `request` entry and returns an
//!   [`AuditRequest`] that owes the `response`: dropped unanswered, it writes
//!   the product's `unfinished` record, so no request entry stays unpaired.
//! - [`AuditProfile`] and [`AuditKeyHasher`] derive keyed, domain-separated
//!   references so audit records never carry raw identifiers.
//! - [`redact`] minimizes query strings, email addresses, and phone numbers.
//! - [`AuthorizationAuditEvent`] is one privacy-safe authorization event shape.
//! - [`require_audit_under`] keeps an audit path under a persistent root.
//!
//! Entries are not hash-chained. Tamper evidence is a deployment concern: ship
//! the stream to append-only storage.

mod authorization;
mod persistent_root;

pub use authorization::{AuthorizationAuditError, AuthorizationAuditEvent, AuthorizationOutcome};
pub use persistent_root::{require_audit_under, PersistentRootFault};

#[cfg(unix)]
mod writer;
#[cfg(unix)]
pub use writer::{
    AuditDestination, AuditDestinationError, AuditDestinationKind, AuditEntry, AuditPhase,
    AuditRequest, AuditUnavailable, AuditUnavailableReason, AuditWriter, FileDestination,
    DEFAULT_AUDIT_RETAIN_DAYS, DEFAULT_AUDIT_ROTATE_BYTES, MAX_AUDIT_RETAIN_DAYS,
    MIN_AUDIT_ROTATE_BYTES,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    sync::Arc,
};

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MIN_AUDIT_SECRET_BYTES: usize = 32;
const KEYED_HASH_PREFIX: &str = "hmac-sha256:";
const UNKEYED_HASH_PREFIX: &str = "sha256:";
const AUDIT_REFERENCE_HASH_CONTEXT: &str = "registry-platform:audit-reference:v1";

/// HKDF-Expand `info` label deriving the identifier-hashing sub-key (AUDIT-03).
const IDENTIFIER_KEY_DERIVATION_INFO: &[u8] = b"registry-platform-audit/identifier-key/v1";

/// Shared application audit profile for keyed identifier hashing.
#[derive(Clone, Debug)]
pub struct AuditProfile {
    key_hasher: AuditKeyHasher,
}

impl AuditProfile {
    /// Production profile backed by caller-owned master secret bytes.
    ///
    /// The bytes are used exactly as supplied, without trimming or decoding,
    /// and are zeroized after the identifier-hash sub-key is derived. This is
    /// the byte-backed counterpart to [`Self::production_from_env`] for file
    /// and external secret providers.
    pub fn production_from_secret_bytes(
        master_secret: Zeroizing<Vec<u8>>,
    ) -> Result<Self, AuditError> {
        let key_hasher = AuditKeyHasher::Keyed(derive_subkey_from_secret_bytes(
            &master_secret,
            IDENTIFIER_KEY_DERIVATION_INFO,
        )?);
        Ok(Self { key_hasher })
    }

    /// Production profile backed by the HMAC secret in `env_var_name`.
    ///
    /// The identifier key is an HKDF-derived sub-key of the master env secret,
    /// bound to a per-purpose `info` label (AUDIT-03). A leak of the derived
    /// sub-key does not reveal the master.
    pub fn production_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Ok(Self {
            key_hasher: AuditKeyHasher::from_env_derived(env_var_name)?,
        })
    }

    /// Explicit test and local-development profile.
    #[must_use]
    pub fn unkeyed_dev_only() -> Self {
        Self {
            key_hasher: AuditKeyHasher::unkeyed_dev_only(),
        }
    }

    #[must_use]
    pub fn key_hasher(&self) -> AuditKeyHasher {
        self.key_hasher.clone()
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuditError {
    #[error("audit JSON serialization or parsing failed: {0}")]
    Json(#[source] serde_json::Error),
    #[error("audit sink I/O failure: {0}")]
    Io(#[source] std::io::Error),
    #[error("audit hash secret environment variable name is empty")]
    EmptyEnvVarName,
    #[error("audit hash secret environment variable {name} is unavailable")]
    EnvVarUnavailable { name: String },
    #[error("audit hash secret environment variable {name} is not valid Unicode")]
    EnvVarNotUnicode { name: String },
    #[error("audit hash secret environment variable {name} is empty")]
    EmptySecret { name: String },
    #[error("audit hash secret from {name} must be at least {min_bytes} bytes")]
    WeakSecret { name: String, min_bytes: usize },
    /// The single-writer advisory lock on the audit file is already held by
    /// another writer (typically a second process sharing the audit volume, or
    /// an overlapping container during a restart or recreate). Each process
    /// writes its own stream, so a second writer on one path is refused.
    #[error("audit sink single-writer lock is already held by another writer: {path}")]
    SinkLocked {
        path: String,
        /// The one-shot command role this destination was derived for via
        /// [`AuditDestination::for_process`], or `None` when this is the
        /// destination the long-running service opens directly. Lets a
        /// caller report accurately whether the lock is held by another
        /// invocation of the same companion command or by the service.
        role: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuditReferenceHashError {
    #[error("audit reference class is empty")]
    EmptyClass,
    #[error("audit reference canonical input is empty")]
    EmptyCanonicalInput,
}

/// Inner key bytes for [`AuditHashSecret`].
///
/// The raw HMAC key is zeroized when the last shared reference is dropped, so a
/// leaked process image is far less likely to retain the deployment secret after
/// the audit profile is torn down.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretBytes(Vec<u8>);

/// Shared per-deployment HMAC secret for audit identifiers.
///
/// The key material is held behind an `Arc<SecretBytes>` whose inner bytes are
/// zeroized on drop of the last clone (AUDIT-02).
#[derive(Clone)]
pub struct AuditHashSecret(Arc<SecretBytes>);

impl AuditHashSecret {
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, AuditError> {
        // Own the bytes directly: on the success path they move into the
        // `ZeroizeOnDrop` `SecretBytes` with no intermediate copy; on the error
        // path the rejected (too-short) secret is scrubbed explicitly.
        let mut secret = secret.into();
        if secret.len() < MIN_AUDIT_SECRET_BYTES {
            secret.zeroize();
            return Err(AuditError::WeakSecret {
                name: "explicit secret".to_string(),
                min_bytes: MIN_AUDIT_SECRET_BYTES,
            });
        }
        Ok(Self(Arc::new(SecretBytes(secret))))
    }

    fn from_env_value(name: &str, value: String) -> Result<Self, AuditError> {
        // Keep ownership of the env value so it can move into `SecretBytes`
        // (`String::into_bytes` is allocation-free) instead of being copied;
        // rejected values are scrubbed before returning.
        let mut value = value;
        if value.is_empty() {
            return Err(AuditError::EmptySecret {
                name: name.to_string(),
            });
        }
        if value.len() < MIN_AUDIT_SECRET_BYTES {
            value.zeroize();
            return Err(AuditError::WeakSecret {
                name: name.to_string(),
                min_bytes: MIN_AUDIT_SECRET_BYTES,
            });
        }
        Ok(Self(Arc::new(SecretBytes(value.into_bytes()))))
    }

    fn from_bytes(secret: Vec<u8>) -> Self {
        Self(Arc::new(SecretBytes(secret)))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0 .0
    }
}

impl fmt::Debug for AuditHashSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditHashSecret")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Deterministic audit identifier hasher.
#[derive(Clone, Debug)]
pub enum AuditKeyHasher {
    Keyed(AuditHashSecret),
    UnkeyedDevOnly,
}

impl AuditKeyHasher {
    /// Load an HMAC secret from the named environment variable.
    ///
    /// This fails closed when the env var name is empty, unset, empty, or shorter
    /// than 32 bytes. Unkeyed hashing requires [`Self::unkeyed_dev_only`].
    pub fn from_env(env_var_name: &str) -> Result<Self, AuditError> {
        if env_var_name.trim().is_empty() {
            return Err(AuditError::EmptyEnvVarName);
        }
        let value = read_secret_env(env_var_name)?;
        Ok(Self::Keyed(AuditHashSecret::from_env_value(
            env_var_name,
            value,
        )?))
    }

    /// Load an identifier hasher whose key is an HKDF-derived sub-key of the
    /// master env secret, bound to the identifier `info` label (AUDIT-03).
    pub fn from_env_derived(env_var_name: &str) -> Result<Self, AuditError> {
        Ok(Self::Keyed(derive_subkey_from_env(
            env_var_name,
            IDENTIFIER_KEY_DERIVATION_INFO,
        )?))
    }

    /// Explicit unkeyed mode for tests and local development.
    #[must_use]
    pub fn unkeyed_dev_only() -> Self {
        Self::UnkeyedDevOnly
    }

    /// Hash a raw audit identifier.
    #[must_use]
    pub fn hash(&self, raw: &str) -> String {
        match self {
            Self::Keyed(secret) => hmac_sha256_hex(secret.as_bytes(), raw.as_bytes()),
            Self::UnkeyedDevOnly => sha256_hex(raw.as_bytes()),
        }
    }

    /// Hash a service-owned canonical audit reference under a versioned class
    /// and scope.
    ///
    /// `class` separates reference families such as matched subjects, table ids,
    /// or primary keys. `scope` may be empty when the service has no narrower
    /// purpose or tenant boundary. `canonical_input` is owned by the caller and
    /// must already be stable and privacy-reviewed for that product surface.
    pub fn audit_reference_hash(
        &self,
        class: &str,
        scope: &str,
        canonical_input: &str,
    ) -> Result<String, AuditReferenceHashError> {
        if class.is_empty() {
            return Err(AuditReferenceHashError::EmptyClass);
        }
        if canonical_input.is_empty() {
            return Err(AuditReferenceHashError::EmptyCanonicalInput);
        }
        let input = audit_reference_hash_input(class, scope, canonical_input);
        Ok(self.hash(&input))
    }

    /// Hash a sensitive audit lookup value under a field-bound platform class.
    ///
    /// This is appropriate for generic redaction surfaces such as URL query
    /// parameters. Services that need product-specific pseudonym classes should
    /// call [`Self::audit_reference_hash`] with their own canonical input.
    #[must_use]
    pub fn sensitive_value_hash(&self, field: &str, value: &str) -> String {
        let canonical_input = format!("value\0{}\0{value}", value.len());
        self.audit_reference_hash("sensitive-value-v1", field, &canonical_input)
            .expect("platform sensitive-value class and canonical input are non-empty")
    }
}

fn audit_reference_hash_input(
    class: &str,
    scope: &str,
    canonical_input: &str,
) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "{AUDIT_REFERENCE_HASH_CONTEXT}\0{}\0{class}\0{}\0{scope}\0{}\0{canonical_input}",
        class.len(),
        scope.len(),
        canonical_input.len()
    ))
}

pub mod redact {
    use super::*;

    const SECRET_PARAM_NAMES: &[&str] = &[
        "token",
        "key",
        "api_key",
        "apikey",
        "password",
        "secret",
        "authorization",
        "auth",
        // AUDIT-05: OAuth / OIDC / generic credential parameter names.
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "client_assertion",
        "assertion",
        "bearer",
        "code",
        "private_key",
        "credential",
        "credentials",
        "passwd",
        "pwd",
        "session_token",
    ];

    /// Fully redact an email address without preserving local-part or domain.
    #[must_use]
    pub fn email(s: &str) -> String {
        if s.is_empty() {
            String::new()
        } else {
            "redacted".to_string()
        }
    }

    /// Fully redact a phone number without preserving digits.
    #[must_use]
    pub fn phone(s: &str) -> String {
        if s.is_empty() {
            String::new()
        } else {
            "redacted".to_string()
        }
    }

    /// Redacts URL query parameters into a stable JSON object.
    #[derive(Debug, Clone, Default)]
    pub struct QueryRedactor {
        sensitive_fields: BTreeSet<String>,
        hasher: Option<AuditKeyHasher>,
    }

    impl QueryRedactor {
        /// Construct a redactor that redacts sensitive values without lookup hashes.
        #[must_use]
        pub fn new<I, S>(sensitive_fields: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                sensitive_fields: sensitive_fields
                    .into_iter()
                    .map(|field| field.into().to_ascii_lowercase())
                    .collect(),
                hasher: None,
            }
        }

        /// Construct a redactor that hashes sensitive lookup values.
        #[must_use]
        pub fn with_hasher<I, S>(hasher: AuditKeyHasher, sensitive_fields: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                hasher: Some(hasher),
                ..Self::new(sensitive_fields)
            }
        }

        #[must_use]
        pub fn redact_query(&self, query: &str) -> Value {
            self.try_redact_query(query).unwrap_or_else(|error| {
                json!({
                    "_error": {
                        "code": "invalid_query_encoding",
                        "detail": error.to_string(),
                    }
                })
            })
        }

        pub fn try_redact_query(&self, query: &str) -> Result<Value, QueryRedactionError> {
            if query.is_empty() {
                return Ok(json!({}));
            }

            let mut out = BTreeMap::new();
            for pair in query.split('&').filter(|pair| !pair.is_empty()) {
                let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
                let name = decode_query_component(raw_name)?;
                let value = decode_query_component(raw_value)?;
                let (field, op) = split_field_operator(&name);
                let field_key = field.to_ascii_lowercase();

                let entry = if is_secret_param_name(field) {
                    json!({ "op": "redacted" })
                } else if self.sensitive_fields.contains(&field_key) {
                    match &self.hasher {
                        Some(hasher) => json!({
                            "op": op,
                            "value_hash": hasher.sensitive_value_hash(field, &value),
                        }),
                        None => json!({ "op": "redacted" }),
                    }
                } else {
                    json!({ "op": op })
                };

                out.insert(name, entry);
            }

            Ok(serde_json::to_value(out).unwrap_or_else(|_| json!({})))
        }
    }

    #[derive(Debug, Error, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum QueryRedactionError {
        #[error("query component is not valid UTF-8")]
        InvalidUtf8,
    }

    fn is_secret_param_name(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        SECRET_PARAM_NAMES.iter().any(|secret| *secret == lower)
    }
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{UNKEYED_HASH_PREFIX}{}", hex_lower(&sha256_bytes(bytes)))
}

fn hmac_sha256_hex(secret: &[u8], bytes: &[u8]) -> String {
    format!(
        "{KEYED_HASH_PREFIX}{}",
        hex_lower(&hmac_sha256_bytes(secret, bytes))
    )
}

fn hmac_sha256_bytes(secret: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(bytes);
    let mut tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    tag.as_mut_slice().zeroize();
    out
}

/// HKDF-Expand (RFC 5869) over SHA-256, producing one 32-byte output block.
///
/// The master env secret is already operator-supplied high-entropy material of
/// at least 32 bytes, so it is used directly as the HKDF pseudorandom key (PRK)
/// without a separate Extract step (Expand-only); a distinct per-purpose `info`
/// label domain-separates each derived sub-key. Because the SHA-256 output is a
/// single block, the counter byte is always `0x01` and no `T(0)` carry is
/// needed. The caller moves the returned bytes straight into the
/// `ZeroizeOnDrop` [`SecretBytes`] backing an [`AuditHashSecret`], so the
/// derived sub-key is scrubbed on drop without an intermediate copy.
fn hkdf_expand_sha256(prk: &[u8], info: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(prk).expect("HMAC-SHA256 accepts any key length");
    mac.update(info);
    mac.update(&[0x01]);
    let mut tag = mac.finalize().into_bytes();
    let derived = tag.to_vec();
    tag.as_mut_slice().zeroize();
    derived
}

/// Derive a domain-separated [`AuditHashSecret`] sub-key from a master env
/// secret using [`hkdf_expand_sha256`] (AUDIT-03).
///
/// A leak of one derived sub-key reveals neither the master secret nor the
/// sibling sub-key, because each is a one-way HMAC over an independent `info`
/// label.
fn derive_subkey_from_env(env_var_name: &str, info: &[u8]) -> Result<AuditHashSecret, AuditError> {
    if env_var_name.trim().is_empty() {
        return Err(AuditError::EmptyEnvVarName);
    }
    let value = Zeroizing::new(read_secret_env(env_var_name)?);
    if value.is_empty() {
        return Err(AuditError::EmptySecret {
            name: env_var_name.to_string(),
        });
    }
    derive_subkey_from_secret_bytes(value.as_bytes(), info).map_err(|error| match error {
        AuditError::WeakSecret { min_bytes, .. } => AuditError::WeakSecret {
            name: env_var_name.to_string(),
            min_bytes,
        },
        error => error,
    })
}

/// Derive one domain-separated sub-key from exact caller-owned master bytes.
///
/// The public byte-backed profile constructors retain the `Zeroizing` owner
/// while this helper borrows the bytes, so both success and failure scrub the
/// master after all requested sub-keys have been derived.
fn derive_subkey_from_secret_bytes(
    master_secret: &[u8],
    info: &[u8],
) -> Result<AuditHashSecret, AuditError> {
    if master_secret.len() < MIN_AUDIT_SECRET_BYTES {
        return Err(AuditError::WeakSecret {
            name: "explicit master secret".to_string(),
            min_bytes: MIN_AUDIT_SECRET_BYTES,
        });
    }
    let derived = hkdf_expand_sha256(master_secret, info);
    Ok(AuditHashSecret::from_bytes(derived))
}

fn read_secret_env(env_var_name: &str) -> Result<String, AuditError> {
    match env::var(env_var_name) {
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Err(AuditError::EnvVarUnavailable {
            name: env_var_name.to_string(),
        }),
        Err(env::VarError::NotUnicode(value)) => {
            let mut bytes = value.into_encoded_bytes();
            bytes.zeroize();
            Err(AuditError::EnvVarNotUnicode {
                name: env_var_name.to_string(),
            })
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn split_field_operator(name: &str) -> (&str, &str) {
    match name.rsplit_once('.') {
        Some((field, op)) if !field.is_empty() && !op.is_empty() => (field, op),
        _ => (name, "eq"),
    }
}

fn decode_query_component(raw: &str) -> Result<String, redact::QueryRedactionError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match (hex_value_any(bytes[i + 1]), hex_value_any(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi << 4) | lo);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| redact::QueryRedactionError::InvalidUtf8)
}

fn hex_value_any(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{redact::QueryRedactor, *};

    #[test]
    fn audit_hash_secret_debug_never_exposes_raw_bytes() {
        let raw_bytes = b"this-is-a-32-byte-secret-1234567";
        let secret = AuditHashSecret::new(raw_bytes.to_vec()).expect("secret builds");

        let debug = format!("{secret:?}");

        assert!(
            debug.contains("<redacted>"),
            "debug must contain <redacted>"
        );
        assert!(
            !debug.contains("this-is-a-32-byte-secret-1234567"),
            "debug must not expose the raw secret bytes"
        );
    }

    #[test]
    fn audit_hasher_from_env_returns_err_when_unset() {
        let name = "REGISTRY_PLATFORM_AUDIT_TEST_UNSET";
        env::remove_var(name);
        assert!(matches!(
            AuditKeyHasher::from_env(name),
            Err(AuditError::EnvVarUnavailable { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn audit_env_loaders_redact_non_unicode_secret_values() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        const NAME: &str = "REGISTRY_PLATFORM_AUDIT_NON_UNICODE_SECRET_TEST";
        const MARKER: &str = "SECRET_BYTES_MUST_NOT_LEAK";
        let mut secret = vec![0xff];
        secret.extend_from_slice(MARKER.as_bytes());
        env::set_var(NAME, OsString::from_vec(secret));

        let errors = [
            AuditKeyHasher::from_env(NAME).expect_err("identifier loader rejects non-Unicode"),
            derive_subkey_from_env(NAME, IDENTIFIER_KEY_DERIVATION_INFO)
                .expect_err("derived loader rejects non-Unicode"),
        ];
        env::remove_var(NAME);

        for error in errors {
            assert!(matches!(error, AuditError::EnvVarNotUnicode { .. }));
            assert!(!format!("{error:?}").contains(MARKER));
            assert!(!error.to_string().contains(MARKER));
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn audit_hasher_requires_explicit_unkeyed_dev_mode() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();
        let hashed = hasher.hash("subject-123");
        assert!(hashed.starts_with(UNKEYED_HASH_PREFIX));
    }

    #[test]
    fn audit_hasher_from_env_uses_hmac_secret() {
        let name = "REGISTRY_PLATFORM_AUDIT_TEST_SECRET";
        env::set_var(name, "0123456789abcdef0123456789abcdef");
        let hasher = AuditKeyHasher::from_env(name).expect("hasher");
        env::remove_var(name);

        let hashed = hasher.hash("subject-123");
        assert!(hashed.starts_with(KEYED_HASH_PREFIX));
        assert_ne!(
            hashed,
            AuditKeyHasher::unkeyed_dev_only().hash("subject-123")
        );
    }

    #[test]
    fn audit_profile_dev_mode_is_explicitly_unkeyed() {
        let profile = AuditProfile::unkeyed_dev_only();

        assert!(profile
            .key_hasher()
            .hash("subject-123")
            .starts_with(UNKEYED_HASH_PREFIX));
    }

    #[test]
    fn audit_reference_hash_is_domain_class_and_scope_separated() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();

        let base = hasher
            .audit_reference_hash(
                "matched-reference-v1",
                "purpose-a",
                r#"{"role":"target","handle":"abc"}"#,
            )
            .expect("reference hash");
        let other_class = hasher
            .audit_reference_hash(
                "matching-attempt-v1",
                "purpose-a",
                r#"{"role":"target","handle":"abc"}"#,
            )
            .expect("reference hash");
        let other_scope = hasher
            .audit_reference_hash(
                "matched-reference-v1",
                "purpose-b",
                r#"{"role":"target","handle":"abc"}"#,
            )
            .expect("reference hash");

        assert!(base.starts_with(UNKEYED_HASH_PREFIX));
        assert_ne!(base, hasher.hash(r#"{"role":"target","handle":"abc"}"#));
        assert_ne!(base, other_class);
        assert_ne!(base, other_scope);
    }

    #[test]
    fn audit_reference_hash_rejects_empty_class_or_input_but_allows_empty_scope() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();

        assert!(matches!(
            hasher.audit_reference_hash("", "scope", "canonical"),
            Err(AuditReferenceHashError::EmptyClass)
        ));
        assert!(matches!(
            hasher.audit_reference_hash("class", "scope", ""),
            Err(AuditReferenceHashError::EmptyCanonicalInput)
        ));
        assert!(hasher
            .audit_reference_hash("class", "", "canonical")
            .expect("empty scope is explicit")
            .starts_with(UNKEYED_HASH_PREFIX));
    }

    #[test]
    fn sensitive_value_hash_is_field_bound_and_reference_domain_separated() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();

        let first = hasher.sensitive_value_hash("person_id", "IND-001");
        let second = hasher.sensitive_value_hash("person_id", "IND-001");
        let other_field = hasher.sensitive_value_hash("household_id", "IND-001");

        assert_eq!(first, second);
        assert_ne!(first, other_field);
        assert_ne!(first, hasher.hash("person_id\0IND-001"));
        assert!(hasher
            .sensitive_value_hash("empty", "")
            .starts_with(UNKEYED_HASH_PREFIX));
    }

    #[test]
    fn query_redactor_redacts_secrets_and_hashes_sensitive_fields() {
        let redactor =
            QueryRedactor::with_hasher(AuditKeyHasher::unkeyed_dev_only(), ["email", "person_id"]);
        let redacted = redactor
            .redact_query("email=jeremi%40example.test&token=secret&limit=10&person_id.gte=abc");

        assert_eq!(redacted["token"]["op"], "redacted");
        assert_eq!(redacted["limit"]["op"], "eq");
        assert_eq!(redacted["email"]["op"], "eq");
        assert!(redacted["email"]["value_hash"]
            .as_str()
            .expect("hash")
            .starts_with(UNKEYED_HASH_PREFIX));
        assert_eq!(redacted["person_id.gte"]["op"], "gte");
        assert!(!redacted.to_string().contains("jeremi"));
        assert!(!redacted.to_string().contains("secret"));
        assert!(!redacted.to_string().contains("abc"));
    }

    #[test]
    fn query_redactor_surfaces_invalid_utf8() {
        let redactor = QueryRedactor::new(["email"]);

        let err = redactor
            .try_redact_query("email=%FF")
            .expect_err("invalid UTF-8 is not silently lossy-decoded");
        assert_eq!(err, redact::QueryRedactionError::InvalidUtf8);

        let redacted = redactor.redact_query("email=%FF");
        assert_eq!(redacted["_error"]["code"], "invalid_query_encoding");
    }

    #[test]
    fn audit_hash_secret_round_trips_and_clones_share_bytes() {
        // AUDIT-02: zeroize-on-drop newtype must not change observable behavior.
        let raw = b"this-is-a-32-byte-audit-secret-ok".to_vec();
        let secret = AuditHashSecret::new(raw.clone()).expect("secret builds");
        assert_eq!(secret.as_bytes(), raw.as_slice());

        let cloned = secret.clone();
        // Clones share the same underlying Arc<SecretBytes> and observe equal bytes.
        assert_eq!(cloned.as_bytes(), secret.as_bytes());

        // Dropping one clone must not disturb the surviving clone's key material.
        drop(secret);
        assert_eq!(cloned.as_bytes(), raw.as_slice());

        // The hasher built from the secret still produces stable keyed output.
        let hasher = AuditKeyHasher::Keyed(cloned);
        let hashed = hasher.hash("subject-123");
        assert!(hashed.starts_with(KEYED_HASH_PREFIX));
    }

    #[test]
    fn audit_hash_secret_rejects_weak_secret() {
        // AUDIT-02: short keys still fail closed after the newtype change.
        assert!(matches!(
            AuditHashSecret::new(b"too-short".to_vec()),
            Err(AuditError::WeakSecret { .. })
        ));
    }

    #[test]
    fn production_profile_derives_an_identifier_key_distinct_from_the_master() {
        // AUDIT-03: the identifier key is a derived sub-key of the master env
        // secret and never the master itself.
        let name = "REGISTRY_PLATFORM_AUDIT_KDF_TEST_SECRET";
        let master = "0123456789abcdef0123456789abcdef-master";
        env::set_var(name, master);

        let ident_key =
            derive_subkey_from_env(name, IDENTIFIER_KEY_DERIVATION_INFO).expect("identifier key");
        env::remove_var(name);

        assert_ne!(ident_key.as_bytes(), master.as_bytes());
        // HKDF-Expand over SHA-256 yields a single 32-byte block.
        assert_eq!(ident_key.as_bytes().len(), 32);
    }

    #[test]
    fn production_profile_key_derivation_is_deterministic_and_stable() {
        // AUDIT-03: the same env secret must yield the same derived sub-key, so
        // keyed references stay correlatable across process restarts.
        let name = "REGISTRY_PLATFORM_AUDIT_KDF_STABLE_SECRET";
        let master = "stable-master-secret-0123456789abcdef";
        env::set_var(name, master);

        let ident_a =
            derive_subkey_from_env(name, IDENTIFIER_KEY_DERIVATION_INFO).expect("identifier a");
        let ident_b =
            derive_subkey_from_env(name, IDENTIFIER_KEY_DERIVATION_INFO).expect("identifier b");
        env::remove_var(name);

        assert_eq!(ident_a.as_bytes(), ident_b.as_bytes());

        // Pins the HKDF-Expand-only construction.
        let expected = hkdf_expand_sha256(master.as_bytes(), IDENTIFIER_KEY_DERIVATION_INFO);
        assert_eq!(ident_a.as_bytes(), expected.as_slice());
    }

    #[test]
    fn byte_backed_profile_matches_the_identifier_key_known_answer() {
        let master = (0_u8..32).collect::<Vec<_>>();
        let profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(master.clone()))
            .expect("byte-backed profile");

        let AuditKeyHasher::Keyed(identifier_key) = profile.key_hasher() else {
            panic!("production audit profile must use a keyed identifier hasher");
        };

        assert_eq!(
            hex_lower(identifier_key.as_bytes()),
            "5aacb786d1d4271f42d5568b3d5a2eb5814446ef0b44067b0d4210b8a60bffdc"
        );
        assert_ne!(identifier_key.as_bytes(), master.as_slice());
    }

    #[test]
    fn production_identifier_hashes_match_known_answers() {
        // Pins the identifier sub-key derivation (HKDF info
        // `registry-platform-audit/identifier-key/v1`), the audit-reference
        // context, and the output hash format. Every product's keyed audit
        // references depend on these bytes staying identical.
        let master = (0_u8..32).collect::<Vec<_>>();
        let hasher = AuditProfile::production_from_secret_bytes(Zeroizing::new(master))
            .expect("byte-backed profile")
            .key_hasher();

        assert_eq!(
            hasher.hash("subject-123"),
            "hmac-sha256:41b7eb1845213ea04c4d15166b04a66d7375bee0087313aa1ed9ac2daa723e17"
        );
        assert_eq!(
            hasher
                .audit_reference_hash(
                    "matched-reference-v1",
                    "purpose-a",
                    r#"{"role":"target","handle":"abc"}"#,
                )
                .expect("reference hash"),
            "hmac-sha256:324c66c4f9c88c52329592890822264ff58395b3edae6c7fb2e4bbe4ea8da0b5"
        );
        assert_eq!(
            hasher
                .audit_reference_hash("class", "", "canonical")
                .expect("empty scope reference hash"),
            "hmac-sha256:663effdb57b4fca978daf3fc297fca5abcf7c204768d00174c69bc4df89bb46f"
        );
        assert_eq!(
            hasher.sensitive_value_hash("person_id", "IND-001"),
            "hmac-sha256:c1b4e7e61581745adb9db625e2ce94e40b87e25efaf88c4b6736f33bd1f32b7e"
        );
        assert_eq!(
            AuditKeyHasher::unkeyed_dev_only().audit_reference_hash(
                "matched-reference-v1",
                "purpose-a",
                r#"{"role":"target","handle":"abc"}"#,
            ),
            Ok(
                "sha256:0f171351475ceebcf948aa13ede666b8e6d568bc3bf15edd5d1710cd32ed9d82"
                    .to_string()
            )
        );
    }

    #[test]
    fn env_and_byte_backed_profiles_derive_the_same_identifier_hashes() {
        let name = "REGISTRY_PLATFORM_AUDIT_ENV_BYTES_PARITY_SECRET";
        let master = "env-bytes-parity-master-0123456789abcdef";
        env::set_var(name, master);
        let from_env = AuditProfile::production_from_env(name).expect("env profile");
        env::remove_var(name);
        let from_bytes =
            AuditProfile::production_from_secret_bytes(Zeroizing::new(master.as_bytes().to_vec()))
                .expect("byte-backed profile");

        assert_eq!(
            from_env
                .key_hasher()
                .audit_reference_hash("class", "scope", "canonical")
                .expect("env reference hash"),
            from_bytes
                .key_hasher()
                .audit_reference_hash("class", "scope", "canonical")
                .expect("byte reference hash")
        );
        assert_eq!(
            from_env.key_hasher().sensitive_value_hash("field", "value"),
            from_bytes
                .key_hasher()
                .sensitive_value_hash("field", "value")
        );
    }

    #[test]
    fn byte_backed_profile_rejects_a_weak_master_secret_without_echo() {
        let marker = b"short-secret-canary".to_vec();
        let error = AuditProfile::production_from_secret_bytes(Zeroizing::new(marker))
            .expect_err("weak profile master must fail");
        assert!(matches!(error, AuditError::WeakSecret { .. }));
        assert!(!format!("{error:?}").contains("short-secret-canary"));
        assert!(!error.to_string().contains("short-secret-canary"));
    }

    #[test]
    fn query_redactor_redacts_oauth_and_credential_param_names() {
        // AUDIT-05: extended denylist covers OAuth/OIDC and credential params.
        let redactor = QueryRedactor::new(Vec::<String>::new());
        let redacted =
            redactor.redact_query("access_token=x&refresh_token=y&client_secret=z&bearer=b");

        assert_eq!(redacted["access_token"]["op"], "redacted");
        assert_eq!(redacted["refresh_token"]["op"], "redacted");
        assert_eq!(redacted["client_secret"]["op"], "redacted");
        assert_eq!(redacted["bearer"]["op"], "redacted");

        let serialized = redacted.to_string();
        assert!(!serialized.contains("\"x\""));
        assert!(!serialized.contains("\"y\""));
        assert!(!serialized.contains("\"z\""));
        assert!(!serialized.contains("\"b\""));
    }

    #[test]
    fn query_redactor_redacts_remaining_new_credential_param_names() {
        // AUDIT-05: exercise the rest of the added names for coverage.
        let redactor = QueryRedactor::new(Vec::<String>::new());
        let redacted = redactor.redact_query(
            "id_token=a&client_assertion=b&assertion=c&code=d&private_key=e&credential=f&credentials=g&passwd=h&pwd=i&session_token=j",
        );

        for name in [
            "id_token",
            "client_assertion",
            "assertion",
            "code",
            "private_key",
            "credential",
            "credentials",
            "passwd",
            "pwd",
            "session_token",
        ] {
            assert_eq!(redacted[name]["op"], "redacted", "{name} must be redacted");
        }
    }
}
