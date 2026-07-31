// SPDX-License-Identifier: Apache-2.0
//! Relay-facing JWKS adapter for the OIDC auth provider.
//!
//! The relay keeps its small public OIDC surface and error taxonomy, but the
//! actual JWKS cache and refresh-on-unknown-kid behavior are delegated to
//! `registry-platform-oidc`.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::DecodingKey;
use registry_platform_oidc::{JwksFetcher as PlatformJwksFetcher, OidcError as PlatformOidcError};
use serde_json::Value;

use super::fetcher::platform_jwks_config;

/// Errors surfaced by the JWKS cache to callers.
#[derive(Debug, thiserror::Error)]
pub enum JwksError {
    /// The requested `kid` is not present in the cache after platform refresh.
    #[error("unknown key id")]
    UnknownKid,
    /// The JWKS document could not be fetched or parsed.
    #[error("jwks unavailable: {0}")]
    Unavailable(String),
}

/// One fetch's worth of verifier keys.
///
/// Kept for compatibility with existing tests and imports. Production fetches
/// are now performed by `registry-platform-oidc`.
pub struct JwksFetchResult {
    pub jwks: JwkSet,
}

/// Errors returned while constructing relay JWKS fetchers.
#[derive(Debug, thiserror::Error)]
pub enum JwksFetchError {
    /// Network or transport failure (DNS, TCP, TLS, HTTP status, timeout).
    #[error("jwks transport failure: {0}")]
    Transport(String),
    /// Response body did not parse as a JWKS document.
    #[error("jwks response did not parse")]
    Parse,
    /// A development JWKS file was not a bounded regular file or could not be
    /// opened without following its final path component.
    #[error("development JWKS file is unavailable or unsafe")]
    DevelopmentFile,
    /// The development JWKS document contains secret key material.
    #[error("development JWKS contains private key material")]
    PrivateKeyMaterial,
    /// The `issuer` field in the OIDC discovery document does not match the
    /// operator-configured issuer.
    #[error("discovery issuer mismatch: expected {expected:?}, got {actual:?}")]
    IssuerMismatch { expected: String, actual: String },
}

/// Pluggable relay fetcher contract. Implementations build the concrete
/// platform fetcher used by `registry-platform-oidc::TokenVerifier`.
pub trait JwksFetcher: Send + Sync + 'static {
    fn platform_fetcher(
        &self,
        cache_ttl: Duration,
        refresh_cooldown: Duration,
    ) -> PlatformJwksFetcher;
}

/// Relay compatibility wrapper around the platform JWKS cache.
pub struct JwksCache {
    fetcher: Arc<PlatformJwksFetcher>,
    observed_key_count: AtomicUsize,
}

impl JwksCache {
    /// Build an empty cache. The first lookup triggers a platform fetch.
    pub fn new(fetcher: Arc<dyn JwksFetcher>, cache_ttl: Duration) -> Self {
        Self::with_refresh_interval(fetcher, cache_ttl, Duration::from_secs(30))
    }

    /// Build a cache with a custom refresh-rate-limit interval.
    pub fn with_refresh_interval(
        fetcher: Arc<dyn JwksFetcher>,
        cache_ttl: Duration,
        refresh_min_interval: Duration,
    ) -> Self {
        Self {
            fetcher: Arc::new(fetcher.platform_fetcher(cache_ttl, refresh_min_interval)),
            observed_key_count: AtomicUsize::new(0),
        }
    }

    pub(crate) fn platform_fetcher(&self) -> Arc<PlatformJwksFetcher> {
        Arc::clone(&self.fetcher)
    }

    /// Fetch the verifier key for `kid`, using the platform JWKS cache.
    pub async fn get(&self, kid: &str) -> Result<Arc<DecodingKey>, JwksError> {
        match self.fetcher.key_for_kid(kid).await {
            Ok(key) => {
                self.observed_key_count.fetch_max(1, Ordering::Relaxed);
                Ok(Arc::new(key))
            }
            Err(err) => Err(map_platform_jwks_error(err)),
        }
    }

    /// Lower-bound operational signal for whether at least one key resolved.
    pub fn key_count(&self) -> usize {
        self.observed_key_count.load(Ordering::Relaxed)
    }
}

fn map_platform_jwks_error(err: PlatformOidcError) -> JwksError {
    match err {
        PlatformOidcError::MissingKid | PlatformOidcError::UnknownKid => JwksError::UnknownKid,
        other => JwksError::Unavailable(other.to_string()),
    }
}

/// Build a fetcher backed by an immutable in-memory [`JwkSet`].
pub fn static_fetcher(jwks: JwkSet) -> Arc<dyn JwksFetcher> {
    Arc::new(StaticFetcher { jwks })
}

/// Load a public JWKS from a bounded regular file and retain only its parsed,
/// in-memory representation.
///
/// This development-only source performs no network I/O. The file is opened
/// without following its final path component, must be a regular file, and is
/// bounded at one MiB. Any private JWK member is rejected before the document
/// reaches `jsonwebtoken`'s typed parser.
pub fn development_jwks_fetcher(path: &Path) -> Result<Arc<dyn JwksFetcher>, JwksFetchError> {
    const MAX_DEVELOPMENT_JWKS_BYTES: usize = 1024 * 1024;

    let normalized: std::path::PathBuf = path.components().collect();
    if !path.is_absolute()
        || path.as_os_str() != normalized.as_os_str()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(JwksFetchError::DevelopmentFile);
    }
    let bytes = read_bounded_regular_file_no_follow(path, MAX_DEVELOPMENT_JWKS_BYTES)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| JwksFetchError::Parse)?;
    if contains_private_jwk_member(&value) {
        return Err(JwksFetchError::PrivateKeyMaterial);
    }
    let jwks = serde_json::from_value(value).map_err(|_| JwksFetchError::Parse)?;
    Ok(static_fetcher(jwks))
}

struct StaticFetcher {
    jwks: JwkSet,
}

impl JwksFetcher for StaticFetcher {
    fn platform_fetcher(
        &self,
        cache_ttl: Duration,
        refresh_cooldown: Duration,
    ) -> PlatformJwksFetcher {
        PlatformJwksFetcher::new_static(
            self.jwks.clone(),
            platform_jwks_config(cache_ttl, refresh_cooldown),
        )
    }
}

fn contains_private_jwk_member(value: &Value) -> bool {
    const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

    match value {
        Value::Object(object) => object.iter().any(|(name, nested)| {
            PRIVATE_MEMBERS.contains(&name.as_str()) || contains_private_jwk_member(nested)
        }),
        Value::Array(values) => values.iter().any(contains_private_jwk_member),
        _ => false,
    }
}

fn read_bounded_regular_file_no_follow(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, JwksFetchError> {
    let mut file = open_read_only_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| JwksFetchError::DevelopmentFile)?;
    let max_bytes_u64 = u64::try_from(max_bytes).map_err(|_| JwksFetchError::DevelopmentFile)?;
    if !metadata.is_file() || metadata.len() > max_bytes_u64 {
        return Err(JwksFetchError::DevelopmentFile);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max_bytes_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| JwksFetchError::DevelopmentFile)?;
    if bytes.len() > max_bytes {
        return Err(JwksFetchError::DevelopmentFile);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_read_only_no_follow(path: &Path) -> Result<File, JwksFetchError> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| JwksFetchError::DevelopmentFile)?;
    Ok(File::from(descriptor))
}

#[cfg(windows)]
fn open_read_only_no_follow(path: &Path) -> Result<File, JwksFetchError> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| JwksFetchError::DevelopmentFile)
}

#[cfg(not(any(unix, windows)))]
fn open_read_only_no_follow(path: &Path) -> Result<File, JwksFetchError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| JwksFetchError::DevelopmentFile)?;
    if metadata.file_type().is_symlink() {
        return Err(JwksFetchError::DevelopmentFile);
    }
    File::open(path).map_err(|_| JwksFetchError::DevelopmentFile)
}

/// Convenience constructor for inspecting a [`JwkSet`] from JSON in tests.
#[cfg(test)]
pub fn jwks_from_json(value: serde_json::Value) -> JwkSet {
    serde_json::from_value(value).expect("valid jwks json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_ed25519_jwk(kid: &str) -> JwkSet {
        let raw = vec![0u8; 32];
        let x = base64_url(&raw);
        jwks_from_json(serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": kid,
                "x": x,
            }]
        }))
    }

    fn base64_url(bytes: &[u8]) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[tokio::test]
    async fn first_lookup_triggers_platform_fetch_and_returns_key() {
        let cache = JwksCache::new(
            static_fetcher(one_ed25519_jwk("kid-1")),
            Duration::from_secs(60),
        );

        let key = cache.get("kid-1").await.expect("kid-1 resolves");
        assert!(Arc::strong_count(&key) >= 1);
        assert_eq!(cache.key_count(), 1);
    }

    #[tokio::test]
    async fn unknown_kid_maps_to_unknown_kid() {
        let cache = JwksCache::new(
            static_fetcher(one_ed25519_jwk("kid-known")),
            Duration::from_secs(60),
        );

        let err = match cache.get("kid-mystery").await {
            Ok(_) => panic!("expected UnknownKid"),
            Err(e) => e,
        };
        assert!(matches!(err, JwksError::UnknownKid));
    }

    #[tokio::test]
    async fn development_file_loads_public_jwks_into_static_fetcher() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let path = temporary.path().join("jwks.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&one_ed25519_jwk("development-kid")).expect("JWKS serializes"),
        )
        .expect("JWKS writes");

        let fetcher = development_jwks_fetcher(&path).expect("public JWKS loads");
        let cache = JwksCache::new(fetcher, Duration::from_secs(60));
        cache
            .get("development-kid")
            .await
            .expect("development key resolves from memory");
    }

    #[test]
    fn development_file_rejects_all_private_jwk_members_recursively() {
        let temporary = tempfile::tempdir().expect("tempdir");
        for private_member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            let path = temporary.path().join(format!("{private_member}.json"));
            let mut document = serde_json::to_value(one_ed25519_jwk("development-kid"))
                .expect("JWKS converts to value");
            document["keys"][0]["extension"] = serde_json::json!({ (private_member): "secret" });
            std::fs::write(
                &path,
                serde_json::to_vec(&document).expect("JWKS serializes"),
            )
            .expect("JWKS writes");

            let err = match development_jwks_fetcher(&path) {
                Ok(_) => panic!("private member {private_member} must be rejected"),
                Err(err) => err,
            };
            assert!(matches!(err, JwksFetchError::PrivateKeyMaterial));
        }
    }

    #[test]
    fn development_file_rejects_oversized_and_non_regular_inputs() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let oversized = temporary.path().join("oversized.json");
        std::fs::write(&oversized, vec![b' '; 1024 * 1024 + 1]).expect("oversized file writes");
        assert!(matches!(
            development_jwks_fetcher(&oversized),
            Err(JwksFetchError::DevelopmentFile)
        ));
        assert!(matches!(
            development_jwks_fetcher(temporary.path()),
            Err(JwksFetchError::DevelopmentFile)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn development_file_does_not_follow_a_symbolic_link() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("tempdir");
        let target = temporary.path().join("jwks.json");
        std::fs::write(
            &target,
            serde_json::to_vec(&one_ed25519_jwk("development-kid")).expect("JWKS serializes"),
        )
        .expect("JWKS writes");
        let link = temporary.path().join("jwks-link.json");
        symlink(&target, &link).expect("symlink created");

        assert!(matches!(
            development_jwks_fetcher(&link),
            Err(JwksFetchError::DevelopmentFile)
        ));
    }
}
