// SPDX-License-Identifier: Apache-2.0
//! Bounded resolution of closed runtime secret references.

use std::{
    collections::BTreeSet,
    env, fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum accepted size of one resolved secret value.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Closed set of secret providers supported by [`SecretResolver`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SecretProvider {
    /// An exact process environment variable.
    Environment,
    /// One owner-only file immediately below the configured root.
    File,
}

/// Parsed `secret:...` reference whose debug form never exposes the name.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference: String,
    provider: SecretProvider,
    name_start: usize,
}

impl SecretReference {
    /// Parse one exact `secret:env/NAME` or `secret:file/name` reference.
    pub fn parse(reference: impl Into<String>) -> Result<Self, SecretError> {
        let reference = reference.into();
        if let Some(name) = reference.strip_prefix("secret:env/") {
            if valid_environment_name(name) {
                return Ok(Self {
                    reference,
                    provider: SecretProvider::Environment,
                    name_start: "secret:env/".len(),
                });
            }
        } else if let Some(name) = reference.strip_prefix("secret:file/") {
            if valid_file_name(name) {
                return Ok(Self {
                    reference,
                    provider: SecretProvider::File,
                    name_start: "secret:file/".len(),
                });
            }
        }
        Err(SecretError::InvalidReference)
    }

    #[must_use]
    pub fn provider(&self) -> SecretProvider {
        self.provider
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.reference[self.name_start..]
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.reference
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("provider", &self.provider)
            .field("name", &"[REDACTED]")
            .finish()
    }
}

/// Value-free secret resolution failure.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum SecretError {
    #[error("the secret reference is invalid")]
    InvalidReference,
    #[error("the secret reference uses a disabled provider")]
    ProviderDisabled,
    #[error("the secret provider configuration is invalid")]
    InvalidProviderConfiguration,
    #[error("the referenced secret is unavailable")]
    Unavailable,
    #[error("the referenced secret file is unsafe")]
    UnsafeFile,
    #[error("the referenced secret could not be read")]
    Read,
    #[error("the referenced secret value is invalid")]
    InvalidValue,
}

/// Secret bytes that are erased when dropped and never exposed by `Debug`.
pub struct ProtectedSecret(Zeroizing<Vec<u8>>);

impl ProtectedSecret {
    /// Borrow the secret for the smallest possible consumer scope.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ProtectedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedSecret([REDACTED])")
    }
}

/// Resolver for exact secret references under an explicit provider allowlist.
///
/// File names are single bounded path components and are opened relative to
/// the configured absolute root with `openat`. The opened file, rather than a
/// later pathname lookup, is checked for type, ownership, mode, and link count
/// before at most [`MAX_SECRET_BYTES`] are retained.
#[derive(Debug)]
pub struct SecretResolver {
    providers: BTreeSet<SecretProvider>,
    file_root: PathBuf,
}

impl SecretResolver {
    /// Build a resolver from the only providers a runtime enables.
    pub fn new(
        providers: impl IntoIterator<Item = SecretProvider>,
        file_root: impl Into<PathBuf>,
    ) -> Result<Self, SecretError> {
        let providers = providers.into_iter().collect::<BTreeSet<_>>();
        let file_root = file_root.into();
        if providers.is_empty()
            || (providers.contains(&SecretProvider::File) && !file_root.is_absolute())
        {
            return Err(SecretError::InvalidProviderConfiguration);
        }
        Ok(Self {
            providers,
            file_root,
        })
    }

    /// Resolve one exact `secret:env/NAME` or `secret:file/name` reference.
    pub fn resolve(&self, reference: &str) -> Result<ProtectedSecret, SecretError> {
        let reference = SecretReference::parse(reference)?;
        self.resolve_reference(&reference)
    }

    /// Resolve an already parsed secret reference.
    pub fn resolve_reference(
        &self,
        reference: &SecretReference,
    ) -> Result<ProtectedSecret, SecretError> {
        if !self.providers.contains(&reference.provider()) {
            return Err(SecretError::ProviderDisabled);
        }

        let bytes = match reference.provider() {
            SecretProvider::Environment => read_environment(reference.name())?,
            SecretProvider::File => read_secret_file(&self.file_root, reference.name())?,
        };
        validate_secret(bytes)
    }
}

fn valid_environment_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'A'..=b'Z'))
        && bytes.len() <= 128
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn valid_file_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 128
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn read_environment(name: &str) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let value = env::var_os(name).ok_or(SecretError::Unavailable)?;
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStringExt as _;
        value.into_vec()
    };
    #[cfg(not(unix))]
    let bytes = value
        .into_string()
        .map_err(|_| SecretError::InvalidValue)?
        .into_bytes();
    Ok(Zeroizing::new(bytes))
}

#[cfg(unix)]
fn read_secret_file(root: &Path, name: &str) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    use rustix::fs::{Mode, OFlags};

    let root = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|_| SecretError::Unavailable)?;
    let secret = rustix::fs::openat(
        &root,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| SecretError::Unavailable)?;
    let file = File::from(secret);
    validate_file_metadata(&file)?;
    read_bounded(file)
}

#[cfg(unix)]
fn validate_file_metadata(file: &File) -> Result<(), SecretError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = file.metadata().map_err(|_| SecretError::Read)?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || !matches!(mode, 0o400 | 0o600)
        || metadata.nlink() != 1
    {
        return Err(SecretError::UnsafeFile);
    }
    Ok(())
}

#[cfg(not(unix))]
fn read_secret_file(root: &Path, name: &str) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let path = root.join(name);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| SecretError::Unavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SecretError::UnsafeFile);
    }
    let file = File::open(path).map_err(|_| SecretError::Unavailable)?;
    read_bounded(file)
}

fn read_bounded(file: File) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SecretError::Read)?;
    Ok(bytes)
}

fn validate_secret(bytes: Zeroizing<Vec<u8>>) -> Result<ProtectedSecret, SecretError> {
    if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES || bytes.contains(&0) {
        return Err(SecretError::InvalidValue);
    }
    Ok(ProtectedSecret(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn environment_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().expect("lock")
    }

    #[test]
    fn references_use_only_the_two_exact_contract_grammars() {
        for (valid, provider, name) in [
            ("secret:env/A", SecretProvider::Environment, "A"),
            (
                "secret:env/SOURCE_2_PASSWORD",
                SecretProvider::Environment,
                "SOURCE_2_PASSWORD",
            ),
            ("secret:file/a", SecretProvider::File, "a"),
            (
                "secret:file/source-token_v2.json",
                SecretProvider::File,
                "source-token_v2.json",
            ),
        ] {
            let reference = SecretReference::parse(valid).expect("valid reference parses");
            assert_eq!(reference.provider(), provider);
            assert_eq!(reference.name(), name);
            assert_eq!(reference.as_str(), valid);
        }
        for invalid in [
            "secret:env/",
            "secret:env/lower",
            "secret:env/A-B",
            "secret:environment/A",
            "secret:file/Upper",
            "secret:file/../token",
            "secret:file/nested/token",
            "secret:file/.token",
            "secret:file/token\0suffix",
            "plain-value",
        ] {
            assert_eq!(
                SecretReference::parse(invalid),
                Err(SecretError::InvalidReference)
            );
        }
        assert!(SecretReference::parse(format!("secret:env/A{}", "B".repeat(127))).is_ok());
        assert_eq!(
            SecretReference::parse(format!("secret:env/A{}", "B".repeat(128))),
            Err(SecretError::InvalidReference)
        );
    }

    #[test]
    fn secret_reference_debug_does_not_render_the_reference_name() {
        let reference =
            SecretReference::parse("secret:file/reference-name-canary").expect("reference parses");
        let rendered = format!("{reference:?}");
        assert!(rendered.contains("File"));
        assert!(!rendered.contains("reference-name-canary"));
        assert!(!rendered.contains(reference.as_str()));
    }

    #[test]
    fn provider_configuration_is_closed_and_file_roots_are_absolute() {
        assert_eq!(
            SecretResolver::new([], "/safe-root").expect_err("a provider is required"),
            SecretError::InvalidProviderConfiguration
        );
        assert_eq!(
            SecretResolver::new([SecretProvider::File], "relative")
                .expect_err("file root must be absolute"),
            SecretError::InvalidProviderConfiguration
        );
        SecretResolver::new([SecretProvider::Environment], "")
            .expect("environment-only resolver needs no file root");
    }

    #[test]
    fn provider_allowlist_is_enforced_before_lookup() {
        let resolver =
            SecretResolver::new([SecretProvider::File], "/safe-root").expect("resolver builds");
        let reference =
            SecretReference::parse("secret:env/DEFINITELY_NOT_PRESENT").expect("reference parses");
        assert!(matches!(
            resolver.resolve_reference(&reference),
            Err(SecretError::ProviderDisabled)
        ));
    }

    #[test]
    fn environment_secret_is_bounded_and_debug_is_redacted() {
        let _guard = environment_lock();
        const NAME: &str = "REGISTRY_PLATFORM_CONFIG_SECRET_RESOLVER_TEST";
        env::set_var(NAME, "environment-canary");
        let resolver =
            SecretResolver::new([SecretProvider::Environment], "").expect("resolver builds");
        let reference =
            SecretReference::parse("secret:env/REGISTRY_PLATFORM_CONFIG_SECRET_RESOLVER_TEST")
                .expect("reference parses");
        let secret = resolver
            .resolve_reference(&reference)
            .expect("secret resolves");
        env::remove_var(NAME);

        assert_eq!(secret.expose_secret(), b"environment-canary");
        assert_eq!(format!("{secret:?}"), "ProtectedSecret([REDACTED])");
        assert!(!format!("{secret:?}").contains("environment-canary"));
        assert_eq!(secret.len(), b"environment-canary".len());
        assert!(!secret.is_empty());
    }

    #[test]
    fn empty_nul_and_oversized_values_are_rejected_without_echo() {
        for value in [
            Vec::new(),
            b"canary\0value".to_vec(),
            vec![b'x'; MAX_SECRET_BYTES + 1],
        ] {
            let error = validate_secret(Zeroizing::new(value)).expect_err("invalid secret");
            assert_eq!(error, SecretError::InvalidValue);
            assert_eq!(error.to_string(), "the referenced secret value is invalid");
        }
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::{fs, os::unix::fs::PermissionsExt as _};

        fn write_secret(root: &Path, name: &str, value: &[u8], mode: u32) {
            let path = root.join(name);
            fs::write(&path, value).expect("write secret");
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
        }

        #[test]
        fn file_secret_accepts_only_owner_read_and_optional_owner_write_modes() {
            let root = tempfile::tempdir().expect("temporary root");
            let resolver =
                SecretResolver::new([SecretProvider::File], root.path()).expect("resolver builds");
            for (name, mode) in [("read-only-token", 0o400), ("writable-token", 0o600)] {
                write_secret(root.path(), name, b"file-canary", mode);
                let secret = resolver
                    .resolve(&format!("secret:file/{name}"))
                    .expect("owner-only file resolves");
                assert_eq!(secret.expose_secret(), b"file-canary");
            }

            for (name, mode) in [
                ("group-readable-token", 0o440),
                ("world-readable-token", 0o404),
                ("group-writable-token", 0o620),
                ("executable-token", 0o500),
            ] {
                write_secret(root.path(), name, b"unsafe-canary", mode);
                assert!(matches!(
                    resolver.resolve(&format!("secret:file/{name}")),
                    Err(SecretError::UnsafeFile)
                ));
            }
        }

        #[test]
        fn file_secret_rejects_symlinks_and_non_regular_files() {
            use std::os::unix::fs::symlink;

            let root = tempfile::tempdir().expect("temporary root");
            write_secret(root.path(), "target", b"symlink-canary", 0o600);
            symlink(root.path().join("target"), root.path().join("link")).expect("create symlink");
            fs::create_dir(root.path().join("directory")).expect("create directory");
            let resolver =
                SecretResolver::new([SecretProvider::File], root.path()).expect("resolver builds");

            assert!(matches!(
                resolver.resolve("secret:file/link"),
                Err(SecretError::Unavailable)
            ));
            assert!(matches!(
                resolver.resolve("secret:file/directory"),
                Err(SecretError::Unavailable | SecretError::UnsafeFile)
            ));
        }

        #[test]
        fn file_secret_rejects_every_name_for_a_hard_link() {
            let root = tempfile::tempdir().expect("temporary root");
            write_secret(root.path(), "first", b"hard-link-canary", 0o600);
            fs::hard_link(root.path().join("first"), root.path().join("second"))
                .expect("create hard link");
            let resolver =
                SecretResolver::new([SecretProvider::File], root.path()).expect("resolver builds");

            for name in ["first", "second"] {
                assert!(matches!(
                    resolver.resolve(&format!("secret:file/{name}")),
                    Err(SecretError::UnsafeFile)
                ));
            }
        }

        #[test]
        fn file_secret_read_is_bounded() {
            let root = tempfile::tempdir().expect("temporary root");
            write_secret(
                root.path(),
                "oversized",
                &vec![b'x'; MAX_SECRET_BYTES + 1],
                0o600,
            );
            let resolver =
                SecretResolver::new([SecretProvider::File], root.path()).expect("resolver builds");
            assert!(matches!(
                resolver.resolve("secret:file/oversized"),
                Err(SecretError::InvalidValue)
            ));
        }
    }
}
