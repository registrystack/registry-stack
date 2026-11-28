// SPDX-License-Identifier: Apache-2.0
//! Bounded resolution of closed runtime secret references.

use std::{
    collections::BTreeSet,
    env, fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU16, Ordering},
};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::DevelopmentWitness;

/// Maximum accepted size of one resolved secret value.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

pub use registry_platform_yaml::SecretProvider;
use registry_platform_yaml::SecretReference as PureSecretReference;

/// Runtime facade over the pure secret reference parsed by
/// `registry-platform-yaml`.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretReference(PureSecretReference);

impl SecretReference {
    /// Parse one exact `secret:env/NAME` or `secret:file/name` reference.
    pub fn parse(reference: impl Into<String>) -> Result<Self, SecretError> {
        PureSecretReference::new(reference)
            .map(Self)
            .map_err(|_| SecretError::InvalidReference)
    }

    #[must_use]
    pub fn provider(&self) -> SecretProvider {
        self.0.provider()
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.0.name()
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl serde::Serialize for SecretReference {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SecretReference {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        PureSecretReference::deserialize(deserializer).map(Self)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for SecretReference {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        PureSecretReference::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        PureSecretReference::json_schema(generator)
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
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
    UnsafeFile(SecretFileCheck),
    #[error("the referenced secret could not be read")]
    Read,
    #[error("the referenced secret value is invalid")]
    InvalidValue,
}

impl SecretError {
    /// What the operator does about this failure. It states the same fix
    /// wherever the failure surfaces, so a product does not restate the rule.
    #[must_use]
    pub fn suggested_action(&self) -> &'static str {
        match self {
            Self::InvalidReference => {
                "Write the reference as an exact secret:env/NAME or secret:file/name."
            }
            Self::ProviderDisabled => {
                "Enable the reference's provider under secretProviders in the runtime file."
            }
            Self::InvalidProviderConfiguration => {
                "Enable at least one secret provider, and give the file provider an absolute root."
            }
            Self::Unavailable => {
                "Create the secret under the configured provider, or correct the name."
            }
            Self::UnsafeFile(check) => check.suggested_action(),
            Self::Read => "Check that the secret can be read by the runtime user.",
            Self::InvalidValue => {
                "Store a non-empty value of at most 64 KiB, without NUL bytes unless the secret is a binary key."
            }
        }
    }
}

/// The check a refused secret file failed. Each has its own code, text and
/// fix, none of which names a path, a reference or a value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretFileCheck {
    /// A link target is absolute, empty, or holds a `..` component.
    LinkLeavesRoot,
    /// More than [`MAX_SECRET_LINKS`] links were followed.
    TooManyLinks,
    /// The runtime user cannot open the file.
    CannotOpen,
    /// The name does not lead to a regular file.
    NotRegular,
    /// The file has more than one hard link.
    HardLinked,
    /// The owner is neither the runtime user nor root.
    Owner,
    /// Users outside the owner and group can write the file.
    WorldWritable,
    /// Users outside the owner and group can read the file.
    WorldReadable,
    /// The group has access the rule does not allow.
    GroupAccess,
    /// An execute, setuid, setgid or sticky bit, or an owner that cannot read.
    ModeBits,
}

impl SecretFileCheck {
    /// The diagnostic code, `platform.secret-file.<check>`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LinkLeavesRoot => "platform.secret-file.link-leaves-root",
            Self::TooManyLinks => "platform.secret-file.too-many-links",
            Self::CannotOpen => "platform.secret-file.cannot-open",
            Self::NotRegular => "platform.secret-file.not-regular",
            Self::HardLinked => "platform.secret-file.hard-linked",
            Self::Owner => "platform.secret-file.owner",
            Self::WorldWritable => "platform.secret-file.world-writable",
            Self::WorldReadable => "platform.secret-file.world-readable",
            Self::GroupAccess => "platform.secret-file.group-access",
            Self::ModeBits => "platform.secret-file.mode-bits",
        }
    }

    /// What is wrong, without a path, a reference or a value.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::LinkLeavesRoot => {
                "the secret file is reached through a link that leaves secretProviders.file.root"
            }
            Self::TooManyLinks => "the secret file is reached through more than 8 links",
            Self::CannotOpen => "the runtime user cannot open the secret file",
            Self::NotRegular => "the secret file is not a regular file",
            Self::HardLinked => "the secret file has more than one hard link",
            Self::Owner => "the secret file is owned by neither the runtime user nor root",
            Self::WorldWritable => {
                "users outside the file's owner and group can write the secret file"
            }
            Self::WorldReadable => {
                "users outside the file's owner and group can read the secret file"
            }
            Self::GroupAccess => "the secret file's group has access the rule does not allow",
            Self::ModeBits => {
                "the secret file has an execute, setuid, setgid or sticky bit, or its owner cannot read it"
            }
        }
    }

    /// The fix, one sentence per step.
    #[must_use]
    pub const fn suggested_action(self) -> &'static str {
        match self {
            Self::LinkLeavesRoot => {
                "Put the file under secretProviders.file.root, or use a relative link without `..` that stays below it."
            }
            Self::TooManyLinks => {
                "Point the name at the file, or at a chain of at most 8 links below secretProviders.file.root."
            }
            Self::CannotOpen => {
                "Make the file readable by the runtime user: mode 0400 or 0600 owned by that user, or 0440 owned by root with the runtime user's group. On Kubernetes, set the secret volume's defaultMode to 0440 and the pod's securityContext.fsGroup to the runtime user's group."
            }
            Self::NotRegular => {
                "Point the name at a regular file, not a directory, device, socket or pipe."
            }
            Self::HardLinked => "Replace it with a copy that has one link.",
            Self::Owner => {
                "Give it to the runtime user with mode 0400 or 0600, or to root with mode 0440 and the runtime user's group."
            }
            Self::WorldWritable => "Remove all access for others (chmod o-rwx).",
            Self::WorldReadable => {
                "Remove access for others: mode 0400 or 0600 for a file the runtime user owns, 0440 for a root-owned file. On Kubernetes, set the secret volume's defaultMode to 0440 and the pod's securityContext.fsGroup to the runtime user's group."
            }
            Self::GroupAccess => {
                "Use mode 0400 or 0600 for a file the runtime user owns. Group read is accepted only on a root-owned file (0440 or 0640) read by a non-root runtime."
            }
            Self::ModeBits => "Set mode 0400 or 0600.",
        }
    }

    /// Whether a development process loads the file with a warning instead of
    /// refusing it. Production refuses every check.
    #[must_use]
    pub const fn warns_in_development(self) -> bool {
        matches!(
            self,
            Self::WorldReadable | Self::GroupAccess | Self::ModeBits
        )
    }

    const fn bit(self) -> u16 {
        1 << (self as u16)
    }
}

/// Which checks have already warned in this process.
#[derive(Default)]
struct WarnedChecks(AtomicU16);

impl WarnedChecks {
    /// True the first time `check` is seen.
    fn first(&self, check: SecretFileCheck) -> bool {
        self.0.fetch_or(check.bit(), Ordering::Relaxed) & check.bit() == 0
    }
}

static WARNED: WarnedChecks = WarnedChecks(AtomicU16::new(0));

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
/// the configured absolute root with `openat`. A link is followed only by
/// downward relative steps from that root, at most [`MAX_SECRET_LINKS`] of
/// them. The opened file, rather than a later pathname lookup, is checked for
/// type, ownership, mode, and link count before at most [`MAX_SECRET_BYTES`]
/// are retained.
///
/// The production rule accepts a file owned by the runtime user with mode 0400
/// or 0600, and a root-owned file with no bit outside 0640 when the runtime is
/// not root. [`Self::in_development`] relaxes the read and mode-bit checks to a
/// warning for a process that declared development.
#[derive(Debug)]
pub struct SecretResolver {
    providers: BTreeSet<SecretProvider>,
    file_root: PathBuf,
    development: bool,
}

impl SecretResolver {
    /// Build a resolver with no enabled providers. Offline replay uses this
    /// capability so a route context cannot resolve environment or file
    /// secrets even if a future replay path reaches live authorization by
    /// mistake.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            providers: BTreeSet::new(),
            file_root: PathBuf::new(),
            development: false,
        }
    }

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
            development: false,
        })
    }

    /// Apply the development rule when the process holds the witness. Without
    /// it the resolver keeps the production rule, so a production path cannot
    /// relax the rule by mistake.
    #[must_use]
    pub fn in_development(mut self, witness: Option<&DevelopmentWitness>) -> Self {
        self.development = witness.is_some();
        self
    }

    /// Run every check a read runs, without retaining the bytes. A check tool
    /// uses this to give the verdict the runtime would give.
    pub fn inspect_reference(&self, reference: &SecretReference) -> Result<(), SecretError> {
        if !self.providers.contains(&reference.provider()) {
            return Err(SecretError::ProviderDisabled);
        }
        match reference.provider() {
            SecretProvider::Environment => env::var_os(reference.name())
                .map(|_| ())
                .ok_or(SecretError::Unavailable),
            SecretProvider::File => {
                open_secret_file(&self.file_root, reference.name(), self.development).map(|_| ())
            }
        }
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
        validate_secret(self.resolve_binary_reference(reference)?.0)
    }

    /// Resolve bounded, opaque secret bytes, including zero bytes in a key file.
    ///
    /// Use this explicitly for binary cryptographic material. Textual consumers
    /// should keep using [`Self::resolve_reference`], which rejects NUL bytes.
    /// File safety checks, provider allowlists, size limits and zeroization are
    /// identical for both paths. Environment values cannot contain NUL bytes.
    pub fn resolve_binary_reference(
        &self,
        reference: &SecretReference,
    ) -> Result<ProtectedSecret, SecretError> {
        if !self.providers.contains(&reference.provider()) {
            return Err(SecretError::ProviderDisabled);
        }

        let bytes = match reference.provider() {
            SecretProvider::Environment => read_environment(reference.name())?,
            SecretProvider::File => {
                read_secret_file(&self.file_root, reference.name(), self.development)?
            }
        };
        validate_binary_secret(bytes)
    }
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

/// The most links a secret name may pass through. Kubernetes uses two.
pub const MAX_SECRET_LINKS: usize = 8;

#[cfg(unix)]
fn read_secret_file(
    root: &Path,
    name: &str,
    development: bool,
) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    read_bounded(open_secret_file(root, name, development)?)
}

/// What the rule looks at in an opened file.
#[derive(Clone, Copy, Debug)]
struct Facts {
    kind: FileKind,
    uid: u32,
    mode: u32,
    nlink: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileKind {
    Regular,
    Directory,
    Fifo,
    Socket,
    Device,
}

/// Judge an opened file. Production refuses at the first failing check. In
/// development the shape, link-count, owner and world-write checks still
/// refuse, and the checks that [`SecretFileCheck::warns_in_development`] names
/// are returned as warnings.
fn judge(
    facts: Facts,
    euid: u32,
    development: bool,
) -> Result<Vec<SecretFileCheck>, SecretFileCheck> {
    use SecretFileCheck::{
        GroupAccess, HardLinked, ModeBits, NotRegular, Owner, WorldReadable, WorldWritable,
    };

    if facts.kind != FileKind::Regular {
        return Err(NotRegular);
    }
    if facts.nlink != 1 {
        return Err(HardLinked);
    }
    if facts.uid != euid && facts.uid != 0 {
        return Err(Owner);
    }
    if facts.mode & 0o002 != 0 {
        return Err(WorldWritable);
    }
    let own = facts.uid == euid;
    let mut failed = Vec::new();
    if facts.mode & 0o005 != 0 {
        failed.push(WorldReadable);
    }
    let group_bits = if own { 0o070 } else { 0o030 };
    if facts.mode & group_bits != 0 {
        failed.push(GroupAccess);
    }
    if facts.mode & 0o7100 != 0 || (own && facts.mode & 0o400 == 0) {
        failed.push(ModeBits);
    }
    match (development, failed.first()) {
        (false, Some(check)) => Err(*check),
        _ => Ok(failed),
    }
}

/// Walk `name` from the root by openat steps, following only relative
/// downward links, then judge the descriptor that will be read.
#[cfg(unix)]
fn open_secret_file(root: &Path, name: &str, development: bool) -> Result<File, SecretError> {
    use rustix::{
        fs::{Mode, OFlags},
        io::Errno,
    };
    use std::collections::VecDeque;

    let unsafe_file = SecretError::UnsafeFile;
    let mut dir = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|_| SecretError::Unavailable)?;
    let mut pending: VecDeque<Vec<u8>> = VecDeque::from([name.as_bytes().to_vec()]);
    let mut links = 0_usize;
    let secret = loop {
        let Some(component) = pending.pop_front() else {
            // A link whose target names only the directory it sits in.
            return Err(unsafe_file(SecretFileCheck::NotRegular));
        };
        let last = pending.is_empty();
        let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NOCTTY;
        flags |= if last {
            OFlags::NONBLOCK
        } else {
            OFlags::DIRECTORY
        };
        match rustix::fs::openat(&dir, component.as_slice(), flags, Mode::empty()) {
            Ok(fd) if last => break fd,
            Ok(fd) => dir = fd,
            Err(Errno::LOOP | Errno::NOTDIR) => {
                let target = match rustix::fs::readlinkat(&dir, component.as_slice(), Vec::new()) {
                    Ok(target) => target,
                    // Not a link: a file where a directory was needed.
                    Err(Errno::INVAL) => return Err(SecretError::Unavailable),
                    Err(_) => return Err(SecretError::Read),
                };
                links += 1;
                if links > MAX_SECRET_LINKS {
                    return Err(unsafe_file(SecretFileCheck::TooManyLinks));
                }
                let target = target.into_bytes();
                if target.is_empty() || target.starts_with(b"/") {
                    return Err(unsafe_file(SecretFileCheck::LinkLeavesRoot));
                }
                let mut steps = Vec::new();
                for step in target.split(|byte| *byte == b'/') {
                    match step {
                        b"" | b"." => {}
                        b".." => return Err(unsafe_file(SecretFileCheck::LinkLeavesRoot)),
                        step => steps.push(step.to_vec()),
                    }
                }
                for step in steps.into_iter().rev() {
                    pending.push_front(step);
                }
            }
            Err(Errno::NOENT) => return Err(SecretError::Unavailable),
            Err(Errno::ACCESS) => return Err(unsafe_file(SecretFileCheck::CannotOpen)),
            Err(_) => return Err(SecretError::Read),
        }
    };
    let file = File::from(secret);
    judge_file(&file, development)?;
    Ok(file)
}

#[cfg(unix)]
fn judge_file(file: &File, development: bool) -> Result<(), SecretError> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};

    let metadata = file.metadata().map_err(|_| SecretError::Read)?;
    let file_type = metadata.file_type();
    let kind = if file_type.is_file() {
        FileKind::Regular
    } else if file_type.is_dir() {
        FileKind::Directory
    } else if file_type.is_fifo() {
        FileKind::Fifo
    } else if file_type.is_socket() {
        FileKind::Socket
    } else {
        FileKind::Device
    };
    let facts = Facts {
        kind,
        uid: metadata.uid(),
        mode: metadata.permissions().mode() & 0o7777,
        nlink: metadata.nlink(),
    };
    match judge(facts, rustix::process::geteuid().as_raw(), development) {
        Err(check) => Err(SecretError::UnsafeFile(check)),
        Ok(warnings) => {
            for check in warnings {
                if WARNED.first(check) {
                    tracing::warn!(
                        error_code = check.code(),
                        "{}; production refuses it. {}",
                        check.message(),
                        check.suggested_action()
                    );
                }
            }
            Ok(())
        }
    }
}

#[cfg(not(unix))]
fn read_secret_file(
    root: &Path,
    name: &str,
    development: bool,
) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    read_bounded(open_secret_file(root, name, development)?)
}

#[cfg(not(unix))]
fn open_secret_file(root: &Path, name: &str, _development: bool) -> Result<File, SecretError> {
    let path = root.join(name);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| SecretError::Unavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SecretError::UnsafeFile(SecretFileCheck::NotRegular));
    }
    File::open(path).map_err(|_| SecretError::Unavailable)
}

/// Read at most one byte past [`MAX_SECRET_BYTES`] into one buffer allocated
/// at that size, which the read never outgrows: a grown buffer would copy
/// the value and free the old buffer without erasing it.
fn read_bounded(file: File) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES + 1));
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

fn validate_binary_secret(bytes: Zeroizing<Vec<u8>>) -> Result<ProtectedSecret, SecretError> {
    if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
        return Err(SecretError::InvalidValue);
    }
    Ok(ProtectedSecret(bytes))
}

#[cfg(test)]
#[path = "secrets_tests.rs"]
mod rule_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn environment_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().expect("lock")
    }

    #[test]
    fn cfg_sec_1_references_use_only_the_two_exact_contract_grammars() {
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
        assert!(SecretReference::parse(format!("secret:file/a{}", "b".repeat(127))).is_ok());
        assert_eq!(
            SecretReference::parse(format!("secret:file/a{}", "b".repeat(128))),
            Err(SecretError::InvalidReference)
        );
    }

    #[test]
    fn cfg_sec_1_a_refused_reference_names_the_grammar_and_never_the_value() {
        use registry_platform_yaml::{EnvelopeRule, Expect, FormatSpec, Reader};
        const REFERENCE: FormatSpec = FormatSpec {
            kind: "SecretReference",
            envelope: EnvelopeRule::Exempt {
                reason: "a secret reference read alone by its unit test",
            },
            removed_keys: &[],
        };
        let report = Reader::new("reference.yaml")
            .decode::<SecretReference>(b"canary-inline-secret", &Expect::one(&REFERENCE))
            .expect_err("a literal is not a reference");
        let message = &report.diagnostics()[0].message;
        assert!(
            message.starts_with("expected an exact secret:env/NAME or secret:file/name reference"),
            "{message:?}"
        );
        let rendered = report.render_human();
        assert!(!rendered.contains("canary-inline-secret"), "{rendered:?}");
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
    fn disabled_resolver_has_no_secret_authority() {
        let resolver = SecretResolver::disabled();
        for reference in ["secret:env/NOT_READ", "secret:file/not-read"] {
            assert!(
                matches!(
                    resolver.resolve(reference),
                    Err(SecretError::ProviderDisabled)
                ),
                "{reference} resolves through a disabled resolver"
            );
        }
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

    /// A grown buffer copies the value and frees the old one unerased, so
    /// the read must fit one buffer allocated at the bound whatever the
    /// file holds.
    #[test]
    fn a_bounded_read_never_grows_its_buffer() {
        use std::io::{Seek as _, SeekFrom, Write as _};

        for length in [
            1,
            4096,
            MAX_SECRET_BYTES,
            MAX_SECRET_BYTES + 1,
            2 * MAX_SECRET_BYTES,
        ] {
            let mut file = tempfile::tempfile().expect("temporary file");
            file.write_all(&vec![b'x'; length]).expect("write");
            file.seek(SeekFrom::Start(0)).expect("rewind");
            let bytes = read_bounded(file).expect("read");
            assert_eq!(bytes.len(), length.min(MAX_SECRET_BYTES + 1));
            assert_eq!(bytes.capacity(), MAX_SECRET_BYTES + 1, "{length} bytes");
        }
    }

    #[test]
    fn binary_values_keep_zero_bytes_within_the_same_bounds() {
        let secret = validate_binary_secret(Zeroizing::new(b"canary\0value".to_vec()))
            .expect("binary secret");
        assert_eq!(secret.expose_secret(), b"canary\0value");
        for value in [Vec::new(), vec![0; MAX_SECRET_BYTES + 1]] {
            let error = validate_binary_secret(Zeroizing::new(value)).expect_err("invalid secret");
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

            for (name, mode, check) in [
                ("group-readable-token", 0o440, SecretFileCheck::GroupAccess),
                (
                    "world-readable-token",
                    0o404,
                    SecretFileCheck::WorldReadable,
                ),
                ("group-writable-token", 0o620, SecretFileCheck::GroupAccess),
                ("executable-token", 0o500, SecretFileCheck::ModeBits),
            ] {
                write_secret(root.path(), name, b"unsafe-canary", mode);
                assert_eq!(
                    resolver
                        .resolve(&format!("secret:file/{name}"))
                        .unwrap_err(),
                    SecretError::UnsafeFile(check)
                );
            }
        }

        #[test]
        fn binary_key_files_preserve_zero_bytes_without_widening_text_secrets() {
            let root = tempfile::tempdir().expect("temporary root");
            let resolver =
                SecretResolver::new([SecretProvider::File], root.path()).expect("resolver builds");
            let bytes = [0_u8, 0xff, 1, 2, 0, 3];
            write_secret(root.path(), "binary-key", &bytes, 0o600);
            let reference = SecretReference::parse("secret:file/binary-key").unwrap();
            let key = resolver.resolve_binary_reference(&reference).unwrap();
            assert_eq!(key.expose_secret(), bytes);
            assert_eq!(format!("{key:?}"), "ProtectedSecret([REDACTED])");
            assert_eq!(
                resolver.resolve_reference(&reference).unwrap_err(),
                SecretError::InvalidValue
            );
            write_secret(root.path(), "binary-key", &bytes, 0o644);
            assert_eq!(
                resolver.resolve_binary_reference(&reference).unwrap_err(),
                SecretError::UnsafeFile(SecretFileCheck::WorldReadable)
            );
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
                assert_eq!(
                    resolver
                        .resolve(&format!("secret:file/{name}"))
                        .unwrap_err(),
                    SecretError::UnsafeFile(SecretFileCheck::HardLinked)
                );
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
