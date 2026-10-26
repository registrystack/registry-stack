//! Versioned symmetric keys, held as a current key and, during a rotation, the
//! key it replaced.
//!
//! Every key this crate holds for its own state is one of these: the tagging
//! key that turns a secret into a lookup tag, the nonce key, and the sealing
//! key the PostgreSQL backend encrypts prepared requests under. New material is
//! always made under the current key. Material made under the previous key is
//! still accepted, so a deployment can roll a new key out to every replica
//! before the old one stops being honoured. Anything made under a key that is
//! neither is unreachable, which is what retiring a key means.
//!
//! Key bytes are wiped on drop and never rendered: `Debug` shows versions only.

use registry_platform_crypto::hmac_sha256_base64url_no_pad;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::store::TRANSACTION_CODE_DOMAIN;

/// The length of every key in a [`KeyRing`], in bytes.
pub const KEY_LENGTH: usize = 32;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum KeyError {
    #[error("a key must be exactly {KEY_LENGTH} bytes")]
    Length,
    #[error("the current and previous keys must carry different versions")]
    RepeatedVersion,
}

/// One key and the version it is known by.
pub struct VersionedKey {
    version: u32,
    bytes: Zeroizing<[u8; KEY_LENGTH]>,
}

impl std::fmt::Debug for VersionedKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VersionedKey")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl VersionedKey {
    /// Copy `bytes` into a key that is wiped on drop. The caller remains
    /// responsible for wiping its own copy.
    pub fn new(version: u32, bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != KEY_LENGTH {
            return Err(KeyError::Length);
        }
        let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
        key.copy_from_slice(bytes);
        Ok(Self {
            version,
            bytes: key,
        })
    }

    /// A fresh random key.
    ///
    /// # Panics
    ///
    /// Panics if the OS CSPRNG is unavailable. On the supported targets that
    /// happens only in catastrophic conditions, and a service that tagged its
    /// state with a predictable key would be worse than one that refused to
    /// start.
    #[must_use]
    pub(crate) fn generate(version: u32) -> Self {
        let mut bytes = Zeroizing::new([0u8; KEY_LENGTH]);
        getrandom::fill(bytes.as_mut_slice()).expect("the OS CSPRNG must be available at startup");
        Self { version, bytes }
    }

    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// The current key and, during a rotation, the previous one.
pub struct KeyRing {
    current: VersionedKey,
    previous: Option<VersionedKey>,
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyRing")
            .field("current", &self.current.version)
            .field(
                "previous",
                &self.previous.as_ref().map(VersionedKey::version),
            )
            .finish()
    }
}

impl KeyRing {
    /// A ring that makes everything under `current` and still accepts what
    /// was made under `previous`.
    pub fn new(current: VersionedKey, previous: Option<VersionedKey>) -> Result<Self, KeyError> {
        if previous
            .as_ref()
            .is_some_and(|previous| previous.version == current.version)
        {
            return Err(KeyError::RepeatedVersion);
        }
        Ok(Self { current, previous })
    }

    /// A ring holding one key and no previous one.
    #[must_use]
    pub fn single(current: VersionedKey) -> Self {
        Self {
            current,
            previous: None,
        }
    }

    /// A ring holding one fresh random key, for state that lives and dies
    /// with one process.
    ///
    /// # Panics
    ///
    /// Panics if the OS CSPRNG is unavailable, for the reason
    /// [`VersionedKey::generate`] gives.
    #[must_use]
    pub(crate) fn generate() -> Self {
        Self::single(VersionedKey::generate(1))
    }

    /// The key everything new is made under.
    #[must_use]
    pub fn current(&self) -> &VersionedKey {
        &self.current
    }

    /// The key a rotation replaced, still accepted for what it made.
    #[must_use]
    pub fn previous(&self) -> Option<&VersionedKey> {
        self.previous.as_ref()
    }

    /// Every key whose material is still accepted, current first.
    pub(crate) fn accepted(&self) -> impl Iterator<Item = &VersionedKey> {
        std::iter::once(&self.current).chain(self.previous.as_ref())
    }

    /// The accepted key carrying `version`, if any.
    pub(crate) fn accepted_version(&self, version: u32) -> Option<&VersionedKey> {
        self.accepted().find(|key| key.version == version)
    }
}

/// Tag a secret for one key-space under one key. The result identifies an
/// entry and is useless as the secret it stands for.
pub(crate) fn tag(key: &VersionedKey, domain: &str, secret: &str) -> Zeroizing<String> {
    let mut input = Zeroizing::new(String::with_capacity(domain.len() + secret.len() + 1));
    input.push_str(domain);
    input.push('\u{0}');
    input.push_str(secret);
    Zeroizing::new(hmac_sha256_base64url_no_pad(key.bytes(), input.as_bytes()))
}

/// Tag a transaction code for the one offer it guards, under the key that
/// offer was tagged with. The offer's tag is part of the input, so one code
/// tags differently on every offer: a reader of the stored tags cannot tell
/// which offers share a code, and tags collected from offers the reader made
/// say nothing about anyone else's.
pub(crate) fn transaction_code_tag(
    key: &VersionedKey,
    offer_tag: &str,
    transaction_code: &str,
) -> Zeroizing<String> {
    let mut input = Zeroizing::new(String::with_capacity(
        offer_tag.len() + transaction_code.len() + 1,
    ));
    input.push_str(offer_tag);
    input.push('\u{0}');
    input.push_str(transaction_code);
    tag(key, TRANSACTION_CODE_DOMAIN, &input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_exactly_thirty_two_bytes() {
        assert_eq!(
            VersionedKey::new(1, &[7u8; 31]).err(),
            Some(KeyError::Length)
        );
        assert_eq!(
            VersionedKey::new(1, &[7u8; 33]).err(),
            Some(KeyError::Length)
        );
        assert_eq!(
            VersionedKey::new(1, &[7u8; 32])
                .expect("a 32-byte key")
                .version(),
            1
        );
    }

    #[test]
    fn a_rotation_names_two_different_versions() {
        let current = VersionedKey::new(2, &[2u8; 32]).expect("a key");
        let previous = VersionedKey::new(2, &[1u8; 32]).expect("a key");
        assert_eq!(
            KeyRing::new(current, Some(previous)).err(),
            Some(KeyError::RepeatedVersion)
        );
    }

    #[test]
    fn the_current_key_comes_first_and_a_retired_version_is_not_accepted() {
        let ring = KeyRing::new(
            VersionedKey::new(2, &[2u8; 32]).expect("a key"),
            Some(VersionedKey::new(1, &[1u8; 32]).expect("a key")),
        )
        .expect("a rotation");
        let versions: Vec<u32> = ring.accepted().map(VersionedKey::version).collect();
        assert_eq!(versions, [2, 1]);
        assert!(ring.accepted_version(1).is_some());
        assert!(ring.accepted_version(0).is_none());
    }

    #[test]
    fn debug_output_renders_versions_and_never_key_bytes() {
        let ring = KeyRing::new(
            VersionedKey::new(2, &[0xab; 32]).expect("a key"),
            Some(VersionedKey::new(1, &[0xcd; 32]).expect("a key")),
        )
        .expect("a rotation");
        let rendered = format!("{ring:?} {:?}", ring.current());
        assert!(rendered.contains("current: 2"), "{rendered}");
        for byte in ["171", "205", "ab", "cd", "[", "bytes"] {
            assert!(!rendered.contains(byte), "rendered: {rendered}");
        }
    }

    #[test]
    fn tags_under_different_keys_differ_and_never_carry_the_secret() {
        let first = VersionedKey::new(1, &[1u8; 32]).expect("a key");
        let second = VersionedKey::new(2, &[2u8; 32]).expect("a key");
        let under_first = tag(&first, "oid4vci.offer", "code-1");
        let under_second = tag(&second, "oid4vci.offer", "code-1");
        assert_ne!(*under_first, *under_second);
        assert!(!under_first.contains("code-1"));
        assert_ne!(*under_first, *tag(&first, "oid4vci.access-token", "code-1"));
    }

    #[test]
    fn one_transaction_code_tags_differently_for_every_offer() {
        let key = VersionedKey::new(1, &[1u8; 32]).expect("a key");
        let first = transaction_code_tag(&key, "offer-tag-a", "4711");
        assert_ne!(*first, *transaction_code_tag(&key, "offer-tag-b", "4711"));
        assert_eq!(*first, *transaction_code_tag(&key, "offer-tag-a", "4711"));
        assert_ne!(*first, *tag(&key, TRANSACTION_CODE_DOMAIN, "4711"));
        assert!(!first.contains("4711"));
    }
}
