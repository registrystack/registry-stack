//! Versioned status keys, key rings, and the key separation rule.
//!
//! Two keys are named: the status pseudonym key and the holder-key digest key.
//! Each is configured separately; neither may equal the other, the audit
//! pseudonymization key, or the subject-binding secret, or whoever holds the
//! ledger could join it to audit records and bindings.

use std::fmt;

use registry_platform_crypto::mac::{constant_time_eq, hmac_sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The shortest key material a status key accepts, matching the audit key.
pub const MINIMUM_STATUS_KEY_BYTES: usize = 32;

/// The version every keyed ledger value records. Stored as a PostgreSQL
/// `integer`, so it runs from 1 to `i32::MAX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyVersion(u32);

impl KeyVersion {
    pub fn new(version: u32) -> Result<Self, KeyError> {
        if version == 0 || version > i32::MAX.unsigned_abs() {
            return Err(KeyError::Version);
        }
        Ok(Self(version))
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for KeyVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Why status key material or a key ring is refused. No variant carries key
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum KeyError {
    #[error("a status key version must be between 1 and 2147483647")]
    Version,
    #[error("a status key must hold at least 32 bytes")]
    TooShort,
    #[error("a status key ring names one key version twice")]
    DuplicateVersion,
    #[error("a retained status key must have a lower version than the current key")]
    RetainedNotOlder,
    #[error("a status key ring holds the same key material under two versions")]
    DuplicateMaterial,
}

/// One versioned status key. The material is erased on drop and never
/// formatted.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StatusKey {
    #[zeroize(skip)]
    version: KeyVersion,
    material: Vec<u8>,
}

impl StatusKey {
    pub fn new(version: KeyVersion, mut material: Zeroizing<Vec<u8>>) -> Result<Self, KeyError> {
        if material.len() < MINIMUM_STATUS_KEY_BYTES {
            return Err(KeyError::TooShort);
        }
        Ok(Self {
            version,
            material: std::mem::take(&mut *material),
        })
    }

    #[must_use]
    pub const fn version(&self) -> KeyVersion {
        self.version
    }

    pub(super) fn material(&self) -> &[u8] {
        &self.material
    }
}

/// Whether HMAC-SHA-256 treats two keys as one key. HMAC zero-pads short keys
/// and hashes long ones, so byte comparison alone would miss a key written
/// with trailing zero bytes or in its hashed form. Comparing the tags of a
/// fixed probe catches both, in constant time.
fn same_hmac_key(left: &[u8], right: &[u8]) -> bool {
    const PROBE: &[u8] = b"registry-evidence/status-key-separation-probe/v1";
    constant_time_eq(&hmac_sha256(left, PROBE), &hmac_sha256(right, PROBE))
}

impl fmt::Debug for StatusKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatusKey")
            .field("version", &self.version)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

/// The current key, used for every write, and the retained earlier versions,
/// used only for lookups.
#[derive(Debug)]
pub struct KeyRing {
    current: StatusKey,
    retained: Vec<StatusKey>,
}

impl KeyRing {
    pub fn new(current: StatusKey, retained: Vec<StatusKey>) -> Result<Self, KeyError> {
        let ring = Self { current, retained };
        let keys: Vec<&StatusKey> = ring.keys().collect();
        for (position, key) in keys.iter().enumerate() {
            if keys[..position]
                .iter()
                .any(|earlier| earlier.version == key.version)
            {
                return Err(KeyError::DuplicateVersion);
            }
        }
        if ring
            .retained
            .iter()
            .any(|key| key.version >= ring.current.version)
        {
            return Err(KeyError::RetainedNotOlder);
        }
        for (position, key) in keys.iter().enumerate() {
            if keys[..position]
                .iter()
                .any(|earlier| same_hmac_key(earlier.material(), key.material()))
            {
                return Err(KeyError::DuplicateMaterial);
            }
        }
        Ok(ring)
    }

    #[must_use]
    pub const fn current(&self) -> &StatusKey {
        &self.current
    }

    /// Every key in the ring, the current key first.
    pub fn keys(&self) -> impl Iterator<Item = &StatusKey> {
        std::iter::once(&self.current).chain(self.retained.iter())
    }

    /// The key written under `version`, if the ring still holds it.
    #[must_use]
    pub fn get(&self, version: KeyVersion) -> Option<&StatusKey> {
        self.keys().find(|key| key.version == version)
    }
}

/// Status pseudonym keys. The previous key stays for lookups (hook intake and
/// operator selectors) until a complete reconciliation run has re-keyed the
/// ledger and every allocation it could not re-key has expired.
#[derive(Debug)]
pub struct PseudonymKeyRing(KeyRing);

impl PseudonymKeyRing {
    #[must_use]
    pub const fn new(ring: KeyRing) -> Self {
        Self(ring)
    }

    #[must_use]
    pub const fn ring(&self) -> &KeyRing {
        &self.0
    }
}

/// Holder-key digest keys. A retired key cannot be re-keyed, because the raw
/// thumbprint is never stored, so it stays verification-only until every
/// allocation written under it has expired.
#[derive(Debug)]
pub struct HolderDigestKeyRing(KeyRing);

impl HolderDigestKeyRing {
    #[must_use]
    pub const fn new(ring: KeyRing) -> Self {
        Self(ring)
    }

    #[must_use]
    pub const fn ring(&self) -> &KeyRing {
        &self.0
    }
}

/// The keys the separation rule compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRole {
    StatusPseudonym,
    HolderKeyDigest,
    AuditPseudonymization,
    SubjectBinding,
}

impl fmt::Display for KeyRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StatusPseudonym => "status pseudonym",
            Self::HolderKeyDigest => "holder-key digest",
            Self::AuditPseudonymization => "audit pseudonymization",
            Self::SubjectBinding => "subject-binding",
        })
    }
}

/// Two keys that must differ are equal. Names the roles, never the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("the {first} key and the {second} key are equal; configure a separate key for each")]
pub struct KeySeparationError {
    pub first: KeyRole,
    pub second: KeyRole,
}

/// Refuse any two equal keys among the status pseudonym keys, the holder-key
/// digest keys, the audit pseudonymization key, and the subject-binding
/// secret. Every key in each ring takes part, retained versions included.
pub fn validate_key_separation(
    pseudonym: &PseudonymKeyRing,
    holder: &HolderDigestKeyRing,
    audit_pseudonymization_key: &[u8],
    subject_binding_secret: &[u8],
) -> Result<(), KeySeparationError> {
    let mut roles: Vec<(KeyRole, &[u8])> = Vec::new();
    roles.extend(
        pseudonym
            .ring()
            .keys()
            .map(|key| (KeyRole::StatusPseudonym, key.material())),
    );
    roles.extend(
        holder
            .ring()
            .keys()
            .map(|key| (KeyRole::HolderKeyDigest, key.material())),
    );
    roles.push((KeyRole::AuditPseudonymization, audit_pseudonymization_key));
    roles.push((KeyRole::SubjectBinding, subject_binding_secret));
    for (position, (second, right)) in roles.iter().enumerate() {
        for (first, left) in &roles[..position] {
            // Keys within one ring are already distinct; this rule is about
            // keys that serve different roles.
            if first != second && same_hmac_key(left, right) {
                return Err(KeySeparationError {
                    first: *first,
                    second: *second,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        validate_key_separation, HolderDigestKeyRing, KeyError, KeyRing, KeyRole,
        KeySeparationError, KeyVersion, PseudonymKeyRing, StatusKey,
    };
    use zeroize::{ZeroizeOnDrop, Zeroizing};

    pub(crate) fn key(version: u32, byte: u8) -> StatusKey {
        StatusKey::new(
            KeyVersion::new(version).unwrap(),
            Zeroizing::new(vec![byte; 32]),
        )
        .unwrap()
    }

    fn ring(current: StatusKey, retained: Vec<StatusKey>) -> KeyRing {
        KeyRing::new(current, retained).unwrap()
    }

    #[test]
    fn key_versions_run_from_one_to_the_largest_stored_integer() {
        assert_eq!(KeyVersion::new(0), Err(KeyError::Version));
        assert_eq!(KeyVersion::new(1).map(KeyVersion::get), Ok(1));
        assert_eq!(
            KeyVersion::new(i32::MAX as u32).map(KeyVersion::get),
            Ok(i32::MAX as u32)
        );
        assert_eq!(KeyVersion::new(i32::MAX as u32 + 1), Err(KeyError::Version));
    }

    #[test]
    fn key_material_shorter_than_thirty_two_bytes_is_refused() {
        let version = KeyVersion::new(1).unwrap();
        assert_eq!(
            StatusKey::new(version, Zeroizing::new(vec![7; 31])).err(),
            Some(KeyError::TooShort)
        );
        assert!(StatusKey::new(version, Zeroizing::new(vec![7; 32])).is_ok());
    }

    #[test]
    fn key_types_erase_their_material_on_drop() {
        fn erased_on_drop<T: ZeroizeOnDrop>() {}
        erased_on_drop::<StatusKey>();
    }

    #[test]
    fn debug_output_never_carries_key_bytes() {
        let material = b"debug-canary-key-material-0123456789".to_vec();
        let canary = StatusKey::new(KeyVersion::new(3).unwrap(), Zeroizing::new(material)).unwrap();
        let pseudonym = PseudonymKeyRing::new(ring(canary, Vec::new()));
        let holder = HolderDigestKeyRing::new(ring(key(4, b'h'), vec![key(2, b'g')]));
        for rendered in [format!("{pseudonym:?}"), format!("{holder:?}")] {
            assert!(!rendered.contains("debug-canary"), "{rendered}");
            assert!(!rendered.contains("104, 104"), "{rendered}");
            assert!(rendered.contains("[REDACTED]"), "{rendered}");
        }
    }

    #[test]
    fn a_ring_writes_with_its_current_key_and_looks_up_with_every_key() {
        let ring = ring(key(3, 3), vec![key(2, 2), key(1, 1)]);
        assert_eq!(ring.current().version().get(), 3);
        let versions: Vec<u32> = ring.keys().map(|key| key.version().get()).collect();
        assert_eq!(versions, [3, 2, 1]);
        assert_eq!(
            ring.get(KeyVersion::new(2).unwrap())
                .map(|key| key.version().get()),
            Some(2)
        );
        assert!(ring.get(KeyVersion::new(9).unwrap()).is_none());
    }

    #[test]
    fn a_ring_refuses_repeated_versions_newer_retained_keys_and_repeated_material() {
        assert_eq!(
            KeyRing::new(key(2, 2), vec![key(2, 3)]).err(),
            Some(KeyError::DuplicateVersion)
        );
        assert_eq!(
            KeyRing::new(key(2, 2), vec![key(1, 1), key(1, 4)]).err(),
            Some(KeyError::DuplicateVersion)
        );
        assert_eq!(
            KeyRing::new(key(2, 2), vec![key(3, 3)]).err(),
            Some(KeyError::RetainedNotOlder)
        );
        assert_eq!(
            KeyRing::new(key(2, 2), vec![key(1, 2)]).err(),
            Some(KeyError::DuplicateMaterial)
        );
    }

    #[test]
    fn separate_keys_pass_the_separation_rule() {
        let pseudonym = PseudonymKeyRing::new(ring(key(2, 1), vec![key(1, 2)]));
        let holder = HolderDigestKeyRing::new(ring(key(2, 3), vec![key(1, 4)]));
        assert_eq!(
            validate_key_separation(&pseudonym, &holder, &[5; 32], &[6; 32]),
            Ok(())
        );
    }

    #[test]
    fn every_pair_of_equal_keys_is_refused_with_its_roles() {
        let cases: [(u8, u8, u8, u8, KeyRole, KeyRole); 6] = [
            (
                1,
                1,
                3,
                4,
                KeyRole::StatusPseudonym,
                KeyRole::HolderKeyDigest,
            ),
            (
                1,
                2,
                1,
                4,
                KeyRole::StatusPseudonym,
                KeyRole::AuditPseudonymization,
            ),
            (
                1,
                2,
                3,
                1,
                KeyRole::StatusPseudonym,
                KeyRole::SubjectBinding,
            ),
            (
                1,
                2,
                2,
                4,
                KeyRole::HolderKeyDigest,
                KeyRole::AuditPseudonymization,
            ),
            (
                1,
                2,
                3,
                2,
                KeyRole::HolderKeyDigest,
                KeyRole::SubjectBinding,
            ),
            (
                1,
                2,
                3,
                3,
                KeyRole::AuditPseudonymization,
                KeyRole::SubjectBinding,
            ),
        ];
        for (pseudonym_byte, holder_byte, audit_byte, binding_byte, first, second) in cases {
            let pseudonym = PseudonymKeyRing::new(ring(key(1, pseudonym_byte), Vec::new()));
            let holder = HolderDigestKeyRing::new(ring(key(1, holder_byte), Vec::new()));
            let refused = validate_key_separation(
                &pseudonym,
                &holder,
                &[audit_byte; 32],
                &[binding_byte; 32],
            );
            assert_eq!(refused, Err(KeySeparationError { first, second }));
        }
    }

    #[test]
    fn retained_keys_take_part_in_the_separation_rule() {
        let pseudonym = PseudonymKeyRing::new(ring(key(2, 1), vec![key(1, 9)]));
        let holder = HolderDigestKeyRing::new(ring(key(3, 3), vec![key(2, 8), key(1, 9)]));
        assert_eq!(
            validate_key_separation(&pseudonym, &holder, &[5; 32], &[6; 32]),
            Err(KeySeparationError {
                first: KeyRole::StatusPseudonym,
                second: KeyRole::HolderKeyDigest,
            })
        );
        let pseudonym = PseudonymKeyRing::new(ring(key(2, 1), vec![key(1, 5)]));
        let holder = HolderDigestKeyRing::new(ring(key(3, 3), Vec::new()));
        assert_eq!(
            validate_key_separation(&pseudonym, &holder, &[5; 32], &[6; 32]),
            Err(KeySeparationError {
                first: KeyRole::StatusPseudonym,
                second: KeyRole::AuditPseudonymization,
            })
        );
    }

    #[test]
    fn keys_that_hmac_treats_as_equal_are_refused() {
        // HMAC zero-pads short keys, so these two byte strings are one key.
        let mut padded = vec![1; 32];
        padded.push(0);
        let pseudonym = PseudonymKeyRing::new(ring(key(1, 1), Vec::new()));
        let holder = HolderDigestKeyRing::new(ring(key(1, 2), Vec::new()));
        assert_eq!(
            validate_key_separation(&pseudonym, &holder, &padded, &[6; 32]),
            Err(KeySeparationError {
                first: KeyRole::StatusPseudonym,
                second: KeyRole::AuditPseudonymization,
            })
        );
        let padded_key =
            StatusKey::new(KeyVersion::new(1).unwrap(), Zeroizing::new(padded)).unwrap();
        assert_eq!(
            KeyRing::new(key(2, 1), vec![padded_key]).err(),
            Some(KeyError::DuplicateMaterial)
        );
    }

    #[test]
    fn separation_errors_name_roles_only() {
        let error = KeySeparationError {
            first: KeyRole::StatusPseudonym,
            second: KeyRole::SubjectBinding,
        };
        assert_eq!(
            error.to_string(),
            "the status pseudonym key and the subject-binding key are equal; configure a separate key for each"
        );
    }
}
