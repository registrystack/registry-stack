//! Hash helpers shared by manifest sealing, envelope hashing, and audit.

use sha2::{Digest, Sha256};

/// sha256 digest of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Lowercase hex sha256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}

/// Short (16 hex char) prefix for logs and audit lines.
pub fn sha256_hex_short(bytes: &[u8]) -> String {
    hex::encode(&sha256(bytes)[..8])
}
