//! Hash helpers shared by request envelopes, rendered output, and audit.

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

/// The labelled digest of `bytes`, `sha256:<lowercase hex>`: the form every
/// `*Digest` member and `X-Registry-*-Digest` header carries, and the form
/// `package.expectedDigest` takes.
pub fn sha256_digest(bytes: &[u8]) -> String {
    sha256_label(&sha256_hex(bytes))
}

/// The labelled form of a lowercase hex SHA-256 already computed elsewhere,
/// such as the hashes a render worker reports.
pub fn sha256_label(hex: &str) -> String {
    format!("sha256:{hex}")
}

/// Short (16 hex char) prefix for logs and audit lines.
pub fn sha256_hex_short(bytes: &[u8]) -> String {
    hex::encode(&sha256(bytes)[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_the_labelled_lowercase_hex() {
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(sha256_digest(b"abc"), format!("sha256:{abc}"));
        assert_eq!(sha256_label(abc), sha256_digest(b"abc"));
    }
}
