// SPDX-License-Identifier: Apache-2.0
//! Bounds shared by promoted Proposal attachment exchanges.
pub const MAX_BREG_ATTACHMENT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_BREG_ATTACHMENT_CONTENT_TYPES: usize = 16;
pub const MAX_BREG_ATTACHMENT_SLOTS: usize = 8;
pub const MAX_BREG_ATTACHMENT_CONTENT_TYPE_BYTES: usize = 255;

/// Check downloaded bytes against the exact frozen document advertisement.
pub(crate) fn verify_download(
    response: crate::BRegComplete<crate::BRegRawDocument>,
    content_type: &str,
    byte_size: u64,
    sha256: &str,
) -> Result<crate::BRegComplete<crate::BRegRawDocument>, crate::BaseRegistryClientError> {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(response.value.as_bytes());
    let actual_hash: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    if response.value.media_type() != content_type
        || response.value.as_bytes().len() as u64 != byte_size
        || actual_hash != sha256
    {
        return Err(crate::BaseRegistryClientError::protocol(
            200,
            crate::BRegProtocolFailure::Body,
            Some(response.metadata.trace_id().clone()),
        ));
    }
    Ok(response)
}

/// The exact concrete media type grammar the engine compiles and serves: one
/// lowercase `type/subtype` pair with no parameters and no wildcard.
#[must_use]
pub fn valid_attachment_content_type(value: &str) -> bool {
    fn component(value: &str) -> bool {
        let mut bytes = value.bytes();
        (1..=127).contains(&value.len())
            && bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && bytes.all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(
                        byte,
                        b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                    )
            })
    }
    value.len() <= MAX_BREG_ATTACHMENT_CONTENT_TYPE_BYTES
        && value
            .split_once('/')
            .is_some_and(|(kind, subtype)| component(kind) && component(subtype))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concrete_attachment_media_types_are_bounded() {
        for value in ["application/pdf", "text/plain", "image/svg+xml"] {
            assert!(valid_attachment_content_type(value));
        }
        for value in [
            "application/*",
            "Application/pdf",
            "text/plain; charset=utf-8",
            "text/",
            "a/b/c",
        ] {
            assert!(!valid_attachment_content_type(value));
        }
        assert!(!valid_attachment_content_type(&format!(
            "application/{}",
            "a".repeat(256)
        )));
    }
}
