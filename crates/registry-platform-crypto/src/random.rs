// SPDX-License-Identifier: Apache-2.0
//! Random tokens from the operating system's random number generator, for
//! nonces, `state` values, and session references.

use aws_lc_rs::rand;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use thiserror::Error;

/// Fewest random bytes a token may carry (128 bits).
pub const MIN_RANDOM_TOKEN_BYTES: usize = 16;

/// Most random bytes a token may carry.
pub const MAX_RANDOM_TOKEN_BYTES: usize = 64;

/// Why a random token was not produced. Carries nothing else, so a refusal
/// never repeats a size or any random material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RandomTokenError {
    /// The requested size is outside
    /// `MIN_RANDOM_TOKEN_BYTES..=MAX_RANDOM_TOKEN_BYTES`.
    #[error("the random token size is outside the permitted range")]
    SizeOutOfRange,
    /// The operating system's random number generator failed.
    #[error("the operating system random number generator failed")]
    Unavailable,
}

/// A token of `bytes` random bytes from the operating system's generator,
/// base64url encoded without padding.
///
/// `bytes` must be within `MIN_RANDOM_TOKEN_BYTES..=MAX_RANDOM_TOKEN_BYTES`.
/// The result is unpredictable, not secret by itself: a caller that treats it
/// as a credential owns its storage and comparison (see
/// [`crate::mac::constant_time_eq`]).
///
/// # Errors
///
/// [`RandomTokenError::SizeOutOfRange`] for a size outside the bound, and
/// [`RandomTokenError::Unavailable`] when the generator fails.
pub fn random_base64url(bytes: usize) -> Result<String, RandomTokenError> {
    if !(MIN_RANDOM_TOKEN_BYTES..=MAX_RANDOM_TOKEN_BYTES).contains(&bytes) {
        return Err(RandomTokenError::SizeOutOfRange);
    }
    let mut buffer = zeroize::Zeroizing::new([0u8; MAX_RANDOM_TOKEN_BYTES]);
    rand::fill(&mut buffer[..bytes]).map_err(|_| RandomTokenError::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(&buffer[..bytes]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn length_matches_the_unpadded_base64url_encoding_of_the_size() {
        for bytes in MIN_RANDOM_TOKEN_BYTES..=MAX_RANDOM_TOKEN_BYTES {
            let token = random_base64url(bytes).expect("in-range size");
            assert_eq!(token.len(), (bytes * 4).div_ceil(3));
            assert_eq!(
                URL_SAFE_NO_PAD.decode(&token).expect("base64url").len(),
                bytes
            );
        }
    }

    #[test]
    fn alphabet_is_unpadded_base64url() {
        for _ in 0..64 {
            let token = random_base64url(MAX_RANDOM_TOKEN_BYTES).expect("in-range size");
            assert!(token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        }
    }

    #[test]
    fn bounds_are_inclusive_and_everything_else_is_refused() {
        assert!(random_base64url(MIN_RANDOM_TOKEN_BYTES).is_ok());
        assert!(random_base64url(MAX_RANDOM_TOKEN_BYTES).is_ok());
        for bytes in [
            0,
            1,
            MIN_RANDOM_TOKEN_BYTES - 1,
            MAX_RANDOM_TOKEN_BYTES + 1,
            usize::MAX,
        ] {
            assert_eq!(
                random_base64url(bytes),
                Err(RandomTokenError::SizeOutOfRange),
                "{bytes}"
            );
        }
    }

    #[test]
    fn tokens_differ_across_calls() {
        let tokens: HashSet<String> = (0..256)
            .map(|_| random_base64url(MIN_RANDOM_TOKEN_BYTES).expect("in-range size"))
            .collect();
        assert_eq!(tokens.len(), 256);
    }
}
