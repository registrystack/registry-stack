// SPDX-License-Identifier: Apache-2.0
//! The `WWW-Authenticate` value of an authentication refusal.

use http::HeaderValue;

/// The `WWW-Authenticate` value every 401 carries: the `Bearer` scheme with no
/// parameter (RFC 6750 section 3), so a refusal names the scheme and nothing
/// about why.
#[must_use]
pub fn bearer_challenge() -> HeaderValue {
    HeaderValue::from_static("Bearer")
}

#[cfg(test)]
mod tests {
    use super::bearer_challenge;

    #[test]
    fn the_challenge_is_the_bare_bearer_scheme() {
        assert_eq!(bearer_challenge(), "Bearer");
    }
}
