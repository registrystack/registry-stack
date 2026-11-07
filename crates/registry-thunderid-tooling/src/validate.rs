//! The small, pure validators and constants this crate shares with the
//! platform HTTP and OIDC crates.
//!
//! They are copied rather than imported so that rendering and checking
//! identity configuration links no signing library: the `session` feature
//! brings those crates in for the development session only. A test compares
//! each copy with the platform original.

use url::Url;

/// The claim a token-exchange assertion issuer is recorded under.
pub const ASSERTION_ISSUER_CLAIM: &str = "registry_assertion_issuer";

const MAXIMUM_RESOURCE_URI_BYTES: usize = 4 * 1024;

/// The caller's original URI bytes, before a parser can trim or encode them
/// into a different identifier. Percent escapes must be complete.
fn valid_resource_uri_bytes(resource: &str) -> bool {
    let bytes = resource.as_bytes();
    if bytes.is_empty() || bytes.len() > MAXIMUM_RESOURCE_URI_BYTES {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
            continue;
        }
        if !byte.is_ascii_alphanumeric() && !b"-._~:/?[]@!$&'()*+,;=".contains(&byte) {
            return false;
        }
        index += 1;
    }
    true
}

/// An RFC 8707 resource indicator: an absolute URI without a fragment or
/// credentials.
pub(crate) fn valid_resource_uri(resource: &str) -> bool {
    if !valid_resource_uri_bytes(resource) {
        return false;
    }
    Url::parse(resource).is_ok_and(|parsed| {
        !parsed.scheme().is_empty()
            && parsed.fragment().is_none()
            && parsed.username().is_empty()
            && parsed.password().is_none()
    })
}

/// One RFC 6749 scope-token.
pub(crate) fn valid_scope_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_copies_agree_with_the_platform_originals() {
        assert_eq!(
            ASSERTION_ISSUER_CLAIM,
            registry_platform_oidc::ASSERTION_ISSUER_CLAIM
        );
        let long = format!("https://a.example/{}", "x".repeat(4100));
        let samples = [
            "",
            "urn:example:resource",
            "https://api.example/v1",
            "https://user:pw@api.example",
            "https://api.example/#frag",
            "https://api.example/%zz",
            "https://api.example/%4",
            "https://api.example/a b",
            " https://api.example",
            "not a uri",
            "no-scheme/path",
            "records:get",
            "a\"b",
            "a\\b",
            "caf\u{e9}",
            "\u{7f}",
            long.as_str(),
        ];
        for sample in samples {
            assert_eq!(
                valid_resource_uri(sample),
                registry_platform_httputil::valid_resource_uri(sample),
                "resource {sample:?}"
            );
            assert_eq!(
                valid_scope_token(sample),
                registry_platform_httputil::valid_scope_token(sample),
                "scope {sample:?}"
            );
        }
    }
}
